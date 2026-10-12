"""Ob observer V2 diagnostics and explicit control wire contract; no Windows API calls."""
import ctypes
import re
import time

FUNCTION = 0x827
REGISTER_FUNCTION = 0x828
UNREGISTER_FUNCTION = 0x829
VERSION = 2
REQUEST_BYTES = 216
CONTROL_BYTES = 32
ALTITUDE_CHARS = 16
STATUS_UNSUCCESSFUL = -1073741823
STATES = {0: 'not_initialized', 1: 'registering', 2: 'registered',
          3: 'failed', 4: 'unregistered', 5: 'unregistering'}
FAILURE_STAGES = {0: 'none', 1: 'resolve_routines', 2: 'format_altitude',
                  3: 'register_callbacks', 4: 'altitude_exhausted',
                  5: 'validate_configuration', 6: 'create_worker', 7: 'cancelled'}


class OB_CALLBACKS_STATUS_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [('StructSize', ctypes.c_uint32), ('Version', ctypes.c_uint32),
                ('ResultStatus', ctypes.c_int32), ('RegistrationStatus', ctypes.c_int32),
                ('State', ctypes.c_uint32), ('FailureStage', ctypes.c_uint32),
                ('RegistrationAttempts', ctypes.c_uint64), ('MinimumAltitude', ctypes.c_int64),
                ('MaximumAltitude', ctypes.c_int64), ('MaximumFraction', ctypes.c_uint32),
                ('LastWhole', ctypes.c_uint32), ('LastFraction', ctypes.c_uint32),
                ('RegisterRoutineResolved', ctypes.c_uint32), ('UnregisterRoutineResolved', ctypes.c_uint32),
                ('CallbackVersion', ctypes.c_uint32), ('OperationCount', ctypes.c_uint32),
                ('ProcessOperations', ctypes.c_uint32), ('ThreadOperations', ctypes.c_uint32),
                ('PreOperationEnabled', ctypes.c_uint32), ('PostOperationEnabled', ctypes.c_uint32),
                ('ObserveOnly', ctypes.c_uint32), ('DynamicResolution', ctypes.c_uint32),
                ('HandlerAddressValid', ctypes.c_uint32), ('WorkerActive', ctypes.c_uint32),
                ('Reserved', ctypes.c_uint32), ('HandlerAddress', ctypes.c_uint64),
                ('RegistrationGeneration', ctypes.c_uint64),
                ('LastRequestedMinimumAltitude', ctypes.c_int64),
                ('LastRequestedMaximumAltitude', ctypes.c_int64),
                ('LastRequestedMaximumFraction', ctypes.c_uint32), ('Reserved2', ctypes.c_uint32),
                # WCHAR has a fixed 16-bit Windows width, including in offline tests.
                ('RegisteredAltitude', ctypes.c_uint16 * ALTITUDE_CHARS),
                ('LastAttemptAltitude', ctypes.c_uint16 * ALTITUDE_CHARS)]


assert ctypes.sizeof(OB_CALLBACKS_STATUS_REQUEST) == REQUEST_BYTES
assert OB_CALLBACKS_STATUS_REQUEST.HandlerAddress.offset == 112
assert OB_CALLBACKS_STATUS_REQUEST.RegisteredAltitude.offset == 152
assert OB_CALLBACKS_STATUS_REQUEST.LastAttemptAltitude.offset == 184


class OB_CALLBACKS_CONTROL_REQUEST(ctypes.Structure):
    _pack_ = 8
    _fields_ = [('StructSize', ctypes.c_uint32), ('Version', ctypes.c_uint32),
                ('ResultStatus', ctypes.c_int32), ('MinimumAltitude', ctypes.c_uint32),
                ('MaximumAltitude', ctypes.c_uint32), ('MaximumFraction', ctypes.c_uint32),
                ('Reserved', ctypes.c_uint32 * 2)]


assert ctypes.sizeof(OB_CALLBACKS_CONTROL_REQUEST) == CONTROL_BYTES
assert OB_CALLBACKS_CONTROL_REQUEST.Reserved.offset == 24

NUMERIC_FIELDS = {
    'RegistrationAttempts': 'registration_attempts', 'MinimumAltitude': 'minimum_altitude',
    'MaximumAltitude': 'maximum_altitude', 'MaximumFraction': 'maximum_fraction',
    'LastWhole': 'last_whole', 'LastFraction': 'last_fraction',
    'CallbackVersion': 'callback_version', 'OperationCount': 'operation_count',
    'ProcessOperations': 'process_operations', 'ThreadOperations': 'thread_operations',
    'RegistrationGeneration': 'registration_generation',
    'LastRequestedMinimumAltitude': 'last_requested_minimum_altitude',
    'LastRequestedMaximumAltitude': 'last_requested_maximum_altitude',
    'LastRequestedMaximumFraction': 'last_requested_maximum_fraction'}
BOOLEAN_FIELDS = {
    'RegisterRoutineResolved': 'register_routine_resolved',
    'UnregisterRoutineResolved': 'unregister_routine_resolved',
    'PreOperationEnabled': 'pre_operation_enabled', 'PostOperationEnabled': 'post_operation_enabled',
    'ObserveOnly': 'observe_only', 'DynamicResolution': 'dynamic_resolution',
    'HandlerAddressValid': 'handler_address_valid', 'WorkerActive': 'worker_active'}


def configuration(minimum, maximum, maximum_fraction=1000):
    values = (minimum, maximum, maximum_fraction)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError('altitude 범위와 최대 소수 카운터는 정수로 입력하세요.')
    if not 0 <= minimum <= maximum <= 0xffffffff:
        raise ValueError('altitude 범위는 0부터 4294967295 사이이며 최솟값은 최댓값 이하여야 합니다.')
    if not 0 <= maximum_fraction <= 1000:
        raise ValueError('최대 소수 카운터는 0부터 1000 사이여야 합니다.')
    return values


def control_request(action, minimum=0, maximum=0, maximum_fraction=0):
    if action not in ('register', 'unregister'):
        raise ValueError('지원하지 않는 Ob 콜백 작업입니다.')
    if action == 'register':
        minimum, maximum, maximum_fraction = configuration(minimum, maximum, maximum_fraction)
    elif (minimum, maximum, maximum_fraction) != (0, 0, 0):
        raise ValueError('해제 요청에는 altitude 설정을 전달하지 않습니다.')
    packet = OB_CALLBACKS_CONTROL_REQUEST()
    packet.StructSize, packet.Version = CONTROL_BYTES, VERSION
    packet.ResultStatus = STATUS_UNSUCCESSFUL
    packet.MinimumAltitude, packet.MaximumAltitude, packet.MaximumFraction = minimum, maximum, maximum_fraction
    return packet


def request():
    packet = OB_CALLBACKS_STATUS_REQUEST()
    packet.StructSize = REQUEST_BYTES
    packet.Version = VERSION
    packet.ResultStatus = STATUS_UNSUCCESSFUL
    packet.RegistrationStatus = STATUS_UNSUCCESSFUL
    return packet


def failure(kind, message, *, connected=False, error_code=0, transport_ok=False,
            packet_valid=False, bytes_returned=0, result_status=None):
    """Unknown live state has null fields, never a source/configuration fallback."""
    result = dict(success=False, error_kind=kind, error=message, error_code=error_code,
                  unsupported=kind == 'unsupported', connected=bool(connected), readonly=True,
                  transport_ok=bool(transport_ok), packet_valid=bool(packet_valid),
                  bytes_returned=bytes_returned, state='unknown', state_code=None,
                  registered=None, result_status=result_status, registration_status=None,
                  registration_status_code=None, failure_stage=None, failure_stage_code=None,
                  registered_altitude=None, last_attempt_altitude=None, handler_address=None,
                  queried_at=time.time())
    result.update({name: None for name in (*NUMERIC_FIELDS.values(), *BOOLEAN_FIELDS.values())})
    return result


def _altitude(units):
    values = list(units)
    try:
        terminator = values.index(0)
    except ValueError as exc:
        raise ValueError('altitude 문자열에 종료 문자가 없습니다') from exc
    value = bytes(units)[:terminator * 2].decode('utf-16-le', errors='strict')
    if value and value != '-1' and not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value):
        raise ValueError('altitude 문자열 형식이 올바르지 않습니다')
    return value


def response(packet, ok, error, returned):
    common = dict(connected=True, error_code=error, transport_ok=ok, bytes_returned=returned)
    if not ok:
        unsupported = error in (1, 50)  # ERROR_INVALID_FUNCTION / ERROR_NOT_SUPPORTED.
        kind = 'unsupported' if unsupported else 'abi_mismatch' if error == 87 else 'read_failed'
        return failure(kind,
                       '현재 로드된 드라이버는 Ob 콜백 V2 상태 조회(0x827)를 지원하지 않습니다.'
                       if unsupported else '현재 드라이버와 Ob 콜백 V2 ABI가 일치하지 않습니다.' if error == 87
                       else 'Ob 콜백 상태 조회에 실패했습니다. 드라이버 연결과 오류 코드를 확인하세요.',
                       **common)
    try:
        if (returned != REQUEST_BYTES or packet.StructSize != REQUEST_BYTES or packet.Version != VERSION
                or packet.Reserved != 0 or packet.Reserved2 != 0 or packet.State not in STATES
                or packet.FailureStage not in FAILURE_STAGES
                or any(getattr(packet, field) not in (0, 1) for field in BOOLEAN_FIELDS)):
            raise ValueError('Ob 콜백 상태 응답의 크기, 버전 또는 필드가 올바르지 않습니다')
        registered_altitude = _altitude(packet.RegisteredAltitude)
        last_attempt_altitude = _altitude(packet.LastAttemptAltitude)
        if bool(packet.HandlerAddressValid) != bool(packet.HandlerAddress):
            raise ValueError('핸들러 주소와 유효성 정보가 일치하지 않습니다')
        if packet.State == 2 and (packet.RegistrationStatus < 0 or registered_altitude in ('', '-1')
                                  or not packet.HandlerAddressValid):
            raise ValueError('등록 완료 상태와 등록 결과가 일치하지 않습니다')
        if packet.State == 4 and (packet.MinimumAltitude != -1 or packet.MaximumAltitude != -1
                                  or packet.MaximumFraction != 0 or registered_altitude != '-1'
                                  or packet.HandlerAddressValid or packet.WorkerActive):
            raise ValueError('해제 상태의 설정 또는 핸들러 정보가 올바르지 않습니다')
    except (ValueError, UnicodeError) as exc:
        return failure('invalid_reply', str(exc), **common)
    result_status = f'0x{packet.ResultStatus & 0xffffffff:08X}'
    if packet.ResultStatus != 0:
        unsupported = packet.ResultStatus & 0xffffffff in (0xC0000010, 0xC00000BB)
        return failure('unsupported' if unsupported else 'read_failed',
                       '현재 로드된 드라이버는 Ob 콜백 상태 조회(0x827)를 지원하지 않습니다.'
                       if unsupported else '드라이버가 Ob 콜백 상태 조회 실패를 반환했습니다.',
                       packet_valid=True, result_status=result_status, **common)
    result = dict(success=True, unsupported=False, connected=True, readonly=True,
                  transport_ok=True, packet_valid=True, error_code=error, bytes_returned=returned,
                  result_status=result_status, state=STATES[packet.State], state_code=packet.State,
                  registered=packet.State == 2, registration_status=f'0x{packet.RegistrationStatus & 0xffffffff:08X}',
                  registration_status_code=packet.RegistrationStatus,
                  failure_stage=FAILURE_STAGES[packet.FailureStage], failure_stage_code=packet.FailureStage,
                  registered_altitude=registered_altitude, last_attempt_altitude=last_attempt_altitude,
                  handler_address=f'0x{packet.HandlerAddress:X}',
                  queried_at=time.time())
    result.update({name: int(getattr(packet, field)) for field, name in NUMERIC_FIELDS.items()})
    result.update({name: bool(getattr(packet, field)) for field, name in BOOLEAN_FIELDS.items()})
    return result


def control_failure(action, kind, message, *, connected=False, error_code=0, transport_ok=False,
                    packet_valid=False, bytes_returned=0, result_status=None):
    return dict(action=action, success=False, accepted=False, completed=False,
                error_kind=kind, error=message, connected=bool(connected), readonly=False,
                unsupported=kind == 'unsupported', error_code=error_code,
                transport_ok=bool(transport_ok), packet_valid=bool(packet_valid),
                bytes_returned=bytes_returned, result_status=result_status, queried_at=time.time())


def control_response(action, packet, expected, ok, error, returned):
    common = dict(connected=True, error_code=error, transport_ok=ok, bytes_returned=returned)
    if not ok:
        kind = 'unsupported' if error in (1, 50) else 'abi_mismatch' if error == 87 else 'control_failed'
        return control_failure(action, kind, '현재 드라이버는 Ob 콜백 V2 제어를 지원하지 않습니다.'
                               if kind == 'unsupported' else 'Ob 콜백 제어 응답을 받지 못했습니다.', **common)
    actual = (packet.MinimumAltitude, packet.MaximumAltitude, packet.MaximumFraction)
    if (returned != CONTROL_BYTES or packet.StructSize != CONTROL_BYTES or packet.Version != VERSION
            or any(packet.Reserved) or actual != expected):
        return control_failure(action, 'invalid_reply', 'Ob 콜백 제어 응답의 ABI 또는 요청 값이 일치하지 않습니다.',
                               **common)
    result_status = f'0x{packet.ResultStatus & 0xffffffff:08X}'
    if packet.ResultStatus != 0:
        kind = 'unsupported' if packet.ResultStatus & 0xffffffff in (0xC0000010, 0xC00000BB) else 'operation_failed'
        return control_failure(action, kind, 'Ob 콜백 요청이 거부되었습니다. 현재 상태와 NTSTATUS를 확인하세요.',
                               packet_valid=True, result_status=result_status, **common)
    return dict(action=action, success=True, accepted=action == 'register', completed=action == 'unregister',
                unsupported=False, connected=True, readonly=False, transport_ok=True, packet_valid=True,
                error_code=error, bytes_returned=returned, result_status=result_status, queried_at=time.time())
