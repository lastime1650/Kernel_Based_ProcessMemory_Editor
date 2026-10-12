"""Fixed-width kernel manual-map wire contract; no process or DLL file access."""
import ctypes
import ntpath
import re

FUNCTION = 0x878
VERSION = 3
MAX_PATH = 520
FAILMESSAGE_BYTES = 1024
REQUEST_BYTES = 2104
MAX_IMAGE_BYTES = 64 << 20
USER_ADDRESS_END = 0x800000000000
STATUS_UNSUCCESSFUL = -1073741823
IDENTITY_NOTE = '매핑 직전에 PID와 시작 키를 확인합니다. 이 IOCTL ABI에는 시작 키가 없어 확인 이후의 PID 교체를 원자적으로 차단하지 못합니다.'


class MANUAL_MAP_REQUEST(ctypes.Structure):
    _pack_ = 1
    # Explicit uint16 WCHARs keep the Windows wire layout on test platforms too.
    _fields_ = [('Version', ctypes.c_uint32), ('Reserved', ctypes.c_uint32),
                ('ProcessId', ctypes.c_uint64), ('ImagePath', ctypes.c_uint16 * MAX_PATH),
                ('ResultStatus', ctypes.c_int32), ('MappedBase', ctypes.c_uint64),
                ('EntryPoint', ctypes.c_uint64), ('failcode', ctypes.c_uint32),
                ('failmessage', ctypes.c_char * FAILMESSAGE_BYTES)]


assert ctypes.sizeof(MANUAL_MAP_REQUEST) == REQUEST_BYTES
assert {name: getattr(MANUAL_MAP_REQUEST, name).offset for name, _ in MANUAL_MAP_REQUEST._fields_} == {
    'Version': 0, 'Reserved': 4, 'ProcessId': 8, 'ImagePath': 16,
    'ResultStatus': 1056, 'MappedBase': 1060, 'EntryPoint': 1068, 'failcode': 1076,
    'failmessage': 1080}


def valid_result_failcode(status, failcode):
    return (type(failcode) is int and 0 <= failcode <= 0xffffffff
            and ((status == 0) == (failcode == 0)))


def valid_failmessage(message):
    """The kernel emits bounded ASCII diagnostics, never a platform-codepage guess."""
    return (type(message) is str and len(message) < FAILMESSAGE_BYTES
            and all(0x20 <= ord(char) <= 0x7e or char in '\r\n\t' for char in message))


def valid_result_diagnostic(status, failcode, message):
    return (valid_result_failcode(status, failcode) and valid_failmessage(message)
            and ((status == 0) == (message == '')))


def decode_failmessage(packet):
    # ctypes c_char-array attributes stop at NUL, hiding a missing terminator or
    # trailing garbage. Inspect all 1024 wire bytes before decoding any string.
    raw = ctypes.string_at(ctypes.addressof(packet) + MANUAL_MAP_REQUEST.failmessage.offset,
                           FAILMESSAGE_BYTES)
    end = raw.find(b'\0')
    if end < 0 or any(raw[end + 1:]):
        return None
    try:
        message = raw[:end].decode('ascii', errors='strict')
    except UnicodeError:
        return None
    return message if valid_failmessage(message) else None


def valid_result_addresses(base, entry):
    if base == 0:
        return entry == 0
    return (0x10000 <= base < USER_ADDRESS_END and base % 0x1000 == 0
            and (entry == 0 or base <= entry < min(base + MAX_IMAGE_BYTES, USER_ADDRESS_END)))


def nt_dll_path(value):
    """Accept an absolute DOS/UNC disk DLL path and encode a terminated NT path."""
    if not isinstance(value, str) or not value or value != value.strip() or re.search(r'[\x00-\x1f]', value):
        raise ValueError('절대 DLL 파일 경로를 확인하세요')
    path = value.replace('/', '\\')
    if path.startswith('\\??\\'):
        path = path[4:]
        if path.upper().startswith('UNC\\'):
            path = '\\\\' + path[4:]
    elif path.startswith('\\\\?\\'):
        path = path[4:]
        if path.upper().startswith('UNC\\'):
            path = '\\\\' + path[4:]
    drive, tail = ntpath.splitdrive(path)
    if not drive or not tail.startswith('\\') or re.search(r'[<>"|?*]', path):
        raise ValueError('드라이브 또는 UNC 공유의 절대 DLL 경로가 필요합니다')
    if drive.startswith('\\\\'):
        if len(drive[2:].split('\\')) != 2 or any(not part for part in drive[2:].split('\\')) or ':' in path:
            raise ValueError('UNC DLL 경로 형식 오류')
    elif not re.fullmatch(r'[A-Za-z]:', drive) or ':' in tail:
        raise ValueError('DLL 경로 형식 오류')
    path = ntpath.normpath(path)
    name = ntpath.basename(path)
    if not name.lower().endswith('.dll') or name.endswith((' ', '.')):
        raise ValueError('디스크의 DLL 파일 경로가 필요합니다')
    if name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *('COM'+str(i) for i in range(1,10)), *('LPT'+str(i) for i in range(1,10))}:
        raise ValueError('예약된 파일 이름입니다')
    normalized = '\\??\\UNC\\' + path[2:] if path.startswith('\\\\') else '\\??\\' + path
    try:
        encoded = normalized.encode('utf-16le', errors='strict')
    except UnicodeError as exc:
        raise ValueError('DLL 경로의 UTF-16 형식 오류') from exc
    if len(encoded) // 2 >= MAX_PATH:
        raise ValueError('NT DLL 경로는 종료 문자를 포함하여 최대 520 UTF-16 문자입니다')
    return normalized, encoded + b'\0\0'


def request(pid, path):
    if isinstance(pid, bool) or not isinstance(pid, int) or not 0 < pid <= 0xffffffff:
        raise ValueError('대상 PID를 확인하세요')
    normalized, encoded = nt_dll_path(path)
    packet = MANUAL_MAP_REQUEST()
    packet.Version = VERSION
    packet.ProcessId = pid
    packet.ResultStatus = STATUS_UNSUCCESSFUL
    ctypes.memmove(ctypes.addressof(packet) + MANUAL_MAP_REQUEST.ImagePath.offset, encoded, len(encoded))
    return packet, normalized
