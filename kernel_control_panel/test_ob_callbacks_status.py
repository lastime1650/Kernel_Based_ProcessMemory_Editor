"""V2 fixed ABI, fake DeviceIoControl and in-process ASGI tests; no live device."""
import ctypes as C
import struct
import threading
import unittest

from fastapi import FastAPI
import driver_bridge as D
import ob_callbacks_protocol as P
from kernel_only_bridge import KernelOnlyBridge
from test_asgi_client import ASGIClient


def altitude(packet, field, value):
    raw = value.encode('utf-16-le') + b'\0\0'
    if len(raw) > 32:
        raise ValueError('test altitude too long')
    C.memmove(C.addressof(packet) + getattr(type(packet), field).offset, raw, len(raw))


def fill(packet, state=2, status=0):
    packet.ResultStatus = 0
    packet.RegistrationStatus = C.c_int32(status).value
    packet.State = state
    packet.FailureStage = 0 if state != 3 else 3
    packet.RegistrationAttempts = 1002
    inactive = state in (0, 4)
    packet.MinimumAltitude = -1 if inactive else 80000
    packet.MaximumAltitude = -1 if inactive else 429999
    packet.MaximumFraction = 0 if inactive else 1000
    packet.LastWhole = 80001
    packet.LastFraction = 0
    packet.RegisterRoutineResolved = packet.UnregisterRoutineResolved = 1
    packet.CallbackVersion = 0x100
    packet.OperationCount = 2
    packet.ProcessOperations = packet.ThreadOperations = 3
    packet.PreOperationEnabled = packet.ObserveOnly = packet.DynamicResolution = 1
    packet.PostOperationEnabled = 0
    packet.HandlerAddressValid = int(state == 2)
    packet.HandlerAddress = 0xFFFFF80123456789 if state == 2 else 0
    packet.WorkerActive = int(state == 1)
    packet.RegistrationGeneration = 42
    packet.LastRequestedMinimumAltitude = -1 if inactive else 80000
    packet.LastRequestedMaximumAltitude = -1 if inactive else 429999
    packet.LastRequestedMaximumFraction = 0 if inactive else 1000
    altitude(packet, 'RegisteredAltitude', '80001' if state == 2 else '-1')
    altitude(packet, 'LastAttemptAltitude', '80001')


class ProtocolTests(unittest.TestCase):
    def test_exact_fixed_width_abi_and_all_offsets(self):
        expected = dict(StructSize=0, Version=4, ResultStatus=8, RegistrationStatus=12,
                        State=16, FailureStage=20, RegistrationAttempts=24, MinimumAltitude=32,
                        MaximumAltitude=40, MaximumFraction=48, LastWhole=52, LastFraction=56,
                        RegisterRoutineResolved=60, UnregisterRoutineResolved=64,
                        CallbackVersion=68, OperationCount=72, ProcessOperations=76,
                        ThreadOperations=80, PreOperationEnabled=84, PostOperationEnabled=88,
                        ObserveOnly=92, DynamicResolution=96, HandlerAddressValid=100,
                        WorkerActive=104, Reserved=108, HandlerAddress=112, RegistrationGeneration=120,
                        LastRequestedMinimumAltitude=128, LastRequestedMaximumAltitude=136,
                        LastRequestedMaximumFraction=144, Reserved2=148,
                        RegisteredAltitude=152, LastAttemptAltitude=184)
        self.assertEqual(C.sizeof(P.OB_CALLBACKS_STATUS_REQUEST), 216)
        self.assertEqual({name: getattr(P.OB_CALLBACKS_STATUS_REQUEST, name).offset
                          for name, _ in P.OB_CALLBACKS_STATUS_REQUEST._fields_}, expected)
        self.assertEqual(P.FUNCTION, 0x827)
        self.assertEqual(D.IOCTL_HELPER_QUERY_OB_CALLBACKS_STATUS, 0x0022E09C)
        self.assertEqual(D.IOCTL_HELPER_REGISTER_OB_CALLBACKS, 0x0022E0A0)
        self.assertEqual(D.IOCTL_HELPER_UNREGISTER_OB_CALLBACKS, 0x0022E0A4)
        self.assertIs(KernelOnlyBridge.get_ob_callbacks_status, D.KernelDriverBridge.get_ob_callbacks_status)

    def test_request_has_defensive_output_status_and_zero_payload(self):
        packet = P.request()
        self.assertEqual(struct.unpack_from('<IIii', bytes(packet)),
                         (216, 2, P.STATUS_UNSUCCESSFUL, P.STATUS_UNSUCCESSFUL))
        self.assertEqual(bytes(packet)[16:], b'\0' * 200)

    def test_all_states_are_successful_queries_independent_of_registration(self):
        for state, name in P.STATES.items():
            packet = P.request()
            fill(packet, state, 0xC0000022 if state == 3 else 0)
            result = P.response(packet, True, 0, 216)
            self.assertTrue(result['success'], result)
            self.assertEqual(result['state'], name)
            self.assertEqual(result['registered'], state == 2)
            self.assertEqual(result['registration_status'], '0xC0000022' if state == 3 else '0x00000000')
        self.assertEqual(result['failure_stage'], 'none')

    def test_actual_configuration_and_disabled_flags_are_not_replaced_by_defaults(self):
        packet = P.request()
        fill(packet, 3, 0xC01C0011)
        packet.MinimumAltitude, packet.MaximumAltitude, packet.MaximumFraction = 420001, 420002, 17
        packet.RegisterRoutineResolved, packet.UnregisterRoutineResolved = 0, 1
        packet.PreOperationEnabled = packet.ObserveOnly = packet.DynamicResolution = 0
        packet.PostOperationEnabled = 1
        packet.FailureStage = 4
        packet.RegistrationAttempts = (1 << 32) * 1001
        result = P.response(packet, True, 0, 216)
        self.assertTrue(result['success'])
        self.assertEqual([result[name] for name in ('minimum_altitude', 'maximum_altitude', 'maximum_fraction')],
                         [420001, 420002, 17])
        self.assertEqual(result['registration_attempts'], 4299262263296)
        self.assertEqual(result['failure_stage'], 'altitude_exhausted')
        self.assertFalse(result['register_routine_resolved'])
        self.assertFalse(result['pre_operation_enabled'])
        self.assertFalse(result['observe_only'])
        self.assertFalse(result['dynamic_resolution'])
        self.assertTrue(result['post_operation_enabled'])

    def test_not_initialized_device_not_ready_is_a_valid_query(self):
        packet = P.request()
        fill(packet, 0, 0xC00000A3)
        packet.RegistrationAttempts = 0
        packet.RegisterRoutineResolved = packet.UnregisterRoutineResolved = 0
        altitude(packet, 'LastAttemptAltitude', '')
        result = P.response(packet, True, 0, 216)
        self.assertTrue(result['success'])
        self.assertFalse(result['registered'])
        self.assertEqual(result['state'], 'not_initialized')
        self.assertEqual(result['registration_status'], '0xC00000A3')
        self.assertFalse(result['register_routine_resolved'])
        self.assertEqual(result['operation_count'], 2)

    def test_fraction_spelling_maximum_length_and_utf16_termination(self):
        packet = P.request()
        fill(packet)
        for value in ('0', '0.1000', '80000.1', '80000.10', '80000.1000', '4294967295.1000'):
            altitude(packet, 'RegisteredAltitude', value)
            result = P.response(packet, True, 0, 216)
            self.assertTrue(result['success'], result)
            self.assertEqual(result['registered_altitude'], value)

    def test_unknown_reply_fields_and_lengths_do_not_expose_registered_state(self):
        corruptions = [lambda p:setattr(p, 'StructSize', 160), lambda p:setattr(p, 'Version', 1),
                       lambda p:setattr(p, 'Reserved', 1), lambda p:setattr(p, 'Reserved2', 1),
                       lambda p:setattr(p, 'State', 6), lambda p:setattr(p, 'FailureStage', 8),
                       lambda p:setattr(p, 'ObserveOnly', 2), lambda p:setattr(p, 'WorkerActive', 2),
                       lambda p:setattr(p, 'HandlerAddressValid', 0), lambda p:setattr(p, 'HandlerAddress', 0),
                       lambda p:setattr(p, 'RegistrationStatus', -1),
                       lambda p:altitude(p, 'RegisteredAltitude', ''),
                       lambda p:altitude(p, 'RegisteredAltitude', '<script>'),
                       lambda p:[p.LastAttemptAltitude.__setitem__(i, ord('1')) for i in range(16)]]
        for corrupt in corruptions:
            packet = P.request()
            fill(packet)
            corrupt(packet)
            result = P.response(packet, True, 0, 216)
            self.assertFalse(result['success'], result)
            self.assertEqual(result['error_kind'], 'invalid_reply')
            self.assertIsNone(result['registered'])
            self.assertIsNone(result['registered_altitude'])
            self.assertIsNone(result['minimum_altitude'])
        for returned in (0, 160, 215, 217):
            packet = P.request()
            fill(packet)
            self.assertFalse(P.response(packet, True, 0, returned)['success'])

    def test_nonzero_query_status_never_becomes_registration_success(self):
        for status, kind in ((0xC0000022, 'read_failed'), (0xC0000010, 'unsupported'),
                             (0xC00000BB, 'unsupported'), (0x103, 'read_failed')):
            packet = P.request()
            fill(packet)
            packet.ResultStatus = C.c_int32(status).value
            result = P.response(packet, True, 0, 216)
            self.assertFalse(result['success'])
            self.assertEqual(result['error_kind'], kind)
            self.assertIsNone(result['registered'])
            self.assertIsNone(result['registration_status'])

    def test_inactive_sentinels_handler_and_historical_range_remain_distinct(self):
        packet = P.request()
        fill(packet, 4)
        packet.LastRequestedMinimumAltitude = 0
        packet.LastRequestedMaximumAltitude = 0xffffffff
        packet.LastRequestedMaximumFraction = 1000
        result = P.response(packet, True, 0, 216)
        self.assertTrue(result['success'], result)
        self.assertEqual((result['minimum_altitude'], result['maximum_altitude'], result['maximum_fraction']),
                         (-1, -1, 0))
        self.assertEqual((result['registered_altitude'], result['handler_address'], result['handler_address_valid']),
                         ('-1', '0x0', False))
        self.assertEqual((result['last_requested_minimum_altitude'], result['last_requested_maximum_altitude'],
                          result['last_requested_maximum_fraction']), (0, 4294967295, 1000))
        self.assertEqual(result['registration_generation'], 42)
        packet.MinimumAltitude = 0
        result = P.response(packet, True, 0, 216)
        self.assertEqual(result['error_kind'], 'invalid_reply')

    def test_async_registering_pending_status_is_a_successful_query(self):
        packet = P.request()
        fill(packet, 1, 0x103)
        result = P.response(packet, True, 0, 216)
        self.assertTrue(result['success'])
        self.assertFalse(result['registered'])
        self.assertTrue(result['worker_active'])
        self.assertEqual(result['registration_status'], '0x00000103')
        self.assertEqual(result['handler_address'], '0x0')


class ControlProtocolTests(unittest.TestCase):
    def test_control_fixed_width_layout_and_reserved_offset(self):
        self.assertEqual(C.sizeof(P.OB_CALLBACKS_CONTROL_REQUEST), 32)
        self.assertEqual({name:getattr(P.OB_CALLBACKS_CONTROL_REQUEST, name).offset
                          for name, _ in P.OB_CALLBACKS_CONTROL_REQUEST._fields_},
                         dict(StructSize=0, Version=4, ResultStatus=8, MinimumAltitude=12,
                              MaximumAltitude=16, MaximumFraction=20, Reserved=24))
        packet = P.control_request('register', 0, 0xffffffff, 1000)
        self.assertEqual(struct.unpack('<IIiIIIII', bytes(packet)),
                         (32, 2, P.STATUS_UNSUCCESSFUL, 0, 0xffffffff, 1000, 0, 0))
        packet = P.control_request('unregister')
        self.assertEqual(struct.unpack('<IIiIIIII', bytes(packet)),
                         (32, 2, P.STATUS_UNSUCCESSFUL, 0, 0, 0, 0, 0))

    def test_configuration_strict_integer_types_and_all_boundaries(self):
        self.assertEqual(P.configuration(0, 0), (0, 0, 1000))
        self.assertEqual(P.configuration(0xffffffff, 0xffffffff, 0), (0xffffffff, 0xffffffff, 0))
        bad = [(True, 1, 1), (0, False, 1), (0, 1, True), (0.0, 1, 1), (0, 1.0, 1),
               ('0', 1, 1), (0, '1', 1), (0, 1, '1000'), (None, 1, 1),
               (-1, 1, 1), (0, 0x100000000, 1), (2, 1, 1), (0, 1, -1), (0, 1, 1001)]
        for values in bad:
            with self.subTest(values=values), self.assertRaises(ValueError):
                P.configuration(*values)


class ControlTransportTests(unittest.TestCase):
    def test_register_acceptance_is_not_completion_or_status_poll(self):
        driver = TransportTests().bridge()
        result = driver.register_ob_callbacks(0, 0xffffffff)
        self.assertTrue(result['success'] and result['accepted'])
        self.assertFalse(result['completed'] or result['readonly'])
        self.assertEqual(result['action'], 'register')
        self.assertNotIn('registered', result)
        self.assertNotIn('handler_address', result)
        self.assertEqual(len(driver._kernel32.calls), 1)
        _, code, raw, size = driver._kernel32.calls[0]
        self.assertEqual((code, size), (0x22E0A0, 32))
        self.assertEqual(struct.unpack('<IIiIIIII', raw), (32, 2, P.STATUS_UNSUCCESSFUL, 0, 0xffffffff, 1000, 0, 0))

    def test_unregister_is_completed_and_sends_only_zero_configuration(self):
        driver = TransportTests().bridge()
        result = driver.unregister_ob_callbacks()
        self.assertTrue(result['success'] and result['completed'])
        self.assertFalse(result['accepted'] or result['readonly'])
        self.assertEqual(result['action'], 'unregister')
        _, code, raw, size = driver._kernel32.calls[0]
        self.assertEqual((code, size), (0x22E0A4, 32))
        self.assertEqual(raw[12:], b'\0' * 20)

    def test_invalid_values_and_disconnected_controls_never_call_fake_device(self):
        driver = TransportTests().bridge()
        for values in ((False, 1), (-1, 2), (0, 0x100000000), (2, 1), (0, 1, 1001), ('0', 1), (0, 1, 1.0)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                driver.register_ob_callbacks(*values)
        driver.handle = None
        self.assertEqual(driver.register_ob_callbacks(0, 1)['error_kind'], 'disconnected')
        self.assertEqual(driver.unregister_ob_callbacks()['error_kind'], 'disconnected')
        self.assertEqual(driver._kernel32.calls, [])

    def test_kernel_busy_wrong_state_and_pending_are_not_control_success(self):
        for status in (0xC000009E, 0xC0000184, 0x103):
            driver = TransportTests().bridge(FakeKernel(control_status=status))
            for call in (lambda:driver.register_ob_callbacks(0, 1), driver.unregister_ob_callbacks):
                result = call()
                self.assertFalse(result['success'] or result['accepted'] or result['completed'])
                self.assertTrue(result['packet_valid'])
                self.assertEqual(result['error_kind'], 'operation_failed')
                self.assertEqual(result['result_status'], f'0x{status:08X}')
            self.assertEqual(len(driver._kernel32.calls), 2)

    def test_truncated_old_abi_corrupt_echo_or_failed_transport_never_accepts(self):
        cases = [dict(returned=31), dict(returned=33), dict(returned=160),
                 dict(corrupt=lambda p:setattr(p, 'StructSize', 216)),
                 dict(corrupt=lambda p:setattr(p, 'Version', 1)),
                 dict(corrupt=lambda p:p.Reserved.__setitem__(0, 1)),
                 dict(corrupt=lambda p:setattr(p, 'MinimumAltitude', 2)),
                 dict(corrupt=lambda p:setattr(p, 'MaximumFraction', 999)),
                 dict(ok=False, error=1), dict(ok=False, error=50), dict(ok=False, error=87),
                 dict(ok=False, error=5)]
        for changes in cases:
            with self.subTest(changes=changes):
                driver = TransportTests().bridge(FakeKernel(**changes))
                result = driver.register_ob_callbacks(0, 1)
                self.assertFalse(result['success'] or result['accepted'])
                self.assertFalse(result['packet_valid'])
                self.assertEqual(len(driver._kernel32.calls), 1)


class FakeKernel:
    def __init__(self, *, ok=True, error=0, returned=None, state=2, registration_status=0,
                 control_status=0, corrupt=None):
        self.ok, self.error, self.returned = ok, error, returned
        self.state, self.registration_status = state, registration_status
        self.control_status, self.corrupt = control_status, corrupt
        self.calls = []

    def DeviceIoControl(self, handle, code, data, size, output, output_size, returned, overlap):
        self.calls.append((handle, code, bytes(C.string_at(data, size)), output_size))
        if code == D.IOCTL_HELPER_QUERY_OB_CALLBACKS_STATUS:
            packet = C.cast(output, C.POINTER(P.OB_CALLBACKS_STATUS_REQUEST)).contents
            fill(packet, self.state, self.registration_status)
        else:
            assert code in (D.IOCTL_HELPER_REGISTER_OB_CALLBACKS, D.IOCTL_HELPER_UNREGISTER_OB_CALLBACKS)
            packet = C.cast(output, C.POINTER(P.OB_CALLBACKS_CONTROL_REQUEST)).contents
            packet.ResultStatus = C.c_int32(self.control_status).value
        if self.corrupt:
            self.corrupt(packet)
        C.cast(returned, C.POINTER(C.wintypes.DWORD)).contents.value = size if self.returned is None else self.returned
        C.set_last_error(self.error)
        return self.ok

    def CreateFileW(self, *args):
        raise AssertionError('status query must never open a device')


class TransportTests(unittest.TestCase):
    def bridge(self, api=None):
        driver = D.KernelDriverBridge.__new__(D.KernelDriverBridge)
        driver._lock = threading.RLock()
        driver.handle = 0x1234567887654321
        driver._kernel32 = api or FakeKernel()
        return driver

    def test_real_transport_wrapper_only_reaches_fake_deviceiocontrol(self):
        driver = self.bridge()
        result = driver.get_ob_callbacks_status()
        self.assertTrue(result['success'])
        self.assertTrue(result['registered'])
        self.assertEqual(len(driver._kernel32.calls), 1)
        handle, code, raw, size = driver._kernel32.calls[0]
        self.assertEqual((handle, code, size), (0x1234567887654321, 0x22E09C, 216))
        self.assertEqual(struct.unpack_from('<IIii', raw), (216, 2, P.STATUS_UNSUCCESSFUL, P.STATUS_UNSUCCESSFUL))
        self.assertEqual(result['handler_address'], '0xFFFFF80123456789')

    def test_disconnected_never_opens_or_queries_device(self):
        driver = self.bridge()
        driver.handle = None
        result = driver.get_ob_callbacks_status()
        self.assertEqual(result['error_kind'], 'disconnected')
        self.assertFalse(result['connected'])
        self.assertIsNone(result['registered'])
        self.assertEqual(driver._kernel32.calls, [])

    def test_old_driver_and_other_transport_failures_clear_all_live_fields(self):
        for error, kind in ((1, 'unsupported'), (50, 'unsupported'), (87, 'abi_mismatch'),
                            (5, 'read_failed'), (6, 'read_failed')):
            driver = self.bridge(FakeKernel(ok=False, error=error, returned=0))
            result = driver.get_ob_callbacks_status()
            self.assertEqual(result['error_kind'], kind)
            self.assertFalse(result['success'])
            self.assertIsNone(result['registered'])
            self.assertIsNone(result['observe_only'])
            self.assertIsNone(result['registration_attempts'])
            self.assertEqual(len(driver._kernel32.calls), 1)

    def test_each_query_is_fresh_and_a_failure_cannot_reuse_previous_success(self):
        driver = self.bridge()
        self.assertTrue(driver.get_ob_callbacks_status()['registered'])
        driver._kernel32.state = 3
        driver._kernel32.registration_status = 0xC0000022
        result = driver.get_ob_callbacks_status()
        self.assertTrue(result['success'])
        self.assertFalse(result['registered'])
        driver._kernel32.ok, driver._kernel32.error = False, 1
        self.assertIsNone(driver.get_ob_callbacks_status()['registered'])
        self.assertEqual(len(driver._kernel32.calls), 3)


class ApiTests(unittest.TestCase):
    def client(self, driver, closing=lambda: False):
        from studio_api import install_ob_callbacks_status
        app = FastAPI()
        install_ob_callbacks_status(app, driver, closing)
        return ASGIClient(app)

    def test_global_get_requires_no_pid_and_preserves_registration_failure(self):
        driver = TransportTests().bridge(FakeKernel(state=3, registration_status=0xC0000022))
        with self.client(driver) as client:
            reply = client.get('/api/ob-callbacks/status')
        self.assertEqual(reply.status_code, 200)
        result = reply.json()
        self.assertTrue(result['success'])
        self.assertFalse(result['registered'])
        self.assertEqual(result['registration_status'], '0xC0000022')
        self.assertEqual(result['failure_stage'], 'register_callbacks')
        self.assertEqual(len(driver._kernel32.calls), 1)

    def test_closing_and_missing_query_do_not_touch_transport(self):
        driver = TransportTests().bridge()
        with self.client(driver, lambda: True) as client:
            result = client.get('/api/ob-callbacks/status').json()
        self.assertEqual(result['error_kind'], 'closing')
        self.assertEqual(driver._kernel32.calls, [])
        with self.client(object()) as client:
            result = client.get('/api/ob-callbacks/status').json()
        self.assertEqual(result['error_kind'], 'unsupported')
        self.assertIsNone(result['registered'])

    def test_only_explicit_post_controls_are_installed(self):
        driver = TransportTests().bridge()
        with self.client(driver) as client:
            self.assertEqual(client.post('/api/ob-callbacks/status', json={}).status_code, 405)
            self.assertEqual(client.get('/api/ob-callbacks/register').status_code, 405)
            self.assertEqual(client.get('/api/ob-callbacks/unregister').status_code, 405)
        self.assertEqual(driver._kernel32.calls, [])

    def test_api_unsupported_disconnected_and_failed_refresh_clear_prior_snapshot(self):
        driver = TransportTests().bridge()
        with self.client(driver) as client:
            self.assertTrue(client.get('/api/ob-callbacks/status').json()['registered'])
            driver._kernel32.ok, driver._kernel32.error = False, 1
            result = client.get('/api/ob-callbacks/status').json()
            self.assertTrue(result['unsupported'])
            self.assertEqual(result['error_kind'], 'unsupported')
            self.assertIsNone(result['registered'])
            self.assertIsNone(result['registration_status'])
            self.assertIsNone(result['registered_altitude'])
            driver.handle = None
            result = client.get('/api/ob-callbacks/status').json()
            self.assertEqual(result['error_kind'], 'disconnected')
            self.assertFalse(result['connected'])
            self.assertIsNone(result['minimum_altitude'])
            self.assertIsInstance(result['queried_at'], (int, float))
        self.assertEqual(len(driver._kernel32.calls), 2)

    def test_query_exception_returns_unknown_state_without_fallback(self):
        class Driver:
            def get_ob_callbacks_status(self):
                raise OSError('simulated read failure')
        with self.client(Driver()) as client:
            result = client.get('/api/ob-callbacks/status').json()
        self.assertFalse(result['success'])
        self.assertEqual(result['error_kind'], 'read_failed')
        self.assertIsNone(result['registered_altitude'])
        self.assertIsNone(result['dynamic_resolution'])

    def test_explicit_controls_are_global_and_register_defaults_fraction_then_get_polls(self):
        driver = TransportTests().bridge(FakeKernel(state=1, registration_status=0x103))
        with self.client(driver) as client:
            result = client.post('/api/ob-callbacks/register',
                                 json={'minimum_altitude':0, 'maximum_altitude':0xffffffff}).json()
            self.assertTrue(result['success'] and result['accepted'])
            self.assertFalse(result['completed'])
            self.assertEqual(len(driver._kernel32.calls), 1)
            snapshot = client.get('/api/ob-callbacks/status').json()
            self.assertTrue(snapshot['success'] and snapshot['worker_active'])
            self.assertFalse(snapshot['registered'])
            result = client.post('/api/ob-callbacks/unregister').json()
            self.assertTrue(result['success'] and result['completed'])
        self.assertEqual([entry[1] for entry in driver._kernel32.calls], [0x22E0A0, 0x22E09C, 0x22E0A4])

    def test_api_rejects_numeric_coercion_missing_reversed_range_and_pid_fields(self):
        driver = TransportTests().bridge()
        invalid = [{}, {'minimum_altitude':0}, {'minimum_altitude':True, 'maximum_altitude':1},
                   {'minimum_altitude':'0', 'maximum_altitude':1}, {'minimum_altitude':0.0, 'maximum_altitude':1},
                   {'minimum_altitude':0, 'maximum_altitude':0x100000000},
                   {'minimum_altitude':2, 'maximum_altitude':1},
                   {'minimum_altitude':0, 'maximum_altitude':1, 'maximum_fraction':1001},
                   {'minimum_altitude':0, 'maximum_altitude':1, 'maximum_fraction':False},
                   {'minimum_altitude':0, 'maximum_altitude':1, 'pid':42}]
        with self.client(driver) as client:
            for body in invalid:
                with self.subTest(body=body):
                    result = client.post('/api/ob-callbacks/register', json=body).json()
                    self.assertEqual(result['error_kind'], 'invalid_input')
                    self.assertFalse(result['success'] or result['accepted'])
        self.assertEqual(driver._kernel32.calls, [])

    def test_control_closing_unsupported_and_kernel_rejection_do_not_fallback(self):
        driver = TransportTests().bridge()
        with self.client(driver, lambda:True) as client:
            result = client.post('/api/ob-callbacks/register',
                                 json={'minimum_altitude':0, 'maximum_altitude':1}).json()
            self.assertEqual(result['error_kind'], 'closing')
            self.assertEqual(client.post('/api/ob-callbacks/unregister').json()['error_kind'], 'closing')
        self.assertEqual(driver._kernel32.calls, [])
        with self.client(object()) as client:
            result = client.post('/api/ob-callbacks/unregister').json()
            self.assertEqual(result['error_kind'], 'unsupported')
            self.assertFalse(result['success'] or result['completed'])
        driver = TransportTests().bridge(FakeKernel(control_status=0xC0000184))
        with self.client(driver) as client:
            result = client.post('/api/ob-callbacks/unregister').json()
            self.assertEqual(result['error_kind'], 'operation_failed')
            self.assertEqual(result['result_status'], '0xC0000184')
        self.assertEqual(len(driver._kernel32.calls), 1)


if __name__ == '__main__':
    unittest.main()
