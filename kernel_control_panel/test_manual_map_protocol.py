"""Pure packet and mocked transport tests; never instantiate/open a driver."""
import ctypes
import struct
import unittest

import manual_map_protocol as P
from driver_bridge import IOCTL_MANUAL_MAP, KernelDriverBridge


class ProtocolTests(unittest.TestCase):
    def test_packed_fixed_width_layout_matches_header(self):
        self.assertEqual(ctypes.sizeof(P.MANUAL_MAP_REQUEST), 2104)
        self.assertEqual({name: getattr(P.MANUAL_MAP_REQUEST, name).offset
                          for name, _ in P.MANUAL_MAP_REQUEST._fields_},
                         dict(Version=0, Reserved=4, ProcessId=8, ImagePath=16,
                              ResultStatus=1056, MappedBase=1060, EntryPoint=1068, failcode=1076, failmessage=1080))
        self.assertEqual(P.FUNCTION, 0x878)
        self.assertEqual(IOCTL_MANUAL_MAP, 0x22E1E0)

    def test_packet_is_zeroed_and_utf16_terminated_with_no_start_key(self):
        packet, normalized = P.request(0xffffffff, r'C:\테스트\😀.dll')
        raw = bytes(packet)
        self.assertEqual(struct.unpack_from('<IIQ', raw), (3, 0, 0xffffffff))
        encoded = normalized.encode('utf-16le') + b'\0\0'
        self.assertEqual(raw[16:16+len(encoded)], encoded)
        self.assertEqual(raw[16+len(encoded):1056], b'\0'*(1040-len(encoded)))
        self.assertEqual(struct.unpack_from('<iQQI', raw, 1056), (P.STATUS_UNSUCCESSFUL, 0, 0, 0))
        self.assertEqual(raw[1080:], b'\0'*1024)
        self.assertNotIn('ProcessStartKey', dict(P.MANUAL_MAP_REQUEST._fields_))

    def test_dos_unc_and_extended_paths_normalize(self):
        examples = [(r'C:/dir/../한국.dll', '\\??\\C:\\한국.dll'),
                    (r'\\server\share\dir\file.dll', '\\??\\UNC\\server\\share\\dir\\file.dll'),
                    (r'\\?\C:\file.dll', '\\??\\C:\\file.dll'),
                    (r'\??\C:\file.dll', '\\??\\C:\\file.dll'),
                    (r'\\?\UNC\server\share\file.dll', '\\??\\UNC\\server\\share\\file.dll'),
                    (r'\??\UNC\server\share\file.dll', '\\??\\UNC\\server\\share\\file.dll')]
        for path, expected in examples:
            with self.subTest(path=path):
                self.assertEqual(P.nt_dll_path(path)[0], expected)

    def test_path_limit_counts_normalized_nt_utf16_code_units(self):
        path = 'C:\\' + 'a'*508 + '.dll'  # NT prefix + drive + filename = 519 units.
        normalized, encoded = P.nt_dll_path(path)
        self.assertEqual(len(normalized.encode('utf-16le')) // 2, 519)
        self.assertEqual(len(encoded), 1040)
        P.request(123, path)
        with self.assertRaises(ValueError):
            P.nt_dll_path('C:\\' + 'a'*509 + '.dll')
        P.nt_dll_path('C:\\' + 'a'*506 + '😀.dll')
        with self.assertRaises(ValueError):
            P.nt_dll_path('C:\\' + 'a'*507 + '😀.dll')

    def test_rejects_relative_device_ads_reserved_and_malformed_paths(self):
        invalid = [None, '', 'file.dll', r'C:file.dll', r'\file.dll', r'C:\file.exe',
                   r'\\.\PhysicalDrive0.dll', r'\Device\HarddiskVolume1\file.dll',
                   r'C:\file.dll:payload', r'C:\NUL.dll', r'C:\COM1.dll',
                   r'C:\bad?.dll', r'\\server\file.dll', 'C:\\bad\0.dll',
                   'C:\\bad\n.dll', 'C:\\bad\ud800.dll', r' C:\file.dll']
        for path in invalid:
            with self.subTest(path=repr(path)), self.assertRaises(ValueError):
                P.request(123, path)

    def test_pid_must_be_nonzero_uint32_integer(self):
        for pid in (True, False, 0, -1, 0x100000000, '123', 123.0, None):
            with self.subTest(pid=pid), self.assertRaises(ValueError):
                P.request(pid, r'C:\file.dll')

    def test_message_contract_rejects_non_ascii_control_and_non_string_values(self):
        for value in (None, True, 7, b'API failed', 'a'*1024, '\0', '\x1b[31m', '실패', '\x7f'):
            with self.subTest(value=repr(value)):
                self.assertFalse(P.valid_failmessage(value))
        for value in ('', 'a'*1023, 'API failed\nstatus=0xC0000022\r\n\tparameter=0x20'):
            self.assertTrue(P.valid_failmessage(value))
        self.assertTrue(P.valid_result_diagnostic(0, 0, ''))
        self.assertTrue(P.valid_result_diagnostic(0xc0000022, 119, 'ZwProtectVirtualMemory: access denied'))
        self.assertFalse(P.valid_result_diagnostic(0, 0, 'failure'))
        self.assertFalse(P.valid_result_diagnostic(0xc0000022, 119, ''))


class TransportTests(unittest.TestCase):
    def setUp(self):
        # No __init__, WinDLL, CreateFile, DeviceIoControl or target process API.
        self.bridge = KernelDriverBridge.__new__(KernelDriverBridge)
        self.calls = []

    def reply(self, status=0, base=0x140000000, entry=0x140001000,
              ok=True, returned=P.REQUEST_BYTES, error=0, corrupt=None, failcode=None, message=None):
        def send(code, packet):
            self.calls.append((code, bytes(packet)))
            packet.ResultStatus = ctypes.c_int32(status).value
            packet.MappedBase = base
            packet.EntryPoint = entry
            packet.failcode = (0 if status == 0 else 28) if failcode is None else failcode
            packet.failmessage = ((b'' if status == 0 else b'PE DOS signature invalid: observed=0x0000; NTSTATUS=0xC000007B')
                                  if message is None else message)
            if corrupt:
                corrupt(packet)
            return ok, error, returned
        self.bridge.send_ioctl = send
        return self.bridge.manual_map_dll(123, r'C:\테스트.dll')

    def test_success_requires_exact_operation_success(self):
        result = self.reply()
        self.assertTrue(result['success'])
        self.assertTrue(result['packet_valid'])
        self.assertFalse(result['execution_unknown'])
        self.assertEqual(result['mapped_base'], '0x140000000')
        self.assertEqual(result['entry_point'], '0x140001000')
        self.assertEqual(result['result_status'], '0x00000000')
        self.assertEqual(result['failcode'], 0)
        self.assertEqual(result['failmessage'], '')
        code, raw = self.calls[0]
        self.assertEqual(code, 0x22E1E0)
        self.assertEqual(len(raw), 2104)
        self.assertEqual(struct.unpack_from('<IIQ', raw), (3, 0, 123))

    def test_non_entry_dll_can_succeed_with_zero_entry(self):
        self.assertTrue(self.reply(entry=0)['success'])

    def test_positive_wait_status_is_uncertain_even_without_base(self):
        for status in (0x102, 0x103):
            with self.subTest(status=status):
                result = self.reply(status=status, base=0, entry=0)
                self.assertFalse(result['success'])
                self.assertTrue(result['packet_valid'])
                self.assertTrue(result['execution_unknown'])

    def test_timeout_retains_addresses_without_retry(self):
        result = self.reply(status=0xc00000b5)
        self.assertFalse(result['success'])
        self.assertTrue(result['execution_unknown'])
        self.assertEqual(result['mapped_base'], '0x140000000')
        self.assertEqual(result['entry_point'], '0x140001000')
        self.assertEqual(len(self.calls), 1)

    def test_other_failure_with_retained_base_is_uncertain(self):
        result = self.reply(status=0xc0000001)
        self.assertFalse(result['success'])
        self.assertTrue(result['execution_unknown'])
        self.assertEqual(result['mapped_base'], '0x140000000')

    def test_confirmed_pre_execution_failure_has_zero_addresses(self):
        result = self.reply(status=0xc000007b, base=0, entry=0)
        self.assertFalse(result['success'])
        self.assertTrue(result['packet_valid'])
        self.assertFalse(result['execution_unknown'])
        self.assertEqual(result['result_status'], '0xC000007B')
        self.assertEqual(result['failcode'], 28)
        self.assertIn('PE DOS signature invalid', result['failmessage'])

    def test_failcode_preserves_full_ulong_and_failure_location(self):
        for code in (1, 21, 28, 130, 137, 0xffffffff):
            with self.subTest(failcode=code):
                result = self.reply(status=0xc0000001, base=0, entry=0, failcode=code)
                self.assertTrue(result['packet_valid'])
                self.assertEqual(result['failcode'], code)
                self.assertFalse(result['success'])

    def test_full_message_and_boundary_are_preserved_without_codepage_guess(self):
        message = (b'ZwProtectVirtualMemory(proc_h=0x44, base=0x140001000, size=0x2000, protect=0x20)'
                   b'\nsection[0]=.text; NTSTATUS=STATUS_ACCESS_DENIED(0xC0000022)')
        result = self.reply(status=0xc0000022, base=0, entry=0, failcode=119, message=message)
        self.assertTrue(result['packet_valid'])
        self.assertEqual(result['failmessage'], message.decode('ascii'))
        result = self.reply(status=0xc0000001, base=0, entry=0, message=b'a'*1023)
        self.assertTrue(result['packet_valid'])
        self.assertEqual(result['failmessage'], 'a'*1023)

    def test_malformed_or_contradictory_message_is_never_exposed(self):
        def raw_message(value):
            def corrupt(packet):
                ctypes.memmove(ctypes.addressof(packet) + P.MANUAL_MAP_REQUEST.failmessage.offset, value, len(value))
            return corrupt
        invalid = [b'a'*1024, b'API failed\0hidden', b'bad\xff\0', b'bad\x01\0', b'bad\x7f\0']
        for value in invalid:
            with self.subTest(raw=value[:30]):
                result = self.reply(status=0xc0000022, base=0, entry=0, corrupt=raw_message(value))
                self.assertFalse(result['packet_valid'])
                self.assertTrue(result['execution_unknown'])
                self.assertIsNone(result['failcode'])
                self.assertIsNone(result['failmessage'])
        for status, message in ((0, b'API failed'), (0xc0000022, b'')):
            with self.subTest(status=status, message=message):
                result = self.reply(status=status, message=message)
                self.assertFalse(result['packet_valid'])
                self.assertIsNone(result['failmessage'])

    def test_contradictory_status_and_failcode_is_untrusted(self):
        for status, code in ((0, 1), (0xc000007b, 0)):
            with self.subTest(status=status, failcode=code):
                result = self.reply(status=status, failcode=code)
                self.assertFalse(result['packet_valid'])
                self.assertFalse(result['success'])
                self.assertTrue(result['execution_unknown'])
                self.assertIsNone(result['failcode'])
                self.assertIsNone(result['failmessage'])

    def test_short_oversized_or_failed_transport_are_indeterminate(self):
        for kwargs in ({'returned':2103}, {'returned':2105}, {'returned':1080}, {'ok':False, 'error':5}):
            with self.subTest(kwargs=kwargs):
                result = self.reply(**kwargs)
                self.assertFalse(result['success'])
                self.assertFalse(result['packet_valid'])
                self.assertTrue(result['execution_unknown'])
                self.assertEqual(result['mapped_base'], '0x0')
                self.assertEqual(result['entry_point'], '0x0')
                self.assertIsNone(result['failcode'])
                self.assertIsNone(result['failmessage'])
        self.assertEqual(len(self.calls), 4)

    def test_echo_mismatch_is_indeterminate(self):
        corruptions = [lambda p:setattr(p, 'Version', 1), lambda p:setattr(p, 'Reserved', 1),
                       lambda p:setattr(p, 'ProcessId', 124), lambda p:p.ImagePath.__setitem__(0, ord('Z'))]
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt):
                result = self.reply(corrupt=corrupt)
                self.assertFalse(result['packet_valid'])
                self.assertTrue(result['execution_unknown'])

    def test_success_without_base_or_invalid_user_address_is_indeterminate(self):
        for base, entry in ((0,0), (1,0), (0x1000,0), (0x10001,0), (0,0x1000),
                            (0xffff800000000000,0), (0x140000000,0x1000),
                            (0x140000000,0x140000000+(64 << 20)),
                            (0x140000000,0xffff800000000000)):
            with self.subTest(base=base, entry=entry):
                result = self.reply(base=base, entry=entry)
                self.assertFalse(result['success'])
                self.assertFalse(result['packet_valid'])
                self.assertTrue(result['execution_unknown'])

    def test_invalid_input_does_not_reach_transport(self):
        self.bridge.send_ioctl = lambda *_: self.fail('invalid input reached transport')
        for pid, path in ((0,r'C:\file.dll'), (123,'file.dll'), (123,r'C:\file.dll:data')):
            with self.subTest(pid=pid, path=path), self.assertRaises(ValueError):
                self.bridge.manual_map_dll(pid, path)


if __name__ == '__main__':
    unittest.main()
