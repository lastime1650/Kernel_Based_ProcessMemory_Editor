"""Bounded 0x826 snapshots with mocked DeviceIoControl, never a live driver."""
import ctypes as C
from pathlib import Path
import shutil
import subprocess
import unittest
import driver_bridge as D


ADDRESS = 0xFFFFA123456789AB
KEY = 18446744073709551614


class ProcessObjectReadTests(unittest.TestCase):
    def bridge(self, **changes):
        bridge = D.KernelDriverBridge.__new__(D.KernelDriverBridge)
        bridge.calls = []
        def send(code, packet):
            bridge.calls.append((code, packet.StructSize, packet.Version, packet.ProcessId, packet.Size,
                                 packet.ExpectedEprocessAddress, packet.ExpectedProcessStartKey))
            packet.ResultStatus = 0
            packet.BytesRead = packet.Size
            packet.EprocessAddress = packet.ExpectedEprocessAddress
            packet.ProcessStartKey = packet.ExpectedProcessStartKey
            for index in range(packet.Size):
                packet.Data[index] = index % 256
            for field, value in changes.items():
                if field not in ('ok', 'error', 'returned'):
                    setattr(packet, field, value)
            return changes.get('ok', True), changes.get('error', 0), changes.get('returned', 4152)
        bridge.send_ioctl = send
        return bridge

    def test_abi_code_size_and_every_offset(self):
        self.assertEqual(D.IOCTL_HELPER_READ_PROCESS_OBJECT, 0x0022E098)
        self.assertEqual(C.sizeof(D.READ_PROCESS_OBJECT_REQUEST), 4152)
        for field, offset in [('StructSize', 0), ('Version', 4), ('ProcessId', 8), ('Size', 12),
                              ('ExpectedEprocessAddress', 16), ('ExpectedProcessStartKey', 24),
                              ('ResultStatus', 32), ('BytesRead', 36), ('EprocessAddress', 40),
                              ('ProcessStartKey', 48), ('Data', 56)]:
            self.assertEqual(getattr(D.READ_PROCESS_OBJECT_REQUEST, field).offset, offset)

    def test_success_preserves_kernel_pointer_start_key_and_exact_bytes(self):
        bridge = self.bridge()
        result = bridge.read_process_object(42, ADDRESS, KEY, 64)
        self.assertTrue(result['success'] and result['readonly'])
        self.assertEqual(result['eprocess_address'], '0xFFFFA123456789AB')
        self.assertEqual(result['process_start_key'], str(KEY))
        self.assertEqual(result['data_hex'], bytes(range(64)).hex())
        self.assertEqual(bridge.calls, [(0x0022E098, 4152, 1, 42, 64, ADDRESS, KEY)])

    def test_maximum_snapshot_and_zero_start_key_are_valid(self):
        result = self.bridge().read_process_object(42, ADDRESS, 0, 4096)
        self.assertTrue(result['success'])
        self.assertEqual(result['bytes_read'], 4096)
        self.assertEqual(result['process_start_key'], '0')
        self.assertEqual(len(result['data_hex']), 8192)

    def test_invalid_arguments_never_submit_an_ioctl(self):
        bridge = self.bridge()
        for args in [(0, ADDRESS, KEY, 64), (2**32, ADDRESS, KEY, 64), (42, 0, KEY, 64),
                     (42, 2**64, KEY, 64), (42, ADDRESS, -1, 64), (42, ADDRESS, 2**64, 64),
                     (42, ADDRESS, KEY, 0), (42, ADDRESS, KEY, 4097), (True, ADDRESS, KEY, 64),
                     (42, ADDRESS, True, 64), (42, ADDRESS, KEY, '64'), (42, ADDRESS, KEY, 1.5)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                bridge.read_process_object(*args)
        self.assertEqual(bridge.calls, [])

    def test_incomplete_failed_wrong_schema_and_reused_owner_never_expose_bytes(self):
        cases = [{'ok': False, 'error': 6}, {'returned': 4151}, {'returned': 4153},
                 {'ResultStatus': -1073741813}, {'StructSize': 24}, {'Version': 2},
                 {'ProcessId': 84}, {'Size': 63}, {'BytesRead': 63},
                 {'EprocessAddress': ADDRESS + 16}, {'ProcessStartKey': KEY - 1}]
        for changes in cases:
            with self.subTest(changes=changes):
                result = self.bridge(**changes).read_process_object(42, ADDRESS, KEY, 64)
                self.assertFalse(result['success'])
                self.assertEqual(result['data_hex'], '')
                self.assertIsNone(result['eprocess_address'])
                self.assertIsNone(result['process_start_key'])

    def test_unsupported_old_driver_reports_required_build(self):
        result = self.bridge(ok=False, error=1, returned=0).read_process_object(42, ADDRESS, KEY, 64)
        self.assertTrue(result['unsupported'])
        self.assertIn('20261010', result['error'])
        self.assertEqual(result['data_hex'], '')

    def test_active_page_monitoring_races_precision_and_nonoverlap(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node.js is required for the EPROCESS browser test')
        root = Path(__file__).resolve().parent
        result = subprocess.run([node, str(root / 'test_eprocess_workspace_ui.js'), str(root / 'static/eprocess_workspace.js')],
                                capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('EPROCESS monitor checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
