"""EPROCESS ABI/HTTP/browser regressions with fake transport only."""
import ctypes as C
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

import driver_bridge as D
from studio_api import Studio, OP_GROUPS, IOCTL_UI


ADDRESS = 0xFFFFA123456789AB
START_KEY = 18446744073709551614


class ProcessObjectTests(unittest.TestCase):
    def bridge(self, *, ok=True, error=0, returned=24, status=0, address=ADDRESS, key=START_KEY, echo=None):
        bridge = D.KernelDriverBridge.__new__(D.KernelDriverBridge)
        bridge.calls = []
        def send(code, request):
            bridge.calls.append((code, request.ProcessId))
            request.ResultStatus = status
            request.EprocessAddress = address
            request.ProcessStartKey = key
            if echo is not None:
                request.ProcessId = echo
            return ok, error, returned
        bridge.send_ioctl = send
        return bridge

    def test_abi_code_size_and_all_offsets(self):
        self.assertEqual(D.IOCTL_HELPER_QUERY_PROCESS_OBJECT, 0x0022E094)
        self.assertEqual(C.sizeof(D.QUERY_PROCESS_OBJECT_REQUEST), 24)
        for name, offset in [('ProcessId', 0), ('ResultStatus', 4), ('EprocessAddress', 8), ('ProcessStartKey', 16)]:
            self.assertEqual(getattr(D.QUERY_PROCESS_OBJECT_REQUEST, name).offset, offset)

    def test_kernel_address_and_start_key_preserve_every_bit_in_json(self):
        bridge = self.bridge()
        result = json.loads(json.dumps(bridge.query_process_object(42)))
        self.assertTrue(result['success'] and result['transport_ok'] and result['packet_valid'])
        self.assertEqual(result['eprocess_address'], '0xFFFFA123456789AB')
        self.assertEqual(result['process_start_key'], str(START_KEY))
        self.assertEqual(bridge.calls, [(0x0022E094, 42)])
        self.assertTrue(result['readonly'])

    def test_invalid_pid_never_reaches_transport(self):
        bridge = self.bridge()
        for pid in (0, -1, 2**32, True, 1.0, '42', None):
            with self.assertRaises(ValueError):
                bridge.query_process_object(pid)
        self.assertEqual(bridge.calls, [])

    def test_short_failed_or_wrong_owner_reply_never_exposes_an_address(self):
        for args in ({'returned': 0}, {'returned': 23}, {'returned': 25}, {'ok': False, 'error': 6},
                     {'status': -1073741813}, {'echo': 84}, {'address': 0}):
            with self.subTest(args=args):
                result = self.bridge(**args).query_process_object(42)
                self.assertFalse(result['success'])
                self.assertIsNone(result['eprocess_address'])
                self.assertIsNone(result['process_start_key'])

    def test_zero_start_key_remains_a_valid_unique_identifier_value(self):
        result = self.bridge(key=0).query_process_object(42)
        self.assertTrue(result['success'])
        self.assertEqual(result['process_start_key'], '0')

    def test_old_driver_explicitly_reports_unsupported_without_a_fake_address(self):
        for args in ({'ok': False, 'error': 1, 'returned': 0},
                     {'ok': False, 'error': 50, 'returned': 0}, {'status': -1073741637}):
            result = self.bridge(**args).query_process_object(42)
            self.assertTrue(result['unsupported'])
            self.assertIn('20261010', result['error'])
            self.assertFalse(result['success'])
            self.assertIsNone(result['eprocess_address'])

    def test_studio_uses_selected_pid_and_exposes_readonly_capability(self):
        studio = Studio.__new__(Studio)
        studio.driver = self.bridge()
        studio.closing = False
        result = studio.run('process_object', {'pid': 84})
        self.assertTrue(result['success'])
        self.assertEqual(result['results'][0]['process_id'], 84)
        self.assertEqual(result['results'][0]['eprocess_address'], '0xFFFFA123456789AB')
        self.assertEqual(studio.driver.calls, [(D.IOCTL_HELPER_QUERY_PROCESS_OBJECT, 84)])
        self.assertIn('process_object', OP_GROUPS['프로세스'])
        self.assertEqual(IOCTL_UI[0x825], 'process_object')

    def test_studio_invalid_pid_is_rejected_before_transport(self):
        studio = Studio.__new__(Studio)
        studio.driver = self.bridge()
        studio.closing = False
        for pid in (0, -1, 2**32, True, 'bad'):
            self.assertFalse(studio.run('process_object', {'pid': pid})['success'])
        self.assertEqual(studio.driver.calls, [])

    def test_http_success_error_and_capabilities_use_mock_only(self):
        import server
        from test_asgi_client import ASGIClient
        client = ASGIClient(server.app)
        result = self.bridge().query_process_object(42)
        with patch.object(server.driver, 'query_process_object', return_value=result) as query:
            response = client.post('/api/studio/execute', json={'operation': 'process_object', 'args': {'pid': 42}})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['eprocess_address'], '0xFFFFA123456789AB')
            query.assert_called_once_with(42)
        unsupported = self.bridge(ok=False, error=1, returned=0).query_process_object(42)
        with patch.object(server.driver, 'query_process_object', return_value=unsupported):
            response = client.post('/api/studio/execute', json={'operation': 'process_object', 'args': {'pid': 42}})
            self.assertFalse(response.json()['success'])
            self.assertIsNone(response.json()['eprocess_address'])
            self.assertIn('20261010', response.json()['error'])
        caps = client.get('/api/studio/capabilities').json()
        self.assertIn({'ioctl': '0x825', 'tool': 'process_object'}, caps['ioctls'])
        self.assertEqual(caps['manual_map']['version'], 3)
        self.assertEqual(caps['manual_map']['request_bytes'], 2104)
        self.assertEqual(caps['manual_map']['failcode'], {'success':0, 'field':'failcode', 'unknown':None})
        self.assertEqual(caps['manual_map']['failmessage'], {'field':'failmessage', 'bytes':1024,
                         'encoding':'ascii', 'success':'', 'unknown':None})
        self.assertEqual(client.get('/api/build').json()['expected_driver_build'], 20261012)
        with patch.object(server.driver, 'query_process_info', return_value={'success': True, 'exit_status': 259,
                          'process_id': 42, 'process_start_key': START_KEY}), \
                patch.object(server.driver, 'query_process_extended', return_value={'success': True, 'create_time': START_KEY}), \
                patch.object(server.driver, 'query_process_token', return_value={'success': True}):
            info = client.get('/api/process/42').json()
            self.assertEqual(info['identity']['process_start_key'], str(START_KEY))

    def test_browser_automatic_lookup_target_races_detach_and_precision(self):
        node = shutil.which('node')
        if node is None:
            self.skipTest('Node.js is required for the browser state regression')
        root = Path(__file__).resolve().parent
        result = subprocess.run([node, str(root / 'test_process_object_ui.js'), str(root / 'static' / 'studio.js')],
                                capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('EPROCESS browser checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
