"""APC_NORMALIZE IOCTL, ABI, and HTTP regressions using fake transport only."""
import ctypes as C
from pathlib import Path
import unittest
from unittest.mock import patch

import driver_bridge as D
from test_asgi_client import ASGIClient


ROOT = Path(__file__).resolve().parent.parent


class ApcNormalizeTests(unittest.TestCase):
    def test_kernel_contract_and_request_layout_match_the_bridge(self):
        kernel = (ROOT / 'ioctl_helper.hpp').read_text(encoding='utf-8')
        apc = (ROOT / 'APC.hpp').read_text(encoding='utf-8')
        self.assertIn('CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)', kernel)
        self.assertIn('GetPacket<REGISTER_USER_APC_REQUEST>(irp, stack)', kernel)
        self.assertIn('request->ResultStatus = RegisterUserApc(', kernel)
        for field in ('ProcessId', 'ThreadId', 'UserApcFunction', 'NormalContext',
                      'NormalSystemParameter1', 'NormalSystemParameter2'):
            self.assertIn(f'request->{field}', kernel)
        self.assertIn('NTSTATUS RegisterUserApc(', apc)
        self.assertEqual(D.IOCTL_HELPER_REGISTER_USER_APC, 0x0022E400)
        self.assertEqual(C.sizeof(D.REGISTER_USER_APC_REQUEST), 48)
        expected = {'ProcessId': 0, 'ThreadId': 4, 'UserApcFunction': 8,
                    'NormalContext': 16, 'NormalSystemParameter1': 24,
                    'NormalSystemParameter2': 32, 'ResultStatus': 40}
        self.assertEqual({name: getattr(D.REGISTER_USER_APC_REQUEST, name).offset
                          for name in expected}, expected)

    def bridge(self, *, ok=True, error=0, returned=48, status=0):
        bridge = D.KernelDriverBridge.__new__(D.KernelDriverBridge)
        bridge.calls = []

        def send(code, request):
            bridge.calls.append((code, request))
            if ok and returned == C.sizeof(request):
                request.ResultStatus = status
            return ok, error, returned

        bridge.send_ioctl = send
        return bridge

    def test_bridge_serializes_all_six_inputs_and_returns_operation_status(self):
        bridge = self.bridge()
        result = bridge.register_user_apc(
            4321, 7654, '0x7FF612341000', '0xFFFFFFFFFFFFFFFF',
            '0x123456789ABCDEF0', '42')
        self.assertTrue(result['success'] and result['transport_ok'] and result['packet_valid'])
        self.assertEqual(result['bytes_returned'], 48)
        self.assertEqual(result['result_status'], '0x00000000')
        self.assertEqual(result['process_id'], 4321)
        self.assertEqual(result['thread_id'], 7654)
        code, packet = bridge.calls[0]
        self.assertEqual(code, 0x0022E400)
        self.assertEqual((packet.ProcessId, packet.ThreadId), (4321, 7654))
        self.assertEqual((packet.UserApcFunction, packet.NormalContext,
                          packet.NormalSystemParameter1, packet.NormalSystemParameter2),
                         (0x7FF612341000, 0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0, 42))

    def test_failed_transport_and_invalid_values_do_not_report_success(self):
        bridge = self.bridge(ok=False, error=5, returned=0)
        result = bridge.register_user_apc(1, 2, '0x10000')
        self.assertFalse(result['success'] or result['packet_valid'])
        self.assertEqual(result['result_status'], '0xC0000001')
        self.assertEqual(result['error_code'], 5)
        rejected = self.bridge(status=-1073741811).register_user_apc(1, 2, '0x10000')
        self.assertFalse(rejected['success'])
        self.assertTrue(rejected['packet_valid'])
        self.assertEqual(rejected['result_status'], '0xC000000D')
        for values in ((0, 2, 0x10000), (1, 0, 0x10000), (1, 2, 0),
                       (1, 2, 1 << 64), (True, 2, 0x10000)):
            with self.assertRaises(ValueError):
                bridge.register_user_apc(*values)

    def test_http_route_forwards_selected_pid_tid_and_rejects_bad_addresses(self):
        import server
        client = ASGIClient(server.app)
        payload = {'attached_process_id': 4321, 'selected_thread_id': 7654,
                   'normalize_address': '0x7FF612341000', 'normalize_context': '0x20',
                   'system_buffer1': '0x30', 'system_buffer2': '0'}
        response = {'success': True, 'result_status': '0x00000000',
                    'process_id': 4321, 'thread_id': 7654}
        with patch.object(server.driver, 'register_user_apc', return_value=response) as send:
            reply = client.post('/api/apc/normalize', json=payload)
        self.assertEqual(reply.status_code, 200)
        self.assertTrue(reply.json()['success'])
        send.assert_called_once_with(4321, 7654, 0x7FF612341000, 0x20, 0x30, 0)

        with patch.object(server.driver, 'register_user_apc') as send:
            for bad in ('-1', '0x10000000000000000', 'invalid'):
                invalid = dict(payload, normalize_address=bad)
                reply = client.post('/api/apc/normalize', json=invalid)
                self.assertEqual(reply.status_code, 400)
            send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
