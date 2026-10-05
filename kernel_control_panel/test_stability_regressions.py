"""Offline regression tests. No driver load or target-process changes."""
import asyncio
import ctypes
import importlib.util
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import driver_bridge as bridge
import memory_scanner as scanner


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


class FakeKernel:
    def __init__(self):
        self.handle = 0x1234567887654321
        self.opens = 0
        self.closed = []
        self.buffers = {}
        self.io_hook = None
        self.CreateFileW = Function(self.open)
        self.CloseHandle = Function(lambda h: self.closed.append(h) or 1)
        self.DeviceIoControl = Function(self.io)
        self.VirtualFree = Function(self.free)

    def open(self, *args):
        self.opens += 1
        time.sleep(0.005)
        return self.handle

    def io(self, h, code, data, size, output, output_size, returned, overlap):
        if self.io_hook:
            return self.io_hook(h, code, data, returned)
        if code == bridge.IOCTL_HELPER_READ_PROCESS:
            req = ctypes.cast(data, ctypes.POINTER(bridge.READ_PROCESS_REQUEST)).contents
            buf = ctypes.create_string_buffer(b'abcd')
            ptr = ctypes.addressof(buf)
            self.buffers[ptr] = buf
            req.DumpedAddress = ptr
            req.ResultStatus = 0
        ctypes.cast(returned, ctypes.POINTER(ctypes.c_ulong)).contents.value = size
        return 1

    def free(self, address, size, flags):
        assert size == 0 and flags == bridge.MEM_RELEASE
        del self.buffers[address]
        return 1


class StabilityTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeKernel()
        self.factory = patch.object(ctypes, 'WinDLL', return_value=self.api)
        self.factory.start()
        self.addCleanup(self.factory.stop)
        self.driver = bridge.KernelDriverBridge()

    def test_pointer_width_and_single_open_under_contention(self):
        threads = [threading.Thread(target=self.driver.open) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(2)
            self.assertFalse(t.is_alive())
        self.assertEqual(self.api.opens, 1)
        self.assertEqual(self.driver.handle, self.api.handle)
        self.assertIs(self.api.CreateFileW.restype, ctypes.wintypes.HANDLE)
        self.assertIs(self.api.DeviceIoControl.argtypes[0], ctypes.wintypes.HANDLE)

    def test_invalid_handle_and_null_do_not_count_as_connected(self):
        for value in (None, 0, ctypes.c_void_p(-1).value):
            self.api.handle = value
            self.assertFalse(self.driver.open())
            self.assertFalse(self.driver.is_connected())

    def test_removed_notifications_never_send_enable_to_old_driver(self):
        calls = []
        self.api.io_hook = lambda *args: calls.append(args[1]) or 1
        for process, image in ((True, False), (False, True), (True, True)):
            result = self.driver.event_monitor_control(process, image)
            self.assertFalse(result['success'])
            self.assertEqual(result['result_status'], '0xC00000BB')
        self.assertEqual(calls, [])

    def test_notification_disable_is_available_for_existing_driver(self):
        calls = []
        def capture(handle, code, data, returned):
            self.assertEqual(code, bridge.IOCTL_HELPER_EVENT_MONITOR_CONTROL)
            req = ctypes.cast(data, ctypes.POINTER(bridge.EVENT_MONITOR_CONTROL_REQUEST)).contents
            self.assertFalse(req.EnableProcessMonitor)
            self.assertFalse(req.EnableImageLoadMonitor)
            calls.append(code)
            return 1
        self.api.io_hook = capture
        self.assertTrue(self.driver.event_monitor_control(False, False)['success'])
        self.assertEqual(len(calls), 1)

    def test_panel_startup_does_not_register_or_poll_notifications(self):
        import server
        calls = []
        self.api.io_hook = lambda *args: calls.append(args[1]) or 1
        async def run():
            with patch.object(server, 'driver', self.driver), patch.object(server.studio, 'driver', self.driver):
                await server.startup_event()
                await asyncio.sleep(0.15)
                await server.shutdown_event()
        asyncio.run(run())
        self.assertEqual(calls, [])

    def test_close_waits_for_inflight_ioctl(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        def io(*args):
            entered.set()
            self.assertTrue(release.wait(2))
            return 1
        self.api.io_hook = io
        request = bridge.DRIVER_STATUS_REQUEST()
        io_thread = threading.Thread(target=self.driver.send_ioctl, args=(bridge.IOCTL_HELPER_GET_DRIVER_STATUS, request))
        io_thread.start()
        self.assertTrue(entered.wait(2))
        close_thread = threading.Thread(target=lambda: (self.driver.close(), closed.set()))
        close_thread.start()
        self.assertFalse(closed.wait(0.05))
        self.assertEqual(self.api.closed, [])
        release.set()
        io_thread.join(2)
        close_thread.join(2)
        self.assertTrue(closed.is_set())
        self.assertEqual(self.api.closed, [self.api.handle])

    def test_raw_read_retains_pointer_and_snapshot_releases_it(self):
        raw = self.driver.read_process_memory(1, 0x10000, 4)
        address = int(raw['dumped_address'], 16)
        self.assertEqual(ctypes.string_at(address, 4), b'abcd')
        self.assertIn(address, self.api.buffers)
        self.api.free(address, 0, bridge.MEM_RELEASE)
        for _ in range(500):
            result = self.driver.read_process_memory_snapshot(1, 0x10000, 4)
            self.assertEqual(result['data_hex'], '61626364')
            self.assertEqual(result.keys(), raw.keys())
            self.assertFalse(self.api.buffers)

    def test_snapshot_releases_buffer_on_preview_error(self):
        with patch.object(ctypes, 'string_at', side_effect=OSError('copy failed')):
            result = self.driver.read_process_memory_snapshot(1, 0x10000, 4)
        self.assertTrue(result['data_hex'].startswith('read_error:'))
        self.assertFalse(self.api.buffers)

    def test_ioctl_failure_reads_captured_last_error(self):
        def failure(*args):
            ctypes.set_last_error(123)
            return 0
        self.api.io_hook = failure
        ok, error, returned = self.driver.send_ioctl(bridge.IOCTL_HELPER_GET_DRIVER_STATUS, bridge.DRIVER_STATUS_REQUEST())
        self.assertFalse(ok)
        self.assertEqual(error, 123)
        self.assertEqual(returned, 0)

    def test_full_length_pattern_keeps_last_wildcard(self):
        seen = []
        def capture(h, code, data, returned):
            req = ctypes.cast(data, ctypes.POINTER(bridge.PATTERN_SCAN_REQUEST)).contents
            seen.append((req.PatternLength, bytes(req.Mask)))
            return 1
        self.api.io_hook = capture
        self.driver.pattern_scan(1, 0x10000, 4096, b'x' * 256, 'x' * 255 + '?')
        self.assertEqual(seen, [(256, b'x' * 255 + b'?')])

    def test_context_getter_keys_preserve_all_registers_in_setter(self):
        registers = {name.lower(): i + 1 for i, (name, _) in
                     enumerate(bridge.THREAD_REGISTERS_REQUEST._fields_)
                     if name not in ('ThreadId', 'ResultStatus')}
        def capture(h, code, data, returned):
            req = ctypes.cast(data, ctypes.POINTER(bridge.THREAD_REGISTERS_REQUEST)).contents
            self.assertEqual(req.ThreadId, 123)
            for name, _ in bridge.THREAD_REGISTERS_REQUEST._fields_:
                if name.lower() in registers:
                    self.assertEqual(getattr(req, name), registers[name.lower()])
            return 1
        self.api.io_hook = capture
        self.driver.set_thread_context(123, registers)

    def test_panel_breakpoint_lengths_translate_to_kernel_byte_lengths(self):
        lengths = []
        def capture(h, code, data, returned):
            req = ctypes.cast(data, ctypes.POINTER(bridge.IOCTL_HWBP_SET_REQUEST)).contents
            lengths.append(req.Length)
            return 1
        self.api.io_hook = capture
        for length in (0, 1, 3, 2, 99):
            self.driver.set_hardware_breakpoint(1, 0x10000, 1, length)
        self.assertEqual(lengths, [1, 2, 4, 8, 0])

    def test_scanner_closes_process_handle_after_read_exception(self):
        api = type('MemoryApi', (), {})()
        closed = []
        api.OpenProcess = lambda *args: 0x1234567887654321
        api.CloseHandle = lambda h: closed.append(h)
        def failing_read(*args):
            raise OSError('process ended')
        api.ReadProcessMemory = failing_read
        regions = [{'keep_for_scan': True, 'base_address_int': 0x10000, 'region_size': 4}]
        session = scanner.MemoryScannerSession(self.driver)
        with patch.object(scanner, '_memory_api', return_value=api), patch.object(scanner, 'get_memory_regions', return_value=regions):
            with self.assertRaises(OSError):
                session.first_scan(1, 'int32', 'exact', '1')
        self.assertEqual(closed, [0x1234567887654321])
        self.assertFalse(session.is_scanning)

    def test_scanner_failed_open_resets_busy_flag(self):
        api = type('MemoryApi', (), {'OpenProcess': lambda *args: None})()
        session = scanner.MemoryScannerSession(self.driver)
        with patch.object(scanner, '_memory_api', return_value=api), patch.object(scanner, 'get_memory_regions', return_value=[]):
            result = session.first_scan(1, 'int32', 'unknown', '')
        self.assertFalse(result['success'])
        self.assertFalse(session.is_scanning)

    def test_scan_reset_waits_for_active_scan(self):
        session = scanner.MemoryScannerSession(self.driver)
        entered, release, reset = threading.Event(), threading.Event(), threading.Event()
        def regions(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(2))
            return []
        api = type('MemoryApi', (), {'OpenProcess': lambda *args: None})()
        with patch.object(scanner, '_memory_api', return_value=api), patch.object(scanner, 'get_memory_regions', side_effect=regions):
            active = threading.Thread(target=session.first_scan, args=(1, 'int32', 'unknown', ''))
            active.start()
            self.assertTrue(entered.wait(2))
            other = threading.Thread(target=lambda: (session.reset(), reset.set()))
            other.start()
            self.assertFalse(reset.wait(0.05))
            release.set()
            active.join(2)
            other.join(2)
        self.assertTrue(reset.is_set())
        self.assertEqual(session.scan_count, 0)

    def test_failed_hwbp_removal_keeps_recovery_list(self):
        import server
        server.driver = self.driver
        with patch.object(self.driver, 'remove_hardware_breakpoint', return_value={'success': False}), patch.object(self.driver, 'free_hardware_breakpoint_result') as free:
            server.remove_hwbp(server.HwbpRemoveRequest(pid=1, first_node='0x10000'))
            free.assert_not_called()
        with patch.object(self.driver, 'remove_hardware_breakpoint', return_value={'success': True}), patch.object(self.driver, 'free_hardware_breakpoint_result') as free:
            server.remove_hwbp(server.HwbpRemoveRequest(pid=1, first_node='0x10000'))
            free.assert_called_once_with(0x10000)

    def test_watch_remove_waits_for_started_freeze_write(self):
        import server
        server.driver = self.driver
        server.watch_table = [server.WatchEntry('x', 1, '0x10000', 0x10000, 'int32', frozen=True, frozen_val=5)]
        entered, release, removed = threading.Event(), threading.Event(), threading.Event()
        def write(*args):
            entered.set()
            self.assertTrue(release.wait(2))
        with patch.object(self.driver, 'write_process_memory', side_effect=write) as writer:
            active = threading.Thread(target=server.maintain_frozen_values)
            active.start()
            self.assertTrue(entered.wait(2))
            remover = threading.Thread(target=lambda: (server.remove_watch_item({'id': 'x'}), removed.set()))
            remover.start()
            self.assertFalse(removed.wait(0.05))
            release.set()
            active.join(2)
            remover.join(2)
            server.maintain_frozen_values()
            self.assertEqual(writer.call_count, 1)
        self.assertTrue(removed.is_set())

    def test_background_worker_is_cancelled_before_close(self):
        import server
        server.driver = self.driver
        async def exercise():
            self.driver.open()
            server.app.state.background_task = asyncio.create_task(asyncio.sleep(60))
            await server.shutdown_event()
            self.assertTrue(server.app.state.background_task.cancelled())
            self.assertFalse(self.driver.is_connected())
        asyncio.run(exercise())


class NativeMemoryTests(unittest.TestCase):
    def test_scanner_reads_local_memory_without_pointer_truncation(self):
        values = (ctypes.c_int32 * 4)(7, 8, 7, 9)
        regions = [{'keep_for_scan': True, 'base_address_int': ctypes.addressof(values), 'region_size': ctypes.sizeof(values)}]
        session = scanner.MemoryScannerSession(None)
        with patch.object(scanner, 'get_memory_regions', return_value=regions):
            result = session.first_scan(os.getpid(), 'int32', 'exact', '7')
        self.assertEqual(result['count'], 2)
        values[0] = 10
        result = session.next_scan('increased')
        self.assertEqual(result['count'], 1)
        self.assertEqual(session.get_results()['results'][0]['address_int'], ctypes.addressof(values))


if __name__ == '__main__':
    unittest.main(verbosity=2)
