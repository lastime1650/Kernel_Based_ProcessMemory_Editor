"""First-use process discovery, refresh races, and driver-only error handling."""
import concurrent.futures
import threading
import time
import unittest
from unittest.mock import patch

from process_catalog import KernelProcessCatalog, DiscoveryError
from test_asgi_client import ASGIClient


class Driver:
    def __init__(self):
        self.connected = True
        self.calls = []
        self.rows = {
            4: self.row(4, '', 1),
            8: self.row(8, 'exited.exe', 2, exit_status=0),
            12: self.row(12, r'\Device\Volume\worker.exe', 134355379964474375),
        }

    @staticmethod
    def row(pid, name, created, exit_status=259):
        return {'success': True, 'process_id': pid, 'image_file_name': name,
                'exit_status': exit_status, 'working_set_kb': 2048,
                'create_time': created, 'thread_count': 3}

    def is_connected(self):
        return self.connected

    def open(self):
        return self.connected

    def query_process_extended(self, pid):
        self.calls.append(pid)
        return self.rows.get(pid, {'success': False, 'error_code': 0,
                                   'result_status': '0xC000000B'})


class ProcessCatalogTests(unittest.TestCase):
    def setUp(self):
        self.driver = Driver()
        self.catalog = KernelProcessCatalog(self.driver)

    def test_first_visit_discovers_unregistered_running_processes(self):
        result = self.catalog.list(16)
        self.assertEqual([p['pid'] for p in result['processes']], [4, 12])
        self.assertEqual([p['name'] for p in result['processes']], ['System', 'worker.exe'])
        self.assertEqual(result['processes'][1]['memory_mb'], 2)
        self.assertEqual(result['processes'][1]['create_time'], '134355379964474375')
        self.assertEqual(self.driver.calls, [4, 8, 12, 16])
        self.assertFalse(result['system_wide'])

    def test_refresh_drops_exited_rows_and_reports_reused_pid_identity(self):
        before = self.catalog.list(16)
        self.driver.rows[4]['exit_status'] = 0
        self.driver.rows[12] = self.driver.row(12, 'replacement.exe', 134355379964474376)
        after = self.catalog.list(16, refresh=True)
        self.assertEqual([p['pid'] for p in after['processes']], [12])
        self.assertNotEqual(before['processes'][1]['create_time'], after['processes'][0]['create_time'])

    def test_cache_is_bounded_and_caller_cannot_modify_it(self):
        result = self.catalog.list(16)
        result['processes'].clear()
        cached = self.catalog.list(16)
        self.assertTrue(cached['cached'])
        self.assertEqual(len(cached['processes']), 2)
        self.assertEqual(len(self.driver.calls), 4)
        self.catalog.cached_at -= 4
        self.assertFalse(self.catalog.list(16)['cached'])
        self.assertEqual(len(self.driver.calls), 8)

    def test_explicit_high_pid_included_without_expanding_entire_range(self):
        self.driver.rows[100] = self.driver.row(100, 'high.exe', 5)
        result = self.catalog.list(16, extra_pids=[100, 101, 100])
        self.assertEqual([p['pid'] for p in result['processes']], [4, 12, 100])
        self.assertEqual(self.driver.calls, [4, 8, 12, 16, 100])

    def test_disconnect_invalidates_cached_result_and_does_not_probe(self):
        self.catalog.list(16)
        self.driver.connected = False
        with self.assertRaises(DiscoveryError):
            self.catalog.list(16)
        self.assertIsNone(self.catalog.cached)
        self.assertEqual(len(self.driver.calls), 4)

    def test_transport_failure_aborts_and_never_caches_partial_results(self):
        self.driver.rows[8] = {'success': False, 'error_code': 6}
        with self.assertRaises(DiscoveryError):
            self.catalog.list(16)
        self.assertEqual(self.driver.calls, [4, 8])
        self.assertIsNone(self.catalog.cached)

    def test_simultaneous_refresh_requests_share_in_progress_snapshot(self):
        first_probe = threading.Event()
        second_started = threading.Event()
        clock_calls = []
        def clock():
            clock_calls.append(threading.current_thread().name)
            if first_probe.is_set():
                second_started.set()
            return time.monotonic()
        catalog = KernelProcessCatalog(self.driver, clock=clock)
        original = self.driver.query_process_extended
        def query(pid):
            if pid == 4:
                first_probe.set()
                self.assertTrue(second_started.wait(2))
            return original(pid)
        self.driver.query_process_extended = query
        with concurrent.futures.ThreadPoolExecutor(2) as executor:
            first = executor.submit(catalog.list, 16, (), True)
            self.assertTrue(first_probe.wait(2))
            second = executor.submit(catalog.list, 16, (), True)
            results = [first.result(3), second.result(3)]
        self.assertEqual(self.driver.calls, [4, 8, 12, 16])
        self.assertEqual(sorted(r['cached'] for r in results), [False, True])

    def test_http_first_visit_validation_and_unavailable_driver(self):
        import server
        with patch.object(server, 'process_catalog', self.catalog), \
                patch.object(server, 'known_processes', {}):
            client = ASGIClient(server.app)
            response = client.get('/api/processes?max_pid=16&refresh=true')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()['processes']), 2)
            for query in ('max_pid=3', 'max_pid=1048577', 'max_pid=invalid'):
                self.assertEqual(client.get('/api/processes?' + query).status_code, 422)
            self.driver.connected = False
            self.assertEqual(client.get('/api/processes?max_pid=16').status_code, 503)


if __name__ == '__main__':
    unittest.main()
