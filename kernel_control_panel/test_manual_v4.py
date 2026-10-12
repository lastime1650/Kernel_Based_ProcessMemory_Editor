import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from test_asgi_client import ASGIClient
import manual_v4 as M


class Driver:
    def __init__(self):
        self._lock = threading.RLock()
        self.calls = []
        self.reply = dict(success=True, transport_ok=True, packet_valid=True, execution_unknown=False,
                          error_code=0, bytes_returned=2104, result_status='0x00000000', failcode=0, failmessage='',
                          mapped_base='0x140000000', entry_point='0x140001000')

    def manual_map_dll(self, pid, path):
        self.calls.append((pid, path))
        return copy.deepcopy(self.reply)


class Studio:
    def __init__(self):
        self.current = '777'
        self.driver = Driver()
        self.queries = []

    def identity(self, pid):
        self.queries.append(pid)
        return self.current


class Queue:
    def __init__(self):
        self.items = []

    def submit(self, fn, *args):
        self.items.append((fn, args))

    def shutdown(self, **kwargs):
        pass


class ManualTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'jobs'
        self.studio = Studio()
        self.manager = M.ManualV4(self.studio, self.root)
        self.manager.pool.shutdown()
        self.manager.pool = Queue()
        self.app = FastAPI()
        M.install(self.app, self.studio, self.manager)
        self.client = ASGIClient(self.app)
        self.headers = {'host': '127.0.0.1'}

    def tearDown(self):
        self.manager.shutdown()
        self.temp.cleanup()

    def body(self, **changes):
        body = dict(pid=123, process_start_key='777', path=r'C:\fixtures\한국.dll')
        body.update(changes)
        return body

    def execute(self):
        fn, args = self.manager.pool.items.pop(0)
        fn(*args)

    def test_submit_queues_without_mapping_or_file_reads(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('DLL bytes must stay in kernel')):
            job = self.manager.submit(self.body())
        self.assertEqual(job['state'], 'queued')
        self.assertIsNone(job['failcode'])
        self.assertIsNone(job['failmessage'])
        self.assertEqual(self.studio.driver.calls, [])
        self.assertEqual(len(self.manager.pool.items), 1)
        self.assertEqual(job['identity_check'], 'preflight_only')
        self.assertIn('시작 키', job['note'])

    def test_worker_maps_only_through_driver_and_preserves_addresses(self):
        job = self.manager.submit(self.body())
        self.execute()
        result = self.manager.get(job['id'])
        self.assertEqual(self.studio.driver.calls, [(123, self.body()['path'])])
        self.assertEqual(result['state'], 'mapped')
        self.assertEqual(result['mapped_base'], '0x140000000')
        self.assertEqual(result['entry_point'], '0x140001000')
        self.assertEqual(result['failcode'], 0)
        self.assertEqual(result['failmessage'], '')
        self.assertIn('failcode 0', result['output'])
        self.assertEqual(self.studio.queries, [123, 123])
        self.assertNotIn('runtime', result)
        self.assertNotIn('session_present', result)

    def test_duplicate_active_request_is_coalesced(self):
        first = self.manager.submit(self.body())
        second = self.manager.submit(self.body())
        self.assertEqual(first['id'], second['id'])
        self.assertEqual(len(self.manager.pool.items), 1)
        self.execute()
        self.assertEqual(len(self.studio.driver.calls), 1)

    def test_concurrent_active_requests_queue_once(self):
        ids = []
        threads = [threading.Thread(target=lambda: ids.append(self.manager.submit(self.body())['id'])) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(len(self.manager.pool.items), 1)

    def test_same_owner_different_path_is_rejected_while_active(self):
        self.manager.submit(self.body())
        with self.assertRaises(ValueError):
            self.manager.submit(self.body(path=r'C:\another.dll'))
        self.assertEqual(len(self.manager.pool.items), 1)

    def test_queue_limit_rejects_fifth_active_target(self):
        for pid in range(1, 5):
            self.manager.submit(self.body(pid=pid))
        with self.assertRaises(ValueError):
            self.manager.submit(self.body(pid=5))
        self.assertEqual(len(self.manager.pool.items), 4)

    def test_bad_identity_prevents_queue(self):
        for identity in ('0', '778', '0777', '18446744073709551616', 777):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                self.manager.submit(self.body(process_start_key=identity))
        self.assertEqual(self.manager.pool.items, [])

    def test_owner_rechecked_immediately_before_ioctl(self):
        job = self.manager.submit(self.body())
        self.studio.current = '778'
        self.execute()
        self.assertEqual(self.studio.driver.calls, [])
        self.assertEqual(self.manager.get(job['id'])['state'], 'failed')

    def test_invalid_pid_path_or_old_fields_cannot_queue(self):
        for changes in ({'pid': True}, {'pid': 0}, {'path': 'relative.dll'}, {'path': r'C:\file.exe'},
                        {'runtime': 'native'}, {'bundle_id': 'a'*32}, {'identity': '777'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.manager.submit(self.body(**changes))
        self.assertEqual(self.manager.pool.items, [])

    def test_durable_intent_failure_prevents_queue(self):
        with patch.object(M, 'write_json', side_effect=OSError('disk full')), self.assertRaises(OSError):
            self.manager.submit(self.body())
        self.assertEqual(self.manager.pool.items, [])
        self.assertEqual(self.studio.driver.calls, [])

    def test_all_job_checkpoints_request_fsync(self):
        original = M.write_json
        with patch.object(M, 'write_json', wraps=original) as save:
            self.manager.submit(self.body())
            self.execute()
        self.assertGreaterEqual(save.call_count, 3)
        self.assertTrue(all(call.kwargs.get('durable') is True for call in save.call_args_list))

    def test_running_checkpoint_failure_prevents_ioctl(self):
        job = self.manager.submit(self.body())
        original = M.write_json
        def save(path, record, **kwargs):
            if record['state'] == 'running':
                raise OSError('disk full')
            return original(path, record, **kwargs)
        with patch.object(M, 'write_json', side_effect=save):
            self.execute()
        self.assertEqual(self.studio.driver.calls, [])
        self.assertEqual(self.manager.get(job['id'])['state'], 'failed')

    def test_post_map_checkpoint_failure_preserves_base_as_indeterminate(self):
        job = self.manager.submit(self.body())
        original = M.write_json
        def save(path, record, **kwargs):
            if record['state'] == 'mapped':
                raise OSError('disk full')
            return original(path, record, **kwargs)
        with patch.object(M, 'write_json', side_effect=save):
            self.execute()
        result = self.manager.get(job['id'])
        self.assertEqual(result['state'], 'indeterminate')
        self.assertEqual(result['mapped_base'], '0x140000000')
        self.assertEqual(len(self.studio.driver.calls), 1)
        self.assertEqual(self.manager.pool.items, [])

    def test_kernel_failure_is_recorded_without_retry(self):
        message = 'PE DOS signature invalid: observed=0x0000; NTSTATUS=STATUS_INVALID_IMAGE_FORMAT(0xC000007B)'
        self.studio.driver.reply.update(success=False, result_status='0xC000007B', failcode=28, failmessage=message, mapped_base='0x0', entry_point='0x0')
        job = self.manager.submit(self.body())
        self.execute()
        result = self.manager.get(job['id'])
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['result_status'], '0xC000007B')
        self.assertEqual(result['failcode'], 28)
        self.assertEqual(result['failmessage'], message)
        self.assertIn(message, result['output'])
        self.assertIn('failcode 28', result['output'])
        self.assertIn('failcode 28', result['error'])
        stored = json.loads(self.manager._job_path(job['id']).read_text(encoding='utf-8'))
        self.assertEqual(stored['failcode'], 28)
        self.assertEqual(stored['failmessage'], message)
        self.assertEqual(len(self.studio.driver.calls), 1)

    def test_uncertain_reply_retains_kernel_base_and_never_resubmits(self):
        self.studio.driver.reply.update(success=False, execution_unknown=True, result_status='0xC00000B5', failcode=130,
                                      failmessage='KeWaitForSingleObject: NTSTATUS=STATUS_IO_TIMEOUT(0xC00000B5)')
        job = self.manager.submit(self.body())
        self.execute()
        result = self.manager.get(job['id'])
        self.assertEqual(result['state'], 'indeterminate')
        self.assertEqual(result['mapped_base'], '0x140000000')
        self.assertEqual(result['failcode'], 130)
        for _ in range(3):
            self.manager.list()
            self.manager.get(job['id'])
        self.assertEqual(len(self.studio.driver.calls), 1)
        self.assertEqual(self.manager.pool.items, [])
        for path in (self.body()['path'], r'C:\another.dll'):
            with self.assertRaises(ValueError):
                self.manager.submit(self.body(path=path))
        self.assertEqual(len(self.studio.driver.calls), 1)

    def test_positive_wait_or_bad_transport_cannot_be_reported_mapped(self):
        for changes in ({'result_status':'0x00000102'}, {'result_status':'0x00000103'},
                        {'transport_ok':False}, {'packet_valid':False}):
            with self.subTest(changes=changes):
                self.studio.driver.reply.update(changes)
                job = self.manager.submit(self.body(pid=len(self.manager.jobs)+123))
                self.execute()
                self.assertEqual(self.manager.get(job['id'])['state'], 'indeterminate')
                self.studio.driver.reply.update(result_status='0x00000000', transport_ok=True, packet_valid=True)

    def test_transport_exception_is_indeterminate_after_attempt(self):
        job = self.manager.submit(self.body())
        with patch.object(self.studio.driver, 'manual_map_dll', side_effect=OSError('transport')):
            self.execute()
        self.assertEqual(self.manager.get(job['id'])['state'], 'indeterminate')
        self.assertIsNone(self.manager.get(job['id'])['failcode'])

    def test_missing_or_contradictory_failcode_never_reports_success(self):
        for changes in ({'failcode':None}, {'failcode':5}, {'failcode':True},
                        {'failcode':-1}, {'failcode':0x100000000}):
            with self.subTest(changes=changes):
                self.studio.driver.reply.update(changes)
                job = self.manager.submit(self.body(pid=123 + len(self.manager.jobs)))
                self.execute()
                result = self.manager.get(job['id'])
                self.assertEqual(result['state'], 'indeterminate')
                self.assertIsNone(result['failcode'])
        self.assertEqual(len(self.studio.driver.calls), 5)

    def test_missing_corrupt_or_contradictory_message_is_unknown_and_blocks_replay(self):
        for message in (None, True, 1, b'bad', 'a'*1024, '\x1b', '실패', 'failure on success'):
            with self.subTest(message=repr(message)):
                self.studio.driver.reply.update(failmessage=message)
                body = self.body(pid=123 + len(self.manager.jobs))
                job = self.manager.submit(body)
                self.execute()
                result = self.manager.get(job['id'])
                self.assertEqual(result['state'], 'indeterminate')
                self.assertIsNone(result['failcode'])
                self.assertIsNone(result['failmessage'])
                with self.assertRaises(ValueError):
                    self.manager.submit(body)
        self.assertEqual(len(self.studio.driver.calls), 8)

    def test_message_from_failed_transport_is_discarded(self):
        self.studio.driver.reply.update(transport_ok=False, packet_valid=False, result_status='0xC0000022',
                                      success=False, failcode=119, failmessage='Untrusted API diagnostic')
        job = self.manager.submit(self.body())
        self.execute()
        result = self.manager.get(job['id'])
        self.assertEqual(result['state'], 'indeterminate')
        self.assertIsNone(result['failmessage'])
        self.assertNotIn('Untrusted API diagnostic', result['output'])

    def test_failure_message_survives_restart_without_replay(self):
        message = 'ZwProtectVirtualMemory: proc_h=0x44; section[0]=.text\nsize=0x2000; status=0xC0000022'
        self.studio.driver.reply.update(success=False, result_status='0xC0000022', failcode=119,
                                      failmessage=message, mapped_base='0x0', entry_point='0x0')
        job = self.manager.submit(self.body())
        self.execute()
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(restored.get(job['id'])['state'], 'failed')
            self.assertEqual(restored.get(job['id'])['failmessage'], message)
            self.assertIn(message, restored.get(job['id'])['output'])
            self.assertEqual(len(self.studio.driver.calls), 1)
        finally:
            restored.shutdown()

    def test_invalid_saved_message_preserves_indeterminate_job_and_blocks_replay(self):
        job = self.manager.submit(self.body())
        self.execute()
        record = json.loads(self.manager._job_path(job['id']).read_text(encoding='utf-8'))
        for message in (None, True, 5, [], 'x'*1024, '\0', '\x1b', '실패', 'failure on success'):
            with self.subTest(message=repr(message)):
                self.manager._job_path(job['id']).write_text(json.dumps(dict(record, failmessage=message,
                                                                           output='untrusted cached diagnostic')), encoding='utf-8')
                restored = M.ManualV4(self.studio, self.root)
                try:
                    result = restored.get(job['id'])
                    self.assertEqual(result['state'], 'indeterminate')
                    self.assertIsNone(result['failcode'])
                    self.assertIsNone(result['failmessage'])
                    self.assertEqual(result['output'], '')
                    with self.assertRaises(ValueError):
                        restored.submit(self.body())
                    self.assertEqual(len(self.studio.driver.calls), 1)
                finally:
                    restored.shutdown()

    def test_legacy_failcode_only_record_has_unknown_message(self):
        job = self.manager.submit(self.body())
        self.execute()
        record = json.loads(self.manager._job_path(job['id']).read_text(encoding='utf-8'))
        record.pop('failmessage')
        self.manager._job_path(job['id']).write_text(json.dumps(record), encoding='utf-8')
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(restored.get(job['id'])['state'], 'mapped')
            self.assertEqual(restored.get(job['id'])['failcode'], 0)
            self.assertIsNone(restored.get(job['id'])['failmessage'])
            self.assertEqual(len(self.studio.driver.calls), 1)
        finally:
            restored.shutdown()

    def test_failcode_survives_restart_and_legacy_jobs_remain_unknown(self):
        job = self.manager.submit(self.body())
        self.execute()
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(restored.get(job['id'])['failcode'], 0)
        finally:
            restored.shutdown()
        record = json.loads(self.manager._job_path(job['id']).read_text(encoding='utf-8'))
        record.pop('failcode')
        record.pop('failmessage')
        self.manager._job_path(job['id']).write_text(json.dumps(record), encoding='utf-8')
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(restored.get(job['id'])['state'], 'mapped')
            self.assertIsNone(restored.get(job['id'])['failcode'])
            self.assertIsNone(restored.get(job['id'])['failmessage'])
            self.assertEqual(len(self.studio.driver.calls), 1)
        finally:
            restored.shutdown()

    def test_persisted_contradictory_failcode_blocks_replay(self):
        job = self.manager.submit(self.body())
        self.execute()
        record = json.loads(self.manager._job_path(job['id']).read_text(encoding='utf-8'))
        record['failcode'] = 28
        self.manager._job_path(job['id']).write_text(json.dumps(record), encoding='utf-8')
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(restored.get(job['id'])['state'], 'indeterminate')
            with self.assertRaises(ValueError):
                restored.submit(self.body())
            self.assertEqual(len(self.studio.driver.calls), 1)
        finally:
            restored.shutdown()

    def test_restart_never_replays_running_or_queued_jobs(self):
        job = self.manager.submit(self.body())
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(restored.get(job['id'])['state'], 'indeterminate')
            self.assertEqual(self.studio.driver.calls, [])
        finally:
            restored.shutdown()

    def test_old_native_session_records_are_ignored(self):
        key = 'a'*32
        (self.root / (key+'.json')).write_text(json.dumps(dict(id=key, state='running', runtime='native')))
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(restored.jobs, {})
            self.assertEqual(self.studio.driver.calls, [])
        finally:
            restored.shutdown()

    def test_damaged_persisted_records_do_not_break_startup_or_listing(self):
        job = self.manager.submit(self.body())
        record = copy.deepcopy(self.manager.jobs[job['id']])
        invalid = [None, [], dict(record, created_at='yesterday'),
                   {key:value for key,value in record.items() if key != 'created_at'},
                   dict(record, created_at=10**400), dict(record, mapped_base=123),
                   dict(record, entry_point='0xffff800000000000'), dict(record, error=[]),
                   dict(record, result_status=0), dict(record, execution_unknown='false')]
        for index, bad in enumerate(invalid):
            key = f'{index:032x}'
            if isinstance(bad, dict):
                bad['id'] = key
            (self.root / (key+'.json')).write_text(json.dumps(bad), encoding='utf-8')
        restored = M.ManualV4(self.studio, self.root)
        try:
            self.assertEqual(len(restored.list()['jobs']), 1)
            self.assertEqual(restored.get(job['id'])['state'], 'indeterminate')
            self.assertEqual(self.studio.driver.calls, [])
        finally:
            restored.shutdown()

    def test_persisted_extra_fields_are_pruned_and_nt_path_rebuilt(self):
        job = self.manager.submit(self.body())
        self.execute()
        record = copy.deepcopy(self.manager.jobs[job['id']])
        record.update(success=False, runtime='native', nt_path='tampered')
        self.manager._job_path(job['id']).write_text(json.dumps(record), encoding='utf-8')
        restored = M.ManualV4(self.studio, self.root)
        try:
            result = restored.get(job['id'])
            self.assertTrue(result['success'])
            self.assertEqual(result['state'], 'mapped')
            self.assertNotIn('runtime', result)
            self.assertEqual(result['nt_path'], '\\??\\C:\\fixtures\\한국.dll')
            self.assertEqual(len(self.studio.driver.calls), 1)
        finally:
            restored.shutdown()

    def test_contradictory_persisted_success_or_failure_is_indeterminate(self):
        job = self.manager.submit(self.body())
        self.execute()
        record = copy.deepcopy(self.manager.jobs[job['id']])
        for changes in ({'execution_unknown':True}, {'transport_ok':False},
                        {'packet_valid':False}, {'state':'failed', 'execution_unknown':True}):
            with self.subTest(changes=changes):
                self.manager._job_path(job['id']).write_text(json.dumps(dict(record, **changes)), encoding='utf-8')
                restored = M.ManualV4(self.studio, self.root)
                try:
                    self.assertEqual(restored.get(job['id'])['state'], 'indeterminate')
                    with self.assertRaises(ValueError):
                        restored.submit(self.body())
                    self.assertEqual(len(self.studio.driver.calls), 1)
                finally:
                    restored.shutdown()

    def test_read_routes_never_execute(self):
        job = self.manager.submit(self.body())
        for _ in range(3):
            self.assertEqual(self.client.get('/api/manual-v4/jobs', headers=self.headers).status_code, 200)
            self.assertEqual(self.client.get('/api/manual-v4/jobs/'+job['id'], headers=self.headers).status_code, 200)
        self.assertEqual(self.studio.driver.calls, [])

    def test_http_map_uses_new_contract(self):
        response = self.client.post('/api/manual-v4/map', json=self.body(), headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['process_start_key'], '777')
        self.assertEqual(len(self.manager.pool.items), 1)
        self.assertEqual(self.studio.driver.calls, [])

    def test_old_upload_request_and_unmap_recover_routes_are_absent(self):
        for path in ('/bundles', '/request', '/jobs/'+'a'*32+'/unmap', '/jobs/'+'a'*32+'/recover'):
            response = self.client.post('/api/manual-v4'+path, json=self.body(), headers=self.headers)
            self.assertEqual(response.status_code, 404)
        self.assertEqual(self.manager.pool.items, [])

    def test_origin_and_host_rejection(self):
        for headers in ({'host':'127.0.0.1', 'origin':'http://evil.test'}, {'host':'evil.test'}, {'host':'[broken'}):
            self.assertEqual(self.client.post('/api/manual-v4/map', json=self.body(), headers=headers).status_code, 403)
        self.assertEqual(self.manager.pool.items, [])

    def test_unknown_job_is_404(self):
        self.assertEqual(self.client.get('/api/manual-v4/jobs/'+'a'*32, headers=self.headers).status_code, 404)

    def test_shutdown_prevents_queued_mapping(self):
        job = self.manager.submit(self.body())
        self.manager.shutdown()
        self.execute()
        self.assertEqual(self.manager.get(job['id'])['state'], 'failed')
        self.assertEqual(self.studio.driver.calls, [])

    def test_shutdown_while_waiting_for_driver_lock_prevents_dispatch(self):
        acquired = threading.Event()
        release = threading.Event()
        class DelayedLock:
            def __enter__(inner):
                acquired.set()
                self.assertTrue(release.wait(3))
            def __exit__(inner, *args):
                pass
        self.studio.driver._lock = DelayedLock()
        job = self.manager.submit(self.body())
        worker = threading.Thread(target=self.execute)
        worker.start()
        self.assertTrue(acquired.wait(3))
        self.manager.shutdown()
        release.set()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.manager.get(job['id'])['state'], 'failed')
        self.assertEqual(self.studio.driver.calls, [])

    def test_shutdown_during_preflight_prevents_dispatch(self):
        job = self.manager.submit(self.body())
        def closing_owner(pid):
            self.manager.shutdown()
            return '777'
        with patch.object(self.studio, 'identity', side_effect=closing_owner):
            self.execute()
        self.assertEqual(self.manager.get(job['id'])['state'], 'failed')
        self.assertEqual(self.studio.driver.calls, [])

    def test_prepare_restores_executor_after_clean_shutdown(self):
        self.manager.shutdown()
        self.manager.prepare()
        try:
            self.assertFalse(self.manager.closing)
            self.assertEqual(self.manager.jobs, {})
        finally:
            self.manager.pool.shutdown()
            self.manager.pool = Queue()


if __name__ == '__main__':
    unittest.main()
