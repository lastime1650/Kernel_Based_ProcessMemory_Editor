"""Dump failure, ownership, continuation and download integrity regressions."""
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import zipfile
from fastapi import FastAPI
from test_asgi_client import ASGIClient as TestClient
from memory_dump import DumpManager, MAX_DUMP_BYTES


BASE = 0x10000


def region(base, size, readable=True, image=False, name='Project1.exe', image_size=0):
    return {'address': hex(base), 'size': size, 'state': '0x1000', 'type': '0x1000000' if image else '0x20000',
        'readable': readable, 'guarded': not readable, 'allocation_base': hex(BASE),
        'image_base': hex(BASE) if image else '0x0', 'image_size': image_size,
        'image_name': name, 'image_path': name, 'main_image': image}


class Driver:
    def __init__(self):
        self.data = (bytes(range(251)) * (5 * 1024 ** 2 // 251 + 1))[:5 * 1024 ** 2]
        self.reads = []
        self.fail_at = None
        self.hook = None
        self.bad_size = False
        self.release_failure = False

    def send_ioctl(self, *args):
        return True, 0, 0

    def read_process_memory_snapshot(self, pid, start, size):
        self.reads.append((pid, start, size))
        if self.hook:
            self.hook()
        if self.release_failure:
            raise RuntimeError('IOCTL snapshot release failed')
        if start == self.fail_at:
            return {'success': False, 'result_status': '0x8000000D'}
        data = self.data[start-BASE:start-BASE+size-(1 if self.bad_size else 0)]
        return {'success': True, 'data_hex': data.hex()}


class Source:
    def __init__(self):
        self.driver = Driver()
        self.key = 'original'
        self.regions = [region(BASE, len(self.driver.data))]
        self.truncated = False

    def identity(self, pid):
        return self.key

    def operate(self, operation, args):
        assert operation == 'regions'
        return {'success': True, 'truncated': self.truncated, 'results': self.regions}


class DumpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.source = Source()
        self.manager = DumpManager(self.source, self.temp.name)

    def tearDown(self):
        self.manager.shutdown()
        self.temp.cleanup()

    def start(self, **args):
        return self.manager.start({'pid': 42, 'mode': 'range', 'address': hex(BASE), 'size': 12288, **args})['dump_id']

    def finish(self, key):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = self.manager.get(key)
            if job['state'] in ('completed', 'failed', 'cancelled'):
                return job
            time.sleep(.005)
        self.fail('dump job timeout')

    def raw(self, key, job):
        return (Path(self.temp.name) / key / job['files'][0]['name']).read_bytes()

    def test_large_unaligned_range_byte_exact_without_large_driver_reads(self):
        size = 2 * 1024 ** 2 + 37
        key = self.start(address=hex(BASE+11), size=size)
        job = self.finish(key)
        self.assertEqual(job['state'], 'completed', job)
        raw = self.raw(key, job)
        self.assertEqual(raw, self.source.driver.data[11:11+size])
        self.assertEqual(job['files'][0]['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(all(size <= 4096 for _, _, size in self.source.driver.reads))

    def test_unmapped_and_guard_pages_preserve_offsets_with_explicit_holes(self):
        self.source.regions = [region(BASE, 4096), region(BASE+8192, 4096, False), region(BASE+12288, 4096)]
        key = self.start(size=16384, policy='zero')
        job = self.finish(key)
        self.assertEqual(job['state'], 'completed')
        self.assertEqual(self.raw(key, job), self.source.driver.data[:4096]+bytes(8192)+self.source.driver.data[12288:16384])
        self.assertEqual(job['zero_bytes'], 8192)
        self.assertEqual([x['reason'] for x in job['holes']], ['unmapped', 'unreadable_or_guarded'])
        self.assertEqual([x[1] for x in self.source.driver.reads], [BASE, BASE+12288])

    def test_strict_read_failure_resumes_at_failure_without_repeating_prefix(self):
        self.source.driver.fail_at = BASE+4096
        key = self.start()
        failed = self.finish(key)
        self.assertEqual((failed['state'], failed['completed_bytes']), ('failed', 4096))
        self.source.driver.fail_at = None
        self.source.driver.reads.clear()
        self.manager.resume(key)
        job = self.finish(key)
        self.assertEqual(job['state'], 'completed', job)
        self.assertEqual(self.source.driver.reads[0][1], BASE+4096)
        self.assertEqual(self.raw(key, job), self.source.driver.data[:12288])

    def test_zero_read_failures_are_marked_not_reported_as_original_bytes(self):
        self.source.driver.fail_at = BASE+4096
        key = self.start(policy='zero')
        job = self.finish(key)
        self.assertEqual(job['state'], 'completed')
        self.assertEqual((job['zero_bytes'], job['read_failures']), (4096, 1))
        self.assertEqual(job['holes'][0]['status'], '0x8000000D')
        self.assertEqual(self.raw(key, job)[4096:8192], bytes(4096))

    def test_cancel_then_resume_preserves_completed_prefix(self):
        entered, release = threading.Event(), threading.Event()
        self.source.driver.hook = lambda: (entered.set(), release.wait(5))
        key = self.start()
        self.assertTrue(entered.wait(5))
        self.manager.cancel(key)
        release.set()
        cancelled = self.finish(key)
        self.assertEqual((cancelled['state'], cancelled['completed_bytes']), ('cancelled', 4096))
        with self.assertRaises(ValueError):
            self.manager.artifact(key, cancelled['files'][0]['name'])
        self.source.driver.hook = None
        self.source.driver.reads.clear()
        self.manager.resume(key)
        job = self.finish(key)
        self.assertEqual(job['state'], 'completed')
        self.assertEqual(self.source.driver.reads[0][1], BASE+4096)
        self.assertEqual(self.raw(key, job), self.source.driver.data[:12288])

    def test_PID_reuse_stops_and_refuses_resume(self):
        self.source.driver.hook = lambda: setattr(self.source, 'key', 'replacement')
        key = self.start(chunk_size=4096)
        job = self.finish(key)
        self.assertEqual((job['state'], job['completed_bytes']), ('failed', 4096))
        self.assertEqual(len(self.source.driver.reads), 1)
        with self.assertRaises(ValueError):
            self.manager.resume(key)

    def test_transport_release_failure_and_short_read_are_fatal_in_zero_mode(self):
        for attribute in ('release_failure', 'bad_size'):
            setattr(self.source.driver, attribute, True)
            key = self.start(policy='zero')
            job = self.finish(key)
            self.assertEqual((job['state'], job['completed_bytes']), ('failed', 0))
            setattr(self.source.driver, attribute, False)

    def test_corrupted_partial_file_cannot_resume(self):
        self.source.driver.fail_at = BASE+4096
        key = self.start()
        job = self.finish(key)
        (Path(self.temp.name) / key / (job['files'][0]['name']+'.part')).write_bytes(b'bad')
        self.manager.resume(key)
        resumed = self.finish(key)
        self.assertEqual(resumed['state'], 'failed')
        self.assertIn('파일 크기', resumed['error'])

    def test_same_size_partial_content_change_fails_hash_check(self):
        self.source.driver.fail_at = BASE+4096
        key = self.start()
        job = self.finish(key)
        (Path(self.temp.name) / key / (job['files'][0]['name']+'.part')).write_bytes(bytes(4096))
        self.manager.resume(key)
        resumed = self.finish(key)
        self.assertEqual(resumed['state'], 'failed')
        self.assertIn('SHA256', resumed['error'])

    def test_image_selection_and_bundle_preserve_RVA_hash_and_manifest(self):
        self.source.regions = [region(BASE, 2 * 1024 ** 2, image=True, image_size=2 * 1024 ** 2)]
        key = self.start(mode='images')
        job = self.finish(key)
        self.assertEqual(job['state'], 'completed', job)
        with zipfile.ZipFile(Path(self.temp.name) / key / 'images.zip') as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(z.read(job['files'][0]['name']), self.source.driver.data[:2 * 1024 ** 2])
            manifest = json.loads(z.read('manifest.json'))
            self.assertEqual(manifest['state'], 'completed')
            self.assertEqual(manifest['files'][0]['sha256'], job['files'][0]['sha256'])
        key = self.start(mode='image', module='project1.exe')
        self.assertEqual(self.finish(key)['state'], 'completed')
        with self.assertRaises(ValueError):
            self.start(mode='image', module='absent.dll')

    def test_post_image_guard_tail_is_not_appended_to_PE_image(self):
        self.source.regions = [region(BASE,8192,image=True,image_size=8192),
                               region(BASE+8192,16384,False,image=True,image_size=8192)]
        key = self.start(mode='image',module='main')
        job = self.finish(key)
        self.assertEqual((job['state'],job['total_bytes'],job['zero_bytes']), ('completed',8192,0))
        self.assertEqual(self.raw(key,job), self.source.driver.data[:8192])

    def test_limits_incomplete_map_and_artifact_path_validation(self):
        for args in ({'size': MAX_DUMP_BYTES+1}, {'address': hex(0x800000000000-1), 'size': 2},
                     {'chunk_size': 4097}, {'policy': 'invalid'}, {'pid': True}):
            with self.assertRaises(ValueError):
                self.start(**args)
        self.source.truncated = True
        with self.assertRaises(ValueError):
            self.start()
        self.source.truncated = False
        key = self.start()
        self.finish(key)
        with self.assertRaises(KeyError):
            self.manager.artifact(key, '../outside.txt')
        self.assertTrue(self.manager.remove(key)['success'])
        with self.assertRaises(KeyError):
            self.manager.get(key)

    def test_completed_download_history_survives_server_restart(self):
        key = self.start()
        job = self.finish(key)
        self.manager.shutdown()
        restored = DumpManager(self.source, self.temp.name)
        try:
            loaded = restored.get(key)
            self.assertEqual(loaded['files'][0]['sha256'], job['files'][0]['sha256'])
            path, _, digest = restored.artifact(key, loaded['files'][0]['name'])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            with self.assertRaises(ValueError):
                restored.resume(key)
        finally:
            restored.shutdown()

    def test_active_download_prevents_file_deletion(self):
        key = self.start()
        job = self.finish(key)
        self.manager.artifact(key,job['files'][0]['name'],lease=True)
        with self.assertRaises(ValueError):
            self.manager.remove(key)
        self.manager.release_download(key)
        self.assertTrue(self.manager.remove(key)['success'])

    def test_shutdown_cancels_running_and_queued_jobs_before_return(self):
        entered, release = threading.Event(), threading.Event()
        self.source.driver.hook = lambda: (entered.set(), release.wait(5))
        first = self.start()
        self.assertTrue(entered.wait(5))
        second = self.start()
        thread = threading.Thread(target=self.manager.shutdown)
        thread.start()
        release.set()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([self.manager.get(k)['state'] for k in (first, second)], ['cancelled', 'cancelled'])

    def test_HTTP_download_range_resume_headers_and_small_dump_compatibility(self):
        from studio_api import install
        app = FastAPI()
        studio = install(app, self.source.driver)
        studio.dumps.shutdown()
        studio.dumps = self.manager
        studio.identity = self.source.identity
        original = studio.operate
        studio.operate = lambda op, args, *a: self.source.operate(op,args) if op == 'regions' else original(op,args,*a)
        self.manager.studio = studio
        try:
            with TestClient(app) as client:
                result = client.post('/api/studio/dumps', json={'pid':42,'address':hex(BASE),'size':2 * 1024 ** 2})
                self.assertEqual(result.status_code, 200)
                key = result.json()['dump_id']
                job = self.finish(key)
                self.assertEqual(job['state'], 'completed', job)
                url = job['files'][0]['download_url']
                ranged = client.get(url, headers={'Range':'bytes=100-199'})
                self.assertEqual(ranged.status_code, 206)
                self.assertEqual(ranged.content, self.source.driver.data[100:200])
                self.assertEqual(ranged.headers['content-range'], f'bytes 100-199/{2 * 1024 ** 2}')
                self.assertEqual(ranged.headers['x-content-sha256'], job['files'][0]['sha256'])
                self.assertEqual(client.get(url,headers={'Range':'bytes=99999999-'}).status_code,416)
                self.assertEqual(self.manager.jobs[key].get('_downloads',0),0)
                metadata=client.get(job['manifest_url'])
                self.assertEqual(metadata.json()['state'],'completed')
                self.assertIn('attachment',metadata.headers['content-disposition'])
                self.assertEqual(self.manager.jobs[key].get('_downloads',0),0)
                old = client.get(f'/api/studio/dump?pid=42&address={hex(BASE)}&size=4096')
                self.assertEqual(old.content, self.source.driver.data[:4096])
                self.assertEqual(client.post('/api/studio/dumps',json={'pid':42,'size':1}).status_code,400)
                self.assertEqual(client.get(f'/api/studio/dumps/{key}/files/other.bin').status_code,404)
        finally:
            studio.shutdown()


if __name__ == '__main__':
    unittest.main(verbosity=2)
