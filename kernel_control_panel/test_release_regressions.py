"""Release regressions for observed sharing failures, image ambiguity and packaging."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import atomic_metadata as A
import runtime_paths as R
import studio_extensions as E

class ReleaseRegressions(unittest.TestCase):
    def test_journal_checkpoint_survives_open_windows_reader(self):
        from change_journal import Journal
        with tempfile.TemporaryDirectory() as folder:
            journal=Journal(None,folder);record=dict(id='a'*32,status='prepared')
            journal.persist(record);path=Path(folder)/('a'*32+'.json');held=path.open('rb')
            worker=threading.Thread(target=lambda:(time.sleep(.05),held.close()));worker.start()
            try:record['status']='verified';journal.persist(record)
            finally:held.close();worker.join()
            self.assertEqual(json.loads(path.read_text())['status'],'verified')

    def test_failed_write_ahead_checkpoint_prevents_target_write(self):
        from test_memory_editor import Studio
        from change_journal import Journal,JournalPersistenceError
        from threading import RLock
        with tempfile.TemporaryDirectory() as folder:
            studio=Studio();studio.driver._lock=RLock();journal=Journal(studio,folder);journal.install()
            with patch('change_journal.write_json',side_effect=OSError('disk full')):
                with self.assertRaises(JournalPersistenceError) as error:studio.driver.write_process_memory(42,0x1000,b'abc')
            self.assertFalse(error.exception.journal_state['write_attempted'])
            self.assertEqual(studio.writes,0)

    def test_final_checkpoint_failure_reports_actual_write_instead_of_http_500(self):
        from test_memory_editor import Studio
        from change_journal import Journal
        from studio_api import Studio as ProductionStudio
        from threading import RLock
        with tempfile.TemporaryDirectory() as folder:
            studio=Studio();studio.driver._lock=RLock();journal=Journal(studio,folder);journal.install()
            original=A.write_json
            def checkpoint(path,record,**kwargs):
                if record['status']=='verified':raise OSError('disk full')
                original(path,record,**kwargs)
            class Endpoint:
                def operate(self,*args):return studio.driver.write_process_memory(42,0x1000,b'abc')
            with patch('change_journal.write_json',side_effect=checkpoint):
                result=ProductionStudio.run(Endpoint(),'write',{})
            self.assertFalse(result['success']);self.assertTrue(result['write_attempted'])
            self.assertEqual(result['observed_hex'],'616263');self.assertTrue(result['write_response']['success'])
            self.assertEqual(studio.writes,1)

    def test_metadata_reader_can_close_before_bounded_retry_expires(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'manifest.json';path.write_text('{"old":true}')
            held=path.open('rb')
            worker=threading.Thread(target=lambda:(time.sleep(.05),held.close()))
            worker.start()
            try:A.write_json(path,{'state':'completed','bytes':8388608})
            finally:held.close();worker.join()
            self.assertEqual(json.loads(path.read_text()),{'state':'completed','bytes':8388608})
            self.assertEqual(list(Path(folder).glob('*.tmp')),[])

    def test_permanent_permission_error_is_bounded_and_preserves_old_record(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'manifest.json';path.write_text('original')
            with patch.object(A.os,'replace',side_effect=PermissionError('held')) as replace,patch.object(A.time,'sleep'):
                with self.assertRaises(PermissionError):A.write_json(path,{'state':'completed'})
            self.assertEqual(replace.call_count,8)
            self.assertEqual(path.read_text(),'original')
            self.assertEqual(list(Path(folder).glob('*.tmp')),[])

    def test_terminal_metadata_failure_is_failed_and_can_resume(self):
        from test_memory_dump import Source, BASE
        from memory_dump import DumpManager
        with tempfile.TemporaryDirectory() as folder:
            manager=DumpManager(Source(),folder);original=manager._manifest
            def fail_terminal(job):
                if job['state']=='completed':raise OSError('disk checkpoint failed')
                original(job)
            manager._manifest=fail_terminal
            try:
                key=manager.start(dict(pid=42,mode='range',address=hex(BASE),size=4096))['dump_id']
                manager.jobs[key]['_future'].result(timeout=5)
                self.assertEqual(manager.get(key)['state'],'failed')
                self.assertEqual(manager.get(key)['completed_bytes'],4096)
                manager._manifest=original;manager.resume(key);manager.jobs[key]['_future'].result(timeout=5)
                self.assertEqual(manager.get(key)['state'],'completed')
            finally:manager.shutdown()

    def resolver(self,images,expression):
        class Studio:
            def operate(self,operation,args):return {'results':images}
        class PE:
            def __init__(self,studio,pid,base):self.base=base
            def exports(self):return [dict(name='Tick',ordinal=1,address=hex(self.base+0x123),forwarder='')]
        with patch.object(E,'LoadedPE',PE):return E.operate(Studio(),'resolve',dict(pid=42,expression=expression),lambda:False)

    @staticmethod
    def images():
        return [dict(name='Realm.exe',path=r'C:\game\Realm.exe',address='0x10000',size=8192,source='MEM_IMAGE',main_image=True),
                dict(name='Realm.exe',path='',address='0x20000',size=8192,source='PE_HEADER',main_image=False)]

    def test_private_PE_does_not_shadow_kernel_mapped_name(self):
        self.assertEqual(self.resolver(self.images(),'Realm.exe!Tick')['address'],'0x10123')
        self.assertEqual(self.resolver(self.images(),'main!Tick')['address'],'0x10123')

    def test_explicit_base_selects_private_image_and_true_duplicates_remain_ambiguous(self):
        self.assertEqual(self.resolver(self.images(),'Realm.exe@0x20000!Tick')['address'],'0x20123')
        self.assertEqual(self.resolver(self.images(),'0x20000!Tick')['address'],'0x20123')
        images=self.images();images[1]['source']='MEM_IMAGE'
        with self.assertRaises(ValueError):self.resolver(images,'Realm.exe!Tick')

    def test_frozen_data_and_assets_have_separate_roots(self):
        with patch.dict(R.os.environ,{},clear=True),patch.object(R.sys,'frozen',True,create=True),patch.object(R.sys,'executable',str(Path('C:/Release/KernelStudio.exe'))),patch.object(R.sys,'_MEIPASS','C:/Release/_internal',create=True):
            self.assertEqual(R.data_path('dumps'),Path('C:/Release/data/dumps'))
            self.assertEqual(R.bundle_root(),Path('C:/Release/_internal'))

    def test_native_legacy_scanner_fails_closed_without_target_API(self):
        import memory_scanner as M
        with self.assertRaisesRegex(RuntimeError,'커널 IOCTL'):
            M.get_memory_regions(42)

    def test_build_endpoint_reports_panel_and_expected_driver_independently(self):
        from server import app
        from test_asgi_client import ASGIClient
        r=ASGIClient(app).get('/api/build').json()
        self.assertEqual(r['panel_version'],'3.2.3')
        self.assertEqual(r['release_id'],'SampleKernel1-2.6.0.2_KernelStudio-3.2.3_APCNormalize')
        self.assertEqual(r['expected_driver_version'],'2.6')
        self.assertEqual(r['default_port'],8005)

if __name__=='__main__':unittest.main()
