import json
from pathlib import Path
import struct
import tempfile
import threading
import time
import unittest
import scan_workspace
from productivity_suite import Suite,definitions,codec
from request_scheduler import Scheduler,PriorityLock,scope
from test_memory_editor import Studio

DEFS=[{'name':'Item','size':8,'fields':[{'name':'Count','offset':0,'type':'uint32'}]},
      {'name':'Player','size':64,'fields':[{'name':'HP','offset':0,'type':'uint32'},
        {'name':'Inventory','offset':8,'type':'struct','ref':'Item','count':3},
        {'name':'Next','offset':40,'type':'pointer','ref':'Player'}]}]

class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=Studio();self.s.driver._lock=threading.RLock()
        self.s.suite=Suite(self.s,Path(self.tmp.name));self.suite=self.s.suite
        self.s.mem[0x1000:0x1004]=struct.pack('<I',845)
        self.s.mem[0x1018:0x101c]=struct.pack('<I',37)
        self.s.mem[0x1028:0x1030]=struct.pack('<Q',0x3000)
    def tearDown(self):self.tmp.cleanup()
    def view(self):return self.suite.view({'pid':123,'address':'0x1000','definitions':DEFS,'schema':'Player'})
    def preview(self,**kw):return self.suite.preview(dict(pid=123,items=[{'address':'0x1000','type':'uint32','value':'999'}],**kw))
    def test_nested_array_and_pointer(self):
        v=self.view();rows={r['path']:r for r in v['results']}
        self.assertEqual(rows['Player.Inventory[2].Count']['value'],'37')
        self.assertIn('Player.Next->.HP',rows)
    def test_pointer_cycle_visible(self):
        self.s.mem[0x3028:0x3030]=struct.pack('<Q',0x1000)
        self.assertTrue(any(r['type']=='cycle' for r in self.view()['results']))
    def test_invalid_pointer_visible(self):
        self.s.mem[0x1028:0x1030]=struct.pack('<Q',0xffffffffffffffff)
        self.assertTrue(any(r['type']=='error' for r in self.view()['results']))
    def test_schema_validation(self):
        for d in ([{'name':'P','size':4,'fields':[{'name':'x','offset':3,'type':'uint32'}]}],
                  [{'name':'P','size':8,'fields':[{'name':'x','offset':0,'type':'struct','ref':'P'}]}]):
            with self.assertRaises(ValueError):definitions(d)
    def test_duplicate_names(self):
        with self.assertRaises(ValueError):definitions(DEFS+[DEFS[0]])
    def test_utf_and_exact_bytes(self):
        self.assertEqual(codec('utf16','용',8,64),'용'.encode('utf-16-le')+bytes(6))
        with self.assertRaises(ValueError):codec('bytes','AB',2,64)
        with self.assertRaises(ValueError):codec('utf8','too long',4,64)
    def test_preview_apply_journal_restore(self):
        p=self.preview();self.assertEqual(self.s.writes,0)
        self.assertTrue(self.suite.apply(p['id'])['verified'])
        self.assertEqual(struct.unpack('<I',self.s.mem[0x1000:0x1004])[0],999)
        record=self.suite.journal.list()[0];self.assertEqual(record['status'],'verified')
        self.suite.journal.restore(record['id']);self.assertEqual(self.s.mem[0x1000:0x1004],struct.pack('<I',845))
    def test_journal_survives_reload(self):
        self.suite.apply(self.preview()['id']);from change_journal import Journal
        j=Journal(self.s,Path(self.tmp.name)/'journal');self.assertEqual(j.list()[0]['status'],'verified')
    def test_stale_preview_no_write(self):
        p=self.preview();self.s.mem[0x1000]=12
        with self.assertRaises(ValueError):self.suite.apply(p['id'])
        self.assertEqual(self.s.writes,0)
    def test_expected_stale_no_write(self):
        with self.assertRaises(ValueError):self.suite.preview({'pid':123,'items':[{'address':'0x1000','type':'uint32','value':'3','expected_hex':'00000000'}]})
        self.assertEqual(self.s.writes,0)
    def test_overlapping_batch(self):
        with self.assertRaises(ValueError):self.suite.preview({'pid':123,'items':[{'address':'0x1000','type':'uint32','value':'3'},{'address':'0x1002','type':'uint32','value':'4'}]})
    def test_replayed_apply(self):
        p=self.preview();self.suite.apply(p['id'])
        with self.assertRaises(ValueError):self.suite.apply(p['id'])
    def test_reused_pid(self):
        p=self.preview();self.s.key='replacement'
        with self.assertRaises(ValueError):self.suite.apply(p['id'])
        self.assertEqual(self.s.writes,0)
    def test_restore_conflict(self):
        self.suite.apply(self.preview()['id']);r=self.suite.journal.list()[0];self.s.mem[0x1000]=1
        with self.assertRaises(ValueError):self.suite.journal.restore(r['id'])
    def test_field_path_stale(self):
        v=self.view();r=next(r for r in v['results'] if r['path']=='Player.Next->.HP')
        p=self.suite.preview({'pid':123,'items':[dict(r,view_id=v['view_id'],value='3')]})
        self.s.mem[0x1028:0x1030]=struct.pack('<Q',0x5000)
        with self.assertRaises(ValueError):self.suite.apply(p['id'])
        self.assertEqual(self.s.writes,0)
    def test_readonly_field_cannot_edit(self):
        d=[{'name':'P','size':4,'fields':[{'name':'HP','offset':0,'type':'uint32','readonly':True}]}]
        v=self.suite.view({'pid':123,'address':'0x1000','definitions':d,'schema':'P'})
        with self.assertRaises(ValueError):self.suite.preview({'pid':123,'items':[dict(v['results'][0],view_id=v['view_id'],value='4')]})
    def test_partial_write_journal(self):
        self.s.readonly=True;p=self.preview();r=self.suite.apply(p['id'])
        self.assertFalse(r['success']);self.assertEqual(self.suite.journal.list()[0]['status'],'failed')
    def test_timeline_exact_values_and_compare(self):
        key=self.suite.timeline_create({'pid':123,'items':[{'address':'0x1000','type':'uint32','width':4,'name':'HP'}]})['id']
        self.suite.sample(key);self.s.mem[0x1000:0x1004]=struct.pack('<I',999);self.suite.timelines[key]['last']=0
        t=self.suite.sample(key);self.assertEqual(t['samples'][-1]['values'][0]['value'],'999')
        c=self.suite.timeline_compare({'id':key,'a':1,'b':2});self.assertTrue(c['results'][0]['changed_offsets'])
    def test_timeline_identity_and_rate(self):
        key=self.suite.timeline_create({'pid':123,'items':[{'address':'0x1000','type':'uint32','width':4}]})['id'];self.suite.sample(key)
        with self.assertRaises(ValueError):self.suite.sample(key)
    def test_timeline_read_never_holds_global_workspace_lock(self):
        key=self.suite.timeline_create({'pid':123,'items':[{'address':'0x1000','type':'uint32','width':4}]})['id']
        entered=threading.Event();original=self.s.read_bytes
        def read(*args):
            entered.set()
            with self.s.driver._lock:return original(*args)
        self.s.read_bytes=read;results=[]
        with self.s.driver._lock:
            t=threading.Thread(target=lambda:results.append(self.suite.sample(key)));t.start();self.assertTrue(entered.wait(1))
            acquired=self.suite.lock.acquire(timeout=.2)
            if acquired:self.suite.lock.release()
        t.join(2);self.assertTrue(acquired,'workspace/driver lock inversion');self.assertEqual(len(results),1)
        self.suite.timelines[key]['last']=0;self.s.key='other'
        with self.assertRaises(ValueError):self.suite.sample(key)
    def test_address_identity_rebinding(self):
        self.assertEqual(self.suite.resolve(123,{'address':'0x1000','identity':'original','offsets':[0]}),845)
        self.s.key='new'
        with self.assertRaises(ValueError):self.suite.resolve(123,{'address':'0x1000','identity':'original'})
    def test_archive_path_traversal(self):
        with self.assertRaises(ValueError):self.suite.journal.archive(['../x'])
    def test_copy_and_released_allocation_journal(self):
        s=Studio();s.driver._lock=threading.RLock();s.allocations={'123:0x3000':{'pid':123,'size':4096}}
        s.mem[0x1000:0x1004]=struct.pack('<I',845)
        def copied(sp,sa,dp,da,n):s.mem[da:da+n]=s.mem[sa:sa+n];return {'success':True,'bytes_copied':n}
        s.driver.copy_process_memory=copied;s.driver.free_virtual_memory=lambda *args:{'success':True}
        suite=Suite(s,Path(self.tmp.name)/'copy')
        s.driver.copy_process_memory(123,0x1000,123,0x3000,4)
        r=suite.journal.list()[0];self.assertEqual(r['status'],'verified');self.assertIn('/ copy',r['source'])
        s.driver.free_virtual_memory(123,0x3000)
        with self.assertRaisesRegex(ValueError,'해제'):suite.journal.restore(r['id'])
    def test_persistent_schemas(self):
        self.suite.save_schemas({'definitions':DEFS});self.assertEqual(json.loads((Path(self.tmp.name)/'structures.json').read_text())[-1]['name'],'Player')
    def test_project_sqlite_backup_closes_connections_and_next_resumes(self):
        class Images:
            def images(self,pid):return {'results':[]}
        self.s.workbench=Images();self.s.scans=scan_workspace.Workspace(self.s)
        try:
            sid=self.s.scans.create(123)['session_id'];session=self.s.scans.sessions[sid]
            cfg=scan_workspace.validate({'data_type':'aob','condition':'exact','value':'4D 03 00 00','start_address':'0x1000','end_address':'0x1040','max_bytes':4096})
            session.cfg=cfg;session.round=1;session.count=0
            key=self.suite.timeline_create({'pid':123,'items':[{'address':'0x1000','type':'uint32','width':4}]})['id'];timeline=self.suite.sample(key)
            r=self.suite.project_save({'pid':123,'name':'Test','state':{'suite':{'timeline':timeline},'scan':{'session':sid},'definitions':DEFS,'addresses':[{'key':'memory','address':'0x1000'},{'key':'timeline:0','address':'0x1000'}]}})['project']
            self.assertTrue((self.suite.root/r['id']/'scan.sqlite').is_file())
            # Windows rename and deletion fail if the backup leaves a SQLite handle open.
            self.s.scans.remove(sid)
            loaded=self.suite.project_load({'id':r['id'],'pid':123});restored=self.s.scans.sessions[loaded['state']['scan']['session']]
            self.assertEqual(loaded['timeline']['samples'][0]['values'][0]['value'],'845')
            self.assertEqual(restored.cfg['pattern'],b'\x4d\x03\x00\x00');self.assertEqual(restored.round,1)
            self.s.scans.remove(restored.id)
        finally:self.s.scans.shutdown()

class SchedulingTests(unittest.TestCase):
    def driver(self):
        class D:
            def __init__(self):self._lock=threading.RLock();self.reads=0
            def read_process_memory_snapshot(self,*args):
                with self._lock:self.reads+=1;time.sleep(.04);return {'success':True,'data_hex':'ab'}
            def write_process_memory(self,*args):return {'success':True}
            copy_process_memory=free_virtual_memory=protect_virtual_memory=alloc_virtual_memory=write_process_memory
        return D()
    def test_inflight_read_sharing(self):
        d=self.driver();s=Scheduler(d);barrier=threading.Barrier(6);values=[]
        def run():
            with scope(2):barrier.wait();values.append(d.read_process_memory_snapshot(1,4096,1))
        threads=[threading.Thread(target=run) for _ in range(6)]
        for t in threads:t.start()
        for t in threads:t.join(2)
        self.assertEqual(d.reads,1);self.assertEqual(len(values),6);self.assertEqual(s.stats()['coalesced_reads'],5)
    def test_manual_read_fresh(self):
        d=self.driver();s=Scheduler(d)
        d.read_process_memory_snapshot(1,4096,1);d.read_process_memory_snapshot(1,4096,1)
        self.assertEqual(d.reads,2)
    def test_priority_and_reentrancy(self):
        lock=PriorityLock();order=[];lock.acquire()
        def run(value):
            with scope(value),lock:order.append(value)
        bg=threading.Thread(target=run,args=(2,));manual=threading.Thread(target=run,args=(0,));bg.start();manual.start()
        deadline=time.monotonic()+1
        while len(lock.waiters)<2 and time.monotonic()<deadline:time.sleep(.001)
        with lock:self.assertTrue(lock._is_owned())
        lock.release();bg.join(2);manual.join(2);self.assertEqual(order,[0,2])
    def test_lock_timeout(self):
        lock=PriorityLock();lock.acquire();r=[]
        t=threading.Thread(target=lambda:r.append(lock.acquire(timeout=.01)));t.start();t.join(1);lock.release();self.assertEqual(r,[False]);self.assertFalse(lock.waiters)

if __name__=='__main__':unittest.main()
