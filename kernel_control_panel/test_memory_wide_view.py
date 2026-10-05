import struct
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from memory_editor import Workspace as Editors
from memory_wide_view import Workspace
from test_memory_editor import Studio


class Tests(unittest.TestCase):
    def setUp(self):
        self.s=Studio();self.s.suite=SimpleNamespace(lock=threading.RLock(),schemas=[
            {'name':'Item','size':8,'fields':[{'name':'Value','offset':0,'type':'uint32'}]},
            {'name':'Hero','size':64,'fields':[{'name':'HP','offset':0,'type':'uint32'},
             {'name':'Items','offset':8,'type':'struct','ref':'Item','count':2,'stride':8},
             {'name':'Name','offset':32,'type':'utf8','length':16}]}])
        self.ws=Workspace(self.s)
    def create(self,**args):return self.ws.create(dict(pid=123,address='0x1000',size=256,**args))
    def test_snapshot_map_and_exact_visible_read(self):
        self.s.mem[0x1000:0x1004]=struct.pack('<I',845);p=self.create()
        self.assertEqual(p['size'],256);self.assertEqual(len(p['data_hex']),512)
        self.assertEqual(self.s.reads,[(0x1000,256)]);self.assertEqual(p['data_hex'][:8],'4d030000')
        self.assertEqual(len(p['regions']),1)
    def test_guard_and_unreadable_regions_are_never_touched(self):
        regions=[{'address':'0x1000','size':0x1000,'allocation_base':'0x1000','state':'0x1000','readable':True,'guarded':True},
                 {'address':'0x2000','size':0x1000,'allocation_base':'0x2000','state':'0x1000','readable':False,'guarded':False}]
        with patch.object(self.s,'operate',return_value={'results':regions}):
            p=self.ws.create({'pid':123,'address':'0x1FF0','size':64})
        self.assertFalse(self.s.reads);self.assertEqual(p['valid_hex'],'00'*64)
    def test_cross_page_hole_keeps_valid_neighbor(self):
        self.s.badpage=0x2000;p=self.ws.create({'pid':123,'address':'0x1FF0','size':64})
        self.assertEqual(bytes.fromhex(p['valid_hex']),b'\x01'*16+bytes(48))
        self.assertEqual(self.s.reads,[(0x1FF0,16),(0x2000,48)])
    def test_unallocated_gap_never_issues_kernel_read(self):
        p=self.ws.create({'pid':123,'address':'0xF00','size':512})
        self.assertEqual(self.s.reads,[(0x1000,256)])
        self.assertEqual(bytes.fromhex(p['valid_hex'])[:256],bytes(256))
    def test_map_action_does_not_resample_memory(self):
        p=self.create();self.s.reads.clear();r=self.ws.invoke(p['id'],'map',{})
        self.assertIn('regions',r);self.assertFalse(self.s.reads)
    def test_pid_reuse_and_closed_session_rejected(self):
        p=self.create();self.s.key='other'
        with self.assertRaisesRegex(ValueError,'교체'):self.ws.invoke(p['id'],'read',{})
        self.ws.remove(p['id'])
        with self.assertRaisesRegex(ValueError,'만료'):self.ws.invoke(p['id'],'read',{})
    def test_read_only_and_limits(self):
        p=self.create()
        for action in ('edit','edit_range','restore','write'):
            with self.assertRaisesRegex(ValueError,'읽기'):self.ws.invoke(p['id'],action,{})
        for size in (0,15,4097):
            with self.assertRaises(ValueError):self.ws.invoke(p['id'],'read',{'size':size})
        self.assertEqual(self.s.writes,0)
    def test_schema_nested_array_layout_does_not_read_extra_fields(self):
        p=self.create(schema='Hero',schema_address='0x1000')
        self.assertEqual([r['path'] for r in p['fields']],['Hero.HP','Hero.Items[0].Value','Hero.Items[1].Value','Hero.Name'])
        self.assertEqual(p['fields'][2]['address'],'0x1010');self.assertEqual(self.s.reads,[(0x1000,256)])
    def test_read_protocol_failure_is_not_silently_a_hole(self):
        self.s.protocol=True
        with self.assertRaisesRegex(ValueError,'크기 불일치'):self.create()
    def test_project_local_structure_definitions_are_supported_without_saving_globals(self):
        defs=[{'name':'Local','size':16,'fields':[{'name':'Gold','offset':0,'type':'uint64'}]}]
        p=self.create(schema='Local',definitions=defs)
        self.assertEqual(p['fields'][0]['path'],'Local.Gold');self.assertEqual(p['fields'][0]['width'],8)
        self.assertEqual(len(self.s.suite.schemas),2)
    def test_relocation_reads_new_range_and_refreshes_map_when_due(self):
        p=self.create();s=self.ws.sessions[p['id']];s.map_time-=6;self.s.reads.clear()
        r=self.ws.invoke(p['id'],'read',{'address':'0x3000','size':512})
        self.assertEqual(self.s.reads,[(0x3000,512)]);self.assertEqual(r['address'],'0x3000');self.assertIn('regions',r)
    def test_large_editor_window_only_reads_viewport_and_wheel_slice(self):
        ws=Editors(self.s);p=ws.create({'pid':123,'address':'0x1000','size':65536,'visible_bytes':160})
        self.assertEqual(self.s.reads,[(0x1000,168)])
        self.s.reads.clear();r=ws.invoke(p['id'],'refresh',{'ranges':[{'node':p['root'],'offset':4096,'count':160}]})
        self.assertEqual(self.s.reads,[(0x2000,168)]);valid=bytes.fromhex(r['nodes'][0]['valid_hex'])
        self.assertEqual(sum(valid),168);self.assertEqual(valid[:4096],bytes(4096))
        self.s.reads.clear();ws.invoke(p['id'],'slide',{'delta':-24,'ranges':[{'node':p['root'],'offset':0,'count':160}]})
        self.assertEqual(self.s.reads,[(0xFE8,24),(0x1000,144)])
    def test_invalid_visible_ranges_and_window_sizes_rejected(self):
        ws=Editors(self.s)
        with self.assertRaises(ValueError):ws.create({'pid':123,'address':'0x1000','visible_bytes':4097})
        p=ws.create({'pid':123,'address':'0x1000','size':128,'visible_bytes':128})
        for offset,count in ((-1,16),(0,5000),(127,2)):
            with self.assertRaises(ValueError):ws.invoke(p['id'],'refresh',{'ranges':[{'node':p['root'],'offset':offset,'count':count}]})

if __name__=='__main__':unittest.main()
