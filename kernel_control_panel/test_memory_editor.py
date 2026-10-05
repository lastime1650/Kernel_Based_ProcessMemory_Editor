import struct
import unittest
from memory_editor import Workspace, encode


class Driver:
    def __init__(self, studio): self.s=studio
    def query_process_extended(self,pid): return {'success':True,'is_wow64':self.s.wow64}
    def write_process_memory(self,pid,address,data):
        if self.s.readonly: return {'success':False,'bytes_written':0}
        self.s.mem[address:address+len(data)]=data
        self.s.writes+=1
        return {'success':True,'bytes_written':len(data)}


class Studio:
    def __init__(self):
        self.mem=bytearray(0x20000);self.key='original';self.wow64=False
        self.writes=0;self.readonly=False;self.badpage=None;self.protocol=False
        self.driver=Driver(self);self.reads=[]
    def identity(self,pid): return self.key
    def operate(self,op,body):
        return {'results':[{'address':'0x1000','allocation_base':'0x1000','image_base':'0x0',
                'size':0x1F000,'type':'0x20000','readable':True,'guarded':False,'image_name':''}]}
    def read_bytes(self,pid,address,size):
        self.reads.append((address,size))
        if self.protocol: raise ValueError('읽기 크기 불일치')
        if self.badpage is not None and address<=self.badpage<address+size: raise ValueError('읽기 실패')
        return bytes(self.mem[address:address+size])


class EditorTests(unittest.TestCase):
    def setUp(self):
        self.s=Studio();self.ws=Workspace(self.s)
        self.s.mem[0x1000:0x1008]=struct.pack('<Q',0x3000)
        self.s.mem[0x3000:0x3008]=struct.pack('<Q',0x5000)
        self.p=self.ws.create({'pid':123,'address':'0x1000','size':128})
        self.session=self.ws.sessions[self.p['id']]
    def call(self,action,**body): return self.ws.invoke(self.p['id'],action,body)
    def expand(self,node=None,offset=0,expected='0x3000'):
        return self.call('expand',node=node or self.p['root'],offset=offset,expected=expected)
    def test_precise_integer_codec(self):
        self.assertEqual(encode('uint64','9007199254742137',64),struct.pack('<Q',9007199254742137))
        self.assertEqual(encode('int64','-9007199254741997',64),struct.pack('<q',-9007199254741997))
    def test_limits_and_invalid_values(self):
        for kind,value in [('byte','A'),('byte','GG'),('uint8','256'),('int8','-129'),('float32','nan')]:
            with self.subTest(kind=kind,value=value), self.assertRaises(ValueError): encode(kind,value,64)
    def test_page_aligned_partial_snapshot(self):
        self.s.badpage=0x2000
        p=self.ws.create({'pid':123,'address':'0x1FF8','size':16})
        valid=bytes.fromhex(p['nodes'][0]['valid_hex'])
        self.assertEqual(valid[:8],b'\x01'*8);self.assertEqual(valid[8:],bytes(16))
        self.assertIn((0x1FF8,8),self.s.reads)
    def test_protocol_error_not_hole(self):
        self.s.protocol=True
        with self.assertRaisesRegex(ValueError,'크기 불일치'): self.call('refresh')
    def test_nested_pointer_and_toggle(self):
        p=self.expand();child=p['nodes'][1]['id']
        p=self.expand(child,expected='0x5000');self.assertEqual(len(p['nodes']),3)
        p=self.expand();self.assertEqual(len(p['nodes']),1)
    def test_cycle_to_ancestor_window(self):
        p=self.expand();child=p['nodes'][1]['id'];self.s.mem[0x3000:0x3008]=struct.pack('<Q',0x1040)
        with self.assertRaisesRegex(ValueError,'순환'): self.expand(child,expected='0x1040')
    def test_changed_pointer_removes_child(self):
        self.expand();self.s.mem[0x1000:0x1008]=struct.pack('<Q',0x7000)
        p=self.call('refresh');self.assertEqual(len(p['nodes']),1)
    def test_stale_child_write_rejected(self):
        p=self.expand();child=p['nodes'][1]['id'];self.s.mem[0x1000:0x1008]=struct.pack('<Q',0x7000)
        with self.assertRaisesRegex(ValueError,'포인터가 변경'): self.call('edit',node=child,offset=16,kind='byte',value='AB',expected_hex='00')
        self.assertEqual(self.s.writes,0)
    def test_owner_reuse_rejected(self):
        self.s.key='reused'
        with self.assertRaisesRegex(ValueError,'교체'): self.call('refresh')
    def test_stale_expected_byte_rejected(self):
        with self.assertRaisesRegex(ValueError,'현재 바이트'): self.call('edit',node=self.p['root'],offset=16,kind='byte',value='FF',expected_hex='AA')
        self.assertEqual(self.s.writes,0)
    def test_write_and_restore(self):
        p=self.call('edit',node=self.p['root'],offset=16,kind='uint32',value='100',expected_hex='00000000')
        self.assertEqual(self.s.mem[0x1010:0x1014],struct.pack('<I',100));self.assertEqual(p['history_count'],1)
        self.call('restore');self.assertEqual(self.s.mem[0x1010:0x1014],bytes(4))
    def test_restore_conflict(self):
        self.call('edit',node=self.p['root'],offset=16,kind='byte',value='FF',expected_hex='00')
        self.s.mem[0x1010]=123
        with self.assertRaisesRegex(ValueError,'값이 변경'): self.call('restore')
    def test_slide_keeps_origin_and_child_address(self):
        self.s.mem[0x1010:0x1018]=struct.pack('<Q',0x3000)
        p=self.expand(offset=16);child=p['nodes'][1]
        p=self.call('slide',delta=8)
        self.assertEqual(p['origin'],'0x1000');self.assertEqual(p['nodes'][0]['base'],'0x1008')
        self.assertEqual(p['nodes'][1]['id'],child['id']);self.assertEqual(p['nodes'][1]['source'],8)
    def test_group_collapses_children(self):
        self.expand();p=self.call('group',group=4);self.assertEqual(p['group'],4);self.assertEqual(len(p['nodes']),1)
    def test_byte_changes_highlight(self):
        self.s.mem[0x1010]=0xAB;p=self.call('refresh');self.assertIn(16,p['nodes'][0]['changed'])
    def test_wow64_pointer_width(self):
        self.s.wow64=True;p=self.ws.create({'pid':123,'address':'0x1000'})
        self.assertEqual(p['bits'],32);self.assertEqual(p['nodes'][0]['pointers']['0']['address'],'0x3000')
    def test_bounds(self):
        for size in (0,15,65537):
            with self.assertRaises(ValueError): self.ws.create({'pid':123,'address':'0x1000','size':size})
        with self.assertRaises(ValueError): self.call('refresh',nodes=list(range(17)))
    def test_readonly_write_rejection(self):
        self.s.readonly=True
        with self.assertRaisesRegex(ValueError,'쓰기 실패'): self.call('edit',node=self.p['root'],offset=16,kind='byte',value='FF',expected_hex='00')
        self.assertEqual(len(self.session.history),1)
    def test_partial_write_can_restore_observed_bytes(self):
        def partial(pid,address,data):
            self.s.mem[address:address+2]=data[:2]
            return {'success':False,'bytes_written':2}
        self.s.driver.write_process_memory=partial
        with self.assertRaisesRegex(ValueError,'부분 쓰기'):
            self.call('edit',node=self.p['root'],offset=16,kind='uint32',value='4294967295',expected_hex='00000000')
        self.s.driver.write_process_memory=Driver(self.s).write_process_memory
        self.call('restore');self.assertEqual(self.s.mem[0x1010:0x1014],bytes(4))
    def test_name_survives_refresh(self):
        self.call('name',name='Hero')
        p=self.call('refresh');self.assertEqual(p['nodes'][0]['name'],'Hero')
    def test_session_count_bounded(self):
        for i in range(31): self.ws.create({'pid':123,'address':'0x1000'})
        with self.assertRaisesRegex(ValueError,'상한'): self.ws.create({'pid':123,'address':'0x1000'})
    def test_architecture_failure_stops_open(self):
        self.s.driver.query_process_extended=lambda pid: {'success':False}
        with self.assertRaisesRegex(ValueError,'아키텍처'): self.ws.create({'pid':123,'address':'0x1000'})
    def test_close_rejects_requests_that_already_obtained_session_reference(self):
        self.ws.remove(self.p['id'])
        with self.assertRaisesRegex(ValueError,'닫혔'): self.session.invoke('refresh',{})
    def test_odd_window_size_preserves_legacy_manual_size_entry(self):
        p=self.ws.create({'pid':123,'address':'0x1001','size':17})
        self.assertEqual(p['size'],17)
        self.assertEqual(len(bytes.fromhex(p['nodes'][0]['data_hex'])),25)
    def test_ansi_uses_legacy_windows_decoder_and_stops_at_window_end(self):
        self.s.mem[0x1000:0x1004]=b'ABC\x00'
        p=self.ws.create({'pid':123,'address':'0x1000','size':17,'group':4})
        self.assertEqual(p['nodes'][0]['ansi']['0'],'ABC·')
        self.assertEqual(len(p['nodes'][0]['ansi']['16']),1)


if __name__=='__main__': unittest.main()
