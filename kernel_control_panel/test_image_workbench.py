"""Actual PE/DIA analysis with simulated target IO; no live injection here."""
import ctypes
import json
from pathlib import Path
import struct
import tempfile
import threading
import unittest

import driver_bridge as D
from image_workbench import Workbench,Symbols,number

FIXTURE=Path(__file__).parent.parent/'samples/PanelHello.dll'
if not FIXTURE.is_file():FIXTURE=Path(r'C:\Users\Administrator\Documents\Codex\2026-10-03\c-users-administrator-source-repos-samplekernel1\work\dll-workbench\PanelHello.dll')

def mapped_image():
    raw=FIXTURE.read_bytes();pe=struct.unpack_from('<I',raw,60)[0];opt=pe+24
    size=struct.unpack_from('<I',raw,opt+56)[0];header=struct.unpack_from('<I',raw,opt+60)[0]
    data=bytearray(size);data[:header]=raw[:header]
    count=struct.unpack_from('<H',raw,pe+6)[0];optional=struct.unpack_from('<H',raw,pe+20)[0]
    for i in range(count):
        _,rva,rawsize,fileoffset=struct.unpack_from('<IIII',raw,opt+optional+i*40+8)
        data[rva:rva+rawsize]=raw[fileoffset:fileoffset+rawsize]
    return data

class Driver:
    def __init__(self):self._lock=threading.RLock();self.calls=[];self.version=2;self.wow=False;self.created=True;self.completed=False
    def get_driver_status(self):return {'success':True,'major_version':2,'minor_version':self.version}
    def query_process_extended(self,pid):return {'success':True,'is_wow64':self.wow}
    def create_function_call(self,pid,key,address,parameter,wait):
        self.calls.append((pid,key,address,parameter,wait))
        return {'success':True,'thread_created':self.created,'call_id':'1','thread_id':123,'completed':self.completed,'exit_value':None}
    def query_function_call(self,key,wait):return {'success':True,'pid':88,'process_start_key':'999','call_id':str(key),
        'completed':True,'thread_created':True,'exit_value':259,'exit_status':'0x00000103'}
    def release_function_call(self,key):self.calls.append(('release',key));return {'success':True}
    def register_dll(self,pid,path):self.calls.append(('load',pid,path));return {'success':False}

class Studio:
    def __init__(self):self.driver=Driver();self.key='999';self.base=0x7FF700000000;self.memory=mapped_image();self.reads=[];self.visible=True
    def identity(self,pid):return self.key
    def read_bytes(self,pid,start,size):
        self.reads.append((pid,start,size))
        if not self.base<=start<self.base+len(self.memory):raise ValueError('unmapped')
        return bytes(self.memory[start-self.base:start-self.base+size])
    def operate(self,operation,args):
        return {'success':True,'results':[{'address':hex(self.base),'allocation_base':hex(self.base),'type':'0x1000000',
            'size':len(self.memory),'image_size':len(self.memory),'image_base':hex(self.base),'image_name':'PanelHello.dll',
            'image_path':'\\Device\\HarddiskVolume3\\PanelHello.dll','main_image':False}] if self.visible else []}

class EmptySymbols:
    def get(self,key):return self.record

class WorkbenchTests(unittest.TestCase):
    def setUp(self):self.studio=Studio();self.symbols=EmptySymbols();self.w=Workbench(self.studio,self.symbols)
    def analysis(self):return self.w.analyze(88,self.studio.base)
    def hello(self,result):return next(r for r in result['results'] if r['name']=='HelloWorld')
    def test_mem_image_catalog(self):
        result=self.w.images(88);self.assertEqual(result['count'],1);self.assertEqual(result['process_start_key'],'999')
    def test_private_readonly_PE_is_selectable_for_existing_function_analysis(self):
        old=self.studio.operate
        def private(operation,args):
            result=old(operation,args)
            for region in result['results']:
                region.update(type='0x20000',state='0x1000',protect='0x2',readable=True,guarded=False,
                              image_base='0x0',image_size=0,image_name='',image_path='',main_image=False)
            return result
        self.studio.operate=private
        result=self.analysis();self.assertEqual(result['image']['source'],'PE_HEADER')
        self.assertEqual(result['image']['name'],'PanelHello.dll');self.assertTrue(self.hello(result))
        self.assertFalse(self.studio.driver.calls)
    def test_same_basename_from_another_directory_does_not_claim_requested_dll_loaded(self):
        result=self.w.load(88,str(FIXTURE),0)
        self.assertFalse(result['loaded']);self.assertFalse(result.get('already_loaded',False))
        self.assertEqual(self.studio.driver.calls[0][0],'load')
    def test_failed_call_history_is_bounded_without_dropping_active_tracking(self):
        result=self.analysis();address=number(self.hello(result)['address'])
        self.w.call(88,result['analysis_id'],address)
        self.studio.driver.create_function_call=lambda *a:{'success':False,'call_id':'0','thread_created':False}
        for _ in range(140):self.w.call(88,result['analysis_id'],address)
        self.assertEqual(len(self.w.calls),128)
        self.assertTrue(any(r['call_id']=='1' for r in self.w.calls.values()))
    def test_large_unwind_directory_returns_bounded_table_instead_of_rejecting_image(self):
        from unittest.mock import patch
        with patch('image_workbench.MAX_FUNCTIONS',4):
            result=self.analysis()
        self.assertTrue(result['truncated']);self.assertLessEqual(result['count'],4)
    def test_export_unwind_private_functions_and_data_exports(self):
        result=self.analysis();self.assertIn('export',self.hello(result)['sources'])
        self.assertTrue(any(r['name'].startswith('sub_') for r in result['results']))
        self.assertTrue(any(r['name']=='g_HelloResult' for r in result['data_exports']))
        self.assertFalse(any(r['name']=='g_HelloResult' for r in result['results']))
    def test_pdb_guid_and_age_mismatch_rejected(self):
        result=self.analysis();self.symbols.record={'guid':'bad','age':1,'functions':[]}
        with self.assertRaisesRegex(ValueError,'GUID'):self.w.analyze(88,self.studio.base,'pdb')
        self.symbols.record={'guid':result['codeview']['guid'],'age':result['codeview']['age']+1,'functions':[]}
        with self.assertRaisesRegex(ValueError,'GUID'):self.w.analyze(88,self.studio.base,'pdb')
    def test_pdb_name_types_and_known_incompatible_signature(self):
        result=self.analysis();rva=number(self.hello(result)['rva'])
        self.symbols.record={**result['codeview'],'functions':[{'rva':rva,'size':1,'name':'ActualPrivateName','source':'pdb_function',
            'types_available':True,'parameters':[{'name':'value','type':'double','kind':'float','size':8}],
            'return':{'type':'double','kind':'float','size':8}}]}
        result=self.w.analyze(88,self.studio.base,'pdb');row=next(r for r in result['results'] if r['name']=='ActualPrivateName')
        self.assertEqual(row['parameter_source'],'pdb');self.assertFalse(row['call_compatible'])
        with self.assertRaisesRegex(ValueError,'인자'):self.w.call(88,result['analysis_id'],number(row['address']))
        self.assertFalse(self.studio.driver.calls)
    def test_capstone_reads_memory_and_displays_argument_hint(self):
        result=self.analysis();row=self.hello(result);detail=self.w.detail(result['analysis_id'],number(row['address']),88)
        self.assertTrue(detail['results']);self.assertIn('추정',detail['note']);self.assertTrue(self.studio.reads)
        self.assertEqual(detail['source'],'kernel_memory')
        self.assertTrue(detail['graph']['nodes']);self.assertIn('code',detail['pseudocode'])
    def test_detail_obeys_known_function_size_and_does_not_label_guessed_signature_as_pdb(self):
        result=self.analysis();row=self.hello(result);row['size']=4;row['signature']='guessed signature';row['parameter_source']='unknown'
        detail=self.w.detail(result['analysis_id'],number(row['address']),88)
        self.assertEqual(self.studio.reads[-1],(88,number(row['address']),4))
        self.assertEqual(detail['read_bytes'],4);self.assertTrue(detail['graph']['range_known'])
        self.assertNotIn('pdb_signature',detail['pseudocode'])
    def test_detail_rejects_pid_reuse_during_code_read(self):
        result=self.analysis();row=self.hello(result);target=number(row['address']);original=self.studio.read_bytes
        def replaced(pid,start,size):
            raw=original(pid,start,size)
            if start==target:self.studio.key='replacement'
            return raw
        self.studio.read_bytes=replaced
        with self.assertRaisesRegex(ValueError,'교체'):self.w.detail(result['analysis_id'],target,88)
    def test_single_word_parameter_preserved(self):
        result=self.analysis();row=self.hello(result);reply=self.w.call(88,result['analysis_id'],number(row['address']),0xffffffffffffffff)
        self.assertEqual(self.studio.driver.calls[-1][3],0xffffffffffffffff);self.assertEqual(reply['parameter'],'0xFFFFFFFFFFFFFFFF')
    def test_wrong_pid_pid_reuse_changed_header_and_unmapped_image_rejected(self):
        result=self.analysis();row=self.hello(result);args=(88,result['analysis_id'],number(row['address']))
        with self.assertRaises(ValueError):self.w.call(99,result['analysis_id'],number(row['address']))
        self.studio.key='1000'
        with self.assertRaises(ValueError):self.w.call(*args)
        self.studio.key='999';self.studio.memory[65]^=1
        with self.assertRaises(ValueError):self.w.call(*args)
        self.studio.memory[65]^=1;self.studio.visible=False
        with self.assertRaises(ValueError):self.w.call(*args)
        self.assertFalse(self.studio.driver.calls)
    def test_old_driver_rejected_without_create(self):
        result=self.analysis();self.studio.driver.version=1
        with self.assertRaisesRegex(ValueError,'2.2'):self.w.call(88,result['analysis_id'],number(self.hello(result)['address']))
        self.assertFalse(self.studio.driver.calls)
    def test_arbitrary_address_or_data_export_cannot_be_called(self):
        result=self.analysis()
        with self.assertRaises(ValueError):self.w.call(88,result['analysis_id'],self.studio.base+1)
    def test_call_query_and_release_keep_original_identity(self):
        result=self.analysis();call=self.w.call(88,result['analysis_id'],number(self.hello(result)['address']))
        self.studio.key='new-process';reply=self.w.query_call(call['id'],88);self.assertTrue(reply['completed']);self.assertEqual(reply['exit_value'],259)
        self.assertTrue(self.w.release_call(call['id'],88)['released'])
    def test_failed_query_preserves_owner_and_thread_reference_for_release(self):
        result=self.analysis();call=self.w.call(88,result['analysis_id'],number(self.hello(result)['address']))
        self.studio.driver.query_function_call=lambda *a:{'success':False,'pid':0,'process_start_key':'0',
            'thread_id':0,'thread_created':False,'call_id':'0','completed':False,'execution_unknown':True,'error_code':6}
        reply=self.w.query_call(call['id'],88)
        self.assertEqual((reply['pid'],reply['thread_id'],reply['call_id']),(88,123,'1'))
        self.assertTrue(reply['thread_created']);self.assertTrue(reply['query_error'])
        self.assertTrue(self.w.release_call(call['id'],88)['released'])
        self.assertTrue(self.w.release_call(call['id'],88)['success'])
    def test_call_records_released_on_shutdown(self):
        result=self.analysis();self.w.call(88,result['analysis_id'],number(self.hello(result)['address']))
        self.w.shutdown();self.assertIn(('release',1),self.studio.driver.calls)
    def test_wow64_loader_rejected_before_injection(self):
        self.studio.driver.wow=True
        with self.assertRaises(ValueError):self.w.load(88,FIXTURE,0)
        self.assertFalse(self.studio.driver.calls)
    def test_failed_loader_is_not_retried(self):
        self.studio.visible=False;result=self.w.load(88,FIXTURE,0)
        self.assertFalse(result['success']);self.assertEqual(len(self.studio.driver.calls),1)
    def test_local_unknown_tracking_record_can_be_cleared(self):
        self.w.calls['x']={'id':'x','pid':88,'call_id':'0','released':False}
        self.assertTrue(self.w.release_call('x',88)['released']);self.assertFalse(self.studio.driver.calls)

class BridgeProtocolTests(unittest.TestCase):
    def test_exact_abi_and_all_uint64_bits(self):
        self.assertEqual((ctypes.sizeof(D.CREATE_FUNCTION_CALL_REQUEST),ctypes.sizeof(D.QUERY_FUNCTION_CALL_REQUEST),ctypes.sizeof(D.RELEASE_FUNCTION_CALL_REQUEST)),(88,96,24))
        b=object.__new__(D.KernelDriverBridge);packets=[]
        def ioctl(code,r):
            packets.append(r.Parameter);r.CallId=2;r.ThreadCreated=1;r.ThreadId=55;r.ResultStatus=0
            return True,0,ctypes.sizeof(r)
        b.send_ioctl=ioctl
        result=b.create_function_call(88,999,0x7ff700001000,0xffffffffffffffff)
        self.assertTrue(result['success']);self.assertEqual(packets,[0xffffffffffffffff])
    def test_transport_failure_and_short_packet_are_unknown_execution(self):
        b=object.__new__(D.KernelDriverBridge);b.send_ioctl=lambda *a:(False,6,0)
        reply=b.create_function_call(88,999,0x7ff700001000);self.assertFalse(reply['success']);self.assertTrue(reply['execution_unknown'])
        b.send_ioctl=lambda *a:(True,0,4)
        reply=b.create_function_call(88,999,0x7ff700001000);self.assertTrue(reply['execution_unknown']);self.assertFalse(reply['packet_valid'])

class NativePdbTests(unittest.TestCase):
    def test_pdb_save_failure_rolls_back_cache_and_preserves_original_file(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            symbols=Symbols(root)
            with patch.object(symbols,'persist',side_effect=OSError('disk full')):
                with self.assertRaises(OSError):symbols.load(FIXTURE.with_suffix('.pdb'))
            self.assertFalse(symbols.cache);self.assertFalse(list(Path(root).glob('*.json')))
            self.assertTrue(FIXTURE.with_suffix('.pdb').is_file())
    def test_one_corrupt_pdb_cache_does_not_hide_other_saved_records(self):
        with tempfile.TemporaryDirectory() as root:
            symbols=Symbols(root);result=symbols.load(FIXTURE.with_suffix('.pdb'))
            bad='f'*32;(Path(root)/(bad+'.json')).write_text('{broken',encoding='utf-8')
            (Path(root)/'index.json').write_text(json.dumps([bad,result['id']]),encoding='utf-8')
            self.assertEqual(Symbols(root).list()[0]['id'],result['id'])
    def test_real_dia_signatures_private_function_and_cache_restore(self):
        with tempfile.TemporaryDirectory() as root:
            symbols=Symbols(root);result=symbols.load(FIXTURE.with_suffix('.pdb'))
            record=symbols.get(result['id']);hello=next(r for r in record['functions'] if r['name']=='HelloWorld')
            self.assertEqual(hello['parameters'][0]['type'],'void*');self.assertEqual(hello['return']['size'],4)
            self.assertTrue(any(r['name']=='InternalFormat' for r in record['functions']))
            restored=Symbols(root);self.assertEqual(restored.list()[0]['guid'],result['guid'])
            self.assertTrue(restored.remove(result['id']));self.assertTrue(FIXTURE.with_suffix('.pdb').is_file())

if __name__=='__main__':unittest.main()
