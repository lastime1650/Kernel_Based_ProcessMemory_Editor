import threading
import unittest

from memory_allocation import Workspace, payload, MAX_BYTES


class Driver:
    def __init__(self):
        self._lock=threading.RLock();self.calls=[];self.memory={};self.fail_write=False
        self.fail_free=False;self.partial=False;self.corrupt=False;self.raise_write=False;self.base=0x10000
    def alloc_virtual_memory(self,pid,size,protect):
        self.calls.append(('alloc',pid,size,protect));base=self.base;self.base+=0x10000
        self.memory[base]=bytes(size);return {'success':True,'allocated_address':hex(base)}
    def write_process_memory(self,pid,base,data):
        self.calls.append(('write',pid,base,data))
        if self.raise_write:raise OSError('journal unavailable')
        self.memory[base]=data if not self.corrupt else bytes(len(data))
        return {'success':not self.fail_write,'bytes_written':len(data)-int(self.partial)}
    def free_virtual_memory(self,pid,base):
        self.calls.append(('free',pid,base))
        if not self.fail_free:self.memory.pop(base,None)
        return {'success':not self.fail_free,'result_status':'0xC0000001'}


class Studio:
    def __init__(self):self.lock=threading.RLock();self.driver=Driver();self.allocations={};self.owner='original'
    def identity(self,pid):return self.owner
    def check_owner(self,r):
        if self.identity(r['pid'])!=r['identity']:raise ValueError('process replaced')
    def prune_allocations(self):pass
    def read_bytes(self,pid,base,size):self.driver.calls.append(('read',pid,base,size));return self.driver.memory[base]


class AllocationTests(unittest.TestCase):
    def setUp(self):self.s=Studio();self.w=Workspace(self.s);self.key=self.w.create({'pid':42})['id']
    def alloc(self,**body):return self.w.invoke(self.key,'allocate',dict(kind='string',text='Hello',**body))
    def test_ansi_null_exact(self):
        data,meta=payload({'text':' Hello '});self.assertEqual(data,b' Hello \0');self.assertEqual(meta['size'],8)
    def test_wide_null_exact(self):
        data,meta=payload({'text':'던전😀','encoding':'wide'});self.assertEqual(data,'던전😀\0'.encode('utf-16le'));self.assertEqual(meta['terminator_bytes'],2)
    def test_unrepresentable_ansi_does_not_silently_replace_character(self):
        # Windows ACP can be UTF-8. Only require rejection if its round trip is lossy.
        value='😀';round_trip=value.encode('mbcs',errors='replace').decode('mbcs',errors='replace')
        if round_trip==value:self.assertEqual(payload({'text':value})[0],value.encode('mbcs')+b'\0')
        else:
            with self.assertRaises(ValueError):self.w.invoke(self.key,'allocate',{'text':value})
            self.assertFalse(self.s.driver.calls)
    def test_file_exact_and_zero_bytes_allowed(self):
        data,meta=payload({'kind':'file','data_hex':'0001ff00','filename':'fixture.bin'});self.assertEqual(data,b'\0\1\xff\0');self.assertEqual(meta['terminator_bytes'],0)
    def test_empty_whitespace_nul_and_empty_file_rejected(self):
        for body in ({'text':''},{'text':' \t\r\n'},{'text':'\x00 '},{'kind':'file','data_hex':''}):
            with self.subTest(body=body),self.assertRaises(ValueError):self.w.invoke(self.key,'allocate',body)
        self.assertEqual(self.s.driver.calls,[])
    def test_over_limit_and_malformed_payload_rejected_before_allocate(self):
        for body in ({'text':'x'*MAX_BYTES},{'kind':'file','data_hex':'00'*(MAX_BYTES+1)},
                     {'kind':'file','data_hex':'0x00'},{'kind':'file','data_hex':'0'},
                     {'text':'ok','encoding':'other'},{'kind':'invalid'}):
            with self.subTest(kind=body.get('kind')),self.assertRaises(ValueError):self.w.invoke(self.key,'allocate',body)
        self.assertEqual(self.s.driver.calls,[])
    def test_user_base_rejected(self):
        with self.assertRaises(ValueError):self.alloc(base_address='0x2000')
        self.assertFalse(self.s.driver.calls)
    def test_allocated_record_kernel_address_size_and_verified(self):
        r=self.alloc();row=r['records'][0];self.assertEqual(row['base_address'],'0x10000');self.assertEqual(row['size'],6)
        self.assertTrue(row['verified']);self.assertEqual(row['status'],'allocated');self.assertEqual(self.s.driver.calls[0],('alloc',42,6,4))
    def test_list_retained_and_free_base_only(self):
        r=self.alloc();self.assertEqual(self.w.invoke(self.key,'list',{})['records'],r['records'])
        r=self.w.invoke(self.key,'free',{'base_address':'0x10000'});self.assertEqual(r['records'][0]['status'],'freed');self.assertFalse(self.s.allocations)
    def test_unknown_or_double_free_rejected(self):
        with self.assertRaises(ValueError):self.w.invoke(self.key,'free',{'base_address':'0x10000'})
        self.alloc();self.w.invoke(self.key,'free',{'base_address':'0x10000'})
        with self.assertRaises(ValueError):self.w.invoke(self.key,'free',{'base_address':'0x10000'})
        self.assertEqual(sum(c[0]=='free' for c in self.s.driver.calls),1)
    def test_failed_free_keeps_record(self):
        self.alloc();self.s.driver.fail_free=True
        with self.assertRaises(ValueError):self.w.invoke(self.key,'free',{'base_address':'0x10000'})
        self.assertEqual(self.w.invoke(self.key,'list',{})['records'][0]['status'],'allocated');self.assertTrue(self.s.allocations)
    def test_partial_write_rollback(self):
        self.s.driver.partial=True;r=self.alloc();self.assertFalse(r['success']);self.assertFalse(r['cleanup_required']);self.assertEqual(r['records'][0]['status'],'rolled_back');self.assertFalse(self.s.allocations)
    def test_failed_write_rollback(self):
        self.s.driver.fail_write=True;r=self.alloc();self.assertFalse(r['success']);self.assertEqual(r['records'][0]['status'],'rolled_back')
    def test_verification_mismatch_rollback(self):
        self.s.driver.corrupt=True;r=self.alloc();self.assertFalse(r['success']);self.assertFalse(self.s.driver.memory)
    def test_exception_rollback(self):
        self.s.driver.raise_write=True;r=self.alloc();self.assertFalse(r['success']);self.assertFalse(self.s.driver.memory)
    def test_cleanup_failure_retains_retryable_address(self):
        self.s.driver.partial=True;self.s.driver.fail_free=True;r=self.alloc();self.assertTrue(r['cleanup_required']);self.assertEqual(r['records'][0]['status'],'needs_free')
        self.s.driver.fail_free=False;r=self.w.invoke(self.key,'free',{'base_address':r['base_address']});self.assertEqual(r['records'][0]['status'],'freed')
    def test_replaced_target_rejected(self):
        self.alloc();self.s.owner='replacement'
        with self.assertRaises(ValueError):self.w.invoke(self.key,'free',{'base_address':'0x10000'})
        self.assertFalse(any(c[0]=='free' for c in self.s.driver.calls))
    def test_reused_allocation_record_rejected(self):
        self.alloc();self.s.allocations['42:0x10000']['reservation_id']='different'
        with self.assertRaises(ValueError):self.w.invoke(self.key,'free',{'base_address':'0x10000'})
    def test_reset_history_does_not_free_memory(self):
        self.alloc();self.w.remove(self.key);new=self.w.create({'pid':42});self.assertEqual(new['records'],[]);self.assertTrue(self.s.driver.memory)
        with self.assertRaises(ValueError):self.w.invoke(new['id'],'free',{'base_address':'0x10000'})
    def test_base_reuse_keeps_prior_freed_history_and_frees_current_size(self):
        self.alloc();self.w.invoke(self.key,'free',{'base_address':'0x10000'})
        self.s.driver.base=0x10000
        r=self.w.invoke(self.key,'allocate',{'text':'reused address'})
        self.assertEqual(len(r['records']),2);self.assertEqual([x['status'] for x in r['records']],['allocated','freed'])
        self.assertEqual(r['records'][0]['size'],15)
        r=self.w.invoke(self.key,'free',{'base_address':'0x10000'})
        self.assertTrue(all(x['status']=='freed' for x in r['records']))
    def test_pid_mismatch_and_session_limit(self):
        with self.assertRaises(ValueError):self.w.invoke(self.key,'allocate',{'pid':43,'text':'x'})
        for _ in range(70):self.w.create({'pid':42})
        self.assertEqual(len(self.w.sessions),64)
    def test_replacement_during_write_cannot_free_new_process(self):
        original=self.s.driver.write_process_memory
        def write(*args):r=original(*args);self.s.owner='replacement';return r
        self.s.driver.write_process_memory=write;r=self.alloc();self.assertFalse(r['success']);self.assertTrue(r['cleanup_required']);self.assertFalse(any(c[0]=='free' for c in self.s.driver.calls))


if __name__=='__main__':unittest.main()
