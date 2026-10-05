"""Kernel scanning regressions with byte arrays and fake IOCTL responses only."""
import struct
import os
import threading
import unittest
from kernel_scanner import KernelMemoryScannerSession
from kernel_only_bridge import KernelOnlyBridge


class FakeDriver:
    def __init__(self): self.memory=bytearray(4096);self.key=1;self.reads=[];self.fail=False
    def query_process_info(self,pid):return {'success':True,'exit_status':259,'process_start_key':self.key}
    def read_process_memory_snapshot(self,pid,start,size):
        self.reads.append((pid,start,size))
        raw=self.memory[start-0x10000:start-0x10000+size]
        return {'success':not self.fail,'data_hex':raw.hex() if not self.fail else ''}


class KernelScannerTests(unittest.TestCase):
    def setUp(self):
        self.driver=FakeDriver()
        self.regions={'success':True,'truncated':False,'results':[{'address':'0x10000','size':4096,'readable':True,'guarded':False,'writable':True}]}
        self.scanner=KernelMemoryScannerSession(self.driver,lambda pid:self.regions)

    def test_new_next_changed_exact_and_previous_value(self):
        struct.pack_into('<IIII',self.driver.memory,0,10,20,10,30)
        r=self.scanner.first_scan(42,'uint32','exact','10');self.assertEqual(r['count'],2)
        struct.pack_into('<I',self.driver.memory,0,100)
        r=self.scanner.next_scan('changed');self.assertEqual(r['count'],1)
        row=self.scanner.get_results()['results'][0]
        self.assertEqual((row['address'],row['current_value'],row['previous_value']),('0x10000','100','10'))
        self.assertEqual(self.scanner.next_scan('exact','100')['count'],1)
        self.assertTrue(all(size<=4096 for _,_,size in self.driver.reads))

    def test_float_tolerance_and_uint64_precision(self):
        struct.pack_into('<f',self.driver.memory,0,30.123)
        self.assertEqual(self.scanner.first_scan(42,'float32','exact','30.123')['count'],1)
        self.assertEqual(self.scanner.next_scan('unchanged')['count'],1)
        struct.pack_into('<Q',self.driver.memory,0,18446744073709551615)
        self.assertEqual(self.scanner.first_scan(42,'uint64','exact','18446744073709551615')['count'],1)
        self.assertEqual(self.scanner.get_results()['results'][0]['current_value'],'18446744073709551615')

    def test_replaced_owner_stops_before_memory_read(self):
        self.scanner.first_scan(42,'uint32','exact','0',max_results=2);self.driver.reads.clear();self.driver.key=2
        self.assertFalse(self.scanner.next_scan('unchanged')['success']);self.assertEqual(self.driver.reads,[])

    def test_invalid_conditions_ranges_and_truncated_map_fail(self):
        for args in [('uint32','invalid','1',None),('unsupported','exact','1',None),('uint32','between','20','10')]:
            self.assertFalse(self.scanner.first_scan(42,*args)['success'])
        self.regions['truncated']=True
        self.assertFalse(self.scanner.first_scan(42,'uint32','exact','10')['success'])

    def test_read_failures_are_reported_without_fallback(self):
        self.driver.fail=True
        r=self.scanner.first_scan(42,'uint32','exact','10')
        self.assertEqual(r['count'],0);self.assertEqual(r['failed_chunks'],1)

    def test_unaligned_page_seam_and_next_scan(self):
        self.driver.memory=bytearray(8192);self.regions['results'][0]['size']=8192
        struct.pack_into('<I',self.driver.memory,4093,4294812563)
        self.assertEqual(self.scanner.first_scan(42,'uint32','exact','4294812563')['count'],0)
        result=self.scanner.first_scan(42,'uint32','exact','4294812563',alignment=1)
        self.assertEqual(result['count'],1)
        self.assertEqual(self.scanner.get_results()['results'][0]['address'],'0x10FFD')
        struct.pack_into('<I',self.driver.memory,4093,4294812564)
        self.assertEqual(self.scanner.next_scan('increased')['count'],1)
        self.assertTrue(all(count<=4096 for _,_,count in self.driver.reads))

    def test_range_cap_persists_after_next_and_bad_pagination(self):
        result=self.scanner.first_scan(42,'uint32','unknown','',max_results=2,
                                      start_address='0x10008',end_address='0x10020')
        self.assertTrue(result['partial']);self.assertEqual(result['bytes_scanned'],24)
        self.assertEqual(self.scanner.get_results()['results'][0]['address'],'0x10008')
        self.assertTrue(self.scanner.next_scan('unchanged')['partial'])
        self.assertTrue(self.scanner.get_results()['partial'])
        self.assertFalse(self.scanner.get_results(page=0)['success'])
        self.assertFalse(self.scanner.first_scan(42,'uint32','exact','1',alignment=3)['success'])

    def test_failed_page_never_bridges_across_hole(self):
        self.driver.memory=bytearray(12288);self.regions['results'][0]['size']=12288
        real=self.driver.read_process_memory_snapshot
        self.driver.read_process_memory_snapshot=lambda pid,start,size: {'success':False} if start==0x11000 else real(pid,start,size)
        self.driver.memory[4095]=0xAB;self.driver.memory[8192]=0xCD
        result=self.scanner.first_scan(42,'uint16','exact','0xCDAB',alignment=1)
        self.assertEqual(result['count'],0);self.assertEqual(result['failed_chunks'],1)

    def test_caller_snapshot_is_freed_by_driver_request(self):
        bridge = object.__new__(KernelOnlyBridge)
        bridge._lock = threading.RLock()
        bridge.read_process_memory = lambda *args: {'success':True,'dumped_address':'0x20000','data_hex':'0a000000'}
        frees=[]
        bridge.free_virtual_memory = lambda pid,start: frees.append((pid,start)) or {'success':True}
        self.assertEqual(bridge.read_process_memory_snapshot(42,0x10000,4)['data_hex'],'0a000000')
        self.assertEqual(frees,[(os.getpid(),0x20000)])

    def test_snapshot_kernel_free_failure_is_not_hidden(self):
        bridge = object.__new__(KernelOnlyBridge)
        bridge._lock = threading.RLock()
        bridge.read_process_memory = lambda *args: {'success':True,'dumped_address':'0x20000','data_hex':'0a000000'}
        bridge.free_virtual_memory = lambda *args: {'success':False,'result_status':'0xC0000001'}
        with self.assertRaises(RuntimeError): bridge.read_process_memory_snapshot(42,0x10000,4)


if __name__=='__main__':unittest.main(verbosity=2)
