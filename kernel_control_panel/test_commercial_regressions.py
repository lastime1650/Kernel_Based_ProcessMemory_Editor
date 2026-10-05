"""Bounded maps, ownership, and cleanup with caller-buffer models only."""
import ctypes as C
import threading
import unittest
from unittest.mock import patch
from studio_api import Studio,Node,RegionInfo

class Driver:
    def __init__(self,count=7):
        self._lock=threading.RLock();self.buffers={};self.read_calls=0;self.frees=[];self.first=0x20000
        self.owners={};self.virtual_frees=[]
        for i in range(count):
            node=Node();node.Signature=0x4C4C535448454C50;node.Previous=self.first+(i-1)*128 if i else 0
            node.Next=self.first+(i+1)*128 if i+1<count else 0;node.Data=0x30000+i*4096;node.DataSize=C.sizeof(RegionInfo)
            info=RegionInfo();info.BaseAddress=0x10000+i*65536;info.RegionSize=4096;info.IsReadable=True
            self.buffers[self.first+i*128]=bytes(node);self.buffers[node.Data]=bytes(info)
    def send_ioctl(self,*args):return True,0,0
    def read_process_information_vad(self,pid):self.read_calls+=1;return {'success':True,'result_list_address_int':self.first}
    def free_linked_list(self,first):self.frees.append(first);self.buffers.clear();return {'success':True}
    free_string_list=free_linked_list
    free_hardware_breakpoint_result=free_linked_list
    def query_process_extended(self,pid):return {'success':True,'thread_count':75,'handle_count':329}
    def enumerate_threads(self,pid,limit):return {'success':True,'threads':[{'thread_id':i} for i in range(limit)],'thread_count':limit}
    def query_process_handles(self,pid,limit):return {'success':True,'handles':[{'handle':i} for i in range(limit)],'returned_count':limit}
    def query_process_info(self,pid):return self.owners[pid]
    def free_virtual_memory(self,pid,start):self.virtual_frees.append((pid,start));return {'success':True}

class CommercialTests(unittest.TestCase):
    def setUp(self):
        self.driver=Driver();self.studio=Studio(self.driver)
        self.studio.local_read=lambda pointer,size:self.driver.buffers[pointer][:size]
    def tearDown(self):self.studio.shutdown()
    def test_map_total_retained_with_small_prefix_and_all_buffers_released(self):
        result=self.studio.run('regions',{'pid':42,'max_results':2})
        self.assertEqual((result['total'],len(result['results']),result['truncated']),(7,2,True))
        self.assertEqual(self.driver.frees,[self.driver.first]);self.assertFalse(self.driver.buffers)
    def test_expanded_map_is_complete(self):
        result=self.studio.run('regions',{'pid':42,'max_results':50000})
        self.assertEqual(result['total'],7);self.assertFalse(result['truncated']);self.assertFalse(self.driver.buffers)
    def test_invalid_limit_rejected_before_kernel_allocation(self):
        for limit in (0,50001,-1):self.assertFalse(self.studio.run('regions',{'pid':42,'max_results':limit})['success'])
        self.assertEqual(self.driver.read_calls,0);self.assertEqual(self.driver.frees,[])
    def test_parsed_response_is_released_even_for_invalid_parser_limit(self):
        with self.assertRaises(ValueError):self.studio.parsed_list(self.driver.read_process_information_vad(42),'regions',limit=0)
        self.assertFalse(self.driver.buffers)
    def test_corrupt_node_fails_and_releases_entire_result(self):
        self.driver.buffers[self.driver.first]=bytes(40)
        self.assertFalse(self.studio.run('regions',{'pid':42})['success']);self.assertFalse(self.driver.buffers)
    def test_inline_thread_and_handle_cap_is_visible(self):
        for operation,total,returned in [('threads',75,64),('handles',329,128)]:
            result=self.studio.run(operation,{'pid':42})
            self.assertEqual((result['total'],result['returned_count'],result['truncated']),(total,returned,True))
    def allocation(self,pid,identity='1'):
        self.studio.allocations[f'{pid}:0x40000']={'pid':pid,'identity':identity,'address':'0x40000','size':4096}
    def test_exited_and_recycled_owners_are_discarded_without_target_free(self):
        for pid,response in [(1,{'success':False,'error_code':87,'result_status':'0x00000000'}),
                             (2,{'success':True,'exit_status':0,'process_start_key':1}),
                             (3,{'success':True,'exit_status':259,'process_start_key':2})]:
            self.allocation(pid);self.driver.owners[pid]=response
        result=self.studio.run('snapshot_list',{'pid':42})
        self.assertTrue(result['success']);self.assertEqual(result['expired_allocations_removed'],3)
        self.assertEqual(result['allocations'],[]);self.assertEqual(self.driver.virtual_frees,[])
    def test_live_and_transient_error_owners_are_retained(self):
        for pid,response in [(1,{'success':True,'exit_status':259,'process_start_key':1}),
                             (2,{'success':False,'error_code':5,'result_status':'0xC0000022'}),
                             (3,{'success':False,'error_code':1450,'result_status':'0xC000009A'})]:
            self.allocation(pid);self.driver.owners[pid]=response
        self.assertEqual(self.studio.prune_allocations(),0);self.assertEqual(len(self.studio.allocations),3)
    def test_managed_free_checks_start_key_before_kernel_free(self):
        self.allocation(42);self.driver.owners[42]={'success':True,'exit_status':259,'process_start_key':2}
        self.assertFalse(self.studio.run('free',{'pid':42,'address':'0x40000'})['success'])
        self.assertEqual(self.driver.virtual_frees,[]);self.assertEqual(len(self.studio.allocations),1)
        self.driver.owners[42]['process_start_key']=1
        self.assertTrue(self.studio.run('free',{'pid':42,'address':'0x40000'})['success'])
        self.assertEqual(self.driver.virtual_frees,[(42,0x40000)]);self.assertFalse(self.studio.allocations)
    def test_malformed_legacy_address_is_http400_without_driver_call(self):
        import server
        from test_asgi_client import ASGIClient
        with patch.object(server.driver,'free_virtual_memory') as free:
            response=ASGIClient(server.app).post('/api/memory/free',json={'pid':42,'address':'garbage'})
        self.assertEqual(response.status_code,400);self.assertFalse(response.json()['success']);free.assert_not_called()
    def test_malformed_legacy_typed_value_is_http400_without_driver_call(self):
        import server
        from test_asgi_client import ASGIClient
        with patch.object(server.driver,'write_process_memory') as write:
            for kind,value in [('hex','GG'),('uint8','999')]:
                response=ASGIClient(server.app).post('/api/memory/write',json={'pid':42,'address':'0x10000','data_type':kind,'value':value})
                self.assertEqual(response.status_code,400);self.assertFalse(response.json()['success'])
        write.assert_not_called()

if __name__=='__main__':unittest.main()
