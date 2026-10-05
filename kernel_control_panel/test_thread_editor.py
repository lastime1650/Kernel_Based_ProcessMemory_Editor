"""Thread edits tested only with fake driver state, never the live Project1."""
import threading
import unittest
from studio_api import Studio
from driver_bridge import THREAD_REGISTERS_REQUEST


class Driver:
    def __init__(self):
        self._lock=threading.RLock()
        self.pid=42;self.tid=123;self.key=1;self.created=10;self.exit_status=259
        self.registers={name.lower():f'0x{i+1:X}' for i,(name,_) in enumerate(THREAD_REGISTERS_REQUEST._fields_)
                        if name not in ('ThreadId','ResultStatus')}
        self.calls=[];self.read_error=False;self.write_error=False;self.mismatch=False;self.resume_error=False;self.recycle=False

    def send_ioctl(self,*args):return True,0,0
    def query_process_info(self,pid):return {'success':True,'exit_status':259,'process_start_key':self.key}
    def query_thread_info(self,tid):return {'success':True,'process_id':self.pid,'thread_id':self.tid,'exit_status':self.exit_status,'create_time':self.created}
    def suspend_thread(self,tid):
        self.calls.append(('suspend',tid))
        if self.recycle:self.created+=1
        return {'success':True}
    def resume_thread(self,tid):self.calls.append(('resume',tid));return {'success':not self.resume_error}
    def get_thread_context(self,tid):
        self.calls.append(('read',tid))
        return {'success':not self.read_error,'thread_id':tid,**self.registers}
    def set_thread_context(self,tid,values):
        self.calls.append(('write',dict(values)))
        if not self.write_error:
            self.registers={name:f'0x{value:X}' for name,value in values.items()}
            if self.mismatch:self.registers['rax']='0xBAD'
        return {'success':not self.write_error}


class ThreadEditorTests(unittest.TestCase):
    def setUp(self):self.driver=Driver();self.studio=Studio(self.driver)
    def tearDown(self):self.studio.shutdown()
    def edit(self,**args):return self.studio.run('set_context',{'pid':42,'tid':123,'registers':{'rax':'0x64'},**args})

    def test_changed_field_verified_and_other_registers_preserved(self):
        before=dict(self.driver.registers);result=self.edit()
        self.assertTrue(result['success'] and result['verified'])
        self.assertEqual(int(result['registers']['rax'],16),100)
        self.assertEqual({k:v for k,v in self.driver.registers.items() if k!='rax'}, {k:v for k,v in before.items() if k!='rax'})
        self.assertEqual([x[0] for x in self.driver.calls],['suspend','read','write','read','resume'])

    def test_wrong_PID_or_TID_does_not_suspend_or_write(self):
        for args in ({'pid':99},{'tid':124}):
            self.assertFalse(self.edit(**args)['success']);self.assertEqual(self.driver.calls,[])

    def test_all_selected_thread_tools_reject_wrong_owner(self):
        for operation in ('thread_info','context','suspend','resume','priority','affinity','hide'):
            result=self.studio.run(operation,{'pid':99,'tid':123,'priority':9,'mask':1})
            self.assertFalse(result['success'],operation);self.assertEqual(self.driver.calls,[])

    def test_invalid_input_rejected_before_suspend(self):
        for values in ({'rax':-1},{'rax':2**64},{'eflags':2**32},{'xmm0':1},{'rax':'bad'},{}):
            self.assertFalse(self.edit(registers=values)['success']);self.assertEqual(self.driver.calls,[])

    def test_dead_thread_or_unknown_creation_time_is_not_edited(self):
        self.driver.exit_status=0;self.assertFalse(self.edit()['success']);self.assertEqual(self.driver.calls,[])
        self.driver.exit_status=259;self.driver.created=0
        self.assertFalse(self.edit()['success']);self.assertEqual(self.driver.calls,[])

    def test_context_read_failure_resumes_the_owned_thread(self):
        self.driver.read_error=True;self.assertFalse(self.edit()['success'])
        self.assertEqual([x[0] for x in self.driver.calls],['suspend','read','resume'])

    def test_context_write_failure_resumes_and_does_not_report_success(self):
        self.driver.write_error=True;self.assertFalse(self.edit()['success'])
        self.assertEqual([x[0] for x in self.driver.calls],['suspend','read','write','resume'])

    def test_mismatched_readback_reports_observed_values_and_resumes(self):
        self.driver.mismatch=True;result=self.edit()
        self.assertFalse(result['success'] or result['verified'])
        self.assertEqual(result['differences']['rax']['observed'],'0xBAD')
        self.assertEqual(self.driver.calls[-1][0],'resume')

    def test_unrequested_live_flags_are_reported_separately(self):
        original=self.driver.set_thread_context
        def write(tid,values):
            result=original(tid,values);self.driver.registers['eflags']='0x202';return result
        self.driver.set_thread_context=write
        result=self.edit()
        self.assertTrue(result['verified']);self.assertEqual(result['verified_fields'],['rax'])
        self.assertIn('eflags',result['unrequested_changes'])

    def test_recycled_thread_is_never_written_or_resumed(self):
        self.driver.recycle=True;result=self.edit()
        self.assertFalse(result['success']);self.assertEqual(self.driver.calls,[('suspend',123)])

    def test_resume_failure_is_not_hidden_by_successful_write(self):
        self.driver.resume_error=True;self.assertFalse(self.edit()['success'])


if __name__=='__main__':unittest.main(verbosity=2)
