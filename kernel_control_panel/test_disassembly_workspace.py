"""Adversarial editing transactions, not just assembler output snapshots."""
import threading
import unittest
from unittest.mock import patch

from disassembly_workspace import Workspace, compile_line, references

BASE = 0x140001000


class Driver:
    def __init__(self, studio):
        self._lock = threading.RLock()
        self.s = studio
        self.writes = []
        self.protects = []
        self.write_fault = None
        self.restore_fault = False

    def query_process_extended(self, pid): return {'success': True, 'is_wow64': False}

    def write_process_memory(self, pid, start, raw):
        self.writes.append((start, raw))
        offset = start-BASE
        if self.write_fault:
            mode, self.write_fault = self.write_fault, None
            self.s.memory[offset:offset+2] = raw[:2]
            if mode == 'conflict': self.s.memory[offset+2] = 0xfe
            return {'success': False, 'bytes_written': 2, 'result_status': '0x8000000D'}
        self.s.memory[offset:offset+len(raw)] = raw
        return {'success': True, 'bytes_written': len(raw)}

    def protect_virtual_memory(self, pid, start, size, protect):
        self.protects.append((start, size, protect))
        if self.restore_fault and protect != 0x40:
            return {'success': False, 'result_status': '0xC0000022'}
        page = start & ~4095
        old = self.s.protect[page]
        self.s.protect[page] = protect
        return {'success': True, 'old_protect': hex(old), 'result_base_address': hex(start), 'result_region_size': size}


class Studio:
    def __init__(self, code='b80a000000c3'):
        self.lock = threading.RLock()
        self.key = '999'
        self.memory = bytearray(bytes.fromhex(code)+b'\xcc'*(8192-len(bytes.fromhex(code))))
        self.protect = {BASE: 0x20, BASE+4096: 0x20}
        self.driver = Driver(self)

    def identity(self, pid): return self.key

    def read_bytes(self, pid, start, size):
        offset = start-BASE
        if offset < 0 or offset+size > len(self.memory): raise ValueError('unmapped')
        return bytes(self.memory[offset:offset+size])

    def operate(self, op, args):
        return {'success': True, 'results': [{'address': hex(page), 'size': 4096, 'state': '0x1000',
            'protect': hex(protect), 'readable': True, 'guarded': False} for page, protect in self.protect.items()]}


class AssemblerTests(unittest.TestCase):
    def test_case_insensitive_and_exact_length(self):
        a = compile_line('MOV EAX, 100', BASE, 64, 5)
        self.assertEqual(a, compile_line('mov eax, 100', BASE, 64, 5))
        self.assertEqual(a['patch_bytes'], 'b8 64 00 00 00')

    def test_shortened_instruction_pads_without_moving_next_boundary(self):
        result = compile_line('XOR EAX, EAX', BASE, 64, 5)
        self.assertEqual(result['patch_bytes'], '31 c0 90 90 90')
        self.assertEqual(result['padding'], 3)

    def test_invalid_instruction_and_length_rejected(self):
        for text in ('movv eax, 1', 'mov eax, 1\nret', 'nop;ret', 'db 0xc3', '.byte 0xc3', 'label: ret'):
            with self.subTest(text=text), self.assertRaises(ValueError): compile_line(text, BASE, 64, 5)
        with self.assertRaisesRegex(ValueError, '길이 초과'): compile_line('mov rax, 0x123456789abcdef0', BASE, 64, 5)

    def test_rel32_target_retained_at_actual_address(self):
        result = compile_line('CALL 0x140002000', BASE, 64, 5)
        refs = references({'bytes': result['bytes'], 'address': hex(BASE)}, 64)
        self.assertEqual(refs[0]['address'], '0x140002000')

    def test_far_branch_truncation_rejected(self):
        with self.assertRaises(ValueError): compile_line('call 0x7fff00000000', BASE, 64, 5)

    def test_immediate_truncation_rejected(self):
        for code in ('mov eax, 0x100000000', 'mov al, 256', 'add rax, 0xffffffff'):
            with self.subTest(code=code), self.assertRaises(ValueError): compile_line(code, BASE, 64, 15)
        self.assertTrue(compile_line('mov eax, -1', BASE, 64, 5))

    def test_rip_indirect_reference_and_register_unknown(self):
        row = {'bytes': 'ff 15 08 00 00 00', 'address': hex(BASE)}
        self.assertEqual(references(row, 64), [{'address': hex(BASE+14).upper().replace('0X', '0x'), 'indirect': True, 'kind': '간접 호출 포인터'}])
        self.assertFalse(references({'bytes': 'ff d0', 'address': hex(BASE)}, 64))


class EditingTests(unittest.TestCase):
    def setUp(self):
        self.s = Studio()
        self.w = Workspace(self.s)
        result = self.w.operate('disasm_analyze', {'pid': 88, 'address': hex(BASE), 'size': 64})
        self.args = {'pid': 88, 'session_id': result['session_id'], 'analysis_id': result['analysis_id']}

    def apply(self, text='mov eax, 100'):
        return self.w.operate('disasm_apply', {**self.args, 'edits': [{'address': hex(BASE), 'text': text}]})

    def test_apply_undo_redo_verifies_bytes_and_restores_rx(self):
        self.assertTrue(self.apply()['verified'])
        self.assertEqual(self.s.memory[:5], bytes.fromhex('b864000000'))
        self.assertEqual(self.s.protect[BASE], 0x20)
        result = self.w.operate('disasm_undo', self.args)
        self.assertTrue(result['can_redo'])
        self.assertEqual(self.s.memory[:5], bytes.fromhex('b80a000000'))
        self.w.operate('disasm_redo', self.args)
        self.assertEqual(self.s.memory[:5], bytes.fromhex('b864000000'))
        self.assertEqual(len(self.s.driver.writes), 3)

    def test_invalid_batch_fails_before_any_protection_or_write(self):
        with self.assertRaises(ValueError):
            self.w.operate('disasm_apply', {**self.args, 'edits': [{'address': hex(BASE), 'text': 'mov eax, 100'}, {'address': hex(BASE+5), 'text': 'movv eax, 1'}]})
        self.assertFalse(self.s.driver.writes)
        self.assertFalse(self.s.driver.protects)

    def test_external_before_change_is_never_overwritten(self):
        self.s.memory[1] = 44
        with self.assertRaisesRegex(ValueError, '원본 불일치'): self.apply()
        self.assertFalse(self.s.driver.writes)

    def test_recycled_pid_never_writes_and_drops_session(self):
        self.s.key = 'new'
        with self.assertRaisesRegex(ValueError, '교체'): self.apply()
        self.assertFalse(self.s.driver.writes)
        self.assertFalse(self.w.sessions)

    def test_transient_failed_query_keeps_recovery_records(self):
        class QueryError(Exception):
            response = {'success': False, 'exit_status': 0, 'result_status': '0xC0000001', 'error_code': 6}
        def fail(pid): raise QueryError('transport failure')
        self.apply()
        self.s.identity = fail
        with self.assertRaises(QueryError): self.w.operate('disasm_history', self.args)
        self.assertTrue(self.w.sessions[self.args['session_id']]['history'])

    def test_confirmed_exit_removes_history_and_marks_target_invalid(self):
        from disassembly_workspace import InvalidTarget
        class QueryError(Exception):
            response = {'success': True, 'exit_status': 0, 'result_status': '0x00000000'}
        def fail(pid): raise QueryError('target exited')
        self.s.identity = fail
        with self.assertRaises(InvalidTarget): self.w.operate('disasm_history', self.args)
        self.assertFalse(self.w.sessions)

    def test_cross_page_patch_restores_each_actual_page_protection(self):
        self.s.memory[4094:4100] = bytes.fromhex('b80a000000c3')
        self.s.protect[BASE+4096] = 0x220
        result = self.w.operate('disasm_analyze', {**self.args, 'address': hex(BASE+4094), 'size': 16})
        self.assertEqual(result['detail']['results'][0]['size'], 5)
        args = {**self.args, 'analysis_id': result['analysis_id']}
        patched = self.w.operate('disasm_apply', {**args, 'edits': [{'address': hex(BASE+4094), 'text': 'mov eax, 123'}]})
        self.assertTrue(patched['success'])
        self.assertEqual(self.s.memory[4094:4099], bytes.fromhex('b87b000000'))
        self.assertEqual(self.s.protect, {BASE: 0x20, BASE+4096: 0x220})
        self.w.operate('disasm_undo', args)
        self.assertEqual(self.s.memory[4094:4099], bytes.fromhex('b80a000000'))

    def test_partial_write_is_rolled_back_and_recovery_acknowledged(self):
        self.s.driver.write_fault = 'partial'
        result = self.apply()
        self.assertFalse(result['success'])
        self.assertEqual(self.s.memory[:5], bytes.fromhex('b80a000000'))
        self.assertEqual(self.s.protect[BASE], 0x20)
        self.assertTrue(self.w.operate('disasm_recover', self.args)['restored'])
        self.assertFalse(self.w.sessions[self.args['session_id']]['history'])

    def test_external_change_during_partial_failure_is_not_clobbered(self):
        self.s.driver.write_fault = 'conflict'
        result = self.apply()
        self.assertFalse(result['success'])
        self.assertEqual(self.s.memory[2], 0xfe)
        self.assertEqual(len(self.s.driver.writes), 1)
        self.assertFalse(self.w.operate('disasm_recover', self.args)['success'])
        self.assertEqual(self.s.protect[BASE], 0x20)

    def test_protection_restore_failure_retains_recovery_and_then_restores_original(self):
        self.s.driver.restore_fault = True
        result = self.apply()
        self.assertFalse(result['success'])
        self.assertTrue(result['recovery']['protection_errors'])
        with self.assertRaisesRegex(ValueError, '복구'): self.w.operate('disasm_undo', self.args)
        self.s.driver.restore_fault = False
        self.assertTrue(self.w.operate('disasm_recover', self.args)['success'])
        self.assertEqual(self.s.memory[:5], bytes.fromhex('b80a000000'))
        self.assertEqual(self.s.protect[BASE], 0x20)

    def test_new_edit_after_undo_discards_redo(self):
        self.apply()
        self.w.operate('disasm_undo', self.args)
        result = self.apply('mov eax, 200')
        self.assertEqual(len(result['history']), 1)
        self.assertFalse(result['can_redo'])

    def test_external_patch_after_apply_prevents_undo(self):
        self.apply()
        self.s.memory[1] = 99
        with self.assertRaisesRegex(ValueError, '원본 불일치'): self.w.operate('disasm_undo', self.args)
        self.assertEqual(len(self.s.driver.writes), 1)

    def test_duplicate_edits_rejected_without_write(self):
        with self.assertRaisesRegex(ValueError, '중복'):
            self.w.operate('disasm_apply', {**self.args, 'edits': [{'address': hex(BASE), 'text': 'mov eax, 11'}]*2})
        self.assertFalse(self.s.driver.writes)

    def test_release_deletes_history_but_does_not_rewrite_target(self):
        self.apply()
        self.w.operate('disasm_release', self.args)
        self.assertFalse(self.w.sessions)
        self.assertEqual(self.s.memory[:5], bytes.fromhex('b864000000'))

    def test_failure_to_create_analysis_does_not_leak_session(self):
        before = len(self.w.sessions)
        for _ in range(20):
            with self.assertRaises(ValueError): self.w.operate('disasm_analyze', {'pid': 88, 'address': '0'})
        self.assertEqual(len(self.w.sessions), before)

    def test_indirect_call_follow_reads_pointer_through_kernel_reader(self):
        self.s.memory[:6] = bytes.fromhex('ff1508000000')
        self.s.memory[14:22] = (BASE+128).to_bytes(8, 'little')
        result = self.w.operate('disasm_analyze', {**self.args, 'address': hex(BASE), 'size': 64})
        follow = self.w.operate('disasm_follow', {**self.args, 'analysis_id': result['analysis_id'], 'address': hex(BASE)})
        self.assertEqual(follow['address'], f'0x{BASE+128:X}')

    def test_guard_noaccess_and_noncommitted_regions_rejected(self):
        old = self.s.operate
        for change in ({'guarded': True}, {'protect': '0x1'}, {'state': '0x2000'}):
            def regions(op, args):
                result = old(op, args)
                result['results'][0].update(change)
                return result
            self.s.operate = regions
            with self.subTest(change=change), self.assertRaises(ValueError): self.apply()
        self.assertFalse(self.s.driver.writes)

    def test_history_capacity_does_not_forget_originals(self):
        self.apply()
        with patch('disassembly_workspace.MAX_HISTORY', 1), self.assertRaisesRegex(ValueError, '상한'):
            self.apply()
        self.assertEqual(len(self.s.driver.writes), 1)


if __name__ == '__main__': unittest.main()
