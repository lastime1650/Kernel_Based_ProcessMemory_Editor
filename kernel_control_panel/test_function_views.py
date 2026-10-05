"""Control-flow correctness and conservative lifting, with adversarial byte input."""
import json
import random
import re
import unittest
from unittest.mock import patch

import function_views as V

START = 0x140001000


def analyze(code, bits=64, name='Example'):
    return V.analyze(bytes.fromhex(code), START, bits, name)


class FunctionViewTests(unittest.TestCase):
    def test_both_paths_after_first_return_are_reachable(self):
        view = analyze('83f9057e06b807000000c3b809000000c3')
        self.assertEqual(view['graph']['block_count'], 3)
        self.assertEqual(sum(i['instruction']=='ret' for i in view['results']), 2)
        code = view['pseudocode']['code']
        self.assertEqual(view['pseudocode']['style'], 'structured')
        self.assertIn('else {', code)
        self.assertIn('(int32_t)', code)
        self.assertIn('0x7', code)
        self.assertIn('0x9', code)
        self.assertEqual(view['argument_registers'], ['RCX'])

    def test_natural_while_loop_is_structured_and_back_edge_preserved(self):
        # xor eax,eax; header: cmp ecx,0; jle end; add eax,1; sub ecx,1; jmp header; end: ret
        view = analyze('31c083f9007e0883c00183e901ebf3c3')
        self.assertTrue(any(e['back_edge'] for e in view['graph']['edges']))
        self.assertEqual(view['pseudocode']['style'], 'structured')
        self.assertIn('while (1)',view['pseudocode']['code'])
        self.assertIn('break;',view['pseudocode']['code'])
        self.assertEqual(sum(i['instruction']=='ret' for i in view['results']),1)

    def test_unreachable_padding_not_present(self):
        view = analyze('b801000000c3cccccccccccc')
        self.assertEqual(view['instruction_count'], 2)
        self.assertEqual(view['graph']['block_count'], 1)

    def test_rip_relative_address_keeps_full_64_bit_precision(self):
        view = analyze('8b0534120000c3')
        self.assertIn('0x140001006 + 0x1234',view['pseudocode']['code'])
        self.assertEqual(view['source'],'kernel_memory')

    def test_partial_register_preserves_upper_bits(self):
        view = analyze('b1014889c8c3')
        self.assertIn('replace_bits',view['pseudocode']['code'])
        self.assertEqual(view['argument_registers'],['RCX'])

    def test_zero_idiom_is_not_incoming_argument(self):
        view = analyze('31c989c8c3')
        self.assertEqual(view['argument_registers'],[])
        self.assertIn('(0)',view['pseudocode']['code'])

    def test_indirect_jump_does_not_invent_destinations(self):
        view = analyze('ffe0')
        self.assertEqual(view['graph']['unresolved_count'],1)
        self.assertTrue(view['graph']['nodes'][-1]['external'])
        self.assertIn('unknown_control_transfer',view['pseudocode']['code'])
        self.assertEqual(view['pseudocode']['style'],'labels')

    def test_outside_conditional_branch_keeps_unknown_path(self):
        view = analyze('85c9757fb801000000c3')
        self.assertEqual(view['graph']['unresolved_count'],1)
        self.assertIn('unresolved_',view['pseudocode']['code'])
        self.assertIn('return',view['pseudocode']['code'])

    def test_branch_into_middle_is_rejected_and_visible(self):
        view = analyze('b801000000ebfa')
        self.assertTrue(any('경계' in n for n in view['graph']['notes']))
        self.assertEqual(view['graph']['unresolved_count'],1)

    def test_unsupported_simd_preserves_original_and_unknown_result(self):
        view = analyze('f20f59c1c3')
        self.assertEqual(len(view['pseudocode']['unsupported']),1)
        self.assertIn('asm_volatile("mulsd xmm0, xmm1")',view['pseudocode']['code'])
        self.assertIn('unknown_after_asm',view['pseudocode']['code'])

    def test_known_stack_argument_reuses_one_slot_across_stack_adjustment(self):
        view = analyze('4883ec28894c24308b4424304883c428c3')
        slots=[v for v in view['pseudocode']['variables'] if v['storage']=='stack 8']
        self.assertEqual(len(slots),1)
        self.assertEqual(view['argument_registers'],['RCX'])

    def test_overlapping_stack_access_is_kept_as_explicit_memory(self):
        view = analyze('4883ec2848894c24088954240c488b4424084883c428c3')
        code=view['pseudocode']['code']
        self.assertIn('store_u64',code)
        self.assertIn('store_u32',code)
        self.assertIn('load_u64',code)

    def test_x86_stack_argument_not_x64_register_abi(self):
        view=analyze('8b44240483c001c3',32)
        self.assertEqual(view['argument_registers'],[])
        self.assertIn('uint32_t a1',view['pseudocode']['code'])

    def test_flags_snapshot_survives_later_mov(self):
        view=analyze('83f900b9070000007406b801000000c3b802000000c3')
        code=view['pseudocode']['code']
        compare=next(v['name'] for v in view['pseudocode']['variables'] if v['storage'].startswith('비교'))
        self.assertRegex(code,r'if \(\(uint32_t\)'+compare+r' ==')
        self.assertIn('0x7',code)

    def test_unknown_call_keeps_machine_context_and_clobbers(self):
        view=analyze('e8100000004889c8c3')
        code=view['pseudocode']['code']
        self.assertIn('machine_context(',code)
        self.assertIn('.rcx',code)
        self.assertIn('call_unknown(',code)

    def test_address_size_override_wraps_effective_address(self):
        view=analyze('678b00c3')
        self.assertIn('load_u32(((uint32_t)',view['pseudocode']['code'])

    def test_x86_short_loop_preserves_upper_counter_bits(self):
        view=analyze('67e2fdc3',32)
        self.assertIn('replace_bits(',view['pseudocode']['code'])
        self.assertIn('(uint16_t)',view['pseudocode']['code'])

    def test_unknown_stack_changes_do_not_create_false_local_slots(self):
        view=analyze('48bc0010000000000000488b0424c3')
        self.assertIn('load_u64',view['pseudocode']['code'])
        self.assertFalse(any(v['storage'].startswith('stack ') for v in view['pseudocode']['variables']))

    def test_x86_short_push_is_explicitly_unsupported(self):
        view=analyze('66508b0424c3',32)
        self.assertTrue(view['pseudocode']['unsupported'])
        self.assertIn('load_u32',view['pseudocode']['code'])

    def test_limits_and_empty_input(self):
        with patch.object(V,'MAX_INSTRUCTIONS',8):
            view=analyze('90'*32+'c3')
        self.assertTrue(view['graph']['truncated'])
        self.assertEqual(view['instruction_count'],8)
        view=analyze('')
        self.assertEqual(view['instruction_count'],0)
        self.assertIn('unknown_return',view['pseudocode']['code'])

    def test_locals_are_consecutive_and_function_name_is_safe(self):
        view=analyze('83f9057e06b807000000c3b809000000c3',name='9 bad <script> */')
        names=[v['name'] for v in view['pseudocode']['variables']]
        self.assertEqual(names,['v'+str(i+1) for i in range(len(names))])
        self.assertIn('sub_9_bad__script____',view['pseudocode']['code'])
        json.dumps(view)

    def test_deterministic_fuzz_is_bounded_and_serializable(self):
        rng=random.Random(428)
        for _ in range(60):
            raw=rng.randbytes(rng.randint(0,160))
            for bits in (32,64):
                view=V.analyze(raw,START,bits,'fuzz')
                json.dumps(view)
                self.assertLessEqual(view['instruction_count'],V.MAX_INSTRUCTIONS)
                ids={n['id'] for n in view['graph']['nodes']}
                self.assertTrue(all(e['source'] in ids and e['target'] in ids for e in view['graph']['edges']))


if __name__=='__main__': unittest.main()
