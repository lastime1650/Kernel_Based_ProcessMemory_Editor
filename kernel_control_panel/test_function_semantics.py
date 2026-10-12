"""Offline regressions for typed calls without inventing source semantics.

All fixtures are inert instruction bytes; no executable or kernel is invoked.
"""
import json
import re
import struct
import unittest

import function_views as V


START = 0x140001000
TARGET = START + 0x100
IAT = START + 0x200


def integer(name='arg', size=4):
    return {'type': f'int{size * 8}_t', 'kind': 'integer', 'size': size, 'name': name}


def pointer(name='arg', spelling='void*'):
    return {'type': spelling, 'kind': 'pointer', 'size': 8, 'name': name}


def floating(name='arg', size=4):
    return {'type': 'float' if size == 4 else 'double', 'kind': 'float', 'size': size, 'name': name}


def prototype(name, parameters=(), result=None, **overrides):
    record = {'name': name, 'parameters': list(parameters),
              'return': integer('return') if result is None else result,
              'calling_convention': 'win64', 'valid': True, 'source': 'pdb'}
    record.update(overrides)
    return record


def direct_call(prefix, target=TARGET):
    return prefix + b'\xe8' + struct.pack('<i', target - START - len(prefix) - 5)


def indirect_call(prefix, slot=IAT):
    return prefix + b'\xff\x15' + struct.pack('<i', slot - START - len(prefix) - 6)


def view(raw, metadata=None, names=None):
    return V.analyze(raw, START, 64, 'fixture', names=names, metadata=metadata or {})


def code(raw, metadata=None, names=None):
    return view(raw, metadata, names)['pseudocode']['code']


class FunctionSemanticTests(unittest.TestCase):
    def test_direct_typed_call_uses_only_declared_arguments(self):
        raw = direct_call(bytes.fromhex('b907000000ba09000000')) + b'\xc3'
        metadata = {'functions': {TARGET: prototype('addValues', [integer('left'), integer('right')])}}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        self.assertIn('addValues(', text)
        self.assertIn('0x7', text)
        self.assertIn('0x9', text)
        self.assertNotIn('call_unknown(', text)
        self.assertNotIn('machine_context(', text)
        self.assertTrue(any(v['type'] == 'int32_t' for v in result['pseudocode']['variables']))

    def test_verified_iat_slot_becomes_a_named_call(self):
        raw = indirect_call(bytes.fromhex('b92a000000')) + b'\xc3'
        metadata = {'imports': {hex(IAT): prototype('consume', [integer('value')])}}
        text = code(raw, metadata)
        self.assertIn('consume(', text)
        self.assertIn('0x2A', text)
        self.assertNotIn('call_unknown(', text)

    def test_a_name_without_prototype_remains_an_unknown_call(self):
        raw = direct_call(bytes.fromhex('b907000000')) + b'\xc3'
        text = code(raw, names={TARGET: 'knownNameOnly'})
        self.assertIn('call_unknown(', text)
        self.assertIn('machine_context(', text)

    def test_unknown_indirect_call_is_not_resolved_from_an_unrelated_import(self):
        raw = b'\xff\xd0\xc3'  # call rax; ret
        text = code(raw, {'imports': {IAT: prototype('unrelated')}})
        self.assertIn('call_unknown(', text)
        self.assertNotIn('unrelated(', text)

    def test_second_float_argument_uses_xmm1_not_stale_rdx(self):
        # int receiver/value in ECX; unrelated EDX; float in XMM1.
        prefix = bytes.fromhex('4883ec38c74424200000803fb907000000ba78563412f30f104c2420')
        raw = direct_call(prefix) + bytes.fromhex('4883c438c3')
        metadata = {'functions': {TARGET: prototype('mixed', [integer('first'), floating('second')])}}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        call_line = next(line for line in text.splitlines() if 'mixed(' in line)
        self.assertIn('0x7', call_line)
        self.assertNotIn('0x12345678', call_line)
        self.assertNotIn('unknown_entry("xmm1")', call_line)
        self.assertFalse(result['pseudocode']['unsupported'])

    def test_mixed_integer_float_stack_reads_preserve_the_original_bits(self):
        # The same bits represent 1065353216 as an integer and 1.0 as a float.
        prefix = bytes.fromhex('4883ec38c74424200000803f8b4c2420')
        raw = direct_call(prefix)
        raw += bytes.fromhex('b907000000f30f104c2420')
        raw = direct_call(raw, TARGET + 0x20) + bytes.fromhex('4883c438c3')
        metadata = {'functions': {TARGET: prototype('integerConsumer', [integer()]),
                                  TARGET + 0x20: prototype('floatConsumer', [integer(), floating()])}}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        slot = next(v for v in result['pseudocode']['variables'] if v['storage'] == 'stack -24')
        self.assertEqual(slot['type'], 'uint32_t')
        integer_line = next(line for line in text.splitlines() if 'integerConsumer(' in line)
        self.assertIn(slot['name'], integer_line)
        float_line = next(line for line in text.splitlines() if 'floatConsumer(' in line)
        self.assertIn('f32_from_bits(' + slot['name'], float_line)

    def test_float_return_is_taken_from_xmm0(self):
        raw = direct_call(b'') + b'\xc3'
        result_type = floating('return')
        metadata = {'functions': {TARGET: prototype('sampleFloat', result=result_type)},
                    'function': prototype('fixture', result=result_type)}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        call_result = re.search(r'\b(v\d+)\s*=\s*sampleFloat\(', text)
        self.assertEqual(text.count('sampleFloat('), 1)
        if call_result:
            self.assertRegex(text, r'\breturn\s+[^;\n]*\b' + call_result[1] + r'\b')
            self.assertTrue(any(v['name'] == call_result[1] and v['type'] == 'float'
                                for v in result['pseudocode']['variables']))
        else:
            self.assertIn('return sampleFloat();', text)

    def test_narrow_integer_return_keeps_full_rax_upper_bits_unknown(self):
        raw = direct_call(b'') + b'\xc3'
        metadata = {'functions': {TARGET: prototype('sampleInt32')}}
        text = code(raw, metadata)
        call_result = re.search(r'\b(v\d+)\s*=\s*sampleInt32\(', text)
        self.assertIsNotNone(call_result)
        self.assertRegex(text, r'unknown_return_upper_bits\(' + call_result[1] + r',\s*32\)')

    def test_narrow_integer_argument_does_not_invent_full_rcx_upper_bits(self):
        raw = bytes.fromhex('4889c8c3')
        metadata = {'function': prototype('fixture', [integer('argument')], integer('return', 8))}
        text = code(raw, metadata)
        self.assertRegex(text, r'unknown_argument_upper_bits\(a1,\s*32\)')

    def test_storing_a_float_call_result_uses_its_scalar_return_value(self):
        raw = direct_call(bytes.fromhex('4883ec38'))
        raw += bytes.fromhex('f30f114424204883c438c3')
        metadata = {'functions': {TARGET: prototype('sampleFloat', result=floating('return'))}}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        call_result = re.search(r'\b(v\d+)\s*=\s*sampleFloat\(', text)
        self.assertIsNotNone(call_result)
        slot = next(v for v in result['pseudocode']['variables'] if v['storage'] == 'stack -24')
        self.assertRegex(text, r'\b' + slot['name'] + r'\s*=\s*' + call_result[1] + r';')

    def test_fifth_argument_uses_current_rsp_plus_32(self):
        prefix = bytes.fromhex('4883ec38b901000000ba0200000041b80300000041b90400000048c744242005000000')
        raw = direct_call(prefix) + bytes.fromhex('4883c438c3')
        metadata = {'functions': {TARGET: prototype('five', [integer(str(i), 8) for i in range(5)])}}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        call_line = next(line for line in text.splitlines() if 'five(' in line)
        for value in range(1, 5):
            self.assertIn(f'0x{value:X}', call_line)
        last_arg = re.search(r',\s*(v\d+)\);$', call_line)
        self.assertIsNotNone(last_arg)
        slot = next(v for v in result['pseudocode']['variables'] if v['name'] == last_arg[1])
        self.assertEqual(slot['storage'], 'stack -24')
        self.assertRegex(text, r'\b' + last_arg[1] + r'\s*=\s*[^;]*0x5')
        self.assertNotIn('unknown_stack', call_line)

    def test_lea_does_not_create_a_false_eight_byte_stack_access(self):
        raw = bytes.fromhex('4883ec38488d542420c74424200a0000004889d04883c438c3')
        result = view(raw, {'functions': {}})
        slots = [v for v in result['pseudocode']['variables'] if v['storage'] == 'stack -24']
        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0]['type'], 'uint32_t')
        self.assertIn('&' + slots[0]['name'], result['pseudocode']['code'])

    def test_true_overlapping_stack_accesses_stay_explicit(self):
        raw = bytes.fromhex('4883ec2848894c24088954240c488b4424084883c428c3')
        text = code(raw)
        self.assertIn('store_u64', text)
        self.assertIn('store_u32', text)
        self.assertIn('*(uint64_t*)', text)

    def test_memory_snapshot_is_not_delayed_past_a_call(self):
        # snapshot = *RCX; mutate(RCX); consume(snapshot).
        prefix = bytes.fromhex('488b19')
        raw = direct_call(prefix)
        raw += bytes.fromhex('4889d9')
        raw = direct_call(raw, TARGET + 0x20) + b'\xc3'
        metadata = {'functions': {TARGET: prototype('mutate', [pointer()]),
                                  TARGET + 0x20: prototype('consumeSnapshot', [integer(size=8)])}}
        text = code(raw, metadata)
        self.assertEqual(text.count('*(uint64_t*)'), 1)
        self.assertLess(text.index('*(uint64_t*)'), text.index('mutate('))
        consume_line = next(line for line in text.splitlines() if 'consumeSnapshot(' in line)
        self.assertNotIn('*(uint64_t*)', consume_line)

    def test_named_global_snapshot_is_not_duplicated_by_copy_propagation(self):
        address = START + 0x300
        prefix = b'\x48\x8b\x05' + struct.pack('<i', address - START - 7)
        prefix += bytes.fromhex('4889c14889c2')
        raw = direct_call(prefix) + b'\xc3'
        metadata = {'functions': {TARGET: prototype('pair', [integer(size=8), integer(size=8)])},
                    'globals': {address: {'name': 'g_value', 'type': 'uint64_t', 'kind': 'integer', 'size': 8}}}
        text = code(raw, metadata)
        self.assertEqual(text.count('g_value'), 1)
        snapshot = re.search(r'\b(v\d+)\s*=\s*g_value;', text)
        self.assertIsNotNone(snapshot)
        call_line = next(line for line in text.splitlines() if 'pair(' in line)
        self.assertNotIn('g_value', call_line)
        self.assertEqual(len(re.findall(r'\b' + snapshot[1] + r'\b', call_line)), 2)

    def test_join_does_not_copy_propagate_one_branch_value(self):
        # EDX is 7 or 9, then used as the call's first argument.
        prefix = bytes.fromhex('85c97407ba07000000eb05ba0900000089d1')
        raw = direct_call(prefix) + b'\xc3'
        metadata = {'functions': {TARGET: prototype('choose', [integer()])}}
        text = code(raw, metadata)
        self.assertIn('0x7', text)
        self.assertIn('0x9', text)
        call_line = next(line for line in text.splitlines() if 'choose(' in line)
        self.assertNotIn('0x7', call_line)
        self.assertNotIn('0x9', call_line)

    def test_conditional_move_does_not_rewrite_its_destination_to_a_constant(self):
        raw = bytes.fromhex('b90100000085d20f45c889c8c3')
        text = code(raw, {'functions': {}})
        conditional = next(line.strip() for line in text.splitlines() if line.strip().startswith('if ('))
        destination = re.search(r'^if\s*\(.+\)\s+(v\d+)\s*=', conditional)
        self.assertIsNotNone(destination)
        return_line = next(line for line in text.splitlines() if line.strip().startswith('return '))
        self.assertIn(destination[1], return_line)
        self.assertRegex(text, r'\b' + destination[1] + r'\s*=\s*[^;]*0x1')

    def test_unconditional_self_loop_is_structured(self):
        # A separate entry block jumps to a loop that reinitializes its argument.
        prefix = bytes.fromhex('31c0eb00b901000000')
        raw = direct_call(prefix)
        raw += b'\xeb' + struct.pack('b', 4 - len(raw) - 2)
        metadata = {'functions': {TARGET: prototype('tick', [integer()],
                                        {'type': 'void', 'kind': 'void', 'size': 0})}}
        result = view(raw, metadata)
        self.assertEqual(result['pseudocode']['style'], 'structured')
        self.assertIn('while (1)', result['pseudocode']['code'])
        self.assertIn('tick(', result['pseudocode']['code'])

    def test_xmm6_survives_a_known_win64_call(self):
        prefix = bytes.fromhex('4883ec38c74424200000803ff30f10742420')
        raw = direct_call(prefix)
        raw += bytes.fromhex('b907000000f30f10ce')  # movss xmm1,xmm6
        raw = direct_call(raw, TARGET + 0x20) + bytes.fromhex('4883c438c3')
        metadata = {'functions': {TARGET: prototype('barrier'),
                                  TARGET + 0x20: prototype('useSavedFloat', [integer(), floating()])}}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        self.assertIn('useSavedFloat(', text)
        self.assertNotIn('unknown_call_clobber("xmm6")', text)
        self.assertFalse(result['pseudocode']['unsupported'])

    def test_wide_ymm6_does_not_claim_its_upper_lanes_survive_a_call(self):
        raw = direct_call(bytes.fromhex('c5fc1031')) + bytes.fromhex('c5fc1132c3')
        text = code(raw, {'functions': {TARGET: prototype('barrier')}})
        self.assertIn('unknown_call_clobber("ymm6")', text)
        self.assertIn('asm_volatile("vmovups ymm6, ymmword ptr [rcx]")', text)

    def test_unsupported_asm_keeps_its_reaching_register_definitions(self):
        raw = bytes.fromhex('4883ec38c74424200000803ff30f104c2420660f59c14883c438c3')
        metadata = {'functions': {}, 'function': prototype('fixture', result=floating('return', 8))}
        result = view(raw, metadata)
        text = result['pseudocode']['code']
        register = next(v for v in result['pseudocode']['variables'] if v['storage'] == 'xmm1')
        assignment = re.search(r'\b' + register['name'] + r'\s*=\s*vec128_from_f32\(', text)
        self.assertIsNotNone(assignment)
        self.assertLess(assignment.start(), text.index('asm_volatile("mulpd xmm0, xmm1")'))

    def test_call_does_not_claim_a_volatile_register_is_preserved(self):
        raw = direct_call(bytes.fromhex('b907000000')) + bytes.fromhex('4889c8c3')
        metadata = {'functions': {TARGET: prototype('touch', [integer()])}}
        text = code(raw, metadata)
        self.assertIn('touch(', text)
        self.assertIn('unknown_call_clobber("rcx")', text)

    def test_invalid_or_unsupported_prototypes_fall_back(self):
        raw = direct_call(bytes.fromhex('b907000000')) + b'\xc3'
        invalid = [prototype('bad', [integer()], valid=False),
                   prototype('bad', [integer()], variadic=True),
                   prototype('bad', [integer()], calling_convention='vectorcall'),
                   prototype('bad', [{'type': 'Blob', 'kind': 'aggregate', 'size': 16}]),
                   prototype('bad', result={'type': 'Blob', 'kind': 'aggregate', 'size': 16}),
                   prototype('bad', [{'type': 'unknown', 'kind': 'unknown', 'size': 8}])]
        for record in invalid:
            with self.subTest(prototype=record):
                text = code(raw, {'functions': {TARGET: record}})
                self.assertIn('call_unknown(', text)
                self.assertNotIn('bad(', text)

    def test_restored_string_tokens_are_not_renamed_as_locals(self):
        address = START + 0x300
        prefix = b'\x48\x8d\x0d' + struct.pack('<i', address - START - 7)
        raw = direct_call(prefix) + b'\xc3'
        value = 'v17 "quoted"\\path\nv1 v2 v3 v4 v5'
        metadata = {'functions': {TARGET: prototype('puts', [pointer(spelling='const char*')])},
                    'strings': {address: {'value': value, 'encoding': 'utf-8'}}}
        text = code(raw, metadata)
        self.assertIn(json.dumps(value), text)
        self.assertNotIn('call_unknown(', text)


if __name__ == '__main__':
    unittest.main()
