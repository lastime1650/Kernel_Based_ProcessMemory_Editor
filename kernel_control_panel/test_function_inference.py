"""Win64 evidence without function-specific names, PDBs, or target access."""
import struct
import unittest

import function_views as V
from function_inference import infer
from api_prototypes import lookup


class InferenceTests(unittest.TestCase):
    def view(self,hex_bytes,metadata=None):
        return V.analyze(bytes.fromhex(hex_bytes),0x1000,64,metadata=metadata)

    def test_raw_unnamed_integer_function_uses_observed_widths(self):
        view=self.view('8D0411C3') # lea eax,[rcx+rdx]; ret
        self.assertEqual([p['size'] for p in view['pseudocode']['inference']['parameters']],[4,4])
        self.assertIn('uint32_t sub_1000(uint32_t a1, uint32_t a2)',view['pseudocode']['code'])
        self.assertNotIn('unknown_entry',view['pseudocode']['code'])
        self.assertTrue(view['pseudocode']['inference']['valid'])

    def test_pointer_and_integer_inputs_and_fifth_stack_argument(self):
        p=infer(bytes.fromhex('8B01C3'),0x1000)
        self.assertEqual(p['parameters'][0]['kind'],'pointer')
        p=infer(bytes.fromhex('8B44242803C103C203C04103C14103C1C3'),0x1000)
        self.assertEqual(len(p['parameters']),5)
        self.assertEqual(p['parameters'][4]['size'],4)

    def test_float_and_double_positions_and_conversion(self):
        for raw,size in (('F30F58C1C3',4),('F20F58C1C3',8)):
            p=infer(bytes.fromhex(raw),0x1000)
            self.assertTrue(p['valid']);self.assertEqual(p['return']['size'],size)
            self.assertEqual([v['kind'] for v in p['parameters']],['float','float'])
        view=self.view('F30F5AC0C3') # cvtss2sd xmm0,xmm0
        self.assertIn('double sub_1000(float a1)',view['pseudocode']['code'])
        self.assertIn('return (double)(a1);',view['pseudocode']['code'])

    def test_unknown_calls_custom_inputs_and_partial_writes_are_incomplete(self):
        for raw in ('E800100000B801000000C3','03C1C3','B001C3','740231C0C3','488BC3C3'):
            self.assertFalse(infer(bytes.fromhex(raw),0x1000)['valid'],raw)

    def test_overwritten_arguments_do_not_become_source_parameters(self):
        p=infer(bytes.fromhex('31C98D4101C3'),0x1000)
        self.assertTrue(p['valid']);self.assertEqual(p['parameters'],[])

    def test_known_import_tail_preserves_void_and_arguments(self):
        api=lookup('Sleep','kernel32.dll',64)
        raw=b'\xff\x25'+struct.pack('<i',0x2000-(0x1000+6))
        view=V.analyze(raw,0x1000,64,metadata={'imports':{0x2000:api}})
        code=view['pseudocode']['code']
        self.assertIn('void sub_1000(uint32_t a1)',code)
        self.assertIn('Sleep(a1);',code);self.assertIn('return;',code)
        self.assertNotIn('unknown_control_transfer',code)

    def test_conditional_tail_and_fallthrough_preserve_both_inputs(self):
        proto={'name':'leaf','valid':True,'inferred':True,'calling_convention':'win64',
               'parameters':[{'type':'uint32_t','kind':'integer','size':4}]*2,
               'return':{'type':'uint32_t','kind':'integer','size':4}}
        raw=bytes.fromhex('85C9')+b'\x0f\x85'+struct.pack('<i',0x2000-0x1008)+bytes.fromhex('8D0411C3')
        code=V.analyze(raw,0x1000,64,metadata={'functions':{0x2000:proto}})['pseudocode']['code']
        self.assertIn('uint32_t a2',code);self.assertIn('return leaf(a1, a2);',code)
        self.assertNotIn('unknown_control_transfer',code)

    def test_entry_value_remains_on_a_path_without_assignment(self):
        code=self.view('85C974028BC2C3')['pseudocode']['code']
        self.assertIn('unknown_entry("rax")',code)
        self.assertFalse(self.view('85C974028BC2C3')['pseudocode']['inference']['valid'])

    def test_tail_fifth_argument_uses_entry_stack_plus_40_not_shadow_space(self):
        proto={'name':'five','valid':True,'calling_convention':'win64',
               'parameters':[{'type':'uint32_t','kind':'integer','size':4}]*5,
               'return':{'type':'uint32_t','kind':'integer','size':4}}
        raw=b'\xe9'+struct.pack('<i',0x2000-0x1005)
        code=V.analyze(raw,0x1000,64,metadata={'functions':{0x2000:proto}})['pseudocode']['code']
        self.assertIn('uint32_t a5)',code)
        self.assertIn('= a5;',code)
        self.assertNotIn('unknown_stack(32)',code)

    def test_float_conversion_memory_source_retains_source_width(self):
        view=self.view('F30F11442408F30F5A442408C3')
        code=view['pseudocode']['code']
        self.assertIn('double sub_1000(float a1)',code)
        self.assertIn('float v1;',code)
        self.assertNotIn('entry_stack_pointer',code)

    def test_duplicate_known_tail_nodes_cannot_mask_an_unresolved_edge(self):
        proto={'name':'leaf','valid':True,'calling_convention':'win64',
               'parameters':[{'type':'uint32_t','kind':'integer','size':4}]*2,
               'return':{'type':'uint32_t','kind':'integer','size':4}}
        first=b'\x85\xc9\x0f\x85'+struct.pack('<i',0x2000-0x1008)
        raw=first+b'\xe9'+struct.pack('<i',0x2000-0x100d)
        self.assertTrue(infer(raw,0x1000,functions={0x2000:proto})['valid'])
        raw=first+b'\x85\xd2\x0f\x85'+struct.pack('<i',0x2000-0x1010)+b'\xe9'+struct.pack('<i',0x3000-0x1015)
        self.assertFalse(infer(raw,0x1000,functions={0x2000:proto})['valid'])

    def test_conflicting_tail_return_conventions_remain_unknown(self):
        proto={'name':'integer_leaf','valid':True,'calling_convention':'win64','parameters':[],
               'return':{'type':'uint32_t','kind':'integer','size':4}}
        other=dict(proto,name='float_leaf',**{'return':{'type':'float','kind':'float','size':4}})
        raw=b'\x85\xc9\x0f\x85'+struct.pack('<i',0x2000-0x1008)+b'\xe9'+struct.pack('<i',0x3000-0x100d)
        view=V.analyze(raw,0x1000,64,metadata={'functions':{0x2000:proto,0x3000:other}})
        self.assertFalse(view['pseudocode']['inference']['return_observed'])
        self.assertIn('unknown_return_abi',view['pseudocode']['code'])

    def test_pdb_declaration_overrides_instruction_inference(self):
        proto={'name':'known','source':'pdb','valid':True,'calling_convention':'win64',
               'parameters':[{'type':'int32_t','kind':'integer','size':4}],
               'return':{'type':'int32_t','kind':'integer','size':4}}
        view=self.view('8BC1C3',{'function':proto})
        self.assertIn('int32_t sub_1000(int32_t a1)',view['pseudocode']['code'])
        self.assertFalse(view['pseudocode']['semantic']['signature_inferred'])


if __name__=='__main__':unittest.main()
