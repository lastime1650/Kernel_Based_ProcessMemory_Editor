"""Expression equivalence, bit widths, and observable operation preservation."""
import random
import unittest
from c_expressions import Parser,pretty


def evaluate(node,values):
    if node.op=='atom':return values[node.value] if node.value in values else int(node.value,0)
    args=[evaluate(child,values) for child in node.children]
    if node.op=='cast':
        import re
        signed,width=re.fullmatch(r'(u?)int(8|16|32|64)_t',node.value).groups()
        width=int(width);value=args[0]&((1<<width)-1)
        return value-(1<<width) if not signed and value>=1<<(width-1) else value
    if node.op=='call':
        low,width=args
        return (low&((1<<width)-1))|(values['upper']&(((1<<64)-1)^((1<<width)-1)))
    if node.op=='unary':return {'-':lambda:-args[0],'~':lambda:~args[0],'+':lambda:args[0]}[node.value]()&((1<<64)-1)
    a,b=args
    return {'+':lambda:a+b,'-':lambda:a-b,'*':lambda:a*b,'&':lambda:a&b,'|':lambda:a|b,'^':lambda:a^b,
            '<<':lambda:a<<b,'>>':lambda:a>>b}[node.op]()&((1<<64)-1)


class ExpressionTests(unittest.TestCase):
    def test_low_bits_remain_equal_with_arbitrary_unknown_upper_bits(self):
        rng=random.Random(20261010)
        for width in (8,16,32):
            for op in ('+','-','*','&','|','^','<<'):
                text=f'(uint{width}_t)(unknown_argument_upper_bits(a, 32) {op} '+('3)' if op=='<<' else 'unknown_return_upper_bits(b, 32))')
                after=pretty(text)
                before_ast,after_ast=Parser(text).expression(),Parser(after).expression()
                for _ in range(80):
                    values={'a':rng.getrandbits(32),'b':rng.getrandbits(32),'upper':rng.getrandbits(64)}
                    self.assertEqual(evaluate(before_ast,values),evaluate(after_ast,values),(text,after,values))

    def test_high_bits_remain_for_right_shift_and_comparison(self):
        self.assertIn('unknown_argument_upper_bits',pretty('(uint32_t)(unknown_argument_upper_bits(a, 32) >> 32)'))
        self.assertIn('unknown_argument_upper_bits',pretty('unknown_argument_upper_bits(a, 32) == 0'))

    def test_integer_promotions_and_unsigned_wrap_are_not_erased(self):
        self.assertIn('(uint32_t)',pretty('(uint32_t)(1) < -1'))
        self.assertIn('+',pretty('0xFFFFFFFF + 1'))
        self.assertIn('~',pretty('~0xFFFFFFFF'))
        self.assertIn('(int64_t)',pretty('(int64_t)(1) + 0xFFFFFFFF'))
        self.assertEqual(pretty('0x140001000 + 0x1234'),'0x140002234')

    def test_calls_memory_reads_and_faulting_operations_are_preserved(self):
        for text in ('read_once() * 0','load_u32(address) - load_u32(address)','0 / read_once()'):
            after=pretty(text,render_memory=False)
            self.assertEqual(after.count('read_once()'),text.count('read_once()'))
            self.assertEqual(after.count('load_u32('),text.count('load_u32('))
        self.assertIn('*(uint32_t*)',pretty('load_u32(address + 4)'))

    def test_unsupported_and_oversized_expressions_remain_unchanged(self):
        for text in ('std::ostream::operator<<(a, "v12")','L"kernel32.dll"','a ? b : c','('*60+'a'+')'*60,'+'.join(['a']*600)):
            self.assertEqual(pretty(text),text)


if __name__=='__main__':unittest.main()
