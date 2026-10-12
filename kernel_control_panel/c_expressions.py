"""Small typed expression tree used for readable, semantics-preserving C output.

Unsupported syntax is returned unchanged. Simplification never removes a call
or a memory access, and bit-width casts are kept unless equivalence is proved.
"""
import re
from dataclasses import dataclass

TOKEN = re.compile(r'\s*(0x[\dA-Fa-f]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?f?|"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|<<|>>|==|!=|<=|>=|&&|\|\||[()+\-*/%^&|~!<>,])')
PRECEDENCE = {'||':1,'&&':2,'|':3,'^':4,'&':5,'==':6,'!=':6,'<':7,'>':7,'<=':7,'>=':7,'<<':8,'>>':8,'+':9,'-':9,'*':10,'/':10,'%':10}
CTYPE = re.compile(r'(?:u?int(?:8|16|32|64)_t|uintptr_t|float|double|void)(?:\*)?\Z')


@dataclass(frozen=True)
class Expr:
    op: str
    value: str = ''
    children: tuple = ()

    def render(self, parent=0):
        if self.op == 'atom':
            return self.value
        if self.op == 'call':
            return self.value+'('+', '.join(x.render() for x in self.children)+')'
        if self.op == 'cast':
            return '('+self.value+')('+self.children[0].render()+')'
        if self.op == 'unary':
            return self.value+self.children[0].render(11)
        precedence = PRECEDENCE[self.op]
        text = self.children[0].render(precedence)+' '+self.op+' '+self.children[1].render(precedence+1)
        return '('+text+')' if precedence < parent else text


class Parser:
    def __init__(self, text):
        self.tokens, position = [], 0
        while position < len(text):
            found = TOKEN.match(text, position)
            if not found:
                if text[position:].strip():
                    raise ValueError('unsupported expression')
                break
            self.tokens.append(found[1]);position = found.end()
            if len(self.tokens) > 512:
                raise ValueError('expression token budget')
        self.index = 0

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else ''

    def take(self, token=None):
        found = self.peek()
        if not found or token is not None and found != token:
            raise ValueError('unexpected token')
        self.index += 1
        return found

    def expression(self, level=0, depth=0):
        if depth > 48:
            raise ValueError('expression nesting budget')
        token = self.take()
        if token == '(':
            at = self.index
            cast = self.take() if CTYPE.fullmatch(self.peek()) else ''
            if cast and self.peek() == '*':
                cast += self.take()
            if cast and self.peek() == ')':
                self.take();left = Expr('cast', cast, (self.expression(11,depth+1),))
            else:
                self.index = at
                left = self.expression(0,depth+1);self.take(')')
        elif token in ('-','+','~','!','&','*'):
            left = Expr('unary',token,(self.expression(11,depth+1),))
        elif re.match(r'[\w"]',token):
            left = Expr('atom',token)
            if self.peek() == '(' and re.fullmatch(r'[A-Za-z_]\w*',token):
                self.take();args=[]
                if self.peek() != ')':
                    while True:
                        args.append(self.expression(0,depth+1))
                        if self.peek() != ',':break
                        self.take()
                self.take(')');left = Expr('call',token,tuple(args))
        else:
            raise ValueError('unexpected expression')
        while self.peek() in PRECEDENCE and PRECEDENCE[self.peek()] >= level:
            op = self.take()
            right = self.expression(PRECEDENCE[op]+1,depth+1)
            left = Expr(op,'',(left,right))
        return left


def integer(node):
    if node.op != 'atom' or not re.fullmatch(r'0x[\dA-Fa-f]+|\d+',node.value):
        return None
    return int(node.value, 0) if node.value.startswith('0x') else int(node.value)


def constant(value):
    return Expr('unary','-',(Expr('atom',f'0x{-value:X}'),)) if value < 0 else Expr('atom',f'0x{value:X}')


def literal_type(value):
    if 0<=value<1<<31:return 32,False
    if 0<=value<1<<32:return 32,True
    if 0<=value<1<<63:return 64,False
    if 0<=value<1<<64:return 64,True
    return None


def project(node, width):
    """Project only operations whose low bits do not depend on high bits."""
    if node.op=='call' and node.value in ('unknown_argument_upper_bits','unknown_return_upper_bits') and len(node.children)==2:
        known=integer(node.children[1])
        if known is not None and known>=width:
            return node.children[0]
    if node.op in ('+','-','*','^','&','|','<<'):
        children=tuple(project(child,width) if index==0 or node.op!='<<' else child for index,child in enumerate(node.children))
        return Expr(node.op,node.value,children)
    if node.op=='unary' and node.value in ('-','~'):
        return Expr(node.op,node.value,(project(node.children[0],width),))
    return node


def simplify(node, types, render_memory=True):
    children = tuple(simplify(child,types,render_memory) for child in node.children)
    node = Expr(node.op,node.value,children)
    if node.op == 'cast':
        inner = children[0]
        if inner.op == 'cast' and inner.value == node.value:
            return inner
        if inner.op == 'atom' and types.get(inner.value) == node.value:
            return inner
        width = re.fullmatch(r'(u?)int(8|16|32|64)_t',node.value)
        if width:
            size = int(width[2]);value = integer(inner)
            if value is not None:
                value %= 1 << size
                if not width[1] and value >= 1 << (size-1):value -= 1 << size
                # A cast also controls integer promotions. For example,
                # (uint32_t)1 < -1 differs from the untyped literal 1 < -1.
                return Expr('cast',node.value,(constant(value),))
            if inner.op == 'call' and inner.value in ('unknown_argument_upper_bits','unknown_return_upper_bits') and len(inner.children) == 2:
                known = integer(inner.children[1])
                if known is not None and size <= known:
                    return simplify(Expr('cast',node.value,(inner.children[0],)),types,render_memory)
            projected=project(inner,size)
            if projected!=inner:
                return simplify(Expr('cast',node.value,(projected,)),types,render_memory)
    if node.op == 'call':
        # A scalar lane extracted from a zero/unspecified-upper vector is
        # precisely the original scalar, including NaN bit patterns.
        match = re.fullmatch(r'f(32|64)_lane0',node.value)
        if match and len(children) == 1 and children[0].op == 'call' and children[0].value in ('vec128_from_f'+match[1],'vec128_return_f'+match[1]):
            return children[0].children[0]
        if match and len(children)==1 and children[0].op=='call' and children[0].value=='replace_low_f'+match[1]:
            old,new=children[0].children
            if old.op=='atom' or old.op=='call' and re.fullmatch(r'vec128_(?:from|return)_f(?:32|64)|unknown_entry',old.value):
                return new
        match = re.fullmatch(r'load_([uf])(8|16|32|64)',node.value)
        if match and len(children) == 1 and render_memory:
            kind='uint'+match[2]+'_t' if match[1]=='u' else 'float' if match[2]=='32' else 'double'
            return Expr('unary','*',(Expr('cast',kind+'*',children),))
    if node.op == 'unary' and node.value in ('+','-','~','!'):
        value = integer(children[0])
        if value is not None:
            result={'+':lambda x:x,'-':lambda x:-x,'~':lambda x:~x,'!':lambda x:int(not x)}[node.value](value)
            if node.value in ('+','!') or literal_type(value)==(32,False) and -(1<<31)<result<1<<31:
                return constant(result)
    if node.op in PRECEDENCE:
        left,right = children
        if node.op in ('+','-','*','/','%','<<','>>','&','|','^'):
            def integer_address(value):
                spelling=types.get(value.value,'') if value.op=='atom' else value.value if value.op=='cast' else ''
                return Expr('cast','uintptr_t',(value,)) if spelling.endswith('*') else value
            left,right=integer_address(left),integer_address(right)
            node=Expr(node.op,node.value,(left,right))
        a,b = integer(left),integer(right)
        if a is not None and b is not None:
            operations = {'+':lambda:a+b,'-':lambda:a-b,'*':lambda:a*b,'&':lambda:a&b,'|':lambda:a|b,'^':lambda:a^b}
            if node.op in operations:
                left_type,right_type=literal_type(a),literal_type(b)
                # Constant folding must retain the usual C arithmetic type
                # and must not turn an unsigned wrap into a wider integer.
                if left_type and right_type:
                    common=max(left_type,right_type)
                    result=operations[node.op]()
                    if literal_type(result)==common:return constant(result)
            if node.op in ('<<','>>') and literal_type(a) and 0 <= b < literal_type(a)[0]:
                result=a << b if node.op=='<<' else a >> b
                if literal_type(result)==literal_type(a):return constant(result)
        if b == 0 and node.op in ('+','-','|','^','<<','>>') or b == 1 and node.op in ('*','/'):
            return left
        if a == 0 and node.op in ('+','|','^') or a == 1 and node.op == '*':
            return right
    return node


def pretty(text, types=None, render_memory=True):
    try:
        parser = Parser(text)
        node = parser.expression()
        if parser.peek():
            return text
        return simplify(node,types or {},render_memory).render()
    except (ValueError,RecursionError,OverflowError):
        return text
