"""Bounded x86 control flow and conservative C-like lifting of caller-provided bytes.

This module has no process/file access. Unknown instructions and unresolved control
transfers remain visible; the output is pseudocode, not reconstructed source code.
"""
from collections import deque
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86_const import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

MAX_BYTES = 16384
MAX_INSTRUCTIONS = 2048
MAX_BLOCKS = 128
TERMINALS = {'ret', 'retf', 'retfq', 'iret', 'iretd', 'iretq', 'ud2', 'hlt', 'int3'}


def hx(value):
    return f'0x{value:X}'


def flow(ins):
    name = ins.mnemonic
    if name in TERMINALS:
        return 'return' if name.startswith('ret') else 'stop', None
    if name.startswith('j') or name.startswith('loop') or name == 'ljmp':
        target = ins.operands[0].imm if ins.operands and ins.operands[0].type == X86_OP_IMM else None
        return ('jump' if name in ('jmp', 'ljmp') else 'condition'), target
    return 'next', None


def decode(raw, start, bits):
    raw = raw[:MAX_BYTES]
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True
    end = start + len(raw)
    pending = deque([start])
    decoded = {}
    notes = []
    limit = False
    while pending:
        pc = pending.popleft()
        while start <= pc < end and pc not in decoded:
            if len(decoded) >= MAX_INSTRUCTIONS:
                notes.append('명령어 해석 상한 적용')
                limit = True
                pending.clear()
                break
            ins = next(md.disasm(raw[pc-start:pc-start+15], pc, count=1), None)
            if ins is None:
                notes.append('해석 불가 바이트: ' + hx(pc))
                break
            if any(other.address < ins.address + ins.size and ins.address < other.address + other.size
                   for other in decoded.values()):
                notes.append('명령어 경계가 겹치는 분기: ' + hx(pc))
                break
            decoded[pc] = ins
            kind, target = flow(ins)
            pc = ins.address + ins.size
            if kind in ('return', 'stop'):
                break
            if kind in ('jump', 'condition'):
                if target is not None and start <= target < end:
                    pending.append(target)
                if kind == 'condition':
                    pending.append(pc)
                break
    leaders = {start}
    for ins in decoded.values():
        kind, target = flow(ins)
        if kind in ('jump', 'condition'):
            if target in decoded:
                leaders.add(target)
            if kind == 'condition' and ins.address + ins.size in decoded:
                leaders.add(ins.address + ins.size)
    blocks = []
    for address in sorted(decoded):
        ins = decoded[address]
        if (not blocks or address in leaders or
                blocks[-1]['instructions'][-1].address + blocks[-1]['instructions'][-1].size != address or
                flow(blocks[-1]['instructions'][-1])[0] != 'next'):
            blocks.append({'id': hx(address), 'address': address, 'instructions': []})
        blocks[-1]['instructions'].append(ins)
    if len(blocks) > MAX_BLOCKS:
        blocks = blocks[:MAX_BLOCKS]
        notes.append('기본 블록 상한 적용')
        limit = True
    addresses = {block['address']: block['id'] for block in blocks}
    edges = []
    external = {}
    for block in blocks:
        ins = block['instructions'][-1]
        kind, target = flow(ins)
        block['terminal'] = kind
        successors = []
        if kind == 'condition':
            successors = [(target, 'true'), (ins.address + ins.size, 'false')]
        elif kind == 'jump':
            successors = [(target, 'jump')]
        elif kind == 'next':
            successors = [(ins.address + ins.size, 'fallthrough')]
        for destination, edge_kind in successors:
            if destination in addresses:
                destination_id = addresses[destination]
            else:
                destination_id = hx(destination) if destination is not None else 'indirect_' + block['id']
                label = ('간접 분기 · ' + ins.op_str) if destination is None else (
                    '범위 밖 분기 · ' + hx(destination) if not start <= destination < end else
                    '해석하지 못한 경로 · ' + hx(destination))
                external[destination_id] = {'id': destination_id, 'address': hx(destination) if destination is not None else '',
                    'label': label, 'external': True, 'instructions': [], 'terminal': 'external'}
            edges.append({'source': block['id'], 'target': destination_id, 'kind': edge_kind})
    # Dominator back edges describe natural loops. DFS additionally identifies
    # cyclic edges in irreducible graphs so top-down layout cannot loop forever.
    ids = {block['id'] for block in blocks}
    preds = {key: [] for key in ids}
    for edge in edges:
        if edge['target'] in ids:
            preds[edge['target']].append(edge['source'])
    entry = hx(start)
    dom = {key: ({key} if key == entry else set(ids)) for key in ids}
    for _ in range(MAX_BLOCKS):
        changed = False
        for key in ids - {entry}:
            parents = preds[key]
            value = {key} | (set.intersection(*(dom[p] for p in parents)) if parents else set())
            if value != dom[key]:
                dom[key] = value
                changed = True
        if not changed:
            break
    outgoing = {key: [] for key in ids}
    for edge in edges:
        edge['back_edge'] = edge['target'] in dom.get(edge['source'], set())
        edge['layout_back'] = edge['back_edge']
        outgoing[edge['source']].append(edge)
    colors = {}
    def visit(key):
        colors[key] = 1
        for edge in outgoing.get(key, []):
            destination = edge['target']
            if colors.get(destination) == 1:
                edge['layout_back'] = True
            elif not colors.get(destination):
                visit(destination)
        colors[key] = 2
    if blocks:
        visit(entry)
    serialized = [{'id': b['id'], 'address': b['id'], 'label': 'loc_' + b['id'][2:], 'external': False,
        'terminal': b['terminal'], 'instructions': [instruction(i) for i in b['instructions']]} for b in blocks]
    if external:
        notes.append('범위 밖 또는 간접 분기 대상은 추적하지 않았습니다')
    return blocks, {'entry': entry, 'nodes': serialized + list(external.values()), 'edges': edges,
                    'block_count': len(blocks), 'unresolved_count': len(external),
                    'truncated': limit, 'notes': list(dict.fromkeys(notes))}, dom


def instruction(ins):
    return {'address': hx(ins.address), 'bytes': ins.bytes.hex(' '),
            'instruction': ins.mnemonic, 'operands': ins.op_str}


def family(name):
    groups = {'rax': ('rax','eax','ax','al','ah'), 'rbx': ('rbx','ebx','bx','bl','bh'),
              'rcx': ('rcx','ecx','cx','cl','ch'), 'rdx': ('rdx','edx','dx','dl','dh'),
              'rsi': ('rsi','esi','si','sil'), 'rdi': ('rdi','edi','di','dil'),
              'rsp': ('rsp','esp','sp','spl'), 'rbp': ('rbp','ebp','bp','bpl')}
    for root, aliases in groups.items():
        if name in aliases:
            return root
    match = re.fullmatch(r'(r\d+)[dwb]?', name)
    return match[1] if match else name


def literal(value):
    return ('-' if value < 0 else '') + hx(abs(value))


def safe_name(name):
    result = re.sub(r'[^A-Za-z0-9_]', '_', name)
    return result if result and not result[0].isdigit() else 'sub_' + result


class Lifter:
    def __init__(self, blocks, graph, bits, names):
        self.blocks, self.graph, self.bits, self.names = blocks, graph, bits, names
        self.variables = []
        self.regs, self.slots, self.input_args, self.lifted = {}, {}, {}, {}
        self.stack_args = set()
        self.unsupported = []
        self.flags = self.variable('flag_state', 'CPU 상태 플래그', 'unknown_flags()')
        self.sp = self.variable('uintptr_t', '진입 시 스택 주소', 'entry_stack_pointer()')
        self.stack_states = self.stack_analysis()
        self.slot_aliases = self.find_slot_aliases()
        self.last_compare = None
        # Register definitions at block entries use intersection: a value is
        # defined only when every incoming path defines it.
        all_regs = set()
        reads, writes = {}, {}
        for block in blocks:
            r, w = set(), set()
            for ins in block['instructions']:
                rd, wr = ins.regs_access()
                zero = (ins.mnemonic in ('xor','sub') and len(ins.operands) == 2 and
                        ins.operands[0].type == ins.operands[1].type == X86_OP_REG and
                        ins.operands[0].reg == ins.operands[1].reg)
                r |= ({family(ins.reg_name(x)) for x in rd} if not zero else set()) - w
                # Partial register writes do not define the untouched upper bits.
                full_writes = set()
                for x in wr:
                    register = ins.reg_name(x)
                    root = family(register)
                    if register == root or (register.startswith('e') and root.startswith('r')) or re.fullmatch(r'r\d+d',register):
                        full_writes.add(root)
                w |= full_writes
            reads[block['id']], writes[block['id']] = r, w
            all_regs |= r | w
        keys = {block['id'] for block in blocks}
        self.defined_in = {key: (set() if key == graph['entry'] else set(all_regs)) for key in keys}
        defined_out = {key: set(all_regs) for key in keys}
        for _ in range(MAX_BLOCKS):
            changed = False
            for block in blocks:
                key = block['id']
                parents = [e['source'] for e in graph['edges'] if e['target'] == key]
                value = set.intersection(*(defined_out[p] for p in parents)) if parents and key != graph['entry'] else set()
                output = value | writes[key]
                if value != self.defined_in[key] or output != defined_out[key]:
                    self.defined_in[key], defined_out[key], changed = value, output, True
            if not changed:
                break
        inputs = set().union(*(reads[key] - self.defined_in[key] for key in keys)) if keys else set()
        abi_regs = ('rcx','rdx','r8','r9') if bits == 64 else ()
        for index, register in enumerate(abi_regs, 1):
            if register in inputs:
                self.input_args[register] = index
        for register in sorted(all_regs):
            if register not in ('rflags','eflags','rip','eip'):
                self.register(register)
        for block in blocks:
            self.last_compare = None
            lines = []
            for ins in block['instructions']:
                self.current_ins = ins
                lines.extend(self.lift(ins))
            self.lifted[block['id']] = lines

    def variable(self, kind, storage='', initial=None):
        name = 'v' + str(len(self.variables) + 1)
        self.variables.append({'name': name, 'type': kind, 'storage': storage, 'initial': initial})
        return name

    def register(self, name):
        root = family(name)
        if root not in self.regs:
            self.regs[root] = self.new_reg(root)
        return self.regs[root]

    def new_reg(self, root):
        if root == 'rsp':
            initial = self.sp
        elif root in self.input_args:
            initial = 'a' + str(self.input_args[root])
        else:
            initial = 'unknown_entry("' + root + '")'
        kind = 'vec128_t' if root.startswith('xmm') else ('vec256_t' if root.startswith('ymm') else 'uint' + str(self.bits) + '_t')
        return self.variable(kind, root, initial)

    def stack_analysis(self):
        if not self.blocks:
            return {}
        entry = self.graph['entry']
        incoming = {entry: (0, None)}
        states = {}
        work = deque([entry])
        by_id = {block['id']: block for block in self.blocks}
        visits = {}
        word = self.bits // 8
        while work:
            key = work.popleft()
            visits[key] = visits.get(key, 0) + 1
            if visits[key] > MAX_BLOCKS:
                continue
            sp, bp = incoming[key]
            for ins in by_id[key]['instructions']:
                states[ins.address] = (sp, bp)
                op = ins.operands
                if ins.mnemonic == 'push':
                    sp = sp - word if sp is not None and op and op[0].size == word else None
                elif ins.mnemonic == 'pop':
                    sp = sp + word if sp is not None and op and op[0].size == word else None
                    if op and op[0].type == X86_OP_REG:
                        destination = family(ins.reg_name(op[0].reg))
                        if destination == 'rsp': sp = None
                        if destination == 'rbp': bp = None
                elif ins.mnemonic in ('sub','add') and len(op) == 2 and op[0].type == X86_OP_REG and family(ins.reg_name(op[0].reg)) == 'rsp':
                    sp = (sp + op[1].imm * (-1 if ins.mnemonic == 'sub' else 1)) if sp is not None and op[1].type == X86_OP_IMM and op[0].size == word else None
                elif ins.mnemonic == 'mov' and len(op) == 2 and op[0].type == op[1].type == X86_OP_REG:
                    dst, src = family(ins.reg_name(op[0].reg)), family(ins.reg_name(op[1].reg))
                    if dst == 'rbp': bp = sp if src == 'rsp' and op[0].size == op[1].size == word else None
                    if dst == 'rsp': sp = bp if src == 'rbp' and op[0].size == op[1].size == word else None
                elif ins.mnemonic == 'leave': sp, bp = (bp + word if bp is not None else None), None
                elif any(family(ins.reg_name(x)) == 'rsp' for x in ins.regs_access()[1]) and ins.mnemonic not in ('call','ret','retf'):
                    sp = None
                if any(family(ins.reg_name(x)) == 'rbp' for x in ins.regs_access()[1]):
                    if not (ins.mnemonic == 'mov' and len(op) == 2 and op[0].type == op[1].type == X86_OP_REG):
                        bp = None
            for edge in self.graph['edges']:
                dst = edge['target']
                if edge['source'] != key or dst not in by_id:
                    continue
                value = (sp, bp)
                if dst in incoming:
                    value = tuple(a if a == b else None for a, b in zip(incoming[dst], value))
                    if value == incoming[dst]:
                        continue
                incoming[dst] = value
                work.append(dst)
        return states

    def find_slot_aliases(self):
        accesses = set()
        word = self.bits // 8
        for block in self.blocks:
            for ins in block['instructions']:
                sp, bp = self.stack_states.get(ins.address, (None,None))
                if ins.mnemonic == 'push' and sp is not None and ins.operands[0].size == word: accesses.add((sp-word,word))
                if ins.mnemonic == 'pop' and sp is not None and ins.operands[0].size == word: accesses.add((sp,word))
                for op in ins.operands:
                    if op.type != X86_OP_MEM or op.mem.index or op.mem.segment or not op.mem.base or ins.addr_size*8 != self.bits:
                        continue
                    base = family(ins.reg_name(op.mem.base))
                    offset = sp if base == 'rsp' else bp if base == 'rbp' else None
                    if offset is not None: accesses.add((offset+op.mem.disp,op.size))
        ordered, aliases = sorted(accesses), set()
        for index, item in enumerate(ordered):
            for other in ordered[index+1:]:
                if other[0] >= item[0]+item[1]: break
                aliases.update((item,other))
        return aliases

    def memory_address(self, operand):
        mem = operand.mem
        parts = []
        if mem.base:
            name = self.current_ins.reg_name(mem.base)
            if name in ('rip','eip'): parts.append(hx(self.current_ins.address + self.current_ins.size))
            elif family(name) in ('rsp','rbp') and self.current_ins.addr_size*8 == self.bits:
                sp, bp = self.stack_states.get(self.current_ins.address, (None,None))
                offset = sp if family(name) == 'rsp' else bp
                parts.append(self.sp + (' + ' + literal(offset) if offset else '') if offset is not None else self.register(name))
            else: parts.append(self.register(name))
        if mem.index: parts.append(self.register(self.current_ins.reg_name(mem.index)) + (f' * {mem.scale}' if mem.scale != 1 else ''))
        if mem.disp or not parts: parts.append(literal(mem.disp))
        address = '(' + ' + '.join(parts).replace('+ -','- ') + ')'
        width = self.current_ins.addr_size*8
        if width < self.bits: address = f'((uint{width}_t){address})'
        if mem.segment: address = '(segment_base("' + self.current_ins.reg_name(mem.segment) + '") + ' + address + ')'
        return address

    def stack_slot(self, operand):
        mem = operand.mem
        if not mem.base or mem.index or mem.segment or self.current_ins.addr_size*8 != self.bits:
            return None
        name = family(self.current_ins.reg_name(mem.base))
        if name not in ('rsp','rbp'):
            return None
        sp, bp = self.stack_states.get(self.current_ins.address, (None,None))
        offset = sp if name == 'rsp' else bp
        if offset is None:
            return None
        offset += mem.disp
        return self.stack_location(offset,operand.size)

    def stack_location(self, offset, size):
        key = (offset,size)
        if key in self.slot_aliases:
            return None
        if key not in self.slots:
            argument_start = 40 if self.bits == 64 else 4
            arg_index = (offset - argument_start) // (self.bits//8) + (5 if self.bits == 64 else 1)
            if offset >= argument_start and (offset-argument_start) % (self.bits//8) == 0:
                self.stack_args.add(arg_index)
                initial = 'a' + str(arg_index)
            else: initial = 'unknown_stack(' + str(offset) + ')'
            self.slots[key] = self.variable('uint' + str(size*8) + '_t', 'stack ' + str(offset), initial)
        return self.slots[key]

    def value(self, operand):
        if operand.type == X86_OP_IMM:
            return literal(operand.imm)
        if operand.type == X86_OP_REG:
            name = self.current_ins.reg_name(operand.reg)
            register = self.register(name)
            if family(name) in ('rsp','rbp'):
                sp, bp = self.stack_states.get(self.current_ins.address,(None,None))
                offset = sp if family(name) == 'rsp' else bp
                if offset is not None: register = '('+self.sp+' + '+literal(offset)+')'
            if name in ('ah','bh','ch','dh'):
                return f'((uint8_t)({register} >> 8))'
            if operand.size*8 < self.bits:
                return f'((uint{operand.size*8}_t){register})'
            return register
        if operand.type == X86_OP_MEM:
            slot = self.stack_slot(operand)
            return slot or f'load_u{operand.size*8}({self.memory_address(operand)})'
        return 'unknown_operand()'

    def assign(self, operand, expression):
        width = operand.size * 8
        if operand.type == X86_OP_REG:
            name = self.current_ins.reg_name(operand.reg)
            register = self.register(name)
            if width == 32 and self.bits == 64:
                return register + ' = (uint32_t)(' + expression + ');'
            if width < self.bits:
                offset = 8 if name in ('ah','bh','ch','dh') else 0
                return f'{register} = replace_bits({register}, {expression}, {offset}, {width});'
            return register + ' = ' + expression + ';'
        if operand.type == X86_OP_MEM:
            slot = self.stack_slot(operand)
            return f'{slot} = (uint{width}_t)({expression});' if slot else f'store_u{width}({self.memory_address(operand)}, {expression});'
        return '/* invalid destination */'

    def condition(self, suffix):
        alias = {'e':'z','ne':'nz','c':'b','nc':'ae','nae':'b','nb':'ae','na':'be','nbe':'a','ng':'le','nge':'l','nl':'ge','nle':'g','pe':'p','po':'np'}
        suffix = alias.get(suffix, suffix)
        if self.last_compare:
            kind, left, right, bits = self.last_compare
            if kind == 'cmp':
                signs = {'z':'==','nz':'!=','a':'>','ae':'>=','b':'<','be':'<=','g':'>','ge':'>=','l':'<','le':'<='}
                if suffix in signs:
                    signed = suffix in ('g','ge','l','le')
                    cast = f'int{bits}_t' if signed else f'uint{bits}_t'
                    return f'({cast}){left} {signs[suffix]} ({cast}){right}'
            if kind == 'test' and suffix in ('z','nz','s','ns'):
                expression = left if left == right else '(' + left + ' & ' + right + ')'
                if suffix in ('s','ns'): return f'(int{bits}_t){expression} ' + ('<' if suffix == 's' else '>=') + ' 0'
                return expression + (' == 0' if suffix == 'z' else ' != 0')
        flag = self.flags
        return {'z':flag+'.ZF','nz':'!'+flag+'.ZF','b':flag+'.CF','ae':'!'+flag+'.CF',
            'be':f'({flag}.CF || {flag}.ZF)','a':f'(!{flag}.CF && !{flag}.ZF)',
            'l':f'({flag}.SF != {flag}.OF)','ge':f'({flag}.SF == {flag}.OF)',
            'le':f'({flag}.ZF || {flag}.SF != {flag}.OF)',
            'g':f'(!{flag}.ZF && {flag}.SF == {flag}.OF)',
            's':flag+'.SF','ns':'!'+flag+'.SF','o':flag+'.OF','no':'!'+flag+'.OF',
            'p':flag+'.PF','np':'!'+flag+'.PF'}.get(suffix, f'unknown_condition("{suffix}")')

    def fallback(self, ins):
        self.unsupported.append(instruction(ins))
        self.last_compare = None
        text = (ins.mnemonic + ' ' + ins.op_str).replace('\\','\\\\').replace('"','\\"')
        result = [f'asm_volatile("{text}"); /* 미변환 명령 */']
        for register in ins.regs_access()[1]:
            name = ins.reg_name(register)
            if name == 'rflags' or name == 'eflags':
                result.append(self.flags + ' = unknown_flags();')
            elif family(name) not in ('rip','eip'):
                result.append(self.register(name) + ' = unknown_after_asm("' + name + '");')
        return result

    def lift(self, ins):
        op, name = ins.operands, ins.mnemonic
        kind, target = flow(ins)
        if kind == 'condition':
            if name in ('jrcxz','jecxz','jcxz'):
                register = {'jrcxz':'rcx','jecxz':'ecx','jcxz':'cx'}[name]
                width = {'jrcxz':64,'jecxz':32,'jcxz':16}[name]
                condition = '(uint'+str(width)+'_t)'+self.register(register) + ' == 0'
            elif name.startswith('loop'):
                width = ins.addr_size*8
                counter = self.register('rcx' if width == 64 else 'ecx')
                condition = f'(uint{width}_t){counter} != 0'
                if name in ('loope','loopz'): condition += ' && ' + self.flags + '.ZF'
                if name in ('loopne','loopnz'): condition += ' && !' + self.flags + '.ZF'
                ins._pseudo_condition = condition
                decrement = '(uint' + str(width) + '_t)(' + counter + ' - 1)'
                if width < self.bits and width != 32:
                    decrement = f'replace_bits({counter}, {decrement}, 0, {width})'
                return [counter + ' = ' + decrement + ';']
            else: condition = self.condition(name[1:])
            ins._pseudo_condition = condition
            return []
        if kind in ('jump','return','stop'):
            return []
        if name in ('nop','endbr64','endbr32'):
            return []
        if name in ('push','pop') and len(op) == 1 and op[0].size == self.bits//8:
            sp, _ = self.stack_states.get(ins.address,(None,None))
            word = self.bits//8
            location = sp-word if name == 'push' and sp is not None else sp
            address = '('+self.sp+' + '+literal(location)+')' if location is not None else self.register('rsp')+(' - '+str(word) if name=='push' else '')
            slot = self.stack_location(location,word) if location is not None else None
            if name == 'push':
                saved = self.variable('uint'+str(self.bits)+'_t','push '+hx(ins.address))
                return [saved+' = '+self.value(op[0])+';',
                        (slot+' = '+saved+';') if slot else f'store_u{self.bits}({address}, {saved});',
                        self.register('rsp')+' = '+address+';']
            result = [self.assign(op[0],slot or f'load_u{self.bits}({address})')]
            if not (op[0].type == X86_OP_REG and family(ins.reg_name(op[0].reg)) == 'rsp'):
                result.append(self.register('rsp')+' = '+address+' + '+str(word)+';')
            return result
        if name == 'leave':
            _, bp = self.stack_states.get(ins.address,(None,None))
            address = '('+self.sp+' + '+literal(bp)+')' if bp is not None else self.register('rbp')
            return [self.register('rsp')+' = '+address+' + '+str(self.bits//8)+';',
                    self.register('rbp')+f' = load_u{self.bits}({address});']
        if name in ('mov','movabs','movzx','movsx','movsxd','lea') and len(op) == 2:
            expression = self.memory_address(op[1]) if name == 'lea' and op[1].type == X86_OP_MEM else self.value(op[1])
            if name in ('movsx','movsxd'): expression = f'(int{op[1].size*8}_t)({expression})'
            return [self.assign(op[0], expression)]
        if name in ('cmp','test') and len(op) == 2:
            bits = op[0].size*8
            left = self.variable('uint'+str(bits)+'_t', '비교 ' + hx(ins.address))
            left_value, right_value = self.value(op[0]), self.value(op[1])
            same = left_value == right_value
            right = left if same else self.variable('uint'+str(bits)+'_t', '비교 ' + hx(ins.address))
            self.last_compare = (name,left,right,bits)
            result = [left + ' = ' + left_value + ';']
            if not same: result.append(right + ' = ' + right_value + ';')
            result.append(f'{self.flags} = {name}_flags_u{bits}({left}, {right});')
            return result
        operators = {'add':'+','sub':'-','xor':'^','and':'&','or':'|','shl':'<<','sal':'<<','shr':'>>','sar':'>>','imul':'*'}
        if name in operators and len(op) >= 2:
            if name == 'imul' and len(op) == 3: left, right = self.value(op[1]), self.value(op[2])
            else: left, right = self.value(op[0]), self.value(op[1])
            bits = op[0].size*8
            if name in ('shl','sal','shr','sar'): right = '(' + right + ' & ' + str(63 if bits == 64 else 31) + ')'
            if name in ('sar','imul'): left = '(int' + str(bits) + '_t)(' + left + ')'
            expression = '0' if name == 'xor' and left == right else '(' + left + ' ' + operators[name] + ' ' + right + ')'
            self.last_compare = None
            return [f'{self.flags} = {name}_flags_u{bits}({left}, {right}, {self.flags});', self.assign(op[0], expression)]
        if name in ('inc','dec','neg','not') and len(op) == 1:
            value, bits = self.value(op[0]), op[0].size*8
            expression = {'inc':'('+value+' + 1)','dec':'('+value+' - 1)','neg':'(-'+value+')','not':'(~'+value+')'}[name]
            if name != 'not': self.last_compare = None
            return ([f'{self.flags} = {name}_flags_u{bits}({value}, {self.flags});'] if name != 'not' else []) + [self.assign(op[0],expression)]
        if name.startswith('set') and len(op) == 1:
            return [self.assign(op[0], '(' + self.condition(name[3:]) + ' ? 1 : 0)')]
        if name.startswith('cmov') and len(op) == 2:
            return ['if (' + self.condition(name[4:]) + ') ' + self.assign(op[0], self.value(op[1]))]
        if name == 'call' and op:
            target = op[0].imm if op[0].type == X86_OP_IMM else None
            target_name = self.names.get(target, 'sub_' + f'{target:X}') if target is not None else '간접 호출'
            location = hx(target) if target is not None else self.value(op[0])
            saved = self.variable('call_state', 'call ' + hx(ins.address))
            context = ', '.join(self.register(register) for register in ('rcx','rdx','r8','r9','rsp') if self.bits == 64)
            if self.bits == 32: context = self.register('rsp')
            result = [f'/* 호출: {target_name.replace("*/", "* /")} · 인자/규약 추정 */',
                      f'{saved} = call_unknown({location}, machine_context({context}));']
            for register in ('rax','rcx','rdx','r8','r9','r10','r11') if self.bits == 64 else ('rax','rcx','rdx'):
                result.append(self.register(register) + ' = ' + saved + '.' + register + ';')
            for register in list(self.regs):
                if register.startswith(('xmm','ymm','zmm')) and register[-1:].isdigit():
                    result.append(self.regs[register]+' = unknown_call_clobber("'+register+'");')
            self.last_compare = None
            result.append(self.flags + ' = unknown_flags();')
            return result
        return self.fallback(ins)


class CannotStructure(Exception):
    pass


def pseudocode(lifter, name, graph, dominators):
    blocks = {b['id']: b for b in lifter.blocks}
    outgoing = {key: [e for e in graph['edges'] if e['source'] == key] for key in blocks}
    loops = {}
    for edge in graph['edges']:
        if not edge['back_edge'] or edge['target'] not in blocks:
            continue
        header = edge['target']
        members = {header, edge['source']}
        stack = [edge['source']] if edge['source'] != header else []
        while stack:
            current = stack.pop()
            for parent in (e['source'] for e in graph['edges'] if e['target'] == current):
                if parent not in members and header in dominators.get(parent, set()):
                    members.add(parent)
                    stack.append(parent)
        loops.setdefault(header,set()).update(members)
    exit_id = '__exit__'
    all_ids = set(blocks) | {exit_id}
    post = {key: set(all_ids) if key != exit_id else {exit_id} for key in all_ids}
    for _ in range(MAX_BLOCKS):
        changed = False
        for key in blocks:
            destinations = [e['target'] if e['target'] in blocks else exit_id for e in outgoing[key]] or [exit_id]
            value = {key} | set.intersection(*(post[d] for d in destinations))
            if value != post[key]: post[key], changed = value, True
        if not changed: break

    def terminal(key):
        last = blocks[key]['instructions'][-1]
        if last.mnemonic.startswith('ret'):
            # Machine return register; source return type is not inferred.
            lifter.current_ins = last
            return ['return ' + lifter.register('rax' if lifter.bits == 64 else 'eax') + ';']
        if blocks[key]['terminal'] == 'stop': return ['trap("' + last.mnemonic + '");']
        return []

    def branch_region(start, join, allowed):
        found, pending = set(), [start]
        while pending:
            current = pending.pop()
            if current == join or current == exit_id: continue
            if current not in allowed: raise CannotStructure()
            if current in found: continue
            found.add(current)
            pending.extend(e['target'] if e['target'] in blocks else exit_id for e in outgoing[current])
        return found

    def emit(start, stop, allowed, seen, depth=0, loop=None):
        if depth > MAX_BLOCKS: raise CannotStructure()
        code, current = [], start
        while current != stop and current != exit_id:
            if loop and current == loop[0]:
                code.append('continue;');break
            if loop and current == loop[1]:
                code.append('break;');break
            if current not in allowed or current in seen: raise CannotStructure()
            seen.add(current)
            block = blocks[current]
            edges = outgoing[current]
            statements = lifter.lifted[current]
            last = block['instructions'][-1]
            if current in loops and block['terminal'] == 'condition' and len(edges) == 2:
                members = loops[current]
                inside = [e for e in edges if e['target'] in members]
                outside = [e for e in edges if e['target'] not in members]
                all_exits = {e['target'] for node in members for e in outgoing[node] if e['target'] not in members}
                if len(inside) != 1 or len(outside) != 1 or len(all_exits) != 1: raise CannotStructure()
                body, after = inside[0]['target'], outside[0]['target']
                if after not in blocks and after != stop: raise CannotStructure()
                condition = last._pseudo_condition
                exit_condition = '!(' + condition + ')' if inside[0]['kind'] == 'true' else condition
                nested = statements + ['if (' + exit_condition + ') break;']
                nested += emit(body,current,members-{current},seen,depth+1,(current,after))
                code += ['while (1) {'] + ['    '+line for line in nested] + ['}']
                current = after
                continue
            code += statements
            if block['terminal'] in ('return','stop'):
                code += terminal(current)
                break
            if block['terminal'] == 'condition' and len(edges) == 2:
                true = next(e['target'] for e in edges if e['kind'] == 'true')
                false = next(e['target'] for e in edges if e['kind'] == 'false')
                if true not in blocks or false not in blocks: raise CannotStructure()
                common = (post[true] & post[false]) - {current}
                candidates = common & (allowed | {stop,exit_id})
                if not candidates: raise CannotStructure()
                join = max(candidates, key=lambda key: len(post.get(key,{key})))
                left, right = branch_region(true,join,allowed), branch_region(false,join,allowed)
                if left & right: raise CannotStructure()
                condition = last._pseudo_condition
                if true == join:
                    nested = emit(false,join,allowed,seen,depth+1,loop)
                    code += ['if (!('+condition+')) {'] + ['    '+line for line in nested] + ['}']
                else:
                    nested = emit(true,join,allowed,seen,depth+1,loop)
                    code += ['if ('+condition+') {'] + ['    '+line for line in nested] + ['}']
                    if false != join:
                        nested = emit(false,join,allowed,seen,depth+1,loop)
                        code += ['else {'] + ['    '+line for line in nested] + ['}']
                current = join
                continue
            if len(edges) != 1 or edges[0]['target'] not in blocks: raise CannotStructure()
            current = edges[0]['target']
        return code

    style = 'structured'
    seen = set()
    try:
        body = emit(graph['entry'],exit_id,set(blocks),seen)
        if seen != set(blocks): raise CannotStructure()
    except CannotStructure:
        style = 'labels'
        body = []
        for key, block in blocks.items():
            body.append('loc_' + key[2:] + ':')
            body += ['    '+line for line in lifter.lifted[key]]
            last, edges = block['instructions'][-1], outgoing[key]
            if block['terminal'] in ('return','stop'):
                body += ['    '+line for line in terminal(key)]
            elif block['terminal'] == 'condition':
                for edge in edges:
                    label = 'loc_' + edge['target'][2:] if edge['target'] in blocks else 'unresolved_' + key[2:]
                    body.append(('    if ('+last._pseudo_condition+') ' if edge['kind']=='true' else '    ') + 'goto '+label+';')
            elif edges:
                edge = edges[0]
                if edge['target'] in blocks: body.append('    goto loc_' + edge['target'][2:] + ';')
                else:
                    body.append('    /* 간접/범위 밖 제어 이전: ' + last.mnemonic + ' ' + last.op_str + ' */')
                    body.append('    return unknown_control_transfer();')
        for key, block in blocks.items():
            if block['terminal'] == 'condition' and any(e['target'] not in blocks for e in outgoing[key]):
                body += ['unresolved_'+key[2:]+':','    return unknown_control_transfer();']
    if not blocks: body = ['/* 해석 가능한 명령어가 없습니다. */','return unknown_return();']
    # Hide flags that no displayed condition observes, then remove unused
    # declarations and renumber locals consecutively for the C view.
    flags_prefix = lifter.flags + ' = '
    non_flag_lines = [line for line in body if not line.lstrip().startswith(flags_prefix)]
    if not any(re.search(r'\b'+lifter.flags+r'\b',line) for line in non_flag_lines):
        body = non_flag_lines
    used = set(re.findall(r'\bv\d+\b','\n'.join(body)))
    for _ in range(len(lifter.variables)):
        dependencies = set().union(*(set(re.findall(r'\bv\d+\b',v['initial'] or ''))
                                     for v in lifter.variables if v['name'] in used)) if used else set()
        if dependencies <= used: break
        used |= dependencies
    variables = [dict(v) for v in lifter.variables if v['name'] in used]
    renamed = {v['name']:'v'+str(index+1) for index,v in enumerate(variables)}
    def rename(text): return re.sub(r'\bv\d+\b',lambda match:renamed.get(match[0],match[0]),text)
    body = [rename(line) for line in body]
    for variable in variables:
        variable['name'] = renamed[variable['name']]
        if variable['initial'] is not None: variable['initial'] = rename(variable['initial'])
    argument_indices = set(lifter.input_args.values()) | lifter.stack_args
    arguments = ', '.join('uint'+str(lifter.bits)+'_t a'+str(i) for i in sorted(argument_indices)) or 'void'
    lines = ['/* 메모리 명령어로부터 만든 의사코드 · 원본 C/타입/ABI 복원 보장 없음 */',
             '/* flags/load/store/call/unknown_*는 동작을 표시하는 의사 연산입니다. */',
             'uint'+str(lifter.bits)+'_t '+safe_name(name)+'('+arguments+')','{']
    for variable in variables:
        declaration = '    '+variable['type']+' '+variable['name']
        if variable['initial'] is not None: declaration += ' = '+variable['initial']
        lines.append(declaration+';')
    lines += [''] + ['    '+line for line in body] + ['}']
    return {'code': '\n'.join(lines), 'style': style, 'variables': variables,
            'unsupported': lifter.unsupported, 'translated_count': sum(len(b['instructions']) for b in lifter.blocks)-len(lifter.unsupported),
            'note': '정수 연산과 분기를 C 형태로 표현한 정적 의사코드입니다. 원본 변수명·타입·호출 규약을 확정하지 않습니다. '
                    '미변환 명령과 미해결 제어 이전은 숨기지 않습니다.'}


def analyze(raw, start, bits, name='', names=None):
    if bits not in (32,64): raise ValueError('지원하지 않는 코드 아키텍처')
    blocks, graph, dominators = decode(raw,start,bits)
    lifter = Lifter(blocks,graph,bits,names or {})
    pseudo = pseudocode(lifter,name or 'sub_'+f'{start:X}',graph,dominators)
    return {'results': [instruction(i) for b in blocks for i in b['instructions']],
            'graph': graph, 'pseudocode': pseudo, 'bits': bits,
            'argument_registers': [key.upper() for key in ('rcx','rdx','r8','r9') if key in lifter.input_args],
            'instruction_count': sum(len(b['instructions']) for b in blocks),
            'source': 'kernel_memory', 'read_bytes': min(len(raw),MAX_BYTES)}
