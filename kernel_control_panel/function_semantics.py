"""Evidence-driven Win64 call lifting; unknown operations keep the base fallback.

Only caller-supplied, bounded metadata is used. No file/process/memory access.
Copy propagation is local to a basic block. Memory reads are never delayed,
and calls, memory writes, escaped stack locals and unsupported asm are retained.
"""
import json
import math
import re
import struct

from capstone.x86_const import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
from function_views import Lifter, family, hx, code_tokens, variable_refs, MAX_BLOCKS
from c_expressions import pretty
from function_inference import infer, scalar_width

SCALAR = {'movss','movsd','addss','addsd','subss','subsd','mulss','mulsd','divss','divsd',
          'minss','minsd','maxss','maxsd','cvtsi2ss','cvtsi2sd','cvtss2sd','cvtsd2ss'}


def address_map(value):
    result = {}
    for key, item in (value or {}).items():
        try:
            result[int(key, 0) if isinstance(key, str) else int(key)] = item
        except (ValueError, TypeError):
            continue
    return result


def display_name(value):
    return re.sub(r'[\x00-\x1f;{}]|/\*|\*/|//', '_', str(value))[:512]


def valid_type(item, result=False):
    if not isinstance(item, dict):
        return False
    kind, size = item.get('kind'), item.get('size')
    return (bool(item.get('type')) and
            ((kind == 'void' and result) or
             (kind == 'pointer' and size == 8) or
             (kind == 'integer' and size in (1, 2, 4, 8)) or
             (kind == 'float' and size in (4, 8))))


def valid_prototype(item):
    return (isinstance(item, dict) and item.get('valid') is True and
            str(item.get('calling_convention', '')).lower() in ('win64', 'x64', 'amd64') and
            not item.get('variadic') and not item.get('hidden_return') and
            isinstance(item.get('parameters'), list) and len(item['parameters']) <= 16 and
            all(valid_type(p) for p in item['parameters']) and valid_type(item.get('return'), True))


def assignment(line):
    return re.fullmatch(r'\s*(v\d+) = (.*);', line)


def floating_literal(number, size):
    raw = number.to_bytes(size, 'little')
    value = struct.unpack('<f' if size == 4 else '<d', raw)[0]
    if math.isfinite(value):
        # Choose the shortest decimal spelling that round-trips to the same
        # IEEE bits; preserve negative zero and all non-finite bit patterns.
        for precision in range(1, 10 if size == 4 else 18):
            text = format(value, f'.{precision}g')
            try:
                if struct.pack('<f' if size == 4 else '<d', float(text)) == raw:
                    if '.' not in text and 'e' not in text:
                        text += '.0'
                    return text + ('f' if size == 4 else '')
            except (OverflowError, ValueError):
                pass
    return f'f{size*8}_from_bits({hx(number)})'


class SemanticLifter(Lifter):
    def __init__(self, blocks, graph, bits, names, metadata, raw=b'', start=0):
        self.metadata = dict(metadata)
        self.functions = address_map(metadata.get('functions'))
        self.imports = address_map(metadata.get('imports'))
        self.strings = address_map(metadata.get('strings'))
        self.globals = address_map(metadata.get('globals'))
        candidate = metadata.get('function')
        if not valid_prototype(candidate):
            self.metadata['function'] = infer(raw,start,bits,self.functions,self.imports,names.get(start,''))
        self.candidate = self.metadata.get('function',{})
        self.summary = {'typed_calls': 0, 'unknown_calls': 0, 'strings': 0,
                        'inferred_calls': 0,
                        'abi': 'Windows x64', 'optimization': 'block copy propagation + CFG liveness'}
        self.summary.update(signature_source=self.candidate.get('source','unknown'),
                            signature_inferred=bool(self.candidate.get('inferred')))
        candidates, excluded, widths = set(), set(), {}
        def observed_width(root,width):
            widths.setdefault(root,set()).add(width)
        for block in blocks:
            for ins in block['instructions']:
                for index,operand in enumerate(ins.operands):
                    if operand.type == X86_OP_REG and ins.reg_name(operand.reg).startswith(('xmm','ymm','zmm')):
                        root = ins.reg_name(operand.reg)
                        (candidates if ins.mnemonic in SCALAR else excluded).add(root)
                        if ins.mnemonic in SCALAR:observed_width(root,scalar_width(ins,index))
                if ins.mnemonic == 'call':
                    operand = ins.operands[0]
                    at = operand.imm if operand.type == X86_OP_IMM else ins.address+ins.size+operand.mem.disp if operand.type == X86_OP_MEM and ins.reg_name(operand.mem.base)=='rip' else None
                    item = (self.functions if operand.type==X86_OP_IMM else self.imports).get(at)
                    if not valid_prototype(item):excluded.update('xmm'+str(i) for i in range(6))
                    elif item['return']['kind']=='float':
                        candidates.add('xmm0');observed_width('xmm0',item['return']['size'])
        for index,parameter in enumerate(self.candidate.get('parameters',[])[:4]):
            if parameter['kind']=='float':observed_width('xmm'+str(index),parameter['size'])
        if self.candidate.get('return',{}).get('kind')=='float':
            candidates.add('xmm0');observed_width('xmm0',self.candidate['return']['size'])
        excluded.update(root for root,seen in widths.items() if len(seen)!=1)
        self.scalar_registers = candidates-excluded
        self.scalar_widths = {root:next(iter(widths[root])) for root in self.scalar_registers if root in widths}
        self.scalar_slots = {}
        self.block_returns = {}
        self.tail_returns = {}
        self.branch_tail_returns = {}
        self.code_range=(start,start+len(raw))
        super().__init__(blocks, graph, bits, names)
        self.check_scalar_slots()
        self.compact_blocks()

    def check_scalar_slots(self):
        blocked = set()
        for block in self.blocks:
            for ins in block['instructions']:
                if ins.mnemonic == 'lea':
                    continue
                self.current_ins = ins
                for index, operand in enumerate(ins.operands):
                    if operand.type != X86_OP_MEM:
                        continue
                    slot = self.stack_slot(operand)
                    if slot not in self.scalar_slots:
                        continue
                    scalar = ins.mnemonic in SCALAR
                    constant_store = (ins.mnemonic in ('mov', 'movabs') and index == 0 and
                                      len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM)
                    if not scalar and not constant_store:
                        blocked.add(slot)
        for slot in blocked:
            size = 32 if self.scalar_slots.pop(slot) == 'float' else 64
            for key, lines in self.lifted.items():
                rewritten = []
                for line in lines:
                    line = line.replace(f'vec128_from_f{size}({slot})',
                                        f'vec128_from_f{size}(f{size}_from_bits({slot}))')
                    match = assignment(line)
                    if match and match[1] in self.regs.values() and match[2] == slot:
                        line = match[1]+f' = f{size}_from_bits({slot});'
                    if match and match[1] == slot and not match[2].startswith('(uint'):
                        line = slot + f' = f{size}_bits(' + match[2] + ');'
                    rewritten.append(line)
                self.lifted[key] = rewritten

    def new_reg(self, root):
        name = super().new_reg(root)
        item = self.metadata.get('function')
        if root in self.scalar_registers:
            width = self.scalar_widths.get(root,4)
            self.variables[-1]['type'] = 'float' if width==4 else 'double'
        if valid_prototype(item) or item.get('inferred'):
            for index, parameter in enumerate(item['parameters'][:4]):
                register = 'xmm'+str(index) if parameter['kind'] == 'float' else ('rcx', 'rdx', 'r8', 'r9')[index]
                if root == register:
                    initial = 'a'+str(index+1)
                    if parameter['kind'] == 'float':
                        initial = initial if root in self.scalar_registers else f'vec128_return_f{parameter["size"]*8}({initial})'
                    elif parameter['kind'] == 'integer' and parameter['size'] < 8:
                        initial = f'unknown_argument_upper_bits({initial}, {parameter["size"]*8})'
                    self.variables[-1]['initial'] = initial
        return name

    def absolute(self, operand):
        if operand.type == X86_OP_IMM:
            return operand.imm
        if operand.type != X86_OP_MEM:
            return None
        mem = operand.mem
        if mem.segment or mem.index:
            return None
        if mem.base and self.current_ins.reg_name(mem.base) == 'rip':
            return self.current_ins.address + self.current_ins.size + mem.disp
        if not mem.base:
            return mem.disp
        return None

    def stack_address(self, operand):
        mem = operand.mem
        if mem.index or mem.segment or not mem.base or self.current_ins.addr_size != 8:
            return None
        sp, bp = self.stack_states.get(self.current_ins.address, (None, None))
        base = family(self.current_ins.reg_name(mem.base))
        offset = sp if base == 'rsp' else bp if base == 'rbp' else None
        if offset is None:
            return None
        offset += mem.disp
        # Use real memory-access widths, never the LEA operand width.
        sizes = set()
        for block in self.blocks:
            for ins in block['instructions']:
                if ins.mnemonic == 'lea':
                    continue
                for op in ins.operands:
                    if op.type != X86_OP_MEM or op.mem.index or op.mem.segment or not op.mem.base or ins.addr_size != 8:
                        continue
                    s, b = self.stack_states.get(ins.address, (None, None))
                    root = family(ins.reg_name(op.mem.base))
                    at = s if root == 'rsp' else b if root == 'rbp' else None
                    if at is not None and at + op.mem.disp == offset:
                        sizes.add(op.size)
        if len(sizes) == 1:
            return self.stack_location(offset, sizes.pop())
        return None

    def memory_address(self, operand):
        if self.current_ins.mnemonic == 'lea':
            slot = self.stack_address(operand)
            if slot:
                return '&' + slot
            absolute = self.absolute(operand)
            item = self.strings.get(absolute)
            if item and isinstance(item.get('value'), str):
                self.summary['strings'] += 1
                prefix = 'L' if item.get('encoding') in ('utf-16', 'utf-16le') else ''
                return prefix + json.dumps(item['value'], ensure_ascii=True)
            if absolute in self.functions:
                return display_name(self.functions[absolute].get('name', hx(absolute)))
            if absolute in self.globals and not self.globals[absolute].get('indirect'):
                return '&' + display_name(self.globals[absolute]['name'])
        return super().memory_address(operand)

    def value(self, operand):
        if operand.type == X86_OP_MEM:
            absolute = self.absolute(operand)
            item = self.globals.get(absolute)
            if item and item.get('size') == operand.size:
                return ('&' if item.get('indirect') else '') + display_name(item['name'])
        return super().value(operand)

    def lift(self, ins):
        op = ins.operands
        tail=False
        if ins.mnemonic.startswith('j') and op and self.stack_states.get(ins.address,(None,None))[0]==0:
            at=self.absolute(op[0])
            candidate=(self.functions if op[0].type==X86_OP_IMM else self.imports).get(at)
            tail=valid_prototype(candidate) and not (op[0].type==X86_OP_IMM and self.code_range[0]<=at<self.code_range[1])
        if ins.mnemonic in SCALAR - {'movss','movsd'} and len(op)==2:
            size = 4 if ins.mnemonic.endswith('ss') else 8
            destination = self.register(ins.reg_name(op[0].reg))
            def scalar(operand):
                if operand.type==X86_OP_REG:
                    root=ins.reg_name(operand.reg)
                    return self.register(root) if root in self.scalar_registers else f'f{size*8}_lane0({self.register(root)})'
                if operand.type==X86_OP_MEM:
                    slot=self.stack_slot(operand)
                    if slot:self.scalar_slots[slot]='float' if size==4 else 'double'
                    return slot or f'load_f{size*8}({self.memory_address(operand)})'
                return self.value(operand)
            operator={'add':'+','sub':'-','mul':'*','div':'/'}
            head=ins.mnemonic[:3]
            if head in operator:
                left,right=scalar(op[0]),scalar(op[1])
                expression=f'({"float" if size==4 else "double"})({left} {operator[head]} {right})'
            elif head in ('min','max'):
                left,right=scalar(op[0]),scalar(op[1])
                expression=f'sse_{head}_f{size*8}({left}, {right})'
            elif ins.mnemonic.startswith('cvtsi2'):
                expression=f'({"float" if size==4 else "double"})((int{op[1].size*8}_t)({self.value(op[1])}))'
            else:
                source_size=4 if ins.mnemonic=='cvtss2sd' else 8
                if op[1].type==X86_OP_REG:source=self.register(ins.reg_name(op[1].reg))
                else:
                    slot=self.stack_slot(op[1])
                    if slot:self.scalar_slots[slot]='float' if source_size==4 else 'double'
                    source=slot or f'load_f{source_size*8}({self.memory_address(op[1])})'
                if op[1].type==X86_OP_REG and ins.reg_name(op[1].reg) not in self.scalar_registers:source=f'f{source_size*8}_lane0({source})'
                expression=f'({"float" if size==4 else "double"})({source})'
            self.last_compare=None
            return [destination+' = '+(expression if ins.reg_name(op[0].reg) in self.scalar_registers else f'replace_low_f{size*8}({destination}, {expression})')+';']
        if ins.mnemonic in ('movss', 'movsd') and len(op) == 2:
            size = 4 if ins.mnemonic == 'movss' else 8
            suffix = str(size * 8)
            self.last_compare = None
            source = op[1]
            if source.type == X86_OP_MEM:
                slot = self.stack_slot(source)
                if slot:
                    self.scalar_slots[slot] = 'float' if size == 4 else 'double'
                    expression = slot
                else:
                    expression = f'load_f{suffix}({self.memory_address(source)})'
            elif source.type == X86_OP_REG:
                root=ins.reg_name(source.reg)
                expression = self.register(root) if root in self.scalar_registers else f'f{suffix}_lane0({self.register(root)})'
            else:
                return self.fallback(ins)
            if op[0].type == X86_OP_REG:
                register = self.register(ins.reg_name(op[0].reg))
                # Legacy scalar loads zero upper lanes; register moves preserve them.
                expression = (expression if ins.reg_name(op[0].reg) in self.scalar_registers else
                              f'vec128_from_f{suffix}({expression})' if source.type == X86_OP_MEM else
                              f'replace_low_f{suffix}({register}, {expression})')
                return [register + ' = ' + expression + ';']
            if op[0].type == X86_OP_MEM:
                slot = self.stack_slot(op[0])
                if slot:
                    self.scalar_slots[slot] = 'float' if size == 4 else 'double'
                    return [slot + ' = ' + expression + ';']
                return [f'store_f{suffix}({self.memory_address(op[0])}, {expression});']
        if (ins.mnemonic == 'call' or tail) and op:
            absolute = self.absolute(op[0])
            item = (self.functions if op[0].type == X86_OP_IMM else self.imports).get(absolute)
            if valid_prototype(item):
                self.summary['typed_calls'] += 1
                if item.get('inferred'):self.summary['inferred_calls'] += 1
                arguments = []
                for index, parameter in enumerate(item['parameters']):
                    if index < 4:
                        if parameter['kind'] == 'float':
                            root='xmm'+str(index)
                            value = self.register(root) if root in self.scalar_registers else f'f{parameter["size"]*8}_lane0({self.register(root)})'
                        else:
                            value = self.register(('rcx', 'rdx', 'r8', 'r9')[index])
                    else:
                        sp, _ = self.stack_states.get(ins.address, (None, None))
                        offset = (40 if tail else 32) + (index-4)*8
                        slot = self.stack_location(sp+offset, parameter['size']) if sp is not None else None
                        value = slot or f'load_u{parameter["size"]*8}({self.register("rsp")} + {offset})'
                        if parameter['kind'] == 'float':
                            value = f'f{parameter["size"]*8}_from_bits({value})'
                    if parameter['kind'] == 'integer' and parameter['size'] < 8:
                        value = '(' + display_name(parameter['type']) + ')(' + value + ')'
                    arguments.append(value)
                ret = item['return']
                call = display_name(item.get('name', self.names.get(absolute, 'sub_'+f'{absolute:X}'))) + '(' + ', '.join(arguments) + ')'
                if tail:
                    returns=[call+';','return;'] if ret['kind']=='void' else ['return '+call+';']
                    if not self.candidate.get('return_observed') and not valid_prototype(self.candidate):
                        returns=['return unknown_return_abi('+call+');'] if ret['kind']!='void' else [call+';','return unknown_return_abi();']
                    if ins.mnemonic!='jmp':
                        self.branch_tail_returns[hx(ins.address)]=returns
                        return super().lift(ins)
                    self.tail_returns[hx(self.current_ins.address)]=returns
                    return []
                lines = []
                if ret['kind'] == 'void':
                    lines.append(call + ';')
                else:
                    temporary = self.variable(display_name(ret['type']), 'typed call ' + hx(ins.address))
                    lines.append(temporary + ' = ' + call + ';')
                    destination = 'xmm0' if ret['kind'] == 'float' else 'rax'
                    if ret['kind'] == 'float':
                        value = temporary if destination in self.scalar_registers else f'vec128_return_f{ret["size"]*8}({temporary})'
                    elif ret['kind'] == 'integer' and ret['size'] < 8:
                        value = f'unknown_return_upper_bits({temporary}, {ret["size"]*8})'
                    else:
                        value = temporary
                    lines.append(self.register(destination) + ' = ' + value + ';')
                for register in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                    if ret['kind'] != 'void' and ret['kind'] != 'float' and register == 'rax':
                        continue
                    lines.append(self.register(register) + ' = unknown_call_clobber("' + register + '");')
                for register in list(self.regs):
                    match = re.fullmatch(r'(?:xmm|ymm|zmm)(\d+)', register)
                    # Only XMM6-15's low 128 bits are nonvolatile. The wider
                    # registers have volatile upper lanes; invalidate them.
                    if match and (not register.startswith('xmm') or int(match[1]) < 6) and not (ret['kind'] == 'float' and register == 'xmm0'):
                        lines.append(self.regs[register] + ' = unknown_call_clobber("' + register + '");')
                self.last_compare = None
                return lines + [self.flags + ' = unknown_flags();']
            self.summary['unknown_calls'] += 1
        return super().lift(ins)

    def compact_blocks(self):
        registers = set(self.regs.values())
        comparisons = {v['name'] for v in self.variables if v['storage'].startswith('비교 ')}
        immutable = {v['name'] for v in self.variables if v['storage'].startswith('typed call ')}
        locals_ = set(self.slots.values())
        variables = {v['name']: v for v in self.variables}
        types = {v['name']:v['type'] for v in self.variables}
        types.update({'a'+str(i+1):p['type'] for i,p in enumerate(self.candidate.get('parameters',[]))})
        def named_read(text):
            found = []
            def inspect(part):
                for item in self.globals.values():
                    name = display_name(item.get('name', ''))
                    if name and not item.get('indirect') and re.search(r'(?<![\w&])'+re.escape(name)+r'(?!\w)', part):
                        found.append(True)
                return part
            code_tokens(text, inspect)
            return bool(found)
        for name, kind in self.scalar_slots.items():
            variables[name]['type'] = kind
        def substitute(text, mapping):
            return code_tokens(text, lambda part: re.sub(r'\bv\d+\b', lambda m: mapping.get(m[0], m[0]), part))
        for block in self.blocks:
            mapping, lines = {}, []
            if block['id']==self.graph['entry']:
                for variable in self.variables:
                    initial=variable.get('initial') or ''
                    if variable['name'] in registers and not initial.startswith(('unknown_entry','entry_stack')):
                        mapping[variable['name']]=initial
            for line in self.lifted[block['id']]:
                match = assignment(line)
                conditional = re.fullmatch(r'(if \(.*\) )(v\d+) = (.*);', line)
                if conditional:
                    # CMOV writes only on one path. Never replace its lvalue
                    # with a propagated constant or keep its old value alias.
                    condition, destination, rhs = conditional.groups()
                    line = substitute(condition, mapping) + destination + ' = ' + substitute(rhs, mapping) + ';'
                    mapping = {key: value for key, value in mapping.items()
                               if key != destination and destination not in variable_refs(value)}
                    lines.append(line)
                    continue
                if line.startswith('asm_volatile('):
                    mapping.clear()
                destination = match[1] if match else None
                # RHS uses the old value, so rewrite before killing definitions.
                rewritten = substitute(match[2] if match else line, mapping)
                if match:rewritten=pretty(rewritten,types,render_memory=False)
                if destination:
                    mapping = {key: value for key, value in mapping.items()
                               if key != destination and destination not in
                               (variable_refs(value) - (set(re.findall(r'&\s*(v\d+)', value)) if destination in locals_ else set()))}
                    if destination in self.scalar_slots:
                        constant = re.fullmatch(r'(?:\(uint(?:32|64)_t\)\()?((?:0x)[0-9A-Fa-f]+)\)?', rewritten)
                        if constant:
                            size = 4 if self.scalar_slots[destination] == 'float' else 8
                            number = int(constant[1], 16)
                            if number < 1 << (size*8):
                                rewritten = floating_literal(number, size)
                    # Avoid unnecessary unsigned storage casts for addresses.
                    pointer = re.fullmatch(r'\(uint64_t\)\((&v\d+)\)', rewritten)
                    if pointer:
                        rewritten = pointer[1]
                        target = variables.get(rewritten[1:])
                        if target:
                            variables[destination]['type'] = target['type'] + '*'
                    if destination in registers or destination in comparisons:
                        pure = not named_read(rewritten) and not re.search(r'\b(?:load_\w+|unknown_\w+|replace_bits|segment_base)\s*\(', rewritten)
                        if pure and destination not in variable_refs(rewritten):
                            # Parentheses preserve precedence for arithmetic aliases.
                            mapping[destination] = rewritten if re.fullmatch(r'&?v\d+|[A-Za-z_][\w:<>*, ]*|(?:L)?"(?:\\.|[^"\\])*"|0x[\dA-Fa-f]+', rewritten) else '('+rewritten+')'
                    line = destination + ' = ' + rewritten + ';'
                else:
                    line = rewritten
                # Simplify the exact scalar load/extract pair, not arbitrary SIMD.
                line = re.sub(r'f(32|64)_lane0\(\(?vec128_(?:from|return)_f\1\((v\d+)\)\)?\)', r'\2', line)
                lines.append(line)
                if (destination in immutable or not match or destination in locals_):
                    # Values obtained from locals/globals cannot cross a memory
                    # write or call; stable addresses and call results can.
                    mapping = {key: value for key, value in mapping.items()
                               if not (variable_refs(value) & locals_ - set(re.findall(r'&\s*(v\d+)', value))) and
                               not any(display_name(g.get('name', '')) in value for g in self.globals.values() if g.get('name'))}
            self.lifted[block['id']] = lines
            last = block['instructions'][-1]
            if hx(last.address) in self.tail_returns:
                self.tail_returns[hx(last.address)]=[substitute(line,mapping) for line in self.tail_returns[hx(last.address)]]
            if hx(last.address) in self.branch_tail_returns:
                self.branch_tail_returns[hx(last.address)]=[substitute(line,mapping) for line in self.branch_tail_returns[hx(last.address)]]
            if hasattr(last, '_pseudo_condition'):
                last._pseudo_condition = substitute(last._pseudo_condition, mapping)
            item = self.metadata.get('function')
            float_return = (valid_prototype(item) or item.get('return_observed')) and item['return']['kind'] == 'float'
            root = 'xmm0' if float_return else 'rax'
            register = self.regs.get(root, 'unknown_return()')
            value = mapping.get(register, register)
            if float_return and root not in self.scalar_registers:
                value = f'f{item["return"]["size"]*8}_lane0({value})'
                value = re.sub(r'f(32|64)_lane0\(\(?vec128_(?:from|return)_f\1\((v\d+)\)\)?\)', r'\2', value)
            elif (valid_prototype(item) or item.get('return_observed')) and item['return']['kind'] == 'integer' and item['return']['size'] < 8:
                value = '(' + display_name(item['return']['type']) + ')(' + value + ')'
            self.block_returns[block['id']] = value
        # Backward liveness over the CFG prevents deleting values consumed in a
        # successor, including loop-carried register values.
        def extra(block):
            last = block['instructions'][-1]
            text = getattr(last, '_pseudo_condition', '')
            text+=' '+' '.join(self.tail_returns.get(hx(last.address),[]))
            text+=' '+' '.join(self.branch_tail_returns.get(hx(last.address),[]))
            if block['terminal'] == 'return':
                item = self.metadata.get('function')
                if not (valid_prototype(item) and item['return']['kind'] == 'void'):
                    text += ' ' + self.block_returns[block['id']]
            if hx(last.address) not in self.tail_returns and hx(last.address) not in self.branch_tail_returns and any(e['source'] == block['id'] and e['target'] not in self.lifted for e in self.graph['edges']):
                return variable_refs(text) | registers
            return variable_refs(text)
        def sweep(block, live):
            live = set(live) | extra(block)
            kept = []
            for line in reversed(self.lifted[block['id']]):
                match = assignment(line)
                if match:
                    dst, rhs = match[1], match[2]
                    removable = dst in registers or dst in comparisons or dst == self.flags
                    observable_read = named_read(rhs) or bool(re.search(r'\bload_\w+\(', rhs))
                    if removable and dst not in live and not observable_read:
                        continue
                    if dst in immutable and dst not in live:
                        # Drop an unused return temporary, never the call.
                        live |= variable_refs(rhs)
                        kept.append(rhs + ';')
                        continue
                    live.discard(dst)
                    live |= variable_refs(rhs)
                else:
                    live |= variable_refs(line)
                    if line.startswith('asm_volatile('):
                        # Unsupported instructions name physical registers in
                        # their literal operand text. Keep all reaching register
                        # definitions instead of pretending they have no inputs.
                        live |= registers
                kept.append(line)
            return live, list(reversed(kept))
        incoming = {b['id']: set() for b in self.blocks}
        for _ in range(MAX_BLOCKS):
            changed = False
            for block in reversed(self.blocks):
                successors = [e['target'] for e in self.graph['edges'] if e['source'] == block['id']]
                live = set().union(*(incoming.get(key, set()) for key in successors)) if successors else set()
                value, _ = sweep(block, live)
                if value != incoming[block['id']]:
                    incoming[block['id']], changed = value, True
            if not changed:
                break
        for block in self.blocks:
            successors = [e['target'] for e in self.graph['edges'] if e['source'] == block['id']]
            live = set().union(*(incoming.get(key, set()) for key in successors)) if successors else set()
            _, self.lifted[block['id']] = sweep(block, live)
        # Keep an entry initializer only if a path reads it before assigning.
        # This uses CFG liveness, including loop edges and conservative asm
        # inputs, rather than deleting unknown values merely for appearance.
        required=set(incoming.get(self.graph['entry'],set()))
        for _ in range(len(self.variables)+1):
            dependencies=set().union(*(variable_refs(v.get('initial') or '') for v in self.variables if v['name'] in required)) if required else set()
            if dependencies<=required:break
            required|=dependencies
        for variable in self.variables:
            if variable['name'] not in required:variable['initial']=None

    def optimize(self, body):
        types={v['name']:v['type'] for v in self.variables}
        types.update({'a'+str(i+1):p['type'] for i,p in enumerate(self.candidate.get('parameters',[]))})
        result=[]
        for line in body:
            match=assignment(line)
            prefix=line[:len(line)-len(line.lstrip())]
            if match:line=prefix+match[1]+' = '+pretty(match[2],types)+';'
            elif line.lstrip().startswith('return ') and line.endswith(';'):
                line=prefix+'return '+pretty(line.lstrip()[7:-1],types)+';'
            elif line.lstrip().startswith('if (') and line.rstrip().endswith(') {'):
                line=prefix+'if ('+pretty(line.strip()[4:-3],types)+') {'
            elif line.endswith(';') and not line.lstrip().startswith(('goto ','break','continue')):
                line=prefix+pretty(line.strip()[:-1],types)+';'
            result.append(line)
        # An adjacent single-use assignment can become the return expression
        # without moving any call, faulting load, or floating-point operation.
        used=variable_refs('\n'.join(result))
        counts={v:sum(len(re.findall(r'\b'+v+r'\b',code_tokens(line,lambda x:x))) for line in result) for v in used}
        final=[]
        for line in result:
            returned=re.fullmatch(r'\s*return (v\d+);',line)
            prior=assignment(final[-1]) if final else None
            private={*self.regs.values(),*(v['name'] for v in self.variables if v['storage'].startswith(('typed call ','비교 ')))}
            if returned and prior and returned[1]==prior[1] and counts.get(returned[1])==2 and prior[1] in private:
                final[-1]=line[:len(line)-len(line.lstrip())]+'return '+prior[2]+';'
            else:final.append(line)
        return final

    def signature(self, return_type, arguments):
        item = self.metadata.get('function')
        if valid_prototype(item) or item.get('inferred'):
            if valid_prototype(item) or item.get('return_observed'):
                return_type = display_name(item['return']['type'])
            arguments = ', '.join(display_name(p['type'])+' a'+str(i+1) for i, p in enumerate(item['parameters'])) or 'void'
        return return_type, arguments

    def return_statement(self, key):
        item = self.metadata.get('function')
        if valid_prototype(item) and item['return']['kind'] == 'void':
            return 'return;'
        value = self.block_returns[key]
        return 'return ' + value + ';'

    def tail_statement(self,key):
        block=next(b for b in self.blocks if b['id']==key)
        return self.tail_returns.get(hx(block['instructions'][-1].address))

    def branch_tail_statement(self,key):
        block=next(b for b in self.blocks if b['id']==key)
        return self.branch_tail_returns.get(hx(block['instructions'][-1].address))
