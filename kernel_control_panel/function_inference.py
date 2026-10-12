"""Bounded instruction evidence for Win64 signatures, without debug symbols.

Observed arguments describe machine inputs, not recovered source declarations.
Opaque calls and frame aliases prevent treating a callee signature as complete.
"""
from capstone import CS_AC_READ
from capstone.x86_const import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
from function_views import decode, family, Lifter, MAX_BLOCKS

GPRS = ('rcx', 'rdx', 'r8', 'r9')
VOLATILE = ('rax', *GPRS, 'r10', 'r11', *(f'xmm{i}' for i in range(6)))


def scalar_width(ins, index):
    if ins.mnemonic == 'cvtss2sd':
        return 8 if index == 0 else 4
    if ins.mnemonic == 'cvtsd2ss':
        return 4 if index == 0 else 8
    return 4 if ins.mnemonic.endswith('ss') else 8


def record(kind, size):
    return {'type': ('void*' if kind == 'pointer' else 'float' if kind == 'float' and size == 4 else
                     'double' if kind == 'float' else f'uint{size*8}_t'), 'kind': kind, 'size': size}


def infer(raw, start, bits=64, functions=None, imports=None, name=''):
    if bits != 64:
        return {'name': name, 'valid': False, 'source': 'instruction_inference'}
    blocks, graph, _ = decode(raw, start, bits)
    layout = object.__new__(Lifter)
    layout.blocks, layout.graph, layout.bits = blocks, graph, bits
    states = layout.stack_analysis()
    functions, imports = functions or {}, imports or {}
    entry, ids = graph['entry'], {b['id'] for b in blocks}
    predecessors = {key: [e['source'] for e in graph['edges'] if e['target'] == key] for key in ids}

    def call_type(ins):
        operand = ins.operands[0]
        target = None
        if operand.type == X86_OP_IMM:
            return functions.get(operand.imm)
        if operand.type == X86_OP_MEM and not operand.mem.index and not operand.mem.segment:
            if ins.reg_name(operand.mem.base) == 'rip':
                target = ins.address+ins.size+operand.mem.disp
            elif not operand.mem.base:
                target = operand.mem.disp
        return imports.get(target)

    def tail_type(ins):
        if not ins.mnemonic.startswith('j') or not ins.operands:
            return None
        operand=ins.operands[0]
        if operand.type==X86_OP_IMM and start<=operand.imm<start+len(raw):
            return None
        if states.get(ins.address,(None,None))[0]!=0:
            return None
        item=call_type(ins)
        return item if item and item.get('valid') else None

    def reads_writes(ins):
        rd, wr = ins.regs_access()
        reads = {family(ins.reg_name(x)): record('integer', 8) for x in rd}
        writes = {family(ins.reg_name(x)) for x in wr}
        zero = (ins.mnemonic in ('xor', 'sub', 'xorps', 'xorpd', 'pxor') and len(ins.operands) == 2 and
                ins.operands[0].type == ins.operands[1].type == X86_OP_REG and
                ins.operands[0].reg == ins.operands[1].reg)
        if zero:
            reads = {}
        for index, operand in enumerate(ins.operands):
            if operand.type == X86_OP_REG and operand.access & CS_AC_READ and not zero:
                register = family(ins.reg_name(operand.reg))
                scalar = ins.mnemonic.endswith(('ss', 'sd')) and register.startswith('xmm')
                reads[register] = record('float', scalar_width(ins,index)) if scalar else record('integer', operand.size)
            if operand.type == X86_OP_MEM:
                for reg in (operand.mem.base, operand.mem.index):
                    if not reg:
                        continue
                    root = family(ins.reg_name(reg))
                    if ins.mnemonic != 'lea' and reg == operand.mem.base:
                        reads[root] = record('pointer', 8)
                    elif ins.mnemonic == 'lea' and ins.operands[0].size == 4:
                        reads[root] = record('integer', 4)
        if ins.mnemonic == 'call' or tail_type(ins):
            item = call_type(ins)
            if item and item.get('valid'):
                for index, parameter in enumerate(item['parameters'][:4]):
                    register = 'xmm'+str(index) if parameter['kind'] == 'float' else GPRS[index]
                    reads[register] = parameter
            if ins.mnemonic in ('call','jmp'):writes.update(VOLATILE)
        # Partial integer writes leave a possible input in the untouched bits.
        for operand in ins.operands[:1]:
            if operand.type == X86_OP_REG and operand.size < 4:
                writes.discard(family(ins.reg_name(operand.reg)))
            if ins.mnemonic.startswith('cmov') and operand.type==X86_OP_REG:
                writes.discard(family(ins.reg_name(operand.reg)))
        return reads, writes

    block_writes = {}
    for block in blocks:
        block_writes[block['id']] = set().union(*(reads_writes(i)[1] for i in block['instructions']))
    universe = set().union(*block_writes.values()) if blocks else set()
    defined_in = {key: set() if key == entry else set(universe) for key in ids}
    defined_out = {key: set(universe) for key in ids}
    for _ in range(MAX_BLOCKS):
        changed = False
        for block in blocks:
            key = block['id']
            incoming = set.intersection(*(defined_out[p] for p in predecessors[key])) if predecessors[key] and key != entry else set()
            outgoing = incoming | block_writes[key]
            if incoming != defined_in[key] or outgoing != defined_out[key]:
                defined_in[key], defined_out[key], changed = incoming, outgoing, True
        if not changed:
            break
    inputs, opaque, frame_alias, unsafe_input = {}, False, False, False
    for block in blocks:
        defined = set(defined_in[block['id']])
        for ins in block['instructions']:
            reads, writes = reads_writes(ins)
            for root, value in reads.items():
                if root not in defined and root in ('rax','r10','r11','xmm4','xmm5','rflags','eflags'):
                    unsafe_input = True
                nonvolatile=root in ('rbx','rbp','rsi','rdi','r12','r13','r14','r15',*(f'xmm{i}' for i in range(6,16)))
                if root not in defined and nonvolatile:
                    saved=ins.mnemonic=='push'
                    if ins.mnemonic=='mov' and len(ins.operands)==2 and ins.operands[0].type==X86_OP_MEM:
                        destination=ins.operands[0].mem
                        saved=not destination.index and not destination.segment and family(ins.reg_name(destination.base))=='rsp' and states.get(ins.address,(None,None))[0] is not None
                    if not saved:unsafe_input=True
                if root in defined or root not in (*GPRS, *(f'xmm{i}' for i in range(4))):
                    continue
                index = GPRS.index(root) if root in GPRS else int(root[-1])
                existing = inputs.get(index)
                value = {k: value[k] for k in ('type', 'kind', 'size')}
                if not existing:
                    inputs[index] = value
                elif existing != value:
                    # Pointer arithmetic often also reads the pointer as u64.
                    if {existing['kind'], value['kind']} <= {'pointer', 'integer'} and max(existing['size'], value['size']) == 8:
                        inputs[index] = record('pointer' if 'pointer' in (existing['kind'], value['kind']) else 'integer', 8)
                    elif existing['kind'] == value['kind'] == 'integer':
                        inputs[index] = record('integer', max(existing['size'], value['size']))
                    else:
                        frame_alias = True
            sp, bp = states.get(ins.address, (None, None))
            for operand in ins.operands:
                if operand.type != X86_OP_MEM or operand.mem.index or operand.mem.segment or not operand.mem.base:
                    continue
                base = family(ins.reg_name(operand.mem.base))
                at = sp if base == 'rsp' else bp if base == 'rbp' else None
                if at is None:
                    continue
                offset = at+operand.mem.disp
                if ins.mnemonic == 'lea' and offset >= 8:
                    frame_alias = True
                elif operand.access & CS_AC_READ and offset >= 40 and (offset-40) % 8 == 0:
                    index = 4+(offset-40)//8
                    if index < 16:
                        inputs[index] = record('float' if ins.mnemonic in ('movss', 'movsd') else 'integer', operand.size)
            if ins.mnemonic == 'call':
                item = call_type(ins)
                opaque |= not bool(item and item.get('valid'))
            tail=tail_type(ins)
            if tail:
                for index,parameter in enumerate(tail['parameters'][4:],4):
                    value={k:parameter[k] for k in ('type','kind','size')}
                    if index in inputs and inputs[index]!=value:frame_alias=True
                    inputs.setdefault(index,value)
            defined.update(writes)
    parameters = [dict(inputs.get(i, record('integer', 8)), name=f'a{i+1}', observed=i in inputs)
                  for i in range(max(inputs, default=-1)+1)]
    parameter_types = {('xmm'+str(i) if p['kind'] == 'float' else GPRS[i]): p
                       for i, p in enumerate(parameters[:4]) if p['observed']}

    # A type is retained at joins only when every predecessor proves it.
    outputs = {key: {} for key in ids}
    def merge(values):
        if not values:
            return {}
        return {key: value for key, value in values[0].items() if all(other.get(key) == value for other in values[1:])}
    for _ in range(MAX_BLOCKS):
        changed = False
        for block in blocks:
            key = block['id']
            current = dict(parameter_types) if key == entry else merge([outputs[p] for p in predecessors[key]])
            for ins in block['instructions']:
                operands = ins.operands
                if ins.mnemonic == 'call' or tail_type(ins):
                    if ins.mnemonic not in ('call','jmp'):continue
                    item = call_type(ins)
                    for root in VOLATILE:
                        current.pop(root, None)
                    if item and item.get('valid') and item['return']['kind'] != 'void':
                        current['xmm0' if item['return']['kind'] == 'float' else 'rax'] = {k: item['return'][k] for k in ('type','kind','size')}
                    continue
                if not operands or operands[0].type != X86_OP_REG:
                    continue
                root = family(ins.reg_name(operands[0].reg))
                _, writes = reads_writes(ins)
                if ins.mnemonic.startswith('cmov'):
                    if current.get(root)!=record('integer',operands[0].size):current.pop(root,None)
                    continue
                if root not in writes:
                    continue
                if root.startswith('xmm'):
                    if ins.mnemonic.endswith(('ss','sd')) and not ins.mnemonic.startswith(('com','ucom')):
                        current[root] = record('float', scalar_width(ins,0))
                    else:
                        current.pop(root, None)
                elif operands[0].size in (4,8) and ins.mnemonic in ('mov','movabs','movzx','movsx','movsxd','lea','add','sub','xor','and','or','shl','shr','sar','imul','inc','dec','neg','not','cmove','cmovne','cmovg','cmovl','cmova','cmovb'):
                    value = record('integer', operands[0].size)
                    if ins.mnemonic == 'mov' and len(operands) == 2 and operands[1].type == X86_OP_REG and operands[0].size == 8:
                        value = current.get(family(ins.reg_name(operands[1].reg)), value)
                    current[root] = value
                else:
                    current.pop(root, None)
            if current != outputs[key]:
                outputs[key], changed = current, True
        if not changed:
            break
    returns = [outputs[b['id']] for b in blocks if b['terminal'] == 'return']
    tails=[tail_type(b['instructions'][-1]) for b in blocks if tail_type(b['instructions'][-1])]
    common = merge(returns)
    ret = common.get('xmm0') if common.get('xmm0', {}).get('kind') == 'float' else common.get('rax')
    if ret is None:
        ret = record('integer', 8)
    resolved_return = bool(returns and ('rax' in common or common.get('xmm0', {}).get('kind') == 'float'))
    if tails:
        tail_returns=[t['return'] for t in tails]
        if all({k:t[k] for k in ('type','kind','size')}=={k:tail_returns[0][k] for k in ('type','kind','size')} for t in tail_returns) and (not returns or ret=={k:tail_returns[0][k] for k in ('type','kind','size')}):
            ret={k:tail_returns[0][k] for k in ('type','kind','size')};resolved_return=True
        else:resolved_return=False
    scalar_types = all(p['kind'] in ('pointer','float','integer') and p['size'] in (1,2,4,8) for p in parameters)
    endings={b['id']:b['instructions'][-1] for b in blocks}
    resolved_edges=all(e['target'] in ids or tail_type(endings[e['source']]) and
                       (endings[e['source']].mnemonic=='jmp' or e['kind']=='true') for e in graph['edges'])
    complete = bool(blocks and not graph['truncated'] and resolved_edges and not opaque and not frame_alias and not unsafe_input and scalar_types and resolved_return)
    return {'name': name or f'sub_{start:X}', 'parameters': parameters, 'return': ret,
            'valid': complete, 'calling_convention': 'win64', 'source': 'instruction_inference',
            'inferred': True, 'return_observed': resolved_return, 'opaque_calls': opaque,
            'non_abi_input': unsafe_input,
            'parameter_registers': [root for root in parameter_types],
            'note': '명령어에서 관찰한 Win64 입력과 반환값이며 원본 선언/사용하지 않는 인자를 확정하지 않습니다.'}
