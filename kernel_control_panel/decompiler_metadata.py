"""Bounded evidence for C-like views; this module never accesses a process.

PDB types remain authoritative only after the caller verifies GUID and Age.
Imported prototypes are deliberately narrow: unrecognised symbols keep names
but never acquire a guessed argument count or calling convention.
"""
from functools import lru_cache
import ctypes
import api_prototypes

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

MAX_REFERENCES = 64
MAX_LITERAL_BYTES = 256


def type_record(name, kind, size):
    return {'type': name, 'kind': kind, 'size': size}


def supported_type(value, result=False):
    if not isinstance(value, dict):
        return False
    kind, size = value.get('kind'), value.get('size', 0)
    return ((result and kind == 'void' and size == 0) or
            (kind == 'integer' and size in (1, 2, 4, 8)) or
            (kind == 'pointer' and size == 8) or
            (kind == 'float' and size in (4, 8)))


def pdb_prototype(symbol, bits):
    """Represent only a fixed, scalar Win64 prototype supported by the lifter."""
    result = {key: symbol.get(key) for key in ('name', 'return', 'calling_convention', 'requires_object')}
    result.update(parameters=[dict(p) for p in symbol.get('parameters', [])], source='pdb', valid=False)
    # The helper presently lacks the object-pointer type. Keep member functions
    # conservative rather than manufacture an implicit this parameter.
    result['valid'] = bool(bits == 64 and symbol.get('types_available') and
                           not symbol.get('variadic') and
                           not symbol.get('requires_object') and symbol.get('calling_convention', 0) == 0 and
                           len(result['parameters']) <= 4 and
                           all(supported_type(p) for p in result['parameters']) and
                           supported_type(result.get('return'), True))
    result['pdb_calling_convention'] = result['calling_convention']
    if result['valid']:
        result['calling_convention'] = 'win64'
    return result


@lru_cache(maxsize=8192)
def undecorate(name):
    if not name.startswith('?') or len(name) > 4096:
        return name
    try:
        api = ctypes.WinDLL('dbghelp').UnDecorateSymbolName
        api.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
        api.restype = ctypes.c_uint
        output = ctypes.create_string_buffer(8192)
        if api(name.encode('ascii'), output, len(output), 0):
            return output.value.decode('ascii', errors='strict')
    except (AttributeError, OSError, UnicodeError):
        pass
    return name


def import_symbol(row, bits):
    """Use complete MSVC demangling evidence, never a substring ABI guess."""
    raw = row.get('name', '')
    full = undecorate(raw)
    value = dict(row, raw_name=raw, demangled=full, source='pe_import', valid=False)
    value['name'] = full if full != raw else raw
    if bits != 64:
        return value
    known = api_prototypes.lookup(raw, row.get('module',''), bits)
    if known:
        value.update(known)
    prefix = '??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@'
    stream = 'class std::basic_ostream<char,struct std::char_traits<char> >'
    head = f'public: {stream} & __ptr64 __cdecl std::basic_ostream<char,struct std::char_traits<char> >::operator<<('
    overloads = {
        'M@Z': ('float', type_record('float', 'float', 4)),
        '_K@Z': ('unsigned __int64', type_record('uint64_t', 'integer', 8)),
        'PEBX@Z': ('void const * __ptr64', type_record('const void*', 'pointer', 8)),
        'I@Z': ('unsigned int', type_record('uint32_t', 'integer', 4)),
        'P6AAEAV01@AEAV01@@Z@Z': (
            f'{stream} & __ptr64 (__cdecl*)({stream} & __ptr64)',
            type_record('std::ostream* (*)(std::ostream*)', 'pointer', 8)),
    }
    suffix = raw[len(prefix):] if raw.startswith(prefix) else ''
    if suffix in overloads:
        parameter_text, parameter = overloads[suffix]
        if full == head + parameter_text + ') __ptr64':
            value.update(name='std::ostream::operator<<', source='msvc_demangled', valid=True,
                         requires_object=True, calling_convention='win64',
                         parameters=[dict(type_record('std::ostream*', 'pointer', 8), name='this'),
                                     dict(parameter, name='value')],
                         **{'return': type_record('std::ostream*', 'pointer', 8)})
    cout_raw = '?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A'
    if raw == cout_raw and full == f'{stream} std::cout':
        value.update(name='std::cout', data=True, type='std::ostream*', kind='pointer', size=8,
                     indirect=True, source='msvc_demangled')
    # Standard CRT declaration, restricted to a CRT import rather than an
    # arbitrary module exporting a function coincidentally named "system".
    module = str(row.get('module', '')).lower()
    if raw == 'system' and (module.startswith('api-ms-win-crt-') or module in ('ucrtbase.dll', 'msvcrt.dll')):
        value.update(name='system', source='crt_declaration', valid=True,
                     requires_object=False, calling_convention='win64',
                     parameters=[dict(type_record('const char*', 'pointer', 8), name='command')],
                     **{'return': type_record('int32_t', 'integer', 4)})
    return value


def referenced_addresses(raw, start, bits, base, size):
    engine = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    engine.detail = True
    found = []
    for ins in engine.disasm(raw, start, count=2048):
        for operand in ins.operands:
            candidate = None
            if ins.mnemonic == 'lea' and operand.type == X86_OP_MEM and ins.reg_name(operand.mem.base) in ('rip', 'eip') and not operand.mem.index:
                candidate = ins.address + ins.size + operand.mem.disp
            elif operand.type == X86_OP_IMM:
                candidate = operand.imm
            if candidate is not None and base <= candidate < base + size and candidate not in found:
                found.append(candidate)
                if len(found) >= MAX_REFERENCES:
                    return found
    return found


def collect(raw, start, bits, record, reader):
    """Read strings only at referenced, immutable, readable PE addresses."""
    base, size = record['base'], record['size']
    functions = dict(record.get('function_prototypes', {}))
    imports = dict(record.get('import_symbols', {}))
    globals_ = {int(row['address'], 16): {'name': row['name'], 'source': 'pe_export', 'valid': False}
                for row in record.get('data_exports', []) if row.get('name')}
    for address, symbol in imports.items():
        if symbol.get('data'):
            globals_[address] = {key: symbol[key] for key in ('name', 'type', 'kind', 'size', 'indirect', 'source')}
    strings = {}
    notes = list(record.get('metadata_notes', []))
    # Wide literals need a verified parameter declaration. Decoding a UTF-16
    # string as UTF-8 would otherwise silently turn L"kernel32.dll" into "k".
    encodings = {}
    if bits == 64:
        from function_views import decode, family
        blocks,_,_=decode(raw,start,bits)
        for block in blocks:
            addresses={}
            for ins in block['instructions']:
                operands=ins.operands
                if ins.mnemonic in ('call','jmp') and operands:
                    target=operands[0]
                    item=None
                    if target.type==X86_OP_IMM:item=functions.get(target.imm)
                    elif target.type==X86_OP_MEM and ins.reg_name(target.mem.base)=='rip' and not target.mem.index and not target.mem.segment:
                        item=imports.get(ins.address+ins.size+target.mem.disp)
                    if item and item.get('valid'):
                        for index,parameter in enumerate(item.get('parameters',[])[:4]):
                            address=addresses.get(('rcx','rdx','r8','r9')[index])
                            encoding=parameter.get('encoding')
                            if parameter.get('type')=='const char*':encoding='utf-8'
                            if address is not None and encoding:
                                encodings.setdefault(address,set()).add(encoding)
                    if ins.mnemonic=='call':
                        for root in ('rax','rcx','rdx','r8','r9','r10','r11'):addresses.pop(root,None)
                candidate=None
                if len(operands)==2 and operands[0].type==X86_OP_REG:
                    source=operands[1]
                    if ins.mnemonic=='lea' and source.type==X86_OP_MEM and ins.reg_name(source.mem.base)=='rip' and not source.mem.index:
                        candidate=ins.address+ins.size+source.mem.disp
                    elif ins.mnemonic in ('mov','movabs'):
                        if source.type==X86_OP_IMM:candidate=source.imm
                        elif source.type==X86_OP_REG:candidate=addresses.get(family(ins.reg_name(source.reg)))
                for reg in ins.regs_access()[1]:addresses.pop(family(ins.reg_name(reg)),None)
                if candidate is not None:addresses[family(ins.reg_name(operands[0].reg))]=candidate
    for address in referenced_addresses(raw, start, bits, base, size):
        section = next((s for s in record.get('sections', []) if s.get('readable') and
                        not s.get('writable') and not s.get('executable') and
                        base + s['start'] <= address < base + s['end']), None)
        if section is None or address in imports or address in globals_:
            continue
        count = min(MAX_LITERAL_BYTES, base + section['end'] - address)
        try:
            data = reader.read_bytes(record['pid'], address, count)
        except (OSError, ValueError):
            notes.append('참조한 문자열을 읽지 못해 주소 표현을 유지했습니다')
            continue
        hints=encodings.get(address,set())
        if len(hints)>1:continue
        encoding=next(iter(hints),'utf-8')
        if encoding=='utf-16le':
            end=next((i for i in range(0,len(data)-1,2) if data[i:i+2]==b'\0\0'),-1)
            terminator=2
        else:
            if not hints and len(data)>=4 and data[1]==0 and data[2]!=0 and data[3]==0:
                continue
            end=data.find(b'\0');terminator=1
        if end < 1:
            continue
        try:
            text = data[:end].decode(encoding, errors='strict')
        except UnicodeError:
            continue
        if not all(char.isprintable() or char in '\r\n\t' for char in text):
            continue
        strings[address] = {'value': text, 'encoding': encoding, 'source': 'referenced_readonly_image', 'bytes': end + terminator}
    return {'functions': functions, 'imports': imports, 'globals': globals_, 'strings': strings,
            'notes': list(dict.fromkeys(notes)), 'abi': 'win64' if bits == 64 else 'unknown'}


def infer_callees(raw, start, bits, record, reader, metadata):
    """Inspect at most 32 direct callees, 4096 bytes each, in this PE image."""
    if bits != 64:
        return
    from function_inference import infer
    from function_views import decode
    base,size=record['base'],record['size']
    rows={int(row['address'],16):row for row in record.get('rows',[])}
    buffers={start:raw}
    pending=[start]
    imports=metadata['imports'];functions=metadata['functions']
    truncated=False
    while pending:
        address=pending.pop(0)
        blocks,_,_=decode(buffers[address],address,bits)
        for ins in (i for b in blocks for i in b['instructions']):
            if not (ins.mnemonic=='call' or ins.mnemonic.startswith('j')) or not ins.operands or ins.operands[0].type!=X86_OP_IMM:
                continue
            target=ins.operands[0].imm
            if ins.mnemonic!='call' and address<=target<address+len(buffers[address]):continue
            if target in buffers or functions.get(target,{}).get('valid'):
                continue
            section=next((s for s in record.get('sections',[]) if s.get('executable') and
                          base+s['start']<=target<base+s['end']),None)
            if section is None:
                continue
            if len(buffers)>=33:
                truncated=True;continue
            following=min((a for a in rows if a>target),default=base+section['end'])
            extent=rows.get(target,{}).get('size') or min(512,following-target)
            count=min(4096,extent,base+section['end']-target)
            if count<=0:
                continue
            try:
                buffers[target]=reader.read_bytes(record['pid'],target,count)
            except (OSError,ValueError):
                truncated=True;continue
            pending.append(target)
    # Leaf summaries become evidence for callers. Recursive/opaque cycles do
    # not acquire a fabricated signature from the fixed iteration budget.
    for _ in range(5):
        changed=False
        for address,data in buffers.items():
            if functions.get(address,{}).get('valid'):
                continue
            blocks,_,_=decode(data,address,bits)
            instructions=[i for b in blocks for i in b['instructions']]
            candidate=None
            if len(instructions)==1 and instructions[0].mnemonic=='jmp':
                ins=instructions[0];operand=ins.operands[0]
                if operand.type==X86_OP_MEM and ins.reg_name(operand.mem.base)=='rip' and not operand.mem.index and not operand.mem.segment:
                    target=ins.address+ins.size+operand.mem.disp
                    item=imports.get(target,{})
                    if item.get('valid'):
                        candidate=dict(item,source='verified_import_thunk',thunk_target=hex(target))
            if candidate is None:
                candidate=infer(data,address,bits,functions,imports,rows.get(address,{}).get('name',''))
            if functions.get(address)!=candidate:
                functions[address]=candidate;changed=True
        if not changed:
            break
    if truncated:
        metadata['notes'].append('호출 대상 분석의 읽기/함수 수 상한 적용; 남은 호출은 미확인으로 보존')
    metadata['function']=functions.get(start,{'valid':False})
