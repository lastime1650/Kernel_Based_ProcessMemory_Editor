"""Instruction editing over the existing kernel reader/writer/protection IOCTLs.

No target process handles or native user-mode process APIs are used here. Histories
are scoped to a browser session and a kernel process-start key, and never persisted.
"""
import re
import threading
import time
import uuid

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM
from keystone import Ks, KsError, KS_ARCH_X86, KS_MODE_32, KS_MODE_64
import function_views as V

OPERATIONS = ['disasm_analyze', 'disasm_validate', 'disasm_apply', 'disasm_undo',
              'disasm_redo', 'disasm_recover', 'disasm_history', 'disasm_follow', 'disasm_release']
MAX_SESSIONS, MAX_HISTORY, MAX_EDITS = 16, 128, 128


class InvalidTarget(ValueError):
    target_invalid = True


def number(value):
    if isinstance(value, bool): raise ValueError('숫자를 입력하세요')
    text = str(value).strip()
    return int(text, 16 if text.lower().startswith(('0x', '-0x')) else 10)


def address(value):
    result = number(value)
    if not 0 < result < 0x800000000000: raise ValueError('사용자 주소 범위가 필요합니다')
    return result


def checked(response, action):
    if not response.get('success'):
        raise ValueError(f'{action} 실패: {response.get("result_status", response.get("error", "드라이버 응답 오류"))}')
    return response


def compile_line(text, start, bits, capacity):
    """Exactly one Intel instruction, bounded to the previous instruction's slot."""
    text = str(text).strip().lower()
    if not text or len(text) > 256: raise ValueError('명령어 한 줄을 256자 이내로 입력하세요')
    if any(c in text for c in ('\n', '\r', ';', '#')):
        raise ValueError('여러 명령어·주석은 입력할 수 없습니다. 한 줄의 명령어만 입력하세요')
    if not re.match(r'^[a-z][a-z0-9]*\b', text) or re.match(r'^(?:db|dw|dd|dq|dt|equ|align|org)\b', text):
        raise ValueError('데이터 지시문·라벨 대신 Intel 어셈블리 명령어를 입력하세요')
    if ':' in text and not re.search(r'\b(?:cs|ds|es|fs|gs|ss)\s*:', text):
        raise ValueError('라벨 정의는 사용할 수 없습니다')
    try:
        encoding, count = Ks(KS_ARCH_X86, KS_MODE_64 if bits == 64 else KS_MODE_32).asm(text, addr=start)
    except KsError as exc:
        raise ValueError('어셈블리 문법·명령·피연산자 오류: ' + str(exc)) from exc
    raw = bytes(encoding or [])
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True
    decoded = list(md.disasm(raw, start))
    if count != 1 or len(decoded) != 1 or decoded[0].size != len(raw):
        raise ValueError('정확히 하나의 유효한 명령어가 필요합니다')
    # Keystone may truncate a far rel32 or an oversized immediate without error.
    # Check direct branch destinations after encoding, including high x64 addresses.
    branch = re.match(r'^(call|j[a-z]+|loop[a-z]*)\s+(-?0x[0-9a-f]+|\d+)$', text)
    if branch:
        target = number(branch[2])
        actual = decoded[0].operands[0]
        if actual.type != X86_OP_IMM or actual.imm != target:
            raise ValueError('분기 목적지가 상대 주소 범위를 벗어났습니다. 인코딩 시 주소가 잘립니다')
    else:
        literal = re.search(r'(?:^|,\s*)(-?0x[0-9a-f]+|-?\d+)\s*$', text)
        immediates = [o for o in decoded[0].operands if o.type == X86_OP_IMM]
        if literal and immediates:
            value, operand = number(literal[1]), immediates[-1]
            width = (decoded[0].operands[0].size or operand.size or bits//8) * 8
            mask = (1 << width)-1
            if not -(1 << (width-1)) <= value <= mask or value & mask != operand.imm & mask:
                raise ValueError('즉시값이 피연산자 범위를 벗어났거나 인코딩 시 잘립니다')
    if len(raw) > capacity:
        raise ValueError(f'길이 초과: 새 명령 {len(raw)}바이트 / 기존 {capacity}바이트. 다음 명령을 덮어쓸 수 없습니다')
    return {'assembly': decoded[0].mnemonic + (' ' + decoded[0].op_str if decoded[0].op_str else ''),
            'text': text, 'bytes': raw.hex(' '), 'patch_bytes': (raw + b'\x90' * (capacity-len(raw))).hex(' '),
            'size': len(raw), 'slot_size': capacity, 'padding': capacity-len(raw)}


def references(row, bits):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
    md.detail = True
    ins = next(md.disasm(bytes.fromhex(row['bytes']), address(row['address']), count=1), None)
    if not ins: return []
    result = []
    control = ins.mnemonic.startswith(('call', 'j', 'loop'))
    for operand in ins.operands:
        target, indirect, kind = None, False, '주소 값'
        if operand.type == X86_OP_IMM:
            target = operand.imm
            if control: kind = '분기 / 호출'
            elif target < 0x10000: continue
        elif operand.type == X86_OP_MEM:
            mem = operand.mem
            # Segment bases and register-dependent addresses require a live
            # execution context; do not invent a destination for those operands.
            if mem.segment: continue
            base = ins.reg_name(mem.base)
            if base in ('rip', 'eip') and not mem.index:
                target = ins.address + ins.size + mem.disp
                if base == 'eip': target &= 0xffffffff
            elif not mem.base and not mem.index:
                target = mem.disp
                if bits == 32: target &= 0xffffffff
            if target is not None:
                indirect, kind = control, '간접 호출 포인터' if control else '메모리 주소'
        if target is not None and 0 < target < 0x800000000000:
            item = {'address': V.hx(target), 'indirect': indirect, 'kind': kind}
            if item not in result: result.append(item)
    return result


class Workspace:
    def __init__(self, studio):
        self.studio = studio
        self.sessions = {}
        self.lock = threading.RLock()

    def session(self, args, create=False):
        pid = number(args.get('pid', 0))
        if not 0 < pid <= 0xffffffff: raise ValueError('대상 PID를 선택하세요')
        key = args.get('session_id')
        if key:
            session = self.sessions.get(key)
            if not session or session['pid'] != pid: raise ValueError('편집 세션이 만료되었습니다. 대상을 다시 선택하세요')
            try:
                same = self.studio.identity(pid) == session['identity']
            except Exception as exc:
                # Retain recovery data for transient driver failures. Never treat
                # a failed lookup as permission to write or forget a pending repair.
                response = getattr(exc, 'response', {})
                if (response.get('success') and response.get('exit_status') != 259 or
                    response.get('result_status') in ('0xC000000B', '0xC0000225', '0xC000010A') or
                    response.get('error_code') == 87):
                    del self.sessions[key]
                    raise InvalidTarget('대상 프로세스가 종료되었습니다. 편집 이력을 지웠습니다') from exc
                raise
            if not same:
                del self.sessions[key]
                raise InvalidTarget('프로세스가 교체되었습니다. 대상 재선택이 필요합니다')
            return session
        if not create: raise ValueError('먼저 주소를 분석하세요')
        if len(self.sessions) >= MAX_SESSIONS:
            raise ValueError('편집 세션 상한에 도달했습니다. 다른 편집 창에서 대상을 다시 선택해 이력을 해제하세요')
        key = uuid.uuid4().hex
        session = {'id': key, 'pid': pid, 'identity': self.studio.identity(pid),
                   'analyses': {}, 'history': [], 'cursor': 0, 'recovery': None}
        self.sessions[key] = session
        return session

    def regions(self, pid):
        result = checked(self.studio.operate('regions', {'pid': pid, 'limit': 50000}), '메모리 맵 조회')
        if result.get('truncated'): raise ValueError('메모리 맵이 잘렸습니다. 정확한 페이지 보호 속성을 확인할 수 없습니다')
        return result['results']

    @staticmethod
    def region_at(regions, start, size=1):
        for region in regions:
            base = number(region['address'])
            if base <= start and start + size <= base + number(region['size']):
                if (number(region['state']) != 0x1000 or not region.get('readable') or
                        region.get('guarded') or number(region['protect']) & 0x101):
                    raise ValueError('커밋된 읽기 가능 영역만 지원합니다. Guard / NoAccess는 제외됩니다')
                return region
        raise ValueError('주소 범위를 포함하는 읽기 가능 메모리 영역이 없습니다')

    def analyze(self, session, args):
        start = address(args['address'])
        size = number(args.get('size', 1024))
        if not 1 <= size <= V.MAX_BYTES: raise ValueError('분석 크기는 1 ~ 16,384바이트입니다')
        bits = args.get('bits', 'auto')
        if bits == 'auto':
            info = checked(self.studio.driver.query_process_extended(session['pid']), '프로세스 아키텍처 조회')
            bits = 32 if info['is_wow64'] else 64
        else: bits = number(bits)
        if bits not in (32, 64): raise ValueError('32 / 64비트 중 선택하세요')
        if bits == 32 and start >= 0x100000000: raise ValueError('32비트 주소 범위 초과')
        regions = self.regions(session['pid'])
        # Continue across adjacent readable VAD entries, including instructions
        # crossing pages with different protection. Stop at the first gap/guard.
        cursor, end = start, min(start+size, 0x100000000 if bits == 32 else 0x800000000000)
        while cursor < end:
            try: region = self.region_at(regions, cursor)
            except ValueError:
                if cursor == start: raise
                break
            cursor = min(end, number(region['address']) + number(region['size']))
        size = cursor-start
        raw = self.studio.read_bytes(session['pid'], start, size)
        detail = V.analyze(raw, start, bits, 'sub_' + f'{start:X}')
        detail.update(function={'name': 'sub_' + f'{start:X}', 'address': V.hx(start)},
                      argument_hint='주소 범위 안에서 도달 가능한 명령과 분기를 분석합니다',
                      note='명령 더블클릭: 편집 · Ctrl+더블클릭: 참조 주소 이동')
        for row in detail['results']:
            row['size'] = len(bytes.fromhex(row['bytes']))
            row['references'] = references(row, bits)
        by_address = {row['address']: row for row in detail['results']}
        for node in detail['graph']['nodes']:
            node['instructions'] = [by_address[row['address']] for row in node['instructions']]
        if self.studio.identity(session['pid']) != session['identity']:
            raise ValueError('분석 도중 대상이 교체되었습니다')
        key = uuid.uuid4().hex
        session['analyses'][key] = {'address': start, 'raw': raw, 'bits': bits, 'rows': by_address}
        if len(session['analyses']) > 8: del session['analyses'][next(iter(session['analyses']))]
        return {'success': True, 'session_id': session['id'], 'analysis_id': key,
                'process_start_key': session['identity'], 'address': V.hx(start),
                'requested_bytes': number(args.get('size', 1024)), 'detail': detail, **self.history(session)}

    def validate(self, session, args):
        analysis = session['analyses'].get(args.get('analysis_id'))
        if not analysis: raise ValueError('분석 결과가 만료되었습니다. 주소를 다시 분석하세요')
        start = V.hx(address(args['address']))
        row = analysis['rows'].get(start)
        if not row: raise ValueError('분석된 명령어 시작 주소만 편집할 수 있습니다')
        compiled = compile_line(args['text'], address(start), analysis['bits'], row['size'])
        return {'success': True, 'address': start, 'before': row['bytes'], **compiled}

    @staticmethod
    def history(session):
        records = [{k: r[k] for k in ('id', 'time', 'state', 'edits')} for r in session['history']]
        recovery = session['recovery']
        return {'history': records, 'cursor': session['cursor'],
                'can_undo': session['cursor'] > 0 and not recovery,
                'can_redo': session['cursor'] < len(records) and not recovery,
                'recovery': None if not recovery else {'error': recovery['error'],
                    'edits': recovery['edits'], 'protection_errors': recovery.get('protection_errors', [])}}

    def owner(self, session):
        if self.studio.identity(session['pid']) != session['identity']:
            raise ValueError('대상 프로세스 생성 식별자가 변경되었습니다')

    def transact(self, session, edits, forward):
        """Preflight every span, restore RX pages, and retain failed recovery data.

        Writes are not atomic relative to running target threads. Conflicts stop
        the operation; automatic repair only touches bytes matching our own write.
        """
        pid = session['pid']
        source, destination = ('before', 'after') if forward else ('after', 'before')
        self.owner(session)
        regions = self.regions(pid)
        pages = {}
        for edit in edits:
            start, raw = address(edit['address']), bytes.fromhex(edit[source])
            for page in range(start & ~4095, (start+len(raw)-1 & ~4095)+4096, 4096):
                region = self.region_at(regions, page, 4096)
                pages[page] = number(region['protect'])
            if self.studio.read_bytes(pid, start, len(raw)) != raw:
                raise ValueError(f'{edit["address"]} 원본 불일치: 외부 변경이 있습니다. 다시 분석하세요')
        self.owner(session)
        recovery = {'edits': edits, 'source': source, 'destination': destination,
                    'written': [], 'pages': [], 'error': '', 'protection_errors': []}
        session['recovery'] = recovery  # Before the first possible mutation.
        failure = None
        try:
            for page, protect in sorted(pages.items()):
                if protect & 0xff in (4, 8, 0x40, 0x80): continue
                result = checked(self.studio.driver.protect_virtual_memory(pid, page, 4096, 0x40), '페이지 쓰기 허용')
                item = {'address': number(result['result_base_address']), 'size': number(result['result_region_size']),
                        'protect': number(result['old_protect'])}
                recovery['pages'].append(item)
                if number(result['result_base_address']) != page or item['size'] != 4096:
                    raise ValueError('페이지 보호 변경 범위가 요청과 다릅니다')
            for edit in edits:
                self.owner(session)
                start, before, after = address(edit['address']), bytes.fromhex(edit[source]), bytes.fromhex(edit[destination])
                if self.studio.read_bytes(pid, start, len(before)) != before:
                    raise ValueError('쓰기 직전 원본이 변경되었습니다')
                # Record even a failed transport: a partial write may have occurred.
                recovery['written'].append(edit)
                result = checked(self.studio.driver.write_process_memory(pid, start, after), '명령어 쓰기')
                if number(result.get('bytes_written', 0)) != len(after): raise ValueError('일부 바이트만 기록되었습니다')
                if self.studio.read_bytes(pid, start, len(after)) != after: raise ValueError('커널 읽기 검증 실패')
            self.owner(session)
        except Exception as exc:
            failure = str(exc)
            # Attempt a bounded rollback while writable pages are still available.
            try: self.rollback_bytes(session, recovery)
            except Exception as repair: failure += ' · 원본 복구 필요: ' + str(repair)
        finally:
            for item in list(reversed(recovery['pages'])):
                try:
                    self.owner(session)
                    checked(self.studio.driver.protect_virtual_memory(pid, item['address'], item['size'], item['protect']), '페이지 보호 복구')
                    recovery['pages'].remove(item)
                except Exception as exc: recovery['protection_errors'].append(str(exc))
        if failure or recovery['pages']:
            recovery['error'] = failure or '바이트는 기록되었으나 페이지 보호 복구가 실패했습니다'
            # Retain failed transaction until an explicit recovery verifies both
            # original bytes and page protections; never claim successful undo.
            return {'success': False, 'error': recovery['error'], **self.history(session)}
        session['recovery'] = None
        return {'success': True, 'verified': True, 'bytes_written': sum(len(bytes.fromhex(e[destination])) for e in edits)}

    def rollback_bytes(self, session, recovery):
        self.owner(session)
        for edit in reversed(recovery['written'][:]):
            start = address(edit['address'])
            before, after = bytes.fromhex(edit[recovery['source']]), bytes.fromhex(edit[recovery['destination']])
            current = self.studio.read_bytes(session['pid'], start, len(before))
            if current != before:
                if any(c not in (a, b) for c, a, b in zip(current, before, after)):
                    raise ValueError(edit['address'] + ' 외부 바이트 변경: 자동 복구를 중단했습니다')
                result = checked(self.studio.driver.write_process_memory(session['pid'], start, before), '원본 복구')
                if number(result.get('bytes_written', 0)) != len(before) or self.studio.read_bytes(session['pid'], start, len(before)) != before:
                    raise ValueError('원본 복구 검증 실패')
            recovery['written'].remove(edit)

    def recover(self, session):
        recovery = session['recovery']
        if not recovery: return {'success': True, **self.history(session)}
        # Re-enable only pages containing incomplete writes, retaining the actual
        # original protection from the failed transaction if it remains pending.
        try:
            regions = self.regions(session['pid'])
            for edit in recovery['written']:
                start, size = address(edit['address']), len(bytes.fromhex(edit['before']))
                for page in range(start & ~4095, (start+size-1 & ~4095)+4096, 4096):
                    region = self.region_at(regions, page, 4096)
                    if number(region['protect']) & 0xff in (4, 8, 0x40, 0x80): continue
                    self.owner(session)
                    result = checked(self.studio.driver.protect_virtual_memory(session['pid'], page, 4096, 0x40), '복구 페이지 쓰기 허용')
                    if not any(p['address'] == page for p in recovery['pages']):
                        recovery['pages'].append({'address': page, 'size': number(result['result_region_size']), 'protect': number(result['old_protect'])})
            self.rollback_bytes(session, recovery)
        except Exception as exc:
            recovery['error'] = str(exc)
        finally:
            recovery['protection_errors'] = []
            for page in reversed(recovery['pages'][:]):
                try:
                    self.owner(session)
                    checked(self.studio.driver.protect_virtual_memory(session['pid'], page['address'], page['size'], page['protect']), '페이지 보호 복구')
                    recovery['pages'].remove(page)
                except Exception as exc: recovery['protection_errors'].append(str(exc))
        if not recovery['written'] and not recovery['pages']:
            session['recovery'] = None
            return {'success': True, 'restored': True, **self.history(session)}
        return {'success': False, 'error': recovery['error'] or '복구가 완료되지 않았습니다', **self.history(session)}

    def operate(self, operation, args):
        with self.studio.lock, self.studio.driver._lock, self.lock:
            if operation == 'disasm_release':
                session = self.sessions.get(args.get('session_id'))
                if session and session['pid'] == number(args.get('pid', 0)):
                    del self.sessions[session['id']]
                return {'success': True}
            session = self.session(args, create=operation == 'disasm_analyze')
            if operation == 'disasm_analyze':
                try: return self.analyze(session, args)
                except Exception:
                    if not args.get('session_id'): self.sessions.pop(session['id'], None)
                    raise
            if operation == 'disasm_history': return {'success': True, **self.history(session)}
            if operation == 'disasm_validate': return self.validate(session, args)
            if operation == 'disasm_recover': return self.recover(session)
            if operation == 'disasm_follow':
                analysis = session['analyses'].get(args.get('analysis_id'))
                if not analysis: raise ValueError('다시 분석하세요')
                row = analysis['rows'].get(V.hx(address(args['address'])))
                index = number(args.get('reference', 0))
                if not row or not 0 <= index < len(row['references']): raise ValueError('해석 가능한 참조 주소가 없습니다')
                ref = row['references'][index]
                target = address(ref['address'])
                if ref['indirect']:
                    target = int.from_bytes(self.studio.read_bytes(session['pid'], target, analysis['bits']//8), 'little')
                target = address(target)
                return {'success': True, 'address': V.hx(target), 'reference': ref}
            if session['recovery']: raise ValueError('이전 요청의 원본 / 페이지 보호 복구를 먼저 완료하세요')
            if operation == 'disasm_apply':
                pending = args.get('edits')
                if not isinstance(pending, list) or not 1 <= len(pending) <= MAX_EDITS: raise ValueError('1 ~ 128개의 편집을 입력하세요')
                if session['cursor'] >= MAX_HISTORY: raise ValueError('복구 이력 상한 128회에 도달했습니다')
                edits = []
                for item in pending:
                    compiled = self.validate(session, {**args, **item})
                    if compiled['before'] == compiled['patch_bytes']: continue
                    edits.append({'address': compiled['address'], 'before': compiled['before'],
                                  'after': compiled['patch_bytes'], 'assembly': compiled['assembly']})
                edits.sort(key=lambda e: address(e['address']))
                if not edits: return {'success': True, 'unchanged': True, **self.history(session)}
                for a, b in zip(edits, edits[1:]):
                    if address(a['address']) + len(bytes.fromhex(a['before'])) > address(b['address']):
                        raise ValueError('편집 주소가 중복되거나 겹칩니다')
                result = self.transact(session, edits, True)
                if result['success']:
                    del session['history'][session['cursor']:]
                    session['history'].append({'id': uuid.uuid4().hex, 'time': time.time(), 'state': 'applied', 'edits': edits})
                    session['cursor'] += 1
                return {**result, **self.history(session)}
            if operation in ('disasm_undo', 'disasm_redo'):
                forward = operation == 'disasm_redo'
                index = session['cursor'] if forward else session['cursor']-1
                if not 0 <= index < len(session['history']): raise ValueError('되돌릴 / 다시 적용할 편집이 없습니다')
                record = session['history'][index]
                result = self.transact(session, record['edits'], forward)
                if result['success']:
                    session['cursor'] += 1 if forward else -1
                    record['state'] = 'applied' if forward else 'restored'
                return {**result, **self.history(session)}
            raise ValueError('지원하지 않는 편집 작업')
