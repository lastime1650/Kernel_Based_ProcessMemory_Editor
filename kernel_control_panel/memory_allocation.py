"""Payload allocation using only the existing kernel bridge; per-page-load history."""
import hashlib
import threading
import time
import uuid

from memory_editor import number, location
from request_scheduler import scope

MAX_BYTES = 1048576


def payload(body):
    if any(k in body for k in ('address', 'base_address', 'BaseAddress')):
        raise ValueError('할당 주소는 커널이 결정합니다')
    kind = body.get('kind', 'string')
    encoding = body.get('encoding', 'ansi')
    if kind == 'string':
        value = body.get('text', '')
        if not isinstance(value, str) or not value.replace('\x00', '').strip():
            raise ValueError('빈 문자열이나 공백만 있는 문자열은 할당할 수 없습니다')
        if len(value) > MAX_BYTES:
            raise ValueError('입력 상한은 1MiB입니다')
        if encoding not in ('ansi', 'wide'):
            raise ValueError('ANSI 또는 Wide를 선택하세요')
        try:
            data = value.encode('mbcs' if encoding == 'ansi' else 'utf-16-le', errors='strict')
            if encoding == 'ansi' and data.decode('mbcs', errors='strict') != value:
                raise ValueError('ANSI 변환 시 문자가 변경됩니다. Wide를 선택하세요')
        except UnicodeError as exc:
            raise ValueError('선택한 문자 인코딩으로 표현할 수 없는 문자가 있습니다') from exc
        data += b'\x00' if encoding == 'ansi' else b'\x00\x00'
        meta = {'kind': kind, 'encoding': encoding, 'source': value[:80],
                'terminator_bytes': 1 if encoding == 'ansi' else 2}
    elif kind == 'file':
        value = body.get('data_hex', '')
        if not isinstance(value, str) or len(value) > MAX_BYTES * 2:
            raise ValueError('파일 상한은 1MiB입니다')
        if len(value) % 2 or any(c not in '0123456789abcdefABCDEF' for c in value):
            raise ValueError('파일 바이트 형식이 올바르지 않습니다')
        data = bytes.fromhex(value)
        meta = {'kind': kind, 'encoding': 'raw', 'source': str(body.get('filename', 'file'))[:260],
                'terminator_bytes': 0}
    else:
        raise ValueError('문자열 또는 파일을 선택하세요')
    if not data:
        raise ValueError('빈 파일은 할당할 수 없습니다')
    if len(data) > MAX_BYTES:
        raise ValueError('NULL을 포함한 할당 데이터 상한은 1MiB입니다')
    return data, dict(meta, size=len(data), sha256=hashlib.sha256(data).hexdigest())


def checked(response, message):
    if not response.get('success'):
        raise ValueError(f'{message}: {response.get("result_status", response.get("error_code", "실패"))}')
    return response


class Workspace:
    def __init__(self, studio):
        self.studio = studio
        self.lock = threading.RLock()
        self.sessions = {}

    def create(self, body):
        pid = number(body.get('pid', 0))
        if not 1 <= pid <= 0xffffffff:
            raise ValueError('대상 PID를 선택하세요')
        with self.lock, self.studio.lock, self.studio.driver._lock:
            identity = self.studio.identity(pid)
            if len(self.sessions) >= 64:
                oldest = min(self.sessions, key=lambda k: self.sessions[k]['used'])
                del self.sessions[oldest]  # History metadata only; never frees target memory.
            key = uuid.uuid4().hex
            self.sessions[key] = {'pid': pid, 'identity': identity, 'records': {}, 'used': time.time()}
            return {'success': True, 'id': key, 'pid': pid, 'identity': identity, 'records': []}

    def remove(self, key):
        with self.lock:
            self.sessions.pop(key, None)
        return {'success': True}

    def packet(self, key, session, **extra):
        return {'success': True, 'id': key, 'pid': session['pid'], 'identity': session['identity'],
                'records': [dict(r) for r in sorted(session['records'].values(),
                                                  key=lambda r: r['created'], reverse=True)], **extra}

    def invoke(self, key, action, body):
        if action not in ('list', 'allocate', 'free'):
            raise ValueError('지원하지 않는 할당 작업입니다')
        # Same lock order as Studio allocation/free operations and the write journal.
        with scope(0), self.lock, self.studio.lock, self.studio.driver._lock:
            s = self.sessions.get(key)
            if not s:
                raise ValueError('할당 이력이 초기화되었습니다. 메뉴를 다시 여세요')
            if body.get('pid') is not None and number(body['pid']) != s['pid']:
                raise ValueError('선택한 대상과 할당 이력의 PID가 다릅니다')
            self.studio.check_owner(s)
            s['used'] = time.time()
            if action == 'list':
                return self.packet(key, s)
            if action == 'free':
                base = location(body.get('base_address', ''))
                address = f'0x{base:X}'
                r = next((r for r in s['records'].values() if r['base_address'] == address
                          and r['status'] in ('allocated', 'needs_free')), None)
                if not r or r['status'] not in ('allocated', 'needs_free'):
                    raise ValueError('이 화면에서 할당한 활성 BaseAddress만 해제할 수 있습니다')
                allocation_key = f'{s["pid"]}:{address}'
                owner = self.studio.allocations.get(allocation_key)
                if not owner or owner.get('reservation_id') != r['reservation_id']:
                    raise ValueError('이 BaseAddress의 할당 기록이 교체되었거나 이미 해제되었습니다')
                checked(self.studio.driver.free_virtual_memory(s['pid'], base), '커널 할당 해제 실패')
                self.studio.allocations.pop(allocation_key, None)
                r.update(status='freed', freed=time.time())
                return self.packet(key, s, base_address=address)

            data, meta = payload(body)
            self.studio.prune_allocations()
            if len(self.studio.allocations) >= 128 or len(s['records']) >= 256:
                raise ValueError('할당 이력 상한입니다. 기존 할당을 해제하거나 이력을 초기화하세요')
            response = checked(self.studio.driver.alloc_virtual_memory(s['pid'], len(data), 4), '커널 할당 실패')
            base = location(response['allocated_address'])
            address = f'0x{base:X}'
            owner = {'pid': s['pid'], 'identity': s['identity'], 'address': address,
                     'size': len(data), 'reservation_id': uuid.uuid4().hex}
            self.studio.allocations[f'{s["pid"]}:{address}'] = owner
            r = dict(owner, **meta, base_address=address, created=time.time(), status='needs_free', verified=False)
            # The same BaseAddress may be reused after MEM_RELEASE. Keep both events,
            # while free still identifies the currently active allocation by BaseAddress.
            s['records'][owner['reservation_id']] = r
            try:
                self.studio.check_owner(s)
                written = checked(self.studio.driver.write_process_memory(s['pid'], base, data), '초기 데이터 쓰기 실패')
                if written.get('bytes_written') != len(data):
                    raise ValueError('초기 데이터 쓰기 크기가 일치하지 않습니다')
                self.studio.check_owner(s)
                if self.studio.read_bytes(s['pid'], base, len(data)) != data:
                    raise ValueError('초기 데이터 읽기 검증 실패')
                r.update(status='allocated', verified=True)
                return self.packet(key, s, base_address=address, verified=True)
            except Exception as exc:
                r['error'] = str(exc)
                try:
                    self.studio.check_owner(s)  # Never free a replacement process's address.
                    checked(self.studio.driver.free_virtual_memory(s['pid'], base), '실패한 할당 정리 실패')
                except Exception as cleanup:
                    r['cleanup_error'] = str(cleanup)
                else:
                    self.studio.allocations.pop(f'{s["pid"]}:{address}', None)
                    r.update(status='rolled_back', freed=time.time())
                return self.packet(key, s, success=False, error=str(exc),
                                   base_address=address, cleanup_required=r['status'] == 'needs_free')
