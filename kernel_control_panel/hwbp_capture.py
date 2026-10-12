"""Target VEH telemetry, transported exclusively with existing kernel IOCTLs.

The pinned target DLL owns its ring. No process/thread handles, pipes or RPM.
The worker copies committed slots and publishes bounded cursor-based history.
"""
import base64
from collections import deque
import struct
import threading
import time
from pathlib import Path

from runtime_paths import bundle_root
from request_scheduler import scope

MAGIC = b'KSHWBP01'
CONFIG_MAGIC = b'KSCFG001'
HEADER = 256
SLOT = 1344
CAPACITY = 256
CONTEXT_SIZE = 1232
HISTORY = 4096
DLL_NAME = 'KernelStudioCapture.dll'


def registers(raw):
    if len(raw) != CONTEXT_SIZE:
        raise ValueError('CONTEXT 크기 불일치')
    result = {'context_flags': hex(struct.unpack_from('<I', raw, 48)[0]),
              'mxcsr': hex(struct.unpack_from('<I', raw, 52)[0]),
              'eflags': hex(struct.unpack_from('<I', raw, 68)[0])}
    for i, name in enumerate(('cs', 'ds', 'es', 'fs', 'gs', 'ss')):
        result[name] = hex(struct.unpack_from('<H', raw, 56 + 2*i)[0])
    for i, name in enumerate(('dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7')):
        result[name] = hex(struct.unpack_from('<Q', raw, 72 + 8*i)[0])
    for i, name in enumerate(('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip')):
        result[name] = hex(struct.unpack_from('<Q', raw, 120 + 8*i)[0])
    # FltSave.XmmRegisters begins at 416 in AMD64 CONTEXT.
    for i in range(16):
        result[f'xmm{i}'] = '0x' + raw[416 + 16*i:432 + 16*i][::-1].hex()
    for i in range(6):
        result[f'p{i+1}_home'] = hex(struct.unpack_from('<Q', raw, i*8)[0])
    float_fields = [('control_word',256,'H'),('status_word',258,'H'),('tag_word',260,'B'),
                    ('reserved1',261,'B'),('error_opcode',262,'H'),('error_offset',264,'I'),
                    ('error_selector',268,'H'),('reserved2',270,'H'),('data_offset',272,'I'),
                    ('data_selector',276,'H'),('reserved3',278,'H'),('mxcsr',280,'I'),('mxcsr_mask',284,'I')]
    for name, offset, fmt in float_fields:
        result['flt_save_'+name] = hex(struct.unpack_from('<'+fmt,raw,offset)[0])
    for i in range(8):
        result[f'flt_save_float_register{i}'] = '0x'+raw[288+16*i:304+16*i][::-1].hex()
    result['flt_save_reserved4'] = '0x'+raw[672:768].hex()
    for i in range(26):
        result[f'vector_register{i}'] = '0x'+raw[768+16*i:784+16*i][::-1].hex()
    for i,name in enumerate(('vector_control','debug_control','last_branch_to_rip',
                             'last_branch_from_rip','last_exception_to_rip','last_exception_from_rip')):
        result[name] = hex(struct.unpack_from('<Q',raw,1184+8*i)[0])
    return result


def config(owners=(), release=False):
    if len(owners) > 4:
        raise ValueError('한 수집 세션의 중단점 주소는 최대 4개입니다')
    data = bytearray(128)
    struct.pack_into('<8sIIIIQ', data, 0, CONFIG_MAGIC, 1, 128, len(owners), int(release), 0)
    for i, owner in enumerate(owners):
        struct.pack_into('<QIIII', data, 32 + 24*i, int(owner['address'], 16),
                         owner['type'], owner['length'], 1, 0)
    return bytes(data)


class Capture:
    def __init__(self, studio):
        self.studio = studio
        self.lock = threading.RLock()
        self.sessions = {}
        self.stop_event = threading.Event()
        self.worker = None

    def _start_worker(self):
        with self.lock:
            if self.worker and self.worker.is_alive():
                return
            self.stop_event.clear()
            self.worker = threading.Thread(target=self._work, name='hwbp-capture', daemon=True)
            self.worker.start()

    def _work(self):
        while not self.stop_event.wait(.05):
            with self.lock:
                records = list(self.sessions.values())
            for record in records:
                if record['state'] not in ('ready', 'capturing', 'paused', 'guard'):
                    continue
                try:
                    with scope(2, 'hwbp-capture'):
                        self.poll(record)
                except Exception as exc:
                    with self.lock:
                        record['last_error'] = str(exc)
                        record['read_failures'] += 1
                        # Query identity on the next poll before reading a reused PID.

    def _require(self, response, message='드라이버 요청 실패'):
        if not response.get('success'):
            from studio_api import StudioError
            raise StudioError(message, response)
        return response

    def _reconcile(self, record):
        if record.get('control_uncertain'):
            raise ValueError('이전 VEH 호출의 실행 여부가 불확실합니다. 새 제어 요청을 차단하고 핸들러를 유지합니다')
        driver = self.studio.driver
        for call_id in list(record['pending_calls']):
            response = self._require(driver.query_function_call(call_id, 0), '이전 VEH 호출 확인 실패')
            self._call_owner(record, response)
            if not response.get('completed') or response.get('exit_value') is None:
                raise ValueError('이전 VEH 호출이 실행 중입니다. 완료 전에는 새 제어 요청을 보낼 수 없습니다')
            for parameter, item in list(record['pending_buffers'].items()):
                if item['call_id'] == call_id:
                    self.studio.check_owner(record)
                    self._require(driver.free_virtual_memory(record['pid'], parameter), 'VEH 인자 해제 실패')
                    record['pending_buffers'].pop(parameter)
            self._require(driver.release_function_call(call_id), 'VEH 호출 기록 해제 실패')
            record['pending_calls'].remove(call_id)
        for parameter, item in list(record['pending_buffers'].items()):
            if item.get('completed'):
                self.studio.check_owner(record)
                self._require(driver.free_virtual_memory(record['pid'], parameter), 'VEH 인자 해제 실패')
                record['pending_buffers'].pop(parameter)

    def _call_owner(self, record, response):
        if response.get('pid') != record['pid'] or str(response.get('process_start_key')) != record['identity']:
            raise ValueError('VEH 호출 기록의 프로세스 소유 정보가 다릅니다')

    def _call(self, record, name, data=None):
        """Retain arguments if completion is unknown; never free live parameters."""
        self.studio.check_owner(record)
        self._reconcile(record)
        parameter = 0
        driver = self.studio.driver
        if data is not None:
            allocation = self._require(driver.alloc_virtual_memory(record['pid'], len(data), 4))
            parameter = int(allocation['allocated_address'], 16)
            record['pending_buffers'][parameter] = {'call_id': None, 'name': name}
            try:
                written = self._require(driver.write_process_memory(record['pid'], parameter, data))
                if written.get('bytes_written') != len(data):
                    raise ValueError('VEH 설정 쓰기 크기 불일치')
            except Exception:
                record['pending_buffers'][parameter]['completed'] = True
                self.studio.check_owner(record)
                freed = driver.free_virtual_memory(record['pid'], parameter)
                if freed.get('success'): record['pending_buffers'].pop(parameter, None)
                raise
        completed = False
        call_id = None
        attempted = False
        try:
            attempted = True
            response = driver.create_function_call(record['pid'], int(record['identity']),
                       record['exports'][name], parameter, 1000)
            call_id = int(response.get('call_id', '0')) or None
            if response.get('execution_unknown') and not call_id:
                record['control_uncertain'] = True
            if not response.get('success') and response.get('packet_valid') and not response.get('thread_created'):
                completed = True # Confirmed no target thread can use the argument.
            if parameter: record['pending_buffers'][parameter]['call_id'] = call_id
            self._require(response, 'VEH 함수 호출 결과를 확인할 수 없습니다')
            deadline = time.monotonic() + 5
            while not response.get('completed') and time.monotonic() < deadline:
                response = self._require(driver.query_function_call(call_id, 1000))
                self._call_owner(record, response)
            if not response.get('completed') or response.get('exit_value') is None:
                raise ValueError('VEH 함수가 아직 실행 중입니다. 인자 버퍼를 보존했습니다')
            completed = True
            if response['exit_value']:
                raise ValueError(f'VEH {name} 실패 (Win32 {response["exit_value"]})')
            self.studio.check_owner(record)
            return self.studio.read_bytes(record['pid'], parameter, len(data)) if data is not None else b''
        finally:
            if completed:
                if parameter: record['pending_buffers'][parameter]['completed'] = True
                if call_id:
                    released = driver.release_function_call(call_id)
                    if not released.get('success'): record['pending_calls'].add(call_id)
                if parameter:
                    try: self.studio.check_owner(record)
                    except Exception:
                        record['state']='exited'
                        record['pending_buffers'].pop(parameter, None)
                    else:
                        freed = driver.free_virtual_memory(record['pid'], parameter)
                        if freed.get('success'): record['pending_buffers'].pop(parameter, None)
            elif call_id:
                record['pending_calls'].add(call_id)
            elif attempted:
                record['control_uncertain'] = True

    def prepare(self, pid):
        pid = int(pid)
        if not 0 < pid <= 0xffffffff: raise ValueError('대상 PID가 필요합니다')
        identity = self.studio.identity(pid)
        with self.lock:
            record = self.sessions.get(pid)
        if record and record['identity'] == identity and record['state'] != 'exited':
            if record['state'] == 'initializing':
                self._reconcile(record)
                output = self._call(record, 'GetCaptureBuffer', bytes(8))
                record['ring'] = struct.unpack('<Q', output)[0]
                self._call(record, 'StartCapture', config())
                self._header(record)
                record['state']='ready'
            if record['state'] == 'stopped':
                self._call(record, 'StartCapture', config())
                record.update(state='ready', owners=[], unknown_arm=False)
            self._start_worker()
            return record
        path = bundle_root() / 'native' / 'hwbp_capture' / DLL_NAME
        if not path.is_file(): raise ValueError(f'VEH 캡처 DLL이 없습니다: {path}')
        loaded = self._require(self.studio.workbench.load(pid, str(path), 8000), 'VEH DLL 로드를 확인하지 못했습니다')
        image = loaded['image']
        from image_workbench import CachedImageReader
        from studio_extensions import LoadedPE
        base = int(image.get('base', image.get('address', '0')), 16)
        pe = LoadedPE(CachedImageReader(self.studio, pid, base), pid, base)
        exports = {row['name']: int(row['address'], 16) for row in pe.exports() if not row.get('forwarder')}
        needed = ('StartCapture', 'StopCapture', 'ShutdownCapture', 'GetCaptureBuffer')
        if not all(name in exports for name in needed): raise ValueError('VEH DLL export ABI 오류')
        record = {'pid': pid, 'identity': identity, 'state': 'initializing', 'base': hex(base),
                  'dll_path': str(path), 'exports': exports, 'ring': 0, 'owners': [], 'guard_owners': [],
                  'events': deque(maxlen=HISTORY), 'cursor': 0, 'last_ticket': 0,
                  'received': 0, 'ring_lost': 0, 'history_evicted': 0, 'read_failures': 0,
                  'last_error': '', 'stats': {}, 'unknown_arm': False,
                  'pending_buffers': {}, 'pending_calls': set(), 'control_uncertain': False,
                  'poll_lock': threading.Lock()}
        with self.lock: self.sessions[pid] = record
        output = self._call(record, 'GetCaptureBuffer', bytes(8))
        record['ring'] = struct.unpack('<Q', output)[0]
        self._call(record, 'StartCapture', config())
        self._header(record)
        record['state'] = 'ready'
        self._start_worker()
        return record

    def arm(self, pid, address, kind, length):
        if kind not in (0, 1, 3) or length not in (1, 2, 4, 8):
            raise ValueError('중단점 유형/길이 오류')
        if (kind == 0 and length != 1) or address % length:
            raise ValueError('실행 중단점은 1바이트, 데이터 중단점은 길이에 맞춘 정렬이 필요합니다')
        record = self.prepare(pid)
        owner = {'address': hex(address), 'type': kind, 'length': length}
        active = [r for r in self.studio.breakpoints.values() if r['pid'] == pid and r['identity'] == record['identity']]
        if any(int(r['address'], 16) == address and r['type'] == kind and r['length'] == length for r in active):
            raise ValueError('같은 중단점이 이미 설정되어 있습니다')
        owners = [{'address': hex(int(x['address'], 16)), 'type': x['type'], 'length': x['length']} for x in active]
        if owner not in owners: owners.append(owner)
        self._call(record, 'StartCapture', config(owners))
        record['owners'] = owners
        if owner not in record['guard_owners']: record['guard_owners'].append(owner)
        header = self._header(record)
        if header['native_state'] != 1: raise ValueError('VEH 준비가 확인되지 않아 중단점을 설정하지 않았습니다')
        record['state'] = 'capturing'
        return record

    def _header(self, record):
        raw = self.studio.read_bytes(record['pid'], record['ring'], HEADER)
        if raw[:8] != MAGIC or struct.unpack_from('<IIIII', raw, 8) != (1, HEADER, SLOT, CAPACITY, CONTEXT_SIZE):
            raise ValueError('VEH 링 버퍼 ABI 오류')
        state, pid = struct.unpack_from('<II', raw, 28)
        if pid != record['pid']: raise ValueError('VEH 링 버퍼 PID 오류')
        freq, ticket, published, contention, overwritten = struct.unpack_from('<QQQQQ', raw, 40)
        stats = dict(native_state=state, capacity=CAPACITY, qpc_frequency=str(freq),
                     next_ticket=ticket, dll_published=published, contention_dropped=contention,
                     dll_overwrites=overwritten, handlers_inflight=struct.unpack_from('<I', raw, 80)[0])
        with self.lock: record['stats'] = stats
        return stats

    def poll(self, record):
        if not record['poll_lock'].acquire(False): return
        try:
            response = self.studio.driver.query_process_info(record['pid'])
            if not response.get('success'):
                self._require(response, '대상 프로세스 상태 조회 실패')
            if response.get('exit_status') != 259 or str(response['process_start_key']) != record['identity']:
                with self.lock: record.update(state='exited', last_error='대상 프로세스가 종료되거나 교체되었습니다')
                return
            header = self._header(record)
            newest = header['next_ticket']
            first = max(record['last_ticket'] + 1, newest - CAPACITY + 1)
            if first > record['last_ticket'] + 1:
                with self.lock: record['ring_lost'] += first - record['last_ticket'] - 1
                record['last_ticket'] = first - 1
            # Read the header's window; records committed while copying remain for the next poll.
            if first > newest: return
            raw = self.studio.read_bytes(record['pid'], record['ring'] + HEADER, SLOT * CAPACITY)
            settled = self._header(record)
            for ticket in range(first, newest + 1):
                index = (ticket - 1) % CAPACITY
                slot = raw[index*SLOT:(index+1)*SLOT]
                begin, actual = struct.unpack_from('<QQ', slot)
                end = struct.unpack_from('<Q', slot, 1296)[0]
                if actual != ticket or begin != ticket*2 or end != begin:
                    # A reserved ticket may still be writing, or have been dropped.
                    # Do not advance across an unfinished ticket until the window overtakes it.
                    if not settled['handlers_inflight'] and settled['next_ticket'] == newest:
                        slot = self.studio.read_bytes(record['pid'], record['ring']+HEADER+index*SLOT, SLOT)
                        begin, actual = struct.unpack_from('<QQ', slot)
                        end = struct.unpack_from('<Q', slot, 1296)[0]
                        if actual != ticket or begin != ticket*2 or end != begin:
                            with self.lock:
                                record['ring_lost'] += 1
                                record['last_ticket'] = ticket
                            continue
                    else: break
                at = record['ring'] + HEADER + index*SLOT
                check_begin = struct.unpack('<Q', self.studio.read_bytes(record['pid'], at, 8))[0]
                check_end = struct.unpack('<Q', self.studio.read_bytes(record['pid'], at+1296, 8))[0]
                if check_begin != begin or check_end != begin: break
                qpc, pid, tid, hit, execute, exception, code, flags, size = struct.unpack_from('<QIIIIQIII', slot, 16)
                if pid != record['pid'] or size != CONTEXT_SIZE or code != 0x80000004:
                    raise ValueError('VEH 이벤트 형식 오류')
                context = slot[64:64+CONTEXT_SIZE]
                event = {'sequence': str(ticket), 'pid': pid, 'thread_id': tid, 'time': time.time(),
                         'qpc': str(qpc), 'hit_mask': hit, 'execute_mask': execute,
                         'exception_address': hex(exception), 'exception_code': hex(code),
                         'registers': registers(context), 'context_base64': base64.b64encode(context).decode(),
                         'context_size': CONTEXT_SIZE}
                with self.lock:
                    record['cursor'] += 1
                    event['id'] = record['cursor']
                    if len(record['events']) == HISTORY: record['history_evicted'] += 1
                    record['events'].append(event)
                    record['received'] += 1
                    record['last_ticket'] = ticket
                    record['last_error'] = ''
        finally:
            record['poll_lock'].release()

    def view(self, pid, after=0, limit=200):
        pid, after, limit = int(pid), int(after), int(limit)
        if after < 0 or not 1 <= limit <= 500: raise ValueError('수집 cursor 또는 목록 크기 오류')
        with self.lock:
            record = self.sessions.get(pid)
            if not record:
                return {'success': True, 'session': {'pid': pid, 'state': 'unprepared'},
                        'stats': {}, 'events': [], 'next_cursor': 0, 'has_more': False}
            public = {key: record[key] for key in ('pid', 'identity', 'state', 'base', 'dll_path',
                       'last_error', 'unknown_arm', 'control_uncertain')}
            rows = [dict(row) for row in record['events'] if row['id'] > after]
            selected = rows[:limit]
            stats = dict(record['stats'], received=record['received'], ring_lost=record['ring_lost'],
                         history_evicted=record['history_evicted'], read_failures=record['read_failures'],
                         retained_guard=record['stats'].get('native_state')==3,
                         pending_buffers=len(record['pending_buffers']), pending_calls=len(record['pending_calls']))
            gap = max(0, record['events'][0]['id'] - after - 1) if record['events'] and after else 0
            return {'success': True, 'session': public, 'stats': stats, 'events': selected,
                    'next_cursor': selected[-1]['id'] if selected else record['cursor'],
                    'has_more': len(rows) > limit, 'client_gap': gap,
                    'note': '원본 AMD64 CONTEXT 1232바이트. 신규 스레드는 자동 적용되지 않습니다. 데이터 BP RIP는 접근 후 위치일 수 있습니다.'}

    def action(self, action, args):
        pid = int(args.get('pid', 0))
        with self.studio.lock:
            if action == 'prepare': self.prepare(pid)
            else:
                with self.lock: record = self.sessions.get(pid)
                if not record: raise ValueError('먼저 수집 DLL을 준비하세요')
                if action == 'clear':
                    with self.lock: record['events'].clear()
                elif action == 'pause':
                    self._call(record, 'StopCapture')
                    record['state'] = 'paused'
                elif action == 'resume':
                    self._call(record, 'StartCapture', config(record['owners']))
                    record['state'] = 'capturing' if record['owners'] else 'ready'
                elif action == 'stop':
                    self.stop(record)
                else: raise ValueError('알 수 없는 수집 작업')
            return self.view(pid)

    def stop(self, record):
        self.studio.check_owner(record)
        self._reconcile(record)
        failures = []
        for key, bp in list(self.studio.breakpoints.items()):
            if bp['pid'] == record['pid'] and bp['identity'] == record['identity']:
                result = self.studio.driver.remove_hardware_breakpoint(record['pid'], bp['node'])
                if result.get('success'):
                    result = self.studio.driver.free_hardware_breakpoint_result(bp['node'])
                    if result.get('success'): self.studio.breakpoints.pop(key, None)
                if not result.get('success'): failures.append(result)
        if failures:
            record.update(state='guard', last_error='중단점 복원 실패: 예외 재개 핸들러를 유지합니다')
            raise ValueError(record['last_error'])
        # A failed METHOD_BUFFERED set may hide a rollback recovery packet.
        # Verify no whitelisted hardware slot remains before removing VEH.
        queried = self.studio.parsed_list(self.studio.driver.query_hardware_breakpoint(record['pid']), 'breakpoints')
        self._require(queried, '중단점 해제 검증 실패: VEH를 유지합니다')
        if queried.get('truncated'): raise ValueError('전체 스레드 검증이 필요하여 VEH를 유지합니다')
        owners = {int(x['address'], 16) for x in record['guard_owners']}
        for row in queried.get('results', []):
            dr7 = int(row.get('dr7', '0'), 16)
            if any(dr7 & (3 << (2*i)) and int(row.get(f'dr{i}', '0'), 16) in owners for i in range(4)):
                record['state'] = 'guard'
                raise ValueError('대상에 관리 주소의 중단점이 남아 있어 VEH를 유지합니다')
        # A #DB may already have been raised before DR restoration, yet not have
        # reached VEH. Keep the pinned, non-recording handler for that late event.
        self._call(record, 'StopCapture')
        record.update(state='stopped', owners=[], unknown_arm=False)
        self._header(record)

    def shutdown(self):
        self.stop_event.set()
        if self.worker: self.worker.join(timeout=5)
        # Studio shutdown restores tracked breakpoints separately. Keep target VEH
        # pinned as a resumable guard if cleanup cannot be confirmed.
        for record in list(self.sessions.values()):
            if record['state'] in ('ready', 'capturing', 'paused', 'guard'):
                try: self.stop(record)
                except Exception as exc:
                    record.update(state='guard', last_error=str(exc))
