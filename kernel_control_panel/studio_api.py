"""Browser tools built on the existing driver ABI. No new kernel operations."""
import base64
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import ctypes as C
import json
import math
import os
import struct
import threading
import time
import uuid
import asyncio

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from memory_dump import DumpManager, MAX_DUMP_BYTES, MAX_CHUNK_BYTES
import driver_bridge as D
import studio_extensions as E
import image_workbench as W
import disassembly_workspace as A
import scan_workspace as S
import memory_editor as M
import memory_wide_view as MV
import memory_allocation as MA
import productivity_suite as P
import sqlite3
from request_scheduler import scope
from pathlib import Path
from memory_scanner import FORMATS

MAX_BYTES = 1024 * 1024
MAX_RESULTS = 5000


class StudioError(Exception):
    def __init__(self, message, response=None):
        super().__init__(message)
        self.response = response or {}


class DumpDownload(FileResponse):
    def __init__(self, path, manager, key, **kwargs):
        self.manager, self.key = manager, key
        super().__init__(path, **kwargs)

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            # Also release for an invalid Range or an interrupted download.
            self.manager.release_download(self.key)


def integer(value):
    if isinstance(value, bool):
        raise ValueError("숫자를 입력하세요")
    return int(str(value).strip(), 16 if str(value).strip().lower().startswith(('0x', '-0x')) else 10)


def address(value):
    result = integer(value)
    if not 0 < result < 0x800000000000:
        raise ValueError("사용자 주소 범위의 주소가 필요합니다")
    return result


def bounded(value, maximum=MAX_BYTES, minimum=1):
    result = integer(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"값은 {minimum}부터 {maximum} 사이여야 합니다")
    return result


def require(response):
    if not response.get('success'):
        raise StudioError("드라이버 요청 실패", response)
    return response


def payload(args):
    kind = args.get('data_type', 'hex')
    value = str(args.get('value', ''))
    if kind == 'hex':
        result = bytes.fromhex(value.replace('0x', '').replace(',', ' '))
    elif kind in ('text', 'utf8'):
        result = value.encode('utf-8')
    elif kind == 'utf16':
        result = value.encode('utf-16-le')
    elif kind in FORMATS:
        fmt, _ = FORMATS[kind]
        number = float(value) if kind.startswith('float') else integer(value)
        if isinstance(number, float) and not math.isfinite(number):
            raise ValueError("유한한 수를 입력하세요")
        result = struct.pack(fmt, number)
    else:
        raise ValueError("지원하지 않는 데이터 형식")
    if not result or len(result) > MAX_BYTES:
        raise ValueError("쓰기 크기는 1바이트부터 1MB까지입니다")
    return result


class Node(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ('Signature', 'Previous', 'Next', 'Data', 'DataSize')]


class StringInfo(C.Structure):
    _fields_ = [('StringAddress', C.c_uint64), ('DumpedAddress', C.c_uint64),
                ('StringSize', C.c_uint64), ('Encoding', C.c_uint32)]


class RegionInfo(C.Structure):
    _fields_ = [('BaseAddress', C.c_uint64), ('AllocationBase', C.c_uint64), ('RegionSize', C.c_uint64),
                ('AllocationProtect', C.c_uint32), ('Protect', C.c_uint32), ('State', C.c_uint32), ('Type', C.c_uint32)]
    _fields_ += [(name, C.c_uint8) for name in ('IsCommitted', 'IsReadable', 'IsWritable', 'IsExecutable',
                 'IsGuarded', 'IsPrivate', 'IsMapped', 'IsImage', 'HasImageInformation',
                 'HasPeHeaderInformation', 'IsImageBase', 'IsMainImage')]
    _fields_ += [('ReservedFlags', C.c_uint8 * 4), ('ImageBaseAddress', C.c_uint64),
                 ('ImageSize', C.c_uint64), ('ImageRegionOffset', C.c_uint64),
                 ('ImageTimeDateStamp', C.c_uint32), ('ImageCheckSum', C.c_uint32),
                 ('ImageName', C.c_wchar * 260), ('ImagePath', C.c_wchar * 520)]


class BreakpointInfo(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ('ProcessId', 'ThreadId', 'Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7')]
    _fields_ += [('EnabledSlotMask', C.c_uint32), ('EnabledBreakpointCount', C.c_uint32)]


OP_GROUPS = {
    '프로세스': ['process', 'handles', 'token', 'threads', 'thread_info'],
    '메모리': ['read', 'write', 'alloc', 'free', 'protect', 'copy', 'fill', 'dump'],
    '검색': ['kernel_value', 'strings', 'pattern', 'pattern_regions', 'pointer_search'],
    '모듈': ['regions', 'modules', 'pe'],
    '스레드': ['context', 'set_context', 'suspend', 'resume', 'priority', 'affinity', 'hide', 'thread_batch'],
    '중단점': ['hwbp_set', 'hwbp_query', 'hwbp_remove', 'hwbp_list'],
    '분석': ['snapshot', 'snapshot_list', 'compare', 'restore', 'patch', 'patch_list', 'undo',
              'pointer_chain', 'structure', 'structure_write', 'disassemble'],
    '기타': ['dll', 'status', 'batch'],
}
OP_GROUPS['확장 분석'] = E.OPERATIONS
OP_GROUPS['DLL·이미지 함수'] = W.OPERATIONS
OP_GROUPS['디스어셈블리 편집'] = A.OPERATIONS
IOCTL_UI = {
    0x800:'process', 0x801:'alloc', 0x802:'free', 0x803:'copy', 0x804:'kernel_value',
    0x805:'read', 0x806:'strings', 0x807:'regions', 0x808:'검색/영역 결과 자동 해제',
    0x809:'문자열 결과 자동 해제', 0x80A:'hwbp_set', 0x80B:'hwbp_query', 0x80C:'hwbp_remove',
    0x80D:'중단점 결과 관리/자동 해제', 0x80E:'dll', 0x80F:'write', 0x810:'protect',
    0x811:'pattern', 0x812:'threads', 0x813:'suspend', 0x814:'resume', 0x815:'context',
    0x816:'set_context',
    0x819:'status', 0x81A:'process', 0x81B:'handles', 0x81C:'token', 0x81D:'thread_info',
    0x81E:'priority', 0x81F:'affinity', 0x821:'hide',
    0x822:'function_call',0x823:'function_call_query',0x824:'function_call_release',
}


class Studio:
    def __init__(self, driver):
        self.driver = driver
        self.lock = threading.RLock()
        self.log_lock = threading.Lock()
        self.event_lock = threading.Lock()
        self.logs = deque(maxlen=1000)
        self.events = deque(maxlen=2048)
        self.sequence = self.event_sequence = 0
        self.counts = {}
        self.snapshots = {}
        self.maps = {}
        self.patches = {}
        self.breakpoints = {}
        self.allocations = {}
        self.jobs = {}
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='studio-job')
        self.closing = False
        self.api = None
        original = driver.send_ioctl

        def traced(code, request):
            start = time.perf_counter()
            response = original(code, request)
            function = (code >> 2) & 0xfff
            with self.log_lock:
                self.sequence += 1
                self.counts[function] = self.counts.get(function, 0) + 1
                self.logs.append({'id': self.sequence, 'time': time.time(), 'ioctl': f'0x{function:03X}',
                     'operation': IOCTL_UI.get(function, '기존 클라이언트'), 'transport_ok': response[0],
                     'error_code': response[1], 'status': f'0x{getattr(request, "ResultStatus", 0) & 0xffffffff:08X}',
                     'milliseconds': round((time.perf_counter() - start) * 1000, 3)})
            return response
        driver.send_ioctl = traced
        self.workbench=W.Workbench(self)
        self.disassembly=A.Workspace(self)

    def prepare(self):
        if self.closing:
            self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='studio-job')
            self.closing = False
        if hasattr(self, 'dumps'):
            self.dumps.prepare()
        if hasattr(self, 'scans') and self.scans.closing:
            self.scans = S.Workspace(self)

    def local_read(self, pointer, size):
        if not pointer or not 0 < size <= MAX_BYTES:
            raise StudioError("드라이버 반환 버퍼 크기 오류")
        # Even pointer-based returned lists are copied via the existing read IOCTL.
        # No Win32 process handle or ReadProcessMemory is used here.
        return self.read_bytes(os.getpid(), pointer, size)

    def nodes(self, first):
        current, previous, seen = first, 0, set()
        while current:
            if current in seen or len(seen) >= 100000:
                raise StudioError("결과 연결 목록 순환 또는 크기 초과")
            seen.add(current)
            node = Node.from_buffer_copy(self.local_read(current, C.sizeof(Node)))
            if node.Signature != 0x4C4C535448454C50 or node.Previous != previous or not node.Data:
                raise StudioError("결과 연결 목록 형식 오류")
            yield node
            previous, current = current, node.Next

    def read_bytes(self, pid, start, size):
        start, size = address(start), bounded(size)
        if start + size > 0x800000000000:
            raise ValueError("주소 범위 초과")
        pieces = []
        for offset in range(0, size, 4096):
            count = min(4096, size - offset)
            response = self.driver.read_process_memory_snapshot(pid, start + offset, count)
            if not response['success']:
                raise StudioError(f"0x{start + offset:X} 읽기 실패 ({offset}바이트까지 완료)", response)
            piece = bytes.fromhex(response['data_hex'])
            if len(piece) != count:
                raise StudioError("읽기 크기 불일치", response)
            pieces.append(piece)
        return b''.join(pieces)

    def identity(self, pid):
        response = require(self.driver.query_process_info(pid))
        if response['exit_status'] != 259:
            raise StudioError("대상 프로세스가 종료되었습니다", response)
        return str(response['process_start_key'])

    def check_owner(self, record):
        if self.identity(record['pid']) != record['identity']:
            raise StudioError("프로세스가 교체되었습니다. 저장 당시의 대상과 다릅니다")

    def prune_allocations(self):
        """Discard bookkeeping only when the original owner has definitely gone."""
        removed = 0
        with self.lock, self.driver._lock:
            for key, record in list(self.allocations.items()):
                response = self.driver.query_process_info(record['pid'])
                if response.get('success'):
                    expired = (response.get('exit_status') != 259 or
                               str(response.get('process_start_key')) != record['identity'])
                else:
                    # QueryProcessInfo has only a PID input. A failed process lookup
                    # is ERROR_INVALID_PARAMETER on the existing device transport.
                    # Keep records on transport, permission, or resource errors.
                    expired = (response.get('result_status') in
                               ('0xC000000B', '0xC0000225', '0xC000010A') or
                               response.get('error_code') == 87)
                if expired:
                    del self.allocations[key]
                    removed += 1
        return removed

    def parsed_list(self, response, kind, limit=MAX_RESULTS):
        first = response.get('result_list_address_int', response.get('first_result_node_int', 0))
        results, total = [], 0
        free = {'strings': self.driver.free_string_list, 'breakpoints': self.driver.free_hardware_breakpoint_result}.get(kind, self.driver.free_linked_list)
        try:
            limit=bounded(limit,50000)
            require(response)
            for node in self.nodes(first):
                total += 1
                if len(results) >= limit:
                    continue
                if kind == 'values':
                    if node.DataSize != 8:
                        raise StudioError("값 검색 결과 형식 오류")
                    results.append({'address': f'0x{struct.unpack("<Q", self.local_read(node.Data, 8))[0]:X}'})
                elif kind == 'strings':
                    if node.DataSize != C.sizeof(StringInfo):
                        raise StudioError("문자열 결과 형식 오류")
                    item = StringInfo.from_buffer_copy(self.local_read(node.Data, node.DataSize))
                    raw = self.local_read(item.DumpedAddress, min(item.StringSize, 4096)) if item.StringSize else b''
                    results.append({'address': f'0x{item.StringAddress:X}', 'size': item.StringSize,
                        'encoding': 'UTF-16' if item.Encoding == 2 else 'ANSI',
                        'text': raw.decode('utf-16-le' if item.Encoding == 2 else 'mbcs', errors='replace'),
                        'preview_truncated': item.StringSize > len(raw)})
                elif kind == 'regions':
                    if node.DataSize != C.sizeof(RegionInfo):
                        raise StudioError(f"영역 구조 크기 불일치: {node.DataSize}/{C.sizeof(RegionInfo)}")
                    item = RegionInfo.from_buffer_copy(self.local_read(node.Data, node.DataSize))
                    results.append({'address': f'0x{item.BaseAddress:X}', 'allocation_base': f'0x{item.AllocationBase:X}',
                        'size': item.RegionSize, 'protect': f'0x{item.Protect:X}', 'state': f'0x{item.State:X}',
                        'type': f'0x{item.Type:X}', 'readable': bool(item.IsReadable), 'writable': bool(item.IsWritable),
                        'executable': bool(item.IsExecutable), 'guarded': bool(item.IsGuarded),
                        'image_base': f'0x{item.ImageBaseAddress:X}', 'image_size': item.ImageSize,
                        'image_name': item.ImageName, 'image_path': item.ImagePath, 'main_image': bool(item.IsMainImage),
                        'has_pe_header': bool(item.HasPeHeaderInformation), 'timestamp': item.ImageTimeDateStamp})
                else:
                    if node.DataSize != C.sizeof(BreakpointInfo):
                        raise StudioError("중단점 조회 결과 형식 오류")
                    item = BreakpointInfo.from_buffer_copy(self.local_read(node.Data, node.DataSize))
                    results.append({'thread_id': item.ThreadId, 'process_id': item.ProcessId,
                        **{name.lower(): f'0x{getattr(item, name):X}' for name in ('Dr0','Dr1','Dr2','Dr3','Dr6','Dr7')},
                        'enabled_mask': item.EnabledSlotMask, 'enabled_count': item.EnabledBreakpointCount})
            return {'success': True, 'results': results, 'total': total, 'truncated': total > len(results), 'buffers_released': True}
        finally:
            if first:
                require(free(first))

    def patch(self, pid, start, data, expected=None):
        start = address(start)
        before = self.read_bytes(pid, start, len(data))
        if expected is not None and before != bytes.fromhex(expected):
            raise StudioError("현재 바이트가 예상 값과 다릅니다. 쓰지 않았습니다")
        if len(self.patches) >= 64:
            raise ValueError("패치 이력은 최대 64개입니다")
        identity = self.identity(pid)
        record_id = uuid.uuid4().hex
        record = {'id': record_id, 'pid': pid, 'identity': identity, 'address': f'0x{start:X}',
                  'before': before.hex(), 'after': data.hex(), 'time': time.time(), 'undone': False}
        # Retain recovery bytes even when a write partially succeeds or verification fails.
        self.patches[record_id] = record
        response = self.driver.write_process_memory(pid, start, data)
        record['write_response'] = response
        require(response)
        if response['bytes_written'] != len(data):
            raise StudioError("부분 쓰기: 패치 이력에 복구 원본을 보관했습니다", response)
        if self.read_bytes(pid, start, len(data)) != data:
            raise StudioError("쓰기 검증 실패: 복구 원본을 보관했습니다", response)
        return {'success': True, 'patch_id': record_id, 'address': record['address'], 'bytes_written': len(data), 'verified': True}

    def operate(self, operation, args, cancelled=lambda: False):
        if operation not in {name for values in OP_GROUPS.values() for name in values}:
            raise ValueError("지원하지 않는 작업")
        if self.closing:
            raise StudioError("서버가 종료 중입니다")
        if operation in E.OPERATIONS:
            return E.operate(self, operation, args, cancelled)
        if operation in W.OPERATIONS:
            return self.workbench.operate(operation,args)
        if operation in A.OPERATIONS:
            return self.disassembly.operate(operation,args)
        pid = bounded(args.get('pid', 1), 0xffffffff)
        d = self.driver
        start = lambda: address(args.get('address', '0x0'))
        size = lambda: bounded(args.get('size', 64))
        tid = lambda: bounded(args.get('tid', 0), 0xffffffff)
        if operation == 'status':
            response = d.get_driver_status()
            return dict(response, connected=d.is_connected())
        if operation == 'process':
            return {'success': True, 'basic': require(d.query_process_info(pid)),
                    'extended': require(d.query_process_extended(pid)), 'token': require(d.query_process_token(pid))}
        if operation in ('handles','threads'):
            response = d.query_process_handles(pid,128) if operation == 'handles' else d.enumerate_threads(pid,64)
            if not response.get('success'): return response
            extended = require(d.query_process_extended(pid))
            returned = len(response['handles' if operation == 'handles' else 'threads'])
            total = extended['handle_count' if operation == 'handles' else 'thread_count']
            return dict(response, returned_count=returned, total=total, truncated=total>returned,
                        note='전체 개수는 별도 커널 조회 시점입니다. 목록 상한: 핸들 128개 / 스레드 64개.')
        if operation == 'token': return d.query_process_token(pid)
        if operation in ('thread_info','context','suspend','resume','priority','affinity','hide'):
            with d._lock:
                thread_id=tid()
                if 'pid' in args:
                    owner=require(d.query_thread_info(thread_id))
                    if owner.get('process_id')!=pid or owner.get('thread_id')!=thread_id:
                        raise StudioError('선택한 프로세스 소속의 스레드가 아닙니다')
                    if operation!='thread_info' and owner.get('exit_status')!=259:
                        raise StudioError('대상 스레드가 종료되었습니다')
                    if operation=='thread_info': return owner
                if operation=='thread_info': return d.query_thread_info(thread_id)
                if operation=='context': return d.get_thread_context(thread_id)
                if operation=='suspend': return d.suspend_thread(thread_id)
                if operation=='resume': return d.resume_thread(thread_id)
                if operation=='priority': return d.set_thread_priority(thread_id,bounded(args['priority'],31,0))
                if operation=='affinity': return d.set_thread_affinity(thread_id,bounded(args['mask'],0xffffffffffffffff))
                return d.set_thread_hide_from_debugger(thread_id)
        if operation == 'set_context':
            registers = args.get('registers', {})
            allowed = {name.lower() for name, _ in D.THREAD_REGISTERS_REQUEST._fields_ if name not in ('ThreadId','ResultStatus')}
            if not isinstance(registers, dict) or not registers or set(registers) - allowed:
                raise ValueError("레지스터 이름과 값을 확인하세요")
            requested = {name: bounded(value, 0xffffffff if name == 'eflags' else 0xffffffffffffffff, 0)
                         for name, value in registers.items()}
            thread_id = tid()
            with d._lock:
                process_identity = self.identity(pid)
                owner = require(d.query_thread_info(thread_id))
                if (owner.get('process_id') != pid or owner.get('thread_id') != thread_id
                        or owner.get('exit_status') != 259 or not owner.get('create_time')):
                    raise StudioError("선택한 프로세스의 살아 있는 스레드가 아닙니다")

                def check_owner():
                    if self.identity(pid) != process_identity:
                        raise StudioError("레지스터 편집 중 대상 프로세스가 교체되었습니다")
                    latest = require(d.query_thread_info(thread_id))
                    if (latest.get('process_id') != pid or latest.get('thread_id') != thread_id
                            or latest.get('exit_status') != 259
                            or str(latest.get('create_time')) != str(owner['create_time'])):
                        raise StudioError("레지스터 편집 중 스레드가 종료되거나 교체되었습니다")

                check_owner()
                require(d.suspend_thread(thread_id))
                try:
                    check_owner()
                    current = require(d.get_thread_context(thread_id))
                    merged = {name: int(current[name], 16) for name in allowed}
                    merged.update(requested)
                    check_owner()
                    response = require(d.set_thread_context(thread_id, merged))
                    check_owner()
                    observed = require(d.get_thread_context(thread_id))
                    differences = {name:{'expected':f'0x{value:X}','observed':observed[name]}
                                   for name,value in requested.items() if int(observed[name],16) != value}
                    other_changes = {name:{'captured':f'0x{value:X}','observed':observed[name]}
                                     for name,value in merged.items()
                                     if name not in requested and int(observed[name],16) != value}
                    if differences:
                        return dict(response,success=False,verified=False,registers=observed,
                                    differences=differences,error='쓰기 이후 레지스터가 요청값과 일치하지 않습니다')
                    return dict(response,verified=True,registers=observed,verified_fields=list(requested),
                                unrequested_changes=other_changes)
                finally:
                    # A recycled TID must not resume an unrelated new thread.
                    check_owner()
                    require(d.resume_thread(thread_id))
        if operation == 'thread_batch':
            tids = args.get('tids', [])
            action = args.get('action')
            if action not in ('suspend','resume','priority','affinity') or not isinstance(tids, list) or not 1 <= len(tids) <= 64:
                raise ValueError("1~64개 스레드와 작업을 선택하세요")
            results = []
            for thread_id in tids:
                item = self.operate(action, dict(args, tid=thread_id))
                results.append({'thread_id': thread_id, **item})
            return {'success': all(r['success'] for r in results), 'results': results}
        if operation in ('read', 'dump'):
            raw = self.read_bytes(pid, start(), size())
            return {'success': True, 'address': f'0x{start():X}', 'size': len(raw), 'data_hex': raw.hex(),
                    'data_ascii': ''.join(chr(x) if 32 <= x < 127 else '.' for x in raw),
                    'base64': base64.b64encode(raw).decode(), 'buffers_released': True}
        if operation == 'write':
            data = payload(args)
            response = require(d.write_process_memory(pid, start(), data))
            verified = self.read_bytes(pid, start(), len(data)) == data
            return dict(response, success=verified, verified=verified)
        if operation == 'alloc':
            with self.lock:
                self.prune_allocations()
                if len(self.allocations) >= 128: raise ValueError("할당 관리 목록이 가득 찼습니다")
                identity = self.identity(pid)
                response = require(d.alloc_virtual_memory(pid, size(), bounded(args.get('protect', 4), 0x7ff)))
                key = f'{pid}:{response["allocated_address"]}'
                self.allocations[key] = {'pid': pid, 'identity': identity, 'address': response['allocated_address'], 'size': size()}
                return response
        if operation == 'free':
            with self.lock, d._lock:
                key = f'{pid}:0x{start():X}'
                record = self.allocations.get(key)
                if record:
                    self.check_owner(record)
                response = require(d.free_virtual_memory(pid, start()))
                self.allocations.pop(key, None)
                return response
        if operation == 'protect': return d.protect_virtual_memory(pid, start(), size(), bounded(args.get('protect', 4), 0x7ff))
        if operation == 'copy':
            return d.copy_process_memory(pid, start(), bounded(args.get('dst_pid', pid), 0xffffffff), address(args['dst_address']), size())
        if operation == 'fill':
            pattern = bytes.fromhex(args.get('pattern', '00'))
            if not 1 <= len(pattern) <= 256: raise ValueError("채움 패턴은 1~256바이트입니다")
            data = (pattern * ((size() + len(pattern) - 1) // len(pattern)))[:size()]
            return self.patch(pid, start(), data)
        if operation in ('regions','modules'):
            limit=bounded(args.get('max_results',50000 if operation=='modules' else MAX_RESULTS),50000)
            result = self.parsed_list(d.read_process_information_vad(pid),'regions',
                                      limit=limit)
            if operation == 'regions': return result
            return self.workbench.images(pid,regions=result,cancelled=cancelled)
        if operation in ('kernel_value','pointer_search'):
            data = struct.pack('<Q', address(args['target'])) if operation == 'pointer_search' else payload(args)
            return self.parsed_list(d.scan_value_process(pid, data, bounded(args.get('protect', 4), 0x7ff)), 'values')
        if operation == 'strings':
            return self.parsed_list(d.read_string_process(pid, bounded(args.get('min_chars', 8), 4096, 2)), 'strings')
        if operation in ('pattern','pattern_regions'):
            tokens = str(args.get('pattern', '')).split()
            if not 1 <= len(tokens) <= 256: raise ValueError("패턴은 1~256바이트입니다")
            pattern = bytes(0 if x in ('?','??') else int(x, 16) for x in tokens)
            mask = ''.join('?' if x in ('?','??') else 'x' for x in tokens)
            if operation == 'pattern':
                return d.pattern_scan(pid, start(), bounded(args.get('size', 4096), 0x40000000), pattern, mask)
            mapped=self.operate('regions', {'pid':pid,'max_results':50000})
            if mapped['truncated']:raise ValueError('전체 메모리 맵 상한을 초과했습니다')
            regions=mapped['results']
            results, scanned = [], 0
            scope = args.get('scope', 'readable')
            for region in regions:
                if cancelled(): break
                if not region['readable'] or region['guarded'] or (scope in ('writable','executable') and not region[scope]): continue
                response = d.pattern_scan(pid, int(region['address'],16), region['size'], pattern, mask)
                scanned += 1
                if response['success'] and response['matches_count']:
                    results.append({'address':response['found_address'], 'matches':response['matches_count'], 'region':region['address']})
            return {'success': True, 'results': results, 'regions_scanned': scanned, 'cancelled': cancelled(),
                    'note': '일치 개수와 각 영역의 첫 주소를 반환합니다'}
        if operation in ('snapshot','patch','restore','undo','compare','snapshot_list','patch_list'):
            with self.lock, d._lock:
                if operation == 'snapshot_list':
                    removed = self.prune_allocations()
                    return {'success':True, 'results':[dict((k,v) for k,v in record.items() if k!='data') for record in self.snapshots.values()],
                            'allocations':list(self.allocations.values()), 'expired_allocations_removed':removed}
                if operation == 'patch_list': return {'success':True, 'results':list(self.patches.values())}
                if operation == 'snapshot':
                    if len(self.snapshots) >= 16: raise ValueError("스냅샷은 최대 16개입니다")
                    key = uuid.uuid4().hex
                    self.snapshots[key] = {'id':key, 'name':str(args.get('name','Snapshot'))[:100], 'pid':pid,
                        'identity':self.identity(pid), 'address':f'0x{start():X}', 'size':size(),
                        'data':self.read_bytes(pid,start(),size()), 'time':time.time()}
                    return {'success':True, 'snapshot_id':key, 'name':self.snapshots[key]['name'], 'size':size()}
                if operation == 'patch': return self.patch(pid, start(), payload(args), args.get('expected'))
                if operation == 'undo':
                    record = self.patches.get(args.get('id'))
                    if not record: raise ValueError("패치 이력을 찾을 수 없습니다")
                    self.check_owner(record)
                    if record['undone']: raise ValueError("이미 복구된 패치입니다")
                    current = self.read_bytes(record['pid'],record['address'],len(bytes.fromhex(record['after'])))
                    if current.hex() != record['after']: raise StudioError("패치 이후 다른 변경이 발생했습니다. 자동 복구하지 않았습니다")
                    require(d.write_process_memory(record['pid'],int(record['address'],16),bytes.fromhex(record['before'])))
                    if self.read_bytes(record['pid'],record['address'],len(bytes.fromhex(record['before']))).hex() != record['before']:
                        raise StudioError("복구 검증 실패")
                    record['undone']=True
                    return {'success':True, 'restored':True}
                record = self.snapshots.get(args.get('id'))
                if not record: raise ValueError("스냅샷을 찾을 수 없습니다")
                self.check_owner(record)
                if operation == 'restore': return self.patch(record['pid'],record['address'],record['data'])
                now = self.read_bytes(record['pid'],record['address'],record['size'])
                changes, count = [], 0
                for i, (a,b) in enumerate(zip(record['data'], now)):
                    if a == b: continue
                    count += 1
                    if len(changes) < MAX_RESULTS:
                        changes.append({'offset':f'0x{i:X}', 'address':f'0x{int(record["address"],16)+i:X}', 'before':f'{a:02X}', 'after':f'{b:02X}'})
                return {'success':True, 'changed_bytes':count, 'results':changes, 'truncated':count>MAX_RESULTS}
        if operation == 'pointer_chain':
            offsets = args.get('offsets', [])
            if not isinstance(offsets,list) or not 1 <= len(offsets) <= 32: raise ValueError("포인터 오프셋은 1~32개입니다")
            current, trace = start(), []
            width = 4 if args.get('bits',64)==32 else 8
            for offset in offsets:
                pointer = int.from_bytes(self.read_bytes(pid,current,width),'little')
                next_address = address(pointer + integer(offset))
                trace.append({'address':f'0x{current:X}', 'pointer':f'0x{pointer:X}', 'offset':str(offset), 'next':f'0x{next_address:X}'})
                current=next_address
            return {'success':True, 'address':f'0x{current:X}', 'results':trace}
        if operation in ('structure','structure_write'):
            fields=args.get('fields',[])
            if not isinstance(fields,list) or not 1<=len(fields)<=128: raise ValueError("필드는 1~128개입니다")
            results=[]
            for field in fields:
                offset=bounded(field.get('offset',0), MAX_BYTES, 0)
                field_address=address(start()+offset)
                kind=field.get('type','int32')
                if kind not in FORMATS and kind!='pointer': raise ValueError("필드 형식을 확인하세요")
                fmt,length=FORMATS.get(kind,('<Q',8))
                if operation=='structure_write':
                    if 'value' not in field: continue
                    results.append({'name':field.get('name',''), **self.patch(pid,field_address,payload({'data_type':'uint64' if kind=='pointer' else kind,'value':field['value']}))})
                else:
                    value=struct.unpack(fmt,self.read_bytes(pid,field_address,length))[0]
                    if isinstance(value,float) and not math.isfinite(value): value=str(value)
                    results.append({'name':field.get('name',''), 'offset':f'0x{offset:X}', 'address':f'0x{field_address:X}',
                                    'type':kind, 'value':f'0x{value:X}' if kind=='pointer' else str(value)})
            return {'success':True,'results':results}
        if operation=='disassemble':
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
            engine=Cs(CS_ARCH_X86,CS_MODE_32 if args.get('bits',64)==32 else CS_MODE_64)
            raw=self.read_bytes(pid,start(),bounded(args.get('size',64),65536))
            instructions=[{'address':f'0x{i.address:X}','bytes':i.bytes.hex(' ').upper(), 'size':i.size,
                           'instruction':i.mnemonic,'operands':i.op_str} for i in engine.disasm(raw,start())]
            return {'success':True,'results':instructions[:MAX_RESULTS], 'decoded_bytes':sum(i['size'] for i in instructions),
                    'requested_bytes':len(raw), 'truncated':len(instructions)>MAX_RESULTS}
        if operation=='pe': return self.pe(pid,start())
        if operation=='hwbp_query':
            response=d.query_hardware_breakpoint(pid)
            parsed=self.parsed_list(response,'breakpoints')
            return dict(parsed,breakpoint_count=response['breakpoint_count'],thread_count=response['thread_count'])
        if operation=='hwbp_list':
            with self.lock: return {'success':True,'results':[dict((k,v) for k,v in x.items() if k!='node') for x in self.breakpoints.values()]}
        if operation=='hwbp_set':
            with self.lock:
                if len(self.breakpoints)>=64: raise ValueError("중단점 관리 목록이 가득 찼습니다")
                identity=self.identity(pid)
                kind=bounded(args.get('type',0),3,0)
                length=bounded(args.get('length',1),8)
                if kind not in (0,1,3) or length not in (1,2,4,8): raise ValueError("중단점 유형/길이를 확인하세요")
                response=d.set_hardware_breakpoint(pid,start(),kind,{1:0,2:1,4:3,8:2}[length])
                key=uuid.uuid4().hex
                if response['first_result_node_int']:
                    self.breakpoints[key]={'id':key,'pid':pid,'identity':identity,'address':f'0x{start():X}',
                         'type':kind,'length':length,'node':response['first_result_node_int'],
                         'threads':response['applied_thread_count'],'recovery_required':not response['success']}
                    response=dict(response,breakpoint_id=key)
                return response
        if operation=='hwbp_remove':
            with self.lock:
                record=self.breakpoints.get(args.get('id'))
                if not record: raise ValueError("관리 중인 중단점 ID가 필요합니다")
                self.check_owner(record)
                response=d.remove_hardware_breakpoint(record['pid'],record['node'])
                if response['success']:
                    require(d.free_hardware_breakpoint_result(record['node']))
                    del self.breakpoints[record['id']]
                return dict(response,recovery_retained=not response['success'])
        if operation=='dll':
            path=str(args.get('path',''))
            if not path or len(path.encode('mbcs'))>518: raise ValueError("DLL 경로가 비어 있거나 너무 깁니다")
            return d.register_dll(pid,path)
        if operation=='batch':
            steps=args.get('steps',[])
            if not isinstance(steps,list) or not 1<=len(steps)<=32: raise ValueError("작업은 1~32개입니다")
            saved,results={},[]
            def resolve(value):
                if isinstance(value,str) and value.startswith('$'):
                    parts=value[1:].split('.')
                    result=saved[parts[0]]
                    for part in parts[1:]: result=result[part]
                    return result
                if isinstance(value,dict): return {k:resolve(v) for k,v in value.items()}
                if isinstance(value,list): return [resolve(v) for v in value]
                return value
            for index,step in enumerate(steps):
                if cancelled(): break
                if step.get('operation')=='batch': raise ValueError("중첩 일괄 작업은 지원하지 않습니다")
                try:
                    result=self.operate(step['operation'],resolve(dict(step.get('args',{}),pid=step.get('args',{}).get('pid',pid))),cancelled)
                except (ValueError,StudioError,KeyError,struct.error) as exc:
                    result={'success':False,'error':str(exc)}
                saved[step.get('id',str(index))]=result
                results.append({'step':step.get('id',str(index)),'operation':step['operation'],'response':result})
                if not result.get('success') and args.get('stop_on_error',True): break
            return {'success':not cancelled() and len(results)==len(steps) and all(x['response'].get('success') for x in results),
                    'results':results,'completed':len(results),'cancelled':cancelled()}

    def pe(self,pid,base):
        header=self.read_bytes(pid,base,4096)
        if header[:2]!=b'MZ': raise ValueError("MZ 헤더가 없습니다")
        offset=struct.unpack_from('<I',header,0x3c)[0]
        if not 0x40<=offset<=3500 or header[offset:offset+4]!=b'PE\0\0': raise ValueError("PE 헤더가 없습니다")
        machine,count,timestamp,_,_,optional_size,flags=struct.unpack_from('<HHIIIHH',header,offset+4)
        magic=struct.unpack_from('<H',header,offset+24)[0]
        if magic not in (0x10b,0x20b) or count>96: raise ValueError("지원하지 않는 PE 형식")
        entry,image_size=struct.unpack_from('<I',header,offset+40)[0],struct.unpack_from('<I',header,offset+80)[0]
        start=offset+24+optional_size
        table=self.read_bytes(pid,base+start,count*40) if count else b''
        rows=[]
        for i in range(count):
            part=table[i*40:(i+1)*40]
            name=part[:8].split(b'\0')[0].decode('ascii',errors='replace')
            virtual_size,rva,raw_size,raw_pointer=struct.unpack_from('<IIII',part,8)
            attributes=struct.unpack_from('<I',part,36)[0]
            rows.append({'name':name,'address':f'0x{base+rva:X}','rva':f'0x{rva:X}', 'size':virtual_size,
                         'raw_size':raw_size,'raw_file_offset':f'0x{raw_pointer:X}','flags':f'0x{attributes:X}'})
        return {'success':True,'machine':f'0x{machine:X}','bits':64 if magic==0x20b else 32,
                'entry_point':f'0x{base+entry:X}','image_size':image_size,'timestamp':timestamp,
                'characteristics':f'0x{flags:X}','results':rows}

    def run(self,operation,args,cancelled=lambda:False):
        try:
            if not isinstance(args, dict): raise ValueError("작업 인수는 객체여야 합니다")
            if operation in ('fill', 'structure_write'):
                with self.lock, self.driver._lock:
                    return self.operate(operation,args,cancelled)
            return self.operate(operation,args,cancelled)
        except StudioError as exc:
            return {'success':False,'error':str(exc),'driver_response':exc.response}
        except (ValueError,KeyError,TypeError,struct.error,OverflowError) as exc:
            result = {'success':False,'error':str(exc)}
            if getattr(exc, 'target_invalid', False): result['target_invalid'] = True
            return result

    def submit(self,operation,args):
        if operation not in ('kernel_value','strings','pattern_regions','pointer_search','regions','modules','batch'):
            raise ValueError("작업 큐가 지원하지 않는 작업입니다")
        with self.lock:
            if self.closing: raise ValueError("서버 종료 중")
            if sum(j['state'] in ('queued','running') for j in self.jobs.values())>=8: raise ValueError("작업 큐가 가득 찼습니다")
            if len(self.jobs)>=32:
                for key,job in list(self.jobs.items()):
                    if job['state'] not in ('queued','running'):
                        del self.jobs[key]
                        break
            key=uuid.uuid4().hex
            job={'id':key,'operation':operation,'state':'queued','created':time.time(),'cancel_requested':False}
            self.jobs[key]=job
        def work():
            with self.lock:
                if job['cancel_requested']:
                    job['state']='cancelled'; return
                job['state']='running'
            result=self.run(operation,args,lambda:job['cancel_requested'])
            with self.lock:
                job['result']=result
                job['state']='cancelled' if job['cancel_requested'] else ('completed' if result.get('success') else 'failed')
                job['finished']=time.time()
        self.executor.submit(work)
        return {'success':True,'job_id':key}

    def shutdown(self):
        self.closing=True
        if hasattr(self, 'scans'):
            self.scans.shutdown()
        self.workbench.shutdown()
        if hasattr(self, 'dumps'):
            self.dumps.shutdown()
        with self.lock:
            for job in self.jobs.values(): job['cancel_requested']=True
        self.executor.shutdown(wait=True,cancel_futures=True)
        with self.lock:
            for key,record in list(self.breakpoints.items()):
                response=self.driver.remove_hardware_breakpoint(record['pid'],record['node'])
                if response['success']:
                    self.driver.free_hardware_breakpoint_result(record['node'])
                    del self.breakpoints[key]


def install(app,driver):
    studio=Studio(driver)
    studio.dumps=DumpManager(studio)
    studio.scans=S.Workspace(studio)
    studio.editors=M.Workspace(studio)
    studio.wide_views=MV.Workspace(studio)
    studio.payload_allocations=MA.Workspace(studio)
    studio.suite=P.Suite(studio)
    router=APIRouter(prefix='/api/studio')

    @app.middleware('http')
    async def prioritize(request,call_next):
        value=2 if request.headers.get('x-kernel-priority')=='live' else 1
        with scope(value,request.url.path): return await call_next(request)

    @router.post('/suite/{action}')
    def suite_action(action:str,body:dict=Body(...)):
        try:return json_safe(studio.suite.dispatch(action,body))
        except (ValueError,StudioError,OSError,KeyError,TypeError,RuntimeError,struct.error,StopIteration,sqlite3.Error) as exc:raise HTTPException(400,str(exc))

    @router.get('/scheduler')
    def scheduler_stats():
        return {'success':True,**(driver.scheduler.stats() if hasattr(driver,'scheduler') else {'available':False})}

    @router.post('/editors')
    def create_editor(body:dict=Body(...)):
        try: return studio.editors.create(body)
        except (ValueError, StudioError, OSError, KeyError, TypeError, RuntimeError) as exc: raise HTTPException(400,str(exc))

    @router.post('/allocation-histories')
    def create_allocation_history(body:dict=Body(...)):
        try:return json_safe(studio.payload_allocations.create(body))
        except (ValueError,StudioError,OSError,KeyError,TypeError,RuntimeError) as exc:raise HTTPException(400,str(exc))

    @router.delete('/allocation-histories/{key}')
    def remove_allocation_history(key:str):return studio.payload_allocations.remove(key)

    @router.post('/allocation-histories/{key}/{action}')
    def allocation_history_action(key:str,action:str,body:dict=Body(...)):
        try:return json_safe(studio.payload_allocations.invoke(key,action,body))
        except (ValueError,StudioError,OSError,KeyError,TypeError,RuntimeError) as exc:raise HTTPException(400,str(exc))

    @router.post('/wide-views')
    def create_wide_view(body:dict=Body(...)):
        try:return json_safe(studio.wide_views.create(body))
        except (ValueError,StudioError,OSError,KeyError,TypeError,RuntimeError) as exc:raise HTTPException(400,str(exc))

    @router.delete('/wide-views/{key}')
    def remove_wide_view(key:str):return studio.wide_views.remove(key)

    @router.post('/wide-views/{key}/{action}')
    def wide_view_action(key:str,action:str,body:dict=Body(...)):
        try:return json_safe(studio.wide_views.invoke(key,action,body))
        except (ValueError,StudioError,OSError,KeyError,TypeError,RuntimeError) as exc:raise HTTPException(400,str(exc))

    @router.delete('/editors/{key}')
    def remove_editor(key:str): return studio.editors.remove(key)

    @router.post('/editors/{key}/{action}')
    def editor_action(key:str,action:str,body:dict=Body(...)):
        try: return studio.editors.invoke(key,action,body)
        except (ValueError, StudioError, OSError, KeyError, TypeError, RuntimeError, struct.error) as exc: raise HTTPException(400,str(exc))

    @router.post('/scans')
    def create_scan(body:dict=Body(...)):
        try: return json_safe(studio.scans.create(body.get('pid', 0)))
        except (ValueError, StudioError, OSError) as exc: raise HTTPException(400,str(exc))

    @router.delete('/scans/{key}')
    def remove_scan(key:str):
        return studio.scans.remove(key)

    @router.post('/scans/{key}/{action}')
    def scan_action(key:str,action:str,body:dict=Body(...)):
        try:
            result = studio.scans.submit(key,action,body) if action in ('new','next','rescan','view','export') else studio.scans.invoke(key,action,body)
            return json_safe(result)
        except (ValueError, StudioError, OSError, RuntimeError, struct.error) as exc: raise HTTPException(400,str(exc))

    @router.get('/scan-jobs/{key}')
    def scan_job(key:str):
        try: return json_safe(studio.scans.status(key))
        except ValueError as exc: raise HTTPException(404,str(exc))

    @router.get('/scans/{key}/exports/{export_id}')
    def download_scan_export(key:str,export_id:str):
        try:
            session = studio.scans.get(key)
            with session.lock:
                session.owner()
                path = session.exports.get(export_id)
                if path is None or not path.is_file(): raise ValueError('CSV 파일을 찾을 수 없습니다')
                return FileResponse(path,media_type='text/csv',filename=f'scan-{session.pid}-{export_id}.csv')
        except (ValueError, StudioError) as exc: raise HTTPException(404,str(exc))

    @router.post('/scan-jobs/{key}/cancel')
    def cancel_scan_job(key:str):
        try: return studio.scans.cancel(key)
        except ValueError as exc: raise HTTPException(404,str(exc))

    @router.get('/capabilities')
    def capabilities():
        return {'success':True,'groups':OP_GROUPS,'ioctls':[{'ioctl':f'0x{key:03X}','tool':value} for key,value in IOCTL_UI.items()],
                'excluded':['프로세스 생성/종료 이벤트','이미지 로드 이벤트','스레드 종료'], 'max_transfer_bytes':MAX_BYTES,
                'max_results':MAX_RESULTS,'handle_limit':128,'thread_limit':64,
                'dumps':{'max_total_bytes':MAX_DUMP_BYTES,'max_chunk_bytes':MAX_CHUNK_BYTES,
                         'kernel_read_bytes':4096,'modes':['range','image','images'],
                         'resume':True,'download_ranges':True}}

    @router.post('/execute')
    def execute(body:dict=Body(...)):
        return json_safe(studio.run(str(body.get('operation','')),body.get('args',{})))

    @router.get('/symbols')
    def list_symbols():return {'success':True,'results':studio.workbench.symbols.list()}

    @router.post('/symbols')
    def add_symbol_path(body:dict=Body(...)):
        try:return {'success':True,**studio.workbench.symbols.load(str(body.get('path','')))}
        except (ValueError,OSError,TimeoutError) as exc:raise HTTPException(400,str(exc))

    @router.delete('/symbols/{key}')
    def delete_symbols(key:str):return {'success':studio.workbench.symbols.remove(key)}

    @router.put('/assets/{kind}')
    async def upload_asset(kind:str,request:Request,filename:str=Query(default='')):
        if kind not in ('pdb','dll') or not filename.lower().endswith('.'+kind):raise HTTPException(400,'PDB 또는 DLL 파일을 선택하세요')
        limit=W.MAX_PDB_BYTES if kind=='pdb' else W.MAX_DLL_BYTES
        length=request.headers.get('content-length')
        if length and (not length.isdigit() or int(length)>limit):raise HTTPException(413,'파일 크기 상한을 초과했습니다')
        root=studio.workbench.symbols.root if kind=='pdb' else Path(__file__).parent/'assets'
        root.mkdir(parents=True,exist_ok=True)
        if kind=='dll' and len(list(root.glob('*.dll')))>=32:raise HTTPException(400,'추가한 DLL 파일 저장 상한 32개를 초과했습니다')
        path=root/(uuid.uuid4().hex+'.'+kind);count=0
        try:
            with path.open('xb') as output:
                async for piece in request.stream():
                    count+=len(piece)
                    if count>limit:raise HTTPException(413,'파일 크기 상한을 초과했습니다')
                    output.write(piece)
            if not count:raise HTTPException(400,'빈 파일입니다')
            if kind=='pdb':
                result=await asyncio.to_thread(studio.workbench.symbols.load,path,Path(filename.replace('\\','/')).name,True)
                if Path(studio.workbench.symbols.get(result['id'])['path'])!=path:path.unlink(missing_ok=True)
                return {'success':True,**result}
            return {'success':True,'path':str(path.resolve()),'size':count,'name':Path(filename.replace('\\','/')).name}
        except (ValueError,OSError) as exc:
            path.unlink(missing_ok=True)
            raise HTTPException(400,str(exc)) from exc
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    @router.get('/dump')
    def dump(pid:int,address:str,size:int=Query(default=4096,ge=1,le=MAX_BYTES)):
        try:
            data=studio.read_bytes(pid,address,size)
            return Response(data,media_type='application/octet-stream',headers={'Content-Disposition':f'attachment; filename="memory_{pid}_{integer(address):X}.bin"'})
        except (StudioError,ValueError) as exc:
            raise HTTPException(400,str(exc))

    def dump_error(exc):
        return HTTPException(404 if isinstance(exc, KeyError) else 400, str(exc))

    @router.post('/dumps')
    def start_dump(body:dict=Body(...)):
        try:
            return studio.dumps.start(body)
        except (StudioError, ValueError, KeyError, TypeError, OSError) as exc:
            raise HTTPException(400,str(exc))

    @router.get('/dumps')
    def list_dumps():
        return {'success':True,'jobs':studio.dumps.list()}

    @router.get('/dumps/{key}')
    def get_dump(key:str):
        try:
            return studio.dumps.get(key)
        except KeyError as exc:
            raise dump_error(exc)

    @router.post('/dumps/{key}/cancel')
    def cancel_dump(key:str):
        try:
            return studio.dumps.cancel(key)
        except KeyError as exc:
            raise dump_error(exc)

    @router.post('/dumps/{key}/resume')
    def resume_dump(key:str):
        try:
            return studio.dumps.resume(key)
        except (StudioError, ValueError, KeyError, OSError) as exc:
            raise dump_error(exc)

    @router.delete('/dumps/{key}')
    def delete_dump(key:str):
        try:
            return studio.dumps.remove(key)
        except (ValueError, KeyError, OSError) as exc:
            raise dump_error(exc)

    @router.get('/dumps/{key}/files/{name}')
    def download_dump(key:str,name:str):
        try:
            if name == 'manifest.json':
                # Return an in-memory metadata snapshot. Keeping the journal file
                # open during download can block its atomic replacement on Windows.
                document = studio.dumps.get(key)
                document['dump_format'] = 'kernel-memory-dump-v1'
                return Response(json.dumps(document,ensure_ascii=False,indent=2).encode('utf-8'),
                    media_type='application/json',headers={'Content-Disposition':'attachment; filename="manifest.json"',
                                                           'X-Content-Type-Options':'nosniff'})
            path, content_type, digest = studio.dumps.artifact(key,name,lease=True)
            headers = {'X-Content-Type-Options':'nosniff'}
            if digest:
                headers.update({'ETag':f'"{digest}"','X-Content-SHA256':digest})
            return DumpDownload(path,studio.dumps,key,media_type=content_type,filename=name,headers=headers)
        except (ValueError, KeyError) as exc:
            raise dump_error(exc)

    @router.post('/jobs')
    def submit(body:dict=Body(...)):
        try: return studio.submit(body.get('operation',''),body.get('args',{}))
        except ValueError as exc: raise HTTPException(400,str(exc))

    @router.get('/jobs')
    def jobs():
        with studio.lock: return {'success':True,'jobs':[dict((k,v) for k,v in job.items() if k!='result') for job in studio.jobs.values()]}

    @router.get('/jobs/{key}')
    def job(key:str):
        with studio.lock:
            if key not in studio.jobs: raise HTTPException(404,'작업을 찾을 수 없습니다')
            return json_safe(dict(studio.jobs[key]))

    @router.post('/jobs/{key}/cancel')
    def cancel(key:str):
        with studio.lock:
            if key not in studio.jobs: raise HTTPException(404,'작업을 찾을 수 없습니다')
            studio.jobs[key]['cancel_requested']=True
            return {'success':True,'note':'진행 중인 IOCTL은 완료를 기다리고 다음 단계부터 취소합니다'}

    @router.get('/events')
    def events(after:int=0,pid:int=0):
        with studio.event_lock:
            return json_safe({'success':True,'events':[x for x in studio.events if x['id']>after and (not pid or x['process_id']==pid)],'cursor':studio.event_sequence})

    @router.get('/history')
    def history(after:int=0):
        with studio.log_lock:
            return {'success':True,'results':[x for x in studio.logs if x['id']>after],
                    'counts':{f'0x{k:03X}':v for k,v in studio.counts.items()},'cursor':studio.sequence}

    app.include_router(router)
    return studio


def json_safe(value):
    """Preserve 64-bit identifiers/integers in browsers without rounding."""
    if isinstance(value, int) and not isinstance(value, bool) and abs(value)>9007199254740991:
        return str(value)
    if isinstance(value, list): return [json_safe(item) for item in value]
    if isinstance(value, dict): return {key:json_safe(item) for key,item in value.items()}
    return value
