"""Paged, transactional memory scans. All target I/O uses the existing kernel ABI.

Live display never changes the comparison baseline. Candidate masks and both
snapshots reside on disk, including Unknown scans larger than 50,000 hits.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import math
import shutil
import sqlite3
import struct
import tempfile
import threading
import time
import uuid
from functools import wraps
from collections import OrderedDict
import csv

import numpy as np
from memory_scanner import FORMATS

CHUNK = 65536
MAX_SCOPE = 4096 * 1048576
MAX_SAVED = 256
INPUT = {'exact', 'not_equal', 'greater', 'less', 'greater_equal', 'less_equal', 'between'}
RELATIVE = {'increased', 'decreased', 'changed', 'unchanged'}
DTYPES = {k: np.dtype(fmt) for k, (fmt, _) in FORMATS.items()}


def integer(value):
    if isinstance(value, bool):
        raise ValueError('정수를 입력하세요')
    s = str(value).strip()
    return int(s, 16 if s.lower().startswith(('0x', '-0x')) else 10)


def number(value, kind):
    try:
        n = float(value) if kind.startswith('float') else integer(value)
        if isinstance(n, float) and not math.isfinite(n):
            raise ValueError('비교값·편집값은 유한한 수여야 합니다')
        return struct.unpack(FORMATS[kind][0], struct.pack(FORMATS[kind][0], n))[0]
    except (ValueError, TypeError, OverflowError, struct.error) as exc:
        raise ValueError(f'{kind} 값의 형식·저장 범위를 확인하세요: {exc}') from exc


def aob(value):
    tokens = str(value).strip().split()
    if not 1 <= len(tokens) <= 256:
        raise ValueError('AOB는 공백으로 구분한 1~256개 바이트입니다')
    pattern, mask = bytearray(), bytearray()
    for token in tokens:
        if token == '?': token = '??'
        if len(token) != 2 or any(c not in '0123456789abcdefABCDEF?' for c in token):
            raise ValueError(f'AOB 바이트 오류: {token} (예: DE AD ?? A?)')
        pattern.append(int(token.replace('?', '0'), 16))
        mask.append(int(''.join('0' if c == '?' else 'F' for c in token), 16))
    if not any(mask):
        raise ValueError('AOB에는 고정된 비트가 하나 이상 필요합니다')
    return bytes(pattern), bytes(mask)


def encode(kind, value, width=None):
    if kind in FORMATS:
        return struct.pack(FORMATS[kind][0], number(value, kind))
    if kind in ('utf8', 'utf16'):
        raw = str(value).encode('utf-8' if kind == 'utf8' else 'utf-16-le')
    else:
        raw = bytes.fromhex(str(value))
    if not raw or len(raw) > 1024 or width is not None and len(raw) != width:
        raise ValueError(f'값은 기존 길이 {width}바이트와 같아야 합니다' if width else '값 길이는 1~1024바이트입니다')
    return raw


def display(raw, kind, fields=None):
    if kind in FORMATS:
        n = struct.unpack(FORMATS[kind][0], raw)[0]
        return str(n)  # Never round a uint64 in the browser or serialize NaN.
    if kind in ('utf8', 'utf16'):
        return raw.decode('utf-8' if kind == 'utf8' else 'utf-16-le', errors='replace')
    if kind == 'structure':
        return ' · '.join(f'{f["name"]}={display(raw[f["offset"]:f["offset"]+f["width"]], f["type"])}' for f in fields)
    return raw.hex(' ').upper()


def validate(args, previous=None):
    kind = str(args.get('data_type', 'int32'))
    condition = str(args.get('condition', 'exact'))
    if condition not in INPUT | RELATIVE | {'unknown', 'rescan'}:
        raise ValueError('지원하지 않는 스캔 조건')
    if previous is None and condition in RELATIVE | {'rescan'}:
        raise ValueError('이 조건은 Next 또는 Rescan에서 사용하세요')
    if previous and kind != previous['data_type']:
        raise ValueError('Next는 최초 검색과 동일한 형식을 사용해야 합니다')
    fields = []
    first = second = pattern = mask = None
    if kind in FORMATS:
        width = FORMATS[kind][1]
        if condition in INPUT:
            first = number(args.get('value', ''), kind)
            if condition == 'between':
                second = number(args.get('value2', ''), kind)
                if first > second: raise ValueError('범위의 시작값은 끝값 이하이어야 합니다')
    elif kind in ('aob', 'utf8', 'utf16'):
        if condition not in {'exact', 'not_equal', 'changed', 'unchanged', 'rescan'}:
            raise ValueError('문자열·AOB는 Exact / 불일치 / 변경 / 유지 / Rescan을 사용하세요')
        if previous and condition not in INPUT:
            width = previous['width']; pattern = previous['pattern']; mask = previous['mask']
        else:
            if kind == 'aob': pattern, mask = aob(args.get('value', ''))
            else:
                pattern = encode(kind, args.get('value', '')); mask = bytes([255])*len(pattern)
                if len(pattern) > 256: raise ValueError('문자열 검색은 최대 256바이트입니다')
            width = len(pattern)
    elif kind == 'structure':
        source = args.get('fields', previous['fields'] if previous else [])
        if not isinstance(source, list) or not 1 <= len(source) <= 32:
            raise ValueError('구조체 필드는 1~32개입니다')
        for index, item in enumerate(source):
            if not isinstance(item, dict) or item.get('type') not in FORMATS:
                raise ValueError('구조체 필드에는 숫자 형식이 필요합니다')
            t = item['type']; off = integer(item.get('offset', 0)); w = FORMATS[t][1]
            c = item.get('condition', 'exact')
            if not 0 <= off <= 1024-w or c not in INPUT | {'ignore'}:
                raise ValueError('구조체 offset / 조건 오류 (최대 크기 1024)')
            v = number(item.get('value', ''), t) if condition == 'exact' and c != 'ignore' else None
            v2 = number(item.get('value2', ''), t) if condition == 'exact' and c == 'between' else None
            if condition == 'exact' and c == 'between' and v > v2: raise ValueError('구조체 범위 값 오류')
            fields.append(dict(name=str(item.get('name', f'v{index+1}'))[:40], offset=off, type=t, width=w, condition=c, value=v, value2=v2))
        width = max(f['offset']+f['width'] for f in fields)
        if condition in INPUT and condition != 'exact':
            raise ValueError('구조체 조건은 Exact (각 필드 조건) 또는 상대 비교를 사용하세요')
        if condition in ('exact','increased','decreased') and all(f['condition'] == 'ignore' for f in fields):
            raise ValueError('구조체에는 비교하는 필드가 하나 이상 필요합니다')
    else:
        raise ValueError('지원하지 않는 데이터 형식')
    if previous and (width != previous['width'] or kind == 'structure' and
                     [(f['offset'], f['type']) for f in fields] != [(f['offset'], f['type']) for f in previous['fields']]):
        raise ValueError('Next에서는 길이·구조체 배치를 변경할 수 없습니다. New로 시작하세요')
    stride = integer(args.get('alignment', 0))
    if stride not in (0, 1, 2, 4, 8, 16): raise ValueError('정렬은 0 / 1 / 2 / 4 / 8 / 16입니다')
    stride = stride or (width if kind in FORMATS else 2 if kind == 'utf16' else 1)
    lower = integer(args.get('start_address') or 0)
    upper = integer(args.get('end_address') or '0x800000000000')
    budget = integer(args.get('max_bytes', 256*1048576))
    if not 0 <= lower < upper <= 0x800000000000: raise ValueError('주소 범위를 확인하세요 (끝 주소 제외)')
    if not 4096 <= budget <= MAX_SCOPE: raise ValueError('검색 예산은 4KB~4GiB입니다')
    scope = args.get('scope', 'writable')
    if scope not in ('readable', 'writable', 'executable'): raise ValueError('메모리 속성 필터 오류')
    return dict(data_type=kind, condition=condition, width=width, stride=stride, first=first, second=second,
                pattern=pattern, mask=mask, fields=fields, lower=lower, upper=upper, max_bytes=budget, scope=scope)


def compare(now, before, condition, a=None, b=None):
    if condition in ('unknown', 'rescan'): return np.ones(len(now), dtype=np.bool_)
    if condition == 'exact': return now == a
    if condition == 'not_equal': return now != a
    if condition == 'greater': return now > a
    if condition == 'less': return now < a
    if condition == 'greater_equal': return now >= a
    if condition == 'less_equal': return now <= a
    if condition == 'between': return (now >= a) & (now <= b)
    if condition == 'increased': return now > before
    if condition == 'decreased': return now < before
    raise ValueError('스캔 비교 조건 오류')


def matches(raw, old, n, cfg):
    width, stride, kind, cond = (cfg[k] for k in ('width', 'stride', 'data_type', 'condition'))
    if cond in ('changed', 'unchanged'):
        keep = np.ones(n, dtype=np.bool_)
        for i in range(width):
            keep &= np.ndarray((n,), 'u1', raw, i, (stride,)) == np.ndarray((n,), 'u1', old, i, (stride,))
        return ~keep if cond == 'changed' else keep
    if kind in FORMATS:
        now = np.ndarray((n,), DTYPES[kind], raw, 0, (stride,))
        before = np.ndarray((n,), DTYPES[kind], old, 0, (stride,))
        return compare(now, before, cond, cfg['first'], cfg['second'])
    keep = np.ones(n, dtype=np.bool_)
    if cond in ('unknown', 'rescan'): return keep
    if kind == 'structure':
        for f in cfg['fields']:
            if f['condition'] == 'ignore': continue
            now = np.ndarray((n,), DTYPES[f['type']], raw, f['offset'], (stride,))
            before = np.ndarray((n,), DTYPES[f['type']], old, f['offset'], (stride,))
            keep &= compare(now, before, f['condition'] if cond == 'exact' else cond, f['value'], f['value2'])
    else:
        for i, mask in enumerate(cfg['mask']):
            if mask: keep &= (np.ndarray((n,), 'u1', raw, i, (stride,)) & mask) == (cfg['pattern'][i] & mask)
        if cond == 'not_equal': keep = ~keep
    return keep


def write_guard(method):
    @wraps(method)
    def invoke(self, *args, **kwargs):
        with self.write_lock:
            if self.closed: raise ValueError('스캔 세션이 닫혔습니다')
            return method(self, *args, **kwargs)
    return invoke


class Session:
    def __init__(self, studio, pid, root):
        if not 0 < pid <= 0xffffffff: raise ValueError('PID 범위 오류')
        self.studio, self.pid = studio, pid
        self.identity = studio.identity(pid)
        self.id = uuid.uuid4().hex
        self.path = root / (self.id+'.sqlite')
        self.lock = threading.RLock()
        self.write_lock = threading.RLock()
        self.cfg = None
        self.count = self.round = 0
        self.stats = {}
        self.saved = {}
        self.job = None
        self.view = None
        self.exports = {}
        self.touched = time.monotonic()
        self.closed = self.invalid = False
        with self.db() as db:
            db.execute('CREATE TABLE chunks (base INTEGER PRIMARY KEY,raw BLOB,previous BLOB,mask BLOB,n INTEGER,count INTEGER)')
            db.execute('CREATE TABLE browse (address INTEGER PRIMARY KEY,base INTEGER,slot INTEGER,sort_key BLOB)')
            db.execute('CREATE INDEX browse_order ON browse(sort_key,address)')

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute('PRAGMA cache_size=-8192')
        try:
            with db: yield db
        finally: db.close()

    def owner(self):
        if self.closed: raise ValueError('스캔 세션이 닫혔습니다')
        if self.invalid: raise ValueError('대상이 종료·교체되었습니다. 다시 선택하세요')
        try:
            if self.studio.identity(self.pid) != self.identity:
                raise ValueError('대상 PID가 다른 프로세스로 교체되었습니다')
        except Exception as exc:
            self.invalid = True
            for row in self.saved.values(): row['frozen'] = False
            raise ValueError(f'대상 프로세스가 종료·교체되었거나 신원을 확인할 수 없습니다. 다시 선택하세요. {exc}') from exc

    def check(self, event):
        if event.is_set() or self.closed: raise InterruptedError('취소되었습니다. 이전 검색은 유지됩니다')

    def read(self, addr, size, cache=None):
        """Read exact spans, sharing 4KB pages. Failed page reads retry the exact span."""
        def exact(start, count):
            try: return self.studio.read_bytes(self.pid, start, count)
            except Exception as exc:
                # Buffer-release/protocol failures are fatal, not unreadable memory.
                # Do not retry allocations when their IOCTL release has failed.
                if hasattr(exc, 'response') and '읽기 실패' in str(exc):
                    raise OSError(str(exc)) from exc
                if isinstance(exc, RuntimeError) or '읽기 크기 불일치' in str(exc):
                    self.invalid = True
                    for row in self.saved.values(): row['frozen'] = False
                    raise RuntimeError(f'커널 복사 버퍼 처리 실패로 검색을 중단했습니다. 다시 선택하세요. {exc}') from exc
                raise
        if cache is None: return exact(addr, size)
        page = addr & ~4095
        if addr+size <= page+4096:
            if page not in cache:
                try: cache[page] = exact(page, 4096)
                except OSError: cache[page] = None
            if cache[page] is not None: return cache[page][addr-page:addr-page+size]
        return exact(addr, size)

    def areas(self, cfg):
        result = self.studio.operate('regions', {'pid': self.pid, 'max_results': 50000})
        if not result.get('success') or result.get('truncated'):
            raise ValueError('전체 커널 메모리 맵을 얻지 못했습니다')
        areas = []
        for r in sorted(result['results'], key=lambda r: integer(r['address'])):
            if not r['readable'] or r['guarded'] or integer(r['state']) != 0x1000: continue
            if cfg['scope'] != 'readable' and not r[cfg['scope']]: continue
            base = max(integer(r['address']), cfg['lower']); end = min(integer(r['address'])+r['size'], cfg['upper'])
            if base >= end: continue
            if areas and areas[-1][1] == base: areas[-1][1] = end
            else: areas.append([base, end])
        return areas

    def new(self, args, event, progress):
        cfg = validate(args)
        self.owner(); self.check(event)
        areas = self.areas(cfg); total = sum(end-base for base, end in areas)
        budget = min(total, cfg['max_bytes'])
        # A transaction keeps the previous search intact on cancellation / disk-full.
        if shutil.disk_usage(self.path.parent).free < budget*3 + self.path.stat().st_size + 64*1048576:
            raise ValueError('스냅샷 저장 공간이 부족합니다. 검색 범위·예산을 줄이세요')
        scanned = failed = count = processed = 0
        width, stride = cfg['width'], cfg['stride']
        started = time.perf_counter()
        with self.db() as db:
            db.execute('DELETE FROM chunks')
            db.execute('DELETE FROM browse')
            for begin, end in areas:
                end = min(end, begin + max(0, budget-processed))
                pos = begin; tail = b''
                while pos < end:
                    self.check(event)
                    length = min(CHUNK, end-pos)
                    # Isolate inaccessible pages; never fill a hole with artificial zeros.
                    segments = []
                    try: segments = [(pos, self.read(pos, length))]
                    except OSError:
                        at = pos
                        while at < pos+length:
                            self.check(event)
                            nbytes = min(4096-at%4096, pos+length-at)
                            try: segments.append((at, self.read(at, nbytes)))
                            except OSError: segments.append((at, None)); failed += nbytes
                            at += nbytes
                    for at, raw in segments:
                        if raw is None: tail = b''; continue
                        scanned += len(raw)
                        combined = tail+raw; origin = at-len(tail)
                        offset = (-origin) % stride
                        n = max(0, (len(combined)-offset-width)//stride+1)
                        if n:
                            data = combined[offset:offset+(n-1)*stride+width]
                            keep = matches(data, data, n, cfg)
                            hits = int(np.count_nonzero(keep)); count += hits
                            if hits:
                                db.execute('INSERT INTO chunks VALUES (?,?,?,?,?,?)', (origin+offset, data, data, np.packbits(keep).tobytes(), n, hits))
                        tail = combined[-(width-1):] if width > 1 else b''
                    pos += length; processed += length
                    progress.update(bytes_scanned=scanned, failed_bytes=failed, count=count, scope_bytes=total,
                                    progress_percent=round(100*processed/max(1,budget), 1))
                    if processed % 1048576 < CHUNK: self.owner()
                if processed >= budget: break
            self.check(event); self.owner()
        self.cfg = cfg; self.count = count; self.round = 1
        self.view = None
        self.stats = dict(bytes_scanned=scanned, failed_bytes=failed, scope_bytes=total, budget_bytes=cfg['max_bytes'],
                          partial=failed > 0 or processed < total, budget_exhausted=processed < total,
                          elapsed_ms=round((time.perf_counter()-started)*1000, 1), condition=cfg['condition'])
        return self.summary()

    def next(self, args, event, progress):
        if not self.cfg: raise ValueError('먼저 New 검색을 실행하세요')
        cfg = validate(dict(args, data_type=self.cfg['data_type']), self.cfg)
        cfg['stride'] = self.cfg['stride']
        self.owner(); self.check(event)
        count = failed = read_bytes = done = 0
        started = time.perf_counter()
        with self.db() as db:
            db.execute('DELETE FROM browse')
            last = -1
            # Chunk batches stay bounded even for millions of candidates.
            while True:
                rows = db.execute('SELECT base,raw,mask,n,count FROM chunks WHERE base>? ORDER BY base LIMIT 32', (last,)).fetchall()
                if not rows: break
                for base, raw, packed, n, oldcount in rows:
                    self.check(event); last = base
                    keep = np.unpackbits(np.frombuffer(packed, 'u1'), count=n).astype(np.bool_)
                    indices = np.flatnonzero(keep)
                    if oldcount > 128:
                        try:
                            current = self.read(base, len(raw)); read_bytes += len(raw)
                            keep &= matches(current, raw, n, cfg)
                        except OSError:
                            # Per-candidate fallback means one inaccessible page does not discard its neighbors.
                            current, keep, lost, used = self.sparse(raw, indices, base, cfg, event)
                            failed += lost; read_bytes += used
                    else:
                        current, keep, lost, used = self.sparse(raw, indices, base, cfg, event)
                        failed += lost; read_bytes += used
                    hits = int(np.count_nonzero(keep)); count += hits; done += oldcount
                    if hits:
                        db.execute('UPDATE chunks SET raw=?,previous=?,mask=?,count=? WHERE base=?',
                                   (current, raw, np.packbits(keep).tobytes(), hits, base))
                    else: db.execute('DELETE FROM chunks WHERE base=?', (base,))
                    progress.update(count=count, candidates_compared=done, failed_candidates=failed,
                                    progress_percent=round(100*done/max(1,self.count), 1))
                self.owner()
            self.check(event); self.owner()
        self.cfg = dict(self.cfg, condition=cfg['condition'], first=cfg['first'], second=cfg['second'],
                        pattern=cfg['pattern'], mask=cfg['mask'], fields=cfg['fields'])
        self.count = count; self.round += 1
        self.view = None
        self.stats = dict(self.stats, partial=self.stats['partial'] or failed > 0, failed_candidates=failed,
                          bytes_read=read_bytes, elapsed_ms=round((time.perf_counter()-started)*1000, 1), condition=cfg['condition'])
        return self.summary()

    def sparse(self, raw, indices, base, cfg, event):
        current = bytearray(raw); keep = np.zeros((len(raw)-cfg['width'])//cfg['stride']+1, dtype=np.bool_)
        cache = {}; lost = used = 0
        # Compare each exact candidate before merging overlapping updated bytes.
        for index in indices:
            self.check(event)
            off = int(index)*cfg['stride']; width = cfg['width']
            try: now = self.read(base+off, width, cache); used += width
            except OSError: lost += 1; continue
            if matches(now, raw[off:off+width], 1, cfg)[0]: keep[index] = True
            current[off:off+width] = now
        return bytes(current), keep, lost, used

    def summary(self):
        return dict(success=True, session_id=self.id, pid=self.pid, identity=self.identity, count=self.count,
                    scan_count=self.round, data_type=self.cfg['data_type'] if self.cfg else None,
                    transport='kernel_ioctl', storage='disk_snapshot', target_invalid=self.invalid,
                    saved_limit=MAX_SAVED, saved_count=len(self.saved), saved_remaining=MAX_SAVED-len(self.saved), **self.stats)

    @staticmethod
    def sort_key(raw, kind):
        """Byte keys preserve uint64/int64 precision and numeric floating-point order."""
        if kind in FORMATS:
            value = struct.unpack(FORMATS[kind][0], raw)[0]
            if kind.startswith('float'):
                if math.isnan(value): return b'\xff'*9
                if value == 0: value = 0.0  # Sort both signs of zero identically.
                bits = int.from_bytes(struct.pack('>d', value), 'big')
                ordered = ~bits & ((1 << 64)-1) if bits >> 63 else bits ^ (1 << 63)
                return b'\x00'+ordered.to_bytes(8, 'big')
            if kind.startswith('int'): value += 1 << 63
            return value.to_bytes(8, 'big')
        if kind in ('utf8', 'utf16'):
            return display(raw, kind).casefold().encode('utf-8')
        return raw

    def build_view(self, args, event, progress):
        """Filter/order ALL disk candidates without changing the scan baseline or target."""
        if not self.cfg: raise ValueError('먼저 New 검색을 실행하세요')
        query = str(args.get('filter', '')).strip().casefold()
        column = str(args.get('sort', 'address'))
        if len(query) > 256 or column not in {'address','current_value','scanned_value','previous_value','data_type','data_hex'}:
            raise ValueError('전체 후보 필터·정렬 입력을 확인하세요')
        descending = args.get('descending', False)
        if not isinstance(descending, bool): raise ValueError('정렬 방향은 참/거짓입니다')
        self.owner(); self.check(event)
        started = time.perf_counter(); count = done = 0
        indexed = bool(query) or column not in ('address', 'data_type')
        cfg = self.cfg
        with self.db() as db:
            db.execute('DELETE FROM browse')
            if indexed:
                if shutil.disk_usage(self.path.parent).free < self.count*160 + 64*1048576:
                    raise ValueError('전체 후보 탐색 인덱스의 저장 공간이 부족합니다')
                cursor = db.execute('SELECT base,raw,previous,mask,n,count FROM chunks ORDER BY base')
                for base, raw, previous, packed, n, oldcount in cursor:
                    indices = np.flatnonzero(np.unpackbits(np.frombuffer(packed, 'u1'), count=n))
                    batch = []
                    for pos, index in enumerate(indices):
                        if pos % 256 == 0: self.check(event)
                        off = int(index)*cfg['stride']; width = cfg['width']; address = base+off
                        data, before = raw[off:off+width], previous[off:off+width]
                        if query:
                            text = ' '.join((f'0x{address:016X}', hex(address), cfg['data_type'],
                                display(data, cfg['data_type'], cfg['fields']),
                                display(before, cfg['data_type'], cfg['fields']), data.hex(' '))).casefold()
                            if query not in text: continue
                        if column in ('address','data_type'): key = address.to_bytes(8, 'big')
                        elif column == 'data_hex': key = data
                        else: key = self.sort_key(before if column == 'previous_value' else data, cfg['data_type'])
                        batch.append((address, base, int(index), key))
                        if len(batch) == 1024:
                            db.executemany('INSERT INTO browse VALUES (?,?,?,?)', batch); count += len(batch); batch.clear()
                    if batch: db.executemany('INSERT INTO browse VALUES (?,?,?,?)', batch); count += len(batch)
                    done += oldcount
                    progress.update(count=count, candidates_compared=done, progress_percent=round(100*done/max(1,self.count),1))
                    self.owner()
            else: count = self.count
            self.check(event); self.owner()
        self.view = dict(id=uuid.uuid4().hex, filter=query, sort=column, descending=descending,
                         count=count, indexed=indexed, scan_count=self.round, basis='scan_snapshot', sampled_at=time.time())
        return dict(self.summary(), view_id=self.view['id'], filtered_count=count,
                    view=self.view, elapsed_ms=round((time.perf_counter()-started)*1000,1))

    def results(self, page=1, size=100, live=True, view_id=None):
        if not 1 <= page or not 1 <= size <= 500: raise ValueError('페이지 ≥ 1, 표시 개수 1~500입니다')
        self.owner(); results = []; cfg = self.cfg
        view = self.view if view_id else None
        if view_id and (not view or view['id'] != view_id): raise ValueError('전체 후보 탐색이 갱신되었습니다. 필터·정렬을 다시 적용하세요')
        total = view['count'] if view else self.count
        pages = max(1, math.ceil(total/size)); page = min(page, pages); offset = (page-1)*size
        descending = bool(view and view['descending'])
        order = 'DESC' if descending else 'ASC'
        if cfg:
            with self.db() as db:
                if view and view['indexed']:
                    cache = {}
                    for address, base, index in db.execute(f'SELECT address,base,slot FROM browse ORDER BY sort_key {order},address {order} LIMIT ? OFFSET ?', (size, offset)):
                        if base not in cache:
                            cache[base] = db.execute('SELECT raw,previous FROM chunks WHERE base=?', (base,)).fetchone()
                        raw, previous = cache[base]; off = index*cfg['stride']; width = cfg['width']
                        results.append(self.row(address,cfg['data_type'],raw[off:off+width],previous[off:off+width],cfg['fields']))
                # Skip pages using only the small count index, not their snapshot BLOBs.
                for base, count in ([] if view and view['indexed'] else db.execute(f'SELECT base,count FROM chunks ORDER BY base {order}')):
                    if offset >= count: offset -= count; continue
                    raw, previous, packed, n = db.execute('SELECT raw,previous,mask,n FROM chunks WHERE base=?', (base,)).fetchone()
                    indices = np.flatnonzero(np.unpackbits(np.frombuffer(packed, 'u1'), count=n))
                    if descending: indices = indices[::-1]
                    for index in indices[offset:offset+size-len(results)]:
                        off = int(index)*cfg['stride']; width = cfg['width']
                        before, scanned = previous[off:off+width], raw[off:off+width]
                        results.append(self.row(base+off, cfg['data_type'], scanned, before, cfg['fields']))
                    offset = 0
                    if len(results) == size: break
        cache = {}
        if live:
            for row in results: self.update_live(row, cache)
        saved = []
        for item in self.saved.values():
            row = dict(item)
            if live: self.update_live(row, cache)
            saved.append(row)
        self.owner()
        return dict(self.summary(), results=results, saved=saved, page=page, page_size=size,
                    pages=pages, filtered_count=total, view=view, sampled_at=time.time(), live=live)

    def read_saved(self, key):
        self.owner()
        row = self.saved.get(key)
        if not row: raise ValueError('보관 주소를 찾을 수 없습니다')
        result = dict(row); self.update_live(result, {}); self.owner()
        return dict(success=True, row=result, sampled_at=time.time())

    def export_csv(self, args, event, progress):
        if not self.cfg: raise ValueError('먼저 New 검색을 실행하세요')
        self.owner(); self.check(event)
        view_id = args.get('view_id')
        view = self.view if view_id else None
        if view_id and (not view or view['id'] != view_id): raise ValueError('전체 후보 탐색을 다시 적용하세요')
        if len(self.exports) >= 4: raise ValueError('세션당 전체 CSV 상한은 4개입니다. 새 대상을 선택하면 정리됩니다')
        total = view['count'] if view else self.count; cfg = self.cfg
        if shutil.disk_usage(self.path.parent).free < total*(600+cfg['width']*8)+64*1048576:
            raise ValueError('전체 CSV를 저장할 공간이 부족합니다')
        key = uuid.uuid4().hex; path = self.path.with_name(self.id+'-'+key+'.csv')
        order = 'DESC' if view and view['descending'] else 'ASC'
        columns = ['address','current_value','scanned_value','previous_value','data_type','data_hex','error','value_basis','scan_count']
        done = 0
        def rows(db):
            if view and view['indexed']:
                cache = OrderedDict()
                for address, base, index in db.execute(f'SELECT address,base,slot FROM browse ORDER BY sort_key {order},address {order}'):
                    if base not in cache:
                        cache[base] = db.execute('SELECT raw,previous FROM chunks WHERE base=?',(base,)).fetchone()
                        if len(cache) > 32: cache.popitem(last=False)
                    cache.move_to_end(base)
                    raw, previous = cache[base]; off = index*cfg['stride']; width = cfg['width']
                    yield self.row(address,cfg['data_type'],raw[off:off+width],previous[off:off+width],cfg['fields'])
            else:
                for base, raw, previous, packed, n in db.execute(f'SELECT base,raw,previous,mask,n FROM chunks ORDER BY base {order}'):
                    indices = np.flatnonzero(np.unpackbits(np.frombuffer(packed,'u1'),count=n))
                    if order == 'DESC': indices = indices[::-1]
                    for index in indices:
                        off = int(index)*cfg['stride']; width = cfg['width']
                        yield self.row(base+off,cfg['data_type'],raw[off:off+width],previous[off:off+width],cfg['fields'])
        try:
            with self.db() as db, path.open('w',encoding='utf-8-sig',newline='') as output:
                writer = csv.DictWriter(output,fieldnames=columns,extrasaction='ignore'); writer.writeheader()
                for row in rows(db):
                    if done % 256 == 0: self.check(event)
                    writer.writerow(dict(row,value_basis='scan_snapshot',scan_count=self.round)); done += 1
                    if done % 4096 == 0:
                        self.owner(); progress.update(count=done,progress_percent=round(100*done/max(1,total),1))
                self.check(event); self.owner()
            self.exports[key] = path
            return dict(success=True,export_id=key,count=done,basis='scan_snapshot',
                        download_url=f'/api/studio/scans/{self.id}/exports/{key}')
        except BaseException:
            path.unlink(missing_ok=True); raise

    @staticmethod
    def row(addr, kind, raw, previous=None, fields=None):
        return dict(address=f'0x{addr:016X}', data_type=kind, width=len(raw), fields=fields or [],
                    current_value=display(raw, kind, fields), scanned_value=display(raw, kind, fields),
                    previous_value=display(previous if previous is not None else raw, kind, fields),
                    data_hex=raw.hex(' ').upper(), baseline_hex=raw.hex(), error='', changed=False)

    def update_live(self, row, cache):
        try:
            raw = self.read(integer(row['address']), row['width'], cache)
            row.update(current_value=display(raw, row['data_type'], row.get('fields')), data_hex=raw.hex(' ').upper(),
                       changed=raw.hex() != row['baseline_hex'], error='')
        except OSError as exc: row.update(current_value='—', data_hex='—', changed=False, error=str(exc))

    def save(self, args):
        self.owner(); addresses = args.get('addresses', [args.get('address')])
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= MAX_SAVED:
            raise ValueError('보관할 주소는 1~256개입니다')
        kind = args.get('data_type') or (self.cfg['data_type'] if self.cfg else 'int32')
        if kind in FORMATS: width = FORMATS[kind][1]; fields = []
        elif kind in ('utf8', 'utf16', 'aob', 'structure'):
            width = integer(args.get('width') or (self.cfg['width'] if self.cfg else 16))
            fields = []
            if kind == 'structure':
                source = args.get('fields', self.cfg['fields'] if self.cfg else [])
                fields = validate(dict(data_type='structure',condition='unknown',fields=source))['fields']
                if max(f['offset']+f['width'] for f in fields) > width: raise ValueError('구조체 보관 길이가 필드 범위보다 작습니다')
        else: raise ValueError('보관 형식 오류')
        if not 1 <= width <= 1024: raise ValueError('보관 길이는 1~1024바이트입니다')
        new = []; existing = {(r['address'], r['data_type'], r['width']) for r in self.saved.values()}
        # Validate capacity before issuing ANY memory reads; never partially save.
        for item in addresses:
            addr = integer(item)
            if not 0 < addr < 0x800000000000-width: raise ValueError('주소 범위 오류')
            key = (f'0x{addr:016X}', kind, width)
            if key in existing: continue
            new.append(addr); existing.add(key)
        if len(self.saved)+len(new) > MAX_SAVED:
            raise ValueError(f'보관 공간 부족: 새 주소 {len(new)}개 / 남은 공간 {MAX_SAVED-len(self.saved)}개 (상한 {MAX_SAVED}개)')
        cache = {}; rows = []
        for addr in new:
            raw = self.read(addr, width, cache)
            row = self.row(addr, kind, raw, fields=fields)
            row.update(id=uuid.uuid4().hex, description=str(args.get('description', ''))[:120], frozen=False, frozen_hex=None)
            rows.append(row)
        self.owner()
        for row in rows: self.saved[row['id']] = row
        return dict(success=True, added=len(rows), saved_count=len(self.saved), saved_remaining=MAX_SAVED-len(self.saved))

    @write_guard
    def edit(self, key, args):
        self.owner(); row = self.saved.get(key)
        if not row: raise ValueError('보관 주소를 찾을 수 없습니다')
        if args.get('remove'):
            del self.saved[key]; return dict(success=True)
        if 'description' in args: row['description'] = str(args['description'])[:120]
        if 'value' in args:
            payload = encode(row['data_type'], args['value'], row['width'])
            before = self.read(integer(row['address']), row['width'])
            expected = bytes.fromhex(str(args.get('expected_hex', '')))
            if before != expected: raise ValueError('표시 이후 값이 바뀌었습니다. 새로 고침 후 다시 편집하세요')
            self.owner()
            response = self.studio.driver.write_process_memory(self.pid, integer(row['address']), payload)
            row['frozen'] = False
            if not response.get('success') or response.get('bytes_written') != len(payload):
                raise ValueError('커널 쓰기 실패 또는 부분 쓰기. 실제 값을 새로 고침하세요')
            self.owner(); actual = self.read(integer(row['address']), row['width'])
            if actual != payload: raise ValueError('쓰기 후 검증값이 다릅니다. 대상이 값을 변경했을 수 있습니다')
            row.update(baseline_hex=actual.hex(), current_value=display(actual,row['data_type'],row['fields']),
                       data_hex=actual.hex(' ').upper(), frozen_hex=actual.hex(), error='')
        if 'frozen' in args:
            if not isinstance(args['frozen'], bool): raise ValueError('고정 옵션은 참/거짓입니다')
            if args['frozen'] and row['data_type'] not in FORMATS: raise ValueError('값 고정은 숫자 형식에 지원합니다')
            if args['frozen']:
                raw = self.read(integer(row['address']), row['width']); self.owner()
                row['frozen_hex'] = raw.hex()
            row['frozen'] = args['frozen']
        return dict(success=True, address=row['address'])

    @write_guard
    def freeze(self):
        if not any(r['frozen'] for r in self.saved.values()): return
        for row in self.saved.values():
            if not row['frozen']: continue
            try:
                self.owner(); payload = bytes.fromhex(row['frozen_hex'])
                response = self.studio.driver.write_process_memory(self.pid, integer(row['address']), payload)
                if not response.get('success') or response.get('bytes_written') != len(payload): raise ValueError('커널 고정 쓰기 실패')
            except Exception as exc: row.update(frozen=False, error=str(exc))


class Workspace:
    def __init__(self, studio):
        self.studio = studio
        self.lock = threading.RLock()
        self.sessions = {}
        self.jobs = {}
        self.closing = False
        self.temp = tempfile.TemporaryDirectory(prefix='kernel-studio-scan-')
        self.root = Path(self.temp.name)
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='memory-scan')
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.maintenance, name='scan-freeze', daemon=True)
        self.thread.start()

    def get(self, key):
        with self.lock:
            s = self.sessions.get(key)
            if not s or s.closed: raise ValueError('스캔 세션이 만료되었습니다. 다시 선택하세요')
            s.touched = time.monotonic()
            return s

    def create(self, pid):
        with self.lock:
            if self.closing: raise ValueError('서버 종료 중입니다')
            if len(self.sessions) >= 4: raise ValueError('동시 스캔 세션 상한 4개입니다. 이전 탭을 닫거나 검색을 초기화하세요')
            s = Session(self.studio, integer(pid), self.root)
            self.sessions[s.id] = s
            return s.summary()

    def submit(self, key, action, args):
        if action not in ('new', 'next', 'rescan', 'view', 'export'): raise ValueError('검색 동작 오류')
        s = self.get(key)
        with self.lock:
            if self.closing: raise ValueError('서버 종료 중입니다')
            if s.job: raise ValueError('현재 검색이 완료된 후 실행하세요')
            # Reject malformed input before scheduling; a failed New leaves existing results intact.
            if action not in ('view','export'): validate(dict(args, condition='rescan') if action == 'rescan' else args, s.cfg if action != 'new' else None)
            if action != 'new' and not s.cfg: raise ValueError('먼저 New 검색을 실행하세요')
            job = dict(id=uuid.uuid4().hex, session_id=key, state='queued', action=action, progress_percent=0,
                       cancel_requested=False, started=time.time(), result=None, event=threading.Event())
            while len(self.jobs) >= 32:
                stale = next((k for k,v in self.jobs.items() if v['state'] not in ('queued','running')), None)
                if stale is None: raise ValueError('검색 작업 큐가 가득 찼습니다')
                del self.jobs[stale]
            self.jobs[job['id']] = job; s.job = job['id']

        def work():
            outcome = {}
            try:
                with s.lock:
                    job['state'] = 'running'
                    if action == 'view': result = s.build_view(args, job['event'], job)
                    elif action == 'export': result = s.export_csv(args, job['event'], job)
                    else: result = s.new(args, job['event'], job) if action == 'new' else s.next(dict(args, condition='rescan') if action == 'rescan' else args, job['event'], job)
                    outcome = dict(state='completed', result=result, progress_percent=100)
            except InterruptedError as exc: outcome = dict(state='cancelled', error=str(exc))
            except Exception as exc: outcome = dict(state='failed', error=str(exc), target_invalid=s.invalid)
            finally:
                with self.lock:
                    s.touched = time.monotonic()
                    s.job = None
                    # Publish completion only after results can be fetched / Next can start.
                    job.update(outcome, finished=time.time())
                if s.closed: self.cleanup(s)

        self.executor.submit(work)
        return dict(success=True, job_id=job['id'])

    def status(self, key):
        with self.lock:
            job = self.jobs.get(key)
            if not job: raise ValueError('검색 작업을 찾을 수 없습니다')
            s = self.sessions.get(job['session_id'])
            if s is not None: s.touched = time.monotonic()
            return dict(success=True, **{k:v for k,v in job.items() if k != 'event'})

    def cancel(self, key):
        with self.lock:
            job = self.jobs.get(key)
            if not job: raise ValueError('검색 작업을 찾을 수 없습니다')
            if job['state'] in ('completed','cancelled','failed'):
                return dict(success=True, accepted=False, state=job['state'], disposition='already_'+job['state'])
            job['cancel_requested'] = True; job['event'].set()
            return dict(success=True, accepted=True, state=job['state'], disposition='cancel_requested')

    def invoke(self, key, action, args):
        s = self.get(key)
        if s.job: raise ValueError('검색 중입니다. 완료 후 값을 갱신하세요')
        with s.lock:
            if s.job: raise ValueError('검색 중입니다. 완료 후 값을 갱신하세요')
            if action == 'results': return s.results(integer(args.get('page', 1)), integer(args.get('page_size', 100)), args.get('live', True), args.get('view_id'))
            if action == 'read_saved': return s.read_saved(str(args.get('id', '')))
            if action == 'save': return s.save(args)
            if action == 'edit': return s.edit(str(args.get('id', '')), args)
            if action == 'reset':
                with s.db() as db:
                    db.execute('DELETE FROM chunks'); db.execute('DELETE FROM browse')
                s.cfg = None; s.count = s.round = 0; s.stats = {}
                s.view = None
                return s.summary()
            raise ValueError('스캔 동작 오류')

    def remove(self, key):
        with self.lock:
            s = self.sessions.pop(key, None)
            if not s: return dict(success=True)
            s.closed = True
            if s.job: self.cancel(s.job)
        with s.write_lock:
            # Any in-flight write completes before the release response.
            for row in s.saved.values(): row['frozen'] = False
        # Synchronize with any already-started data write before returning.
        if not s.job:
            with s.lock: self.cleanup(s)
        return dict(success=True)

    def cleanup(self, s):
        with s.lock:
            s.saved.clear()
            for path in s.exports.values(): path.unlink(missing_ok=True)
            s.exports.clear()
            for suffix in ('', '-journal', '-wal', '-shm'): Path(str(s.path)+suffix).unlink(missing_ok=True)

    def maintenance(self):
        while not self.stop.wait(0.1):
            with self.lock: sessions = list(self.sessions.values())
            for s in sessions:
                if time.monotonic()-s.touched > 1800 and not s.job:
                    self.remove(s.id); continue
                if not s.lock.acquire(blocking=False): continue
                try:
                    if not s.closed: s.freeze()
                except Exception as exc:
                    for row in s.saved.values(): row.update(frozen=False,error=str(exc))
                finally: s.lock.release()

    def shutdown(self):
        with self.lock:
            self.closing = True
            for job in self.jobs.values(): job['event'].set()
        self.stop.set(); self.thread.join(timeout=10)
        self.executor.shutdown(wait=True, cancel_futures=False)
        for key in list(self.sessions): self.remove(key)
        self.temp.cleanup()
