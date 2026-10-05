"""Bounded PID discovery through the existing driver ABI, without OS enumeration."""
import copy
import threading
import time
from itertools import chain


DEFAULT_MAX_PID = 65536
MAX_PID_LIMIT = 1048576


class DiscoveryError(RuntimeError):
    pass


class KernelProcessCatalog:
    def __init__(self, driver, cache_seconds=3, clock=time.monotonic):
        self.driver = driver
        self.cache_seconds = cache_seconds
        self.clock = clock
        self.lock = threading.Lock()
        self.cached = None
        self.cached_at = 0
        self.cached_extra = ()

    def list(self, max_pid=DEFAULT_MAX_PID, extra_pids=(), refresh=False):
        if not isinstance(max_pid, int) or not 4 <= max_pid <= MAX_PID_LIMIT:
            raise ValueError('PID 조회 범위 오류')
        # The Windows CID lookup used by this ABI aliases the low two bits.
        # Probe each canonical PID once, avoiding four copies of each process.
        extras = tuple(sorted({int(pid) & ~3 for pid in extra_pids
                               if 4 <= int(pid) <= 0xffffffff}))
        requested_at = self.clock()
        with self.lock:
            if not self.driver.is_connected() and not self.driver.open():
                self.cached = None
                raise DiscoveryError('드라이버에 연결할 수 없습니다')
            now = self.clock()
            if (self.cached is not None and self.cached['max_pid'] == max_pid
                    and self.cached_extra == extras
                    and now - self.cached_at < self.cache_seconds
                    and (not refresh or self.cached_at > requested_at)):
                result = copy.deepcopy(self.cached)
                result['cached'] = True
                return result
            self.cached = None
            started = self.clock()
            processes = []
            denied = 0
            probes = 0
            candidates = range(4, max_pid + 1, 4)
            extra_candidates = (pid for pid in extras if pid > max_pid)
            for pid in chain(candidates, extra_candidates):
                info = self.driver.query_process_extended(pid)
                probes += 1
                # A disconnected device is not an empty process list. Stop
                # immediately rather than reopening it for every candidate.
                if info.get('error_code'):
                    raise DiscoveryError('커널 프로세스 조회 통신 실패: '
                                         + str(info['error_code']))
                if not info.get('success'):
                    if info.get('result_status') == '0xC0000022':
                        denied += 1
                    continue
                if info.get('exit_status') != 259:
                    continue
                path = info.get('image_file_name') or ''
                name = path.replace('\\', '/').rsplit('/', 1)[-1]
                if not name:
                    name = 'System' if pid == 4 else f'unknown (PID {pid})'
                working_set = info.get('working_set_kb')
                processes.append({'pid': pid, 'name': name, 'status': 'running',
                    'memory_mb': round(working_set / 1024, 2)
                                 if working_set is not None else None,
                    'cpu_percent': None, 'image_path': path,
                    'create_time': str(info.get('create_time', 0)),
                    'thread_count': info.get('thread_count'),
                    'is_protected': bool(info.get('is_protected'))})
            processes.sort(key=lambda process: process['pid'])
            result = {'success': True, 'processes': processes,
                      'source': 'kernel_pid_probe', 'system_wide': False,
                      'min_pid': 4, 'max_pid': max_pid, 'probe_count': probes,
                      'access_denied_count': denied, 'cached': False,
                      'seconds': round(self.clock() - started, 3),
                      'note': '현재 ABI에는 전체 PID 열거 요청이 없어 지정 범위를 '
                              '커널로 조회합니다. 범위 밖 PID는 직접 입력하거나 '
                              '조회 범위를 확장하세요. 종료된 프로세스와 조회 '
                              '불가 프로세스는 제외됩니다.'}
            self.cached = copy.deepcopy(result)
            self.cached_at = self.clock()
            self.cached_extra = extras
            return result
