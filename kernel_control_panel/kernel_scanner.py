"""New/Next scanning without target-process Win32 APIs or user-mode handles."""
import math
import struct
from memory_scanner import MemoryScannerSession, ScanCandidate, FORMATS, _serialized_scan


class KernelMemoryScannerSession(MemoryScannerSession):
    def __init__(self, bridge, regions_provider):
        super().__init__(bridge)
        self.regions_provider = regions_provider
        self.identity = None
        self.partial = False

    def owner(self):
        response = self.bridge.query_process_info(self.pid)
        if not response.get('success') or response.get('exit_status') != 259:
            raise ValueError('대상 프로세스가 실행 중이 아닙니다')
        identity = str(response['process_start_key'])
        if self.identity is not None and identity != self.identity:
            raise ValueError('스캔 대상 PID의 프로세스가 교체되었습니다')
        return identity

    @staticmethod
    def matches(now, previous, kind, condition, first, second=None):
        floating = kind.startswith('float')
        if floating and (math.isnan(now) or previous is not None and math.isnan(previous)):
            return False
        same = lambda a,b: math.isclose(a,b,rel_tol=1e-5,abs_tol=1e-6) if floating else a == b
        if condition == 'unknown': return True
        if condition == 'exact': return same(now,first)
        if condition == 'between': return first <= now <= second
        if condition == 'bigger': return now >= first
        if condition == 'smaller': return now <= first
        if condition == 'increased': return now > previous
        if condition == 'decreased': return now < previous
        if condition == 'changed': return not same(now,previous)
        if condition == 'unchanged': return same(now,previous)
        raise ValueError('지원하지 않는 스캔 조건')

    def values(self, kind, condition, val1, val2=None):
        if kind not in FORMATS: raise ValueError('지원하지 않는 숫자 형식')
        a = self._parse_val(val1,kind) if val1 not in (None,'') else None
        b = self._parse_val(val2,kind) if val2 not in (None,'') else None
        if condition in ('exact','bigger','smaller','between') and a is None:
            raise ValueError('비교 값을 입력하세요')
        if condition == 'between' and (b is None or a > b): raise ValueError('범위 값을 확인하세요')
        for value in (a,b):
            if isinstance(value,float) and not math.isfinite(value): raise ValueError('유한한 값을 입력하세요')
        if not kind.startswith('float') and a is not None: struct.pack(FORMATS[kind][0],a)
        return a,b

    @_serialized_scan
    def reset(self):
        super().reset()
        self.identity = None
        self.partial = False

    @_serialized_scan
    def get_results(self, page=1, page_size=100):
        if page < 1 or not 1 <= page_size <= 50000:
            return {'success':False,'error':'페이지는 1 이상, 페이지 크기는 1~50000입니다','results':[]}
        return dict(super().get_results(page,page_size), partial=self.partial,
                    note='초기 스캔 상한·읽기 실패로 일부 후보만 검색했습니다' if self.partial else '')

    @_serialized_scan
    def first_scan(self,pid,data_type,scan_type,val1,val2=None,writable_only=True,max_results=50000,
                   alignment=0,start_address=None,end_address=None):
        self.reset()
        try:
            if scan_type not in ('exact','bigger','smaller','between','unknown'): raise ValueError('New 스캔 조건 오류')
            if not 1 <= max_results <= 50000: raise ValueError('결과 상한은 1~50000입니다')
            first, second = self.values(data_type,scan_type,val1,val2)
            self.pid, self.data_type, self.is_scanning = pid, data_type, True
            self.identity = self.owner()
            result = self.regions_provider(pid)
            if not result.get('success') or result.get('truncated'): raise ValueError('전체 커널 메모리 맵을 얻지 못했습니다')
            fmt,size = FORMATS[data_type]
            stride = size if alignment == 0 else alignment
            if stride not in (1,2,4,8): raise ValueError('정렬은 자연 정렬(0) 또는 1/2/4/8바이트입니다')
            lower = int(str(start_address),0) if start_address not in (None,'') else 0
            upper = int(str(end_address),0) if end_address not in (None,'') else 0x800000000000
            if not 0 <= lower < upper <= 0x800000000000: raise ValueError('스캔 주소 범위를 확인하세요')
            candidates = [];scanned = failed = regions = 0
            carry = b''; previous_end = None
            for region in result['results']:
                if not region['readable'] or region['guarded'] or writable_only and not region['writable']:
                    carry=b'';previous_end=None;continue
                original_base=int(region['address'],16)
                base=max(original_base,lower);end=min(original_base+region['size'],upper)
                if base>=end:continue
                regions += 1
                for current in range(base,end,4096):
                    count = min(4096,end-current)
                    if previous_end != current:carry=b''
                    response = self.bridge.read_process_memory_snapshot(pid,current,count)
                    raw = bytes.fromhex(response.get('data_hex','')) if response.get('success') else b''
                    if len(raw) != count:
                        failed += 1;carry=b'';previous_end=None;continue
                    scanned += count
                    combined=carry+raw;combined_base=current-len(carry)
                    # Carry only unfinished starts; already complete values are not repeated.
                    for i in range((-combined_base)%stride,len(combined)-size+1,stride):
                        value = struct.unpack_from(fmt,combined,i)[0]
                        if self.matches(value,value,data_type,scan_type,first,second):
                            candidates.append(ScanCandidate(combined_base+i,value,value))
                            if len(candidates) >= max_results: break
                    carry=combined[-(size-1):] if size>1 else b'';previous_end=current+count
                    if len(candidates) >= max_results: break
                if len(candidates) >= max_results: break
            self.owner()
            self.candidates, self.scan_count = candidates, 1
            self.partial = len(candidates)>=max_results or failed>0
            return {'success':True,'count':len(candidates),'scan_count':1,'max_hit':len(candidates)>=max_results,
                    'transport':'kernel_ioctl','regions_scanned':regions,'bytes_scanned':scanned,'failed_chunks':failed,
                    'alignment':stride,'partial':self.partial,
                    'note':'상한·읽기 실패로 전체 후보를 검색하지 못했습니다' if self.partial else ''}
        except (ValueError,TypeError,struct.error,RuntimeError) as exc:
            return {'success':False,'error':str(exc),'count':0,'transport':'kernel_ioctl'}

    @_serialized_scan
    def next_scan(self,scan_type,val1=None,val2=None):
        try:
            if not self.pid or not self.scan_count: raise ValueError('먼저 New 스캔을 실행하세요')
            if scan_type not in ('exact','bigger','smaller','increased','decreased','changed','unchanged'):
                raise ValueError('Next 스캔 조건 오류')
            self.owner();first,second = self.values(self.data_type,scan_type,val1,val2)
            fmt,size = FORMATS[self.data_type];survivors=[];failed=pages=0;cache={}
            self.is_scanning = True
            for candidate in self.candidates:
                page = candidate.address & ~4095
                if page not in cache:
                    r = self.bridge.read_process_memory_snapshot(self.pid,page,4096);pages += 1
                    cache[page] = bytes.fromhex(r.get('data_hex','')) if r.get('success') else b''
                raw = cache[page][candidate.address-page:candidate.address-page+size]
                if len(raw) != size:
                    r = self.bridge.read_process_memory_snapshot(self.pid,candidate.address,size)
                    raw = bytes.fromhex(r.get('data_hex','')) if r.get('success') else b''
                if len(raw) != size: failed += 1;continue
                value = struct.unpack(fmt,raw)[0]
                if self.matches(value,candidate.current_value,self.data_type,scan_type,first,second):
                    survivors.append(ScanCandidate(candidate.address,value,candidate.current_value))
            self.owner();self.candidates=survivors;self.scan_count += 1
            self.partial = self.partial or failed>0
            return {'success':True,'count':len(survivors),'scan_count':self.scan_count,'transport':'kernel_ioctl',
                    'pages_read':pages,'failed_candidates':failed,'partial':self.partial}
        except (ValueError,TypeError,struct.error,RuntimeError) as exc:
            return {'success':False,'error':str(exc),'count':len(self.candidates),'transport':'kernel_ioctl'}
