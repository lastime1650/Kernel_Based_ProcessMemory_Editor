"""Bounded read-only analysis and saved-record management using existing IOCTLs.

PE layout: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
"""
import struct
import time
import uuid
from pathlib import PureWindowsPath

OPERATIONS = ['pe_imports', 'pe_exports', 'resolve', 'address_info', 'memory_diff',
              'patch_preview', 'signature', 'strings_filter', 'map_snapshot',
              'map_list', 'map_compare', 'map_delete', 'snapshot_delete', 'patch_delete']


class LoadedPE:
    def __init__(self, studio, pid, base):
        self.studio, self.pid, self.base = studio, pid, base
        header = studio.read_bytes(pid, base, 4096)
        if header[:2] != b'MZ': raise ValueError('MZ 헤더가 없습니다')
        offset = struct.unpack_from('<I', header, 0x3c)[0]
        if not 0x40 <= offset <= 3500 or header[offset:offset+4] != b'PE\0\0':
            raise ValueError('PE 헤더 위치가 올바르지 않습니다')
        optional = struct.unpack_from('<H', header, offset+20)[0]
        opt = offset+24
        magic = struct.unpack_from('<H', header, opt)[0]
        if magic not in (0x10b, 0x20b): raise ValueError('PE32 / PE32+ 형식이 필요합니다')
        self.width = 8 if magic == 0x20b else 4
        self.size = struct.unpack_from('<I', header, opt+56)[0]
        relative = 112 if self.width == 8 else 96
        if not 4096 <= self.size <= 0x40000000 or base+self.size > 0x800000000000:
            raise ValueError('이미지 크기가 올바르지 않습니다')
        if optional < relative or opt+optional > len(header): raise ValueError('선택 헤더 크기 오류')
        count = struct.unpack_from('<I', header, opt+relative-4)[0]
        if count > 16 or optional < relative+count*8: raise ValueError('데이터 디렉터리 크기 오류')
        self.directories = [struct.unpack_from('<II', header, opt+relative+i*8) for i in range(count)]

    def read(self, rva, size):
        if rva < 0 or size < 1 or rva+size > self.size or size > 1024*1024:
            raise ValueError('PE RVA 또는 크기가 이미지 범위를 벗어났습니다')
        return self.studio.read_bytes(self.pid, self.base+rva, size)

    def directory(self, index):
        rva, size = self.directories[index] if index < len(self.directories) else (0, 0)
        if not rva and not size: return 0, 0
        if not rva or not size or rva+size > self.size: raise ValueError('PE 디렉터리 범위 오류')
        return rva, size

    def text(self, rva, end=None):
        limit = min(self.size, end or self.size, rva+512)
        raw = bytearray()
        while rva+len(raw) < limit:
            chunk = self.read(rva+len(raw), min(64, limit-rva-len(raw)))
            if b'\0' in chunk:
                raw.extend(chunk.split(b'\0', 1)[0])
                return raw.decode('ascii', errors='replace')
            raw.extend(chunk)
        raise ValueError('PE 문자열 종료 문자가 없거나 길이 상한을 초과했습니다')

    def exports(self):
        rva, size = self.directory(0)
        if not rva: return []
        if size < 40: raise ValueError('내보내기 디렉터리가 너무 작습니다')
        fields = struct.unpack('<IIHHIIIIIII', self.read(rva, 40))
        ordinal_base, count, names, functions_rva, names_rva, ordinals_rva = fields[5:]
        if count > 65536 or names > 65536: raise ValueError('내보내기 개수 상한 초과')
        functions = struct.unpack(f'<{count}I', self.read(functions_rva, count*4)) if count else ()
        pointers = struct.unpack(f'<{names}I', self.read(names_rva, names*4)) if names else ()
        ordinals = struct.unpack(f'<{names}H', self.read(ordinals_rva, names*2)) if names else ()
        named = {}
        for pointer, ordinal in zip(pointers, ordinals):
            if ordinal >= count: raise ValueError('내보내기 ordinal 범위 오류')
            named.setdefault(ordinal, []).append(self.text(pointer))
        rows = []
        for i, function in enumerate(functions):
            if not function: continue
            if function >= self.size: raise ValueError('내보내기 함수 RVA 범위 오류')
            forwarder = self.text(function, rva+size) if rva <= function < rva+size else ''
            for name in named.get(i, ['']):
                rows.append({'name': name, 'ordinal': ordinal_base+i, 'rva': f'0x{function:X}',
                    'address': f'0x{self.base+function:X}', 'forwarder': forwarder})
        return rows

    def imports(self):
        rva, size = self.directory(1)
        if not rva: return [], False
        rows = []
        for i in range(min(size//20, 256)):
            original, stamp, chain, name, first = struct.unpack('<IIIII', self.read(rva+i*20, 20))
            if not any((original, stamp, chain, name, first)): return rows, False
            dll = self.text(name)
            for j in range(5001):
                lookup = int.from_bytes(self.read((original or first)+j*self.width, self.width), 'little')
                if not lookup: break
                if len(rows) >= 5000: return rows, True
                current = int.from_bytes(self.read(first+j*self.width, self.width), 'little')
                by_ordinal = bool(lookup & (1 << (self.width*8-1)))
                symbol = '<bound IAT>' if not original else f'#{lookup & 0xffff}' if by_ordinal else self.text(lookup+2)
                rows.append({'module': dll, 'name': symbol, 'address': f'0x{self.base+first+j*self.width:X}',
                    'target_address': f'0x{current:X}', 'by_ordinal': by_ordinal if original else None})
            else: raise ValueError('가져오기 thunk 종료 상한 초과')
        raise ValueError('가져오기 디렉터리 종료 항목이 없거나 상한을 초과했습니다')


def operate(studio, operation, args, cancelled):
    # Imported lazily to avoid a dependency cycle during server initialization.
    from studio_api import address, bounded, integer, payload, MAX_RESULTS
    pid = bounded(args.get('pid', 1), 0xffffffff)
    start = lambda: address(args.get('address', '0x0'))
    if operation in ('pe_imports', 'pe_exports'):
        pe = LoadedPE(studio, pid, start())
        if operation == 'pe_imports': rows, truncated = pe.imports()
        else: rows, truncated = pe.exports(), False
        query = str(args.get('query', '')).casefold()
        filtered = [r for r in rows if query in str(r).casefold()]
        return {'success': True, 'results': filtered[:MAX_RESULTS], 'total': len(filtered),
                'image_address': f'0x{pe.base:X}', 'bits': pe.width*8,
                'truncated': truncated or len(filtered) > MAX_RESULTS}
    if operation == 'resolve':
        expression = str(args.get('expression', '')).strip()
        modules = studio.operate('modules', {'pid': pid})['results']
        def module(name):
            matches = [m for m in modules if PureWindowsPath(m['path'] or m['name']).name.casefold() in
                       (name.casefold(), name.casefold()+'.dll')]
            if len(matches) != 1: raise ValueError(f'로드된 모듈을 고유하게 찾을 수 없습니다: {name}')
            return matches[0]
        trace, seen = [], set()
        for depth in range(8):
            if expression in seen: raise ValueError('전달 내보내기 순환을 발견했습니다')
            seen.add(expression)
            if '!' in expression:
                name, symbol = expression.split('!', 1)
                m = module(name); pe = LoadedPE(studio, pid, int(m['address'], 16))
                matches = [r for r in pe.exports() if r['name'] == symbol or
                           (symbol.startswith('#') and str(r['ordinal']) == symbol[1:])]
                if len(matches) != 1: raise ValueError(f'내보내기 함수를 찾을 수 없습니다: {symbol}')
                row = matches[0];trace.append({'expression': expression, **row})
                if row['forwarder']:
                    if '.' not in row['forwarder']: raise ValueError('전달 내보내기 형식 오류')
                    name, symbol = row['forwarder'].rsplit('.', 1)
                    expression = name+'!'+symbol
                    continue
                result = address(row['address'])
            elif '+' in expression:
                name, offset = expression.rsplit('+', 1)
                m = module(name);rva = bounded(offset, integer(m['size'])-1, 0)
                result = address(integer(m['address'])+rva)
                trace.append({'expression': expression, 'module': m['name'], 'address': f'0x{result:X}'})
            else:
                result = address(expression);trace.append({'expression': expression, 'address': f'0x{result:X}'})
            return {'success': True, 'address': f'0x{result:X}', 'results': trace}
        raise ValueError('전달 내보내기 깊이가 8단계를 초과했습니다')
    if operation == 'address_info':
        regions = studio.operate('regions', {'pid': pid,'max_results':50000})['results']
        matches = [r for r in regions if integer(r['address']) <= start() < integer(r['address'])+r['size']]
        if not matches: raise ValueError('주소에 해당하는 메모리 영역이 없습니다')
        region = matches[0]; rows = [{'address': f'0x{start():X}', 'region_base': region['address'],
            'offset': f'0x{start()-integer(region["address"]):X}', **{k:v for k,v in region.items() if k != 'address'}}]
        if region['image_base'] != '0x0':
            pe = studio.pe(pid, integer(region['image_base']))
            for section in pe['results']:
                if integer(section['address']) <= start() < integer(section['address'])+section['size']:
                    rows[0]['section'] = section['name']
            rows[0]['module_rva'] = f'0x{start()-integer(region["image_base"]):X}'
        return {'success': True, 'results': rows}
    if operation in ('memory_diff', 'patch_preview'):
        if operation == 'memory_diff':
            size = bounded(args.get('size', 64))
            after = studio.read_bytes(bounded(args.get('dst_pid', pid), 0xffffffff), address(args['dst_address']), size)
        else: after = payload(args);size = len(after)
        before = studio.read_bytes(pid, start(), size)
        rows, changes, base = [], 0, start()
        for i,(a,b) in enumerate(zip(before, after)):
            if a == b: continue
            changes += 1
            if len(rows) < MAX_RESULTS:
                rows.append({'address': f'0x{base+i:X}', 'offset': f'0x{i:X}', 'before': f'{a:02X}', 'after': f'{b:02X}'})
        result = {'success': True, 'changed_bytes': changes, 'results': rows, 'size': size,
                  'truncated': changes > MAX_RESULTS, 'wrote_memory': False}
        if operation == 'patch_preview':
            expected = args.get('expected')
            result.update(expected_matches=expected is None or bytes.fromhex(expected) == before,
                          before_hex=before.hex(), after_hex=after.hex(),
                          note='미리보기 후에도 값이 바뀔 수 있습니다. 기록 시 expected 원본을 다시 확인하세요.')
        return result
    if operation == 'signature':
        size = bounded(args.get('size', 32), 256)
        raw = studio.read_bytes(pid, start(), size)
        ranges = args.get('wildcards', [])
        if not isinstance(ranges, list) or len(ranges) > 128: raise ValueError('와일드카드 범위는 최대 128개입니다')
        wild = set()
        for item in ranges:
            if not isinstance(item, dict): raise ValueError('와일드카드 범위는 offset / size 객체입니다')
            offset, count = bounded(item['offset'], size-1, 0), bounded(item['size'], size)
            if offset+count > size: raise ValueError('와일드카드 범위 초과')
            wild.update(range(offset, offset+count))
        if len(wild) == size: raise ValueError('고정 바이트가 한 개 이상 필요합니다')
        pattern = ' '.join('??' if i in wild else f'{x:02X}' for i,x in enumerate(raw))
        return {'success': True, 'address': f'0x{start():X}', 'pattern': pattern,
                'results': [{'pattern': pattern, 'size': size, 'fixed_bytes': size-len(wild)}]}
    if operation == 'strings_filter':
        result = studio.operate('strings', args, cancelled)
        query = str(args.get('query', ''))
        if len(query) > 512: raise ValueError('문자열 필터는 최대 512자입니다')
        mode = args.get('mode', 'contains')
        if mode not in ('contains','prefix','exact'): raise ValueError('문자열 비교 모드 오류')
        sensitive = args.get('case_sensitive', False)
        if not isinstance(sensitive, bool): raise ValueError('대소문자 옵션은 참 / 거짓입니다')
        def match(row):
            text, needle = row['text'], query
            if not sensitive: text, needle = text.casefold(), needle.casefold()
            return needle in text if mode == 'contains' else text.startswith(needle) if mode == 'prefix' else text == needle
        rows = [r for r in result['results'] if match(r)]
        return dict(result, results=rows, matched_returned=len(rows), scanned_returned=len(result['results']),
                    note='드라이버 문자열 결과의 반환 상한 내에서 필터링합니다. 긴 문자열은 미리보기 범위에 적용합니다.')
    if operation in ('map_snapshot','map_list','map_compare','map_delete'):
        with studio.lock:
            if operation == 'map_list':
                return {'success': True, 'results': [{k:v for k,v in r.items() if k != 'regions'} for r in studio.maps.values()]}
            if operation == 'map_snapshot':
                if len(studio.maps) >= 8: raise ValueError('메모리 맵 스냅샷은 최대 8개입니다')
                identity = studio.identity(pid)
                result = studio.operate('regions', {'pid': pid,'max_results':50000})
                if result['truncated']: raise ValueError('전체 메모리 맵이 반환 상한을 초과해 저장하지 않았습니다')
                record = {'id': uuid.uuid4().hex, 'pid': pid, 'identity': identity, 'time': time.time(),
                          'name': str(args.get('name', 'Memory map'))[:100], 'region_count': result['total'],
                          'regions': result['results']}
                studio.check_owner(record);studio.maps[record['id']] = record
                return {'success': True, 'map_id': record['id'], 'region_count': record['region_count'],
                        'results': [{k:v for k,v in record.items() if k != 'regions'}]}
            record = studio.maps.get(args.get('id'))
            if not record: raise ValueError('메모리 맵 스냅샷을 찾을 수 없습니다')
            if operation == 'map_delete':
                del studio.maps[record['id']];return {'success': True, 'deleted': True, 'wrote_memory': False}
            studio.check_owner(record)
            current = studio.operate('regions', {'pid': record['pid'],'max_results':50000})
            if current['truncated']: raise ValueError('현재 맵이 반환 상한을 초과해 비교할 수 없습니다')
            before = {r['address']:r for r in record['regions']};after = {r['address']:r for r in current['results']}
            rows = []
            for key in sorted(before.keys() | after.keys(), key=integer):
                a,b = before.get(key), after.get(key)
                change = 'added' if a is None else 'removed' if b is None else 'changed' if a != b else None
                if a and b and a['state'] == '0x10000' and b['state'] != '0x10000': change = 'allocated'
                if a and b and a['state'] != '0x10000' and b['state'] == '0x10000': change = 'released'
                if change: rows.append({'address': key, 'change': change, 'before': a, 'after': b})
            return {'success': True, 'results': rows[:MAX_RESULTS], 'changes': len(rows),
                    'truncated': len(rows) > MAX_RESULTS, 'note': '조회 시점 간 비교이며 중간에 발생한 모든 변경을 기록하지는 않습니다.'}
    if operation in ('snapshot_delete','patch_delete'):
        with studio.lock:
            records = studio.snapshots if operation == 'snapshot_delete' else studio.patches
            record = records.get(args.get('id'))
            if not record: raise ValueError('저장 기록을 찾을 수 없습니다')
            if operation == 'patch_delete' and not record['undone']:
                raise ValueError('복구가 완료된 패치만 이력에서 삭제할 수 있습니다')
            del records[record['id']]
            return {'success': True, 'deleted': True, 'wrote_memory': False}
    raise ValueError('지원하지 않는 확장 작업')

