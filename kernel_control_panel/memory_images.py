"""Discover PE headers in committed memory using the existing kernel reader.

MEM_IMAGE metadata is retained. A header-discovered PE is not proof that the
Windows loader loaded it, that its payload is complete, or that it is executable.
"""
from bisect import bisect_right
from pathlib import PureWindowsPath
import struct

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MAX_HEADER = 65536
MAX_IMAGE = 0x40000000
USER_LIMIT = 0x800000000000
TYPE_NAMES = {0x1000000: 'MEM_IMAGE', 0x20000: 'MEM_PRIVATE', 0x40000: 'MEM_MAPPED'}


def integer(value):
    return int(str(value), 16 if str(value).lower().startswith('0x') else 10)


class ProbeError(ValueError):
    pass


class ReadError(ProbeError):
    pass


def readable(region):
    return (integer(region.get('state', 0)) == MEM_COMMIT and
            bool(region.get('readable')) and not region.get('guarded') and
            not integer(region.get('protect', 0)) & 0x100)


class RegionReader:
    def __init__(self, studio, pid, base, regions):
        self.studio, self.pid, self.base = studio, pid, base
        self.regions = sorted(regions, key=lambda r: integer(r['address']))
        self.starts = [integer(r['address']) for r in self.regions]
        self.image_size = MAX_IMAGE
        self.budget = 256 * 1024
        self.requests = 0

    def read(self, rva, size):
        if rva < 0 or size < 1 or size > MAX_HEADER or rva + size > self.image_size:
            raise ProbeError('PE 범위 오류')
        start, end = self.base + rva, self.base + rva + size
        if end > USER_LIMIT or self.budget < size or self.requests >= 96:
            raise ProbeError('PE 조회 상한 초과')
        cursor = start
        while cursor < end:
            index = bisect_right(self.starts, cursor) - 1
            if index < 0:
                raise ReadError('PE 메타데이터가 할당 영역 밖입니다')
            region = self.regions[index]
            right = self.starts[index] + integer(region['size'])
            if right <= cursor or not readable(region):
                raise ReadError('PE 메타데이터를 읽을 수 없습니다')
            cursor = min(right, end)
        self.budget -= size
        self.requests += 1
        try:
            data = self.studio.read_bytes(self.pid, start, size)
        except Exception as exc:
            raise ReadError('커널 PE 조회 실패') from exc
        if len(data) != size:
            raise ReadError('PE 조회 크기 불일치')
        return data

    def text(self, rva):
        data = bytearray()
        while len(data) < 512:
            # A name near a page/allocation boundary need not have 512 bytes after it.
            index = bisect_right(self.starts, self.base + rva + len(data)) - 1
            if index < 0:
                raise ReadError('PE 이름 주소 오류')
            available = self.starts[index] + integer(self.regions[index]['size']) - self.base - rva - len(data)
            count = min(64, 512 - len(data), self.image_size - rva - len(data), available)
            if count <= 0:
                raise ReadError('PE 이름 범위 오류')
            part = self.read(rva + len(data), count)
            if b'\0' in part:
                data.extend(part.split(b'\0', 1)[0])
                return data.decode('utf-8', errors='replace')
            data.extend(part)
        raise ProbeError('PE 이름 길이 상한 초과')


def filename(value, kind):
    name = PureWindowsPath(value.strip()).name
    if not name or name in ('.', '..') or len(name) > 260 or any(ord(c) < 32 or c in '<>:"|?*' for c in name):
        return ''
    return name if PureWindowsPath(name).suffix else name + '.' + kind.lower()


class FileOffsets:
    """Optional names may be in a copied file buffer rather than an RVA image."""
    def __init__(self, reader, sections, header_size):
        self.reader, self.sections, self.header_size = reader, sections, header_size

    def offset(self, rva, size):
        if rva < self.header_size and rva + size <= self.header_size:
            return rva
        for virtual, raw_size, raw_offset in self.sections:
            if virtual <= rva and rva + size <= virtual + raw_size:
                return raw_offset + rva - virtual
        raise ProbeError('파일 배치 RVA 범위 오류')

    def read(self, rva, size):
        return self.reader.read(self.offset(rva, size), size)

    def text(self, rva):
        return self.reader.text(self.offset(rva, 1))


def version_name(data):
    """Walk bounded VS_VERSION_INFO blocks; do not match arbitrary UTF-16 bytes."""
    values = {}
    blocks = 0

    def walk(start, end, parents=()):
        nonlocal blocks
        blocks += 1
        if blocks > 256 or len(parents) > 5 or start + 6 > end:
            raise ProbeError('버전 정보 블록 상한 오류')
        length, value_length, value_type = struct.unpack_from('<HHH', data, start)
        limit = start + length
        if length < 8 or limit > end or value_type not in (0, 1):
            raise ProbeError('버전 정보 블록 범위 오류')
        cursor = start + 6
        key_start = cursor
        while cursor + 2 <= limit and data[cursor:cursor+2] != b'\0\0':
            cursor += 2
        if cursor + 2 > limit:
            raise ProbeError('버전 정보 이름 종료 오류')
        key = data[key_start:cursor].decode('utf-16-le')
        cursor = (cursor + 2 + 3) & ~3
        value_end = cursor + value_length * (2 if value_type else 1)
        if value_end > limit:
            raise ProbeError('버전 정보 값 범위 오류')
        if (value_type == 1 and len(parents) == 3 and
                parents[:2] == ('VS_VERSION_INFO', 'StringFileInfo') and
                key in ('OriginalFilename', 'InternalName')):
            values.setdefault(key, data[cursor:value_end].decode('utf-16-le').rstrip('\0'))
        child = (value_end + 3) & ~3
        while child + 6 <= limit:
            used = walk(child, limit, parents + (key,))
            child = (child + used + 3) & ~3
        return length

    walk(0, len(data))
    return values


def resource_names(reader, rva, size):
    def part(offset, count):
        if offset < 0 or offset + count > size:
            raise ProbeError('리소스 디렉터리 범위 오류')
        return reader.read(rva + offset, count)

    def entries(offset):
        header = part(offset, 16)
        named, ids = struct.unpack_from('<HH', header, 12)
        if named + ids > 256:
            raise ProbeError('리소스 항목 상한 초과')
        if not named + ids:
            return []
        return list(struct.iter_unpack('<II', part(offset + 16, (named + ids) * 8)))

    for type_id, type_offset in entries(0):
        if type_id != 16 or not type_offset & 0x80000000:
            continue
        for _, name_offset in entries(type_offset & 0x7fffffff)[:8]:
            if not name_offset & 0x80000000:
                continue
            for _, language_offset in entries(name_offset & 0x7fffffff)[:8]:
                if language_offset & 0x80000000:
                    continue
                data_rva, length, _, _ = struct.unpack('<IIII', part(language_offset, 16))
                if not 1 <= length <= MAX_HEADER:
                    continue
                names = version_name(reader.read(data_rva, length))
                if names:
                    return names
    return {}


def probe(reader, prefix):
    offset = struct.unpack_from('<I', prefix, 60)[0]
    if not 64 <= offset <= MAX_HEADER - 24:
        raise ProbeError('PE 헤더 위치 오류')
    coff = reader.read(offset, 24)
    if coff[:4] != b'PE\0\0':
        raise ProbeError('PE 서명 오류')
    machine, sections, timestamp = struct.unpack_from('<HHI', coff, 4)
    optional_size, characteristics = struct.unpack_from('<HH', coff, 20)
    if not characteristics & 2 or not 1 <= sections <= 96 or not 96 <= optional_size <= 4096:
        raise ProbeError('PE 파일 헤더 오류')
    table_start = offset + 24 + optional_size
    if table_start + sections * 40 > MAX_HEADER:
        raise ProbeError('PE 섹션 헤더 상한 초과')
    optional = reader.read(offset + 24, optional_size)
    magic = struct.unpack_from('<H', optional)[0]
    if magic not in (0x10b, 0x20b):
        raise ProbeError('PE32 / PE32+ 헤더가 필요합니다')
    relative = 96 if magic == 0x10b else 112
    if optional_size < relative:
        raise ProbeError('선택 헤더 크기 오류')
    if machine not in ((0x14c, 0x1c4) if magic == 0x10b else (0x8664, 0xaa64, 0xa641, 0xa64e)):
        raise ProbeError('PE 아키텍처 오류')
    entry = struct.unpack_from('<I', optional, 16)[0]
    alignment, file_alignment = struct.unpack_from('<II', optional, 32)
    image_size, headers_size = struct.unpack_from('<II', optional, 56)
    if (not alignment or alignment & (alignment - 1) or not file_alignment or
            file_alignment & (file_alignment - 1) or alignment < file_alignment or
            (alignment < 4096 and alignment != file_alignment)):
        raise ProbeError('PE 정렬 오류')
    if (not 1 <= image_size <= MAX_IMAGE or image_size % alignment or
            reader.base + image_size > USER_LIMIT or not table_start + sections * 40 <= headers_size <= image_size or
            headers_size > MAX_HEADER or entry >= image_size):
        raise ProbeError('PE 이미지 크기 오류')
    reader.image_size = image_size
    table = reader.read(table_start, sections * 40)
    raw_sections = []
    for i in range(sections):
        virtual_size, section_rva, raw_size, raw_offset = struct.unpack_from('<IIII', table, i * 40 + 8)
        if section_rva + (virtual_size or raw_size) > image_size:
            raise ProbeError('PE 섹션이 이미지 크기를 벗어납니다')
        if raw_offset + raw_size <= MAX_IMAGE:
            raw_sections.append((section_rva, raw_size, raw_offset))
    count = struct.unpack_from('<I', optional, relative - 4)[0]
    if count > 16 or relative + count * 8 > optional_size:
        raise ProbeError('PE 디렉터리 개수 오류')
    directories = [struct.unpack_from('<II', optional, relative + i * 8) for i in range(count)]
    kind = 'DLL' if characteristics & 0x2000 else 'EXE'
    name, name_source, name_layout = '', 'unknown', 'unknown'
    for layout, name_reader in (('RVA', reader), ('file_offset', FileOffsets(reader, raw_sections, headers_size))):
        for index in (2, 0):
            if index >= len(directories):
                continue
            rva, length = directories[index]
            if not rva or not length or rva + length > image_size:
                continue
            try:
                if index == 2:
                    names = resource_names(name_reader, rva, length)
                    for key in ('OriginalFilename', 'InternalName'):
                        name = filename(names.get(key, ''), kind)
                        if name:
                            name_source = 'version_' + key
                            break
                elif length >= 40:
                    name_rva = struct.unpack_from('<I', name_reader.read(rva, 40), 12)[0]
                    if name_rva:
                        name = filename(name_reader.text(name_rva), kind)
                        if name:
                            name_source = 'export'
            except (ProbeError, UnicodeError, struct.error):
                # Missing/uncommitted/invalid optional metadata must not hide a valid header.
                pass
            if name:
                name_layout = layout
                break
        if name:
            break
    return {'image_size': image_size, 'size': image_size, 'name': name or 'unknown.' + kind.lower(),
            'name_source': name_source, 'pe_kind': kind, 'bits': 32 if magic == 0x10b else 64,
            'machine': hex(machine), 'entry_point': hex(reader.base + entry) if entry else '0x0',
            'timestamp': timestamp, 'header_size': headers_size, 'name_layout': name_layout}


def discover(studio, pid, regions, cancelled=lambda: False):
    groups, allocations, candidates = {}, {}, []
    stats = {'regions_checked': 0, 'mz_candidates': 0, 'pe_rejected': 0, 'read_failures': 0, 'header_images': 0}
    for region in regions:
        start, size = integer(region['address']), integer(region['size'])
        allocation = integer(region.get('allocation_base', 0)) or start
        allocations.setdefault(allocation, []).append(region)
        if integer(region['type']) == MEM_IMAGE:
            base = integer(region.get('image_base', 0)) or allocation
            item = groups.setdefault(base, {'address': hex(base), 'base': hex(base), 'image_size': 0,
                'mapped_extent': 0, 'name': '', 'path': '', 'main_image': False,
                'source': 'MEM_IMAGE', 'memory_type': 'MEM_IMAGE', 'name_source': 'kernel', 'timestamp': 0})
            item['mapped_extent'] = max(item['mapped_extent'], start + size - base)
            if region.get('image_size'):
                item['image_size'] = max(item['image_size'], integer(region['image_size']))
            if region.get('image_name'):
                item['name'] = region['image_name']
            if region.get('image_path'):
                item['path'] = region['image_path']
            if region.get('timestamp'):
                item['timestamp'] = region['timestamp']
            item['main_image'] |= bool(region.get('main_image'))
        elif readable(region) and size >= 64 and 0 < start < start + size <= USER_LIMIT:
            candidates.append((start, allocation, region))
    for base, allocation, region in candidates:
        if cancelled():
            break
        stats['regions_checked'] += 1
        reader = RegionReader(studio, pid, base, allocations[allocation])
        try:
            prefix = reader.read(0, 64)
            if prefix[:2] != b'MZ':
                continue
            stats['mz_candidates'] += 1
            metadata = probe(reader, prefix)
        except ReadError:
            stats['read_failures'] += 1
            continue
        except (ProbeError, struct.error):
            stats['pe_rejected'] += 1
            continue
        if base in groups:
            continue
        end = base + metadata['image_size']
        available = sum(max(0, min(end, integer(r['address']) + integer(r['size'])) - max(base, integer(r['address'])))
                        for r in allocations[allocation] if integer(r.get('state', 0)) == MEM_COMMIT)
        extent = max(integer(r['address']) + integer(r['size']) for r in allocations[allocation]) - base
        groups[base] = dict(metadata, address=hex(base), base=hex(base), mapped_extent=extent,
            committed_bytes=available, source='PE_HEADER', memory_type=TYPE_NAMES.get(integer(region['type']), 'OTHER'),
            path='', main_image=False, header_region_size=integer(region['size']),
            protect=region.get('protect', '0x0'), payload_complete=available == metadata['image_size'])
        stats['header_images'] += 1
    rows = []
    for base, item in sorted(groups.items()):
        item['address'] = item['base'] = f'0x{base:X}'
        item['image_size'] = item['image_size'] or item['mapped_extent']
        item.setdefault('size', item['image_size'])
        item['name'] = item['name'] or PureWindowsPath(item['path']).name or 'image_' + item['base']
        rows.append(item)
    return rows, stats
