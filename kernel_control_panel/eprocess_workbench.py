"""Offline OS layouts and identity-bound EPROCESS snapshots; no pointer following."""
from __future__ import annotations

import copy
import ctypes as C
import hashlib
import json
import platform
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from runtime_paths import bundle_root

MAX_SNAPSHOT = 4096
MAX_PRESET_BYTES = 4 * 1024 * 1024


def unsigned(value, maximum, label):
    if isinstance(value, bool):
        raise ValueError(f'{label}: 정수가 필요합니다')
    text = str(value).strip()
    number = int(text, 16 if text.lower().startswith('0x') else 10)
    if not 0 <= number <= maximum:
        raise ValueError(f'{label}: 범위를 확인하세요')
    return number


def detect_system():
    """RtlGetVersion avoids application-manifest version virtualization."""
    class Version(C.Structure):
        _fields_ = [('size', C.c_uint32), ('major', C.c_uint32),
                    ('minor', C.c_uint32), ('build', C.c_uint32),
                    ('platform', C.c_uint32), ('csd', C.c_wchar * 128),
                    ('sp_major', C.c_uint16), ('sp_minor', C.c_uint16),
                    ('suite', C.c_uint16), ('product_type', C.c_uint8),
                    ('reserved', C.c_uint8)]
    version = Version()
    version.size = C.sizeof(version)
    api = C.WinDLL('ntdll')
    api.RtlGetVersion.argtypes = [C.POINTER(Version)]
    api.RtlGetVersion.restype = C.c_int32
    if api.RtlGetVersion(C.byref(version)) < 0:
        raise OSError('현재 Windows 버전을 조회하지 못했습니다')

    # Native architecture also rejects x64 emulation on ARM64.
    class Architecture(C.Structure):
        _fields_ = [('architecture', C.c_uint16), ('reserved', C.c_uint16)]
    class ArchitectureUnion(C.Union):
        _fields_ = [('oem_id', C.c_uint32), ('native', Architecture)]
    class SystemInfo(C.Structure):
        _fields_ = [('processor', ArchitectureUnion), ('page_size', C.c_uint32),
                    ('minimum', C.c_void_p), ('maximum', C.c_void_p),
                    ('mask', C.c_size_t), ('processors', C.c_uint32),
                    ('processor_type', C.c_uint32), ('allocation_granularity', C.c_uint32),
                    ('level', C.c_uint16), ('revision', C.c_uint16)]
    kernel = C.WinDLL('kernel32')
    kernel.GetNativeSystemInfo.argtypes = [C.POINTER(SystemInfo)]
    kernel.GetNativeSystemInfo.restype = None
    info = SystemInfo()
    kernel.GetNativeSystemInfo(C.byref(info))
    architecture = {9: 'x64', 12: 'arm64', 0: 'x86'}.get(info.processor.native.architecture, 'unknown')
    details = {'architecture': architecture, 'major': version.major, 'minor': version.minor,
               'build': version.build, 'product_type': version.product_type,
               'service_pack': version.sp_major, 'ubr': None, 'display_version': '',
               'product_name': platform.system()}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            for name, field in [('UBR', 'ubr'), ('DisplayVersion', 'display_version'),
                                ('ProductName', 'product_name')]:
                try:
                    details[field] = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    pass
    except OSError:
        pass
    return details


def field_rows(fields, data, parent_path='', base_offset=0):
    """Decode declared little-endian values; unknown composite spans remain raw."""
    result = []
    for field in fields:
        absolute_child = bool(parent_path) and 'relative_offset' in field
        offset = int(field['offset']) if absolute_child else base_offset + int(field['offset'])
        name = str(field['name'])
        path = str(field.get('path') or name)
        if parent_path and not absolute_child:
            path = parent_path + '.' + path
        declared_size = field.get('size')
        span = declared_size if declared_size is not None else field.get('raw_span_size', 0)
        size = int(span or 0)
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError(f'프리셋 필드 범위 오류: {path}')
        raw = data[offset:offset + size]
        kind = field.get('kind', 'raw')
        value = raw.hex(' ').upper()
        storage = None
        if kind == 'pointer' and size == 8:
            storage = int.from_bytes(raw, 'little')
            value = f'0x{storage:016X}'
        elif kind == 'bitfield':
            start, width = int(field['bit_offset']), int(field['bit_width'])
            if width <= 0 or start < 0 or start + width > size * 8:
                raise ValueError(f'프리셋 비트 범위 오류: {path}')
            storage = (int.from_bytes(raw, 'little') >> start) & ((1 << width) - 1)
            if field.get('signed') and storage & (1 << (width - 1)):
                storage -= 1 << width
            value = bool(storage) if width == 1 else str(storage)
        elif kind == 'scalar' and size in (1, 2, 4, 8):
            clean_type = field.get('type', '').replace('volatile', '').replace('const', '').strip()
            if clean_type in ('FLOAT', 'DOUBLE') and size in (4, 8):
                value = repr(struct.unpack('<f' if size == 4 else '<d', raw)[0])
            else:
                storage = int.from_bytes(raw, 'little', signed=bool(field.get('signed')))
                value = str(storage)
        elif kind == 'array':
            count = int(field.get('array_count') or 0)
            if name == 'ImageFileName' and size:
                value = raw.split(b'\0', 1)[0].decode('ascii', errors='replace')
            elif count > 0 and size % count == 0:
                element_size = size // count
                if element_size in (1, 2, 4, 8):
                    pointer_elements = field.get('element_kind') == 'pointer'
                    values = [int.from_bytes(raw[i:i + element_size], 'little',
                                             signed=bool(field.get('signed')) and not pointer_elements)
                              for i in range(0, min(size, element_size * 32), element_size)]
                    value = '[' + ', '.join(f'0x{item:016X}' if pointer_elements else str(item) for item in values)
                    value += (', …' if count > 32 else '') + ']'
        elif kind in ('struct', 'union'):
            value = f"{field.get('type', kind)} · {size} bytes"
        row = {'path': path, 'name': name, 'type': field.get('type', ''), 'offset': offset,
               'offset_hex': f'0x{offset:X}', 'size': declared_size,
               'raw_span_size': field.get('raw_span_size'), 'kind': kind,
               'value': value, 'raw_hex': raw.hex().upper(), 'depth': path.count('.'),
               'size_source': field.get('size_source', ''),
               'container_path': field.get('container_path', ''),
               'union_path': field.get('union_path', '')}
        if kind == 'bitfield':
            row.update(bit_offset=field['bit_offset'], bit_width=field['bit_width'])
        if storage is not None:
            # Decimal strings preserve kernel addresses and 64-bit counters in JSON.
            row['numeric_value'] = str(storage)
        result.append(row)
        children = field.get('child_fields') or []
        if children:
            result.extend(field_rows(children, data, path, offset))
    return result


class Catalog:
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else bundle_root() / 'presets' / 'eprocess'
        self.entries = None
        self.loaded = {}
        self.lock = threading.RLock()

    def metadata(self):
        with self.lock:
            if self.entries is None:
                manifest = self.root / 'manifest.json'
                if not manifest.is_file():
                    raise ValueError('로컬 EPROCESS 프리셋 목록이 없습니다')
                if manifest.stat().st_size > MAX_PRESET_BYTES:
                    raise ValueError('프리셋 목록이 너무 큽니다')
                payload = json.loads(manifest.read_text(encoding='utf-8-sig'))
                if payload.get('schema_version') != 1 or not isinstance(payload.get('presets'), list):
                    raise ValueError('프리셋 목록 형식 오류')
                self.entries = payload['presets']
            return copy.deepcopy(self.entries)

    def match(self, system):
        if system.get('architecture') != 'x64':
            return {'success': False, 'reason': 'x64 네이티브 Windows 프리셋만 지원합니다'}
        candidates = []
        for preset in self.metadata():
            if (preset.get('auto_select', True)
                    and preset.get('architecture') == system['architecture']
                    and preset.get('nt_major', system.get('major')) == system.get('major')
                    and preset.get('nt_minor', system.get('minor')) == system.get('minor')
                    and system['build'] in preset.get('build_numbers', [])
                    and system['product_type'] in preset.get('product_types', [])
                    and int(preset.get('service_pack') or 0) == int(system.get('service_pack') or 0)):
                release = str(preset.get('release', '')).casefold()
                display = str(system.get('display_version', '')).casefold()
                if display and release.endswith(('h2', 'h1')):
                    if display != release:
                        continue
                candidates.append(preset)
        if len(candidates) != 1:
            return {'success': False,
                    'reason': '현재 OS의 아키텍처·정확한 기본 빌드·제품 종류·서비스 팩과 일치하는 프리셋이 없습니다'
                              if not candidates else '현재 OS에 맞는 프리셋이 여러 개여서 자동 선택하지 않았습니다'}
        preset = candidates[0]
        return {'success': True, 'preset': preset,
                'reason': '기본 빌드 일치. 누적 업데이트(UBR)별 레이아웃 보증은 사이트에서 제공하지 않습니다.'}

    def load(self, entry):
        with self.lock:
            key = entry['id']
            if key in self.loaded:
                return self.loaded[key]
            path = (self.root / str(entry['file'])).resolve()
            if not path.is_relative_to(self.root.resolve()) or not path.is_file():
                raise ValueError('프리셋 파일 경로 오류')
            raw = path.read_bytes()
            if len(raw) > MAX_PRESET_BYTES:
                raise ValueError('프리셋 파일이 너무 큽니다')
            expected_hash = entry.get('sha256') or entry.get('preset_sha256')
            if expected_hash and hashlib.sha256(raw).hexdigest() != expected_hash:
                raise ValueError('프리셋 파일 무결성 오류')
            preset = json.loads(raw.decode('utf-8-sig'))
            if (preset.get('schema_version') != 1 or preset.get('id') != key
                    or preset.get('architecture') != 'x64' or preset.get('pointer_size') != 8
                    or not 0 < int(preset.get('size', 0)) <= MAX_SNAPSHOT
                    or preset.get('size') != entry.get('size')
                    or not isinstance(preset.get('fields'), list) or not preset['fields']):
                raise ValueError('EPROCESS 프리셋 ABI 또는 크기 오류')
            rows = field_rows(preset['fields'], bytes(preset['size']))
            if not any(row['name'] == 'UniqueProcessId' and row['size'] == 8 for row in rows):
                raise ValueError('EPROCESS 프로세스 식별 필드가 없습니다')
            if len(rows) > 20000 or len({row['path'] for row in rows}) != len(rows):
                raise ValueError('프리셋 필드 개수 또는 경로 오류')
            self.loaded[key] = preset
            return preset


class Workbench:
    def __init__(self, driver, catalog=None, system_provider=None):
        self.driver = driver
        self.catalog = catalog or Catalog()
        self.system_provider = system_provider or detect_system
        self.system = None
        self.context = None
        self.lock = threading.RLock()

    def _context(self):
        try:
            with self.lock:
                if self.context is not None:
                    return copy.deepcopy(self.context)
                if self.system is None:
                    self.system = dict(self.system_provider())
                system = dict(self.system)
            match = self.catalog.match(system)
            if match['success']:
                preset = self.catalog.load(match['preset'])
                match['preset']['field_count'] = len(field_rows(preset['fields'], bytes(preset['size'])))
            self.context = {'success': True, 'system': system, 'match': match,
                            'target_interval_ms': 10, 'readonly': True}
            return copy.deepcopy(self.context)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            return {'success': False, 'error': str(exc), 'match': {'success': False, 'reason': str(exc)},
                    'system': dict(self.system or {}), 'presets': [], 'readonly': True}

    def info(self):
        result = self._context()
        if result['success']:
            result['presets'] = self.catalog.metadata()
        return result

    def snapshot(self, body):
        started = time.perf_counter()
        pid = unsigned(body.get('pid', 0), 0xffffffff, 'PID')
        expected_address = unsigned(body.get('expected_address', 0), 0xffffffffffffffff, 'EPROCESS 주소')
        expected_key = unsigned(body.get('expected_start_key', -1), 0xffffffffffffffff, '프로세스 시작 키')
        if not pid or not expected_address:
            raise ValueError('선택된 PID와 EPROCESS 주소가 필요합니다')
        details = self._context()
        if not details['success'] or not details['match']['success']:
            return {'success': False, 'error': details.get('error') or details['match']['reason'],
                    'system': details['system'], 'preset_match': False, 'fields': [], 'data_hex': ''}
        entry = details['match']['preset']
        preset = self.catalog.load(entry)
        response = self.driver.read_process_object(pid, expected_address, expected_key, preset['size'])
        if not response.get('success'):
            return dict(response, fields=[], data_hex='', system=details['system'], preset=entry)
        raw = bytes.fromhex(response.get('data_hex', ''))
        if (len(raw) != preset['size'] or response.get('bytes_read') != preset['size']
                or response.get('eprocess_address') != f'0x{expected_address:016X}'
                or str(response.get('process_start_key')) != str(expected_key)
                or response.get('process_id') != pid):
            return {'success': False, 'error': 'EPROCESS 응답 크기 또는 대상 일치 검증에 실패했습니다',
                    'identity_mismatch': True, 'fields': [], 'data_hex': ''}
        rows = field_rows(preset['fields'], raw)
        pid_rows = [row for row in rows if row['name'] == 'UniqueProcessId' and row['size'] == 8]
        if not pid_rows or any(int(row['numeric_value']) != pid for row in pid_rows):
            return {'success': False, 'error': '프리셋 UniqueProcessId가 선택 PID와 다릅니다. OS 레이아웃을 확인하세요.',
                    'preset_mismatch': True, 'fields': [], 'data_hex': ''}
        return dict(response, system=details['system'], preset=entry, fields=rows,
                    size=preset['size'], sampled_at=datetime.now(timezone.utc).isoformat(),
                    timing_ms=round((time.perf_counter() - started) * 1000, 3),
                    readonly=True, coherent_snapshot=False)
