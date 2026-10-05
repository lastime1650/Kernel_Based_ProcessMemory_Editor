"""Header-only, private, mapped and malformed PE discovery regressions."""
import random
import struct
import unittest

from image_workbench import Workbench
from memory_images import discover

BASE = 0x100000


def pe(bits=64, dll=False, name=''):
    data = bytearray(0x4000)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 240 if bits == 64 else 224
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if bits == 64 else 0x14c,
                     1, 12345, 0, 0, optional_size, 2 | (0x2000 if dll else 0))
    struct.pack_into('<H', data, 0x98, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', data, 0x98 + 16, 0x1200)
    struct.pack_into('<II', data, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into('<II', data, 0x98 + 56, 0x4000, 0x200)
    relative = 112 if bits == 64 else 96
    struct.pack_into('<I', data, 0x98 + relative - 4, 16)
    section = 0x98 + optional_size
    data[section:section+5] = b'.text'
    struct.pack_into('<IIII', data, section + 8, 0x3000, 0x1000, 0x3000, 0x200)
    struct.pack_into('<I', data, section + 36, 0x60000020)
    if name:
        struct.pack_into('<II', data, 0x98 + relative, 0x1000, 0x200)
        struct.pack_into('<I', data, 0x1000 + 12, 0x1100)
        raw = name.encode() + b'\0'
        data[0x1100:0x1100+len(raw)] = raw
    data[0x1200] = 0xc3
    return data


def block(key, value=b'', children=(), text=False):
    content = bytearray(b'\0' * 6 + (key + '\0').encode('utf-16-le'))
    content += b'\0' * (-len(content) % 4)
    content += value
    if children:
        content += b'\0' * (-len(content) % 4)
        for child in children:
            content += child
            content += b'\0' * (-len(content) % 4)
    struct.pack_into('<HHH', content, 0, len(content), len(value)//2 if text else len(value), int(text))
    return content


def add_version(data, name, key='OriginalFilename'):
    version = block('VS_VERSION_INFO', children=[block('StringFileInfo', children=[
        block('040904B0', children=[block(key, (name + '\0').encode('utf-16-le'), text=True)])])])
    opt = 0x98
    relative = 112 if struct.unpack_from('<H', data, opt)[0] == 0x20b else 96
    struct.pack_into('<II', data, opt + relative + 16, 0x2000, 0x800)
    for offset, item_id, target in ((0, 16, 0x80000020), (0x20, 1, 0x80000040), (0x40, 1033, 0x60)):
        struct.pack_into('<HH', data, 0x2000 + offset + 12, 0, 1)
        struct.pack_into('<II', data, 0x2000 + offset + 16, item_id, target)
    struct.pack_into('<IIII', data, 0x2060, 0x2100, len(version), 1200, 0)
    data[0x2100:0x2100+len(version)] = version


def region(base=BASE, size=0x4000, allocation=BASE, kind=0x20000, **extra):
    return dict(address=hex(base), size=size, allocation_base=hex(allocation), type=hex(kind),
                state='0x1000', protect='0x2', readable=True, guarded=False, **extra)


class Memory:
    def __init__(self, data, regions=None):
        self.data = data
        self.regions = regions or [region(size=len(data))]
        self.reads = []
        self.key = 'original'
        self.fail_at = None

    def identity(self, pid):
        return self.key

    def operate(self, op, args):
        assert op == 'regions'
        return dict(success=True, results=self.regions, truncated=False)

    def read_bytes(self, pid, address, size):
        self.reads.append((address, size))
        if address == self.fail_at:
            raise RuntimeError('target exited')
        start = address - BASE
        if not 0 <= start < start + size <= len(self.data):
            raise AssertionError('probe read escaped available memory')
        return bytes(self.data[start:start+size])


class MemoryImageTests(unittest.TestCase):
    def catalog(self, source):
        return Workbench(source, symbols=object()).images(1)

    def test_read_only_PE32_and_PE64_EXE_DLL_discovered_without_MEM_IMAGE(self):
        for bits in (32, 64):
            for dll in (False, True):
                source = Memory(pe(bits, dll))
                result = self.catalog(source)
                row = result['results'][0]
                self.assertEqual((row['source'], row['memory_type'], row['image_size'], row['bits']),
                                 ('PE_HEADER', 'MEM_PRIVATE', 0x4000, bits))
                self.assertEqual(row['name'], 'unknown.dll' if dll else 'unknown.exe')
                self.assertEqual(result['discovery']['header_images'], 1)

    def test_one_4KB_header_page_has_declared_image_size_and_partial_coverage(self):
        source = Memory(pe()[:4096])
        row = self.catalog(source)['results'][0]
        self.assertEqual((row['header_region_size'], row['image_size'], row['committed_bytes']), (4096, 0x4000, 4096))
        self.assertFalse(row['payload_complete'])
        self.assertTrue(all(start + size <= BASE + 4096 for start, size in source.reads))

    def test_split_read_only_header_and_executable_payload_share_one_image(self):
        data = pe(dll=True, name='Unlisted.dll')
        source = Memory(data, [region(size=4096), region(BASE+4096, 0x3000)])
        row = self.catalog(source)['results'][0]
        self.assertEqual((row['name'], row['name_source'], row['image_size']), ('Unlisted.dll', 'export', 0x4000))
        self.assertTrue(row['payload_complete'])

    def test_version_original_filename_and_internal_name(self):
        for key in ('OriginalFilename', 'InternalName'):
            data = pe();add_version(data, 'PrivateProgram.exe', key)
            row = self.catalog(Memory(data))['results'][0]
            self.assertEqual((row['name'], row['name_source']), ('PrivateProgram.exe', 'version_' + key))

    def test_file_buffer_metadata_uses_raw_offsets(self):
        data = pe();add_version(data, 'CopiedFile.exe')
        raw = data[:0x200] + data[0x1000:]
        row = self.catalog(Memory(raw, [region(size=len(raw), kind=0x40000)]))['results'][0]
        self.assertEqual((row['name'], row['name_layout'], row['memory_type']), ('CopiedFile.exe', 'file_offset', 'MEM_MAPPED'))

    def test_bad_optional_names_do_not_hide_valid_header_or_invent_filename(self):
        data = pe(dll=True, name='bad:name.dll')
        struct.pack_into('<II', data, 0x98 + 112 + 16, 0x3ff0, 4096)
        row = self.catalog(Memory(data))['results'][0]
        self.assertEqual(row['name'], 'unknown.dll')

    def test_MZ_only_corrupt_sizes_offsets_sections_and_machine_rejected(self):
        mutations = [(60, '<I', 0xffffffff), (0x80, '<I', 0), (0x84, '<H', 0),
                     (0x86, '<H', 97), (0x96, '<H', 0), (0x98+56, '<I', 0xffffffff),
                     (0x98+60, '<I', 128), (0x98+32, '<I', 3), (0x98+108, '<I', 17),
                     (0x98+240+12, '<I', 0x4000)]
        for offset, fmt, value in mutations:
            data = pe();struct.pack_into(fmt, data, offset, value)
            result = self.catalog(Memory(data))
            self.assertFalse(result['results'], (offset, result))

    def test_reserved_guarded_unreadable_regions_never_read(self):
        for field, value in (('state', '0x2000'), ('guarded', True), ('readable', False), ('protect', '0x102')):
            row = region();row[field] = value
            source = Memory(pe(), [row]);self.assertFalse(self.catalog(source)['results'])
            self.assertFalse(source.reads)

    def test_name_pointer_into_another_allocation_never_read(self):
        source = Memory(pe(name='Other.exe'), [region(size=4096), region(BASE+4096, 0x3000, allocation=BASE+4096)])
        row = self.catalog(source)['results'][0]
        self.assertEqual(row['name'], 'unknown.exe')
        self.assertFalse(any(start == BASE+0x1100 for start, _ in source.reads))

    def test_MEM_IMAGE_metadata_and_split_regions_remain_one_row(self):
        source = Memory(pe(), [region(size=4096, kind=0x1000000, image_base=hex(BASE), image_name='Original.exe', image_size=0x4000),
                               region(BASE+4096, 0x3000, kind=0x1000000, image_base=hex(BASE))])
        row = self.catalog(source)['results'][0]
        self.assertEqual((row['name'], row['source'], row['image_size']), ('Original.exe', 'MEM_IMAGE', 0x4000))
        self.assertFalse(source.reads)

    def test_failed_read_does_not_abort_other_regions(self):
        data = pe();data += pe(name='StillPresent.exe')
        source = Memory(data, [region(), region(BASE+0x4000, allocation=BASE+0x4000)])
        source.fail_at = BASE
        result = self.catalog(source)
        self.assertEqual(result['results'][0]['name'], 'StillPresent.exe')
        self.assertEqual(result['discovery']['read_failures'], 1)

    def test_identity_change_discards_whole_catalog(self):
        source = Memory(pe())
        read = source.read_bytes
        def changed(*args):
            source.key = 'replacement'
            return read(*args)
        source.read_bytes = changed
        with self.assertRaisesRegex(ValueError, '교체'):
            self.catalog(source)

    def test_cancelled_discovery_is_explicitly_truncated(self):
        source = Memory(pe());result = Workbench(source, symbols=object()).images(1, cancelled=lambda: True)
        self.assertTrue(result['cancelled']);self.assertTrue(result['truncated']);self.assertFalse(source.reads)

    def test_random_MZ_header_mutations_are_bounded(self):
        rng = random.Random(20261004)
        for _ in range(100):
            data = pe();struct.pack_into('<I', data, rng.choice([60, 0x98+56, 0x98+60, 0x98+108]), rng.getrandbits(32))
            source = Memory(data);self.catalog(source)
            self.assertLess(len(source.reads), 100)


if __name__ == '__main__':
    unittest.main()
