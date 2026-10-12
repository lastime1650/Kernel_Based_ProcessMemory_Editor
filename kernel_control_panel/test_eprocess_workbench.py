"""EPROCESS decoder/catalog/HTTP regressions use synthetic bytes, never a driver."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import eprocess_workbench as E

SYSTEM = dict(architecture='x64', major=10, minor=0, build=26200, product_type=1,
              service_pack=0, ubr=9999, display_version='25H2', product_name='fixture')
ADDRESS = 0xFFFFA123456789AB
KEY = 2**63 + 37


def fixture():
    def f(name, offset, size, kind='scalar', **kwargs):
        return dict(name=name, path=name, type='ULONG', offset=offset,
                    size=size, kind=kind, **kwargs)
    return dict(schema_version=1, id='x64/windows-11/25h2', architecture='x64',
                pointer_size=8, family='windows-11', release='25h2', size=96,
                fields=[f('UniqueProcessId', 0, 8, 'pointer'), f('Counter', 8, 8),
                        f('Signed', 16, 4, signed=True), f('Flags', 20, 4),
                        f('Flags.Bits', 20, 4, 'bitfield', bit_offset=3, bit_width=2),
                        f('ImageFileName', 24, 15, 'array', array_count=15),
                        f('Nested', 40, 16, 'struct', child_fields=[f('Tag', 0, 4), f('Ptr', 8, 8, 'pointer')]),
                        f('Opaque', 56, None, 'raw', raw_span_size=8),
                        f('Counters', 64, 16, 'array', array_count=2),
                        f('SignedBits', 80, 1, 'bitfield', signed=True, bit_offset=0, bit_width=3),
                        f('Enabled', 81, 1, 'bitfield', bit_offset=7, bit_width=1),
                        f('PointerArray', 88, 8, 'array', array_count=1, element_kind='pointer')])


def bytes_fixture(pid=42):
    data = bytearray(96)
    data[:8] = pid.to_bytes(8, 'little')
    data[8:16] = KEY.to_bytes(8, 'little')
    data[16:20] = (-123).to_bytes(4, 'little', signed=True)
    data[20:24] = (3 << 3).to_bytes(4, 'little')
    data[24:39] = b'fixture.exe\0'.ljust(15, b'\0')
    data[40:44] = (7).to_bytes(4, 'little')
    data[48:56] = ADDRESS.to_bytes(8, 'little')
    data[64:72] = KEY.to_bytes(8, 'little')
    data[72:80] = (9).to_bytes(8, 'little')
    data[80], data[81] = 7, 128
    data[88:96] = ADDRESS.to_bytes(8, 'little')
    return bytes(data)


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.preset = fixture()
        self.entry = dict(id=self.preset['id'], file='fixture.json', size=96,
                          architecture='x64', release='25h2', build_numbers=[26200],
                          product_types=[1], service_pack=0, nt_major=10, nt_minor=0,
                          auto_select=True, source_url='https://www.vergiliusproject.com/fixture')
        self.save()
        self.driver = Mock()
        self.driver.read_process_object.return_value = dict(success=True, process_id=42,
            eprocess_address=f'0x{ADDRESS:016X}', process_start_key=str(KEY),
            bytes_read=96, data_hex=bytes_fixture().hex())
        self.system_provider = Mock(return_value=SYSTEM)
        self.workbench = E.Workbench(self.driver, E.Catalog(self.root), self.system_provider)

    def save(self):
        data = json.dumps(self.preset).encode()
        (self.root / 'fixture.json').write_bytes(data)
        self.entry['preset_sha256'] = hashlib.sha256(data).hexdigest()
        (self.root / 'manifest.json').write_text(json.dumps(dict(schema_version=1, presets=[self.entry])))

    def body(self):
        return dict(pid=42, expected_address=f'0x{ADDRESS:016X}', expected_start_key=str(KEY))

    def test_full_snapshot_decodes_union_bits_arrays_and_nested_fields(self):
        result = self.workbench.snapshot(self.body())
        self.assertTrue(result['success'])
        fields = {f['path']: f for f in result['fields']}
        self.assertEqual(fields['Counter']['value'], str(KEY))
        self.assertEqual(fields['Signed']['value'], '-123')
        self.assertEqual(fields['Flags.Bits']['value'], '3')
        self.assertEqual(fields['SignedBits']['value'], '-1')
        self.assertIs(fields['Enabled']['value'], True)
        self.assertEqual(fields['ImageFileName']['value'], 'fixture.exe')
        self.assertEqual(fields['Nested.Ptr']['value'], f'0x{ADDRESS:016X}')
        self.assertEqual(fields['Nested.Ptr']['offset'], 48)
        self.assertIsNone(fields['Opaque']['size'])
        self.assertEqual(fields['Counters']['value'], f'[{KEY}, 9]')
        self.assertEqual(fields['PointerArray']['value'], f'[0x{ADDRESS:016X}]')
        self.assertFalse(result['coherent_snapshot'])
        self.driver.read_process_object.assert_called_once_with(42, ADDRESS, KEY, 96)

    def test_unknown_build_arch_product_release_or_major_never_calls_driver(self):
        for changes in (dict(build=26300), dict(architecture='arm64'), dict(product_type=3),
                        dict(display_version='24H2'), dict(major=6), dict(service_pack=1)):
            with self.subTest(changes=changes):
                driver = Mock()
                workbench = E.Workbench(driver, E.Catalog(self.root), lambda: dict(SYSTEM, **changes))
                self.assertFalse(workbench.snapshot(self.body())['success'])
                driver.read_process_object.assert_not_called()

    def test_missing_or_ambiguous_or_disabled_preset_never_calls_driver(self):
        for entries in ([], [self.entry, copy.deepcopy(self.entry)], [dict(self.entry, auto_select=False)]):
            (self.root / 'manifest.json').write_text(json.dumps(dict(schema_version=1, presets=entries)))
            workbench = E.Workbench(self.driver, E.Catalog(self.root), lambda: SYSTEM)
            self.assertFalse(workbench.snapshot(self.body())['success'])
        self.driver.read_process_object.assert_not_called()

    def test_bad_hash_path_size_bitfield_or_duplicate_path_is_rejected(self):
        for mutation in ('hash', 'path', 'size', 'bit', 'duplicate'):
            with self.subTest(mutation=mutation):
                self.preset, self.entry = fixture(), dict(self.entry, file='fixture.json', size=96)
                if mutation == 'size': self.preset['fields'][0]['offset'] = 95
                if mutation == 'bit': self.preset['fields'][4]['bit_width'] = 40
                if mutation == 'duplicate': self.preset['fields'][1]['path'] = 'UniqueProcessId'
                self.save()
                if mutation == 'hash': (self.root / 'fixture.json').write_text('{}')
                if mutation == 'path':
                    self.entry['file'] = '../fixture.json'
                    (self.root / 'manifest.json').write_text(json.dumps(dict(schema_version=1, presets=[self.entry])))
                result = E.Workbench(self.driver, E.Catalog(self.root), lambda: SYSTEM).snapshot(self.body())
                self.assertFalse(result['success'])
        self.driver.read_process_object.assert_not_called()

    def test_mismatched_identity_partial_and_wrong_pid_bytes_expose_no_fields(self):
        original = self.driver.read_process_object.return_value
        for changes in (dict(bytes_read=95), dict(eprocess_address='0xFFFF000000000000'),
                        dict(process_start_key='0'), dict(process_id=43),
                        dict(data_hex=bytes_fixture(43).hex()), dict(success=False, error='partial')):
            self.driver.read_process_object.return_value = dict(original, **changes)
            result = self.workbench.snapshot(self.body())
            self.assertFalse(result['success'])
            self.assertEqual(result['fields'], [])
            self.assertEqual(result['data_hex'], '')

    def test_invalid_pid_address_key_rejected_before_driver(self):
        for key, value in [('pid', 0), ('pid', True), ('pid', 2**32),
                           ('expected_address', 0), ('expected_address', 2**64),
                           ('expected_start_key', -1), ('expected_start_key', True)]:
            with self.assertRaises(ValueError): self.workbench.snapshot(dict(self.body(), **{key:value}))
        self.driver.read_process_object.assert_not_called()

    def test_zero_start_key_and_os_info_are_cached(self):
        self.driver.read_process_object.return_value['process_start_key'] = '0'
        body = dict(self.body(), expected_start_key='0')
        self.assertTrue(self.workbench.snapshot(body)['success'])
        self.assertTrue(self.workbench.snapshot(body)['success'])
        self.workbench.info()
        self.system_provider.assert_called_once()

    def test_all_bundled_layouts_and_absolute_nested_offsets(self):
        catalog = E.Catalog()
        entries = catalog.metadata()
        self.assertEqual(len(entries), 30)
        for entry in entries:
            with self.subTest(preset=entry['id']):
                preset = catalog.load(entry)
                rows = E.field_rows(preset['fields'], bytes(preset['size']))
                self.assertTrue(rows)
                self.assertEqual(len({row['path'] for row in rows}), len(rows))
                self.assertTrue(all(0 <= row['offset'] < preset['size'] for row in rows))
        modern = catalog.load(next(e for e in entries if e['id'] == 'x64/windows-11/25h2'))
        self.assertEqual(modern['size'], 0x840)
        self.assertEqual(catalog.load(next(e for e in entries if e['id'] == 'x64/windows-11/23h2'))['size'], 0xb80)
        self.assertEqual(catalog.load(next(e for e in entries if e['id'] == 'x64/windows-10/22h2'))['size'], 0xa40)
        data = bytearray(modern['size'])
        data[0x1f0:0x1f4] = (0x80000001).to_bytes(4, 'little')
        rows = E.field_rows(modern['fields'], data)
        for name in ('JobNotReallyActive', 'InPrivate'):
            row = next(row for row in rows if row['name'] == name)
            self.assertEqual(row['offset'], 0x1f0)
            self.assertIs(row['value'], True)
        pcb = next(f for f in modern['fields'] if f['name'] == 'Pcb')
        for child in pcb['child_fields']:
            row = next(row for row in rows if row['path'] == child['path'])
            self.assertEqual(row['offset'], child['offset'])
            self.assertFalse(row['path'].startswith('Pcb.Pcb.'))

    def test_http_metadata_snapshot_failure_and_shutdown_are_mock_only(self):
        import server
        from test_asgi_client import ASGIClient
        client = ASGIClient(server.app)
        with patch.object(server.studio, 'eprocess', self.workbench):
            self.assertTrue(client.get('/api/studio/eprocess/presets').json()['match']['success'])
            result = client.post('/api/studio/eprocess/snapshot', json=self.body())
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()['process_start_key'], str(KEY))
            self.assertFalse(client.post('/api/studio/eprocess/snapshot', json=dict(self.body(), pid=0)).json()['success'])
            with patch.object(server.studio, 'closing', True):
                self.assertFalse(client.post('/api/studio/eprocess/snapshot', json=self.body()).json()['success'])
        self.assertEqual(self.driver.read_process_object.call_count, 1)


if __name__ == '__main__':
    unittest.main()
