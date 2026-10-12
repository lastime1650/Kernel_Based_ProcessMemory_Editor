"""Offline parser/data contract tests. No driver or target process is opened."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('eprocess_preset_sync', ROOT/'tools/sync_eprocess_presets.py')
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


def parse(code, links=None, sizes=None):
    layout, errors = SYNC.parse_layout(code, links)
    if errors:
        raise AssertionError(errors)
    SYNC.resolve_sizes(layout, sizes or {})
    return SYNC.flatten_fields(layout)


class ParserContracts(unittest.TestCase):
    def test_html_extracts_only_copyblock_and_type_links(self):
        raw = b"<p>ignored</p><a href='/outside'>other</a><div id='copyblock'>//0x8 bytes (sizeof)\nstruct X\n{\n struct <a href='/kernels/x64/windows-11/25h2/_A'>_A</a> Pcb; //0x0\n};</div><p>ignored too</p>"
        page = SYNC.parse_page(raw)
        self.assertNotIn('ignored', ''.join(page.code))
        self.assertEqual(page.type_links['_A'], '/kernels/x64/windows-11/25h2/_A')
        self.assertEqual(SYNC.sizeof_code(''.join(page.code)), 8)

    def test_subtree_discovery_filters_siblings_and_types(self):
        page = SYNC.Page()
        page.links = ['/kernels/x64/windows-11/25h2','/kernels/x64/windows-10/22h2',
                      '/kernels/x64/windows-11/25h2/_EPROCESS','https://evil.example/kernels/x64/windows-11/24h2']
        urls = SYNC.direct_children(page, SYNC.BASE+'/kernels/x64/windows-11', 4)
        self.assertEqual(urls, [SYNC.BASE+'/kernels/x64/windows-11/25h2'])

    def test_scalar_signed_pointer_qualifiers_and_arrays(self):
        fields = parse('''//0x30 bytes (sizeof)
struct _EPROCESS
{
 volatile LONG ExitStatus; //0x0
 VOID* volatile Token; //0x8
 UCHAR ImageFileName[15]; //0x10
 USHORT Words[2][2]; //0x20
};''')
        self.assertEqual([(f['name'], f['size'], f['kind']) for f in fields],
                         [('ExitStatus',4,'scalar'),('Token',8,'pointer'),('ImageFileName',15,'array'),('Words',8,'array')])
        self.assertTrue(fields[0]['signed'])
        self.assertFalse(fields[1]['signed'])
        self.assertEqual(fields[3]['array_dimensions'],[2,2])
        self.assertEqual(fields[3]['array_count'],4)

    def test_union_aliases_and_bit_offsets_preserved(self):
        fields = parse('''//0x8 bytes (sizeof)
struct _EPROCESS
{
 union
 {
  ULONG Flags; //0x0
  struct
  {
   ULONG Enabled:1; //0x0
   ULONG Priority:3; //0x0
   ULONG Spare:28; //0x0
  } Values; //0x0
 };
 ULONG Other:2; //0x4
 ULONG Tail:30; //0x4
};''')
        names = {f['name']:f for f in fields}
        self.assertEqual(names['Enabled']['bit_offset'],0)
        self.assertEqual(names['Priority']['bit_offset'],1)
        self.assertEqual(names['Spare']['bit_offset'],4)
        self.assertEqual(names['Other']['bit_offset'],0)
        self.assertEqual(names['Tail']['bit_offset'],2)
        self.assertEqual(names['Flags']['offset'],names['Priority']['offset'])
        self.assertIn('Values',names['Priority']['path'])
        self.assertTrue(names['Priority']['union_path'])
        self.assertEqual(names['Priority']['size'],4)

    def test_named_struct_union_paths_do_not_collapse(self):
        fields = parse('''//0x10 bytes (sizeof)
struct _EPROCESS
{
 union
 {
  struct
  {
   ULONGLONG Allowed; //0x0
   ULONGLONG Default; //0x8
  } Direct; //0x0
  struct
  {
   ULONGLONG* Allowed; //0x0
   ULONGLONG* Default; //0x8
  } Indirect; //0x0
 };
};''')
        allowed = [f for f in fields if f['name']=='Allowed']
        self.assertEqual(len(allowed),2)
        self.assertNotEqual(allowed[0]['path'],allowed[1]['path'])
        self.assertEqual([f['kind'] for f in allowed],['scalar','pointer'])

    def test_linked_size_is_used_instead_of_next_offset_gap(self):
        url = SYNC.BASE+'/kernels/x64/windows-11/25h2/_KPROCESS'
        fields = parse('''//0x30 bytes (sizeof)
struct _EPROCESS
{
 struct _KPROCESS Pcb; //0x0
 ULONG Flags; //0x20
};''', {'_KPROCESS':url}, {url:0x18})
        self.assertEqual(fields[0]['size'],0x18)
        self.assertEqual(fields[0]['size_source'],'linked_type_sizeof')
        self.assertNotIn('raw_span_size',fields[0])

    def test_unknown_composite_keeps_unknown_size_and_labeled_raw_span(self):
        fields = parse('''//0x30 bytes (sizeof)
struct _EPROCESS
{
 struct _UNPUBLISHED Unknown; //0x0
 ULONG Flags; //0x20
};''')
        self.assertIsNone(fields[0]['size'])
        self.assertEqual(fields[0]['raw_span_size'],0x20)
        self.assertEqual(fields[0]['raw_span_source'],'next_explicit_offset_gap_not_sizeof')

    def test_overflow_bitfield_and_missing_size_fail(self):
        layout, errors = SYNC.parse_layout('''//0x4 bytes (sizeof)
struct _EPROCESS
{
 ULONG TooWide:33; //0x0
};''')
        self.assertTrue(errors)
        with self.assertRaises(ValueError):
            SYNC.sizeof_code('struct _EPROCESS {};')

    def test_exact_build_mapping_never_uses_latest_for_insider_or_ambiguous_81(self):
        self.assertEqual(SYNC.mapping('windows-11','25h2')['build_numbers'],[26200])
        self.assertEqual(SYNC.mapping('windows-11','24h2')['build_numbers'],[26100])
        self.assertEqual(SYNC.mapping('windows-10','22h2')['build_numbers'],[19045])
        self.assertEqual(SYNC.mapping('server-2022','21h2')['product_types'],[2,3])
        insider = SYNC.mapping('windows-11','insider-preview-jun-2021')
        self.assertEqual(insider['build_numbers'],[])
        self.assertFalse(insider['auto_select'])
        self.assertFalse(SYNC.mapping('windows-8.1','rtm')['auto_select'])
        self.assertFalse(SYNC.mapping('windows-8.1','update-1')['auto_select'])


class DownloadedDataContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = ROOT/'presets/eprocess'
        cls.manifest = json.loads((cls.folder/'manifest.json').read_text(encoding='utf-8'))

    def test_all_real_releases_downloaded_without_missing_or_error(self):
        self.assertEqual(self.manifest['family_count'],8)
        self.assertEqual(self.manifest['release_count'],30)
        self.assertEqual(self.manifest['preset_count'],30)
        self.assertEqual(self.manifest['missing'],[])
        self.assertEqual(self.manifest['errors'],[])

    def test_fields_ranges_provenance_and_bit_bounds(self):
        for entry in self.manifest['presets']:
            data = json.loads((self.folder/entry['file']).read_text(encoding='utf-8'))
            self.assertEqual(data['architecture'],'x64')
            self.assertEqual(data['pointer_size'],8)
            self.assertEqual(len(data['content_sha256']),64)
            self.assertTrue(data['downloaded_at_utc'])
            self.assertEqual(data['size'],entry['size'])
            paths = []
            def validate(fields):
                for f in fields:
                    self.assertGreaterEqual(f['offset'],0)
                    self.assertLess(f['offset'],data['size'])
                    if f['size'] is not None:
                        self.assertLessEqual(f['offset']+f['size'],data['size'])
                    else:
                        self.assertEqual(f['size_source'],'unknown')
                    if f['kind']=='bitfield':
                        self.assertGreaterEqual(f['bit_offset'],0)
                        self.assertLessEqual(f['bit_offset']+f['bit_width'],f['size']*8)
                    if f['kind']=='pointer':
                        self.assertEqual(f['size'],8)
                        self.assertFalse(f.get('child_fields'))
                    validate(f.get('child_fields',[]))
            validate(data['fields'])
            paths = [f['path'] for f in data['fields']]
            self.assertEqual(len(paths),len(set(paths)))

    def test_25h2_tail_fields_have_explicit_offsets(self):
        data = json.loads((self.folder/'windows-11-25h2.json').read_text(encoding='utf-8'))
        fields = {f['name']:f for f in data['fields']}
        self.assertEqual(data['size'],0x840)
        self.assertEqual(fields['ThreadIndexTable']['offset'],0x800)
        self.assertEqual(fields['FreezeWorkLinks']['offset'],0x808)
        self.assertEqual(fields['FreezeWorkLinks']['size'],0x10)


if __name__ == '__main__':
    unittest.main()
