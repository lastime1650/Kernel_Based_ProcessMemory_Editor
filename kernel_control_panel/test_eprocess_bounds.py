"""Kernel size limits must remain synchronized with verified local layouts."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.generate_eprocess_bounds import generate


class BoundsTests(unittest.TestCase):
    def test_bundled_modern_build_limits_and_no_guessed_newer_build(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'limits.h'
            bounds = generate(root / 'presets/eprocess/manifest.json', output)
            self.assertEqual(bounds[26200], 0x840)
            self.assertEqual(bounds[26100], 0x840)
            self.assertEqual(bounds[22631], 0xb80)
            self.assertEqual(bounds[19045], 0xa40)
            self.assertNotIn(28000, bounds)
            self.assertNotIn(26300, bounds)
            self.assertTrue(all(build >= 15063 for build in bounds))
            self.assertIn('default: return 0;', output.read_text())

    def test_checked_in_kernel_limits_match_the_local_preset_data(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'limits.h'
            generate(root / 'presets/eprocess/manifest.json', output)
            checked_in = root.parent / 'helper/process_object_layouts.h'
            self.assertEqual(output.read_bytes(), checked_in.read_bytes())

    def fixture(self, root, sizes):
        entries = []
        for i, size in enumerate(sizes):
            preset = dict(id=str(i), size=size)
            raw = json.dumps(preset).encode()
            path = root / f'{i}.json'
            path.write_bytes(raw)
            entries.append(dict(id=str(i), file=path.name, size=size, architecture='x64',
                                nt_major=10, nt_minor=0, build_numbers=[26200], auto_select=True,
                                preset_sha256=hashlib.sha256(raw).hexdigest()))
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps(dict(schema_version=1, presets=entries)))
        return manifest, entries

    def test_shared_build_uses_the_smaller_object_allocation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest, _ = self.fixture(root, [0xb80, 0x840])
            self.assertEqual(generate(manifest, root / 'limits.h'), {26200:0x840})

    def test_corruption_or_unbounded_layout_never_generates_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest, entries = self.fixture(root, [0x840])
            (root / '0.json').write_text('{}')
            with self.assertRaises(ValueError): generate(manifest, root / 'limits.h')
            manifest, _ = self.fixture(root, [4097])
            with self.assertRaises(ValueError): generate(manifest, root / 'limits.h')
            manifest, entries = self.fixture(root, [0x840])
            entries[0]['file'] = '../escape.json'
            manifest.write_text(json.dumps(dict(schema_version=1, presets=entries)))
            with self.assertRaises(ValueError): generate(manifest, root / 'limits.h')


if __name__ == '__main__':
    unittest.main()
