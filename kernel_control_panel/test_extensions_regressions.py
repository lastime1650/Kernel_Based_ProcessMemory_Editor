"""Malformed external PE data and ownership changes that live PID tests cannot force."""
import random
import struct
import threading
import unittest
from unittest.mock import patch
from studio_extensions import LoadedPE


def image(bits=64, bound=False):
    raw = bytearray(0x3000);raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 0x3c, 0x80);raw[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', raw, 0x94, 240 if bits == 64 else 224)
    struct.pack_into('<H', raw, 0x98, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', raw, 0x98+56, len(raw))
    relative = 112 if bits == 64 else 96
    struct.pack_into('<I', raw, 0x98+relative-4, 16)
    struct.pack_into('<II', raw, 0x98+relative, 0x1000, 256)
    struct.pack_into('<II', raw, 0x98+relative+8, 0x1800, 40)
    struct.pack_into('<IIHHIIIIIII', raw, 0x1000, 0, 0, 0, 0, 0, 5, 2, 1, 0x1100, 0x1200, 0x1300)
    struct.pack_into('<II', raw, 0x1100, 0x1500, 0x1080)
    struct.pack_into('<I', raw, 0x1200, 0x1700)
    raw[0x1700:0x1705] = b'Test\0';raw[0x1080:0x108b] = b'other.Real\0'
    struct.pack_into('<IIIII', raw, 0x1800, 0 if bound else 0x1a00, 0, 0, 0x1900, 0x1b00)
    raw[0x1900:0x190d] = b'kernel32.dll\0';raw[0x1c02:0x1c08] = b'Sleep\0'
    fmt = '<QQQ' if bits == 64 else '<III'
    struct.pack_into(fmt, raw, 0x1a00, 0x1c00, (1 << (bits-1)) | 7, 0)
    struct.pack_into(fmt, raw, 0x1b00, 0xe0001000, 0xe0002000, 0)
    return raw


class Memory:
    def __init__(self, data): self.data = data;self.reads = 0
    def read_bytes(self, pid, address, size):
        self.reads += 1
        if self.reads > 500: raise AssertionError('unbounded reads')
        offset = address-0x10000
        if offset < 0 or offset+size > len(self.data): raise AssertionError('out-of-image read')
        return bytes(self.data[offset:offset+size])


class ExtensionRegressionTests(unittest.TestCase):
    def test_PE32_and_PE64_names_ordinals_and_forwarders(self):
        for bits in (32,64):
            pe = LoadedPE(Memory(image(bits)), 1, 0x10000)
            exports = pe.exports();imports, truncated = pe.imports()
            self.assertEqual(exports[0]['name'], 'Test');self.assertEqual(exports[1]['forwarder'], 'other.Real')
            self.assertEqual(exports[0]['ordinal'], 5)
            self.assertEqual(imports[0]['name'], 'Sleep');self.assertEqual(imports[1]['name'], '#7')
            self.assertFalse(truncated)

    def test_bound_PE32_IAT_is_not_mistaken_for_ordinals(self):
        pe = LoadedPE(Memory(image(32, True)), 1, 0x10000)
        imports, _ = pe.imports()
        self.assertEqual([r['name'] for r in imports], ['<bound IAT>', '<bound IAT>'])
        self.assertIsNone(imports[0]['by_ordinal'])

    def test_bad_directory_and_ordinal_rejected(self):
        raw = image();struct.pack_into('<II', raw, 0x98+112, 0x2fff, 40)
        with self.assertRaises(ValueError): LoadedPE(Memory(raw), 1, 0x10000).exports()
        raw = image();struct.pack_into('<H', raw, 0x1300, 2)
        with self.assertRaises(ValueError): LoadedPE(Memory(raw), 1, 0x10000).exports()

    def test_random_external_header_mutations_are_bounded(self):
        rng = random.Random(20261003);rejected = 0
        positions = [0x3c,0x94,0x98,0x98+56,0x98+108,0x98+112,0x98+116,0x1014,0x1018,0x101c,0x1020,0x1024]
        for _ in range(256):
            raw = image();struct.pack_into('<I', raw, rng.choice(positions), rng.getrandbits(32))
            try: LoadedPE(Memory(raw), 1, 0x10000).exports()
            except ValueError: rejected += 1
        self.assertGreater(rejected, 230)

    def test_freeze_never_writes_to_reused_PID(self):
        import server
        entry = server.WatchEntry('test', 1, '0x10000', 0x10000, 'int32', frozen=True, frozen_val=7, identity='original')
        with patch.object(server, 'watch_table', [entry]), patch.object(server.driver, 'query_process_info', return_value={'success':True,'exit_status':259,'process_start_key':'replacement'}), patch.object(server.driver, 'write_process_memory') as write:
            server.maintain_frozen_values();write.assert_not_called()
        self.assertFalse(entry.frozen);self.assertTrue(entry.error)

    def test_watch_write_failure_disarms_freeze(self):
        import server
        entry = server.WatchEntry('test', 1, '0x10000', 0x10000, 'int32', frozen=True, frozen_val=7)
        with patch.object(server, 'watch_table', [entry]), patch.object(server.driver, 'write_process_memory', return_value={'success':False,'bytes_written':0}) as write:
            server.maintain_frozen_values();server.maintain_frozen_values();self.assertEqual(write.call_count, 1)
        self.assertFalse(entry.frozen)


if __name__ == '__main__': unittest.main(verbosity=2)
