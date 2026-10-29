"""Offline tests execute the proposed detector against immutable ROM bytes."""
from pathlib import Path
import struct
import unittest

from msm5xxx_emulator.detection import audio
import json
FIXTURES = json.loads((Path(__file__).with_name('fixtures') / 'ma5_timed_transport_graphs.json').read_text())

def bl(source, target):
    delta = (target - source - 4) & 0x7fffff
    return struct.pack('<HH', 0xf000 | delta >> 12 & 0x7ff,
                       0xf800 | delta >> 1 & 0x7ff)


def fixture(shift=0):
    saved = FIXTURES[str(shift)]
    image = bytearray(saved['size'])
    for address, encoded in saved['segments']:
        data = bytes.fromhex(encoded)
        image[address:address + len(data)] = data
    return bytes(image), saved['entries']


class MA5TimedTransportTests(unittest.TestCase):
    def test_relocated_graph(self):
        for shift in (0, 0x100, 0x802):
            image, _ = fixture(shift)
            candidate = audio.find_ma5_readback_candidate(image)
            self.assertEqual(candidate['static_status'], 'candidate')
            self.assertEqual(candidate['structural_evidence']['timing_table'], (0x4000 + shift + 3) & ~3)
            self.assertIn([(0x4000 + shift + 3) & ~3, 16], candidate['nor_dependencies'])

    def test_closed_mutations(self):
        original, entries = fixture()
        cases = []
        for role, offset in [('check', 22), ('timed_wait', 20),
                             ('timed_empty', 40), ('timed_write', 24),
                             ('timed_write', 26), ('timed_block', 36),
                             ('timed_dataread', 24), ('timed_index', 18)]:
            changed = bytearray(original); changed[entries[role] + offset] ^= 1; cases.append(changed)
        changed = bytearray(original)
        changed[entries['timed_block'] + 40:entries['timed_block'] + 44] = bl(entries['timed_block'] + 40, entries['timed_delay'] + 2)
        cases.append(changed)
        for role, n, value in [('timed_status', 1, 0x4000),
                               ('timed_write', 0, 0x013ad158),
                               ('timed_dataread', 1, 0x4100)]:
            changed = bytearray(original)
            pool = (entries[role] + 0x100 + 3) & ~3
            struct.pack_into('<I', changed, pool + 4*n, value); cases.append(changed)
        changed = bytearray(original); struct.pack_into('<I', changed, 0x4000, 0); cases.append(changed)
        for index, changed in enumerate(cases):
            with self.subTest(index=index):
                self.assertEqual(audio.find_ma5_readback_candidate(bytes(changed))['static_status'], 'rejected')
        self.assertEqual(audio.find_ma5_readback_candidate(original[:0x400c])['static_status'], 'rejected')

    def test_ambiguity(self):
        first, _ = fixture()
        second, _ = fixture(0x5000)
        combined = bytearray(second)
        combined[:len(first)] = first
        self.assertEqual(audio.find_ma5_readback_candidate(bytes(combined))['reject_reason'], 'structural-ambiguous')


if __name__ == '__main__':
    unittest.main()
