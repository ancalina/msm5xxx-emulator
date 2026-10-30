"""Synthetic gated scanner programs; no firmware byte fixtures."""
import struct
import unittest

from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.input import find_board_status_input
from msm5xxx_emulator.detection.input_scanner_gated import gated_scanner_at


def gated_scanner(start=0x100, address=0x03000674, mask=0x20):
    image = bytearray(b'\xff' * 0x1000)
    join, low, event = start + 0x80, start + 0x60, 0x600
    pool = start + 0x300

    def words(pc, *values):
        struct.pack_into('<' + 'H' * len(values), image, pc, *values)

    def literal(pc, reg, value):
        nonlocal pool
        pool = (pool + 3) & ~3
        words(pc, 0x4800 | reg << 8 | (pool - ((pc + 4) & ~3)) // 4)
        struct.pack_into('<I', image, pool, value)
        pool += 4

    def call(pc, target):
        delta = target - pc - 4
        words(pc, 0xF000 | (delta >> 12 & 2047), 0xF800 | (delta >> 1 & 2047))

    def jump(pc, target):
        words(pc, 0xE000 | ((target - pc - 4) // 2 & 2047))

    state, display, gate, inhibit = 0x01002000, 0x01004000, 0x01005000, 0x01006000
    words(start, 0xB5F0)
    literal(start + 2, 0, address)
    words(start + 4, 0x7800, 0x2300 | mask)
    literal(start + 8, 6, address)
    words(start + 10, 0x4018, 0x3610, 0x2800, 0xD100)
    jump(start + 18, low)
    literal(start + 20, 5, 0x01001000)
    words(start + 22, 0x7828, 0x2800, 0xD001, 0x2700, 0xE000, 0x2701)
    literal(start + 34, 4, state)
    jump(start + 36, join)
    literal(low, 4, state)
    words(low + 2, 0x2700)
    jump(low + 4, join)
    literal(join, 3, 0x01007000)
    literal(join + 2, 0, 0x100)
    words(join + 4, 0x2400, 0x18C5)
    literal(join + 8, 0, display)
    words(join + 10, 0x2F00)
    literal(join + 12, 1, inhibit)
    literal(join + 14, 2, gate)
    words(join + 16, 0xD029)
    words(join + 0x12, 0x7893, 0x2B00, 0xD000, 0xE07A, 0x7809, 0x2900, 0xD000, 0xE076)
    literal(join + 0x22, 1, inhibit + 1)
    words(join + 0x24, 0x7809, 0x2900, 0xD000, 0xE071)
    literal(join + 0x2C, 7, state)
    words(join + 0x2E, 0x7A79, 0x3101, 0x0609, 0x0E09, 0x7279, 0x2901,
          0xDA00, 0xE068, 0x2101, 0x7279, 0x72BB, 0x7091, 0x723B, 0x71C1, 0x245F, 0x1C20)
    call(join + 0x4E, event)
    literal(join + 0x52, 0, 0x01008000)
    words(join + 0x54, 0x7800, 0x2800, 0xD100, 0xE059, 0x7B29, 0x2001)
    call(join + 0x60, 0x700)
    words(join + 0x64, 0xE054)
    literal(join + 0x66, 7, state)
    words(join + 0x68, 0x7A3E, 0x2E00, 0xD150, 0x7809, 0x2900, 0xD14D)
    literal(join + 0x74, 1, inhibit + 1)
    words(join + 0x76, 0x7809, 0x2900, 0xD149)
    literal(join + 0x7C, 1, 0x01009000)
    words(join + 0x7E, 0x7809, 0x2900, 0xD145)
    literal(join + 0x84, 1, 0x100)
    words(join + 0x86, 0x3150, 0x1859, 0x7889, 0x2900, 0xD03F,
          0x7AB9, 0x3101, 0x0609, 0x0E09, 0x72B9, 0x2905, 0xDB38,
          0x2101, 0x72B9, 0x2300, 0x727B, 0x7239, 0x7093, 0x71C3)
    literal(join + 0xAC, 0, 0x01008000)
    words(join + 0xAE, 0x2460, 0x7800, 0x2800, 0xD003, 0x7B29, 0x2001)
    call(join + 0xBA, 0x700)
    literal(join + 0xBE, 0, 0x0100A000)
    words(join + 0xC0, 0x7800, 0x2800, 0xD11E, 0x2001)
    for offset, target in ((0xC8, 0x720), (0xCC, 0x740), (0xE6, 0x760),
                           (0xEA, 0x740), (0x100, 0x760)):
        call(join + offset, target)
    literal(join + 0xD0, 1, 0x0100B000)
    words(join + 0xD2, 0x2310, 0x780A)
    literal(join + 0xD6, 7, address)
    words(join + 0xD8, 0x439A, 0x700A, 0x7809, 0x3F10, 0x7039, 0x2800, 0xD101)
    literal(join + 0xEE, 2, 0x0100C000)
    words(join + 0xF0, 0x7811, 0x0849, 0x0049, 0x7011, 0x7811, 0x7139, 0x2800, 0xD101)
    words(join + 0x104, 0x1C20)
    call(join + 0x106, event)
    words(join + 0x10A, 0x20FF)
    call(join + 0x10C, event)
    words(join + 0x110, 0x1C20, 0xBCF0, 0xBC08, 0x4718)
    words(event, 0xB590, 0x1C07)
    pool = 0x680
    literal(event + 4, 0, state)
    words(event + 6, 0x79C1, 0x2900, 0xD101, 0x2F60, 0xD138)
    words(0x800, 0xB5F0)
    call(0x84C, start)
    words(0xB00, 0x2201, 0x9200, 0x2219, 0x2319, 0x1C28)
    pool = 0xBC0
    literal(0xB0A, 1, 0x801)
    call(0xB0C, 0xC00)
    return image, join


class GatedScannerTests(unittest.TestCase):
    def test_relocation_and_mask(self):
        for start, address, mask in ((0x100, 0x03000674, 0x20), (0x122, 0x03000680, 2)):
            image, _ = gated_scanner(start, address, mask)
            self.assertEqual(gated_scanner_at(image, start),
                             (BoardStatusInput(address, mask, mask), ''))
            self.assertEqual(find_board_status_input(image),
                             BoardStatusInput(address, mask, mask))

    def test_closed_body_mutations(self):
        image, join = gated_scanner()
        # Mutate every instruction in the body, including previously unchecked tails.
        for pc in range(join, join + 0x118, 2):
            with self.subTest(pc=hex(pc)):
                broken = image.copy()
                struct.pack_into('<H', broken, pc, 0xFFFF)
                self.assertIsNone(gated_scanner_at(broken, 0x100)[0])
                self.assertIsNone(find_board_status_input(broken))

    def test_conflicting_rule_descriptors_reject(self):
        image, _ = gated_scanner()
        struct.pack_into('<10H', image, 0xD00, 0xB5F0, 0x483C, 0x7800,
                         0x2308, 0x4018, 0x2808, 0xD101, 0x275F, 0x2760, 0xBDF0)
        struct.pack_into('<I', image, 0xDF4, 0x03000670)
        notes = []
        self.assertIsNone(find_board_status_input(image, notes))
        self.assertIn('board-status input rejected: ambiguous descriptors', notes)

    def test_setup_and_callback_mutations(self):
        image, _ = gated_scanner()
        for pc, value in ((0x11C, 0x2701), (0x124, 0x2700), (0x124, 0xE7FE),
                          (0x162, 0x2701), (0x84C, 0), (0xB04, 0),
                          (0x604, 0), (0x60A, 0)):
            with self.subTest(pc=hex(pc), value=hex(value)):
                broken = image.copy()
                struct.pack_into('<H', broken, pc, value)
                self.assertIsNone(gated_scanner_at(broken, 0x100)[0])

    def test_state_alias_and_paired_call_mismatch(self):
        image, join = gated_scanner()
        for pc, value in ((join + 8, 0x01002001),  # display+7 aliases state+8
                          (join + 14, 0x01002006),  # gate+2 aliases closed state byte
                          (join + 0x66, 0x01002100)):
            with self.subTest(pc=hex(pc)):
                broken = image.copy()
                instruction = struct.unpack_from('<H', broken, pc)[0]
                pool = ((pc + 4) & ~3) + (instruction & 255) * 4
                struct.pack_into('<I', broken, pool, value)
                self.assertIsNone(gated_scanner_at(broken, 0x100)[0])
        broken = image.copy()
        instruction = struct.unpack_from('<H', broken, join + 0xBA + 2)[0]
        struct.pack_into('<H', broken, join + 0xBA + 2, instruction ^ 1)
        self.assertIsNone(gated_scanner_at(broken, 0x100)[0])

    def test_truncation(self):
        image, join = gated_scanner()
        for length in (0, 0x101, 0x123, join, join + 0x110, 0x610, 0xB0F):
            self.assertIsNone(gated_scanner_at(image[:length], 0x100)[0])
