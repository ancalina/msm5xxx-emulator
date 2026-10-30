"""Synthetic scanner data flow and optional private-corpus regressions."""
import struct
import unittest

from corpus import firmware_path
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.input import find_board_status_input


def scanner(start=0x100, address=0x03000674, mask=0x20):
    image = bytearray(b'\xff' * 0x1000)
    pool = (start + 0x300) & ~3
    join = start + 0x80
    closed = join + 0xB0
    opened = join + 0x50
    end = closed + 54
    flush, power, event = 0x600, 0x700, 0x800

    def words(pc, *values):
        struct.pack_into('<' + 'H' * len(values), image, pc, *values)

    def branch(pc, target, opcode):
        words(pc, opcode | (((target - pc - 4) // 2) & (0x7FF if opcode == 0xE000 else 255)))

    def literal(pc, reg, pool, value):
        words(pc, 0x4800 | reg << 8 | (pool - ((pc + 4) & ~3)) // 4)
        struct.pack_into('<I', image, pool, value)

    def call(pc, target):
        delta = target - pc - 4
        words(pc, 0xF000 | ((delta >> 12) & 2047), 0xF800 | ((delta >> 1) & 2047))

    words(start, 0xB5F0)
    literal(start + 2, 4, pool, address)
    words(start + 4, 0x7820, 0x2300 | mask, 0x4018, 0x2800 | mask)
    literal(start + 12, 6, pool + 4, 0x01002000)
    literal(start + 14, 5, pool + 8, 0x01003000)
    branch(start + 16, start + 0x40, 0xD100)
    words(start + 18, 0x2701)
    # A GPIO setup call and conditional reconvergence preserve r7.
    call(start + 20, power)
    branch(start + 24, start + 28, 0xD100)
    words(start + 26, 0x2100)
    branch(start + 28, join, 0xE000)
    words(start + 0x40, 0x2700)
    branch(start + 0x42, join, 0xE000)
    words(join, 0x1C39, 0x2701, 0x2400, 0x2500, 0x2900)
    literal(join + 10, 0, pool + 12, 0x01001000)
    branch(join + 12, closed, 0xD000)
    words(join + 14, 0x7941, 0x2900)
    branch(join + 18, end, 0xD100)
    words(join + 20, 0x79C1, 0x3101, 0x0609, 0x0E09, 0x71C1, 0x2902)
    branch(join + 32, end, 0xDB00)
    words(opened, 0x1C39, 0x71C1, 0x7205, 0x7141, 0x7185, 0x7245,
          0x1C07, 0x245F, 0x2000)
    call(opened + 18, power)
    words(opened + 22, 0x1C20)
    call(opened + 24, event)
    words(closed - 8, 0x2001)
    call(closed - 6, flush)
    branch(closed - 2, end, 0xE000)
    words(closed, 0x1C06, 0x7980, 0x2800)
    branch(closed + 6, end, 0xD100)
    words(closed + 8, 0x7A30, 0x3001, 0x0600, 0x0E00, 0x7230, 0x2803)
    branch(closed + 20, end, 0xDB00)
    words(closed + 28, 0x7237, 0x71F5, 0x71B7, 0x7175, 0x2460, 0x2001, 0x7277)
    call(closed + 42, power)
    words(closed + 46, 0x7237, 0x1C20)
    call(closed + 50, event)
    words(end, 0x1C20, 0xBDF0)
    words(flush, 0xB5F0)
    literal(flush + 2, 1, 0x680, 0x01001009)
    words(flush + 4, 0x7809, 0x2900, 0xD003)
    literal(flush + 10, 1, 0x684, 0x01004000)
    words(flush + 12, 0x7909, 0x2900)
    branch(flush + 16, flush + 0x40, 0xD000)
    words(flush + 0x40, 0xBDF0)
    words(0xA00, 0xB5F8)
    call(0xA02, start)
    words(0xA06, 0xBDF8)
    words(0xB00, 0x2201, 0x9200, 0x2219, 0x2319, 0x1C28)
    literal(0xB0A, 1, 0xBC0, 0xA01)
    call(0xB0C, 0xC00)
    return image, join, opened, closed


class ScannerTests(unittest.TestCase):
    def test_relocation_and_masks(self):
        for start, address, mask in [(0x100, 0x03000674, 0x20), (0x182, 0x03000680, 2)]:
            image, *_ = scanner(start, address, mask)
            self.assertEqual(find_board_status_input(image), BoardStatusInput(address, mask, mask))

    def test_mutations_fail_closed_with_reason(self):
        image, join, opened, closed = scanner()
        for pc in [0x112, 0x140, join + 10, join + 12, join + 30,
                   opened + 10, opened + 14, opened + 18, closed + 18,
                   closed + 36, closed + 40, closed + 42, closed + 50,
                   0x602, 0x604, 0x610, 0x640, 0xA02, 0xB04, 0xB06, 0xB0A]:
            with self.subTest(pc=hex(pc)):
                broken = image.copy()
                struct.pack_into('<H', broken, pc, 0)
                notes = []
                self.assertIsNone(find_board_status_input(broken, notes))
                self.assertTrue(any('rejected' in n for n in notes))

    def test_truncated_images_do_not_raise(self):
        image, *_ = scanner()
        for size in (0, 1, 0x102, 0x113, 0x180, 0x300, 0x601, 0x641, 0xB0F):
            with self.subTest(size=size):
                self.assertIsNone(find_board_status_input(image[:size]))

    def test_unknown_setup_writes_and_loops_rejected(self):
        image, *_ = scanner()
        for instruction in (0x1C0F, 0xE7FE, 0x4700, 0x2700):
            broken = image.copy()
            struct.pack_into('<H', broken, 0x11A, instruction)
            notes = []
            self.assertIsNone(find_board_status_input(broken, notes))
            self.assertTrue(notes)

    def test_conflicting_descriptors_have_reason(self):
        image, *_ = scanner()
        struct.pack_into('<6H', image, 0x900, 0xB5F0, 0x483C, 0x7800, 0x2308, 0x4018, 0x2808)
        struct.pack_into('<4H', image, 0x90C, 0xD101, 0x275F, 0x2760, 0xBDF0)
        struct.pack_into('<I', image, 0x9F4, 0x03000670)
        notes = []
        self.assertIsNone(find_board_status_input(image, notes))
        self.assertIn('board-status input rejected: ambiguous descriptors', notes)

    def test_private_firmware(self):
        for parts in [('incoming-20260914', 'x460_ul26_cai6.bin'), ('x350_VC22.bin',)]:
            with self.subTest(parts=parts):
                image = firmware_path(*parts).read_bytes()
                self.assertEqual(find_board_status_input(image), BoardStatusInput(0x03000670, 8, 8))
