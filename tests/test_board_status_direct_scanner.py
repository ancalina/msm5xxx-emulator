"""Synthetic carry-bit lid scanners; private firmware stays outside the repo."""
import struct
import unittest

from corpus import firmware_path
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.input import find_board_status_input
from msm5xxx_emulator.detection.input_scanner_direct import direct_scanner_at


def direct_scanner(start=0x100, address=0x03000664, bit=2, state=0x01003000):
    image = bytearray(b'\xff' * 0x1000)
    pool = (start + 0x200) & ~3
    next_pool = pool

    def words(pc, *values):
        struct.pack_into('<' + 'H' * len(values), image, pc, *values)

    def literal(pc, reg, value):
        nonlocal next_pool
        words(pc, 0x4800 | reg << 8 | (next_pool - ((pc + 4) & ~3)) // 4)
        struct.pack_into('<I', image, next_pool, value)
        next_pool += 4

    def branch(pc, target, opcode):
        words(pc, opcode | (((target - pc - 4) // 2) & (2047 if opcode == 0xE000 else 255)))

    def call(pc, target):
        delta = target - pc - 4
        words(pc, 0xF000 | ((delta >> 12) & 2047), 0xF800 | ((delta >> 1) & 2047))

    def at(offset, *values):
        words(start + offset, *values)

    end, emit, closed = start + 0x9A, start + 0x94, start + 0x5E
    literal(start, 0, address)
    at(2, 0xB5B0, 0x7800, 0x0800 | ((bit + 1) << 6))
    branch(start + 8, start + 0xE, 0xD300)
    at(0xA, 0x2001)
    branch(start + 0xC, start + 0x10, 0xE000)
    at(0xE, 0x2000, 0x2700, 0x2300, 0x2401, 0x2800)
    literal(start + 0x18, 1, 0x01001000)
    literal(start + 0x1A, 2, 0x01002000)
    literal(start + 0x1C, 5, state)
    branch(start + 0x1E, closed, 0xD000)
    at(0x20, 0x7810, 0x2800)
    branch(start + 0x24, end, 0xD100)
    at(0x26, 0x7808, 0x2800)
    branch(start + 0x2A, end, 0xD100)
    literal(start + 0x2C, 0, 0x01001001)
    at(0x2E, 0x7800, 0x2800)
    branch(start + 0x32, end, 0xD100)
    # Byte counter six increments and accepts its first nonzero eligible scan.
    at(0x34, 0x79A8, 0x3001, 0x0600, 0x0E00, 0x71A8, 0x2801)
    branch(start + 0x40, end, 0xDB00)
    at(0x42, 0x71AC, 0x71EB, 0x2001, 0x7010, 0x716B, 0x7A28, 0x275F, 0x2800)
    branch(start + 0x52, start + 0x5A, 0xD000)
    at(0x54, 0x1DE8, 0x3009, 0x7384, 0x722B)  # synthetic wake-request byte
    branch(start + 0x5C, emit, 0xE000)
    at(0x5E, 0x7968, 0x2800)
    branch(start + 0x62, end, 0xD100)
    at(0x64, 0x7808, 0x2800)
    branch(start + 0x68, end, 0xD100)
    literal(start + 0x6A, 0, 0x01001001)
    at(0x6C, 0x7800, 0x2800)
    branch(start + 0x70, end, 0xD100)
    literal(start + 0x72, 0, 0x01004000)
    at(0x74, 0x7800, 0x2800)
    branch(start + 0x78, end, 0xD100)
    # Byte counter seven accepts the second eligible scan and reverses the flags.
    at(0x7A, 0x79E8, 0x3001, 0x0600, 0x0E00, 0x71E8, 0x2802)
    branch(start + 0x86, end, 0xDB00)
    at(0x88, 0x71EC, 0x71AB, 0x716C, 0x7013, 0x722C, 0x2760, 0x1C38)
    call(start + 0x96, 0x900)
    at(0x9A, 0x1C38, 0xBCB0, 0xBC08, 0x4718)
    # Refresh gate takes its inhibit byte to the same return as the normal body.
    words(0x500, 0xB5F0, 0x1C06)
    next_pool = 0x580
    literal(0x504, 0, state + 8)
    words(0x506, 0x7800, 0x2800, 0xD000)
    branch(0x50C, 0x540, 0xE000)
    words(0x540, 0xBCF0, 0xBC08, 0x4718)
    words(0x600, 0xB5F0)
    call(0x602, start)
    words(0x606, 0xBDF0)
    words(0x700, 0x2201, 0x9200, 0x2219, 0x2319, 0x1C20)
    next_pool = 0x780
    literal(0x70A, 1, 0x601)
    call(0x70C, 0x800)
    return image


class DirectScannerTests(unittest.TestCase):
    def test_relocation_and_all_byte_bits(self):
        for bit in range(8):
            start = 0x100 if bit % 2 else 0x182
            address = 0x03000680 + bit
            image = direct_scanner(start, address, bit, 0x01005000 + bit * 64)
            with self.subTest(bit=bit):
                self.assertEqual(direct_scanner_at(image, start)[0], BoardStatusInput(address, 1 << bit, 1 << bit))
                self.assertEqual(find_board_status_input(image), BoardStatusInput(address, 1 << bit, 1 << bit))

    def test_semantic_mutations_fail_closed(self):
        image = direct_scanner()
        for pc in (0x100, 0x106, 0x108, 0x10A, 0x10C, 0x10E, 0x112, 0x114,
                   0x118, 0x11A, 0x11C, 0x11E, 0x124, 0x132, 0x13C, 0x13E,
                   0x140, 0x148, 0x14A, 0x14E, 0x152, 0x158, 0x15A, 0x15C,
                   0x162, 0x16A, 0x172, 0x184, 0x18C, 0x18E, 0x190, 0x192,
                   0x196, 0x19C, 0x500, 0x502, 0x504, 0x506, 0x50C, 0x540, 0x602, 0x700,
                   0x704, 0x706, 0x708, 0x70A, 0x70C):
            with self.subTest(pc=hex(pc)):
                broken = image.copy()
                struct.pack_into('<H', broken, pc, 0)
                result, reason = direct_scanner_at(broken, 0x100)
                self.assertIsNone(result)
                self.assertTrue(reason)
                self.assertIsNone(find_board_status_input(broken))

    def test_ram_links_and_guard_frame_fail_closed(self):
        image = direct_scanner()
        for literal_pc, value in ((0x11A, 0x01003005), (0x16A, 0x01001002),
                                  (0x11C, 0x03003000), (0x504, 0x01003009)):
            with self.subTest(literal_pc=hex(literal_pc)):
                broken = image.copy()
                opcode = struct.unpack_from('<H', broken, literal_pc)[0]
                pool = ((literal_pc + 4) & ~3) + (opcode & 255) * 4
                struct.pack_into('<I', broken, pool, value)
                self.assertIsNone(find_board_status_input(broken))
        for pc, word in ((0x502, 0xE01D), (0x502, 0xB001), (0x502, 0x4700),
                         (0x708, 0x1C30), (0x706, 0x231A), (0x106, 0x0A40)):
            with self.subTest(pc=hex(pc), word=hex(word)):
                broken = image.copy()
                struct.pack_into('<H', broken, pc, word)
                self.assertIsNone(find_board_status_input(broken))

    def test_truncation_rejects(self):
        image = direct_scanner()
        for size in (0, 1, 0x100, 0x102, 0x19F, 0x301, 0x505, 0x545, 0x603, 0x70F):
            with self.subTest(size=size):
                self.assertIsNone(direct_scanner_at(image[:size], 0x100)[0])
                self.assertIsNone(find_board_status_input(image[:size]))

    def test_private_firmware(self):
        paths = [
            ('incoming-msm5xxx-candidates-20260726', 'Samsung', 'SCH-X430', 'X430', 'X430_A562.bin'),
            ('X430_VE21_Dump.bin',),
            ('incoming-20260719-r1', 'MSM5000', 'x430rus_cai6.bin'),
        ]
        for parts in paths:
            with self.subTest(parts=parts):
                image = firmware_path(*parts).read_bytes()
                self.assertEqual(find_board_status_input(image), BoardStatusInput(0x03000660, 1, 1))
                self.assertNotEqual(find_board_status_input(image), BoardStatusInput(0x03000670, 8, 8))
