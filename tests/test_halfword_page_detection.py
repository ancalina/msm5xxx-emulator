"""Synthetic instruction graphs for the halfword/low-byte secondary panel."""
import struct
import unittest
from msm5xxx_emulator.detection.registry import device_domain
find_halfword_page_secondary = device_domain('display.halfword_page').find_halfword_page_secondary


def fixture(independent=False):
    image = bytearray(0x1000)
    shift, field = (-2, 0x28) if independent else (0, 4)
    dirty, geometry = 0x01002000, (0x01001000 if independent else 0x01001fc0)
    def put(at, *words):
        struct.pack_into('<' + 'H' * len(words), image, at, *words)
    def bl(at, target):
        delta = target - at - 4
        put(at, 0xf000 | (delta >> 12 & 0x7ff), 0xf800 | (delta >> 1 & 0x7ff))
    def literal(at, register, slot, value):
        put(at, 0x4800 | register << 8 | (slot - ((at + 4) & ~3)) // 4)
        struct.pack_into('<I', image, slot, value)
    put(0x20, 0x2105, 0x05c9, 0x8008, 0x4770)
    put(0x30, 0x2105, 0x05c9, 0x8048, 0x4770)
    put(0x100, 0xb580)
    bl(0x102, 0x50)
    for i, value in enumerate((0xae, 0x40, 0xa1, 0x10, 0, 0xa6, 0xa3, 0xc0, 0x2c)):
        put(0x106 + i * 6, 0x2000 | value)
        bl(0x108 + i * 6, 0x20)
    if independent:
        literal(0x13c, 7, 0x1a0, 50000)
        put(0x13e, 0x1c38)
    else:
        put(0x13c, 0x277d, 0x00ff, 0x1c38)
    for off, value in ((0x46, 0x2e), (0x52, 0x2f), (0x5e, 0x24), (0x64, 0x81), (0x6a, 0x23)):
        put(0x100 + off + shift, 0x2000 | value)
        bl(0x102 + off + shift, 0x20)
    for off in (0x42, 0x4e, 0x5a):
        bl(0x100 + off + shift, 0x60)
    literal(0x170 + shift, 1, 0x1b0, dirty)
    put(0x172 + shift, 0x2007, 0x6008 | (field + 12) // 4 << 6,
        0x2200, 0x600a | (field + 8) // 4 << 6, 0x205f,
        0x6008 | (field + 4) // 4 << 6, 0x600a | field // 4 << 6)
    bl(0x180 + shift, 0x300)
    put(0x300, 0xb5f0)
    literal(0x302, 4, 0x3b0, dirty)
    for off, displacement, bound, branch in ((4, field, 0, 0xda01), (0xe, field + 4, 96, 0xdd01),
                                            (0x18, field + 8, 0, 0xda01), (0x22, field + 12, 7, 0xdd01)):
        put(0x300 + off, 0x6820 | displacement // 4 << 6, 0x2800 | bound, branch,
            0x2000 | bound, 0x6020 | displacement // 4 << 6)
    bl(0x32c, 0x50)
    literal(0x332, 5, 0x3b4, geometry if independent else geometry + 0x40)
    if not independent:
        put(0x33a, 0x3d40)
    put(0x33e + shift, 0x0638, 0x0e00, 0x30b0)
    for off in (0x44, 0x50, 0x5c):
        bl(0x300 + off + shift, 0x20)
    put(0x348 + shift, 0x6820 | field // 4 << 6, 0x3004, 0x1100, 0x4330)
    put(0x354 + shift, 0x6820 | field // 4 << 6, 0x3004, 0x0700, 0x0f00)
    put(0x368 + shift, 0x8aa9, 0x1c38, 0x4348, 0x6aa9, 0x1840, 0x5c80)
    bl(0x374 + shift, 0x30)
    put(0x384 + shift, 0x2a60)
    put(0x394 + shift, 0x2f08)
    literal(0x600, 7, 0x650, geometry)
    put(0x608, 0x2060, 0x82b8, 0x2040, 0x82f8, 0x2008, 0x84b8, 0x62b9)
    return image


class HalfwordPageDetectionTests(unittest.TestCase):
    def test_two_relocated_dirty_layouts_and_broken_links(self):
        for independent in (False, True):
            image = fixture(independent)
            self.assertEqual(find_halfword_page_secondary(bytes(image)), 0x02800000)
            shift = -2 if independent else 0
            for at in (0x20, 0x34, 0x108, 0x180 + shift, 0x304, 0x32c,
                       0x344 + shift, 0x354 + shift, 0x374 + shift, 0x394 + shift,
                       0x600, 0x608):
                with self.subTest(independent=independent, mutation=hex(at)):
                    broken = image.copy()
                    broken[at:at + 2] = b'\0\0'
                    self.assertIsNone(find_halfword_page_secondary(bytes(broken)))
            duplicate = image.copy()
            duplicate[0x800:0x808] = image[0x20:0x28]
            self.assertIsNone(find_halfword_page_secondary(bytes(duplicate)))
            unlinked = image.copy()
            unlinked[0x102:0x106] = bytes(4)
            unlinked[0x32c:0x330] = bytes(4)
            self.assertIsNone(find_halfword_page_secondary(bytes(unlinked)))
        self.assertIsNone(find_halfword_page_secondary(bytes(512)))
