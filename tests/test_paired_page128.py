"""Synthetic producer admission and interleaved page scanout."""
import struct
import unittest

from msm5xxx_emulator.detection.paired_page128 import (
    _CLEAR, _PIXEL, _TRANSFER, find_paired_page128,
)
import test_lcd_geometry as display_helpers


def fixture():
    image = bytearray(0x3000)
    pixel, transfer = 0x1000, 0x1b38
    clear = transfer + 0xa98
    struct.pack_into('<H', image, transfer, 0xb5f0)
    for base, shape in ((pixel, _PIXEL), (transfer, _TRANSFER), (clear, _CLEAR)):
        for offset, word in shape:
            struct.pack_into('<H', image, base + offset, word)
    def literal(at, register, pool, value):
        displacement = pool - ((at + 4) & ~3)
        struct.pack_into('<H', image, at, 0x4800 | register << 8 | displacement // 4)
        struct.pack_into('<I', image, pool, value)
    literal(transfer + 22, 3, transfer + 0x60, 0x01010000)
    literal(transfer + 32, 3, transfer + 0x64, 0x2000)
    literal(pixel + 0x70, 3, pixel + 0xb0, 0x2000)
    return image


class PairedPage128Tests(unittest.TestCase):
    def test_shape_admission_and_near_misses(self):
        image = fixture()
        profile = find_paired_page128(image)
        self.assertEqual((profile['width'], profile['height']), (128, 128))
        for address in (0x1000 + 6, 0x1000 + 0x8a, 0x1b38 + 46,
                        0x1b38 + 0x64, 0x1b38 + 0xa98 + 28):
            changed = bytearray(image)
            changed[address] ^= 1
            self.assertIsNone(find_paired_page128(changed), hex(address))
        self.assertIsNone(find_paired_page128(image[:0x2000]))
        self.assertIsNone(find_paired_page128(image + image))

    def test_page_scanout_and_partial_columns(self):
        display = display_helpers.LCDGeometryTests()._routing_emulator(width=128, height=128)
        display.image = bytes(fixture())
        display.config.display_geometry_source = 'interleaved-page-driver'
        def write(address, value):
            display._lcd_write_fallback(None, 0, address, 1, value, None)
        def row(page, values, column=0):
            for value in (0xb0 | page, 0x10 | column >> 4, column & 15):
                write(0x02000000, value)
            for value in values:
                write(0x02000004, value)
        for page in range(16):
            row(page, [0, 0] * 128)
        # The alternate initializer uses halfword stores of byte values.
        for value in (0x2c, 0xae, 0xb0, 0x10, 0):
            display._lcd_write_fallback(None, 0, 0x02000000, 2, value, None)
        for _ in range(256):
            display._lcd_write_fallback(None, 0, 0x02000004, 2, 0, None)
        self.assertFalse(display.odd_page_snapshot()["rejected"])
        for command in (0xae, 0x48, 0x7f, 0xaf):
            write(0x02000000, command)
        row(0, [0xff, 0, 0, 0xff, 0xff, 0xff], column=3)
        write(0x02000000, 0xb1)
        width, height, pixels = display.display_snapshot()
        self.assertEqual((width, height), (128, 128))
        for x, shade in ((2, 0), (3, 85), (4, 170), (5, 255), (6, 0)):
            self.assertEqual(pixels[x * 3:x * 3 + 3], bytes([shade]) * 3)
        self.assertTrue(display._lcd_page_qualified)


if __name__ == '__main__':
    unittest.main()
