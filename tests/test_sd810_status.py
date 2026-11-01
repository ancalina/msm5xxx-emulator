"""Tests for the SD810 halfword GPIO reader admission."""
import struct
import unittest

from msm5xxx_emulator.detection.input_sd810 import sd810_gpio_board_status_profile


def reader(image, start, pointer=0x01816618):
    # Construct a Thumb reader with a PC-relative literal in a synthetic image.
    literal = start + 0x80
    ldr = 0x4800 | ((literal - ((start + 4) & ~3)) // 4)
    words = [ldr, 0x6840, 0x8800, 0x07c1, 0x0fc9, 0x227f,
             0x4800, 0x0112, 0x1810, 0x2900, 0x4c00, 0xd100,
             0x7141, 0x2008, 0xf000, 0xf800, 0x20ff, 0xf000, 0xf800]
    struct.pack_into(f"<{len(words)}H", image, start, *words)
    struct.pack_into("<I", image, literal, pointer)


class SD810StatusTests(unittest.TestCase):
    def test_requires_unique_matching_reader(self):
        image = bytearray(0x400)
        reader(image, 0x100)
        self.assertEqual(sd810_gpio_board_status_profile(image),
                         (0x03000720, 1, 1))
        reader(image, 0x200)
        self.assertIsNone(sd810_gpio_board_status_profile(image))

    def test_rejects_wrong_pointer_or_branch(self):
        image = bytearray(0x400)
        reader(image, 0x100, pointer=0x0181661c)
        self.assertIsNone(sd810_gpio_board_status_profile(image))
        reader(image, 0x100)
        struct.pack_into("<H", image, 0x100 + 22, 0xd000)
        self.assertIsNone(sd810_gpio_board_status_profile(image))
