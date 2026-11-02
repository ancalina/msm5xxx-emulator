"""Tests for the SD810 halfword GPIO reader admission."""
import struct
import unittest

from msm5xxx_emulator.detection.input_sd810 import (
    sd810_fold_event_source, sd810_gpio_board_status_profile,
)


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

    def test_fold_events_require_both_polarities_and_same_raw_sink(self):
        image = bytearray(0x400)
        start, sink = 0x100, 0x300
        reader(image, start)
        struct.pack_into('<H', image, start + 22, 0xd122)
        for offset, value in ((94, 0x2101), (96, 0x7141), (98, 0x2006),
                              (104, 0x20ff)):
            struct.pack_into('<H', image, start + offset, value)
        for offset in (28, 34, 100, 106):
            displacement = sink - (start + offset + 4)
            struct.pack_into('<2H', image, start + offset,
                             0xf000 | ((displacement >> 12) & 0x7ff),
                             0xf800 | ((displacement >> 1) & 0x7ff))
        self.assertTrue(sd810_fold_event_source(image, sink))
        self.assertFalse(sd810_fold_event_source(image, sink + 2))
        struct.pack_into('<H', image, start + 98, 0x2008)
        self.assertFalse(sd810_fold_event_source(image, sink))

    def test_rejects_wrong_pointer_or_branch(self):
        image = bytearray(0x400)
        reader(image, 0x100, pointer=0x0181661c)
        self.assertIsNone(sd810_gpio_board_status_profile(image))
        reader(image, 0x100)
        struct.pack_into("<H", image, 0x100 + 22, 0xd000)
        self.assertIsNone(sd810_gpio_board_status_profile(image))
