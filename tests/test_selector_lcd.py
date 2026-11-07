"""Synthetic controller-window and selector/data bridge evidence."""
import struct
import unittest

from msm5xxx_emulator.detection.selector_lcd import find_selector_lcd_profile


def selector_image(width=64, height=80):
    image = bytearray(0x400)
    struct.pack_into('<3H', image, 0x80, 0x2407, 0x2000, 0x06a4)
    struct.pack_into('<17H', image, 0x90,
                     0x2000, 0x8020, 0x2044, 0x8060, 0x2001, 0x8020,
                     0x2100 | (width - 1), 0x0209, 0x8061, 0x2100,
                     0x8021, 0x2145, 0x8061, 0x8020,
                     0x2000 | (height - 1), 0x0200, 0x8060)
    struct.pack_into('<15H', image, 0x100,
                     0x2100, 0x802b, 0x806c, 0x3101, 0x0609, 0x0e09,
                     0x2900 | width, 0xd3f8, 0x703b, 0x703e,
                     0x3201, 0x0612, 0x0e12, 0x2a00 | height, 0xd3f0)
    return bytes(image)


class SelectorLCDTests(unittest.TestCase):
    def test_geometry_requires_matching_window_and_clear(self):
        profile, reason = find_selector_lcd_profile(selector_image())
        self.assertEqual(reason, 'accepted')
        self.assertEqual((profile['width'], profile['height']), (64, 80))
        self.assertEqual(profile['base'], 0x1c000000)
        self.assertEqual(profile['mode'], 'selector-data')

    def test_every_protocol_instruction_is_required(self):
        image = selector_image()
        for at in list(range(0x80, 0x86, 2)) + list(range(0x90, 0xb2, 2)) + list(range(0x100, 0x11e, 2)):
            with self.subTest(at=hex(at)):
                altered = bytearray(image)
                struct.pack_into('<H', altered, at, 0x46c0)
                self.assertIsNone(find_selector_lcd_profile(bytes(altered))[0])

    def test_mismatched_extent_or_loop_target_is_rejected(self):
        for at, value in ((0x10c, 0x2941), (0x11a, 0x2a51),
                          (0x10e, 0xd3f7), (0x11c, 0xd3ef)):
            with self.subTest(at=hex(at)):
                altered = bytearray(selector_image())
                struct.pack_into('<H', altered, at, value)
                self.assertIsNone(find_selector_lcd_profile(bytes(altered))[0])

    def test_ambiguous_complete_bindings_are_rejected(self):
        self.assertIsNone(find_selector_lcd_profile(selector_image() * 2)[0])
