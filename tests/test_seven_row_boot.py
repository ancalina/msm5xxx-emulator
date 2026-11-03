"""Source-bound cold-boot NOR and keypad profiles."""
import unittest

from corpus import firmware_path
from msm5xxx_emulator.detection.boot_format_nor import find_boot_format_nor
from msm5xxx_emulator.detection.input_seven_row import (
    find_seven_row_board_status, find_seven_row_scanners,
)
from msm5xxx_emulator.detection.legacy_lcd import _COLUMN16_BOOT
from msm5xxx_emulator.detection.thumb_patterns import match


class SevenRowBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = firmware_path('SCH-E140.bin').read_bytes()

    def test_nor_geometry_and_watchdog(self):
        profile = find_boot_format_nor(self.image, 0x1000000, 0x800000)
        self.assertIsNotNone(profile)
        self.assertEqual((profile['id0'], profile['id1']), (1, 0x227e))
        regions = profile['erase_regions']
        self.assertEqual(sum(count for count, _ in regions), 142)
        self.assertEqual(sum(count * size for count, size in regions), 0x800000)
        self.assertEqual(regions, ((8, 0x2000), (126, 0x10000), (8, 0x2000)))
        self.assertEqual((profile['watchdog_register'], profile['watchdog_mask']),
                         (0x3001080, 1))
        self.assertIsNone(find_boot_format_nor(self.image, 0x1000000, 0x400000))
        self.assertIsNone(find_boot_format_nor(self.image[:0x1000], 0x1000000, 0x800000))

    def test_matrix_and_open_lid(self):
        profiles = find_seven_row_scanners(self.image)
        self.assertEqual(len(profiles), 1)
        matrix = profiles[0]
        self.assertEqual((matrix['rows'], matrix['columns']), (7, 4))
        self.assertEqual(matrix['row_select_mask'], 0x7f00)
        self.assertEqual(matrix['single_key_column_sense'], [14, 13, 11, 7])
        cells = matrix['token_cells']
        self.assertEqual(len({(c['row'], c['column']) for c in cells}), len(cells))
        status = find_seven_row_board_status(self.image)
        self.assertEqual((status.address, status.mask, status.default), (0x3000720, 4, 4))
        self.assertEqual(find_seven_row_scanners(self.image[:0x1000]), [])
        self.assertIsNone(find_seven_row_board_status(self.image[:0x1000]))

    def test_instruction_and_descriptor_mutations_reject(self):
        from msm5xxx_emulator.detection.boot_format_nor import _CODE
        from msm5xxx_emulator.detection.input_seven_row import _SCANNER_CODE, _SCANNER, _shape
        for at, _ in _CODE:
            with self.subTest(nor=hex(at)):
                image = bytearray(self.image)
                image[at] ^= 1
                self.assertIsNone(find_boot_format_nor(image, 0x1000000, 0x800000))
        for at in (0x3f61cc, 0x3f61d0, 0x3f6408, 0x3f6418, 0x7224d8, 0x83dfc):
            image = bytearray(self.image)
            image[at] ^= 1
            self.assertIsNone(find_boot_format_nor(image, 0x1000000, 0x800000))
        for offset, _ in _SCANNER_CODE:
            image = bytearray(self.image)
            image[0x91090 + offset] ^= 1
            self.assertIsNone(_shape(image, 0x91090, _SCANNER, _SCANNER_CODE))
        self.assertTrue(match(self.image, _COLUMN16_BOOT))
        for at, _ in _COLUMN16_BOOT:
            image = bytearray(self.image)
            image[at] ^= 1
            self.assertFalse(match(image, _COLUMN16_BOOT))

    def test_other_firmware_does_not_match_new_profiles(self):
        for name in ('LG-KP6200.bin', 'LG-SV130.bin', 'LG-SD810-General.bin'):
            with self.subTest(name=name):
                image = firmware_path(name).read_bytes()
                self.assertIsNone(find_boot_format_nor(image, 0x1000000, 0x800000))
                self.assertEqual(find_seven_row_scanners(image), [])
                self.assertIsNone(find_seven_row_board_status(image))
                self.assertFalse(match(image, _COLUMN16_BOOT))
