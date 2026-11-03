"""Composite source and negative checks for KP2600 keypad input."""
import copy
import os
from pathlib import Path
import unittest

from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.input_lg_kp2600 import find_kp2600_scanner
from msm5xxx_emulator.devices.input import InputMixin
from msm5xxx_emulator.qemu.transport import (
    qemu_kp2600_irq_compatible, qemu_kp2600_matrix_property,
)


ROOT = Path(os.environ.get('MSM5XXX_TEST_FIRMWARE_ROOT', '/nonexistent'))
IMAGE = ROOT / 'incoming-20260719-r1/incoming-20250804/LG-KP2600.bin'


@unittest.skipUnless(IMAGE.is_file(), 'KP2600 firmware unavailable')
class KP2600KeypadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = IMAGE.read_bytes()
        cls.config = detect(IMAGE)
        cls.profile = find_kp2600_scanner(cls.image, cls.config)

    def test_numeric_positions_follow_split_rows(self):
        self.assertIsNotNone(self.profile)
        positions = InputMixin._direct_matrix_positions(self.profile)
        self.assertEqual(positions[11], (ord('1'), 1, 3))
        self.assertEqual(positions[21], (ord('0'), 4, 2))
        self.assertEqual(set(positions), set(range(11, 23)))
        self.assertEqual(qemu_kp2600_matrix_property(self.image, self.config, self.profile),
                         'matrix-low5=19462c4:6d5e4:6d712:6d574:6d5d2')

    def test_rejects_mutated_scanner_timer_descriptor_and_route(self):
        for offset in (0x6d574, 0x6d616, 0x6d696, 0x6d6fe, 0x6d712,
                       0x6d72e, 0xc674, 0x6d9f6, 0x6e526, 0x77c250):
            image = bytearray(self.image)
            image[offset] ^= 1
            with self.subTest(offset=hex(offset)):
                self.assertIsNone(find_kp2600_scanner(image, self.config))
        config = copy.deepcopy(self.config)
        config.rex_static_controller_candidate['mask'] ^= 1
        self.assertIsNone(find_kp2600_scanner(self.image, config))
        profile = copy.deepcopy(self.profile)
        profile['single_key_column_sense'][0] ^= 1
        self.assertIsNone(qemu_kp2600_matrix_property(self.image, self.config, profile))

    def test_irq_owner_must_match_without_conflicts(self):
        route = '3000c80:3000c94:200:4c4b40:1800000:3824:19fb0ec:a47a8:1b6:1949048:c604'
        self.assertTrue(qemu_kp2600_irq_compatible(route, None, None, None, False))
        self.assertFalse(qemu_kp2600_irq_compatible(route + '0', None, None, None, False))
        for index in range(3):
            conflicts = [None, None, None]
            conflicts[index] = 'other-owner'
            self.assertFalse(qemu_kp2600_irq_compatible(route, *conflicts, False))
        self.assertFalse(qemu_kp2600_irq_compatible(route, None, None, None, True))
