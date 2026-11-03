"""Synthetic copied NAND producer and ready pin."""
import struct
import unittest
from unittest.mock import patch
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.guarded_middle_nand import (
    _STATUS, _READY, _BAD_PREFIX, _BAD_TRANSFER, _SWEEP_PREFIX, _SWEEP_TAIL,
    find_guarded_middle_nand_profile,
)
from test_legacy_keypad import branch


class GuardedMiddleNandTests(unittest.TestCase):
    def fixture(self):
        image = bytearray(0x4000)
        guard = bytes.fromhex(
            'b0b40020134901220a7000220a70114fbc89102323402024002b08d1'
            '3888c00814d2bc813a80012008700a70fce73d88eb080bd2094b1b88'
            '5b0807d2bc813a8001230b700a700130ff28fad3b0bc7047')
        for at in (0x102, 0x302):
            image[at:at + len(guard)] = guard
            for off, value in ((0x52, 0x03001080), (0x56, 0x03000720),
                               (0x5a, 0x04800020)):
                struct.pack_into('<I', image, at + off, value)
        table, source, status = 0x800, 0x100c, 0x110c
        struct.pack_into('<III', image, table, source, 0x03800000, 0x2000)
        image[status:status + len(_STATUS)] = _STATUS
        reset, ready, spare = status + 0x30, status + 0x3a, status + 0x60
        image[reset:reset + 10] = bytes.fromhex('ff200d21490508707047')
        image[ready:ready + len(_READY)] = _READY
        for off, value in ((2, 0x017f0000), (6, 0x03001080)):
            pool = ((ready + off + 4) & ~3) + 24
            struct.pack_into('<I', image, pool, value)
        image[spare:spare + len(_BAD_PREFIX)] = _BAD_PREFIX
        branch(image, spare + 0x10, reset)
        image[spare + 0x14:spare + 0x14 + len(_BAD_TRANSFER)] = _BAD_TRANSFER
        branch(image, spare + 0x2a, ready)
        sweep = reset + 0x104
        image[sweep:sweep + len(_SWEEP_PREFIX)] = _SWEEP_PREFIX
        branch(image, sweep + 0x10, reset + 0x19a)
        image[sweep + 0x14:sweep + 0x14 + len(_SWEEP_TAIL)] = _SWEEP_TAIL
        struct.pack_into('<I', image, ((sweep + 6 + 4) & ~3) + 28, 0x03001080)
        return image

    def test_guard_and_copied_driver_are_admitted_together(self):
        image = self.fixture()
        result = find_guarded_middle_nand_profile(image)
        self.assertEqual(result['ready_mask'], 2)
        image[0x102] ^= 1
        self.assertIsNone(find_guarded_middle_nand_profile(image))

    def test_copied_driver_and_ready_mask(self):
        image = self.fixture()
        with patch('msm5xxx_emulator.detection.guarded_middle_nand.find_cold_power_guard',
                   return_value=BoardStatusInput(0x03000720, 4, 4)):
            profile = find_guarded_middle_nand_profile(image)
            self.assertEqual((profile['data_size'], profile['ready_address'], profile['ready_mask']),
                             (0x2000000, 0x03000720, 2))
            for offset in (0x800, 0x110c, 0x113c, 0x1164, 0x116c + 0x10, 0x1240 + 0x18):
                changed = bytearray(image)
                changed[offset] ^= 1
                self.assertIsNone(find_guarded_middle_nand_profile(changed))
        with patch('msm5xxx_emulator.detection.guarded_middle_nand.find_cold_power_guard', return_value=None):
            self.assertIsNone(find_guarded_middle_nand_profile(image))

    def test_transport_requires_disjoint_nand_aperture(self):
        from types import SimpleNamespace
        from msm5xxx_emulator.qemu.transport import qemu_raw_nand_main_profile
        config = SimpleNamespace(nand_enabled=True, load_address=0, flash_size=0x1000000,
                                 ram_base=0x01000000, ram_size=0x800000,
                                 upper_flash_address=None)
        profile = dict(data_size=0x2000000)
        with patch('msm5xxx_emulator.qemu.transport.find_guarded_middle_nand_profile',
                   return_value=profile):
            bus, error = qemu_raw_nand_main_profile(bytes(64), config)
            self.assertIsNone(error)
            self.assertEqual(bus, (0x01800000, 0x01900000, 0x01a00000, 0x2000000, 512, 32, 2))
            config.upper_flash_address = 0x01800000
            self.assertEqual(qemu_raw_nand_main_profile(bytes(64), config),
                             (None, 'guarded-middle-aperture-mapping-conflict'))
