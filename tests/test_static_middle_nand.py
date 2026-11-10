"""Synthetic direct-ROM NAND driver recognition."""
import struct
import unittest

from msm5xxx_emulator.detection.registry import device_domain
find_static_middle_nand_profile = device_domain('storage.static_middle_nand').find_static_middle_nand_profile


def branch(image, site, target):
    delta = target - site - 4
    struct.pack_into('<HH', image, site, 0xf000 | ((delta >> 12) & 0x7ff),
                     0xf800 | ((delta >> 1) & 0x7ff))


class StaticMiddleNandTests(unittest.TestCase):
    def fixture(self):
        image = bytearray(0x24000)
        reset = 0x1000
        fragments = ((0, 'ff200d21490508707047'),
            (-0x58, '0320c0050d21490570220a700478c02c05d0c12c03d0'),
            (0x14, '406a0188490801d2013ffad1'), (0x90, '0320c0050088'),
            (0xb8, '80b501277801'), (0xc2, '013701239b029f42f7db80bc08bc1847'),
            (0x15e, '60200d21490508701920000507700470d0200870'),
            (0x294, '0d204005ff2301339d4201d2002100e05021017080210170051c1921'),
            (0x2c8, 'c00f0322d205002807d103e04100615a11800130b042f9d3'))
        for offset, code in fragments:
            data = bytes.fromhex(code)
            image[reset + offset:reset + offset + len(data)] = data
        for site, target in ((0x6a, 0), (0x8c, 0xa), (0xbe, 0xd2),
                             (0x15a, 0), (0x17a, 0xa), (0x17e, -0x60), (0x290, 0)):
            branch(image, reset + site, reset + target)
        pool = reset + 0x3f0
        struct.pack_into('<H', image, reset + 0x12, 0x4800 | ((pool - ((reset + 0x16) & ~3)) // 4))
        struct.pack_into('<I', image, pool, 0x01001000)
        struct.pack_into('<III', image, 0x100, 0x20000, 0x01000000, 0x2000)
        struct.pack_into('<I', image, 0x21024, 0x03000728)
        return image

    def test_calls_geometry_and_ready_source_must_match(self):
        image = self.fixture()
        profile = find_static_middle_nand_profile(image)
        self.assertEqual(profile['ready_mask'], 1)
        self.assertEqual(profile['bus_width'], 2)
        for offset in (0x1000, 0x1000 + 0x6a, 0x21024):
            altered = bytearray(image)
            altered[offset] ^= 1
            self.assertIsNone(find_static_middle_nand_profile(altered))

    def test_native_aperture_requires_signature_and_disjoint_mapping(self):
        from types import SimpleNamespace
        from msm5xxx_emulator.qemu.transport import qemu_raw_nand_main_profile
        image = self.fixture()
        config = SimpleNamespace(nand_enabled=True, load_address=0, flash_size=0x800000,
                                 ram_base=0x01000000, ram_size=0x800000,
                                 upper_flash_address=None)
        from unittest.mock import patch
        with patch("msm5xxx_emulator.detection.devices.storage.transport_projection.find_table7_matrix", return_value={}):
            result, error = qemu_raw_nand_main_profile(image, config)
        self.assertIsNone(error)
        self.assertEqual(result[:3], (0x01800000, 0x01900000, 0x01a00000))
        config.upper_flash_address = 0x01800000
        with patch("msm5xxx_emulator.detection.devices.storage.transport_projection.find_table7_matrix", return_value={}):
            result, error = qemu_raw_nand_main_profile(image, config)
        self.assertIsNone(result)
        self.assertEqual(error, 'direct-middle-aperture-mapping-conflict')
