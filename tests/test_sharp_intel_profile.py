"""Source-bound Sharp EFS recognition, using optional private captures."""
import os
from pathlib import Path
import unittest

from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.registry import device_domain
find_sharp_intel_profile = device_domain('storage.sharp_intel').find_sharp_intel_profile


class SharpIntelProfileTests(unittest.TestCase):
    def test_captures_and_changed_driver(self):
        root = Path(os.environ.get("MSM5XXX_TEST_FIRMWARE_ROOT", "/nonexistent"))
        names = ("T030TEDT09_5.177_JTAG*.bin", "T050VMDM01_3.191_JTAG.bin",
                 "T000VEDW00_0.000_JTAG.bin")
        paths = [next(root.rglob(name), None) for name in names]
        if any(path is None for path in paths):
            self.skipTest("Sharp firmware captures unavailable")
        for path in paths:
            with self.subTest(image=path.name):
                config = detect(path)
                image = path.read_bytes()
                args = (config.flash_size, config.ram_base, config.ram_size)
                profile = find_sharp_intel_profile(image, *args)
                self.assertIsNotNone(profile)
                self.assertEqual(profile["geometry"], (0x600000, 0x200000, 0x10000, 0xb0, 0xb1))
                altered = bytearray(image)
                altered[profile["probe"]] ^= 1
                self.assertIsNone(find_sharp_intel_profile(bytes(altered), *args))

class LegacySharpPCRTests(unittest.TestCase):
    def fixture(self):
        import struct
        image = bytearray(0x1000)
        image[0x100:0x102] = b'\xb8\xb5'
        for site, target in ((0x102, 0x200), (0x10a, 0x300)):
            delta = target - site - 4
            struct.pack_into('<HH', image, site, 0xf000 | ((delta >> 12) & 0x7ff),
                             0xf800 | ((delta >> 1) & 0x7ff))
        setup = bytes.fromhex('f0b570240427602290211501084802800780c00204800688330afcd3'
                              '01808689ae42f3d150210180ff210180f0bd0000000c6000')
        image[0x200:0x200 + len(setup)] = setup
        image[0x300:0x314] = bytes.fromhex('f8b50124a40570262f2560202080258026802088')
        image[0x340:0x34e] = bytes.fromhex('01231b04e418db019c42ded3f8bd')
        struct.pack_into('<II39I5I', image, 0x400, 0x900, 32,
                         *([0x10000] * 32 + [0] * 7), 0x00b100b0, 0, 1,
                         0x300000, 0x100000)
        return image

    def test_code_geometry_and_unique_match(self):
        image = self.fixture()
        args = (0x800000, 0x1000000, 0x800000)
        profile = find_sharp_intel_profile(image, *args)
        self.assertEqual(profile['nv_geometry'], (0x600000, 0x200000))
        for offset in (0x200, 0x300, 0x340, 0x408):
            altered = bytearray(image)
            altered[offset] ^= 1
            self.assertIsNone(find_sharp_intel_profile(altered, *args))
        altered = bytearray(image)
        altered[0x500:0x500 + 80] = image[0x200:0x200 + 80]
        self.assertIsNone(find_sharp_intel_profile(altered, *args))

    def test_dmd_driver_must_be_inside_immutable_prefix(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from msm5xxx_emulator.qemu.transport import qemu_dmd5000_property

        profile = dict(completion=0x1000000, entry=0x10, descriptors=[0x20, 0x30],
                       payloads=[0x40, 0x50], pairs=3)
        config = SimpleNamespace(load_address=0, image_offset=0, entry=0,
                                 flash_size=256, ram_base=0x1000000,
                                 ram_size=0x1000, image_kind='firmware')
        original = bytes(128)
        loaded = bytes(256)
        def detect_driver(image):
            return profile if len(image) >= 80 else None
        with patch('msm5xxx_emulator.detection.devices.dmd.dual.find_dmd5000_profile',
                   side_effect=detect_driver):
            accepted, error = qemu_dmd5000_property(original, loaded, config,
                                                     immutable_limit=100)
            self.assertIsNone(error)
            self.assertTrue(accepted.startswith('dmd5000-program='))
            accepted, error = qemu_dmd5000_property(original, loaded, config,
                                                     immutable_limit=60)
            self.assertIsNone(accepted)
            self.assertIsNotNone(error)
