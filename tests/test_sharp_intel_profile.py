"""Source-bound Sharp EFS recognition, using optional private captures."""
import os
from pathlib import Path
import unittest

from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.sharp_intel import find_sharp_intel_profile


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
