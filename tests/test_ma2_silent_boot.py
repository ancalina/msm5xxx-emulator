"""Yamaha MA2 silent-boot HLE qualification and ABI checks."""
from __future__ import annotations

from pathlib import Path
import unittest


from msm5xxx_emulator.qemu.decoder import QemuDecoder
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.boot import find_ma2_silent_boot_wait
from corpus import FIRMWARE_ROOT


FIRMWARES = FIRMWARE_ROOT


class Ma2SilentBootTests(unittest.TestCase):
    def test_three_native_drivers_enable_named_silent_boot_stub(self) -> None:
        if not FIRMWARES.is_dir():
            self.skipTest("private firmware corpus is not available")
        for name in ("x350_VC22.bin", "schx150.bin", "SCH-X250.bin"):
            with self.subTest(name=name):
                path = FIRMWARES / name
                image = path.read_bytes()
                address = find_ma2_silent_boot_wait(image)
                self.assertIsNotNone(address)
                config = detect(path)
                self.assertEqual(config.ma2_silent_boot_address, address)
                self.assertTrue(any(
                    "MA2 silent boot stub" in note
                    for note in config.detection_notes
                ))

    def test_wait_only_unrelated_firmware_is_rejected(self) -> None:
        if not FIRMWARES.is_dir():
            self.skipTest("private firmware corpus is not available")
        path = FIRMWARES / "SPH-X4500.bin"

        self.assertIsNone(find_ma2_silent_boot_wait(path.read_bytes()))
        self.assertIsNone(detect(path).ma2_silent_boot_address)


if __name__ == "__main__":
    unittest.main()
