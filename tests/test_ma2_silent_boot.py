"""Yamaha MA2 silent-boot HLE qualification and ABI checks."""
from __future__ import annotations

from pathlib import Path
import unittest

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
)

from msm5xxx import GenericMSMEmulator, detect, find_ma2_silent_boot_wait


FIRMWARES = Path(__file__).resolve().parent.parent / "firmwares"


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

    def test_hle_returns_success_to_thumb_lr_and_counts_call(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.ma2_silent_boot_calls = 0
        emulator._thumb_runtime_matches = lambda *args, **kwargs: True
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
        uc.reg_write(UC_ARM_REG_LR, 0x2001)
        uc.reg_write(UC_ARM_REG_PC, 0x1000)
        uc.reg_write(UC_ARM_REG_CPSR, 0xD3)

        emulator._ma2_silent_boot(uc, 0x1000, 2, None)

        self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 0)
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x2000)
        self.assertEqual(uc.reg_read(UC_ARM_REG_LR), 0x2001)
        self.assertTrue(uc.reg_read(UC_ARM_REG_CPSR) & 0x20)
        self.assertEqual(emulator.ma2_silent_boot_calls, 1)


if __name__ == "__main__":
    unittest.main()
