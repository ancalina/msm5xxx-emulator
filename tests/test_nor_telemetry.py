"""NOR command and persistence telemetry regressions."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2

from msm5xxx import GenericMSMEmulator, qualcomm_efs_seed
from nor_flash import FUJITSU_MB84VD2219X_IDS, NORFlash


class NORTelemetryTests(unittest.TestCase):
    def test_capture_efs_seed_is_limited_to_msm5500(self) -> None:
        erased = b"\xff" * 0x200
        self.assertEqual(qualcomm_efs_seed(0x200, "MSM5000"), erased)
        self.assertNotEqual(qualcomm_efs_seed(0x200, "MSM5500"), erased)

    def test_fujitsu_bottom_boot_sector_geometry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            flash = NORFlash(b"\x00" * 0x400000,
                             Path(directory) / "flash.json")
            flash.ids = FUJITSU_MB84VD2219X_IDS

            flash._erase(*flash._sector_bounds(0x2345))
            self.assertEqual(bytes(flash.data[:0x2000]), b"\x00" * 0x2000)
            self.assertEqual(bytes(flash.data[0x2000:0x4000]), b"\xff" * 0x2000)
            self.assertEqual(bytes(flash.data[0x4000:0x6000]), b"\x00" * 0x2000)

            flash._erase(*flash._sector_bounds(0x12345))
            self.assertEqual(bytes(flash.data[0x10000:0x20000]),
                             b"\xff" * 0x10000)

    def test_program_read_and_sector_erase_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            flash = NORFlash(b"\xff" * 0x20000, Path(directory) / "flash.json")

            flash.write(0xAAA, 1, 0xAA)
            flash.write(0x554, 1, 0x55)
            flash.write(0xAAA, 1, 0xA0)
            flash.write(0x1234, 2, 0x55AA)
            self.assertEqual(flash.read(0x1234, 2), bytes.fromhex("aa55"))

            flash.write(0xAAA, 1, 0xAA)
            flash.write(0x554, 1, 0x55)
            flash.write(0xAAA, 1, 0x80)
            flash.write(0xAAA, 1, 0xAA)
            flash.write(0x554, 1, 0x55)
            flash.write(0x1234, 1, 0x30)

            telemetry = flash.telemetry()
            self.assertEqual(telemetry["reads"], 1)
            self.assertEqual(telemetry["read_bytes"], 2)
            self.assertEqual(telemetry["programs"], 1)
            self.assertEqual(telemetry["program_bytes"], 2)
            self.assertEqual(telemetry["last_program_address"], 0x1234)
            self.assertEqual(telemetry["erases"], 1)
            self.assertEqual(telemetry["erase_bytes"], 0x10000)
            self.assertEqual(telemetry["last_erase_address"], 0)

    def test_fujitsu_bulk_hle_normalizes_absolute_secondary_address(self) -> None:
        body = bytes.fromhex(
            "f0b5141c051c0f1c400803d2780801d2600802d3184919481ae00120c0050cf7"
            "a3fa174e301c1fe02e8895f0dffa154aa02151813e80002801d195f0e5fa0122"
            "381c311cfff78afc002805d00a490e481ef7a6fe0120f0bd0120c005023c0235"
            "02370cf781fa0648084967f713f8002cdad10020f0bd0000acca1b00dc050000"
            "308f4001a00a4000ed050000c5030000"
        )
        base = 0x00400000
        ram = 0x01000000
        incoming = bytes.fromhex("12345678")
        with tempfile.TemporaryDirectory() as directory:
            flash = NORFlash(b"\xff" * 0x1000, Path(directory) / "flash.json")
            emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
            emulator.config = SimpleNamespace(
                load_address=0, flash_size=0x400000,
                ram_base=ram, ram_size=0x1000, overlays=[],
                secondary_flash_address=base, secondary_flash_size=0x1000,
            )
            emulator.flash = SimpleNamespace(phase="idle")
            emulator.secondary_flash = flash
            emulator.secondary_flash_writes = 0
            emulator._original_runtime_bytes = lambda _address, length: body[:length]
            emulator._thumb_runtime_matches = lambda *args, **kwargs: True
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            uc.mem_map(base, 0x1000)
            uc.mem_map(ram, 0x1000)
            uc.mem_write(base, b"\xff" * 0x1000)
            uc.mem_write(ram, incoming)
            uc.reg_write(UC_ARM_REG_R0, ram)
            uc.reg_write(UC_ARM_REG_R1, base + 0x100)
            uc.reg_write(UC_ARM_REG_R2, len(incoming))
            uc.reg_write(UC_ARM_REG_LR, 0x3001)

            emulator._secondary_flash_write_fast(uc, 0x112378, 2, None)
            self.assertEqual(emulator.secondary_flash_writes, 0)

            flash.phase = "bypass"
            uc.reg_write(UC_ARM_REG_R1, 0x100)
            emulator._secondary_flash_write_fast(uc, 0x112378, 2, None)
            self.assertEqual(emulator.secondary_flash_writes, 0)

            uc.reg_write(UC_ARM_REG_R0, ram + 1)
            uc.reg_write(UC_ARM_REG_R1, base + 0x100)
            uc.reg_write(UC_ARM_REG_R2, 0)
            emulator._secondary_flash_write_fast(uc, 0x112378, 2, None)
            self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 1)

            uc.reg_write(UC_ARM_REG_R0, ram)
            uc.reg_write(UC_ARM_REG_R2, len(incoming))
            emulator._secondary_flash_write_fast(uc, 0x112378, 2, None)

            self.assertEqual(bytes(flash.data[0x100:0x104]), incoming)
            self.assertEqual(bytes(uc.mem_read(base + 0x100, 4)), incoming)
            self.assertEqual(emulator.secondary_flash_writes, 1)
            self.assertEqual(flash.telemetry()["program_bytes"], 4)
            self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 0)
            self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x3000)


if __name__ == "__main__":
    unittest.main()
