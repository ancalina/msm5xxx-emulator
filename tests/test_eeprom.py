"""24LCxx detection-hook and persistence regressions."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import (UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC,
                               UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)

from msm5xxx import (EEPROM_24LCXX_READ_SIGNATURE,
                     EEPROM_24LCXX_WRITE_PREFIX,
                     EEPROM_24LCXX_X430_READ_PREFIX,
                     EEPROM_24LCXX_X430_WRITE_PREFIX,
                     EEPROM_24LCXX_X270_READ_PREFIX,
                     EEPROM_24LCXX_X270_WRITE_PREFIX,
                     EEPROM_24LCXX_X7700_READ_PREFIX,
                     EEPROM_24LCXX_X7700_WRITE_PREFIX, GenericMSMEmulator)


class EEPROMTests(unittest.TestCase):
    @staticmethod
    def _emulator(state: Path,
                  write_signature: bytes = EEPROM_24LCXX_WRITE_PREFIX,
                  read_signature: bytes = EEPROM_24LCXX_READ_SIGNATURE
                  ) -> tuple[GenericMSMEmulator, Uc, int, int, int]:
        write = 0x1000
        read = 0x1100
        ram = 0x10000
        geometry = ram + 0x100
        original = bytearray(b"\xff" * 0x1000)
        original[:len(write_signature)] = write_signature
        original[read - write:read - write + len(read_signature)] = read_signature

        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            eeprom_geometry_address=geometry,
            overlays=[], linker=None,
            load_address=write, flash_size=0x1000,
            ram_base=ram, ram_size=0x1000,
            secondary_flash_address=None, secondary_flash_size=0,
        )
        emulator.original_image = bytes(original)
        emulator.flash = SimpleNamespace(phase="idle")
        emulator.secondary_flash = None
        emulator.eeprom_enabled = True
        emulator.eeprom_state_path = state
        emulator.eeprom_data = bytearray()
        emulator.eeprom_original = b""
        emulator.eeprom_loaded = b""
        emulator.eeprom_operations = []
        emulator.eeprom_capacity = 0
        emulator.eeprom_loaded_from_state = False
        emulator.eeprom_error = None
        emulator.eeprom_reads = 0
        emulator.eeprom_read_bytes = 0
        emulator.eeprom_writes = 0
        emulator.eeprom_write_bytes = 0

        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(write, 0x1000)
        uc.mem_write(write, bytes(original))
        uc.mem_map(ram, 0x1000)
        uc.mem_write(geometry, bytes.fromhex("0080010004"))
        uc.reg_write(UC_ARM_REG_CPSR, 0xF3)
        emulator.uc = uc
        return emulator, uc, write, read, ram

    def test_read_write_and_cold_warm_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "eeprom.bin"
            emulator, uc, write, read, ram = self._emulator(state)
            source = ram + 0x200
            destination = ram + 0x300
            payload = bytes.fromhex("2a51")
            uc.mem_write(source, payload)
            uc.reg_write(UC_ARM_REG_R0, source)
            uc.reg_write(UC_ARM_REG_R1, 0xDF1)
            uc.reg_write(UC_ARM_REG_R2, len(payload))
            uc.reg_write(UC_ARM_REG_LR, 0x1301)

            emulator._eeprom_write_fast(uc, write, 2, None)

            self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 0)
            self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x1300)
            self.assertEqual(emulator.eeprom_data[0xDF1:0xDF3], payload)
            self.assertEqual(emulator.eeprom_writes, 1)
            emulator._save_eeprom()
            self.assertEqual(len(state.read_bytes()), 0x8000)

            warm, warm_uc, _write, warm_read, warm_ram = self._emulator(state)
            warm_destination = warm_ram + 0x300
            warm_uc.reg_write(UC_ARM_REG_R0, warm_destination)
            warm_uc.reg_write(UC_ARM_REG_R1, 0xDF1)
            warm_uc.reg_write(UC_ARM_REG_R2, len(payload))
            warm_uc.reg_write(UC_ARM_REG_LR, 0x1401)

            warm._eeprom_read_fast(warm_uc, warm_read, 2, None)

            self.assertEqual(bytes(warm_uc.mem_read(warm_destination, 2)), payload)
            self.assertEqual(warm_uc.reg_read(UC_ARM_REG_R0), 0)
            self.assertTrue(warm.eeprom_loaded_from_state)
            self.assertEqual(warm.eeprom_reads, 1)

    def test_out_of_range_returns_firmware_bad_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            emulator, uc, write, _read, ram = self._emulator(
                Path(directory) / "eeprom.bin"
            )
            uc.mem_write(ram + 0x200, b"\x00")
            uc.reg_write(UC_ARM_REG_R0, ram + 0x200)
            uc.reg_write(UC_ARM_REG_R1, 0x7FFF)
            uc.reg_write(UC_ARM_REG_R2, 1)
            uc.reg_write(UC_ARM_REG_LR, 0x1501)

            emulator._eeprom_write_fast(uc, write, 2, None)

            self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 6)
            self.assertEqual(emulator.eeprom_writes, 0)

    def test_zero_length_succeeds_without_touching_buffer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            emulator, uc, write, read, _ram = self._emulator(
                Path(directory) / "eeprom.bin"
            )
            for entry, callback in ((write, emulator._eeprom_write_fast),
                                    (read, emulator._eeprom_read_fast)):
                uc.reg_write(UC_ARM_REG_R0, 0xDEADBEEF)
                uc.reg_write(UC_ARM_REG_R1, 0x7FFF)
                uc.reg_write(UC_ARM_REG_R2, 0)
                uc.reg_write(UC_ARM_REG_LR, 0x1601)
                callback(uc, entry, 2, None)
                self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 0)

            uc.reg_write(UC_ARM_REG_R0, 0xDEADBEEF)
            uc.reg_write(UC_ARM_REG_R1, 0x8000)
            uc.reg_write(UC_ARM_REG_R2, 0)
            uc.reg_write(UC_ARM_REG_LR, 0x1601)
            emulator._eeprom_read_fast(uc, read, 2, None)
            self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 6)

    def test_empty_existing_state_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "eeprom.bin"
            state.write_bytes(b"")
            emulator, uc, _write, _read, _ram = self._emulator(state)

            self.assertFalse(emulator._ensure_eeprom(uc))
            self.assertIn("expected 0x8000", emulator.eeprom_error or "")

    def test_variant_pristine_prefix_keeps_24lc256_abi(self) -> None:
        for write_signature, read_signature in (
                (EEPROM_24LCXX_X430_WRITE_PREFIX,
                 EEPROM_24LCXX_X430_READ_PREFIX),
                (EEPROM_24LCXX_X270_WRITE_PREFIX,
                 EEPROM_24LCXX_X270_READ_PREFIX),
                (EEPROM_24LCXX_X7700_WRITE_PREFIX,
                 EEPROM_24LCXX_X7700_READ_PREFIX)):
            with self.subTest(write_signature=write_signature):
                with tempfile.TemporaryDirectory() as directory:
                    emulator, uc, write, read, ram = self._emulator(
                        Path(directory) / "eeprom.bin", write_signature,
                        read_signature,
                    )
                    source = ram + 0x200
                    destination = ram + 0x300
                    uc.mem_write(source, b"\x5a")
                    uc.reg_write(UC_ARM_REG_R0, source)
                    uc.reg_write(UC_ARM_REG_R1, 0x20)
                    uc.reg_write(UC_ARM_REG_R2, 1)
                    uc.reg_write(UC_ARM_REG_LR, 0x1301)
                    emulator._eeprom_write_fast(uc, write, 2, None)

                    uc.reg_write(UC_ARM_REG_R0, destination)
                    uc.reg_write(UC_ARM_REG_R1, 0x20)
                    uc.reg_write(UC_ARM_REG_R2, 1)
                    uc.reg_write(UC_ARM_REG_LR, 0x1401)
                    emulator._eeprom_read_fast(uc, read, 2, None)
                    self.assertEqual(bytes(uc.mem_read(destination, 1)), b"\x5a")

                    for entry, callback, counter in (
                            (write, emulator._eeprom_write_fast, "eeprom_writes"),
                            (read, emulator._eeprom_read_fast, "eeprom_reads")):
                        before = getattr(emulator, counter)
                        uc.mem_write(entry, b"\0\0")
                        uc.reg_write(UC_ARM_REG_PC, entry)
                        callback(uc, entry, 2, None)
                        self.assertEqual(getattr(emulator, counter), before)
                        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), entry)


if __name__ == "__main__":
    unittest.main()
