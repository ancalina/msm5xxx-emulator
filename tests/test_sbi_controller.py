"""Focused tests for runtime-admitted MSM5000 SBI aliases."""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from msm5xxx_emulator.soc.sbi import SBI_BASE
from msm5xxx_emulator.soc.sbi import SbiMixin
from unicorn import UC_ARCH_ARM
from unicorn import UC_MODE_ARM
from unicorn import Uc


class Harness(SbiMixin):
    def __init__(self, *, eligible: bool = True) -> None:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(0x03000000, 0x1000)
        self._init_sbi_state(SimpleNamespace(
            chipset="MSM5000" if eligible else "MSM5100",
            board_adc_reader_address=0x4050,
        ))


class SbiControllerTest(unittest.TestCase):
    @staticmethod
    def write(emulator: Harness, address: int, size: int, value: int) -> None:
        emulator._sbi_write(emulator.uc, 0, address, size, value, None)
        emulator.uc.mem_write(address, value.to_bytes(size, "little"))

    @staticmethod
    def read(emulator: Harness, address: int, size: int = 2) -> int:
        emulator._sbi_read(emulator.uc, 0, address, size, 0, None)
        return int.from_bytes(emulator.uc.mem_read(address, size), "little")

    def admit(self, emulator: Harness) -> None:
        for address, size, value in (
            (SBI_BASE, 1, 0x45),
            (SBI_BASE, 1, 0xC5),
            (SBI_BASE + 4, 2, 0x085F),
            (SBI_BASE + 0x0C, 2, 0x041F),
            (SBI_BASE + 0x10, 1, 0),
            (SBI_BASE + 0x10, 1, 1),
        ):
            self.write(emulator, address, size, value)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x5F20)
        self.write(emulator, SBI_BASE + 0x0C, 2, 0x0900)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x5F20)
        self.assertEqual(emulator._sbi_profile_status, "accepted")

    def test_admits_exact_bootstrap_and_closes_read_buffer(self) -> None:
        emulator = Harness()
        self.admit(emulator)
        self.write(emulator, SBI_BASE + 4, 2, 0x086A)
        self.write(emulator, SBI_BASE + 0x0C, 2, 0x8B00)

        self.assertEqual(self.read(emulator, SBI_BASE), 0x6A22)
        emulator.uc.mem_write(SBI_BASE + 0x0C, b"\xC2\x8B")
        self.assertEqual(self.read(emulator, SBI_BASE + 0x0C), 0x8BC2)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x6A20)

    def test_ineligible_firmware_keeps_native_backing(self) -> None:
        emulator = Harness(eligible=False)
        emulator.uc.mem_write(SBI_BASE, b"\xA5\xA5")
        self.assertEqual(self.read(emulator, SBI_BASE), 0xA5A5)
        self.assertEqual(emulator._sbi_telemetry()["status"], "not-detected")

    def test_candidate_mismatch_restores_native_backing(self) -> None:
        emulator = Harness()
        for address, size, value in (
            (SBI_BASE, 1, 0x45),
            (SBI_BASE, 1, 0xC5),
            (SBI_BASE + 4, 2, 0x085F),
            (SBI_BASE + 0x0C, 2, 0x041F),
            (SBI_BASE + 0x10, 1, 0),
            (SBI_BASE + 0x10, 1, 1),
        ):
            self.write(emulator, address, size, value)
        self.assertEqual(self.read(emulator, SBI_BASE), 0x5F20)

        self.assertEqual(self.read(emulator, SBI_BASE), 0x00C5)
        self.assertEqual(emulator._sbi_profile_status, "rejected")
        self.assertIsNone(emulator._sbi_poll_aperture)


if __name__ == "__main__":
    unittest.main()
