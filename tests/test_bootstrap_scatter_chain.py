"""Tests for the narrowly leased bootstrap scatter-load HLE."""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM

from msm5xxx import GenericMSMEmulator


class BootstrapScatterChainTests(unittest.TestCase):
    STROBE = 0x1000
    RAM = 0x01000000

    def _emulator(self) -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        emulator.uc.mem_map(0, 0x20000)
        # MOVS r0,#1; LDR r1,[pc,#12]; STRB r0,[r1];
        # MOVS r0,#0; STRB r0,[r1]. The pointer is at 0x1010.
        emulator.uc.mem_write(
            self.STROBE,
            bytes.fromhex(
                "01 20 03 49 08 70 00 20 08 70 00 00 00 00 00 00 "
                "00 07 00 03"
            ),
        )
        emulator.config = SimpleNamespace(
            load_address=0,
            flash_size=0x100000,
            ram_base=self.RAM,
            ram_size=0x00800000,
        )
        emulator.flash = SimpleNamespace(phase="idle")
        emulator.primary_rom_end = 0x100000
        emulator.reset_entries = 1
        emulator.instructions = 0
        emulator.lcd_writes = 0
        emulator.frame_sequence = 0
        emulator.rex_ticks = 0
        emulator.input_events = 0
        emulator._bootstrap_data_end = None
        emulator._bootstrap_rom_end = None
        emulator._bootstrap_bss_end = None
        emulator._bootstrap_bss_complete = False
        emulator._bootstrap_iram_end = None
        return emulator

    def test_strobe_opens_only_contiguous_bootstrap_chain(self) -> None:
        emulator = self._emulator()

        self.assertTrue(emulator._thumb_watchdog_strobe(self.STROBE))
        self.assertEqual(
            emulator._bootstrap_copy_stage(
                self.RAM + 0x100, 0x6000, self.RAM + 0x3000, 0x8F00, self.STROBE
            ),
            "data",
        )

        emulator._bootstrap_data_end = self.RAM + 0x3000
        emulator._bootstrap_rom_end = 0x8F00
        self.assertEqual(
            emulator._bootstrap_clear_stage(
                self.RAM + 0x3100, self.RAM + 0x4000, self.RAM + 0x9000,
                self.STROBE,
            ),
            "open",
        )

    def test_noncontiguous_or_nonstrobe_work_is_rejected(self) -> None:
        emulator = self._emulator()

        self.assertIsNone(emulator._bootstrap_copy_stage(
            self.RAM + 0x1000, 0x6000, self.RAM + 0x3000, 0x8000, self.STROBE
        ))
        emulator.uc.mem_write(self.STROBE, bytes.fromhex("01 20 03 49 08 70 01 20 08 70"))
        self.assertFalse(emulator._thumb_watchdog_strobe(self.STROBE))

    def test_padded_nor_tail_cannot_open_bootstrap_copy(self) -> None:
        emulator = self._emulator()
        emulator.primary_rom_end = 0x8000

        self.assertIsNone(emulator._bootstrap_copy_stage(
            self.RAM + 0x100, 0x7000, self.RAM + 0x3000, 0x9000, self.STROBE
        ))


if __name__ == "__main__":
    unittest.main()
