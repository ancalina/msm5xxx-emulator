"""Regression tests for shared MSM5000 board ADC reader discovery/device path."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import unittest

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_ALL
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_R0

from msm5xxx import (BOARD_ADC_READER_DATA_ADDRESS,
                     BOARD_ADC_READER_READ_OFFSET, GenericMSMEmulator,
                     detect, find_board_adc_reader)


ROOT = Path(__file__).resolve().parent.parent


class BoardADCReaderTests(unittest.TestCase):
    readers = {
        "schx150.bin": 0x4050,
        "x350_VC22.bin": 0x4050,
        "SCH-X350_UJ08_JTAG.bin": 0x4050,
        "SCH-X250.bin": 0x4050,
        "SCH-x127.bin": 0x10050,
        "SPH-X4500.bin": 0x10050,
    }

    def test_shared_reader_requires_complete_unique_grammar(self) -> None:
        if not (ROOT / "firmwares").is_dir():
            self.skipTest("private firmware corpus is not available")
        for name, expected in self.readers.items():
            image = (ROOT / "firmwares" / name).read_bytes()
            self.assertEqual(find_board_adc_reader(image), expected, name)

        detected = {
            firmware.name: address
            for firmware in ROOT.joinpath("firmwares").iterdir()
            if firmware.is_file()
            and (address := find_board_adc_reader(firmware.read_bytes())) is not None
        }
        self.assertEqual(detected, self.readers)
        self.assertEqual(
            detect(ROOT / "firmwares" / "SCH-X250.bin").board_adc_reader_address,
            self.readers["SCH-X250.bin"],
        )

        image = bytearray((ROOT / "firmwares" / "SCH-X250.bin").read_bytes())
        reader = self.readers["SCH-X250.bin"]
        image[reader + 0x53] = 0
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((ROOT / "firmwares" / "SCH-X250.bin").read_bytes())
        duplicate = reader + 0x1000
        image[duplicate:duplicate + 0x98] = image[reader:reader + 0x98]
        self.assertIsNone(find_board_adc_reader(image))

    def test_channel_two_only_changes_pristine_reader_low_byte(self) -> None:
        if not (ROOT / "firmwares").is_dir():
            self.skipTest("private firmware corpus is not available")
        image = (ROOT / "firmwares" / "SCH-X250.bin").read_bytes()
        source = self.readers["SCH-X250.bin"]
        reader = image[source:source + 0x98]
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x03000000, 0x1000, UC_PROT_ALL)
        uc.mem_write(0x1000, reader)
        uc.reg_write(UC_ARM_REG_CPSR, 0x20)

        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            board_adc_reader_address=0x1000,
            board_adc_value=0xC2,
            overlays=[], linker=None, load_address=0x1000, flash_size=0x1000,
            rex_irq_status_address=None,
        )
        emulator.original_image = reader + b"\xff" * (0x1000 - len(reader))
        emulator.board_adc_reads = 0
        emulator._board_adc_reader_channel = None
        emulator._refresh_board_status_input = lambda *_: None
        emulator.ready_bits = {}
        emulator.mmio_reads = Counter()
        emulator.mmio_read_totals = Counter()

        def read_channel(channel: int, low: int) -> bytes:
            uc.mem_write(BOARD_ADC_READER_DATA_ADDRESS, bytes((low, 0xA5)))
            uc.reg_write(UC_ARM_REG_R0, channel)
            emulator._board_adc_reader_entry(uc, 0x1000, 2, None)
            uc.reg_write(UC_ARM_REG_PC, 0x1000 + BOARD_ADC_READER_READ_OFFSET | 1)
            emulator._read(uc, 0, BOARD_ADC_READER_DATA_ADDRESS, 2, 0, None)
            return bytes(uc.mem_read(BOARD_ADC_READER_DATA_ADDRESS, 2))

        self.assertEqual(read_channel(2, 0x5A), b"\xc2\xa5")
        self.assertEqual(emulator.board_adc_reads, 1)
        self.assertEqual(read_channel(1, 0x5A), b"\x5a\xa5")
        self.assertEqual(emulator.board_adc_reads, 1)

        uc.mem_write(0x1000 + 0x16, b"\x00")
        self.assertEqual(read_channel(2, 0x5A), b"\x5a\xa5")
        self.assertEqual(emulator.board_adc_reads, 1)


if __name__ == "__main__":
    unittest.main()
