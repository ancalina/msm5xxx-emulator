"""Regression tests for shared MSM5000 board ADC reader discovery/device path."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import struct
import unittest
from unittest.mock import patch

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_ALL
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_R0

from msm5xxx import (BOARD_ADC_READER_DATA_ADDRESS,
                     BOARD_ADC_READER_READ_OFFSET, GenericMSMEmulator,
                     detect, find_board_adc_reader)
from msm5xxx_emulator.detection.input import (
    BOARD_ADC_READER_EXTENDED_FIXED,
    BOARD_ADC_READER_EXTENDED_SIZE,
    BOARD_ADC_READER_LITERAL,
    BOARD_ADC_READER_REORDERED_FIXED,
    BOARD_ADC_READER_VARIANT_SIZE,
    board_adc_reader_read_offset_at,
)


ROOT = Path(__file__).resolve().parent.parent


class BoardADCReaderTests(unittest.TestCase):
    readers = {
        "schx150.bin": 0x4050,
        "x350_VC22.bin": 0x4050,
        "SCH-X350_UJ08_JTAG.bin": 0x4050,
        "SCH-X250.bin": 0x4050,
        "SCH-x127.bin": 0x10050,
        "SPH-X4500.bin": 0x10050,
        "SPH-X7500-X75.00-WD01.bin": 0x1005C,
        "SPH-X7509.bin": 0x1005C,
        "SCH-X730.bin": 0x62C8,
        "SCH-x820.bin": 0x10050,
        "SCH-X270.bin": 0x5050,
        "sph-x8000.bin": 0x1005C,
        "X430_VE21_Dump.bin": 0x10050,
        "SCH-X430.bin": 0x10050,
        "SPH-X5900.bin": 0x1005C,
        "X4209.bin": 0x1005C,
        "x4000.bin": 0x605C,
    }

    def test_reordered_reader_grammar_is_exact(self) -> None:
        image = bytearray(BOARD_ADC_READER_VARIANT_SIZE)
        for offset, expected in BOARD_ADC_READER_REORDERED_FIXED:
            image[offset:offset + len(expected)] = expected
        struct.pack_into("<I", image, 0x98, BOARD_ADC_READER_LITERAL)
        self.assertEqual(board_adc_reader_read_offset_at(image, 0), 0x7C)
        image[0x2E] = 0x20
        self.assertIsNone(board_adc_reader_read_offset_at(image, 0))

    def test_extended_reader_grammar_is_exact(self) -> None:
        image = bytearray(BOARD_ADC_READER_EXTENDED_SIZE)
        for offset, expected in BOARD_ADC_READER_EXTENDED_FIXED:
            image[offset:offset + len(expected)] = expected
        struct.pack_into("<I", image, 0xA4, BOARD_ADC_READER_LITERAL)
        self.assertEqual(board_adc_reader_read_offset_at(image, 0), 0x88)
        image[0x70] = 0
        self.assertIsNone(board_adc_reader_read_offset_at(image, 0))

    def test_shared_reader_requires_complete_unique_grammar(self) -> None:
        if not (ROOT / "firmwares").is_dir():
            self.skipTest("private firmware corpus is not available")
        for name, expected in self.readers.items():
            image = (ROOT / "firmwares" / name).read_bytes()
            self.assertEqual(find_board_adc_reader(image), expected, name)
            expected_offset = (0x7E if name in {
                "schx150.bin", "x350_VC22.bin", "SCH-X350_UJ08_JTAG.bin",
                "SCH-X250.bin", "SCH-x127.bin", "SPH-X4500.bin",
            } else 0x7C)
            self.assertEqual(board_adc_reader_read_offset_at(image, expected),
                             expected_offset, name)

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
        for name in ("SPH-X7500-X75.00-WD01.bin", "SPH-X7509.bin"):
            self.assertEqual(
                detect(ROOT / "firmwares" / name).board_adc_reader_address,
                self.readers[name], name,
            )
        nested = ROOT / (
            "firmwares/incoming-msm5xxx-selected/bulk-msm5xxx-candidates/"
            "unpacked/A612_XB24/A612_XB24.bin"
        )
        if nested.is_file():
            self.assertEqual(find_board_adc_reader(nested.read_bytes()), 0x6050)

        image = bytearray((ROOT / "firmwares" / "SCH-X250.bin").read_bytes())
        reader = self.readers["SCH-X250.bin"]
        image[reader + 0x53] = 0
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((ROOT / "firmwares" / "SCH-X250.bin").read_bytes())
        duplicate = reader + 0x1000
        image[duplicate:duplicate + 0x98] = image[reader:reader + 0x98]
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((ROOT / "firmwares" / "SPH-X7509.bin").read_bytes())
        reader = self.readers["SPH-X7509.bin"]
        image[reader + 0x2E] = 0x40
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((ROOT / "firmwares" / "SCH-X270.bin").read_bytes())
        image[0x5050 + 0x2E] = 0x20
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((ROOT / "firmwares" / "SPH-X7509.bin").read_bytes())
        duplicate = reader + 0x1000
        image[duplicate:duplicate + 0x9C] = image[reader:reader + 0x9C]
        self.assertIsNone(find_board_adc_reader(image))

    def test_channel_two_only_changes_pristine_reader_low_byte(self) -> None:
        if not (ROOT / "firmwares").is_dir():
            self.skipTest("private firmware corpus is not available")
        self._assert_reader_hook("SCH-X250.bin", BOARD_ADC_READER_READ_OFFSET)
        self._assert_reader_hook("SPH-X7509.bin", 0x7C)
        self._assert_reader_hook("SCH-X270.bin", 0x7C)

    def test_layout_cache_revalidates_changed_pristine_body(self) -> None:
        if not (ROOT / "firmwares").is_dir():
            self.skipTest("private firmware corpus is not available")
        legacy = (ROOT / "firmwares" / "SCH-X250.bin").read_bytes()
        variant = (ROOT / "firmwares" / "SPH-X7509.bin").read_bytes()
        bodies = [legacy[0x4050:0x4050 + 0x98],
                  variant[0x1005C:0x1005C + 0x9C]]
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x03000000, 0x1000, UC_PROT_ALL)
        uc.reg_write(UC_ARM_REG_CPSR, 0x20)
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            board_adc_reader_address=0x1000, board_adc_value=0xC2,
        )
        emulator.board_adc_reads = 0
        emulator._board_adc_reader_channel = 2
        emulator._board_adc_reader_layout_cache = None
        emulator._original_runtime_bytes = lambda *_args: bodies[0]
        emulator._thumb_runtime_matches = lambda *_args, **_kwargs: True

        def read(offset: int) -> None:
            uc.mem_write(BOARD_ADC_READER_DATA_ADDRESS, b"\x5a\xa5")
            uc.reg_write(UC_ARM_REG_PC, 0x1000 + offset | 1)
            emulator._board_adc_reader_data_read(
                uc, BOARD_ADC_READER_DATA_ADDRESS, 2
            )

        with patch(
            "msm5xxx_emulator.soc.adc.board_adc_reader_read_offset_at",
            wraps=board_adc_reader_read_offset_at,
        ) as parsed:
            read(0x7E)
            emulator._board_adc_reader_channel = 2
            read(0x7E)
            self.assertEqual(parsed.call_count, 1)
            bodies[0] = bodies[1]
            emulator._board_adc_reader_channel = 2
            read(0x7C)
            self.assertEqual(parsed.call_count, 2)
        self.assertEqual(emulator.board_adc_reads, 3)

    def _assert_reader_hook(self, name: str, read_offset: int) -> None:
        image = (ROOT / "firmwares" / name).read_bytes()
        source = self.readers[name]
        reader = image[source:source + (0x9C if read_offset == 0x7C else 0x98)]
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x03000000, 0x1000, UC_PROT_ALL)
        uc.mem_write(0x1000, reader)
        uc.reg_write(UC_ARM_REG_CPSR, 0x20)

        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            board_adc_reader_address=0x1000,
            board_adc_value=0xC2,
            overlays=[], linker=None, load_address=0x1000, flash_size=len(reader),
            rex_irq_status_address=None,
        )
        emulator.original_image = reader
        emulator.board_adc_reads = 0
        emulator.board_adc_channel_entries = Counter()
        emulator._board_adc_reader_channel = None
        emulator._refresh_board_status_input = lambda *_: None
        emulator.ready_bits = {}
        emulator.mmio_reads = Counter()
        emulator.mmio_read_totals = Counter()

        def read_channel(channel: int, low: int) -> bytes:
            uc.mem_write(BOARD_ADC_READER_DATA_ADDRESS, bytes((low, 0xA5)))
            uc.reg_write(UC_ARM_REG_R0, channel)
            emulator._board_adc_reader_entry(uc, 0x1000, 2, None)
            uc.reg_write(UC_ARM_REG_PC, 0x1000 + read_offset | 1)
            emulator._read(uc, 0, BOARD_ADC_READER_DATA_ADDRESS, 2, 0, None)
            return bytes(uc.mem_read(BOARD_ADC_READER_DATA_ADDRESS, 2))

        self.assertEqual(read_channel(2, 0x5A), b"\xc2\xa5")
        self.assertEqual(emulator.board_adc_reads, 1)
        self.assertEqual(read_channel(1, 0x5A), b"\x5a\xa5")
        self.assertEqual(emulator.board_adc_reads, 1)
        self.assertEqual(emulator.board_adc_channel_entries, Counter({2: 1, 1: 1}))

        uc.mem_write(BOARD_ADC_READER_DATA_ADDRESS, b"\x5a\xa5")
        uc.reg_write(UC_ARM_REG_R0, 2)
        emulator._board_adc_reader_entry(uc, 0x1000, 2, None)
        uc.reg_write(UC_ARM_REG_PC, 0x1000 + read_offset + 2 | 1)
        emulator._read(uc, 0, BOARD_ADC_READER_DATA_ADDRESS, 2, 0, None)
        self.assertEqual(bytes(uc.mem_read(BOARD_ADC_READER_DATA_ADDRESS, 2)),
                         b"\x5a\xa5")
        self.assertEqual(emulator.board_adc_reads, 1)

        uc.mem_write(0x1000 + 0x16, b"\x00")
        self.assertEqual(read_channel(2, 0x5A), b"\x5a\xa5")
        self.assertEqual(emulator.board_adc_reads, 1)


if __name__ == "__main__":
    unittest.main()
