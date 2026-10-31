"""Regression tests for shared MSM5000 board ADC reader discovery/device path."""
from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


from msm5xxx_emulator.detection.input import BOARD_ADC_READER_DATA_ADDRESS, find_board_adc_reader
from msm5xxx_emulator.detection.boot import BOARD_ADC_READER_READ_OFFSET
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.input import (
    BOARD_ADC_READER_EXTENDED_FIXED,
    BOARD_ADC_READER_EXTENDED_SIZE,
    BOARD_ADC_READER_LITERAL,
    BOARD_ADC_READER_REORDERED_FIXED,
    BOARD_ADC_READER_VARIANT_SIZE,
    board_adc_reader_read_offset_at,
    find_dc0_board_adc_profile,
)
from corpus import FIRMWARE_ROOT


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
        "X700_Kor_Eng.bin": 0x10050,
    }

    def test_dc0_battery_policy_is_complete_and_fail_closed(self) -> None:
        firmware = FIRMWARE_ROOT / "KTFT_X3500_verX3p56.73.0_riffdump_clean.bin"
        if not firmware.is_file():
            self.skipTest("private firmware corpus is not available")
        image = bytearray(firmware.read_bytes())
        profile = find_dc0_board_adc_profile(image)
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertTrue(profile["accepted"])
        self.assertEqual(profile["response_raw"], 0xFF)
        self.assertEqual(profile["low_thresholds"], [0xC8, 0xDE])
        self.assertEqual(profile["caller_offsets"], [0x550DA2, 0x550E4E])
        config = detect(firmware)
        self.assertEqual(config.board_adc_value, 0xC2)
        self.assertEqual(config.dc0_board_adc_profile, profile)
        self.assertIn("virtual full raw byte", " ".join(config.detection_notes))

        invalid_root = bytearray(image)
        struct.pack_into("<I", invalid_root, 0x3D00EC, 0)
        struct.pack_into("<I", invalid_root, 0x3D0110, 0)
        rejected = find_dc0_board_adc_profile(invalid_root)
        self.assertIsNotNone(rejected)
        assert rejected is not None
        self.assertEqual(rejected["reject_reason"],
                         "raw-getter/service-grammar-mismatch")

        image[int(profile["filter_offset"]) + 0xCA] ^= 1
        rejected = find_dc0_board_adc_profile(image)
        self.assertIsNotNone(rejected)
        assert rejected is not None
        self.assertFalse(rejected["accepted"])
        self.assertEqual(rejected["reject_reason"],
                         "battery-filter-policy-mismatch")
        with tempfile.NamedTemporaryFile(suffix=".bin") as changed:
            changed.write(image)
            changed.flush()
            fallback = detect(Path(changed.name))
        self.assertEqual(fallback.board_adc_value, 0xC2)
        self.assertFalse(fallback.dc0_board_adc_profile["accepted"])
        self.assertIn("battery-filter-policy-mismatch",
                      " ".join(fallback.detection_notes))

        peer = firmware.with_name("LG-KH5000.bin")
        if peer.is_file():
            rejected = find_dc0_board_adc_profile(peer.read_bytes())
            self.assertIsNotNone(rejected)
            assert rejected is not None
            self.assertFalse(rejected["accepted"])
            self.assertEqual(rejected["reject_reason"],
                             "battery-filter-consumer-not-unique")
            self.assertEqual(detect(peer).board_adc_value, 0xC2)

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
        if not FIRMWARE_ROOT.is_dir():
            self.skipTest("private firmware corpus is not available")
        for name, expected in self.readers.items():
            image = (FIRMWARE_ROOT / name).read_bytes()
            self.assertEqual(find_board_adc_reader(image), expected, name)
            expected_offset = (0x88 if name == "X700_Kor_Eng.bin" else 0x7E if name in {
                "schx150.bin", "x350_VC22.bin", "SCH-X350_UJ08_JTAG.bin",
                "SCH-X250.bin", "SCH-x127.bin", "SPH-X4500.bin",
            } else 0x7C)
            self.assertEqual(board_adc_reader_read_offset_at(image, expected),
                             expected_offset, name)

        detected = {
            firmware.name: address
            for firmware in FIRMWARE_ROOT.iterdir()
            if firmware.is_file()
            and (address := find_board_adc_reader(firmware.read_bytes())) is not None
        }
        self.assertEqual(detected, self.readers)
        extended = bytearray((FIRMWARE_ROOT / "X700_Kor_Eng.bin").read_bytes())
        extended[self.readers["X700_Kor_Eng.bin"] + 0x70] = 0
        self.assertIsNone(find_board_adc_reader(extended))
        self.assertEqual(
            detect(FIRMWARE_ROOT / "SCH-X250.bin").board_adc_reader_address,
            self.readers["SCH-X250.bin"],
        )
        for name in ("SPH-X7500-X75.00-WD01.bin", "SPH-X7509.bin"):
            self.assertEqual(
                detect(FIRMWARE_ROOT / name).board_adc_reader_address,
                self.readers[name], name,
            )
        nested = FIRMWARE_ROOT / (
            "incoming-msm5xxx-selected/bulk-msm5xxx-candidates/"
            "unpacked/A612_XB24/A612_XB24.bin"
        )
        if nested.is_file():
            self.assertEqual(find_board_adc_reader(nested.read_bytes()), 0x6050)

        image = bytearray((FIRMWARE_ROOT / "SCH-X250.bin").read_bytes())
        reader = self.readers["SCH-X250.bin"]
        image[reader + 0x53] = 0
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((FIRMWARE_ROOT / "SCH-X250.bin").read_bytes())
        duplicate = reader + 0x1000
        image[duplicate:duplicate + 0x98] = image[reader:reader + 0x98]
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((FIRMWARE_ROOT / "SPH-X7509.bin").read_bytes())
        reader = self.readers["SPH-X7509.bin"]
        image[reader + 0x2E] = 0x40
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((FIRMWARE_ROOT / "SCH-X270.bin").read_bytes())
        image[0x5050 + 0x2E] = 0x20
        self.assertIsNone(find_board_adc_reader(image))

        image = bytearray((FIRMWARE_ROOT / "SPH-X7509.bin").read_bytes())
        duplicate = reader + 0x1000
        image[duplicate:duplicate + 0x9C] = image[reader:reader + 0x9C]
        self.assertIsNone(find_board_adc_reader(image))


if __name__ == "__main__":
    unittest.main()
