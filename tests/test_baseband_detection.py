"""Focused static-only auxiliary completion shape tests."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.baseband import detect_aux_completion_shape


def _image() -> bytearray:
    image = bytearray(b"\xff" * 0x100)
    words = (
        0xB5F0, 0x1C02, 0x1C0B, 0x2400, 0x481D, 0x7801, 0x2601, 0x40A6,
        0x4F1F, 0x703E, 0x250A, 0x4365, 0x18AD, 0x8028, 0x8068, 0x80A8,
        0x60A8, 0x4818, 0x8801, 0x4818, 0x7801, 0x4818, 0x8801, 0x429C,
        0xD1F1, 0xE003, 0x80A8, 0x0000, 0x0000, 0x60A8, 0xBDF0,
    )
    struct.pack_into(f"<{len(words)}H", image, 0, *words)
    struct.pack_into("<5I", image, 0x80, 0x1000, 0x1004, 0x1008, 0x100C, 0x1010)
    return image


def _literal_clobber_image() -> bytearray:
    image = bytearray(b"\xff" * 0x100)
    words = (
        0xB5F0, 0x1C02, 0x1C0B, 0x2400, 0x491D, 0x2100, 0x780A, 0x2601,
        0x40A6, 0x4F1F, 0x703E, 0x250A, 0x4365, 0x18AD, 0x8028, 0x8068,
        0x80A8, 0x60A8, 0x4811, 0x8801, 0x480F, 0x7801, 0x480F, 0x8801,
        0x429C, 0xD1F1, 0xE003, 0x80A8, 0x0000, 0x0000, 0x60A8, 0xBDF0,
    )
    struct.pack_into(f"<{len(words)}H", image, 0, *words)
    struct.pack_into("<5I", image, 0x80, 0x1000, 0x1004, 0x1008, 0x100C, 0x1010)
    return image


class BasebandDetectionTests(unittest.TestCase):
    def test_unique_shape_and_fail_closed_variants(self) -> None:
        image = _image()
        accepted = detect_aux_completion_shape(bytes(image), 0).as_dict()
        self.assertEqual(accepted["confidence"], "static-shape")
        self.assertEqual(accepted["work_stride"], 10)
        self.assertEqual(accepted["record_u16_offsets"], (0, 2, 4))
        self.assertEqual(
            (accepted["saved_work_register"], accepted["saved_count_register"],
             accepted["index_register"]),
            (2, 3, 4),
        )
        self.assertEqual(accepted["selector"], {"pc": 16, "base": 0x1010, "offset": 0})
        self.assertEqual(accepted["loads"], {
            "E": {"pc": 8, "use_pc": 10, "base": 0x1000, "width": "u8", "offset": 0, "value_register": 1},
            "M": {"pc": 34, "use_pc": 36, "base": 0x1004, "width": "u16", "offset": 0, "value_register": 1},
            "L": {"pc": 38, "use_pc": 40, "base": 0x1008, "width": "u8", "offset": 0, "value_register": 1},
            "S": {"pc": 42, "use_pc": 44, "base": 0x100C, "width": "u16", "offset": 0, "value_register": 1},
        })
        rebased = detect_aux_completion_shape(bytes(image), 0x1000, 0x1000)
        self.assertEqual(rebased.confidence, "static-shape")
        self.assertEqual(rebased.entry_file_offset, 0x1000)
        self.assertEqual(rebased.return_file_offset, 0x103C)
        self.assertEqual(rebased.selector.pc, 0x1010)

        near_miss = bytearray(image)
        struct.pack_into("<H", near_miss, 30, 0x7028)
        self.assertEqual(
            detect_aux_completion_shape(bytes(near_miss), 0).reject_reason,
            "aux-w-3xu16-u32-store-shape-missing",
        )

        stale_alias = bytearray(image)
        struct.pack_into("<2H", stale_alias, 30, 0x7028, 0x7028)
        struct.pack_into(
            "<5H", stale_alias, 50,
            0x1C28, 0x2000, 0x8081, 0x6081, 0xE7FF,
        )
        self.assertEqual(
            detect_aux_completion_shape(bytes(stale_alias), 0).reject_reason,
            "aux-w-3xu16-u32-store-shape-missing",
        )

        self.assertEqual(
            detect_aux_completion_shape(
                bytes(_literal_clobber_image()), 0
            ).reject_reason,
            "aux-e-m-l-s-width-shape-missing",
        )

        ambiguous = bytearray(image)
        struct.pack_into("<2H", ambiguous, 32, 0x4365, 0x18AD)
        self.assertEqual(
            detect_aux_completion_shape(bytes(ambiguous), 0).reject_reason,
            "aux-record-base-cardinality:2",
        )
