"""Focused static admission checks for the SBI bootstrap-only bridge."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.input import find_sbi_bootstrap_profile


class SbiBootstrapProfileTest(unittest.TestCase):
    @staticmethod
    def _image(layout: str) -> tuple[bytearray, int]:
        image = bytearray(0x200)
        entry = 0x20
        if layout == "arithmetic":
            words = {
                0: 0x2045, 4: 0x7008, 6: 0x20C5, 8: 0x7008,
                0x0C: 0x303D, 0x0E: 0x8088, 0x12: 0x38F4, 0x14: 0x8188,
                0x16: 0x2000, 0x1A: 0x3110, 0x1C: 0x7008, 0x1E: 0x2001,
                0x20: 0x7008, 0x24: 0x8800, 0x26: 0x0840, 0x28: 0xD2FB,
                0x2C: 0x30DE, 0x30: 0x8188, 0x34: 0x8800, 0x36: 0x0840,
                0x38: 0xD306,
            }
            literals = (
                (2, 1, 0x03000780), (0x0A, 0, 0x0822),
                (0x10, 0, 0x0513), (0x18, 1, 0x03000780),
                (0x22, 0, 0x03000780), (0x2A, 0, 0x0822),
                (0x2E, 1, 0x03000780), (0x32, 0, 0x03000780),
            )
        else:
            words = {
                0: 0x2045, 4: 0x7008, 6: 0x20C5, 8: 0x7008,
                0x0C: 0x8088, 0x10: 0x8188, 0x12: 0x2000, 0x16: 0x7008,
                0x18: 0x2001, 0x1A: 0x7008, 0x1E: 0x8800, 0x20: 0x07C0,
                0x22: 0x0FC0, 0x24: 0x2801, 0x26: 0xD100, 0x28: 0xE7F8,
                0x2A: 0x2009, 0x2C: 0x0200, 0x30: 0x8188, 0x34: 0x8800,
                0x36: 0x07C0, 0x38: 0x0FC0, 0x3A: 0x2801, 0x3C: 0xD100,
                0x3E: 0xE7F8,
            }
            literals = (
                (2, 1, 0x03000780), (0x0A, 0, 0x085F),
                (0x0E, 0, 0x041F), (0x14, 1, 0x03000790),
                (0x1C, 0, 0x03000780), (0x2E, 1, 0x03000780),
                (0x32, 0, 0x03000780),
            )
        for offset, word in words.items():
            struct.pack_into("<H", image, entry + offset, word)
        for index, (offset, register, value) in enumerate(literals):
            literal = 0x100 + index * 4
            pc = (entry + offset + 4) & ~3
            struct.pack_into("<H", image, entry + offset,
                             0x4800 | register << 8 | (literal - pc) // 4)
            struct.pack_into("<I", image, literal, value)
        return image, entry

    def test_admits_both_exact_layouts_and_rejects_mutation(self) -> None:
        for layout, mutation in (("arithmetic", 0x28), ("direct", 0x3E)):
            with self.subTest(layout=layout):
                image, entry = self._image(layout)
                profile = find_sbi_bootstrap_profile(image)
                self.assertIsNotNone(profile)
                assert profile is not None
                self.assertEqual(profile["entries"], [entry])
                image[entry + mutation] ^= 1
                self.assertIsNone(find_sbi_bootstrap_profile(image))
