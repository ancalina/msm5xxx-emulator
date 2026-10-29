"""Focused static admission checks for the SBI bootstrap-only bridge."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.input import find_sbi_bootstrap_profile, _sbi_words_match


class SbiBootstrapProfileTest(unittest.TestCase):
    @staticmethod
    def _image(layout: str, entry: int | None = None) -> tuple[bytearray, int]:
        image = bytearray(0x400)
        if entry is None:
            entry = 0x80 if layout == "preserved" else 0x20
        if layout == "reloaded":
            words = {
                0:0x2045,4:0x7008,6:0x20C5,0x0A:0x7008,0x10:0x8088,
                0x16:0x8188,0x18:0x2000,0x1C:0x7408,0x1E:0x2001,0x22:0x7408,
                0x26:0x8800,0x28:0x07C0,0x2A:0x0FC0,0x2C:0x2801,
                0x2E:0xD100,0x30:0xE7F8,0x32:0x2009,0x34:0x0200,
                0x38:0x8188,0x3C:0x8800,0x3E:0x07C0,0x40:0x0FC0,
                0x42:0x2801,0x44:0xD100,0x46:0xE7F8,
            }
            literals = ((2,1,0x03000780),(8,1,0x03000780),(0x0C,0,0x085F),
                        (0x0E,1,0x03000780),(0x12,0,0x041F),(0x14,1,0x03000780),
                        (0x1A,1,0x03000780),(0x20,1,0x03000780),(0x24,0,0x03000780),
                        (0x36,1,0x03000780),(0x3A,0,0x03000780))
        elif layout == "preserved":
            prefix = bytes.fromhex(
                "012222732272d32080000921c90508840884088408840884088408840884"
                "0000000038800000b8800020b8823a8101256d033d830000bd833a253d823a84"
                "b8810000388604270f808a8000003877ff2101311981188118809880")
            words = {offset-0x5A:struct.unpack_from('<H',prefix,offset)[0]
                     for offset in range(0,len(prefix),2)}
            words.update({0:0x2545,4:0x700D,6:0x25C5,8:0x700D,0x0C:0x808D,
                          0x10:0x818D,0x12:0x7408,0x14:0x740A,0x16:0x880D,
                          0x18:0x07ED,0x1A:0x0FED,0x1C:0x2D01,0x1E:0xD0FA,
                          0x20:0x2509,0x22:0x022D,0x24:0x818D,0x26:0x880D,
                          0x28:0x07ED,0x2A:0x0FED,0x2C:0x2D01,0x2E:0xD0FA})
            literals = ((-0x3C,0,0x0822),(-0x3A,7,0x04800080),(-0x36,0,0x0222),
                        (-0x26,5,0x0513),(-0x1A,7,0x04800040),(-0x10,7,0x03000320),
                        (2,1,0x03000780),(0x0A,5,0x085F),(0x0E,5,0x041F))
        elif layout == "arithmetic":
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
            literal = 0x200 + index * 4
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

    def test_new_layouts_relocate_and_preserve_wire_contract(self) -> None:
        for layout in ("arithmetic", "direct", "reloaded", "preserved"):
            image, entry = self._image(layout)
            for shift in (0, 0x204):
                with self.subTest(layout=layout, shift=shift):
                    profile = find_sbi_bootstrap_profile(bytes(shift) + image)
                    self.assertIsNotNone(profile)
                    self.assertEqual(profile['entries'], [entry + shift])
                    self.assertEqual(profile['signature'], 'thumb-sbi-bootstrap-only-v1')
                    self.assertEqual(profile['admission'], 'temporary-evidence-gated')
                    self.assertEqual(profile['bootstrap'], [[0,1,0x45],[0,1,0xC5],
                                     [4,2,0x085F],[12,2,0x041F],[16,1,0],[16,1,1]])
                    self.assertEqual(profile['validation'], [[0,2,None],[12,2,0x0900],[0,2,None]])
                    self.assertNotIn('C11', profile['layout'])
                    self.assertNotIn('N200', profile['layout'])

    def test_new_layout_mutations_unknown_registers_values_and_edges(self) -> None:
        mutations = {
            'reloaded': (0,4,6,0x0A,0x10,0x16,0x18,0x1C,0x1E,0x22,0x26,
                         0x2C,0x2E,0x30,0x32,0x34,0x38,0x3C,0x44,0x46),
            'preserved': (-0x5A,-0x58,-0x54,-0x32,-0x30,-0x2E,-0x14,-0x0C,
                          0,4,6,8,0x0C,0x10,0x12,0x14,0x16,0x1C,0x1E,
                          0x20,0x22,0x24,0x26,0x2C,0x2E),
        }
        for layout, offsets in mutations.items():
            image, entry = self._image(layout)
            for offset in offsets:
                with self.subTest(layout=layout, offset=offset):
                    changed = bytearray(image); changed[entry + offset] ^= 1
                    self.assertIsNone(find_sbi_bootstrap_profile(bytes(changed)))
            for offset in range(0x200, 0x200 + (11 if layout == "reloaded" else 9) * 4, 4):
                changed = bytearray(image); changed[offset] ^= 1
                self.assertIsNone(find_sbi_bootstrap_profile(bytes(changed)))
            stores = (4,0x0A,0x10,0x16,0x1C,0x22,0x26,0x38,0x3C) if layout == 'reloaded' else (4,8,0x0C,0x10,0x12,0x14,0x16,0x24,0x26)
            for offset in stores:
                changed = bytearray(image)
                opcode = struct.unpack_from('<H', changed, entry + offset)[0]
                struct.pack_into('<H', changed, entry + offset, opcode ^ 0x1000)
                self.assertIsNone(find_sbi_bootstrap_profile(bytes(changed)))
            end = entry + (0x48 if layout == 'reloaded' else 0x30)
            self.assertIsNone(find_sbi_bootstrap_profile(bytes(image[:end-1])))
            self.assertIsNone(find_sbi_bootstrap_profile(bytes(image[:0x220])))
            self.assertIsNone(find_sbi_bootstrap_profile(bytes(image) * 2))
        first, _ = self._image('reloaded'); second, _ = self._image('preserved')
        self.assertIsNone(find_sbi_bootstrap_profile(bytes(first) + bytes(second)))

    def test_preserved_prefix_lower_bound_and_odd_alignment(self) -> None:
        self.assertFalse(_sbi_words_match(bytes(4), 0, {-2: 0}))
        image, entry = self._image('preserved', 0x5A)
        self.assertIsNotNone(find_sbi_bootstrap_profile(bytes(image)))
        # Remove the first producer while preserving every later relative position.
        self.assertIsNone(find_sbi_bootstrap_profile(bytes(image[2:])))
        self.assertIsNone(find_sbi_bootstrap_profile(b'\0' + bytes(image)))
        image, entry = self._image('reloaded', 0)
        self.assertIsNotNone(find_sbi_bootstrap_profile(bytes(image)))
