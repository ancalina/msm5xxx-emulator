"""Synthetic linker-row evidence for the generic two-bank RAM envelope."""
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.core.config import LinkerLayout
from msm5xxx_emulator.detection.devices.memory import capture


def linked_image(*, target=0x01700000, data_size=0x00100000,
                 bss_size=0x00100000, source=0x1000, load=0):
    image = bytearray(0x110000)
    table = 0x100
    bss_target = target + data_size
    struct.pack_into("<5I", image, table, source, target, data_size,
                     bss_target, bss_size)
    return image, LinkerLayout(table, source, target, data_size,
                               bss_target, bss_size)


class LinkerRamSpanTests(unittest.TestCase):
    def capture(self, image, linker, *, load=0, ram_base=None, ram_size=None,
                image_kind="firmware"):
        # Keep these policy tests independent from reset/bootstrap signatures.
        patches = (
            patch.object(capture, "infer_ram_base", return_value=0x01000000),
            patch.object(capture, "reset_copy_ram_profile", return_value=None),
            patch.object(capture, "high_ram_bootstrap_profile", return_value=None),
            patch.object(capture, "dual_stage_ram_profile", return_value=(None, None)),
            patch.object(capture, "has_dual_sdram_bootstrap", return_value=False),
            patch.object(capture, "has_high_bank_reader_bootstrap", return_value=False),
            patch.object(capture, "find_high_ram_readback_tests", return_value=[]),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            notes = []
            result = capture.capture_layout(
                bytes(image), linker, "MSM5000", load, ram_base, ram_size,
                image_kind, notes,
            )
        return result, notes

    def test_contiguous_source_linker_span_crossing_banks_widens(self):
        image, linker = linked_image()
        (base, size, profile, _image), notes = self.capture(image, linker)
        self.assertEqual((base, size), (0x01000000, 0x01000000))
        self.assertIsNone(profile)
        self.assertIn("source-proven linker RAM envelope detected; capacity unverified", notes)

    def test_single_bank_span_keeps_default_size(self):
        image, linker = linked_image(target=0x01000000)
        (base, size, _profile, _image), notes = self.capture(image, linker)
        self.assertEqual((base, size), (0x01000000, 0x00800000))
        self.assertFalse(any("source-proven linker" in note for note in notes))

    def test_bad_or_unmatched_linker_rows_do_not_widen(self):
        image, linker = linked_image()
        corrupt = bytearray(image)
        corrupt[0x104] ^= 1
        outside_image, outside_linker = linked_image(source=0x00ff0000)
        # The source is valid in the synthetic loaded image but extends past ROM.
        outside_image.extend(bytes(0x00f00000))
        outside_linker.data_size = 0x20000
        struct.pack_into("<I", outside_image, outside_linker.table_offset + 8,
                          outside_linker.data_size)
        outside_linker.bss_target = outside_linker.data_target + outside_linker.data_size
        struct.pack_into("<I", outside_image, outside_linker.table_offset + 12,
                          outside_linker.bss_target)
        oversized_image, oversized = linked_image(
            target=0x01eff000, data_size=0x00100000, bss_size=0x2000)
        noncontiguous_image, noncontiguous = linked_image()
        noncontiguous.bss_target += 4
        struct.pack_into("<I", noncontiguous_image, noncontiguous.table_offset + 12,
                          noncontiguous.bss_target)

        for candidate_image, candidate in (
                (corrupt, linker),
                (outside_image, outside_linker),
                (oversized_image, oversized),
                (noncontiguous_image, noncontiguous)):
            with self.subTest(layout=candidate):
                (base, size, _profile, _image), notes = self.capture(candidate_image, candidate)
                self.assertEqual((base, size), (0x01000000, 0x00800000))
                self.assertFalse(any("source-proven linker" in note for note in notes))

    def test_explicit_ram_overrides_keep_priority(self):
        image, linker = linked_image()
        for base_override, size_override, expected in (
                (0x01800000, None, (0x01800000, 0x00800000)),
                (None, 0x00400000, (0x01000000, 0x00400000))):
            with self.subTest(overrides=(base_override, size_override)):
                (base, size, _profile, _image), notes = self.capture(
                    image, linker, ram_base=base_override,
                    ram_size=size_override)
                self.assertEqual((base, size), expected)
                self.assertFalse(any("source-proven linker" in note for note in notes))


if __name__ == "__main__":
    unittest.main()
