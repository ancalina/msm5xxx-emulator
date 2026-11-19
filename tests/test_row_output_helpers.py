"""Synthetic source summary for linked keypad row clear helpers."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.devices.input.sparse_rows import (
    find_sparse_row_scanners,
)

from test_sparse_rows import _bl, _image, _put16, _put32


def _helper_image():
    image = _image()
    descriptor = 0x01000100
    entry = 0x0a00
    _bl(image, 0x504, entry)
    words = {
        0x00: 0xB500,  # PUSH {lr}
        0x06: 0x4907,  # LDR r1, [pc, #0x1c]
        0x08: 0x233F,  # MOVS r3, #0x3f
        0x0A: 0x8800 | (14 << 6) | (1 << 3) | 2,  # LDRH r2, [r1, #0x1c]
        0x0C: 0x021B,  # LSLS r3, r3, #8
        0x0E: 0x439A,  # BICS r2, r3
        0x10: 0x8000 | (14 << 6) | (1 << 3) | 2,  # STRH r2, [r1, #0x1c]
        0x12: 0x8800 | (14 << 6) | (1 << 3) | 2,  # LDRH r2, [r1, #0x1c]
        0x14: 0x6800 | (4 << 6) | (1 << 3) | 1,  # LDR r1, [r1, #0x10]
        0x16: 0x8000 | (1 << 3) | 2,  # STRH r2, [r1]
        0x18: 0x2800,  # CMP r0, #0
        0x1A: 0xD101,  # BNE return
        0x20: 0xBC08,  # POP {r3}
        0x22: 0x4718,  # BX r3
    }
    for offset, word in words.items():
        _put16(image, entry + offset, word)
    _bl(image, entry + 2, 0x1000)
    _bl(image, entry + 0x1C, 0x1020)
    _put32(image, entry + 0x24, descriptor)
    return image


class RowOutputHelperTests(unittest.TestCase):
    def test_linked_clear_commit_helper_is_summarized(self):
        image = _helper_image()
        profiles = find_sparse_row_scanners(image)
        self.assertEqual(len(profiles), 1)
        dependencies = profiles[0]["dependencies"]
        for span in ((0x0A00, 36), (0x0A24, 4), (0x1000, 24),
                     (0x1020, 24)):
            self.assertIn(span, dependencies)

    def test_rejects_changed_descriptor_mask_commit_and_irq_pair(self):
        mutations = (
            (0x0A24, lambda image: _put32(image, 0x0A24, 0x01000104)),
            (0x0A08, lambda image: _put16(image, 0x0A08, 0x237F)),
            (0x0A16, lambda image: _put16(image, 0x0A16, 0x8012)),
        )
        for label, (site, mutate) in enumerate(mutations):
            with self.subTest(site=hex(site), case=label):
                image = _helper_image()
                mutate(image)
                self.assertEqual(find_sparse_row_scanners(image), [])

        image = _helper_image()
        _bl(image, 0x0A1C, 0x1000)
        self.assertEqual(find_sparse_row_scanners(image), [])

    def test_rejects_unrecognized_helper_callee(self):
        image = _helper_image()
        _bl(image, 0x0A02, 0x0B00)
        self.assertEqual(find_sparse_row_scanners(image), [])


if __name__ == "__main__":
    unittest.main()
