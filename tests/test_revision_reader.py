"""Synthetic source-shape checks for a cached hardware revision reader."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.devices.boot.revision_reader import find_cached_revision


def _put16(image: bytearray, offset: int, *values: int) -> None:
    struct.pack_into(f'<{len(values)}H', image, offset, *values)


def _put32(image: bytearray, offset: int, *values: int) -> None:
    struct.pack_into(f'<{len(values)}I', image, offset, *values)


def _ldr_literal(register: int, instruction: int, literal: int) -> int:
    pc = (instruction + 4) & ~3
    delta = literal - pc
    assert delta >= 0 and delta % 4 == 0 and delta // 4 < 256
    return 0x4800 | (register << 8) | (delta // 4)


def _thumb_bl(source: int, target: int) -> tuple[int, int]:
    displacement = target - (source + 4)
    immediate = (displacement >> 1) & 0xFFFFFF
    return 0xF000 | (immediate >> 11 & 0x7ff), 0xF800 | (immediate & 0x7ff)


def _synthetic_image(*, load_width='halfword', transform_shift=8,
                     threshold=0xf051, accepted_shift=15, link_reader=True) -> bytes:
    image = bytearray(0x200)
    # Reader: read the revision register, perform its 16-bit permutation,
    # cache the result as a halfword, then return the cached halfword.
    reader = 0x100
    _put16(image, reader,
           _ldr_literal(1, reader, 0x140),
           _ldr_literal(0, reader + 2, 0x144),
           0x8b80 if load_width == 'halfword' else 0x6880,
           0x0a02,
           0x23f0,
           0x401a,
           0x4003,
           0x001b | (transform_shift << 6),
           0x0700,
           0x0f00,
           0x431a,
           0x4310,
           0x8048,
           0x8848,
           0x4770)
    _put32(image, 0x140, 0x14010000, 0x03000740)

    # Consumer: call the reader, compare with a literal threshold, and return
    # zero below it or 0x8000 at and above it.
    helper = 0x180
    call = helper + 2
    high, low = _thumb_bl(call, reader)
    _put16(image, helper, 0xb500, high, low,
           _ldr_literal(1, helper + 6, 0x1a0),
           0x4288,
           0xd303,
           0x2001,
           0x03c0 if accepted_shift == 15 else 0x0380,
           0xbc08,
           0x4718,
           0x2000,
           0xbc08,
           0x4718)
    _put32(image, 0x1a0, threshold)
    if not link_reader:
        _put16(image, call, 0x46c0, 0x46c0)
    return bytes(image)


class CachedRevisionSourceTests(unittest.TestCase):
    def test_linked_halfword_permutation_and_threshold_are_accepted(self):
        profile = find_cached_revision(_synthetic_image())
        self.assertIsNotNone(profile)
        self.assertEqual(profile['register'], 0x0300075c)
        self.assertEqual(profile['raw_value'], 0x20f5)
        self.assertEqual(profile['revision'], 0xf025)
        self.assertEqual(profile['threshold'], 0xf051)
        self.assertTrue(profile['evidence'])

    def test_wrong_read_width_or_permutation_is_rejected(self):
        self.assertIsNone(find_cached_revision(_synthetic_image(load_width='word')))
        self.assertIsNone(find_cached_revision(_synthetic_image(transform_shift=7)))

    def test_wrong_threshold_result_or_reader_link_is_rejected(self):
        self.assertIsNone(find_cached_revision(_synthetic_image(threshold=0xf050)))
        self.assertIsNone(find_cached_revision(_synthetic_image(accepted_shift=14)))
        self.assertIsNone(find_cached_revision(_synthetic_image(link_reader=False)))


if __name__ == '__main__':
    unittest.main()
