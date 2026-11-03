"""Synthetic paired-plane display source recognition."""
import unittest

from msm5xxx_emulator.detection.byte_pair128 import (
    _WRITERS, _PAGE_COLUMN, _FLUSH, _PREFIX, find_byte_pair128_profile,
)
from test_legacy_keypad import branch, literal


class BytePair128Tests(unittest.TestCase):
    def fixture(self):
        image = bytearray(0x2000)
        writer, init, flush = 0x100, 0x200, 0x500
        image[writer:writer + len(_WRITERS + _PAGE_COLUMN)] = _WRITERS + _PAGE_COLUMN
        for i, value in enumerate(_PREFIX):
            image[init + i * 6:init + i * 6 + 2] = bytes((value, 0x20))
            branch(image, init + i * 6 + 2, writer)
        image[flush:flush + len(_FLUSH)] = _FLUSH
        literal(image, flush + 2, 5, 0x700, 0x01001000)
        literal(image, flush + 8, 3, 0x704, 0x01002000)
        return image

    def test_page_writer_init_and_planes_are_linked(self):
        image = self.fixture()
        profile, reason = find_byte_pair128_profile(image)
        self.assertEqual(reason, 'accepted-source-byte-pair128-page')
        self.assertEqual(profile['plane_stride'], 0x800)
        for offset in (0x100, 0x200 + 2, 0x500, 0x704):
            altered = bytearray(image)
            altered[offset] ^= 1
            self.assertIsNone(find_byte_pair128_profile(altered)[0])
