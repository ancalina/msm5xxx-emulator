"""Synthetic seven-row matrix and independent fold contact."""
import hashlib
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.input_table7 import (
    _PATTERN_SIZE, _CALLS, _LITERALS, _FOLD_SIZE, _FOLD_CALLS,
    _FOLD_LITERALS, find_table7_matrix,
)
from test_legacy_keypad import branch, literal


class Table7Tests(unittest.TestCase):
    def fixture(self):
        image = bytearray(0x4000)
        loop, fold, helper = 0x500, 0xa00, 0xd00
        descriptor, preserve = 0x01000200, 0xffffff80
        image[loop:loop + _PATTERN_SIZE] = bytes((i * 13 + 11) & 255 for i in range(_PATTERN_SIZE))
        image[loop + 0x4a:loop + 0x56] = bytes.fromhex("406b00880007000f0f281ed0")
        image[fold:fold + _FOLD_SIZE] = bytes((i * 19 + 3) & 255 for i in range(_FOLD_SIZE))
        for off, target in zip(_CALLS, (helper, 0xf00, 0xf20, helper)):
            branch(image, loop + off, target)
        vals = (descriptor, preserve, 0x01000300, preserve, descriptor, descriptor, 0x152c)
        for i, (off, value) in enumerate(zip(_LITERALS, vals)):
            reg = (2, 3, 3, 3, 2, 0, 2)[i]
            literal(image, loop + off, reg, 0x800 + i * 4, value)
        for off, target in zip(_FOLD_CALLS, (0xf40, 0xf60, 0xf40, 0xf80, 0xf60)):
            branch(image, fold + off, target)
        for i, off in enumerate(_FOLD_LITERALS):
            reg = (2, 0, 0, 0, 0, 0, 0, 0)[i]
            literal(image, fold + off, reg, 0xc00 + i * 4, descriptor if off == 16 else 0x01000000)
        branch(image, loop - 0xbc, fold)
        contact = loop - 0xa4
        image[contact - 2:contact + 2] = bytes.fromhex('606b0088')
        image[contact + 4:contact + 8] = bytes.fromhex('10231840')
        literal(image, contact - 4, 4, 0x7f0, descriptor)
        image[helper:helper + 2] = bytes.fromhex('00b5')
        branch(image, helper + 2, 0xf00)
        branch(image, helper + 26, 0xf20)
        literal(image, helper + 6, 1, 0xe00, descriptor)
        literal(image, helper + 8, 3, 0xe04, preserve)
        image[helper + 10:helper + 26] = bytes.fromhex('8a8b1a408a838a8b09690a80002801d1')
        image[0x1500:0x151c] = bytes(range(16)) + b'123456789*0#'
        for off, value in ((8, 0x300072c), (16, 0x3000724), (36, 0x3000728), (52, 0x300072c)):
            struct.pack_into('<I', image, 0x2200 + off, value)
        struct.pack_into('<7H', image, 0x2300, *(0x7f ^ (1 << b) for b in range(7)))
        return image

    def test_matrix_and_fold_source_linkage(self):
        image = self.fixture()
        def digest(start, size, calls, literals):
            code = bytearray(image[start:start + size])
            for offset in calls:
                code[offset:offset + 4] = bytes(4)
            for offset in literals:
                code[offset] = 0
            return hashlib.sha256(code).hexdigest()
        loop_hash = digest(0x500, _PATTERN_SIZE, _CALLS, _LITERALS)
        fold_hash = digest(0xa00, _FOLD_SIZE, _FOLD_CALLS, _FOLD_LITERALS)
        with patch('msm5xxx_emulator.detection.input_table7._PATTERN_HASH', loop_hash), \
             patch('msm5xxx_emulator.detection.input_table7._FOLD_HASH', fold_hash), \
             patch('msm5xxx_emulator.detection.input_table7._layouts',
                   return_value=[(0x100, 0x2000, 0x01000000, 0x400, 0)]):
            profile = find_table7_matrix(image)
            self.assertEqual((profile['rows'], profile['fold_input']['mask']), (7, 2))
            for offset in (0x500 + 0x4a, 0x2200 + 36, 0x2300, 0xa04):
                changed = bytearray(image)
                changed[offset] ^= 1
                self.assertIsNone(find_table7_matrix(changed))
