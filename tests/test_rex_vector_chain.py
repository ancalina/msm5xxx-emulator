"""Synthetic reset copier and IRQ vector veneer closure."""
import struct
import unittest

from msm5xxx_emulator.detection.registry import device_domain
_RESET = device_domain('rex.vector_chain')._RESET
_RESET_LITERALS = device_domain('rex.vector_chain')._RESET_LITERALS
_COPY = device_domain('rex.vector_chain')._COPY
_COPY_LITERALS = device_domain('rex.vector_chain')._COPY_LITERALS
find_nor_veneer_vector_copy = device_domain('rex.vector_chain').find_nor_veneer_vector_copy
from test_legacy_keypad import literal


def word(image, at, value):
    struct.pack_into('<I', image, at, value & 0xffffffff)


def arm_branch(image, at, target):
    word(image, at, 0xea000000 | (((target - at - 8) >> 2) & 0xffffff))


class RexVectorChainTests(unittest.TestCase):
    def fixture(self):
        image = bytearray(0x3000)
        arm_branch(image, 0, 0x200)
        arm_branch(image, 0x18, 0x818)
        arm_branch(image, 0x818, 0x01000000)
        arm_branch(image, 0x800, 0x400)
        for entry, next_stage in ((0x200, 0x800), (0x400, 0x900)):
            image[entry:entry + len(_RESET)] = _RESET
            values = {}
            for off in (0, 0x18, 0x30, 0x60, 0x78):
                values[off] = 0x1001 if entry == 0x400 and off == 0x60 else 0x1201
                values[off + 8] = (entry + off + 20) | 1
                values[off + 12] = entry + off + 24
            for i, off in enumerate(_RESET_LITERALS):
                pool = entry + 0xa0 + 4 * i
                instruction = struct.unpack_from('<I', image, entry + off)[0]
                delta = pool - (entry + off + 8)
                assert 0 <= delta < 4096
                word(image, entry + off, instruction | 0x00800000 | delta)
                word(image, pool, values.get(off, 0x01001000))
            arm_branch(image, entry + 0x98, next_stage)
        image[0x1000:0x1000 + len(_COPY)] = _COPY
        values = {0: 0x03000700, 12: 0x944, 14: 0x948, 22: 0x940,
                  56: 0x980, 58: 0x984, 86: 0x92c, 88: 0x930, 96: 0x928,
                  124: 0x964, 126: 0x968, 134: 0x960}
        for i, off in enumerate(_COPY_LITERALS):
            reg = _COPY[off + 1] & 7
            literal(image, 0x1000 + off, reg, 0x1100 + i * 4, values[off])
        for table, source, dest in ((0x940, 0x2000, 0x02000000),
                                    (0x928, 0x2100, 0x01000000),
                                    (0x960, 0x2200, 0x03010000)):
            struct.pack_into('<III', image, table, source, dest, 0x40)
        word(image, 0x934, 0x01000040)
        word(image, 0x938, 0x80)
        word(image, 0x980, 0x01001000)
        word(image, 0x984, 0x100)
        # The branch is encoded relative to its eventual RAM address.
        delta = 0x2400 - 0x01000000 - 8
        word(image, 0x2100, 0xea000000 | ((delta >> 2) & 0xffffff))
        return image

    def test_vector_copy_veneer_and_source_mutations(self):
        image = self.fixture()
        def detect(data):
            return find_nor_veneer_vector_copy(data, ram_base=0x01000000, ram_size=0x800000)
        result = detect(image)
        self.assertEqual(result['copy_target'], 0x01000000)
        self.assertEqual(result['wrapper'], 0x2400)
        for offset in (0x18, 0x818, 0x200, 0x400, 0x1000, 0x928):
            altered = bytearray(image)
            altered[offset] ^= 1
            self.assertIsNone(detect(altered))
        altered = bytearray(image)
        altered[0x2100] ^= 1
        self.assertNotEqual(detect(altered)['wrapper'], result['wrapper'])

    def test_veneer_route_requires_nand_producer(self):
        from unittest.mock import patch
        from msm5xxx_emulator.detection.registry import device_domain
        _nand_backed_veneer_chain = device_domain('rex.rules')._nand_backed_veneer_chain
        with patch('msm5xxx_emulator.detection.devices.rex.rules.find_static_middle_nand_profile', return_value=None), \
             patch('msm5xxx_emulator.detection.devices.rex.rules.find_nor_veneer_vector_copy') as vector:
            self.assertIsNone(_nand_backed_veneer_chain(b'', ram_base=1, ram_size=2))
            vector.assert_not_called()
        with patch('msm5xxx_emulator.detection.devices.rex.rules.find_static_middle_nand_profile', return_value={}), \
             patch('msm5xxx_emulator.detection.devices.rex.rules.find_nor_veneer_vector_copy', return_value={'copy_target': 1}):
            self.assertEqual(_nand_backed_veneer_chain(b'', ram_base=1, ram_size=2), {'copy_target': 1})
