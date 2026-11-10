"""Independent synthetic checks for masked instruction contracts."""
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain
protected_nor = device_domain('storage.protected_nor')


def program(with_call=False):
    image = bytearray(0x180)
    entry, pool, target = 0x100, 0x110, 0x140
    literal = 0x4900 | (pool - ((entry + 4) & ~3)) // 4
    if with_call:
        displacement = target - (entry + 2) - 4
        struct.pack_into('<5H', image, entry, literal,
                         0xF000 | (displacement >> 12 & 0x7FF),
                         0xF800 | (displacement >> 1 & 0x7FF), 0x2000, 0x4770)
        mask = '??49????????00207047'
    else:
        struct.pack_into('<3H', image, entry, literal, 0x2000, 0x4770)
        mask = '??4900207047'
    struct.pack_into('<I', image, pool, 0x03000720)
    struct.pack_into('<H', image, target, 0x4770)
    return image, entry, pool, mask


class ProtectedNorContractTests(unittest.TestCase):
    def test_literal_contract_and_pool_capture(self):
        image, entry, pool, mask = program()
        with patch.dict(protected_nor._BODY_SPECS,
                        {'synthetic': protected_nor._body_spec(mask)}):
            body = protected_nor._body(bytes(image), entry, 'synthetic')
            self.assertEqual(body.values, {0: 0x03000720})
            self.assertEqual(body.pools, (pool,))
            self.assertTrue(protected_nor._code(bytes(image), entry, 'synthetic'))
            self.assertEqual(list(protected_nor._hits(bytes(image), 'synthetic')), [entry])
            changed = bytearray(image)
            struct.pack_into('<H', changed, entry + 2, 0x2100)
            self.assertFalse(protected_nor._body(bytes(changed), entry, 'synthetic'))
            self.assertFalse(protected_nor._code(bytes(changed), entry, 'synthetic'))
            self.assertFalse(protected_nor._body(bytes(image[:pool]), entry, 'synthetic'))

    def test_call_and_literal_fields_are_separate_evidence(self):
        image, entry, pool, mask = program(with_call=True)
        with patch.dict(protected_nor._BODY_SPECS,
                        {'synthetic': protected_nor._body_spec(mask)}):
            body = protected_nor._body(bytes(image), entry, 'synthetic')
            self.assertEqual(body.targets, {2: 0x140})
            self.assertEqual(body.values, {0: 0x03000720})
            self.assertTrue(protected_nor._code(bytes(image), entry, 'synthetic'))
            changed = bytearray(image)
            changed[entry + 2:entry + 6] = bytes(4)
            self.assertFalse(protected_nor._body(bytes(changed), entry, 'synthetic'))
            self.assertFalse(protected_nor._code(bytes(changed), entry, 'synthetic'))
