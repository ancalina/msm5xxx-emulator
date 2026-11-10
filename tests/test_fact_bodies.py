import hashlib
import struct
import unittest
from capstone.arm import ARM_REG_R0

from msm5xxx_emulator.detection.fact_bodies import (
    match_thumb_shape, normalized_body,
)
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.values import CodeAddress


class NormalizedBodyTests(unittest.TestCase):
    def test_thumb_call_normalization_and_truncated_prefix(self):
        image = bytes.fromhex('00f000f87047')
        facts = facts_for(image)
        body = normalized_body(
            facts, CodeAddress(0, 'thumb'), 4, limit=len(image),
            thumb_calls=(0,), call_fill=b'CALL',
        )
        self.assertIsNotNone(body)
        self.assertEqual(body.calls, ((0, 4),))
        self.assertEqual(body.normalized, b'CALL')
        self.assertIs(body, normalized_body(
            facts, CodeAddress(0, 'thumb'), 4, limit=len(image),
            thumb_calls=(0,), call_fill=b'CALL',
        ))

        prefix = bytes.fromhex('00f0')
        shape = (2, hashlib.sha256(prefix).hexdigest(), (), ())
        self.assertEqual(match_thumb_shape(prefix, 0, shape), ({}, {}, []))

    def test_arm_literal_and_branch_observations(self):
        literal_image = struct.pack('<I', 0xE59F0000) + bytes(4) + struct.pack('<I', 0x12345678)
        facts = facts_for(literal_image)
        body = normalized_body(
            facts, CodeAddress(0, 'arm'), 4, limit=len(literal_image),
            arm_literals=(0,), literal_masks={0: 0xFFFFF000},
        )
        self.assertIsNotNone(body)
        self.assertEqual(body.literals, ((0, ARM_REG_R0, 8, 0x12345678),))
        self.assertEqual(body.pools, ((8, 12),))
        self.assertEqual(body.normalized, struct.pack('<I', 0xE59F0000))

        branch_image = struct.pack('<I', 0xEA000000) + bytes(8)
        branch = normalized_body(
            facts_for(branch_image), CodeAddress(0, 'arm'), 4,
            limit=len(branch_image), arm_branches=(0,), call_fill=b'BRCH',
        )
        self.assertIsNotNone(branch)
        self.assertEqual(branch.branches, ((0, 8),))
        self.assertEqual(branch.normalized, b'BRCH')

    def test_arm_literal_pool_can_precede_the_body(self):
        image = struct.pack('<2I', 0x12345678, 0xE51F000C)
        body = normalized_body(facts_for(image), CodeAddress(4, 'arm'), 4,
                               limit=len(image), arm_literals=(0,))
        self.assertIsNotNone(body)
        self.assertEqual(body.literals, ((0, ARM_REG_R0, 0, 0x12345678),))
        self.assertEqual(body.normalized, struct.pack('<I', 0xE51F0000))

    def test_explicit_sites_and_limits_are_required(self):
        image = bytes.fromhex('00f000f87047')
        facts = facts_for(image)
        self.assertIsNone(normalized_body(
            facts, CodeAddress(0, 'thumb'), 4, limit=4, thumb_calls=(0,),
        ))
        self.assertIsNone(normalized_body(
            facts, CodeAddress(0, 'thumb'), 4, limit=len(image),
            thumb_calls=(0,), literal_masks={0: 0xFF00},
        ))


if __name__ == '__main__':
    unittest.main()
