"""Synthetic branch/value lineage queries for ARM and Thumb code."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts, SymbolicValue
from msm5xxx_emulator.detection.value_query import branch_predicate


BASE = 0x03000780


def thumb_words(*values):
    return struct.pack('<' + 'H' * len(values), *values)


def arm_words(*values):
    return struct.pack('<' + 'I' * len(values), *values)


class BranchValueQueryTests(unittest.TestCase):
    def test_flag_setting_data_operations_link_the_read_and_preserve_unknown_carry(self):
        # LDRH r0,[r4]; MOV r1,#2; ANDS r0,r1; BNE; two returns.
        facts = FirmwareFacts(thumb_words(
            0x8820, 0x2102, 0x4008, 0xD100, 0x4770, 0x4770))
        function = facts.function(CodeAddress(0), initial_registers={a.ARM_REG_R4: BASE})
        predicate = facts.branch_predicate(function, CodeAddress(6))
        self.assertIsNotNone(predicate)
        self.assertTrue(predicate.evaluate({CodeAddress(0): 2}))
        self.assertFalse(predicate.evaluate({CodeAddress(0): 0x5F20}))
        self.assertEqual(predicate.read_sources[0].width, 2)
        carry_facts = FirmwareFacts(thumb_words(
            0x8820, 0x2102, 0x4008, 0xD200, 0x4770, 0x4770))
        function = carry_facts.function(CodeAddress(0), initial_registers={a.ARM_REG_R4: BASE})
        carry = carry_facts.branch_predicate(function, CodeAddress(6))
        self.assertIsNone(carry.evaluate({CodeAddress(0): 2}))

    def test_add_and_subtract_flags_use_wrapping_32_bit_arithmetic(self):
        for opcode, initial, expected in ((0x3001, 0xFFFFFFFF, True),
                                          (0x3801, 0, False)):
            with self.subTest(opcode=opcode):
                # ADDS/SUBS r0,#1; BHS; two returns.
                facts = FirmwareFacts(thumb_words(opcode, 0xD200, 0x4770, 0x4770))
                function = facts.function(CodeAddress(0), symbolic_registers={
                    a.ARM_REG_R0: SymbolicValue.arg(0),
                })
                predicate = facts.branch_predicate(function, CodeAddress(2))
                self.assertIsNotNone(predicate)
                self.assertEqual(predicate.evaluate(arguments={0: initial}), expected)

    def test_formal_argument_substitution_keeps_unknown_inputs_unknown(self):
        # CMP r4,#0x40; BEQ to return; alternate return.
        facts = FirmwareFacts(thumb_words(0x2C40, 0xD000, 0x4770, 0x4770))
        function = facts.function(CodeAddress(0), symbolic_registers={
            a.ARM_REG_R4: SymbolicValue.arg(0),
        })
        predicate = facts.branch_predicate(function, CodeAddress(2))
        self.assertIsNotNone(predicate)
        self.assertTrue(predicate.evaluate(arguments={0: 0x40}))
        self.assertFalse(predicate.evaluate(arguments={0: 0x60}))
        self.assertIsNone(predicate.evaluate())

    def test_thumb_cmp_links_status_read_and_evaluates_native_value(self):
        # Literal base; one status read; extract bit 0; compare; branch; loop
        # or continue. Pool is after the local code and does not overlap flow.
        image = thumb_words(
            0x4C07,       # LDR r4, [PC, #28]
            0x8820,       # LDRH r0, [r4]
            0x07C0,       # LSLS r0, r0, #31
            0x0FC0,       # LSRS r0, r0, #31
            0x2801,       # CMP r0, #1
            0xD101,       # BNE to the continuation
            0xE7F9,       # B back to the read
            0x2000,       # continuation
            0x4770,       # BX LR
        ) + bytes(32 - 18) + struct.pack('<I', BASE)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'thumb'), budget=32)
        predicate = branch_predicate(facts, function, CodeAddress(10, 'thumb'))
        self.assertIsNotNone(predicate)
        assert predicate is not None
        self.assertEqual(len(predicate.read_sources), 1)
        source = predicate.read_sources[0]
        self.assertEqual((source.site, source.width, source.address.value),
                         (CodeAddress(2), 2, BASE))
        self.assertTrue(predicate.evaluate({source.site: 0x5F20}))
        self.assertFalse(predicate.evaluate({source.site: 0x5F21}))
        self.assertIsNone(predicate.evaluate({}))

    def test_arm_tst_links_read_and_uses_only_flags_it_sets(self):
        image = arm_words(
            0xE1D420B0,  # LDRH r2, [r4]
            0xE3120001,  # TST r2, #1
            0x1AFFFFFC,  # BNE back to the read
            0xE12FFF1E,  # BX LR
        )
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'arm'), initial_registers={
            a.ARM_REG_R4: BASE,
        })
        predicate = branch_predicate(facts, function, CodeAddress(8, 'arm'))
        self.assertIsNotNone(predicate)
        assert predicate is not None
        self.assertEqual([(item.site, item.width, item.address.value)
                          for item in predicate.read_sources],
                         [(CodeAddress(0, 'arm'), 2, BASE)])
        self.assertFalse(predicate.evaluate({CodeAddress(0, 'arm'): 0x5F20}))
        self.assertTrue(predicate.evaluate({CodeAddress(0, 'arm'): 0x5F21}))
        # TST defines N/Z; it cannot establish carry for BHS.
        facts = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE3120001, 0x2AFFFFFC, 0xE12FFF1E))
        function = facts.function(CodeAddress(0, 'arm'), initial_registers={
            a.ARM_REG_R4: BASE,
        })
        carry = branch_predicate(facts, function, CodeAddress(8, 'arm'))
        self.assertIsNotNone(carry)
        assert carry is not None
        self.assertIsNone(carry.evaluate({CodeAddress(0, 'arm'): 0x5F20}))

    def test_shift_carry_query_and_zero_shift_are_conservative(self):
        image = arm_words(
            0xE1D420B0,  # LDRH r2, [r4]
            0xE1B020A2,  # MOVS r2, r2, LSR #1 (decoded as a flag-setting shift)
            0x2AFFFFFC,  # BHS back to the read
            0xE12FFF1E,
        )
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'arm'), initial_registers={
            a.ARM_REG_R4: BASE,
        })
        predicate = branch_predicate(facts, function, CodeAddress(8, 'arm'))
        self.assertIsNotNone(predicate)
        assert predicate is not None
        source = predicate.read_sources[0]
        self.assertFalse(predicate.evaluate({source.site: 0x5F20}))
        self.assertTrue(predicate.evaluate({source.site: 0x5F21}))

        zero_predicate = FirmwareFacts(thumb_words(
            0x2000, 0x0000, 0xD201, 0xE7FB, 0x4770, 0x4770))
        function = zero_predicate.function(CodeAddress(0))
        zero = branch_predicate(zero_predicate, function, CodeAddress(4))
        self.assertIsNotNone(zero)
        assert zero is not None
        self.assertIsNone(zero.evaluate())

    def test_joined_flag_origins_and_unlinked_reads_are_rejected(self):
        # Two paths produce flags independently, so no unique status test can
        # be substituted for this branch.
        image = arm_words(
            0xE1D420B0, 0xE3120001, 0x0A000000,
            0xE3500000, 0xEA000000, 0xE3500001,
            0x1AFFFFF7, 0xE12FFF1E,
        )
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'arm'), initial_registers={
            a.ARM_REG_R4: BASE,
        })
        self.assertIsNone(branch_predicate(facts, function, CodeAddress(24, 'arm')))


if __name__ == '__main__':
    unittest.main()
