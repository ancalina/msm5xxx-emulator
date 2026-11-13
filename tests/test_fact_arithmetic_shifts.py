"""Arithmetic shifts preserve signed values, dependencies and ARM carry rules."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import (
    CodeAddress, FirmwareFacts, SymbolicValue, evaluate_value,
)


def thumb(*instructions):
    return struct.pack('<' + 'H' * len(instructions), *instructions)


class ArithmeticShiftFactsTests(unittest.TestCase):
    def test_signed_substitutions_and_saturated_shift(self):
        expression = SymbolicValue('op', 'asr', (
            SymbolicValue.arg(0), SymbolicValue.arg(1)))
        for value, amount, expected in (
                (0x80000001, 1, 0xC0000000),
                (0x7FFFFFFF, 1, 0x3FFFFFFF),
                (0x80000001, 31, 0xFFFFFFFF),
                (0x80000001, 32, 0xFFFFFFFF),
                (0x7FFFFFFF, 255, 0),
                (0x80000001, 0, 0x80000001)):
            with self.subTest(value=value, amount=amount):
                self.assertEqual(evaluate_value(expression,
                    arguments={0: value, 1: amount}), expected)

    def test_immediate_result_reaches_memory_and_register_queries(self):
        # ASRS r0,r0,#1; STR r0,[r1]; BX lr.
        facts = FirmwareFacts(thumb(0x1040, 0x6008, 0x4770))
        for value, expected in ((0x80000001, 0xC0000000), (0x53, 0x29)):
            body = facts.function(CodeAddress(0), initial_registers={
                a.ARM_REG_R0: value, a.ARM_REG_R1: 0x14000100})
            self.assertEqual(next(use.value for use in body.accesses
                                  if use.operation == 'write'), expected)
            self.assertEqual(facts.register_value(body, CodeAddress(2),
                                                 a.ARM_REG_R0),
                             SymbolicValue.const(expected))

    def test_register_shift_uses_only_low_byte(self):
        # ASRS r0,r2; STR r0,[r1]; BX lr.
        facts = FirmwareFacts(thumb(0x4110, 0x6008, 0x4770))
        for amount, expected in ((1, 0xC0000000), (32, 0xFFFFFFFF),
                                 (255, 0xFFFFFFFF), (256, 0x80000001)):
            body = facts.function(CodeAddress(0), initial_registers={
                a.ARM_REG_R0: 0x80000001, a.ARM_REG_R2: amount,
                a.ARM_REG_R1: 0x14000100})
            self.assertEqual(next(use.value for use in body.accesses
                                  if use.operation == 'write'), expected)
            self.assertEqual(facts.register_value(body, CodeAddress(2),
                                                 a.ARM_REG_R0),
                             SymbolicValue.const(expected))

    def test_signed_rounding_chain_proves_store_address(self):
        # Normalize an odd positive address with the signed divide-by-two
        # sequence before restoring byte addressing and issuing a halfword.
        image = thumb(0x2153, 0x0FC8, 0x1840, 0x1040, 0x0040, 0x8002, 0x4770)
        body = FirmwareFacts(image).function(CodeAddress(0), symbolic_registers={})
        stores = [use for use in body.symbolic_accesses if use.operation == 'write']
        self.assertEqual(stores[0].address, SymbolicValue.const(0x52))

    def test_shifted_load_keeps_read_provenance(self):
        facts = FirmwareFacts(thumb(0x6808, 0x1040, 0x6010, 0x4770))
        body = facts.function(CodeAddress(0), initial_registers={
            a.ARM_REG_R1: 0x03000100, a.ARM_REG_R2: 0x14000100},
            symbolic_registers={})
        value = facts.register_value(body, CodeAddress(4), a.ARM_REG_R0)
        self.assertEqual(evaluate_value(value, reads={CodeAddress(0): 0x80000001}),
                         0xC0000000)
        self.assertIsNone(evaluate_value(value, reads={CodeAddress(2): 0x80000001}))

    def test_register_shift_carry_and_zero_amount_preservation(self):
        # CMP r3,#0 sets carry. ASRS r0,r2 then selects a value with BCS.
        image = thumb(0x2B00, 0x4110, 0xD201, 0x2401,
                      0xE000, 0x2402, 0x600C, 0x4770)
        facts = FirmwareFacts(image)
        for amount, expected in ((0, 2), (1, 1), (32, 2), (255, 2), (256, 2)):
            body = facts.function(CodeAddress(0), initial_registers={
                a.ARM_REG_R0: 0x80000000, a.ARM_REG_R1: 0x14000100,
                a.ARM_REG_R2: amount, a.ARM_REG_R3: 0})
            self.assertEqual(next(use.value for use in body.accesses
                                  if use.operation == 'write'), expected)


if __name__ == '__main__':
    unittest.main()
