"""Concrete substitutions preserve ARM widths and unknown dependencies."""
import unittest

import struct

from msm5xxx_emulator.detection.facts import (
    CodeAddress, FirmwareFacts, SymbolicValue, evaluate_value,
)


class ValueEvaluationTests(unittest.TestCase):
    def test_cfg_completeness_does_not_hide_multiple_register_memory(self):
        # STMIA r4!,{r0,r1}; BX LR is a complete local CFG, but the
        # scalar observation model does not describe its memory writes.
        facts = FirmwareFacts(struct.pack('<2H', 0xC403, 0x4770))
        function = facts.function(CodeAddress(0), symbolic_registers={})
        self.assertTrue(function.complete)
        self.assertEqual(facts.unmodelled_memory(function), (CodeAddress(0),))
        self.assertIsNone(FirmwareFacts(bytes(16)).unmodelled_memory(function))

    def test_caller_arguments_and_wrapping_arithmetic(self):
        value = SymbolicValue('op', 'add', (
            SymbolicValue.arg(1), SymbolicValue.const(0x30)))
        self.assertEqual(evaluate_value(value, arguments={1: 0xFFFFFFF0}), 0x20)
        self.assertIsNone(evaluate_value(value, arguments={0: 12}))
        self.assertIsNone(evaluate_value(value, arguments={1: True}))

    def test_inverted_mask_retains_a_byte_read_dependency(self):
        # MOV r1,#0x80; MVNS r1,r1; LDRB r0,[r4]; ANDS r0,r1;
        # STRB r0,[r4]; BX LR. The query closes the mask at its real store.
        facts = FirmwareFacts(struct.pack('<6H', 0x2180, 0x43C9, 0x7820,
                                           0x4008, 0x7020, 0x4770))
        from capstone import arm as a
        function = facts.function(CodeAddress(0), initial_registers={
            a.ARM_REG_R4: 0x01000100,
        })
        value = facts.register_value(function, CodeAddress(8), a.ARM_REG_R0)
        for byte in range(256):
            self.assertEqual(evaluate_value(value, reads={CodeAddress(4): byte}), byte & 0x7F)

    def test_signed_reads_are_explicit_and_do_not_alias_equal_addresses(self):
        address = SymbolicValue.const(0x03000780)
        source, other = CodeAddress(0x100), CodeAddress(0x200)
        signed = SymbolicValue('load', operands=(address,), width=1,
                               signed=True, site=source)
        self.assertEqual(evaluate_value(signed, reads={source: 0x180}), 0xFFFFFF80)
        self.assertIsNone(evaluate_value(signed, reads={other: 0x80}))
        unsigned = SymbolicValue('load', operands=(address,), width=2, site=source)
        self.assertEqual(evaluate_value(unsigned, reads={source: 0x12345678}), 0x5678)

    def test_unknown_operations_and_excessive_depth_remain_unknown(self):
        value = SymbolicValue.arg(0)
        for _ in range(10):
            value = SymbolicValue('op', 'add', (value, SymbolicValue.const(1)))
        self.assertIsNone(evaluate_value(value, arguments={0: 0}))
        unknown = SymbolicValue('op', 'divide', (
            SymbolicValue.const(4), SymbolicValue.const(2)))
        self.assertIsNone(evaluate_value(unknown))
        self.assertIsNone(evaluate_value(SymbolicValue('unknown')))


if __name__ == '__main__':
    unittest.main()
