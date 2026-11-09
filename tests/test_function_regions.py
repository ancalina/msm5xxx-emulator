"""Explicit source-covered CFG boundaries for peripheral initialization."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.image_view import ImageView


class FunctionRegionTests(unittest.TestCase):
    def test_stop_before_store_exposes_its_input_without_claiming_its_write(self):
        facts = FirmwareFacts(struct.pack('<3H', 0x2001, 0x6008, 0xFFFF))
        region = facts.function_region(CodeAddress(0), stop_before=CodeAddress(2),
                                       initial_registers={a.ARM_REG_R1: 0x03000780},
                                       symbolic_registers={})
        self.assertTrue(region.complete)
        self.assertEqual(region.scope_before, (CodeAddress(2),))
        self.assertEqual(region.accesses, ())
        self.assertEqual(facts.register_value(region, CodeAddress(2), a.ARM_REG_R0).value, 1)

    def test_call_or_return_can_end_a_prefix_only_before_its_effects(self):
        facts = FirmwareFacts(struct.pack('<4H', 0x2007, 0xF000, 0xF800, 0xBD00))
        call = facts.function_region(CodeAddress(0), stop_before=CodeAddress(2))
        self.assertTrue(call.complete)
        self.assertEqual(call.calls, ())
        self.assertEqual(facts.register_value(call, CodeAddress(2), a.ARM_REG_R0).value, 7)
        tail = facts.function_region(CodeAddress(0), stop_before=CodeAddress(6))
        self.assertTrue(tail.complete)
        self.assertEqual(len(tail.calls), 1)
        self.assertEqual(facts.unmodelled_memory(tail), ())
        self.assertEqual(facts.register_value(tail, CodeAddress(6), a.ARM_REG_R0).kind, 'unknown')

    def test_mixed_boundaries_keep_an_undeclared_early_exit_incomplete(self):
        facts = FirmwareFacts(struct.pack('<5H', 0x2800, 0xD001, 0x2101, 0x6008, 0x4770))
        partial = facts.function_region(CodeAddress(0), CodeAddress(6))
        self.assertFalse(partial.complete)
        closed = facts.function_region(CodeAddress(0), CodeAddress(6), stop_before=CodeAddress(8))
        self.assertTrue(closed.complete)
        self.assertEqual(set(closed.scope_exits), {CodeAddress(6), CodeAddress(8)})

    def test_closed_prefix_does_not_claim_an_unknown_tail(self):
        image = struct.pack('<3H', 0x2001, 0x6008, 0xFFFF)
        facts = FirmwareFacts(image)
        self.assertFalse(facts.function(CodeAddress(0)).complete)
        region = facts.function_region(CodeAddress(0), CodeAddress(2))
        self.assertTrue(region.complete)
        self.assertEqual(region.instructions, (CodeAddress(0), CodeAddress(2)))
        self.assertEqual(region.scope_exits, (CodeAddress(2),))
        self.assertEqual(region.scope_escapes, ())

    def test_early_return_cannot_bypass_the_requested_event(self):
        image = struct.pack('<5H', 0x2800, 0xD001, 0x2101, 0x6008, 0x4770)
        facts = FirmwareFacts(image)
        region = facts.function_region(CodeAddress(0), CodeAddress(6))
        self.assertFalse(region.complete)
        self.assertEqual(region.scope_escapes, (CodeAddress(8),))

    def test_missing_instruction_or_budget_limit_is_not_a_closed_region(self):
        image = struct.pack('<3H', 0x2001, 0x6008, 0x4770)
        view = ImageView.sparse(((0, image[:2]), (4, image[4:])))
        self.assertFalse(FirmwareFacts(image, view=view).function_region(
            CodeAddress(0), CodeAddress(2)).complete)
        region = FirmwareFacts(image).function_region(CodeAddress(0), CodeAddress(2), budget=1)
        self.assertFalse(region.complete)
        self.assertTrue(region.truncated)

    def test_control_transfer_cannot_be_disguised_as_an_endpoint_effect(self):
        facts = FirmwareFacts(struct.pack('<2H', 0xE7FE, 0x4770))
        with self.assertRaises(ValueError):
            facts.function_region(CodeAddress(0), CodeAddress(0))
