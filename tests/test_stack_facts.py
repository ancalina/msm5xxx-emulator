"""Synthetic checks for bounded relative stack-frame facts."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.stack_facts import stack_frame


class StackFactsTests(unittest.TestCase):
    def test_thumb_push_allocation_scalar_spill_and_pop(self):
        image = struct.pack('<6H', 0xB510, 0xB082, 0x9000,
                            0x9900, 0xB002, 0xBD10)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'thumb'))
        frame = stack_frame(facts, function)
        self.assertIsNotNone(frame)
        self.assertTrue(frame.complete)
        self.assertTrue(frame.balanced)
        self.assertEqual(frame.offset_at(CodeAddress(0, 'thumb')), 0)
        self.assertEqual(frame.offset_at(CodeAddress(2, 'thumb')), -8)
        self.assertEqual(frame.offset_at(CodeAddress(4, 'thumb')), -16)
        self.assertEqual(frame.offset_at(CodeAddress(10, 'thumb')), -8)
        self.assertEqual(frame.exit_offsets, ((CodeAddress(10, 'thumb'), 0),))
        self.assertEqual(
            [(item.operation, item.offset, item.width, item.register)
             for item in frame.accesses],
            [('write', -8, 4, 70), ('write', -4, 4, 10),
             ('write', -16, 4, 66), ('read', -16, 4, 67),
             ('read', -8, 4, 70), ('read', -4, 4, 11)],
        )

    def test_pop_to_low_return_register_balances_a_saved_link_frame(self):
        facts = FirmwareFacts(struct.pack('<4H', 0xB510, 0xBC10, 0xBC08, 0x4718))
        function = facts.function(CodeAddress(0))
        self.assertTrue(function.complete)
        frame = stack_frame(facts, function)
        self.assertIsNotNone(frame)
        self.assertTrue(frame.balanced)
        self.assertEqual(frame.exit_offsets, ((CodeAddress(6), 0),))

    def test_unknown_branch_register_is_not_a_stack_return(self):
        facts = FirmwareFacts(struct.pack('<2H', 0xB500, 0x4718))
        function = facts.function(CodeAddress(0))
        self.assertFalse(function.complete)
        self.assertIsNone(stack_frame(facts, function))

    def test_arm_register_list_order_and_relative_spill(self):
        image = struct.pack('<6I', 0xE92D4010, 0xE24DD008,
                            0xE58D0000, 0xE59D1000,
                            0xE28DD008, 0xE8BD8010)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'arm'))
        frame = stack_frame(facts, function)
        self.assertIsNotNone(frame)
        self.assertTrue(frame.balanced)
        self.assertEqual(
            [(item.operation, item.offset, item.register)
             for item in frame.accesses],
            [('write', -8, 70), ('write', -4, 10),
             ('write', -16, 66), ('read', -16, 67),
             ('read', -8, 70), ('read', -4, 11)],
        )

    def test_incompatible_stack_height_at_branch_join_rejects(self):
        # One branch allocates four extra bytes before the common return.
        image = struct.pack('<8H', 0xB500, 0x2800, 0xD001, 0xB081,
                            0xE000, 0x46C0, 0xB001, 0xBD00)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'thumb'))
        self.assertTrue(function.complete)
        self.assertIsNone(stack_frame(facts, function))

    def test_equal_stack_height_at_conditional_join_is_retained(self):
        image = struct.pack('<7H', 0xB500, 0x2800, 0xD001, 0x1C09,
                            0xE000, 0x46C0, 0xBD00)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'thumb'))
        frame = stack_frame(facts, function)
        self.assertIsNotNone(frame)
        self.assertTrue(frame.balanced)
        self.assertEqual(frame.exit_offsets, ((CodeAddress(12, 'thumb'), 0),))

    def test_unknown_sp_write_and_mode_change_are_barriers(self):
        unknown = struct.pack('<2I', 0xE1A0D000, 0xE12FFF1E)  # MOV sp,r0; BX lr
        facts = FirmwareFacts(unknown)
        self.assertIsNone(stack_frame(facts, facts.function(CodeAddress(0, 'arm'))))

        mode_change = struct.pack('<2I', 0xE121F000, 0xE12FFF1E)  # MSR CPSR_c,r0
        facts = FirmwareFacts(mode_change)
        self.assertIsNone(stack_frame(facts, facts.function(CodeAddress(0, 'arm'))))

    def test_stop_before_endpoint_reports_input_sp_without_its_access(self):
        image = struct.pack('<4H', 0xB500, 0x9000, 0xB001, 0xBD00)
        facts = FirmwareFacts(image)
        function = facts.function_region(
            CodeAddress(0, 'thumb'), stop_before=CodeAddress(2, 'thumb'))
        frame = stack_frame(facts, function)
        self.assertIsNotNone(frame)
        self.assertEqual(frame.stopped_offsets, ((CodeAddress(2, 'thumb'), -4),))
        self.assertEqual(frame.offset_at(CodeAddress(2, 'thumb')), -4)
        self.assertEqual(len(frame.accesses), 1)  # PUSH only; stopped STR excluded.
        self.assertFalse(frame.balanced)

    def test_conditional_stack_change_is_rejected(self):
        image = struct.pack('<2I', 0x024DD004, 0xE12FFF1E)  # SUBEQ sp,sp,#4
        facts = FirmwareFacts(image)
        self.assertIsNone(stack_frame(facts, facts.function(CodeAddress(0, 'arm'))))

    def test_foreign_function_and_exception_mode_switch_are_not_a_frame_proof(self):
        image = struct.pack('<2H', 0xB500, 0xBD00)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0))
        self.assertIsNotNone(stack_frame(facts, function))
        self.assertIsNone(stack_frame(FirmwareFacts(image), function))
        exception = FirmwareFacts(struct.pack('<3H', 0xB500, 0xDF00, 0xBD00))
        self.assertIsNone(stack_frame(exception, exception.function(CodeAddress(0))))

    def test_prefix_before_mode_change_does_not_claim_the_mode_change_effect(self):
        facts = FirmwareFacts(struct.pack('<2I', 0xE121F000, 0xE12FFF1E))
        prefix = facts.function_region(CodeAddress(0, 'arm'),
                                       stop_before=CodeAddress(0, 'arm'))
        frame = stack_frame(facts, prefix)
        self.assertIsNotNone(frame)
        self.assertEqual(frame.stopped_offsets, ((CodeAddress(0, 'arm'), 0),))


if __name__ == '__main__':
    unittest.main()
