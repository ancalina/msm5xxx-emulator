"""Synthetic instruction images for GPIO source and control-flow evidence."""
import struct
import unittest
from types import SimpleNamespace

from capstone import arm

from msm5xxx_emulator.detection.devices.eeprom.wire_rules import (
    _byte_line_transition,
    _call_context_tree,
    _closed_gpio_function,
    _call_effect_contexts,
    _byte_ack_sample,
    _descriptor_runtime_context,
)
from msm5xxx_emulator.detection.devices.eeprom.gpio_facts import (
    _gpio_output_transitions,
    _gpio_port_uses,
    _gpio_store_transitions,
    _sampled_gpio_bit,
    _linked_descriptor_matches,
)
from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.image_view import ImageView


def _thumb(words, literals=()):
    data = bytearray(struct.pack('<' + 'H' * len(words), *words))
    for address, value in literals:
        end = address + 4
        if len(data) < end:
            data.extend(bytes(end - len(data)))
        struct.pack_into('<I', data, address, value)
    return FirmwareFacts(bytes(data))


class GPIODataflowTests(unittest.TestCase):
    def test_descriptor_backing_bytes_must_be_supplied(self):
        expected = (0x03000720, 0x03000720, 0x0300072C)
        image = bytearray(0x100)
        struct.pack_into('<3I', image, 0xC0, *expected)
        image = bytes(image)
        layout = SimpleNamespace(data_source=0xC0, data_target=0x1000, data_size=12)
        self.assertTrue(_linked_descriptor_matches(
            FirmwareFacts(image), layout, 0x1000, expected))
        for begin, end in ((0xC0, 0xCC), (0xC4, 0xC8)):
            view = ImageView.sparse(((0, image[:begin]), (end, image[end:])))
            self.assertFalse(_linked_descriptor_matches(
                FirmwareFacts(image, view=view), layout, 0x1000, expected))

    def test_runtime_descriptor_does_not_read_same_offset_dump_bytes(self):
        # The descriptor's RAM address overlaps supplied dump offsets. Neither
        # possible raw value may determine the GPIO sample's branch outcome.
        for sampled in (0, 0xFF):
            image = bytearray(0x100)
            struct.pack_into('<8H', image, 0,
                             0x4A07, 0x6851, 0x7809, 0x0989,
                             0xD300, 0x2001, 0x4302, 0x4770)
            struct.pack_into('<I', image, 0x20, 0x80)
            struct.pack_into('<I', image, 0x84, 0xC0)
            image[0xC0] = sampled
            original = FirmwareFacts(bytes(image))
            runtime = _descriptor_runtime_context(original, 0x80, 0)
            function = runtime.function(
                CodeAddress(0, 'thumb', 'eeprom-wire'), symbolic_registers={})
            self.assertTrue(_sampled_gpio_bit(
                runtime, function, 0x03000720, width=1, shift=6,
                branch_condition=arm.ARM_CC_LO, descriptor=0x80))
            self.assertFalse(_sampled_gpio_bit(
                runtime, function, 0x03000720, width=1, shift=5,
                branch_condition=arm.ARM_CC_LO, descriptor=0x80))
            self.assertEqual(original.view.read(0x84, 4), struct.pack('<I', 0xC0))
            self.assertIsNone(runtime.view.read(0x84, 4, phase='eeprom-wire'))

    def _ack_sample_function(self, *, clock_before_sample=True,
                             released=True, whole_byte_compare=False):
        # Set SDA direction, pulse SCL high, sample SDA bit 0, then lower SCL.
        direction_update = 0x4388 if released else 0x4308
        bit_test = 0x2801 if whole_byte_compare else 0x0840
        if clock_before_sample:
            words = [
                0x7828, 0x2101, direction_update, 0x7028,
                0x7830, 0x2120, 0x4308, 0x7030,
                0x7820, bit_test, 0xD301, 0x46C0, 0x46C0,
                0x7830, 0x2120, 0x4388, 0x7030, 0x4770,
            ]
        else:
            words = [
                0x7828, 0x2101, direction_update, 0x7028,
                0x7820, bit_test, 0xD304, 0x46C0,
                0x7830, 0x2120, 0x4308, 0x7030,
                0x7830, 0x2120, 0x4388, 0x7030, 0x4770,
            ]
        facts = FirmwareFacts(struct.pack('<' + 'H' * len(words), *words))
        function = facts.function(
            CodeAddress(0, 'thumb'), initial_registers={
                arm.ARM_REG_R4: 0x03000664,
                arm.ARM_REG_R5: 0x0300067C,
                arm.ARM_REG_R6: 0x03000660,
            }, symbolic_registers={})
        return facts, function

    def test_ack_branch_samples_sda_after_release_and_clock_high(self):
        facts, function = self._ack_sample_function()
        self.assertTrue(_byte_ack_sample(
            facts, function, 0x03000664, 0x0300067C, 0x03000660, 1, 0x20))

    def test_ack_sample_before_clock_pulse_is_rejected(self):
        facts, function = self._ack_sample_function(clock_before_sample=False)
        self.assertFalse(_byte_ack_sample(
            facts, function, 0x03000664, 0x0300067C, 0x03000660, 1, 0x20))

    def test_ack_direction_must_be_released_for_sampling(self):
        facts, function = self._ack_sample_function(released=False)
        self.assertFalse(_byte_ack_sample(
            facts, function, 0x03000664, 0x0300067C, 0x03000660, 1, 0x20))

    def test_ack_branch_must_depend_only_on_the_configured_sda_bit(self):
        facts, function = self._ack_sample_function(whole_byte_compare=True)
        self.assertFalse(_byte_ack_sample(
            facts, function, 0x03000664, 0x0300067C, 0x03000660, 1, 0x20))

    def test_callsite_arguments_seed_byte_gpio_helper(self):
        code = bytearray(0x34)
        struct.pack_into('<4H', code, 0, 0x4803, 0xF000, 0xF80D, 0x4770)
        struct.pack_into('<I', code, 0x10, 0x03000664)
        struct.pack_into('<9H', code, 0x20,
                         0x7801, 0x2201, 0x4311, 0x7001,
                         0x7801, 0x2201, 0x4391, 0x7001, 0x4770)
        facts = FirmwareFacts(bytes(code))
        caller = facts.function(CodeAddress(0, 'thumb'), symbolic_registers={})
        contexts = _call_effect_contexts(facts, caller)
        self.assertEqual(len(contexts), 1)
        helper = contexts[0]
        self.assertEqual([(item.operation, item.address, item.width)
                          for item in helper.accesses],
                         [('read', 0x03000664, 1),
                          ('write', 0x03000664, 1),
                          ('read', 0x03000664, 1),
                          ('write', 0x03000664, 1)])
        reads = _gpio_port_uses(
            facts, helper, address=0x03000664, operation='read', width=1,
            descriptor=0, field=4, allow_call_argument=True)
        self.assertEqual(tuple(item.instruction.address for item in reads), (0x20, 0x28))
        self.assertEqual(_gpio_port_uses(
            facts, helper, address=0x03000668, operation='read', width=1,
            descriptor=0, field=4, allow_call_argument=True), ())
        context = ((facts, helper),)
        self.assertTrue(_byte_line_transition(context, 0x03000664, 1))
        self.assertFalse(_byte_line_transition(context, 0x03000664, 2))

    def test_callsite_argument_is_a_source_for_sampled_sda(self):
        code = bytearray(0x30)
        struct.pack_into('<4H', code, 0, 0x4803, 0xF000, 0xF80D, 0x4770)
        struct.pack_into('<I', code, 0x10, 0x03000664)
        struct.pack_into('<6H', code, 0x20,
                         0x7801, 0x0849, 0xD300, 0x2001, 0x4302, 0x4770)
        facts = FirmwareFacts(bytes(code))
        caller = facts.function(CodeAddress(0, 'thumb'), symbolic_registers={})
        helper = _call_effect_contexts(facts, caller)[0]
        self.assertTrue(_sampled_gpio_bit(
            facts, helper, 0x03000664, width=1, shift=1,
            branch_condition=arm.ARM_CC_LO, descriptor=0,
            allow_call_argument=True))

    def test_unknown_scalar_write_callee_is_not_a_closed_effect(self):
        facts = _thumb((0xF000, 0xF802, 0x4770, 0x46C0,
                        0x7001, 0x4770))
        caller = facts.function(CodeAddress(0, 'thumb'), symbolic_registers={})
        call = caller.call_sites[0]
        self.assertIsNone(_call_context_tree(facts, call))

    def test_irq_save_restore_leaf_is_a_closed_non_mmio_effect(self):
        image = struct.pack('<4I', 0xE10F0000, 0xE3C00080,
                            0xE121F000, 0xE12FFF1E)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'arm'), symbolic_registers={})
        self.assertTrue(_closed_gpio_function(facts, function))

    def test_shadow_forwarding_rejects_an_intervening_unknown_alias(self):
        for intervening, expected in ((0x46C0, ('orrs', 0x20)), (0x702A, None)):
            with self.subTest(intervening=intervening):
                # Update a RAM halfword shadow, reload it, then write the
                # GPIO port. An unknown STRB [r5] can alias the shadow.
                facts = _thumb((0x4C0B, 0x8820, 0x2120, 0x4308, 0x8020,
                                intervening, 0x8820, 0x4E09, 0x8030, 0x4770),
                               ((0x30, 0x01000100), (0x34, 0x03000720)))
                function = facts.function(CodeAddress(0), symbolic_registers={})
                output = next(item for item in function.accesses
                              if item.operation == 'write' and item.address == 0x03000720)
                self.assertEqual(_gpio_output_transitions(facts, function, (output,)), (expected,))

    def test_store_transition_requires_matching_read_and_reaching_mask(self):
        facts = _thumb((
            0x4C03,       # ldr r4, [pc, #12] -> 0x03000720
            0x8821,       # ldrh r1, [r4]
            0x2220,       # movs r2, #0x20
            0x4391,       # bics r1, r2
            0x8021,       # strh r1, [r4]
            0x4770,       # bx lr
            0x46C0, 0x46C0,
        ), ((16, 0x03000720),))
        function = facts.function(CodeAddress(0, 'thumb'))
        access = next(item for item in function.accesses
                      if item.operation == 'write')
        self.assertEqual(_gpio_store_transitions(facts, function, (access,)),
                         (('bics', 0x20),))

    def test_mask_can_be_computed_without_a_fixed_immediate_layout(self):
        facts = _thumb((0x4C03, 0x8821, 0x2210, 0x0052,
                        0x4391, 0x8021, 0x4770, 0x46C0),
                       ((16, 0x03000720),))
        function = facts.function(CodeAddress(0))
        access = next(item for item in function.accesses if item.operation == 'write')
        self.assertEqual(_gpio_store_transitions(facts, function, (access,)),
                         (('bics', 0x20),))

    def test_wrong_store_register_is_rejected(self):
        facts = _thumb((
            0x4C03, 0x8821, 0x2220, 0x4391,
            0x8020,       # strh r0, [r4], not the updated r1
            0x4770, 0x46C0, 0x46C0,
        ), ((16, 0x03000720),))
        function = facts.function(CodeAddress(0, 'thumb'))
        access = next(item for item in function.accesses
                      if item.operation == 'write')
        self.assertEqual(_gpio_store_transitions(facts, function, (access,)),
                         (None,))

    def test_sampled_bit_requires_load_to_shift_to_live_branch(self):
        facts = _thumb((
            0x4C03,       # ldr r4, [pc, #12] -> data input
            0x7821,       # ldrb r1, [r4]
            0x0989,       # lsrs r1, r1, #6
            0xD201,       # bhs target 12
            0x2000,       # fallthrough: movs r0, #0
            0x4770,
            0x060A,       # target: lsls r2, r1, #24
            0x4770,
        ), ((16, 0x03000724),))
        function = facts.function(CodeAddress(0, 'thumb'))
        self.assertTrue(_sampled_gpio_bit(
            facts, function, 0x03000724, width=1, shift=6,
            branch_condition=arm.ARM_CC_HS, descriptor=0))

    def test_sampled_bit_rejects_flag_clobber_and_branch_bypass(self):
        facts = _thumb((
            0x4C04,       # ldr r4, [pc, #16] -> data input
            0x7821,       # ldrb r1, [r4]
            0x0989,       # lsrs r1, r1, #6
            0x2300,       # movs r3, #0 overwrites flags
            0xD201,       # bhs, no longer tests the sampled bit
            0x2000,
            0x4770,
            0x060A,       # target shape alone must not admit
            0x4770,
        ), ((20, 0x03000724),))
        function = facts.function(CodeAddress(0, 'thumb'))
        self.assertFalse(_sampled_gpio_bit(
            facts, function, 0x03000724, width=1, shift=6,
            branch_condition=arm.ARM_CC_HS, descriptor=0))

if __name__ == '__main__':
    unittest.main()
