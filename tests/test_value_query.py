"""Synthetic constants and opaque load lineage at actual register uses."""
import struct
import unittest

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts, SymbolicValue, UNKNOWN_VALUE
from msm5xxx_emulator.detection.image_view import ImageView, LoadOperation


def image_with_pool(instructions, pointer, value=0x9964):
    image = bytearray(0x40)
    struct.pack_into('<' + 'H' * len(instructions), image, 0, *instructions)
    struct.pack_into('<I', image, 0x20, pointer)
    struct.pack_into('<I', image, 0x30, value)
    return bytes(image)


class RegisterValueTests(unittest.TestCase):
    def test_readonly_table_shift_and_arithmetic(self):
        image = image_with_pool((0x4807, 0x6800, 0x0840, 0x3004, 0x6008, 0x4770), 0x30)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0))
        self.assertEqual(facts.register_value(function, CodeAddress(8), a.ARM_REG_R0),
                         SymbolicValue.const((0x9964 >> 1) + 4))

    def test_mmio_load_shift_mask_keeps_its_read_site(self):
        image = image_with_pool((0x4807, 0x8800, 0x07C0, 0x0FC0,
                                 0x2801, 0xD100, 0x4770, 0x4770), 0x03000780)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0))
        value = facts.register_value(function, CodeAddress(8), a.ARM_REG_R0)
        self.assertEqual((value.kind, value.value), ('op', 'lsr'))
        left = value.operands[0]
        self.assertEqual((left.kind, left.value), ('op', 'lsl'))
        loaded = left.operands[0]
        self.assertEqual((loaded.kind, loaded.width, loaded.site), ('load', 2, CodeAddress(2)))
        self.assertEqual(loaded.operands, (SymbolicValue.const(0x03000780),))

    def test_mutable_copied_data_does_not_become_an_immutable_constant(self):
        image = image_with_pool((0x4807, 0x6800, 0x6008, 0x4770), 0x01000000)
        view = ImageView.raw(image).materialize((
            LoadOperation('copy', 0x30, 0x01000000, 4, (0,)),))
        facts = FirmwareFacts(image, view=view)
        function = facts.function(CodeAddress(0, phase='post-copy'))
        value = facts.register_value(function, CodeAddress(4, phase='post-copy'), a.ARM_REG_R0)
        self.assertEqual(value.kind, 'load')
        self.assertEqual(value.operands, (SymbolicValue.const(0x01000000),))

    def test_explicit_entry_state_and_first_iteration_cut(self):
        image = struct.pack('<5H', 0x3404, 0x600C, 0x4294, 0xD3FB, 0x4770)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0), initial_registers={
            a.ARM_REG_R4: 0x1000, a.ARM_REG_R2: 0x1010})
        self.assertIs(facts.register_value(function, CodeAddress(2), a.ARM_REG_R4), UNKNOWN_VALUE)
        self.assertEqual(facts.register_value(function, CodeAddress(2), a.ARM_REG_R4,
                         cut_edges=((CodeAddress(6), CodeAddress(0)),)),
                         SymbolicValue.const(0x1004))

    def test_differing_branch_values_and_foreign_context_are_unknown(self):
        image = struct.pack('<7H', 0x2800, 0xD001, 0x2101, 0xE000, 0x2102, 0x6021, 0x4770)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0))
        self.assertIs(facts.register_value(function, CodeAddress(10), a.ARM_REG_R1), UNKNOWN_VALUE)
        self.assertIs(FirmwareFacts(image).register_value(function, CodeAddress(10), a.ARM_REG_R1), UNKNOWN_VALUE)
