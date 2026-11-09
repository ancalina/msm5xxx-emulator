"""Stack spills preserve values only through closed local memory dependencies."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts, SymbolicValue


def thumb(*words):
    return struct.pack('<' + 'H' * len(words), *words)


class StackValueTests(unittest.TestCase):
    def test_argument_spill_reload_uses_the_stored_value_not_the_clobbered_register(self):
        # PUSH {r0,lr}; clobber r0; reload original argument; restore frame.
        facts = FirmwareFacts(thumb(0xB501, 0x2055, 0x9800, 0xBD02))
        function = facts.function(CodeAddress(0), symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
        self.assertEqual(facts.register_value(function, CodeAddress(6), a.ARM_REG_R0).kind, 'unknown')
        self.assertEqual(facts.register_value(function, CodeAddress(6), a.ARM_REG_R0,
                                              follow_stack=True), SymbolicValue.arg(0))
        # A wrong slot contains LR, never the incoming argument.
        wrong = FirmwareFacts(thumb(0xB501, 0x2055, 0x9801, 0xBD02))
        function = wrong.function(CodeAddress(0), symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
        self.assertEqual(wrong.register_value(function, CodeAddress(6), a.ARM_REG_R0,
                                              follow_stack=True).kind, 'unknown')

    def test_local_stack_adjustment_and_multi_register_pop(self):
        facts = FirmwareFacts(thumb(0xB501, 0xB081, 0x9801, 0xB001, 0xBD02))
        function = facts.function(CodeAddress(0), symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
        self.assertEqual(facts.register_value(function, CodeAddress(8), a.ARM_REG_R0,
                                              follow_stack=True), SymbolicValue.arg(0))
        facts = FirmwareFacts(thumb(0xB501, 0x2055, 0xBC05, 0x4770))
        function = facts.function(CodeAddress(0), symbolic_registers={
            a.ARM_REG_R0: SymbolicValue.arg(0), a.ARM_REG_LR: SymbolicValue.arg(14)})
        self.assertEqual(facts.register_value(function, CodeAddress(6), a.ARM_REG_R0,
                                              follow_stack=True), SymbolicValue.arg(0))
        self.assertEqual(facts.register_value(function, CodeAddress(6), a.ARM_REG_R2,
                                              follow_stack=True), SymbolicValue.arg(14))

    def test_unknown_alias_and_opaque_call_block_spill_forwarding(self):
        facts = FirmwareFacts(thumb(0xB501, 0x6022, 0x9800, 0xBD02))
        function = facts.function(CodeAddress(0), symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
        self.assertEqual(facts.register_value(function, CodeAddress(6), a.ARM_REG_R0,
                                              follow_stack=True).kind, 'unknown')
        image = bytearray(thumb(0xB501, 0xF000, 0xF807, 0x9800, 0xBD02) + bytes(24))
        struct.pack_into('<H', image, 20, 0x4770)
        facts = FirmwareFacts(bytes(image))
        function = facts.function(CodeAddress(0), symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
        self.assertEqual(facts.register_value(function, CodeAddress(8), a.ARM_REG_R0,
                                              follow_stack=True).kind, 'unknown')
        helper = facts.function(CodeAddress(20))
        self.assertTrue(helper.complete)
        self.assertFalse(helper.calls or helper.accesses)
        self.assertEqual(facts.register_value(function, CodeAddress(8), a.ARM_REG_R0,
                                              follow_stack=True, allowed_calls=(CodeAddress(2),)),
                         SymbolicValue.arg(0))

    def test_arm_byte_and_signed_loads_extract_the_correct_saved_word_bits(self):
        for load, value, expected in ((0xE5DD0002, 0x12345678, 0x34),
                                       (0xE1DD00D0, 0x80, 0xFFFFFF80)):
            with self.subTest(load=load):
                facts = FirmwareFacts(struct.pack('<4I', 0xE92D4001, 0xE3A00000,
                                                   load, 0xE8BD8002))
                function = facts.function(CodeAddress(0, 'arm'), initial_registers={a.ARM_REG_R0: value})
                self.assertEqual(facts.register_value(function, CodeAddress(12, 'arm'), a.ARM_REG_R0,
                                                      follow_stack=True), SymbolicValue.const(expected))


if __name__ == '__main__':
    unittest.main()
