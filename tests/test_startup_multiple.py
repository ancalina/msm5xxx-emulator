"""Synthetic one-word Thumb multiple-transfer instruction contracts."""
import struct
import unittest

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone import arm as a

from msm5xxx_emulator.detection.startup_cfg import _memory_register


class StartupMultipleTransferTests(unittest.TestCase):
    def test_single_register_increment_after_transfers_are_word_updates(self):
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        decoder.detail = True
        instructions = tuple(decoder.disasm(
            struct.pack("<HH", 0xCD08, 0xC408), 0x100))
        self.assertEqual(len(instructions), 2)
        self.assertEqual(instructions[0].mnemonic, "ldm")
        self.assertEqual(_memory_register(instructions[0], a.ARM_INS_LDM),
                         (a.ARM_REG_R3, a.ARM_REG_R5))
        self.assertEqual(instructions[1].mnemonic, "stm")
        self.assertEqual(_memory_register(instructions[1], a.ARM_INS_STM),
                         (a.ARM_REG_R3, a.ARM_REG_R4))

    def test_multiple_register_and_arm_forms_are_rejected(self):
        thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        thumb.detail = True
        multiple = tuple(thumb.disasm(struct.pack("<H", 0xCD48), 0x100))[0]
        self.assertIsNone(_memory_register(multiple, a.ARM_INS_LDM))
        arm = Cs(CS_ARCH_ARM, 0)
        arm.detail = True
        wide = tuple(arm.disasm(struct.pack("<I", 0xE8B50008), 0x100))[0]
        self.assertIsNone(_memory_register(wide, a.ARM_INS_LDM))


if __name__ == "__main__":
    unittest.main()
