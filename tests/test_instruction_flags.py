"""Concrete ARM/Thumb flag and PC-relative address regressions."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts


def thumb_words(*values):
    return struct.pack('<' + 'H' * len(values), *values)


def arm_words(*values):
    return struct.pack('<' + 'I' * len(values), *values)


class InstructionFlagTests(unittest.TestCase):
    def test_lsrs_known_zero_prunes_beq_fallthrough(self):
        # LSRS r2,r1,#5; BEQ +2; MOVS r0,#0; BX LR; BX LR.
        facts = FirmwareFacts(thumb_words(
            0x094A, 0xD001, 0x2000, 0x4770, 0x4770))
        function = facts.function(CodeAddress(0), initial_registers={
            a.ARM_REG_R1: 31,
        })
        self.assertTrue(function.complete)
        self.assertEqual(tuple(target for source, target in function.control_edges
                               if source == CodeAddress(2)), (CodeAddress(8),))

    def test_lsrs_updates_carry_and_preserves_overflow(self):
        # CMP r0,#1 makes V=1; LSRS r2,r1,#5 sets C=1 and preserves V.
        # BVS at +4 must take its target at +8.
        facts = FirmwareFacts(thumb_words(
            0x2801, 0x094A, 0xD600, 0x4770, 0x4770))
        function = facts.function(CodeAddress(0), initial_registers={
            a.ARM_REG_R0: 0x80000000,
            a.ARM_REG_R1: 31,
        })
        self.assertTrue(function.complete)
        self.assertEqual(tuple(target for source, target in function.control_edges
                               if source == CodeAddress(4)), (CodeAddress(8),))

    def test_unmodelled_flag_write_does_not_reuse_stale_compare(self):
        # CMP r0,#0; MOVS r0,r1 (unknown input); BEQ. Both paths remain live.
        facts = FirmwareFacts(thumb_words(
            0x2800, 0x0008, 0xD000, 0x4770, 0x4770))
        function = facts.function(CodeAddress(0), initial_registers={
            a.ARM_REG_R0: 0,
        })
        self.assertEqual(set(target for source, target in function.control_edges
                             if source == CodeAddress(4)),
                         {CodeAddress(6), CodeAddress(8)})

    def test_register_shift_over_32_clears_carry(self):
        # CMP r0,#0 sets C; LSRS r2,r1,r3 with r3=33 must clear it.
        facts = FirmwareFacts(arm_words(
            0xE3500000, 0xE1B02331, 0x2A000000,
            0xE12FFF1E, 0xE12FFF1E))
        function = facts.function(CodeAddress(0, 'arm'), initial_registers={
            a.ARM_REG_R0: 0,
            a.ARM_REG_R1: 0x80000000,
            a.ARM_REG_R3: 33,
        })
        self.assertEqual(tuple(target for source, target in function.control_edges
                               if source == CodeAddress(8, 'arm')),
                         (CodeAddress(12, 'arm'),))

    def test_rotated_arm_movs_immediate_sets_shifter_carry(self):
        # CMP r1,#1 sets C=0. MOVS r0,#0x80000000 rotates the immediate and
        # sets C from its top bit, so BHS takes the target.
        facts = FirmwareFacts(arm_words(
            0xE3510001, 0xE3B00102, 0x2A000000,
            0xE12FFF1E, 0xE12FFF1E))
        function = facts.function(CodeAddress(0, 'arm'), initial_registers={
            a.ARM_REG_R1: 0,
        })
        self.assertEqual(tuple(target for source, target in function.control_edges
                               if source == CodeAddress(8, 'arm')),
                         (CodeAddress(16, 'arm'),))

    def test_thumb_adr_uses_aligned_pc_and_arm_add_pc_uses_arm_pc(self):
        thumb = bytearray(0x64)
        thumb[:4] = thumb_words(0xA117, 0x4770)  # ADR r1,#0x5c; BX LR
        facts = FirmwareFacts(bytes(thumb), base=0x100)
        function = facts.function(CodeAddress(0x100, 'thumb'))
        self.assertEqual(facts.register_value(
            function, CodeAddress(0x102, 'thumb'), a.ARM_REG_R1).value, 0x160)

        arm = arm_words(0xE28F105C, 0xE12FFF1E)  # ADD r1,pc,#0x5c; BX LR
        facts = FirmwareFacts(arm, base=0x100)
        function = facts.function(CodeAddress(0x100, 'arm'))
        self.assertEqual(facts.register_value(
            function, CodeAddress(0x104, 'arm'), a.ARM_REG_R1).value, 0x164)


if __name__ == '__main__':
    unittest.main()
