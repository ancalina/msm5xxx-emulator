"""Synthetic, firmware-independent checks for the arithmetic call proof."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.devices.input.arithmetic_calls import prove_small_divmod


def _words(*words):
    return b"".join(struct.pack("<I", word) for word in words)


def _thumb_to_arm(*arm_words):
    # BX PC; two bytes of alignment padding; ARM body.
    return struct.pack("<HH", 0x4778, 0x46C0) + _words(*arm_words)


class ArithmeticCallTests(unittest.TestCase):
    def test_proves_concrete_division_result_from_executed_instructions(self):
        # r2 = dividend - divisor - divisor; r0 = 7 - r2; r1 = r2.
        # For 17 / 6 this computes quotient 2 and remainder 5.
        image = _thumb_to_arm(
            0xE1A02001,  # mov r2, r1
            0xE0522000,  # subs r2, r2, r0
            0xE0A0C000,  # adc r12, r0, r0 (uses the carry set above)
            0xE0A03060,  # adc r3, r0, r0, rrx (known C=1)
            0xE0522000,  # subs r2, r2, r0
            0xE2620007,  # rsb r0, r2, #7
            0xE1A01002,  # mov r1, r2
            0xE12FFF1E,  # bx lr
        )
        proof = prove_small_divmod(image, 0, 6, 17)
        self.assertIsNotNone(proof)
        registers, spans = proof
        self.assertEqual(registers[a.ARM_REG_R0], 2)
        self.assertEqual(registers[a.ARM_REG_R1], 5)
        self.assertEqual(registers[a.ARM_REG_R3], 0x8000000A)
        self.assertEqual(registers[a.ARM_REG_R12], 13)
        self.assertIn((0, 2), spans)
        self.assertIn((4, 4), spans)


    def test_tracks_carry_for_conditional_subtraction_path(self):
        # 5 - 6 clears C, so MOVCC executes and restores the remainder input.
        # ADC then consumes the cleared carry and RSB produces the zero quotient.
        image = _thumb_to_arm(
            0xE1A02001,  # mov r2, r1
            0xE0522000,  # subs r2, r2, r0
            0x31A02001,  # movcc r2, r1 (conditional, no flags)
            0xE0A03001,  # adc r3, r0, r1
            0xE263000B,  # rsb r0, r3, #11
            0xE12FFF1E,
        )
        proof = prove_small_divmod(image, 0, 6, 5)
        self.assertIsNotNone(proof)
        self.assertEqual(proof[0][a.ARM_REG_R0], 0)
        self.assertEqual(proof[0][a.ARM_REG_R1], 5)


    def test_rejects_wrong_result_clobber_memory_and_bad_return(self):
        wrong = _thumb_to_arm(0xE1A00001, 0xE1A01000, 0xE12FFF1E)
        self.assertIsNone(prove_small_divmod(wrong, 0, 6, 17))

        clobber = _thumb_to_arm(0xE3A04000, 0xE1A00001, 0xE1A01000, 0xE12FFF1E)
        self.assertIsNone(prove_small_divmod(clobber, 0, 6, 17))

        memory = _thumb_to_arm(0xE5902000, 0xE12FFF1E)  # ldr r2, [r0]
        self.assertIsNone(prove_small_divmod(memory, 0, 6, 17))

        bad_return = _thumb_to_arm(0xE1A00001, 0xE1A01000, 0xE12FFF10)  # bx r0
        self.assertIsNone(prove_small_divmod(bad_return, 0, 6, 17))


    def test_rejects_unbounded_branch_and_out_of_image_branch(self):
        loop = _thumb_to_arm(0xEAFFFFFE)  # b .
        outside = _thumb_to_arm(0xEA000100)
        self.assertIsNone(prove_small_divmod(loop, 0, 6, 17))
        self.assertIsNone(prove_small_divmod(outside, 0, 6, 17))

    def test_rejects_unknown_inputs(self):
        image = _thumb_to_arm(0xE12FFF1E)
        for args in ((image, None, 6, 5), (image, 0, None, 5),
                     (image, 0, 6, None)):
            with self.subTest(args=args):
                self.assertIsNone(prove_small_divmod(*args))

    def test_rejects_conditional_branch_before_flags_are_known(self):
        # BEQ can skip the correct result initialization; entry flags are
        # inherited from an unknown caller state.
        image = _thumb_to_arm(
            0x0A000002,  # beq to the bad return at offset 20
            0xE3A00002,  # mov r0, #2
            0xE3A01005,  # mov r1, #5
            0xE12FFF1E,  # bx lr
            0xE12FFF1E,  # bx lr
        )
        self.assertIsNone(prove_small_divmod(image, 0, 6, 17))

    def test_rejects_adc_with_unknown_carry(self):
        image = _thumb_to_arm(0xE0A02001, 0xE12FFF1E)
        self.assertIsNone(prove_small_divmod(image, 0, 6, 17))

    def test_rejects_rotated_immediate_flag_carry_and_unaligned_target(self):
        image = _thumb_to_arm(
            0xE3B02102,  # movs r2, #0x80000000 (rotated immediate)
            0xE3A00000,  # mov r0, #0
            0xE3A01000,  # mov r1, #0
            0xE12FFF1E,
        )
        self.assertIsNone(prove_small_divmod(image, 0, 1, 0))
        self.assertIsNone(prove_small_divmod(image, 1, 1, 0))

    def test_rejects_rrx_when_entry_carry_is_unknown(self):
        image = _thumb_to_arm(
            0xE0A02061,  # adc r2, r0, r1, rrx: carry is an input to the shift
            0xE1A00001,
            0xE1A01002,
            0xE12FFF1E,
        )
        self.assertIsNone(prove_small_divmod(image, 0, 2, 7))


if __name__ == "__main__":
    unittest.main()
