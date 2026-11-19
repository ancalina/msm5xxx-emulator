import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.devices.input.branch_conditions import (
    add_flags, compare_flags, condition_holds, flag_mask, move_flags,
    refine_flags, unknown_flags,
)


class InputBranchConditionsTests(unittest.TestCase):
    def test_signed_and_unsigned_comparisons_at_word_boundaries(self):
        for left, right, unsigned_less, signed_less in (
                (0, 1, True, True), (1, 0, False, False),
                (0xffffffff, 0, False, True),
                (0x80000000, 1, False, True),
                (0x7fffffff, 0xffffffff, True, False)):
            with self.subTest(left=left, right=right):
                flags = compare_flags(left, right)
                self.assertEqual(condition_holds(a.ARM_CC_LO, flags), unsigned_less)
                self.assertEqual(condition_holds(a.ARM_CC_HS, flags), not unsigned_less)
                self.assertEqual(condition_holds(a.ARM_CC_LT, flags), signed_less)
                self.assertEqual(condition_holds(a.ARM_CC_GE, flags), not signed_less)

    def test_addition_distinguishes_carry_and_signed_overflow(self):
        self.assertEqual(add_flags(0xffffffff, 1), (False, True, True, False))
        self.assertEqual(add_flags(0x7fffffff, 1), (True, False, False, True))

    def test_thumb_move_updates_zero_but_preserves_carry_and_overflow(self):
        flags = move_flags(0, compare_flags(1, 0))
        self.assertEqual(flags, (False, True, True, False))
        self.assertIs(condition_holds(a.ARM_CC_NE, flags), False)
        self.assertIs(condition_holds(a.ARM_CC_LO, flags), False)

    def test_partial_flags_only_reject_conditions_that_are_known_false(self):
        flags = move_flags(0, unknown_flags())
        self.assertIs(condition_holds(a.ARM_CC_GT, flags), False)
        self.assertIs(condition_holds(a.ARM_CC_LE, flags), True)
        self.assertIsNone(condition_holds(a.ARM_CC_LT, flags))
        self.assertEqual(compare_flags(None, 1), unknown_flags())

    def test_branch_constraints_retain_correlated_sign_and_overflow(self):
        ge = refine_flags(a.ARM_CC_GE, unknown_flags(), True)
        self.assertNotEqual(ge, 0)
        self.assertEqual(refine_flags(a.ARM_CC_LT, ge, True), 0)
        self.assertIs(condition_holds(a.ARM_CC_GE, ge), True)
        equal = refine_flags(a.ARM_CC_EQ, unknown_flags(), True)
        self.assertEqual(refine_flags(a.ARM_CC_NE, equal, True), 0)

    def test_move_updates_a_constrained_domain_without_losing_carry(self):
        carry = refine_flags(a.ARM_CC_HS, unknown_flags(), True)
        moved = move_flags(0, carry)
        self.assertIs(condition_holds(a.ARM_CC_EQ, moved), True)
        self.assertIs(condition_holds(a.ARM_CC_LO, moved), False)
        self.assertEqual(flag_mask(compare_flags(0, 0)), 1 << 6)


if __name__ == '__main__':
    unittest.main()
