"""Synthetic Thumb graphs for closed source-prefix return proofs."""
import struct
import unittest

from msm5xxx_emulator.detection.devices.input.source_flow import closed_input_region


def _image(*halfwords):
    return struct.pack("<" + "H" * len(halfwords), *halfwords)


class InputSourceFlowTests(unittest.TestCase):
    def test_local_stm_disjoint_from_saved_lr_is_accepted(self):
        # push {lr}; reserve 12 bytes; r4 = sp; stm r4!, {r0-r2};
        # release locals; pop {r3}; bx r3.
        region = closed_input_region(_image(0xB500, 0xB083, 0x466C, 0xC407,
                                            0xB003, 0xBC08, 0x4718), 0, ())
        self.assertIsNotNone(region)
        self.assertEqual(len(region.scope_exits), 1)

    def test_stm_overwriting_saved_lr_is_rejected(self):
        # Save LR, point r4 at its slot, overwrite with one word, then return.
        self.assertIsNone(closed_input_region(_image(0xB500, 0x466C, 0xC410,
                                                     0xBC08, 0x4718), 0, ()))

    def test_scalar_overlap_with_saved_lr_is_rejected(self):
        self.assertIsNone(closed_input_region(_image(0xB500, 0x2000, 0x9000,
                                                     0xBC08, 0x4718), 0, ()))

    def test_unrelated_bx_register_is_rejected(self):
        self.assertIsNone(closed_input_region(_image(0xB500, 0xBC08, 0x4710), 0, ()))

    def test_unbalanced_sp_is_rejected(self):
        self.assertIsNone(closed_input_region(_image(0xB500, 0xB081, 0xBC08,
                                                     0x4718), 0, ()))

    def test_unknown_pointer_store_is_rejected(self):
        self.assertIsNone(closed_input_region(_image(0xB500, 0x6008, 0xBC08,
                                                     0x4718), 0, ()))

    def test_sp_pointer_passed_to_opaque_call_is_rejected(self):
        # mov r0,sp; bl next; pop {r3}; bx r3.
        self.assertIsNone(closed_input_region(_image(0xB500, 0x4668, 0xF000,
                                                     0xF800, 0xBC08, 0x4718), 0, ()))

    def test_alternative_path_overwriting_lr_is_rejected(self):
        # One branch reaches POP untouched; the other stores over saved LR.
        self.assertIsNone(closed_input_region(_image(0xB500, 0x2800, 0xD001,
                                                     0x2000, 0x9000, 0xBC08,
                                                     0x4718), 0, ()))

    def test_complete_prefix_without_bx_is_returned(self):
        region = closed_input_region(_image(0x2000, 0x4770), 0, (2,))
        self.assertIsNotNone(region)
        self.assertTrue(region.complete)
        self.assertEqual(region.scope_exits, (region.instructions[-1],))

    def test_early_return_can_coexist_with_requested_loop_exit(self):
        # The conditional path reaches the BX; fallthrough reaches the
        # requested loop endpoint and is outside the return proof.
        region = closed_input_region(_image(0xB500, 0x2800, 0xD000, 0xE7FE,
                                            0xBC08, 0x4718), 0, (6,))
        self.assertIsNotNone(region)
        self.assertIn(region.instructions[-1], region.scope_exits)
        self.assertIn(type(region.instructions[0])(6), region.scope_exits)

    def test_indexed_stack_store_is_rejected(self):
        # STR r0,[sp,r1] could overlap the saved LR word.
        self.assertIsNone(closed_input_region(_image(0xB500, 0x50A8, 0xBC08,
                                                     0x4718), 0, ()))

    def test_requested_bxr0_endpoint_is_not_trusted(self):
        # One conditional edge reaches the caller endpoint BX r0; the other
        # reaches the requested loop boundary. The endpoint still needs proof.
        self.assertIsNone(closed_input_region(_image(0xB500, 0x2800, 0xD001,
                                                     0xE7FE, 0x4710), 0,
                                              (6, 8)))

    def test_requested_bx_restoring_entry_lr_is_accepted(self):
        # The requested endpoint itself pops the saved entry LR into r3.
        region = closed_input_region(_image(0xB500, 0xBC08, 0x4718), 0, (4,))
        self.assertIsNotNone(region)
        self.assertEqual(region.scope_exits, (region.instructions[-1],))


if __name__ == "__main__":
    unittest.main()
