import struct
import unittest

from msm5xxx_emulator.detection.devices.rex.slot_controller import (
    _copy_source,
    _common_handler_mask_load,
    _collapse_route_candidates,
    _descriptor_seeds,
    _literal_call_arguments,
    _row_layout,
    _unique_call_for_slot,
)
from msm5xxx_emulator.detection.devices.rex.slot_controller_flow import (
    group_stride_proof,
    one_definition,
    prove_setter_path,
    prove_vector_path,
)


class SlotControllerSourceTests(unittest.TestCase):
    def setUp(self):
        # Synthetic Thumb registrar: slot * 28 + literal table, then store the
        # callback argument at field 20. The literal is data, not firmware.
        self.registrar = bytearray.fromhex(
            "10b5041c0f1c1c2304495c43641867616268a268e268226910bd00bf"
            "80000010")

    def test_indexed_registrar_requires_live_slot_stride_base_and_callback(self):
        accepted = _row_layout(bytes(self.registrar), 0,
            callback_table=0x10000080, callback_pointer=0x10000041)
        self.assertIsNotNone(accepted)
        self.assertEqual((accepted["row_size"], accepted["callback_offset"]),
                         (0x1c, 0x14))

        wrong_stride = bytearray(self.registrar)
        wrong_stride[6] = 0x1d  # MOVS r3,#29.
        self.assertIsNone(_row_layout(bytes(wrong_stride), 0,
            callback_table=0x10000080, callback_pointer=0x10000041))

        clobbered_slot = bytearray(self.registrar)
        clobbered_slot[2:4] = bytes.fromhex("0224")  # MOVS r4,#2.
        self.assertIsNone(_row_layout(bytes(clobbered_slot), 0,
            callback_table=0x10000080, callback_pointer=0x10000041))

        clobbered_callback = bytearray(self.registrar)
        clobbered_callback[4:6] = bytes.fromhex("0127")  # MOVS r7,#1.
        self.assertIsNone(_row_layout(bytes(clobbered_callback), 0,
            callback_table=0x10000080, callback_pointer=0x10000041))

        wrong_base = bytearray(self.registrar)
        wrong_base[12:14] = bytes.fromhex("a418")  # ADD r4,r4,r2.
        self.assertIsNone(_row_layout(bytes(wrong_base), 0,
            callback_table=0x10000080, callback_pointer=0x10000041))

    def test_registrar_extent_stops_at_complete_pop_bx_return(self):
        # POP {r4}; POP {r3}; BX r3 is the return. The following MOVS changes
        # the stride register but is outside this function's CFG.
        image = bytes(0x20) + bytes.fromhex(
            "10b5041c0f1c1c2305495c43641867616268a268e268226910bc08bc"
            "1847012380000010")
        layout = _row_layout(image, 0x20, callback_table=0x10000080,
                             callback_pointer=0x10000041)
        self.assertIsNotNone(layout)
        self.assertEqual(layout["row_size"], 0x1c)
        self.assertNotIn((0x3e, 2), layout["source_sites"])

    def test_entry_arguments_cross_calls_only_when_callee_preserves_them(self):
        image = bytearray.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
            "10b500f00df8041c0f1c1c2305495c43641867616268a268e268226910bd00bf"
            "0020704780000010")
        preserving = bytearray(image)
        preserving[0x40:0x42] = bytes.fromhex("c046")  # No incoming-register writes.
        self.assertIsNotNone(_row_layout(bytes(preserving), 0x20,
            callback_table=0x10000080, callback_pointer=0x10000041))

        for clobber in ("0020", "0121"):
            with self.subTest(clobber=clobber):
                changed = bytearray(preserving)
                changed[0x40:0x42] = bytes.fromhex(clobber)
                self.assertIsNone(_row_layout(bytes(changed), 0x20,
                    callback_table=0x10000080, callback_pointer=0x10000041))

    def test_call_between_argument_copies_must_preserve_callback_register(self):
        image = bytearray.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
            "10b5041c00f00cf80f1c1c2305495c43641867616268a268e268226910bd00bf"
            "0021704780000010")
        self.assertIsNone(_row_layout(bytes(image), 0x20,
            callback_table=0x10000080, callback_pointer=0x10000041))
        preserving = bytearray(image)
        preserving[0x40:0x42] = bytes.fromhex("c046")
        self.assertIsNotNone(_row_layout(bytes(preserving), 0x20,
            callback_table=0x10000080, callback_pointer=0x10000041))

    def test_group_scan_requires_source_owned_counter_table_and_fields(self):
        code = bytes.fromhex(
            "10b586b00120059005980a230949584340180090028842888288c288"
            "027a427a059801300004000c0590042800daebe706b010bd00010010")
        rows = ((0, 0, 0, 0, 0, 0), (1, 1, 1, 1, 1, 28),
                (1, 2, 3, 4, 29, 29), (0x200, 0, 0x200, 4, 30, 30),
                (0, 0, 0, 0, 0, 0))

        def analyze(change=None):
            image = bytearray(0x300)
            body = bytearray(code)
            if change is not None:
                change(body)
            image[0x20:0x20 + len(body)] = body
            for index, row in enumerate(rows):
                struct.pack_into("<4H2B", image, 0x100 + index * 10, *row)
            return group_stride_proof(bytes(image), 0x20, 0x10000100,
                (0x100, 0x10000100, 0x40, 0), 3, 10, 30, 0x200)

        accepted = analyze()
        self.assertIsNotNone(accepted)
        self.assertEqual(accepted["group_row_size"], 10)
        self.assertEqual(accepted["group_records"][2][4:], (30, 30))

        mutations = (
            lambda body: body.__setitem__(10, 11),  # wrong MUL stride
            lambda body: body.__setitem__(slice(34, 36), bytes.fromhex("481c")),  # ADD uses wrong counter
            lambda body: body.__setitem__(slice(8, 10), bytes.fromhex("0120")),  # no counter load
            lambda body: body.__setitem__(slice(12, 14), bytes.fromhex("0021")),  # base clobber
            lambda body: body.__setitem__(slice(18, 20), bytes.fromhex("0191")),  # pointer spill clobber
            lambda body: body.__setitem__(slice(44, 46), bytes.fromhex("01d1")),  # dead bound branch
            lambda body: body.__setitem__(slice(10, 12), bytes.fromhex("08bf")),  # predicated source
            lambda body: body.__setitem__(slice(28, 30), bytes.fromhex("0a88")),  # decoy field base
        )
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                self.assertIsNone(analyze(mutation))

    def test_call_registration_requires_reachable_unpredicated_arguments(self):
        direct = bytes(0x20) + bytes.fromhex(
            "10b503491e2000f001f810bd704700bf01000010")
        self.assertEqual(_literal_call_arguments(direct, 0x26)["slot"], 30)

        bypass = bytes(0x20) + bytes.fromhex(
            "10b509e003491e2000f002f810bd00bf704700bf01000010f6e7")
        self.assertIsNone(_literal_call_arguments(bypass, 0x28))

        predicated = bytes(0x20) + bytes.fromhex(
            "10b508bf03491e2000f002f810bd00bf704700bf01000010")
        self.assertIsNone(_literal_call_arguments(predicated, 0x28))

    def test_setter_branch_uses_unconditional_compare_flags(self):
        setter = bytes(0x20) + bytes.fromhex(
            "034a002801d1516000e09160704700bf80000010")
        self.assertTrue(prove_setter_path(setter, 0x20, 0x22,
            (0x26, 0x2a), 68, 0x10000080))

        clobbered_flags = bytes(0x20) + bytes.fromhex(
            "034a0028012301d1516000e09160704780000010")
        self.assertFalse(prove_setter_path(clobbered_flags, 0x20, 0x22,
            (0x28, 0x2c), 68, 0x10000080))

    def test_arm_vector_route_rejects_conditional_indirect_branch(self):
        vector = bytes(0x20) + bytes.fromhex("04009fe5001090e511ff2fe140000010")
        self.assertTrue(prove_vector_path(vector, 0x20, 0x20, 0x24, 0x28))

        conditional = bytes(0x20) + bytes.fromhex("04009fe5001090e511ff2f1140000010")
        self.assertFalse(prove_vector_path(conditional, 0x20, 0x20, 0x24, 0x28))

    def test_common_handler_requires_mask_literal_in_r2(self):
        common = bytearray(0x40)
        struct.pack_into("<H", common, 0x28, 0x4a00)  # LDR r2,[pc]
        struct.pack_into("<I", common, 0x2c, 0x0200)
        self.assertTrue(_common_handler_mask_load(bytes(common), 0x20, 0x0200))

        alternate = bytearray(common)
        struct.pack_into("<H", alternate, 0x28, 0x4f00)  # LDR r7,[pc]
        self.assertFalse(_common_handler_mask_load(bytes(alternate), 0x20, 0x0200))

    def test_reset_owned_descriptor_seed_maps_to_source(self):
        image = bytearray(96)
        words = (0x03000C80, 0x03000C94, 0x0200, 0x10000020,
                 0x10000026, 0x41, 0)
        struct.pack_into("<7I", image, 16, *words)
        copy = (16, 0x10000000, 64, 0x200)

        seeds = _descriptor_seeds(bytes(image), copy, 0x03000C80,
                                  0x03000C94, 0x0200)

        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0][:2], (16, 0x10000000))
        self.assertEqual(_copy_source(copy, 0x10000000, 28, len(image)), 16)
        self.assertIsNone(_copy_source(copy, 0x10000040, 4, len(image)))

    def test_descriptor_seed_rejects_wrong_mmio_and_bad_callback(self):
        for words in (
            (0x03000C84, 0x03000C94, 0x0200, 0x10000020,
             0x10000026, 0x41, 0),
            (0x03000C80, 0x03000C94, 0x0200, 0x10000020,
             0x10000026, 0x40, 0),
        ):
            image = bytearray(96)
            struct.pack_into("<7I", image, 16, *words)
            self.assertEqual(_descriptor_seeds(bytes(image),
                (16, 0x10000000, 64, 0x200), 0x03000C80,
                0x03000C94, 0x0200), [])

    def test_identical_slot_registration_duplicates_merge(self):
        calls = [
            {"slot": 30, "callback_pointer": 0x101},
            {"slot": 30, "callback_pointer": 0x101},
        ]
        self.assertEqual(_unique_call_for_slot(calls, 30), calls[0])

    def test_conflicting_slot_registrations_reject(self):
        calls = [
            {"slot": 30, "callback_pointer": 0x101},
            {"slot": 30, "callback_pointer": 0x201},
        ]
        self.assertIsNone(_unique_call_for_slot(calls, 30))

    def test_duplicate_outer_registration_contexts_merge_only_same_route(self):
        def candidate(callback_pointer, outer_callsite):
            return (16, 0x10000020, 0x10000000, (1, 2, 3),
                {"row_size": 0x1c, "callback_offset": 0x14}, 0x80,
                {"callback_pointer": callback_pointer,
                 "callback": callback_pointer & ~1}, (5, 0x90), (5, 0xa0),
                0x200, {"handler_slot": 0x10000040,
                        "selector_calls": ((0x110, 0, 0x201),)},
                {"group_table": 0x10000100,
                 "group_records": [(1, 2, 3, 4, 1, 28),
                                   (1, 2, 3, 4, 29, 29),
                                   (0x200, 0, 0x200, 4, 30, 30)]},
                30, (0x120, 0x140, 0x160), outer_callsite)

        merged = _collapse_route_candidates((candidate(0x301, 0x180),
                                              candidate(0x301, 0x1a0),
                                              candidate(0x301, 0x1c0)))
        self.assertIsNotNone(merged)
        self.assertEqual(merged[1], (0x180, 0x1a0, 0x1c0))
        self.assertEqual(merged[0][-1], 0x180)

        conflicting = _collapse_route_candidates((candidate(0x301, 0x180),
                                                   candidate(0x501, 0x1a0)))
        self.assertIsNone(conflicting)

    def test_other_slot_cannot_satisfy_timer_registration(self):
        calls = [{"slot": 29, "callback_pointer": 0x101}]
        self.assertIsNone(_unique_call_for_slot(calls, 30))

    def test_register_clobber_or_multiple_reaching_definitions_reject(self):
        source_definition = object()
        self.assertIs(one_definition((source_definition,)), source_definition)
        self.assertIsNone(one_definition((None,)))
        self.assertIsNone(one_definition((source_definition, object())))
        self.assertIsNone(one_definition(None))

    def test_entry_definition_is_not_a_new_source_definition(self):
        self.assertIsNone(one_definition((None,)))


if __name__ == "__main__":
    unittest.main()
