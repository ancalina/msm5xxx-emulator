"""Synthetic code evidence, address views, and conservative propagation."""
import struct
import random
import unittest

from capstone.arm import ARM_CC_EQ, ARM_CC_NE

from msm5xxx_emulator.detection.arm import (
    thumb_bl_target as legacy_thumb_call_target,
    thumb_literal_value as legacy_thumb_literal_value,
)
from msm5xxx_emulator.detection.facts import (
    CodeAddress, FirmwareFacts, bind_facts, fact_scope, facts_for,
    source_prefix, with_fact_scope,
)
from msm5xxx_emulator.detection.image_view import ImageView, LoadOperation


def words(*values):
    return struct.pack('<' + 'H' * len(values), *values)


class FactsTests(unittest.TestCase):
    def test_mode_stack_uses_control_field_mask_independent_of_flag_fields(self):
        for instruction in (0xE121F000, 0xE129F000, 0xE12FF000):
            with self.subTest(instruction=hex(instruction)):
                image = struct.pack('<8I', 0xE59F0010, instruction,
                                    0xE59FD00C, 0xE12FFF1E, 0, 0, 0x13, 0x2000)
                result = FirmwareFacts(image, base=0x1000).function(
                    CodeAddress(0x1000, 'arm'))
                self.assertEqual(result.mode_stacks, ((0x1008, 0x13, 0x2000),))
        image = struct.pack('<8I', 0xE59F0010, 0xE128F000,
                            0xE59FD00C, 0xE12FFF1E, 0, 0, 0x13, 0x2000)
        result = FirmwareFacts(image, base=0x1000).function(CodeAddress(0x1000, 'arm'))
        self.assertEqual(result.mode_stacks, ())


    def test_reloaded_identical_image_reuses_only_an_equal_address_view(self):
        image = words(0x4900, 0x4770) + struct.pack('<I', 0x3000720)
        with fact_scope():
            first = bind_facts(image, ImageView.raw(image))
            decoded = first.decode(CodeAddress(0))
        reloaded = bytes(bytearray(image))
        self.assertIsNot(reloaded, image)
        with fact_scope():
            second = bind_facts(reloaded, ImageView.raw(reloaded))
            self.assertIs(second, first)
            self.assertIs(second.decode(CodeAddress(0)), decoded)
            hole = bind_facts(reloaded, ImageView.sparse(((0, reloaded[:4]),)))
            self.assertIsNot(hole, first)
            self.assertIsNone(hole.literal(CodeAddress(0)))
        changed = reloaded[:-1] + bytes((reloaded[-1] ^ 1,))
        with fact_scope():
            self.assertIsNot(bind_facts(changed, ImageView.raw(changed)), first)

    def test_local_paths_stop_at_branches_calls_and_missing_sites(self):
        source = FirmwareFacts(words(0x2001, 0xF000, 0xF802, 0x2102, 0x4770, 0x4770))
        function = source.function(CodeAddress(0))
        self.assertIsNone(function.linear_path(CodeAddress(0), CodeAddress(8)))
        self.assertEqual(function.linear_path(CodeAddress(0), CodeAddress(8),
                                             allowed_calls=(CodeAddress(2),)),
                         tuple(CodeAddress(pc) for pc in (0, 2, 6, 8)))
        self.assertIsNone(function.linear_path(CodeAddress(50), CodeAddress(50)))
        branch = FirmwareFacts(words(0xD000, 0x2001, 0x4770)).function(CodeAddress(0))
        self.assertIsNone(branch.linear_path(CodeAddress(0), CodeAddress(4)))

    def test_dominance_checks_all_paths_of_a_complete_local_graph(self):
        # Both paths reach BX LR; only one executes MOV r1,#1.
        function = FirmwareFacts(words(0x2800, 0xD101, 0x2101, 0xE000,
                                       0x2102, 0x4770)).function(CodeAddress(0))
        self.assertTrue(function.complete)
        self.assertTrue(function.dominates(CodeAddress(2), CodeAddress(10)))
        self.assertFalse(function.dominates(CodeAddress(4), CodeAddress(10)))
        self.assertFalse(function.dominates(CodeAddress(50), CodeAddress(10)))
        incomplete = FirmwareFacts(words(0x4700)).function(CodeAddress(0))
        self.assertFalse(incomplete.dominates(CodeAddress(0), CodeAddress(0)))

    def test_stack_loaded_return_requires_pop_on_every_incoming_path(self):
        ordinary = FirmwareFacts(words(0xB510, 0xBC10, 0xBC08, 0x4718))
        self.assertTrue(ordinary.function(CodeAddress(0)).complete)
        # One path bypasses POP r3, so BX r3 is still an unknown transfer.
        bypass = FirmwareFacts(words(0xD000, 0xBC08, 0x4718))
        result = bypass.function(CodeAddress(0))
        self.assertFalse(result.complete)
        self.assertIn(CodeAddress(4), result.unresolved)

    def test_callee_summary_stops_at_its_known_entry_return(self):
        from capstone.arm import ARM_REG_LR
        image = words(0x4770, 0x4800, 0x4770, 0x46C0) + struct.pack('<I', 0x3000720)
        facts = FirmwareFacts(image)
        result = facts.function(CodeAddress(0), initial_registers={ARM_REG_LR: 3},
                                stop_at_initial_return=True)
        self.assertTrue(result.complete)
        self.assertEqual(result.instructions, (CodeAddress(0),))
        self.assertEqual(result.literals, ())
        self.assertEqual(result.control_edges, ())

    def test_known_compare_excludes_impossible_call(self):
        image = words(0x2000, 0x2800, 0xD001, 0xF000, 0xF801, 0x4770, 0x4770)
        result = FirmwareFacts(image).function(CodeAddress(0))
        self.assertTrue(result.complete)
        self.assertEqual(result.calls, ())
        self.assertNotIn(CodeAddress(6), result.instructions)
        self.assertEqual([target for source, target in result.control_edges
                          if source == CodeAddress(4)], [CodeAddress(10)])

    def test_unknown_condition_keeps_both_control_successors(self):
        result = FirmwareFacts(words(0xD000, 0x4770, 0x4770)).function(CodeAddress(0))
        self.assertEqual({target for source, target in result.control_edges
                          if source == CodeAddress(0)}, {CodeAddress(2), CodeAddress(4)})

    def test_known_test_closes_interworking_return_continuation(self):
        # TST of a known Thumb entry selects its Thumb return veneer.
        code = struct.pack('<12I', 0xE59F4018, 0xE3140001,
                           0x159FE014, 0x059FE014, 0xE12FFF14,
                           0x00004778, 0xE59F000C, 0xEAFFFFFE,
                           0x41, 0x15, 0x18, 0x03000720)
        image = code + bytes(0x40 - len(code)) + words(0x4770)
        facts = FirmwareFacts(image)
        result = facts.function(CodeAddress(0, 'arm'))
        self.assertTrue(result.complete)
        self.assertIn(CodeAddress(0x18, 'arm'), result.instructions)
        self.assertIn(CodeAddress(0x40), result.instructions)
        self.assertTrue(any(item.value == 0x03000720 for item in result.literals))
        self.assertFalse(any(item.instruction.address == 0xC for item in result.literals))

    def test_thumb_literals_and_poll(self):
        # LDR r1, pool; LDRB r0,[r1,#4]; CMP r0,#0; BEQ read; BX lr.
        image = words(0x4902, 0x7908, 0x2800, 0xD0FC, 0x4770, 0x46C0)
        image += struct.pack('<I', 0x030007B0)
        facts = FirmwareFacts(image)
        result = facts.function(CodeAddress(0))
        self.assertTrue(result.complete)
        self.assertEqual([(use.address, use.width) for use in result.polls], [(0x030007B4, 1)])
        self.assertEqual(result.peripheral_map()[0].evidence, (0, 2, 4, 6, 8, 12))
        self.assertIs(result, facts.function(CodeAddress(0)))
        self.assertIs(facts.decode(CodeAddress(0)), facts.decode(CodeAddress(0)))

    def test_arm_literal_and_read(self):
        image = struct.pack('<5I', 0xE59F1008, 0xE5910004, 0xE12FFF1E, 0, 0x030007B0)
        facts = FirmwareFacts(image, base=0x1000)
        result = facts.function(CodeAddress(0x1000, 'arm'))
        self.assertTrue(result.complete)
        self.assertEqual(result.literals[0].pool, 0x1010)
        self.assertEqual(result.peripheral_map()[0].address, 0x030007B4)

    def test_thumb_pool_aligns_guest_pc(self):
        # A non-word-aligned load address changes the PC alignment.
        image = words(0x4900) + struct.pack('<I', 0x030007B0)
        facts = FirmwareFacts(image, base=0x1002)
        self.assertEqual(facts.literal(CodeAddress(0x1002)).pool, 0x1004)
        self.assertEqual(facts.literal(CodeAddress(0x1002)).value, 0x030007B0)

    def test_supplied_hole_is_not_literal(self):
        view = ImageView.sparse(((0, words(0x4900)), (8, b'\xff' * 4)))
        self.assertIsNone(FirmwareFacts(b'', view=view).literal(CodeAddress(0)))

    def test_opaque_call_clobbers_argument_registers(self):
        image = words(0x4903, 0xF000, 0xF805, 0x7908, 0x4770, 0, 0, 0)
        image += struct.pack('<I', 0x030007B0)
        result = FirmwareFacts(image).function(CodeAddress(0))
        self.assertEqual(len(result.calls), 1)
        self.assertEqual(result.peripheral_map(), ())

    def test_join_removes_speculative_access(self):
        # First path supplies r1, another incoming path overwrites it from r0.
        image = words(0x4903, 0x2800, 0xD000, 0xE000, 0x1C01,
                      0x7908, 0x4770, 0)
        image += struct.pack('<I', 0x030007B0)
        self.assertEqual(FirmwareFacts(image).function(CodeAddress(0)).peripheral_map(), ())

    def test_unresolved_and_budget_are_incomplete(self):
        self.assertFalse(FirmwareFacts(words(0x4700)).function(CodeAddress(0)).complete)
        self.assertFalse(FirmwareFacts(words(0x46C0, 0x4770)).function(CodeAddress(0), budget=1).complete)
        self.assertFalse(FirmwareFacts(words(0xDF00)).function(CodeAddress(0)).complete)

    def test_discovery_is_separate_from_function_proof(self):
        image = words(0xF000, 0xF802, 0x4770, 0, 0x4770)
        facts = FirmwareFacts(image)
        self.assertEqual(facts.call_candidates(), ((0, 8),))
        self.assertEqual(facts.function(CodeAddress(8)).calls, ())

    def test_identity_cache_and_mutable_inputs(self):
        image = words(0x4770)
        self.assertIs(facts_for(image), facts_for(image))
        mutable = bytearray(image)
        before = facts_for(mutable)
        mutable[:] = words(0x4700)
        self.assertIsNot(before, facts_for(mutable))
        view = ImageView.raw(image, base=0x1000)
        self.assertIs(facts_for(image, base=0x1000, view=view),
                      facts_for(image, base=0x1000, view=view))

    def test_scoped_binding_controls_reads_and_survives_cache_eviction(self):
        image = words(0x4900, 0x4770) + struct.pack('<I', 0x3001)
        view = ImageView.sparse(((0, image[:4]),))
        with fact_scope():
            bound = bind_facts(image, view)
            self.assertEqual(bound.image, image)
            self.assertIs(facts_for(image), bound)
            self.assertIsNotNone(bound.decode(CodeAddress(0)))
            self.assertIsNone(bound.literal(CodeAddress(0)))
            self.assertIsNone(bound.decode(CodeAddress(4)))

            for index in range(8):
                facts_for(bytes((index,)) * 12)
            self.assertIs(facts_for(image), bound)
        self.assertIsNot(facts_for(image), bound)
        self.assertIsNotNone(facts_for(image).literal(CodeAddress(0)))

    def test_scoped_bindings_nest_restore_and_mutable_inputs_do_not_bind(self):
        outer_image = words(0x4900, 0x4770) + struct.pack('<I', 0x3001)
        inner_image = words(0x4900, 0x4770) + struct.pack('<I', 0x4001)
        with fact_scope():
            outer = bind_facts(outer_image, ImageView.sparse(((0, outer_image[:4]),)))
            with fact_scope():
                self.assertIs(facts_for(outer_image), outer)
                inner = bind_facts(inner_image, ImageView.sparse(((0, inner_image[:4]),)))
                self.assertIs(facts_for(inner_image), inner)
            self.assertIs(facts_for(outer_image), outer)
            self.assertIsNot(facts_for(inner_image), inner)

            mutable = bytearray(outer_image)
            self.assertIsNone(bind_facts(mutable, ImageView.raw(mutable)))
            self.assertIsNot(facts_for(mutable).view, outer.view)

    def test_with_fact_scope_decorator_isolates_bindings(self):
        image = words(0x4770)

        @with_fact_scope
        def inspect_scoped_image():
            bound = bind_facts(image, ImageView.sparse(((0, image),)))
            return facts_for(image) is bound

        self.assertTrue(inspect_scoped_image())
        with fact_scope():
            self.assertIsNotNone(facts_for(image))

    def test_thumb_fact_helpers_match_legacy_decoders_and_respect_holes(self):
        literal_image = words(0x4901, 0x4770, 0x46C0, 0x46C0) + struct.pack('<I', 0x3001)
        facts = FirmwareFacts(literal_image)
        self.assertEqual(facts.thumb_literal_value(0, 1),
                         legacy_thumb_literal_value(literal_image, 0, 1))
        literal_hole = ImageView.sparse(((0, literal_image[:4]),))
        self.assertIsNone(FirmwareFacts(literal_image, view=literal_hole)
                          .thumb_literal_value(0, 1))

        call_image = struct.pack('<2H', 0xF000, 0xF800)
        call_facts = FirmwareFacts(call_image)
        self.assertEqual(call_facts.thumb_call_target(0),
                         legacy_thumb_call_target(call_image, 0))
        call_hole = ImageView.sparse(((0, call_image[:2]),))
        self.assertIsNone(FirmwareFacts(call_image, view=call_hole)
                          .thumb_call_target(0))

    def test_source_prefix_caches_and_preserves_normalized_holes(self):
        image = words(0x4902, 0x4770) + b'\xff' * 8 + struct.pack('<I', 0x3001)
        supplied = ImageView.sparse(((0, image[:4]),), origin=0)
        with fact_scope():
            full_facts = bind_facts(image, supplied)
            prefix = source_prefix(image, 16)
            self.assertIs(source_prefix(image, 16), prefix)
            prefix_facts = facts_for(prefix)
            self.assertIs(prefix_facts, facts_for(prefix))
            self.assertEqual(prefix_facts.view.origin, supplied.origin)
            self.assertEqual(len(prefix_facts.view.segments), len(supplied.segments))
            self.assertIsNone(prefix_facts.view.read(4, 8))
            self.assertIsNone(prefix_facts.literal(CodeAddress(0)))
            self.assertIs(facts_for(image), full_facts)

    def test_source_prefix_raw_outside_scope_and_full_prefix_identity(self):
        image = words(0x4900, 0x4770) + struct.pack('<I', 0x3001)
        prefix = source_prefix(image, 4)
        self.assertEqual(prefix, image[:4])
        self.assertTrue(facts_for(prefix).view.covers(0, 4))

        with fact_scope():
            view = ImageView.sparse(((0, image[:2]),))
            bound = bind_facts(image, view)
            self.assertIs(source_prefix(image, len(image)), image)
            self.assertIs(facts_for(image), bound)

    def test_reachability_reports_entry_budget_exhaustion(self):
        image = struct.pack('<3I', 0xEB000000, 0xE12FFF1E, 0xE12FFF1E)
        result = FirmwareFacts(image).reset_references(
            CodeAddress(0, 'arm'), max_entries=1)

        self.assertFalse(result.complete)
        self.assertTrue(result.entry_budget_exhausted)

    def test_arm_register_blx_resolves_thumb_veneer(self):
        # LDR r0,[pc,#4]; BLX r0; BX lr; pool=0x100c -> Thumb 0x2000.
        image = struct.pack('<4I', 0xE59F0004, 0xE12FFF30,
                            0xE12FFF1E, 0x00002001)
        result = FirmwareFacts(image, base=0x1000).function(
            CodeAddress(0x1000, 'arm'))

        self.assertTrue(result.complete)
        self.assertEqual(len(result.calls), 1)
        caller, target = result.calls[0]
        self.assertEqual((caller.address, caller.isa), (0x1004, 'arm'))
        self.assertEqual((target.address, target.isa), (0x2000, 'thumb'))

    def test_arm_bx_register_interworks_to_thumb_target(self):
        source = ImageView.sparse((
            (0x1000, struct.pack('<3I', 0xE59F0000, 0xE12FFF10, 0x2001)),
            (0x2000, words(0x4770, 0x46C0)),
        ))
        result = FirmwareFacts(b'', view=source).function(CodeAddress(0x1000, 'arm'))

        self.assertTrue(result.complete)
        self.assertEqual(result.calls, ())
        self.assertIn(CodeAddress(0x2000, 'thumb'), result.instructions)

    def test_mode_stack_records_only_known_control_mode_changes(self):
        image = struct.pack('<9I',
                            0xE59F0010, 0xE121F000,
                            0xE59FD00C, 0xE59F000C,
                            0xE121F000, 0xE12FFF1D,
                            0x13, 0x2000, 0x12)
        result = FirmwareFacts(image, base=0x1000).function(
            CodeAddress(0x1000, 'arm'))

        self.assertEqual(result.mode_stacks, ((0x1008, 0x13, 0x2000),))
        self.assertIn(CodeAddress(0x1014, 'arm'), result.unresolved)
        self.assertNotIn(CodeAddress(0x2000, 'arm'), result.instructions)

        unknown = bytearray(image)
        struct.pack_into('<I', unknown, 0x20, 0)
        rejected = FirmwareFacts(bytes(unknown), base=0x1000).function(
            CodeAddress(0x1000, 'arm'))
        self.assertEqual(rejected.mode_stacks, ((0x1008, 0x13, 0x2000),))

    def test_fiq_mode_change_invalidates_banked_register_constants(self):
        image = struct.pack('<9I',
                            0xE59F0010, 0xE121F000,
                            0xE59F800C, 0xE59F000C,
                            0xE121F000, 0xE12FFF18,
                            0x13, 0x2001, 0x11)
        view = ImageView.sparse(((0x1000, image),
                                 (0x2000, words(0x4770, 0x46C0))))
        result = FirmwareFacts(image, base=0x1000, view=view).function(
            CodeAddress(0x1000, 'arm'))

        self.assertIn(CodeAddress(0x1014, 'arm'), result.unresolved)
        self.assertNotIn(CodeAddress(0x2000, 'thumb'), result.instructions)

    def test_postcopy_descriptor_indirect_thumb_callback(self):
        # LDR r4, descriptor pointer; LDR r1,[r4]; BLX r1; BX lr.
        code = words(0x4C03, 0x6821, 0x4788, 0x4770, 0x46C0, 0x46C0,
                     0x46C0, 0x46C0) + struct.pack('<I', 0x4000)
        source = ImageView.sparse((
            (0x1000, code),
            (0x2000, struct.pack('<I', 0x3001)),
            (0x3000, words(0x4770, 0x46C0)),
        ))
        postcopy = source.materialize((
            LoadOperation('copy', 0x2000, 0x4000, 4, (0x800,)),
        ))
        facts = FirmwareFacts(code, base=0x1000, view=postcopy)
        result = facts.function(
            CodeAddress(0x1000, 'thumb', 'post-copy'), initial_memory=True)

        self.assertTrue(result.complete)
        self.assertEqual(len(result.calls), 1)
        self.assertEqual(result.calls[0][1], CodeAddress(0x3000, 'thumb', 'post-copy'))
        self.assertTrue(any(access.address == 0x4000 and access.operation == 'read'
                            for access in result.accesses))
        without_initial_memory = FirmwareFacts(b'', view=postcopy).function(
            CodeAddress(0x1000, 'thumb', 'post-copy'))
        self.assertNotEqual(len(without_initial_memory.calls), 1)
        self.assertIn(CodeAddress(0x1004, 'thumb', 'post-copy'),
                      without_initial_memory.unresolved)

    def test_rom_constant_load_resolves_without_initial_memory_opt_in(self):
        code = words(0x4C03, 0x6821, 0x4788, 0x4770, 0x46C0, 0x46C0,
                     0x46C0, 0x46C0) + struct.pack('<I', 0x2000)
        source = ImageView.sparse(((0x1000, code),
                                   (0x2000, struct.pack('<I', 0x3001)),
                                   (0x3000, words(0x4770))))
        result = FirmwareFacts(b'', view=source).function(CodeAddress(0x1000, 'thumb'))

        self.assertTrue(result.complete)
        self.assertEqual(result.calls[0][1], CodeAddress(0x3000, 'thumb'))

    def test_opaque_call_does_not_invalidate_read_only_rom_constants(self):
        code = words(0x4C03, 0x4790, 0x6821, 0x4788, 0x4770,
                     0x46C0, 0x46C0, 0x46C0) + struct.pack('<I', 0x2000)
        source = ImageView.sparse(((0x1000, code),
                                   (0x2000, struct.pack('<I', 0x3001)),
                                   (0x3000, words(0x4770))))
        result = FirmwareFacts(b'', view=source).function(CodeAddress(0x1000, 'thumb'))

        self.assertIn(CodeAddress(0x1002, 'thumb'), result.unresolved)
        self.assertEqual(len(result.calls), 1)
        self.assertEqual(result.calls[0][0], CodeAddress(0x1006, 'thumb'))
        self.assertEqual(result.calls[0][1], CodeAddress(0x3000, 'thumb'))

    def test_opaque_call_invalidates_initial_memory_descriptor(self):
        # Preserve descriptor address in r4 across unknown BLX r2, then read it.
        code = words(0x4C03, 0x4790, 0x6821, 0x4788, 0x4770,
                     0x46C0, 0x46C0, 0x46C0) + struct.pack('<I', 0x4000)
        source = ImageView.sparse(((0x1000, code),
                                   (0x2000, struct.pack('<I', 0x3001)),
                                   (0x3000, words(0x4770))))
        postcopy = source.materialize((
            LoadOperation('copy', 0x2000, 0x4000, 4, (0x800,)),
        ))
        facts = FirmwareFacts(code, base=0x1000, view=postcopy)
        result = facts.function(
            CodeAddress(0x1000, 'thumb', 'post-copy'), initial_memory=True)

        self.assertEqual(result.literals[0].value, 0x4000)
        self.assertEqual(result.calls, ())
        self.assertIn(CodeAddress(0x1002, 'thumb', 'post-copy'), result.unresolved)
        self.assertIn(CodeAddress(0x1006, 'thumb', 'post-copy'), result.unresolved)
        refs = facts.reset_references(CodeAddress(0x1000, 'thumb', 'post-copy'))
        self.assertFalse(any(ref.value == 0x3001 for ref in refs.references))

    def test_store_invalidates_initial_memory_descriptor(self):
        # Known, unknown, stack and multiple-register stores can alias RAM.
        for store in (0x6020, 0x6010, 0xB401, 0xC201):
            with self.subTest(store=store):
                code = words(0x4C03, store, 0x6821, 0x4788, 0x4770,
                             0x46C0, 0x46C0, 0x46C0) + struct.pack('<I', 0x4000)
                source = ImageView.sparse(((0x1000, code),
                                           (0x2000, struct.pack('<I', 0x3001)),
                                           (0x3000, words(0x4770))))
                postcopy = source.materialize((
                    LoadOperation('copy', 0x2000, 0x4000, 4, (0x800,)),
                ))
                result = FirmwareFacts(b'', view=postcopy).function(
                    CodeAddress(0x1000, 'thumb', 'post-copy'), initial_memory=True)

                self.assertNotIn(CodeAddress(0x1006, 'thumb'),
                                 {call[0] for call in result.calls})
                self.assertIn(CodeAddress(0x1006, 'thumb', 'post-copy'), result.unresolved)
                self.assertTrue(any(access.instruction.address == 0x1004
                                    and access.operation == 'read'
                                    for access in result.accesses))

    def test_indirect_targets_follow_relocated_register_allocation(self):
        # The literal pool is part of copied code; r6 carries a callback pointer.
        code = words(0x4E03, 0x47B0, 0x4770, 0x46C0, 0x46C0, 0x46C0,
                     0x46C0, 0x46C0) + struct.pack('<I', 0x3001)
        source = ImageView.sparse(((0x1000, code), (0x3000, words(0x4770))))
        postcopy = source.materialize((
            LoadOperation('copy', 0x1000, 0x5000, len(code), (0x900,)),
        ))
        result = FirmwareFacts(b'', view=postcopy).function(
            CodeAddress(0x5000, 'thumb', 'post-copy'))

        self.assertTrue(result.complete)
        self.assertEqual(result.calls[0][1], CodeAddress(0x3000, 'thumb', 'post-copy'))

    def test_join_removes_stale_indirect_call_proof(self):
        # One path retains the descriptor pointer; the other overwrites r0.
        image = words(0x4803, 0x2900, 0xD002, 0x2000, 0xE000,
                      0x46C0, 0x4780, 0x4770) + struct.pack('<I', 0x3001)
        result = FirmwareFacts(image).function(CodeAddress(0))

        self.assertEqual(result.calls, ())
        self.assertIn(CodeAddress(12, 'thumb'), result.unresolved)
        self.assertEqual(result.peripheral_map(), ())

    def test_reset_references_preserve_interworking_and_dereference_sites(self):
        image = words(0x4C03, 0x6821, 0x4788, 0x4770, 0x46C0, 0x46C0,
                      0x46C0, 0x46C0) + struct.pack('<I', 0x2000)
        view = ImageView.sparse(((0x1000, image),
                                 (0x2000, struct.pack('<I', 0x3001)),
                                 (0x3000, words(0x4770))))
        facts = FirmwareFacts(image, base=0x1000, view=view).reset_references(
            CodeAddress(0x1000, 'thumb'))

        self.assertIn(CodeAddress(0x3000, 'thumb'), facts.calls)
        self.assertTrue(any(ref.kind == 'literal' and ref.value == 0x2000
                            and ref.literal == 0x1010 for ref in facts.references))
        self.assertTrue(any(ref.kind == 'dereference' and ref.value == 0x2000
                            and ref.dereference == 0x2000 for ref in facts.references))
        self.assertTrue(any(ref.kind == 'literal' and ref.value == 0x3001
                            and ref.literal == 0x2000 for ref in facts.references))

    def test_reset_reference_drops_clobbered_dereference(self):
        image = words(0x4C02, 0x462C, 0x6821, 0x4770, 0x46C0, 0x46C0,
                      0x46C0) + struct.pack('<I', 0x2000)
        view = ImageView.sparse(((0x1000, image),
                                 (0x2000, struct.pack('<I', 0x3001))))
        facts = FirmwareFacts(image, base=0x1000, view=view).reset_references(
            CodeAddress(0x1000, 'thumb'))

        self.assertFalse(any(ref.kind == 'dereference'
                             and ref.instruction.address == 0x1004
                             for ref in facts.references))







if __name__ == '__main__':
    unittest.main()
