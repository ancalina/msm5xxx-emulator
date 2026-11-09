"""Synthetic instruction images for local def-use and loop-entry queries."""
import struct
import unittest

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts


def thumb(*instructions):
    return FirmwareFacts(struct.pack('<' + 'H' * len(instructions), *instructions))


class ReachingDefinitionTests(unittest.TestCase):
    def test_register_origins_follow_renamed_zero_offset_copies(self):
        # LDR r1,[r5]; ADDS r0,r1,#0; MOV r4,r0; STR r4,[r6].
        facts = thumb(0x6829, 0x1C08, 0x4604, 0x6034, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertEqual(facts.register_origins(function, CodeAddress(6), a.ARM_REG_R4),
                         ((CodeAddress(0), a.ARM_REG_R1),))

    def test_register_origins_keep_nonzero_operations_as_definitions(self):
        facts = thumb(0x6829, 0x1C48, 0x4604, 0x6034, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertEqual(facts.register_origins(function, CodeAddress(6), a.ARM_REG_R4),
                         ((CodeAddress(2), a.ARM_REG_R0),))

    def test_register_origins_keep_distinct_branch_sources(self):
        # CMP r0,#0; BEQ second; MOV r4,r1; B store; MOV r4,r2.
        facts = thumb(0x6829, 0x6832, 0x2800, 0xD001, 0x460C,
                      0xE000, 0x4614, 0x603C, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertEqual(facts.register_origins(function, CodeAddress(14), a.ARM_REG_R4),
                         ((CodeAddress(0), a.ARM_REG_R1),
                          (CodeAddress(2), a.ARM_REG_R2)))

    def test_cyclic_copy_lineage_is_unknown_until_first_pass_is_selected(self):
        facts = thumb(0x2400, 0x4624, 0x2800, 0xD1FC, 0x602C, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertIsNone(facts.register_origins(function, CodeAddress(8), a.ARM_REG_R4))
        self.assertEqual(facts.register_origins(
            function, CodeAddress(8), a.ARM_REG_R4,
            cut_edges=((CodeAddress(6), CodeAddress(2)),)),
            ((CodeAddress(0), a.ARM_REG_R4),))

    def test_register_copy_cannot_recover_a_call_clobbered_input(self):
        facts = thumb(0x6829, 0xF000, 0xF804, 0x460C, 0x602C,
                      0x4770, 0x46C0, 0x46C0, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertIsNone(facts.register_origins(function, CodeAddress(8), a.ARM_REG_R4))

    def test_two_branch_definitions_remain_explicit_alternatives(self):
        facts = thumb(0x2800, 0xD001, 0x2101, 0xE000, 0x2102, 0x6021, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertEqual(facts.reaching_definitions(function, CodeAddress(10), a.ARM_REG_R1),
                         (CodeAddress(4), CodeAddress(8)))
        self.assertIsNone(facts.reaching_definitions(function, CodeAddress(10), a.ARM_REG_R4))

    def test_store_uses_the_last_write_instead_of_a_nearby_mask(self):
        # MOV r2,#0x40; ORR r1,r2; MOV r1,#0; STRH r1,[r4]; BX lr.
        facts = thumb(0x2240, 0x4311, 0x2100, 0x8021, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertEqual(facts.reaching_definitions(function, CodeAddress(6), a.ARM_REG_R1),
                         (CodeAddress(4),))
        self.assertEqual(facts.reaching_definitions(function, CodeAddress(2), a.ARM_REG_R2),
                         (CodeAddress(0),))

    def test_path_bypassing_the_value_producer_is_unknown(self):
        facts = thumb(0x2800, 0xD001, 0x2140, 0xE7FF, 0x8021, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertIsNone(facts.reaching_definitions(function, CodeAddress(8), a.ARM_REG_R1))

    def test_opaque_calls_clobber_arguments_and_flags_but_preserve_saved_registers(self):
        facts = thumb(0x2140, 0x2407, 0xF000, 0xF804, 0x8021, 0x4770,
                      0x46C0, 0x46C0, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertIsNone(facts.reaching_definitions(function, CodeAddress(8), a.ARM_REG_R1))
        self.assertIsNone(facts.reaching_definitions(function, CodeAddress(8), a.ARM_REG_CPSR))
        self.assertEqual(facts.reaching_definitions(function, CodeAddress(8), a.ARM_REG_R4),
                         (CodeAddress(2),))

    def test_cut_loop_latch_separates_initial_counter_from_recurrence(self):
        facts = thumb(0x2400, 0x3401, 0x2C08, 0xDBFC, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertEqual(facts.reaching_definitions(function, CodeAddress(2), a.ARM_REG_R4),
                         (CodeAddress(0), CodeAddress(2)))
        self.assertEqual(facts.reaching_definitions(
            function, CodeAddress(2), a.ARM_REG_R4,
            cut_edges=((CodeAddress(6), CodeAddress(2)),)), (CodeAddress(0),))

    def test_cut_graph_ignores_predecessors_disconnected_from_its_entry(self):
        facts = thumb(0x2800, 0xD001, 0x2401, 0xE000, 0x46C0, 0x602C, 0x4770)
        function = facts.function(CodeAddress(0))
        self.assertIsNone(facts.reaching_definitions(function, CodeAddress(10), a.ARM_REG_R4))
        self.assertEqual(facts.reaching_definitions(
            function, CodeAddress(10), a.ARM_REG_R4,
            cut_edges=((CodeAddress(2), CodeAddress(8)),)), (CodeAddress(4),))

    def test_conditional_writes_and_foreign_contexts_do_not_prove_a_value(self):
        image = struct.pack('<5I', 0xE3A01040, 0xE3500000, 0x13A01000,
                            0xE1C410B0, 0xE12FFF1E)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'arm'))
        self.assertIsNone(facts.reaching_definitions(function, CodeAddress(12, 'arm'),
                                                    a.ARM_REG_R1))
        foreign = FirmwareFacts(image)
        self.assertIsNone(foreign.reaching_definitions(
            function, CodeAddress(12, 'arm'), a.ARM_REG_R1))
        self.assertIsNone(foreign.register_origins(
            function, CodeAddress(12, 'arm'), a.ARM_REG_R1))
        self.assertEqual(foreign.bit_tests(function), ())

    def test_mode_switch_does_not_preserve_a_banked_stack_definition(self):
        for fields in (1, 9, 15):
            with self.subTest(fields=fields):
                image = struct.pack('<5I', 0xE3A0DA01, 0xE3A00012,
                                    0xE120F000 | fields << 16,
                                    0xE581D000, 0xE12FFF1E)
                facts = FirmwareFacts(image)
                function = facts.function(CodeAddress(0, 'arm'))
                self.assertIsNone(facts.reaching_definitions(
                    function, CodeAddress(12, 'arm'), a.ARM_REG_SP))
                self.assertEqual(facts.reaching_definitions(
                    function, CodeAddress(12, 'arm'), a.ARM_REG_R0),
                    (CodeAddress(4, 'arm'),))

    def test_flags_only_msr_preserves_a_stack_definition(self):
        image = struct.pack('<5I', 0xE3A0DA01, 0xE3A00012, 0xE128F000,
                            0xE581D000, 0xE12FFF1E)
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0, 'arm'))
        self.assertEqual(facts.reaching_definitions(
            function, CodeAddress(12, 'arm'), a.ARM_REG_SP),
            (CodeAddress(0, 'arm'),))
