"""Opt-in symbolic expressions over the shared bounded CFG."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import (
    CodeAddress, FirmwareFacts, SymbolicValue, UNKNOWN_VALUE,
)
from msm5xxx_emulator.detection.image_view import ImageView


def words(*values):
    return struct.pack('<' + 'H' * len(values), *values)


def arm_words(*values):
    return struct.pack('<' + 'I' * len(values), *values)


class SymbolicFactsTests(unittest.TestCase):
    def test_initial_loop_pass_is_explicitly_partial_and_keeps_cfg_edges(self):
        image = words(0x6008, 0x3104, 0xD1FC, 0x4770)
        result = FirmwareFacts(image).function(
            CodeAddress(0), symbolic_registers={
                a.ARM_REG_R0: SymbolicValue.arg(0),
                a.ARM_REG_R1: SymbolicValue.arg(1)}, follow_back_edges=False)
        self.assertFalse(result.complete)
        self.assertFalse(result.truncated)
        self.assertEqual(result.loop_frontiers, ((CodeAddress(4), CodeAddress(0)),))
        self.assertIn((CodeAddress(4), CodeAddress(0)), result.control_edges)
        self.assertEqual(result.symbolic_accesses[0].value, SymbolicValue.arg(0))

    def test_call_context_expressions_and_empty_symbolic_query_are_supported(self):
        image = words(0x6848, 0x4770)
        facts = FirmwareFacts(image)
        ordinary = facts.function(CodeAddress(0), initial_registers={a.ARM_REG_R1: 0x14001000})
        symbolic = facts.function(CodeAddress(0), initial_registers={a.ARM_REG_R1: 0x14001000},
                                  symbolic_registers={})
        self.assertEqual(ordinary.symbolic_accesses, ())
        self.assertEqual(symbolic.symbolic_accesses[0].value.kind, 'load')
        argument = SymbolicValue('op', 'add', (SymbolicValue.arg(0), SymbolicValue.const(8)))
        child = facts.function(CodeAddress(0), initial_registers={a.ARM_REG_R1: argument})
        self.assertEqual(child.symbolic_accesses[0].value.kind, 'load')
        self.assertIn(argument, child.symbolic_accesses[0].address.operands)

    def symbolic(self, image, entry=0, regs=None):
        return FirmwareFacts(image).function(
            CodeAddress(entry), symbolic_registers=regs or {})

    def test_register_renaming_preserves_argument_offset_expression(self):
        first = self.symbolic(words(0x6048, 0x4770), regs={
            a.ARM_REG_R1: SymbolicValue.arg(0),
            a.ARM_REG_R0: SymbolicValue.arg(1),
        })
        second = self.symbolic(words(0x605A, 0x4770), regs={
            a.ARM_REG_R3: SymbolicValue.arg(0),
            a.ARM_REG_R2: SymbolicValue.arg(1),
        })
        self.assertEqual(first.symbolic_accesses[0].address,
                         second.symbolic_accesses[0].address)
        self.assertEqual(first.symbolic_accesses[0].value,
                         SymbolicValue.arg(1))
        self.assertEqual(first.symbolic_accesses[0].address.kind, 'op')
        self.assertEqual(first.symbolic_accesses[0].address.value, 'add')
        legacy = FirmwareFacts(words(0x6048, 0x4770)).function(
            CodeAddress(0), initial_registers={a.ARM_REG_R1: 0x3000700,
                                                a.ARM_REG_R0: 0x1234})
        self.assertEqual(legacy.accesses[0].address, 0x3000704)
        self.assertEqual(legacy.symbolic_accesses, ())

    def test_symbolic_pointer_chain_is_bounded_and_site_sensitive(self):
        # LDR r3,[r4]; LDR r1,[r3,#4]; STR r0,[r1,#4]; BX lr.
        result = self.symbolic(words(0x6823, 0x6859, 0x6048, 0x4770), regs={
            a.ARM_REG_R4: SymbolicValue.arg(0),
            a.ARM_REG_R0: SymbolicValue.arg(1),
        })
        accesses = result.symbolic_accesses
        self.assertEqual([access.operation for access in accesses],
                         ['read', 'read', 'write'])
        first_load = accesses[0].value
        second_load = accesses[1].value
        self.assertEqual(first_load.kind, 'load')
        self.assertEqual(first_load.width, 4)
        self.assertEqual(first_load.site.address, 0)
        self.assertEqual(second_load.kind, 'load')
        self.assertEqual(second_load.site.address, 2)
        self.assertNotEqual(first_load, second_load)
        self.assertEqual(accesses[2].value, SymbolicValue.arg(1))

    def test_known_global_address_can_supply_a_symbolic_pointer(self):
        # A supplied literal names mutable RAM; its unknown contents form a load.
        code = words(0x4C01, 0x6821, 0x6008, 0x4770) + struct.pack('<I', 0x14001000)
        result = self.symbolic(code, regs={a.ARM_REG_R0: SymbolicValue.arg(0)})
        load = next(item for item in result.symbolic_accesses
                    if item.instruction.address == 2)
        self.assertEqual(load.address, SymbolicValue.const(0x14001000))
        self.assertEqual(load.value.kind, 'load')
        store = next(item for item in result.symbolic_accesses if item.operation == 'write')
        self.assertEqual(store.value, SymbolicValue.arg(0))
        self.assertTrue(all(isinstance(item.address, SymbolicValue)
                            for item in result.symbolic_accesses))

    def test_scalar_load_widths_and_signed_load(self):
        # LDRB r0,[r1,#1]; LDRH r2,[r1,#2]; LDRSB r3,[r1,r4]; BX lr.
        image = words(0x7848, 0x888A, 0x5688, 0x4770)
        result = self.symbolic(image, regs={
            a.ARM_REG_R1: SymbolicValue.arg(0),
            a.ARM_REG_R4: SymbolicValue.arg(1),
        })
        self.assertEqual([(item.width, item.value.kind,
                           item.value.signed) for item in result.symbolic_accesses],
                         [(1, 'load', False), (2, 'load', False),
                          (1, 'load', True)])
        self.assertEqual(result.symbolic_accesses[2].value.width, 1)
        self.assertTrue(result.symbolic_accesses[2].value.signed)

    def test_calls_invalidate_mutable_load_identity_and_registers(self):
        # BL to a local opaque function, then STR through caller-saved r1.
        image = words(0xF000, 0xF803, 0x6048, 0x4770, 0x4770)
        result = self.symbolic(image, regs={
            a.ARM_REG_R1: SymbolicValue.arg(0),
            a.ARM_REG_R0: SymbolicValue.arg(1),
        })
        store = next(item for item in result.symbolic_accesses
                     if item.operation == 'write')
        self.assertIs(store.address, UNKNOWN_VALUE)
        self.assertTrue(result.complete)

    def test_loop_join_widens_without_unbounded_expression_growth(self):
        # ADDS r0,#1; BNE back; STR r0,[r1]; BX lr.
        result = self.symbolic(words(0x1C40, 0xD1FD, 0x6008, 0x4770), regs={
            a.ARM_REG_R0: SymbolicValue.arg(0),
            a.ARM_REG_R1: SymbolicValue.arg(1),
        })
        self.assertLessEqual(len(result.instructions), 4)
        self.assertEqual(len(result.symbolic_accesses), 1)
        self.assertIs(result.symbolic_accesses[0].value, UNKNOWN_VALUE)

    def test_shifted_arithmetic_is_unknown(self):
        # ADD r0,r1,r2,LSL #2; STR r0,[r3]; BX lr.
        image = struct.pack('<3I', 0xE0810102, 0xE5830000, 0xE12FFF1E)
        result = FirmwareFacts(image).function(
            CodeAddress(0, 'arm'), symbolic_registers={
                a.ARM_REG_R1: SymbolicValue.arg(0),
                a.ARM_REG_R2: SymbolicValue.arg(1),
                a.ARM_REG_R3: SymbolicValue.arg(2),
            })
        self.assertIs(result.symbolic_accesses[0].value, UNKNOWN_VALUE)

    def test_shifted_or_subtracted_index_is_not_an_unshifted_sum(self):
        for opcode in (0xE7910102, 0xE7110002):
            with self.subTest(opcode=opcode):
                image = struct.pack('<2I', opcode, 0xE12FFF1E)
                result = FirmwareFacts(image).function(
                    CodeAddress(0, 'arm'), symbolic_registers={
                        a.ARM_REG_R1: SymbolicValue.arg(0),
                        a.ARM_REG_R2: SymbolicValue.arg(1),
                    })
                self.assertIs(result.symbolic_accesses[0].address, UNKNOWN_VALUE)

    def test_register_shift_uses_only_low_eight_amount_bits(self):
        # LSLS r0,r1 with r1=0x100 shifts by zero, then stores seven.
        image = words(0x4088, 0x6010, 0x4770)
        result = FirmwareFacts(image).function(
            CodeAddress(0), initial_registers={
                a.ARM_REG_R0: 7, a.ARM_REG_R1: 0x100, a.ARM_REG_R2: 0x3000700})
        self.assertEqual(result.accesses[0].value, 7)

    def test_overlapping_lexical_candidates_are_retained(self):
        facts = FirmwareFacts(b'\x00\x11\xf0\xf0\xf8\xf8')
        self.assertIn(2, tuple(call[0] for call in facts.call_candidates()))
        self.assertEqual(FirmwareFacts(b'aaaaa').string_candidates(b'aaa'),
                         (0, 1, 2))
        self.assertEqual(FirmwareFacts(b'\x01' * 5).pointer_candidates(0x01010101),
                         (0, 1))

    def test_reachability_records_instruction_literal_and_data_source_spans(self):
        code = words(0x4901, 0x6808, 0x4770, 0x46C0) + struct.pack('<I', 0x3000)
        view = ImageView.sparse(((0, code), (0x3000, words(0x4770, 0))))
        result = FirmwareFacts(code, view=view).reset_references(CodeAddress(0))
        sources = {(site.address, size, kind)
                   for site, size, kind in result.source_sites}
        self.assertIn((0, 2, 'instruction'), sources)
        self.assertIn((8, 4, 'literal'), sources)
        self.assertIn((0x3000, 4, 'dereference'), sources)

    def test_call_sites_capture_preclobber_constants_and_symbolic_values(self):
        constants = FirmwareFacts(arm_words(
            0xE3A00007, 0xE3A01009, 0xEB000002, 0xE12FFF1E,
            0xE1A00000, 0xE1A00000, 0xE12FFF1E)).function(CodeAddress(0, 'arm'))
        call = constants.call_sites[0]
        registers = dict(call.registers)
        self.assertEqual(registers[a.ARM_REG_R0], 7)
        self.assertEqual(registers[a.ARM_REG_R1], 9)
        self.assertEqual(call.target.address, 0x18)

        symbolic = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE1A00002, 0xEB000001, 0xE12FFF1E,
            0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R4: SymbolicValue.arg(0)})
        argument = dict(symbolic.call_sites[0].registers)[a.ARM_REG_R0]
        self.assertEqual(argument.kind, 'load')
        self.assertEqual(argument.site.address, 0)

    def test_symbolic_branch_condition_links_status_load_and_rejects_counter_loop(self):
        status = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE3120001, 0x1AFFFFFC, 0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R4: SymbolicValue.arg(0)})
        branch = status.branch_conditions[0]
        self.assertEqual(branch.site.address, 8)
        self.assertIsNotNone(branch.origin)
        self.assertEqual(branch.origin.value, 'flags:tst')
        self.assertTrue(any(item.kind == 'load' and item.site.address == 0
                            for item in branch.origin.operands))

        no_test_bits = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE3120000, 0x1AFFFFFC, 0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R4: SymbolicValue.arg(0)})
        self.assertIsNone(no_test_bits.branch_conditions[0].origin)

        stale_overflow = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE3120001, 0x6AFFFFFC, 0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R4: SymbolicValue.arg(0)})
        self.assertIsNone(stale_overflow.branch_conditions[0].origin)

        counter = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE3A03002, 0xE2533001, 0x1AFFFFFC,
            0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R4: SymbolicValue.arg(0)})
        counter_branch = next(item for item in counter.branch_conditions
                              if item.site.address == 12)
        self.assertIsNone(counter_branch.origin)

    def test_joined_flag_producers_must_agree(self):
        function = FirmwareFacts(arm_words(
            0xE3500000, 0x0A000002,       # CMP r0,#0; BEQ path B
            0xE1D420B0, 0xE3120001,       # LDRH/TST via r4
            0xEA000001,                   # B join
            0xE1D520B0, 0xE3120001,       # LDRH/TST via r5
            0x1A000000, 0xE12FFF1E, 0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                                    a.ARM_REG_R4: SymbolicValue.arg(1),
                                    a.ARM_REG_R5: SymbolicValue.arg(2)})
        branch = next(item for item in function.branch_conditions
                      if item.site.address == 28)
        self.assertIsNone(branch.origin)

    def test_opaque_call_invalidates_symbolic_flag_origin(self):
        function = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE3520000, 0xEB000002, 0x1AFFFFFB,
            0xE12FFF1E, 0xE1A00000, 0xE1A00000, 0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R4: SymbolicValue.arg(0)})
        branch = next(item for item in function.branch_conditions
                      if item.site.address == 12)
        self.assertIsNone(branch.origin)

    def test_unmodelled_flag_write_invalidates_symbolic_origin_without_cpsr_write(self):
        # LDRH; set a mask; TST links the load; MOVS r2,r3 overwrites flags
        # before BNE. The second flag writer must invalidate the TST lineage
        # even on disassemblers whose regs_access omits the CPSR register.
        function = FirmwareFacts(words(
            0x8820, 0x2101, 0x4208, 0x001A, 0xD100, 0x4770, 0x4770)).function(
                CodeAddress(0), symbolic_registers={
                    a.ARM_REG_R4: SymbolicValue.arg(0),
                    a.ARM_REG_R3: SymbolicValue.arg(1),
                })
        branch = next(item for item in function.branch_conditions
                      if item.site == CodeAddress(8))
        self.assertIsNone(branch.origin)

    def test_predicated_flag_write_does_not_dominate_branch_origin(self):
        function = FirmwareFacts(arm_words(
            0xE1D420B0, 0xE3500000, 0x03120001, 0x1A000000,
            0xE12FFF1E)).function(
                CodeAddress(0, 'arm'),
                symbolic_registers={a.ARM_REG_R4: SymbolicValue.arg(0),
                                    a.ARM_REG_R0: SymbolicValue.arg(1)})
        branch = next(item for item in function.branch_conditions
                      if item.site.address == 12)
        self.assertIsNone(branch.origin)


if __name__ == '__main__':
    unittest.main()
