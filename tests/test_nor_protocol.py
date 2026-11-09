"""Synthetic semantic evidence for AMD x16 command callbacks."""
import struct
import unittest
from dataclasses import replace

from capstone import arm as a

from msm5xxx_emulator.detection.facts import (
    CodeAddress, FirmwareFacts, FunctionFacts, ScatterCandidate,
    SymbolicValue,
)
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.detection.startup_entry import startup_load_operations
from msm5xxx_emulator.detection.startup_facts import (
    CopyLoopTransfer, OrderedCopyTransfer, StartupCopyRow, VectorCopyRow,
    _compose_ordered_transfers, _definition_reaches, _state_initializer,
    _stride_exit, prove_ordered_copy_transfer,
    prove_reset_prefix_completion, prove_startup_copy_consumer,
    prove_copy_consumer, proven_startup_rows,
)
from msm5xxx_emulator.detection.nor_protocol import (
    CopyConsumerProof, known_amd_x16_profile,
    prove_amd_x16_hardware_contract, summarize_amd_x16,
)


from nor_fixtures import (
    _ARGUMENTS,
    arm_function,
    command_function,
    callback_fixture,
    copy_consumer_fixture,
    ordered_copy_fixture,
    reset_handoff_fixture,
)


class NORProtocolTests(unittest.TestCase):
    def test_shared_startup_row_query_proves_supplied_copy_and_zero_rows(self):
        image, source_row = copy_consumer_fixture()
        row = StartupCopyRow(source_row.table, source_row.source,
                             source_row.target, source_row.size,
                             source_row.table + 12, source_row.zero_target,
                             source_row.zero_size)
        facts = FirmwareFacts(image)
        found = proven_startup_rows(
            facts, CodeAddress(0x100, 'thumb'),
            target_ranges=((0x1000, 0x2000),))
        self.assertEqual(len(found), 1)
        self.assertIs(found, proven_startup_rows(
            facts, CodeAddress(0x100, 'thumb'),
            target_ranges=((0x1000, 0x2000),)))
        actual, consumer = found[0]
        self.assertEqual(actual, row)
        self.assertEqual(consumer.entry, CodeAddress(0x100, 'thumb'))
        copy_only = proven_startup_rows(
            facts, CodeAddress(0x100, 'thumb'),
            target_ranges=((0x1000, 0x2000),),
            zero_ranges=((0x1100, 0x2000),))
        # The zero loop still executes even when its target is excluded from
        # discovery, so its write cannot be omitted from a closed procedure.
        self.assertEqual(copy_only, ())

        incomplete = ImageView.sparse((
            (0, image[:0x240]), (0x244, image[0x244:]),
        ))
        self.assertEqual(proven_startup_rows(
            FirmwareFacts(image, view=incomplete), CodeAddress(0x100, 'thumb'),
            target_ranges=((0x1000, 0x2000),)), ())

    def test_symbolic_command_offsets_and_width(self):
        facts = command_function(0x100, ((0xAA0, 0xAA), (0x540, 0x55)))
        summary = summarize_amd_x16(facts)
        self.assertTrue(summary.complete)
        self.assertEqual([(item.offset, item.value, item.width)
                          for item in summary.writes],
                         [(0xAA0, 0xAA, 2), (0x540, 0x55, 2)])

    def test_required_command_classification(self):
        _, callbacks = callback_fixture()
        erase = summarize_amd_x16(callbacks['erase'])
        bypass = summarize_amd_x16(callbacks['bypass-enter'])
        self.assertIn('bypass-enter', bypass.operations)
        self.assertIn('sector-erase', erase.operations)

    def test_profile_requires_evidenced_id_and_geometry(self):
        sectors = (0x10000,) * 14
        profile = known_amd_x16_profile(0x005F0004, sectors)
        self.assertEqual((profile.window_base, profile.capacity,
                          profile.manufacturer_id, profile.device_id),
                         (0x400000, 0x200000, 4, 95))
        self.assertIsNone(known_amd_x16_profile(0x005F0005, sectors))
        self.assertIsNone(known_amd_x16_profile(0x005F0004, sectors[:-1]))
        self.assertIsNone(known_amd_x16_profile(0x005F0004,
                                                (0x10000,) * 13 + (0x20000,)))

    def test_copy_table_consumer_requires_bounded_copy_and_zero_loops(self):
        image, row = copy_consumer_fixture()
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        proofs = prove_copy_consumer(facts, row, references)
        self.assertEqual(len(proofs), 1)
        self.assertIs(proofs, prove_copy_consumer(facts, row, references))
        self.assertEqual(proofs[0].entry.address, 0x100)
        self.assertIsNotNone(proofs[0].copy_back_edge)
        self.assertIsNotNone(proofs[0].zero_back_edge)

    def test_copy_consumer_retains_only_declared_typed_device_writes(self):
        image, row = copy_consumer_fixture(side_effect_store=True)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        self.assertEqual(prove_copy_consumer(facts, row, references), ())
        proofs = prove_copy_consumer(
            facts, row, references,
            extra_write_ranges=((0x03000600, 0x03000780),))
        self.assertEqual(len(proofs), 1)
        self.assertEqual(len(proofs[0].side_effect_writes), 1)
        write = proofs[0].side_effect_writes[0]
        self.assertEqual((write.address, write.width, write.value),
                         (0x03000620, 4, 1))

    def test_startup_procedure_closes_writes_after_transfer_loops(self):
        image, _ = copy_consumer_fixture(outside_store_address=0x03000624)
        facts = FirmwareFacts(image)
        entry = CodeAddress(0x100, 'thumb')
        self.assertEqual(proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),)), ())
        found = proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            extra_write_ranges=((0x03000600, 0x03000780),))
        self.assertEqual(len(found), 1)
        procedure = found[0][1].procedure
        self.assertIsNotNone(procedure)
        self.assertEqual([(item.address, item.value)
                          for item in procedure.side_effect_writes],
                         [(0x03000624, 1)])

    def test_startup_procedure_accepts_stack_word_killed_by_zero_span(self):
        image, _ = copy_consumer_fixture(stack_temporary=True)
        facts = FirmwareFacts(image)
        entry = CodeAddress(0x100, 'thumb')
        found = proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x1044)
        self.assertEqual(len(found), 1)
        stack_writes = found[0][1].procedure.stack_writes
        self.assertEqual(len(stack_writes), 1)
        self.assertEqual((stack_writes[0].address, stack_writes[0].width),
                         (0x1040, 4))
        outside = proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x1104)
        self.assertEqual(len(outside), 1)
        self.assertEqual([(item.address, item.width, item.value)
                          for item in outside[0][1].procedure.unknown_stack_writes],
                         [(0x1100, 4, None)])

    def test_startup_procedure_marks_unoverwritten_stack_bytes_unknown(self):
        image, _ = copy_consumer_fixture(stack_temporary=True)
        capture = ImageView.sparse(((0, image), (0x8000, b'abcd')))
        facts = FirmwareFacts(image, view=capture)
        entry = CodeAddress(0x100, 'thumb')
        found = proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x8004)
        self.assertEqual(len(found), 1)
        unknown = found[0][1].procedure.unknown_stack_writes
        self.assertEqual([(item.address, item.width, item.value)
                          for item in unknown], [(0x8000, 4, None)])
        loaded = facts.after_loads(startup_load_operations(found))
        self.assertIsNone(loaded.view.read(0x8000, 4, phase='post-copy'))
        self.assertEqual(loaded.view.read(0x8000, 4, phase='reset'), b'abcd')
        row = found[0][0]
        self.assertEqual(loaded.view.read(row.target, 4, phase='post-copy'),
                         image[row.source:row.source + 4])
        self.assertEqual(proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            initial_sp=0x224), ())

    def test_startup_procedure_rejects_bypassed_rows_and_opaque_calls(self):
        entry = CodeAddress(0x100, 'thumb')
        for options in ({'bypass_row': True}, {'outside_call': True}):
            with self.subTest(options=options):
                image, _ = copy_consumer_fixture(**options)
                facts = FirmwareFacts(image)
                self.assertEqual(proven_startup_rows(
                    facts, entry, target_ranges=((0x1000, 0x2000),)), ())

    def test_copy_completion_observes_memory_before_an_opaque_call(self):
        entry = CodeAddress(0x100, 'thumb')
        image, row = copy_consumer_fixture(saved_lr_call=True)
        call, target = FirmwareFacts(image).function(entry).calls[0]
        changed = bytearray(image)
        # A real, unclosed write in the later helper cannot be treated as a
        # no-effect call. The pre-call snapshot makes no claim about it.
        struct.pack_into('<2H', changed, target.address, 0x6008, 0x4770)
        facts = FirmwareFacts(bytes(changed))
        options = dict(target_ranges=((0x1000, 0x2000),), initial_sp=0x8008)
        self.assertEqual(proven_startup_rows(facts, entry, **options), ())
        found = proven_startup_rows(facts, entry, completion=call, **options)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][1].procedure.completion, call)
        with self.assertRaisesRegex(ValueError, 'epoch'):
            startup_load_operations(found)
        operations = startup_load_operations(found, completion=call)
        snapshot = facts.after_loads(operations, phase='copy-complete')
        self.assertEqual(snapshot.view.read(row.target, row.size,
                                           phase='copy-complete'),
                         image[row.source:row.source + row.size])
        self.assertEqual(snapshot.view.read(row.zero_target, row.zero_size,
                                           phase='copy-complete'),
                         bytes(row.zero_size))
        self.assertIsNone(snapshot.view.read(0x8000, 8, phase='copy-complete'))

    def test_copy_completion_rejects_a_call_before_the_zero_loop(self):
        entry = CodeAddress(0x100, 'thumb')
        image, row = copy_consumer_fixture()
        facts = FirmwareFacts(image)
        zero_start = next(literal.instruction for literal in
                          facts.function(entry).literals
                          if literal.value == row.table + 12)
        changed = bytearray(image)
        struct.pack_into('<2H', changed, zero_start.address, 0xF000, 0xF800)
        self.assertEqual(proven_startup_rows(
            FirmwareFacts(bytes(changed)), entry,
            target_ranges=((0x1000, 0x2000),), completion=zero_start), ())
        bypassed, _ = copy_consumer_fixture(bypass_row=True, saved_lr_call=True)
        facts = FirmwareFacts(bypassed)
        call, _ = facts.function(entry).calls[0]
        self.assertEqual(proven_startup_rows(
            facts, entry, target_ranges=((0x1000, 0x2000),),
            completion=call, initial_sp=0x8008), ())

    def test_joining_a_loop_exit_does_not_prove_the_loop_executed(self):
        entry = CodeAddress(0x100, 'thumb')
        for bypass in ('bypass_copy_loop', 'bypass_zero_loop'):
            with self.subTest(bypass=bypass):
                image, _ = copy_consumer_fixture(saved_lr_call=True, **{bypass: True})
                facts = FirmwareFacts(image)
                call, _ = facts.function(entry).calls[0]
                self.assertEqual(proven_startup_rows(
                    facts, entry, target_ranges=((0x1000, 0x2000),),
                    initial_sp=0x8008, completion=call), ())

    def test_three_word_copy_row_with_separate_zero_row(self):
        image, row = copy_consumer_fixture(separate_zero=True)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 12),
             (row.zero_table, row.zero_table + 8)), limit=len(image))
        proofs = prove_startup_copy_consumer(facts, row, references)
        self.assertEqual(len(proofs), 1)
        self.assertIs(proofs, prove_startup_copy_consumer(facts, row, references))
        self.assertIsNotNone(proofs[0].copy_back_edge)
        self.assertIsNotNone(proofs[0].zero_back_edge)

    def test_three_word_copy_row_can_omit_zero_loop(self):
        image, source_row = copy_consumer_fixture(separate_zero=True)
        row = StartupCopyRow(source_row.table, source_row.source,
                             source_row.target, source_row.size)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 12),), limit=len(image))
        proofs = prove_startup_copy_consumer(facts, row, references)
        self.assertEqual(len(proofs), 1)
        self.assertIsNotNone(proofs[0].copy_back_edge)
        self.assertIsNone(proofs[0].zero_back_edge)

    def test_zero_loop_accepts_invariant_zero_copied_into_value_register(self):
        image, row = copy_consumer_fixture(invariant_zero_register=True)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        proofs = prove_copy_consumer(facts, row, references)
        self.assertEqual(len(proofs), 1)
        self.assertIsNotNone(proofs[0].zero_back_edge)

    def test_ordered_loop_transfer_composes_split_copy_and_clear_spans(self):
        image, row = ordered_copy_fixture()
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        proofs = prove_ordered_copy_transfer(
            facts, row, references, entry=CodeAddress(row.wrapper, 'thumb'))
        self.assertEqual(len(proofs), 1)
        proof = proofs[0]
        self.assertEqual(proof.copy_spans, (
            (0x600, 0x610, 0x1000, 0x1010),
            (0x610, 0x620, 0x1010, 0x1020),
        ))
        self.assertEqual(proof.clear_spans, (
            (0x1020, 0x1030),
            (0x1030, 0x1040),
        ))
        self.assertEqual(proof.cleared_target, (0x1020, 0x1040))
        self.assertEqual(_stride_exit(0x1000, 0x100E, 4), (4, 0x1010))
        self.assertEqual(prove_ordered_copy_transfer(
            facts, row, references, entry=CodeAddress(row.wrapper, 'thumb'),
            protected_ranges=((row.end, row.end + 4),)), ())
        self.assertIsNone(_compose_ordered_transfers(
            CodeAddress(row.wrapper, 'thumb'), row, proof.copy_loops,
            proof.clear_loops, ((row.end, row.end + 4),)))
        first = CopyLoopTransfer((0x20, 0x10), CodeAddress(0x10, 'thumb'),
                                 70, 71, 0x1000, 0x1010, 4, 4, 0x1010,
                                 0x600, 0x610)
        gap = CopyLoopTransfer((0x40, 0x30), CodeAddress(0x30, 'thumb'),
                               70, 71, 0x1014, 0x1020, 4, 3, 0x1020,
                               0x610, 0x61C)
        clear_first = CopyLoopTransfer((0x60, 0x50), CodeAddress(0x50, 'thumb'),
                                       70, None, 0x1020, 0x1030, 4, 4, 0x1030)
        clear_second = CopyLoopTransfer((0x80, 0x70), CodeAddress(0x70, 'thumb'),
                                        70, None, 0x1030, 0x1040, 4, 4, 0x1040)
        self.assertIsNone(_compose_ordered_transfers(
            CodeAddress(row.wrapper, 'thumb'), row, (first, gap),
            (clear_first, clear_second)))

    def test_ordered_transfer_closes_outside_loop_writes(self):
        image, row = ordered_copy_fixture(outside_store_address=0x03000624)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        entry = CodeAddress(row.wrapper, 'thumb')
        self.assertEqual(prove_ordered_copy_transfer(
            facts, row, references, entry=entry), ())
        proofs = prove_ordered_copy_transfer(
            facts, row, references, entry=entry,
            extra_write_ranges=((0x03000600, 0x03000780),))
        self.assertEqual(len(proofs), 1)
        self.assertEqual([(item.address, item.value)
                          for item in proofs[0].side_effect_writes],
                         [(0x03000624, 1)])

    def test_ordered_loop_transfer_rejects_noncontiguous_cursor_step(self):
        image, row = ordered_copy_fixture(wrong_stride=True)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        self.assertEqual(prove_ordered_copy_transfer(
            facts, row, references, entry=CodeAddress(row.wrapper, 'thumb')), ())

    def test_ordered_transfer_requires_table_origins_and_unambiguous_loop_flags(self):
        for options in (
                {'unused_row_fields': True},
                {'reverse_second': True},
                {'bypass_second_compare': True},
                {'clobber_bound': True},
                {'duplicate_update': True},
                {'conditional_duplicate_update': True},
                {'unmodelled_multiple_transfer': True},
                {'nested_cycle': True}):
            with self.subTest(options=options):
                image, row = ordered_copy_fixture(**options)
                facts = FirmwareFacts(image)
                references = facts.literal_access_candidates(
                    ((row.table, row.table + 20),), limit=len(image))
                self.assertEqual(prove_ordered_copy_transfer(
                    facts, row, references,
                    entry=CodeAddress(row.wrapper, 'thumb')), ())

        image, row = ordered_copy_fixture(source_gap=True)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        self.assertEqual(prove_ordered_copy_transfer(
            facts, row, references, entry=CodeAddress(row.wrapper, 'thumb')), ())

        row = VectorCopyRow(0x400, 0x600, 0x1000, 0x20, 0x1020, 0x100)
        first = CopyLoopTransfer((0x20, 0x10), CodeAddress(0x10, 'thumb'),
                                 70, 71, 0x1000, 0x100E, 4, 4, 0x1010,
                                 0x600, 0x610)
        second = CopyLoopTransfer((0x40, 0x30), CodeAddress(0x30, 'thumb'),
                                  70, 71, 0x1010, 0x1020, 4, 4, 0x1020,
                                  0x610, 0x620)
        clear_first = CopyLoopTransfer((0x60, 0x50), CodeAddress(0x50, 'thumb'),
                                       70, None, 0x1020, 0x1030, 4, 4, 0x1030)
        clear_second = CopyLoopTransfer((0x80, 0x70), CodeAddress(0x70, 'thumb'),
                                        70, None, 0x1030, 0x1040, 4, 4, 0x1040)
        proof = _compose_ordered_transfers(
            CodeAddress(row.wrapper, 'thumb'), row, (first, second),
            (clear_first, clear_second))
        self.assertIsNotNone(proof)

    def test_reset_prefix_requires_a_unique_computed_interworking_handoff(self):
        facts, transfer = reset_handoff_fixture()
        proof = prove_reset_prefix_completion(
            facts, CodeAddress(0x40, 'thumb'), transfer)
        self.assertIsNotNone(proof)
        self.assertEqual(proof.continuation_site, CodeAddress(0x46, 'thumb'))
        self.assertEqual(proof.continuation_target, CodeAddress(0x80, 'arm'))

        disconnected, transfer = reset_handoff_fixture(disconnected=True)
        self.assertIsNone(prove_reset_prefix_completion(
            disconnected, CodeAddress(0x40, 'thumb'), transfer))

        bypassed, transfer = reset_handoff_fixture(bypass=True)
        self.assertIsNone(prove_reset_prefix_completion(
            bypassed, CodeAddress(0x40, 'thumb'), transfer))

        unrelated_call, transfer = reset_handoff_fixture(alternate_call=True)
        proof = prove_reset_prefix_completion(
            unrelated_call, CodeAddress(0x40, 'thumb'), transfer)
        self.assertIsNotNone(proof)
        self.assertEqual(proof.continuation_site, CodeAddress(0x46, 'thumb'))

    def test_three_word_copy_row_checks_both_supplied_tables_and_loop_shape(self):
        for options in ({'separate_zero': True, 'wrong_destination': True},
                        {'separate_zero': True, 'bypass_store': True},
                        {'separate_zero': True, 'extra_unknown_store': True}):
            with self.subTest(options=options):
                image, row = copy_consumer_fixture(**options)
                facts = FirmwareFacts(image)
                spans = ((row.table, row.table + 12),
                         (row.zero_table, row.zero_table + 8))
                references = facts.literal_access_candidates(spans, limit=len(image))
                self.assertEqual(prove_startup_copy_consumer(facts, row, references), ())

        image, row = copy_consumer_fixture(separate_zero=True)
        facts = FirmwareFacts(image)
        spans = ((row.table, row.table + 12),
                 (row.zero_table, row.zero_table + 8))
        references = facts.literal_access_candidates(spans, limit=len(image))
        self.assertEqual(prove_startup_copy_consumer(
            facts, replace(row, zero_size=row.zero_size + 4), references), ())

    def test_state_initializer_requires_store_through_literal_state(self):
        state = 0x200
        code = struct.pack('<6HI', 0x4802, 0x2100, 0x6001, 0x4770, 0x46C0,
                           0x46C0, state)
        self.assertIsNotNone(_state_initializer(FirmwareFacts(code), state))

        clobbered = struct.pack('<6HI', 0x4802, 0x2100, 0x2000, 0x6001,
                                0x4770, 0x46C0, state)
        self.assertIsNone(_state_initializer(FirmwareFacts(clobbered), state))

    def test_copy_table_consumer_rejects_unrelated_store_destination(self):
        image, row = copy_consumer_fixture(wrong_destination=True)
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        self.assertEqual(prove_copy_consumer(facts, row, references), ())

    def test_copy_table_consumer_checks_supplied_row_bytes(self):
        image, row = copy_consumer_fixture()
        facts = FirmwareFacts(image)
        references = facts.literal_access_candidates(
            ((row.table, row.table + 20),), limit=len(image))
        self.assertEqual(prove_copy_consumer(
            facts, replace(row, source=row.source + 4), references), ())

    def test_copy_table_consumer_rejects_reversed_bound_and_store_bypass(self):
        for options in ({'reverse_bound': True}, {'bypass_store': True},
                        {'extra_unknown_store': True}):
            with self.subTest(options=options):
                image, row = copy_consumer_fixture(**options)
                facts = FirmwareFacts(image)
                references = facts.literal_access_candidates(
                    ((row.table, row.table + 20),), limit=len(image))
                self.assertEqual(prove_copy_consumer(facts, row, references), ())

    def test_opaque_call_clobbers_copy_definition(self):
        words = (0xE3A00001, 0xEB000003, 0xE5810000,
                 0xE12FFF1E, 0xE1A00000, 0xE1A00000, 0xE12FFF1E)
        facts = FirmwareFacts(struct.pack('<7I', *words))
        function = facts.function(
            CodeAddress(0, 'arm'),
            symbolic_registers={a.ARM_REG_R1: SymbolicValue.arg(0)})
        self.assertTrue(any(site.address == 4 for site, _ in function.calls))
        self.assertFalse(_definition_reaches(
            facts, function, CodeAddress(0, 'arm'), CodeAddress(8, 'arm'),
            a.ARM_REG_R0, (100, 104)))

    def test_hardware_contract_requires_callback_link_to_command_helpers(self):
        entries = {
            'read': CodeAddress(0x100, 'thumb'),
            'program': CodeAddress(0x200, 'thumb'),
            'erase': CodeAddress(0x300, 'thumb'),
        }
        bypass = CodeAddress(0x500, 'arm')
        sector_erase = CodeAddress(0x600, 'arm')
        roots = {}
        callbacks = callback_fixture()[1]
        callbacks['bypass-enter'] = command_function(
            0x500, ((0xAAA, 0xAA), (0x554, 0x55), (0xAAA, 0x20)))
        callbacks['erase'] = command_function(
            0x300, ((0xAAA, 0xAA), (0x554, 0x55), (0xAAA, 0x80),
                    (0xAAA, 0xAA), (0x554, 0x55), (0x000, 0x30)))
        for name, entry in entries.items():
            base = callbacks['read']
            roots[entry.address] = replace(
                base, entry=entry, calls=()
            )
        roots[entries['program'].address] = replace(
            roots[entries['program'].address],
            calls=((CodeAddress(0x204, 'thumb'), bypass),),
        )
        roots[entries['erase'].address] = replace(
            roots[entries['erase'].address],
            calls=((CodeAddress(0x304, 'thumb'), sector_erase),),
        )

        class FactsStub:
            image = bytes(0x1000)

            def __init__(self, linked):
                self.linked = linked

            def decode(self, entry):
                return object() if entry.address in roots else None

            def function(self, entry, **kwargs):
                if entry.address in roots:
                    return roots[entry.address]
                if entry == bypass:
                    return callbacks['bypass-enter']
                if entry == sector_erase:
                    return callbacks['erase']
                raise KeyError(entry)

        copy = CopyConsumerProof(
            0x700, CodeAddress(0x800, 'thumb'), (0x820, 0x810),
            (0x840, 0x830), (),
        )
        self.assertIsNotNone(prove_amd_x16_hardware_contract(
            0x005F0004, (0x10000,) * 14, entries, FactsStub(True), copy))

        callbacks['bypass-enter'] = command_function(
            0x500, ((0xAA0, 0xAA), (0x540, 0x55), (0xAA0, 0x20)))
        self.assertIsNone(prove_amd_x16_hardware_contract(
            0x005F0004, (0x10000,) * 14, entries, FactsStub(True), copy))
        callbacks['bypass-enter'] = command_function(
            0x500, ((0xAAA, 0xAA), (0x554, 0x55), (0xAAA, 0x20)))

        roots[entries['program'].address] = replace(
            roots[entries['program'].address], calls=())
        roots[entries['erase'].address] = replace(
            roots[entries['erase'].address], calls=())
        self.assertIsNone(prove_amd_x16_hardware_contract(
            0x005F0004, (0x10000,) * 14, entries, FactsStub(False), copy))

    def test_mutually_exclusive_command_path_is_not_combined(self):
        function = callback_fixture()[1]['bypass-enter']
        source = CodeAddress(0x514, 'arm')
        edges = tuple(edge for edge in function.control_edges
                      if edge[0] != source)
        split = replace(function, control_edges=edges + (
            (source, CodeAddress(0x518, 'arm')),
            (source, CodeAddress(0x520, 'arm')),
        ))
        self.assertNotIn('bypass-enter', summarize_amd_x16(split).operations)


if __name__ == '__main__':
    unittest.main()
