"""Synthetic checks for stack-pair linkage and seven-wire row evidence."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from capstone import arm as a
from msm5xxx_emulator.detection.devices.input import pair_rows
from msm5xxx_emulator.detection.devices.input.pair_events import (
    _event_classifier_table,
)
from msm5xxx_emulator.detection.devices.input.row_execution import _Bits
from msm5xxx_emulator.detection.devices.input.startup_copy import reset_linked_input_copy
from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts, SymbolicValue


def _put16(image, at, value):
    struct.pack_into("<H", image, at, value)


def _bl(image, at, target):
    delta = target - at - 4
    _put16(image, at, 0xf000 | ((delta >> 12) & 0x7ff))
    _put16(image, at + 2, 0xf800 | ((delta >> 1) & 0x7ff))


def _branch(image, at, condition, target):
    delta = (target - at - 4) // 2
    _put16(image, at, 0xd000 | condition << 8 | (delta & 255))


def _jump(image, at, target):
    delta = (target - at - 4) // 2
    _put16(image, at, 0xe000 | (delta & 0x7ff))


def _counter_normalize(image, at, register):
    _put16(image, at, 0x0600 | (24 << 6) | register << 3 | register)
    _put16(image, at + 2, 0x0e00 | (24 << 6) | register << 3 | register)


def _first_loop_image(*, drive_bound=7, sense_bound=4, drive_backedge=None,
                      counter_init=0, clobber=False, clobber_gap=False,
                      orphan=False):
    image = bytearray(0x400)
    sense = 0x100
    _put16(image, sense + 10, 0xe000 if orphan else 0x2700)
    if orphan:
        _jump(image, sense + 10, sense + 26)
    _put16(image, sense + 12, 0x2601)
    _put16(image, sense + 14, 0x2400 | counter_init)
    _put16(image, sense + 26, 0x5d28) # LDRB r0,[r5,r4]
    _put16(image, sense + 28, 0x3401 if not clobber else 0x2401)
    _counter_normalize(image, sense + 30, 4)
    if clobber_gap:
        _put16(image, sense + 30, 0x2401)
    _put16(image, sense + 34, 0x2c00 | drive_bound)
    _branch(image, sense + 36, 11,
            sense + 26 if drive_backedge is None else drive_backedge)
    _put16(image, sense + 38, 0x3701)
    _counter_normalize(image, sense + 40, 7)
    _put16(image, sense + 44, 0x2f00 | sense_bound)
    _branch(image, sense + 46, 11, sense + 14)
    _put16(image, sense + 48, 0x4770)
    return bytes(image), sense


def _second_loop_image(*, sense_bound=4, row_bound=7,
                       sense_backedge=None, row_backedge=None,
                       sense_init=0, clobber_gap=False):
    image = bytearray(0x400)
    row_entry, sense = 0x80, 0x100
    _put16(image, row_entry - 2, 0x2500)
    _put16(image, row_entry, 0x46c0)
    _put16(image, sense + 8, 0x2400 | sense_init)
    _put16(image, sense + 10, 0x46c0)
    _put16(image, sense + 30, 0x5d47) # LDRB r7,[r0,r5]
    _put16(image, sense + 40, 0x3401)
    _counter_normalize(image, sense + 42, 4)
    if clobber_gap:
        _put16(image, sense + 42, 0x2401)
    _put16(image, sense + 46, 0x2c00 | sense_bound)
    _branch(image, sense + 48, 11,
            sense + 10 if sense_backedge is None else sense_backedge)
    _put16(image, sense + 50, 0x3501)
    _counter_normalize(image, sense + 52, 5)
    _put16(image, sense + 56, 0x2d00 | row_bound)
    _branch(image, sense + 58, 10, sense + 62)
    _jump(image, sense + 60,
          row_entry if row_backedge is None else row_backedge)
    _put16(image, sense + 62, 0x4770)
    return bytes(image), row_entry, sense


def _event_index_images():
    image = bytearray(0x400)
    sense, second_sense, table = 0x100, 0x140, 0x280
    words = (0x00f8, 0x491b, 0x1bc0, 0x393c, 0x180d, 0x5d28)
    for index, word in enumerate(words):
        _put16(image, sense + 16 + index * 2, word)
    struct.pack_into("<I", image, 0x180, table + 0x3c)
    _put16(image, second_sense + 20, 0x00e0) # LSLS r0,r4,#3
    words2 = (0x491a, 0x1b00, 0x393c, 0x1840, 0x5d47)
    for index, word in enumerate(words2):
        _put16(image, second_sense + 22 + index * 2, word)
    struct.pack_into("<I", image, 0x1c0, table + 0x3c)
    return image, sense, second_sense, table


def _classifier_table_image(*, index_source=0):
    image = bytearray(0x400)
    _put16(image, 0x100, 0x4c08) # LDR r4, [PC, #0x20] -> 0x124
    _put16(image, 0x102, 0x7802 | (index_source << 3)) # LDRB r2,[rN]
    _put16(image, 0x104, 0x5ca3) # LDRB r3,[r4,r2]
    for offset, value in ((6, 0), (10, 1), (14, 2), (18, 3)):
        _put16(image, 0x100 + offset, 0x2b00 | value) # CMP r3,#class
        _branch(image, 0x100 + offset + 2, 0, 0x11c)
    _put16(image, 0x116, 0x54a3) # STRB r3,[r4,r2]
    _put16(image, 0x118, 0x4770)
    _put16(image, 0x11c, 0x4770)
    struct.pack_into("<I", image, 0x124, 0x300)
    image[0x330:0x332] = b"\x00\x03"
    return bytes(image)


def _sense_column_image(*, index_register=4, shift_register=1,
                        alternate_return=False, clobbered_sample=False):
    image = bytearray(0x400)
    sense, helper = 0x100, 0x220
    _put16(image, sense - 2, 0x6b60) # descriptor+34 pointer load
    for offset, word in ((0, 0x8800), (2, 0x0700), (4, 0x0f00),
                         (6, 0x9005), (8, 0x2400)):
        _put16(image, sense + offset, word)
    # ADD r1,r4,#0 selects the current sense index; the LDR reloads
    # the extracted low nibble before the bit-test call.
    _put16(image, sense + 10,
           0x1c00 | (index_register << 3) | 1)
    _put16(image, sense + 12, 0x9805)
    _bl(image, sense + 14, helper)
    _put16(image, sense + 18, 0x1c06) # ADD r6,r0,#0
    guard = helper
    if clobbered_sample:
        _put16(image, helper, 0x2001) # MOVS r0,#1 destroys the sample
        guard += 2
    _put16(image, guard, 0x2900) # CMP r1,#0
    _branch(image, guard + 2, 11, guard + 14)
    _put16(image, guard + 4, 0x2920) # CMP r1,#32
    valid_target = guard + 20
    _branch(image, guard + 6, 11,
            guard + 14 if alternate_return else valid_target)
    for at in (guard + 8, guard + 14):
        _put16(image, at, 0x2000)
        _put16(image, at + 2, 0x43c0) # MVNS r0,r0
        _put16(image, at + 4, 0x4770)
    shift = valid_target
    _put16(image, shift, 0x4108 | (shift_register << 3))
    _put16(image, shift + 2, 0x07c0)
    _put16(image, shift + 4, 0x0fc0)
    _put16(image, shift + 6, 0x4770)
    return bytes(image), sense


def _second_pair_image(*, consumer_target=0x260, consumer_offset=0x0c,
                       event_source=7, mode_branch=True):
    image = bytearray(0x400)
    callee, _, _, _ = _pair_image()
    image[0x240:0x280] = callee[0x240:0x280]
    image[0x2a0:0x2a2] = callee[0x2a0:0x2a2]
    entry, event_load, event_store = 0xe0, 0xf0, 0x100
    _put16(image, 0xe4, 0x1c06) # ADD r6,r0,#0: sensed column result
    _put16(image, event_load, 0x5d47) # LDRB r7,[r0,r5]
    _put16(image, event_store - 2, 0xab00) # ADD r3,sp,#0
    _put16(image, event_store,
           0x7000 | (16 << 6) | (3 << 3) | event_source)
    _put16(image, event_store + 2, 0x2e01 if mode_branch else 0x2e02)
    _branch(image, event_store + 4, 1, event_store + 10)
    _put16(image, event_store + 6, 0x2001)
    _jump(image, event_store + 8, event_store + 16)
    _put16(image, event_store + 10, 0x2000)
    _put16(image, event_store + 12, 0x9002)
    _put16(image, event_store + 14, 0x2002)
    _put16(image, event_store + 16, 0xab00)
    _put16(image, event_store + 18,
           0x7000 | (17 << 6) | (3 << 3))
    _put16(image, event_store + 20, 0xa804)
    _put16(image, event_store + 22, 0xa903)
    pred_call = event_store + 24
    _bl(image, pred_call, 0x240)
    _put16(image, event_store + 28, 0x2801)
    consumer_call = event_store + 40
    _branch(image, event_store + 30, 1, consumer_call + 4)
    _put16(image, event_store + 38, 0xa800 | (consumer_offset // 4))
    _bl(image, consumer_call, consumer_target)
    _put16(image, consumer_call + 4, 0x4770)
    return bytes(image), event_load, pred_call, consumer_call, entry


def _pair_image(*, mode=1, event_offset=0x10, consumer_offset=0x0c,
                predicate_target=0x240, consumer_target=0x260,
                constant_predicate=False, no_op_consumer=False,
                callee_consumer_offset=0, predicate_output_offset=0,
                mode_rejects_one=False, event_rejects_nonzero=False,
                normalized_mode=False, predicate_event_offset=0):
    image = bytearray(0x400)
    base = 0x100
    words = (0xb500, 0x2600 | mode, 0x5d28, 0xab00, 0xa903,
             0x7000 | (event_offset << 6) | (3 << 3),
             0x7000 | ((event_offset + 1) << 6) | (3 << 3) | 6,
             0xa800 | (event_offset // 4),)
    for index, word in enumerate(words):
        _put16(image, base + index * 2, word)
    pred_call = base + len(words) * 2
    _bl(image, pred_call, predicate_target)
    cmp_pc = pred_call + 4
    _put16(image, cmp_pc, 0x2801)
    branch_pc = cmp_pc + 2
    consumer_arg_pc = branch_pc + 2
    _put16(image, consumer_arg_pc, 0xa800 | (consumer_offset // 4))
    consumer_call = consumer_arg_pc + 2
    _bl(image, consumer_call, consumer_target)
    _branch(image, branch_pc, 1, consumer_call + 4)
    _put16(image, consumer_call + 4, 0xbd00)
    if constant_predicate:
        _put16(image, predicate_target, 0x2001)
        _put16(image, predicate_target + 2, 0x4770)
    else:
        _put16(image, predicate_target,
               0x7802 | (predicate_event_offset << 6)) # LDRB event
        _put16(image, predicate_target + 2, 0x2a00) # CMP event,#0
        _branch(image, predicate_target + 4,
                1 if event_rejects_nonzero else 0,
                predicate_target + 0x18)
        _put16(image, predicate_target + 6, 0x7843) # LDRB r3,[r0,#1]
        _put16(image, predicate_target + 8, 0x2b01) # CMP mode,#1
        _branch(image, predicate_target + 10,
                0 if mode_rejects_one else 1, predicate_target + 0x18)
        if normalized_mode:
            _put16(image, predicate_target + 12, 0x2301) # MOVS r3,#1
            event_store, mode_store = predicate_target + 14, predicate_target + 16
            success, ret = predicate_target + 18, predicate_target + 20
        else:
            event_store, mode_store = predicate_target + 12, predicate_target + 14
            success, ret = predicate_target + 16, predicate_target + 18
        _put16(image, event_store,
               0x700a | (predicate_output_offset << 6)) # STRB event,[r1,#offset]
        _put16(image, mode_store,
               0x704b | ((predicate_output_offset + 1) << 6)) # STRB mode
        _put16(image, success, 0x2001)
        _put16(image, ret, 0x4770)
        _put16(image, predicate_target + 0x18, 0x2000)
        _put16(image, predicate_target + 0x1a, 0x4770)
    if no_op_consumer:
        _put16(image, consumer_target, 0x4770)
    else:
        _put16(image, consumer_target, 0xb510)       # PUSH {r4,lr}
        _put16(image, consumer_target + 2, 0x4604)   # MOV r4,r0
        _put16(image, consumer_target + 4,
               0x7822 | (callee_consumer_offset << 6)) # LDRB r2,[r4,#offset]
        _put16(image, consumer_target + 6,
               0x7863 | (callee_consumer_offset << 6)) # LDRB r3,[r4,#offset+1]
        _put16(image, consumer_target + 8, 0x2b02)   # CMP mode,#2
        _branch(image, consumer_target + 10, 1, consumer_target + 0x16)
        _put16(image, consumer_target + 12, 0x1c10)  # ADDS r0,r2,#0
        _bl(image, consumer_target + 14, 0x2a0)
        _put16(image, consumer_target + 18, 0xe003)  # B done
        _put16(image, consumer_target + 0x16, 0x1c10)
        _bl(image, consumer_target + 0x18, 0x2a0)
        _put16(image, consumer_target + 0x1c, 0xbd10) # POP {r4,pc}
    _put16(image, 0x2a0, 0x4770)
    return bytes(image), base + 4, pred_call, consumer_call


class PairRowTests(unittest.TestCase):
    def test_pair_argument_reaches_both_calls(self):
        image, load, predicate, consumer = _pair_image()
        result = pair_rows._stack_pair_linkage(image, load, event_codes=(49,))
        self.assertIsNotNone(result)
        self.assertEqual(result["event_stack_offset"], 0x10)
        self.assertEqual(result["mode_stack_offset"], 0x11)
        self.assertEqual(result["mode"], 1)
        self.assertEqual(result["event_register"], 0)
        self.assertEqual(result["predicate_site"], predicate)
        self.assertEqual(result["consumer_site"], consumer)
        self.assertEqual(result["consumer_arg_stack_offset"], 0x0c)
        self.assertEqual(result["consumer_event_offset"], 0)
        self.assertEqual(result["consumer_mode_offset"], 1)

    def test_different_pair_byte_and_consumer_object_are_rejected(self):
        for options in ({"event_offset": 0x14}, {"consumer_offset": 0x10}):
            image, load, _, _ = _pair_image(**options)
            with self.subTest(options=options):
                self.assertIsNone(pair_rows._stack_pair_linkage(
                    image, load, event_codes=(49,)))

    def test_mismatched_call_target_and_nonmode1_pair_are_visible(self):
        image, load, _, _ = _pair_image(mode=2)
        self.assertIsNone(pair_rows._stack_pair_linkage(
            image, load, event_codes=(49,)))
        image, load, _, _ = _pair_image()
        self.assertIsNone(pair_rows._stack_pair_linkage(
            image, load, predicate=0x220, event_codes=(49,)))

    def test_hardware_proof_does_not_select_input_or_output_mode(self):
        image, load, _, _ = _pair_image(normalized_mode=True)
        result = pair_rows._stack_pair_linkage(image, load, event_codes=(49,))
        self.assertIsNotNone(result)
        self.assertTrue(result["predicate_hardware"]["hardware_only"])
        self.assertEqual(result["predicate_hardware"]["classifier_tables"], [])

    def test_unrelated_callees_and_wrong_consumer_bytes_are_rejected(self):
        for options in ({"constant_predicate": True}, {"no_op_consumer": True},
                        {"callee_consumer_offset": 2},
                        {"predicate_output_offset": 2},
                        {"predicate_event_offset": 2}):
            image, load, _, _ = _pair_image(**options)
            with self.subTest(options=options):
                self.assertIsNone(pair_rows._stack_pair_linkage(
                    image, load, event_codes=(49,)))

    def test_seven_wire_order_and_row_clobber(self):
        wires = [(0x03000720, 0x10), (0x03000720, 0x20),
                 *[(0x03000728, 1 << bit) for bit in range(5)]]
        selected = [wires[index] for index in (2, 3, 4, 5, 6, 1, 0)]
        outputs = []
        for pin in selected:
            # Construct a known bank value with exactly one selected low pin.
            state = {port: _Bits(zero=(~sum(bit for p, bit in wires if p == port and (p, bit) != pin)) & 0xffff,
                                 one=sum(bit for p, bit in wires if p == port and (p, bit) != pin))
                     for port in {p for p, _ in wires}}
            outputs.append(state)
        layout = pair_rows._row_wires_seven(outputs)
        self.assertIsNotNone(layout)
        self.assertEqual(layout[1], [2, 3, 4, 5, 6, 1, 0])
        broken = list(outputs)
        broken[3] = dict(broken[3])
        broken[3][0x03000728] = _Bits.constant(0xffff)
        self.assertIsNone(pair_rows._row_wires_seven(broken))

    def test_first_loop_requires_initialized_counters_exact_bounds_and_backedges(self):
        valid, sense = _first_loop_image()
        facts = FirmwareFacts(valid)
        function = facts.function(CodeAddress(sense + 10), budget=128)
        self.assertTrue(pair_rows._first_scan_loops(valid, sense, facts, function))
        for options in ({"drive_bound": 6}, {"sense_bound": 5},
                        {"counter_init": 1}, {"clobber": True},
                        {"clobber_gap": True},
                        {"drive_backedge": sense + 28}, {"orphan": True}):
            image, site = _first_loop_image(**options)
            facts = FirmwareFacts(image)
            function = facts.function(CodeAddress(site + 10), budget=128)
            with self.subTest(options=options):
                self.assertFalse(pair_rows._first_scan_loops(
                    image, site, facts, function))

    def test_second_loop_binds_inner_sense_and_real_row_counter(self):
        valid, row, sense = _second_loop_image()
        facts = FirmwareFacts(valid)
        function = facts.function(CodeAddress(row - 2), budget=256)
        self.assertTrue(pair_rows._second_scan_loops(
            valid, sense, row, facts, function))
        for options in ({"sense_bound": 3}, {"row_bound": 6},
                        {"sense_init": 1}, {"sense_backedge": sense + 12},
                        {"row_backedge": row + 2}, {"clobber_gap": True}):
            image, row, sense = _second_loop_image(**options)
            facts = FirmwareFacts(image)
            function = facts.function(CodeAddress(row - 2), budget=256)
            with self.subTest(options=options):
                self.assertFalse(pair_rows._second_scan_loops(
                    image, sense, row, facts, function))

    def test_both_event_lookups_keep_exact_destinations_and_same_table(self):
        image, sense, second_sense, table = _event_index_images()
        facts = FirmwareFacts(bytes(image))
        self.assertTrue(pair_rows._event_index_shape(image, sense, facts))
        self.assertEqual(pair_rows._event_index_shape_second(
            image, second_sense, table, facts), second_sense + 30)
        self.assertIsNone(pair_rows._event_index_shape_second(
            image, second_sense, table + 1, facts))
        changed = bytearray(image)
        _put16(changed, sense + 24, 0x1bc1) # wrong destination
        self.assertFalse(pair_rows._event_index_shape(changed, sense,
                                                      FirmwareFacts(bytes(changed))))

    def test_classifier_table_is_symbolically_indexed_and_mutable_bytes_are_not_inputs(self):
        image = _classifier_table_image()
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(0x100), budget=64,
            symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                                a.ARM_REG_R1: SymbolicValue.arg(1)})
        metadata = _event_classifier_table(image, facts, function, (0x30, 0x31))
        self.assertIsNotNone(metadata)
        table = metadata[0]
        self.assertEqual(table["base"], 0x300)
        self.assertEqual((table["address_start"], table["address_end"]),
                         (0x330, 0x332))
        self.assertEqual(table["index_source"], "input-event-byte")
        self.assertEqual(table["contents"], "mutable-runtime-state")
        changed = bytearray(image)
        changed[0x330:0x332] = b"\x03\x01"
        changed = bytes(changed)
        changed_facts = FirmwareFacts(changed)
        changed_function = changed_facts.function(CodeAddress(0x100), budget=64,
            symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                                a.ARM_REG_R1: SymbolicValue.arg(1)})
        self.assertEqual(_event_classifier_table(
            changed, changed_facts, changed_function, (0x30, 0x31)), metadata)
        broken = _classifier_table_image(index_source=1)
        broken_facts = FirmwareFacts(broken)
        broken_function = broken_facts.function(CodeAddress(0x100), budget=64,
            symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                                a.ARM_REG_R1: SymbolicValue.arg(1)})
        self.assertIsNone(_event_classifier_table(
            broken, broken_facts, broken_function, (0x30, 0x31)))

    def test_classifier_index_requires_unsigned_event_byte(self):
        for instruction in (0x6802, 0x8802, 0x56c2, 0x7842):
            with self.subTest(instruction=hex(instruction)):
                image = bytearray(_classifier_table_image())
                _put16(image, 0x102, instruction)
                image = bytes(image)
                facts = FirmwareFacts(image)
                function = facts.function(CodeAddress(0x100), budget=64,
                    initial_registers={a.ARM_REG_R3: 0},
                    symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                                        a.ARM_REG_R1: SymbolicValue.arg(1)})
                self.assertIsNone(_event_classifier_table(
                    image, facts, function, (0x30, 0x31)))

    def test_column_order_is_derived_from_live_nibble_bit_test(self):
        image, sense = _sense_column_image()
        self.assertEqual(pair_rows._sense_column_map(
            image, sense, FirmwareFacts(image))[0], [14, 13, 11, 7])
        for options in ({"index_register": 5}, {"shift_register": 3},
                        {"alternate_return": True},
                        {"clobbered_sample": True}):
            changed, site = _sense_column_image(**options)
            with self.subTest(options=options):
                self.assertIsNone(pair_rows._sense_column_map(
                    changed, site, FirmwareFacts(changed)))

    def test_second_table_pair_must_reach_matching_consumer_and_mode(self):
        image, event_load, pred, consumer, entry = _second_pair_image()
        facts = FirmwareFacts(image)
        function = facts.function(CodeAddress(entry), budget=128)
        pair = pair_rows._second_pair_linkage(
            image, event_load, function, 0x240, 0x260, facts,
            event_codes=(49,))
        self.assertIsNotNone(pair)
        self.assertEqual(pair["event_register"], 7)
        self.assertEqual(pair["consumer_event_offset"], 0)
        self.assertEqual(pair["consumer_mode_offset"], 1)
        for options in ({"consumer_target": 0x280},
                        {"consumer_offset": 0x10},
                        {"event_source": 6}, {"mode_branch": False}):
            changed, load, _, _, root = _second_pair_image(**options)
            facts = FirmwareFacts(changed)
            function = facts.function(CodeAddress(root), budget=128)
            with self.subTest(options=options):
                self.assertIsNone(pair_rows._second_pair_linkage(
                    changed, load, function, 0x240, 0x260, facts,
                    event_codes=(49,)))
    def test_reset_copy_orphan_and_property_bounds(self):
        orphan = bytes(0x800)
        self.assertIsNone(reset_linked_input_copy(
            orphan, ((0x01000100, 0x38),), ram_base=0x01000000,
            ram_size=0x00800000, flash_size=len(orphan)))
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
            ram_size=0x00800000, flash_size=0x100, board_status_input=None)
        profile = {"dependencies": [(0x100, 4)], "sense_address": 0x0300072c,
            "row_ports": [0x03000720, 0x03000728], "descriptor": 0x01000100,
            "presence_site": 0x20, "sense_site": 0x30,
            "row_masks": [0x30, 0x1f]}
        with patch.object(pair_rows, "find_pair_row_scanners", return_value=[profile]):
            self.assertEqual(pair_rows.pair_row_property(bytes(0x200), config),
                             (None, None))


if __name__ == "__main__":
    unittest.main()
