"""Independent synthetic proof fixtures for five-column halfword scanners."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from capstone import arm as a
from msm5xxx_emulator.detection.devices.input.five_column_rows import (
    GRAMMAR,
    five_column_row_property,
)
from msm5xxx_emulator.detection.devices.input.startup_copy import (
    reset_linked_input_copy,
)
from test_sparse_rows import _linked_copy_reset_fixture, _put16, _put32


def _branch(image, at, condition, target):
    delta = (target - at - 4) // 2
    assert -128 <= delta <= 127
    _put16(image, at, 0xd000 | condition << 8 | (delta & 255))


def _jump(image, at, target):
    delta = (target - at - 4) // 2
    assert -1024 <= delta <= 1023
    _put16(image, at, 0xe000 | (delta & 0x7ff))


def _bl(image, at, target):
    delta = target - at - 4
    _put16(image, at, 0xf000 | ((delta >> 12) & 0x7ff))
    _put16(image, at + 2, 0xf800 | ((delta >> 1) & 0x7ff))


def _literal(image, at, register, pool, value):
    pc = (at + 4) & ~3
    delta = pool - pc
    assert 0 <= delta <= 1020 and delta % 4 == 0
    _put16(image, at, 0x4800 | (register << 8) | (delta // 4))
    _put32(image, pool, value)


def _event_map_fixture(*, pointer_clobber=False):
    image = bytearray(0x1000)
    descriptor, descriptor_rom = 0x01000100, 0x900
    sample, event_load, capture_end = 0x100, 0x118, 0x120
    # The event trace starts after the sample LDRH. R6 is a source-proved
    # descriptor alias, and its +0x34 field supplies the reread pointer.
    _put16(image, sample, 0x8808)
    _put16(image, sample + 2, 0x6b73)  # LDR r3,[r6,#0x34]
    _put16(image, sample + 4, 0x2000 if pointer_clobber else 0x46c0)
    _put16(image, sample + 6, 0x881d)  # LDRH r5,[r3]
    _put16(image, sample + 8, 0x2d00)  # CMP r5,#0; unknown input splits paths.
    _branch(image, sample + 10, 0, capture_end)
    _literal(image, sample + 12, 2, 0x300, 0x500)
    _put16(image, sample + 14, 0x5c10)  # LDRB r0,[r2,r0] -> column.
    _put16(image, sample + 16, 0x2306)  # MOVS r3,#6.
    _put16(image, sample + 18, 0x4358)  # MULS r0,r3,r0.
    _put16(image, sample + 20, 0x1900)  # ADDS r0,r0,r4.
    _literal(image, sample + 22, 2, 0x304, 0x600)
    _put16(image, event_load, 0x5c17)   # LDRB r7,[r2,r0] -> numeric event.
    _put16(image, capture_end, 0x4770)
    struct.pack_into("<I", image, descriptor_rom + 0x34, 0x0300072c)
    columns = bytearray(32)
    for raw, column in zip((0x1e, 0x1d, 0x1b, 0x17, 0x0f), range(5)):
        columns[raw] = column
    image[0x500:0x520] = columns
    image[0x600:0x61e] = b"123456789*0#" + bytes(range(0x40, 0x40 + 18))
    return bytes(image), (sample, event_load, capture_end, descriptor,
                          descriptor_rom, 0x106)


def _fixture(*, bad_clear=False, clobber_counter=False,
             wrong_sense=False, bad_lookup=False, duplicate_key=False,
             bad_bound=False, row_count=6, inverted_no_key=False,
             noninplace_add=False, dead_footer=False,
             bypass_increment=False, different_backedge=False,
             handler_clobbers_counter=False, local_clobber=False,
             alternate_clobber=False, event_early_exit=False,
             event_early_loop=False, pointer_gap=False,
             row_port=0x03000728, handler_saved_frame=False,
             handler_clobbers_saved_slot=False, normalized_counter=False,
             conditional_counter=False, conditional_restore=False):
    image = _linked_copy_reset_fixture()
    ram, descriptor, descriptor_source = 0x01000000, 0x01000100, 0x1100
    port, other_port = row_port, 0x03000724
    struct.pack_into("<I", image, descriptor_source, other_port)
    struct.pack_into("<I", image, descriptor_source + 0x10, other_port)
    struct.pack_into("<I", image, descriptor_source + 0x20, port)
    struct.pack_into("<I", image, descriptor_source + 0x34,
                     0x03000720 if wrong_sense else 0x0300072c)

    pool = 0x980
    literal_slots = {}

    def literal(at, reg, value):
        nonlocal pool
        slot = literal_slots.get(value)
        if slot is None:
            slot = pool
            pool += 4
            literal_slots[value] = slot
            _put32(image, slot, value)
        distance = slot - ((at + 4) & ~3)
        assert 0 <= distance <= 1020 and distance % 4 == 0
        _put16(image, at, 0x4800 | reg << 8 | distance // 4)

    entry, loop = 0x600, 0x620
    _put16(image, entry, 0xb5f0)  # Save the working row and descriptor registers.
    literal(entry + 2, 6, descriptor)
    _put16(image, entry + 4, 0x2400)  # Firmware row counter begins at zero.
    _put16(image, entry + 6, 0x6b71)  # LDR r1,[r6,#0x34]
    if pointer_gap:
        _put16(image, entry + 8, 0x4620)  # MOV r0,r4; preserve pointer in r1.
        _put16(image, entry + 10, 0x8808) # LDRH r0,[r1]
        _put16(image, entry + 12, 0x06c0)
        _put16(image, entry + 14, 0x0ec0)
        _put16(image, entry + 16, 0x281f)
        _branch(image, entry + 18, 0, loop)
        _jump(image, entry + 20, loop)
    else:
        _put16(image, entry + 8, 0x8808)  # LDRH r0,[r1]
        _put16(image, entry + 10, 0x06c0) # LSLS r0,r0,#27
        _put16(image, entry + 12, 0x0ec0) # LSRS r0,r0,#27
        _put16(image, entry + 14, 0x281f) # CMP r0,#31
        _branch(image, entry + 16, 0, loop)
        _jump(image, entry + 18, loop)

    _put16(image, loop, 0x2c00 | row_count)
    # Patched after sample and row arms are laid out.
    _put16(image, loop + 2, 0xd200)
    _put16(image, loop + 4, 0x46c0)  # No-op alignment before row dispatch.
    dispatch = loop + 6
    for row in range(row_count):
        _put16(image, dispatch + row * 4, 0x2c00 | row)
        _put16(image, dispatch + row * 4 + 2, 0xd000)
    default_branch = dispatch + row_count * 4
    arms = default_branch + 2
    arm_size = 22
    common = arms + row_count * arm_size
    sample_pointer = common + (4 if clobber_counter else 2)
    sample_pc = sample_pointer + 2
    footer = sample_pc + (40 if handler_saved_frame else 32) + (4 if normalized_counter else 0)
    prefix = 2 if conditional_counter else 0
    footer_exit = footer + prefix + (14 if normalized_counter else 10)
    row_exit = common if clobber_counter else sample_pointer
    if bad_bound:
        row_count_compare = row_count - 1
    else:
        row_count_compare = row_count
    _branch(image, loop + 2, 2, row_exit)
    _jump(image, default_branch, row_exit)

    for row in range(row_count):
        arm = arms + row * arm_size
        words = (
            0x8db1,                  # LDRH r1,[r6,#0x2c] shadow
            0x227e if not bad_clear else 0x2200,
            0x4311,                  # ORRS r1,r2: release all six row pins
            0x2301,                  # MOVS r3,#1
            0x001b | (row + 1) << 6,       # LSLS r3,r3,#(row+1)
            0x4399,                  # BICS r1,r3: select one active-low row
            0x85b1,                  # STRH r1,[r6,#0x2c]
            0x8db1,                  # Reload committed shadow
            0x6a32,                  # LDR r2,[r6,#0x20]
            0x8011,                  # STRH r1,[r2] physical GPIO commit
        )
        for index, word in enumerate(words):
            _put16(image, arm + index * 2, word)
        _jump(image, arm + 20, row_exit)
        _branch(image, dispatch + row * 4 + 2, 0, arm)

    cursor = common
    if clobber_counter:
        _put16(image, cursor, 0x2400)  # Unrelated source clobbers r4 before sense.
        cursor += 2
    _jump(image, cursor, sample_pointer)
    _put16(image, sample_pointer, 0x6b71) # Re-read D+0x34 for the row sense.
    _put16(image, sample_pc, 0x8808)      # LDRH r0,[r1]
    _put16(image, sample_pc + 2, 0x06c0)
    _put16(image, sample_pc + 4, 0x0ec0)
    _put16(image, sample_pc + 6, 0x281f)
    _branch(image, sample_pc + 8, 1 if inverted_no_key else 0,
            footer_exit if dead_footer else footer)
    literal(sample_pc + 10, 2, 0x1800)
    _put16(image, sample_pc + 12, 0x5c10) # LDRB r0,[r2,r0] five-column map
    _put16(image, sample_pc + 14, 0x2300 | row_count) # MOVS r3,#row_count
    _put16(image, sample_pc + 16, 0x4358) # MULS r0,r3,r0
    _put16(image, sample_pc + 18, 0x1900) # ADDS r0,r0,r4
    literal(sample_pc + 20, 2, 0x1900)
    event_load = sample_pc + 22
    _put16(image, event_load, 0x5c17)     # LDRB r7,[r2,r0]
    if handler_saved_frame:
        _put16(image, event_load + 2, 0x46c0) # NOP before saved-frame helper.
        _bl(image, event_load + 4, 0x900)
        _put16(image, event_load + 8, 0x4638) # MOV r0,r7; explicit sink argument
        _bl(image, event_load + 10, 0x910)
        _jump(image, event_load + 14, footer)
        _put16(image, event_load + 16, 0x46c0)
    else:
        _put16(image, event_load + 2, 0x4638) # MOV r0,r7; explicit handler argument
        _bl(image, event_load + 4, 0x900)
    if alternate_clobber:
        _branch(image, event_load + 8, 0, event_load + 12)
        _jump(image, event_load + 10, footer)
        _put16(image, event_load + 12, 0x2400) # Alternate path overwrites r4.
        _jump(image, event_load + 14, footer)
    elif local_clobber:
        _put16(image, event_load + 8, 0x2400) # Clobber after the event call.
        _jump(image, event_load + 10, footer)
    elif not handler_saved_frame:
        target = (loop if event_early_loop else footer_exit if event_early_exit
                  else footer + 2 if bypass_increment else footer)
        _jump(image, event_load + 8, target)
    if conditional_counter:
        _put16(image, footer, 0xbf08)       # IT EQ; conditional ADD must reject.
    increment_pc = footer + prefix
    _put16(image, increment_pc, 0x1c6c if noninplace_add else 0x3401)
    # A three-operand add deliberately writes r4 from r5 in the negative case.
    shift = 4 if normalized_counter else 0
    if normalized_counter:
        _put16(image, increment_pc + 2, 0x0624) # LSLS r4,r4,#24
        _put16(image, increment_pc + 4, 0x0e24) # LSRS r4,r4,#24
    compare_pc = increment_pc + 2 + shift
    _put16(image, compare_pc, 0x2c00 | row_count_compare)
    _branch(image, compare_pc + 2, 2, footer_exit)
    _jump(image, compare_pc + 4, loop + 4 if different_backedge else loop)
    _put16(image, footer_exit, 0x4770)
    if handler_saved_frame:
        _put16(image, 0x900, 0xb580)          # PUSH {r7,lr}
        if handler_clobbers_saved_slot:
            _put16(image, 0x902, 0x9400)      # STR r4,[sp,#0], corrupt saved r7.
            _put16(image, 0x904, 0xbc80)
            _put16(image, 0x906, 0xbc08)
            _put16(image, 0x908, 0x4718)
        elif conditional_restore:
            _put16(image, 0x902, 0xbf08)      # IT EQ makes POP conditional.
            _put16(image, 0x904, 0xbc80)
            _put16(image, 0x906, 0xbc08)
            _put16(image, 0x908, 0x4718)
        else:
            _put16(image, 0x902, 0xbc80)      # POP {r7}
            _put16(image, 0x904, 0xbc08)      # POP {r3}
            _put16(image, 0x906, 0x4718)      # BX r3
        _put16(image, 0x910, 0x4770)
    elif handler_clobbers_counter:
        _put16(image, 0x900, 0x2400)       # Handler clobbers r4 without saving it.
        _put16(image, 0x902, 0x4770)
    else:
        _put16(image, 0x900, 0x4770)       # Source-visible event handler return.

    columns = bytearray(32)
    for raw, column in zip((0x1e, 0x1d, 0x1b, 0x17, 0x0f), range(5)):
        columns[raw] = column
    if bad_lookup:
        columns[0x1d] = 0
    image[0x1800:0x1820] = columns
    keys = b"147*2580369#"
    code_map = bytearray(0x40 + i for i in range(5 * row_count))
    for column in range(5):
        for row, key in enumerate(keys[column * row_count:(column + 1) * row_count]):
            code_map[column * row_count + row] = key
    if duplicate_key:
        code_map[1] = ord("1")
    image[0x1900:0x1900 + len(code_map)] = code_map
    return image, {"descriptor": descriptor, "source": descriptor_source,
                   "loop": loop, "sample": sample_pc,
                   "presence": entry + (10 if pointer_gap else 8), "event_load": event_load,
                   "table": 0x1900, "rows": row_count, "port": port,
                   "footer": footer}


class FiveColumnRowsTests(unittest.TestCase):
    def setUp(self):
        self.config = SimpleNamespace(load_address=0, ram_base=0x01000000,
            ram_size=0x00800000, flash_size=0x5000, board_status_input=None)

    def test_unconditional_guard_rejects_predicated_effects(self):
        from capstone import arm as a
        from msm5xxx_emulator.detection.devices.input.five_column_flow import unconditional
        self.assertTrue(unconditional(SimpleNamespace(cc=a.ARM_CC_AL)))
        self.assertTrue(unconditional(SimpleNamespace(cc=a.ARM_CC_INVALID)))
        self.assertFalse(unconditional(SimpleNamespace(cc=a.ARM_CC_EQ)))

    def test_event_map_keeps_proven_sense_reread_unknown(self):
        from msm5xxx_emulator.detection.devices.input.five_column_flow import event_map
        image, (sample, event_load, capture_end, descriptor,
                descriptor_rom, read_pc) = _event_map_fixture()
        result = event_map(image, sample, event_load, a.ARM_REG_R4, 6,
            a.ARM_REG_R0, capture_end, descriptor, descriptor_rom,
            (0x1e, 0x1d, 0x1b, 0x17, 0x0f), b"123456789*0#",
            descriptor_registers=(a.ARM_REG_R6,),
            extra_sense_reads=((read_pc, 0x0300072c),))
        self.assertIsNotNone(result)
        table, events, _dependencies = result
        self.assertEqual(table, 0x600)
        self.assertEqual(events[:12], list(b"123456789*0#"))

    def test_event_map_reread_requires_descriptor_provenance(self):
        from msm5xxx_emulator.detection.devices.input.five_column_flow import event_map
        image, (sample, event_load, capture_end, descriptor,
                descriptor_rom, read_pc) = _event_map_fixture()
        args = (image, sample, event_load, a.ARM_REG_R4, 6, a.ARM_REG_R0,
                capture_end, descriptor, descriptor_rom,
                (0x1e, 0x1d, 0x1b, 0x17, 0x0f), b"123456789*0#")
        self.assertIsNone(event_map(*args,
            extra_sense_reads=((read_pc, 0x0300072c),)))

    def test_event_map_rejects_wrong_reread_address_or_clobbered_pointer(self):
        from msm5xxx_emulator.detection.devices.input.five_column_flow import event_map
        for pointer_clobber, input_address in ((False, 0x03000728),
                                                (True, 0x0300072c)):
            with self.subTest(pointer_clobber=pointer_clobber,
                              input_address=hex(input_address)):
                image, (sample, event_load, capture_end, descriptor,
                        descriptor_rom, read_pc) = _event_map_fixture(
                            pointer_clobber=pointer_clobber)
                result = event_map(image, sample, event_load, a.ARM_REG_R4,
                    6, a.ARM_REG_R0, capture_end, descriptor, descriptor_rom,
                    (0x1e, 0x1d, 0x1b, 0x17, 0x0f), b"123456789*0#",
                    descriptor_registers=(a.ARM_REG_R6,),
                    extra_sense_reads=((read_pc, input_address),))
                self.assertIsNone(result)

    def test_five_column_row_and_numeric_event_mapping(self):
        image, expected = _fixture()
        copy = reset_linked_input_copy(image, ((expected["descriptor"], 0x38),),
            ram_base=self.config.ram_base, ram_size=self.config.ram_size,
            flash_size=self.config.flash_size)
        self.assertIsNotNone(copy)
        self.assertEqual(copy.source_address(expected["descriptor"], 0x38),
                         expected["source"])
        prop, profile = five_column_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-halfword-five-wires="))
        self.assertEqual(profile["grammar"], GRAMMAR)
        self.assertEqual((profile["rows"], profile["columns"]), (6, 5))
        self.assertEqual(profile["single_key_column_sense"], [30, 29, 27, 23, 15])
        self.assertEqual(profile["event_table"], expected["table"])
        self.assertEqual(profile["event_codes"][:12], list(b"147*2580369#"))
        self.assertEqual(profile["row_masks"], [0x7e])
        self.assertEqual(profile["row_wire_order"], list(range(6)))
        self.assertEqual(profile["read_sites"], [expected["presence"], expected["sample"]])

    def test_descriptor_pointer_can_cross_a_proved_instruction_gap(self):
        image, expected = _fixture(pointer_gap=True)
        prop, profile = five_column_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-halfword-five-wires="))
        self.assertEqual(profile["read_sites"], [expected["presence"], expected["sample"]])

    def test_event_early_exit_without_counter_reentry_is_valid(self):
        image, _ = _fixture(event_early_exit=True)
        prop, profile = five_column_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-halfword-five-wires="))
        self.assertEqual(profile["rows"], 6)

    def test_source_proved_saved_frame_helper_preserves_event_register(self):
        image, _ = _fixture(handler_saved_frame=True)
        prop, _ = five_column_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-halfword-five-wires="))
        image, _ = _fixture(handler_saved_frame=True,
                            handler_clobbers_saved_slot=True)
        self.assertEqual(five_column_row_property(image, self.config), (None, None))
        image, _ = _fixture(handler_saved_frame=True, conditional_restore=True)
        self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_event_early_exit_cannot_reenter_the_row_loop_without_increment(self):
        image, _ = _fixture(event_early_loop=True)
        self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_accepts_five_row_scan_when_bound_and_wires_close(self):
        image, expected = _fixture(row_count=5)
        prop, profile = five_column_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-halfword-five-wires="))
        self.assertEqual(profile["rows"], 5)
        self.assertEqual(profile["row_masks"], [0x3e])
        self.assertEqual(profile["row_wire_order"], [0, 1, 2, 3, 4])

    def test_accepts_exact_byte_normalization_after_counter_increment(self):
        image, _ = _fixture(normalized_counter=True)
        prop, profile = five_column_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-halfword-five-wires="))
        self.assertEqual(profile["rows"], 6)
        image, expected = _fixture(normalized_counter=True)
        # A lone shift no longer proves the exact source normalization pair.
        _put16(image, expected["footer"] + 4, 0x46c0)
        self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_rejects_counter_clobber_polarity_bad_column_map_and_duplicate_key(self):
        for options in ({"clobber_counter": True}, {"bad_clear": True},
                        {"bad_lookup": True}, {"duplicate_key": True},
                        {"bad_bound": True}):
            with self.subTest(options=options):
                image, _ = _fixture(**options)
                self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_rejects_a_sense_register_as_a_row_output(self):
        image, _ = _fixture(row_port=0x0300066c)
        self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_rejects_inverted_blank_test_and_unproved_footer_paths(self):
        for options in ("inverted_no_key", "noninplace_add", "dead_footer",
                        "bypass_increment", "different_backedge",
                        "conditional_counter"):
            with self.subTest(options=options):
                image, _ = _fixture(**{options: True})
                self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_rejects_row_counter_clobbers_on_event_paths(self):
        for options in ("handler_clobbers_counter", "local_clobber",
                        "alternate_clobber"):
            with self.subTest(options=options):
                image, _ = _fixture(**{options: True})
                self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_counter_path_rejects_an_opaque_interworking_call(self):
        from capstone import arm as a
        from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
        from msm5xxx_emulator.detection.devices.input.five_column_rows import _no_intervening_write
        image = bytearray(0x40)
        _put16(image, 0x20, 0x4798)  # BLX r3; local instruction does not write r4.
        flow = SimpleNamespace(control_edges=((CodeAddress(0x20), CodeAddress(0x22)),))
        self.assertFalse(_no_intervening_write(bytes(image), flow, facts_for(bytes(image)),
                                               a.ARM_REG_R4, 0x20, 0x22))

    def test_saved_event_slot_uses_architectural_push_order(self):
        from capstone import arm as a
        from msm5xxx_emulator.detection.devices.input.five_column_flow import _saved_frame_call
        image = bytearray(0x80)
        # PUSH {r4,lr}; load a return sentinel; overwrite the saved r4 slot;
        # POP {r4}; POP {r3}; BX r3. Enum-sorted slots would hide this write.
        for offset, word in enumerate((0xb510, 0x4807, 0x9000, 0xbc10, 0xbc08, 0x4718)):
            _put16(image, 0x20 + offset * 2, word)
        _put32(image, 0x40, 0x5a5a0000 | a.ARM_REG_LR)
        self.assertIsNone(_saved_frame_call(bytes(image), 0x20, a.ARM_REG_R4,
                                            [ord("1")], 0x01000000, 0))

    def test_rejects_wrong_descriptor_sense_pointer_and_unrooted_copy(self):
        image, _ = _fixture(wrong_sense=True)
        self.assertEqual(five_column_row_property(image, self.config), (None, None))
        image, _ = _fixture()
        _put32(image, 0, 0)  # Remove reset-rooted startup copy entry.
        self.assertEqual(five_column_row_property(image, self.config), (None, None))

    def test_property_rejects_source_bounds(self):
        image, _ = _fixture()
        self.config.flash_size = 0x1200
        self.assertEqual(five_column_row_property(image, self.config), (None, None))


if __name__ == "__main__":
    unittest.main()
