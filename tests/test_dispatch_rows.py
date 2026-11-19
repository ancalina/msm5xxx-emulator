"""Synthetic evidence for descriptor-owned computed six-row dispatch."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from nor_fixtures import copy_consumer_fixture
from test_startup_entry import reset_entry_fixture
from msm5xxx_emulator.detection.devices.input.dispatch_rows import (
    dispatch_row_property,
    find_dispatch_row_scanners,
)
from msm5xxx_emulator.detection.devices.input.event_projection import (
    _matrix_input_position,
)
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import (
    matrix_input_command,
)
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


def _put16(image, at, value):
    struct.pack_into("<H", image, at, value)


def _put32(image, at, value):
    struct.pack_into("<I", image, at, value)


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


class _Thumb:
    """Small semantic emitter with symbolic branch and literal labels."""

    def __init__(self, image, start):
        self.image = image
        self.pc = start
        self.labels = {}
        self.fixups = []
        self.pool = 0x900
        self.literals = {}

    def label(self, name):
        self.labels[name] = self.pc

    def emit(self, word):
        _put16(self.image, self.pc, word)
        self.pc += 2

    def branch(self, label, condition):
        self.fixups.append(("branch", self.pc, label, condition))
        self.emit(0)

    def jump(self, label):
        self.fixups.append(("jump", self.pc, label, None))
        self.emit(0)

    def bl(self, target):
        _bl(self.image, self.pc, target)
        self.pc += 4

    def literal(self, register, value):
        slot = self.literals.get(value)
        if slot is None:
            slot = self.pool
            self.pool += 4
            self.literals[value] = slot
            _put32(self.image, slot, value)
        displacement = slot - ((self.pc + 4) & ~3)
        assert 0 <= displacement <= 1020 and displacement % 4 == 0
        self.emit(0x4800 | register << 8 | displacement // 4)

    def finish(self):
        for kind, site, label, condition in self.fixups:
            target = self.labels[label]
            if kind == "branch":
                _branch(self.image, site, condition, target)
            else:
                _jump(self.image, site, target)


def _irq_helper(image, entry, *, enable):
    # Source-qualified ARM helper reached through a Thumb return stub.
    _put16(image, entry, 0x4778)
    _put16(image, entry + 2, 0)
    body = (0xe10f0000, 0xe3c010c0 if enable else 0xe38010c0,
            0xe121f001, 0xe20000c0, 0xe12fff1e)
    for index, word in enumerate(body):
        _put32(image, entry + 4 + index * 4, word)


def _fixture(*, counter_init=True, counter_offset=0x0b,
             sample_offset=0x0e, counter_store=True, counter_backedge=True,
             counter_bound=6, sense_source=True, column_table=True,
             clear=True, descriptor=True, reset_copy=True,
             state_in_bounds=True, duplicate_column=False,
             event_table=True, contact=False, contact_bit=True,
             contact_branch=True, contact_field=True, numeric_gate=True,
             clobber_state=False, clear_clobber=False,
             overlap_state_descriptor=False, contact_high_to_low=False):
    """Emit reset/copy, descriptor, a computed row switch, and lookup bytes."""
    image = bytearray(0x3000)
    ram = 0x01000000
    descriptor_ok = ram + 0x180
    state_offset = (0x1a0 if overlap_state_descriptor else 0x280)
    state = ram + (state_offset if state_in_bounds else 0x00800100)
    descriptor_rom = 0x1180
    column_rom, events_rom = 0x0980, 0x0990
    column_pointer, events_pointer = 0x08b0, 0x08b4
    function, dispatch = 0x420, 0x4a0
    sense = 0x580
    clear_entry = 0x880
    table = 0x4ac
    arms_start = 0x4c0
    common = 0x660
    footer = 0x740

    # Reuse the existing synthetic reset root and bounded copy consumer.
    consumer, copy = copy_consumer_fixture()
    image[0x100:len(consumer)] = consumer[0x100:]
    image[:0x100] = reset_entry_fixture()[:0x100]
    _put32(image, 0x80, ram + 0x1000)
    struct.pack_into("<5I", image, copy.table,
                     0x1000, ram, 0x1000, ram + 0x1000, 0x40)
    if not reset_copy:
        _put32(image, 0, 0)
    _put32(image, descriptor_rom + 0x34,
           0x0300066c if sense_source else 0x03000100)
    if contact:
        _put32(image, descriptor_rom, 0x0300066c)
        _put32(image, descriptor_rom + 8, 0x0300066c)

    # Function prefix establishes descriptor and state bases, initializes the
    # byte counter, then clears outputs before a descriptor-backed presence read.
    p = _Thumb(image, function)
    p.pool = 0x800
    p.emit(0xb580)                         # PUSH {r7,lr}
    p.literal(7, descriptor_ok if descriptor else ram + 0x3f0000)
    p.literal(4, state)
    p.emit(0x2000)                         # MOVS r0,#0
    if contact:
        p.emit(0x7000 | ((sample_offset & 31) << 6) | (4 << 3)) # clear event byte
        p.emit(0x7800 | ((sample_offset & 31) << 6) | (4 << 3)) # LDRB event
        p.emit(0x2800)                     # CMP r0,#0
        p.branch("contact_read", 0 if numeric_gate else 1) # BEQ to contact read
        p.jump("finish")                  # nonzero event skips numeric scan
        p.label("contact_read")
        p.emit(0x6b78)                     # LDR r0,[r7,#0x34]
        p.emit(0x8800)                     # LDRH r0,[r0]
        p.emit(0x0940 if contact_bit else 0x0900) # LSRS r0,r0,#5 (or wrong #4)
        p.branch("low_store" if contact_high_to_low else "continue",
                 2 if contact_branch else 1) # BHS around the low event store
        p.label("low_store")
        p.emit(0x2073)                     # MOVS r0,#0x73
        event_store = 0x7000 | ((sample_offset & 31) << 6) | (4 << 3)
        p.emit(event_store if contact_field else event_store ^ 0x0800)
        p.jump("finish")                  # B to bounded scanner exit
        p.label("continue")
        p.emit(0x2000)                     # MOVS r0,#0 before counter init
    if counter_init:
        p.emit(0x7000 | ((counter_offset & 31) << 6) | (4 << 3)) # STRB r0,[r4,#counter]
    p.bl(clear_entry if clear else 0x8a0)
    p.emit(0x6b78)                         # LDR r0,[r7,#0x34]
    p.emit(0x8800)                         # LDRH r0,[r0]
    p.emit(0x0700)                         # LSLS r0,r0,#28
    p.emit(0x0f00)                         # LSRS r0,r0,#28
    p.emit(0x280f)                         # CMP r0,#15
    p.branch("dispatch", 0)               # BEQ dispatch
    p.jump("dispatch")
    while p.pc < dispatch:
        p.emit(0x46c0)
    p.label("dispatch")
    assert p.pc == dispatch

    # Computed six-way dispatch: the ROM halfword table contains offsets from
    # ADD PC's architectural PC. Each arm changes one distinct active-low pin.
    _put16(image, dispatch, 0x2806)         # CMP r0,#6
    _branch(image, dispatch + 2, 10, sense) # BGE to sample/lookup
    _put16(image, dispatch + 4, 0xa103)     # ADR r1, dispatch table
    _put16(image, dispatch + 6, 0x0042)     # LSLS r2,r0,#1
    _put16(image, dispatch + 8, 0x1889)     # ADDS r1,r1,r2
    _put16(image, dispatch + 10, 0x880a)    # LDRH r2,[r1]
    _put16(image, dispatch + 12, 0x0052)    # LSLS r2,r2,#1
    _put16(image, dispatch + 14, 0x4497)    # ADD pc,r2

    # Place short, label-driven arms; the table entries are written below.
    cursor = arms_start
    masks = (0x0002, 0x0020, 0x0008, 0x0004, 0x0040, 0x0010)
    ports = (0x03000660, 0x03000664)
    selected = ((ports[0], masks[0]), (ports[1], masks[1]),
                (ports[0], masks[2]), (ports[1], masks[3]),
                (ports[0], masks[4]), (ports[1], masks[5]))
    arm_sites = []

    def literal(at, register, value, pool):
        displacement = pool - ((at + 4) & ~3)
        assert 0 <= displacement <= 1020 and displacement % 4 == 0
        _put16(image, at, 0x4800 | register << 8 | displacement // 4)
        _put32(image, pool, value)
        return at + 2

    literal_pool = 0x8c0
    for active_port, active_mask in selected:
        arm_sites.append(cursor)
        if clobber_state and len(arm_sites) == 1:
            _put16(image, cursor, 0x2400)   # Deliberately corrupt scanner state r4.
            cursor += 2
        for port, shadow_offset in ((ports[0], 0x0c), (ports[1], 0x1c)):
            if port == active_port:
                cursor = literal(cursor, 7, descriptor_ok, literal_pool); literal_pool += 4
                _put16(image, cursor, 0x8800 | ((shadow_offset // 2) << 6) | (7 << 3)); cursor += 2
                _put16(image, cursor, 0x21ff); cursor += 2
                _put16(image, cursor, 0x4308); cursor += 2
                _put16(image, cursor, 0x2100 | (active_mask & 255)); cursor += 2
                _put16(image, cursor, 0x4388); cursor += 2
                _put16(image, cursor, 0x8000 | ((shadow_offset // 2) << 6) | (7 << 3)); cursor += 2
            else:
                _put16(image, cursor, 0x20ff); cursor += 2
            cursor = literal(cursor, 2, port, literal_pool); literal_pool += 4
            _put16(image, cursor, 0x8010); cursor += 2
        _put16(image, cursor, 0xe000)        # jump to shared path
        cursor += 2
    # ADR points at the aligned table while ADD PC uses its own architectural
    # base two bytes before the first table entry.
    table = dispatch + 20
    for row, arm in enumerate(arm_sites):
        _put16(image, table + row * 2, (arm - (dispatch + 18)) // 2)
    common = cursor
    _put16(image, common, 0x46c0)           # harmless common fallthrough
    _jump(image, common, sense)
    for site in arm_sites:
        # Patch each arm's terminal branch to the common path.
        end = site
        # Locate the first unconditional branch within the arm by bounded scan.
        while _word16(image, end) & 0xf800 != 0xe000:
            end += 2
        _jump(image, end, common)

    # The descriptor read at sense is separately checked and is tied to the
    # copied source descriptor. The sample nibble is stored in the RAM state.
    _put16(image, sense - 2, 0x6b78)       # LDR r0,[r7,#0x34]
    _put16(image, sense, 0x8800)           # LDRH r0,[r0]
    _put16(image, sense + 2, 0x0700)
    _put16(image, sense + 4, 0x0f00)
    _put16(image, sense + 6, 0x7000 | ((sample_offset & 31) << 6) | (4 << 3))
    _put16(image, sense + 8, 0x0600)
    _put16(image, sense + 10, 0x0e00)
    _put16(image, sense + 12, 0x280f)

    # Raw column value -> column index -> column*6+row -> event byte.
    cursor = sense + 16
    column_literal = cursor
    _put16(image, cursor, 0); cursor += 2
    _put16(image, cursor, 0x5c10); cursor += 2
    _put16(image, cursor, 0x2106); cursor += 2
    _put16(image, cursor, 0x4348); cursor += 2
    _put16(image, cursor, 0x7801 | ((counter_offset & 31) << 6) | (4 << 3)); cursor += 2
    _put16(image, cursor, 0x1840); cursor += 2
    event_literal = cursor
    _put16(image, cursor, 0); cursor += 2
    event_load = cursor
    _put16(image, cursor, 0x5c13); cursor += 2
    if contact:
        _put16(image, cursor, 0x7000 | ((sample_offset & 31) << 6) | (4 << 3) | 3)
        cursor += 2
    footer = cursor
    finish = footer + 14
    load = 0x7800 | (counter_offset << 6) | (4 << 3)
    _put16(image, footer, load)
    _put16(image, footer + 2, 0x3001)
    _put16(image, footer + 4, load ^ 0x0800 if counter_store else 0x7000 | ((counter_offset + 1) << 6) | (4 << 3))
    _put16(image, footer + 6, load)
    _put16(image, footer + 8, 0x2800 | (counter_bound & 255))
    _branch(image, footer + 10, 10, finish)
    _jump(image, footer + 12, dispatch if counter_backedge else finish)
    _branch(image, sense + 14, 0, footer)
    _put16(image, finish, 0xbc80)
    _put16(image, finish + 2, 0xbc08)
    _put16(image, finish + 4, 0x4718)
    if contact:
        p.labels["finish"] = finish
    p.finish()

    # Descriptor and table data are synthetic ROM bytes, independent of any
    # firmware image. Numeric events are column-major and individually mapped.
    colmap = bytearray(16)
    for raw, col in zip((14, 13, 11, 7), range(4)):
        colmap[raw] = col
    if duplicate_column:
        colmap[13] = colmap[14]
    if column_table:
        image[column_rom:column_rom + 16] = colmap
    if event_table:
        image[events_rom:events_rom + 24] = b"147*2580369#" + bytes(range(0x50, 0x5c))

    _put32(image, column_pointer, column_rom)
    _put32(image, events_pointer, events_rom)
    displacement = column_pointer - ((column_literal + 4) & ~3)
    _put16(image, column_literal, 0x4a00 | (displacement // 4))
    displacement = events_pointer - ((event_literal + 4) & ~3)
    _put16(image, event_literal, 0x4a00 | (displacement // 4))

    if clear:
        # Bounded all-row release/commit helper; final POP sequence restores
        # saved r7 and the incoming return address through r3.
        c = _Thumb(image, clear_entry)
        c.pool = 0xb00
        c.emit(0xb580)
        c.bl(0x1000)
        c.literal(7, descriptor_ok)
        if clear_clobber:
            c.emit(0x2500)                 # Deliberately corrupt unsaved r5.
        for port, shadow_offset, rowmask in ((ports[0], 0x0c, 0x4a),
                                              (ports[1], 0x1c, 0x34)):
            c.emit(0x8800 | ((shadow_offset // 2) << 6) | (7 << 3) | 2)
            c.emit(0x2300 | rowmask)
            c.emit(0x439a)                 # BICS r2,r3
            c.emit(0x8000 | ((shadow_offset // 2) << 6) | (7 << 3) | 2)
            c.literal(0, port)
            c.emit(0x8002)                 # STRH r2,[r0]
        c.bl(0x1020)
        c.emit(0xbc80)
        c.emit(0xbc08)
        c.emit(0x4718)
        c.finish()
    _irq_helper(image, 0x1000, enable=False)
    _irq_helper(image, 0x1020, enable=True)
    return image, {"descriptor": descriptor_ok, "state": state, "dispatch": dispatch,
                   "sense": sense, "footer": footer, "finish": finish,
                   "event_load": event_load, "column": column_rom,
                   "events": events_rom, "counter": counter_offset,
                   "sample": sample_offset, "clear": clear_entry}


def _word16(image, at):
    return struct.unpack_from("<H", image, at)[0]


class DispatchRowScannerTests(unittest.TestCase):
    def setUp(self):
        self.config = SimpleNamespace(load_address=0, ram_base=0x01000000,
            ram_size=0x00800000, flash_size=0x3000, board_status_input=None)

    def test_computed_six_row_scan_maps_numeric_contacts(self):
        image, points = _fixture()
        found = find_dispatch_row_scanners(bytes(image), self.config)
        self.assertEqual(len(found), 1)
        profile = found[0]
        self.assertEqual(profile["grammar"], "descriptor-dispatch-six-row-v1")
        self.assertEqual((profile["rows"], profile["columns"]), (6, 4))
        self.assertEqual(profile["descriptor"], points["descriptor"])
        self.assertEqual(profile["row_ports"], [0x03000660, 0x03000664])
        self.assertEqual(profile["row_masks"], [0x4a, 0x34])
        self.assertEqual(profile["single_key_column_sense"], [14, 13, 11, 7])
        self.assertEqual(profile["event_codes"][:12], list(b"147*2580369#"))
        owner = SimpleNamespace(matrix_input_profile=profile)
        for column in range(4):
            for row in range(6):
                event = profile["event_codes"][column * 6 + row]
                if event in b"123456789*0#":
                    position = _matrix_input_position(owner, event, event)
                    self.assertEqual(position, (event, row, column))
                    self.assertEqual(matrix_input_command(profile, position, True),
                                     bytes((HOST_INPUT, 1,
                                            profile["row_wire_order"][row],
                                            (14, 13, 11, 7)[column])))
        prop, admitted = dispatch_row_property(bytes(image), self.config)
        self.assertTrue(prop.startswith("matrix-halfword-wires="))
        self.assertEqual(admitted, profile)

    def test_rejects_counter_contract_mutations(self):
        for options in ({"counter_init": False}, {"counter_store": False},
                        {"counter_backedge": False}, {"counter_bound": 5},
                        {"counter_offset": 0x0e}):
            image, _ = _fixture(**options)
            with self.subTest(options=options):
                self.assertEqual(find_dispatch_row_scanners(bytes(image), self.config), [])

    def test_rejects_wrong_sense_lookup_or_duplicate_mapping(self):
        for options in ({"sense_source": False}, {"column_table": False},
                        {"duplicate_column": True}, {"event_table": False}):
            image, _ = _fixture(**options)
            with self.subTest(options=options):
                self.assertEqual(find_dispatch_row_scanners(bytes(image), self.config), [])

    def test_requires_clear_descriptor_reset_copy_and_in_bounds_state(self):
        for options in ({"clear": False}, {"descriptor": False},
                        {"reset_copy": False}, {"state_in_bounds": False}):
            image, _ = _fixture(**options)
            with self.subTest(options=options):
                self.assertEqual(find_dispatch_row_scanners(bytes(image), self.config), [])

    def test_preserves_scanner_state_clear_saved_registers_and_distinct_banks(self):
        for options in ({"clobber_state": True}, {"clear_clobber": True},
                        {"overlap_state_descriptor": True}):
            image, _ = _fixture(**options)
            with self.subTest(options=options):
                self.assertEqual(find_dispatch_row_scanners(bytes(image), self.config), [])

    def test_property_rejects_status_conflicts_and_dependency_overrun(self):
        image, _ = _fixture()
        self.config.board_status_input = SimpleNamespace(address=0x03000660)
        self.assertEqual(dispatch_row_property(bytes(image), self.config), (None, None))
        self.config.board_status_input = None
        self.config.flash_size = 0x100
        self.assertEqual(dispatch_row_property(bytes(image), self.config), (None, None))

    def test_optional_contact_requires_descriptor_bit_gate_and_shared_event_field(self):
        image, _ = _fixture(contact=True)
        profile = find_dispatch_row_scanners(bytes(image), self.config)[0]
        self.assertEqual(profile["released_contact"]["grammar"],
                         "state-event-matrix-contact-v1")
        prop, _ = dispatch_row_property(bytes(image), self.config)
        self.assertIn("experimental-matrix-contact=", prop)
        for options in ({"contact_bit": False}, {"contact_branch": False},
                        {"contact_field": False}, {"numeric_gate": False}):
            broken, _ = _fixture(contact=True, **options)
            profiles = find_dispatch_row_scanners(bytes(broken), self.config)
            self.assertEqual(len(profiles), 1)
            self.assertIsNone(profiles[0]["released_contact"])
            prop, _ = dispatch_row_property(bytes(broken), self.config)
            self.assertNotIn("experimental-matrix-contact=", prop)
        high_path, _ = _fixture(contact=True, contact_high_to_low=True)
        self.assertEqual(find_dispatch_row_scanners(bytes(high_path), self.config), [])


if __name__ == "__main__":
    unittest.main()
