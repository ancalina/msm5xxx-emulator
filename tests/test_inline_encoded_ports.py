"""Synthetic source fixtures for the inline encoded keypad grammar."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.input.encoded_poller import (
    _inline_profile,
    find_inline_encoded_port_profiles,
)
from msm5xxx_emulator.detection.devices.input.encoded_ports import (
    _descriptor_sources,
    encoded_ports_property,
)
from msm5xxx_emulator.detection.facts import facts_for


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value & 0xFFFF)


def _put32(image, address, value):
    struct.pack_into("<I", image, address, value & 0xFFFFFFFF)


def _b16(site, target, condition=None):
    delta = target - site - 4
    assert delta % 2 == 0
    if condition is None:
        assert -2048 <= delta // 2 <= 2047
        return 0xE000 | ((delta // 2) & 0x7FF)
    assert -256 <= delta // 2 <= 255
    return 0xD000 | (condition << 8) | ((delta // 2) & 0xFF)


def _bl(image, site, target):
    delta = target - site - 4
    assert delta % 2 == 0
    _put16(image, site, 0xF000 | ((delta >> 12) & 0x7FF))
    _put16(image, site + 2, 0xF800 | ((delta >> 1) & 0x7FF))


def _ldr_literal(image, site, register, pool):
    displacement = pool - ((site + 4) & ~3)
    assert 0 <= displacement <= 1020 and displacement % 4 == 0
    _put16(image, site, 0x4800 | (register << 8) | (displacement // 4))


def _ldr_word(rt, rn, offset):
    assert offset % 4 == 0 and 0 <= offset <= 124
    return 0x6800 | ((offset // 4) << 6) | (rn << 3) | rt


def _ldrh(rt, rn, offset=0):
    assert offset % 2 == 0 and 0 <= offset <= 62
    return 0x8800 | ((offset // 2) << 6) | (rn << 3) | rt


def _ldrb(rt, rn, offset=0):
    assert 0 <= offset <= 31
    return 0x7800 | (offset << 6) | (rn << 3) | rt


def _strb(rt, rn, offset=0):
    assert 0 <= offset <= 31
    return 0x7000 | (offset << 6) | (rn << 3) | rt


def _add_reg(rd, rn, rm):
    return 0x1800 | (rm << 6) | (rn << 3) | rd


def _lsl(rd, rm, amount):
    return (amount << 6) | (rm << 3) | rd


def _lsr(rd, rm, amount):
    return 0x0800 | (amount << 6) | (rm << 3) | rd


def _and(rd, rm):
    return 0x4000 | (rm << 3) | rd


def _orr(rd, rm):
    return 0x4300 | (rm << 3) | rd


def _cmp_reg(rn, rm):
    return 0x4280 | (rm << 3) | rn


def _profile_image():
    """Assemble a compact independent Thumb poller and callback chain."""
    image = bytearray(0x1000)
    entry, descriptor, source = 0x100, 0x01000200, 0x900
    table, dispatch, producer, callback = 0xA00, 0, 0x400, 0x480
    pool_descriptor, pool_table = 0x300, 0x304
    pc = entry
    labels, branches = {}, []

    def label(name):
        assert name not in labels
        labels[name] = pc

    def emit(word):
        nonlocal pc
        _put16(image, pc, word)
        pc += 2

    def branch(name, condition=None):
        nonlocal pc
        branches.append((pc, name, condition))
        emit(0)

    emit(0xB500)                        # Preserve entry LR across producer calls.
    # Descriptor backed presence gate. Low is an independent queued event;
    # high falls through to the idle check and numeric scanner.
    _ldr_literal(image, pc, 0, pool_descriptor)
    pc += 2
    emit(_ldr_word(2, 0, 0x24))
    aux_site = pc
    emit(_ldrh(1, 2))
    emit(_lsr(1, 1, 1))
    branch("high", 2)                  # BHS
    emit(0x2700 | 0x6F)                 # MOVS R7, #separate event
    branch("dispatch")
    label("high")

    # Descriptor backed p34 idle sentinel, then pointers for inline packing.
    emit(_ldr_word(3, 0, 0x34))
    emit(_ldrh(4, 3))
    emit(_lsl(4, 4, 28))
    emit(_lsr(4, 4, 28))
    emit(0x2800 | (4 << 8) | 0x0F)
    branch("dispatch", 0)              # BEQ
    emit(_ldr_word(2, 0, 0x24))
    emit(_ldr_word(0, 0, 0x34))

    row_site = pc
    # Inline pack: p24 bits 1..3 and p34 bits 0..4, narrowed to one byte.
    for word in (_ldrh(1, 2), 0x231E, _and(1, 3), _lsl(1, 1, 4),
                 0x227F, _ldrh(0, 0), _lsl(2, 2, 9), _orr(1, 2),
                 _lsl(0, 0, 27), _lsr(0, 0, 27), _orr(0, 1),
                 _lsl(1, 0, 24), _lsr(1, 1, 24)):
        emit(word)
    sense_site = row_site + 10

    # 19 x 3-byte event lookup. The compare branches to the increment path;
    # a match loads the event token and dispatches it.
    lookup = pc
    _ldr_literal(image, pc, 2, pool_table)
    pc += 2
    for word in (0x2000, _lsl(3, 0, 1), _add_reg(3, 3, 0),
                 _add_reg(3, 3, 2), _ldrb(3, 3, 1), _cmp_reg(3, 1)):
        emit(word)
    branch("increment", 1)             # BNE
    for word in (_lsl(3, 0, 1), _add_reg(0, 3, 0), _add_reg(0, 0, 2),
                 _ldrb(7, 0, 2)):
        emit(word)
    branch("dispatch")
    label("increment")
    emit(0x3001)                        # ADDS R0,#1
    emit(_lsl(0, 0, 24))
    emit(_lsr(0, 0, 24))
    emit(0x2800 | 0x13)                 # CMP R0,#19
    branch("lookup+4", 11)             # BLT back to index*3
    label("dispatch")
    dispatch = labels["dispatch"]

    # Stateful auxiliary dispatcher checks the retained event against context
    # state, then forwards R7 in R0 to the source-proved callback producer.
    emit(_ldrb(1, 0, 3))
    emit(_cmp_reg(7, 1))
    branch("no_event", 1)              # BNE
    emit(0x2103)                        # MOVS R1,#3
    emit(_strb(1, 0, 2))
    emit(0x1C38)                        # ADDS R0,R7,#0
    _bl(image, pc, producer)
    pc += 4
    emit(0xBD00)
    label("no_event")
    emit(0xBD00)

    for site, name, condition in branches:
        target = labels[name] if name in labels else lookup + int(name[6:])
        _put16(image, site, _b16(site, target, condition))

    # Strict event producer and indirect callback stub, assembled from Thumb
    # instructions with synthetic state literals.
    words = (0xB5B8, 0x1C07, 0x4800, 0x4D00, 0x7800, 0x2800,
             0xD00A, 0x6B29, 0x2900, 0xD007, 0xAB00, 0x701F,
             0x9800)
    for i, word in enumerate(words):
        _put16(image, producer + 2 * i, word)
    _ldr_literal(image, producer + 4, 0, 0x520)
    _ldr_literal(image, producer + 6, 5, 0x524)
    _put32(image, 0x520, 0x01000240)
    _put32(image, 0x524, 0x01000260)
    _bl(image, producer + 0x1A, callback)
    _put16(image, producer + 0x1E, _b16(producer + 0x1E, producer + 0x24))
    _put16(image, producer + 0x24, 0xBDB8)
    _put16(image, callback, 0x4708)     # BX R1

    _put32(image, pool_descriptor, descriptor)
    _put32(image, pool_table, table)
    for offset, value in ((0x20, 0x03000728), (0x24, 0x03000728),
                          (0x34, 0x0300072C)):
        _put32(image, source + offset, value)
    tokens = b"123456789*0#" + bytes((1, 2, 3, 4, 5, 6, 7))
    for index, token in enumerate(tokens):
        image[table + 3 * index:table + 3 * index + 3] = bytes(
            (0x80 + index, 0x20 + index, token))
    return image, {"entry": entry, "descriptor": descriptor,
        "source": source, "table": table, "row": row_site,
        "sense": sense_site, "idle": labels["high"] + 2,
        "aux": aux_site, "dispatch": dispatch,
        "producer": producer, "callback": callback,
        "lookup": lookup, "pool_descriptor": pool_descriptor}


class InlineEncodedPortsTests(unittest.TestCase):
    def _profile(self, image, loc):
        return _inline_profile(image, facts_for(image), loc["entry"],
            loc["descriptor"], [loc["source"]], len(image))

    def test_synthetic_inline_source_has_five_distinct_live_sites(self):
        image, loc = _profile_image()
        profile = self._profile(image, loc)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["descriptor"], loc["descriptor"])
        self.assertEqual(profile["row_read_site"], loc["row"])
        self.assertEqual(profile["sense_read_site"], loc["sense"])
        self.assertEqual(profile["idle_site"], loc["idle"])
        self.assertEqual(profile["aux_read_site"], loc["aux"])
        self.assertEqual(len({profile["descriptor"], profile["row_read_site"],
            profile["sense_read_site"], profile["idle_site"],
            profile["aux_read_site"]}), 5)
        self.assertEqual(profile["event_table"], loc["table"])
        self.assertEqual(len(profile["event_records"]), 19)
        self.assertEqual(profile["producer"], loc["producer"])
        self.assertEqual(profile["producer_call_site"], profile["aux_dispatch_site"])
        self.assertEqual(profile["callback_stub"], loc["callback"])
        self.assertTrue(all(0 <= at < len(image) and 0 < size <= len(image) - at
                            for at, size in profile["dependencies"]))

    def test_descriptor_literal_must_match_live_descriptor_provenance(self):
        image, loc = _profile_image()
        self.assertIsNone(_inline_profile(image, facts_for(image), loc["entry"],
            loc["descriptor"] + 4, [loc["source"]], len(image)))

    def test_pack_must_narrow_the_cross_byte_value(self):
        image, loc = _profile_image()
        struct.pack_into("<H", image, loc["sense"] + 12, 0x0E09 ^ 0x0040)
        self.assertIsNone(self._profile(image, loc))

    def test_lookup_cannot_bypass_the_packed_value(self):
        image, loc = _profile_image()
        site = loc["idle"] + 10
        _put16(image, site, _b16(site, loc["lookup"], 0))
        self.assertIsNone(self._profile(image, loc))

    def test_callback_spill_and_reload_keep_the_event_byte(self):
        mutations = ((22, _strb(7, 2)), (22, _strb(6, 3)), (24, 0x9801))
        for offset, word in mutations:
            with self.subTest(offset=offset, word=word):
                image, loc = _profile_image()
                _put16(image, loc["producer"] + offset, word)
                self.assertIsNone(self._profile(image, loc))

    def test_public_discovery_requires_configured_producer_state_ranges(self):
        image, _ = _profile_image()
        profiles = find_inline_encoded_port_profiles(image, flash_size=len(image),
            ram_base=0x01000000, ram_size=0x1000)
        self.assertEqual(len(profiles), 1)
        for enable, control in ((0x01800000, 0x01800020),
                                (0x01000240, 0x01000FD0)):
            with self.subTest(enable=enable, control=control):
                changed = bytearray(image)
                _put32(changed, 0x520, enable)
                _put32(changed, 0x524, control)
                self.assertEqual(find_inline_encoded_port_profiles(changed,
                    flash_size=len(changed), ram_base=0x01000000, ram_size=0x1000), [])

    def test_table_requires_exact_nineteen_record_bound(self):
        image, loc = _profile_image()
        # CMP immediate in the loop footer no longer agrees with the table.
        struct.pack_into("<H", image, loc["lookup"] + 34, 0x2812)
        self.assertIsNone(self._profile(image, loc))

    def test_table_requires_three_byte_record_addressing(self):
        image, loc = _profile_image()
        # Replace the index*2 step with index*4; record addresses are no longer
        # tied to the source's index*3 calculation.
        struct.pack_into("<H", image, loc["lookup"] + 2, _lsl(3, 0, 2))
        self.assertIsNone(self._profile(image, loc))

    def test_table_branch_must_keep_both_lookup_paths_in_the_closed_cfg(self):
        image, loc = _profile_image()
        branch_site = loc["lookup"] + 14
        # Send a mismatch directly to dispatch, bypassing bounded iteration.
        struct.pack_into("<H", image, branch_site,
                         _b16(branch_site, loc["dispatch"], 1))
        self.assertIsNone(self._profile(image, loc))

    def test_numeric_event_must_reach_the_proved_producer(self):
        image, loc = _profile_image()
        # Redirect the dispatcher BL away from the only producer in the chain.
        site = loc["dispatch"] + 12
        _bl(image, site, 0x440)
        self.assertIsNone(self._profile(image, loc))

    def test_dispatch_requires_event_in_r0_not_only_state_argument_r1(self):
        image, loc = _profile_image()
        # Turn ADDS R0,R7,#0 into ADDS R1,R7,#0, leaving only the state value
        # at the callback's event argument position.
        struct.pack_into("<H", image, loc["dispatch"] + 10, 0x1C39)
        self.assertIsNone(self._profile(image, loc))

    def test_aux_path_cannot_clobber_event_before_producer(self):
        image, loc = _profile_image()
        # Change the dispatcher equality check to use R6 rather than R7.
        struct.pack_into("<H", image, loc["dispatch"] + 2, _cmp_reg(6, 1))
        self.assertIsNone(self._profile(image, loc))

    def test_aux_event_must_share_the_numeric_producer_and_callback(self):
        image, loc = _profile_image()
        # Same event state, but the dispatcher calls an unrelated in-image
        # return stub instead of the callback producer.
        _bl(image, loc["dispatch"] + 12, 0x490)
        _put16(image, 0x490, 0x4770)
        self.assertIsNone(self._profile(image, loc))

    def test_property_rejects_event_table_past_flash_end(self):
        image, loc = _profile_image()
        profile = self._profile(image, loc)
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
            ram_size=0x10000, flash_size=loc["table"] + 56)

        class CopyProof:
            evidence = ()

            @staticmethod
            def source_address(address, size):
                return loc["source"] if (address, size) == (
                    loc["descriptor"], 0x38) else None

        with (patch("msm5xxx_emulator.detection.devices.input.encoded_ports.find_encoded_port_profiles",
                    return_value=[profile]),
              patch("msm5xxx_emulator.detection.devices.input.encoded_ports.reset_linked_input_copy",
                    return_value=CopyProof())):
            prop, admitted = encoded_ports_property(image, config)
        self.assertIsNone(prop)
        self.assertIsNone(admitted)

    def test_inline_profile_requires_reset_linked_descriptor_copy(self):
        image, loc = _profile_image()
        profile = self._profile(image, loc)
        config = SimpleNamespace(load_address=0, ram_base=0x01000000,
            ram_size=0x10000, flash_size=len(image))
        with (patch("msm5xxx_emulator.detection.devices.input.encoded_ports.find_encoded_port_profiles",
                    return_value=[profile]),
              patch("msm5xxx_emulator.detection.devices.input.encoded_ports.reset_linked_input_copy",
                    return_value=None)):
            prop, admitted = encoded_ports_property(image, config)
        self.assertIsNone(prop)
        self.assertIsNone(admitted)


if __name__ == "__main__":
    unittest.main()
