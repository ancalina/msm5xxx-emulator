"""Synthetic instruction proofs for alternate sparse-matrix presence reads."""
from __future__ import annotations

import struct
import unittest

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.devices.input.sparse_presence import (
    nibble_read_sites,
    presence_for_loop,
    released_contact,
)
from msm5xxx_emulator.detection.devices.input.sparse_rows import (
    _coalesce_wire_profiles,
)


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value)


def _put32(image, address, value):
    struct.pack_into("<I", image, address, value)


def _branch(image, site, condition, target):
    delta = (target - site - 4) // 2
    assert -128 <= delta <= 127
    _put16(image, site, 0xD000 | (condition << 8) | (delta & 0xff))


def _bl(image, site, target):
    delta = target - site - 4
    assert delta % 2 == 0
    _put16(image, site, 0xf000 | ((delta >> 12) & 0x7ff))
    _put16(image, site + 2, 0xf800 | ((delta >> 1) & 0x7ff))


def _literal_load(image, site, register, pool):
    displacement = pool - ((site + 4) & ~3)
    assert 0 <= displacement <= 1020 and displacement % 4 == 0
    _put16(image, site, 0x4800 | (register << 8) | (displacement // 4))


def _fixture(*, pointer=0x1000, sense_fields=(0x03000500, 0x03000500),
             event_value=0x51, clobber_sample=False, clobber_flags=False,
             clobber_event=False, state=0x1100, status_condition=2,
             handler_target=0x122, second_state=None):
    image = bytearray(0x400)
    _literal_load(image, 0x100, 4, 0x180)
    _put16(image, 0x102, 0x6b61)  # LDR r1,[r4,#0x34]
    _put16(image, 0x104, 0x8808)  # LDRH r0,[r1]
    _literal_load(image, 0x106, 3, 0x184)
    _put16(image, 0x108, 0x0940)  # LSRS r0,r0,#5
    _branch(image, 0x10a, status_condition, 0x110)
    _put16(image, 0x10c, 0x2700 | event_value)  # MOVS r7,event
    _put16(image, 0x10e, 0xe000 | ((handler_target - 0x112) // 2))
    _put16(image, 0x110, 0x8808)  # LDRH r0,[r1]
    _put16(image, 0x112, 0x0722 if clobber_sample else 0x0702)
    _literal_load(image, 0x114, 3, 0x184)
    _put16(image, 0x116, 0x0f12)  # LSRS r2,r2,#28
    _put16(image, 0x118, 0x2a0f)  # CMP r2,#15
    if clobber_flags:
        _put16(image, 0x11a, 0x2301)  # MOVS r3,#1 clobbers flags
        _branch(image, 0x11c, 1, 0x120)
        _put16(image, 0x11e, 0x4770)
        _put16(image, 0x120, 0x781f)  # LDRB r7,[r3]: numeric event source.
    else:
        _branch(image, 0x11a, 1, 0x120)
        _put16(image, 0x11c, 0x4770)
        _put16(image, 0x120, 0x781f)  # LDRB r7,[r3]: numeric event source.
    _literal_load(image, 0x122, 2, 0x188)
    store = 0x126 if clobber_event else 0x124
    if clobber_event:
        _put16(image, 0x124, 0x2700)  # MOVS r7,#0 on the event route
    _put16(image, store, 0x7117)  # STRB r7,[r2,#4]
    if second_state is None:
        _put16(image, store + 2, 0x4770)
    else:
        _literal_load(image, store + 2, 3, 0x18c)
        _put16(image, store + 4, 0x711f)  # STRB r7,[r3,#4]
        _put16(image, store + 6, 0x4770)
    _put16(image, 0x12a, 0x4770)
    _put32(image, 0x180, pointer)
    _put32(image, 0x184, 0x350)
    _put32(image, 0x188, state)
    _put32(image, 0x18c, second_state or 0)
    _put32(image, 0x208, sense_fields[0])
    _put32(image, 0x234, sense_fields[1])
    image[0x350] = ord("1")
    return image


def _facts(image):
    facts = facts_for(image)
    function = facts.function(CodeAddress(0x100, "thumb"), budget=256)
    if not function.complete or function.unresolved:
        raise AssertionError((function.complete, function.unresolved))
    return facts, function


class SparsePresenceProofTests(unittest.TestCase):
    def test_transferred_nibble_accepts_literal_interposition_without_flag_clobber(self):
        image = _fixture()
        facts, function = _facts(image)
        samples = nibble_read_sites(facts, function, 0x1000)
        self.assertEqual([(sample["read_site"], sample["compare_site"],
                           sample["branch_site"]) for sample in samples],
                         [(0x110, 0x118, 0x11a)])

    def test_nibble_rejects_wrong_field_clobbered_value_and_flags(self):
        for image, descriptor in (
                (_fixture(), 0x1010),
                (_fixture(clobber_sample=True), 0x1000),
                (_fixture(clobber_flags=True), 0x1000),
                (_fixture(pointer=0x1030), 0x1000)):
            facts, function = _facts(image)
            with self.subTest(descriptor=descriptor, bytes=image[0x110:0x11c]):
                self.assertEqual(nibble_read_sites(facts, function, descriptor), ())
        other_field = _fixture()
        _put16(other_field, 0x102, 0x6b21)  # LDR r1,[r4,#0x30]
        facts, function = _facts(other_field)
        self.assertEqual(nibble_read_sites(facts, function, 0x1000), ())

    def test_presence_selects_nearest_reaching_source_without_dominance(self):
        entry = CodeAddress(0x100, "thumb")
        first_branch = CodeAddress(0x106, "thumb")
        second_branch = CodeAddress(0x112, "thumb")
        first_loop = CodeAddress(0x120, "thumb")
        second_loop = CodeAddress(0x130, "thumb")
        function = type("Graph", (), {
            "instructions": (entry, first_branch, second_branch, first_loop, second_loop),
            "control_edges": ((entry, first_branch), (entry, second_branch),
                              (first_branch, first_loop), (second_branch, second_loop)),
        })()
        samples = ({"read_site": 0x102, "branch_site": 0x106},
                   {"read_site": 0x110, "branch_site": 0x112})
        self.assertEqual(presence_for_loop(None, function, samples, 0x120), 0x102)
        self.assertEqual(presence_for_loop(None, function, samples, 0x130), 0x110)

    def test_released_contact_links_event_to_ram_state_and_keeps_high_route(self):
        image = _fixture()
        facts, function = _facts(image)
        samples = nibble_read_sites(facts, function, 0x1000)
        contact = released_contact(
            image, facts, function, 0x1000, 0x200, 0x03000500,
            samples, 0x1000, 0x2000, len(image),
            event_register=7, event_load_site=0x120)
        self.assertIsNotNone(contact)
        self.assertEqual(contact["status_site"], 0x104)
        self.assertEqual(contact["released_level"], 0x10)
        self.assertEqual(contact["state_ranges"], [(0x1100, 5)])
        self.assertEqual(contact["event_store_site"], 0x124)
        self.assertEqual(contact["event_register"], 7)
        self.assertEqual(contact["event_state_address"], 0x1104)

    def test_contact_rejects_nonaliased_fields_event_clobber_wrong_event_and_unbounded_state(self):
        for image, descriptor, base, end in (
                (_fixture(sense_fields=(0x03000500, 0x03000504)), 0x1000, 0x1000, 0x2000),
                (_fixture(clobber_event=True), 0x1000, 0x1000, 0x2000),
                (_fixture(event_value=0x52), 0x1000, 0x1000, 0x2000),
                (_fixture(second_state=0x1200), 0x1000, 0x1000, 0x2000),
                (_fixture(handler_target=0x12a), 0x1000, 0x1000, 0x2000),
                (_fixture(state=0x3000), 0x1000, 0x1000, 0x2000),
                (_fixture(status_condition=0), 0x1000, 0x1000, 0x2000)):
            facts, function = _facts(image)
            samples = nibble_read_sites(facts, function, descriptor)
            with self.subTest(descriptor=descriptor, state=base):
                self.assertIsNone(released_contact(
                    image, facts, function, descriptor, 0x200,
                    0x03000500, samples, base, end, len(image),
                    event_register=7, event_load_site=0x120))

    def test_auxiliary_event_cannot_use_an_unrelated_register(self):
        image = _fixture()
        _put16(image, 0x10c, 0x2651)  # MOVS r6,#separate event.
        _put16(image, 0x124, 0x7116)  # STRB r6,[r2,#4].
        facts, function = _facts(image)
        self.assertIsNone(released_contact(
            image, facts, function, 0x1000, 0x200, 0x03000500,
            nibble_read_sites(facts, function, 0x1000),
            0x1000, 0x2000, len(image), event_register=7,
            event_load_site=0x120))

    def test_auxiliary_event_does_not_survive_unmodeled_callee(self):
        image = _fixture()
        _bl(image, 0x122, 0x160)
        _literal_load(image, 0x126, 2, 0x188)
        _put16(image, 0x128, 0x7117)  # STRB r7,[r2,#4] after the call.
        _put16(image, 0x12a, 0x4770)
        _put16(image, 0x160, 0x2700)  # Callee clobbers R7.
        _put16(image, 0x162, 0x4770)
        facts, function = _facts(image)
        self.assertTrue(any(site.address == 0x122 for site, _ in function.calls))
        self.assertIsNone(released_contact(
            image, facts, function, 0x1000, 0x200, 0x03000500,
            nibble_read_sites(facts, function, 0x1000),
            0x1000, 0x2000, len(image), event_register=7,
            event_load_site=0x120))

    def test_saved_register_leaf_callee_proves_event_preservation(self):
        image = _fixture()
        _bl(image, 0x122, 0x160)
        _literal_load(image, 0x126, 2, 0x188)
        _put16(image, 0x128, 0x7117)  # STRB r7,[r2,#4] after the call.
        _put16(image, 0x12a, 0x4770)
        _put16(image, 0x160, 0xb580)  # PUSH {r7,lr}.
        _put16(image, 0x162, 0x46c0)  # NOP inside the saved frame.
        _put16(image, 0x164, 0xbd80)  # POP {r7,pc} restores and returns.
        facts, function = _facts(image)
        contact = released_contact(
            image, facts, function, 0x1000, 0x200, 0x03000500,
            nibble_read_sites(facts, function, 0x1000),
            0x1000, 0x2000, len(image), event_register=7,
            event_load_site=0x120)
        self.assertIsNotNone(contact)
        self.assertEqual(contact["event_store_site"], 0x128)
        self.assertTrue({(0x160, 2), (0x162, 2), (0x164, 2)}
                        <= set(contact["dependencies"]))

    def test_predicated_callee_frame_does_not_prove_event_preservation(self):
        image = _fixture()
        _bl(image, 0x122, 0x160)
        _literal_load(image, 0x126, 2, 0x188)
        _put16(image, 0x128, 0x7117)  # STRB r7,[r2,#4] after the call.
        _put16(image, 0x12a, 0x4770)
        _put16(image, 0x160, 0xbf08)  # IT EQ: the following PUSH is conditional.
        _put16(image, 0x162, 0xb580)  # PUSH {r7,lr} only when Z is set.
        _put16(image, 0x164, 0xbd80)  # POP {r7,pc} executes on either route.
        facts, function = _facts(image)
        self.assertIsNone(released_contact(
            image, facts, function, 0x1000, 0x200, 0x03000500,
            nibble_read_sites(facts, function, 0x1000),
            0x1000, 0x2000, len(image), event_register=7,
            event_load_site=0x120))

    def test_saved_frame_proof_checks_every_numeric_byte(self):
        image = _fixture()
        _bl(image, 0x122, 0x160)
        _literal_load(image, 0x126, 2, 0x188)
        _put16(image, 0x128, 0x7117)  # STRB r7,[r2,#4] after the call.
        _put16(image, 0x12a, 0x4770)
        _put16(image, 0x160, 0xb580)  # PUSH {r7,lr}.
        _put16(image, 0x162, 0x2f51)  # CMP r7,#0x51.
        _branch(image, 0x164, 0, 0x16a)  # Only 0x51 skips the stack write.
        _put16(image, 0x166, 0x2000)  # MOVS r0,#0.
        _put16(image, 0x168, 0x9000)  # STR r0,[sp,#0] clobbers saved R7.
        _put16(image, 0x16a, 0xbc80)  # POP {r7}.
        _put16(image, 0x16c, 0xbc01)  # POP {r0}.
        _put16(image, 0x16e, 0x4700)  # BX r0.
        facts, function = _facts(image)
        from msm5xxx_emulator.detection.devices.input.five_column_flow import (
            _saved_frame_call,
        )
        self.assertIsNotNone(_saved_frame_call(
            image, 0x160, a.ARM_REG_R7, (0x51,), 0x1000, 0x200))
        self.assertIsNone(_saved_frame_call(
            image, 0x160, a.ARM_REG_R7, tuple(range(256)), 0x1000, 0x200))
        self.assertIsNone(released_contact(
            image, facts, function, 0x1000, 0x200, 0x03000500,
            nibble_read_sites(facts, function, 0x1000),
            0x1000, 0x2000, len(image), event_register=7,
            event_load_site=0x120))

    def test_numeric_and_auxiliary_events_must_share_the_state_store(self):
        image = _fixture()
        _branch(image, 0x11a, 1, 0x130)
        _put16(image, 0x130, 0x781f)
        _literal_load(image, 0x132, 2, 0x18c)
        _put32(image, 0x18c, 0x1200)
        _put16(image, 0x134, 0x7117)
        _put16(image, 0x136, 0x4770)
        facts, function = _facts(image)
        self.assertIsNone(released_contact(
            image, facts, function, 0x1000, 0x200, 0x03000500,
            nibble_read_sites(facts, function, 0x1000),
            0x1000, 0x2000, len(image), event_register=7,
            event_load_site=0x130))

    def test_coalescing_requires_same_numeric_wires_and_auxiliary_source(self):
        def profile(presence, sense, port=0x3000060, contact=0x142):
            return {
                "grammar": "sparse-halfword-six-row-v1", "descriptor": 0x1000,
                "sense_address": 0x03000500, "rows": 6, "columns": 4,
                "row_ports": [port, 0x3000068], "row_masks": [0x20, 0x1f],
                "row_wire_order": [1, 2, 3, 4, 5, 0],
                "event_codes": list(b"123456789*0#") + [0] * 12,
                "single_key_column_sense": [14, 13, 11, 7],
                "presence_site": presence, "sense_site": sense,
                "event_load_site": sense + 12, "event_register": 7,
                "dependencies": [], "ram_dependencies": [],
                "released_contact": {"status_site": contact, "released_level": 0x10},
            }

        valid = _coalesce_wire_profiles((profile(0x110, 0x120),
                                         profile(0x130, 0x140)))
        self.assertIsNotNone(valid)
        self.assertEqual(len(valid["source_sites"]), 2)
        self.assertIsNone(_coalesce_wire_profiles((profile(0x110, 0x120),
                                                   profile(0x130, 0x140, port=0x3000070))))
        self.assertIsNone(_coalesce_wire_profiles((profile(0x110, 0x120),
                                                   profile(0x130, 0x140, contact=0x150))))


if __name__ == "__main__":
    unittest.main()
