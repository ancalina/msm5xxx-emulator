"""Generated source checks for the word-interface external windows."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.devices.storage.boot_nand_word_windows import (
    _callers,
    _constructors,
    _interworking_evidence,
    _owners_with_accesses,
    _pointer_field,
    _typed_502_control,
    _typed_502_evidence,
    _linked_owners,
    _partial_callers,
    _upload_windows,
    find_word_windows,
)


def _direct_call(target: int, site: int) -> tuple[int, int]:
    displacement = target - (site + 4)
    encoded = displacement & 0x7FFFFF
    return (0xF000 | ((encoded >> 12) & 0x7FF),
            0xF800 | ((encoded >> 1) & 0x7FF))


def _thumb_blx(site: int, target: int) -> tuple[int, int]:
    displacement = target - ((site + 4) & ~3)
    if displacement & 3:
        raise ValueError("Thumb BLX target must be word aligned")
    encoded = displacement & 0x1FFFFFF
    sign = encoded >> 24 & 1
    i1, i2 = encoded >> 23 & 1, encoded >> 22 & 1
    j1, j2 = 1 ^ (i1 ^ sign), 1 ^ (i2 ^ sign)
    return (0xF000 | sign << 10 | (encoded >> 12 & 0x3FF),
            0xC800 | j1 << 13 | j2 << 11 | (encoded >> 2 & 0x3FF) << 1)


def _called_function(words: tuple[int, ...]) -> bytes:
    image = bytearray(0x100)
    struct.pack_into(f"<{len(words)}H", image, 0, *words)
    first, second = _direct_call(0, 0x22)
    struct.pack_into("<3H", image, 0x20, 0xB500, first, second)
    struct.pack_into("<H", image, 0x26, 0xBD00)
    return bytes(image)


def _profile():
    return {
        "version": 1,
        "ranges": [
            {"base": 0x50000000, "length": 0x8000},
            {"base": 0x50200000, "length": 0x8000},
            {"base": 0x50400000, "length": 0x4000},
            {"base": 0x50800000, "length": 0x8000},
            {"base": 0x58000000, "length": 0x2000},
            {"base": 0x58200000, "length": 0x8000},
            {"base": 0x58400000, "length": 0x4000},
            {"base": 0x58800000, "length": 0x5000},
        ],
        "evidence": [{"span": [0, 16]}],
    }


def _linked_page_access(register_base: int) -> bytes:
    image = bytearray(0x100)
    first, second = _direct_call(0x30, 8)
    struct.pack_into("<7H", image, 0,
                     0xB500, 0x4807, 0x8B81, 0x8381,
                     first, second, 0xBD00)
    image[0x20:0x24] = register_base.to_bytes(4, "little")
    struct.pack_into("<H", image, 0x30, 0x4770)
    first, second = _direct_call(0, 0x42)
    struct.pack_into("<4H", image, 0x40, 0xB500, first, second, 0xBD00)
    return bytes(image)


def _page_access_with_partial_caller(*, indirect_before_call=False,
                                     caller=True, literal=0x50203220) -> bytes:
    image = bytearray(0x100)
    # Complete callee: load a page address from its literal pool and read at +1c.
    struct.pack_into("<5H", image, 0x20,
                     0xB500, 0x4803, 0x8B81, 0xBD00, 0x46C0)
    image[0x30:0x34] = literal.to_bytes(4, "little")
    if caller:
        if indirect_before_call:
            first, second = _direct_call(0x20, 0x44)
            struct.pack_into("<5H", image, 0x40, 0xB500, 0x4790,
                             first, second, 0xBD00)
        else:
            first, second = _direct_call(0x20, 0x42)
            struct.pack_into("<5H", image, 0x40, 0xB500, first, second,
                             0x4790, 0xBD00)
    return bytes(image)


class WordNandWindowTests(unittest.TestCase):
    def test_upload_claims_keep_only_the_four_required_external_spans(self):
        claims = _upload_windows(_profile(), 0x100)
        self.assertEqual(
            claims,
            [
                {"base": 0x50000000, "length": 0x4000},
                {"base": 0x50200000, "length": 0x3000},
                {"base": 0x50400000, "length": 0x1000},
                {"base": 0x58000000, "length": 0x1000},
            ],
        )

    def test_upload_claims_reject_missing_window_bad_bounds_and_bad_evidence(self):
        profile = _profile()
        profile["ranges"] = [item for item in profile["ranges"]
                             if item["base"] != 0x50400000]
        self.assertIsNone(_upload_windows(profile, 0x100))

        profile = _profile()
        profile["ranges"][0] = {"base": 0x50000001, "length": 0x4000}
        self.assertIsNone(_upload_windows(profile, 0x100))

        profile = _profile()
        profile["evidence"] = [{"span": [0xF0, 0x20]}]
        self.assertIsNone(_upload_windows(profile, 0x100))
        profile["evidence"] = [{}]
        self.assertIsNone(_upload_windows(profile, 0x100))

    def test_linked_typed_access_at_page_offset_230_proves_extra_page(self):
        facts = facts_for(_linked_page_access(0x50203220))
        owner = _typed_502_control(facts)
        self.assertIsNotNone(owner)
        self.assertTrue(owner.complete)
        self.assertIn(("read", 0x5020323C, 2), {
            (item.operation, item.address, item.width) for item in owner.accesses
        })

    def test_extra_page_candidate_outside_page_is_rejected(self):
        facts = facts_for(_linked_page_access(0x50204000))
        self.assertIsNone(_typed_502_control(facts))

    def test_called_complete_page_helper_accepts_later_indirect_exit(self):
        facts = facts_for(_page_access_with_partial_caller())
        owner = _typed_502_control(facts)
        self.assertIsNotNone(owner)
        self.assertEqual(owner.entry.address, 0x20)
        callers = tuple(_partial_callers(facts, owner))
        self.assertEqual(len(callers), 1)
        self.assertFalse(callers[0].complete)
        self.assertTrue(any(item.address == 0x46 for item in callers[0].unresolved))
        spans = {tuple(item["span"]) for item in _typed_502_evidence(facts, owner)}
        self.assertIn((0x40, 10), spans)

    def test_page_helper_rejects_unresolved_exit_before_call(self):
        facts = facts_for(_page_access_with_partial_caller(
            indirect_before_call=True))
        self.assertIsNone(_typed_502_control(facts))

    def test_page_helper_rejects_missing_incoming_call_and_out_of_page_literal(self):
        facts = facts_for(_page_access_with_partial_caller(caller=False))
        self.assertIsNone(_typed_502_control(facts))
        facts = facts_for(_page_access_with_partial_caller(literal=0x50204000))
        self.assertIsNone(_typed_502_control(facts))

    def test_interworking_call_links_thumb_owner_through_arm_literal_veneer(self):
        image = bytearray(0x180)
        high, low = _thumb_blx(0x40, 0x80)
        struct.pack_into("<4H", image, 0x40,
                         high, low, 0xBD08, 0x46C0)
        struct.pack_into("<2I", image, 0x80, 0xE59FC000, 0xE12FFF1C)
        struct.pack_into("<I", image, 0x88, 0x101)
        struct.pack_into("<3H", image, 0x100, 0xB500, 0x46C0, 0xBD00)
        facts = facts_for(bytes(image))

        owners = tuple(_linked_owners(facts, 0x102, _callers(facts)))
        self.assertEqual(len(owners), 1)
        self.assertEqual(owners[0].entry.address, 0x100)
        evidence = _interworking_evidence(facts, owners[0])
        self.assertTrue(any(item["span"] == [0x40, 6] for item in evidence))
        self.assertTrue(any(item["span"] == [0x80, 8]
                            and item["extra_spans"] == [[0x88, 4]]
                            for item in evidence))

    def test_computed_timer_window_requires_linked_constructor_and_typed_accesses(self):
        image = _called_function((
            0xB500,  # PUSH {lr}
            0x2065,  # MOVS r0, #0x65
            0x0600,  # LSLS r0, r0, #24
            0x6040,  # STR r0, [r0, #4]
            0x6100,  # STR r0, [r0, #0x10]
            0x6140,  # STR r0, [r0, #0x14]
            0x6981,  # LDR r1, [r0, #0x18]
            0x69C1,  # LDR r1, [r0, #0x1c]
            0xBD00,  # POP {pc}
        ))
        facts = facts_for(image)
        owners = _owners_with_accesses(
            facts, 0x65, 24, 0x65000000,
            {("write", 4, 4), ("write", 0x10, 4), ("write", 0x14, 4)},
            _callers(facts),
        )
        self.assertEqual(len(owners), 1)
        accesses = {(item.operation, item.address, item.width)
                    for item in owners[0].accesses}
        self.assertTrue({
            ("read", 0x65000018, 4),
            ("read", 0x6500001C, 4),
        } <= accesses)

    def test_computed_signal_window_checks_base_pointer_field(self):
        image = bytearray(0x100)
        struct.pack_into("<7H", image, 0,
                         0xB500, 0x20C5, 0x05C0, 0x6000,
                         0x6080, 0x6408, 0xBD00)
        facts = facts_for(bytes(image))
        function = facts.function(CodeAddress(0, "thumb"), budget=32)
        self.assertTrue(function.complete)
        self.assertTrue(_pointer_field(facts, function, 0x62800000))

    def test_computed_signal_window_accepts_adjacent_base_and_offset_state_fields(self):
        image = bytearray(0x40)
        struct.pack_into("<9H", image, 0,
                         0xB500, 0x20C5, 0x05C0, 0x4C06, 0x60A0,
                         0x1C01, 0x3140, 0x60E1, 0xBD00)
        image[0x20:0x24] = (0x100).to_bytes(4, "little")
        facts = facts_for(bytes(image))
        function = facts.function(CodeAddress(0, "thumb"), budget=32)
        self.assertTrue(function.complete)
        self.assertTrue(_pointer_field(facts, function, 0x62800000))
        writes = {(item.address, item.value) for item in function.accesses
                  if item.operation == "write"}
        self.assertIn((0x108, 0x62800000), writes)
        self.assertIn((0x10C, 0x62800040), writes)

    def test_computed_signal_window_rejects_nonadjacent_or_unrelated_state_fields(self):
        for second_store, add_immediate in ((0x6121, 0x3140),
                                            (0x60E1, 0x3130)):
            image = bytearray(0x40)
            struct.pack_into("<9H", image, 0,
                             0xB500, 0x20C5, 0x05C0, 0x4C06, 0x60A0,
                             0x1C01, add_immediate, second_store, 0xBD00)
            image[0x20:0x24] = (0x100).to_bytes(4, "little")
            facts = facts_for(bytes(image))
            function = facts.function(CodeAddress(0, "thumb"), budget=32)
            self.assertTrue(function.complete)
            self.assertFalse(_pointer_field(facts, function, 0x62800000))

    def test_unlinked_metadata_and_boot_descriptor_are_rejected(self):
        image = bytes(0x20000)
        reset = SimpleNamespace(
            entry=CodeAddress(0, "arm"),
            instructions=(CodeAddress(0, "arm"),),
            literals=(),
        )
        self.assertIsNone(find_word_windows(
            image, 0x4000, 0x10000, reset, _profile()))

    def test_constructor_without_a_direct_caller_is_not_admitted(self):
        image = bytearray(0x100)
        struct.pack_into("<9H", image, 0,
                         0xB500, 0x2065, 0x0600, 0x6040, 0x6100,
                         0x6140, 0x6981, 0x69C1, 0xBD00)
        facts = facts_for(bytes(image))
        self.assertEqual(
            _constructors(facts, 0x65, 24, _callers(facts)),
            (),
        )

    def test_constructor_call_to_literal_prefix_links_push_owner(self):
        image = bytearray(0x100)
        struct.pack_into("<11H", image, 0,
                         0x480B, 0xB500, 0x2065, 0x0600, 0x6040,
                         0x6100, 0x6140, 0x6981, 0x69C1, 0xBD00, 0x0000)
        image[0x20:0x24] = (0x11223344).to_bytes(4, "little")
        first, second = _direct_call(0, 0x42)
        struct.pack_into("<4H", image, 0x40, 0xB500, first, second, 0xBD00)
        facts = facts_for(bytes(image))
        owners = _constructors(facts, 0x65, 24, _callers(facts))
        self.assertEqual(len(owners), 1)
        self.assertEqual(owners[0].entry.address, 0)


if __name__ == "__main__":
    unittest.main()
