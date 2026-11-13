"""Generated-byte checks for secondary protected-NOR source queries."""
from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.devices.storage.secondary_protected_nor import (
    _object_geometry,
    _prefix_consumers,
    _select_candidate,
    find_secondary_protected_nor,
)
from msm5xxx_emulator.detection.devices.storage.secondary_protected_protocol import (
    identify_base_path,
    identify_base_probe,
)


def put16(image, at, *values):
    struct.pack_into("<" + "H" * len(values), image, at, *values)


def put32(image, at, *values):
    struct.pack_into("<" + "I" * len(values), image, at, *values)


def thumb_bl(source, target):
    displacement = (target - (source + 4)) & 0x1FFFFFF
    s = (displacement >> 24) & 1
    i1 = (displacement >> 23) & 1
    i2 = (displacement >> 22) & 1
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    return (0xF000 | (s << 10) | ((displacement >> 12) & 0x3FF),
            0xD000 | (j1 << 13) | (j2 << 11) | ((displacement >> 1) & 0x7FF))


def make_linked_prefix_consumer():
    image = bytearray(0x240)
    entry, global_address, literal, trampoline = 0x40, 0x14000100, 0x80, 0x100
    put16(image, entry, 0xB5B0, 0x4D0F, 0x1C04, 0x2000, 0x2100,
          0x686A, 0x008B, 0x189B, 0x689B, 0x1818, 0x3101, 0x42A1,
          0xDBF8, 0x32C0, 0x6811)
    put16(image, entry + 30, *thumb_bl(entry + 30, trampoline),
          0xBCB0, 0xBC08, 0x4718)
    put16(image, trampoline, 0x4708)  # BX R1 callback bridge
    put32(image, literal, global_address)
    return image, entry


class SecondaryProtectedNorSyntheticTests(unittest.TestCase):
    def test_f3_identify_probe_derives_aligned_bank_base(self):
        image = bytearray(0x400)
        entry = 0x80
        put16(image, entry, 0x2100, 0x20F3, 0x8008, 0x2109,
              0x0649, 0x8008, 0x4770)
        self.assertEqual(identify_base_probe(facts_for(bytes(image))),
                         (entry, entry + 14, 0x12000000))

        for offset, value in ((entry + 2, 0x20F2), (entry + 8, 0x0641),
                              (entry + 4, 0x8000)):
            changed = bytearray(image)
            put16(changed, offset, value)
            with self.subTest(offset=offset):
                self.assertIsNone(identify_base_probe(facts_for(bytes(changed))))

    def test_f3_base_probe_requires_one_complete_direct_caller(self):
        image = bytearray(0x500)
        probe, caller = 0x80, 0x200
        put16(image, probe, 0x2100, 0x20F3, 0x8008, 0x2109,
              0x0649, 0x8008, 0x4770)
        put16(image, caller, 0xB500, *thumb_bl(caller + 2, probe), 0xBD00)
        facts = facts_for(bytes(image))
        self.assertEqual(identify_base_path(facts),
                         (probe, probe + 14, 0x12000000, caller, caller + 8))

        unlinked = bytearray(image)
        put16(unlinked, caller + 2, 0x46C0, 0x46C0)
        self.assertIsNone(identify_base_path(facts_for(bytes(unlinked))))

        duplicate = bytearray(image)
        second = 0x240
        put16(duplicate, second, 0xB500, *thumb_bl(second + 2, probe), 0xBD00)
        self.assertIsNone(identify_base_path(facts_for(bytes(duplicate))))

    def test_table_geometry_uses_sector_sum_and_separate_bound(self):
        image = bytearray(0x600)
        obj = 0x100
        put32(image, obj + 4, 3)
        put32(image, obj + 8, 0x10000, 0x20000, 0x10000)
        put32(image, obj + 0xAC, 2)
        put32(image, obj + 0xB0, 0x08000000)
        put32(image, obj + 0xB4, 0x100000)
        put32(image, obj + 0xB8, 0x301, 0x321, 0x341,
              0x361, 0x381, 0x3A1)

        found = _object_geometry(bytes(image), obj)
        self.assertIsNotNone(found)
        self.assertEqual(found["begin"], 0x10000000)
        self.assertEqual(found["extent"], 0x40000)
        self.assertEqual(found["max_bound"], 0x200000)
        self.assertEqual(found["sector_sizes"], (0x10000, 0x20000, 0x10000))

    def test_table_rejects_invalid_width_size_bound_and_methods(self):
        def make():
            image = bytearray(0x600)
            obj = 0x100
            put32(image, obj + 4, 2)
            put32(image, obj + 8, 0x10000, 0x10000)
            put32(image, obj + 0xAC, 2)
            put32(image, obj + 0xB0, 0x08000000)
            put32(image, obj + 0xB4, 0x100000)
            put32(image, obj + 0xB8, 0x301, 0x321, 0x341,
                  0x361, 0x381, 0x3A1)
            return image

        mutations = []
        wrong_width = make()
        put32(wrong_width, 0x100 + 0xAC, 4)
        mutations.append(wrong_width)
        odd_sector = make()
        put32(odd_sector, 0x108, 0x10001)
        mutations.append(odd_sector)
        short_bound = make()
        put32(short_bound, 0x100 + 0xB4, 0x8000)
        mutations.append(short_bound)
        non_thumb = make()
        put32(non_thumb, 0x100 + 0xB8, 0x300)
        mutations.append(non_thumb)
        for image in mutations:
            with self.subTest(image=mutations.index(image)):
                self.assertIsNone(_object_geometry(bytes(image), 0x100))

    def test_prefix_consumer_sums_byte_entries_then_dispatches_erase(self):
        image = bytearray(0x200)
        entry = 0x40
        put16(image, entry, 0xB5B0, 0x4D2F, 0x1C04, 0x6868,
              0x2800, 0xD106)
        # Keep the conditional path and setup between the descriptor load and
        # the table loop, then emit the loop and indirect callback dispatch.
        put16(image, entry + 12, 0x46C0, 0x46C0, 0x482B, 0xA1A6,
              0x3031, 0x46C0, 0x46C0, 0x2000, 0x2100, 0x686A,
              0xE004, 0x008B, 0x189B, 0x689B, 0x1818, 0x3101,
              0x42A1, 0xDBF8, 0x32C0, 0x6811, 0x46C0, 0x46C0,
              0xBCB0, 0xBC08, 0x4718)
        put32(image, 0x100, 0x140AC234)

        found = _prefix_consumers(facts_for(bytes(image)))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["entry"], entry)
        self.assertEqual(found[0]["global_address"], 0x140AC234)

        unlinked = bytearray(image)
        put16(unlinked, entry + 12 + 20, 0x2000)
        self.assertEqual(_prefix_consumers(facts_for(bytes(unlinked))), ())

    def test_prefix_consumer_accepts_moved_loop_with_active_erase_dispatch(self):
        image, entry = make_linked_prefix_consumer()
        found = _prefix_consumers(facts_for(bytes(image)))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["entry"], entry)
        self.assertEqual(found[0]["global_address"], 0x14000100)

        mutations = []
        wrong_scale = bytearray(image)
        put16(wrong_scale, entry + 12, 0x004B)  # LSL #1
        mutations.append(wrong_scale)
        wrong_table_stride = bytearray(image)
        put16(wrong_table_stride, entry + 16, 0x68DB)  # LDR [table, #12]
        mutations.append(wrong_table_stride)
        wrong_callback_slot = bytearray(image)
        put16(wrong_callback_slot, entry + 26, 0x32C4)  # object +0xc4
        mutations.append(wrong_callback_slot)
        wrong_callback_register = bytearray(image)
        put16(wrong_callback_register, 0x100, 0x4700)  # BX R0, not loaded callback R1
        mutations.append(wrong_callback_register)
        wrong_count_source = bytearray(image)
        put16(wrong_count_source, entry + 4, 0x1C0C)  # limit from R1, not ABI count R0
        mutations.append(wrong_count_source)
        for changed in mutations:
            with self.subTest(changed=mutations.index(changed)):
                self.assertEqual(_prefix_consumers(facts_for(bytes(changed))), ())

    def test_unlinked_descriptor_alone_does_not_select_a_model(self):
        image = bytearray(0x800)
        obj = 0x100
        put32(image, obj + 4, 1)
        put32(image, obj + 8, 0x10000)
        put32(image, obj + 0xAC, 2)
        put32(image, obj + 0xB0, 0x08000000)
        put32(image, obj + 0xB4, 0x10000)
        put32(image, obj + 0xB8, 0x301, 0x321, 0x341,
              0x361, 0x381, 0x3A1)
        self.assertIsNone(find_secondary_protected_nor(bytes(image), 0x14000000,
                                                        0x02000000))

    def test_duplicate_geometry_requires_one_lifecycle_selected_object(self):
        facts = facts_for(bytes(16))
        first = ({'object': 4}, {'_sector_masks': {0x3F}})
        duplicate = ({'object': 8}, {'_sector_masks': {0x3F}})
        lifecycle = {'selector': 1}

        def linked(_facts, geometry, _global, _caller):
            return lifecycle if geometry['object'] == 4 else None

        with patch('msm5xxx_emulator.detection.devices.storage.secondary_protected_nor._linked_lifecycle', linked):
            selected = _select_candidate(facts, [first, duplicate], 12, {})
        self.assertEqual(selected, (first[0], first[1], lifecycle))
        self.assertIsNot(selected[1], first[1])
        self.assertEqual(first[1]['_sector_masks'], {0x3F})

    def test_duplicate_candidates_without_unique_lifecycle_are_rejected(self):
        facts = facts_for(bytes(16))
        candidates = [({'object': 4}, {}), ({'object': 8}, {})]
        for results in ((None, None), ({'selector': 1}, {'selector': 2})):
            with self.subTest(results=results), patch(
                    'msm5xxx_emulator.detection.devices.storage.secondary_protected_nor._linked_lifecycle',
                    side_effect=results):
                self.assertIsNone(_select_candidate(facts, candidates, 12, {}))

    def test_single_open_candidate_remains_diagnostic(self):
        facts = facts_for(bytes(16))
        candidate = ({'object': 4}, {'_sector_masks': {0x7F}})
        with patch('msm5xxx_emulator.detection.devices.storage.secondary_protected_nor._linked_lifecycle',
                   return_value=None):
            selected = _select_candidate(facts, [candidate], 12, {})
        self.assertEqual(selected, (candidate[0], candidate[1], None))
        self.assertIsNot(selected[1], candidate[1])


if __name__ == "__main__":
    unittest.main()
