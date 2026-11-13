"""Generated instruction/data checks for direct secondary x16 NOR proof."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.devices.storage.secondary_direct_nor import (
    _BANK_SIZE,
    _command_leaf,
    _range_rows,
    _table_index_consumer,
    _range_table,
    find_secondary_direct_nor,
)


def put16(data, at, *words):
    struct.pack_into("<" + "H" * len(words), data, at, *words)


def put32(data, at, *words):
    struct.pack_into("<" + "I" * len(words), data, at, *words)


def thumb_bl(source, target):
    displacement = (target - (source + 4)) & 0x1FFFFFF
    sign = (displacement >> 24) & 1
    i1, i2 = (displacement >> 23) & 1, (displacement >> 22) & 1
    j1, j2 = (~(i1 ^ sign)) & 1, (~(i2 ^ sign)) & 1
    return (0xF000 | (sign << 10) | ((displacement >> 12) & 0x3FF),
            0xD000 | (j1 << 13) | (j2 << 11) | ((displacement >> 1) & 0x7FF))


def command_helper():
    data = bytearray(0x100)
    entry = 0x20
    # R0 address -> sector index (>>16)&0x7f; issue source-derived unlock
    # sequence, then clear the address bits used by the lock command.
    put16(data, entry, 0x217F, 0x2260, 0x8002, 0x0C02, 0x1C13,
          0x400B, 0x8003, 0x23AC, 0x8003, 0x4391, 0x8001,
          0x217B, 0x8001, 0x4770)
    return data, entry


def range_table(rows):
    data = bytearray(0x400)
    at = 0x100
    for start, length in rows:
        put32(data, at, start, 0, length, start + length, 0x10000, 0, 0)
        at += 0x1C
    return data, at


def write_range_consumer(data, entry, pool, table):
    literal_pc = entry + 8
    displacement = pool - ((literal_pc + 4) & ~3)
    assert displacement >= 0 and displacement % 4 == 0
    put16(data, entry, 0xB500, 0x1C19, 0x231C, 0x4359,
          0x4A00 | (displacement // 4), 0x1889, 0x68C9, 0x4770)
    put32(data, pool, table)


def branch_cond(source, target, condition=1):
    displacement = (target - (source + 4)) // 2
    assert -128 <= displacement <= 127
    return 0xD000 | (condition << 8) | (displacement & 0xFF)


def linked_direct_nor_image():
    data = bytearray(0x10000)
    probe, owner, manager = 0x20, 0x80, 0xA0
    erase, poll, read, helper = 0x200, 0x240, 0x280, 0x300
    table = 0x600
    put16(data, probe, 0x2100, 0x20F3, 0x8008, 0x2109,
          0x0649, 0x8008, 0x4770)
    put16(data, owner, 0xB500, *thumb_bl(owner + 2, probe),
          *thumb_bl(owner + 6, manager), 0xBC08, 0x4718)
    put16(data, manager, 0xB500, *thumb_bl(manager + 2, erase),
          *thumb_bl(manager + 6, poll), *thumb_bl(manager + 10, read),
          0xBC08, 0x4718)

    put16(data, erase, 0xB500, *thumb_bl(erase + 2, helper),
          0x2120, 0x8001, 0x21D0, 0x8001, 0xBC08, 0x4718)
    poll_loop = poll + 6
    poll_branch = poll + 10
    put16(data, poll, 0xB500, 0x2170, 0x8001, 0x8802, 0x2A00,
          branch_cond(poll_branch, poll_loop), 0x2150, 0x8001,
          0x21FF, 0x8001, 0xBC08, 0x4718)
    read_loop = read + 16
    read_branch = read + 22
    put16(data, read, 0xB500, *thumb_bl(read + 2, helper),
          0x2140, 0x8001, 0x2141, 0x8001, 0x2100, 0x8001,
          0x3101, 0x2980, branch_cond(read_branch, read_loop),
          0xBC08, 0x4718)
    helper_bytes, helper_offset = command_helper()
    put16(data, helper, *struct.unpack_from("<14H", helper_bytes, helper_offset))

    write_range_consumer(data, 0x100, 0x130, table)
    for index, start in enumerate((0x12020000, 0x12010000, 0x12000000)):
        put32(data, table + index * 0x1C, start, 0, 0x100,
              start + 0x10000, 0x10000, 0, 0)
    return bytes(data)


class SecondaryDirectNorTests(unittest.TestCase):
    def test_address_unlock_requires_shift_mask_commands_and_halfword_stores(self):
        data, entry = command_helper()
        body = _command_leaf(facts_for(bytes(data)), entry)
        self.assertIsNotNone(body)
        self.assertEqual(_BANK_SIZE, 0x800000)

        mutations = []
        wrong_mask, _ = command_helper()
        put16(wrong_mask, entry, 0x213F)
        mutations.append(wrong_mask)
        wrong_shift, _ = command_helper()
        put16(wrong_shift, entry + 6, 0x0802)  # LSR #2, not a sector address
        mutations.append(wrong_shift)
        missing_unlock, _ = command_helper()
        put16(missing_unlock, entry + 10, 0x2101)
        mutations.append(missing_unlock)
        unused_mask, _ = command_helper()
        put16(unused_mask, entry + 12, 0x8001)  # Store R1, not the AND result R3.
        mutations.append(unused_mask)
        for changed in mutations:
            with self.subTest(changed=mutations.index(changed)):
                self.assertIsNone(_command_leaf(facts_for(bytes(changed)), entry))

    def test_range_rows_must_be_valid_aligned_and_inside_code_derived_bank(self):
        base = 0x12000000
        valid, end = range_table(((base + 0x20000, 0x10000),
                                  (base + 0x10000, 0x10000),
                                  (base, 0x10000)))
        rows = _range_rows(bytes(valid), 0x100, base)
        self.assertIsNotNone(rows)
        self.assertEqual(rows[0], [(base + 0x20000, base + 0x30000),
                                   (base + 0x10000, base + 0x20000),
                                   (base, base + 0x10000)])
        self.assertEqual(rows[1], end)

        outside, _ = range_table(((base + _BANK_SIZE, 0x10000),
                                  (base + 0x10000, 0x10000),
                                  (base, 0x10000)))
        bad_end, _ = range_table(((base + 0x20000, 0x10000),
                                  (base + 0x10000, 0x10000),
                                  (base, 0x10000)))
        put32(bad_end, 0x10C, base + _BANK_SIZE + 1)
        bad_delta, _ = range_table(((base + 0x20000, 0x10000),
                                    (base + 0x10000, 0x10000),
                                    (base, 0x10000)))
        put32(bad_delta, 0x104, 0x20000)
        overlap, _ = range_table(((base + 0x10000, 0x20000),
                                  (base, 0x20000),
                                  (base - 0x10000, 0x10000)))
        for changed in (outside, bad_end, bad_delta, overlap):
            with self.subTest(changed=(outside, bad_end, bad_delta, overlap).index(changed)):
                self.assertIsNone(_range_rows(bytes(changed), 0x100, base))

    def test_range_consumer_links_abi_index_literal_base_and_end_field(self):
        image = bytearray(0x100)
        entry, pool, table = 0x20, 0x40, 0x80
        # Copy ABI row index R3, scale it by a source constant 0x1c, add the
        # literal-backed table address, then read the exclusive-end field.
        put16(image, entry, 0xB500, 0x1C19, 0x231C, 0x4359,
              0x4A05, 0x1889, 0x68C9, 0x4770)
        put32(image, pool, table)
        put32(image, table, 0x12000000)
        facts = facts_for(bytes(image))
        body = facts.function(CodeAddress(entry, "thumb"), budget=128,
                              symbolic_registers={})
        self.assertIsNotNone(_table_index_consumer(facts, body, table))

        wrong_scale = bytearray(image)
        put16(wrong_scale, entry + 4, 0x2318)
        wrong_index = bytearray(image)
        put16(wrong_index, entry + 2, 0x1C01)  # R0 instead of row index R3.
        wrong_field = bytearray(image)
        put16(wrong_field, entry + 12, 0x6949)  # Load +0x14, not exclusive end +0xc.
        for changed in (wrong_scale, wrong_index, wrong_field):
            changed_facts = facts_for(bytes(changed))
            changed_body = changed_facts.function(CodeAddress(entry, "thumb"),
                                                  budget=128, symbolic_registers={})
            with self.subTest(changed=(wrong_scale, wrong_index, wrong_field).index(changed)):
                self.assertIsNone(_table_index_consumer(changed_facts, changed_body, table))

    def test_range_table_uses_linked_consumers_and_deduplicates_same_rows(self):
        image = bytearray(0x300)
        table = 0x120
        write_range_consumer(image, 0x20, 0x50, table)
        write_range_consumer(image, 0x70, 0xA0, table)
        for index, start in enumerate((0x12020000, 0x12010000, 0x12000000)):
            put32(image, table + index * 0x1C, start, 0, 0x100,
                  start + 0x10000, 0x10000, 0, 0)
        facts = facts_for(bytes(image))
        profile = _range_table(facts, bytes(image), 0x12000000)
        self.assertIsNotNone(profile)
        self.assertEqual(profile[0], table)
        self.assertEqual(len(profile[3]), 2)
        self.assertEqual(profile[2], ((0x12020000, 0x12030000),
                                      (0x12010000, 0x12020000),
                                      (0x12000000, 0x12010000)))

        wrong_scale = bytearray(image)
        put16(wrong_scale, 0x24, 0x2318)
        put16(wrong_scale, 0x74, 0x2318)
        rejected = _range_table(facts_for(bytes(wrong_scale)),
                                bytes(wrong_scale), 0x12000000)
        self.assertIsNone(rejected)

    def test_finder_requires_complete_f3_protocol_and_source_ranges(self):
        image = linked_direct_nor_image()
        profile = find_secondary_direct_nor(image)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["bank_base"], 0x12000000)
        self.assertEqual(profile["bank_size"], 0x800000)
        self.assertEqual(profile["sector_size"], 0x10000)
        self.assertFalse(profile["identity_queried"])
        self.assertTrue(profile["evidence_spans"])

        changed = bytearray(image)
        put16(changed, 0x24, 0x2318)
        self.assertIsNone(find_secondary_direct_nor(bytes(changed)))


if __name__ == "__main__":
    unittest.main()
