"""Synthetic checks for upload descriptor and copy-unit evidence."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.devices.external_bus.signal_memory import (
    _copy_unit, _merged_pages, _object_linked_tables, _table_candidate,
    find_signal_memory,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


def _descriptor_image(*, count=2):
    image = bytearray(0x2000)
    table = 0x100c
    descriptors = ((0x1000, 0x800, 0), (0x1004, 0x820, 0), (0x1008, 0x840, 0))
    for index, (payload, rows, last) in enumerate(descriptors):
        struct.pack_into('<III', image, table + index * 12, payload, rows, last)
        destination = (0x08000000, 0x08200000, 0x08800000)[index]
        row_count = count if index == 0 else 2
        struct.pack_into('<II', image, rows, destination, row_count)
        image[payload:payload + 4] = b'\x12\x34\x56\x78'
    return image, table


def _copy_image(*, halfword=True, decrement=True):
    image = bytearray(0x100)
    step = 2 if halfword else 4
    code = [0x3201, 0xe003, 0x8803 if halfword else 0x6803,
            0x800b if halfword else 0x600b, 0x3000 | step, 0x3100 | step,
            0x3a01 if decrement else 0x3201, 0xd1f9, 0x4770]
    struct.pack_into(f'<{len(code)}H', image, 0x20, *code)
    return bytes(image)


class _Thumb:
    def __init__(self, image, entry):
        self.image, self.pc = image, entry
        self.labels, self.fixups = {}, []

    def word(self, value):
        struct.pack_into('<H', self.image, self.pc, value)
        self.pc += 2

    def label(self, name):
        self.labels[name] = self.pc

    def branch(self, opcode, label):
        self.fixups.append((self.pc, opcode, label))
        self.word(opcode)

    def call(self, target):
        delta = target - self.pc - 4
        self.word(0xf000 | (delta >> 12 & 0x7ff))
        self.word(0xf800 | (delta >> 1 & 0x7ff))

    def finish(self):
        for at, opcode, label in self.fixups:
            mask = 0x7ff if opcode == 0xe000 else 0xff
            delta = (self.labels[label] - at - 4) // 2
            struct.pack_into('<H', self.image, at, opcode | delta & mask)


def _linked_image():
    image, table = _descriptor_image()
    struct.pack_into('<I', image, 0x844, 1)
    for entry, unit, copy in ((0x100, 2, 0x220), (0x180, 4, 0x260)):
        code = _Thumb(image, entry)
        for word in (0xb5f0, 0xb081, 0x2800):
            code.word(word)
        code.branch(0xd000, 'done')
        for word in (0x8901, 0x9100, 0x6805, 0x6847, 0x2400):
            code.word(word)
        code.branch(0xe000, 'compare')
        code.label('rows')
        for word in (0x00e0, 0x1839, 0x684e, 0x5839, 0x1c32, 0x1c28):
            code.word(word)
        code.call(copy)
        for word in (0x0070 if unit == 2 else 0x00b0, 0x182d, 0x3401):
            code.word(word)
        code.label('compare')
        code.word(0x9800)
        code.word(0x4284)
        code.branch(0xd900, 'rows')
        code.label('done')
        code.word(0xb001)
        code.word(0xbdf0)
        code.finish()
        image[copy:copy + 18] = _copy_image(halfword=unit == 2)[0x20:0x32]
    wrapper = _Thumb(image, 0x300)
    wrapper.word(0xb510)
    for word in (0x2900,):
        wrapper.word(word)
    wrapper.branch(0xd000, 'done')
    wrapper.word(0x6a09)
    wrapper.word(0x2900)
    wrapper.branch(0xd000, 'done')
    wrapper.word(0x0080)
    wrapper.word(0x580c)
    wrapper.word(0x2c00)
    wrapper.branch(0xd000, 'done')
    for field, parser in ((0x0c, 0x100), (0x10, 0x100), (0x20, 0x180)):
        wrapper.word(0x6820 | (field // 4) << 6)
        wrapper.call(parser)
    wrapper.label('done')
    wrapper.word(0xbd10)
    wrapper.finish()
    caller = _Thumb(image, 0x400)
    for word in (0xb500, 0x2000, 0x4906):
        caller.word(word)
    caller.call(0x300)
    caller.word(0xbd00)
    struct.pack_into('<I', image, 0x420, 0x600)
    struct.pack_into('<I', image, 0x620, 0x640)
    struct.pack_into('<I', image, 0x640, table + 36)
    for index, field in enumerate((0x0c, 0x10, 0x20)):
        struct.pack_into('<I', image, table + 36 + field, table + index * 12)
    return bytes(image)


class SignalMemoryTests(unittest.TestCase):
    def test_linked_rows_and_calling_convention_select_three_memory_banks(self):
        profile = find_signal_memory(_linked_image())
        self.assertIsNotNone(profile)
        self.assertEqual(profile['ranges'], [
            {'base': 0x08000000, 'length': 0x1000},
            {'base': 0x08200000, 'length': 0x1000},
            {'base': 0x08800000, 'length': 0x1000}])
        self.assertEqual(profile['units'], [2, 4])

    def test_parser_row_stride_and_payload_unit_mutations_decline(self):
        for entry, before, after in ((0x100, 0x00e0, 0x00a0),
                                     (0x180, 0x00b0, 0x0070)):
            image = bytearray(_linked_image())
            at = next(offset for offset in range(entry, entry + 0x60, 2)
                      if struct.unpack_from('<H', image, offset)[0] == before)
            struct.pack_into('<H', image, at, after)
            self.assertIsNone(find_signal_memory(bytes(image)))

    def test_descriptor_rows_yield_page_rounded_ranges(self):
        image, table = _descriptor_image()
        candidate = _table_candidate(bytes(image), table)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate['unit'], 2)
        self.assertEqual(candidate['ranges'], [
            (0x08000000, 0x08001000),
            (0x08200000, 0x08201000),
            (0x08800000, 0x08801000),
        ])

    def test_ranges_merge_gaps_within_each_64k_section(self):
        self.assertEqual(_merged_pages(((0x50000010, 0x50001000),
                                        (0x50005000, 0x50006010),
                                        (0x50010000, 0x50011000))),
                         [(0x50000000, 0x50007000),
                          (0x50010000, 0x50011000)])

    def test_count_mutation_breaks_payload_boundary(self):
        image, table = _descriptor_image(count=3)
        self.assertIsNone(_table_candidate(bytes(image), table))

    def test_halfword_payload_may_pad_to_the_next_word_payload(self):
        image, table = _descriptor_image()
        for index, payload in enumerate((0x1000, 0x1002, 0x1008)):
            struct.pack_into('<I', image, table + index * 12, payload)
            struct.pack_into('<I', image, (0x800, 0x820, 0x840)[index] + 4,
                             (1, 2, 1)[index])
        candidate = _table_candidate(bytes(image), table, (2, 2, 4))
        self.assertEqual(candidate['units'], (2, 2, 4))
        struct.pack_into('<I', image, table + 24, 0x100a)
        self.assertIsNone(_table_candidate(bytes(image), table))

    def test_selected_object_links_each_registry_entry(self):
        image, table = _descriptor_image()
        object_at = table + 3 * 12
        fields = (0x0c, 0x10, 0x14)
        for index, field in enumerate(fields):
            struct.pack_into('<I', image, object_at + field, table + index * 12)
        self.assertEqual(list(_object_linked_tables(bytes(image), list(fields))),
                         [(table, object_at, 3)])
        struct.pack_into('<I', image, object_at + fields[1], table + 0x18)
        self.assertEqual(list(_object_linked_tables(bytes(image), list(fields))), [])

    def test_copy_loop_proves_transfer_width_and_predecrement(self):
        image = _copy_image(halfword=True)
        facts = facts_for(image)
        function = facts.function(CodeAddress(0x20, 'thumb'), budget=32)
        self.assertEqual(_copy_unit(facts, function), 2)
        word = _copy_image(halfword=False)
        word_facts = facts_for(word)
        self.assertEqual(_copy_unit(word_facts, word_facts.function(
            CodeAddress(0x20, 'thumb'), budget=32)), 4)

    def test_copy_value_counter_and_pretest_are_required(self):
        for offset, opcode in ((0x22, 0x46c0), (0x26, 0x800a),
                               (0x20, 0x3301), (0x2c, 0x3b01)):
            image = bytearray(_copy_image())
            struct.pack_into('<H', image, offset, opcode)
            facts = facts_for(bytes(image))
            self.assertIsNone(_copy_unit(facts, facts.function(
                CodeAddress(0x20), budget=32)))

    def test_protocol_width_or_counter_mutation_is_rejected(self):
        image = bytearray(0x100)
        code = [0x3301, 0x8802, 0x600a, 0x3002, 0x3102,
                0x3b01, 0xd1f9, 0x4770]
        struct.pack_into(f'<{len(code)}H', image, 0x20, *code)
        facts = facts_for(bytes(image))
        function = facts.function(CodeAddress(0x20, 'thumb'), budget=32)
        self.assertIsNone(_copy_unit(facts, function))

        image = bytearray(0x100)
        code = [0x3301, 0x8802, 0x800a, 0x3002, 0x3102,
                0x3301, 0xd1f9, 0x4770]
        struct.pack_into(f'<{len(code)}H', image, 0x20, *code)
        facts = facts_for(bytes(image))
        function = facts.function(CodeAddress(0x20, 'thumb'), budget=32)
        self.assertIsNone(_copy_unit(facts, function))

    def test_unlinked_descriptor_data_does_not_select_profile(self):
        image, _table = _descriptor_image()
        self.assertIsNone(find_signal_memory(bytes(image)))
        self.assertIsNone(find_signal_memory(bytes(image), code_limit=len(image) + 1))


if __name__ == '__main__':
    unittest.main()
