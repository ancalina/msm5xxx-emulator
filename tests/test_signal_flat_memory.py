"""Synthetic checks for flat upload objects and reset-published catalogs."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.devices.external_bus.signal_flat_memory import (
    _copied_catalogs, _flat_object, _flat_parser,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


def _image():
    image = bytearray(0x1200)
    parents = (0x500, 0x520, 0x540)
    objects = (0x600, 0x620, 0x640)
    rows = (0x100, 0x120, 0x140)
    payloads = (0x200, 0x220, 0x240)
    for parent, obj, row, payload, base in zip(
            parents, objects, rows, payloads,
            (0x08000000, 0x08200000, 0x08800000)):
        struct.pack_into('<I', image, parent + 0x14, obj)
        struct.pack_into('<IIH', image, obj, payload, row, 1)
        struct.pack_into('<II', image, row, base, 4)
        struct.pack_into('<II', image, row + 8, base + 8, 4)
        image[payload:payload + 16] = bytes(range(16))
    struct.pack_into('<III', image, 0x800, *parents)
    linker = {'regions': [{'kind': 'rw-copy', 'load': 0x800, 'size': 12,
                           'exec': 0x14000000,
                           'evidence': {'table_offset': 0x40}}]}
    return bytes(image), linker, list(objects)


class _ThumbCode:
    def __init__(self, image, address):
        self.image, self.pc = image, address
        self.labels, self.fixups = {}, []

    def emit(self, opcode):
        struct.pack_into('<H', self.image, self.pc, opcode)
        self.pc += 2

    def label(self, name):
        self.labels[name] = self.pc

    def branch(self, opcode, label):
        self.fixups.append((self.pc, opcode, label))
        self.emit(opcode)

    def call(self, target):
        delta = target - self.pc - 4
        self.emit(0xF000 | (delta >> 12 & 0x7FF))
        self.emit(0xF800 | (delta >> 1 & 0x7FF))

    def finish(self):
        for address, opcode, label in self.fixups:
            delta = (self.labels[label] - address - 4) // 2
            mask = 0xFF if opcode & 0xF000 == 0xD000 else 0x7FF
            struct.pack_into('<H', self.image, address,
                             opcode | delta & mask)


def _source_program(*, payload_shift=1, row_shift=3, leaf_step=2,
                    zero_mode=True, flag_clobber=False,
                    count_source=6, wrong_destination_row=False,
                    wrong_payload_source=False, bound_offset=8):
    image = bytearray(0x240)
    parser = _ThumbCode(image, 0x40)
    bound_opcode = 0x8800 | ((bound_offset // 2) << 6)
    for opcode in (0xB5FE, 0x2102, 0x9102, 0xC8A0, 0x3808,
                   bound_opcode, 0x2400, 0x9001):
        parser.emit(opcode)
    parser.branch(0xE000, 'rows')
    parser.label('rows')
    parser.emit(0x0000 | row_shift << 6 | 4 << 3)  # LSL r0,r4,#n
    parser.emit(0x1839)  # ADD r1,r7,r0
    parser.emit(0x684E)  # LDR r6,[r1,#4]
    parser.emit(0x5819 if wrong_destination_row else 0x5839)
    # LDR r1,[r7,r0], or deliberately use an unrelated row base.
    parser.emit(0x1C02 | count_source << 3)  # r2 = selected count source
    parser.emit(0x1C20 if wrong_payload_source else 0x1C28)
    # r0 = payload cursor, or deliberately use the row index.
    parser.call(0x100)
    parser.emit(0x0000 | payload_shift << 6 | 6 << 3)  # LSL r0,r6,#n
    parser.emit(0x182D)  # ADD r5,r0,r5
    parser.emit(0x3401)  # ADD r4,#1
    parser.emit(0x9801)  # LDR r0,[sp,#4]
    parser.emit(0x4284)  # CMP r4,r0
    parser.branch(0xD900, 'rows')  # BLS rows
    parser.emit(0x9802)
    parser.emit(0xBCFE)
    parser.emit(0xBC08)
    parser.emit(0x4718)
    parser.finish()

    wrapper = _ThumbCode(image, 0x100)
    for opcode in (0xB510, 0x1C04, 0x1C08, 0x1C21,
                   0x2300 if zero_mode else 0x2301):
        wrapper.emit(opcode)
    wrapper.call(0x140)
    wrapper.emit(0xBC10)
    wrapper.emit(0xBC08)
    wrapper.emit(0x4718)
    wrapper.finish()

    leaf = _ThumbCode(image, 0x140)
    for opcode in (0xB5F8, 0x1C17, 0x1C1E, 0x1C05,
                   0x1C0C, 0x1C78, 0x2E00):
        leaf.emit(opcode)
    leaf.branch(0xD000, 'tail')  # BEQ tail when the mode is zero
    leaf.branch(0xE000, 'done')
    leaf.label('loop')
    for opcode in (0x8821, 0x8029,
                   0x3400 | leaf_step, 0x3500 | leaf_step):
        leaf.emit(opcode)
    leaf.label('tail')
    leaf.emit(0x3801)
    if flag_clobber:
        leaf.emit(0x2201)  # Change flags between SUBS and BNE.
    leaf.branch(0xD100, 'loop')
    leaf.branch(0xE000, 'done')
    leaf.label('done')
    leaf.emit(0xBCF8)
    leaf.emit(0xBC08)
    leaf.emit(0x4718)
    leaf.finish()

    caller = _ThumbCode(image, 0x1C0)
    for opcode in (0xB510, 0x1C0C, 0x6948):  # R4=R1; R0=*(R1+0x14)
        caller.emit(opcode)
    caller.call(0x40)
    caller.emit(0xBC10)
    caller.emit(0xBC08)
    caller.emit(0x4718)
    caller.finish()
    return bytes(image)


class FlatSignalMemoryTests(unittest.TestCase):
    def test_generated_parser_and_copy_chain_require_real_geometry_and_steps(self):
        good = _source_program()
        parser = _flat_parser(facts_for(good), CodeAddress(0x40, 'thumb'))
        self.assertIsNotNone(parser)
        self.assertEqual(parser['unit'], 2)
        self.assertIn(0x14, parser['field_offsets'])
        for kwargs in (
            {'zero_mode': False},
            {'row_shift': 2},
            {'payload_shift': 2},
            {'leaf_step': 4},
            {'flag_clobber': True},
            {'count_source': 4},
            {'wrong_destination_row': True},
            {'wrong_payload_source': True},
            {'bound_offset': 6},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertIsNone(_flat_parser(
                    facts_for(_source_program(**kwargs)),
                    CodeAddress(0x40, 'thumb')))

    def test_flat_halfword_rows_produce_bounded_ranges(self):
        image, _linker, objects = _image()
        parsed = _flat_object(image, objects[0], 2)
        self.assertEqual(parsed['intervals'], [
            (0x08000000, 0x08000008),
            (0x08000008, 0x08000010),
        ])
        self.assertEqual(parsed['payload_span'], [0x200, 16])
        self.assertEqual(parsed['rows_span'], [0x100, 16])

    def test_flat_object_mutations_outside_bounds_are_rejected(self):
        image, _linker, objects = _image()
        for address, value in ((objects[0] + 8, 0x41),
                               (0x104, 0x100001),
                               (0x100, 0x09000000),
                               (objects[0], len(image) - 2)):
            mutated = bytearray(image)
            struct.pack_into('<I', mutated, address, value)
            self.assertIsNone(_flat_object(bytes(mutated), objects[0], 2))

        for address, value in ((objects[0], 0x201), (0x100, 0x08000001)):
            mutated = bytearray(image)
            struct.pack_into('<I', mutated, address, value)
            self.assertIsNone(_flat_object(bytes(mutated), objects[0], 2))

    def test_catalog_requires_three_consecutive_linked_records(self):
        image, linker, objects = _image()
        self.assertEqual(len(_copied_catalogs(image, linker, {0x14: (2,)})), 1)
        mutated = bytearray(image)
        struct.pack_into('<I', mutated, 0x804, 0)
        self.assertEqual(_copied_catalogs(bytes(mutated), linker,
                                          {0x14: (2,)}), [])

    def test_unlinked_or_noncopy_regions_do_not_publish_catalog(self):
        image, linker, _objects = _image()
        self.assertEqual(_copied_catalogs(image, {'regions': []},
                                          {0x14: (2,)}), [])
        noncopy = {'regions': [{'kind': 'zero-init', 'load': 0x800,
                                'size': 12, 'exec': 0x14000000}]}
        self.assertEqual(_copied_catalogs(image, noncopy, {0x14: (2,)}), [])


if __name__ == '__main__':
    unittest.main()
