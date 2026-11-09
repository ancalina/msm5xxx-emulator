"""Synthetic shared-geometry bindings and supplied-source boundaries."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import bind_facts, fact_scope
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.detection.devices.eeprom import (
    _paired_eeprom_driver,
)


class EEPROMPairFactsTests(unittest.TestCase):
    def image(self):
        image = bytearray(0x1200)
        write, read, init = 0x100, 0x600, 0xB00
        prefixes = (struct.pack('<HH', 0xB510, 0x2451),
                    struct.pack('<HH', 0xB520, 0x2552),
                    struct.pack('<HH', 0x2001, 0x4904))
        for at, prefix in zip((write, read, init), prefixes):
            image[at:at + len(prefix)] = prefix
        for at, offset in ((write, 14), (read, 12)):
            pool = at + 0x3E8
            struct.pack_into('<H', image, at + offset,
                             0x4800 | ((pool - ((at + offset + 4) & ~3)) // 4))
            struct.pack_into('<I', image, pool, 0x1004000)
        struct.pack_into('<I', image, init + 0x14, 0x1004000)
        image[0x1000:0x100B] = b'nv24lcxx.c\0'
        return bytes(image), prefixes, (read, write, 0x1004000)

    def query(self, image, prefixes):
        return _paired_eeprom_driver(image, *prefixes, 0x3E8, 0x3E8)

    def test_geometry_requires_both_loads_and_initializer(self):
        image, prefixes, expected = self.image()
        self.assertEqual(self.query(image, prefixes), expected)
        for at in (0x4E8, 0x9E8, 0xB14):
            changed = bytearray(image)
            struct.pack_into('<I', changed, at, expected[2] + 4)
            self.assertIsNone(self.query(bytes(changed), prefixes))

    def test_source_holes_cannot_supply_prefix_or_literal(self):
        image, prefixes, _ = self.image()
        for hole in (0x102, 0x10E, 0x300, 0x4E8, 0xB14):
            view = ImageView.sparse(((0, image[:hole]), (hole + 2, image[hole + 2:])))
            with fact_scope():
                bind_facts(image, view)
                self.assertIsNone(self.query(image, prefixes))

    def test_duplicate_entry_is_ambiguous_even_with_equal_geometry(self):
        image, prefixes, _ = self.image()
        changed = bytearray(image)
        changed[0xC00:0xC04] = prefixes[0]
        self.assertIsNone(self.query(bytes(changed), prefixes))

    def test_prefix_mutation_and_duplicate_source_marker(self):
        image, prefixes, expected = self.image()
        changed = bytearray(image)
        changed[0x101] ^= 1
        self.assertIsNone(self.query(bytes(changed), prefixes))

        changed = bytearray(image)
        changed[0x1100:0x110B] = b'nv24lcxx.c\0'
        self.assertIsNone(self.query(bytes(changed), prefixes))
        self.assertEqual(
            _paired_eeprom_driver(
                bytes(changed), *prefixes, 0x3E8, 0x3E8,
                unique_marker=False,
            ),
            expected,
        )

    def test_literal_instruction_and_initializer_prefix_must_be_present(self):
        image, prefixes, _ = self.image()
        for at in (0x10E, 0x60C):
            changed = bytearray(image)
            value = struct.unpack_from('<H', changed, at)[0]
            struct.pack_into('<H', changed, at, value + 1)
            self.assertIsNone(self.query(bytes(changed), prefixes))

        view_hole = ImageView.sparse(((0, image[:0xB00]), (0xB02, image[0xB02:])))
        with fact_scope():
            bind_facts(image, view_hole)
            self.assertIsNone(self.query(image, prefixes))
