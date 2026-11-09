"""Synthetic tests for bounded storage descriptor observations."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.storage_facts import (
    parse_sector_table,
    parse_u32_array,
    parse_x16_descriptor,
    printable_name_end,
    sector_regions,
    sector_tables_before,
    u32_at,
    uniform_sector_size,
)
from msm5xxx_emulator.detection.facts import FirmwareFacts


class StorageFactsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image = bytearray(0x400)

    def reader(self, holes=()):
        def read(address: int, size: int) -> bytes | None:
            if (address < 0 or address + size > len(self.image)
                    or any(address < end and start < address + size
                           for start, end in holes)):
                return None
            return bytes(self.image[address:address + size])
        return read

    def test_parse_sector_table_and_neighbor_search(self) -> None:
        descriptor = 0x180
        name = descriptor + 0x30
        entry = descriptor - 8 - 3 * 4
        struct.pack_into('<2I3I', self.image, entry, name, 3,
                         0x1000, 0x1000, 0x1000)
        direct = parse_sector_table(self.reader(), entry)
        self.assertEqual((direct.address, direct.name_address,
                          direct.sectors, direct.count),
                         (entry, name, (0x1000,) * 3, 3))
        self.assertEqual(sector_tables_before(
            self.reader(), descriptor, expected_name=name), (direct,))

    def test_sector_candidate_query_is_cached_on_its_image_facts(self) -> None:
        descriptor, name = 0x180, 0x1B0
        entry = descriptor - 8 - 2 * 4
        struct.pack_into('<2I2I', self.image, entry, name, 2, 0x1000, 0x1000)
        source = bytes(self.image)
        facts = FirmwareFacts(source)
        reads = 0

        def counted(address: int, size: int) -> bytes | None:
            nonlocal reads
            reads += 1
            return source[address:address + size] if 0 <= address <= len(source) - size else None

        args = dict(expected_name=name, facts=facts, cache_key=('synthetic',))
        first = sector_tables_before(counted, descriptor, **args)
        read_count = reads
        second = sector_tables_before(counted, descriptor, **args)
        self.assertIs(first, second)
        self.assertEqual(reads, read_count)

    def test_table_rejects_invalid_counts_truncation_and_holes(self) -> None:
        struct.pack_into('<2I', self.image, 0x40, 0x100, 3)
        self.assertIsNone(parse_sector_table(self.reader(), 0x40, max_count=2))
        self.assertIsNone(parse_sector_table(self.reader(holes=((0x48, 0x54),)), 0x40))
        self.assertIsNone(parse_sector_table(self.reader(), len(self.image) - 8))
        self.assertEqual(sector_tables_before(
            self.reader(), 0x48, expected_name=0x100), ())

    def test_descriptor_layouts_share_observed_fields(self) -> None:
        words7 = (0x00840098, 0, 1, 0x00900000, 0x00200000,
                  *[0x1001 + i * 4 for i in range(7)])
        words9 = (*words7[:5], *[0x2001 + i * 4 for i in range(9)])
        struct.pack_into('<12I', self.image, 0x80, *words7)
        struct.pack_into('<14I', self.image, 0xC0, *words9)
        amd = parse_x16_descriptor(self.image, 0x80, callback_count=7, address=0x400)
        primary = parse_x16_descriptor(self.image, 0xC0, callback_count=9, address=0x500)
        self.assertEqual((amd.manufacturer, amd.device, amd.base_words,
                          amd.usable_words, len(amd.callbacks)),
                         (0x98, 0x0084, 0x00900000, 0x00200000, 7))
        self.assertEqual((primary.address, len(primary.callbacks)), (0x500, 9))
        self.assertIsNone(parse_x16_descriptor(self.image, 0x3D0, callback_count=9))

    def test_uniform_and_nonuniform_geometry_queries(self) -> None:
        self.assertEqual(uniform_sector_size((0x1000,) * 4, minimum=0x1000), 0x1000)
        self.assertIsNone(uniform_sector_size((0x1000, 0x2000), minimum=0x1000))
        self.assertIsNone(uniform_sector_size((0x1800,), minimum=0x1000))
        self.assertEqual(sector_regions(
            (0x2000,) * 2 + (0x1000,) * 4, minimum=0x1000),
            (((2, 0x2000), (4, 0x1000)), None))
        self.assertEqual(sector_regions((0x1000, 0x2000), minimum=0x1000)[1],
                         'geometry-sector-mismatch')
        self.assertEqual(sector_regions((0x8000, 0x4000, 0x2000, 0x1000, 0x800),
                                        minimum=0x800, max_regions=1)[1],
                         'geometry-region-count-mismatch')

    def test_word_array_is_bounded_and_reusable_by_profiles(self) -> None:
        struct.pack_into('<3I', self.image, 0x60, 0x10000, 0x10000, 0x10000)
        self.assertEqual(u32_at(self.image, 0x60), 0x10000)
        self.assertIsNone(u32_at(self.image, -1))
        self.assertIsNone(u32_at(self.image, len(self.image) - 3))
        values = parse_u32_array(self.image, 0x60, 3)
        self.assertEqual(values, (0x10000,) * 3)
        self.assertEqual(uniform_sector_size(values, minimum=0x10000,
                                             maximum=0x10000), 0x10000)
        self.assertIsNone(parse_u32_array(self.image, 0x3FC, 2))
        self.assertIsNone(parse_u32_array(self.image, 0x20, 4, max_count=3))

    def test_printable_name_is_bounded_and_rejects_control_bytes(self) -> None:
        self.image[0x20:0x2A] = b'NOR model\0'
        self.assertEqual(printable_name_end(self.image, 0x20, len(self.image)), 0x29)
        self.image[0x22] = 1
        self.assertIsNone(printable_name_end(self.image, 0x20, len(self.image)))
        self.assertIsNone(printable_name_end(self.image, 0x20, 0x25))


if __name__ == '__main__':
    unittest.main()
