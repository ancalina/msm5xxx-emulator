"""Synthetic checks for code-linked x16 NOR descriptor evidence."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.detection.image_view import LoadOperation
from msm5xxx_emulator.detection.nv_nor_word import (
    _descriptor_profile, _source_pool_matches,
)
from msm5xxx_emulator.detection.startup_facts import (
    OrderedCopyTransfer, VectorCopyRow, vector_copy_rows,
)


def descriptor_image(*, code_id=0x225F0004, sectors=(0x10000,) * 32,
                     window_word=0x200000, capacity_word=0x80000):
    image = bytearray(0x500)
    descriptor = 0x200
    struct.pack_into('<I', image, descriptor + 4, len(sectors))
    struct.pack_into('<' + 'I' * len(sectors), image, descriptor + 8,
                     *sectors)
    struct.pack_into('<4I', image, descriptor + 164,
                     code_id, 0, 1, window_word)
    struct.pack_into('<I', image, descriptor + 180, capacity_word)
    for index, field in enumerate((184, 188, 192, 196)):
        struct.pack_into('<I', image, descriptor + field,
                         (0x100 + index * 4) | 1)
    for index, field in enumerate((208, 212, 216)):
        struct.pack_into('<I', image, descriptor + field,
                         (0x140 + index * 4) | 1)
    for address in range(0x100, 0x14A, 2):
        struct.pack_into('<H', image, address, 0x4770)  # BX LR
    return bytes(image), descriptor


class WordNORDescriptorTests(unittest.TestCase):
    def test_vector_copy_row_needs_vector_and_source_branch(self):
        image = bytearray(0x1000)
        target, table, source, wrapper = 0x01000000, 0x300, 0x500, 0x580
        vector_delta = (target - (0x18 + 8)) // 4
        struct.pack_into('<I', image, 0x18, 0xEA000000 | vector_delta)
        struct.pack_into('<4I', image, table, source, target, 0x100,
                         target + 0x100)
        source_delta = (wrapper - (target + 8)) // 4
        struct.pack_into('<I', image, source,
                         0xEA000000 | (source_delta & 0xFFFFFF))
        facts = FirmwareFacts(bytes(image))
        rows = vector_copy_rows(facts, target, 0x1000)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].table, rows[0].source, rows[0].target,
                          rows[0].size, rows[0].wrapper),
                         (table, source, target, 0x100, wrapper))

        malformed = bytearray(image)
        struct.pack_into('<I', malformed, table + 12, target + 0x104)
        self.assertEqual(vector_copy_rows(
            FirmwareFacts(bytes(malformed)), target, 0x1000), ())

        without_source_word = ImageView.sparse((
            (0, bytes(image[:source])), (source + 4, bytes(image[source + 4:])),
        ))
        self.assertEqual(vector_copy_rows(
            FirmwareFacts(bytes(image), view=without_source_word), target, 0x1000), ())

    def test_source_pool_evidence_requires_supplied_row_bytes(self):
        image = bytearray(0x400)
        row = VectorCopyRow(0x40, 0x100, 0x1000, 0x40, 0x1040, 0x80)
        pool, descriptor = 0x1008, 0x240
        struct.pack_into('<4I', image, 0x108, descriptor, 0, 0, 0)
        facts = FirmwareFacts(bytes(image))
        transfer = OrderedCopyTransfer(
            CodeAddress(0x80, 'thumb'), (), (),
            ((0x100, 0x140, 0x1000, 0x1040),), (),
            (0x100, 0x140), (0x1000, 0x1040), (0x1040, 0x1040))
        postcopy = facts.after_loads((LoadOperation(
            'copy', 0x100, 0x1000, 0x40, (0x80,)),))
        self.assertEqual(_source_pool_matches(
            postcopy, transfer, pool, descriptor), 0x108)

        view_with_hole = ImageView.sparse((
            (0, bytes(image[:0x110])), (0x118, bytes(image[0x118:])),
        ))
        with self.assertRaises(ValueError):
            FirmwareFacts(bytes(image), view=view_with_hole).after_loads(
                (LoadOperation('copy', 0x100, 0x1000, 0x40, (0x80,)),))

        cleared = facts.after_loads((
            LoadOperation('copy', 0x100, 0x1000, 0x40, (0x80,)),
            LoadOperation('zero', None, pool, 16, (0x90,)),
        ))
        self.assertIsNone(_source_pool_matches(
            cleared, transfer, pool, descriptor))

    def test_descriptor_requires_code_id_geometry_and_callback_shape(self):
        image, descriptor = descriptor_image()
        profile = _descriptor_profile(
            image, descriptor, 0x01000000, 0x00800000,
            FirmwareFacts(image))
        self.assertIsNotNone(profile)
        self.assertEqual((profile.window_base, profile.physical_size,
                          profile.logical_capacity, profile.sector_size,
                          profile.manufacturer_id, profile.device_id),
                         (0x400000, 0x200000, 0x100000, 0x10000, 4, 0x225F))

        sparse = ImageView.sparse((
            (0, image[:descriptor + 176]),
            (descriptor + 180, image[descriptor + 180:]),
        ))
        self.assertIsNone(_descriptor_profile(
            image, descriptor, 0x01000000, 0x00800000,
            FirmwareFacts(image, view=sparse)))

        unused_stub_fields = bytearray(image)
        struct.pack_into('<3I', unused_stub_fields, descriptor + 208, 0, 0, 0)
        self.assertIsNotNone(_descriptor_profile(
            bytes(unused_stub_fields), descriptor, 0x01000000, 0x00800000,
            FirmwareFacts(bytes(unused_stub_fields))))

        bad_id, _ = descriptor_image(code_id=0x005F0004)
        self.assertIsNone(_descriptor_profile(
            bad_id, descriptor, 0x01000000, 0x00800000,
            FirmwareFacts(bad_id)))

        bad_sectors, _ = descriptor_image(sectors=(0x10000,) * 31 + (0x20000,))
        self.assertIsNone(_descriptor_profile(
            bad_sectors, descriptor, 0x01000000, 0x00800000,
            FirmwareFacts(bad_sectors)))

        bad_capacity, _ = descriptor_image(capacity_word=0x40000)
        self.assertIsNone(_descriptor_profile(
            bad_capacity, descriptor, 0x01000000, 0x00800000,
            FirmwareFacts(bad_capacity)))


if __name__ == '__main__':
    unittest.main()
