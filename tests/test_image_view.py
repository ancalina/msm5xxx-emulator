import unittest
import struct

from msm5xxx_emulator.detection.image_view import (
    ImageView, LoadOperation, Mapping, SourceSpan,
)


class ImageViewTests(unittest.TestCase):
    def test_unknown_writes_remove_postcopy_bytes_without_restoring_capture(self):
        source = ImageView.raw(b'abcdefgh', base=0x1000)
        unknown = LoadOperation('invalidate', None, 0x1002, 2, (0x40,))
        result = source.materialize((unknown,))
        self.assertEqual(result.read(0x1000, 2, phase='post-copy'), b'ab')
        self.assertIsNone(result.read(0x1002, 2, phase='post-copy'))
        self.assertEqual(result.read(0x1004, 4, phase='post-copy'), b'efgh')
        self.assertEqual(result.read(0x1002, 2, phase='reset'), b'cd')
        with self.assertRaises(ValueError):
            source.materialize((unknown, LoadOperation('copy', 0x1002, 0x2000, 2, (0x44,))))
        replaced = source.materialize((unknown, LoadOperation('zero', None, 0x1002, 2, (0x48,))))
        self.assertEqual(replaced.read(0x1002, 2, phase='post-copy'), bytes(2))

    def test_multistage_copies_preserve_original_address_and_dependencies(self):
        original = ImageView.sparse(((0x1000, b'ab'), (0x1002, b'cd')))
        first = original.materialize((
            LoadOperation('copy', 0x1000, 0x8000, 4, (0x20,)),
            LoadOperation('zero', None, 0x9000, 4, (0x24,)),
        ))
        second = first.materialize((
            LoadOperation('copy', 0x8000, 0xA000, 4, (0x28,)),
        ), source_phase='post-copy', phase='application')
        self.assertEqual(second.read(0xA000, 4, phase='application'), b'abcd')
        self.assertEqual(second.original_address(0xA000, 4, phase='application'), 0x1000)
        self.assertEqual(second.original_address(0x8001, 2, phase='application'), 0x1001)
        self.assertIsNone(second.original_address(0x9000, 4, phase='application'))
        mappings = [item for item in second.mappings
                    if item.phase == 'application' and item.guest_base == 0xA000]
        self.assertEqual(mappings[0].dependencies, (0, 2))
        self.assertEqual(mappings[0].evidence, (0x20, 0x28))

    def test_original_address_rejects_source_aliases_and_discontinuous_ranges(self):
        aliased = ImageView((b'abcd',), (
            Mapping(0, 0, 0x1000, 4), Mapping(0, 0, 0x2000, 4),
        )).materialize((LoadOperation('copy', 0x1000, 0x8000, 4, (0,)),))
        self.assertIsNone(aliased.original_address(0x8000, 4, phase='post-copy'))
        split = ImageView.sparse(((0x1000, b'ab'), (0x2000, b'cd'))).materialize((
            LoadOperation('copy', 0x1000, 0x8000, 2, (0,)),
            LoadOperation('copy', 0x2000, 0x8002, 2, (4,)),
        ))
        self.assertIsNone(split.original_address(0x8000, 4, phase='post-copy'))

    def test_raw_preserves_nonzero_load_origin_and_thumb_alignment(self):
        image = ImageView.raw(b"\x00\xbf\x70\x47", base=0x10003)

        self.assertEqual(image.origin, 0x10003)
        self.assertEqual(image.read(0x10003, 4, phase="reset"), b"\x00\xbf\x70\x47")
        self.assertEqual(image.read(0x10004, 2), b"\xbf\x70")
        self.assertEqual(image.source_offset(0x10005, 2, phase="reset"), 2)
        self.assertIsNone(image.read(0x10002, 1))
        self.assertIsNone(ImageView.raw(b"", base=0x20000).read(0x20000))
        self.assertTrue(image.covers(0x10003, 4))
        self.assertFalse(image.covers(0x10002, 1))

    def test_sparse_segments_keep_holes_distinct_from_erased_bytes(self):
        image = ImageView.sparse(((0x8000, b"\xffA"), (0x8004, b"\xffB")))

        self.assertEqual(image.read(0x8000, 2), b"\xffA")
        self.assertIsNone(image.read(0x8002, 2))
        self.assertEqual(image.read(0x8004, 2), b"\xffB")
        self.assertEqual(image.source_offset(0x8004, 2), 0)
        self.assertFalse(image.covers(0x8001, 4))
        self.assertTrue(image.covers(0x8004, 2))

    def test_reads_can_cross_adjacent_supplied_segments(self):
        image = ImageView.sparse(((0x1000, b"ab"), (0x1002, b"cd")))

        self.assertEqual(image.read(0x1001, 3), b"bcd")
        self.assertIsNone(image.source_offset(0x1001, 3))
        self.assertTrue(image.covers(0x1001, 3))

    def test_normalized_trims_nonzero_origin_and_inserts_unknown_gap(self):
        image = ImageView.sparse((
            (0x1010, b"abcd"),
            (0x1016, b"ghij"),
        ), origin=0x1000)
        normalized = image.normalized(
            image_offset=0x10, size=12, gap=(2, 2), base=0x8000,
        )

        self.assertEqual(normalized.origin, 0x8000)
        self.assertEqual(normalized.read(0x8000, 2), b"ab")
        self.assertIsNone(normalized.read(0x8002, 2))
        self.assertEqual(normalized.read(0x8004, 2), b"cd")
        self.assertIsNone(normalized.read(0x8006, 2))
        self.assertEqual(normalized.read(0x8008, 4), b"ghij")
        self.assertEqual(normalized.source_offset(0x8004, 2), 2)
        self.assertEqual(normalized.source_offset(0x8008, 4), 0)

    def test_normalized_splits_crossing_mapping_and_clips_primary_size(self):
        image = ImageView.raw(b"abcdefgh", base=0x4000)
        normalized = image.normalized(
            image_offset=2, size=8, gap=(3, 2), base=0x9000,
        )

        self.assertEqual(normalized.read(0x9000, 3), b"cde")
        self.assertIsNone(normalized.read(0x9003, 2))
        self.assertEqual(normalized.read(0x9005, 3), b"fgh")
        self.assertEqual(normalized.source_offset(0x9005, 3), 5)
        self.assertEqual(
            [(item.guest_base, item.source_offset, item.size)
             for item in normalized.mappings],
            [(0x9000, 2, 3), (0x9005, 5, 3)],
        )

        clipped = image.normalized(image_offset=2, size=3, base=0xA000)
        self.assertEqual(clipped.read(0xA000, 3), b"cde")
        self.assertIsNone(clipped.read(0xA003, 1))
        self.assertEqual(clipped.mappings[0].size, 3)

    def test_normalized_preserves_mapping_phase_bank_and_source_span_metadata(self):
        original = ImageView((b"012345",), (
            Mapping(0, 0, 0x5000, 6, phase="application", bank="secondary",
                    kind="copy", evidence=(0x44,),
                    source_spans=(SourceSpan(0, 0, 6, "driver", b"012345"),),
                    dependencies=(2, 5)),
        ), origin=0x5000)
        normalized = original.normalized(2, size=4, base=0xB000)
        mapping = normalized.mappings[0]

        self.assertEqual(normalized.read(0xB000, 4, phase="application",
                                         bank="secondary"), b"2345")
        self.assertEqual((mapping.phase, mapping.bank, mapping.kind),
                         ("application", "secondary", "copy"))
        self.assertEqual((mapping.source_offset, mapping.evidence,
                          mapping.dependencies), (2, (0x44,), (2, 5)))
        self.assertEqual(mapping.source_spans,
                         (SourceSpan(0, 2, 6, "driver", b"2345"),))

    def test_materialize_keeps_partial_updates_to_prior_aliases(self):
        image = ImageView((b"abcdefgh",), (
            Mapping(0, 0, 0x1000, 8, phase="reset", bank="primary",
                    source_spans=(SourceSpan(0, 0, 8, "supplied"),)),
            Mapping(0, 4, 0x2000, 4, phase="reset", bank="primary",
                    kind="alias", evidence=(0x80,),
                    source_spans=(SourceSpan(0, 4, 8, "alias"),)),
        ), origin=0x1000)

        copied = image.materialize((
            LoadOperation("copy", 0x1000, 0x2000, 2, (0x90,)),
            LoadOperation("copy", 0x2000, 0x3000, 4, (0xA0,)),
        ))
        self.assertEqual(copied.read(0x3000, 4, phase='post-copy'), b'abgh')

    def test_copy_mapping_requires_evidence_and_retains_source_link(self):
        original = ImageView.raw(b"ROM!", base=0x1000)

        with self.assertRaisesRegex(ValueError, "evidence"):
            original.with_copy(0, 0, 0x2000, 4, phase="application",
                               bank="primary", evidence=())
        copied = original.with_copy(0, 0, 0x2000, 4, phase="application",
                                    bank="primary", evidence=(0x1100, 0x1108))

        self.assertIsNone(original.read(0x2000, 4))
        self.assertEqual(copied.read(0x2000, 4, phase="application"), b"ROM!")
        self.assertEqual(copied.source_offset(0x2002, 2, phase="application"), 2)
        self.assertIsNone(copied.view(phase="reset").read(0x2000, 1))
        self.assertEqual(copied.mappings[-1].evidence, (0x1100, 0x1108))

    def test_overlap_is_rejected_only_within_same_phase_and_bank(self):
        with self.assertRaisesRegex(ValueError, "overlapping"):
            ImageView.sparse(((0x1000, b"abcd"), (0x1002, b"ef")))

        banked = ImageView((b"abcd", b"ef"), (
            Mapping(0, 0, 0x1000, 4, phase="reset", bank="low"),
            Mapping(1, 0, 0x1000, 2, phase="reset", bank="high"),
        ), 0x1000)
        self.assertEqual(banked.read(0x1000, 2, bank="low"), b"ab")
        self.assertEqual(banked.read(0x1000, 2, bank="high"), b"ef")
        self.assertIsNone(banked.read(0x1000, 1))
        self.assertFalse(banked.covers(0x1000, 1))
        self.assertTrue(banked.covers(0x1000, 1, bank="high"))

        later_phase = ImageView((b"ab", b"cd"), (
            Mapping(0, 0, 0x2000, 2, phase="reset", bank="low"),
            Mapping(1, 0, 0x2000, 2, phase="application", bank="low"),
        ), 0x2000)
        self.assertIsNone(later_phase.read(0x2000, 2))
        self.assertEqual(later_phase.read(0x2000, 2, phase="application"), b"cd")
        self.assertFalse(later_phase.covers(0x2000, 2))

    def test_invalid_mapping_bounds_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "exceeds supplied segment"):
            ImageView((b"abc",), (Mapping(0, 1, 0x1000, 3),))

    def test_inputs_are_copied_into_immutable_storage(self):
        source = bytearray(b"abcd")
        image = ImageView.raw(source)
        source[:] = b"wxyz"

        self.assertEqual(image.read(0, 4), b"abcd")
        self.assertIsInstance(image.segments[0], bytes)

    def test_copy_overlap_is_rejected_in_same_view(self):
        image = ImageView.raw(b"abcd", 0x1000)
        with self.assertRaisesRegex(ValueError, "overlapping"):
            image.with_copy(0, 0, 0x1002, 2, phase="reset",
                            bank="primary", evidence=(0x80,))

    def test_materialize_copies_across_bases_and_preserves_indirect_pointer(self):
        source = ImageView.sparse((
            (0x1000, b"\x00\xbf\x70\x47"),
            (0x2000, struct.pack("<I", 0x3000)),
        ))
        result = source.materialize((
            LoadOperation("copy", 0x1000, 0x3000, 4, (0x800,)),
            LoadOperation("copy", 0x3000, 0x4000, 4, (0x820,)),
            LoadOperation("copy", 0x2000, 0x5000, 4, (0x840,)),
        ))

        self.assertEqual(result.read(0x3000, 4, phase="post-copy"),
                         b"\x00\xbf\x70\x47")
        self.assertEqual(result.read(0x4000, 4, phase="post-copy"),
                         b"\x00\xbf\x70\x47")
        pointer = int.from_bytes(result.read(0x5000, 4, phase="post-copy"), "little")
        self.assertEqual(pointer, 0x3000)
        self.assertEqual(result.read(pointer, 4, phase="post-copy"),
                         b"\x00\xbf\x70\x47")
        descriptor = next(item for item in result.mappings
                          if item.guest_base == 0x5000)
        self.assertEqual(descriptor.dependencies, (2,))
        self.assertEqual(descriptor.source_spans[0].segment, 1)

    def test_materialize_is_ordered_splits_mappings_and_tracks_dependencies(self):
        source = ImageView.raw(b"ABCD", base=0x1000)
        result = source.materialize((
            LoadOperation("copy", 0x1000, 0x3000, 4, (0x500,)),
            LoadOperation("copy", 0x3000, 0x4000, 4, (0x600,)),
            LoadOperation("zero", None, 0x3001, 1, (0x700,)),
            LoadOperation("copy", 0x3000, 0x6000, 4, (0x800,)),
        ))

        self.assertEqual(result.read(0x3000, 4, phase="post-copy"), b"A\x00CD")
        self.assertEqual(result.read(0x4000, 4, phase="post-copy"), b"ABCD")
        self.assertEqual(result.read(0x6000, 4, phase="post-copy"), b"A\x00CD")
        parts = [item for item in result.mappings
                 if item.phase == "post-copy" and 0x3000 <= item.guest_base < 0x3004]
        self.assertEqual([(item.guest_base, item.size, item.kind) for item in parts],
                         [(0x3000, 1, "copy"), (0x3001, 1, "zero"),
                          (0x3002, 2, "copy")])
        zero = parts[1]
        self.assertEqual(zero.dependencies, (2,))
        self.assertEqual(zero.source_spans[0].role, "zero")
        copied = [item for item in result.mappings
                  if item.guest_base == 0x6000 or item.guest_base == 0x6001
                  or item.guest_base == 0x6002]
        self.assertEqual(copied[0].dependencies, (0, 3))
        self.assertEqual(copied[1].dependencies, (2, 3))

    def test_materialize_rejects_holes_overlap_and_missing_evidence(self):
        source = ImageView.sparse(((0x1000, b"AB"), (0x1004, b"CD")))
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            source.materialize((LoadOperation("copy", 0x1000, 0x2000, 5, (1,)),))
        with self.assertRaisesRegex(ValueError, "overlapping copy"):
            source.materialize((LoadOperation("copy", 0x1000, 0x1000, 1, (2,)),))
        with self.assertRaisesRegex(ValueError, "evidence"):
            LoadOperation("zero", None, 0x3000, 2, ())

    def test_materialize_bounds_zero_fill_and_operation_phase(self):
        source = ImageView.raw(b"AB", base=0x1000)
        zero = LoadOperation("zero", None, 0x3000, 2, (0x900,))
        result = source.materialize((zero,), max_zero_bytes=2)
        self.assertEqual(result.read(0x3000, 2, phase="post-copy"), b"\0\0")
        with self.assertRaisesRegex(ValueError, "limit exceeded"):
            source.materialize((LoadOperation("zero", None, 0x3000, 3, (0x900,)),),
                               max_zero_bytes=2)
        with self.assertRaisesRegex(ValueError, "phase"):
            source.materialize((LoadOperation("zero", None, 0x3000, 1, (1,), "other"),))
        with self.assertRaisesRegex(ValueError, "target bounds"):
            LoadOperation("zero", None, 0xFFFFFFFF, 2, (1,))


