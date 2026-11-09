"""Synthetic code evidence, address views, and conservative propagation."""
import struct
import random
import unittest

from capstone.arm import ARM_CC_EQ, ARM_CC_NE

from msm5xxx_emulator.detection.arm import (
    thumb_bl_target as legacy_thumb_call_target,
    thumb_literal_value as legacy_thumb_literal_value,
)
from msm5xxx_emulator.detection.facts import (
    CodeAddress, FirmwareFacts, bind_facts, fact_scope, facts_for,
    source_prefix, with_fact_scope,
)
from msm5xxx_emulator.detection.image_view import ImageView, LoadOperation


def words(*values):
    return struct.pack('<' + 'H' * len(values), *values)


class FactIndexTests(unittest.TestCase):
    def test_ranged_literal_xrefs_include_only_validated_pool_consumers(self):
        image = bytearray(0x40)
        struct.pack_into('<3H', image, 0, 0x4807, 0x4908, 0x4770)
        struct.pack_into('<3I', image, 0x20, 0x02000000, 0x03000780, 0x03000784)
        facts = FirmwareFacts(bytes(image))
        expected = facts.literal_references(0x03000780)
        selected = facts.literal_references_in(((0x03000780, 0x03000788),))
        self.assertEqual(selected, expected)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].instruction, CodeAddress(2))
        self.assertIs(selected, facts.literal_references_in(((0x03000780, 0x03000788),)))

    def test_string_xrefs_join_arm_and_thumb_pools_in_each_execution_phase(self):
        text = b'DRIVER\0'
        view = ImageView.sparse((
            (0x1000, struct.pack('<I', 0x1020)),
            (0x1008, struct.pack('<2I', 0xE51F1010, 0xE12FFF1E)),
            (0x1020, text),
            (0x2000, words(0x4800, 0x4770) + struct.pack('<I', 0x1020)),
            (0x3000, b'UNUSED\0'),
        ))
        facts = FirmwareFacts(b'', view=view).after_loads((
            LoadOperation('copy', 0x2000, 0x8000, 8, (0x40,)),
        ))
        self.assertEqual({literal.instruction for _, literal in facts.string_xrefs(text)},
                         {CodeAddress(0x1008, 'arm'), CodeAddress(0x2000)})
        copied = facts.string_xrefs(text, phase='post-copy')
        self.assertIn(CodeAddress(0x8000, phase='post-copy'),
                      {literal.instruction for _, literal in copied})
        self.assertEqual(facts.string_xrefs(b'UNUSED\0'), ())
        self.assertEqual(facts.literal_references(0x1020, bank='other'), ())

    def test_literal_access_index_uses_copied_and_overwritten_instructions(self):
        image = words(0x4901, 0x7808, 0x4770, 0x46C0) + struct.pack('<I', 0x03000720)
        facts = FirmwareFacts(image).after_loads((
            LoadOperation('copy', 0, 0x03800000, len(image), (0x20,)),
            LoadOperation('zero', None, 0, 4, (0x24,)),
        ))
        ranges = ((0x03000720, 0x03000721),)
        self.assertEqual(len(facts.literal_access_candidates(ranges)), 1)
        # The reset bytes at address zero have been overwritten in this phase.
        self.assertEqual(facts.literal_access_candidates(ranges, phase='post-copy'), ())
        copied = facts.literal_access_candidates(ranges, phase='post-copy', limit=1 << 32)
        self.assertEqual(len(copied), 1)
        self.assertEqual(copied[0].load, CodeAddress(0x03800000, phase='post-copy'))
        self.assertEqual((copied[0].literal, copied[0].address),
                         (0x03800008, 0x03000720))

    def test_candidate_indexes_follow_execution_phase_and_bank(self):
        arm = struct.pack('<3I', 0xEB000000, 0xE12FFF1E, 0xE12FFF1E)
        thumb = words(0xF000, 0xF802, 0x4770, 0x46C0, 0x4770)
        view = ImageView.sparse(((0x1000, arm), (0x2000, thumb),
                                 (0x3000, b'AB'), (0x3002, b'CD')))
        facts = FirmwareFacts(b'', view=view).after_loads((
            LoadOperation('copy', 0x1000, 0x8000, len(arm), (0x40,)),
            LoadOperation('copy', 0x2000, 0x9002, len(thumb), (0x44,)),
            LoadOperation('copy', 0x3000, 0xA000, 4, (0x48,)),
        ))
        self.assertIn((0x1000, 0x1008), facts.call_candidates('arm'))
        self.assertNotIn((0x8000, 0x8008), facts.call_candidates('arm'))
        self.assertIn((0x8000, 0x8008), facts.call_candidates('arm', phase='post-copy'))
        self.assertIn((0x9002, 0x900A), facts.call_candidates(phase='post-copy'))
        self.assertEqual(facts.string_candidates(b'ABCD'), (0x3000,))
        self.assertEqual(facts.string_candidates(b'ABCD', phase='post-copy'),
                         (0x3000, 0xA000))
        self.assertEqual(facts.string_candidates(b'ABCD', phase='post-copy', bank='other'), ())

    def test_byte_candidates_cannot_cross_a_hole(self):
        view = ImageView.sparse(((0, b'AB'), (4, b'CD')))
        facts = FirmwareFacts(b'ABCDCD', view=view)
        self.assertEqual(facts.string_candidates(b'ABCD'), ())
        self.assertEqual(facts.string_candidates(b'CD'), (4,))

    def test_scatter_candidates_require_supplied_table_fields(self):
        image = bytes(0x20) + struct.pack('<5I', 0, 0x1000000, 16, 0x1000010, 8)
        complete = FirmwareFacts(image).scatter_candidates()
        self.assertTrue(any(row.table == 0x20 and row.zero_size == 8 for row in complete))
        missing_header = ImageView.sparse(((0, image[:0x24]), (0x28, image[0x28:])))
        self.assertFalse(any(row.table == 0x20 for row in
                             FirmwareFacts(image, view=missing_header).scatter_candidates()))
        missing_zero = ImageView.sparse(((0, image[:0x2C]),))
        rows = FirmwareFacts(image, view=missing_zero).scatter_candidates()
        self.assertIsNone(next(row for row in rows if row.table == 0x20).zero_size)

    def test_scatter_and_string_candidates(self):
        image = struct.pack('<5I', 24, 0x14000000, 4, 0x14000004, 16) + b'abcdTEXT\0'
        facts = FirmwareFacts(image)
        candidate = facts.scatter_candidates()[0]
        self.assertEqual((candidate.table, candidate.source, candidate.target, candidate.size),
                         (0, 24, 0x14000000, 4))
        self.assertEqual(candidate.zero_size, 16)
        self.assertEqual(facts.string_candidates(b'TEXT\0'), (24,))

    def test_call_candidates_require_complete_supplied_instruction(self):
        image = struct.pack('<2H', 0xF000, 0xF800)
        partial = ImageView.sparse(((0, image[:2]),))
        complete = ImageView.sparse(((0, image),))

        self.assertEqual(FirmwareFacts(image, view=partial).call_candidates(), ())
        self.assertTrue(FirmwareFacts(image, view=complete).call_candidates())

    def test_literal_access_candidates_keep_signed_conditional_arm_shape(self):
        # LDR{EQ} r4,[pc,#-12] followed by LDR{EQ} r0,[r4,#-4].
        code = struct.pack('<2I', 0x051F400C, 0x05140004)
        view = ImageView.sparse(((0x1008, code),
                                 (0x1004, struct.pack('<I', 0x3004))))
        found = FirmwareFacts(code, base=0x1008, view=view).literal_access_candidates(
            ((0x3000, 0x3100),))

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].literal, 0x1004)
        self.assertEqual(found[0].address, 0x3000)
        self.assertEqual(found[0].operation, 'read')
        self.assertEqual(found[0].predicate, ARM_CC_EQ)

    def test_arm_literal_access_predicate_uses_following_instruction(self):
        # The literal load is AL, while the negative-offset use is conditional NE.
        code = struct.pack('<2I', 0xE51F400C, 0x15140004)
        view = ImageView.sparse(((0x1008, code),
                                 (0x1004, struct.pack('<I', 0x3004))))
        found = FirmwareFacts(code, base=0x1008, view=view).literal_access_candidates(
            ((0x3000, 0x3100),))

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].predicate, ARM_CC_NE)

    def test_literal_access_candidate_rejects_hole_in_instruction_pair(self):
        image = words(0x4801, 0x6800, 0x46C0, 0x46C0) + struct.pack('<I', 0x3000)
        view = ImageView.sparse(((0, image[:2]), (8, image[8:])))

        self.assertEqual(FirmwareFacts(image, view=view).literal_access_candidates(
            ((0x3000, 0x3100),)), ())

    def test_literal_access_prefilter_matches_bounded_manual_scan(self):
        rng = random.Random(0x5A17)
        image = bytearray(rng.randbytes(160))
        struct.pack_into('<2H', image, 0x10, 0x4801, 0x6800)
        struct.pack_into('<I', image, 0x18, 0x3000)
        struct.pack_into('<2I', image, 0x40, 0xE59F4000, 0xE5940000)
        struct.pack_into('<I', image, 0x48, 0x3000)
        image = bytes(image)
        view = ImageView.raw(image)
        facts = FirmwareFacts(image, view=view)
        ranges = ((0x3000, 0x3100),)

        manual = []
        for offset in range(0, max(0, len(image) - 3), 2):
            first = struct.unpack_from('<H', image, offset)[0]
            if first & 0xF800 == 0x4800 and view.covers(offset, 4):
                register = first >> 8 & 7
                pool = ((offset + 4) & ~3) + (first & 0xFF) * 4
                literal = view.read(pool, 4)
                use = struct.unpack_from('<H', image, offset + 2)[0]
                opcode = use & 0xF800
                width = {0x6000: 4, 0x6800: 4, 0x7000: 1,
                         0x7800: 1, 0x8000: 2, 0x8800: 2}.get(opcode)
                if (literal is not None and width is not None
                        and use >> 3 & 7 == register):
                    pointer = int.from_bytes(literal, 'little')
                    address = pointer + ((use >> 6 & 31) * width)
                    if any(lo <= address and address + width <= hi for lo, hi in ranges):
                        manual.append((offset, 'thumb', offset + 2, pool, address, width,
                                       'read' if opcode in (0x6800, 0x7800, 0x8800)
                                       else 'write', 15))

            if offset % 4 or offset + 8 > len(image) or not view.covers(offset, 8):
                continue
            first = struct.unpack_from('<I', image, offset)[0]
            condition = first >> 28
            if (condition == 15 or first & 0x0E000000 != 0x04000000
                    or first & ((1 << 25) | (1 << 22) | (1 << 21))
                    or not first & (1 << 24) or not first & (1 << 20)
                    or first >> 16 & 15 != 15 or first >> 12 & 15 == 15):
                continue
            register = first >> 12 & 15
            displacement = first & 0xFFF
            pool = offset + 8 + (displacement if first & (1 << 23) else -displacement)
            literal = view.read(pool, 4)
            if literal is None:
                continue
            pointer = int.from_bytes(literal, 'little')
            use = struct.unpack_from('<I', image, offset + 4)[0]
            use_condition = use >> 28
            destination = use >> 12 & 15
            if (use_condition == 15 or use & 0x0C000000 != 0x04000000
                    or use & ((1 << 25) | (1 << 21)) or not use & (1 << 24)
                    or use >> 16 & 15 != register or destination == 15
                    or (condition != 14 and use_condition != condition)):
                continue
            width = 1 if use & (1 << 22) else 4
            displacement = use & 0xFFF
            address = pointer + (displacement if use & (1 << 23) else -displacement)
            if any(lo <= address and address + width <= hi for lo, hi in ranges):
                manual.append((offset, 'arm', offset + 4, pool, address, width,
                               'read' if use & (1 << 20) else 'write', use_condition + 1))

        actual = facts.literal_access_candidates(ranges)
        key = lambda item: (item.load.address,
                            0 if item.load.isa == 'thumb' else 1)
        actual_rows = tuple((item.load.address, item.load.isa, item.use.address,
                             item.literal, item.address, item.width, item.operation,
                             item.predicate) for item in sorted(actual, key=key))
        manual_rows = tuple((site, isa, use, pool, address, width, operation, predicate)
                            for site, isa, use, pool, address, width, operation, predicate
                            in sorted(manual, key=lambda row: (
                                row[0], 0 if row[1] == 'thumb' else 1)))
        self.assertEqual(actual_rows, manual_rows)

    def test_literal_access_windows_share_one_extraction(self):
        image = words(0x4800, 0x6800) + struct.pack('<I', 0x3000)
        facts = FirmwareFacts(image)
        extracted = []
        original_memo = facts.memo

        def counted_memo(name, parameters, extract):
            def counted_extract():
                extracted.append(name)
                return extract()
            return original_memo(name, parameters, counted_extract)

        facts.memo = counted_memo
        first = facts.literal_access_candidates(((0x3000, 0x3100),))
        second = facts.literal_access_candidates(((0x4000, 0x4100),))
        repeated = facts.literal_access_candidates(((0x3000, 0x3100),))

        self.assertEqual(len(first), 1)
        self.assertEqual(second, ())
        self.assertEqual(repeated, first)
        self.assertEqual(extracted.count('literal-access-shapes'), 1)


if __name__ == "__main__":
    unittest.main()
