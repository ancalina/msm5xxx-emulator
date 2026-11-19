"""Synthetic tests for reset-rooted branched Thumb word copies."""
import struct
import unittest
from capstone.arm import ARM_REG_R5

from msm5xxx_emulator.detection.startup_reset_copy import reset_linked_copy
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.values import CodeAddress
from msm5xxx_emulator.detection.startup_reset_cfg_copy import (
    LinkedThumbWordCopy, _alias_input, linked_thumb_cfg_word_copies,
)
from msm5xxx_emulator.detection.startup_reset_cfg_records import (
    linked_thumb_cfg_word_copy_records,
)
from test_startup_entry import reset_entry_fixture


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value)


def _put32(image, address, value):
    struct.pack_into("<I", image, address, value)


def _branch(image, site, condition, target):
    delta = (target - site - 4) // 2
    assert -128 <= delta <= 127
    _put16(image, site, 0xD000 | (condition << 8) | (delta & 0xff))


def _unconditional(image, site, target):
    delta = (target - site - 4) // 2
    assert -1024 <= delta <= 1023
    _put16(image, site, 0xE000 | (delta & 0x7ff))


def _branched_copy_fixture(*, bad_store=False, broken_backedge=False,
                           orphan=False, destination=0x01000000,
                           wrong_destination_field=False):
    image = bytearray(0x1000)
    image[:0x100] = reset_entry_fixture()[:0x100]
    code = 0x100
    destination_cell = 0x320 if wrong_destination_field else 0x304
    literal_values = ((code, 0, 0x308), (code + 2, 1, destination_cell),
                      (code + 14, 0, 0x300), (code + 20, 0, 0x304))
    for site, register, value in literal_values:
        pool = 0x180 + ((site - code) // 2) * 4
        displacement = pool - ((site + 4) & ~3)
        assert 0 <= displacement <= 1020 and displacement % 4 == 0
        _put16(image, site, 0x4800 | (register << 8) | (displacement // 4))
        _put32(image, pool, value)

    # Read three adjacent literal-addressed fields. The size is halved for
    # this first copy phase, and the copy loop uses separate body/update CFGs.
    words = {
        0x104: 0x6800,  # LDR r0,[r0]
        0x106: 0x6809,  # LDR r1,[r1]
        0x108: 0x0840,  # LSRS r0,r0,#1
        0x10a: 0x1840,  # ADDS r0,r0,r1
        0x10c: 0x4606,  # MOV r6,r0
        0x110: 0x6800,  # LDR r0,[r0]
        0x112: 0x1c05,  # ADDS r5,r0,#0
        0x116: 0x6800,  # LDR r0,[r0]
        0x118: 0x1c04,  # ADDS r4,r0,#0
        0x11a: 0x42b4,  # CMP r4,r6
        0x120: 0x1d28,  # ADDS r0,r5,#4
        0x122: 0x1c05,  # ADDS r5,r0,#0
        0x124: 0x1d20,  # ADDS r0,r4,#4
        0x126: 0x1c04,  # ADDS r4,r0,#0
        0x128: 0x0000,
        0x12c: 0x6828,  # LDR r0,[r5]
        0x12e: 0x6020,  # STR r0,[r4]
        0x134: 0x4770,  # BX LR
    }
    for address, word in words.items():
        _put16(image, address, word)
    if bad_store:
        _put16(image, 0x12e, 0x6018)  # STR r0,[r3]
    _branch(image, 0x11c, 2, 0x134)  # BHS exit
    _unconditional(image, 0x11e, 0x12c)
    _unconditional(image, 0x128, 0x11a)
    _unconditional(image, 0x130,
                   0x122 if broken_backedge else 0x120)

    _put32(image, 0x300, 0x500)
    _put32(image, 0x304, destination)
    _put32(image, 0x308, 0x80)
    _put32(image, 0x320, destination)
    image[0x500:0x580] = bytes(range(0x80))
    if orphan:
        _put32(image, 0, 0)
    return image


class StartupResetCfgCopyTests(unittest.TestCase):
    def setUp(self):
        self.options = dict(ram_base=0x01000000, ram_size=0x00800000,
                            flash_size=0x1000)

    def test_reset_linked_copy_tracks_fields_through_cursor_aliases(self):
        image = _branched_copy_fixture()
        copy = reset_linked_copy(image, ((0x01000018, 4),), **self.options)
        self.assertIsNotNone(copy)
        self.assertEqual((copy.source, copy.target, copy.size),
                         (0x500, 0x01000000, 0x40))
        self.assertEqual(copy.source_address(0x01000018, 4), 0x518)
        self.assertIn((0x300, 12), copy.evidence)

    def test_copy_rejects_orphan_mismatched_store_and_wrong_loop_edge(self):
        for image in (_branched_copy_fixture(orphan=True),
                      _branched_copy_fixture(bad_store=True),
                      _branched_copy_fixture(broken_backedge=True),
                      _branched_copy_fixture(wrong_destination_field=True)):
            with self.subTest(image=image[:4]):
                self.assertIsNone(reset_linked_copy(
                    image, ((0x01000018, 4),), **self.options))

    def test_copy_rejects_destination_outside_configured_ram(self):
        image = _branched_copy_fixture(destination=0x01800000)
        self.assertIsNone(reset_linked_copy(
            image, ((0x01000018, 4),), **self.options))

    def test_cfg_proof_rejects_destination_over_code_and_input_fields(self):
        for destination, allowed in (
                (0x12C, ((0x100, 0x200),)),
                (0x180, ((0x180, 0x200),)),
                (0x304, ((0x300, 0x400),))):
            with self.subTest(destination=destination):
                image = _branched_copy_fixture(destination=destination)
                facts = facts_for(image)
                function = facts.function(
                    CodeAddress(0x100), budget=1024,
                    initial_registers={}, symbolic_registers={})
                records = linked_thumb_cfg_word_copies(
                    facts, function, image, nor_end=len(image),
                    ram_ranges=allowed, detailed=True)
                self.assertEqual(records, ())

    def test_copy_rejects_truncated_flash_source_extent(self):
        image = _branched_copy_fixture()
        options = dict(self.options, flash_size=0x520)
        self.assertIsNone(reset_linked_copy(
            image, ((0x01000018, 4),), **options))

    def test_conditional_cursor_alias_is_not_a_proven_cursor_update(self):
        # MOVNE r5,r0: conditional execution cannot establish an unconditional
        # cursor alias for the following copy-loop proof.
        image = bytearray(0x204)
        _put32(image, 0x200, 0x11A05000)
        instruction = facts_for(image).decode(CodeAddress(0x200, "arm"))
        self.assertIsNotNone(instruction)
        self.assertEqual(_alias_input(instruction, ARM_REG_R5), None)

    def test_detailed_record_preserves_tuple_contract_and_loop_exit(self):
        image = _branched_copy_fixture()
        facts = facts_for(image)
        function = facts.function(CodeAddress(0x100), budget=1024,
                                  initial_registers={}, symbolic_registers={})
        regular = linked_thumb_cfg_word_copies(
            facts, function, image, nor_end=len(image),
            ram_base=0x01000000, ram_end=0x01800000)
        detailed = linked_thumb_cfg_word_copy_records(
            facts, function, image, nor_end=len(image),
            ram_ranges=((0x01000000, 0x01800000),))
        self.assertEqual(len(regular[0]), 4)
        self.assertIsInstance(detailed[0], LinkedThumbWordCopy)
        self.assertEqual((detailed[0].source, detailed[0].target,
                          detailed[0].written_size), regular[0][:3])
        self.assertEqual(detailed[0].loop_exit, CodeAddress(0x134))
        self.assertIs(detailed[0].function, function)

    def test_auxiliary_range_is_separate_and_cannot_cover_gap(self):
        allowed = ((0x03800000, 0x03A00000),)
        for destination, expected in ((0x03800000, True),
                                      (0x02800000, False)):
            image = _branched_copy_fixture(destination=destination)
            facts = facts_for(image)
            function = facts.function(CodeAddress(0x100), budget=1024,
                                      initial_registers={},
                                      symbolic_registers={})
            records = linked_thumb_cfg_word_copies(
                facts, function, image, nor_end=len(image),
                ram_base=0x01000000, ram_end=0x01800000,
                auxiliary_ram_ranges=allowed, detailed=True)
            self.assertEqual(bool(records), expected)
        image = _branched_copy_fixture(destination=0x03800000)
        facts = facts_for(image)
        function = facts.function(CodeAddress(0x100), budget=1024,
                                  initial_registers={}, symbolic_registers={})
        overlapping = linked_thumb_cfg_word_copies(
            facts, function, image, nor_end=len(image),
            ram_base=0x01000000, ram_end=0x01800000,
            auxiliary_ram_ranges=((0x01700000, 0x03900000),), detailed=True)
        self.assertEqual(overlapping, ())

    def test_detailed_api_uses_only_the_supplied_range_set(self):
        allowed = ((0x03800000, 0x03A00000),)
        for destination, expected in ((0x03800000, True),
                                      (0x01000000, False)):
            image = _branched_copy_fixture(destination=destination)
            facts = facts_for(image)
            function = facts.function(CodeAddress(0x100), budget=1024,
                                      initial_registers={},
                                      symbolic_registers={})
            records = linked_thumb_cfg_word_copy_records(
                facts, function, image, nor_end=len(image),
                ram_ranges=allowed)
            self.assertEqual(bool(records), expected)


if __name__ == "__main__":
    unittest.main()
