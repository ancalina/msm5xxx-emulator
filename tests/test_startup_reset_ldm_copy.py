"""Synthetic tests for source-linked Thumb LDMIA/STMIA reset copies."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.startup_reset_cfg_copy import (
    _literal_field_uses, linked_thumb_cfg_word_copies,
)
from msm5xxx_emulator.detection.startup_reset_ldm_copy import ldm_word_loop_proof


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value)


def _put32(image, address, value):
    struct.pack_into("<I", image, address, value)


def _fixture(*, wrong_store=False, wrong_branch=False, wrong_size=False,
             multi_register=False, incomplete=False, end_register_alias=False,
             source_clobber=False, entry_bypass_body=False,
             entry_bypass_store=False, exit_bypass=False, early_return=False,
             source=0x500, destination=0x01000000):
    image = bytearray(0x800)
    # Three literal-addressed parameter fields and the initial end calculation.
    words = {
        0x100: 0x481F,  # LDR r0, [PC, #0x7c] -> 0x300
        0x102: 0x6805,  # LDR r5, [r0]
        0x104: 0x491F,  # LDR r1, [PC, #0x7c] -> 0x304
        0x106: 0x680C,  # LDR r4, [r1]
        0x108: 0x4A1F,  # LDR r2, [PC, #0x7c] -> 0x308
        0x10A: 0x6817,  # LDR r7, [r2]
        0x10C: 0x19E6,  # ADDS r6, r4, r7 (or wrong size register)
        0x10E: (0x2500 if source_clobber else
                0xD114 if entry_bypass_body else
                0xD115 if entry_bypass_store else 0x46C0),
        0x110: 0xE010,  # B 0x134, first comparison
        0x134: 0x42B4,  # CMP r4, r6
        0x136: 0xD300 if not wrong_branch else 0xD200,  # BLO body / BHS body
        0x138: 0x4770,  # BX LR
        0x13A: 0xCD01,  # LDMIA r5!, {r0}
        0x13C: 0xC401 if not wrong_store else 0xC402,  # STMIA r4!, {r0}
        0x13E: 0x42B4,  # CMP r4, r6
        0x140: 0xD3FB if not wrong_branch else 0xD2FB,  # BLO/BHS 0x13a
        0x142: 0x4770,  # BX LR
    }
    # The function's real first CMP is the node at 0x13e. Redirect the
    # preheader there; the 0x134 sequence is unreachable padding/data.
    if exit_bypass or early_return:
        target = 0x144 if early_return else 0x142
        delta = (target - (0x110 + 4)) // 2
        words[0x10E] = 0x42A3  # CMP r3,r4
        words[0x110] = 0xD000 | delta  # BEQ direct exit/early return
        words[0x112] = 0xE014  # B to the copy's first compare
        if early_return:
            words[0x144] = 0x4770  # independent BX LR
    else:
        words[0x110] = 0xE015
    for address, value in words.items():
        _put16(image, address, value)
    if wrong_size:
        _put16(image, 0x10C, 0x19A6)  # ADDS r6, r4, r6
    if multi_register:
        _put16(image, 0x13A, 0xCD03)  # LDMIA r5!, {r0,r1}
        _put16(image, 0x13C, 0xC403)  # STMIA r4!, {r0,r1}
    if end_register_alias:
        _put16(image, 0x13A, 0xCD40)  # LDMIA r5!, {r6}
        _put16(image, 0x13C, 0xC440)  # STMIA r4!, {r6}, clobbers bound
    if incomplete:
        _put16(image, 0x142, 0xDE00)  # undefined terminal instruction
    _put32(image, 0x180, 0x300)
    _put32(image, 0x184, 0x304)
    _put32(image, 0x188, 0x308)
    _put32(image, 0x300, source)
    _put32(image, 0x304, destination)
    _put32(image, 0x308, 0x40)
    image[0x500:0x540] = bytes(range(0x40))
    return bytes(image)


class StartupResetLdmCopyTests(unittest.TestCase):
    def prove(self, image, target_ranges=((0x01000000, 0x01800000),)):
        facts = facts_for(image)
        function = facts.function(
            CodeAddress(0x100, "thumb"), budget=128,
            initial_registers={}, symbolic_registers={})
        fields = _literal_field_uses(facts, function, len(image))
        source, destination, size = struct.unpack_from("<III", image, 0x300)
        return ldm_word_loop_proof(
            facts, function, fields, 0x300, 0x304, 0x308,
            source, destination, size, len(image),
            target_ranges)

    def test_single_register_linked_loop_proves_exact_copy(self):
        proof = self.prove(_fixture())
        self.assertIsNotNone(proof)
        self.assertEqual(proof[0], 0x40)
        self.assertEqual(proof[2], CodeAddress(0x142, "thumb"))
        self.assertIn((0x300, 12), proof[1])
        self.assertIn((0x500, 0x40), proof[1])

    def test_wrong_store_register_and_branch_condition_reject(self):
        self.assertIsNone(self.prove(_fixture(wrong_store=True)))
        self.assertIsNone(self.prove(_fixture(wrong_branch=True)))

    def test_wrong_end_expression_and_multiregister_list_reject(self):
        self.assertIsNone(self.prove(_fixture(wrong_size=True)))
        self.assertIsNone(self.prove(_fixture(multi_register=True)))
        self.assertIsNone(self.prove(_fixture(end_register_alias=True)))

    def test_unaligned_extents_and_source_cursor_clobber_reject(self):
        self.assertIsNone(self.prove(_fixture(source=0x501)))
        self.assertIsNone(self.prove(_fixture(destination=0x01000001)))
        self.assertIsNone(self.prove(_fixture(source_clobber=True)))

    def test_entry_bypass_to_body_or_store_rejects(self):
        self.assertIsNone(self.prove(_fixture(entry_bypass_body=True)))
        self.assertIsNone(self.prove(_fixture(entry_bypass_store=True)))

    def test_direct_exit_bypass_and_early_return_reject(self):
        self.assertIsNone(self.prove(_fixture(exit_bypass=True)))
        self.assertIsNone(self.prove(_fixture(early_return=True)))

    def test_incomplete_function_rejects(self):
        self.assertIsNone(self.prove(_fixture(incomplete=True)))

    def test_target_extent_must_fit_one_configured_range(self):
        image = bytearray(_fixture())
        _put32(image, 0x304, 0x017FFFF0)
        _put32(image, 0x308, 0x40)
        facts = facts_for(bytes(image))
        function = facts.function(CodeAddress(0x100, "thumb"), budget=128,
                                  initial_registers={}, symbolic_registers={})
        fields = _literal_field_uses(facts, function, len(image))
        self.assertIsNone(ldm_word_loop_proof(
            facts, function, fields, 0x300, 0x304, 0x308,
            0x500, 0x017FFFF0, 0x40, len(image),
            ((0x01000000, 0x01800000),)))

    def test_destination_end_must_not_wrap_address_space(self):
        image = _fixture(destination=0xFFFFFFC0)
        facts = facts_for(image)
        function = facts.function(CodeAddress(0x100, "thumb"), budget=128,
                                  initial_registers={}, symbolic_registers={})
        fields = _literal_field_uses(facts, function, len(image))
        self.assertIsNone(ldm_word_loop_proof(
            facts, function, fields, 0x300, 0x304, 0x308,
            0x500, 0xFFFFFFC0, 0x40, len(image),
            ((0xFFFFFFC0, 0x100000000),)))

    def test_overlapping_source_and_destination_reject(self):
        self.assertIsNone(self.prove(
            _fixture(destination=0x500), target_ranges=((0x500, 0x800),)))

    def test_public_linked_cfg_hook_includes_ldm_copy(self):
        image = _fixture()
        facts = facts_for(image)
        function = facts.function(CodeAddress(0x100, "thumb"), budget=128,
                                  initial_registers={}, symbolic_registers={})
        records = linked_thumb_cfg_word_copies(
            facts, function, image, nor_end=len(image),
            ram_ranges=((0x01000000, 0x01800000),), detailed=True)
        self.assertEqual(
            [(record.source, record.target, record.written_size)
             for record in records],
            [(0x500, 0x01000000, 0x40)])


if __name__ == "__main__":
    unittest.main()
