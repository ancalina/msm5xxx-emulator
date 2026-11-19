"""Synthetic tests for literal-linked scalar copy loops with GPIO pulses."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.startup_reset_cfg_copy import (
    _literal_field_uses, linked_thumb_cfg_word_copies,
)
from msm5xxx_emulator.detection.startup_reset_pulsed_copy import (
    pulsed_word_loop_proof,
)


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value)


def _put32(image, address, value):
    struct.pack_into("<I", image, address, value)


def _fixture(*, source=0x500, destination=0x01000000, size=0x40,
             port=0x03000700, high=1, low=0, wrong_branch=False,
             missing_high=False, missing_low=False, wrong_port=False,
             extra_write=False, entry_bypass=False,
             early_return=False, source_clobber=False,
             high_alias_value=False, port_alias_value=False,
             source_word=0x03020100):
    image = bytearray(0x800)
    words = {
        0x100: 0x481F,  # LDR r0, literal address 0x300
        0x102: 0x6805,  # LDR r5, [r0] source
        0x104: 0x491F,  # LDR r1, literal address 0x304
        0x106: 0x680F,  # LDR r7, [r1] destination
        0x108: 0x4B1F,  # LDR r3, literal address 0x308
        0x10A: 0x681C,  # LDR r4, [r3] size
        0x10C: 0x193E,  # ADDS r6, r7, r4 -> end
        0x10E: 0x4A1F,  # LDR r2, literal port address
        0x110: 0x2000 | high,  # MOVS r0, high level
        0x112: 0x2100 | low,  # MOVS r1, low level
        0x114: 0x2500 if source_clobber else 0x46C0,
        0x116: 0xE00D,  # B first CMP at 0x134
        0x128: 0x682B,  # LDR r3, [r5]
        0x12A: 0x603B,  # STR r3, [r7]
        0x12C: (0x46C0 if missing_high else
                0x7013 if high_alias_value else
                0x7018 if port_alias_value else 0x7010),
        0x12E: (0x46C0 if missing_low else
                0x7019 if port_alias_value else 0x7011),
        0x130: 0x3504,  # ADDS r5, #4
        0x132: 0x3704,  # ADDS r7, #4
        0x134: 0x42B7,  # CMP r7, r6
        0x136: 0xD2F7 if wrong_branch else 0xD3F7,  # BHS/BLO 0x128
        0x138: 0x4770,  # BX LR
        0x13A: 0x4770,  # independent return for early-return negative
    }
    if wrong_port:
        words[0x12E] = 0x7019  # STRB r1, [r3], not the pulse port
    if extra_write:
        # Add an unmodeled third pulse before cursor updates.
        words[0x116] = 0xE00E
        words[0x130] = 0x7010
        words[0x132] = 0x3504
        words[0x134] = 0x3704
        words[0x136] = 0x42B7
        words[0x138] = 0xD3F6
        words[0x13A] = 0x4770
    if entry_bypass or early_return:
        target = 0x13A if early_return else 0x138
        delta = (target - (0x116 + 4)) // 2
        words[0x114] = 0x45C8  # CMP r8,r9; both inputs remain unknown
        words[0x116] = 0xD000 | delta  # BEQ direct exit/return
        words[0x118] = 0xE00C  # B first copy CMP at 0x134
    for address, value in words.items():
        _put16(image, address, value)
    _put32(image, 0x180, 0x300)
    _put32(image, 0x184, 0x304)
    _put32(image, 0x188, 0x308)
    _put32(image, 0x18C, port)
    _put32(image, 0x300, source)
    _put32(image, 0x304, destination)
    _put32(image, 0x308, size)
    image[0x500:0x540] = bytes(range(0x40))
    _put32(image, 0x500, source_word)
    return bytes(image)


class StartupResetPulsedCopyTests(unittest.TestCase):
    def prove(self, image, target_ranges=((0x01000000, 0x01800000),),
              nor_end=None):
        facts = facts_for(image)
        function = facts.function(
            CodeAddress(0x100, "thumb"), budget=128,
            initial_registers={}, symbolic_registers={})
        fields = _literal_field_uses(facts, function, len(image))
        source, destination, size = struct.unpack_from("<III", image, 0x300)
        return pulsed_word_loop_proof(
            facts, function, fields, 0x300, 0x304, 0x308,
            source, destination, size,
            len(image) if nor_end is None else nor_end, target_ranges)

    def test_linked_fixed_pulse_loop_proves_exact_copy(self):
        proof = self.prove(_fixture())
        self.assertIsNotNone(proof)
        self.assertEqual(proof[0], 0x40)
        self.assertEqual(proof[2], CodeAddress(0x138, "thumb"))
        self.assertIn((0x300, 12), proof[1])
        self.assertIn((0x500, 0x40), proof[1])
        self.assertNotIn((0x03000700, 1), proof[1])

    def test_wrong_pulse_values_or_port_reject(self):
        self.assertIsNone(self.prove(_fixture(high=0)))
        self.assertIsNone(self.prove(_fixture(low=1)))
        self.assertIsNone(self.prove(_fixture(wrong_port=True)))
        self.assertIsNone(self.prove(_fixture(port=0x03000800)))
        self.assertIsNone(self.prove(_fixture(extra_write=True)))

    def test_pulse_value_and_port_cannot_alias_copy_data(self):
        # The first source word is 1, so using it as the high-pulse source
        # could appear correct on the first iteration while failing later.
        self.assertIsNone(self.prove(_fixture(
            high_alias_value=True, source_word=1)))
        self.assertIsNone(self.prove(_fixture(port_alias_value=True)))

    def test_missing_pulse_wrong_flags_and_cursor_clobber_reject(self):
        self.assertIsNone(self.prove(_fixture(missing_high=True)))
        self.assertIsNone(self.prove(_fixture(missing_low=True)))
        self.assertIsNone(self.prove(_fixture(wrong_branch=True)))
        self.assertIsNone(self.prove(_fixture(source_clobber=True)))

    def test_direct_exit_and_early_return_bypasses_reject(self):
        self.assertIsNone(self.prove(_fixture(entry_bypass=True)))
        self.assertIsNone(self.prove(_fixture(early_return=True)))

    def test_alignment_bounds_overlap_and_port_range_reject(self):
        self.assertIsNone(self.prove(_fixture(source=0x501)))
        self.assertIsNone(self.prove(_fixture(destination=0x01000001)))
        self.assertIsNone(self.prove(_fixture(size=0x42)))
        self.assertIsNone(self.prove(_fixture(), nor_end=0x520))
        self.assertIsNone(self.prove(
            _fixture(source=0x500, destination=0x520, size=0x40),
            target_ranges=((0x400, 0x800),)))
        self.assertIsNone(self.prove(_fixture(destination=0x01000000,
                                              source=0x500),
                                     target_ranges=((0x500, 0x800),)))
        self.assertIsNone(self.prove(
            _fixture(destination=0xFFFFFFC0),
            target_ranges=((0xFFFFFFC0, 0x100000000),)))
        self.assertIsNone(self.prove(
            _fixture(destination=0x03000800),
            target_ranges=((0x03000700, 0x03001000),)))

    def test_public_linked_cfg_hook_includes_pulsed_copy(self):
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
