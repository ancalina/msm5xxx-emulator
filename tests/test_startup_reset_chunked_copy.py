"""Synthetic checks for bounded aligned-prefix/unrolled/tail copies."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.startup_reset_cfg_copy import _literal_field_uses
from msm5xxx_emulator.detection.startup_reset_chunked_copy import (
    chunked_word_loop_proof,
)


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value & 0xFFFF)


def _put32(image, address, value):
    struct.pack_into("<I", image, address, value & 0xFFFFFFFF)


def _branch(address, target, *, condition=None):
    delta = target - (address + 4)
    assert delta % 2 == 0
    offset = delta // 2
    if condition is None:
        return 0xE000 | (offset & 0x7FF)
    return 0xD000 | (condition << 8) | (offset & 0xFF)


def _fixture(*, source=0x500, destination=0x01000000, size=0x80,
             chunk_words=4, mutation=None):
    image = bytearray(0x1000)
    # Literal-pointer field loads followed by one direct field dereference.
    words = {
        0x100: 0x481F,       # LDR r0, [PC, #0x7c] -> pool 0x180 -> field 0x300
        0x102: 0x6805,       # LDR r5, [r0]
        0x104: 0x491F,       # LDR r1 -> pool 0x184 -> field 0x304
        0x106: 0x680C,       # LDR r4, [r1]
        0x108: 0x4A1F,       # LDR r2 -> pool 0x188 -> field 0x308
        0x10A: 0x6817,       # LDR r7, [r2]
        0x10C: 0x19E6,       # ADDS r6, r4, r7
        0x10E: _branch(0x10E, 0x120),
        0x110: 0xCD08,       # LDMIA r5!, {r3}
        0x112: 0xC408,       # STMIA r4!, {r3}
        0x114: 0x06E3,       # LSLS r3, r4, #27
        0x116: _branch(0x116, 0x120, condition=1),  # BNE prefix CMP
        0x118: _branch(0x118, 0x140),              # B bulk guard
        0x120: 0x42B4,       # CMP r4, r6
        0x122: _branch(0x122, 0x110, condition=3), # BLO prefix body
        0x124: _branch(0x124, 0x140),              # B bulk guard
        0x140: 0x1DE3,       # ADDS r3, r4, #7; second ADD patched below
        0x142: 0x3309,       # ADDS r3, #9 -> 16-byte chunk
        0x144: 0x42B3,       # CMP r3, r6
        0x146: _branch(0x146, 0x130, condition=3), # BLO unrolled chunk
        0x148: _branch(0x148, 0x14E),              # B tail CMP
        0x14A: 0xCD08,       # LDMIA r5!, {r3}
        0x14C: 0xC408,       # STMIA r4!, {r3}
        0x14E: 0x42B4,       # CMP r4, r6
        0x150: _branch(0x150, 0x14A, condition=3), # BLO tail body
        0x152: 0x4770,       # BX LR
    }
    for index in range(chunk_words):
        words[0x130 + index * 4] = 0xCD08
        words[0x132 + index * 4] = 0xC408
    words[0x140] = 0x1DE3   # ADDS r3, r4, #7
    words[0x142] = 0x3309   # ADDS r3, #9 -> 16 bytes
    if chunk_words != 4:
        # Keep the chunk size data-derived: two immediate additions sum to
        # exactly four bytes per unrolled pair. First ADD contributes seven.
        total = chunk_words * 4
        second = total - 7
        assert 0 <= second <= 255
        words[0x142] = 0x3300 | second
    if mutation:
        words.update(mutation)
    for address, value in words.items():
        _put16(image, address, value)
    _put32(image, 0x180, 0x300)
    _put32(image, 0x184, 0x304)
    _put32(image, 0x188, 0x308)
    _put32(image, 0x300, source)
    _put32(image, 0x304, destination)
    _put32(image, 0x308, size)
    image[source:source + size] = bytes((i * 17 + 3) & 0xFF for i in range(size))
    return bytes(image)


class StartupResetChunkedCopyTests(unittest.TestCase):
    def prove(self, image, target_ranges=((0x01000000, 0x01800000),),
              nor_end=None):
        facts = facts_for(image)
        function = facts.function(
            CodeAddress(0x100, "thumb"), budget=512,
            initial_registers={}, symbolic_registers={})
        fields = _literal_field_uses(facts, function, len(image))
        source, destination, size = struct.unpack_from("<III", image, 0x300)
        return chunked_word_loop_proof(
            facts, function, fields, 0x300, 0x304, 0x308,
            source, destination, size,
            len(image) if nor_end is None else nor_end, target_ranges)

    def test_aligned_prefix_bulk_and_tail_close(self):
        proof = self.prove(_fixture(size=0x80))
        self.assertIsNotNone(proof)
        self.assertEqual(proof[0], 0x80)
        self.assertEqual(proof[2], CodeAddress(0x152, "thumb"))
        self.assertIn((0x300, 12), proof[1])
        self.assertIn((0x500, 0x80), proof[1])

    def test_misaligned_start_prefix_and_short_tail(self):
        proof = self.prove(_fixture(destination=0x01000004, size=0x74))
        self.assertIsNotNone(proof)
        self.assertEqual(proof[0], 0x74)

    def test_reject_wrong_conditions_cursors_and_clobbered_end(self):
        self.assertIsNone(self.prove(_fixture(mutation={0x116: 0xD003})))
        self.assertIsNone(self.prove(_fixture(mutation={0x114: 0x06EB})))
        self.assertIsNone(self.prove(_fixture(mutation={0x120: 0x42B5})))
        self.assertIsNone(self.prove(_fixture(mutation={0x10C: 0x19FE})))
        self.assertIsNone(self.prove(_fixture(mutation={0x10E: _branch(0x10E, 0x110)})))

    def test_reject_bad_bulk_shape_and_flags(self):
        self.assertIsNone(self.prove(_fixture(mutation={0x138: 0x46C0})))
        self.assertIsNone(self.prove(_fixture(mutation={0x13A: 0xCC10})))
        self.assertIsNone(self.prove(_fixture(mutation={0x132: 0xC410})))
        self.assertIsNone(self.prove(_fixture(mutation={0x146: 0xD1F3})))
        self.assertIsNone(self.prove(_fixture(mutation={0x142: 0x3308})))

    def test_reject_incomplete_bounds_overlap_and_escape(self):
        self.assertIsNone(self.prove(_fixture(size=0x7F)))
        self.assertIsNone(self.prove(_fixture(source=0x501)))
        self.assertIsNone(self.prove(_fixture(destination=0x01000001)))
        self.assertIsNone(self.prove(_fixture(), nor_end=0x520))
        self.assertIsNone(self.prove(
            _fixture(source=0x500, destination=0x520, size=0x80),
            target_ranges=((0x400, 0x800),)))
        self.assertIsNone(self.prove(_fixture(destination=0xFFFFFF80),
                                     target_ranges=((0xFFFFFF80,
                                                    0x100000000),)))


if __name__ == "__main__":
    unittest.main()
