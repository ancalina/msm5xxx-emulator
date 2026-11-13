"""Synthetic checks for immediate ARM/Thumb interworking calls."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.image_view import ImageView


def _thumb_blx(address: int, displacement: int) -> bytes:
    if displacement & 3 or not -(1 << 24) <= displacement < (1 << 24):
        raise ValueError("Thumb BLX displacement must be aligned and in range")
    encoded = displacement & 0x1FFFFFF
    sign = encoded >> 24 & 1
    i1, i2 = encoded >> 23 & 1, encoded >> 22 & 1
    j1, j2 = 1 ^ (i1 ^ sign), 1 ^ (i2 ^ sign)
    high = 0xF000 | sign << 10 | (encoded >> 12 & 0x3FF)
    low = 0xC800 | j1 << 13 | j2 << 11 | (encoded >> 2 & 0x3FF) << 1
    return struct.pack("<HH", high, low)


def _arm_blx(address: int, displacement: int) -> bytes:
    if displacement & 1 or not -(1 << 25) <= displacement < (1 << 25):
        raise ValueError("ARM BLX displacement must be halfword aligned and in range")
    encoded = displacement & 0x3FFFFFF
    word = 0xFA000000 | (encoded >> 1 & 1) << 24 | (encoded >> 2 & 0xFFFFFF)
    return struct.pack("<I", word)


class InterworkingCallIndexTests(unittest.TestCase):
    def test_thumb_blx_to_arm_uses_aligned_pc_and_signed_offsets(self):
        base = 0x1000
        image = (_thumb_blx(base, 4) + _thumb_blx(base + 4, -8)
                 + _thumb_blx(base + 8, 0x800000))
        facts = FirmwareFacts(image, base=base)

        self.assertEqual(
            facts.interworking_call_candidates(),
            ((CodeAddress(base, "thumb"), CodeAddress(base + 8, "arm")),
             (CodeAddress(base + 4, "thumb"), CodeAddress(base, "arm")),
             (CodeAddress(base + 8, "thumb"), CodeAddress(base + 0x80000C, "arm"))),
        )

    def test_arm_blx_to_thumb_preserves_halfword_target_and_signed_offsets(self):
        base = 0x2000
        image = _arm_blx(base, 2) + _arm_blx(base + 4, -10)
        facts = FirmwareFacts(image, base=base)

        self.assertEqual(
            facts.interworking_call_candidates(),
            ((CodeAddress(base, "arm"), CodeAddress(base + 10, "thumb")),
             (CodeAddress(base + 4, "arm"), CodeAddress(base + 2, "thumb"))),
        )

    def test_phase_bank_limit_and_nonzero_base_are_preserved(self):
        base = 0x3002
        code = _thumb_blx(base, -8) + bytes(4)
        view = ImageView.sparse(((base, code),), phase="loaded", bank="secondary")
        facts = FirmwareFacts(b"", base=base, view=view)

        found = facts.interworking_call_candidates(
            phase="loaded", bank="secondary", limit=len(code))
        self.assertEqual(
            found,
            ((CodeAddress(base, "thumb", "loaded", "secondary"),
              CodeAddress(0x2FFC, "arm", "loaded", "secondary")),),
        )
        self.assertEqual(facts.interworking_call_candidates(
            phase="loaded", bank="secondary", limit=2), ())

    def test_invalid_or_non_interworking_encodings_are_rejected(self):
        image = bytearray(0x20)
        struct.pack_into("<4H", image, 0, 0xF000, 0xE801, 0xF000, 0xF800)
        struct.pack_into("<2I", image, 8, 0xEB000000, 0xEA000000)
        facts = FirmwareFacts(bytes(image))

        self.assertEqual(facts.interworking_call_candidates(), ())
        self.assertEqual(facts.call_candidates("thumb"), ((4, 8),))
        self.assertIn((8, 16), facts.call_candidates("arm"))

        invalid = FirmwareFacts(struct.pack("<HH", 0xF000, 0xC801))
        self.assertEqual(invalid.interworking_call_candidates(), ())


if __name__ == "__main__":
    unittest.main()
