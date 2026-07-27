"""Closed-shape tests for automatic direct-MMIO keypad detection."""
from __future__ import annotations

import struct
import unittest
from pathlib import Path

from src.msm5xxx_emulator.detection.input_matrix import (
    DIRECT_MATRIX_FINGERPRINT,
    LG_RING256,
    SAMSUNG_RING32,
    find_direct_matrix_scanners,
    resolve_direct_matrix_input,
)


class DirectInputMatrixTests(unittest.TestCase):
    @staticmethod
    def _image(sink_words: tuple[int, ...]) -> bytearray:
        image = bytearray(b"\xff" * 0x180)
        struct.pack_into("<H", image, 0x10, 0xB500)
        image[0x20:0x20 + 26] = bytes.fromhex(
            "274800790007000f0f2807d023490623085c183958434018075d"
        )
        struct.pack_into("<H", image, 0x1C, 0x2400)
        struct.pack_into("<H", image, 0x3A, 0xE004)
        struct.pack_into(
            "<8H", image, 0x3C,
            0x3401, 0x0624, 0x0E24, 0x2C06,
            0xDBEB, 0x1C38, 0xF000, 0xF81A,
        )
        struct.pack_into(
            f"<{len(sink_words)}H", image, 0x80, *sink_words
        )
        struct.pack_into("<I", image, 0xBC, 0x100)
        struct.pack_into("<I", image, 0xC0, 0x03000690)
        image[0xE8:0x100] = bytes((
            99, 102, ord("1"), ord("4"), ord("7"), ord("*"),
            91, 83, ord("2"), ord("5"), ord("8"), ord("0"),
            101, 80, ord("3"), ord("6"), ord("9"), ord("#"),
            135, 100, 82, 0, 84, 85,
        ))
        image[0x100:0x110] = bytes((
            0, 1, 0, 2, 0, 1, 0, 3,
            0, 1, 0, 2, 0, 1, 0, 0,
        ))
        return image

    def test_samsung_ring32_profile_is_accepted(self) -> None:
        image = self._image((
            0xB580, 0x1C07, 0x28FF, 0x2F60, 0x06C0,
            0x0EC0, 0x7087, 0x7048, 0x4770,
        ))

        profile, status, rejected = resolve_direct_matrix_input(bytes(image))

        self.assertEqual(status, "accepted")
        self.assertEqual(rejected, [])
        assert profile is not None
        self.assertEqual(profile["event_sink_family"], SAMSUNG_RING32)
        self.assertEqual(
            profile["grammar_fingerprint"], DIRECT_MATRIX_FINGERPRINT
        )

    def test_samsung_raw_telemetry_requires_complete_relocation_abi(self) -> None:
        root = Path(__file__).resolve().parents[2]
        expected = {
            "x350_VC22.bin": (0x013A2248, 0x328E6, 0x32868, 0x32882, 0xB5252),
            "schx150.bin": (0x013A3EC8, 0x329B6, 0x32938, 0x32952, 0xB539A),
        }
        for name, values in expected.items():
            image = (root / "firmwares" / name).read_bytes()
            profile, status, rejected = resolve_direct_matrix_input(image)
            self.assertEqual((status, rejected), ("accepted", []))
            assert profile is not None
            self.assertEqual(
                tuple(profile[field] for field in (
                    "raw_ring", "raw_enqueue_store", "raw_dequeue",
                    "raw_dequeue_return", "raw_task_entry",
                )), values,
            )
            self.assertEqual(profile["raw_ring_capacity"], 32)
            self.assertEqual(profile["raw_enqueue_register"], 7)
            self.assertEqual(profile["raw_task_register"], 0)

            near_miss = bytearray(image)
            near_miss[values[2] + 0x16] ^= 1
            profile, status, rejected = resolve_direct_matrix_input(bytes(near_miss))
            self.assertEqual((status, rejected), ("accepted", []))
            assert profile is not None
            self.assertNotIn("raw_ring", profile)

    def test_lg_ring256_shape_is_classified_without_model_name(self) -> None:
        image = self._image((
            0xB580, 0x1C07, 0x0600, 0x0E00,
            0x7107, 0x8800, 0x8840, 0x8040, 0x4770,
        ))

        profile, status, rejected = resolve_direct_matrix_input(bytes(image))

        self.assertEqual((status, rejected), ("accepted", []))
        assert profile is not None
        self.assertEqual(profile["event_sink_family"], LG_RING256)

    def test_unclosed_sink_is_rejected_with_exact_reason(self) -> None:
        image = self._image((
            0xB580, 0x1C07, 0x28FF, 0x2F60, 0x46C0,
            0x0EC0, 0x7087, 0x7048, 0x4770,
        ))

        profile, status, rejected = resolve_direct_matrix_input(bytes(image))

        self.assertIsNone(profile)
        self.assertEqual(status, "rejected")
        self.assertEqual(
            rejected[0]["reasons"],
            ["event-sink-family-unclassified"],
        )

    def test_evidenced_pre_push_entry_is_recovered(self) -> None:
        image = self._image((
            0xB580, 0x1C07, 0x28FF, 0x2F60, 0x06C0,
            0x0EC0, 0x7087, 0x7048, 0x4770,
        ))
        struct.pack_into("<2H", image, 0x0E, 0x4841, 0xB500)
        struct.pack_into("<H", image, 0x12, 0x7800)
        struct.pack_into("<I", image, 0x114, 0x03000000)
        struct.pack_into("<I", image, 0x118, 0x0F)

        scanner = find_direct_matrix_scanners(bytes(image))[0]

        self.assertEqual(scanner["function"], 0x0E)
        self.assertEqual(
            scanner["callable_entry_evidence"],
            "pc-literal+inbound-reference+post-push-consumer",
        )


if __name__ == "__main__":
    unittest.main()
