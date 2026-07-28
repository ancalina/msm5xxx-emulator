"""Focused exact KEYEMUL semantic-parser checks."""
from __future__ import annotations

import hashlib
import json
import struct
import unittest

import msm5xxx_emulator.detection.input_semantics as semantic
from msm5xxx_emulator.detection.input_semantics import (
    KEYEMU_EVENTS,
    KEYEMU_GRAMMAR_FINGERPRINT,
    KEYEMU_NORMALIZER,
    KEYEMU_SEMANTIC_CONTRACT,
    KEYEMUL_MARKER,
    detect_keyemu_semantics,
)


def _branch(source: int, target: int) -> int:
    return 0xE000 | ((target - source - 4) // 2 & 0x7FF)


def _bl(source: int, target: int) -> bytes:
    displacement = (target - source - 4) & 0x7FFFFF
    return struct.pack("<2H", 0xF000 | displacement >> 12 & 0x7FF,
                       0xF800 | displacement >> 1 & 0x7FF)


class KeyemuSemanticsTests(unittest.TestCase):
    @staticmethod
    def _image(variant: str) -> bytearray:
        image = bytearray(b"\xff" * 0x500)
        normalizer, common, dispatcher = 0x100, 0x300, 0x380
        image[0xFC:0xFE] = b"\x00\xb5"
        image[normalizer:normalizer + len(KEYEMU_NORMALIZER)] = KEYEMU_NORMALIZER
        after = normalizer + len(KEYEMU_NORMALIZER)
        struct.pack_into("<H", image, after, 0xD201)
        targets: dict[str, int] = {digit: common for digit in "0123456789"}
        targets["#"], targets["*"] = common - 2, 0x208
        for index, (key, value) in enumerate(KEYEMU_EVENTS):
            target = 0x220 + index * 8
            targets[key] = target
            struct.pack_into(
                "<2H", image, target,
                0x2000 | value, _branch(target + 2, common),
            )
        targets["W"] = 0x2A0
        struct.pack_into("<2H", image, 0x2A0, 0x2087, _branch(0x2A2, common))
        targets["E"], targets["L"] = 0x2A8, 0x2B8
        struct.pack_into(
            "<7H", image, 0x2A8,
            0x7800, 0x2800, 0xD001, 0x2060,
            _branch(0x2B0, common), 0x2051, _branch(0x2B4, common),
        )
        struct.pack_into(
            "<7H", image, 0x2B8,
            0x2800, 0xD001, 0x2078, _branch(0x2BE, common),
            0x20FF, 0x3002, _branch(0x2C4, common),
        )
        struct.pack_into("<H", image, common - 2, 0x2023)
        struct.pack_into("<2H", image, 0x208, 0x202A, _branch(0x20A, common))
        image[common:common + 4] = _bl(common, dispatcher)
        struct.pack_into("<H", image, common + 4, 0x20FF)
        image[common + 6:common + 10] = _bl(common + 6, dispatcher)
        if variant == "byte-offset-table":
            table = ((after + 6) & ~3) + 8
            struct.pack_into(
                "<4H", image, after + 2,
                0xA302, 0x5C5B, 0x005B, 0x449F,
            )
            base = after + 12
            for character, target in targets.items():
                image[table + ord(character) - 0x23] = (target - base) // 2
        else:
            table = after + 8
            struct.pack_into("<2H", image, after + 2, 0x004B, 0x449F)
            for character, target in targets.items():
                source = table + 2 * (ord(character) - 0x23)
                struct.pack_into("<H", image, source, _branch(source, target))
        return image

    def test_byte_offset_table_accepts_complete_grammar(self) -> None:
        result = detect_keyemu_semantics(
            self._image("byte-offset-table"), 0x10000000
        ).as_dict()
        self.assertEqual(result["variant"], "byte-offset-table")
        self.assertEqual(result["event_map"]["O"], [0x53])
        self.assertEqual(result["event_map"]["("], [0x5F])
        self.assertEqual(result["event_map"][")"], [0x60])
        self.assertIn("paired-flip-tokens", result["evidence"])
        self.assertEqual(result["event_map"]["E"], [0x51, 0x60])
        self.assertEqual(result["addresses"]["normalizer"], 0x10000100)

    def test_halfword_branch_table_accepts_complete_grammar(self) -> None:
        result = detect_keyemu_semantics(self._image("halfword-branch-table"))
        self.assertEqual(result.variant, "halfword-branch-table")
        self.assertEqual(dict(result.event_map)["release"], (0xFF,))

    def test_fingerprint_reproduces_semantic_contract(self) -> None:
        self.assertEqual(
            KEYEMU_GRAMMAR_FINGERPRINT,
            hashlib.sha256(json.dumps(
                KEYEMU_SEMANTIC_CONTRACT, sort_keys=True,
                separators=(",", ":"),
            ).encode()).hexdigest(),
        )

    def test_external_event_mutation_cannot_change_admission(self) -> None:
        fingerprint = KEYEMU_GRAMMAR_FINGERPRINT
        with self.assertRaises(TypeError):
            KEYEMU_EVENTS[0] = ("(", 0x5E)

        external = dict(KEYEMU_EVENTS)
        external["("] = 0x5E
        image = self._image("byte-offset-table")
        struct.pack_into("<H", image, 0x220, 0x205E)

        self.assertEqual(
            detect_keyemu_semantics(image).confidence, "rejected"
        )
        self.assertEqual(KEYEMU_GRAMMAR_FINGERPRINT, fingerprint)
        self.assertEqual(
            KEYEMU_GRAMMAR_FINGERPRINT,
            hashlib.sha256(json.dumps(
                KEYEMU_SEMANTIC_CONTRACT, sort_keys=True,
                separators=(",", ":"),
            ).encode()).hexdigest(),
        )

    def test_public_event_rebind_cannot_change_admission(self) -> None:
        original = semantic.KEYEMU_EVENTS
        fingerprint = semantic.KEYEMU_GRAMMAR_FINGERPRINT
        image = self._image("byte-offset-table")
        struct.pack_into("<H", image, 0x220, 0x205E)
        try:
            semantic.KEYEMU_EVENTS = (("(", 0x5E),) + original[1:]
            self.assertEqual(
                semantic.detect_keyemu_semantics(image).confidence, "rejected"
            )
            self.assertEqual(
                semantic.KEYEMU_GRAMMAR_FINGERPRINT, fingerprint
            )
            self.assertEqual(
                fingerprint,
                hashlib.sha256(json.dumps(
                    semantic.KEYEMU_SEMANTIC_CONTRACT, sort_keys=True,
                    separators=(",", ":"),
                ).encode()).hexdigest(),
            )
        finally:
            semantic.KEYEMU_EVENTS = original

    def test_near_miss_rejects_wrong_common_dispatcher(self) -> None:
        image = self._image("byte-offset-table")
        struct.pack_into("<H", image, 0x220 + 2, _branch(0x222, 0x286))
        result = detect_keyemu_semantics(image)
        self.assertEqual(result.confidence, "rejected")
        self.assertEqual(result.reject_reason, "normalizer-without-exact-grammar")

    def test_near_miss_rejects_each_mutated_flip_token(self) -> None:
        for address, event in ((0x220, 0x5E), (0x228, 0x5F)):
            with self.subTest(address=address):
                image = self._image("byte-offset-table")
                struct.pack_into("<H", image, address, 0x2000 | event)
                result = detect_keyemu_semantics(image)
                self.assertEqual(result.confidence, "rejected")
                self.assertEqual(
                    result.reject_reason, "normalizer-without-exact-grammar"
                )

    def test_truncated_table_rejects_without_exception(self) -> None:
        result = detect_keyemu_semantics(
            bytes(self._image("byte-offset-table")[:0x150])
        )
        self.assertEqual(result.confidence, "rejected")

    def test_multiple_reachable_release_calls_are_rejected(self) -> None:
        image = self._image("byte-offset-table")
        struct.pack_into("<H", image, 0x30A, 0x20FF)
        image[0x30C:0x310] = _bl(0x30C, 0x380)

        result = detect_keyemu_semantics(image)

        self.assertEqual(result.confidence, "rejected")

    def test_extension_variant_and_marker_only_status(self) -> None:
        image = self._image("byte-offset-table")
        struct.pack_into("<H", image, 0x2A0, 0x208C)
        result = detect_keyemu_semantics(image)
        self.assertEqual(dict(result.event_map)["W"], (0x8C,))

        marker_only = detect_keyemu_semantics(KEYEMUL_MARKER)
        self.assertEqual(
            (marker_only.confidence, marker_only.reject_reason),
            ("rejected", "marker-without-normalizer"),
        )
        absent = detect_keyemu_semantics(b"\xff" * 64)
        self.assertEqual(
            (absent.confidence, absent.reject_reason),
            ("not-found", "not-found"),
        )


if __name__ == "__main__":
    unittest.main()
