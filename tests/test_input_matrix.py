"""Closed-shape tests for automatic direct-MMIO keypad detection."""
from __future__ import annotations

from corpus import snippet

import os
import struct
import unittest
from pathlib import Path

from src.msm5xxx_emulator.detection.input_matrix import (
    DIRECT_MATRIX_FINGERPRINT,
    LG_RING256,
    SAMSUNG_DUAL_PLANE_RING32,
    SAMSUNG_RING32,
    _same_image_keyemu_ok_mapping,
    _same_image_ring32_confirm_mapping,
    _same_image_selected_confirm_mapping,
    _SAMSUNG_CONFIRM_CONVERTER,
    _SAMSUNG_CONFIRM_STATE_CONVERTER,
    _SAMSUNG_CONFIRM_PRESS,
    _SAMSUNG_CONFIRM_MESSAGE_SINK,
    _samsung_consumer_route_metadata,
    _samsung_flags_sideband_51_metadata,
    _samsung_sideband_51_family_metadata,
    _samsung_raw_saved_consumer_metadata,
    classify_matrix_event_sink,
    find_direct_matrix_scanners,
    resolve_direct_matrix_input,
    resolve_distributed_matrix_input,
)
from src.msm5xxx_emulator.detection.input_semantics import (
    KEYEMU_GRAMMAR_FINGERPRINT,
    KEYEMU_PASSTHROUGH,
    KeyemuSemantics,
)
from corpus import FIRMWARE_ROOT


def _test_firmware_root() -> Path | None:
    return FIRMWARE_ROOT if FIRMWARE_ROOT.is_dir() else None


class DirectInputMatrixTests(unittest.TestCase):
    def test_saved_register_ring32_consumer_requires_complete_chain(self) -> None:
        image = bytearray(b"\xff" * 0x400)
        sink, ring, dequeue, receiver, task = (
            0x100, 0x01002000, 0x200, 0x280, 0x300
        )

        def call(at: int, target: int) -> None:
            displacement = target - (at + 4)
            struct.pack_into(
                "<2H", image, at,
                0xF000 | (displacement >> 12 & 0x7FF),
                0xF800 | (displacement >> 1 & 0x7FF),
            )

        struct.pack_into("<H", image, sink, 0xB500)
        struct.pack_into("<H", image, sink + 4, 0x4A1E)
        for current in range(sink + 6, sink + 0x5E, 2):
            struct.pack_into("<H", image, current, 0x46C0)
        struct.pack_into(
            "<3H", image, sink + 0x5E, 0x1880, 0x7087, 0x4770
        )
        struct.pack_into("<I", image, 0x180, ring)
        struct.pack_into(
            "<14H", image, dequeue,
            0x4A06, 0x7850, 0x7811, 0x4288, 0xD101, 0x2000, 0x4770,
            0x1888, 0x3101, 0x06C9, 0x0EC9, 0x7880, 0x7011, 0x4770,
        )
        struct.pack_into("<I", image, dequeue + 28, ring)
        call(receiver, dequeue)
        struct.pack_into("<2H", image, receiver + 4, 0x1C04, 0xD001)
        call(receiver + 8, task)
        struct.pack_into("<H", image, receiver + 12, 0x4770)
        struct.pack_into(
            "<7H", image, task,
            0x2C51, 0x46C0, 0x2C54, 0x46C0, 0x2C55, 0x46C0, 0x4770,
        )

        metadata = _samsung_raw_saved_consumer_metadata(
            bytes(image), sink, [0x51, 0x54, 0x55], 0x100000
        )
        self.assertEqual(metadata["raw_task_register"], 4)
        self.assertEqual(metadata["raw_ring"], ring)
        struct.pack_into("<I", image, dequeue + 28, ring + 4)
        self.assertIsNone(_samsung_raw_saved_consumer_metadata(
            bytes(image), sink, [0x51, 0x54, 0x55], 0x100000
        ))

    def test_exact_keyemu_binds_only_unique_shared_ok_namespace(self) -> None:
        event_map = tuple(
            (character, (ord(character),))
            for character in KEYEMU_PASSTHROUGH
        ) + (("O", (0x53,)), ("release", (0xFF,)))
        semantics = KeyemuSemantics(
            "test", (), event_map, "exact-native", (),
            KEYEMU_GRAMMAR_FINGERPRINT, None,
        )
        profile = {
            "event_codes": [
                *map(ord, KEYEMU_PASSTHROUGH), 0x53, 0x65,
            ],
        }

        mapping = _same_image_keyemu_ok_mapping(profile, semantics)

        self.assertEqual(mapping[5]["event"], 0x53)
        profile["event_codes"].append(0x53)
        self.assertEqual(_same_image_keyemu_ok_mapping(profile, semantics), {})

    def test_ring32_confirm_mapping_requires_complete_paired_consumer(self) -> None:
        def fixture(shape: str, relocation: int = 0, load_address: int = 0x100000):
            image = bytearray(b"\xff" * 0x1400)
            call, converter, press, sink, dequeue = (
                position + relocation
                for position in (0x200, 0x700, 0xA00, 0xB00, 0xC00)
            )
            raw = call - 0x60

            def bl(at: int, target: int) -> None:
                displacement = target - at - 4
                struct.pack_into(
                    "<2H", image, at,
                    0xF000 | (displacement >> 12 & 0x7FF),
                    0xF800 | (displacement >> 1 & 0x7FF),
                )

            def branch(at: int, target: int, opcode: int) -> None:
                struct.pack_into("<H", image, at,
                                 opcode | ((target - at - 4) // 2 & 0xFF))

            image[converter:converter + len(_SAMSUNG_CONFIRM_CONVERTER)] = _SAMSUNG_CONFIRM_CONVERTER
            image[press:press + len(_SAMSUNG_CONFIRM_PRESS)] = _SAMSUNG_CONFIRM_PRESS
            image[sink:sink + len(_SAMSUNG_CONFIRM_MESSAGE_SINK)] = _SAMSUNG_CONFIRM_MESSAGE_SINK
            bl(call, converter)
            bl(raw, dequeue)
            struct.pack_into("<H", image, raw + 4, 0x2800)
            branch(raw + 6, call + 0x70, 0xD000)
            if shape == "valid-event-timestamp":
                struct.pack_into("<H", image, raw + 8, 0x28FF)
                raw_guard = raw + 0xA
                image[call + 4:call + 0xA] = bytes.fromhex("0123071cd842")
                branch(call + 0xA, call + 0x44, 0xD000)
                struct.pack_into("<H", image, call + 0xC, 0x4800)
                bl(call + 0xE, 0xD00)
                struct.pack_into("<H", image, call + 0x12, 0x1C38)
                press_call = call + 0x14
            else:
                struct.pack_into("<2H", image, raw + 8, 0x4D00, 0x28FF)
                raw_guard = raw + 0xC
                image[call + 4:call + 8] = bytes.fromhex("071cbf28")
                branch(call + 8, call + 0x10, 0xD100)
                struct.pack_into("<H", image, call + 0xA, 0x4800)
                bl(call + 0xC, 0xD00)
                struct.pack_into("<H", image, call + 0x10, 0x1C38)
                press_call = call + 0x12
            branch(raw_guard, call, 0xD100)
            bl(press_call, press)
            bl(press + 0x10, sink)
            struct.pack_into("<2I", image, sink + 0x44,
                             0x01003000, 0x01004000)
            profile = {
                "event_sink_family": SAMSUNG_RING32,
                "raw_ring": 0x01002000,
                "raw_dequeue": load_address + dequeue,
                "raw_consumer_evidence": "samsung-byte-ring32-r0-receiver-v1",
                "event_codes": [*b"123456789*0#", 0x53, 0x54, 0x55,
                                0x5B, 0x63, 0x64, 0x65, 0x66],
            }
            return image, profile, load_address, bl, {
                "call": call, "raw": raw, "dequeue": dequeue,
                "converter": converter, "raw_guard": raw_guard,
                "press_call": press_call, "press": press, "sink": sink,
            }

        fingerprints = set()
        for shape in ("valid-event-timestamp", "conditional-timestamp"):
            for relocation, base in ((0, 0), (0, 0x100000), (0x100, 0x200000)):
                with self.subTest(shape=shape, relocation=relocation, base=base):
                    image, profile, load, _, sites = fixture(shape, relocation, base)
                    mapping, metadata = _same_image_ring32_confirm_mapping(
                        bytes(image), profile, load,
                    )
                    self.assertEqual(mapping[5]["event"], 0x53)
                    self.assertEqual(mapping[5]["converter"], load + sites["converter"])
                    self.assertEqual(metadata, {
                        "ok_mapping_status": "accepted-provisional",
                        "ok_mapping_reject_reasons": [],
                    })
                    fingerprints.add(mapping[5]["semantic_grammar_fingerprint"])
        self.assertEqual(len(fingerprints), 1)

        negatives = {
            "other-ring": "dequeue-call-mismatch",
            "raw-guard-edge": "raw-release-guard-unclosed",
            "empty-edge": "raw-release-guard-unclosed",
            "result-save": "translated-press-shape-unclosed",
            "invalid-edge": "translated-press-shape-unclosed",
            "press-target": "press-message-abi-mismatch",
            "press-action": "press-message-abi-mismatch",
            "sink-target": "message-sink-unclosed",
            "sink-body": "message-sink-unclosed",
            "sink-literal": "message-sink-unclosed",
            "missing-caller": "converter-caller-not-unique",
            "multiple-callers": "converter-caller-not-unique",
            "multiple-converters": "exact-converter-missing-or-ambiguous",
            "converter-variant": "exact-converter-missing-or-ambiguous",
            "duplicate-event": "namespace-not-unique",
            "missing-event": "namespace-not-unique",
            "missing-raw-metadata": "raw-consumer-not-closed",
        }
        for mutation, expected in negatives.items():
            with self.subTest(mutation=mutation):
                image, profile, load, bl, sites = fixture("valid-event-timestamp")
                if mutation == "other-ring":
                    bl(sites["raw"], sites["dequeue"] + 0x40)
                elif mutation == "raw-guard-edge":
                    image[sites["raw_guard"]] ^= 1
                elif mutation == "empty-edge":
                    struct.pack_into("<H", image, sites["raw"] + 6, 0xD000)
                elif mutation == "result-save":
                    image[sites["call"] + 6] ^= 1
                elif mutation == "invalid-edge":
                    struct.pack_into("<H", image, sites["call"] + 0xA, 0xD000)
                elif mutation == "press-target":
                    bl(sites["press_call"], sites["press"] + 2)
                elif mutation == "press-action":
                    image[sites["press"] + 4] = 2
                elif mutation == "sink-target":
                    bl(sites["press"] + 0x10, sites["sink"] + 2)
                elif mutation == "sink-body":
                    image[sites["sink"] + 0x1C] ^= 1
                elif mutation == "sink-literal":
                    struct.pack_into("<I", image, sites["sink"] + 0x44, 0)
                elif mutation == "missing-caller":
                    bl(sites["call"], sites["converter"] + 2)
                elif mutation == "multiple-callers":
                    bl(0x1000, sites["converter"])
                elif mutation == "multiple-converters":
                    image[0x1000:0x1000 + len(_SAMSUNG_CONFIRM_CONVERTER)] = _SAMSUNG_CONFIRM_CONVERTER
                elif mutation == "converter-variant":
                    image[sites["converter"]] ^= 1
                elif mutation == "duplicate-event":
                    profile["event_codes"].append(0x53)
                elif mutation == "missing-event":
                    profile["event_codes"].remove(0x54)
                else:
                    del profile["raw_dequeue"]
                mapping, metadata = _same_image_ring32_confirm_mapping(bytes(image), profile, load)
                self.assertEqual(mapping, {})
                self.assertEqual(metadata["ok_mapping_reject_reasons"], [expected])

    def test_confirm_class_preserves_keyemu_priority_and_admits_saved_state(self) -> None:
        root = _test_firmware_root()
        cases = (
            ("SCH-X250.bin", "same-image-exact-keyemul-O-unique-cell"),
            ("incoming-msm5xxx-candidates-20260726/Samsung/SCH-X250/X250rus/extracted/X250rus.bin",
             "same-image-exact-keyemul-O-unique-cell"),
            ("SCH-X350_UJ08_JTAG.bin", "same-image-ring32-confirm-consumer-v1"),
            ("schx150.bin", "same-image-ring32-confirm-saved-state-v1"),
        )
        if root is None or any(not (root / path).is_file() for path, _ in cases):
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        for path, expected_rule in cases:
            with self.subTest(path=path):
                profile, status, rejected = resolve_direct_matrix_input((root / path).read_bytes())
                self.assertEqual((status, rejected), ("accepted", []))
                self.assertIsNotNone(profile)
                mapping = profile.get("provisional_mappings", {}).get(5)
                if expected_rule is None:
                    self.assertIsNone(mapping)
                    self.assertEqual(profile["ok_mapping_reject_reasons"],
                                     ["exact-converter-missing-or-ambiguous"])
                else:
                    self.assertEqual(mapping["event"], 0x53)
                    self.assertEqual(mapping["rule"], expected_rule)

    def test_saved_state_confirm_requires_reached_clock_preservation(self) -> None:
        root = _test_firmware_root()
        if root is None or not (root / "schx150.bin").is_file():
            self.skipTest("firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT")
        original = (root / "schx150.bin").read_bytes()
        profile, status, rejected = resolve_direct_matrix_input(original)
        self.assertEqual((status, rejected), ("accepted", []))
        original_mapping = profile["provisional_mappings"][5]
        call = original_mapping["converter_callsite"]
        raw = call - 0x66

        from src.msm5xxx_emulator.detection.arm import thumb_bl_target

        def literal_slot(image, at):
            word = struct.unpack_from("<H", image, at)[0]
            return ((at + 4) & ~3) + (word & 0xFF) * 4

        def bl(image, at, target):
            displacement = target - at - 4
            struct.pack_into("<2H", image, at,
                             0xF000 | (displacement >> 12 & 0x7FF),
                             0xF800 | (displacement >> 1 & 0x7FF))

        for relocation, base in ((0, 0), (0x100, 0x100000)):
            with self.subTest(relocation=relocation, base=base):
                image = b"\xff" * relocation + original
                relocated_profile = dict(profile, raw_dequeue=profile["raw_dequeue"] + relocation + base)
                mapping, metadata = _same_image_ring32_confirm_mapping(image, relocated_profile, base)
                self.assertEqual(metadata["ok_mapping_status"], "accepted-provisional")
                self.assertEqual(mapping[5]["converter_callsite"], call + relocation + base)
                self.assertEqual(mapping[5]["semantic_status"], "temporary-evidence-gated-provisional")
                self.assertEqual(mapping[5]["semantic_grammar_fingerprint"],
                                 original_mapping["semantic_grammar_fingerprint"])

        clock = thumb_bl_target(original, call + 0x10)
        hardware = thumb_bl_target(original, clock + 0x26)
        state = struct.unpack_from("<I", original, literal_slot(original, raw + 8))[0]
        for mutation in ("clock-store", "callee-store", "output-alias", "flag-alias",
                         "unaligned-state", "store-offset", "reload-offset", "bad-edge",
                         "clock-edge", "ambiguous-signature", "ambiguous-caller", "zero-divisor",
                         "timestamp-pointer-clobber"):
            with self.subTest(mutation=mutation):
                image = bytearray(original)
                expected = "saved-state-clock-unclosed"
                if mutation == "clock-store":
                    image[clock + 0x18] ^= 1
                elif mutation == "timestamp-pointer-clobber":
                    struct.pack_into("<H", image, raw - 8, 0x2400)
                elif mutation == "callee-store":
                    addition = thumb_bl_target(original, clock + 0x60)
                    image[addition + 0x1E] ^= 1
                elif mutation == "output-alias":
                    struct.pack_into("<I", image, literal_slot(image, raw - 0xC), state + 0x20)
                elif mutation == "flag-alias":
                    struct.pack_into("<I", image, literal_slot(image, hardware + 8), state + 0x20)
                elif mutation == "unaligned-state":
                    struct.pack_into("<I", image, literal_slot(image, raw + 8), state + 1)
                elif mutation in ("store-offset", "reload-offset"):
                    image[call + (0xA if mutation == "store-offset" else 0x14)] ^= 0x40
                    expected = "translated-press-shape-unclosed"
                elif mutation == "bad-edge":
                    bl(image, clock + 0x20, clock + 2)
                elif mutation == "clock-edge":
                    bl(image, call + 0x10, clock + 2)
                elif mutation == "ambiguous-signature":
                    image += b"\xff" * (len(image) & 1) + _SAMSUNG_CONFIRM_STATE_CONVERTER
                    expected = "exact-converter-missing-or-ambiguous"
                elif mutation == "ambiguous-caller":
                    bl(image, 0, original_mapping["converter"])
                    expected = "converter-caller-not-unique"
                else:
                    struct.pack_into("<I", image, literal_slot(image, hardware + 0x28), 0)
                mapping, metadata = _same_image_ring32_confirm_mapping(bytes(image), profile, 0)
                self.assertEqual(mapping, {})
                self.assertEqual(metadata["ok_mapping_reject_reasons"], [expected])

    def test_dual_plane_features_must_share_one_return_path(self) -> None:
        image = bytearray(b"\xff" * 0x30)
        struct.pack_into(
            "<5H", image, 0,
            0xB500, 0x1C04, 0x46C0, 0x1C0D, 0xD006,
        )
        struct.pack_into(
            "<6H", image, 0x0A,
            0x06C0, 0x0EC0, 0x7084, 0x7085, 0x7040, 0x4770,
        )
        struct.pack_into("<4H", image, 0x18,
                         0x06C0, 0x0EC0, 0x8800, 0x4770)

        classified = classify_matrix_event_sink(bytes(image), 0)

        self.assertEqual(classified["family"], "unclassified")

    def test_samsung_consumer_route_fingerprint_is_closed(self) -> None:
        image = bytearray(b"\xff" * 0x300)
        handler = 0x100
        routes = (0x140, 0x150, 0x160, 0x170)
        targets = (0x200, 0x200, 0x220, 0x220)

        def branch(at: int, target: int) -> None:
            displacement = target - (at + 4)
            struct.pack_into("<H", image, at, 0xD000 | (displacement >> 1 & 0xFF))

        def call(at: int, target: int) -> None:
            displacement = target - (at + 4)
            struct.pack_into(
                "<2H", image, at,
                0xF000 | (displacement >> 12 & 0x7FF),
                0xF800 | (displacement >> 1 & 0x7FF),
            )

        for index, (event, route) in enumerate(zip((0x54, 0x55, 0x63, 0x64), routes)):
            struct.pack_into("<H", image, handler + index * 4, 0x2F00 | event)
            branch(handler + index * 4 + 2, route)
        struct.pack_into("<H", image, handler + 16, 0x4770)
        for route, target in zip(routes, targets):
            call(route, target)
            struct.pack_into("<H", image, route + 4, 0x4770)
        struct.pack_into("<2H", image, 0x200, 0xB500, 0xBD00)
        struct.pack_into("<3H", image, 0x220, 0xB500, 0x2001, 0xBD00)

        route = _samsung_consumer_route_metadata(bytes(image), {
            "raw_task_entry": handler,
            "raw_task_register": 7,
            "raw_consumer_evidence": "samsung-byte-ring32-r7-task-dispatch-v1",
        }, 0)

        self.assertEqual(route["consumer_route_status"], "closed")
        self.assertEqual(
            set(route["consumer_route_event_fingerprints"]),
            {"0x54", "0x55", "0x63", "0x64"},
        )

    def test_n330_5x6_profile_requires_complete_release_grammar(self) -> None:
        image = bytearray(b"\xff" * 0x1300)
        scanner = 0x100
        press = scanner + 0x3EC
        release = scanner + 0x472
        press_prefix = snippet("test_input_matrix", "n330_press_prefix")
        release_prefix = bytes.fromhex(
            "295d081c0938f12803d889300006000e00e08020"
        )
        image[scanner:scanner + 64] = snippet("test_input_matrix", "n330_scanner")
        image[scanner + 0x6A:scanner + 0x78] = bytes.fromhex(
            "9b4f786b0068c006c00e1f2871d0"
        )
        image[scanner + 0xF8:scanner + 0x106] = bytes.fromhex(
            "774f786b0068c206d20e1f2a15d0"
        )
        image[press:press + len(press_prefix)] = press_prefix
        image[release:release + len(release_prefix)] = release_prefix

        def call(at: int, target: int) -> None:
            displacement = target - (at + 4)
            struct.pack_into(
                "<2H", image, at,
                0xF000 | ((displacement >> 12) & 0x7FF),
                0xF800 | ((displacement >> 1) & 0x7FF),
            )

        call(press + len(press_prefix), 0x80)
        call(release + len(release_prefix), 0x80)
        struct.pack_into(
            "<5H", image, 0x80,
            0xB500, 0x1C04, 0x46C0, 0x1C0D, 0xD006,
        )
        struct.pack_into(
            "<6H", image, 0x8A,
            0x06C0, 0x0EC0, 0x7084, 0x7085, 0x7040, 0x4770,
        )
        struct.pack_into(
            "<4H", image, 0x98,
            0x06C0, 0x0EC0, 0x8800, 0x4770,
        )
        load_address = 0x1000
        table = 0x1200
        struct.pack_into("<I", image, scanner + 0x6A0, load_address + table)
        struct.pack_into("<I", image, scanner + 0x90C, load_address + table)
        image[table:table + 30] = bytes((
            0x61, 0x50, ord("1"), ord("4"), ord("7"), ord("*"),
            0x54, 0x55, ord("2"), ord("5"), ord("8"), ord("0"),
            0x5B, 0x52, ord("3"), ord("6"), ord("9"), ord("#"),
            0x53, 0x65, 0x66, 0x64, 0x63, 0x63, 0x62, 0, 0, 0, 0, 0,
        ))
        self.assertEqual(
            classify_matrix_event_sink(bytes(image), 0x80)["family"],
            "unclassified",
        )

        profile, status, rejected = resolve_direct_matrix_input(
            bytes(image), load_address
        )

        self.assertEqual((status, rejected), ("accepted", []))
        assert profile is not None
        self.assertEqual(profile["event_sink_family"], SAMSUNG_DUAL_PLANE_RING32)
        self.assertEqual(
            tuple(profile[field] for field in (
                "rows", "columns", "row_register", "register",
                "register_size", "sense_mask", "no_key",
            )), (6, 5, 5, 0x09000070, 4, 0x1F, 0x1F),
        )
        self.assertEqual(
            profile["single_key_column_sense"], [0x1E, 0x1D, 0x1B, 0x17, 0x0F]
        )
        self.assertEqual(profile["event_sink"], load_address + 0x80)
        self.assertEqual(profile["sense_site"], load_address + scanner + 0xFC)
        self.assertEqual(profile["global_sense_sites"],
                         [load_address + scanner + 0x6E])
        self.assertEqual(profile["row_sense_sites"],
                         [load_address + scanner + 0xFC])
        self.assertEqual(profile["release_grammar"],
                         "event-plus-0x80; invalid fallback=0x80")

        image[scanner + 0x0E] ^= 1
        image[press + 0x1C] ^= 1
        self.assertEqual(
            resolve_direct_matrix_input(bytes(image), load_address)[1],
            "accepted",
        )
        image[scanner + 0x0E] ^= 1
        image[press + 0x1C] ^= 1
        image[scanner + 0x0D] = 0xE0
        self.assertEqual(
            resolve_direct_matrix_input(bytes(image), load_address)[1],
            "not-found",
        )
        image[scanner + 0x0D] = 0xF0

        image[release] ^= 1
        self.assertEqual(
            resolve_direct_matrix_input(bytes(image), load_address)[1],
            "not-found",
        )
        image[release] ^= 1
        image[scanner + 0xFC] ^= 1
        self.assertEqual(
            resolve_direct_matrix_input(bytes(image), load_address)[1],
            "not-found",
        )
        image[scanner + 0xFC] ^= 1
        image[0x90] ^= 1
        self.assertEqual(
            resolve_direct_matrix_input(bytes(image), load_address)[1],
            "not-found",
        )

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
        expected = {
            "x350_VC22.bin": (0x013A2248, 0x328E6, 0x32868, 0x32882, 0xB5252),
            "schx150.bin": (0x013A3EC8, 0x329B6, 0x32938, 0x32952, 0xB539A),
        }
        root = _test_firmware_root()
        if root is None or any(
                not (root / name).is_file() for name in expected):
            self.skipTest(
                "firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT"
            )
        for name, values in expected.items():
            image = (root / name).read_bytes()
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

    def test_samsung_sideband_event_metadata_requires_complete_shape(self) -> None:
        root = _test_firmware_root()
        path = root / "SPH-X7509.bin" if root is not None else None
        if path is None or not path.is_file():
            self.skipTest(
                "firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT"
            )
        image = path.read_bytes()
        profile, status, rejected = resolve_direct_matrix_input(image)
        self.assertEqual((status, rejected), ("accepted", []))
        assert profile is not None
        self.assertEqual(profile["sideband_producers"], [{
            "grammar": "active-low-mmio-bit-debounced-event-v1",
            "evidence": "literal+mask+local-state+shared-queue",
            "semantic_status": "temporary-evidence-gated",
            "semantic_key": 7,
            "semantic_name": "END",
            "semantic_evidence": "event-0x51-independent-keyemu-maps",
            "event": 0x51,
            "event_register": 7,
            "register": 0x03000694,
            "register_width": 1,
            "mask": 0x10,
            "polarity": "active-low",
            "press_callsite": 0x0007FA66,
            "release_event": 0xFF,
            "release_callsite": 0x0007FA1C,
            "event_sink": 0x0007F3F0,
        }])

        collision = bytearray(image)
        collision[int(profile["event_table"])] = 0x51
        changed, status, rejected = resolve_direct_matrix_input(
            bytes(collision)
        )
        self.assertIsNone(changed)
        self.assertEqual(status, "rejected")
        self.assertIn(
            "sideband-event-conflicts-with-matrix",
            {reason for candidate in rejected
             for reason in candidate["reasons"]},
        )

        near_miss = bytearray(image)
        near_miss[int(profile["function"]) + 0x28] ^= 1
        changed, status, rejected = resolve_direct_matrix_input(bytes(near_miss))
        self.assertEqual((status, rejected), ("accepted", []))
        assert changed is not None
        self.assertNotIn("sideband_producers", changed)
        self.assertEqual(changed["sideband_detection_status"], "rejected")
        self.assertEqual(
            changed["sideband_detection_reject_reasons"],
            ["shape-word-0x028-mismatch"],
        )

    def test_sideband_flags_and_two_classified_release_paths(self) -> None:
        root = _test_firmware_root()
        if root is None or not (root / "SPH-X4500.bin").is_file():
            self.skipTest("firmware corpus unavailable")
        image = (root / "SPH-X4500.bin").read_bytes()
        parent, status, _ = resolve_distributed_matrix_input(image)
        self.assertEqual(status, "static-candidate")
        assert parent is not None
        arguments = (parent["function"], parent["sense_site"],
                     parent["producer"]["enqueue"], 0)
        result = _samsung_sideband_51_family_metadata(image, *arguments)
        self.assertEqual(result["sideband_detection_status"], "accepted")
        producer = result["sideband_producers"][0]
        self.assertEqual((producer["register"], producer["mask"],
                          producer["event"], producer["press_callsite"]),
                         (0x03000694, 0x10, 0x51, 0x80664))
        self.assertEqual(producer["release_callsites"], [0x8060A, 0x80632])
        for address, opcode in ((0x80170, b"\x00\x24"),
                                (0x80172, b"\x0e\xd0"),
                                (0x8016C, b"\x08\x23"),
                                (0x80608, b"\xfe\x20"),
                                (0x80630, b"\xfe\x20")):
            with self.subTest(address=address):
                changed = bytearray(image)
                changed[address:address + 2] = opcode
                rejected = _samsung_sideband_51_family_metadata(
                    bytes(changed), *arguments)
                self.assertNotEqual(rejected.get("sideband_detection_status"),
                                    "accepted")

    def test_samsung_sideband_family_closes_compiler_variants(self) -> None:
        expected = {
            "schx150.bin": (0x330C4, 0x33056, 0x32958),
            "SCH-X250.bin": (0x345C2, 0x34584, 0x34030),
            "SCH-x127.bin": (0x3FCCE, 0x3FC30, 0x3F52C),
        }
        root = _test_firmware_root()
        if root is None or any(
                not (root / name).is_file() for name in expected):
            self.skipTest(
                "firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT"
            )
        for name, callsites in expected.items():
            image = (root / name).read_bytes()
            profile, status, rejected = resolve_direct_matrix_input(image)
            self.assertEqual((status, rejected), ("accepted", []))
            assert profile is not None
            self.assertEqual(profile["sideband_detection_status"], "accepted")
            producer = profile["sideband_producers"][0]
            self.assertEqual(
                (producer["event"], producer["mask"],
                 producer["press_callsite"], producer["release_callsite"],
                 producer["event_sink"]),
                (0x51, 0x10, *callsites),
            )

        image = bytearray((root / "schx150.bin").read_bytes())
        profile, _, _ = resolve_direct_matrix_input(bytes(image))
        assert profile is not None
        image[int(profile["function"]) + 0x21] ^= 1
        changed, status, rejected = resolve_direct_matrix_input(bytes(image))
        self.assertEqual((status, rejected), ("accepted", []))
        assert changed is not None
        self.assertNotIn("sideband_producers", changed)
        self.assertEqual(
            changed["sideband_detection_reject_reasons"],
            ["bit4-active-low-chain-not-unique"],
        )

        image = bytearray((root / "schx150.bin").read_bytes())
        image[0x32D36] ^= 0x40
        changed, status, rejected = resolve_direct_matrix_input(bytes(image))
        self.assertEqual((status, rejected), ("accepted", []))
        assert changed is not None
        self.assertNotIn("sideband_producers", changed)
        self.assertEqual(
            changed["sideband_detection_reject_reasons"],
            ["sideband-active-flag-dataflow-not-closed"],
        )

        image = bytearray((root / "schx150.bin").read_bytes())
        image[0x3302A] ^= 0x40
        changed, status, rejected = resolve_direct_matrix_input(bytes(image))
        self.assertEqual((status, rejected), ("accepted", []))
        assert changed is not None
        self.assertNotIn("sideband_producers", changed)
        self.assertEqual(
            changed["sideband_detection_reject_reasons"],
            ["candidate-debounce-state-not-closed"],
        )

    def test_samsung_r7_raw_telemetry_requires_closed_task_dispatch(self) -> None:
        expected = {
            "incoming-msm5xxx-candidates-20260726/Samsung/SCH-X350/x350eng/x350eng.bin": ((
                0x013A2ED4, 0x340F6, 0x34078, 0x34092, 0xB85EC,
            ), 0, "samsung-byte-ring32-r0-receiver-v1", None),
            "SCH-X250.bin": ((
                0x01124BA8, 0x34086, 0x34010, 0xBB498, 0xBAE66,
            ), 7, "samsung-byte-ring32-r7-task-dispatch-v1", 0xBB498),
            "incoming-msm5xxx-candidates-20260726/Samsung/SCH-X250/X250rus/extracted/X250rus.bin": ((
                0x01124BA4, 0x3405E, 0x33FE8, 0xBB47E, 0xBAE5E,
            ), 7, "samsung-byte-ring32-r7-task-dispatch-v1", 0xBB47E),
        }
        root = _test_firmware_root()
        if root is None or any(
                not (root / name).is_file() for name in expected):
            self.skipTest(
                "firmware corpus unavailable; set MSM5XXX_TEST_FIRMWARE_ROOT"
            )
        for name, (values, register, evidence, capture) in expected.items():
            image = (root / name).read_bytes()
            profile, status, rejected = resolve_direct_matrix_input(image)
            self.assertEqual((status, rejected), ("accepted", []))
            assert profile is not None
            self.assertEqual(
                tuple(profile[field] for field in (
                    "raw_ring", "raw_enqueue_store", "raw_dequeue",
                    "raw_dequeue_return", "raw_task_entry",
                )), values,
            )
            self.assertEqual(profile["raw_task_register"], register)
            self.assertEqual(profile["raw_consumer_evidence"], evidence)
            if capture is not None:
                near_miss = bytearray(image)
                near_miss[capture] ^= 1
                profile, status, rejected = resolve_direct_matrix_input(
                    bytes(near_miss)
                )
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



class SelectedFunctionalConfirmTests(unittest.TestCase):
    # Exact instruction spans only; BLs and RAM literal words built separately.
    @staticmethod
    def _spans():
        return (
        ("forward", 0xb98ac,
         snippet("test_input_matrix", "x7509_forward").hex()
         , ((30, -16860),)),
        ("producer", 0xb56d0,
         snippet("test_input_matrix", "x7509_producer").hex()
         , ((38, -266836),)),
        ("secondary", 0xb5b1e,
         snippet("test_input_matrix", "x7509_secondary").hex()
         , ((42, 288614), (54, 198054))),
        ("app_entry", 0xe60c4,
         "f0b5071ceb48ea499ab0"
         , ()),
        ("publication", 0xe6112,
         "00290bd0381c00f000f8d549ff2301339842086001d100f000f801e0d1490f60"
         , ((6, 538862), (22, 7294))),
        ("global_read", 0xe615e,
         "c549cb4a0868"
         , ()),
        ("outer_state", 0xe7dbe,
         "104da87b00f000f8254f021c381c1fa100f000f8306800f000f8021c381c20a1336800f000f8a87b"
         "0e2806d10e99214bc989994201d0204a118002383fe0"
         , ((4, 11486), (16, 793034), (22, 3990), (34, 793034))),
        ("outer_switch", 0xe7e7c,
         "222800d377e002a31b5c5b009f440000"
         , ()),
        ("selected_call", 0xe7ee4,
         "00f000f841e0"
         , ((0, -103832),)),
        ("handler_entry", 0xce94c,
         snippet("test_input_matrix", "x7509_dispatch").hex()
         , ((60, -5692), (370, 31610))),
        ("raw_arm", 0xcec5c,
         "334800685b2801d100f000f82fdc372801d100f000f814dc3228fad008dc2328f7d02a28f5d03028"
         "f3d03128add1f0e73328eed03428ecd03528ead03628a4d1e7e7522800d130e109dc3828e1d03928"
         "dfd05028ddd0512897d100f000f8532800d1e7e0542819d055288ed1"
         , ((8, 3226), (18, 1860), (90, 29718))),
        ("selection", 0xcee90,
         snippet("test_input_matrix", "x7509_handler").hex()
         , ((28, 5300), (114, 30150))),
        ("tail", 0xd6456,
         "387335e0"
         , ()),
        ("tail_return", 0xd64c6,
         "387b002801d000f000f8787b57b0f0bc08bc1847"
         , ((6, -31236),)),
        ("state_bridge", 0xceac2,
         snippet("test_input_matrix", "x7509_tail").hex()
         , ((28, 31214),)),
        ("selected_entry", 0xcebec,
         "4d4e6149203ef06b884205d14c490868872801d100f000f84898484a407a00280dd1f06b007e0138"
         "7063489901204872e078a070ff20e0705069013830633f4ad07c002804d00020d074514800f000f8"
         "3949504e2039c86bb04206d12d99487a002802dd00f000f802e0012000f000f8"
         , ((20, 184492), (76, -100084), (100, -720), (108, 91880))),
        ("child", 0xcf3a0,
         "00f000f8002804d1924a1068502800d181e48a4a904ed06bb04209d18d480068232801d1092239e0"
         "30380206120e35e08a49884209d1874800682a2801d10a222ce02328f0d10b2228e08549884204d1"
         "804800683028e7d1f1e7824988420bd17c4a1068502801d1062217e03628dbd1ff20013000f000f8"
         "724988422ed17548ff2300680533984201d1002206e03028d5d02a28d7d02328c6d10c22049200f0"
         "00f8002827d0654ad06bb04223d1007e049988421fdd6c480499405c00281ad0a0785f49e0700498"
         "3030a0700498486148990020487200f000f83ce46349884206d15c4a1068c11f2a390629c0d89be7"
         "584a1068fbe7514ad06b017e049b9942ebdd049909012691926b89180a79002a05d08a68002a02d1"
         "ca68002addd0a278474b4c4ee270049a3032a270049a5a610b79424a002b00d18ce1d11d49310a68"
         "d20052189060049a002a06d1484a904201d1002302e0012300e0049b0a68d200521853600a680132"
         "0a6047994979002902d1049900f000f80499092904dcab2080010499301841722c4a2699906b0818"
         "8068002805d047994979002901d100f000f8264ad11dd06b393108602699906b0818c068d063"
         , ((0, -87088), (116, 11596), (158, -87088), (214, -36672), (372, -36408), (414, -843540))),
    )
    _LITERALS = (
        (0xb5728, 0x20db078),
        (0xb5b80, 0x20db0e0),
        (0xced24, 0x20dd2a0),
        (0xced28, 0x2006c70),
        (0xced2c, 0x20dfad8),
        (0xcf1a0, 0x20dfad8),
        (0xcf1a4, 0x20077b8),
        (0xcf1ac, 0x20dd280),
        (0xcf1c0, 0x2008714),
        (0xcf1c4, 0x2007f6c),
        (0xcf1c8, 0x2008224),
        (0xcf1cc, 0x20086d4),
        (0xcf5dc, 0x20dd280),
        (0xcf5e4, 0x2008714),
        (0xcf5f4, 0x20dfad8),
        (0xcf5f8, 0x20077b8),
        (0xcf5fc, 0x2007f6c),
        (0xcf600, 0x2008224),
        (0xcf604, 0x20086d4),
        (0xe6474, 0x20dfad8),
        (0xe7e00, 0x200714c),
    )

    @classmethod
    def fixture(cls, shift=0, ram_delta=0, load=0):
        image = bytearray(b"\xff" * (0x1A9800 + shift))

        def bl(at, target):
            delta = target - at - 4
            struct.pack_into("<HH", image, at + shift,
                             0xF000 | (delta >> 12 & 0x7FF),
                             0xF800 | (delta >> 1 & 0x7FF))

        def branch(at, target):
            struct.pack_into("<H", image, at + shift,
                             0xE000 | ((target - at - 4) // 2 & 0x7FF))

        for _, at, code, calls in cls._spans():
            data = bytes.fromhex(code)
            image[at + shift:at + shift + len(data)] = data
            for offset, target in calls:
                bl(at + offset, at + target)
        for at, value in cls._LITERALS:
            if 0x01000000 <= value < 0x04000000:
                value += ram_delta
            struct.pack_into("<I", image, at + shift, value)
        # Synthetic r4-preserving task reaches the uniquely anchored forward call.
        branch(0xB8EE4, 0xB96E4)
        branch(0xB96E4, 0xB98AC)
        bl(0xB98CE, 0x7F3D0)
        image[0xB98D2 + shift:0xB98D6 + shift] = bytes.fromhex("041c01d0")
        bl(0xB98D6, 0xB8EE4)
        image[0x7F3D0 + shift:0x7F3EC + shift] = bytes.fromhex(
            "064a50781178884201d10020704750180131c906c90e807811707047")
        struct.pack_into("<I", image, 0x7F3EC + shift, 0x20BA8A8 + ram_delta)
        image[0xCEAE8 + shift:0xCEAEA + shift] = bytes.fromhex("8600")
        image[0xE7E8C + shift:0xE7EAE + shift] = snippet("test_input_matrix", "x7509_key_table")
        profile = {
            "grammar": "direct-low-nibble-6-row-v1", "rows": 6, "columns": 4,
            "event_sink_family": SAMSUNG_RING32,
            "raw_consumer_evidence": "samsung-byte-ring32-saved-task-dispatch-v1",
            "raw_task_register": 4, "raw_ring": 0x20BA8A8 + ram_delta,
            "raw_dequeue": load + shift + 0x7F3D0,
            "raw_dequeue_return": load + shift + 0xB98D2,
            "raw_task_entry": load + shift + 0xB8EE4,
            "event_codes": [0x53, 0x66, 0x31, 0x34, 0x37, 0x2A, 0x5B, 0x52,
                            0x32, 0x35, 0x38, 0x30, 0x65, 0x50, 0x33, 0x36,
                            0x39, 0x23, 0x63, 0x64, 0x87, 0, 0x54, 0x55],
        }
        return image, profile, load

    def test_relocated_sparse_class(self):
        for shift, ram_delta, load in ((0, 0, 0), (0x100, 0x1000, 0x200000)):
            with self.subTest(shift=shift):
                image, profile, base = self.fixture(shift, ram_delta, load)
                mapping, metadata = _same_image_selected_confirm_mapping(bytes(image), profile, base)
                self.assertEqual(metadata["ok_mapping_status"], "accepted-provisional")
                self.assertEqual(mapping[5]["event"], 0x53)
                self.assertTrue(mapping[5]["functional_only"])
                self.assertEqual(mapping[5]["consumer"], load + shift + 0xCE94C)
                self.assertNotIn("semantic_name", mapping[5])

    def test_closed_edges_reject_independent_mutants(self):
        mutations = {
            "state-index-subtract": (0xE7DF8, b"\x03\x38"),
            "selected-reentry-branch": (0xCEBF6, b"\x00\xd1"),
            "forward-register": (0xB98C8, b"\x28\x1c"),
            "forward-target": (0xB98CA, b"\x00\xf0\x00\xf8"),
            "secondary-ring": (0xB5728, struct.pack("<I", 0x10DB07C)),
            "consumer-ring": (0xB5B80, struct.pack("<I", 0x10DB0E4)),
            "app-global": (0xE6474, struct.pack("<I", 0x10DFADC)),
            "raw-event-branch": (0xCECBC, b"\x01\xd1"),
            "selected-global": (0xCF1A0, struct.pack("<I", 0x10DFADC)),
            "descriptor": (0xCF1C0, struct.pack("<I", 0x1008718)),
            "state-bridge": (0xCEAC6, b"\x90\x73"),
            "child-store": (0xCF554, b"\x90\x63"),
            "unrelated-bl": (0xCF414, b"\x00\xf0\x00\xf8"),
        }
        for name, (at, replacement) in mutations.items():
            with self.subTest(name=name):
                image, profile, load = self.fixture()
                image[at:at + len(replacement)] = replacement
                mapping, metadata = _same_image_selected_confirm_mapping(bytes(image), profile, load)
                self.assertEqual(mapping, {})
                self.assertEqual(metadata["ok_mapping_status"], "rejected")
        image, profile, load = self.fixture()
        profile["event_codes"][1] = 0x53
        self.assertEqual(_same_image_selected_confirm_mapping(bytes(image), profile, load)[0], {})
        image, profile, load = self.fixture()
        duplicate = 0xD0002
        image[duplicate:duplicate + 0x48] = image[0xB5B1E:0xB5B66]
        pool = (duplicate + 4 & ~3) + 0x18 * 4
        struct.pack_into("<I", image, pool, 0x20DB0E0)
        self.assertEqual(_same_image_selected_confirm_mapping(bytes(image), profile, load)[0], {})

    def test_malformed_profiles_and_truncation(self):
        image, profile, load = self.fixture()
        for key in ("raw_dequeue", "raw_dequeue_return", "raw_task_entry", "raw_ring"):
            for value in (None, True, -2, len(image) + 10):
                with self.subTest(key=key, value=value):
                    changed = dict(profile, **{key: value})
                    self.assertEqual(_same_image_selected_confirm_mapping(bytes(image), changed, load)[0], {})
        for length in (0, 1, 0xB98CE, 0xE6474):
            self.assertEqual(_same_image_selected_confirm_mapping(bytes(image[:length]), profile, load)[0], {})

    def test_auxiliary_bl_target_requires_backing_image(self):
        image, profile, load = self.fixture()
        # Main selected-handler spans remain present; one exact auxiliary target
        # lies beyond this truncation, so a valid BL encoding alone is insufficient.
        mapping, metadata = _same_image_selected_confirm_mapping(
            bytes(image[:0xE7EEA]), profile, load,
        )
        self.assertEqual(mapping, {})
        self.assertEqual(metadata["ok_mapping_status"], "rejected")

    def test_actual_corpus_activation_both_closed_classes(self):
        root = _test_firmware_root()
        if root is None:
            self.skipTest("local firmware corpus unavailable")
        for name, accepted in (("SPH-X7509.bin", True), ("SPH-X7500-X75.00-WD01.bin", True)):
            path = root / name
            if not path.exists():
                self.fail("required local corpus missing: " + name)
            with self.subTest(name=name):
                profile, status, _ = resolve_direct_matrix_input(path.read_bytes())
                self.assertEqual(status, "accepted")
                self.assertEqual(sum(profile["event_codes"].count(event) for event in b"123456789*0#"), 12)
                mapping = profile.get("provisional_mappings", {}).get(5)
                if accepted:
                    self.assertEqual(mapping["rule"], "same-image-selected-functional-confirm-v1")
                else:
                    self.assertIsNone(mapping)


class SelectedFunctionalConfirmR7Tests(unittest.TestCase):
    # Distinct saved-r7 class; only contract opcodes, synthetic calls/literals.
    @staticmethod
    def _spans():
        return (
        ("forward", 0xb3680,
         "542f01d0552f02d1381c00f000f8"
         , ((10, -16104),)),
        ("producer", 0xaf798,
         snippet("test_input_matrix", "x7500_producer").hex()
         , ((38, -259788),)),
        ("secondary", 0xafbf4,
         snippet("test_input_matrix", "x7500_secondary").hex()
         , ((42, 248016), (54, 188048))),
        ("app_entry", 0xdda84,
         "f0b5fb4d041c2878002799b0"
         , ()),
        ("app_global", 0xddaaa,
         "f54df5482e18b07b012808d100f000f8f34909680831814201d80020b073f0480078002805d0ef48"
         "0078002801d000f000f8ed4e092080013018407a012801d0032801d100f000f8e848e74900793031"
         "1891"
         , ((12, -813002), (46, -166444), (68, 498846))),
        ("publication", 0xddafc,
         "00280ed01898007b00280ad1201c00f000f8ff2301339842286001d100f000f800e02c60"
         , ((14, 488656), (28, 8028))),
        ("global_read", 0xddb4a,
         "cd4dcc49d34a2868"
         , ()),
        ("outer_state", 0xdf900,
         snippet("test_input_matrix", "x7500_key_fragment").hex()
         , ()),
        ("selected_call", 0xdf978,
         "00f000f833e0"
         , ((0, -102116),)),
        ("handler_entry", 0xc6a94,
         snippet("test_input_matrix", "x7500_dispatch").hex()
         , ((56, -5904), (320, 33884))),
        ("raw_arm", 0xc6d2e,
         "45480068552800d138e22edc362801d100f000f812dc3228fad008dc2328f7d02a28f5d03028f3d0"
         "3128b6d1f0e73328eed03428ecd03528afd1e9e7512801d100f000f808dc3728e2d03828e0d03928"
         "ded05028a1d1dbe7522800d126e1532800d1d4e0542898d1d2e2"
         , ((16, 1914), (64, 30214))),
        ("selection", 0xc6f3c,
         snippet("test_input_matrix", "x7500_handler").hex()
         , ((28, 18232), (154, 29898))),
        ("tail_return", 0xceef0,
         "387a002801d000f000f8787a77b0f0bc08bc1847"
         , ((6, -33560),)),
        ("state_bridge", 0xc6bd8,
         snippet("test_input_matrix", "x7500_tail").hex()
         , ((28, 33548),)),
        ("selected_entry", 0xc6cca,
         snippet("test_input_matrix", "x7500_extra").hex()
         , ((64, -91922), (88, -618), (96, 90182))),
        ("child", 0xc74a8,
         "00f000f8002804d184490868502800d159e47d4a864e40329068b04207d17f480068232801d10921"
         "59e0303855e08149884209d1794800682a2801d10a214ee02328f2d10b214ae07b49884204d17348"
         "00683028e9d1f1e77849884204d16f4800683028e1d1e9e7754988420bd16b490868502801d10621"
         "31e03628d5d1ff20013000f000f8674988420fd16348ff2300680533984201d1002120e03028cdd0"
         "2a28cfd02328c0d10c2118e0654988423cd15a49ff2308685333984201d101210de0ff2354339842"
         "01d1022107e00a1cc11f2a39062925d82e380106090e1b9100f000f8002824d0474840308068b042"
         "1fd1007e1b9988421bdd53481b99405c002816d04f9b44499878d8701b984f9b303098701b988860"
         "689a0020507300f000f878e4ff20013000f000f83b4908687be7354a40329068017e1b9b9942f0dd"
         "1b9909014891526889180a79002a05d08a68002a02d1ca68002ae2d04f9b2e4e9a78da701b9a4f9b"
         "30329a701b9ab260254a0b794032002b00d199e1d11d15310a68d200521890601b9a002a06d12f4a"
         "904201d1002302e0012300e01b9b0a68d200521853600a6801320a601c4a517c002902d11b9900f0"
         "00f81b99092904dc164a23481b99101801720f4848994030406808188068002805d0114a517c0029"
         "01d100f000f8084940318868c86048984a688018c0680a4a8860517c002929d00123b3602ae0"
         , ((0, -73500), (130, 26664), (224, -73500), (286, -31224), (296, 18812), (438, -30960), (482, -811088))),
    )
    _LITERALS = (
        (0xaf7f0, 0x20c8a98),
        (0xafc50, 0x20c8b00),
        (0xc6e3c, 0x20c9dc8),
        (0xc6e40, 0x2005774),
        (0xc6e44, 0x20cd420),
        (0xc72a4, 0x20cd420),
        (0xc72a8, 0x20c9d98),
        (0xc72ac, 0x2006ebc),
        (0xc72b0, 0x2006058),
        (0xc72b4, 0x20066d4),
        (0xc72b8, 0x20069ac),
        (0xc72bc, 0x2006e7c),
        (0xc72c0, 0x2006e1c),
        (0xc72c4, 0x200690c),
        (0xc76b0, 0x20c9d98),
        (0xc76c4, 0x20cd420),
        (0xc76cc, 0x2006ebc),
        (0xc76d8, 0x2006058),
        (0xc76dc, 0x20066d4),
        (0xc76e0, 0x20069ac),
        (0xc76e4, 0x2006e1c),
        (0xc76e8, 0x2006e7c),
        (0xc76ec, 0x200690c),
        (0xdde80, 0x20cd420),
        (0xdfa64, 0x2005b4c),
    )

    @classmethod
    def fixture(cls, shift=0, ram_delta=0, load=0):
        image = bytearray(b"\xff" * (0x160000 + shift))

        def bl(at, target):
            delta = target - at - 4
            struct.pack_into("<HH", image, at + shift,
                             0xF000 | (delta >> 12 & 0x7FF),
                             0xF800 | (delta >> 1 & 0x7FF))

        def branch(at, target):
            struct.pack_into("<H", image, at + shift,
                             0xE000 | ((target - at - 4) // 2 & 0x7FF))

        for _, at, code, calls in cls._spans():
            data = bytes.fromhex(code)
            image[at + shift:at + shift + len(data)] = data
            for offset, target in calls:
                bl(at + offset, at + target)
        for at, value in cls._LITERALS:
            struct.pack_into("<I", image, at + shift, value + ram_delta)
        # Saved r7 reaches the exact forwarding call without clobbering r7.
        branch(0xB2BE2, 0xB3380)
        branch(0xB3380, 0xB3680)
        bl(0xB368E, 0x7B198)
        image[0xB3692 + shift:0xB3696 + shift] = bytes.fromhex("071c01d0")
        bl(0xB3696, 0xB2BE2)
        image[0x7B198 + shift:0x7B1B4 + shift] = bytes.fromhex(
            "064a50781178884201d10020704750180131c906c90e807811707047")
        struct.pack_into("<I", image, 0x7B1B4 + shift, 0x20B5AEC + ram_delta)
        image[0xC6BFC + shift:0xC6BFE + shift] = bytes.fromhex("6a00")
        image[0xDF918 + shift:0xDF936 + shift] = snippet("test_input_matrix", "x7500_key_table")
        image[0xCE406 + shift:0xCE408 + shift] = bytes.fromhex("3872")
        for at, target in ((0xCE408, 0xCDCD2), (0xCDCD2, 0xCD538),
                           (0xCD538, 0xCCF50), (0xCCF50, 0xCCC42),
                           (0xCCC42, 0xCC480), (0xCC480, 0xCBD00),
                           (0xCBD00, 0xCB50C), (0xCB50C, 0xCB46E)):
            branch(at, target)
        bl(0xCB46E, 0xCEEF0)
        profile = {
            "grammar": "direct-low-nibble-6-row-v1", "rows": 6, "columns": 4,
            "event_sink_family": SAMSUNG_RING32,
            "raw_consumer_evidence": "samsung-byte-ring32-saved-task-dispatch-v1",
            "raw_task_register": 7, "raw_ring": 0x20B5AEC + ram_delta,
            "raw_dequeue": load + shift + 0x7B198,
            "raw_dequeue_return": load + shift + 0xB3692,
            "raw_task_entry": load + shift + 0xB2BE2,
            "event_codes": [0x53, 0x66, 0x31, 0x34, 0x37, 0x2A, 0x5B, 0x52,
                            0x32, 0x35, 0x38, 0x30, 0x65, 0x50, 0x33, 0x36,
                            0x39, 0x23, 0x63, 0x64, 0x87, 0, 0x54, 0x55],
        }
        return image, profile, load

    def test_relocated_r7_sparse_class(self):
        for shift, ram_delta, load in ((0, 0, 0), (0x100, 0x1000, 0x200000)):
            with self.subTest(shift=shift):
                image, profile, base = self.fixture(shift, ram_delta, load)
                mapping, metadata = _same_image_selected_confirm_mapping(bytes(image), profile, base)
                self.assertEqual(metadata["ok_mapping_status"], "accepted-provisional")
                self.assertEqual(mapping[5]["event"], 0x53)
                self.assertTrue(mapping[5]["functional_only"])
                self.assertEqual(mapping[5]["consumer"], load + shift + 0xC6A94)
                self.assertNotIn("semantic_name", mapping[5])

    def test_r7_independent_edges_fail_closed(self):
        mutations = {
            "saved-register": (0xB3688, b"\x20\x1c"),
            "forward-call": (0xB368A, b"\x00\xf0\x00\xf8"),
            "application-global": (0xDDE80, struct.pack("<I", 0x20CD424)),
            "state-index": (0xDF906, b"\x03\x38"),
            "state-dispatch": (0xDF914, b"\x9e\x44"),
            "raw-53-arm": (0xC6D8E, b"\x01\xd1"),
            "selected-global": (0xC72A4, struct.pack("<I", 0x20CD424)),
            "descriptor-fork": (0xC76D8, struct.pack("<I", 0x200605C)),
            "state-bridge": (0xC6BDC, b"\x88\x73"),
            "state-table": (0xC6BFC, b"\x6b\x00"),
            "tail-first": (0xCE408, b"\x00\xe0"),
            "tail-middle": (0xCCC42, b"\x00\xe0"),
            "tail-return": (0xCB46E, b"\x00\xf0\x00\xf8"),
            "child-install": (0xC76A0, b"\x88\x63"),
            "auxiliary-call": (0xC6F58, b"\x00\xf0\x00\xf8"),
        }
        for name, (at, data) in mutations.items():
            with self.subTest(name=name):
                image, profile, load = self.fixture()
                image[at:at + len(data)] = data
                self.assertEqual(_same_image_selected_confirm_mapping(bytes(image), profile, load)[0], {})

    def test_r7_rejection_preserves_actual_numeric_profile(self):
        root = _test_firmware_root()
        if root is None:
            self.skipTest("local firmware corpus unavailable")
        image = bytearray((root / "SPH-X7500-X75.00-WD01.bin").read_bytes())
        before, status, _ = resolve_direct_matrix_input(bytes(image))
        self.assertEqual(status, "accepted")
        image[0xC6D8E] ^= 1
        after, status, _ = resolve_direct_matrix_input(bytes(image))
        self.assertEqual(status, "accepted")
        self.assertNotIn(5, after.get("provisional_mappings", {}))
        self.assertEqual(after["ok_mapping_status"], "rejected")
        for key in ("event_codes", "event_table", "rows", "columns", "raw_ring",
                    "raw_dequeue", "raw_task_entry", "raw_task_register"):
            self.assertEqual(after[key], before[key])

    def test_r7_ambiguity_and_truncation(self):
        image, profile, load = self.fixture()
        profile["event_codes"][1] = 0x53
        self.assertEqual(_same_image_selected_confirm_mapping(bytes(image), profile, load)[0], {})
        image, profile, load = self.fixture()
        # Duplicate independently relocated consumer and its decoded calls.
        duplicate = 0xD0000
        _, at, code, calls = next(span for span in self._spans() if span[0] == "secondary")
        image[duplicate:duplicate + 0x48] = bytes.fromhex(code)
        for offset, target in calls:
            delta = target - offset - 4
            struct.pack_into("<HH", image, duplicate + offset,
                             0xF000 | (delta >> 12 & 0x7FF), 0xF800 | (delta >> 1 & 0x7FF))
        struct.pack_into("<I", image, duplicate + 4 + 0x16 * 4, 0x20C8B00)
        self.assertEqual(_same_image_selected_confirm_mapping(bytes(image), profile, load)[0], {})
        image, profile, load = self.fixture()
        for length in (0, 1, 0xB368E, 0xDF97E):
            self.assertEqual(_same_image_selected_confirm_mapping(bytes(image[:length]), profile, load)[0], {})
        for register in (4, 7.0, None):
            self.assertEqual(_same_image_selected_confirm_mapping(
                bytes(image), dict(profile, raw_task_register=register), load)[0], {})
        for key in ("raw_dequeue", "raw_dequeue_return", "raw_task_entry", "raw_ring"):
            for value in (None, True, -2, len(image) + 10):
                self.assertEqual(_same_image_selected_confirm_mapping(
                    bytes(image), dict(profile, **{key: value}), load)[0], {})


class FlagsSidebandEndTests(unittest.TestCase):
    # Five exact spans only; no surrounding firmware resources.
    @staticmethod
    def _spans():
        return (
        (0x7b52c,
         "f0b50421ce4800f000f800f000f8071c00d08be100f000f8002800d086e100f000f8061c"
         , ((6, 1587208), (10, -652), (20, -300), (30, 1587008))),
        (0x7b550,
         snippet("test_input_matrix", "sideband_flags_body").hex()
         , ()),
        (0x7b610,
         "687a012803d16a72ff2000f000f8"
         , ((10, -1112),)),
        (0x7b7aa,
         "002e01d100f000f839480078002801d000272f722f482038c17b012911d0022919d0032944d1002f"
         "41d100242c720122c273ff2000f000f82e492e480818447231e02f72002f02d00221c1732fe0c078"
         "002828d02be0297a8f421dd10321c173017a002909d00178002911d1552f0fd0542f0dd00122c273"
         "19e0882f08d11e480078002804d000f000f81c2800d15327381c00f000f80ae02f72002f07d10122"
         "c27300222a72"
         , ((4, 1586394), (52, -1522), (134, 399606), (146, -1522))),
        (0x7b1b8,
         snippet("test_input_matrix", "sideband_event_sink").hex()
         , ((26, 219948), (154, -45292), (188, 1588080))),
    )
    _LITERALS = (
        (0x7b28c, 0x20b5aec),
        (0x7b870, 0x3000690),
        (0x7b874, 0x20cd580),
        (0x7b878, 0x20b5b40),
        (0x7b87c, 0x2001dd4),
        (0x7b880, 0x2005588),
        (0x7b898, 0x2006f12),
    )

    @classmethod
    def fixture(cls, shift=0, ram_delta=0, load=0):
        image = bytearray(b"\xff" * (0x200000 + shift))
        for at, code, calls in cls._spans():
            data = bytes.fromhex(code)
            image[at + shift:at + shift + len(data)] = data
            for offset, target in calls:
                delta = target - offset - 4
                struct.pack_into("<HH", image, at + offset + shift,
                                 0xF000 | (delta >> 12 & 0x7FF),
                                 0xF800 | (delta >> 1 & 0x7FF))
        for at, value in cls._LITERALS:
            value += ram_delta if value != 0x03000690 else 0
            struct.pack_into("<I", image, at + shift, value)
        # Original unqualified matrix-release route is reachable independently.
        struct.pack_into("<H", image, 0x7B5F6 + shift, 0xE00B)
        image[0x7B198 + shift:0x7B19A + shift] = bytes.fromhex("064a")
        struct.pack_into("<I", image, 0x7B1B4 + shift, 0x20B5AEC + ram_delta)
        profile = {
            "grammar": "direct-low-nibble-6-row-v1", "event_sink_family": SAMSUNG_RING32,
            "raw_consumer_evidence": "samsung-byte-ring32-saved-task-dispatch-v1",
            "raw_task_register": 7, "function": load + shift + 0x7B52C,
            "sense_site": load + shift + 0x7B77E,
            "event_sink": load + shift + 0x7B1B8,
            "raw_dequeue": load + shift + 0x7B198,
            "raw_ring": 0x20B5AEC + ram_delta, "event_codes": list(b"123456789*0#"),
        }
        return image, profile, load

    def test_exact_sideband_relocates_and_retains_parser_fields(self):
        for shift, delta, load in ((0, 0, 0), (0x100, 0x1000, 0x200000)):
            image, profile, base = self.fixture(shift, delta, load)
            result = _samsung_flags_sideband_51_metadata(bytes(image), profile, base)
            self.assertEqual(result["sideband_detection_status"], "accepted")
            producer = result["sideband_producers"][0]
            self.assertEqual((producer["semantic_key"], producer["event"], producer["mask"]), (7, 0x51, 0x10))
            self.assertEqual(producer["press_callsite"], load + shift + 0x7B83C)
            self.assertEqual(producer["release_callsite"], load + shift + 0x7B7DE)
            self.assertEqual(producer["register"], 0x03000694)
            self.assertEqual(producer["polarity"], "active-low")

    def test_independent_end_contract_mutations_reject(self):
        mutations = {
            "flags-gap": (0x7B558, b"\x00\x20"),
            "mask": (0x7B554, b"\x20\x22"),
            "polarity": (0x7B55E, b"\x13\xd0"),
            "branch-target": (0x7B55E, b"\x14\xd1"),
            "active-flag-store": (0x7B574, b"\x5a\x77"),
            "inactive-flag-store": (0x7B594, b"\x5a\x77"),
            "gate-flag": (0x7B5D8, b"\x52\x7f"),
            "gate-polarity": (0x7B5DC, b"\x00\xd0"),
            "candidate-read": (0x7B800, b"\x69\x7a"),
            "state-read": (0x7B7C2, b"\x01\x7c"),
            "early-release": (0x7B61A, b"\x00\xf0\x00\xf8"),
            "release-sink": (0x7B7DE, b"\x00\xf0\x00\xf8"),
            "press-sink": (0x7B83C, b"\x00\xf0\x00\xf8"),
            "flag-owner-alias": (0x7B878, struct.pack("<I", 0x2001DD4)),
            "flag-owner-partial-overlap": (0x7B878, struct.pack("<I", 0x2001DF4)),
            "candidate-owner-bounds": (0x7B87C, struct.pack("<I", 0x00FFFFF0)),
            "ring-literal": (0x7B28C, struct.pack("<I", 0x20B5AF0)),
            "dequeue-ring": (0x7B1B4, struct.pack("<I", 0x20B5AF0)),
        }
        for name, (at, data) in mutations.items():
            with self.subTest(name=name):
                image, profile, load = self.fixture()
                image[at:at + len(data)] = data
                result = _samsung_flags_sideband_51_metadata(bytes(image), profile, load)
                self.assertNotEqual(result.get("sideband_detection_status"), "accepted")

    def test_end_ambiguity_bounds_and_malformed_profiles(self):
        image, profile, load = self.fixture()
        for key in ("function", "sense_site", "event_sink", "raw_dequeue", "raw_ring"):
            for value in (None, True, -2, len(image) + 10):
                result = _samsung_flags_sideband_51_metadata(bytes(image), dict(profile, **{key: value}), load)
                self.assertNotEqual(result.get("sideband_detection_status"), "accepted")
        for value in (None, "51", True):
            result = _samsung_flags_sideband_51_metadata(bytes(image), dict(profile, event_codes=value), load)
            self.assertEqual(result, {})
        for length in (0, 1, 0x7B850, 0x1FEC84):
            result = _samsung_flags_sideband_51_metadata(bytes(image[:length]), profile, load)
            self.assertNotEqual(result.get("sideband_detection_status"), "accepted")
        changed = dict(profile, event_codes=[0x51])
        self.assertEqual(_samsung_flags_sideband_51_metadata(bytes(image), changed, load)["sideband_detection_status"], "rejected")
        # Reachable second 51 materialization outside the pinned producer span.
        image[0x7B5F6:0x7B5FA] = bytes.fromhex("512709e0")
        result = _samsung_flags_sideband_51_metadata(bytes(image), profile, load)
        self.assertEqual(result["sideband_detection_reject_reasons"], ["flags-sideband-producer-release-ambiguity"])
        image, profile, load = self.fixture()
        site, target = 0x7B5F8, 0x7B1B8
        image[0x7B5F6:0x7B5F8] = bytes.fromhex("ff20")
        delta = target - site - 4
        struct.pack_into("<HH", image, site, 0xF000 | (delta >> 12 & 0x7FF),
                         0xF800 | (delta >> 1 & 0x7FF))
        struct.pack_into("<H", image, site + 4, 0xE008)
        result = _samsung_flags_sideband_51_metadata(bytes(image), profile, load)
        self.assertEqual(result["sideband_detection_reject_reasons"], ["flags-sideband-producer-release-ambiguity"])

    def test_actual_end_peer_and_rejection_keep_confirm_numeric(self):
        root = _test_firmware_root()
        if root is None:
            self.skipTest("local firmware corpus unavailable")
        for name in ("SPH-X7500-X75.00-WD01.bin", "SPH-X7509.bin"):
            image = bytearray((root / name).read_bytes())
            before, status, _ = resolve_direct_matrix_input(bytes(image))
            self.assertEqual(status, "accepted")
            self.assertEqual(before["sideband_detection_status"], "accepted")
            self.assertEqual(before["sideband_producers"][0]["semantic_key"], 7)
            self.assertEqual(before["provisional_mappings"][5]["event"], 0x53)
            if name.endswith("WD01.bin"):
                image[0x7B55E] ^= 1
                after, status, _ = resolve_direct_matrix_input(bytes(image))
                self.assertEqual(status, "accepted")
                self.assertEqual(after["sideband_detection_status"], "rejected")
                self.assertNotIn("sideband_producers", after)
                for key in ("event_codes", "raw_ring", "provisional_mappings"):
                    self.assertEqual(after[key], before[key])


if __name__ == "__main__":
    unittest.main()
