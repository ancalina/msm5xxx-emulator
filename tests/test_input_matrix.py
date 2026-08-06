"""Closed-shape tests for automatic direct-MMIO keypad detection."""
from __future__ import annotations

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
    _samsung_consumer_route_metadata,
    _samsung_raw_saved_consumer_metadata,
    classify_matrix_event_sink,
    find_direct_matrix_scanners,
    resolve_direct_matrix_input,
)
from src.msm5xxx_emulator.detection.input_semantics import (
    KEYEMU_GRAMMAR_FINGERPRINT,
    KEYEMU_PASSTHROUGH,
    KeyemuSemantics,
)


def _test_firmware_root() -> Path | None:
    configured = os.environ.get("MSM5XXX_TEST_FIRMWARE_ROOT")
    if configured:
        root = Path(configured).expanduser()
        return root if root.is_dir() else None
    test_file = Path(__file__).resolve()
    for parent in (test_file.parents[1], test_file.parents[2]):
        root = parent / "firmwares"
        if root.is_dir():
            return root
    return None


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
        press_prefix = bytes.fromhex(
            "285d2a2801d052280dd1ac490978002909d0ff212d310122480067f066f9"
            "285da74908800be00021"
        )
        release_prefix = bytes.fromhex(
            "295d081c0938f12803d889300006000e00e08020"
        )
        image[scanner:scanner + 64] = bytes.fromhex(
            "f0b501260024f1058bb0b04823f046fa002106224a43002000236a4400231354"
            "01300006000e0628f8d301310906090e0529eed3"
        )
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


if __name__ == "__main__":
    unittest.main()
