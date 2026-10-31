"""CPU-free mapping and validation for candidate GPIO keypad profiles."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import struct
import tempfile
import unittest

from msm5xxx_emulator.qemu.decoder import QemuDecoder
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.input_descriptor import LG_DESCRIPTOR_RAW


class InputRuntimeTests(unittest.TestCase):
    @staticmethod
    def _direct_profile() -> dict[str, object]:
        return {
            "grammar": "direct-low-nibble-6-row-v1",
            "grammar_fingerprint": "test-direct-matrix-fingerprint",
            "evidence": "test-static-scan-to-call",
            "function": 0x32000,
            "sense_site": 0x33000,
            "register": 0x03000694,
            "row_register": 5,
            "event_sink_callsite": 0x33020,
            "event_sink": 0x31000,
            "raw_ring": 0x018B0C54,
            "raw_ring_capacity": 4,
            "raw_enqueue_store": 0x31010,
            "raw_enqueue_register": 7,
            "raw_dequeue": 0x31020,
            "raw_dequeue_return": 0x31022,
            "raw_task_entry": 0x31030,
            "raw_task_register": 7,
            "raw_consumer_evidence": "shared-ring-post-bl-r7-v1",
            "consumer_route_status": "closed",
            "consumer_route_evidence": "test-r7-route-v1",
            "consumer_route_fingerprint": "a" * 64,
            "consumer_route_event_fingerprints": {
                "0x54": "b" * 64, "0x55": "c" * 64,
                "0x63": "d" * 64, "0x64": "e" * 64,
            },
            "event_sink_family": "samsung-filtered-ring32-event-queue-v1",
            "rows": 6,
            "columns": 4,
            "no_key": 0xF,
            "single_key_column_sense": [0xE, 0xD, 0xB, 0x7],
            "event_codes": [
                99, 102, ord("1"), ord("4"), ord("7"), ord("*"),
                91, 83, ord("2"), ord("5"), ord("8"), ord("0"),
                101, 80, ord("3"), ord("6"), ord("9"), ord("#"),
                135, 100, 82, 0, 84, 85,
            ],
        }

    def _direct_emulator(self):
        decoder = QemuDecoder.__new__(QemuDecoder)
        decoder.config = SimpleNamespace(key_register=None)
        decoder.direct_input_profile = self._direct_profile()
        decoder.direct_input_positions = decoder._direct_matrix_positions(
            decoder.direct_input_profile)
        return decoder

    def test_samsung_matrix_uses_evidenced_events_not_table_order(self) -> None:
        emulator = self._direct_emulator()

        self.assertEqual(len(emulator.direct_input_positions), 19)
        self.assertEqual(emulator.direct_input_positions[0], (0x5B, 0, 1))
        self.assertEqual(emulator.direct_input_positions[2], (0x52, 2, 3))
        self.assertEqual(emulator.direct_input_positions[14], (0x34, 3, 0))
        self.assertNotIn(5, emulator.direct_input_positions)


    def test_direct_matrix_prefers_evidence_gated_semantic_metadata(self) -> None:
        profile = self._direct_profile()
        profile["provisional_mappings"] = {
            5: {
                "event": 0x53,
                "rule": "same-image-exact-keyemul-O-unique-cell",
                "evidence": "same-image-exact-keyemul-semantics+unique-matrix-event;offline-corpus-crosscheck",
                "semantic_grammar_fingerprint": "exact-keyemul",
            },
        }
        positions = QemuDecoder._direct_matrix_positions(profile)
        self.assertEqual(positions[5], (0x53, 1, 1))
        self.assertEqual(positions[14], (0x34, 3, 0))
        self.assertEqual(len(positions), 20)


    def test_direct_matrix_recognized_profiles_share_raw_table_order(
            self) -> None:
        for family in ("lg-ring256-event-queue-v1", LG_DESCRIPTOR_RAW):
            profile = self._direct_profile()
            profile["event_sink_family"] = family

            positions = QemuDecoder._direct_matrix_positions(profile)

            self.assertEqual(len(positions), 23)
            self.assertEqual(positions[0], (0x63, 0, 0))
            self.assertEqual(len(set(positions.values())), 23)

    def test_direct_matrix_experimental_fallback_is_stable_and_filtered(
            self) -> None:
        profile = self._direct_profile()
        profile["event_sink_family"] = "lg-ring256-event-queue-v1"

        first = QemuDecoder._direct_matrix_positions(profile)
        second = QemuDecoder._direct_matrix_positions(profile)
        self.assertEqual(first, second)
        self.assertEqual(len(set(first.values())), len(first))

        profile["event_codes"][0] = profile["no_key"]
        profile["event_codes"][18] = 0x53
        filtered = QemuDecoder._direct_matrix_positions(profile)
        self.assertNotIn(
            profile["no_key"], (position[0] for position in filtered.values())
        )
        self.assertNotIn(0x53, (position[0] for position in filtered.values()))

    def test_direct_matrix_unclassified_profile_maps_no_keys(self) -> None:
        profile = self._direct_profile()
        profile["event_sink_family"] = "unclassified"

        self.assertEqual(QemuDecoder._direct_matrix_positions(profile), {})


    def test_partial_stable_mmio_key_overlap_is_rejected(self) -> None:
        image = bytearray(b"\xff" * 0x1000)
        for offset in range(0, 32, 4):
            struct.pack_into("<I", image, offset, 0xEA000000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "firmware.bin"
            firmware.write_bytes(image)
            config = detect(firmware, SimpleNamespace(
                key_register=0x03000721,
                key_active_low=True,
            ))
            config.flash_state = str(root / "flash.json")

            with self.assertRaisesRegex(
                    ValueError, "key register overlaps stable MSM MMIO"):
                QemuDecoder(config)

    def test_manual_event_requires_a_unique_detected_cell(self):
        decoder = self._direct_emulator()
        self.assertFalse(decoder.can_set_key(5))
        self.assertTrue(decoder.can_set_key(5, 0x53))
        self.assertFalse(decoder.can_set_key(5, 0x7f))
        decoder.direct_input_profile['event_codes'][0] = 0x53
        self.assertFalse(decoder.can_set_key(5, 0x53))


if __name__ == "__main__":
    unittest.main()
