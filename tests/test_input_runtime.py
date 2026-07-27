"""Runtime evidence gate for candidate GPIO keypad profiles."""
from __future__ import annotations

from collections import Counter, deque
import json
from pathlib import Path
from types import SimpleNamespace
import struct
import tempfile
import unittest
from unittest import mock

from msm5xxx import GenericMSMEmulator, detect
from msm5xxx_emulator.detection.input_descriptor import LG_DESCRIPTOR_RAW
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R2,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R7,
)


class RegisterMemoryUc:
    def __init__(self) -> None:
        self.registers: dict[int, int] = {}
        self.memory: dict[int, bytes] = {}

    def reg_read(self, register: int) -> int:
        return self.registers.get(register, 0)

    def mem_write(self, address: int, data: bytes) -> None:
        self.memory[address] = bytes(data)

    def mem_read(self, address: int, size: int) -> bytes:
        return self.memory.get(address, b"\0" * size)[:size]


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

    def _direct_emulator(self) -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(key_register=None)
        emulator.direct_input_profile = self._direct_profile()
        emulator.direct_input_detection = "accepted"
        emulator.direct_input_positions = emulator._direct_matrix_positions(
            emulator.direct_input_profile
        )
        emulator.direct_key_positions = {}
        emulator.direct_key_scan_epochs = {}
        emulator.direct_matrix_scans = 0
        emulator.direct_matrix_active_reads = 0
        emulator.direct_matrix_sink_events = 0
        emulator.direct_matrix_raw_enqueue_events = 0
        emulator.direct_matrix_dequeue_events = 0
        emulator.direct_matrix_task_consumer_events = 0
        emulator._direct_matrix_pending_events = deque()
        emulator._direct_matrix_pending_dequeue = None
        emulator._direct_matrix_raw_enqueue_marker = None
        emulator.key_press_read_epochs = {}
        emulator.key_read_epoch = 0
        emulator.key_register_reads = 0
        emulator.key_register_read_pcs = Counter()
        emulator.held_keys = set()
        emulator.input_events = 0
        emulator.firmware_key_events = 0
        emulator.input_error = ""
        return emulator

    def _emulator(self) -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(key_register=0x03000738)
        emulator.key_register_reads = 0
        emulator.key_read_epoch = 0
        emulator.key_register_read_pcs = Counter()
        emulator.key_press_read_epochs = {2: 0}
        emulator.held_keys = {2}
        emulator.input_events = 0
        emulator.firmware_key_events = 0
        emulator.input_error = "pending"
        return emulator

    def _descriptor_emulator(self) -> GenericMSMEmulator:
        emulator = self._direct_emulator()
        profile = {
            **self._direct_profile(),
            "family": LG_DESCRIPTOR_RAW,
            "event_sink_family": LG_DESCRIPTOR_RAW,
            "register": 0x0300072C,
            "sense_site": 0x34010,
            "sense_sites": [0x34000, 0x34010, 0x34020],
            "global_sense_sites": [0x34000],
            "row_sense_sites": [0x34010, 0x34020],
            "row_state_address": 0x01001000,
            "row_state_offset": 9,
            "row_order": [3, 0, 1, 2, 4, 5],
            "no_key": 0x1F,
            "single_key_column_sense": [0x1E, 0x1D, 0x1B, 0x17, 0x0F],
            "columns": 5,
            "event_codes": [
                *self._direct_profile()["event_codes"],
                0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
            ],
        }
        profile.pop("row_register")
        emulator.direct_input_profile = profile
        emulator.direct_input_positions = emulator._direct_matrix_positions(
            profile
        )
        return emulator

    def test_candidate_register_requires_read_after_press_before_consumer(self) -> None:
        emulator = self._emulator()

        emulator._input_entry_observed(None, 0, 0, None)
        self.assertEqual(emulator.input_events, 1)
        self.assertEqual(emulator.firmware_key_events, 0)

        emulator._record_key_register_read(0x03000738, 4, 0x1234)
        emulator._input_entry_observed(None, 0, 0, None)
        self.assertEqual(emulator.key_register_reads, 1)
        self.assertEqual(emulator.key_register_read_pcs, Counter({0x1234: 1}))
        self.assertEqual(emulator.firmware_key_events, 1)
        self.assertEqual(emulator.input_error, "")

    def test_raw_queue_telemetry_requires_ordered_register_chain(self) -> None:
        emulator = self._direct_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        event = ord("5")
        uc.registers[UC_ARM_REG_LR] = int(profile["event_sink_callsite"]) + 5
        uc.registers[UC_ARM_REG_R0] = event
        uc.registers[UC_ARM_REG_R7] = event
        emulator._direct_input_event_observed(uc, 0, 0, None)
        emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        emulator._direct_raw_task_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_raw_enqueue_events, 1)
        self.assertEqual(emulator.direct_matrix_dequeue_events, 1)
        self.assertEqual(emulator.direct_matrix_task_consumer_events, 1)
        self.assertEqual(list(emulator._direct_matrix_pending_events), [])

    def test_raw_queue_telemetry_accepts_r0_receiver_copy(self) -> None:
        emulator = self._direct_emulator()
        emulator.direct_input_profile["raw_task_register"] = 0
        uc = RegisterMemoryUc()
        event = ord("5")
        uc.registers[UC_ARM_REG_LR] = int(
            emulator.direct_input_profile["event_sink_callsite"]
        ) + 5
        uc.registers[UC_ARM_REG_R0] = event
        uc.registers[UC_ARM_REG_R7] = event
        emulator._direct_input_event_observed(uc, 0, 0, None)
        emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        emulator._direct_raw_task_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_task_consumer_events, 1)

    def test_raw_queue_telemetry_rejects_wrong_order_or_register(self) -> None:
        emulator = self._direct_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        event = ord("5")
        uc.registers[UC_ARM_REG_R0] = event
        uc.registers[UC_ARM_REG_R7] = event
        emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        emulator._direct_raw_task_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_raw_enqueue_events, 0)
        uc.registers[UC_ARM_REG_LR] = int(profile["event_sink_callsite"]) + 5
        emulator._direct_input_event_observed(uc, 0, 0, None)
        uc.registers[UC_ARM_REG_R7] = event + 1
        emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_raw_enqueue_events, 0)
        self.assertIsNone(emulator._direct_matrix_raw_enqueue_marker)
        uc.registers[UC_ARM_REG_R7] = event
        emulator._direct_input_event_observed(uc, 0, 0, None)
        emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        uc.registers[UC_ARM_REG_R0] = event + 1
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        emulator._direct_raw_task_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_dequeue_events, 0)
        self.assertEqual(emulator.direct_matrix_task_consumer_events, 0)

    def test_raw_queue_task_register_mismatch_discards_dequeued_head(self) -> None:
        emulator = self._direct_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        event = ord("5")
        uc.registers[UC_ARM_REG_LR] = int(profile["event_sink_callsite"]) + 5
        uc.registers[UC_ARM_REG_R0] = event
        uc.registers[UC_ARM_REG_R7] = event
        emulator._direct_input_event_observed(uc, 0, 0, None)
        emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        uc.registers[UC_ARM_REG_R7] = event + 1
        emulator._direct_raw_task_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_task_consumer_events, 0)
        self.assertEqual(list(emulator._direct_matrix_pending_events), [])
        self.assertIsNone(emulator._direct_matrix_pending_dequeue)
        uc.registers[UC_ARM_REG_R0] = event
        uc.registers[UC_ARM_REG_R7] = event
        emulator._direct_input_event_observed(uc, 0, 0, None)
        emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        emulator._direct_raw_task_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_task_consumer_events, 1)

    def test_raw_queue_next_dequeue_discards_taskless_stale_head(self) -> None:
        emulator = self._direct_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        uc.registers[UC_ARM_REG_LR] = int(profile["event_sink_callsite"]) + 5
        for event in (ord("5"), 0xFF):
            uc.registers[UC_ARM_REG_R0] = event
            uc.registers[UC_ARM_REG_R7] = event
            emulator._direct_input_event_observed(uc, 0, 0, None)
            emulator._direct_raw_enqueue_store_observed(uc, 0, 0, None)
        uc.registers[UC_ARM_REG_R0] = ord("5")
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        uc.registers[UC_ARM_REG_R0] = 0xFF
        uc.registers[UC_ARM_REG_R7] = 0xFF
        emulator._direct_raw_dequeue_return_observed(uc, 0, 0, None)
        emulator._direct_raw_task_observed(uc, 0, 0, None)
        self.assertEqual(emulator.direct_matrix_dequeue_events, 2)
        self.assertEqual(emulator.direct_matrix_task_consumer_events, 1)
        self.assertEqual(list(emulator._direct_matrix_pending_events), [])
        self.assertIsNone(emulator._direct_matrix_pending_dequeue)

    def test_unrelated_read_cannot_confirm_candidate_register(self) -> None:
        emulator = self._emulator()

        emulator._record_key_register_read(0x0300073C, 4, 0x1234)
        emulator._input_entry_observed(None, 0, 0, None)

        self.assertEqual(emulator.key_register_reads, 0)
        self.assertEqual(emulator.firmware_key_events, 0)

    def test_no_detected_transport_does_not_touch_guest_register(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(key_register=None)
        emulator.held_keys = set()
        emulator.input_error = ""

        with mock.patch(
                "msm5xxx_emulator.devices.input.LOGGER.info") as logged:
            emulator.set_key(0, True)

        self.assertEqual(emulator.held_keys, set())
        self.assertEqual(
            emulator.input_error,
            "automatic keypad transport not detected; physical register override required",
        )
        payload = json.loads(logged.call_args.args[1])
        self.assertFalse(payload["accepted"])
        self.assertEqual(payload["reason"], "keypad-transport-not-detected")
        self.assertEqual(payload["mapping_source"], "automatic-experimental")
        self.assertEqual(payload["mapping_rule"], "transport-profile-required")
        self.assertEqual(payload["detection_status"], "not-found")
        self.assertEqual(payload["requested_source"], "automatic")
        self.assertIsNone(payload["family"])
        self.assertIsNone(payload["grammar_fingerprint"])

    def test_direct_matrix_preserves_evidence_and_fills_remaining_cells(
            self) -> None:
        emulator = self._direct_emulator()

        self.assertEqual(len(emulator.direct_input_positions), 23)
        self.assertEqual(emulator.direct_input_positions[0], (0x5B, 0, 1))
        self.assertEqual(emulator.direct_input_positions[1], (0x54, 4, 3))
        self.assertEqual(emulator.direct_input_positions[2], (0x52, 2, 3))
        self.assertEqual(emulator.direct_input_positions[3], (0x50, 1, 2))
        self.assertEqual(emulator.direct_input_positions[4], (0x65, 0, 2))
        self.assertEqual(emulator.direct_input_positions[6], (0x66, 1, 0))
        self.assertEqual(emulator.direct_input_positions[9], (0x55, 5, 3))
        self.assertEqual(
            emulator.direct_input_positions[15],
            (ord("5"), 3, 1),
        )
        self.assertEqual(
            {bit: emulator.direct_input_positions[bit]
             for bit in (5, 7, 8, 10)},
            {
                5: (0x63, 0, 0),
                7: (0x53, 1, 1),
                8: (0x87, 0, 3),
                10: (0x64, 1, 3),
            },
        )

    def test_direct_matrix_lg_profiles_fill_non_numeric_unique_cells(
            self) -> None:
        for family in ("lg-ring256-event-queue-v1", LG_DESCRIPTOR_RAW):
            profile = self._direct_profile()
            profile["event_sink_family"] = family

            positions = GenericMSMEmulator._direct_matrix_positions(profile)

            self.assertEqual(len(positions), 23)
            self.assertEqual(positions[15], (ord("5"), 3, 1))
            self.assertEqual(len(set(positions.values())), 23)

    def test_direct_matrix_experimental_fallback_is_stable_and_filtered(
            self) -> None:
        profile = self._direct_profile()

        first = GenericMSMEmulator._direct_matrix_positions(profile)
        second = GenericMSMEmulator._direct_matrix_positions(profile)
        self.assertEqual(first, second)
        self.assertEqual(len(set(first.values())), len(first))

        profile["event_codes"][0] = profile["no_key"]
        profile["event_codes"][18] = 0x53
        filtered = GenericMSMEmulator._direct_matrix_positions(profile)
        self.assertEqual(filtered[5], (0x64, 1, 3))
        self.assertNotIn(7, filtered)
        self.assertNotIn(8, filtered)
        self.assertNotIn(10, filtered)
        self.assertNotIn(
            profile["no_key"], (position[0] for position in filtered.values())
        )

    def test_direct_matrix_unclassified_profile_maps_no_keys(self) -> None:
        profile = self._direct_profile()
        profile["event_sink_family"] = "unclassified"

        self.assertEqual(GenericMSMEmulator._direct_matrix_positions(profile), {})

    def test_manual_event_uses_unique_detected_matrix_cell_only(self) -> None:
        emulator = self._direct_emulator()

        self.assertTrue(emulator.can_set_key(5))
        self.assertTrue(emulator.can_set_key(5, 0x53))
        self.assertFalse(emulator.can_set_key(5, 0x7F))
        self.assertFalse(emulator.can_set_key(5, 0))
        self.assertFalse(emulator.can_set_key(5, 0xFF))
        emulator.direct_input_profile["event_codes"][0] = (
            emulator.direct_input_profile["no_key"]
        )
        self.assertFalse(emulator.can_set_key(
            5, emulator.direct_input_profile["no_key"]
        ))
        emulator.direct_input_profile = self._direct_profile()
        emulator.direct_input_profile["event_codes"][0] = 0x53
        self.assertFalse(emulator.can_set_key(5, 0x53))
        with mock.patch(
                "msm5xxx_emulator.devices.input.LOGGER.info") as logged:
            emulator.set_key(5, True, 0x53)
        self.assertEqual(emulator.held_keys, set())
        rejected = json.loads(logged.call_args.args[1])
        self.assertEqual(
            rejected["reason"], "manual-event-absent-or-ambiguous"
        )
        self.assertFalse(rejected["event_unique"])
        self.assertTrue(rejected["manual_override"])
        self.assertEqual(rejected["requested_source"], "manual")
        self.assertEqual(rejected["mapping_source"], "manual")
        self.assertEqual(rejected["mapping_rule"], "manual-event-rejected")
        self.assertFalse(rejected["accepted"])
        emulator.direct_input_profile = self._direct_profile()

        emulator.set_key(5, True)
        self.assertEqual(emulator.direct_key_positions[5], (0x63, 0, 0))
        emulator.set_key(5, False)
        emulator.set_key(5, True, 0x53)
        self.assertEqual(emulator.direct_key_positions[5], (0x53, 1, 1))
        self.assertEqual(emulator.held_keys, {5})
        emulator.set_key(5, False)
        self.assertEqual(emulator.direct_key_positions, {})
        self.assertEqual(emulator.held_keys, set())

    def test_direct_matrix_sense_is_row_scoped_and_active_low(self) -> None:
        emulator = self._direct_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        register = int(profile["register"])
        uc.registers[UC_ARM_REG_PC] = int(profile["sense_site"]) + 2
        uc.registers[UC_ARM_REG_R5] = 3

        emulator._stable_mmio_read(
            uc, 0, register, 1, 0, (register, b"\x10")
        )
        self.assertEqual(uc.memory[register], b"\x1f")

        emulator.set_key(15, True)
        emulator._stable_mmio_read(
            uc, 0, register, 1, 0, (register, b"\x10")
        )
        self.assertEqual(uc.memory[register], b"\x1d")
        self.assertEqual(emulator.direct_matrix_active_reads, 1)

        uc.registers[UC_ARM_REG_R5] = 2
        emulator._stable_mmio_read(
            uc, 0, register, 1, 0, (register, b"\x10")
        )
        self.assertEqual(uc.memory[register], b"\x1f")
        self.assertEqual(emulator.direct_matrix_scans, 3)

        uc.registers[UC_ARM_REG_PC] += 2
        emulator._stable_mmio_read(
            uc, 0, register, 1, 0, (register, b"\x10")
        )
        self.assertEqual(uc.memory[register], b"\x10")
        self.assertEqual(emulator.direct_matrix_scans, 3)

    def test_direct_matrix_keyedge_logging_preserves_mapping_and_hold_scan(self) -> None:
        emulator = self._direct_emulator()
        with mock.patch(
                "msm5xxx_emulator.devices.input.LOGGER.info") as logged:
            emulator.set_key(5, True, 0x53)
            emulator.direct_matrix_scans += 1
            emulator.direct_matrix_raw_enqueue_events += 1
            emulator.set_key(5, False)
            emulator.set_key(15, True)
            emulator.set_key(15, False)
            emulator.set_key(5, True)
            emulator.set_key(5, False)

        payloads = [json.loads(call.args[1]) for call in logged.call_args_list]
        (
            manual_press, manual_release,
            evidenced_press, evidenced_release,
            experimental_press, experimental_release,
        ) = payloads
        self.assertEqual(
            (manual_press["mapping"], manual_release["mapping"],
             manual_press["firmware_event"], manual_release["firmware_event"]),
            ("manual", "manual", "0x53", "0x53"),
        )
        self.assertIsNone(manual_press["scanner_active_during_hold"])
        self.assertTrue(manual_release["scanner_active_during_hold"])
        self.assertEqual(manual_release["counters"]["scans"], 1)
        self.assertEqual(manual_release["counters"]["raw_enqueues"], 1)
        self.assertEqual(
            (evidenced_press["mapping_source"],
             evidenced_release["mapping_source"],
             evidenced_release["scanner_active_during_hold"]),
            ("automatic-evidenced", "automatic-evidenced", False),
        )
        self.assertEqual(
            (experimental_press["mapping_source"],
             experimental_release["mapping_source"],
             experimental_press["mapping_rule"],
             experimental_press["fallback_rank"]),
            (
                "automatic-experimental", "automatic-experimental",
                "remaining-unique-cell-table-order", 1,
            ),
        )
        for payload in payloads:
            self.assertEqual(
                payload["grammar_fingerprint"],
                "test-direct-matrix-fingerprint",
            )
            self.assertEqual(payload["detection_status"], "accepted")
            self.assertIn("raw_enqueues", payload["counters"])
        self.assertTrue(manual_press["manual_override"])
        self.assertTrue(manual_release["manual_override"])
        self.assertEqual(manual_release["requested_event"], "0x53")
        self.assertEqual(manual_press["requested_source"], "manual")
        self.assertFalse(evidenced_press["manual_override"])
        self.assertEqual(evidenced_press["requested_source"], "automatic")

    def test_descriptor_matrix_uses_global_gate_and_guest_row_state(self) -> None:
        emulator = self._descriptor_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        register = int(profile["register"])
        row_state = int(profile["row_state_address"]) + 9
        uc.memory[register] = b"\xE0\x55"

        uc.registers[UC_ARM_REG_PC] = 0x34002
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xff\x55")

        emulator.set_key(15, True)
        profile["row_register"] = 0
        profile["row_state_evidence"] = "ldrb-state-increment-store"
        uc.registers[UC_ARM_REG_R0] = 0xFF
        uc.registers[UC_ARM_REG_PC] = 0x34002
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xfd\x55")

        uc.memory[row_state] = b"\0"
        uc.registers[UC_ARM_REG_PC] = 0x34012
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xfd\x55")

        uc.memory[row_state] = b"\1"
        uc.registers[UC_ARM_REG_PC] = 0x34022
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xff\x55")

        emulator.set_key(15, False)
        uc.memory[row_state] = b"\0"
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xff\x55")

    def test_descriptor_manual_event_uses_held_position_and_consumer(self) -> None:
        emulator = self._descriptor_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        register = int(profile["register"])
        uc.memory[register] = b"\xE0\x55"

        self.assertTrue(emulator.can_set_key(5))
        self.assertTrue(emulator.can_set_key(5, 0xA0))
        emulator.set_key(5, True, 0xA0)
        self.assertEqual(emulator.direct_key_positions[5], (0xA0, 0, 4))

        uc.registers[UC_ARM_REG_PC] = 0x34002
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xef\x55")

        uc.registers[UC_ARM_REG_LR] = int(
            profile["event_sink_callsite"]
        ) + 5
        uc.registers[UC_ARM_REG_R0] = 0xA0
        emulator._direct_input_event_observed(uc, 0, 0, None)
        self.assertEqual(emulator.firmware_key_events, 1)
        self.assertEqual(emulator.input_error, "")

        emulator.set_key(5, False)
        self.assertEqual(emulator.direct_key_positions, {})

    def test_descriptor_matrix_wrong_width_and_pc_fail_closed(self) -> None:
        emulator = self._descriptor_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        register = int(profile["register"])
        emulator.set_key(15, True)

        uc.registers[UC_ARM_REG_PC] = 0x34012
        emulator._stable_mmio_read(
            uc, 0, register, 1, 0, (register, b"\xaa\xbb")
        )
        self.assertEqual(uc.memory[register], b"\xaa\xbb")
        self.assertEqual(emulator.direct_matrix_scans, 0)

        uc.registers[UC_ARM_REG_PC] = 0x34014
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\xaa\xbb")
        )
        self.assertEqual(uc.memory[register], b"\xaa\xbb")
        self.assertEqual(emulator.direct_matrix_scans, 0)

    def test_descriptor_matrix_can_use_proven_local_row_register(self) -> None:
        emulator = self._descriptor_emulator()
        profile = emulator.direct_input_profile
        profile.pop("row_state_address")
        profile.pop("row_state_offset")
        profile["row_register"] = 4
        profile["row_register_evidence"] = (
            "zero-indexed-ldrb-six-row-backedge"
        )
        uc = RegisterMemoryUc()
        register = int(profile["register"])
        uc.memory[register] = b"\xE0\x55"
        uc.registers[UC_ARM_REG_PC] = 0x34012
        emulator.set_key(15, True)

        uc.registers[UC_ARM_REG_R4] = 0
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xfd\x55")

        profile.pop("row_register_evidence")
        uc.registers[UC_ARM_REG_R4] = 0
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xff\x55")
        profile["row_register_evidence"] = (
            "zero-indexed-ldrb-six-row-backedge"
        )
        uc.registers[UC_ARM_REG_R4] = 1
        emulator._stable_mmio_read(
            uc, 0, register, 2, 0, (register, b"\x1f\x00")
        )
        self.assertEqual(uc.memory[register], b"\xff\x55")

    def test_direct_matrix_experimental_key_rejects_simultaneous_key(
            self) -> None:
        emulator = self._direct_emulator()

        emulator.set_key(5, True)
        self.assertEqual(emulator.held_keys, {5})
        with mock.patch(
                "msm5xxx_emulator.devices.input.LOGGER.info") as logged:
            emulator.set_key(16, True)
        self.assertEqual(emulator.held_keys, {5})
        self.assertIn("one key at a time", emulator.input_error)
        rejected = json.loads(logged.call_args.args[1])
        self.assertFalse(rejected["accepted"])
        self.assertEqual(rejected["reason"], "simultaneous-key-unsupported")
        self.assertEqual(
            rejected["mapping_source"], "automatic-evidenced"
        )

        emulator.set_key(5, False)
        self.assertEqual(emulator.held_keys, set())

    def test_direct_matrix_consumer_requires_matching_edge_after_scan(self) -> None:
        emulator = self._direct_emulator()
        uc = RegisterMemoryUc()
        profile = emulator.direct_input_profile
        emulator.set_key(15, True)
        uc.registers[UC_ARM_REG_R0] = ord("5")

        uc.registers[UC_ARM_REG_LR] = int(profile["event_sink_callsite"]) + 3
        emulator._direct_input_event_observed(uc, 0, 0, None)
        self.assertEqual(emulator.input_events, 0)

        uc.registers[UC_ARM_REG_LR] = int(profile["event_sink_callsite"]) + 5
        emulator._direct_input_event_observed(uc, 0, 0, None)
        self.assertEqual(emulator.input_events, 1)
        self.assertEqual(emulator.firmware_key_events, 0)

        emulator.direct_matrix_scans += 1
        emulator._direct_input_event_observed(uc, 0, 0, None)
        self.assertEqual(emulator.input_events, 2)
        self.assertEqual(emulator.direct_matrix_sink_events, 2)
        self.assertEqual(emulator.firmware_key_events, 1)
        self.assertEqual(emulator.input_error, "")

    def test_direct_matrix_register_read_is_telemetry_only(self) -> None:
        emulator = self._direct_emulator()

        emulator._record_key_register_read(0x03000694, 1, 0x33002)
        emulator._record_key_register_read(0x03000695, 1, 0x33004)

        self.assertEqual(emulator.key_register_reads, 2)
        self.assertEqual(
            emulator.key_register_read_pcs,
            Counter({0x33002: 1, 0x33004: 1}),
        )

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
                GenericMSMEmulator(config)

    def test_explicit_key_register_owns_overlapping_stable_byte(self) -> None:
        image = bytearray(b"\xff" * 0x1000)
        for offset in range(0, 32, 4):
            struct.pack_into("<I", image, offset, 0xEA000000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / "firmware.bin"
            firmware.write_bytes(image)
            config = detect(firmware, SimpleNamespace(
                key_register=0x03000694,
                key_active_low=True,
            ))
            config.flash_state = str(root / "flash.json")
            emulator = GenericMSMEmulator(config)
            try:
                self.assertEqual(
                    emulator.direct_input_detection,
                    "explicit-key-register-override",
                )
                emulator.set_key(15, True)
                code = config.ram_base
                emulator.uc.mem_write(
                    code, struct.pack("<2H", 0x6802, 0x4770)
                )
                emulator.uc.reg_write(UC_ARM_REG_R0, config.key_register)
                emulator.uc.reg_write(UC_ARM_REG_LR, code + 5)
                emulator.uc.reg_write(UC_ARM_REG_CPSR, 0x30)
                emulator.uc.emu_start(code | 1, 0, count=1)

                self.assertEqual(
                    emulator.uc.reg_read(UC_ARM_REG_R2),
                    0xFFFF7FFF,
                )
            finally:
                emulator.close()


if __name__ == "__main__":
    unittest.main()
