"""Runtime evidence gate for candidate GPIO keypad profiles."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import struct
import tempfile
import unittest

from msm5xxx import GenericMSMEmulator, detect
from unicorn.arm_const import (
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R2,
    UC_ARM_REG_R5,
)


class RegisterMemoryUc:
    def __init__(self) -> None:
        self.registers: dict[int, int] = {}
        self.memory: dict[int, bytes] = {}

    def reg_read(self, register: int) -> int:
        return self.registers.get(register, 0)

    def mem_write(self, address: int, data: bytes) -> None:
        self.memory[address] = bytes(data)


class InputRuntimeTests(unittest.TestCase):
    @staticmethod
    def _direct_profile() -> dict[str, object]:
        return {
            "grammar": "direct-low-nibble-6-row-v1",
            "function": 0x32000,
            "sense_site": 0x33000,
            "register": 0x03000694,
            "row_register": 5,
            "event_sink_callsite": 0x33020,
            "event_sink": 0x31000,
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
        emulator.direct_input_positions = emulator._direct_matrix_positions(
            emulator.direct_input_profile
        )
        emulator.direct_key_scan_epochs = {}
        emulator.direct_matrix_scans = 0
        emulator.direct_matrix_active_reads = 0
        emulator.direct_matrix_sink_events = 0
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

        emulator.set_key(0, True)

        self.assertEqual(emulator.held_keys, set())
        self.assertEqual(
            emulator.input_error,
            "automatic keypad transport not detected; physical register override required",
        )

    def test_direct_matrix_maps_evidenced_samsung_keys_to_firmware_matrix(
            self) -> None:
        emulator = self._direct_emulator()

        self.assertEqual(len(emulator.direct_input_positions), 19)
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
        self.assertNotIn(5, emulator.direct_input_positions)
        self.assertNotIn(7, emulator.direct_input_positions)
        self.assertNotIn(8, emulator.direct_input_positions)
        self.assertNotIn(10, emulator.direct_input_positions)

    def test_direct_matrix_lg_profile_keeps_menu_unmapped(self) -> None:
        profile = self._direct_profile()
        profile["event_sink_family"] = "lg-ring256-event-queue-v1"

        positions = GenericMSMEmulator._direct_matrix_positions(profile)

        self.assertEqual(len(positions), 12)
        self.assertNotIn(0, positions)
        self.assertNotIn(1, positions)
        self.assertNotIn(2, positions)

    def test_direct_matrix_unclassified_profile_maps_no_keys(self) -> None:
        profile = self._direct_profile()
        profile["event_sink_family"] = "unclassified"

        self.assertEqual(GenericMSMEmulator._direct_matrix_positions(profile), {})

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

    def test_direct_matrix_rejects_unproven_and_simultaneous_keys(self) -> None:
        emulator = self._direct_emulator()

        emulator.set_key(5, True)
        self.assertEqual(emulator.held_keys, set())
        self.assertIn("semantic is not proven", emulator.input_error)

        emulator.set_key(0, True)
        emulator.set_key(16, True)
        self.assertEqual(emulator.held_keys, {0})
        self.assertIn("one evidenced key", emulator.input_error)

        emulator.set_key(0, False)
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
