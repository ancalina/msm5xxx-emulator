"""Boot-probe phase classification regressions."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest import mock

import boot_probe
from boot_probe import boot_event, boot_phase, firmware_visible_frame


class BootProbePhaseTests(unittest.TestCase):
    def _state(self, **changes: object) -> dict[str, object]:
        state: dict[str, object] = {
            "fault": None,
            "frame_sequence": 0,
            "firmware_frame_sequence": 0,
            "rex_ticks": 0,
            "secondary_flash_reads": 0,
            "secondary_flash_writes": 0,
            "nand_reads": 0,
            "nand_writes": 0,
            "lcd_writes": 0,
            "control_sink": None,
        }
        state.update(changes)
        return state

    def test_control_sink_beats_one_setup_write_without_a_frame(self) -> None:
        self.assertEqual(
            boot_phase(self._state(lcd_writes=1, control_sink="0x000832AC"), 0),
            "control-sink",
        )

    def test_visible_frame_remains_stronger_than_control_sink_hint(self) -> None:
        self.assertEqual(
            boot_phase(self._state(
                frame_sequence=1, firmware_frame_sequence=1,
                control_sink="0x000832AC",
            ), 10),
            "visible-frame",
        )

    def test_preseed_frame_is_not_runtime_display(self) -> None:
        self.assertEqual(
            boot_phase(self._state(frame_sequence=1), 10),
            "preseed-frame",
        )

    def test_firmware_visible_frame_does_not_require_a_hash_change(self) -> None:
        self.assertTrue(firmware_visible_frame(
            self._state(frame_sequence=1, firmware_frame_sequence=1), 10,
        ))

    def test_timeline_distinguishes_preseed_splash_and_later_changes(self) -> None:
        event, saw_splash = boot_event(
            self._state(frame_sequence=1), 10, "seed", "seed", "seed", False,
        )
        self.assertEqual((event, saw_splash), ("early-boot", False))

        event, saw_splash = boot_event(
            self._state(frame_sequence=2, firmware_frame_sequence=1),
            10, "splash", "seed", "seed", saw_splash,
        )
        self.assertEqual((event, saw_splash), ("boot-splash", True))

        event, saw_splash = boot_event(
            self._state(frame_sequence=3, firmware_frame_sequence=2),
            10, "next", "seed", "splash", saw_splash,
        )
        self.assertEqual((event, saw_splash), ("post-splash-changing", True))

    def test_probe_checkpoint_carries_reset_entries(self) -> None:
        state = dict.fromkeys((
            "instructions", "reset_entries", "frame_sequence",
            "firmware_frame_sequence", "lcd_writes", "lcd_port_writes",
            "fast_register_ramps", "rex_idle_entries", "rex_ticks",
            "rex_elapsed_ms", "secondary_flash_reads",
            "secondary_flash_writes", "secondary_flash_changed_pages",
            "eeprom_capacity", "eeprom_reads", "eeprom_read_bytes",
            "eeprom_writes", "eeprom_write_bytes", "eeprom_changed_bytes",
            "eeprom_loaded_from_state", "nand_reads", "nand_writes",
            "poll_escapes",
        ), 0)
        state.update({
            "config": {}, "reset_entries": 2, "pc": "0x00000000",
            "lr": "0x00000000", "registers": {}, "fault": None,
            "fault_context": None, "lcd_protocol": None,
            "lcd_frame_protocol": None, "primary_flash_ids": None,
            "primary_flash_telemetry": {},
            "primary_parallel_nor_direct_id_probes": [], "input_mode": None,
            "input_events": [], "firmware_key_events": [],
            "secondary_flash_telemetry": {}, "eeprom_error": None,
            "nand_commands": [], "control_sink": None,
            "last_unmapped": None, "tail": [],
        })

        class FakeEmulator:
            def __init__(self, _config: object) -> None:
                self.hot: Counter[int] = Counter()
                self.mmio_reads: Counter[tuple[int, int, int]] = Counter()
                self.mmio_read_totals: Counter[tuple[int, int, int]] = Counter()

            def run(self, instructions: int) -> dict[str, object]:
                return dict(state, instructions=instructions)

            @staticmethod
            def display_snapshot() -> tuple[int, int, bytes]:
                return 1, 1, b"\0\0\0"

            def close(self) -> None:
                pass

        config = SimpleNamespace(
            model="test", chipset="MSM5000", chipset_confidence="test",
            image_kind="firmware", dump_status="complete", image_offset=0,
            load_address=0, flash_size=1, ram_base=0, ram_size=1,
            rex_idle_address=None, rex_tick_address=None,
            secondary_flash_address=None, detection_notes=[], width=1, height=1,
        )
        with TemporaryDirectory() as directory:
            with mock.patch.object(boot_probe, "detect", return_value=config), \
                 mock.patch.object(boot_probe, "GenericMSMEmulator", FakeEmulator):
                report = boot_probe.probe(
                    Path("test.bin"), [1], Path(directory) / "frames"
                )
        self.assertEqual(report["checkpoints"][0]["reset_entries"], 2)


if __name__ == "__main__":
    unittest.main()
