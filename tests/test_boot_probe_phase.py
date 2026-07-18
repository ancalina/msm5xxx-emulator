"""Boot-probe phase classification regressions."""
from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
