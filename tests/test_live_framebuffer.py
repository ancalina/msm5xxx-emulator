"""Live framebuffer colour-map update regressions."""
from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest

from gui import can_apply_live_framebuffer_format
from msm5xxx import GenericMSMEmulator


class LiveFramebufferTests(unittest.TestCase):
    def test_colour_format_only_change_can_stay_live(self) -> None:
        self.assertTrue(can_apply_live_framebuffer_format(
            {"framebuffer_format"}, False, 0x01010000, "bgr565le"
        ))

    def test_address_change_or_disabled_framebuffer_requires_restart(self) -> None:
        self.assertFalse(can_apply_live_framebuffer_format(
            {"framebuffer_address", "framebuffer_format"},
            False, 0x01010000, "bgr565le",
        ))
        self.assertFalse(can_apply_live_framebuffer_format(
            {"framebuffer_format"}, False, None, "none"
        ))

    def test_inactive_worker_requires_a_restart(self) -> None:
        self.assertFalse(can_apply_live_framebuffer_format(
            {"framebuffer_format"}, False, 0x01010000, "bgr565le",
            worker_active=False,
        ))

    def test_emulator_reinterprets_mapped_framebuffer_without_reboot(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            framebuffer_address=0x01010000,
            framebuffer_format="rgb565le",
            width=128,
            height=160,
        )
        calls: list[tuple[int, int, int, int, bool, bool]] = []
        emulator._render_framebuffer_region = (
            lambda x0, y0, x1, y1, force, firmware_originated: calls.append(
                (x0, y0, x1, y1, force, firmware_originated)
            )
        )

        emulator.set_framebuffer_format("bgr565le")

        self.assertEqual(emulator.config.framebuffer_format, "bgr565le")
        self.assertEqual(calls, [(0, 0, 127, 159, True, False)])

    def test_preseed_publish_does_not_count_as_firmware_frame(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.framebuffer = bytearray((1, 2, 3))
        emulator.display_frame = bytes(3)
        emulator.frame_sequence = 0
        emulator.firmware_frame_sequence = 0
        emulator._display_lock = threading.Lock()
        emulator._lcd_protocol = "framebuffer-rgb565le"
        emulator._lcd_frame_protocol = "none"

        emulator._publish_frame(firmware_originated=False)

        self.assertEqual(emulator.display_frame, bytes((1, 2, 3)))
        self.assertEqual(emulator.frame_sequence, 1)
        self.assertEqual(emulator.firmware_frame_sequence, 0)

        emulator._publish_frame()

        self.assertEqual(emulator.frame_sequence, 2)
        self.assertEqual(emulator.firmware_frame_sequence, 1)


if __name__ == "__main__":
    unittest.main()
