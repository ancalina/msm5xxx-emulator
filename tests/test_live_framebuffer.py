"""Live framebuffer colour-map update regressions."""
from __future__ import annotations

from types import SimpleNamespace
import threading
import unittest

from gui import can_apply_live_framebuffer_format
from msm5xxx import GenericMSMEmulator


class LiveFramebufferTests(unittest.TestCase):
    def test_partial_framebuffer_render_has_exact_format_and_publish_semantics(self) -> None:
        width, height, address = 4, 3, 0x01010000
        expected = bytes((
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0,
        ))
        pixels = (0xF800, 0x07E0, 0x001F, 0xFFFF)

        for framebuffer_format in (
                "rgb565le", "bgr565le", "rgb565be", "bgr565be"):
            bgr = framebuffer_format.startswith("bgr")
            endian = "big" if framebuffer_format.endswith("be") else "little"
            values = tuple(
                ((value & 0x07E0) | (value & 0x001F) << 11
                 | (value >> 11 & 0x001F)) if bgr else value
                for value in pixels
            )
            memory = bytearray(width * height * 2)
            for offset, value in zip((10, 12, 18, 20), values):
                memory[offset:offset + 2] = value.to_bytes(2, endian)
            emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
            emulator.config = SimpleNamespace(
                framebuffer_address=address, framebuffer_stride=width * 2,
                framebuffer_format=framebuffer_format, width=width, height=height,
            )
            emulator.framebuffer = bytearray(width * height * 3)
            emulator.uc = SimpleNamespace(
                mem_read=lambda offset, size: bytes(memory[offset - address:
                                                          offset - address + size])
            )
            publishes: list[bool] = []
            emulator._publish_frame = (
                lambda *, firmware_originated=True: publishes.append(
                    firmware_originated
                )
            )

            self.assertTrue(emulator._render_framebuffer_region(1, 1, 2, 2))
            self.assertEqual(emulator.framebuffer, expected)
            self.assertEqual(emulator._lcd_protocol,
                             f"framebuffer-{framebuffer_format}")
            self.assertEqual(publishes, [True])
            self.assertFalse(emulator._render_framebuffer_region(1, 1, 2, 2,
                                                                  force=False))
            self.assertEqual(publishes, [True])
            self.assertFalse(emulator._render_framebuffer_region(1, 1, 2, 2,
                                                                  force=True))
            self.assertEqual(publishes, [True, True])

    def test_abnormal_mem_read_length_keeps_legacy_render_semantics(self) -> None:
        def render(row: bytes, width: int, height: int,
                   x0: int, x1: int) -> bytes:
            emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
            emulator.config = SimpleNamespace(
                framebuffer_address=0x01010000, framebuffer_stride=width * 2,
                framebuffer_format="rgb565le", width=width, height=height,
            )
            emulator.framebuffer = bytearray(width * height * 3)
            emulator.uc = SimpleNamespace(mem_read=lambda _address, _size: row)
            emulator._publish_frame = lambda **_kwargs: None
            self.assertTrue(emulator._render_framebuffer_region(
                x0, 0, x1, 0, force=False
            ))
            return bytes(emulator.framebuffer)

        self.assertEqual(
            render(b"\x00\xf8\xe0", 3, 1, 0, 1),
            bytes((255, 0, 0, 0, 28, 0, 0, 0, 0)),
        )
        self.assertEqual(
            render(b"\x00\xf8\xe0\x07\x1f\x00\xff\xff", 2, 2, 1, 1),
            bytes((0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255)),
        )

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
