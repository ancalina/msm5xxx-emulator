import hashlib
import struct
import unittest
from pathlib import Path

from msm5xxx_emulator.devices.display.cursor_panel import PackedCursorPanel


PORT = 0x02800000


def command(panel, register, value=None):
    assert panel.write(PORT, 2, register)
    if value is not None:
        assert panel.write(PORT + 4, 2, value)


def baseline(panel, pixels=None):
    command(panel, 0x05, 0x1030)
    command(panel, 0x16, 0x7F00)
    command(panel, 0x17, 0x9F00)
    command(panel, 0x21, 0)
    assert panel.write(PORT, 2, 0x22)
    for index in range(panel._PIXELS if pixels is None else pixels):
        assert panel.write(PORT + 4, 2, (index * 13) & 0xFFFF)


def glyph_setup(panel, y=32):
    command(panel, 0x05, 0x1038)
    command(panel, 0x16, 0x7E00)
    command(panel, 0x17, ((y + 15) << 8) | y)
    command(panel, 0x21, (y << 8) | 1)


class PackedCursorPanelTests(unittest.TestCase):
    def test_controller_selects_qualified_frame_and_restores_native_on_reject(self):
        import threading
        from types import SimpleNamespace
        from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin
        controller = DisplayControllerMixin()
        controller._display_lock = threading.Lock()
        controller.config = SimpleNamespace(width=2, height=3)
        controller.display_frame = bytes(range(18))
        panel = controller._lcd_cursor_panel = PackedCursorPanel(PORT)
        baseline(panel)
        self.assertEqual(controller.display_snapshot(), (2, 3, bytes(range(18))))
        glyph_setup(panel)
        command(panel, 0x22)
        for _ in range(96):
            panel.write(PORT + 4, 2, 0xF800)
        self.assertEqual(controller.display_snapshot(), (128, 160, panel.frame))
        self.assertTrue(controller.packed_cursor_snapshot()["qualified"])
        panel.write(PORT, 2, 0xFF)
        self.assertEqual(controller.display_snapshot(), (2, 3, bytes(range(18))))
        self.assertEqual(controller.packed_cursor_snapshot()["rejection"],
                         "unsupported command 0xff")

    def test_baseline_alone_does_not_qualify(self):
        panel = PackedCursorPanel(PORT)
        baseline(panel)
        self.assertFalse(panel.qualified)
        self.assertEqual(panel.sequence, 1)

    def test_interleaved_other_port_is_ignored(self):
        panel = PackedCursorPanel(PORT)
        self.assertTrue(panel.write(0x02000000, 2, 0))
        self.assertTrue(panel.write(0x02000004, 2, 0xFFFF))
        baseline(panel)
        glyph_setup(panel)
        command(panel, 0x22)
        for _ in range(96):
            self.assertTrue(panel.write(PORT + 4, 2, 0xF800))
        self.assertTrue(panel.qualified)

    def test_repeated_glyph_chunks_preserve_cursor_and_publish(self):
        panel = PackedCursorPanel(PORT)
        baseline(panel)
        glyph_setup(panel)
        command(panel, 0x22)
        for _ in range(96):
            self.assertTrue(panel.write(PORT + 4, 2, 0xF800))
        self.assertTrue(panel.qualified)
        self.assertEqual(panel.cursor, (7, 32))
        sequence = panel.sequence
        command(panel, 0x22)
        for _ in range(96):
            self.assertTrue(panel.write(PORT + 4, 2, 0x07E0))
        self.assertEqual(panel.cursor, (13, 32))
        self.assertEqual(panel.sequence, sequence + 1)

    def test_mode_exit_allows_full_raster_without_cursor_rewrite(self):
        panel = PackedCursorPanel(PORT)
        baseline(panel)
        glyph_setup(panel)
        command(panel, 0x22)
        for _ in range(96):
            panel.write(PORT + 4, 2, 0xF800)
        self.assertTrue(panel.qualified)
        command(panel, 0x05, 0x1030)
        command(panel, 0x16, 0x7F00)
        command(panel, 0x17, 0x9F00)
        command(panel, 0x22)
        for _ in range(panel._PIXELS):
            self.assertTrue(panel.write(PORT + 4, 2, 0x001F))
        self.assertEqual(panel.sequence, 3)

    def test_packed_cursor_uses_full_high_byte(self):
        panel = PackedCursorPanel(PORT)
        command(panel, 0x16, 0x7E00)
        command(panel, 0x17, 0x9F80)
        command(panel, 0x21, 0x8001)
        self.assertEqual(panel.cursor, (1, 128))

    def test_reject_is_sticky(self):
        panel = PackedCursorPanel(PORT)
        self.assertFalse(panel.write(PORT, 1, 0x05))
        reason = panel.rejection
        self.assertFalse(panel.write(PORT, 2, 0x05))
        self.assertEqual(panel.rejection, reason)
        self.assertFalse(panel.qualified)

    def test_wrong_setup_order_does_not_qualify(self):
        panel = PackedCursorPanel(PORT)
        baseline(panel)
        command(panel, 0x05, 0x1038)
        command(panel, 0x17, 0x2F20)
        command(panel, 0x16, 0x7E00)
        command(panel, 0x21, 0x2001)
        command(panel, 0x22)
        self.assertFalse(panel.write(PORT + 4, 2, 0xFFFF))
        self.assertFalse(panel.qualified)

    def test_missing_setup_data_does_not_qualify(self):
        panel = PackedCursorPanel(PORT)
        baseline(panel)
        command(panel, 0x05)  # No mode value before the next command.
        command(panel, 0x16, 0x7E00)
        command(panel, 0x17, 0x2F20)
        command(panel, 0x21, 0x2001)
        command(panel, 0x22)
        self.assertFalse(panel.write(PORT + 4, 2, 0xFFFF))
        self.assertFalse(panel.qualified)

    def test_complete_saved_trace_hash(self):
        root = Path(__file__).resolve().parents[2]
        trace = root / "evidence/r13/analysis/dual-display-20260929/e160-complete-trace-r2/SCH-E160/lcd-records.bin"
        if not trace.exists():
            self.skipTest("saved E160 trace is unavailable")
        panel = PackedCursorPanel(PORT)
        raw = trace.read_bytes()
        self.assertEqual(len(raw) % 16, 0)
        for offset in range(0, len(raw), 16):
            record = raw[offset:offset + 16]
            if record[0] != 1 or record[1] != 2:
                continue
            address, value = struct.unpack_from("<II", record, 4)
            if address in (PORT, PORT + 4):
                panel.write(address, 2, value)
        self.assertTrue(panel.qualified, panel.rejection)
        self.assertEqual(hashlib.sha256(panel.frame).hexdigest(),
                         "4fba7e571f26b0f41426342275443f11c3095e793633a6957461783d9ea8adf0")


if __name__ == "__main__":
    unittest.main()
