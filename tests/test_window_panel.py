import unittest
from msm5xxx_emulator.devices.display.window_panel import WindowPanel

SOURCE_INIT = (
    0x2C, 0x02, 0x01, 0x20, 0x05, 0x22, 0x11, 0x26, 0x0F,
    0x40, 0x01, 0x53, 0x00, 0x34, 0x86, 0x30, 0x00, 0x2A, 0xCC,
    0x43, 0x00, 0x7F, 0x42, 0x00, 0x7F, 0x10, 0x02,
)
SOURCE_CONTROLS = (
    (0x51,), (0x2C, 0x51), (0x50, 0x2D),
    (0x50, 0x2D, 0x26, 0x00, 0x02, 0x00),
)


class WindowPanelTests(unittest.TestCase):
    def test_modes_partial_window_and_rejection(self):
        p = WindowPanel(0x02000000, 2, 2)
        def command(*values):
            for value in values:
                p.write(p.port, 1, value)
        command(0x40, 0, 0x43, 0, 1, 0x42, 0, 1)
        for value in (0xF800, 0x07E0, 0x001F, 0xFFFF):
            p.write(p.port + 4, 2, value)
        self.assertEqual(p.frame, bytes((255,0,0,0,255,0,0,0,255,255,255,255)))
        command(0x40, 2, 0x43, 0, 0, 0x42, 0, 1)
        for value in (0x001F, 0xF800):
            p.write(p.port + 4, 2, value)
        self.assertEqual(p.frame, bytes((0,0,255,0,255,0,255,0,0,255,255,255)))
        command(0x40, 0)
        p.write(p.port + 4, 2, 0)
        command(0x40)
        self.assertFalse(p.qualified)
        self.assertEqual(p.rejection, 'incomplete-window')

    def test_top_left_fragment_cannot_qualify(self):
        p = WindowPanel(0x02000000, 128, 160)
        for value in (0x40, 0, 0x43, 0, 0, 0x42, 0, 0):
            p.write(p.port, 1, value)
        p.write(p.port + 4, 2, 0xFFFF)
        self.assertFalse(p.qualified)
        self.assertEqual(p.rejection, 'missing-full-raster')

    def test_default_protocol_keeps_offset4_and_strobe51(self):
        p = WindowPanel(0x02000000, 1, 1)
        for value in (0x40, 0, 0x43, 0, 0, 0x42, 0, 0):
            p.write(p.port, 1, value)
        p.write(p.port + 4, 2, 0xFFFF)
        frame, sequence = p.frame, p.sequence
        p.write(p.port, 1, 0x51)
        p.write(p.port + 2, 2, 0)
        self.assertTrue(p.qualified)
        self.assertIsNone(p.rejection)
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

    @staticmethod
    def _command(panel, command, *args):
        for value in (command, *args):
            panel.write(panel.port, 1, value)

    @staticmethod
    def _source_panel():
        return WindowPanel(0x02000000, 128, 128, protocol="copied-half128",
                           source_init=SOURCE_INIT,
                           source_controls=SOURCE_CONTROLS)

    @classmethod
    def _source_init(cls, panel):
        for value in SOURCE_INIT:
            panel.write(panel.port, 1, value)

    @classmethod
    def _source_window(cls, panel, x0, x1, y0, y1):
        cls._command(panel, 0x43, x0, x1)
        cls._command(panel, 0x42, y0, y1)

    @staticmethod
    def _source_pixels(panel, values):
        for value in values:
            panel.write(panel.port + 2, 2, value)

    def test_copied_half128_partial_is_atomic_row_major_at_nonzero_origin(self):
        p = self._source_panel()
        self._source_init(p)
        self._source_window(p, 0, 127, 0, 127)
        self._source_pixels(p, [0] * (128 * 128))
        blank = bytes(128 * 128 * 3)
        self.assertTrue(p.qualified)
        self.assertEqual(p.frame, blank)
        self.assertEqual(p.sequence, 1)

        self._source_window(p, 15, 16, 42, 43)
        colors = (0xF800, 0x07E0, 0x001F, 0xFFFF)
        self._source_pixels(p, colors[:-1])
        self.assertEqual(p.frame, blank)
        self.assertEqual(p.sequence, 1)
        self._source_pixels(p, colors[-1:])

        expected = bytearray(blank)
        rgb = ((255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255))
        for i, color in enumerate(rgb):
            y, x = 42 + divmod(i, 2)[0], 15 + divmod(i, 2)[1]
            offset = (y * 128 + x) * 3
            expected[offset:offset + 3] = bytes(color)
        self.assertEqual(p.frame, bytes(expected))
        self.assertEqual(p.sequence, 2)

        self._source_window(p, 10, 11, 10, 10)
        self._source_pixels(p, (0xF800, 0x07E0))
        self.assertEqual(p.sequence, 3)

    def test_copied_half128_reinitialize_requires_mode_and_full_raster(self):
        p = self._source_panel()
        self._source_init(p)
        self._source_window(p, 0, 127, 0, 127)
        self._source_pixels(p, [0xF800] * (128 * 128))
        previous = p.frame
        self.assertTrue(p.qualified)

        self._source_init(p)
        self.assertFalse(p.qualified)
        self.assertEqual(p.frame, previous)
        self._source_window(p, 15, 16, 42, 43)
        self._source_pixels(p, [0])
        self.assertEqual(p.rejection, "missing-full-raster")
        self.assertEqual(p.frame, previous)

        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        self.assertEqual(p.frame, bytes(128 * 128 * 3))
        self.assertEqual(p.sequence, 2)

    def test_copied_half128_malformed_partial_overflow_and_recovery(self):
        p = self._source_panel()
        self._source_init(p)
        self._source_window(p, 0, 127, 0, 127)
        self._source_pixels(p, [0] * (128 * 128))
        previous = p.frame

        self._source_window(p, 15, 16, 42, 43)
        self._source_pixels(p, [0xF800, 0x07E0, 0x001F, 0xFFFF])
        committed = p.frame
        p.write(p.port + 2, 2, 0)
        self.assertEqual(p.rejection, "window-overflow")
        self.assertEqual(p.frame, committed)

        self._source_init(p)
        self._source_window(p, 15, 16, 42, 43)
        p.write(p.port + 2, 2, 0x1234)
        self.assertEqual(p.rejection, "missing-full-raster")
        self.assertEqual(p.frame, committed)

        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        previous = p.frame
        self._source_window(p, 15, 16, 42, 43)
        p.write(p.port + 2, 2, 0x1234)
        self._command(p, 0x43, 15, 16)
        self.assertEqual(p.rejection, "incomplete-window")
        self.assertEqual(p.frame, previous)

    def test_copied_half128_bounds_mode_width_and_other_port_fail_closed(self):
        with self.assertRaises(ValueError):
            WindowPanel(0x02000000, 128, 160, protocol="copied-half128",
                        source_init=SOURCE_INIT, source_controls=SOURCE_CONTROLS)
        with self.assertRaises(ValueError):
            WindowPanel(0x02000004, 128, 128, protocol="copied-half128",
                        source_init=SOURCE_INIT, source_controls=SOURCE_CONTROLS)

        p = self._source_panel()
        with self.assertRaises(ValueError):
            WindowPanel(0x02000000, 128, 128, protocol="copied-half128")
        self._source_init(p)
        self._command(p, 0x40, 0)
        self.assertEqual(p.rejection, "unsupported-entry-mode")
        self.assertEqual(p.frame, b"")
        self._source_init(p)
        self._command(p, 0x10, 1)
        self.assertEqual(p.rejection, "unsupported-pixel-mode")

        p = self._source_panel()
        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        p.write(p.port + 2, 1, 0)
        self.assertEqual(p.rejection, "invalid-pixel-transfer")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

        p = self._source_panel()
        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        p.write(p.port + 4, 2, 0xFFFF)
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

    def test_copied_half128_rejects_out_of_bounds_and_retains_frame(self):
        p = self._source_panel()
        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence

        p.write(p.port + 2, 1, 0)
        self.assertEqual(p.rejection, "invalid-pixel-transfer")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

        self._source_init(p)
        self._command(p, 0x43, 127, 128)
        self.assertEqual(p.rejection, "invalid-window")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

    def test_copied_half128_requires_fresh_ordered_xy_for_each_window(self):
        p = self._source_panel()
        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence

        self._command(p, 0x43, 15, 16)
        p.write(p.port + 2, 2, 0xF800)
        self.assertEqual(p.rejection, "missing-y-window")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        self._command(p, 0x42, 42, 43)
        self.assertEqual(p.rejection, "missing-x-window")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        self._command(p, 0x43, 16, 15)
        self.assertEqual(p.rejection, "invalid-window")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        self._command(p, 0x40, 1)
        self._command(p, 0x10, 2)
        p.write(p.port + 2, 2, 0xF800)
        self.assertEqual(p.rejection, "missing-x-window")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

    def test_copied_half128_accepts_only_source_qualified_postclear_51(self):
        p = self._source_panel()
        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        self._command(p, 0x51)
        self._command(p, 0x2C, 0x51)
        self._command(p, 0x50, 0x2D, 0x26, 0, 2, 0)
        self.assertIsNone(p.rejection)
        self.assertTrue(p.qualified)
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

        self._command(p, 0x50, 0x2D)
        self._source_window(p, 15, 16, 42, 43)
        self._source_pixels(p, [0xF800, 0x07E0, 0x001F, 0xFFFF])
        self.assertEqual(p.sequence, sequence + 1)

    def test_copied_half128_controls_do_not_reuse_previous_xy(self):
        p = self._source_panel()
        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        self._command(p, 0x51)
        self._command(p, 0x2C, 0x51)
        self._command(p, 0x50, 0x2D)
        p.write(p.port + 2, 2, 0xF800)
        self.assertEqual(p.rejection, "window-overflow")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

    def test_copied_half128_init_rejects_main_data_and_recovers_fresh(self):
        for prefix in (1, 5, len(SOURCE_INIT) - 1):
            for size, value in ((1, 0xAA), (2, 0x1234), (4, 0)):
                with self.subTest(prefix=prefix, size=size):
                    p = self._source_panel()
                    self._source_init(p)
                    self._source_pixels(p, [0] * (128 * 128))
                    frame, sequence = p.frame, p.sequence
                    for command in SOURCE_INIT[:prefix]:
                        p.write(p.port, 1, command)
                    p.write(p.port + 2, size, value)
                    self.assertFalse(p.qualified)
                    self.assertEqual(p.rejection, "data-during-source-init")
                    for command in SOURCE_INIT[prefix:]:
                        p.write(p.port, 1, command)
                    self._source_pixels(p, [0xFFFF] * (128 * 128))
                    self.assertEqual((p.frame, p.sequence), (frame, sequence))
                    self._source_init(p)
                    self._source_pixels(p, [0xFFFF] * (128 * 128))
                    self.assertTrue(p.qualified)
                    self.assertIsNone(p.rejection)
                    self.assertEqual(p.sequence, sequence + 1)
                    self.assertEqual(p.frame, bytes([255]) * (128 * 128 * 3))

        p = self._source_panel()
        self._source_init(p)
        self._source_pixels(p, [0] * (128 * 128))
        frame, sequence = p.frame, p.sequence
        p.write(p.port, 1, 0x50)
        p.write(p.port + 2, 2, 0xFFFF)
        self.assertEqual(p.rejection, "incomplete-source-control")
        self.assertEqual((p.frame, p.sequence), (frame, sequence))

    def test_copied_half128_aux_does_not_interrupt_init(self):
        p = self._source_panel()
        for command in SOURCE_INIT[:5]:
            p.write(p.port, 1, command)
        p.write(0x02800002, 1, 0xAA)
        for command in SOURCE_INIT[5:]:
            p.write(p.port, 1, command)
        self._source_pixels(p, [0] * (128 * 128))
        self.assertTrue(p.qualified)
        self.assertEqual(p.sequence, 1)
