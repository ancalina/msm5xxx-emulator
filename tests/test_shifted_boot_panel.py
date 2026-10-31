"""Synthetic bus transactions for the shifted monochrome boot display."""
import unittest

from msm5xxx_emulator.devices.display.shifted_boot_panel import ShiftedBootPanel


class ShiftedBootPanelTests(unittest.TestCase):
    def command(self, panel, command, *arguments):
        panel.write(panel.command_port, 2, command)
        for value in arguments:
            panel.write(panel.data_port, 2, value)

    def window(self, panel, x0=2, x1=177, y0=0, y1=219):
        self.command(panel, 0x75, y0 & 255, y0 >> 8, y1 & 255, y1 >> 8)
        self.command(panel, 0x15, x0 & 255, x0 >> 8, x1 & 255, x1 >> 8)
        self.command(panel, 0x5C)

    def clear(self, panel):
        self.window(panel)
        for _ in range(panel.width * panel.height):
            panel.write(panel.data_port, 2, 0xFFFF)
        self.command(panel, 0xAF)

    def test_complete_clear_is_required_before_publication(self):
        panel = ShiftedBootPanel()
        self.window(panel)
        for _ in range(panel.width * panel.height - 1):
            panel.write(panel.data_port, 2, 0xFFFF)
        self.command(panel, 0xAF)
        self.assertFalse(panel.qualified)
        self.assertEqual(panel.sequence, 0)
        self.clear(panel)
        self.assertTrue(panel.qualified)
        self.assertEqual(set(panel.frame), {255})

    def test_partial_glyph_preserves_unwritten_rows_and_column_bias(self):
        panel = ShiftedBootPanel()
        self.clear(panel)
        self.window(panel, x0=2, x1=7, y0=0, y1=15)
        for _ in range(14 * 6):
            panel.write(panel.data_port, 2, 0)
        before = panel.sequence
        self.command(panel, 0xAF)
        self.assertEqual(panel.sequence, before + 1)
        for row in range(16):
            pixels = panel.frame[row * panel.width * 3:(row + 1) * panel.width * 3]
            self.assertEqual(pixels[:18], bytes(18) if row < 14 else b"\xff" * 18)
            self.assertEqual(pixels[18:], b"\xff" * (len(pixels) - 18))

    def test_colour_and_malformed_axes_do_not_guess_a_wire_format(self):
        panel = ShiftedBootPanel()
        self.window(panel)
        panel.write(panel.data_port, 2, 0xF800)
        self.assertEqual(panel.rejection, "colour-mode-unverified")
        self.assertFalse(panel.qualified)
        panel = ShiftedBootPanel()
        self.command(panel, 0x75, 0, 0, 219)
        self.command(panel, 0x15)
        self.assertEqual(panel.rejection, "incomplete-axis")

    def test_foreign_port_is_ignored_and_wrong_width_rejected(self):
        panel = ShiftedBootPanel()
        panel.write(0x02800004, 2, 0x75)
        self.assertIsNone(panel._command)
        panel.write(panel.command_port, 1, 0x75)
        self.assertEqual(panel.rejection, "unsupported-transfer")

    def test_display_off_preserves_gram_for_display_on(self):
        panel = ShiftedBootPanel()
        self.clear(panel)
        self.command(panel, 0xAE)
        self.assertEqual(set(panel.frame), {0})
        self.command(panel, 0xAF)
        self.assertEqual(set(panel.frame), {255})


if __name__ == "__main__":
    unittest.main()
