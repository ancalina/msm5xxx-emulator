import unittest
from msm5xxx_emulator.devices.display.window_panel import WindowPanel


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
