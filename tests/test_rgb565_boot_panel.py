"""The source window, exact pixel count, final control, and RGB565 channels."""
import unittest
from msm5xxx_emulator.devices.display.rgb565_boot_panel import Rgb565BootPanel


class Rgb565BootTests(unittest.TestCase):
    def window(self, panel):
        for value in panel.window:panel.write(0x02000002,2,value)

    def pixels(self,panel,count=None):
        for i in range(panel.width*panel.height if count is None else count):
            panel.write(0x02000000,2,(0xf800,0x07e0,0x001f,0xffff)[i%4])

    def test_complete_blit_and_final_control(self):
        p=Rgb565BootPanel();self.window(p);self.pixels(p)
        self.assertFalse(p.qualified);self.assertEqual(p.sequence,0)
        p.write(0x02000002,2,0x1819)
        self.assertTrue(p.qualified);self.assertEqual(p.sequence,1)
        self.assertEqual(p.frame[:12],bytes((255,0,0,0,255,0,0,0,255,255,255,255)))
        self.assertIsNone(p.rejection)
        self.window(p);self.pixels(p);p.write(0x02000002,2,0x1819)
        self.assertEqual(p.sequence,2)

    def test_wrong_window_incomplete_extra_and_interrupted_data(self):
        window_values=Rgb565BootPanel.window
        for window in window_values[:3], tuple(reversed(window_values)), (0x047c,0x0584,0x0606,0x0700):
            p=Rgb565BootPanel()
            for value in window:p.write(0x02000002,2,value)
            self.pixels(p);p.write(0x02000002,2,0x1819)
            self.assertFalse(p.qualified)
        p=Rgb565BootPanel();self.window(p);self.pixels(p,15959);p.write(0x02000002,2,0x1819)
        self.assertFalse(p.qualified)
        p=Rgb565BootPanel();self.window(p);self.pixels(p);p.write(0x02000000,2,0)
        p.write(0x02000002,2,0x1819);self.assertFalse(p.qualified);self.assertIsNotNone(p.rejection)
        p=Rgb565BootPanel();self.window(p);self.pixels(p,10)
        p.write(0x02000002,2,p.window[0]);self.pixels(p);p.write(0x02000002,2,0x1819)
        self.assertFalse(p.qualified)

    def test_width_and_foreign_bus(self):
        for address in (0x02000000,0x02000002):
            p=Rgb565BootPanel();p.write(address,1,0);self.assertIsNotNone(p.rejection)
        p=Rgb565BootPanel();self.assertFalse(p.write(0x02800000,2,0));self.assertIsNone(p.rejection)
