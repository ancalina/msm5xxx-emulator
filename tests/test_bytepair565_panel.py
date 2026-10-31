"""Window, enable, byte order and complete source-sized raster boundaries."""
import unittest
from msm5xxx_emulator.devices.display.bytepair565_panel import BytePair565Panel


class BytePair565Tests(unittest.TestCase):
    def commands(self,p,*values):
        for value in values:p.write(0x02000000,2,value)

    def pixels(self,p,count=None):
        for i in range(p.width*p.height if count is None else count):
            value=(0xf800,0x07e0,0x001f,0xffff)[i%4]
            p.write(0x02400000,2,value>>8);p.write(0x02400000,2,value&255)

    def test_complete_window_and_color_order(self):
        p=BytePair565Panel();self.commands(p,0xaf,*p.window);self.pixels(p,8319)
        p.write(0x02400000,2,255);self.assertEqual(p.sequence,0)
        p.write(0x02400000,2,255)
        self.assertEqual(p.sequence,1);self.assertTrue(p.qualified)
        self.assertEqual(p.frame[:12],bytes((255,0,0,0,255,0,0,0,255,255,255,255)))
        self.commands(p,*p.window);self.pixels(p);self.assertEqual(p.sequence,2)

    def test_missing_enable_extent_or_interrupted_pair(self):
        for enable,window in [(False,BytePair565Panel.window),(True,BytePair565Panel.window[:-1]),
                              (True,(0xf8,0xf4,1,0xf5,0,0xf6,103,0xf7,79,0xf9))]:
            p=BytePair565Panel()
            if enable:self.commands(p,0xaf)
            self.commands(p,*window);self.pixels(p);self.assertEqual(p.sequence,0)
        p=BytePair565Panel();self.commands(p,0xaf,*p.window);self.pixels(p,8000)
        p.write(0x02400000,2,0);self.commands(p,0xf8);self.pixels(p)
        self.assertEqual(p.sequence,0)

    def test_access_width_value_and_foreign_bus(self):
        for address,size,value in [(0x02000000,1,0xaf),(0x02400000,1,255),(0x02400000,2,256)]:
            p=BytePair565Panel();p.write(address,size,value);self.assertIsNotNone(p.rejection)
        p=BytePair565Panel();p.write(0x02800000,2,0xaf);self.assertFalse(p.enabled)
