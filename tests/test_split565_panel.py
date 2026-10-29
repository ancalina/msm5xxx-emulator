import struct
import unittest
from msm5xxx_emulator.devices.display.split565_panel import (
    Split565Panel, decode_split565, find_split565_port,
)


def encode(pixel):
    return pixel >> 14, (pixel & 0x3800) << 2 | (pixel & 0x7ff) << 1


class Split565Tests(unittest.TestCase):
    def window(self, panel, alternate=False):
        words = (0x0800,0x0977,0x0a00,0x0b9f) if alternate else (0x0200,0x0300,0x0477,0x059f)
        for value in words:
            panel.write(panel.port+0x78,2,value)
        panel.write(panel.port+0x78,2,0x0d00)
        panel.write(panel.port+0x78,2,0x0e00)

    def test_all_65536_roundtrip(self):
        for pixel in range(65536):
            self.assertEqual(decode_split565(*encode(pixel)),pixel)

    def test_full_and_every_flush_prefix(self):
        for alternate in (False,True):
            panel = Split565Panel()
            self.window(panel,alternate)
            for index in range(19200):
                for value in encode(0xf800):
                    panel.write(panel.port+0xfa,2,value)
                    panel.flush()
                    self.assertIsNone(panel.rejection)
                if index != 19199:
                    self.assertEqual(panel.frame,b'')
                    self.assertFalse(panel.qualified)
            self.assertTrue(panel.qualified)
            self.assertEqual(panel.frame,bytes((255,0,0))*19200)
            self.assertEqual(panel.sequence,1)
            snapshot=panel.snapshot()
            self.assertEqual(snapshot['frame'],panel.frame)
            self.assertEqual((snapshot['width'],snapshot['height']),(120,160))
            self.assertTrue(snapshot['qualified'])
            self.assertIsNone(snapshot['enabled'])
            panel.flush()
            panel.write(0x02400000,1,123)
            self.assertEqual(panel.sequence,1)
            self.assertTrue(panel.qualified)

    def test_invalid_pairs(self):
        for pair in ((4,0),(0,1),(0,0x1000),(0,65535)):
            panel=Split565Panel()
            self.window(panel)
            for value in pair:
                panel.write(panel.port+0xfa,2,value)
            panel.flush()
            self.assertEqual(panel.rejection,'invalid-split565-pair')
            self.assertEqual(panel.sequence,0)
            with self.assertRaises(ValueError):
                decode_split565(*pair)

    def test_incomplete_interrupt_reset_and_overflow(self):
        for count in (1,38399,38401):
            panel=Split565Panel()
            self.window(panel)
            for _ in range(count):
                panel.write(panel.port+0xfa,2,0)
            if count != 38401:
                panel.flush()
                self.assertIsNone(panel.rejection)
            panel.write(panel.port+0x78,2,0x0200)
            self.assertTrue(panel.rejection)
            self.assertEqual(panel.sequence,0)
        panel=Split565Panel()
        self.window(panel)
        panel.write(panel.port+0xfa,2,0)
        panel.reset()
        panel.write(panel.port+0xfa,2,0)
        self.assertEqual(panel.rejection,'missing-full-window')
        panel.reset()
        self.window(panel)
        panel.write(panel.port+0xfa,1,0)
        self.assertEqual(panel.rejection,'invalid-halfword-transfer')
        with self.assertRaises(ValueError):
            Split565Panel(0x02800000)

    def test_unsupported_window(self):
        panel=Split565Panel()
        for word in (0x0200,0x0300,0x0407,0x050f):
            panel.write(panel.port+0x78,2,word)
        self.assertEqual(panel.rejection,'unsupported-window')

    def test_bound_source_and_near_miss(self):
        image=bytearray(1024)
        producer=bytes.fromhex('b200d4e04027a0e1ba2fc3e1e02d00e20221a0e1f80cc0e3800082e1ba0fc3e1')
        image[512:544]=producer
        image[740:772]=producer
        image[436:448]=bytes.fromhex('7720a0e30610a0e10000a0e3')
        image[460:464]=bytes.fromhex('80a7a0e3')
        image[496:500]=bytes.fromhex('0a30a0e1')
        image[504:508]=bytes.fromhex('7810a0e3')
        image[808:812]=bytes.fromhex('a00056e3')
        image[128:216]=bytes.fromhex(
            'f0402de90370a0e10260a0e10150a0e10040a0e1b80c00eb770066e2800f80e3'
            '8067a0e3b807c6e1b30c00ebc00f85e3b807c6e1b00c00eb770064e2400e80e3'
            'b807c6e1ac0c00eb500e87e3b807c6e1f040bde81eff2fe1')
        struct.pack_into('<I',image,448,0xeb000000|(((128-448-8)//4)&0xffffff))
        self.assertEqual(find_split565_port(bytes(image))[0],0x02000000)
        for offset in (461,497,517,744,809,160,448):
            changed=image.copy()
            changed[offset]^=1
            self.assertIsNone(find_split565_port(bytes(changed))[0],offset)
        self.assertIsNone(find_split565_port(b'x'+image)[0])
        self.assertIsNone(find_split565_port(producer)[0])


if __name__ == '__main__':
    unittest.main()
