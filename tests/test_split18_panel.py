import unittest

from msm5xxx_emulator.devices.display.split18_panel import (
    Split18Panel, find_split18_port,
)


class Split18PanelTests(unittest.TestCase):
    def test_snapshot_contract(self):
        panel = Split18Panel()
        state = panel.snapshot()
        self.assertEqual(set(state), {"width", "height", "frame", "qualified", "enabled",
                                     "port", "rejection", "observation", "sequence"})
        self.assertFalse(state["qualified"])
        self.assertEqual((state["width"], state["height"]), (128, 160))
        self.assertEqual(state["port"], 0x02000000)

    def window(self, panel, bounds=(0, 0, 127, 159)):
        x0, y0, x1, y1 = bounds
        for register, argument in ((8,x0),(10,y0),(9,x1),(11,y1),(6,x0),(7,y0)):
            panel.write(panel.port, 2, register << 8 | argument)

    def fill(self, panel, count, white=True):
        for _ in range(count):
            panel.write(panel.port+2, 2, 65535 if white else 0)
            panel.write(panel.port+2, 2, 3 if white else 0)

    def full(self):
        panel = Split18Panel()
        self.window(panel)
        self.fill(panel, 128*160)
        self.assertFalse(panel.qualified)
        self.assertEqual(panel.sequence, 0)
        panel.flush()
        self.assertTrue(panel.qualified)
        return panel

    def test_full_partial_and_preservation(self):
        panel = self.full()
        self.assertEqual(panel.frame, b'\xff'*(128*160*3))
        panel.flush()
        self.assertEqual(panel.sequence, 1)
        self.window(panel, (8,16,15,31))
        self.fill(panel, 128, False)
        panel.flush()
        self.assertEqual(panel.sequence, 2)
        for y in range(160):
            for x in range(128):
                level = 0 if 8 <= x <= 15 and 16 <= y <= 31 else 255
                offset = (y*128+x)*3
                self.assertEqual(panel.frame[offset:offset+3], bytes([level])*3)

    def test_near_miss_no_commit(self):
        for words in (1, 40959, 40961):
            with self.subTest(words=words):
                panel = Split18Panel()
                self.window(panel)
                for i in range(words):
                    panel.write(panel.port+2, 2, 65535 if i%2 == 0 else 3)
                panel.flush()
                self.assertFalse(panel.qualified)
                self.assertEqual(panel.sequence, 0)
                panel.write(panel.port, 2, 0x0800)
                self.assertTrue(panel.rejection)

    def test_telemetry_flush_during_every_halfword_prefix(self):
        panel = Split18Panel()
        self.window(panel)
        for i in range(40960):
            panel.write(panel.port+2, 2, 65535 if i%2 == 0 else 3)
            panel.flush()
            self.assertIsNone(panel.rejection)
            if i < 40959:
                self.assertFalse(panel.qualified)
                self.assertEqual(panel.frame, b'')
                self.assertEqual(panel.sequence, 0)
        self.assertTrue(panel.qualified)
        self.assertEqual(panel.sequence, 1)
        frame = panel.frame
        self.window(panel, (0,0,7,15))
        for i in range(255):
            panel.write(panel.port+2, 2, 0)
            panel.flush()
            self.assertIsNone(panel.rejection)
            self.assertEqual(panel.frame, frame)
            self.assertEqual(panel.sequence, 1)
        panel.write(panel.port, 2, 0x0800)
        self.assertEqual(panel.rejection, 'incomplete-window')
        self.assertEqual(panel.frame, frame)
        self.assertEqual(panel.sequence, 1)

    def test_malformed_window_and_bus(self):
        for bounds, reason in [((8,0,7,159),'reversed-window'),
                               ((0,0,128,159),'window-outside-viewport'),
                               ((0,0,7,15),'missing-full-raster')]:
            panel = Split18Panel()
            self.window(panel, bounds)
            panel.write(panel.port+2, 2, 0)
            self.assertEqual(panel.rejection, reason)
        panel = Split18Panel()
        self.window(panel)
        panel.write(panel.port+2, 1, 0)
        self.assertEqual(panel.rejection, 'invalid-halfword-transfer')
        panel = Split18Panel()
        self.window(panel)
        panel.write(panel.port, 2, 0x0601)
        panel.write(panel.port+2, 2, 0)
        self.assertEqual(panel.rejection, 'cursor-window-mismatch')
        with self.assertRaises(ValueError):
            Split18Panel(0x02800000)

    def test_color_and_interruption_reject_before_commit(self):
        for pair in ((1,0), (65535,0), (0,3), (65535,4)):
            panel = Split18Panel()
            self.window(panel)
            for value in pair:
                panel.write(panel.port+2, 2, value)
            panel.flush()
            self.assertEqual(panel.rejection, 'unproved-color-packing')
            self.assertEqual(panel.sequence, 0)
        panel = Split18Panel()
        self.window(panel)
        panel.write(panel.port+2, 2, 0)
        panel.write(panel.port, 2, 0x0800)
        self.assertEqual(panel.rejection, 'incomplete-window')

    def test_reset_drops_odd_data_and_stale_window(self):
        panel = self.full()
        self.window(panel, (0,0,7,15))
        panel.write(panel.port+2, 2, 0)
        panel.reset()
        self.assertFalse(panel.qualified)
        self.assertEqual(panel.frame, b'')
        panel.write(panel.port+2, 2, 0)
        self.assertEqual(panel.rejection, 'missing-window-or-cursor')
        panel.reset()
        self.window(panel)
        self.fill(panel, 20480)
        panel.flush()
        self.assertTrue(panel.qualified)

    def test_control_and_foreign_panel_do_not_erase_frame(self):
        panel = self.full()
        frame = panel.frame
        panel.write(panel.port, 2, 0x2201)
        panel.write(0x02800000, 1, 0)
        self.assertTrue(panel.qualified)
        self.assertEqual(panel.frame, frame)
        panel.write(panel.port+2, 2, 0)
        self.assertEqual(panel.rejection, 'missing-window-or-cursor')

    def test_source_binding_and_mutations(self):
        # Captured original Thumb producer, base construction and row/column loops.
        image = bytearray(256)
        image[0:8] = bytes.fromhex('0121c9028f033980')
        image[126:142] = bytes.fromhex('8700d459240c6c80d759bf07bf0f6f80')
        image[156:170] = bytes.fromhex('013101308028ecd30133a02be5d3')
        self.assertEqual(find_split18_port(bytes(image))[0], 0x02000000)
        for offset in (3, 130, 161, 166):
            changed = image.copy()
            changed[offset] ^= 1
            self.assertIsNone(find_split18_port(bytes(changed))[0])
        self.assertIsNone(find_split18_port(bytes(image+image))[0])
        self.assertIsNone(find_split18_port(b'')[0])
        self.assertIsNone(find_split18_port(b'x'+bytes(image))[0])


if __name__ == '__main__':
    unittest.main()
