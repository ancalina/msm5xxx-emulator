import unittest

from msm5xxx_emulator.devices.display.packed_window2 import PackedWindow2

CMD, DATA = 0x02000000, 0x02000004


def configure(panel):
    for address, value in ((CMD, 0xa8), (DATA, 3), (DATA, 66),
                           (CMD, 0xfb), (DATA, 7)):
        panel.write(address, 1, value)


def window(panel, x0=7, x1=22, y0=3, y1=66):
    for address, value in ((CMD, 0x5c), (CMD, 0x15), (DATA, x0), (DATA, x1),
                           (CMD, 0x75), (DATA, y0), (DATA, y1),
                           (CMD, 0xfb), (CMD, 7), (CMD, 0x5c)):
        panel.write(address, 1, value)


class PackedWindowTests(unittest.TestCase):
    def test_complete_window_and_partial_update(self):
        panel = PackedWindow2()
        configure(panel)
        window(panel)
        for _ in range(16 * 64 - 1):
            self.assertIsNone(panel.write(DATA, 1, 0x1b))
        width, height, frame = panel.write(DATA, 1, 0x1b)
        self.assertEqual((width, height), (64, 64))
        self.assertEqual(frame[:12], bytes((0, 0, 0, 85, 85, 85,
                                            170, 170, 170, 255, 255, 255)))
        window(panel, 8, 8, 4, 4)
        _, _, frame = panel.write(DATA, 1, 0xff)
        at = (64 + 4) * 3
        self.assertEqual(frame[at:at + 12], bytes([255]) * 12)
        self.assertEqual(frame[:12], bytes((0, 0, 0, 85, 85, 85,
                                            170, 170, 170, 255, 255, 255)))

    def test_mode_row_extent_and_transaction_are_required(self):
        for configure_first, bad_mode, y1 in ((False, False, 66),
                                               (True, True, 66),
                                               (True, False, 65)):
            panel = PackedWindow2()
            if configure_first:
                configure(panel)
            if bad_mode:
                panel.write(CMD, 1, 0xfb)
                panel.write(DATA, 1, 6)
            window(panel, y1=y1)
            for _ in range(16 * 64):
                self.assertIsNone(panel.write(DATA, 1, 0))
            self.assertIsNone(panel.canvas)

    def test_interrupted_write_does_not_publish(self):
        panel = PackedWindow2()
        configure(panel)
        window(panel)
        panel.write(DATA, 1, 0xff)
        panel.write(CMD, 1, 0x11)
        self.assertIsNone(panel.canvas)
        self.assertIsNone(panel.window)
