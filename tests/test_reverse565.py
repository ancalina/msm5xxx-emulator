import unittest

from msm5xxx_emulator.devices.display.reverse565 import Reverse565
from msm5xxx_emulator.detection.devices.display.reverse565_writer import find_reverse565_writer

C, D = 0x02000004, 0x02000000


def window(panel, x0=6, y0=0, x1=125, y1=132):
    for value in (4, x0, 5, y0, 6, x1, 7, y1):
        panel.write(C, 1, value)


class Reverse565Tests(unittest.TestCase):
    def test_unrelated_source_is_rejected(self):
        self.assertIsNone(find_reverse565_writer(bytes(4096)))

    def test_full_frame_and_partial_update(self):
        panel = Reverse565()
        window(panel)
        for i in range(120 * 133):
            panel.write(D, 1, 255)
            _, frame = panel.write(D, 1, 255)
            if i != 120 * 133 - 1:
                self.assertIsNone(frame)
        self.assertEqual(frame, b'\xff' * (120 * 133 * 3))
        window(panel, 7, 2, 7, 2)
        self.assertIsNone(panel.write(D, 1, 0)[1])
        _, frame = panel.write(D, 1, 0xf8)
        at = (2 * 120 + 1) * 3
        self.assertEqual(frame[at:at + 3], b'\xff\0\0')
        self.assertEqual(frame[at + 3:at + 6], b'\xff' * 3)

    def test_outside_window_and_wrong_width(self):
        panel = Reverse565()
        window(panel, 5, 0, 125, 132)
        self.assertIsNone(panel.window)
        self.assertEqual(panel.write(D, 2, 0), (False, None))


if __name__ == '__main__':
    unittest.main()
