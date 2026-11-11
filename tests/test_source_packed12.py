import unittest

from msm5xxx_emulator.devices.display.source_packed12 import SourcePacked12
from msm5xxx_emulator.detection.devices.display.source_packed12_writer import find_source_packed12

C, D = 0x02000040, 0x02000042


def window(panel, x0=0, x1=63, y0=0, y1=127):
    for address, value in ((C, 0x75), (D, y0), (D, y1),
                           (C, 0x15), (D, x0), (D, x1), (C, 0x5c)):
        panel.write(address, 1, value)


def configure(panel, mode=(2, 1, 2)):
    panel.write(C, 1, 0xbc)
    for value in mode:
        panel.write(D, 1, value)


class SourcePacked12Tests(unittest.TestCase):
    def test_unrelated_source_is_rejected(self):
        self.assertIsNone(find_source_packed12(bytes(4096)))

    def test_frame_and_partial_window(self):
        panel = SourcePacked12()
        configure(panel)
        window(panel)
        for i in range(64 * 128):
            panel.write(D, 1, 0x12)
            panel.write(D, 1, 0x34)
            _, frame = panel.write(D, 1, 0x56)
            if i != 64 * 128 - 1:
                self.assertIsNone(frame)
        self.assertEqual(frame[:6], bytes((17, 34, 51, 68, 85, 102)))
        window(panel, 1, 1, 2, 2)
        panel.write(D, 1, 0xff)
        panel.write(D, 1, 0xff)
        _, frame = panel.write(D, 1, 0xff)
        at = (2 * 128 + 2) * 3
        self.assertEqual(frame[at:at + 6], b'\xff' * 6)
        self.assertEqual(frame[:6], bytes((17, 34, 51, 68, 85, 102)))

    def test_initial_overscan_and_interruption(self):
        panel = SourcePacked12()
        configure(panel)
        window(panel, 0, 64, 0, 129)
        frames = []
        for _ in range(65 * 130):
            panel.write(D, 1, 0)
            panel.write(D, 1, 0)
            _, frame = panel.write(D, 1, 0)
            if frame is not None:
                frames.append(frame)
        self.assertTrue(panel.qualified)
        self.assertEqual(frames[-1], bytes(128 * 128 * 3))
        window(panel, 2, 2, 3, 3)
        panel.write(D, 1, 0xff)
        panel.write(C, 1, 0xaf)
        self.assertIsNone(panel.window)
        self.assertEqual(panel.write(D, 2, 0), (False, None))

    def test_controller_mode_is_required(self):
        panel = SourcePacked12()
        configure(panel, (2, 0, 2))
        window(panel)
        for value in (0x12, 0x34, 0x56):
            self.assertIsNone(panel.write(D, 1, value)[1])
        self.assertEqual(panel.seen_count, 0)


if __name__ == '__main__':
    unittest.main()
