import unittest

from msm5xxx_emulator.devices.display.indexed1c import Indexed1C


class Indexed1CTests(unittest.TestCase):
    def panel(self):
        panel = Indexed1C(3, 2)
        for command, value in ((0x220, 0), (0x222, 0),
                               (0x224, 2), (0x226, 1)):
            self.assertEqual(panel.write(panel.command_port, 2, command), (True, None))
            self.assertEqual(panel.write(panel.data_port, 2, value), (True, None))
        return panel

    def test_full_window_publishes_rgb565_frame(self):
        panel = self.panel()
        panel.write(panel.command_port, 2, 0x28)
        frame = None
        colors = (0xf800, 0x07e0, 0x001f, 0xffff, 0, 0x8410)
        for color in colors:
            _, frame = panel.write(panel.data_port, 2, color)
        self.assertEqual(len(frame), 3 * 2 * 3)
        self.assertEqual(frame[:9], bytes((255, 0, 0, 0, 255, 0, 0, 0, 255)))
        self.assertEqual(frame[9:], bytes((255, 255, 255, 0, 0, 0, 132, 130, 132)))

    def test_partial_window_cannot_publish_a_synthetic_full_frame(self):
        panel = self.panel()
        panel.write(panel.command_port, 2, 0x222)
        panel.write(panel.data_port, 2, 0)
        panel.write(panel.command_port, 2, 0x224)
        panel.write(panel.data_port, 2, 1)
        panel.write(panel.command_port, 2, 0x226)
        panel.write(panel.data_port, 2, 0)
        panel.write(panel.command_port, 2, 0x28)
        for _ in range(2):
            self.assertIsNone(panel.write(panel.data_port, 2, 0xffff)[1])
        panel.write(panel.command_port, 2, 0x224)
        panel.write(panel.data_port, 2, 2)
        panel.write(panel.command_port, 2, 0x226)
        panel.write(panel.data_port, 2, 1)
        panel.write(panel.command_port, 2, 0x28)
        frame = None
        for _ in range(6):
            _, frame = panel.write(panel.data_port, 2, 0xffff)
        self.assertIsNotNone(frame)

    def test_invalid_window_does_not_publish(self):
        panel = self.panel()
        panel.write(panel.command_port, 2, 0x226)
        panel.write(panel.data_port, 2, 2)
        panel.write(panel.command_port, 2, 0x28)
        for _ in range(6):
            self.assertIsNone(panel.write(panel.data_port, 2, 0xffff)[1])

    def test_unknown_port_unconsumed_bad_width_resets_stream(self):
        panel = self.panel()
        self.assertEqual(panel.write(0x1234, 2, 1), (False, None))
        panel.write(panel.command_port, 2, 0x28)
        panel.write(panel.data_port, 2, 0x11223344)
        self.assertIsNone(panel.write(panel.data_port, 2, 0x1234)[1])

    def test_constructor_bounds(self):
        for arguments in ((1, 2), (3, 0), (513, 2), (2, 513)):
            with self.assertRaises(ValueError):
                Indexed1C(*arguments)
        with self.assertRaises(ValueError):
            Indexed1C(3, 2, command_port=4, data_port=4)


if __name__ == '__main__':
    unittest.main()
