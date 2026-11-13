"""Synthetic packed-window transactions and publication boundaries."""
import unittest

from msm5xxx_emulator.devices.display.indexed44 import Indexed44


class Indexed44Tests(unittest.TestCase):
    def register(self, panel, index, value):
        panel.write(panel.command_port, 2, index)
        return panel.write(panel.data_port, 2, value)

    def window(self, panel, bounds=(0, 1, 0, 1), cursor=0):
        x0, x1, y0, y1 = bounds
        self.register(panel, 0x44, x0 | x1 << 8)
        self.register(panel, 0x45, y0 | y1 << 8)
        self.register(panel, 0x21, cursor)
        panel.write(panel.command_port, 2, 0x22)

    def test_rgb565_pixels_publish_after_the_complete_window(self):
        panel = Indexed44(2, 2)
        self.window(panel)
        for pixel in (0xf800, 0x07e0, 0x001f):
            self.assertEqual(panel.write(panel.data_port, 2, pixel), (True, None))
        consumed, frame = panel.write(panel.data_port, 2, 0xffff)
        self.assertTrue(consumed)
        self.assertEqual(frame, bytes((255, 0, 0, 0, 255, 0,
                                       0, 0, 255, 255, 255, 255)))

    def test_origin_cursor_and_partial_window_preserve_other_observed_pixels(self):
        panel = Indexed44(2, 2, x_origin=4, y_origin=8)
        self.window(panel, (4, 5, 8, 9), 4 | 8 << 8)
        for _ in range(4):
            panel.write(panel.data_port, 2, 0xffff)
        self.window(panel, (5, 5, 9, 9), 5 | 9 << 8)
        _, frame = panel.write(panel.data_port, 2, 0x001f)
        self.assertEqual(frame, b'\xff' * 9 + bytes((0, 0, 255)))

    def test_unbounded_or_missing_cursor_never_publishes(self):
        panel = Indexed44(2, 2)
        self.register(panel, 0x44, 0x0100)
        self.register(panel, 0x45, 0x0100)
        panel.write(panel.command_port, 2, 0x22)
        for _ in range(4):
            self.assertEqual(panel.write(panel.data_port, 2, 0xffff), (True, None))
        self.window(panel, (0, 3, 0, 1))
        for _ in range(8):
            self.assertIsNone(panel.write(panel.data_port, 2, 0xffff)[1])

    def test_wrong_port_and_width_do_not_create_pixels(self):
        panel = Indexed44(2, 2)
        self.window(panel)
        self.assertEqual(panel.write(panel.data_port + 2, 2, 0xffff), (False, None))
        self.assertEqual(panel.write(panel.data_port, 1, 0xff), (True, None))
        self.assertFalse(any(panel.rgb))
        panel.write(panel.command_port, 2, 0x202)
        self.assertIsNone(panel.write(panel.data_port, 2, 0xffff)[1])
        self.assertFalse(any(panel.rgb))

    def test_geometry_must_fit_packed_coordinates(self):
        with self.assertRaises(ValueError):
            Indexed44(257, 2)
