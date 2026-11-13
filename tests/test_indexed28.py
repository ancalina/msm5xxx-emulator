"""Synthetic GRAM transactions for the indexed RGB565 panel model."""
from __future__ import annotations

import unittest

from msm5xxx_emulator.devices.display.indexed28 import Indexed28


COMMAND = 0x28000000
DATA = 0x28000100


def write(panel, address, value, size=2):
    return panel.write(address, size, value)


def command(panel, value):
    return write(panel, COMMAND, value)


def data(panel, value):
    return write(panel, DATA, value)


def set_register(panel, register, value):
    assert command(panel, register)[0]
    assert data(panel, value)[0]


def set_window(panel, x0, x1, y0, y1):
    for register, value in zip((0x210, 0x211, 0x212, 0x213),
                               (x0, x1, y0, y1)):
        set_register(panel, register, value)


def set_cursor(panel, x, y):
    set_register(panel, 0x200, x)
    set_register(panel, 0x201, y)


def start_pixels(panel):
    assert command(panel, 0x202)[0]


class Indexed28Transactions(unittest.TestCase):
    def test_rgb565_full_window_publishes_only_after_all_pixels(self):
        panel = Indexed28(2, 2)
        set_window(panel, 0, 1, 0, 1)
        set_cursor(panel, 0, 0)
        start_pixels(panel)

        pixels = (0xF800, 0x07E0, 0x001F, 0xFFFF)
        published = []
        for pixel in pixels:
            ok, frame = data(panel, pixel)
            self.assertTrue(ok)
            published.append(frame)
        self.assertEqual(published[:3], [None, None, None])
        self.assertEqual(published[3], bytes((255, 0, 0, 0, 255, 0,
                                              0, 0, 255, 255, 255, 255)))

    def test_partial_rectangle_preserves_other_gram_pixels(self):
        panel = Indexed28(2, 2)
        set_window(panel, 0, 1, 0, 1)
        set_cursor(panel, 0, 0)
        start_pixels(panel)
        for pixel in (0xF800, 0x07E0, 0x001F, 0xFFFF):
            _, frame = data(panel, pixel)
        self.assertIsNotNone(frame)

        set_window(panel, 1, 1, 0, 0)
        set_cursor(panel, 1, 0)
        start_pixels(panel)
        ok, updated = data(panel, 0x001F)
        self.assertTrue(ok)
        self.assertEqual(updated, bytes((255, 0, 0, 0, 0, 255,
                                         0, 0, 255, 255, 255, 255)))

    def test_bounds_cursor_ports_and_access_widths_are_checked(self):
        panel = Indexed28(2, 2)
        baseline = bytes(panel.rgb)

        set_window(panel, 0, 2, 0, 1)
        set_cursor(panel, 0, 0)
        start_pixels(panel)
        self.assertEqual(data(panel, 0xF800), (True, None))
        self.assertEqual(bytes(panel.rgb), baseline)

        set_window(panel, 0, 1, 0, 1)
        set_cursor(panel, 2, 0)
        start_pixels(panel)
        self.assertEqual(data(panel, 0xF800), (True, None))
        self.assertEqual(bytes(panel.rgb), baseline)

        self.assertEqual(panel.write(0x28000004, 2, 0xF800), (False, None))
        self.assertEqual(panel.write(DATA, 1, 0xF800), (True, None))
        self.assertEqual(bytes(panel.rgb), baseline)

    def test_long_stream_wraps_and_publishes_complete_windows_only(self):
        panel = Indexed28(2, 2)
        set_window(panel, 0, 1, 0, 1)
        set_cursor(panel, 0, 0)
        start_pixels(panel)
        stream = (0xF800, 0x07E0, 0x001F, 0xFFFF,
                  0x0000, 0xFFFF, 0xF800, 0x07E0)
        frames = [data(panel, pixel)[1] for pixel in stream]
        self.assertEqual([index for index, frame in enumerate(frames)
                          if frame is not None], [3, 7])
        self.assertEqual(frames[7], bytes((0, 0, 0, 255, 255, 255,
                                           255, 0, 0, 0, 255, 0)))

    def test_pixel_command_and_register_writes_do_not_create_pixels(self):
        panel = Indexed28(2, 2)
        baseline = bytes(panel.rgb)
        self.assertEqual(command(panel, 0x202), (True, None))
        self.assertEqual(data(panel, 0xF800), (True, None))
        self.assertEqual(bytes(panel.rgb), baseline)

        set_window(panel, 0, 1, 0, 1)
        set_cursor(panel, 0, 0)
        self.assertEqual(bytes(panel.rgb), baseline)
        start_pixels(panel)
        self.assertEqual(bytes(panel.rgb), baseline)

    def test_panel_geometry_bounds_raise(self):
        for width, height in ((1, 2), (2, 1), (513, 2), (2, 513), (True, 2)):
            with self.subTest(width=width, height=height):
                with self.assertRaises(ValueError):
                    Indexed28(width, height)

    def test_shifted_ports_and_physical_origin_keep_visible_gram_coordinates(self):
        command_port, data_port = 0x20000000, 0x20080000
        panel = Indexed28(2, 2, command_port=command_port, data_port=data_port,
                          x_origin=1, y_origin=96)

        def put_command(value):
            return panel.write(command_port, 2, value)

        def put_data(value):
            return panel.write(data_port, 2, value)

        for register, value in zip((0x210, 0x211, 0x212, 0x213),
                                   (1, 2, 96, 97)):
            put_command(register)
            put_data(value)
        for register, value in ((0x200, 1), (0x201, 96)):
            put_command(register)
            put_data(value)
        put_command(0x202)
        published = [put_data(pixel)[1]
                     for pixel in (0xF800, 0x07E0, 0x001F, 0xFFFF)]
        expected = bytes((255, 0, 0, 0, 255, 0,
                          0, 0, 255, 255, 255, 255))
        self.assertEqual(published[-1], expected)

        for register, value in zip((0x210, 0x211, 0x212, 0x213),
                                   (0, 1, 96, 97)):
            put_command(register)
            put_data(value)
        put_command(0x200)
        put_data(1)
        put_command(0x201)
        put_data(96)
        put_command(0x202)
        self.assertEqual(put_data(0), (True, None))
        self.assertEqual(bytes(panel.rgb), expected)

    def test_shifted_panel_parameters_must_fit_address_space(self):
        for options in (
            {'command_port': 0x20000001},
            {'command_port': 0x20000000, 'data_port': 0x20000001},
            {'command_port': 0x20000000, 'data_port': 0x20000000},
            {'command_port': 0x20000008, 'data_port': 0x20000004,
             'data_aperture': 32},
            {'command_port': 0x100000000},
            {'data_port': 0xfffffffe, 'data_aperture': 32},
            {'data_aperture': 4},
            {'data_aperture': False},
            {'x_origin': 0xffff - 1},
            {'y_origin': 0xffff - 1},
            {'x_origin': -1},
            {'y_origin': True},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                Indexed28(2, 2, **options)

    def test_word_fifo_aliases_split_little_endian_pixels_in_order(self):
        command_port, data_port = 0x20000000, 0x20080000
        panel = Indexed28(2, 2, command_port=command_port, data_port=data_port,
                          data_aperture=32, y_origin=96)

        def put_command(value):
            return panel.write(command_port, 2, value)

        def put_data(offset, value, size=2):
            return panel.write(data_port + offset, size, value)

        for register, value in zip((0x210, 0x211, 0x212, 0x213),
                                   (0, 1, 96, 97)):
            put_command(register)
            put_data(0, value)
        for register, value in ((0x200, 0), (0x201, 96)):
            put_command(register)
            put_data(0, value)
        put_command(0x202)

        self.assertEqual(put_data(4, 0x07E0F800, 4), (True, None))
        self.assertEqual(bytes(panel.rgb[:6]), bytes((255, 0, 0, 0, 255, 0)))
        self.assertEqual(put_data(30, 0xFFFF001F, 4), (False, None))
        self.assertEqual(put_data(32, 0x001F), (False, None))
        self.assertEqual(panel.written, 2)
        self.assertEqual(bytes(panel.rgb[6:]), bytes(6))
        published = put_data(28, 0xFFFF001F, 4)
        self.assertEqual(published, (True, bytes((255, 0, 0, 0, 255, 0,
                                                 0, 0, 255, 255, 255, 255))))

    def test_default_data_aperture_does_not_accept_word_pixel_writes(self):
        panel = Indexed28(2, 2)
        set_window(panel, 0, 1, 0, 1)
        set_cursor(panel, 0, 0)
        start_pixels(panel)
        baseline = bytes(panel.rgb)

        self.assertEqual(panel.write(DATA, 4, 0x07E0F800), (True, None))
        self.assertEqual(bytes(panel.rgb), baseline)
        self.assertEqual(panel.written, 0)


if __name__ == '__main__':
    unittest.main()
