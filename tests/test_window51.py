"""Synthetic evidence and RGB565 behavior for the windowed pixel FIFO."""
from __future__ import annotations

import struct
import copy
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.display.source_writers import machine_plan
from msm5xxx_emulator.detection.devices.display.window51_writer import find_window51
from msm5xxx_emulator.devices.display.source_plan import apply_source_plan
from msm5xxx_emulator.devices.display.window51 import Window51
from msm5xxx_emulator.detection.registry import device_domain
from test_external_devices import _thumb_bl, ldr_literal, put16, put32


def _image(*, width=4, height=3, x_origin=0, y_origin=0,
           window_width=None, window_height=None, port=0x18040000,
           fill=0xFFFF, computed_fill=False, include_caller=True, row_end=None):
    image = bytearray(0x10000)
    owner, caller, pool = 0x100, 0x80, 0x400
    put16(image, owner, 0xB510)
    window_width = width if window_width is None else window_width
    window_height = height if window_height is None else window_height
    commands = (0x42, y_origin, y_origin + window_height - 1,
                0x43, x_origin, x_origin + window_width - 1,
                0x60, 0, 0x61, 0, 0x51)
    pc = owner + 2
    for command in commands:
        put16(image, pc, ldr_literal(4, pc, pool), 0x2000 | command,
              0x8020)
        pc += 6
    setup = [0x2100 | height]
    if computed_fill:
        setup.extend((0x2401, 0x0424, 0x3C01))
        data_load = pc + len(setup) * 2
        setup.extend((ldr_literal(2, data_load, pool + 4), 0xE004,
                      0x2000 | width, 0xE000, 0x8014, 0x3801, 0xD2FC,
                      0x3901, 0xD2F8))
    else:
        setup.extend((ldr_literal(2, pc + 2, pool + 4),
                      ldr_literal(4, pc + 4, pool + 8), 0xE004,
                      0x2000 | width, 0xE000, 0x8014, 0x3801, 0xD2FC,
                      0x3901, 0xD2F8))
    put16(image, pc, *setup)
    pixel_load = pc + 2
    if row_end is not None:
        if computed_fill:
            raise ValueError('row_end mutation only applies to literal-fill loop')
        put16(image, pc + 18, row_end)
    pc += len(setup) * 2
    put16(image, pc, 0xBD10)
    put32(image, pool, 0x18000000, port, *((fill,) if not computed_fill else ()))
    if include_caller:
        hi, lo = _thumb_bl(caller + 2, owner)
        put16(image, caller, 0xB500, hi, lo, 0xBD00)
    return bytes(image), pixel_load


def _command(model, command, *parameters):
    assert model.write(0x02000000, 2, command)[0]
    for parameter in parameters:
        assert model.write(0x02000000, 2, parameter)[0]


class Window51EvidenceTests(unittest.TestCase):
    def test_conflicting_called_fifo_drivers_do_not_select_a_port(self):
        image, _ = _image(port=0x18040000)
        other, _ = _image(port=0x18080000)
        combined = bytearray(image)
        combined[0x1080:0x1500] = other[0x80:0x500]
        self.assertIsNone(find_window51(bytes(combined)))

    def test_each_data_literal_selects_its_exact_native_port(self):
        bus = device_domain('external_bus.rules')
        projection = device_domain('external_bus.projection')
        for port in (0x18040000, 0x18080000):
            with self.subTest(port=hex(port)):
                image, _ = _image(port=port)
                self.assertEqual(find_window51(image)['data_port'], port)
                profile, _ = bus.detect_external_bus(image)
                resolution, reason = projection.external_bus_plan(profile, image, None, None)
                self.assertIsNone(reason)
                self.assertIn(('external-lcd-18-data-offset', port - 0x18000000), resolution.plan.properties)
                self.assertIn((port, port + 2), {(claim.start, claim.end) for claim in resolution.plan.claims})
                changed = copy.deepcopy(profile)
                other = 0x18080000 if port == 0x18040000 else 0x18040000
                changed['machine_properties']['external-lcd-18-data-offset'] = other - 0x18000000
                changed['capabilities']['lcd_18_window']['parameters']['data_port'] = other
                _, reason = projection.external_bus_plan(changed, image, None, None)
                self.assertEqual(reason, 'window-data-port-mismatch')

    def test_backed_data_aperture_does_not_get_a_conflicting_fifo(self):
        image, _ = _image(port=0x18080000)
        profile, _ = device_domain('external_bus.rules').detect_external_bus(
            image, ram_base=0x18080000, ram_size=0x1000)
        self.assertFalse(profile['machine_properties']['external-lcd-18-window'])
        self.assertNotIn('external-lcd-18-data-offset', profile['machine_properties'])

    def test_requires_matching_called_window_and_fifo_clear(self):
        image, _ = _image()
        profile = find_window51(image)
        self.assertEqual((profile["width"], profile["height"]), (4, 3))
        self.assertEqual((profile["x_origin"], profile["y_origin"]), (0, 0))
        self.assertTrue(profile["evidence"])

        offset_image, _ = _image(x_origin=2, y_origin=4, port=0x18080000,
                                 computed_fill=True)
        offset_profile = find_window51(offset_image)
        self.assertIsNotNone(offset_profile)
        self.assertEqual((offset_profile["width"], offset_profile["height"],
                          offset_profile["x_origin"], offset_profile["y_origin"],
                          offset_profile["data_port"]),
                         (4, 3, 2, 4, 0x18080000))

        cfg = SimpleNamespace(image_kind='firmware', load_address=0,
                              image_offset=0, entry=0, missing_overlays=[],
                              ram_bootstrap_profile=None,
                              display_geometry_source='auto-default',
                              width=176, height=220)
        plan = machine_plan(image, image, cfg)
        self.assertEqual(dict(plan.capabilities[0].parameters)['window51'], (4, 3, 0, 0))
        decoder = SimpleNamespace()
        apply_source_plan(decoder, plan)
        self.assertIsInstance(decoder._lcd_b0_source_page, Window51)
        self.assertEqual((decoder._lcd_b0_source_page.width,
                          decoder._lcd_b0_source_page.height,
                          decoder._lcd_b0_source_page.x_origin,
                          decoder._lcd_b0_source_page.y_origin), (4, 3, 0, 0))
        self.assertFalse(machine_plan(image, b'X' + image[1:], cfg).capabilities)
        offset_plan = machine_plan(offset_image, offset_image, cfg)
        offset_parameters = dict(offset_plan.capabilities[0].parameters)
        self.assertEqual(offset_parameters['window51'], (4, 3, 2, 4))
        offset_decoder = SimpleNamespace()
        apply_source_plan(offset_decoder, offset_plan)
        offset_source = offset_decoder._lcd_b0_source_page
        self.assertEqual((offset_source.width, offset_source.height,
                          offset_source.x_origin, offset_source.y_origin),
                         (4, 3, 2, 4))

        mutations = (
            _image(height=4, window_height=3)[0],
            _image(width=5, window_width=4)[0],
            _image(window_height=4)[0],
            _image(window_width=5)[0],
            _image(x_origin=2, window_width=3)[0],
            _image(y_origin=4, window_height=2)[0],
            _image(port=0x18040002)[0],
            _image(fill=0xFFFE)[0],
            _image(include_caller=False)[0],
            _image(row_end=0xD2FB)[0],
        )
        for mutated in mutations:
            with self.subTest(mutation=mutated[0x400:0x40c].hex()):
                self.assertIsNone(find_window51(mutated))

        wrong_command_width = bytearray(image)
        # The final command access is byte-wide, while the FIFO clear is valid.
        command_store = 0x100 + 2 + 10 * 6 + 4
        put16(wrong_command_width, command_store, 0x7000)
        self.assertIsNone(find_window51(bytes(wrong_command_width)))


class Window51RuntimeTests(unittest.TestCase):
    def test_rgb565_pixels_are_published_only_after_the_window_completes(self):
        model = Window51(4, 3, 2, 4)
        _command(model, 0x43, 2, 5)
        _command(model, 0x42, 4, 6)
        _command(model, 0x51)
        colors = (0xF800, 0x07E0, 0x001F, 0xFFFF, 0x0000, 0x8410,
                  0x001F, 0x07E0, 0xF800, 0x8410, 0xFFFF, 0x0000)
        frames = []
        for color in colors:
            consumed, frame = model.write(0x02000002, 2, color)
            self.assertTrue(consumed)
            if frame is not None:
                frames.append(frame)
        self.assertEqual(len(frames), 1)
        self.assertEqual(len(frames[0]), 4 * 3 * 3)
        pixels = [frames[0][(y * 4 + x) * 3:(y * 4 + x) * 3 + 3]
                  for y in range(3) for x in range(4)]
        self.assertEqual(pixels[0], bytes((255, 0, 0)))
        self.assertEqual(pixels[1], bytes((0, 255, 0)))
        self.assertEqual(pixels[2], bytes((0, 0, 255)))
        self.assertEqual(pixels[3], bytes((255, 255, 255)))
        self.assertEqual(pixels[4], bytes((0, 0, 0)))
        self.assertEqual(pixels[5], bytes((132, 130, 132)))
        self.assertEqual(pixels[6], bytes((0, 0, 255)))
        self.assertEqual(pixels[11], bytes((0, 0, 0)))

    def test_partial_rectangles_reset_cursor_and_invalid_windows_are_ignored(self):
        model = Window51(4, 3, 2, 4)
        _command(model, 0x43, 2, 5)
        _command(model, 0x42, 4, 6)
        _command(model, 0x51)
        model.write(0x02000002, 2, 0xFFFF)
        _command(model, 0x43, 4, 5)
        _command(model, 0x42, 5, 5)
        _command(model, 0x51)
        consumed, frame = model.write(0x02000002, 2, 0xF800)
        self.assertTrue(consumed)
        self.assertIsNone(frame)
        consumed, frame = model.write(0x02000002, 2, 0x07E0)
        self.assertTrue(consumed)
        self.assertEqual(frame, bytes(model.rgb))
        offset = (1 * 4 + 2) * 3
        self.assertEqual(frame[offset:offset + 3], bytes((255, 0, 0)))
        self.assertEqual(frame[offset + 3:offset + 6], bytes((0, 255, 0)))

        _command(model, 0x43, 2, 9)
        _command(model, 0x42, 4, 4)
        _command(model, 0x51)
        self.assertIsNone(model.window)
        consumed, frame = model.write(0x02000002, 2, 0xFFFF)
        self.assertTrue(consumed)
        self.assertIsNone(frame)
        consumed, frame = model.write(0x02000002, 1, 0xFFFF)
        self.assertTrue(consumed)
        self.assertIsNone(frame)
        self.assertFalse(model.write(0x02000004, 2, 0xFFFF)[0])


if __name__ == '__main__':
    unittest.main()
