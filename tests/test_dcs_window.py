"""Synthetic source evidence and runtime behavior for DCS GRAM windows."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.display.source_writers import machine_plan
from msm5xxx_emulator.detection.devices.display.dcs_window_writer import find_dcs_window
from msm5xxx_emulator.detection.registry import device_domain
from msm5xxx_emulator.devices.display.dcs_window import DcsWindow
from msm5xxx_emulator.devices.display.source_plan import apply_source_plan
from test_external_devices import _thumb_bl, ldr_literal, put16, put32


def _image(*, width=4, height=3, x0=2, y0=4, x1=None, y1=None,
           clear_width=None, clear_height=None, helper_port=0x18040000,
           clear_port=None, first_command=0x2A, second_command=0x2B,
           fill=0xFFFF, ramwr=True, include_caller=True):
    """Build tiny linked Thumb routines with no firmware-derived bytes."""
    image = bytearray(0x10000)
    caller, owner, helper = 0x80, 0x100, 0x300
    helper_pool, owner_pool = 0x500, 0x420
    x1 = x0 + width - 1 if x1 is None else x1
    y1 = y0 + height - 1 if y1 is None else y1
    clear_width = width if clear_width is None else clear_width
    clear_height = height if clear_height is None else clear_height
    clear_port = helper_port if clear_port is None else clear_port

    # Called four-argument setter: 2A + four parameter halfwords, then
    # 2B + four parameter halfwords. High bytes are zero for these test values.
    pc = helper
    put16(image, pc, 0xB5F0)
    pc += 2
    put16(image, pc, ldr_literal(4, pc, helper_pool),
          ldr_literal(5, pc + 2, helper_pool + 4),
          0x2600, 0x272A if first_command == 0x2A else 0x2700 | first_command,
          0x8027, 0x802E, 0x8028, 0x802E, 0x8029,
          0x272B if second_command == 0x2B else 0x2700 | second_command,
          0x8027, 0x802E, 0x802A, 0x802E, 0x802B,
          0xBDF0)
    put32(image, helper_pool, 0x18000000, helper_port)

    # Clear routine passes the window coordinates, emits RAMWR, then performs
    # the shared counted halfword fill loop used by the source proof.
    pc = owner
    put16(image, pc, 0xB510,
          0x2000 | x0, 0x2100 | x1, 0x2200 | y0, 0x2300 | y1)
    call_hi, call_lo = _thumb_bl(pc + 10, helper)
    put16(image, pc + 10, call_hi, call_lo)
    pc += 14
    if ramwr:
        put16(image, pc, ldr_literal(4, pc, owner_pool), 0x272C, 0x8027)
        pc += 6
    else:
        put16(image, pc, 0x46C0, 0x46C0, 0x46C0)
        pc += 6
    put16(image, pc,
          ldr_literal(2, pc, owner_pool + 4),
          0x2100 | clear_height,
          ldr_literal(4, pc + 4, owner_pool + 8),
          0xE004, 0x2000 | clear_width, 0xE000, 0x8014,
          0x3801, 0xD2FC, 0x3901, 0xD2F8, 0xBD10)
    put32(image, owner_pool, 0x18000000, clear_port, fill)

    if include_caller:
        hi, lo = _thumb_bl(caller + 2, owner)
        put16(image, caller, 0xB500, hi, lo, 0xBD00)
    return bytes(image)


def _command(model, command, *parameters):
    assert model.write(0x02000000, 2, command)[0]
    for parameter in parameters:
        assert model.write(0x02000002, 2, parameter)[0]


class DcsWindowEvidenceTests(unittest.TestCase):
    def test_linked_window_selects_dcs_profile_and_fifo_offset(self):
        for port in (0x18040000, 0x18080000):
            with self.subTest(port=hex(port)):
                image = _image(helper_port=port)
                profile = find_dcs_window(image)
                self.assertIsNotNone(profile)
                self.assertEqual((profile['width'], profile['height'],
                                  profile['x_origin'], profile['y_origin'],
                                  profile['data_port'], profile['protocol']),
                                 (4, 3, 2, 4, port, 'dcs'))

                bus = device_domain('external_bus.rules')
                projection = device_domain('external_bus.projection')
                detected, _ = bus.detect_external_bus(image)
                resolution, reason = projection.external_bus_plan(
                    detected, image, None, None)
                self.assertIsNone(reason)
                properties = dict(resolution.plan.properties)
                self.assertTrue(properties['external-lcd-18-dcs'])
                self.assertEqual(properties['external-lcd-18-data-offset'],
                                 port - 0x18000000)

                cfg = SimpleNamespace(image_kind='firmware', load_address=0,
                    image_offset=0, entry=0, missing_overlays=[],
                    ram_bootstrap_profile=None, display_geometry_source='auto-default',
                    width=176, height=220)
                plan = machine_plan(image, image, cfg)
                parameters = dict(plan.capabilities[0].parameters)
                self.assertEqual(parameters['dcs_window'], (4, 3, 2, 4))
                decoder = SimpleNamespace()
                apply_source_plan(decoder, plan)
                self.assertIsInstance(decoder._lcd_b0_source_page, DcsWindow)
                self.assertEqual((decoder._lcd_b0_source_page.width,
                                  decoder._lcd_b0_source_page.height,
                                  decoder._lcd_b0_source_page.x_origin,
                                  decoder._lcd_b0_source_page.y_origin), (4, 3, 2, 4))

    def test_mismatched_or_incomplete_source_evidence_is_rejected(self):
        mutations = (
            _image(first_command=0x2B),
            _image(second_command=0x2A),
            _image(x1=4),
            _image(y1=5),
            _image(helper_port=0x18080000, clear_port=0x18040000),
            _image(fill=0xFFFE),
            _image(x0=2, y0=4, x1=1),
            _image(ramwr=False),
            _image(include_caller=False),
        )
        for image in mutations:
            with self.subTest(prefix=image[0x300:0x310].hex()):
                self.assertIsNone(find_dcs_window(image))

        image = _image(helper_port=0x18040000)
        detected, _ = device_domain('external_bus.rules').detect_external_bus(image)
        projection = device_domain('external_bus.projection')
        changed = dict(detected['machine_properties'])
        changed['external-lcd-18-data-offset'] = 0x80000
        detected = {**detected, 'machine_properties': changed}
        _, reason = projection.external_bus_plan(detected, image, None, None)
        self.assertEqual(reason, 'window-data-port-mismatch')

    def test_wrong_command_store_width_is_rejected(self):
        image = bytearray(_image())
        # The helper's first command store uses STRH r7,[r4].
        put16(image, 0x300 + 10, 0x7027)
        self.assertIsNone(find_dcs_window(bytes(image)))


class DcsWindowRuntimeTests(unittest.TestCase):
    def test_partial_gram_waits_for_display_on_and_full_rgb565_scanout(self):
        model = DcsWindow(4, 3, 2, 4)
        _command(model, 0x2A, 0, 3, 0, 3)
        _command(model, 0x2B, 0, 5, 0, 5)
        _command(model, 0x2C)
        self.assertIsNone(model.write(0x02000002, 2, 0xF800)[1])
        self.assertIsNone(model.write(0x02000000, 2, 0x29)[1])

        _command(model, 0x2A, 0, 2, 0, 5)
        _command(model, 0x2B, 0, 4, 0, 6)
        _command(model, 0x2C)
        colors = (0xF800, 0x07E0, 0x001F, 0xFFFF,
                  0x0000, 0x8410, 0x001F, 0x07E0,
                  0xF800, 0x8410, 0xFFFF, 0x0000)
        frames = []
        for color in colors:
            consumed, frame = model.write(0x02000002, 2, color)
            self.assertTrue(consumed)
            if frame is not None:
                frames.append(frame)
        self.assertEqual(len(frames), 1)
        frame = frames[0]
        self.assertEqual(len(frame), 4 * 3 * 3)
        pixels = [frame[i:i + 3] for i in range(0, len(frame), 3)]
        self.assertEqual(pixels[0], bytes((255, 0, 0)))
        self.assertEqual(pixels[1], bytes((0, 255, 0)))
        self.assertEqual(pixels[2], bytes((0, 0, 255)))
        self.assertEqual(pixels[5], bytes((132, 130, 132)))
        self.assertEqual(pixels[11], bytes((0, 0, 0)))

        _command(model, 0x28)
        _command(model, 0x2A, 0, 3, 0, 3)
        _command(model, 0x2B, 0, 5, 0, 5)
        _command(model, 0x2C)
        self.assertIsNone(model.write(0x02000002, 2, 0x07E0)[1])
        consumed, frame = model.write(0x02000000, 2, 0x29)
        self.assertTrue(consumed)
        self.assertEqual(frame[(1 * 4 + 1) * 3:(1 * 4 + 1) * 3 + 3],
                         bytes((0, 255, 0)))

    def test_invalid_bounds_and_data_widths_do_not_publish_frames(self):
        model = DcsWindow(4, 3, 2, 4)
        _command(model, 0x2A, 0, 2, 0, 6)
        _command(model, 0x2B, 0, 4, 0, 6)
        _command(model, 0x2C)
        self.assertIsNone(model.write(0x02000002, 2, 0xFFFF)[1])
        self.assertIsNone(model.write(0x02000000, 2, 0x29)[1])

        _command(model, 0x2A, 0, 2, 0, 5)
        _command(model, 0x2B, 0, 4, 0, 6)
        _command(model, 0x2C)
        self.assertIsNone(model.write(0x02000002, 1, 0xFFFF)[1])
        self.assertIsNone(model.write(0x02000000, 2, 0x29)[1])


if __name__ == '__main__':
    unittest.main()
