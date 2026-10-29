"""Page transport source ownership, complete scanout and icon-plane isolation."""
import unittest

import test_lcd_geometry as display_helpers
from test_mono_page_detection import fixture


def emulator(bound=True):
    result = display_helpers.LCDGeometryTests()._routing_emulator(width=128, height=160)
    result.image = bytes(fixture()[0]) if bound else bytes(0x20000)
    result.frame_sequence = 0
    result.config.display_geometry_source = "auto-default"
    return result


def write(display, address, value, size=1):
    display._lcd_route_write(None, 0, address, size, value, None)


def row(display, page, values, column=4):
    for command in (0xb0 | page, 0x10 | column >> 4, column & 15):
        write(display, 0x02000001, command)
    for value in values:
        write(display, 0x02000003, value)


def frame(display, byte=0x55):
    for page in range(8):
        row(display, page, [byte] * 128)
    write(display, 0x02000001, 0xb8)


class OddPageRuntimeTests(unittest.TestCase):
    def test_full_raster_source_geometry_and_bias(self):
        display = emulator()
        for page in range(7):
            row(display, page, [0x55] * 128)
        self.assertEqual(display.frame_sequence, 0)
        row(display, 7, [0x55] * 128)
        write(display, 0x02000001, 0xb8)
        width, height, pixels = display.display_snapshot()
        self.assertEqual((width, height), (128, 64))
        self.assertGreater(display.frame_sequence, 0)
        for y in range(64):
            shade = 255 if y % 2 == 0 else 0
            self.assertEqual(pixels[y * width * 3:(y + 1) * width * 3], bytes([shade]) * (width * 3))

    def test_icon_and_init_arguments_never_change_main_height_or_pixels(self):
        display = emulator()
        write(display, 0x02000001, 0xf0)
        write(display, 0x02000003, 2)
        self.assertEqual(display.frame_sequence, 0)
        frame(display)
        before = display.display_snapshot()
        sequence = display.frame_sequence
        for command in (0x10, 4):
            write(display, 0x02000001, command)
        for value in range(132):
            write(display, 0x02000003, value)
        self.assertEqual(display.display_snapshot(), before)
        self.assertEqual(display.frame_sequence, sequence)
        self.assertEqual(display.odd_page_snapshot()['icon_words'], 132)
        self.assertEqual(display.odd_page_snapshot()['icon_bytes'], bytes(range(132)))

    def test_partial_update_high_low_columns_preserves_other_pixels(self):
        display = emulator()
        frame(display, byte=0)
        row(display, 2, [0xff], column=0x14)
        write(display, 0x02000001, 0xb8)
        width, height, pixels = display.display_snapshot()
        self.assertEqual((width, height), (128, 64))
        for y in range(16, 24):
            start = (y * width + 16) * 3
            self.assertEqual(pixels[start:start + 3], b'\xff' * 3)
            self.assertEqual(pixels[start - 3:start], b'\0' * 3)
            self.assertEqual(pixels[start + 3:start + 6], b'\0' * 3)

    def test_unbound_width_and_foreign_owner_fallback(self):
        display = emulator(False)
        frame(display)
        self.assertEqual(display.frame_sequence, 0)
        self.assertFalse(display.odd_page_snapshot()['source_bound'])
        for address, size in ((0x02000001, 2), (0x02000003, 2), (0x02000000, 1)):
            display = emulator()
            frame(display)
            sequence, pixels = display.frame_sequence, display.display_snapshot()
            write(display, address, 0, size)
            self.assertTrue(display.odd_page_snapshot()['rejected'])
            frame(display, 0xff)
            self.assertEqual(display.display_snapshot(), pixels)
            self.assertEqual(display.frame_sequence, sequence)

    def test_partial_nonsequential_scan_does_not_qualify(self):
        display = emulator()
        for page in (0, 2, 3, 4, 5, 6, 7):
            row(display, page, [0xff] * 128)
        write(display, 0x02000001, 0xb8)
        self.assertEqual(display.frame_sequence, 0)
        self.assertFalse(display._lcd_page_qualified)

    def test_manual_geometry_is_not_replaced(self):
        display = emulator()
        display.config.display_geometry_source = 'external-config'
        frame(display)
        self.assertEqual((display.config.width, display.config.height), (128, 160))
        self.assertEqual(display.frame_sequence, 0)

    def test_icon_interruption_does_not_count_a_phantom_main_page(self):
        display = emulator()
        for _ in range(2):
            for page in range(7):
                row(display, page, [0xff] * 128)
            write(display, 0x02000001, 0xb8)
            for command in (0x10, 4):
                write(display, 0x02000001, command)
            for value in range(132):
                write(display, 0x02000003, value)
            self.assertFalse(display._lcd_page_qualified)
            self.assertEqual(display.frame_sequence, 0)
        frame(display)
        self.assertGreater(display.frame_sequence, 0)

    def test_bad_argument_and_overflow_withdraw_raster_ownership(self):
        for kind in ('argument', 'main', 'icon'):
            display = emulator()
            frame(display)
            before, sequence = display.display_snapshot(), display.frame_sequence
            if kind == 'argument':
                write(display, 0x02000001, 0xf0)
                write(display, 0x02000003, 3)
            elif kind == 'main':
                row(display, 0, [0] * 129)
            else:
                for command in (0x10, 4):
                    write(display, 0x02000001, command)
                for value in range(133):
                    write(display, 0x02000003, value)
            self.assertTrue(display.odd_page_snapshot()['rejected'], kind)
            self.assertFalse(display._lcd_page_qualified, kind)
            self.assertEqual(display.display_snapshot(), before)
            self.assertEqual(display.frame_sequence, sequence)

    def test_unqualified_foreign_row_cannot_complete_odd_scan(self):
        display = emulator()
        for command in (0xb0, 0x10, 0):
            write(display, 0x02000000, command)
        for _ in range(128):
            write(display, 0x02000004, 0xff)
        for page in range(1, 8):
            row(display, page, [0x55] * 128)
        write(display, 0x02000001, 0xb8)
        self.assertFalse(display._lcd_page_qualified)
        self.assertEqual(display.frame_sequence, 0)
        frame(display)
        self.assertGreater(display.frame_sequence, 0)

    def test_qualified_foreign_page_owner_is_not_revoked(self):
        display = emulator()
        for page in range(2):
            for command in (0xb0 | page, 0x10, 0):
                write(display, 0x02000000, command)
            for _ in range(128):
                write(display, 0x02000004, 0x33)
        write(display, 0x02000000, 0xb2)
        self.assertTrue(display._lcd_page_qualified)
        before = bytes(display._lcd_page_ram)
        write(display, 0x02000001, 0xb0)
        self.assertTrue(display._lcd_page_qualified)
        self.assertEqual(display._lcd_page_port, 0x02000000)
        self.assertEqual(bytes(display._lcd_page_ram), before)
        self.assertTrue(display.odd_page_snapshot()['blocked'])

    def test_rejected_odd_proof_and_ram_do_not_leak_into_legacy(self):
        display = emulator()
        frame(display)
        row(display, 2, [0] * 129)
        self.assertFalse(display._lcd_page_qualified)
        self.assertEqual(display._lcd_page_candidate_rows, 0)
        self.assertEqual(display._lcd_page_last_finished, -1)
        self.assertFalse(any(display._lcd_page_ram))
        for command in (0xb0, 0x10, 0):
            write(display, 0x02000000, command)
        for _ in range(128):
            write(display, 0x02000004, 0x22)
        write(display, 0x02000000, 0xb1)
        self.assertFalse(display._lcd_page_qualified)
        self.assertEqual(display._lcd_page_candidate_rows, 1)
