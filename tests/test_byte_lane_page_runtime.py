"""Source-owned BYTE lanes, complete scan proof, and padded logical viewport."""
import unittest
from unittest.mock import patch

import test_lcd_geometry as display_helpers


PROFILE = dict(width=120, height=80, column_capacity=128, bits_per_pixel=1,
               command_port=0x02000000, data_port=0x02000002, access_width=1,
               main_pages=list(range(10)), icon_page=None, column_bias=0,
               init_data_argument=None, init_row_bytes=128, required_pages=10,
               init_commands=[0xE2, 0xAB, 0x67, 0xAE, 0xA0, 0xC8, 0x24, 0x81,
                              0x18, 0x2F, 0x4C, 5, 0xAF, 0xAE, 0x56, 0x24, 0xAF])


def write(display, value, *, data=False, size=1, address=None):
    port = 0x02000002 if data else 0x02000000
    display._lcd_route_write(None, 0, port if address is None else address,
                             size, value, None)


def row(display, page, values, column=0):
    for command in (0xB0 | page, 0x10 | (column >> 4), column & 15):
        write(display, command)
    for value in values:
        write(display, value, data=True)


def snapshot(display):
    # Match the shared Transport replay flush before GUI readback.
    display._lcd_page_flush_current()
    return display.display_snapshot()


def init(display):
    for command in PROFILE['init_commands']:
        write(display, command)


def full(display):
    init(display)
    for page in range(10):
        row(display, page, [0x88 >> (x & 3) for x in range(128)])


class ByteLanePageRuntimeTests(unittest.TestCase):
    def setUp(self):
        patcher = patch('msm5xxx_emulator.detection.byte_lane_page.find_byte_lane_page_profile',
                        return_value=(PROFILE, 'accepted-test-source-contract'))
        patcher.start()
        self.addCleanup(patcher.stop)

    def display(self):
        display = display_helpers.LCDGeometryTests()._routing_emulator(width=176, height=220)
        display.image = bytes(0x2000)
        display.frame_sequence = 0
        display.config.display_geometry_source = 'auto-default'
        return display

    def test_complete_ten_pages_and_padding_render_exact_logical_pixels(self):
        display = self.display()
        init(display)
        for page in range(9):
            row(display, page, [0x88 >> (x & 3) for x in range(128)])
        self.assertFalse(display._lcd_page_qualified)
        self.assertEqual(display.frame_sequence, 0)
        row(display, 9, [0x88 >> (x & 3) for x in range(128)])
        width, height, pixels = snapshot(display)
        self.assertEqual((width, height), (120, 80))
        expected = bytes(shade for y in range(80) for x in range(120)
                         for shade in [255 * ((0x88 >> (x & 3) >> (y & 7)) & 1)] * 3)
        self.assertEqual(pixels, expected)
        self.assertGreater(display.frame_sequence, 0)
        self.assertEqual(display.odd_page_snapshot()['main_raster'], (120, 80))
        self.assertEqual(display.odd_page_snapshot()['icon_words'], 0)

    def test_missing_source_image_keeps_native_fallback(self):
        display = self.display()
        del display.image
        with patch('msm5xxx_emulator.detection.byte_lane_page.find_byte_lane_page_profile',
                   return_value=(None, 'no-source')) as finder:
            self.assertFalse(display._lcd_odd_page_write(0x02000000, 1, 0xE2))
            finder.assert_called_once_with(b'')
        self.assertFalse(display._lcd_page_qualified)

    def test_partial_last_column_last_page_preserves_other_pixels(self):
        display = self.display()
        full(display)
        before = snapshot(display)[2]
        row(display, 9, [0xFF], column=119)
        after = snapshot(display)[2]
        expected = bytearray(before)
        for y in range(72, 80):
            at = (y * 120 + 119) * 3
            expected[at:at + 3] = b'\xff' * 3
        self.assertEqual(after, bytes(expected))

    def test_missing_or_wrong_init_and_word_bus_do_not_acquire(self):
        for mode in ('missing', 'wrong', 'word'):
            with self.subTest(mode=mode):
                display = self.display()
                if mode == 'wrong':
                    write(display, PROFILE['init_commands'][0])
                    write(display, PROFILE['init_commands'][1] ^ 1)
                elif mode == 'word':
                    for command in PROFILE['init_commands']:
                        write(display, command, size=2)
                for page in range(10):
                    row(display, page, [0x55] * 128)
                snapshot(display)
                self.assertFalse(display._lcd_page_qualified)
                self.assertEqual(display.frame_sequence, 0)

    def test_hole_or_short_terminal_row_cannot_prove_complete_scan(self):
        for pages, final_count in (([0, 1, 2, 3, 5, 6, 7, 8, 9], 128),
                                   (list(range(10)), 127)):
            display = self.display()
            init(display)
            for page in pages:
                row(display, page, [0x55] * (final_count if page == 9 else 128))
            snapshot(display)
            self.assertFalse(display._lcd_page_qualified)
            self.assertEqual(display.frame_sequence, 0)

    def test_qualified_legacy_data_lane_keeps_ownership(self):
        display = self.display()
        for page in range(2):
            for command in (0xB0 | page, 0x10, 0):
                write(display, command)
            for _ in range(128):
                write(display, 0x33, address=0x02000004)
        write(display, 0xB2)
        self.assertTrue(display._lcd_page_qualified)
        before = bytes(display._lcd_page_ram)
        init(display)
        self.assertTrue(display.odd_page_snapshot()['blocked'])
        self.assertTrue(display._lcd_page_qualified)
        self.assertEqual(bytes(display._lcd_page_ram), before)

    def test_overflow_and_foreign_aperture_withdraw_without_new_frame(self):
        for kind in ('overflow', 'foreign'):
            display = self.display()
            full(display)
            before = snapshot(display)
            sequence = display.frame_sequence
            if kind == 'overflow':
                row(display, 0, [0] * 129)
            else:
                write(display, 0, address=0x02000004)
            self.assertTrue(display.odd_page_snapshot()['rejected'])
            self.assertFalse(display._lcd_page_qualified)
            self.assertEqual(snapshot(display), before)
            self.assertEqual(display.frame_sequence, sequence)


if __name__ == '__main__':
    unittest.main()


PAIRED_PROFILE = dict(
    PROFILE, class_name='descending-paired-byte-page128-v1',
    width=128, height=128, column_capacity=256, bits_per_pixel=2,
    main_pages=list(range(15, -1, -1)), required_pages=16,
    init_row_bytes=256, init_commands=[0xe2, 0xae, 0xaf],
    page_step=-1, logical_y_reverse=True, logical_plane_weights=[2, 1],
    source_intervals=[[0x10, 0x14], [0x100, 0x104]],
    ram_intervals=[[0x1001000, 0x1002000]],
)


class DescendingPairedPageRuntimeTests(unittest.TestCase):
    def setUp(self):
        patcher = patch('msm5xxx_emulator.detection.byte_lane_page.find_byte_lane_page_profile',
                        return_value=(PAIRED_PROFILE, 'accepted-test-paired-source'))
        patcher.start()
        self.addCleanup(patcher.stop)

    def display(self):
        display = display_helpers.LCDGeometryTests()._routing_emulator(width=176, height=220)
        display.image = bytes(0x2000)
        display.frame_sequence = 0
        display.config.display_geometry_source = 'auto-default'
        display.config.ram_base, display.config.ram_size = 0x1000000, 0x800000
        return display

    def initialize(self, display):
        for command in PAIRED_PROFILE['init_commands']:
            write(display, command)

    def full(self, display, value=255):
        self.initialize(display)
        for page in range(15, -1, -1):
            row(display, page, [value] * 256)

    def test_complete_descending_scan_uses_source_logical_coordinates_and_two_planes(self):
        display = self.display()
        self.initialize(display)
        values = lambda page: [v for x in range(128) for v in
                               ((page * 17 + x) & 255, (255 - page * 11 - x) & 255)]
        for page in range(15, 0, -1):
            row(display, page, values(page))
        self.assertFalse(display._lcd_page_qualified)
        self.assertEqual(display.frame_sequence, 0)
        row(display, 0, values(0))
        width, height, pixels = snapshot(display)
        self.assertEqual((width, height), (128, 128))
        expected = bytearray()
        for y in range(128):
            page, bit = 15 - y // 8, 7 - y % 8
            for x in range(128):
                first, second = (page * 17 + x) & 255, (255 - page * 11 - x) & 255
                shade = (((first >> bit) & 1) * 2 + ((second >> bit) & 1)) * 85
                expected.extend((shade,) * 3)
        self.assertEqual(pixels, bytes(expected))
        self.assertTrue(display._lcd_page_qualified)
        self.assertIsNone(display.odd_page_snapshot()['physical_calibration'])

    def test_partial_pixel_waits_for_both_planes_and_preserves_neighbors(self):
        display = self.display()
        self.full(display)
        before = snapshot(display)
        sequence = display.frame_sequence
        row(display, 15, [0], column=127)
        self.assertEqual(snapshot(display), before)
        self.assertEqual(display.frame_sequence, sequence)
        write(display, 0, data=True)
        after = snapshot(display)
        expected = bytearray(before[2])
        for y in range(8):
            offset = (y * 128 + 127) * 3
            expected[offset:offset + 3] = bytes(3)
        self.assertEqual(after[2], bytes(expected))
        self.assertGreater(display.frame_sequence, sequence)

    def test_odd_pair_at_command_barrier_withdraws_without_publishing(self):
        display = self.display()
        self.full(display)
        before = snapshot(display)
        row(display, 15, [0])
        write(display, 0xbe)
        self.assertTrue(display.odd_page_snapshot()['rejected'])
        self.assertEqual(snapshot(display), before)

    def test_reset_discards_staging_and_retains_visible_frame_until_full_new_scan(self):
        display = self.display()
        self.full(display)
        before = snapshot(display)
        row(display, 15, [0])
        self.initialize(display)
        for page in range(15, 0, -1):
            row(display, page, [0] * 256)
        self.assertFalse(display._lcd_page_qualified)
        self.assertEqual(snapshot(display), before)
        row(display, 0, [0] * 256)
        self.assertTrue(display._lcd_page_qualified)
        self.assertEqual(snapshot(display)[2], bytes(128 * 128 * 3))

    def test_bad_scan_order_short_tail_width_and_column_cannot_acquire(self):
        for mode in ('ascending', 'missing-page', 'odd-tail', 'word', 'column'):
            with self.subTest(mode=mode):
                display = self.display()
                self.initialize(display)
                pages = list(range(15, -1, -1))
                if mode == 'ascending':
                    pages.reverse()
                if mode == 'missing-page':
                    pages.remove(7)
                for page in pages:
                    if mode == 'word':
                        for command in (0xb0 | page, 0x10, 0):
                            write(display, command, size=2)
                    else:
                        row(display, page, [255] * (255 if mode == 'odd-tail' and page == 0 else 256),
                            column=128 if mode == 'column' else 0)
                snapshot(display)
                self.assertFalse(display._lcd_page_qualified)
                self.assertEqual(display.frame_sequence, 0)

    def test_foreign_auxiliary_page_candidate_cannot_steal_main_owner(self):
        display = self.display()
        self.full(display)
        before = snapshot(display)
        for command in (0xe2, 0xae, 0xb7, 0x10, 0):
            write(display, command, address=0x02800000)
        for _ in range(104):
            write(display, 0, address=0x02800002)
        self.assertTrue(display._lcd_page_qualified)
        self.assertEqual(display._lcd_page_port, 0x02000000)
        self.assertEqual(snapshot(display), before)
        row(display, 0, [0, 0], column=0)
        self.assertFalse(display.odd_page_snapshot()['blocked'])
        self.assertNotEqual(snapshot(display)[2], before[2])

    def test_loaded_source_and_RAM_bounds_fail_closed_but_unguarded_state_can_change(self):
        for mode in ('source', 'RAM', 'state'):
            with self.subTest(mode=mode):
                display = self.display()
                loaded = bytearray(display.image)
                if mode == 'source':
                    loaded[0x10] = 1
                elif mode == 'state':
                    loaded[0x900] = 1
                else:
                    display.config.ram_size = 0x1000
                display._lcd_page_loaded_image = bytes(loaded)
                self.full(display)
                self.assertEqual(display._lcd_page_qualified, mode == 'state')
                if mode != 'state':
                    self.assertFalse(display.odd_page_snapshot()['source_bound'])
                    self.assertEqual(display.frame_sequence, 0)

    def test_loaded_reparse_cannot_change_the_source_owner(self):
        display = self.display()
        loaded = bytearray(display.image); loaded[0x900] = 1
        display._lcd_page_loaded_image = bytes(loaded)
        target = 'msm5xxx_emulator.detection.byte_lane_page.find_byte_lane_page_profile'
        with patch(target, side_effect=((PAIRED_PROFILE, 'accepted'), (None, 'ambiguous'))):
            write(display, 0xe2)
        self.assertFalse(display.odd_page_snapshot()['source_bound'])
        self.assertEqual(display.odd_page_snapshot()['reason'], 'paired-page-loaded-owner-mismatch')
