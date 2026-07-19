"""Regression tests for controller-proven display geometry."""
from __future__ import annotations

from collections import Counter, deque
from types import SimpleNamespace
import threading
import unittest

from msm5xxx import GenericMSMEmulator, detect_lcd_width_hint


class LCDGeometryTests(unittest.TestCase):
    def test_full_zero_based_gram_window_proves_128_by_160(self) -> None:
        self.assertEqual(
            GenericMSMEmulator._lcd_full_window_geometry([0, 127], [0, 159]),
            (128, 160),
        )

    def test_partial_or_offset_window_does_not_change_panel_geometry(self) -> None:
        self.assertIsNone(
            GenericMSMEmulator._lcd_full_window_geometry([2, 127], [0, 159])
        )
        self.assertIsNone(
            GenericMSMEmulator._lcd_full_window_geometry([0, 31], [0, 159])
        )

    def _blank_emulator(self, visible: bool, width: int = 176,
                        height: int = 220, model: str = "") -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(width=width, height=height, model=model)
        emulator.framebuffer = bytearray(width * height * 3)
        if visible:
            emulator.framebuffer[0] = 1
        emulator.display_frame = bytes(emulator.framebuffer)
        emulator.frame_sequence = 7
        emulator._display_lock = threading.Lock()
        emulator._lcd_direct_calibrated = [False, False]
        emulator._lcd_raw_streams = {}
        emulator._lcd_raw_counts = Counter()
        emulator._lcd_raw_frames = Counter()
        emulator._lcd_raw_port = None
        emulator._lcd_raw_segment_streams = {}
        emulator._lcd_raw_segment_counts = Counter()
        emulator._lcd_recent_commands = deque(maxlen=8)
        emulator._lcd_lowbyte_page_stage = ""
        emulator._lcd_lowbyte_page_page = -1
        emulator._lcd_lowbyte_page_last = -1
        emulator._lcd_lowbyte_page_high = -1
        emulator._lcd_lowbyte_page_rows = 0
        emulator._lcd_lowbyte_page_words = []
        emulator._lcd_selector_registers = {}
        emulator._lcd_selector_words = []
        emulator._lcd_selector_expected = 0
        emulator._lcd_selector_window = None
        emulator._lcd_selector_format = None
        emulator._lcd_window_rgb565_header = []
        emulator._lcd_window_rgb565_window = None
        emulator._lcd_window_rgb565_pixels = []
        emulator._lcd_window_rgb565_high = None
        emulator._lcd_bgr444_command = None
        emulator._lcd_bgr444_axis_state = 0
        emulator._lcd_bgr444_cursor = [0, 0]
        emulator._lcd_bgr444_qualified = False
        emulator._lcd_bgr444_dirty = False
        emulator._lcd_bgr444_streamed_pixels = 0
        emulator._lcd_bgr444_run_origin = None
        emulator._lcd_bgr444_run_words = []
        emulator._lcd_bgr444_runs = []
        emulator._lcd_protocol = "selector-4"
        emulator._lcd_frame_protocol = "none"
        emulator._lcd_page_current = -1
        emulator._lcd_page_port = None
        emulator._lcd_page_column_high = None
        emulator._lcd_page_column_ready = False
        emulator._lcd_page_column = 0
        emulator._lcd_page_start_column = 0
        emulator._lcd_page_data_count = 0
        emulator._lcd_page_row_bytes = 0
        emulator._lcd_page_width = 0
        emulator._lcd_page_height = 0
        emulator._lcd_page_bits_per_pixel = 1
        emulator._lcd_page_width_hint = 128
        emulator._lcd_page_geometry_rendered = False
        emulator._lcd_page_candidate_rows = 0
        emulator._lcd_page_last_finished = -1
        emulator._lcd_page_qualified = False
        emulator._lcd_page_seen = set()
        emulator._lcd_page_ram = bytearray(16 * 256)
        return emulator

    def _routing_emulator(self, *, width: int = 128,
                          height: int = 128) -> GenericMSMEmulator:
        emulator = self._blank_emulator(False, width, height)
        emulator.lcd_writes = 0
        emulator.lcd_port_writes = Counter()
        emulator._lcd_byte_rgb565_commands = bytearray()
        emulator._lcd_byte_rgb565_payload = None
        emulator._lcd_recent_commands = deque(maxlen=8)
        emulator._lcd_mode = 0
        emulator._lcd_command = 0
        emulator._lcd_args = []
        emulator._lcd_expected = 0
        emulator._lcd_streamed = 0
        emulator._lcd_data_byte_latch = {}
        emulator._lcd_028_direct_probe = []
        emulator._lcd_x = [0, width - 1]
        emulator._lcd_y = [0, height - 1]
        emulator._lcd_direct_cursor = [0, 0]
        emulator._lcd_direct_window = [width, height]
        emulator._lcd_direct_origin = [0, 0]
        emulator._lcd_cursor = [0, 0]
        emulator._lcd_gram_cursor = [0, 0]
        emulator._lcd_gram_addressed = False
        emulator._lcd_gram_dirty = False
        emulator._lcd_packed_21_state = 0
        return emulator

    def test_black_provisional_frames_can_be_replaced_by_proven_geometry(self) -> None:
        emulator = self._blank_emulator(visible=False)

        emulator._set_display_geometry(128, 160)

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))
        self.assertEqual(len(emulator.display_frame), 128 * 160 * 3)

    def test_visible_frame_is_not_reinterpreted_without_force(self) -> None:
        emulator = self._blank_emulator(visible=True)

        emulator._set_display_geometry(128, 160)

        self.assertEqual((emulator.config.width, emulator.config.height), (176, 220))

    def test_full_gram_window_replaces_only_generic_fallback(self) -> None:
        emulator = self._blank_emulator(visible=False)
        emulator._lcd_x, emulator._lcd_y = [0, 127], [0, 159]

        emulator._lcd_promote_gram_geometry()

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))

    def test_full_gram_window_does_not_expand_known_panel(self) -> None:
        emulator = self._blank_emulator(
            visible=False, width=120, height=160, model="LG-SD810",
        )
        emulator._lcd_x, emulator._lcd_y = [0, 175], [0, 219]

        emulator._lcd_promote_gram_geometry()

        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))

    def test_packed_selector_registers_prove_rgb666_frame(self) -> None:
        emulator = self._blank_emulator(visible=False)
        emulator.frame_sequence = 0
        for command in (0x0D00, 0x0200, 0x0300, 0x047F, 0x059F):
            self.assertFalse(emulator._lcd_selector_begin_command(2, command))
        self.assertTrue(emulator._lcd_selector_begin_command(2, 0x0E00))

        words = [3, 0xF000, 0, 0x0FC0, 0, 0x003F]
        words.extend([0, 0] * (128 * 160 - 3))
        for word in words:
            self.assertTrue(emulator._lcd_selector_feed(2, word))

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))
        self.assertEqual(emulator._lcd_protocol, "selector-rgb666")
        self.assertEqual(emulator._lcd_frame_protocol, "selector-rgb666")
        self.assertEqual(emulator.display_frame[:9],
                         bytes((255, 0, 0, 0, 255, 0, 0, 0, 255)))

    def test_selector_stream_requires_mode_and_valid_rgb666_high_words(self) -> None:
        emulator = self._blank_emulator(visible=False)
        for command in (0x0200, 0x0300, 0x047F, 0x059F):
            emulator._lcd_selector_begin_command(2, command)
        self.assertFalse(emulator._lcd_selector_begin_command(2, 0x0E00))

        emulator._lcd_selector_begin_command(2, 0x0D00)
        self.assertTrue(emulator._lcd_selector_begin_command(2, 0x0E00))
        self.assertFalse(emulator._lcd_selector_feed(2, 4))
        self.assertEqual(emulator.frame_sequence, 7)

    def test_packed_selector_rgb565_updates_exact_rectangle(self) -> None:
        emulator = self._blank_emulator(visible=False, width=128, height=160)
        for command in (0x0D01, 0x0201, 0x0302, 0x0402, 0x0502):
            self.assertFalse(emulator._lcd_selector_begin_command(2, command))
        self.assertTrue(emulator._lcd_selector_begin_command(2, 0x0E00))
        self.assertTrue(emulator._lcd_selector_feed(2, 0xF800))
        self.assertTrue(emulator._lcd_selector_feed(2, 0x07E0))

        offset = (2 * 128 + 1) * 3
        self.assertEqual(emulator.display_frame[offset:offset + 6],
                         bytes((255, 0, 0, 0, 255, 0)))
        self.assertEqual(emulator._lcd_frame_protocol, "selector-rgb565")

    def test_byte_window_rgb565_requires_exact_large_rectangle(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        for address, value in zip(range(0x0200001A, 0x0200001E), (0, 0, 127, 63)):
            emulator._lcd_write(None, 0, address, 1, value, None)
        for index in range(128 * 64):
            pixel = 0xF800 if index == 0 else 0x07E0
            emulator._lcd_write(None, 0, 0x02000010, 1, pixel >> 8, None)
            emulator._lcd_write(None, 0, 0x02000011, 1, pixel & 0xFF, None)

        self.assertEqual(emulator._lcd_protocol, "window-byte-rgb565")
        self.assertEqual(emulator._lcd_frame_protocol, "window-byte-rgb565")
        self.assertEqual(emulator.display_frame[:6], bytes((255, 0, 0, 0, 255, 0)))

    def test_cursor_bgr444_sequence_updates_exact_horizontal_run(self) -> None:
        emulator = self._blank_emulator(visible=False, width=128, height=160)
        for command, argument in ((0x03, 1), (0x05, 2)):
            self.assertTrue(emulator._lcd_bgr444_begin_command(2, command))
            self.assertTrue(emulator._lcd_bgr444_feed(2, argument))
        self.assertTrue(emulator._lcd_bgr444_begin_command(2, 0x0B))
        self.assertTrue(emulator._lcd_bgr444_feed(2, 0x0FF0))
        self.assertTrue(emulator._lcd_bgr444_feed(2, 0x0000))
        self.assertFalse(emulator._lcd_bgr444_begin_command(2, 0x2B))

        offset = (2 * 128 + 1) * 3
        self.assertEqual(emulator.display_frame[offset:offset + 6],
                         bytes((0, 255, 255, 0, 0, 0)))
        self.assertEqual(emulator._lcd_frame_protocol, "cursor-bgr444")

    def test_cursor_bgr444_full_raster_proves_unknown_geometry(self) -> None:
        emulator = self._blank_emulator(visible=False)
        emulator.frame_sequence = 0
        for y in range(160):
            for command, argument in ((0x03, 0), (0x05, y)):
                self.assertTrue(emulator._lcd_bgr444_begin_command(2, command))
                self.assertTrue(emulator._lcd_bgr444_feed(2, argument))
            self.assertTrue(emulator._lcd_bgr444_begin_command(2, 0x0B))
            for _ in range(128):
                self.assertTrue(emulator._lcd_bgr444_feed(2, 0x0FF0))
        self.assertFalse(emulator._lcd_bgr444_begin_command(2, 0x2B))

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))
        self.assertEqual(emulator.display_frame[:3], bytes((0, 255, 255)))

    def test_page_lcd_publish_records_proven_protocol(self) -> None:
        emulator = self._blank_emulator(visible=False)
        emulator._lcd_protocol = "direct"
        emulator._lcd_page_bits_per_pixel = 1
        emulator._lcd_page_render_current = lambda: True

        emulator._lcd_page_flush_current()

        self.assertEqual(emulator._lcd_frame_protocol, "page-1bpp")

    def test_page_lcd_metadata_supplies_only_an_unambiguous_width(self) -> None:
        self.assertEqual(
            detect_lcd_width_hint(b"m.LCD_PIXEL\0" b"128112\0"), 128
        )
        self.assertIsNone(detect_lcd_width_hint(
            b"m.LCD_PIXEL\0" b"128112\0"
            b"m.LCD_PIXEL\0" b"176202\0"
        ))

    def test_page_lcd_layout_separates_two_planes_from_physical_width(self) -> None:
        self.assertEqual(GenericMSMEmulator._lcd_page_layout(256, 128), (128, 2))
        self.assertEqual(GenericMSMEmulator._lcd_page_layout(128, 128), (128, 1))
        self.assertEqual(GenericMSMEmulator._lcd_page_layout(256, None), (256, 1))

    def test_page_lcd_two_planes_render_msb_then_lsb_as_four_grays(self) -> None:
        emulator = self._blank_emulator(visible=False, width=128, height=128)
        emulator._lcd_page_width = 128
        emulator._lcd_page_height = 128
        emulator._lcd_page_bits_per_pixel = 2
        emulator._lcd_page_ram = bytearray(16 * 256)
        emulator._lcd_page_ram[:8] = bytes((1, 0, 0, 1, 1, 1, 0, 0))

        self.assertTrue(emulator._lcd_page_render_all())

        self.assertEqual(
            emulator.framebuffer[:12],
            bytes((170, 170, 170, 85, 85, 85, 255, 255, 255, 0, 0, 0)),
        )

    def test_low_byte_strh_page_scan_is_2bpp_without_raw_takeover(self) -> None:
        emulator = self._routing_emulator()
        first_row = bytes((1, 0, 0, 1, 1, 1, 0, 0)) + bytes(248)
        for page in range(2, 16):
            for command in (0xB0 + page, 0x10, 0x00):
                emulator._lcd_write(None, 0, 0x02800000, 2, command, None)
            for value in first_row if page == 2 else bytes(256):
                emulator._lcd_write(None, 0, 0x02800004, 2, value, None)
        emulator._lcd_write(None, 0, 0x02800000, 2, 0xB2, None)

        self.assertTrue(emulator._lcd_page_qualified)
        self.assertEqual(emulator._lcd_page_bits_per_pixel, 2)
        self.assertEqual(
            emulator.display_frame[16 * 128 * 3:16 * 128 * 3 + 12],
            bytes((170, 170, 170, 85, 85, 85, 255, 255, 255, 0, 0, 0)),
        )
        self.assertFalse(emulator._lcd_raw_frames)

        count = emulator._lcd_page_data_count
        ram = bytes(emulator._lcd_page_ram)
        emulator._lcd_write(None, 0, 0x02800000, 2, 0x01B2, None)
        emulator._lcd_write(None, 0, 0x02800004, 2, 0x0101, None)
        self.assertEqual(emulator._lcd_page_data_count, count)
        self.assertEqual(bytes(emulator._lcd_page_ram), ram)

    def test_028_parallel_window_promotes_complete_direct_grammar(self) -> None:
        emulator = self._routing_emulator(width=2, height=2)
        emulator._lcd_protocol = "parallel-2"
        for address, value in (
            (0x02800000, 0x75),
            (0x02800004, 0x00),
            (0x02800004, 0x01),
            (0x02800000, 0x15),
            (0x02800004, 0x00),
            (0x02800004, 0x01),
        ):
            emulator._lcd_write(None, 0, address, 2, value, None)

        self.assertEqual(emulator._lcd_protocol, "parallel-2")
        self.assertEqual(emulator._lcd_command, 0)
        self.assertEqual(emulator._lcd_args, [])
        for address, value in (
            (0x02800000, 0x5C),
            (0x02800004, 0xF800),
            (0x02800004, 0x07E0),
            (0x02800004, 0x001F),
            (0x02800004, 0xFFFF),
        ):
            emulator._lcd_write(None, 0, address, 2, value, None)

        self.assertEqual(emulator._lcd_protocol, "direct")
        self.assertEqual(emulator._lcd_028_direct_probe, [])
        self.assertEqual(
            emulator.display_frame,
            bytes((255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255)),
        )

    def test_qualified_packed_21_cursor_keeps_xy(self) -> None:
        def write(emulator: GenericMSMEmulator, command: int, value: int) -> None:
            emulator._lcd_write(None, 0, 0x02000000, 2, command, None)
            emulator._lcd_write(None, 0, 0x02000002, 2, value, None)

        emulator = self._routing_emulator(width=128, height=160)
        for command, value in ((0x16, 0x7F00), (0x17, 0x9F00),
                               (0x05, 0x0230), (0x20, 0)):
            write(emulator, command, value)
        write(emulator, 0x21, 0x2006)
        emulator._lcd_write(None, 0, 0x02000000, 2, 0x22, None)
        for _ in range(6):
            emulator._lcd_write(None, 0, 0x02000002, 2, 0xFFFF, None)

        expected = (0x20 * 128 + 6) * 3
        self.assertEqual(emulator.framebuffer[expected:expected + 18],
                         b"\xff" * 18)
        self.assertEqual(emulator.framebuffer[6 * 128 * 3:6 * 128 * 3 + 18],
                         b"\0" * 18)

        legacy = self._routing_emulator(width=128, height=160)
        write(legacy, 0x20, 0)
        write(legacy, 0x21, 0x2006)
        self.assertEqual(legacy._lcd_gram_cursor, [0, 6])

    def test_parallel_subwindow_beats_stale_gram_cursor(self) -> None:
        emulator = self._routing_emulator(width=6, height=4)
        emulator._lcd_protocol = "parallel-2"
        emulator._lcd_x, emulator._lcd_y = [1, 2], [0, 1]
        emulator._lcd_gram_addressed = True
        emulator._lcd_gram_cursor = [5, 3]

        emulator._lcd_begin_command(0x22)
        for pixel in (0xF800, 0x07E0, 0x001F, 0xFFFF):
            emulator._lcd_feed_parallel_data(0x02800002, 2, pixel)

        self.assertEqual(emulator.display_frame[3:6], bytes((255, 0, 0)))
        self.assertEqual(emulator.display_frame[6:9], bytes((0, 255, 0)))
        self.assertEqual(emulator.display_frame[21:24], bytes((0, 0, 255)))
        self.assertEqual(emulator.display_frame[24:27], b"\xff" * 3)
        self.assertEqual(emulator.display_frame[-3:], b"\0\0\0")

    def test_028_direct_probe_replays_parallel_page_near_miss(self) -> None:
        emulator = self._routing_emulator()
        emulator._lcd_protocol = "parallel-2"
        for address, value in (
            (0x02800000, 0x75),
            (0x02800004, 0x00),
            (0x02800002, 0x0000),
            (0x02800000, 0xB2),
            (0x02800000, 0x10),
            (0x02800000, 0x00),
            (0x02800004, 0x01),
        ):
            emulator._lcd_write(None, 0, address, 2, value, None)

        self.assertEqual(emulator._lcd_protocol, "parallel-2")
        self.assertEqual(emulator._lcd_028_direct_probe, [])
        self.assertEqual(emulator._lcd_page_current, 2)
        self.assertTrue(emulator._lcd_page_column_ready)
        self.assertEqual(emulator._lcd_page_data_count, 1)

    def test_x150_page_packets_do_not_join_raw_raster(self) -> None:
        emulator = self._routing_emulator()
        port = (0x02000004, 2)
        for page in (2, 3):
            for command in (0xB0 + page, 0x12, 0x00):
                emulator._lcd_write(None, 0, 0x02000000, 2, command, None)
            for _ in range(96):
                emulator._lcd_write(None, 0, 0x02000004, 2, 0x001F, None)

        self.assertEqual(emulator.frame_sequence, 7)
        self.assertEqual(emulator._lcd_raw_frames[port], 0)
        self.assertEqual(emulator._lcd_raw_counts[port], 0)
        self.assertEqual(len(emulator._lcd_raw_streams[port]), 0)
        self.assertEqual(emulator.lcd_port_writes[port], 192)
        self.assertFalse(emulator._lcd_page_qualified)
        self.assertIsNone(emulator._lcd_page_port)

    def test_e100_lowbyte_page_packets_do_not_join_raw_raster(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        port = (0x02000004, 2)
        for page in range(8):
            for command in (0xB0 + page, 0x10, 0x04):
                emulator._lcd_write(None, 0, 0x02000000, 1, command, None)
            for _ in range(96):
                emulator._lcd_write(None, 0, 0x02000004, 2, 0x001F, None)

        self.assertEqual(emulator.frame_sequence, 7)
        self.assertEqual(emulator._lcd_raw_frames[port], 0)
        self.assertEqual(emulator._lcd_raw_counts[port], 0)
        self.assertEqual(len(emulator._lcd_raw_streams.get(port, ())), 0)
        self.assertEqual(emulator.lcd_port_writes[(0x02000000, 1)], 24)
        self.assertEqual(emulator.lcd_port_writes[port], 768)

    def test_e100_sidecar_requires_two_adjacent_rows_before_suppression(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        port = (0x02000004, 2)
        for page in (0, 1):
            for command in (0xB0 + page, 0x10, 0x04):
                emulator._lcd_write(None, 0, 0x02000000, 1, command, None)
            for _ in range(96):
                emulator._lcd_write(None, 0, 0x02000004, 2, 0x001F, None)
            if page == 0:
                self.assertEqual(emulator._lcd_lowbyte_page_rows, 1)
                self.assertEqual(len(emulator._lcd_lowbyte_page_words), 96)
                self.assertEqual(emulator._lcd_raw_counts[port], 0)

        self.assertEqual(emulator._lcd_lowbyte_page_rows, 2)
        self.assertEqual(emulator._lcd_lowbyte_page_words, [])
        self.assertEqual(emulator._lcd_raw_counts[port], 0)
        self.assertEqual(emulator.frame_sequence, 7)
        self.assertEqual(emulator._lcd_protocol, "parallel-2")

    def test_e100_sidecar_replays_wrong_column_and_wide_word(self) -> None:
        wrong_column = self._routing_emulator(width=128, height=160)
        port = (0x02000004, 2)
        for command in (0xB0, 0x10, 0x05):
            wrong_column._lcd_write(None, 0, 0x02000000, 1, command, None)
        for _ in range(96):
            wrong_column._lcd_write(None, 0, 0x02000004, 2, 0x001F, None)
        self.assertEqual(wrong_column._lcd_raw_counts[port], 96)

        wide_word = self._routing_emulator(width=128, height=160)
        for command in (0xB0, 0x10, 0x04):
            wide_word._lcd_write(None, 0, 0x02000000, 1, command, None)
        for _ in range(95):
            wide_word._lcd_write(None, 0, 0x02000004, 2, 0x001F, None)
        wide_word._lcd_write(None, 0, 0x02000004, 2, 0x0101, None)
        self.assertEqual(wide_word._lcd_raw_counts[port], 96)
        self.assertEqual(wide_word._lcd_lowbyte_page_stage, "")

    def test_e100_sidecar_replays_on_size2_base_or_other_port(self) -> None:
        size2_base = self._routing_emulator(width=128, height=160)
        port = (0x02000004, 2)
        size2_base._lcd_write(None, 0, 0x02000000, 1, 0xB0, None)
        size2_base._lcd_write(None, 0, 0x02000000, 2, 0x10, None)
        size2_base._lcd_write(None, 0, 0x02000000, 1, 0x04, None)
        for _ in range(96):
            size2_base._lcd_write(None, 0, 0x02000004, 2, 0x001F, None)
        self.assertEqual(size2_base._lcd_raw_counts[port], 96)

        other_port = self._routing_emulator(width=128, height=160)
        for command in (0xB0, 0x10, 0x04):
            other_port._lcd_write(None, 0, 0x02000000, 1, command, None)
        for _ in range(95):
            other_port._lcd_write(None, 0, 0x02000004, 2, 0x001F, None)
        other_port._lcd_write(None, 0, 0x02000002, 2, 0x001F, None)
        self.assertEqual(other_port._lcd_raw_counts[port], 95)
        self.assertEqual(other_port._lcd_raw_counts[(0x02000002, 2)], 1)
        self.assertEqual(other_port._lcd_lowbyte_page_stage, "")

    def test_byte_020_page_scan_requires_zero_column_byte_grammar(self) -> None:
        def page_scan(emulator: GenericMSMEmulator, size: int,
                      column_high: int = 0x10, include_low: bool = True) -> None:
            for page in range(16):
                commands = (0xB0 + page, column_high)
                if include_low:
                    commands += (0x00,)
                for command in commands:
                    emulator._lcd_write(None, 0, 0x02000000, size, command, None)
                values = bytes((1,)) + bytes(255) if page == 0 else bytes(256)
                for value in values:
                    emulator._lcd_write(None, 0, 0x02000004, size, value, None)
            emulator._lcd_write(None, 0, 0x02000000, size, 0xB0, None)

        emulator = self._routing_emulator(width=176, height=220)
        emulator._lcd_page_width_hint = None
        page_scan(emulator, 1)
        self.assertTrue(emulator._lcd_page_qualified)
        self.assertEqual((emulator.config.width, emulator.config.height), (256, 128))
        self.assertEqual(emulator._lcd_page_bits_per_pixel, 1)
        self.assertEqual(emulator._lcd_frame_protocol, "page-1bpp")
        self.assertTrue(any(emulator.display_frame))

        near_miss = self._routing_emulator(width=176, height=220)
        near_miss._lcd_page_width_hint = None
        page_scan(near_miss, 1, column_high=0x11)
        self.assertFalse(near_miss._lcd_page_qualified)
        self.assertEqual((near_miss.config.width, near_miss.config.height), (176, 220))

        missing_low = self._routing_emulator(width=176, height=220)
        missing_low._lcd_page_width_hint = None
        page_scan(missing_low, 1, include_low=False)
        self.assertFalse(missing_low._lcd_page_qualified)
        self.assertEqual((missing_low.config.width, missing_low.config.height), (176, 220))

        wide = self._routing_emulator(width=176, height=220)
        wide._lcd_page_width_hint = None
        page_scan(wide, 2)
        self.assertFalse(wide._lcd_page_qualified)
        self.assertEqual((wide.config.width, wide.config.height), (176, 220))

    def test_unqualified_all_low_byte_raw_raster_still_publishes(self) -> None:
        emulator = self._blank_emulator(visible=False, width=128, height=128)
        port = (0x02000004, 2)
        for _ in range(128 * 128):
            emulator._capture_raw_lcd_stream(0x02000004, 2, 0x001F)

        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_raw_frames[port], 1)


if __name__ == "__main__":
    unittest.main()
