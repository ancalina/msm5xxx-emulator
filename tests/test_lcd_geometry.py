"""Regression tests for controller-proven display geometry."""
from __future__ import annotations

from collections import Counter, deque
from types import SimpleNamespace
import threading
import unittest

from msm5xxx import GenericMSMEmulator, detect_lcd_width_hint
from msm5xxx_emulator.devices.display.protocols.direct import _028_SPLIT16_PREFIX


class LCDGeometryTests(unittest.TestCase):
    def test_byte_raster_requires_all_160_rows_and_completion(self) -> None:
        emulator = self._blank_emulator(False)
        emulator._lcd_byte_raster_stage = ""
        emulator._lcd_byte_raster_row = 0
        emulator._lcd_byte_raster_pixels = bytearray()
        for row in range(160):
            for address, value in (
                    (0x02000000, 0x05), (0x02000002, row),
                    (0x02000000, 0x03), (0x02000002, 0),
                    (0x02000000, 0x0B)):
                self.assertFalse(emulator._lcd_byte_raster_write(address, 1, value))
            for _column in range(128):
                emulator._lcd_byte_raster_write(0x02000002, 1, 0xF8)
                emulator._lcd_byte_raster_write(0x02000002, 1, 0x00)
        self.assertEqual(emulator.frame_sequence, 7)
        emulator._lcd_byte_raster_write(0x02000000, 1, 0x2B)
        self.assertTrue(emulator._lcd_byte_raster_write(0x02000002, 1, 1))
        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_protocol, "byte-raster-rgb565")
        self.assertEqual(emulator.framebuffer[:3], b"\xff\0\0")

    def test_same_geometry_returns_before_scanning_framebuffer(self) -> None:
        class UnscannableFramebuffer:
            def __iter__(self):
                raise AssertionError("same geometry must not scan framebuffer")

        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(width=128, height=160)
        emulator.framebuffer = UnscannableFramebuffer()
        emulator._set_display_geometry(128, 160, source="runtime:test")

    def test_geometry_visibility_check_uses_native_byte_count(self) -> None:
        class UniterableFramebuffer(bytearray):
            def __iter__(self):
                raise AssertionError("visibility check must not iterate in Python")

        emulator = self._blank_emulator(False)
        emulator.framebuffer = UniterableFramebuffer(emulator.framebuffer)

        emulator._set_display_geometry(128, 160, source="runtime:test")

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))

    def test_pixel_writes_exact_rgb565_channels_without_touching_neighbours(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(width=2, height=1)
        emulator.framebuffer = bytearray(b"\xaa" * 6)

        emulator._pixel(1, 0xF81F)
        self.assertEqual(emulator.framebuffer, b"\xaa\xaa\xaa\xff\x00\xff")
        emulator._pixel(2, 0)
        self.assertEqual(emulator.framebuffer, b"\xaa\xaa\xaa\xff\x00\xff")

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
                        height: int = 220, model: str = "",
                        geometry_source: str | None = None) -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            width=width, height=height, model=model,
            display_geometry_source=(geometry_source if geometry_source is not None
                                     else ("auto-default" if (width, height) == (176, 220)
                                           else "external-config")),
        )
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
        emulator._lcd_selector_reacquire_index = None
        emulator._lcd_selector_reacquire_words = []
        emulator._lcd_selector_reacquire_protocol = "unknown"
        emulator._lcd_selector_reacquire_replaying = False
        emulator._lcd_selector_transfers = deque(maxlen=32)
        emulator._lcd_selector_full_transfers = 0
        emulator._lcd_selector_partial_transfers = 0
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
        emulator._lcd_page_dirty = False
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
        emulator._lcd_byte_020_row_probe = []
        emulator._lcd_byte_020_row_events = []
        emulator._lcd_byte_020_row_stage = ""
        emulator._lcd_byte_020_row_y = -1
        emulator._lcd_byte_020_row_words = []
        emulator._lcd_byte_raster_stage = ""
        emulator._lcd_byte_raster_row = 0
        emulator._lcd_byte_raster_pixels = bytearray()
        emulator._lcd_window_raw8_header = []
        emulator._lcd_window_raw8_payload = bytearray()
        emulator._lcd_window_raw8_window = None
        emulator._lcd_window_raw8_qualified = False
        emulator._lcd_window_raw8_ram = bytearray(128 * 128)
        emulator._lcd_window_raw8_separate_events = []
        emulator._lcd_window_raw8_separate_stage = ""
        emulator._lcd_window_raw8_separate_axis = []
        emulator._lcd_window_raw8_separate_window = None
        emulator._lcd_window_raw8_separate_payload = bytearray()
        emulator._lcd_window_raw8_separate_qualified = False
        emulator._lcd_window_raw8_separate_ram = bytearray(64 * 96)
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
        emulator._lcd_028_rgb444_qualified = False
        emulator._lcd_028_be_word_events = []
        emulator._lcd_028_be_word_qualified = False
        emulator._lcd_028_be_word_replaying = False
        emulator._lcd_028_split16_events = []
        emulator._lcd_028_split16_qualified = False
        emulator._lcd_028_split16_replaying = False
        emulator._lcd_028_split16_disabled = False
        emulator._lcd_028_split16_pending_x = None
        emulator._lcd_028_split16_window = None
        emulator._lcd_028_split16_expected = 0
        emulator._lcd_028_split16_streamed = 0
        emulator._lcd_028_split16_bootstrap_stage = 0
        emulator._lcd_028_split16_frame_ready = False
        emulator._lcd_028_split16_ram = bytearray(128 * 160 * 2)
        emulator._lcd_028_rgb332_probe = []
        emulator._lcd_028_rgb332_window = (0, 0, 0, 0)
        emulator._lcd_028_rgb332_qualified = False
        emulator._lcd_028_window_fifo_qualified = False
        emulator._lg_pixels = []
        emulator._lcd_lgfa_window_order = []
        emulator._lcd_lgfa_window = None
        emulator._lcd_split_port_stage = 0
        emulator._lcd_split_port_variant = 0
        emulator._lcd_split_port_payload = bytearray()
        emulator._lcd_split_port_qualified = False
        emulator._lcd_x = [0, width - 1]
        emulator._lcd_y = [0, height - 1]
        emulator._lcd_window_axis_mask = 0
        emulator._lcd_020_compact_44 = None
        emulator._lcd_direct_cursor = [0, 0]
        emulator._lcd_direct_window = [width, height]
        emulator._lcd_direct_origin = [0, 0]
        emulator._lcd_cursor = [0, 0]
        emulator._lcd_gram_cursor = [0, 0]
        emulator._lcd_gram_addressed = False
        emulator._lcd_gram_dirty = False
        emulator._lcd_packed_21_state = 0
        return emulator

    def test_lg_paired_window_proves_geometry_before_complete_frame(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        for value in (0x0200, 0x0300, 0x0477, 0x059F):
            emulator._lcd_write(None, 0, 0x02000078, 2, value, None)
        pixels = (0xF800, 0x07E0, 0x001F) + (0,) * (120 * 160 - 3)
        for pixel in pixels:
            first = ((pixel & 0xF800) | ((pixel & 0x07E0) >> 1)
                     | ((pixel & 0x001E) >> 1))
            emulator._lcd_write(None, 0, 0x020000FA, 2, first, None)
            emulator._lcd_write(
                None, 0, 0x020000FA, 2, (pixel & 1) << 1, None
            )

        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_frame_protocol, "lg-paired-rgb565")
        self.assertEqual(
            emulator.display_frame[:9],
            bytes((255, 0, 0, 0, 255, 0, 0, 0, 255)),
        )

        xy_window = self._routing_emulator(width=176, height=220)
        for value in (0x0800, 0x0977, 0x0A00, 0x0B9F):
            xy_window._lcd_write(None, 0, 0x02000078, 2, value, None)
        xy_window._lcd_write(None, 0, 0x020000FA, 2, 0, None)
        self.assertEqual((xy_window.config.width, xy_window.config.height),
                         (120, 160))

        xy_near_miss = self._routing_emulator(width=176, height=220)
        for value in (0x0801, 0x0977, 0x0A00, 0x0B9F):
            xy_near_miss._lcd_write(None, 0, 0x02000078, 2, value, None)
        xy_near_miss._lcd_write(None, 0, 0x020000FA, 2, 0, None)
        self.assertEqual(
            (xy_near_miss.config.width, xy_near_miss.config.height),
            (176, 220),
        )

        near_miss = self._routing_emulator(width=176, height=220)
        for value in (0x0201, 0x0300, 0x0477, 0x059F):
            near_miss._lcd_write(None, 0, 0x02000078, 2, value, None)
        near_miss._lcd_write(None, 0, 0x020000FA, 2, 0, None)
        self.assertEqual((near_miss.config.width, near_miss.config.height), (176, 220))

    @staticmethod
    def _write_split_port_word(emulator: GenericMSMEmulator,
                               address: int, value: int) -> None:
        for lane in (value >> 8, value & 0xFF):
            emulator._lcd_write(None, 0, address, 2, lane, None)

    def _start_split_port_frame(self, emulator: GenericMSMEmulator) -> None:
        for command, argument in ((0x16, 0x7F00), (0x17, 0x7F00),
                                  (0x21, 0x0000)):
            self._write_split_port_word(emulator, 0x02000000, command)
            self._write_split_port_word(emulator, 0x02200000, argument)
        self._write_split_port_word(emulator, 0x02000000, 0x22)

    def _start_split_port_init_frame(self, emulator: GenericMSMEmulator) -> None:
        for command, argument in ((0x16, 0x7F00), (0x17, 0x7F00),
                                  (0x20, 0x0000), (0x21, 0x0000)):
            self._write_split_port_word(emulator, 0x02000000, command)
            self._write_split_port_word(emulator, 0x02200000, argument)
        self._write_split_port_word(emulator, 0x02000000, 0x22)

    def test_split_port_rgb565_requires_exact_full_frame(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        self._start_split_port_frame(emulator)
        pixels = (0xF800, 0x07E0, 0x001F) + (0,) * (128 * 128 - 3)
        for pixel in pixels[:-1]:
            self._write_split_port_word(emulator, 0x02200000, pixel)

        self.assertEqual(emulator.frame_sequence, 7)
        self.assertFalse(any(emulator.framebuffer))
        emulator._lcd_write(None, 0, 0x02200000, 2, 0, None)
        self.assertEqual(emulator.frame_sequence, 7)
        emulator._lcd_write(None, 0, 0x02200000, 2, 0, None)

        self.assertTrue(emulator._lcd_split_port_qualified)
        self.assertEqual((emulator.config.width, emulator.config.height), (128, 128))
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_frame_protocol, "split-byte-rgb565")
        self.assertEqual(emulator.display_frame[:9],
                         bytes((255, 0, 0, 0, 255, 0, 0, 0, 255)))
        routed = []
        emulator._lcd_route_write = lambda *event: routed.append(event[2:5])
        emulator._lcd_write(None, 0, 0x02200000, 2, 0xFF, None)
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(routed, [(0x02200000, 2, 0xFF)])
        self._start_split_port_frame(emulator)
        self.assertEqual(routed, [(0x02200000, 2, 0xFF)])

    def test_split_port_rgb565_accepts_exact_init_prefix(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        self._start_split_port_init_frame(emulator)
        for _ in range(128 * 128):
            self._write_split_port_word(emulator, 0x02200000, 0xFFFF)

        self.assertTrue(emulator._lcd_split_port_qualified)
        self.assertEqual((emulator.config.width, emulator.config.height), (128, 128))
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_frame_protocol, "split-byte-rgb565")
        self.assertEqual(emulator.display_frame, b"\xff" * (128 * 128 * 3))

    def test_split_port_rgb565_rejects_mutated_init_prefix(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        for command, argument in ((0x16, 0x7F00), (0x17, 0x7F00),
                                  (0x20, 0x0001), (0x21, 0x0000)):
            self._write_split_port_word(emulator, 0x02000000, command)
            self._write_split_port_word(emulator, 0x02200000, argument)
        self._write_split_port_word(emulator, 0x02000000, 0x22)
        for _ in range(128 * 128):
            self._write_split_port_word(emulator, 0x02200000, 0xFFFF)

        self.assertFalse(emulator._lcd_split_port_qualified)
        self.assertEqual((emulator.config.width, emulator.config.height), (176, 220))
        self.assertEqual(emulator.frame_sequence, 7)

    @staticmethod
    def _write_028_split16_packet(emulator: GenericMSMEmulator,
                                  command: int, value: int,
                                  high_lane_low: int = 0) -> None:
        for address, packed in (
                (0x02800000, 0), (0x02800000, command << 8),
                (0x02800080, value & 0xFF00 | high_lane_low),
                (0x02800080, value << 8 & 0xFF00)):
            emulator._lcd_write(None, 0, address, 2, packed, None)

    def test_028_split16_requires_exact_init_and_full_physical_raster(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        for command, value in _028_SPLIT16_PREFIX:
            self._write_028_split16_packet(emulator, command, value)
        for _ in range(4 * 160):
            self._write_028_split16_packet(emulator, 0x22, 0)
        for command, value in ((0x44, 0x7F7C), (0x45, 0x9F00), (0x21, 0x007C)):
            self._write_028_split16_packet(emulator, command, value)
        for _ in range(4 * 160):
            self._write_028_split16_packet(emulator, 0x22, 0)
        for command, value in ((0x44, 0x7B04), (0x45, 0x9F00), (0x21, 0x0004)):
            self._write_028_split16_packet(emulator, command, value)
        for index in range(120 * 160 - 1):
            self._write_028_split16_packet(
                emulator, 0x22,
                (0xF800, 0x07E0, 0x001F)[index] if index < 3 else 0,
                high_lane_low=0xFF,
            )

        self.assertEqual(emulator.frame_sequence, 7)
        self.assertEqual((emulator.config.width, emulator.config.height), (176, 220))
        self._write_028_split16_packet(emulator, 0x22, 0)
        self.assertTrue(emulator._lcd_028_split16_qualified)
        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))
        self.assertEqual(emulator._lcd_frame_protocol, "split-halfword-rgb565")
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator.display_frame[:9],
                         bytes((255, 0, 0, 0, 255, 0, 0, 0, 255)))

        near_miss = self._routing_emulator(width=176, height=220)
        self._write_028_split16_packet(near_miss, 0x00, 0x0002)
        self.assertFalse(near_miss._lcd_028_split16_qualified)
        self.assertEqual((near_miss.config.width, near_miss.config.height),
                         (176, 220))
        self.assertEqual(near_miss.frame_sequence, 7)
        self.assertEqual(near_miss._lcd_raw_counts[(0x02800080, 2)], 2)

        for name, bad_slot in (("nonzero-packet-head", 0),
                               ("dirty-command-low-byte", 1),
                               ("dirty-data-low-low-byte", 3)):
            with self.subTest(name=name):
                malformed = self._routing_emulator(width=176, height=220)
                for index, (command, value) in enumerate(_028_SPLIT16_PREFIX):
                    packet = [
                        (0x02800000, 0),
                        (0x02800000, command << 8),
                        (0x02800080, value & 0xFF00),
                        (0x02800080, value << 8 & 0xFF00),
                    ]
                    if index == 0:
                        address, packed = packet[bad_slot]
                        packet[bad_slot] = (address, packed | 1)
                    for address, packed in packet:
                        malformed._lcd_write(
                            None, 0, address, 2, packed, None
                        )
                self.assertFalse(malformed._lcd_028_split16_qualified)
                self.assertEqual(
                    (malformed.config.width, malformed.config.height),
                    (176, 220),
                )

    def test_split_port_rgb565_rejects_near_misses(self) -> None:
        cases = (
            ("nonzero-command-prefix", ((0x02000000, 2, 1),)),
            ("reversed-window", (
                (0x02000000, 2, 0), (0x02000000, 2, 0x16),
                (0x02200000, 2, 0), (0x02200000, 2, 0x7F),
            )),
            ("out-of-range-window", (
                (0x02000000, 2, 0), (0x02000000, 2, 0x16),
                (0x02200000, 2, 0x80), (0x02200000, 2, 0),
            )),
            ("wrong-command", (
                (0x02000000, 2, 0), (0x02000000, 2, 0x17),
            )),
            ("wide-lane", (
                (0x02000000, 2, 0), (0x02000000, 2, 0x16),
                (0x02200000, 2, 0x100),
            )),
            ("intervening-port", (
                (0x02000000, 2, 0), (0x02000000, 2, 0x16),
                (0x02800000, 2, 0),
            )),
        )
        for name, events in cases:
            with self.subTest(name=name):
                emulator = self._routing_emulator(width=176, height=220)
                for event in events:
                    emulator._lcd_write(None, 0, *event, None)
                self.assertEqual(emulator._lcd_split_port_stage, 0)
                self.assertFalse(emulator._lcd_split_port_qualified)
                self.assertEqual(emulator.frame_sequence, 7)

        incomplete = self._routing_emulator(width=176, height=220)
        self._start_split_port_frame(incomplete)
        incomplete._lcd_write(None, 0, 0x02200000, 2, 0xF8, None)
        incomplete._lcd_write(None, 0, 0x02000004, 2, 0, None)
        self.assertEqual(incomplete._lcd_split_port_stage, 0)
        self.assertEqual(incomplete._lcd_split_port_payload, bytearray())
        self.assertEqual(incomplete.frame_sequence, 7)

        interrupted = self._routing_emulator(width=176, height=220)
        self._start_split_port_frame(interrupted)
        interrupted._lcd_write(None, 0, 0x02200000, 2, 0xF8, None)
        self._write_split_port_word(interrupted, 0x02000000, 0x16)
        self.assertEqual(interrupted._lcd_split_port_stage, 2)
        self.assertEqual(interrupted._lcd_split_port_payload, bytearray())
        self.assertEqual(interrupted.frame_sequence, 7)

    def test_black_provisional_frames_can_be_replaced_by_proven_geometry(self) -> None:
        emulator = self._blank_emulator(visible=False)

        emulator._set_display_geometry(128, 160, source="runtime:test")

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))
        self.assertEqual(len(emulator.display_frame), 128 * 160 * 3)

    def test_visible_frame_is_not_reinterpreted_without_force(self) -> None:
        emulator = self._blank_emulator(visible=True)

        emulator._set_display_geometry(128, 160, source="runtime:test")

        self.assertEqual((emulator.config.width, emulator.config.height), (176, 220))

    def test_full_gram_window_replaces_only_generic_fallback(self) -> None:
        emulator = self._blank_emulator(visible=False)
        emulator._lcd_x, emulator._lcd_y = [0, 127], [0, 159]

        emulator._lcd_promote_gram_geometry()

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))
        self.assertEqual(emulator.config.display_geometry_source, "runtime:gram")

    def test_explicit_default_geometry_is_not_runtime_replaceable(self) -> None:
        emulator = self._blank_emulator(
            visible=False, geometry_source="override"
        )
        emulator._lcd_x, emulator._lcd_y = [0, 127], [0, 159]

        emulator._lcd_promote_gram_geometry()

        self.assertEqual((emulator.config.width, emulator.config.height), (176, 220))
        self.assertEqual(emulator.config.display_geometry_source, "override")

    def test_descriptor_geometry_is_not_force_replaceable(self) -> None:
        emulator = self._blank_emulator(
            visible=False, width=120, height=160,
            geometry_source="framebuffer-descriptor",
        )

        emulator._set_display_geometry(
            128, 160, source="runtime:test", force=True
        )

        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))
        self.assertEqual(emulator.config.display_geometry_source,
                         "framebuffer-descriptor")

    def test_same_geometry_promotes_auto_provenance_only(self) -> None:
        emulator = self._blank_emulator(visible=False)

        emulator._set_display_geometry(
            176, 220, source="runtime:test"
        )

        self.assertEqual(emulator.config.display_geometry_source, "runtime:test")

    def test_full_gram_window_does_not_replace_nondefault_geometry(self) -> None:
        emulator = self._blank_emulator(visible=False, width=120, height=160)
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
        self.assertEqual(emulator._lcd_selector_telemetry(), {
            "full_transfers": 0,
            "partial_transfers": 1,
            "recent": [{
                "window": [1, 2, 2, 2],
                "format": "rgb565",
                "words": 2,
                "full_screen": False,
                "instructions": 0,
                "frame_sequence": emulator.frame_sequence,
            }],
        })

    def test_proven_selector_reacquires_bus_after_parallel_traffic(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        emulator._lcd_selector_full_transfers = 1
        emulator._lcd_selector_registers[0x0D] = 1
        emulator._lcd_protocol = "direct"
        port = (0x02000004, 2)
        pixels = emulator.config.width * emulator.config.height
        emulator._lcd_raw_streams[port] = deque([1] * (pixels - 1),
                                                 maxlen=pixels)
        emulator._lcd_raw_counts[port] = pixels - 1

        emulator._lcd_write(None, 0, 0x02000000, 2, 0, None)
        for command in (0x0201, 0x0302, 0x0402, 0x0502, 0x1500, 0x0E00):
            emulator._lcd_write(None, 0, 0x02000004, 2, command, None)
        self.assertEqual(emulator._lcd_protocol, "direct")
        self.assertEqual(emulator._lcd_selector_expected, 0)
        self.assertEqual(emulator._lcd_raw_counts[port], pixels - 1)
        self.assertFalse(emulator._lcd_raw_frames)
        emulator._lcd_write(None, 0, 0x02000000, 2, 1, None)
        for pixel in (0xF800, 0x07E0):
            emulator._lcd_write(None, 0, 0x02000004, 2, pixel, None)

        offset = (2 * 128 + 1) * 3
        self.assertEqual(
            emulator.display_frame[offset:offset + 6],
            bytes((255, 0, 0, 0, 255, 0)),
        )
        self.assertEqual(emulator._lcd_frame_protocol, "selector-rgb565")
        self.assertFalse(emulator._lcd_raw_frames)

    def test_proven_selector_does_not_capture_parallel_zero_command(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        emulator._lcd_selector_full_transfers = 1
        emulator._lcd_protocol = "parallel-2"

        emulator._lcd_write(None, 0, 0x02000000, 2, 0, None)
        emulator._lcd_write(None, 0, 0x02000004, 2, 0x1234, None)

        self.assertEqual(emulator._lcd_protocol, "parallel-2")
        self.assertIsNone(emulator._lcd_selector_reacquire_index)
        self.assertEqual(
            emulator._lcd_raw_counts[(0x02000004, 2)], 1
        )

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

    @staticmethod
    def _write_byte_row_packet(emulator: GenericMSMEmulator,
                               command: int, word: int) -> None:
        for address, value in ((0x02000000, 0), (0x02000000, command),
                               (0x02000002, word >> 8),
                               (0x02000002, word & 0xFF)):
            emulator._lcd_write(None, 0, address, 1, value, None)

    def test_byte_row_rgb565_requires_complete_128_word_row(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        self._write_byte_row_packet(emulator, 0x05, 0x14)
        self._write_byte_row_packet(emulator, 0x10, 0)
        self._write_byte_row_packet(emulator, 0x11, 3)
        for x in range(128):
            self._write_byte_row_packet(emulator, 0x12, 0xF800 if x == 0 else 0x07E0)

        row = 3 * 128 * 3
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_protocol, "byte-row-rgb565")
        self.assertEqual(emulator.display_frame[row:row + 6],
                         bytes((255, 0, 0, 0, 255, 0)))

        self._write_byte_row_packet(emulator, 0x05, 0x14)
        self._write_byte_row_packet(emulator, 0x10, 0)
        self._write_byte_row_packet(emulator, 0x11, 4)
        for _ in range(128):
            self._write_byte_row_packet(emulator, 0x12, 0x001F)
        self.assertEqual(emulator.frame_sequence, 9)
        self.assertEqual(emulator.display_frame[4 * 128 * 3:4 * 128 * 3 + 3],
                         bytes((0, 0, 255)))

    def test_byte_row_rgb565_127_words_do_not_change_frame(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        self._write_byte_row_packet(emulator, 0x05, 0x14)
        self._write_byte_row_packet(emulator, 0x10, 0)
        self._write_byte_row_packet(emulator, 0x11, 3)
        for _ in range(127):
            self._write_byte_row_packet(emulator, 0x12, 0xF800)

        self.assertEqual(emulator.frame_sequence, 7)
        self.assertEqual(emulator._lcd_protocol, "selector-4")
        self.assertFalse(any(emulator.framebuffer))

    def test_byte_row_rgb565_requires_05_preamble(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        self._write_byte_row_packet(emulator, 0x10, 0)
        self._write_byte_row_packet(emulator, 0x11, 3)
        for _ in range(128):
            self._write_byte_row_packet(emulator, 0x12, 0xF800)

        self.assertEqual(emulator.frame_sequence, 7)
        self.assertNotEqual(emulator._lcd_protocol, "byte-row-rgb565")
        self.assertFalse(any(emulator.framebuffer))

    def test_byte_row_rgb565_interleaving_replays_and_resets(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        self._write_byte_row_packet(emulator, 0x05, 0x14)
        self._write_byte_row_packet(emulator, 0x10, 0)
        self._write_byte_row_packet(emulator, 0x11, 3)
        for _ in range(7):
            self._write_byte_row_packet(emulator, 0x12, 0xF800)
        emulator._lcd_write(None, 0, 0x02000004, 1, 0, None)

        self.assertEqual(emulator.frame_sequence, 7)
        self.assertFalse(any(emulator.framebuffer))
        self._write_byte_row_packet(emulator, 0x05, 0x14)
        self._write_byte_row_packet(emulator, 0x10, 0)
        self._write_byte_row_packet(emulator, 0x11, 4)
        for _ in range(128):
            self._write_byte_row_packet(emulator, 0x12, 0x001F)
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator.display_frame[4 * 128 * 3:4 * 128 * 3 + 3],
                         bytes((0, 0, 255)))

    def test_byte_row_rgb565_mismatch_replays_each_event_once(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        replayed = []
        emulator._lcd_route_write = lambda *event: replayed.append(event[2:5])
        handled = True
        for address, value in ((0x02000000, 0), (0x02000000, 0x06),
                               (0x02000002, 0), (0x02000002, 1)):
            handled = emulator._lcd_byte_020_row_write(address, 1, value)

        self.assertTrue(handled)
        self.assertEqual(replayed, [
            (0x02000000, 1, 0), (0x02000000, 1, 0x06),
            (0x02000002, 1, 0), (0x02000002, 1, 1),
        ])

    def test_byte_row_rgb565_zero_row_clears_published_pixels(self) -> None:
        emulator = self._routing_emulator(width=128, height=160)
        for pixel in (0xF800, 0):
            self._write_byte_row_packet(emulator, 0x05, 0x14)
            self._write_byte_row_packet(emulator, 0x10, 0)
            self._write_byte_row_packet(emulator, 0x11, 3)
            for _ in range(128):
                self._write_byte_row_packet(emulator, 0x12, pixel)

        row = 3 * 128 * 3
        self.assertEqual(emulator.display_frame[row:row + 128 * 3],
                         bytes(128 * 3))

    def test_cursor_bgr444_sequence_updates_exact_horizontal_run(self) -> None:
        emulator = self._blank_emulator(visible=False, width=128, height=160)
        for command, argument in ((0x03, 1), (0x05, 2)):
            self.assertTrue(emulator._lcd_bgr444_begin_command(2, command))
            self.assertTrue(emulator._lcd_bgr444_feed(2, argument))
        self.assertTrue(emulator._lcd_bgr444_begin_command(2, 0x0B))
        self.assertTrue(emulator._lcd_bgr444_feed(2, 0x00FF))
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
                self.assertTrue(emulator._lcd_bgr444_feed(2, 0x00FF))
        self.assertFalse(emulator._lcd_bgr444_begin_command(2, 0x2B))

        self.assertEqual((emulator.config.width, emulator.config.height), (128, 160))
        self.assertEqual(emulator.display_frame[:3], bytes((0, 255, 255)))

    def test_cursor_bgr444_replaces_chunk_flushed_gram_fallback(self) -> None:
        emulator = self._blank_emulator(
            visible=True, geometry_source="runtime:gram"
        )
        for y in range(160):
            for command, argument in ((0x03, 0), (0x05, y)):
                self.assertTrue(
                    emulator._lcd_bgr444_begin_command(2, command)
                )
                self.assertTrue(emulator._lcd_bgr444_feed(2, argument))
            self.assertTrue(emulator._lcd_bgr444_begin_command(2, 0x0B))
            for _ in range(128):
                self.assertTrue(emulator._lcd_bgr444_feed(2, 0x00FF))
        self.assertFalse(emulator._lcd_bgr444_begin_command(2, 0x2B))

        self.assertEqual(
            (emulator.config.width, emulator.config.height), (128, 160)
        )
        self.assertEqual(
            emulator.config.display_geometry_source,
            "runtime:cursor-bgr444",
        )
        self.assertEqual(emulator.display_frame[:3], bytes((0, 255, 255)))

    def test_cursor_bgr444_uses_rgb_nibble_order(self) -> None:
        emulator = self._blank_emulator(visible=False)

        self.assertEqual(emulator._lcd_bgr444_rgb565(0x0F00), 0xF800)
        self.assertEqual(emulator._lcd_bgr444_rgb565(0x000F), 0x001F)

    def test_page_lcd_publish_records_proven_protocol(self) -> None:
        emulator = self._blank_emulator(visible=False)
        emulator._lcd_protocol = "direct"
        emulator._lcd_page_bits_per_pixel = 1
        emulator._lcd_page_port = 0x02000000
        emulator._lcd_page_current = 0
        emulator._lcd_page_column_ready = True
        emulator._lcd_page_qualified = True
        renders = []
        emulator._lcd_page_render_current = lambda: renders.append(1) or True

        self.assertTrue(emulator._lcd_page_feed_data(0x02000004, 1, 1))
        emulator._lcd_page_flush_current()
        emulator._lcd_page_flush_current()

        self.assertEqual(emulator._lcd_frame_protocol, "page-1bpp")
        self.assertEqual(renders, [1])

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

    def test_page_lcd_cached_shades_match_all_two_plane_bytes(self) -> None:
        emulator = self._blank_emulator(visible=False, width=1, height=8)
        emulator._lcd_page_width = 1
        emulator._lcd_page_height = 8
        emulator._lcd_page_bits_per_pixel = 2
        emulator._lcd_page_ram = bytearray(16 * 256)

        for first in range(256):
            for second in range(256):
                emulator._lcd_page_ram[:2] = bytes((first, second))
                emulator._lcd_page_render_column(0, 0)
                expected = bytes(
                    channel
                    for bit in range(8)
                    for channel in (((((first >> bit) & 1) << 1)
                                      | ((second >> bit) & 1)) * 85,) * 3
                )
                self.assertEqual(emulator.framebuffer, expected)

        self.assertEqual(len(emulator._lcd_page_shade_cache), 1024)
        self.assertFalse(emulator._lcd_page_render_column(0, 0))

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

    def test_028_full_raster_promotes_left_aligned_rgb444(self) -> None:
        emulator = self._routing_emulator(width=120, height=160)
        emulator.config.display_geometry_source = "auto-default"
        emulator._lcd_protocol = "parallel-2"
        for address, value in (
            (0x02800000, 0x75), (0x02800004, 0),
            (0x02800004, 159), (0x02800000, 0x15),
            (0x02800004, 0), (0x02800004, 119),
            (0x02800000, 0x5C),
        ):
            emulator._lcd_write(None, 0, address, 2, value, None)
        payload = [0xF000, 0x0F00, 0x00F0, 0x25F0]
        payload += [(value << 12) | (value << 8) | (value << 4)
                    for value in range(16)]
        payload += [0xFFF0] * (120 * 160 - len(payload))
        for value in payload:
            emulator._lcd_write(None, 0, 0x02800004, 2, value, None)

        self.assertTrue(emulator._lcd_028_rgb444_qualified)
        self.assertEqual(emulator._lcd_frame_protocol, "direct-rgb444")
        self.assertEqual(emulator.config.display_geometry_source,
                         "runtime:direct-rgb444")
        self.assertEqual(emulator.display_frame[:12], bytes((
            255, 0, 0, 0, 255, 0, 0, 0, 255, 33, 85, 255,
        )))

    def test_028_rgb444_qualification_follows_low_information_frame(self) -> None:
        emulator = self._routing_emulator(width=120, height=160)
        emulator.config.display_geometry_source = "auto-default"
        emulator._lcd_protocol = "parallel-2"

        def frame(payload: list[int]) -> None:
            for address, value in (
                (0x02800000, 0x75), (0x02800004, 0),
                (0x02800004, 159), (0x02800000, 0x15),
                (0x02800004, 0), (0x02800004, 119),
                (0x02800000, 0x5C),
            ):
                emulator._lcd_write(None, 0, address, 2, value, None)
            for value in payload:
                emulator._lcd_write(None, 0, 0x02800004, 2, value, None)

        frame([0xFFF0] * (120 * 160))
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_frame_protocol, "direct")
        self.assertFalse(emulator._lcd_028_rgb444_qualified)
        self.assertEqual(emulator._lcd_028_direct_probe, [])

        varied = [0xF000, 0x0F00, 0x00F0, 0x25F0]
        varied += [(value << 12) | (value << 8) | (value << 4)
                   for value in range(16)]
        frame(varied + [0xFFF0] * (120 * 160 - len(varied)))
        self.assertEqual(emulator.frame_sequence, 9)
        self.assertEqual(emulator._lcd_frame_protocol, "direct-rgb444")
        self.assertTrue(emulator._lcd_028_rgb444_qualified)
        self.assertEqual(emulator._lcd_028_direct_probe, [])

    def test_028_be_word_packets_require_initializer_and_stream_22(self) -> None:
        def packet(target: GenericMSMEmulator, command: int, data: int) -> None:
            for address, value in (
                    (0x02800000, command >> 8),
                    (0x02800000, command & 0xFF),
                    (0x02800002, data >> 8),
                    (0x02800002, data & 0xFF)):
                target._lcd_write(None, 0, address, 1, value, None)

        miss = self._routing_emulator(width=176, height=220)
        packet(miss, 0, 2)
        self.assertFalse(miss._lcd_028_be_word_qualified)
        self.assertEqual(miss._lcd_028_be_word_events, [])

        emulator = self._routing_emulator(width=176, height=220)
        for command, data in ((0, 1), (3, 0x6478), (12, 1),
                              (4, 0x0648), (3, 0x6C78)):
            packet(emulator, command, data)
        self.assertTrue(emulator._lcd_028_be_word_qualified)
        for command, data in ((0x16, 0x7F00), (0x17, 0x8E00),
                              (0x21, 0), (0x22, 0xF800),
                              (0x22, 0x07E0), (0x07, 0)):
            packet(emulator, command, data)

        self.assertEqual((emulator.config.width, emulator.config.height),
                         (128, 143))
        self.assertEqual(emulator.display_frame[:6],
                         bytes((255, 0, 0, 0, 255, 0)))

    def test_028_byte_rgb332_requires_complete_full_window(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)

        def frame(target: GenericMSMEmulator, x1: int, payload: bytes) -> None:
            for address, value in ((0x02800000, 0x75), (0x02800004, 0),
                                   (0x02800004, 159), (0x02800000, 0x15),
                                   (0x02800004, 0), (0x02800004, x1),
                                   (0x02800000, 0x5C)):
                target._lcd_write(None, 0, address, 1, value, None)
            for value in payload:
                target._lcd_write(None, 0, 0x02800004, 1, value, None)

        frame(emulator, 119, bytes((0xFD,)) * (120 * 160))
        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))
        self.assertEqual(emulator._lcd_protocol, "direct-rgb332")
        self.assertEqual(emulator.display_frame[:3], bytes((255, 255, 85)))
        self.assertEqual(emulator.frame_sequence, 8)

        for address, value in ((0x02800000, 0x75), (0x02800004, 2),
                               (0x02800004, 2), (0x02800000, 0x15),
                               (0x02800004, 1), (0x02800004, 1),
                               (0x02800000, 0x5C), (0x02800004, 0xFF)):
            emulator._lcd_write(None, 0, address, 1, value, None)
        pixel = (2 * 120 + 1) * 3
        self.assertEqual(emulator.display_frame[pixel:pixel + 3], b"\xff\xff\xff")

        for address, value in ((0x02800000, 0x75), (0x02800004, 3),
                               (0x02800004, 3), (0x02800000, 0x15),
                               (0x02800004, 2), (0x02800004, 2),
                               (0x02800000, 0x5C), (0x02800004, 0xE3)):
            emulator._lcd_write(None, 0, address, 2, value, None)
        pixel = (3 * 120 + 2) * 3
        self.assertEqual(emulator.display_frame[pixel:pixel + 3], b"\xff\x00\xff")
        self.assertEqual(emulator._lcd_protocol, "direct-rgb332")

        for address, value in ((0x02800000, 0x75), (0x02800004, 4),
                               (0x02800004, 4), (0x02800000, 0x15),
                               (0x02800004, 3), (0x02800004, 3),
                               (0x02800000, 0x5C), (0x02800004, 0xF800)):
            emulator._lcd_write(None, 0, address, 2, value, None)
        pixel = (4 * 120 + 3) * 3
        self.assertEqual(emulator.display_frame[pixel:pixel + 3], b"\xff\x00\x00")
        self.assertEqual(emulator._lcd_protocol, "direct")

        near_miss = self._routing_emulator(width=176, height=220)
        frame(near_miss, 62, bytes((0xFF,)) * (63 * 160))
        self.assertEqual((near_miss.config.width, near_miss.config.height), (176, 220))
        self.assertFalse(near_miss._lcd_028_rgb332_qualified)

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

    def test_parallel_44_45_window_promotes_full_geometry(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        for command, value in ((0x44, 0x7F00), (0x45, 0x9F00)):
            emulator._lcd_write(None, 0, 0x02000000, 2, command, None)
            emulator._lcd_write(None, 0, 0x02000002, 2, value, None)
        emulator._lcd_write(None, 0, 0x02000000, 2, 0x22, None)

        self.assertEqual((emulator.config.width, emulator.config.height),
                         (128, 160))
        self.assertEqual(emulator.config.display_geometry_source,
                         "runtime:direct-window")
        self.assertEqual(emulator._lcd_expected, 128 * 160)

        near_miss = self._routing_emulator(width=176, height=220)
        for command, value in ((0x44, 0x7E00), (0x45, 0x9F00)):
            near_miss._lcd_write(None, 0, 0x02000000, 2, command, None)
            near_miss._lcd_write(None, 0, 0x02000002, 2, value, None)
        near_miss._lcd_write(None, 0, 0x02000000, 2, 0x22, None)
        self.assertEqual((near_miss.config.width, near_miss.config.height),
                         (176, 220))
        self.assertEqual(near_miss._lcd_window_axis_mask, 0)

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

    def test_qualified_byte_020_page_scan_accepts_halfword_continuation(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        emulator._lcd_page_width_hint = None

        for size, first in ((1, 1), (2, 2)):
            for page in range(16):
                for command in (0xB0 + page, 0x10, 0x00):
                    emulator._lcd_write(
                        None, 0, 0x02000000, size, command, None
                    )
                values = bytes((first,)) + bytes(255) if page == 0 else bytes(256)
                for value in values:
                    emulator._lcd_write(
                        None, 0, 0x02000004, size, value, None
                    )
            emulator._lcd_write(None, 0, 0x02000000, size, 0xB0, None)

        self.assertEqual(emulator._lcd_frame_protocol, "page-1bpp")
        self.assertEqual(emulator._lcd_raw_counts[(0x02000004, 2)], 0)
        self.assertEqual(emulator.display_frame[:3], b"\0\0\0")
        self.assertEqual(emulator.display_frame[256 * 3:256 * 3 + 3], b"\xff" * 3)

    def test_unqualified_all_low_byte_raw_raster_still_publishes(self) -> None:
        emulator = self._blank_emulator(visible=False, width=128, height=128)
        port = (0x02000004, 2)
        for _ in range(128 * 128):
            emulator._capture_raw_lcd_stream(0x02000004, 2, 0x001F)

        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_raw_frames[port], 1)

    def test_paired_fifo_rgb565_requires_every_word_pair(self) -> None:
        def write_pair(target: GenericMSMEmulator, pixel: int) -> None:
            target._capture_raw_lcd_stream(
                0x02000080, 2, (pixel & 0xF800) | ((pixel & 0x07FF) >> 1)
            )
            target._capture_raw_lcd_stream(0x02000080, 2, pixel << 1 & 0xFFFF)

        emulator = self._routing_emulator(width=176, height=220)
        emulator.frame_sequence = 0
        for index in range(120 * 160):
            write_pair(emulator, (0xF81F, 0x07E0)[index & 1])

        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))
        self.assertEqual(emulator._lcd_frame_protocol, "paired-fifo-rgb565")
        self.assertEqual(emulator.display_frame[:6], b"\xff\0\xff\0\xff\0")

        first_sequence = emulator.frame_sequence
        for _ in range(120 * 160):
            write_pair(emulator, 0x001F)
        self.assertEqual(emulator.frame_sequence, first_sequence + 1)
        self.assertEqual(emulator._lcd_frame_protocol, "paired-fifo-rgb565")
        self.assertEqual(emulator.display_frame[:3], b"\0\0\xff")

        near_miss = self._routing_emulator(width=176, height=220)
        near_miss.frame_sequence = 0
        for index in range(120 * 160):
            pixel = 0x001F
            first = (pixel & 0xF800) | ((pixel & 0x07FF) >> 1)
            second = pixel << 1 & 0xFFFF
            near_miss._capture_raw_lcd_stream(0x02000080, 2, first)
            near_miss._capture_raw_lcd_stream(
                0x02000080, 2, second ^ (4 if index == 120 * 160 - 1 else 0)
            )

        self.assertEqual((near_miss.config.width, near_miss.config.height), (160, 240))
        self.assertEqual(near_miss._lcd_frame_protocol, "raw-fifo@0x02000080")

    def test_shifted_pair_fifo_rgb565_requires_full_relation(self) -> None:
        pixels = 176 * 220

        def write_pair(target: GenericMSMEmulator, address: int,
                       pixel: int) -> None:
            target._capture_raw_lcd_stream(
                address, 2,
                ((pixel >> 8) & 0x7) | ((pixel >> 7) & 0x1F0),
            )
            target._capture_raw_lcd_stream(
                address, 2, pixel << 1 & 0xFFFF
            )

        for address in (0x02000002, 0x0200007A):
            with self.subTest(address=address):
                emulator = self._routing_emulator(width=176, height=220)
                first_sequence = emulator.frame_sequence
                for index in range(pixels):
                    write_pair(emulator, address, (0xF81F, 0x07E0)[index & 1])
                    if index + 1 == pixels // 2:
                        self.assertEqual(emulator.frame_sequence, first_sequence)

                self.assertEqual(emulator.frame_sequence, first_sequence + 1)
                self.assertEqual(
                    emulator.config.display_geometry_source,
                    "runtime:shifted-pair-fifo-rgb565",
                )
                self.assertEqual(
                    emulator._lcd_frame_protocol,
                    "shifted-pair-fifo-rgb565",
                )
                self.assertEqual(
                    emulator.display_frame[:6], b"\xff\0\xff\0\xff\0"
                )

                for _ in range(pixels):
                    write_pair(emulator, address, 0x001F)
                self.assertEqual(emulator.frame_sequence, first_sequence + 2)
                self.assertEqual(emulator.display_frame[:3], b"\0\0\xff")

        near_miss = self._routing_emulator(width=176, height=220)
        first_sequence = near_miss.frame_sequence
        for index in range(pixels // 2):
            pixel = 0xF81F
            near_miss._capture_raw_lcd_stream(
                0x0200007A, 2,
                ((pixel >> 8) & 0x7) | ((pixel >> 7) & 0x1F0),
            )
            near_miss._capture_raw_lcd_stream(
                0x0200007A, 2,
                (pixel << 1 & 0xFFFF) ^ (1 if index + 1 == pixels // 2 else 0),
            )
        self.assertEqual(near_miss.frame_sequence, first_sequence + 1)
        self.assertEqual(
            near_miss.config.display_geometry_source, "auto-default"
        )
        self.assertEqual(
            near_miss._lcd_frame_protocol, "raw-fifo@0x0200007A"
        )

    def test_shifted_pair_segment_ignores_rolling_prefix(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        emulator._lcd_write(None, 0, 0x02000000, 2, 0x0E, None)
        emulator._lcd_write(None, 0, 0x02000002, 2, 0x1234, None)
        emulator._lcd_write(None, 0, 0x02000000, 2, 0x44, None)
        for index in range(176 * 220):
            pixel = (0xF81F, 0x07E0)[index & 1]
            for value in (
                    ((pixel >> 8) & 0x7) | ((pixel >> 7) & 0x1F0),
                    pixel << 1 & 0xFFFF):
                emulator._lcd_write(
                    None, 0, 0x02000002, 2, value, None
                )
        emulator._lcd_write(None, 0, 0x02000000, 2, 0, None)

        self.assertEqual(
            emulator.config.display_geometry_source,
            "runtime:shifted-pair-fifo-rgb565",
        )
        self.assertEqual(
            emulator._lcd_frame_protocol, "shifted-pair-fifo-rgb565"
        )
        self.assertEqual(emulator.display_frame[:6], b"\xff\0\xff\0\xff\0")
        self.assertEqual(emulator._lcd_raw_counts[(0x02000002, 2)], 0)

    def test_shifted_pair_rolling_publish_is_not_repeated_at_segment_end(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        sequence = emulator.frame_sequence
        pixel = 0x001F
        pair = (
            ((pixel >> 8) & 0x7) | ((pixel >> 7) & 0x1F0),
            pixel << 1 & 0xFFFF,
        )
        for _ in range(176 * 220):
            for value in pair:
                emulator._capture_raw_lcd_stream(0x02000002, 2, value)

        self.assertEqual(emulator.frame_sequence, sequence + 1)
        emulator._finish_020_raw_segment(0)
        self.assertEqual(emulator.frame_sequence, sequence + 1)

    def test_raw_lcd_capture_has_a_global_port_bound(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        owner = (0x02000000, 2)
        emulator._lcd_raw_port = owner
        for offset in range(0, 0x1000, 2):
            emulator._capture_raw_lcd_stream(0x02000000 + offset, 2, offset)

        self.assertLessEqual(len(emulator._lcd_raw_streams), 32)
        self.assertIn(owner, emulator._lcd_raw_streams)

    def test_shifted_pair_owner_rejects_foreign_direct_subwindow(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        emulator._lcd_protocol = "parallel-2"
        emulator._lcd_x[:] = [0, 1]
        emulator._lcd_y[:] = [0, 0]
        emulator._lcd_begin_command(0x22)
        emulator._lcd_feed_parallel_data(0x02800002, 2, 0x001F)
        self.assertEqual((emulator._lcd_expected, emulator._lcd_streamed), (2, 1))

        for _ in range(176 * 220):
            emulator._capture_raw_lcd_stream(0x02000002, 2, 0x01F0)
            emulator._capture_raw_lcd_stream(0x02000002, 2, 0xF03E)
        sequence = emulator.frame_sequence
        frame = emulator.display_frame
        self.assertEqual((emulator._lcd_expected, emulator._lcd_streamed), (0, 0))
        emulator._lcd_begin_command(0)
        self.assertEqual(emulator.frame_sequence, sequence)

        emulator._lcd_protocol = "parallel-2"
        emulator._lcd_x[:] = [0, 0]
        emulator._lcd_y[:] = [0, 0]
        emulator._lcd_begin_command(0x22)
        emulator._lcd_feed_parallel_data(0x02800002, 2, 0x001F)

        self.assertEqual(emulator.frame_sequence, sequence)
        self.assertEqual(emulator.display_frame, frame)
        self.assertEqual(emulator._lcd_streamed, 0)

        emulator._lcd_begin_command(0x22)
        emulator._lcd_feed_parallel_data(0x02000002, 2, 0x001F)
        self.assertEqual(emulator.frame_sequence, sequence + 1)
        self.assertEqual(emulator.display_frame[:3], b"\0\0\xff")

    def test_020_raw_120x160_requires_full_word_terminator(self) -> None:
        def write_frame(target: GenericMSMEmulator, pixel: int) -> None:
            for _ in range(120 * 160):
                target._lcd_write(None, 0, 0x02000002, 2, pixel, None)
            target._lcd_write(None, 0, 0x02000000, 2, 0x1002, None)

        emulator = self._routing_emulator(width=176, height=220)
        write_frame(emulator, 0)
        self.assertEqual((emulator.config.width, emulator.config.height), (176, 220))
        self.assertEqual(emulator.frame_sequence, 7)

        write_frame(emulator, 0xF81F)
        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))
        self.assertEqual(emulator._lcd_frame_protocol, "raw-fifo@0x02000002")
        self.assertEqual(emulator.display_frame[:3], b"\xff\0\xff")

        near_miss = self._routing_emulator(width=176, height=220)
        for _ in range(120 * 160 - 1):
            near_miss._lcd_write(None, 0, 0x02000002, 2, 0xF81F, None)
        near_miss._lcd_write(None, 0, 0x02000000, 2, 0x1002, None)
        self.assertEqual((near_miss.config.width, near_miss.config.height), (176, 220))
        self.assertEqual(near_miss.frame_sequence, 7)

    def test_packed_fifo_rgb666_requires_two_bit_first_word(self) -> None:
        def write_pair(target: GenericMSMEmulator, pixel: int) -> None:
            target._capture_raw_lcd_stream(0x02000080, 2, pixel >> 16)
            target._capture_raw_lcd_stream(0x02000080, 2, pixel & 0xFFFF)

        emulator = self._routing_emulator(width=176, height=220)
        emulator.frame_sequence = 0
        pixels = (0x3F000, 0x00FC0, 0x0003F)
        for index in range(120 * 160):
            write_pair(emulator, pixels[index % len(pixels)])

        self.assertEqual((emulator.config.width, emulator.config.height), (120, 160))
        self.assertEqual(emulator._lcd_frame_protocol, "packed-fifo-rgb666")
        self.assertEqual(emulator.display_frame[:9], b"\xff\0\0\0\xff\0\0\0\xff")

        first_sequence = emulator.frame_sequence
        for _ in range(120 * 160):
            write_pair(emulator, 0x0003F)
        self.assertEqual(emulator.frame_sequence, first_sequence + 1)
        self.assertEqual(emulator._lcd_frame_protocol, "packed-fifo-rgb666")
        self.assertEqual(emulator.display_frame[:3], b"\0\0\xff")

        near_miss = self._routing_emulator(width=176, height=220)
        near_miss.frame_sequence = 0
        for index in range(120 * 160):
            pixel = pixels[index % len(pixels)]
            write_pair(near_miss, pixel | (0x40000 if index == 0 else 0))

        self.assertEqual((near_miss.config.width, near_miss.config.height), (160, 240))
        self.assertEqual(near_miss._lcd_frame_protocol, "raw-fifo@0x02000080")

    @staticmethod
    def _write_window_raw8_separate(emulator: GenericMSMEmulator,
                                    x0: int, x1: int, y0: int, y1: int,
                                    payload: bytes) -> None:
        for command, values in ((0x07, (x0, x1)), (0x06, (y0, y1)),
                                (0x08, payload)):
            emulator._lcd_write(None, 0, 0x02000000, 1, command, None)
            for value in values:
                emulator._lcd_write(None, 0, 0x02200002, 1, value, None)

    def test_window_raw8_separate_requires_full_panel_before_publish(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        self._write_window_raw8_separate(emulator, 0, 1, 0, 1,
                                         b"\xff\xff\xff\xff")
        self.assertEqual((emulator.config.width, emulator.config.height), (176, 220))
        self.assertEqual(emulator.frame_sequence, 7)

        payload = bytearray(64 * 96)
        payload[0] = 0xFF
        payload[2 * 64 + 3] = 0x7F
        self._write_window_raw8_separate(emulator, 0, 63, 0, 95, payload)
        self.assertEqual((emulator.config.width, emulator.config.height), (64, 96))
        self.assertEqual(emulator.config.display_geometry_source, "runtime:window-raw8")
        self.assertEqual(emulator.frame_sequence, 8)
        self.assertEqual(emulator._lcd_frame_protocol, "window-raw8-gray")
        self.assertEqual(emulator.framebuffer[:3], b"\xff\xff\xff")
        offset = (2 * 64 + 3) * 3
        self.assertEqual(emulator.framebuffer[offset:offset + 3],
                         b"\x7f\x7f\x7f")

        self._write_window_raw8_separate(emulator, 1, 2, 3, 4,
                                         b"\x20\x40\x60\x80")
        self.assertEqual(emulator.frame_sequence, 9)
        offset = (3 * 64 + 1) * 3
        self.assertEqual(emulator.framebuffer[offset:offset + 3],
                         b"\x20\x20\x20")

        mismatch = self._routing_emulator(width=176, height=220)
        mismatch._lcd_write(None, 0, 0x02000000, 1, 0x07, None)
        mismatch._lcd_write(None, 0, 0x02200000, 1, 0, None)
        self.assertEqual((mismatch.config.width, mismatch.config.height),
                         (176, 220))
        self.assertEqual(mismatch.frame_sequence, 7)

    def test_window_raw8_separate_replays_invalid_endpoint(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)
        replayed = []
        emulator._lcd_route_write = (
            lambda _uc, _access, address, size, value, _data:
            replayed.append((address, size, value))
        )
        for address, value in ((0x02000000, 0x07), (0x02200002, 63),
                               (0x02200002, 64)):
            emulator._lcd_write(None, 0, address, 1, value, None)

        self.assertEqual(replayed, [
            (0x02000000, 1, 0x07), (0x02200002, 1, 63),
            (0x02200002, 1, 64),
        ])
        self.assertEqual(emulator._lcd_window_raw8_separate_stage, "")
        self.assertFalse(emulator._lcd_window_raw8_separate_events)

    def test_window_raw8_requires_full_frame_then_accepts_subwindows(self) -> None:
        emulator = self._routing_emulator(width=176, height=220)

        for value in (0x31, 0, 127, 0x21, 0, 127):
            emulator._lcd_write(None, 0, 0x02000000, 1, value, None)
        for index in range(128 * 128):
            if index == 10:
                emulator._lcd_write(
                    None, 0, 0x02000000, 1, 0x0E, None
                )
            emulator._lcd_write(
                None, 0, 0x02000002, 1, index & 0xFF, None
            )

        self.assertEqual((emulator.config.width, emulator.config.height),
                         (128, 128))
        self.assertEqual(emulator._lcd_frame_protocol,
                         "window-raw8-preview")
        self.assertEqual(emulator.display_frame[3:6], b"\x01\x01\x01")

        for value in (0x31, 0, 5, 0x21, 32, 47):
            emulator._lcd_write(None, 0, 0x02000000, 1, value, None)
        for _ in range(16 * 6):
            emulator._lcd_write(None, 0, 0x02000002, 1, 0xE0, None)
        offset = 32 * 3
        self.assertEqual(emulator.display_frame[offset:offset + 3],
                         b"\xE0\xE0\xE0")

        for value in (0x21, 0, 10, 0x31, 0, 127):
            emulator._lcd_write(None, 0, 0x02000000, 1, value, None)
        payload = bytearray(b"\xff" * (128 * 11))
        payload[0], payload[1], payload[127], payload[128] = (
            0xE0, 0x1C, 0x03, 0x00
        )
        for packed in payload:
            emulator._lcd_write(None, 0, 0x02000002, 1, packed, None)
        self.assertEqual(emulator.frame_sequence, 10)
        self.assertEqual(emulator._lcd_frame_protocol, "window-raw8-rgb332")
        self.assertEqual(emulator.display_frame[:6], b"\xff\0\0\0\xff\0")
        self.assertEqual(emulator.display_frame[127 * 3:128 * 3], b"\0\0\xff")
        self.assertEqual(emulator.display_frame[128 * 3:129 * 3], b"\0\0\0")

        mismatch = self._routing_emulator(width=176, height=220)
        replayed = []
        mismatch._lcd_route_write = (
            lambda _uc, _access, address, size, value, _data:
            replayed.append((address, size, value))
        )
        for value in (0x31, 0, 127, 0x20):
            self.assertTrue(mismatch._lcd_window_raw8_write(
                0x02000000, 1, value
            ))
        self.assertEqual(replayed, [
            (0x02000000, 1, 0x31), (0x02000000, 1, 0),
            (0x02000000, 1, 127), (0x02000000, 1, 0x20),
        ])


if __name__ == "__main__":
    unittest.main()
