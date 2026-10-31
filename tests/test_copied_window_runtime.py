"""Source/loaded-image admission and main-window ownership boundaries."""
from collections import defaultdict, deque
from copy import deepcopy
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin


INIT = (0x2c, 2, 1, 0x20, 5, 0x22, 0x11, 0x26, 15, 0x40, 1,
        0x53, 0, 0x34, 0x86, 0x30, 0, 0x2a, 0xcc, 0x43, 0, 127,
        0x42, 0, 127, 0x10, 2)
CONTROLS = [[0x51], [0x2c, 0x51], [0x50, 0x2d], [0x50, 0x2d, 0x26, 0, 2, 0]]
FINDER = 'msm5xxx_emulator.detection.copied_window.find_copied_window_profile'


def profile():
    return dict(signature='copied-byte-range-half128-v1', admission='temporary-evidence-gated',
                role='main', command_port=0x2000000, data_port=0x2000002,
                command_width=1, access_width=2, width=128, height=128,
                protocol='copied-half128', init_commands=list(INIT),
                opaque_control_sequences=deepcopy(CONTROLS),
                ram_intervals=[[0x1000000, 0x1001000]],
                iram_intervals=[[0x3800000, 0x3800100]],
                code_intervals=[[0x100, 0x120]], literal_intervals=[[0x200, 0x204]],
                data_intervals=[[0x300, 0x310]], boot_guard_intervals=[[0, 4]])


class Harness(DisplayControllerMixin):
    def __init__(self):
        self.config = SimpleNamespace(image_kind='firmware', load_address=0,
            image_offset=0, entry=0, flash_size=0x1000, ram_base=0x1000000,
            ram_size=0x800000, width=176, height=220, display_geometry_source='auto-default')
        self.framebuffer = bytearray(176 * 220 * 3)
        self.display_frame = bytes(self.framebuffer)
        self._display_lock = threading.Lock()
        self.frame_sequence = self.firmware_frame_sequence = 0
        self._lcd_protocol, self._lcd_frame_protocol = 'parallel-2', 'none'
        self._lcd_raw_streams = defaultdict(deque)
        self._lcd_raw_counts = defaultdict(int)
        self._lcd_raw_frames = defaultdict(int)
        self._lcd_raw_segment_streams = defaultdict(deque)
        self._lcd_raw_segment_counts = defaultdict(int)

    def command(self, *values):
        for value in values:
            self._lcd_source_window_write(0x2000000, 1, value)

    def pixels(self, values):
        return [self._lcd_source_window_write(0x2000002, 2, value) for value in values]


class CopiedWindowRuntimeTests(unittest.TestCase):
    def bind(self, h, p=None, original=None, loaded=None, **kwargs):
        p = profile() if p is None else p
        original = bytes(0x1000) if original is None else original
        loaded = original if loaded is None else loaded
        with patch(FINDER, return_value=(p, 'accepted-static')):
            h._lcd_bind_source_window(original, loaded, **kwargs)

    def test_rom_content_writer_retains_chipset_scope(self):
        p = profile()
        p['writer_layout'] = 'arm-loop-count-tail-rom-content-v1'
        for chipset in ('MSM5100', 'MSM5105', 'MSM5500', 'MSM6000', None):
            h = Harness(); h.config.chipset = chipset
            self.bind(h, p)
            with self.subTest(chipset=chipset):
                self.assertEqual(h._lcd_source_window_panel is not None,
                                 chipset in ('MSM5100', 'MSM5105'))

    def test_full_bus_raster_acquires_then_rectangles_own_the_main_display(self):
        h = Harness(); self.bind(h)
        self.assertIsNotNone(h._lcd_source_window_panel)
        self.assertFalse(h._lcd_source_window_owned)
        self.assertEqual((h.config.width, h.config.height), (176, 220))
        h.command(*INIT)
        self.assertTrue(all(not v for v in h.pixels([0] * 16383)))
        self.assertTrue(h.pixels([0])[0])
        self.assertEqual(h.frame_sequence, 1)
        self.assertEqual(h.display_snapshot(), (128, 128, bytes(128 * 128 * 3)))
        h.command(0x51, 0x43, 10, 11, 0x42, 20, 21)
        before = h.display_snapshot()[2]
        h.pixels([0xf800, 0x07e0, 0x001f])
        self.assertEqual(h.display_snapshot()[2], before)
        h.pixels([0xffff])
        expected = bytearray(before)
        for x, y, rgb in [(10, 20, b'\xff\0\0'), (11, 20, b'\0\xff\0'),
                          (10, 21, b'\0\0\xff'), (11, 21, b'\xff\xff\xff')]:
            at = (y * 128 + x) * 3; expected[at:at + 3] = rgb
        self.assertEqual(h.display_snapshot()[2], bytes(expected))
        self.assertEqual(h.frame_sequence, 2)
        h.command(0x43, 10, 11, 0x42, 20, 21)
        h.pixels([0] * 4)
        self.assertEqual(h.display_snapshot()[2], before)
        self.assertEqual(h.frame_sequence, 3)
        self.assertFalse(h._lcd_source_window_write(0x2800002, 1, 0xff))
        h._set_display_geometry(96, 64, source='runtime:unbound-aux', force=True)
        h._lcd_protocol = 'page-1bpp'; h._publish_frame()
        self.assertEqual(h.frame_sequence, 3)
        self.assertEqual(h.display_snapshot(), (128, 128, before))
        h.command(0x99)
        self.assertIsNotNone(h._lcd_source_window_panel.rejection)
        self.assertTrue(h._lcd_source_window_write(0x2000002, 2, 0xffff))
        self.assertEqual(h.display_snapshot(), (128, 128, before))

    def test_incomplete_init_never_steals_existing_native_fallback(self):
        h = Harness(); self.bind(h); h.command(*INIT[:-1])
        self.assertFalse(any(h.pixels([0xffff] * 8)))
        self.assertFalse(h._lcd_source_window_owned)
        self.assertEqual(h.frame_sequence, 0)

    def test_loaded_mutations_memory_owners_and_explicit_geometry_fail_closed(self):
        for at in (0, 0x100, 0x200, 0x300):
            h = Harness(); changed = bytearray(0x1000); changed[at] = 1
            self.bind(h, loaded=bytes(changed))
            self.assertIsNone(h._lcd_source_window_panel)
        h = Harness(); changed = bytearray(0x1000); changed[0x900] = 1
        self.bind(h, loaded=bytes(changed))
        self.assertIsNotNone(h._lcd_source_window_panel)
        h = Harness(); self.bind(h, ram_claimed=True)
        self.assertIsNone(h._lcd_source_window_panel)
        h = Harness(); h.config.ram_size = 0xfff; self.bind(h)
        self.assertIsNone(h._lcd_source_window_panel)
        h = Harness(); h.config.load_address = False; self.bind(h)
        self.assertIsNone(h._lcd_source_window_panel)
        h = Harness(); h.config.display_geometry_source = 'external-config'; self.bind(h)
        self.assertIsNone(h._lcd_source_window_panel)


if __name__ == '__main__':
    unittest.main()


class MuxPageRuntimeTests(unittest.TestCase):
    def bind(self, h, p=None, loaded=None, **kwargs):
        p = profile() if p is None else p
        p.update(signature='source-external-bit4-mono96-page-v1', width=96, height=64,
                 clear_pages=10, clear_row_bytes=96, data_port=0x02000000,
                 mode_port=0x02800000, mode_mask=0x10, access_width=1)
        h.config.chipset = 'MSM5100'
        original = bytes(0x1000)
        with patch('msm5xxx_emulator.detection.mux_page.find_mux_page_profile', return_value=(p, 'source')):
            h._lcd_bind_source_mux(original, original if loaded is None else loaded, **kwargs)

    def test_source_raster_acquires_snapshot_and_geometry_ownership(self):
        h = Harness(); self.bind(h)
        self.assertIsNotNone(h._lcd_mux_page_panel)
        def write(address, value): h._lcd_source_mux_write(address, 1, value)
        def command(*values):
            write(0x02800000, 2)
            for value in values: write(0x02000000, value)
        command(0, 0xe2, 0xa4)
        for page in range(10):
            command(0xb0+page, 0x11, 0)
            write(0x02800000, 0x12)
            for _ in range(96): write(0x02000000, 0)
        command(0xaf)
        self.assertTrue(h._lcd_mux_page_owned)
        self.assertEqual(h.frame_sequence, 1)
        self.assertEqual(h.display_snapshot(), (96, 64, bytes(96*64*3)))
        h._set_display_geometry(176, 220, source='runtime:foreign', force=True)
        self.assertEqual((h.config.width, h.config.height), (96, 64))
        h.framebuffer[:] = bytes([17])*len(h.framebuffer)
        h._publish_frame()
        self.assertEqual(h.frame_sequence, 1)
        self.assertEqual(h.display_snapshot(), (96, 64, bytes(96*64*3)))

    def test_loaded_source_and_memory_owner_negatives(self):
        h = Harness(); self.bind(h, loaded=bytes(0xfff)+b'1')
        self.assertIsNone(h._lcd_mux_page_panel)
        h = Harness(); self.bind(h, ram_claimed=True)
        self.assertIsNone(h._lcd_mux_page_panel)
        h = Harness(); h.config.ram_size=16; self.bind(h)
        self.assertIsNone(h._lcd_mux_page_panel)
        h = Harness(); h.config.display_geometry_source='manual'; self.bind(h)
        self.assertIsNone(h._lcd_mux_page_panel)
