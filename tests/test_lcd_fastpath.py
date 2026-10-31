"""Fast/slow decoder equivalence on synthetic bus traffic, without a CPU."""
import random
import unittest
from unittest.mock import patch

import test_lcd_geometry as fixtures
from msm5xxx_emulator.devices.display.page_panel import PagePanel


class LCDFastpathTests(unittest.TestCase):
    def pair(self):
        helper = fixtures.LCDGeometryTests()
        fast = helper._routing_emulator(width=128, height=128)
        slow = helper._routing_emulator(width=128, height=128)
        slow._lcd_bind_fast_write = lambda *args: None
        return fast, slow

    def replay(self, pair, events):
        for address, size, value in events:
            for device in pair:
                device._lcd_write(None, 0, address, size, value, None)
            fast, slow = pair
            self.assertEqual(fast.display_snapshot(), slow.display_snapshot())
            for name in ('framebuffer', 'frame_sequence', 'lcd_writes',
                         'lcd_port_writes', '_lcd_protocol', '_lcd_command',
                         '_lcd_args', '_lcd_page_ram', '_lcd_page_qualified',
                         '_lcd_page_column', '_lcd_page_data_count'):
                self.assertEqual(getattr(fast, name), getattr(slow, name), name)
            if getattr(fast, '_lcd_secondary_panel', None):
                self.assertEqual(vars(fast._lcd_secondary_panel),
                                 vars(slow._lcd_secondary_panel))

    def test_parallel_pixels_publish_identical_frames_and_interrupt(self):
        pair = self.pair()
        self.replay(pair, [(0x02800002, 2, 0), (0x02000000, 2, 0x2c)])
        self.replay(pair, [(0x02800002, 2, color)
                           for color in (0xf800, 0x7e0, 0x1f, 0xffff) * 4096])
        self.assertIsNotNone(pair[0]._lcd_fast_write)
        self.assertGreater(pair[0].frame_sequence, 7)
        self.replay(pair, [(0x02000000, 2, 0x2c), (0x02800002, 1, 0xf8),
                           (0x02800002, 1, 0), (0x02000000, 2, 0x15),
                           (0x02800002, 2, 0), (0x02800002, 2, 127)])

    def test_parallel_register_binding_matches_slow_for_every_opcode(self):
        pair = self.pair()
        for command in (*range(256), 0x100, 0xffff):
            with self.subTest(command=command):
                self.replay(pair, [(0x02000000, 2, command)])
                self.replay(pair, [(0x02800002, 2, value)
                                   for value in (0, 127, 0xf800, 0x1234, 0xffff)])

    def test_telemetry_protocol_change_invalidates_idle_binding(self):
        pair = self.pair()
        self.replay(pair, [(0x02800002, 2, 0), (0x02800002, 2, 1)])
        self.assertIsNotNone(pair[0]._lcd_fast_write)
        for device in pair:
            device._lcd_protocol = 'page-1bpp'
        self.replay(pair, [(0x02800002, 2, 2)])
        self.assertEqual(pair[0]._lcd_protocol, 'parallel-2')

    def test_qualified_page_data_and_malformed_width(self):
        pair = self.pair()
        events = []
        for page in range(4):
            events.extend((0x02800000, 2, value) for value in (0xb0 + page, 0x10, 0))
            events.extend((0x02800004, 2, (x * 31 + page) & 255) for x in range(128))
        self.replay(pair, events)
        self.assertTrue(pair[0]._lcd_page_qualified)
        self.assertIsNotNone(pair[0]._lcd_fast_write)
        self.replay(pair, [(0x02800004, 4, 0xffff), (0x02800004, 2, 256),
                           (0x02800000, 2, 0xb4), (0x02800000, 2, 0x10),
                           (0x02800000, 2, 0), (0x02800004, 1, 0x55)])

    def test_secondary_commit_overflow_and_rejection(self):
        for data_offset in (2, 4):
            pair = self.pair()
            for device in pair:
                device._lcd_secondary_panel = PagePanel(0x02000000, data_offset=data_offset)
            events = []
            for page in range(4):
                events.extend((0x02000000, 2, value) for value in (0xb0 + page, 0x10, 0))
                events.extend(((0x02000000 + data_offset), 2, (x * 17 + page) & 255) for x in range(96))
            self.replay(pair, events)
            self.assertTrue(pair[0]._lcd_secondary_panel.committed)
            self.assertIsNotNone(pair[0]._lcd_fast_write)
            self.replay(pair, [((0x02000000 + data_offset), 2, 0xa5)] * 162)
            self.assertIsNotNone(pair[0]._lcd_secondary_panel.rejection)
            self.replay(pair, [(0x02000000, 2, 0xaf), ((0x02000000 + data_offset), 1, 3)])

    def test_steady_data_skips_observers_but_command_runs_them(self):
        fast, _slow = self.pair()
        fast._lcd_write(None, 0, 0x02800002, 2, 0, None)
        with patch.object(fast, '_lcd_write_slow', wraps=fast._lcd_write_slow) as slow:
            fast._lcd_write(None, 0, 0x02800002, 2, 0, None)
            slow.assert_not_called()
            fast._lcd_write(None, 0, 0x02800000, 2, 0xb0, None)
            slow.assert_called_once()

    def test_interrupted_held_candidates_replay_before_binding(self):
        for size in (1, 2):
            with self.subTest(size=size):
                pair = self.pair()
                self.replay(pair, [(0x02800000, size, 0),
                                   (0x02800000, size, 0x1500 if size == 2 else 0x15),
                                   (0x02800002, 2, 0x1234),
                                   (0x02800002, 2, 0x5678),
                                   (0x02800002, 2, 0xabcd)])
                self.assertIsNotNone(pair[0]._lcd_fast_write)

    def test_admitted_observers_and_source_profiles_block_binding(self):
        fast, _slow = self.pair()
        fast._lcd_protocol = 'parallel-2'
        for name, value in (('_lcd_packed2_panel', object()),
                            ('_lcd_page_source_profile', {'data_port': 0x02800002}),
                            ('_lcd_odd_page_state', {'profile': {'class': 'source'}})):
            with self.subTest(name=name):
                old = getattr(fast, name, None)
                setattr(fast, name, value)
                fast._lcd_bind_fast_write(0x02800002, 2)
                self.assertIsNone(getattr(fast, '_lcd_fast_write', None))
                if old is None:
                    delattr(fast, name)
                else:
                    setattr(fast, name, old)

    def test_page_translation_matches_scalar_at_extreme_biases(self):
        rng = random.Random(0)
        for bias in (0, 4, 160):
            panel = PagePanel(0x02000000)
            panel.ram[:] = bytes(rng.randrange(256) for _ in panel.ram)
            panel.bias, panel.dirty = bias, True
            expected = bytearray(96 * 64 * 3)
            for page in range(8):
                for x in range(96):
                    value = panel.ram[page * 256 + bias + x]
                    for bit in range(8):
                        offset = ((page * 8 + bit) * 96 + x) * 3
                        expected[offset:offset + 3] = bytes((255 if value & (1 << bit) else 0,)) * 3
            panel.flush()
            self.assertEqual(panel.frame, bytes(expected))
