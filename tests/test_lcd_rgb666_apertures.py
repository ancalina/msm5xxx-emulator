"""Packed FIFO aperture parity and ownership, using the existing LCD fixture."""
import unittest
from tests import test_lcd_geometry as geometry


class PackedRGB666ApertureTests(unittest.TestCase):
    def make(self):
        e = geometry.LCDGeometryTests()._routing_emulator(width=176, height=220)
        e.frame_sequence = 0
        return e

    @staticmethod
    def prefix(e, values=(0x0200, 0x0300, 0x0477, 0x059F, 0x0D00, 0x0E00)):
        for value in values:
            e._lcd_packed_window_observe(0x02800000, 2, value)

    @staticmethod
    def pair(e, port, pixel):
        e._lcd_packed_window_observe(port, 2, pixel >> 16)
        e._capture_raw_lcd_stream(port, 2, pixel >> 16)
        e._lcd_packed_window_observe(port, 2, pixel & 0xFFFF)
        e._capture_raw_lcd_stream(port, 2, pixel & 0xFFFF)

    def test_both_apertures_complete_pair_and_second_frame(self):
        for port in (0x02000080, 0x02800080):
            with self.subTest(port=hex(port)):
                e = self.make()
                if port == 0x02800080:
                    self.prefix(e)
                colors = (0x3F000, 0xFC0, 0x3F)
                for i in range(19200 - 1):
                    self.pair(e, port, colors[i % 3])
                e._lcd_packed_window_observe(port, 2, colors[19199 % 3] >> 16)
                e._capture_raw_lcd_stream(port, 2, colors[19199 % 3] >> 16)
                self.assertEqual(e.frame_sequence, 0)
                e._lcd_packed_window_observe(port, 2, colors[19199 % 3] & 0xFFFF)
                e._capture_raw_lcd_stream(port, 2, colors[19199 % 3] & 0xFFFF)
                self.assertEqual((e.config.width, e.config.height), (120, 160))
                self.assertEqual(e._lcd_frame_protocol, 'packed-fifo-rgb666')
                self.assertEqual(e.display_frame[:9], bytes((255,0,0,0,255,0,0,0,255)))
                seq = e.frame_sequence
                if port == 0x02800080:
                    self.prefix(e)
                for _ in range(19199):
                    self.pair(e, port, 0x3F)
                self.assertEqual(e.frame_sequence, seq)
                self.pair(e, port, 0x3F)
                self.assertEqual(e.frame_sequence, seq + 1)
                self.assertEqual(e.display_frame[:3], bytes((0,0,255)))

    def test_qualified_black_frame_is_not_rejected_as_empty_candidate(self):
        for port in (0x02000080, 0x02800080):
            with self.subTest(port=hex(port)):
                e = self.make()
                if port == 0x02800080:
                    self.prefix(e)
                for _ in range(19200):
                    self.pair(e, port, 0x3F000)
                sequence = e.frame_sequence
                if port == 0x02800080:
                    self.prefix(e)
                for _ in range(19199):
                    self.pair(e, port, 0)
                self.assertEqual(e.frame_sequence, sequence)
                self.pair(e, port, 0)
                self.assertEqual(e.frame_sequence, sequence + 1)
                self.assertEqual(e._lcd_frame_protocol, 'packed-fifo-rgb666')
                self.assertEqual(bytes(e.display_frame), bytes(120 * 160 * 3))
                self.assertEqual(e._lcd_raw_port, (port, 2))

    def test_unqualified_028_aperture_preserves_second_generic_frame(self):
        e = self.make()
        port = 0x02800080
        for _ in range(160 * 240):
            e._lcd_packed_window_observe(port, 2, 0xF800)
            e._capture_raw_lcd_stream(port, 2, 0xF800)
        self.assertEqual((e.config.width, e.config.height), (160, 240))
        self.assertEqual(e._lcd_frame_protocol, 'raw-fifo@0x02800080')
        self.assertEqual(bytes(e.display_frame), bytes((255,0,0)) * (160 * 240))
        sequence = e.frame_sequence
        for _ in range(160 * 240 - 1):
            e._lcd_packed_window_observe(port, 2, 0x07E0)
            e._capture_raw_lcd_stream(port, 2, 0x07E0)
        self.assertEqual(e.frame_sequence, sequence)
        e._lcd_packed_window_observe(port, 2, 0x07E0)
        e._capture_raw_lcd_stream(port, 2, 0x07E0)
        self.assertEqual(e.frame_sequence, sequence + 1)
        self.assertEqual(e._lcd_frame_protocol, 'raw-fifo@0x02800080')
        self.assertEqual(bytes(e.display_frame), bytes((0,255,0)) * (160 * 240))
        self.assertEqual(e._lcd_raw_port, (port, 2))

    def test_non_two_bit_high_word_keeps_generic_fallback(self):
        for port in (0x02000080, 0x02800080):
            with self.subTest(port=hex(port)):
                e = self.make()
                if port == 0x02800080:
                    self.prefix(e)
                for i in range(19200):
                    self.pair(e, port, 0x3F000 | (0x40000 if i == 0 else 0))
                self.assertEqual((e.config.width, e.config.height), (160, 240))
                self.assertEqual(e._lcd_frame_protocol, f'raw-fifo@0x{port:08X}')

    def test_other_aperture_cannot_take_qualified_packed_owner(self):
        for port, other in ((0x02000080,0x02800080),(0x02800080,0x02000080)):
            with self.subTest(port=hex(port)):
                e = self.make()
                if port == 0x02800080:
                    self.prefix(e)
                for _ in range(19200):
                    self.pair(e, port, 0x3F000)
                before = (e.frame_sequence, bytes(e.display_frame), e._lcd_raw_port)
                for _ in range(19200):
                    self.pair(e, other, 0x3F)
                self.assertEqual((e.frame_sequence, bytes(e.display_frame), e._lcd_raw_port), before)
                self.assertEqual(e._lcd_frame_protocol, 'packed-fifo-rgb666')


    def test_wrong_or_incomplete_prefix_does_not_admit(self):
        for commands in ((0x0200,0x0300,0x0476,0x059F,0x0D00,0x0E00),
                         (0x0200,0x0300,0x0477,0x059F,0x0D01,0x0E00),
                         (0x0200,0x0300,0x0477,0x059F,0x0D00)):
            e = self.make()
            self.prefix(e, commands)
            for _ in range(19200):
                self.pair(e, 0x02800080, 0x3F000)
            self.assertNotEqual(e._lcd_frame_protocol, 'packed-fifo-rgb666')

    def test_interrupted_partial_cannot_join_fresh_frame_and_reset_revokes(self):
        e = self.make()
        self.prefix(e)
        for _ in range(100):
            self.pair(e, 0x02800080, 0x3F000)
        e._lcd_packed_window_observe(0x0280007C, 2, 1)
        self.prefix(e)
        for _ in range(19199):
            self.pair(e, 0x02800080, 0x3F)
        self.assertEqual(e.frame_sequence, 0)
        self.pair(e, 0x02800080, 0x3F)
        self.assertEqual(e.display_frame[:3], bytes((0,0,255)))
        before = (e.frame_sequence, bytes(e.display_frame))
        for _ in range(19200):
            self.pair(e, 0x02800080, 0x3F000)
        self.assertEqual((e.frame_sequence, bytes(e.display_frame)), before)
        self.prefix(e)
        e._lcd_raw_streams = {}
        e._lcd_packed_window_observe(0x02800080, 2, 0)
        self.assertFalse(e._lcd_packed_window_armed)

if __name__ == '__main__':
    unittest.main()
