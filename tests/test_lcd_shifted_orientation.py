"""Temporary ordered scanout admission; unqualified pair streams stay linear."""
from types import SimpleNamespace
import unittest
from msm5xxx_emulator.devices.display.protocols.page import (
    PageProtocolMixin, _SHIFTED_ORIENTATION_PREFIX)


class Decoder(PageProtocolMixin):
    def __init__(self):
        self.config = SimpleNamespace(width=176, height=220)
        self._lcd_raw_streams = {}
        self.pixels = {}

    def _pixel(self, index, pixel):
        self.pixels[index] = pixel


class ShiftedOrientationTests(unittest.TestCase):
    def feed(self, decoder, events):
        for event in events:
            decoder._lcd_observe_shifted_orientation(*event)

    def publish(self, decoder, port=(0x02000002, 2)):
        pixels = list(range(176 * 220))
        decoder._lcd_publish_shifted_pixels(pixels, port)

    def test_exact_prefix_first_and_subsequent_frame(self):
        d = Decoder()
        self.feed(d, _SHIFTED_ORIENTATION_PREFIX)
        self.assertFalse(d.shifted_orientation_snapshot()['qualified'])
        self.publish(d)
        self.assertEqual((d.pixels[0], d.pixels[175], d.pixels[176]),
                         (175, 0, 351))
        self.assertTrue(d.shifted_orientation_snapshot()['qualified'])
        # Existing later initialization repeats the same mode.
        self.feed(d, ((0x02000000, 2, 0), (0x02000000, 2, 6),
                      (0x02000002, 2, 0x24), (0x02000002, 2, 0x60)))
        self.publish(d)
        self.assertEqual(d.pixels[0], 175)

    def test_unqualified_mutated_truncated_and_foreign_prefix(self):
        variants = [(), _SHIFTED_ORIENTATION_PREFIX[:-1]]
        for position in (1, 2, 6, 10):
            events = list(_SHIFTED_ORIENTATION_PREFIX)
            a, size, value = events[position]
            events[position] = (a, size, value ^ 1)
            variants.append(events)
        events = list(_SHIFTED_ORIENTATION_PREFIX)
        events[4:4] = [(0x02800000, 2, 0)]
        variants.append(events)
        variants.append([(a, 1, v) for a, _, v in _SHIFTED_ORIENTATION_PREFIX])
        variants.append([(a + 0x800000, s, v) for a, s, v in _SHIFTED_ORIENTATION_PREFIX])
        for events in variants:
            with self.subTest(events=events):
                d = Decoder()
                self.feed(d, events)
                self.publish(d)
                self.assertEqual(d.pixels[0], 0)
                self.assertFalse(d.shifted_orientation_snapshot()['qualified'])

    def test_changed_or_incomplete_mode_and_reset_revoke(self):
        for suffix in (((0x02000000, 2, 0), (0x02000000, 2, 6)),
                       ((0x02000000, 2, 0), (0x02000000, 2, 6),
                        (0x02000002, 2, 0x24), (0x02000002, 2, 0x61))):
            d = Decoder()
            self.feed(d, _SHIFTED_ORIENTATION_PREFIX)
            self.publish(d)
            self.feed(d, suffix)
            self.publish(d)
            self.assertEqual(d.pixels[0], 0)
            self.assertFalse(d.shifted_orientation_snapshot()['qualified'])
        d._lcd_raw_streams = {}
        self.feed(d, [(0x02000002, 2, 1)])
        self.publish(d)
        self.assertEqual(d.pixels[0], 0)

    def test_other_port_or_geometry_cannot_promote(self):
        d = Decoder()
        self.feed(d, _SHIFTED_ORIENTATION_PREFIX)
        self.publish(d, (0x0200007A, 2))
        self.assertEqual(d.pixels[0], 0)
        d.config.width = 175
        self.publish(d)
        self.assertEqual(d.pixels[0], 0)

    def test_changed_dimensions_and_foreign_pending_transaction(self):
        for command, values in ((0x88, (0x15D, 0)), (0x8A, (0x1B5, 0)),
                                (0x88, ()), (0x8A, ())):
            d = Decoder()
            self.feed(d, _SHIFTED_ORIENTATION_PREFIX)
            self.publish(d)
            self.feed(d, [(0x02000000, 2, 0), (0x02000000, 2, command)]
                         + [(0x02000002, 2, value) for value in values])
            self.publish(d)
            self.assertEqual(d.pixels[0], 0)
        d = Decoder()
        self.feed(d, _SHIFTED_ORIENTATION_PREFIX)
        self.publish(d)
        self.feed(d, [(0x02000000, 2, 0), (0x02000000, 2, 6),
                      (0x02000002, 2, 0x24), (0x02800002, 2, 0),
                      (0x02000002, 2, 0x60)])
        self.publish(d)
        self.assertEqual(d.pixels[0], 0)

    def test_geometry_revocation_clears_partial_mode(self):
        d = Decoder()
        self.feed(d, _SHIFTED_ORIENTATION_PREFIX)
        self.publish(d)
        self.feed(d, [(0x02000000, 2, 0), (0x02000000, 2, 6),
                      (0x02000002, 2, 0x24)])
        d.config.width = 175
        self.feed(d, [(0x02800002, 2, 0)])
        d.config.width = 176
        self.feed(d, [(0x02000002, 2, 0x60)])
        self.publish(d)
        self.assertEqual(d.pixels[0], 0)
        self.assertFalse(d.shifted_orientation_snapshot()['qualified'])

    def test_routing_geometry_promotion_and_two_complete_frames(self):
        import test_lcd_geometry as geometry
        d = geometry.LCDGeometryTests()._routing_emulator(width=176, height=220)
        for address, size, value in _SHIFTED_ORIENTATION_PREFIX:
            d._lcd_write(None, 0, address, size, value, None)
        for frame in range(2):
            for index in range(176 * 220):
                pixel = 0xF800 if index % 176 == 0 else 0x001F
                for value in (((pixel >> 8) & 7) | ((pixel >> 7) & 0x1F0),
                              pixel << 1 & 0xFFFF):
                    d._lcd_write(None, 0, 0x02000002, 2, value, None)
            # Command boundary publishes the exact relation-valid segment.
            d._lcd_write(None, 0, 0x02000000, 2, 0, None)
            self.assertEqual(d.config.display_geometry_source,
                             'runtime:shifted-pair-fifo-rgb565')
            self.assertEqual(d.display_frame[:3], b'\0\0\xff')
            self.assertEqual(d.display_frame[175 * 3:176 * 3], b'\xff\0\0')
            self.assertTrue(d.shifted_orientation_snapshot()['qualified'])
        self.assertIs(d._lcd_shifted_orientation["owner"], d._lcd_raw_streams)
        before = d.display_snapshot()
        d._lcd_write(None, 0, 0x02000000, 2, 0x22, None)
        d._lcd_write(None, 0, 0x02000002, 2, 0, None)
        self.assertEqual(d.display_snapshot(), before)


if __name__ == '__main__':
    unittest.main()
