import unittest
from msm5xxx_emulator.devices.display.indexed_byte_panel import IndexedBytePanel


def packet(cursor=95):
    events = []
    for command, value in ((7, 0), (8, 95), (9, 0), (10, 63), (4, cursor), (5, 0)):
        events.extend(((0x02000000, 2, command), (0x02000004, 2, value)))
    return events + [(0x02000000, 2, 12)]


class IndexedBytePanelTests(unittest.TestCase):
    def test_complete_capture_only_and_native_fallback_preserved(self):
        from test_secondary_page_panel import SecondaryPagePanelTests
        controller, fallback = SecondaryPagePanelTests().controller()
        controller._lcd_secondary_panel = None
        panel = controller._lcd_indexed_byte_panel = IndexedBytePanel(95)
        initial = controller.secondary_display_snapshot()
        self.assertEqual(len(initial['frame']), initial['width'] * initial['height'] * 3)
        self.assertFalse(initial['qualified'])
        payload = bytes(range(256)) * 24
        events = packet() + [(panel.port + 4, 2, value) for value in payload]
        for address, size, value in events[:-1]:
            controller._lcd_write(None, 0, address, size, value, None)
        self.assertFalse(controller.secondary_display_snapshot()['qualified'])
        controller._lcd_write(None, 0, *events[-1], None)
        self.assertEqual(len(fallback), len(events))
        snapshot = controller.secondary_display_snapshot()
        self.assertTrue(snapshot['qualified'])
        self.assertEqual(snapshot['frame'][::3], payload)
        self.assertEqual(snapshot['encoding'], 'unverified-byte-preview')
        self.assertIsNone(snapshot['enabled'])
        self.assertEqual(panel.sequence, 1)
        # Overflow and interrupted windows must never publish a new capture.
        panel.write(panel.port + 4, 2, 1)
        for event in packet() + [(panel.port + 4, 2, 7)] * 4032:
            panel.write(*event)
        panel.write(panel.port, 2, 3)
        self.assertEqual(panel.sequence, 1)
        self.assertEqual(panel.raw, payload)
        # Wrong cursor and wrong transfer width cannot qualify.
        for cursor in (0, 94):
            rejected = IndexedBytePanel(95)
            for event in packet(cursor) + events[13:]:
                rejected.write(*event)
            self.assertFalse(rejected.snapshot()['qualified'])
        rejected = IndexedBytePanel(0)
        for address, size, value in packet(0):
            rejected.write(address, 1, value)
        for event in events[13:]:
            rejected.write(*event)
        self.assertFalse(rejected.snapshot()['qualified'])

    def test_cursor95_partial_merge_requires_complete_base(self):
        def window(left, right, top, bottom, x=None):
            events = []
            for command, value in ((7, left), (8, right), (9, top), (10, bottom),
                                   (4, 95-left if x is None else x), (5, top)):
                events.extend(((0x02000000, 2, command), (0x02000004, 2, value)))
            return events + [(0x02000000, 2, 12)]
        def send(panel, header, payload):
            for event in header:
                panel.write(*event)
            for value in payload:
                panel.write(panel.port + 4, 2, value)
        panel = IndexedBytePanel(95)
        send(panel, window(0, 95, 0, 16), bytes([7]) * 1632)
        self.assertFalse(panel.snapshot()['qualified'])
        self.assertEqual(panel.raw, b'')
        full = bytes(range(256)) * 24
        send(panel, packet(), full)
        expected = bytearray(full)
        # Static dirty request clamped to inclusive y0..16: 96*17 bytes.
        expected[:1632] = bytes([9]) * 1632
        send(panel, window(0, 95, 0, 16), bytes([9]) * 1632)
        self.assertEqual(panel.raw, bytes(expected))
        self.assertEqual(panel.sequence, 2)
        # Source rows ascend; nonzero bounds affect only their original cells.
        for row in (20, 21, 22):
            expected[row*96+4:row*96+7] = bytes([row]) * 3
        send(panel, window(4, 6, 20, 22), bytes([20])*3 + bytes([21])*3 + bytes([22])*3)
        self.assertEqual(panel.raw, bytes(expected))
        self.assertEqual(panel.frame[::3], bytes(expected))
        self.assertEqual(panel.sequence, 3)
        # Exact prefix completes immediately; extra data never alters it.
        panel.write(panel.port + 4, 2, 255)
        self.assertEqual(panel.raw, bytes(expected))
        self.assertEqual(panel.sequence, 3)
        send(panel, window(4, 6, 20, 22), bytes([0])*8)
        panel.write(panel.port, 2, 3)
        for bad in (window(7, 6, 20, 22), window(4, 6, 20, 64),
                    window(4, 6, 20, 22, x=90)):
            send(panel, bad, bytes([0])*9)
        self.assertEqual(panel.raw, bytes(expected))
        self.assertEqual(panel.sequence, 3)
        peer = IndexedBytePanel(0)
        send(peer, packet(0), full)
        send(peer, window(4, 6, 20, 22), bytes([0])*9)
        self.assertEqual(peer.raw, full)
        self.assertEqual(peer.sequence, 1)


if __name__ == '__main__':
    unittest.main()
