import struct
import unittest

from msm5xxx_emulator.devices.display.packed2_panel import (
    Packed2Panel, find_packed2_port, _HELPER, _CONSUMER,
)


def image():
    data = bytearray(4096)
    consumer = 0x202
    helper = consumer - 0x17e
    data[helper:helper + len(_HELPER)] = _HELPER
    data[consumer:consumer + len(_CONSUMER)] = _CONSUMER
    for delta, imm, table, plane in ((4, 14, 0x400, 1), (14, 12, 0x600, 0)):
        struct.pack_into('<I', data, ((consumer + delta + 4) & ~3) + imm * 4, table)
        for n in range(256):
            struct.pack_into('<H', data, table + n * 2,
                             sum(((n >> b) & 1) << (2*b + plane) for b in range(8)))
    return data


def packet(panel, command, word):
    for address, value in ((0x2000000, 0), (0x2000000, command),
                           (0x2000002, word >> 8), (0x2000002, word & 255)):
        panel.write(address, 1, value)


def full(panel):
    for c, w in ((3, 0x504), (13, 0x7f00), (14, 0)):
        packet(panel, c, w)
    for page in range(1, 21):
        for c, w in ((5, 20), (16, 0), (17, page)):
            packet(panel, c, w)
        for _ in range(128):
            packet(panel, 18, 0xffff)
    panel.flush()


class Packed2Tests(unittest.TestCase):
    def test_static_requires_consumer_helper_and_both_complete_tables(self):
        self.assertEqual(find_packed2_port(bytes(image()))[0], 0x2000000)
        for offset in (0x84, 0x202, 0x400 + 510, 0x600 + 510, 0x240):
            data = image()
            data[offset] ^= 1
            self.assertIsNone(find_packed2_port(bytes(data))[0], hex(offset))
        self.assertIsNone(find_packed2_port(bytes(4096))[0])

    def test_qualification_partial_and_zero_clear(self):
        panel = Packed2Panel(0x2000000)
        full(panel)
        self.assertTrue(panel.qualified)
        self.assertEqual(panel.sequence, 1)
        self.assertEqual(panel.frame, bytes(128 * 160 * 3))
        packet(panel, 17, (10 << 5) | 3)
        for _ in range(6):
            packet(panel, 18, 0)
        self.assertEqual(panel.sequence, 1)
        panel.flush()
        self.assertEqual(panel.sequence, 2)
        for y in range(160):
            for x in range(128):
                self.assertEqual(panel.frame[(y*128+x)*3],
                                 255 if 16 <= y < 24 and 10 <= x < 16 else 0)
        self.assertIsNone(panel.snapshot()['enabled'])
        panel.flush()
        self.assertEqual(panel.sequence, 2)
        packet(panel, 17, 1)
        packet(panel, 18, 0)
        panel.write(0x2000000, 1, 0)
        panel.flush()
        self.assertEqual(panel.sequence, 2)
        self.assertEqual(len(panel._packet), 1)
        self.assertTrue(panel.qualified)

    def test_unqualified_short_wrong_order_and_reset(self):
        panel = Packed2Panel(0x2000000)
        for c, w in ((3, 0x504), (13, 0x7f00), (14, 0), (5, 20), (16, 0), (17, 1), (18, 0)):
            packet(panel, c, w)
        panel.flush()
        self.assertFalse(panel.qualified)
        self.assertEqual(panel._words, [0])
        packet(panel, 5, 20)
        self.assertEqual(panel.rejection, 'incomplete-full-page')
        full(panel)
        packet(panel, 17, 1)
        packet(panel, 18, 0)
        packet(panel, 3, 0x504)
        self.assertFalse(panel.qualified)
        self.assertEqual(panel._words, [])
        self.assertEqual(panel.sequence, 1)

    def test_telemetry_flush_can_split_every_byte_and_continue_partial_run(self):
        class TickPanel(Packed2Panel):
            def write(self, address, size, value):
                super().write(address, size, value)
                self.flush()

        panel = TickPanel(0x2000000)
        full(panel)
        self.assertTrue(panel.qualified)
        self.assertEqual(panel.sequence, 1)
        self.assertEqual(panel.frame, bytes(128 * 160 * 3))
        self.assertEqual(panel._next_page, 21)
        panel.flush()
        self.assertEqual(panel._next_page, 21)
        packet(panel, 17, (10 << 5) | 3)
        for _ in range(3):
            packet(panel, 18, 0)
        panel.flush()
        for _ in range(3):
            packet(panel, 18, 0)
        sequence = panel.sequence
        panel.flush()
        self.assertEqual(panel.sequence, sequence)
        self.assertEqual(len(panel._words), 6)
        for x in range(9, 17):
            self.assertEqual(panel.frame[(16 * 128 + x) * 3],
                             255 if 10 <= x < 16 else 0)

    def test_boundaries_malformed_and_foreign(self):
        panel = Packed2Panel(0x2000000)
        full(panel)
        before = panel.snapshot()
        panel.write(0x2800002, 2, 0xffff)
        self.assertEqual(panel.snapshot(), before)
        for word in (0, 21, 128 << 5 | 1):
            packet(panel, 17, word)
            self.assertEqual(panel.rejection, 'invalid-packed-address')
        packet(panel, 17, 127 << 5 | 1)
        packet(panel, 18, 0)
        packet(panel, 18, 0)
        panel.flush()
        self.assertEqual(panel.sequence, 1)
        self.assertEqual(panel.rejection, 'packed-row-overflow')
        panel.write(0x2000000, 2, 0)
        self.assertEqual(panel.rejection, 'unsupported-transfer')
        panel.write(0x2000000, 1, 0)
        panel.write(0x2000002, 1, 0)
        self.assertEqual(panel.rejection, 'malformed-packet')


if __name__ == '__main__':
    unittest.main()
