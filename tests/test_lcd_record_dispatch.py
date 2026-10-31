"""Offline record dispatch contracts; no guest or external binary is started."""
import struct
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.qemu.transport import LCD_WRITE, RECORD_SIZE, Transport


class LCDRecordDispatchTests(unittest.TestCase):
    def transport(self):
        writes = []
        transport = object.__new__(Transport)
        transport.decoder = SimpleNamespace(
            uc=object(), _lcd_write=lambda *args: writes.append(args))
        return transport, writes

    def test_batch_matches_single_records_and_retains_non_lcd_order(self):
        batch, writes = self.transport()
        single, expected = self.transport()
        single.decoder.uc = batch.decoder.uc
        seen = []
        batch._replay_record = lambda record: seen.append((len(writes), record))
        records = [
            struct.pack('<BBHIII', LCD_WRITE, 2, 0xabcd, 0x02000002,
                        0xfedcba98, 0x76543210),
            struct.pack('<BBHIII', 0xff, 9, 0x1234, 1, 2, 3),
            struct.pack('<BBHIII', LCD_WRITE, 1, 0, 0x02c00004, 0x81, 0),
        ]
        pending = bytearray(b''.join(records) + b'tail')
        with memoryview(pending)[:3 * RECORD_SIZE] as view:
            batch._replay_records(view)
        # No exported view remains after dispatch; real receive buffers resize.
        del pending[:3 * RECORD_SIZE]
        self.assertEqual(pending, b'tail')
        for record in (records[0], records[2]):
            single._replay_record(record)
        self.assertEqual(writes, expected)
        self.assertEqual(seen, [(1, records[1])])
        self.assertEqual(writes[0][2:5], (0x02000002, 2, 0xfedcba98))

    def test_empty_batch(self):
        transport, writes = self.transport()
        with memoryview(b'') as view:
            transport._replay_records(view)
        self.assertEqual(writes, [])
