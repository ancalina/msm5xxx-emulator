"""Synthetic display transfers exercise completion and rejection guards."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.devices.display.padded_gray import PaddedGray
from msm5xxx_emulator.detection.devices.display import source_writers


class PaddedGrayTests(unittest.TestCase):
    def transfer(self, panel, pixel=0x0841, padding=0):
        result = None
        data = [0] * 4 + ([pixel] * 120 + [padding] * 8) * 160
        for value in data:
            _, result = panel.write(0x02800010, 2, value)
        return result

    def test_complete_observed_transfer(self):
        frame = self.transfer(PaddedGray())
        self.assertEqual(len(frame), 128 * 160 * 3)
        self.assertEqual(frame[:12], bytes(12))
        self.assertEqual(frame[12:15], bytes((8, 8, 8)))
        self.assertEqual(frame[-12:], bytes(12))

    def test_incomplete_clear_and_non_gray_transfers_do_not_publish(self):
        panel = PaddedGray()
        for _ in range(128 * 160):
            self.assertIsNone(panel.write(0x02800010, 2, 0)[1])
        panel.write(0x02800030, 2, 0)
        self.assertIsNone(self.transfer(panel, pixel=0))
        self.assertIsNone(self.transfer(panel, pixel=0xf800))
        self.assertIsNone(self.transfer(panel, padding=1))

    def test_channel_precision_is_preserved(self):
        frame = self.transfer(PaddedGray(), pixel=0x0861)
        self.assertEqual(frame[12:15], bytes((8, 12, 8)))

    def test_complete_black_transfer_clears_a_qualified_frame(self):
        panel = PaddedGray()
        self.assertIsNotNone(self.transfer(panel))
        self.assertEqual(self.transfer(panel, pixel=0), bytes(128 * 160 * 3))

    def test_loaded_writer_change_rejects_plan(self):
        original = bytes(0x80100)
        config = SimpleNamespace(image_kind='firmware', load_address=0,
                                 image_offset=0, entry=0, missing_overlays=(),
                                 ram_bootstrap_profile=None, overlays=(),
                                 width=128, height=160,
                                 display_geometry_source='auto-default')
        context = SimpleNamespace(original=original, loaded=original, config=config)
        names = ('has_packed_window2_writer', 'find_source_packed_cursor',
                 'has_paired_page_writer', 'has_byte_paired_page_writer',
                 'has_separate_mono_page_writer', 'has_offset_mono_page_writer',
                 'has_row565_writer', 'has_binary_window_writer',
                 'find_reverse565_writer', 'find_source_packed12')
        with patch.multiple(source_writers, **{name: lambda *_: None for name in names}), \
                patch.object(source_writers, 'find_padded_gray_writer',
                             return_value=(0, 0x80000, 64, 0x80000, 0x100, 0x200)):
            capability = source_writers._decision(context)
            self.assertEqual(dict(capability.parameters)['page'], 'padded-gray')
            self.assertEqual(capability.evidence[0].locations[-1], 0x800a4)
            changed = bytearray(original)
            changed[0x80000] = 1
            context.loaded = bytes(changed)
            self.assertIsNone(source_writers._decision(context))


if __name__ == '__main__':
    unittest.main()
