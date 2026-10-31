"""Synthetic command/data mux, clear proof and retained viewport checks."""
import unittest
from msm5xxx_emulator.devices.display.mux_page_panel import MuxPagePanel


class MuxPagePanelTests(unittest.TestCase):
    def command(self, panel, *values):
        panel.write(0x02800000, 1, 2)
        for value in values:
            panel.write(0x02000000, 1, value)

    def data(self, panel, values):
        panel.write(0x02800000, 1, 0x12)
        for value in values:
            panel.write(0x02000000, 1, value)

    def clear(self, panel, pages=range(10)):
        for page in pages:
            self.command(panel, 0xa1, 0xb0+page, 0x11, 0)
            self.data(panel, [0]*96)
        self.command(panel, 0xaf)

    def started(self):
        panel = MuxPagePanel()
        self.command(panel, 0, 0xe2, 0xa4)
        return panel

    def test_ten_clear_pages_qualify_an_eight_page_viewport(self):
        panel = self.started(); self.clear(panel)
        self.assertTrue(panel.qualified)
        self.assertEqual(panel.sequence, 1)
        self.assertEqual(panel.frame, bytes(96*64*3))
        self.command(panel, 0xa1, 0xb0, 0x11, 0)
        self.data(panel, [1, 0x80])
        self.assertEqual(panel.sequence, 1)
        self.command(panel, 0xaf)
        expected = bytearray(96*64*3)
        expected[:3] = bytes([255])*3
        expected[(7*96+1)*3:(7*96+1)*3+3] = bytes([255])*3
        self.assertEqual(panel.frame, bytes(expected))
        self.command(panel, 0xb9, 0x11, 0); self.data(panel, [255]*96)
        self.command(panel, 0xaf)
        self.assertEqual(panel.frame, bytes(expected))
        self.command(panel, 0xb0, 0x11, 0); self.data(panel, [2])
        self.command(panel, 0xb1)
        self.assertEqual(panel.sequence, 3)  # Retained updates need no extra AF.

    def test_incomplete_nonzero_and_disordered_clear_do_not_qualify(self):
        for pages in (range(8), range(9), (0, 1, 3, 4, 5, 6, 7, 8, 9)):
            panel = self.started(); self.clear(panel, pages)
            self.assertFalse(panel.qualified)
            self.assertEqual(panel.sequence, 0)
        panel = self.started()
        self.command(panel, 0xb0, 0x11, 0); self.data(panel, [1]*96)
        self.clear(panel, range(1, 10))
        self.assertFalse(panel.qualified)

    def test_reset_requires_fresh_clear_and_mode_gate_is_required(self):
        panel = MuxPagePanel()
        for value in (0, 0xe2, 0xa4):
            panel.write(0x02000000, 1, value)
        self.assertFalse(panel.started)
        panel = self.started(); self.clear(panel)
        self.command(panel, 0xe2)
        self.assertFalse(panel.qualified)
        self.clear(panel)
        self.assertTrue(panel.qualified)
        self.command(panel, 0xb0, 0x11, 0)
        panel.write(0x02800000, 2, 0x12)
        self.assertEqual(panel.rejection, 'source-byte-mux-width-required')

    def test_column_bias_overflow_and_foreign_ports(self):
        panel = self.started()
        self.assertFalse(panel.write(0x02800002, 1, 17))
        self.assertIsNone(panel.rejection)
        self.clear(panel)
        self.command(panel, 0xb0, 0x10, 0)
        self.assertEqual(panel.rejection, 'column-outside-source-viewport')
        panel = self.started()
        self.command(panel, 0xb0, 0x11, 0); self.data(panel, [0]*97)
        self.assertEqual(panel.rejection, 'data-outside-source-page-column')
        panel = self.started()
        self.assertFalse(panel.write(0x02000002, 1, 0))
        self.assertEqual(panel.rejection, 'foreign-main-aperture-owner')

    def test_origin_is_derived_consistently_then_frozen(self):
        for origin in (0, 16, 32):
            panel = self.started()
            for page in range(10):
                self.command(panel, 0xb0+page, 0x10+(origin >> 4), origin & 15)
                self.data(panel, [0]*96)
            self.command(panel, 0xaf)
            self.assertTrue(panel.qualified)
            self.assertEqual(panel.origin, origin)
        panel = self.started()
        self.command(panel, 0xb0, 0x11, 0); self.data(panel, [0]*96)
        self.command(panel, 0xb1, 0x12, 0); self.data(panel, [0]*96)
        self.clear(panel, range(2, 10))
        self.assertFalse(panel.qualified)
