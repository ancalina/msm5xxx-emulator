"""Synthetic GPIO edges, mixed bit orders and complete coverage admission."""
import unittest
from msm5xxx_emulator.devices.display.gpio_serial_panel import GpioSerial89Panel


class GpioSerialPanelTests(unittest.TestCase):
    def send(self, panel, data, values):
        base = 0x100 if data else 0
        for value in values:
            for n in range(8):
                bit = (value >> (n if data else 7-n)) & 1
                panel.write(0x03000660, 2, base | bit*0x80)
                panel.write(0x03000660, 2, base | bit*0x80 | 0x40)
        panel.write(0x03000660, 2, base | 0x20 | 0x40)

    def clear(self, panel, pages=range(8), width=89):
        for page in pages:
            self.send(panel, False, [0x40+page, 0, 0x80])
            self.send(panel, True, [0]*width)

    def test_full_distinct_coverage_and_both_bit_orders(self):
        panel = GpioSerial89Panel(); self.clear(panel)
        self.assertTrue(panel.qualified)
        self.assertEqual((panel.coverage, panel.sequence), (712, 1))
        self.send(panel, False, [0x45, 0, 0x83])
        self.send(panel, True, [0x96, 0x21])
        self.assertEqual(panel.ram[5*89+3:5*89+5], bytes([0x96, 0x21]))
        self.assertEqual(panel.sequence, 2)
        self.assertEqual(panel.frame[((5*8+1)*89+3)*3:((5*8+1)*89+3)*3+3], bytes([255])*3)

    def test_repeated_and_partial_rows_do_not_supply_missing_cells(self):
        for pages, width in (([0]*8,89),(range(7),89),(range(8),88)):
            panel = GpioSerial89Panel(); self.clear(panel,pages,width)
            self.assertFalse(panel.qualified)
            self.assertEqual(panel.sequence, 0)

    def test_chip_select_mode_and_width_boundaries(self):
        panel = GpioSerial89Panel()
        panel.write(0x03000660,2,0);panel.write(0x03000660,2,0x40)
        panel.write(0x03000660,2,0x60)
        self.assertEqual(panel.rejection,'incomplete-byte-at-chip-select')
        panel = GpioSerial89Panel()
        panel.write(0x03000660,2,0);panel.write(0x03000660,2,0x40)
        panel.write(0x03000660,2,0x100)
        self.assertEqual(panel.rejection,'mode-changed-within-byte')
        panel = GpioSerial89Panel();self.assertFalse(panel.write(0x03000664,2,0))
        self.assertIsNone(panel.rejection)
        panel.write(0x03000660,1,0);self.assertEqual(panel.rejection,'source-halfword-required')

    def test_unknown_control_requires_a_fresh_complete_raster(self):
        panel = GpioSerial89Panel();self.clear(panel)
        self.send(panel,False,[0x3e])
        self.assertFalse(panel.qualified)
        self.clear(panel)
        self.assertTrue(panel.qualified)
