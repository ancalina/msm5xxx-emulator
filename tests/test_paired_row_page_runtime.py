"""Synthetic repeated paired-plane page transfers."""
import unittest
from unittest.mock import patch
import test_lcd_geometry as helpers


class PairedRowPageTests(unittest.TestCase):
    def test_full_rows_reacquire_after_display_command(self):
        display = helpers.LCDGeometryTests()._routing_emulator(width=128, height=128)
        display.image = bytes(4); display.frame_sequence = 0
        display.config.ram_base = 0x01000000; display.config.ram_size = 0x100000
        display.config.display_geometry_source = 'auto-default'
        profile = dict(class_name='source-byte-pair128-page-v1', width=128, height=128,
            bits_per_pixel=2, logical_y_reverse=False, command_port=0x02000000,
            data_port=0x02000002, access_width=1, main_pages=list(range(16)),
            required_pages=16, init_row_bytes=256, whole_rows_only=True,
            column_capacity=256, column_bias=0, icon_page=-1, init_commands=[0xe2, 0xa1, 0xc0],
            code_intervals=[[0,2]], literal_intervals=[], data_intervals=[],
            ram_intervals=[[0x01000000,0x01000004]])
        def command(value):
            display._lcd_route_write(None, 0, 0x02000000, 1, value, None)
        def data(value):
            display._lcd_route_write(None, 0, 0x02000002, 1, value, None)
        def raster(a,b):
            for page in range(16):
                for value in (0xb0 | page, 0x10, 0): command(value)
                for _ in range(128): data(a); data(b)
            command(0xaf)
        with patch('msm5xxx_emulator.detection.devices.display.mono_page.find_odd_byte_page_profile',
                   return_value=(profile, 'synthetic')):
            for value in profile['init_commands']: command(value)
            raster(1,0)
            self.assertEqual(display.display_snapshot()[2][:3], bytes([170]) * 3)
            raster(0,1)
            self.assertEqual(display.display_snapshot()[2][:3], bytes([85]) * 3)
            self.assertFalse(display.odd_page_snapshot()['rejected'])
