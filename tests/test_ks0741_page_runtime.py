"""Synthetic paired-plane transport, raster proof and ownership checks."""
import unittest
from unittest.mock import patch
import test_lcd_geometry as helpers


def profile(height=128):
    return dict(class_name='source-byte-paired-plane-page-v1', width=120,
        height=height, bits_per_pixel=2, logical_y_reverse=False,
        command_port=0x02000000, data_port=0x02000004, access_width=1,
        main_pages=list(range(16)), required_pages=16, init_row_bytes=240,
        column_capacity=240, column_bias=0, icon_page=-1,
        init_commands=[0xe2,0x81,None,0xa4], code_intervals=[[0,2]],
        literal_intervals=[], data_intervals=[], ram_intervals=[[0x01000000,0x01000004]])


class PairedPlaneRuntimeTests(unittest.TestCase):
    def display(self, height=128, manual=False):
        display=helpers.LCDGeometryTests()._routing_emulator(width=128,height=160)
        display.image=bytes(4); display.frame_sequence=0; display.config.chipset='MSM5105'
        display.config.ram_base=0x01000000; display.config.ram_size=0x100000
        display.config.display_geometry_source='manual' if manual else 'auto-default'
        self.enterContext(patch('msm5xxx_emulator.detection.mono_page.find_odd_byte_page_profile',
                                return_value=(profile(height),'synthetic')))
        return display

    def write(self, d, value, data=False, size=1):
        d._lcd_route_write(None,0,0x02000004 if data else 0x02000000,size,value,None)

    def init(self,d):
        for value in [0xe2,0x81,0x37,0xa4]:self.write(d,value)

    def row(self,d,page,pairs=120,column=0,first=1,second=0):
        for value in [0xb0|page,0x10|(column>>4),column&15]:self.write(d,value)
        for _ in range(pairs):
            self.write(d,first,True);self.write(d,second,True)

    def raster(self,d):
        self.init(d)
        for page in range(16):self.row(d,page)
        self.write(d,0xaf)

    def test_full_physical_raster_and_source_plane_order(self):
        d=self.display();self.init(d)
        for page in range(15):self.row(d,page)
        self.assertEqual(d.frame_sequence,0)
        self.row(d,15);self.write(d,0xaf)
        w,h,p=d.display_snapshot();self.assertEqual((w,h),(120,128))
        self.assertGreater(d.frame_sequence,0)
        self.assertEqual(p[:3],bytes([170])*3)
        self.assertEqual(p[w*3:w*3+3],bytes(3))
        self.row(d,0,pairs=7,column=5,first=0,second=1)
        self.write(d,0xaf)
        self.assertFalse(d.odd_page_snapshot()['blocked'])
        self.assertFalse(d.odd_page_snapshot()['logical_y_reverse'])
        _,_,p=d.display_snapshot()
        self.assertEqual(p[5*3:6*3],bytes([85])*3)
        self.assertEqual(p[4*3:5*3],bytes([170])*3)

    def test_short_view_still_requires_sixteen_physical_pages(self):
        d=self.display(96);self.raster(d)
        self.assertEqual(d.display_snapshot()[:2],(120,96))
        self.assertGreater(d.frame_sequence,0)

    def test_odd_pair_rejected_and_frame_proof_cleared(self):
        d=self.display();self.raster(d)
        self.row(d,0,pairs=0);self.write(d,1,True);self.write(d,0xb1)
        self.assertTrue(d.odd_page_snapshot()['rejected'])
        self.assertFalse(d._lcd_page_qualified)

    def test_wrong_prefix_and_width_rejected(self):
        for size,value in [(1,0x82),(2,0x81)]:
            with self.subTest(size=size):
                d=self.display();self.write(d,0xe2);self.write(d,value,size=size)
                self.assertTrue(d.odd_page_snapshot()['rejected'])
                self.assertEqual(d.frame_sequence,0)

    def test_manual_geometry_retained(self):
        d=self.display(manual=True);self.raster(d)
        self.assertEqual(d.display_snapshot()[:2],(128,160))

    def test_controller_reinitialization_requires_new_complete_raster(self):
        d=self.display();self.raster(d)
        sequence=d.frame_sequence
        self.init(d)
        self.assertFalse(d._lcd_page_qualified)
        for page in range(15):self.row(d,page,first=0,second=1)
        self.assertEqual(d.frame_sequence,sequence)
        self.row(d,15,first=0,second=1);self.write(d,0xaf)
        self.assertTrue(d._lcd_page_qualified)
        self.assertGreater(d.frame_sequence,sequence)
        self.assertFalse(d.odd_page_snapshot()['blocked'])
