"""Complete clear, plane boundaries and source-canvas byte placement."""
import unittest
from msm5xxx_emulator.devices.display.boot_page_panel import BootPagePanel


class BootPageTests(unittest.TestCase):
    def command(self,p,*values):
        for value in values:p.write(0x02000000,2,value)

    def clear(self,p,pages=None,width=128):
        self.command(p,0xae)
        for page in (range(p.pages)if pages is None else pages):
            self.command(p,0xb0+page,0x10,0)
            for _ in range(width*p.planes):p.write(0x02000002,2,0)
        self.command(p,0xaf)

    def test_full_clears_and_retained_pixels(self):
        for pages,planes in ((9,1),(16,2)):
            p=BootPagePanel(pages,planes);self.clear(p)
            self.assertTrue(p.qualified);self.assertEqual(p.sequence,1)
            self.command(p,0xb3,0x10,4)
            for _ in range(planes):p.write(0x02000002,2,0x81)
            self.assertEqual(p.frame[(24*128+4)*3:(24*128+4)*3+3],bytes(3))
            self.assertEqual(p.frame[(31*128+4)*3:(31*128+4)*3+3],bytes(3))
            self.assertEqual(p.frame[(25*128+4)*3:(25*128+4)*3+3],bytes([255])*3)
            self.assertIsNone(p.rejection)

    def test_partial_repeated_and_wrong_plane_clear_never_qualify(self):
        for pages,planes in ((9,1),(16,2)):
            for rows,width in ((range(pages-1),128),([0]*pages,128),(range(pages),127)):
                p=BootPagePanel(pages,planes);self.clear(p,rows,width)
                self.assertFalse(p.qualified);self.assertEqual(p.sequence,0)
        p=BootPagePanel(16,2);self.command(p,0xae)
        for page in range(16):
            self.command(p,0xb0+page,0x10,0)
            for _ in range(128):p.write(0x02000002,2,0)
        self.command(p,0xaf);self.assertFalse(p.qualified)

    def test_access_width_and_address_boundaries(self):
        p=BootPagePanel(9,1);self.assertFalse(p.write(0x02800002,2,255));self.assertIsNone(p.rejection)
        p.write(0x02000002,1,0);self.assertEqual(p.rejection,'source-halfword-byte-value-required')
        p=BootPagePanel(9,1);self.clear(p);self.command(p,0xff)
        p.write(0x02000002,2,1);self.assertEqual(p.rejection,'data-without-source-page-column')

    def test_readdressed_columns_count_distinct_cells_and_both_planes(self):
        for pages,planes in ((9,1),(16,2)):
            p=BootPagePanel(pages,planes);self.command(p,0xae)
            for page in range(pages):
                self.command(p,0xb0+page)
                for column in range(128):
                    self.command(p,0x10|(column>>4),column&15)
                    for _ in range(planes):p.write(0x02000002,2,0)
            self.command(p,0xaf);self.assertTrue(p.qualified)
        p=BootPagePanel(9,1);self.command(p,0xae,0xb0)
        for _ in range(128):
            self.command(p,0x10,0);p.write(0x02000002,2,0)
        self.assertEqual(p.clear_next,0)
