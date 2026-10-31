"""Synthetic padded allocation and independent main/sub scanout regression."""
import struct
import unittest
from msm5xxx_emulator.detection.display import find_dual_page_ports, detect_lcd_width_hint
from msm5xxx_emulator.devices.display.page_panel import PagePanel
import test_lcd_geometry as fixtures


def fixture():
    image = bytearray(0x200)
    words = (0xb590, 0x1c1c, 0x2800, 0x4f1c, 0xd10c,
             0x2080, 0x8238, 0x2070, 0x8278, 0x200e, 0x2301, 0x02db,
             0x8378, 0x18c8, 0x6238, 0x61f9, 0xc714, 0xbd90,
             0x2060, 0x82b8, 0x2040, 0x82f8, 0x2008, 0x84b8, 0x62b9)
    struct.pack_into('<' + 'H' * len(words), image, 0, *words)
    struct.pack_into('<I', image, 0x78, 0x01180000)
    start = 0x100
    struct.pack_into('<17H', image, start,
                     0x4f00, 0x2100, 0x1c38, 0, 0, 0x4b00, 0x1c39, 0x2000,
                     0x1f1a, 0, 0, 0x4b00, 0x2001, 0x1f1a, 0x4900, 0, 0)
    for offset, register, literal, value in (
            (0, 7, 0x180, 0x011a0000), (10, 3, 0x184, 0x02800004),
            (22, 3, 0x188, 0x02000004), (28, 1, 0x18c, 0x011a1000)):
        at = start + offset
        struct.pack_into('<H', image, at, 0x4800 | register << 8 |
                         (literal - ((at + 4) & ~3)) // 4)
        struct.pack_into('<I', image, literal, value)
    for offset in (18, 30):
        at = start + offset
        delta = -at - 4
        struct.pack_into('<HH', image, at, 0xf000 | (delta >> 12 & 0x7ff),
                         0xf800 | (delta >> 1 & 0x7ff))
    return image


class PaddedPageOwnershipTests(unittest.TestCase):
    def test_allocation_extent_closes_both_ports_without_metadata_change(self):
        image = fixture()
        self.assertEqual(find_dual_page_ports(image), (0x02800000, 0x02000000))
        self.assertIsNone(detect_lcd_width_hint(image))
        for at, value in ((0x16, 0x029b), (0x1a, 0x18c0), (0x11e, 0)):
            changed = image.copy()
            struct.pack_into('<H', changed, at, value)
            self.assertIsNone(find_dual_page_ports(changed))
        changed = image.copy()
        # The logical fourteen-page viewport is not the allocation extent.
        struct.pack_into('<I', changed, 0x18c, 0x011a0e00)
        self.assertIsNone(find_dual_page_ports(changed))
        changed = image.copy()
        struct.pack_into('<I', changed, 0x78, 0x011a0040)
        self.assertIsNone(find_dual_page_ports(changed))
        changed = image.copy()
        struct.pack_into('<II', changed, 0x184, 0x02000004, 0x02800004)
        self.assertIsNone(find_dual_page_ports(changed))

    def test_monochrome_sub_updates_cannot_replace_paired_main_pixels(self):
        decoder = fixtures.LCDGeometryTests()._routing_emulator(width=128, height=128)
        panel = PagePanel(0x02000000, independent_ports=True)
        decoder._lcd_secondary_panel = panel
        def write(port, value):
            decoder._lcd_write(None, 0, port, 2, value, None)
        for page in range(16):
            for command in (0xb0 + page, 0x10, 0):
                write(0x02800000, command)
            for _ in range(128):
                write(0x02800004, 0xff)
                write(0x02800004, 0)
        write(0x02800000, 0xaf)
        decoder._lcd_page_flush_current()
        before = decoder.display_snapshot()
        for page in range(3):
            for command in (0xb0 + page, 0x12, 0):
                write(panel.port, command)
            for _ in range(96):
                write(panel.port + 4, 0)
            write(0x02800000, 0xaf)  # Main traffic before sub qualification.
        decoder._lcd_page_flush_current()
        self.assertTrue(panel.committed)
        self.assertIsNone(panel.rejection)
        self.assertEqual(decoder._lcd_page_port, 0x02800000)
        self.assertEqual(decoder.display_snapshot(), before)

    def test_existing_main_guard_ignores_unowned_halfword_sub_rows(self):
        decoder = fixtures.LCDGeometryTests()._routing_emulator(width=128, height=128)
        def write(port, value):
            decoder._lcd_write(None, 0, port, 2, value, None)
        for page in range(16):
            for command in (0xb0 + page, 0x10, 0):
                write(0x02800000, command)
            for _ in range(128):
                write(0x02800004, 0xff)
                write(0x02800004, 0)
        write(0x02800000, 0xaf)
        decoder._lcd_page_flush_current()
        before = decoder.display_snapshot()
        for page in range(2):
            for command in (0xb0 + page, 0x12, 0):
                write(0x02000000, command)
            for _ in range(96):
                write(0x02000004, 0)
        write(0x02000000, 0xaf)
        decoder._lcd_page_flush_current()
        # The existing 0x020 halfword guard already prevents this particular
        # transfer from changing the main plane. Ownership adds a real sub
        # scanout; it must preserve that protection rather than bypass it.
        self.assertTrue(decoder.display_snapshot() == before)
        self.assertEqual(decoder._lcd_page_port, 0x02800000)
        self.assertIsNone(getattr(decoder, '_lcd_secondary_panel', None))
