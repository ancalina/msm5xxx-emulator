import unittest
from msm5xxx_emulator.devices.display.segmented_panel import SegmentedPanel, ROWS

PORT, DATA = 0x02800000, 0x02800004

def commands(values):
    return [(1, 2, PORT, v) for v in values]


def full():
    events = commands([0x43, 0, 127])
    for y in ROWS:
        events += commands([0x42, y, y]) + [(1, 2, DATA, 0) for _ in range(128)]
    return events


def check_protocol():
    def run(tail):
        d = SegmentedPanel(PORT)
        for event in full() + tail:
            d.write(event[2], event[1], event[3])
        return d
    pixels = [(1, 2, DATA, 0xffff)] * 84
    for axes in ([0x43, 126, 131, 0x42, 22, 35], [0x42, 22, 35, 0x43, 126, 131]):
        d = run(commands(axes) + pixels)
        assert d.qualified and d.rectangles == 1
        assert d.ram[131, 35] == 0xffff and d.ram[125, 35] == 0
        assert len(d.snapshot()) == 128 * 128 * 3
        retained = d.snapshot()
        for e in commands([0x50, 0x2d]): d.write(e[2], e[1], e[3])
        assert d.snapshot() == bytes(128 * 128 * 3)
        for e in commands([0x2c, 0x51]): d.write(e[2], e[1], e[3])
        assert d.snapshot() == retained
    d = run(commands([0x42, 143, 143, 0x42, 22, 22, 0x43, 126, 131]) + pixels[:6])
    assert d.qualified and d.rectangles == 1 and (126, 143) not in d.ram
    for e in commands([0x42, 23, 23]) + pixels[:6]: d.write(e[2], e[1], e[3])
    assert d.qualified and d.rectangles == 2 and d.ram[131, 23] == 0xffff
    for bad in ([(1, 2, DATA, 0xffff)] * 128, commands([0x43, 0, 143, 0x42, 7, 7]) + pixels + pixels[:44],
                commands([0x43, 126, 131, 0x42, 22, 35]) + pixels[:-1],
                commands([0x43, 0, 0, 0x42, 71, 81]),
                commands([0x43, 0, 144]), commands([0x99]),
                commands([0x50, 0x51]),
                commands([0x43, 126, 131, 0x42, 22, 35]) + pixels + pixels[:1]):
        d = run(bad)
        assert d.snapshot() is None
        for e in full(): d.write(e[2], e[1], e[3])
        assert d.active and d.raster.admissions == 2
        if d.enabled is None:
            assert d.snapshot() is None
            for e in commands([0x50, 0x2d]): d.write(e[2], e[1], e[3])
            assert d.qualified and d.snapshot() == bytes(128 * 128 * 3)
        else:
            assert d.qualified
    d = run(commands([0x50, 0x2d, 0x2c, 0x99]) + full())
    assert d.active and d.enabled is None and d.snapshot() is None
    for e in commands([0x50, 0x2d, 0x2c, 0x51]): d.write(e[2], e[1], e[3])
    assert d.qualified and d.enabled is True


class SegmentedPanelTests(unittest.TestCase):
    def test_admission_rectangles_power_and_recovery(self):
        check_protocol()

    def test_port_isolation_and_malformed_power(self):
        panel = SegmentedPanel(0x02000000)
        for _, size, address, value in full():
            panel.write(address, size, value)
        self.assertEqual(panel.raster.admissions, 0)
        for _, size, address, value in full():
            panel.write(address - 0x800000, size, value)
        self.assertTrue(panel.qualified)
        panel.write(panel.port, 2, 0x50)
        panel.write(panel.port, 2, 0x2d)
        panel.write(panel.port, 1, 0x51)
        for _, size, address, value in full():
            panel.write(address - 0x800000, size, value)
        self.assertIsNone(panel.enabled)
        self.assertIsNone(panel.snapshot())

    def test_snapshot_ownership_and_native_fallback(self):
        from threading import RLock
        from types import SimpleNamespace
        from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin
        controller = DisplayControllerMixin()
        controller._display_lock = RLock()
        controller.config = SimpleNamespace(width=1, height=1)
        controller.display_frame = bytes((1, 2, 3))
        panel = controller._lcd_segmented_panel = SegmentedPanel(PORT)
        self.assertEqual(controller.display_snapshot(), (1, 1, bytes((1, 2, 3))))
        for _, size, address, value in full():
            panel.write(address, size, value)
        width, height, frame = controller.display_snapshot()
        self.assertEqual((width, height, len(frame)), (128, 128, 49152))
        committed = frame
        for value in (0x43, 0, 1, 0x42, 6, 6):
            panel.write(PORT, 2, value)
            self.assertEqual(controller.display_snapshot(), (128, 128, committed))
        panel.write(DATA, 2, 0xffff)
        self.assertFalse(panel.qualified)
        self.assertIsNone(panel.snapshot())
        self.assertEqual(controller.display_snapshot(), (128, 128, committed))
        panel.write(DATA, 2, 0xffff)
        self.assertNotEqual(controller.display_snapshot()[2], committed)
        panel.write(PORT, 2, 0x99)
        self.assertEqual(controller.display_snapshot(), (1, 1, bytes((1, 2, 3))))
        self.assertFalse(controller.segmented_panel_snapshot()['qualified'])

    def test_detector_structural_admission_and_mutations(self):
        import struct
        from msm5xxx_emulator.detection.segmented import detect_segmented_panel
        image = bytearray(1024)
        def put(offset, value):
            data = bytes.fromhex(value)
            image[offset:offset+len(data)] = data
        row = 128
        put(row-20, '0524e40520800a4eb0692080f0692080306a44e0')
        put(row, '42281dda42212180811d1de0')
        put(row+64, '42212180c11d08310904090c21802180')
        put(row+96, 'c1018918')
        put(row+118, '13880232a3800131bfdd')
        put(row+0x8a, '0004716a000c8842b5dd')
        struct.pack_into('<I', image, 156, 0x01010000)
        put(512, '90b4c706ff0e3f225201024052091f23db021840c00a904203d1b84201d1ba42')
        put(612, '00d500201f2800dd1f200004800a0004000c1104090c084340010004000c3904090c084390bc')
        self.assertEqual(detect_segmented_panel(image)[0], PORT)
        self.assertEqual(detect_segmented_panel(bytes(4096)+image)[0], PORT)
        for offset in (row-20, row-2, row+2, row+122, 156, 512):
            broken = bytearray(image)
            broken[offset] ^= 1
            self.assertIsNone(detect_segmented_panel(broken)[0])
        self.assertIsNone(detect_segmented_panel(image+image)[0])
