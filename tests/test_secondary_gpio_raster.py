import unittest
from threading import RLock
from types import SimpleNamespace
from corpus import FIRMWARE_ROOT
from msm5xxx_emulator.detection.secondary_gpio_raster import find_secondary_gpio_raster
from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin
from msm5xxx_emulator.devices.display.secondary_gpio_raster import SecondaryGpioRaster


class SecondaryGpioRasterTest(unittest.TestCase):
    def test_detects_closed_copied_writer_and_rejects_mutation(self):
        path = FIRMWARE_ROOT / 'LG-SD810-General.bin'
        if not path.is_file():
            self.skipTest('firmware corpus unavailable')
        image = path.read_bytes()
        profile = find_secondary_gpio_raster(image, 0x1800000, 0x800000)
        self.assertIsNotNone(profile)
        self.assertEqual((profile['width'], profile['height']), (128, 48))
        damaged = bytearray(image)
        damaged[profile['source'] + 0xc258 + 0x144] ^= 1
        self.assertIsNone(find_secondary_gpio_raster(damaged, 0x1800000, 0x800000))

    def test_complete_serial_raster_and_partial_frame(self):
        panel = SecondaryGpioRaster()
        payload = bytearray(1600)
        # Source pixels at corners and an interior location, encoded as the
        # producer's transposed two-bit stream.
        pixels = ((0, 0), (127, 47), (37, 19))
        for x, y in pixels:
            payload[y * 32 + x // 8 * 2 + x % 8 // 4] |= 3 << (2 * x & 7)
        bits = [(value >> bit) & 1 for value in payload for bit in range(7, -1, -1)]
        for index, bit in enumerate(bits[:-1]):
            panel.write(panel.port, 2, bit | (0x8000 if not index else 0))
        panel.flush()
        self.assertFalse(panel.committed)
        panel.write(panel.port, 2, bits[-1] | 0x4000)
        self.assertTrue(panel.committed)
        self.assertEqual(panel.sequence, 1)
        owner = SimpleNamespace(_lcd_secondary_panel=panel, _display_lock=RLock())
        snapshot = DisplayControllerMixin.secondary_display_snapshot(owner)
        self.assertEqual((snapshot['width'], snapshot['height']), (128, 48))
        self.assertTrue(snapshot['qualified'])
        self.assertEqual(snapshot['frame'], panel.frame)
        for x, y in pixels:
            offset = (y * 128 + x) * 3
            self.assertEqual(panel.frame[offset:offset + 3], b'\0\0\0')
        self.assertEqual(panel.frame[3:6], b'\xff\xff\xff')
        old = panel.frame
        panel.write(panel.port, 2, 0x8000)
        panel.write(panel.port, 2, 0x4000)
        self.assertEqual(panel.frame, old)
        self.assertEqual(panel.sequence, 1)
