import unittest

from msm5xxx_emulator.detection.devices.external_bus.observations.lcd import has_lcd029_output


class Lcd029DetectionTest(unittest.TestCase):
    def test_mirror_and_halfword_output_sequence(self):
        image = bytearray(0x100)
        image[0x20:0x36] = bytes.fromhex('08200e49292212050880108008888023184308801080')
        image[0x5c:0x60] = (0x01001000).to_bytes(4, 'little')
        self.assertTrue(has_lcd029_output(bytes(image), 0x01000000, 0x800000))
        self.assertFalse(has_lcd029_output(bytes(image), 0x02000000, 0x800000))
        image[0x2a] ^= 1
        self.assertFalse(has_lcd029_output(bytes(image), 0x01000000, 0x800000))

