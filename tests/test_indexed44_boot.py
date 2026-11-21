import struct
import unittest

from msm5xxx_emulator.detection.devices.display.indexed44_writer import find_indexed44_boot


def _bl(image, site, target):
    displacement = (target - site - 4) >> 1
    struct.pack_into('<HH', image, site, 0xf000 | ((displacement >> 11) & 0x7ff),
                     0xf800 | (displacement & 0x7ff))


class Indexed44BootTest(unittest.TestCase):
    def test_linked_clear_and_cursor_are_required(self):
        image = bytearray(0x1000)
        window = 0x102
        clear = window + 0x444
        cursor = 0xc24
        image[window:window + 40] = bytes.fromhex(
            '10b504321406090201431a1d0b1c44210520240ec0060180ec490b8012022243452303800a8010bd')
        image[window + 0x3ca:window + 0x3ce] = bytes.fromhex('00010028')
        image[clear:clear + 44] = bytes.fromhex(
            'db230022af210020fff7d8fd0021002000f065fb22202080dc20d64904e0b02200e02980013afcd20138f8d2')
        image[cursor:cursor + 20] = bytes.fromhex('21220523db061a80043109020843354908807047')
        image[cursor + 0xe4:cursor + 0xe8] = bytes.fromhex('00010028')
        _bl(image, clear + 8, window)
        _bl(image, clear + 0x10, cursor)
        panel = find_indexed44_boot(bytes(image))
        self.assertEqual((panel['width'], panel['height'], panel['y_origin']), (176, 220, 4))
        image[clear + 0x22] ^= 1
        self.assertIsNone(find_indexed44_boot(bytes(image)))
