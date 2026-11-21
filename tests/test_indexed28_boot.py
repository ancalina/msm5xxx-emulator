import unittest

from msm5xxx_emulator.detection.devices.display.indexed28_boot import (
    _CLEAR, _CURSOR, _WINDOW, find_indexed28_boot,
)


class Indexed28BootTest(unittest.TestCase):
    def test_linked_geometry_and_ports_are_required(self):
        image = bytearray(0x1000)
        window = 0x102
        clear, cursor, literal = window + 0x4d2, window + 0x586, window + 0x3f0
        image[window:window + len(_WINDOW)] = _WINDOW
        image[clear:clear + len(_CLEAR)] = _CLEAR
        image[cursor:cursor + len(_CURSOR)] = _CURSOR
        image[literal:literal + 4] = bytes.fromhex('00000828')
        # The embedded branches are position-independent when the layout is preserved.
        panel = find_indexed28_boot(bytes(image))
        self.assertEqual((panel['width'], panel['height'], panel['y_origin'], panel['data_port']),
                         (240, 320, 96, 0x28080000))
        image[literal] ^= 1
        self.assertIsNone(find_indexed28_boot(bytes(image)))
