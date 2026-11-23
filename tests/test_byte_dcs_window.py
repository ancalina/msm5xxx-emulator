import unittest

from msm5xxx_emulator.detection.devices.display.byte_dcs_writer import find_byte_dcs_writer
from msm5xxx_emulator.devices.display.byte_dcs_window import ByteDcsWindow


class ByteDcsWindowTests(unittest.TestCase):
    def test_source_and_offset_rgb565_stream(self):
        image = bytearray(512)
        image[64:102] = bytes.fromhex(
            '2a204107087011480d4f427803923a717f323a712b220a700078029038717f3038712c200870')
        image[126:130] = bytes.fromhex('00001e40')
        image[154:172] = bytes.fromhex('05e0ff233b713b7101300004000c9042f7d3')
        self.assertEqual(find_byte_dcs_writer(bytes(image)), ((64, 108),))
        image[126] ^= 1
        self.assertFalse(find_byte_dcs_writer(bytes(image)))

        panel = ByteDcsWindow(2, 2)
        def send(command, *data):
            panel.write(0x40000000, 1, command)
            for value in data:
                panel.write(0x401e0004, 1, value)
        send(0x29)
        send(0x2a, 4, 5)
        send(0x2b, 4, 5)
        send(0x2c)
        frame = None
        for value in (0xf8, 0x00, 0x07, 0xe0, 0x00, 0x1f, 0xff, 0xff):
            _, frame = panel.write(0x401e0004, 1, value)
        self.assertEqual(frame, bytes((255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255)))
        self.assertEqual((panel.x_origin, panel.y_origin), (4, 4))


if __name__ == '__main__':
    unittest.main()
