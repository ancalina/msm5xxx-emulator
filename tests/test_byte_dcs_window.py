import unittest

from msm5xxx_emulator.detection.devices.display.byte_dcs_writer import find_byte_dcs_writer
from msm5xxx_emulator.devices.display.byte_dcs_window import ByteDcsWindow


class ByteDcsWindowTests(unittest.TestCase):
    def test_byte_and_halfword_accessors_require_data_port(self):
        image = bytearray(0x400)
        accessors = bytes.fromhex(
            '0121890708707047a349087170470120800700787047a04800797047'
            '01218907088070479c49888070470120800700887047994880887047'
            '01040a0e96490a7108717047')
        image[0x40:0x40 + len(accessors)] = accessors
        image[0x2d8:0x2dc] = bytes.fromhex('00001e40')
        self.assertEqual(find_byte_dcs_writer(image), ((0x40, len(accessors)),))
        image[0x2db] ^= 1
        self.assertFalse(find_byte_dcs_writer(image))
        image = bytearray(0x400)
        image[0x42:0x42 + len(accessors)] = accessors
        for offset, immediate in zip((8, 22, 36, 50, 60), (0x89, 0x85, 0x82, 0x7e, 0x7c)):
            image[0x42 + offset] = immediate
        image[0x270:0x274] = bytes.fromhex('00001e40')
        self.assertEqual(find_byte_dcs_writer(image), ((0x42, len(accessors)),))
        image[0x42 + 22] ^= 1
        self.assertFalse(find_byte_dcs_writer(image))

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
        send(0x36, 0x20)
        _, oriented = panel.write(0x40000000, 1, 0x29)
        self.assertEqual(oriented, bytes((255, 0, 0, 0, 0, 255, 0, 255, 0, 255, 255, 255)))

    def test_four_byte_window_parameters(self):
        panel = ByteDcsWindow(2, 2)
        def send(command, *values):
            panel.write(0x40000000, 1, command)
            for value in values:
                panel.write(0x401e0004, 1, value)
        send(0x29)
        send(0x2a, 0, 2, 0, 3)
        send(0x2b, 0, 3, 0, 4)
        send(0x36, 0xc8)
        send(0x2c)
        for value in (0xf8, 0, 0x07, 0xe0, 0, 0x1f, 0xff):
            panel.write(0x401e0004, 1, value)
        _, frame = panel.write(0x401e0004, 1, 0xff)
        self.assertEqual(frame, bytes((255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255)))
        self.assertEqual((panel.x_origin, panel.y_origin), (2, 3))


if __name__ == '__main__':
    unittest.main()
