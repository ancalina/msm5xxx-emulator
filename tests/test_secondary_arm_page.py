import struct
import unittest
from msm5xxx_emulator.detection.secondary_arm_page import (
    _BODY, _DATA_AND_COMMAND, find_secondary_arm_page,
)


def fixture():
    image = bytearray(0x1000)
    def word(at, value):
        struct.pack_into('<I', image, at, value)
    def branch(at, dest, link=True):
        assert (dest - at - 8) % 4 == 0
        word(at, (0xeb000000 if link else 0xea000000) | (((dest - at - 8) >> 2) & 0xffffff))
    producer, page, column, data, caller, literal = 0x400, 0x200, 0x300, 0x100, 0x700, 0x6f0
    descriptor = 0x01002000
    image[producer:producer + len(_BODY)] = _BODY
    word(producer - 4, descriptor)
    for offset, target in ((0x10, page), (0x28, column), (0x34, data)):
        branch(producer + offset, target)
    image[data:data + len(_DATA_AND_COMMAND)] = _DATA_AND_COMMAND
    image[page:page + 12] = bytes.fromhex('070050e300f18f90170000ea')
    for n in range(8):
        branch(page + 12 + n * 4, page + 44 + n * 8, False)
        word(page + 44 + n * 8, 0xe3a000b7 - n)
        branch(page + 48 + n * 8, data + 12, False)
    image[column:column + 20] = bytes.fromhex('0020a0e10f00a0e3420200e0100080e204e02de5')
    branch(column + 20, data + 12)
    image[column + 24:column + 32] = bytes.fromhex('0f0002e204e09de4')
    branch(column + 32, data + 12, False)
    word(literal, descriptor)
    word(caller, 0xe51f1000 | (caller + 8 - literal))
    image[caller + 4:caller + 12] = bytes.fromhex('140094e5c00281e5')
    branch(caller + 12, producer)
    return image


class SecondaryArmPageTests(unittest.TestCase):
    def test_linked_producer_and_rejections(self):
        image = fixture()
        profile, reason = find_secondary_arm_page(bytes(image))
        self.assertEqual(reason, 'accepted-source-bound-arm-page-candidate')
        self.assertEqual((profile['command_port'], profile['data_port'],
                          profile['width'], profile['height']), (0x2800000, 0x2800002, 96, 64))
        for offset in (0x100, 0x104, 0x20c, 0x22c, 0x300, 0x314, 0x3fc,
                       0x400, 0x410, 0x434, 0x43c, 0x6f0, 0x704, 0x70c):
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.subTest(offset=hex(offset)):
                self.assertIsNone(find_secondary_arm_page(bytes(changed))[0])
        self.assertIsNone(find_secondary_arm_page(bytes(image[:0x450]))[0])
        self.assertIsNone(find_secondary_arm_page(bytes(len(image)))[0])
