"""Synthetic checks for the copied group timer's structural guards."""
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.rex.rules.group10_timer import (
    group10_callback, group10_handler, group10_registrar,
)


class Facts:
    def __init__(self, literals=(), calls=()):
        self.literals = dict(literals)
        self.calls = dict(calls)

    def thumb_literal_value(self, position, register):
        return self.literals.get((position, register))

    def thumb_call_target(self, position):
        return self.calls.get(position)


def words(image, base, values):
    for offset, value in values.items():
        struct.pack_into('<H', image, base + offset, value)


class GroupTimerShapes(unittest.TestCase):
    def test_handler_checks_group_row_and_acknowledgement(self):
        image = bytearray(0x2000)
        handler, source, target, masks = 0x100, 0x900, 0x10000, 0x10020
        row = masks + 12 + 30 * 28
        descriptor = source + row - target
        group = row + 32
        words(image, handler, {0:0xb5f0, 2:0xb088, 4:0x2080, 6:0x9001,
              0x4c:0x2001, 0x4e:0x9007,
              0x52:0x230a, 0x56:0x4358, 0x58:0x1840, 0xa6:0x201c,
              0xaa:0x4370, 0xac:0x1847, 0xd2:0x6978,
              0xf0:0x8008, 0x178:0x8088, 0x180:0x9802, 0x182:0x7a40,
              0x184:0x42b0, 0x186:0xdb03, 0x188:0x2d00, 0x18a:0xd18c,
              0x18c:0x2c00, 0x18e:0xd18a, 0x19a:0x2804, 0x19c:0xda00,
              0x19e:0xe757, 0x248:0xb008, 0x24e:0x4718})
        words(image, 0x800, {0:0x4700})
        struct.pack_into('<4H2B', image, source + group + 30 - target,
                         0x200, 0, 0x200, 4, 30, 30)
        status = 0x3000c80
        literals = {(handler + off, reg): value for off, reg, value in (
            (0x10,7,masks), (0x1a,7,status), (0x1e,2,masks),
            (0x78,2,masks), (0x7c,7,status), (0xa8,1,masks+12),
            (0xec,1,status), (0x174,1,status), (0x54,1,group))}
        with patch('msm5xxx_emulator.detection.devices.rex.rules.facts_for',
                   return_value=Facts(literals.items(), {handler+0xda:0x800}.items())):
            args = (handler, masks, status, (source,target,0x600,0), descriptor)
            self.assertTrue(group10_handler(image, *args))
            image[handler + 0xf0] ^= 1
            self.assertFalse(group10_handler(image, *args))
            image[handler + 0xf0] ^= 1
            image[source + group + 30 - target] ^= 1
            self.assertFalse(group10_handler(image, *args))

    def test_registrar_and_timer_walker_are_required(self):
        image = bytearray(0x500)
        registrar, callback, walker, masks, default = 0x20, 0x100, 0x200, 0x1000, 0x301
        words(image, registrar, {0:0xb5f8,2:0x1c07,4:0x1c0c,0x46:0x201c,
              0x4a:0x4378,0x4c:0x1840,0x4e:0x2f00,0x50:0xd117,
              0x82:0x6144,0x9e:0x6802,0xa0:0x8011})
        words(image, callback, {2:0xb580,4:0x6808,0x16:0x28a5,0x30:0x2105,0x4e:0x2005})
        words(image, walker, {0:0xb5f0,2:0x1c04,0x10:0x6807,0x14:0x68b8,
              0x34:0x1b00,0x36:0x60b8,0x3a:0x42b7})
        facts = Facts({(registrar+0x10,4):default, (registrar+0x48,1):masks+12,
                       (registrar+0x84,1):default}.items(), {callback+0x50:walker}.items())
        with patch('msm5xxx_emulator.detection.devices.rex.rules.facts_for', return_value=facts):
            self.assertEqual(group10_registrar(image, registrar, masks, default), masks+12)
            self.assertEqual(group10_callback(image, callback), walker)
            image[walker + 0x36] ^= 1
            self.assertIsNone(group10_callback(image, callback))
            image[registrar + 0x82] ^= 1
            self.assertIsNone(group10_registrar(image, registrar, masks, default))


if __name__ == '__main__':
    unittest.main()
