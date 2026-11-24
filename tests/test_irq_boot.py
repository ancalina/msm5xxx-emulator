import struct
import unittest

from msm5xxx_emulator.detection.devices.memory.irq_boot import (
    constructor_stack_page, high_stack_irq_boot_ram, requires_armv5,
)


class IrqBootTest(unittest.TestCase):
    def test_constructor_high_stack_is_linked_to_a_table(self):
        image = bytearray(0x200)
        struct.pack_into('<5I', image, 0x4C, 0xE59FD0AC, 0xE59F40AC,
                         0xE4940004, 0xE3500000, 0x0A000009)
        image[0x60:0x7c] = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
        struct.pack_into('<2I', image, 0x100, 0xFFFF2000, 0x180)
        struct.pack_into('<I', image, 0x180, 0x1A1)
        struct.pack_into('<H', image, 0x1A0, 0xB510)
        self.assertEqual(constructor_stack_page(bytes(image)), 0xFFFF1000)
        struct.pack_into('<I', image, 0x100, 0x78002000)
        self.assertEqual(constructor_stack_page(bytes(image)), 0x78001000)
        struct.pack_into('<I', image, 0x100, 0x01FF0000)
        self.assertEqual(constructor_stack_page(bytes(image)), 0x01FEF000)
        image[0x8C:0xBC] = image[0x4C:0x7C]
        struct.pack_into('<2I', image, 0x140, 0x78002000, 0x180)
        self.assertIsNone(constructor_stack_page(bytes(image)))
        image[0x8C:0xBC] = bytes(0x30)
        struct.pack_into('<I', image, 0x104, 0x200)
        self.assertIsNone(constructor_stack_page(bytes(image)))

    def test_repeated_arm_blx_immediate_calls_require_linked_targets(self):
        image = bytearray(0x200)
        for start in (0x40, 0x54):
            call = 0xFA000000 | ((0x100 - (start + 12)) >> 2)
            branch = 0xEA000000 | ((0xC0 - (start + 24)) >> 2)
            struct.pack_into('<5I', image, start, 0xE92D4000, call,
                             0xE3A00005, 0xE89D0002, branch)
        image[0x100:0x104] = b'\x70\x47\x01\x20'
        self.assertTrue(requires_armv5(bytes(image)))
        image[0x58] ^= 1
        self.assertFalse(requires_armv5(bytes(image)))

    def test_constructor_arm_blx_requires_aligned_code(self):
        image = bytearray(0x100)
        image[0x20:0x3c] = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
        self.assertTrue(requires_armv5(bytes(image)))
        image[0x60:0x7c] = image[0x20:0x3c]
        self.assertTrue(requires_armv5(bytes(image)))
        image[0x2c] ^= 1
        image[0x6c] ^= 1
        self.assertFalse(requires_armv5(bytes(image)))
        image[0x20:0x34] = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe1000050e3')
        self.assertTrue(requires_armv5(bytes(image)))

    def test_requires_dispatcher_stacks_and_register_initializer(self):
        image = bytearray(0x600)
        image[0x20:0x3c] = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
        image[0x110:0x114] = bytes.fromhex('0020ffff')
        image[0x140:0x158] = bytes.fromhex('00d27f1890e77f1800c97f1890db7f1890e87f1800da7f18')
        image[0x200:0x220] = bytes.fromhex('f8b5bf49002008608904c8600121c9020b22d2065160bb4a49041160d160b24a')
        image[0x502:0x506] = bytes.fromhex('00160080')
        self.assertEqual(high_stack_irq_boot_ram(bytes(image)), (0x187f0000, 0x10000))
        image[0x502] ^= 1
        self.assertIsNone(high_stack_irq_boot_ram(bytes(image)))

    def test_second_stack_layout(self):
        image = bytearray(0x900)
        image[0x20:0x3c] = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
        image[0x2f8:0x2fc] = bytes.fromhex('0020ffff')
        image[0x334:0x34c] = bytes.fromhex('00120330905f033000090330905303309060033000520330')
        image[0x400:0x41e] = bytes.fromhex('b0b55048002404605049072008724948012505614e492020088200f0abf9')
        image[0x544:0x548] = bytes.fromhex('00160080')
        self.assertEqual(high_stack_irq_boot_ram(bytes(image)), (0x30000000, 0x40000))
        image[0x334] ^= 1
        self.assertIsNone(high_stack_irq_boot_ram(bytes(image)))

    def test_low_panel_stack_and_initializer(self):
        from msm5xxx_emulator.detection.devices.memory.irq_boot import _BOOT_10FF, _IRQ, _STACKS_10FF

        image = bytearray(0x800)
        image[0x20:0x20 + len(_IRQ)] = _IRQ
        image[0x150:0x154] = bytes.fromhex('0020ffff')
        image[0x198:0x1b0] = _STACKS_10FF
        image[0x300:0x300 + len(_BOOT_10FF)] = _BOOT_10FF
        self.assertEqual(high_stack_irq_boot_ram(bytes(image)), (0x10ff0000, 0x10000))
        image[0x198] ^= 1
        self.assertIsNone(high_stack_irq_boot_ram(bytes(image)))
