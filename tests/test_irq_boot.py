import unittest

from msm5xxx_emulator.detection.devices.memory.irq_boot import has_high_stack_irq_boot


class IrqBootTest(unittest.TestCase):
    def test_requires_dispatcher_stacks_and_register_initializer(self):
        image = bytearray(0x600)
        image[0x20:0x3c] = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
        image[0x110:0x114] = bytes.fromhex('0020ffff')
        image[0x140:0x158] = bytes.fromhex('00d27f1890e77f1800c97f1890db7f1890e87f1800da7f18')
        image[0x200:0x220] = bytes.fromhex('f8b5bf49002008608904c8600121c9020b22d2065160bb4a49041160d160b24a')
        image[0x502:0x506] = bytes.fromhex('00160080')
        self.assertTrue(has_high_stack_irq_boot(bytes(image)))
        image[0x502] ^= 1
        self.assertFalse(has_high_stack_irq_boot(bytes(image)))
