import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.storage import boot_dual_nor


class BootDualNorTest(unittest.TestCase):
    def test_requires_linked_boot_commands_and_bank_table(self):
        image = bytearray(0xb000)
        window = 0x3202
        dram, nor, table = window - 0x1f26, window + 0x65ac, window + 0x4036
        image[dram:dram + len(boot_dual_nor._DRAM)] = boot_dual_nor._DRAM
        image[nor:nor + len(boot_dual_nor._NOR)] = boot_dual_nor._NOR
        image[table:table + len(boot_dual_nor._TABLE)] = boot_dual_nor._TABLE
        image[dram + 0x80:dram + 0x84] = bytes.fromhex('a6221200')
        providers = {'high_stack_irq_boot_ram': lambda _: (0x187f0000, 0x10000),
                     'find_indexed44_boot': lambda _: {'evidence': [{'span': [window, 40]}]}}
        with patch.dict(boot_dual_nor.__dict__, providers):
            self.assertTrue(boot_dual_nor.has_boot_dual_nor(bytes(image)))
            image[nor + 8] ^= 1
            self.assertFalse(boot_dual_nor.has_boot_dual_nor(bytes(image)))
