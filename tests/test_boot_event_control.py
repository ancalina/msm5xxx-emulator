import struct
import unittest

from msm5xxx_emulator.detection.devices.memory.boot_rules import (
    callback_control_address, has_boot_event_500_reset, has_boot_event_control_reset,
    has_boot_output_880,
    has_high_context_reset, has_high_handoff,
)


class BootEventControlTest(unittest.TestCase):
    def test_thumb_control_writes_resolve_all_three_banks(self):
        image = bytearray(0x100)
        struct.pack_into('<9H', image, 0x20, 0x4817, 0x2400, 0x6004,
                         0x4917, 0x2007, 0x7208, 0x4816, 0x2501, 0x6105)
        struct.pack_into('<3I', image, 0x80, 0x80001600, 0x80000740, 0x88004000)
        self.assertTrue(has_boot_output_880(bytes(image)))
        struct.pack_into('<I', image, 0x88, 0x88008000)
        self.assertFalse(has_boot_output_880(bytes(image)))

    def test_high_handoff_requires_magic_consumer_and_calls(self):
        image = bytearray(0x300)
        words = [0] * 23
        words[:12] = [0xE59F00F8, 0xE5101010, 0xE59F20F4, 0xE1520001,
                      0x1AFFFFDA, 0xE321F0D1, 0xE500E010, 0xE321F0D3,
                      0xE59F0000, 0xE5901000, 0xE2011004, 0xE3510004]
        words[18] = words[22] = 0xE12FFF30
        struct.pack_into('<23I', image, 0x100, *words)
        struct.pack_into('<2I', image, 0x200, 0xFFFFE000, 0x12345678)
        self.assertTrue(has_high_handoff(bytes(image)))
        struct.pack_into('<I', image, 0x204, 0x12345679)
        self.assertFalse(has_high_handoff(bytes(image)))

    def test_reset_context_and_high_stack_are_linked(self):
        image = bytearray(0x300)
        struct.pack_into('<I', image, 0, 0xEA000006)
        struct.pack_into('<8I', image, 0x20, 0xE59FC1C8, 0xE8AC67FF,
                         0xE10FB000, 0xE8AC0800, 0xE14FB000, 0xE8AC0800,
                         0xE10F1000, 0xE3C1201F)
        struct.pack_into('<12I', image, 0x94, 0xE59F0164, 0xE1A0D000,
                         0xE59F0160, 0xE3A02000, 0xE5802000, 0xE59F0158,
                         0xE5802000, 0xE59F0154, 0xE3A02F40, 0xE5802000,
                         0xE3A02000, 0xE5802000)
        struct.pack_into('<I', image, 0x1F0, 0xFFFF2F00)
        struct.pack_into('<4I', image, 0x200, 0xFFFF2F00, 0x80000500,
                         0x80000504, 0x8000050C)
        self.assertTrue(has_high_context_reset(bytes(image)))
        struct.pack_into('<I', image, 0x24, 0xE8AC67FE)
        self.assertFalse(has_high_context_reset(bytes(image)))

    def test_reset_event_pulse_and_high_thumb_call(self):
        image = bytearray(0x200)
        struct.pack_into('<I', image, 0, 0xEA000006)
        struct.pack_into('<12I', image, 0x20, 0xE59F0078, 0xE1A0D000,
                         0xE59F0074, 0xE3A02000, 0xE5802000, 0xE59F006C,
                         0xE5802000, 0xE59F0068, 0xE3A02F40, 0xE5802000,
                         0xE3A02000, 0xE5802000)
        struct.pack_into('<2I', image, 0x60, 0xE59F0098, 0xE12FFF30)
        struct.pack_into('<4I', image, 0xA0, 0xFFFF2000, 0x80000500,
                         0x80000504, 0x8000050C)
        struct.pack_into('<I', image, 0x100, 0xFFFF03F1)
        self.assertTrue(has_boot_event_500_reset(bytes(image)))
        struct.pack_into('<I', image, 0xAC, 0x80000508)
        self.assertFalse(has_boot_event_500_reset(bytes(image)))

    def test_reset_sequence_resolves_both_banks(self):
        image = bytearray(0x100)
        struct.pack_into('<I', image, 0, 0xEA000006)
        struct.pack_into('<9I', image, 0x20, 0xE59F0058, 0xE3A02000,
                         0xE5802000, 0xE59F0050, 0xE3A01008, 0xE1C010B0,
                         0xE3A00458, 0xE3A01008, 0xE1C010B0)
        struct.pack_into('<2I', image, 0x80, 0x80001600, 0x58000008)
        self.assertTrue(has_boot_event_control_reset(bytes(image)))
        struct.pack_into('<I', image, 0x84, 0x5800000A)
        self.assertFalse(has_boot_event_control_reset(bytes(image)))

    def test_callback_control_requires_both_linked_writes(self):
        image = bytearray(0x500)
        words = (0xE321F0D3, 0xE59F10F4, 0xE3A00003, 0xE5810000,
                 0xE59FD058, 0xE59F4058, 0xE4940004, 0xE3500000,
                 0x0A000009, 0xE321F0D2, 0xE1A0E004, 0xE321F0D3,
                 0xE12FFF30, 0xE3500000, 0x1A000000, 0xE321F0D2,
                 0xE1A0400E, 0xE321F0D3, 0xEAFFFFF2, 0xE59F10AC,
                 0xE3A00000, 0xE5810000)
        struct.pack_into('<22I', image, 0x100, *words)
        struct.pack_into('<I', image, 0x200, 0x60000240)
        self.assertEqual(callback_control_address(bytes(image)), 0x60000240)
        struct.pack_into('<I', image, 0x200, 0x80000320)
        self.assertEqual(callback_control_address(bytes(image)), 0x80000320)
        image[0x300:0x358] = image[0x100:0x158]
        struct.pack_into('<I', image, 0x400, 0x60000240)
        self.assertIsNone(callback_control_address(bytes(image)))
        image[0x300:0x358] = bytes(0x58)
        struct.pack_into('<I', image, 0x150, 0xE3A00001)
        self.assertIsNone(callback_control_address(bytes(image)))

