"""Synthetic external power-allow GPIO recognition."""
import struct
import unittest

from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.registry import device_domain
find_cold_power_guard = device_domain('external_bus.cold_power_guard').find_cold_power_guard
from msm5xxx_emulator.detection.registry import device_domain
find_board_status_input = device_domain('input.rules').find_board_status_input


class ColdPowerGuardTests(unittest.TestCase):
    def test_guard_requires_instructions_and_literals(self):
        image = bytearray(0x800)
        guard = bytes.fromhex(
            'b0b40020134901220a7000220a70114fbc89102323402024002b08d1'
            '3888c00814d2bc813a80012008700a70fce73d88eb080bd2094b1b88'
            '5b0807d2bc813a8001230b700a700130ff28fad3b0bc7047')
        def place(at):
            image[at:at + len(guard)] = guard
            for offset, value in ((0x52, 0x03001080), (0x56, 0x03000720),
                                  (0x5a, 0x04800020)):
                struct.pack_into('<I', image, at + offset, value)
        place(0x102)
        place(0x302)
        self.assertEqual(find_cold_power_guard(image), BoardStatusInput(0x03000720, 4, 4))
        self.assertEqual(find_board_status_input(bytes(image)), BoardStatusInput(0x03000720, 4, 4))
        for offset in (0x102, 0x154, 0x158, 0x15c):
            altered = bytearray(image)
            altered[offset] ^= 1
            self.assertIsNone(find_cold_power_guard(altered))
        place(0x502)
        self.assertIsNone(find_cold_power_guard(image))
