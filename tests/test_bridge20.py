"""Synthetic code-query fixtures for indexed bridge identification."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.devices.external_bus.bridge20 import find_bridge20


class ThumbImage:
    def __init__(self, size=0x600):
        self.image = bytearray(size)
        self.pools = {}

    def half(self, address, value):
        struct.pack_into('<H', self.image, address, value)

    def word(self, address, value):
        struct.pack_into('<I', self.image, address, value)

    def literal(self, address, register, value, name, pool):
        base = (address + 4) & ~3
        displacement = pool - base
        if displacement < 0 or displacement % 4 or displacement // 4 > 255:
            raise AssertionError('literal is outside Thumb range')
        self.half(address, 0x4800 | register << 8 | displacement // 4)
        self.word(pool, value)
        self.pools[name] = pool

    def bl(self, address, target):
        displacement = target - address - 4
        if displacement & 1 or not -(1 << 22) <= displacement < (1 << 22):
            raise AssertionError('call is outside Thumb range')
        value = displacement >> 1
        self.half(address, 0xF000 | (value >> 11 & 0x7ff))
        self.half(address + 2, 0xF800 | (value & 0x7ff))

    def finish(self):
        return bytes(self.image)


def _bridge_image():
    assembler = ThumbImage()

    # Controller-ID owner: getter(0), then compare the returned ID with 0x7068.
    assembler.half(0x80, 0xB500)       # push {lr}
    assembler.half(0x82, 0x2000)       # movs r0, #0
    assembler.bl(0x84, 0x140)
    assembler.literal(0x88, 3, 0x7068, 'controller_id', 0x100)
    assembler.half(0x8a, 0x4298)       # cmp r0, r3
    assembler.half(0x8c, 0xD001)       # beq 0x90
    assembler.half(0x8e, 0x2000)       # movs r0, #0
    assembler.half(0x90, 0xBD00)       # pop {pc}

    # Indexed getter selects register 1, reads its value, polls mask 4,
    # and restores selector 0.
    assembler.half(0x140, 0xB510)
    assembler.literal(0x142, 4, 0x20000000, 'command_port', 0x200)
    assembler.half(0x144, 0x2101)
    assembler.half(0x146, 0x8021)      # strh r1, [r4]
    assembler.literal(0x148, 3, 0x20000004, 'data_port', 0x204)
    assembler.half(0x14a, 0x8819)      # ldrh r1, [r3]
    assembler.half(0x14c, 0x2004)      # movs r0, #4
    assembler.bl(0x14e, 0x1c0)
    assembler.half(0x152, 0x2100)
    assembler.half(0x154, 0x8021)
    assembler.half(0x156, 0xBD10)

    # Status poll reads command-base + 2 and loops while the selected bit is set.
    assembler.half(0x1c0, 0xB500)
    assembler.literal(0x1c2, 2, 0x20000000, 'status_base', 0x280)
    assembler.half(0x1c4, 0x8851)      # ldrh r1, [r2, #2]
    assembler.half(0x1c6, 0x4201)      # tst r1, r0
    assembler.half(0x1c8, 0xD1FC)      # bne 0x1c4
    assembler.half(0x1ca, 0xBD00)
    return assembler


class Bridge20Queries(unittest.TestCase):
    def test_generated_id_getter_and_status_poll_are_linked(self):
        assembler = _bridge_image()
        profile = find_bridge20(assembler.finish())
        self.assertIsNotNone(profile)
        self.assertEqual({key: profile[key] for key in (
            'controller_id', 'command_port', 'status_port', 'data_port',
            'data_aperture')}, {
                'controller_id': 0x7068,
                'command_port': 0x20000000,
                'status_port': 0x20000002,
                'data_port': 0x20000004,
                'data_aperture': 2,
            })
        self.assertGreaterEqual(len(profile['evidence']), 3)

    def test_wrong_controller_id_mask_or_status_offset_rejects(self):
        for mutation, expected in (
            ('controller_id', 0x7069),
            ('wrong_mask', 1),
            ('wrong_status_offset', 0x8811),
        ):
            assembler = _bridge_image()
            if mutation == 'controller_id':
                assembler.word(assembler.pools['controller_id'], expected)
            elif mutation == 'wrong_mask':
                assembler.half(0x14c, 0x2000 | expected)
            else:
                assembler.half(0x1c4, expected)
            with self.subTest(mutation=mutation):
                self.assertIsNone(find_bridge20(assembler.finish()))

    def test_unlinked_id_literal_is_not_a_controller_profile(self):
        assembler = ThumbImage()
        assembler.literal(0x40, 3, 0x7068, 'controller_id', 0x100)
        self.assertIsNone(find_bridge20(assembler.finish()))


if __name__ == '__main__':
    unittest.main()
