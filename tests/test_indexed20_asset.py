"""Synthetic source checks for stack-passed indexed image arguments."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.devices.display import indexed20_asset


class ThumbSource:
    def __init__(self):
        self.image = bytearray(0x300)

    def half(self, address, value):
        struct.pack_into('<H', self.image, address, value)

    def literal(self, address, register, value, pool):
        base = (address + 4) & ~3
        delta = pool - base
        if delta < 0 or delta % 4 or delta // 4 > 255:
            raise AssertionError('literal outside Thumb range')
        self.half(address, 0x4800 | register << 8 | delta // 4)
        struct.pack_into('<I', self.image, pool, value)

    def bl(self, address, target):
        delta = target - address - 4
        value = delta >> 1
        self.half(address, 0xF000 | ((value >> 11) & 0x7ff))
        self.half(address + 2, 0xF800 | (value & 0x7ff))

    def build(self, *, output_slot=4, source_slot=0):
        # Caller places source and output pointers into outgoing stack slots.
        self.half(0x20, 0xB500)  # push {lr}
        self.literal(0x22, 1, 0xa0, 0x280)
        self.literal(0x24, 2, 0x14000000, 0x284)
        self.half(0x26, 0x9100 | (source_slot // 4))  # str r1, [sp, #imm]
        self.half(0x28, 0x9200 | (output_slot // 4))  # str r2, [sp, #imm]
        self.bl(0x2a, 0x100)
        self.half(0x2e, 0xbd00)  # pop {pc}

        # Callee frame maps entry-SP slots 0 and 4, reads an image header,
        # and sends a halfword through the second pointer.
        self.half(0x100, 0xb510)  # push {r4, lr}
        self.half(0x102, 0xb081)  # sub sp, #4
        self.half(0x104, 0xab03)  # add r3, sp, #12
        self.half(0x106, 0x681c)  # ldr r4, [r3]
        self.half(0x108, 0xab04)  # add r3, sp, #16
        self.half(0x10a, 0x681d)  # ldr r5, [r3]
        self.half(0x10c, 0x78e0)  # ldrb r0, [r4, #3]
        self.half(0x10e, 0x7901)  # ldrb r1, [r4, #4]
        self.half(0x110, 0x1c2e)  # adds r6, r5, #0
        self.half(0x112, 0x8030)  # strh r0, [r6]
        self.half(0x114, 0xbd10)  # pop {r4, pc}
        return bytes(self.image)


class Indexed20AssetQueries(unittest.TestCase):
    def test_stack_slots_bind_header_pointer_and_rgb_halfword_output(self):
        facts = facts_for(ThumbSource().build())
        caller = facts.function(CodeAddress(0x20, 'thumb'), budget=128)
        decoder = facts.function(CodeAddress(0x100, 'thumb'), budget=128)
        call_site = CodeAddress(0x2a, 'thumb')
        loads = indexed20_asset.stack_argument_loads(facts, decoder)
        self.assertEqual([(slot, register) for slot, register, _ in loads],
                         [(0, 70), (4, 71)])
        bindings = indexed20_asset.stack_argument_bindings(
            facts, caller, call_site, decoder)
        self.assertEqual([(item['slot'], item['register'], item['value'])
                          for item in bindings],
                         [(0, 70, 0xa0), (4, 71, 0x14000000)])
        self.assertEqual(indexed20_asset.output_stack_slots(
            facts, decoder, loads), frozenset({4}))

    def test_mutated_outgoing_slot_does_not_bind_output_pointer(self):
        facts = facts_for(ThumbSource().build(output_slot=8))
        caller = facts.function(CodeAddress(0x20, 'thumb'), budget=128)
        decoder = facts.function(CodeAddress(0x100, 'thumb'), budget=128)
        bindings = indexed20_asset.stack_argument_bindings(
            facts, caller, CodeAddress(0x2a, 'thumb'), decoder)
        self.assertEqual([(item['slot'], item['value']) for item in bindings],
                         [(0, 0xa0)])


if __name__ == '__main__':
    unittest.main()
