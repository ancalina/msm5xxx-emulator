"""Synthetic reset-linked presence input and released strap projection."""
from __future__ import annotations

import unittest

from msm5xxx_emulator.detection.registry import device_domain
from test_external_devices import _reset_helper, ldr_literal, put16, put32

find_boot_presence = device_domain(
    'external_bus.boot_presence').find_boot_presence
detect_external_bus = device_domain('external_bus.rules').detect_external_bus
external_bus_plan = device_domain('external_bus.projection').external_bus_plan


def _image(*, read_width='half', shift=27, mask=0x1f, present=1,
           absent=0, control_value=0xe040, absent_write=True,
           status_base=0x09000020, status_add=0x40, setup_width='half',
           reset_link=True):
    image = bytearray(0x1000)
    put32(image, 0, 0xEA000006)
    _reset_helper(image, 0x20, 0x101 if reset_link else 0x181, 0x80)

    entry, pool = 0x100, 0x300
    read = 0x8800 | (8 << 6) | (2 << 3)
    if read_width == 'word':
        read = 0x6810  # LDR r0, [r2]
    elif read_width == 'byte':
        read = 0x7810  # LDRB r0, [r2]
    absent_entry = entry + 30
    branch_imm = (absent_entry - (entry + 24)) // 2
    words = (
        0xB510,
        ldr_literal(4, entry + 2, pool),
        ldr_literal(1, entry + 4, pool + 4),
        {'half': 0x8021, 'word': 0x6021, 'byte': 0x7021}[setup_width],
        ldr_literal(2, entry + 8, pool + 8),
        0x3200 | status_add,  # ADDS r2, #status_add
        read,
        (shift << 6),  # LSLS r0, r0, #shift
        0x0800 | (shift << 6),  # LSRS r0, r0, #shift
        0x2800 | mask,
        0xD000 | branch_imm,  # BEQ absent
        ldr_literal(1, entry + 22, pool + 12),
        0x8021 if absent_write else 0x0000,
        0x2000 | present,
        0xBD10,
        0x2000 | absent,
        0xBD10,
    )
    put16(image, entry, *words)
    put32(image, pool, 0x09000000, control_value, status_base, 0x2000)
    return bytes(image)


def _scratch_return_image():
    image = bytearray(_image())
    entry = 0x100
    put16(image, entry, 0xB5F0)  # PUSH {r4-r7,lr}
    put16(image, entry + 28, 0xBDF0)  # present path: POP {r4-r7,pc}
    put16(image, entry + 30, 0xE7FF, 0x2000, 0xE7FF,
          0xBCF0, 0xBC08, 0x4718)
    return image


class BootPresenceTests(unittest.TestCase):
    def test_reset_linked_presence_test_projects_value_and_guarded_claim(self):
        image = _image()
        profile = find_boot_presence(image)
        self.assertEqual(profile['value'], 0x1f)
        self.assertEqual(profile['read_mask'], 0x1f)
        self.assertTrue(profile['sites'])

        plan, reason = detect_external_bus(image)
        self.assertEqual(reason, 'accepted')
        self.assertEqual(plan['machine_properties']['external-strap-value'], 0x1f)
        resolution, reason = external_bus_plan(plan, image, None, None)
        self.assertIsNone(reason)
        self.assertIn(('external-strap-value', 0x1f), resolution.plan.properties)
        claim, = resolution.plan.claims
        self.assertEqual((claim.start, claim.end, claim.shared_resource),
                         (0x09000070, 0x09000071, 'cs09-strap'))

        changed = bytearray(image)
        changed[0x102] ^= 1
        mutated, _ = detect_external_bus(bytes(changed))
        self.assertFalse(mutated and 'external-strap-value' in
                         mutated['machine_properties'])
        _, reason = external_bus_plan(plan, bytes(changed), None, None)
        self.assertEqual(reason, 'source-guard-mismatch')

    def test_rejects_unproved_width_mask_return_and_reset_link(self):
        mutations = (
            ('wrong read width', _image(read_width='word')),
            ('wrong shift mask', _image(shift=26)),
            ('wrong comparison mask', _image(mask=0x0f)),
            ('absent path returns present', _image(absent=1)),
            ('wrong control value', _image(control_value=0xe000)),
            ('missing present path control write', _image(absent_write=False)),
            ('wrong status register', _image(status_base=0x09000024)),
            ('reset does not call initializer', _image(reset_link=False)),
        )
        for name, image in mutations:
            with self.subTest(name=name):
                self.assertIsNone(find_boot_presence(image))

    def test_word_controller_setup_accepts_independent_status_base(self):
        image = _image(control_value=0x55, status_base=0x09000030,
                       status_add=0x30, setup_width='word')
        profile = find_boot_presence(image)
        self.assertEqual(profile['value'], 0x1f)

        plan, reason = detect_external_bus(image)
        self.assertEqual(reason, 'accepted')
        self.assertEqual(plan['machine_properties']['external-strap-value'], 0x1f)
        resolution, reason = external_bus_plan(plan, image, None, None)
        self.assertIsNone(reason)
        self.assertIn(('external-strap-value', 0x1f), resolution.plan.properties)

        changed = bytearray(image)
        changed[0x106] ^= 1  # mutate the word controller setup instruction
        _, reason = external_bus_plan(plan, bytes(changed), None, None)
        self.assertEqual(reason, 'source-guard-mismatch')

    def test_byte_controller_write_without_halfword_setup_is_rejected(self):
        image = _image(control_value=0x55, status_base=0x09000030,
                       status_add=0x30, setup_width='byte')
        self.assertIsNone(find_boot_presence(image))

    def test_shared_tail_zero_return_restores_saved_lr_to_scratch(self):
        image = _scratch_return_image()
        profile = find_boot_presence(bytes(image))
        self.assertEqual(profile['value'], 0x1f)

        wrong_register = bytearray(image)
        put16(wrong_register, 0x100 + 40, 0x4710)  # BX r2, while POP restored r3
        self.assertIsNone(find_boot_presence(bytes(wrong_register)))

        wrong_stack = bytearray(image)
        put16(wrong_stack, 0x100, 0xB5E0)  # parent no longer saves LR
        self.assertIsNone(find_boot_presence(bytes(wrong_stack)))

        mismatched_pop = bytearray(image)
        put16(mismatched_pop, 0x100 + 36, 0xBC70)  # POP omits saved r7
        self.assertIsNone(find_boot_presence(bytes(mismatched_pop)))

        clobbered_scratch = bytearray(image)
        put16(clobbered_scratch, 0x100 + 38, 0x2301)  # MOVS r3,#1 before BX r3
        self.assertIsNone(find_boot_presence(bytes(clobbered_scratch)))

        extra_push = bytearray(image)
        put16(extra_push, 0x100 + 28, 0xB401)  # PUSH r0 on the present path
        self.assertIsNone(find_boot_presence(bytes(extra_push)))

        stack_adjust = bytearray(image)
        put16(stack_adjust, 0x100 + 26, 0xB081)  # SUB SP,#4 on the present path
        self.assertIsNone(find_boot_presence(bytes(stack_adjust)))

        non_callee_save = bytearray(image)
        put16(non_callee_save, 0x100, 0xB5F1)  # PUSH adds caller-saved r0
        self.assertIsNone(find_boot_presence(bytes(non_callee_save)))

if __name__ == '__main__':
    unittest.main()
