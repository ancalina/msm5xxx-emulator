"""Synthetic checks for seven-row source layout and copied halfword reads."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from capstone import arm as a

from msm5xxx_emulator.detection.devices.input.mapped_seven_rows import (
    _event_handoff,
    _callee_preserves_register,
    _path_exists,
    _scan_control_flow,
    _wire_layout,
    mapped_seven_row_property,
)
from msm5xxx_emulator.detection.devices.input.row_execution import _Bits, _row_outputs
from msm5xxx_emulator.detection.devices.input.mapped_seven_rows_flow import _clear_commit_helper


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value)


def _clear_helper_fixture(*, clobber_event=False, unknown_call=False,
                          clear_low=False):
    image = bytearray(0x200)
    descriptor, descriptor_rom, entry, port, row_mask = 0x01000000, 0x01a0, 0x100, 0x03000720, 1
    body = [0xb500, 0x491f]  # push {lr}; ldr r1, [pc, #0x7c]
    if unknown_call:
        body.extend((0xf000, 0xf800))  # unresolved nested BL into following code
    body.extend((0x2301,))  # movs r3, #1
    if clobber_event:
        body.append(0x2420)  # movs r4, #0x20
    body.extend((0x898a, 0x439a if clear_low else 0x431a,
                 0x818a, 0x898a, 0x6909,
                 0x800a, 0xbc08, 0x4718))
    for index, word in enumerate(body):
        _put16(image, entry + index * 2, word)
    struct.pack_into("<I", image, 0x180, descriptor)
    struct.pack_into("<I", image, descriptor_rom + 0x10, port)
    return image, descriptor, descriptor_rom, entry, port, row_mask


class MappedSevenRowTests(unittest.TestCase):
    def test_row_wire_order_comes_from_alternating_source_bits(self):
        bits = (7, 1, 2, 3, 4, 5, 6)
        outputs = [{0x03000720: _Bits.constant(0xffff ^ (1 << bit))}
                   for bit in bits]
        self.assertEqual(_wire_layout(outputs),
                         ([0x03000720], [0x00fe], [6, 0, 1, 2, 3, 4, 5]))

    def test_reset_owned_halfword_row_value_reaches_gpio_output(self):
        image = bytearray(0x400)
        # ldrh r2, [r1, r0]; strh r2, [r3]
        _put16(image, 0x100, 0x5a0a)
        _put16(image, 0x102, 0x801a)
        struct.pack_into("<H", image, 0x300, 0x3b02)
        ram_target = 0x01001ef0
        dependencies = set()
        outputs, code = _row_outputs(image, 0x100, 0x104,
            {a.ARM_REG_R0: _Bits.constant(0),
             a.ARM_REG_R1: _Bits.constant(ram_target),
             a.ARM_REG_R3: _Bits.constant(0x03000724)},
            0x01000000, 0x200,
            copied_row=(None, 0x300, ram_target, 2),
            ram_dependencies=dependencies)
        self.assertEqual(outputs[0x03000724].value(), 0x3b02)
        self.assertIn((ram_target, 2), dependencies)
        self.assertIn((0x300, 2), code)

    def test_copied_halfword_read_rejects_unowned_or_unaligned_bytes(self):
        image = bytearray(0x400)
        _put16(image, 0x100, 0x5a0a)
        _put16(image, 0x102, 0x801a)
        struct.pack_into("<H", image, 0x300, 0x3b02)
        registers = {a.ARM_REG_R0: _Bits.constant(1),
                     a.ARM_REG_R1: _Bits.constant(0x01001ef0),
                     a.ARM_REG_R3: _Bits.constant(0x03000724)}
        self.assertIsNone(_row_outputs(image, 0x100, 0x104, registers,
            0x01000000, 0x200, copied_row=(None, 0x300, 0x01001ef0, 2)))
        registers[a.ARM_REG_R0] = _Bits.constant(2)
        self.assertIsNone(_row_outputs(image, 0x100, 0x104, registers,
            0x01000000, 0x200, copied_row=(None, 0x300, 0x01001ef0, 2)))

    def test_status_descriptor_claim_rejects_admission(self):
        self.assertEqual(mapped_seven_row_property(b"", SimpleNamespace(load_address=0),
            status_descriptor_claimed=True), (None, None))

    def test_event_handoff_tracks_the_loaded_register_into_stack_buffer(self):
        image = bytearray(0x200)
        # ldrb r4, [r0, r1]; mov r1, sp; strb r4, [r1]
        _put16(image, 0x100, 0x5c44)
        _put16(image, 0x102, 0x4669)
        _put16(image, 0x104, 0x700c)
        self.assertEqual(_event_handoff(image, 0x100, a.ARM_REG_R4, 0x20), 0x104)

        # A write to the event register breaks the source flow.
        _put16(image, 0x102, 0x2400)
        _put16(image, 0x104, 0x4669)
        _put16(image, 0x106, 0x700c)
        self.assertIsNone(_event_handoff(image, 0x100, a.ARM_REG_R4, 0x20))

    def test_event_handoff_follows_conditional_handler_branches(self):
        image = bytearray(0x200)
        # ldrb r4, [r0, r1]; cmp r2, #0; bne 0x10a; both arms store r4 to SP.
        for address, word in ((0x100, 0x5c44), (0x102, 0x2a00),
                              (0x104, 0xd101), (0x106, 0x4669),
                              (0x108, 0x700c), (0x10a, 0x4669),
                              (0x10c, 0x700c)):
            _put16(image, address, word)
        self.assertEqual(_event_handoff(image, 0x100, a.ARM_REG_R4, 0x20), 0x108)

    def test_event_register_crosses_only_source_proven_saved_callee(self):
        image = bytearray(0x200)
        # push {r4, lr}; movs r0, #1; pop {r4, pc}
        for address, word in ((0x100, 0xb510), (0x102, 0x2001),
                              (0x104, 0xbd10)):
            _put16(image, address, word)
        self.assertTrue(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

        # A callee that changes the event register without restoring it fails.
        _put16(image, 0x100, 0x2401)  # movs r4, #1
        _put16(image, 0x102, 0x4770)  # bx lr
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

        # The untouched-register path also requires the entry link to survive.
        _put16(image, 0x100, 0x4686)  # mov lr, r0
        _put16(image, 0x102, 0x4770)  # bx lr
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

    def test_saved_callee_rejects_stack_aliases_and_unmodeled_stack_changes(self):
        image = bytearray(0x200)
        # An extra PUSH changes the saved event and return slot depths.
        for address, word in ((0x100, 0xb510), (0x102, 0xb402),
                              (0x104, 0xbd10)):
            _put16(image, address, word)
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

        # A PUSH without the modeled event/link save cannot precede a return.
        for address, word in ((0x100, 0xb402), (0x102, 0x4770)):
            _put16(image, address, word)
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

        # An unrelated PUSH before the modeled pair leaves SP unbalanced.
        for address, word in ((0x100, 0xb402), (0x102, 0xb510),
                              (0x104, 0xbd10)):
            _put16(image, address, word)
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

        # An extra POP likewise cannot be matched to the initial save.
        for address, word in ((0x100, 0xb510), (0x102, 0xbc20),
                              (0x104, 0xbd10)):
            _put16(image, address, word)
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

        # Copying SP to a general register does not make stores harmless.
        for address, word in ((0x100, 0xb510), (0x102, 0x4668),
                              (0x104, 0x6001), (0x106, 0xbd10)):
            _put16(image, address, word)
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

        # An indirect SP write is rejected even without a memory operand.
        for address, word in ((0x100, 0xb510), (0x102, 0x4685),
                              (0x104, 0xbd10)):
            _put16(image, address, word)
        self.assertFalse(_callee_preserves_register(image, 0x100, a.ARM_REG_R4))

    def test_clear_commit_helper_preserves_event_and_balances_saved_link(self):
        image, descriptor, rom, entry, port, mask = _clear_helper_fixture()
        self.assertIsNotNone(_clear_commit_helper(image, entry, descriptor, rom,
            a.ARM_REG_R4, (0x31, 0x23), port, mask))

        clear_low, descriptor, rom, entry, port, mask = _clear_helper_fixture(
            clear_low=True)
        self.assertIsNotNone(_clear_commit_helper(clear_low, entry, descriptor, rom,
            a.ARM_REG_R4, (0x31, 0x23), port, mask))

        clobber, descriptor, rom, entry, port, mask = _clear_helper_fixture(
            clobber_event=True)
        self.assertIsNone(_clear_commit_helper(clobber, entry, descriptor, rom,
            a.ARM_REG_R4, (0x31, 0x23), port, mask))

        nested, descriptor, rom, entry, port, mask = _clear_helper_fixture(
            unknown_call=True)
        self.assertIsNone(_clear_commit_helper(nested, entry, descriptor, rom,
            a.ARM_REG_R4, (0x31, 0x23), port, mask))

    def test_scan_flow_uses_reachable_edges_and_dominators(self):
        image = bytearray(0x200)
        # movs r0, #0; cmp r0, #0; beq 0x10a; movs r1, #0; b 0x10c;
        # movs r1, #1; bx lr
        for address, word in ((0x100, 0x2000), (0x102, 0x2800),
                              (0x104, 0xd001), (0x106, 0x2100),
                              (0x108, 0xe000), (0x10a, 0x2101),
                              (0x10c, 0x4770)):
            _put16(image, address, word)
        flow = _scan_control_flow(image, 0x100, 0x110, 0x180, ())
        self.assertIsNotNone(flow)
        edges, reachable, dominators = flow
        self.assertIn(0x10c, reachable)
        self.assertIn(0x100, dominators[0x10c])
        self.assertNotIn(0x106, dominators[0x10c])
        self.assertTrue(_path_exists(edges, 0x10a, 0x10c))


if __name__ == "__main__":
    unittest.main()
