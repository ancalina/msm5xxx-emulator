import struct
import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch

from capstone import arm as a

from msm5xxx_emulator.detection.devices.input.halfword_jump_flow import (
    _contact_read, _event_buffer_store,
)
from msm5xxx_emulator.detection.devices.input.halfword_jump_rows import (
    _contact_event_code, halfword_jump_row_property,
)


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value & 0xffff)


def _contact_image(*, field_offset=0x34, mask=0x10, released_condition=1,
                   clobber_descriptor=False):
    image = bytearray(0x100)
    # Literal-owned descriptor pointer -> halfword input -> masked low-active
    # branch. The addresses and registers are independent of production scans.
    _put16(image, 0x7a, 0x4e09)  # LDR R6, literal at 0xa0
    _put16(image, 0x7c, 0x2633 if clobber_descriptor else 0x46c0)
    pointer = 0x6800 | (field_offset // 4) << 6 | 6 << 3
    _put16(image, 0x7e, pointer)  # LDR R0,[R6,#field_offset]
    _put16(image, 0x80, 0x8800)  # LDRH R0,[R0]
    _put16(image, 0x82, 0x2300 | mask)  # MOVS R3,#mask
    _put16(image, 0x84, 0x46c0)  # NOP
    _put16(image, 0x86, 0x4018)  # ANDS R0,R3
    _put16(image, 0x88, 0x3520)  # ADDS R5,#0x20
    _put16(image, 0x8a, 0x2800)  # CMP R0,#0
    delta = (0xb0 - (0x8c + 4)) // 2
    _put16(image, 0x8c, 0xd000 | released_condition << 8 | (delta & 0xff))
    struct.pack_into("<I", image, 0xa0, 0x10001000)
    # Low-contact path stores a source-derived event byte at SP+4.
    _put16(image, 0x8e, 0x205a)  # MOVS R0,#0x5a
    _put16(image, 0x90, 0xab00)  # ADD R3,SP,#0
    _put16(image, 0x92, 0x7118)  # STRB R0,[R3,#4]
    _put16(image, 0x94, 0x2401)  # MOVS R4,#1
    _put16(image, 0x96, 0xe013)  # B outside the bounded contact fragment
    return image


def _event_store_image(*, clobber_base=False, clobber_event=False,
                       stack_offset=4):
    image = bytearray(0x140)
    _put16(image, 0x100, 0x5c00 | 2 << 6 | 1 << 3 | 6)  # LDRB R6,[R1,R2]
    _put16(image, 0x102, 0xab00 | (stack_offset // 4))  # ADD R3,SP,#offset
    pc = 0x104
    if clobber_base:
        _put16(image, pc, 0x2300)  # MOVS R3,#0 destroys the frame alias
        pc += 2
    if clobber_event:
        _put16(image, pc, 0x2633)  # MOVS R6,#0x33 destroys the loaded event
        pc += 2
    _put16(image, pc, 0x5400 | 4 << 6 | 3 << 3 | 6)  # STRB R6,[R3,R4]
    return image


class HalfwordJumpRowsTests(unittest.TestCase):
    def test_proves_descriptor_backed_active_low_contact_and_event_byte(self):
        image = _contact_image()
        profile = _contact_read(image, 0x80, 0x10001000, 0x40)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["mask"], 0x10)
        self.assertEqual(profile["released_target"], 0xb0)
        event, evidence = _contact_event_code(image, profile["branch_site"])
        self.assertEqual(event, 0x5a)
        self.assertIn((0x92, 2), evidence)

    def test_rejects_wrong_descriptor_field_mask_and_polarity(self):
        self.assertIsNone(_contact_read(
            _contact_image(field_offset=0x30), 0x80, 0x10001000, 0x40))
        self.assertIsNone(_contact_read(
            _contact_image(mask=8), 0x80, 0x10001000, 0x40))
        self.assertIsNone(_contact_read(
            _contact_image(released_condition=0), 0x80, 0x10001000, 0x40))
        self.assertIsNone(_contact_read(
            _contact_image(clobber_descriptor=True), 0x80,
            0x10001000, 0x40))

    def test_rejects_contact_path_without_proven_buffer_event(self):
        image = _contact_image()
        _put16(image, 0x92, 0x7218)  # Writes at SP+8, not the event slot.
        profile = _contact_read(image, 0x80, 0x10001000, 0x40)
        self.assertIsNotNone(profile)
        self.assertIsNone(_contact_event_code(image, profile["branch_site"]))

    def test_event_load_reaches_stack_buffer_store(self):
        self.assertEqual(_event_buffer_store(
            _event_store_image(), 0x100, a.ARM_REG_R6), 0x104)

    def test_rejects_clobbered_event_stack_alias_or_wrong_slot(self):
        for image in (_event_store_image(clobber_base=True),
                      _event_store_image(clobber_event=True),
                      _event_store_image(stack_offset=8)):
            self.assertIsNone(_event_buffer_store(
                image, 0x100, a.ARM_REG_R6))

    def test_admitted_property_includes_the_proven_released_contact(self):
        image = bytes(0x1000)
        profile = {'descriptor': 0x01000100, 'dependencies': [(0x100, 2)],
                   'row_ports': [0x03000720, 0x03000724],
                   'row_masks': [0x42, 0x1015],
                   'presence_site': 0x100, 'sense_site': 0x200,
                   'sense_address': 0x0300072c,
                   'contact': {'read_site': 0x80, 'mask': 0x10,
                               'dependencies': {(0x80, 2)}}}
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x01000000, ram_size=0x1000,
                                 board_status_input=None)
        with patch('msm5xxx_emulator.detection.devices.input.halfword_jump_rows._scan_profiles',
                   return_value=[profile]):
            value, admitted = halfword_jump_row_property(image, config)
        self.assertEqual(value,
            'matrix-halfword-wires=1000100:100:200:3000720:42:3000724:1015,'
            'experimental-matrix-contact=80:10')
        self.assertEqual(admitted['released_contact']['status_site'], 0x80)
        json.dumps(admitted)


if __name__ == "__main__":
    unittest.main()
