import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.devices.input.halfword_jump_flow import (
    _cfg_preserves_register, _jump_switch, _matrix_lookup, _row_footer,
)


def _put16(image, address, value):
    struct.pack_into("<H", image, address, value & 0xffff)


def _conditional(pc, target, condition):
    delta = target - (pc + 4)
    assert delta % 2 == 0 and -256 <= delta // 2 <= 255
    return 0xd000 | condition << 8 | (delta // 2 & 0xff)


def _unconditional(pc, target):
    delta = target - (pc + 4)
    assert delta % 2 == 0 and -2048 <= delta // 2 <= 2047
    return 0xe000 | (delta // 2 & 0x7ff)


def _switch_image(*, bound=6, branch_condition=2, wrong_row=False,
                  bad_init=False, duplicate=False, outside=False,
                  table_at=0x120):
    image = bytearray(0x240)
    # Independent Thumb layout: zeroed R4 counter, six-way unsigned guard,
    # ADR/LDRH halfword-offset switch and six separated arm destinations.
    _put16(image, 0xF0, 0xB500)
    for site in range(0xF2, 0x100, 2):
        _put16(image, site, 0x46C0)
    _put16(image, 0x100, 0x2401 if bad_init else 0x2400)
    _put16(image, 0x102, 0x2c00 | bound)  # CMP R4,#bound
    _put16(image, 0x104, _conditional(0x104, 0x190, branch_condition))
    _put16(image, 0x106, 0xa306)  # ADR R3,table at 0x120
    adr_pc_base = (0x106 + 4) & ~3
    adr_delta = table_at - adr_pc_base
    assert adr_delta % 4 == 0 and 0 <= adr_delta // 4 <= 255
    _put16(image, 0x106, 0xa300 | (adr_delta // 4))
    row_index = 5 if wrong_row else 4
    # ADD R3,R3,R4; LDRH R3,[R3,R4]
    _put16(image, 0x108, 0x1800 | row_index << 6 | 3 << 3 | 3)
    _put16(image, 0x10a, 0x5a00 | row_index << 6 | 3 << 3 | 3)
    _put16(image, 0x10c, 0x1800 | 3 << 6 | 3 << 3 | 3)  # ADD R3,R3,R3
    _put16(image, 0x10e, 0x449f)  # ADD PC,R3
    targets = [0x130 + 0x10 * index for index in range(6)]
    offsets = [(target - (0x10e + 4)) // 2 for target in targets]
    if duplicate:
        offsets[-1] = offsets[-2]
    if outside:
        offsets[-1] = 0x7fff
    for index, offset in enumerate(offsets):
        if table_at + 2 * index <= len(image) - 2:
            _put16(image, table_at + 2 * index, offset)
    _put16(image, 0x1a0, 0x46c0)
    _put16(image, 0x190, _unconditional(0x190, 0x1C0))
    return image


def _lookup_image(*, stride=6, wrong_index=False, wrong_raw=False,
                  duplicate_key=False, outside_table=False):
    image = bytearray(0x1c0)
    sample = 0x100
    # Sample and normalize the low nibble, then select a single low column bit.
    code = {
        0x100: 0x8808,  # LDRH R0,[R1]
        0x102: 0x0700,  # LSL R0,R0,#28
        0x104: 0x0f00,  # LSR R0,R0,#28
        0x106: 0x280f,  # CMP R0,#15
        0x108: _conditional(0x108, 0x160, 0),
        0x10a: 0x0701,  # LSL R1,R0,#28
        0x10c: 0x0f09,  # LSR R1,R1,#28
        0x10e: 0x2000,  # MOVS R0,#0 (column)
        0x110: 0x2201,  # MOVS R2,#1 (sense bit)
        0x112: 0x4082,  # LSL R2,R0
        0x114: 0x438a,  # BIC R2,R1
        0x116: _conditional(0x116, 0x122, 0),
        0x118: 0x2200 | stride,  # MOVS R2,#stride
        0x11a: 0x4b0d,  # LDR R3,[PC,#0x34] -> table address at 0x180
        0x11c: 0x4342,  # MULS R2,R0,R2
        0x11e: 0x1800 | 3 << 6 | 2 << 3 | 2,  # ADD R2,R2,R3
        0x120: 0x5c00 | (6 if wrong_index else 7) << 6 | 2 << 3 | 6,
        0x122: 0x2c0a,  # CMP R4,#10
        0x124: _conditional(0x124, 0x170, 10),
        0x126: 0x3001,  # ADD R0,#1
        0x128: 0x0600,  # LSL R0,R0,#24
        0x12a: 0x0e00,  # LSR R0,R0,#24
        0x12c: 0x2804,  # CMP R0,#4
        0x12e: _conditional(0x12e, 0x110, 11),
    }
    if wrong_raw:
        code[0x10a] = 0x0709  # LSL R1,R1,#28; no longer derives from sample
    for address, value in code.items():
        _put16(image, address, value)
    table = 0x180
    if outside_table:
        struct.pack_into("<I", image, 0x150, 0x1b8)
    else:
        struct.pack_into("<I", image, 0x150, table)
    cells = bytearray(b"123456789*0#abcdefghijkl")
    if duplicate_key:
        cells[1] = ord("1")
    image[table:table + 24] = cells
    return image


class HalfwordJumpFlowTests(unittest.TestCase):
    def test_resolves_six_bounded_halfword_offsets(self):
        result = _jump_switch(_switch_image(), 0x1c0)
        self.assertIsNotNone(result)
        self.assertEqual(result["row_register"], a.ARM_REG_R4)
        self.assertEqual(result["arms"], (0x130, 0x140, 0x150,
                                          0x160, 0x170, 0x180))
        self.assertEqual(result["table"], 0x120)

    def test_rejects_wrong_guard_register_or_polarity(self):
        wrong = _switch_image()
        _put16(wrong, 0x102, 0x2d06)  # CMP R5,#6
        self.assertIsNone(_jump_switch(wrong, 0x1c0))
        self.assertIsNone(_jump_switch(
            _switch_image(branch_condition=3), 0x1c0))
        self.assertIsNone(_jump_switch(
            _switch_image(bound=5), 0x1c0))
        self.assertIsNone(_jump_switch(
            _switch_image(wrong_row=True), 0x1c0))
        self.assertIsNone(_jump_switch(
            _switch_image(bad_init=True), 0x1c0))

    def test_rejects_duplicate_and_out_of_range_arm_targets(self):
        self.assertIsNone(_jump_switch(
            _switch_image(duplicate=True), 0x1c0))
        self.assertIsNone(_jump_switch(
            _switch_image(outside=True), 0x1c0))
        self.assertIsNone(_jump_switch(
            _switch_image(table_at=0x23c), 0x1c0))

    def test_initializer_and_guard_cannot_be_predicated_or_bypassed(self):
        for site, word in ((0xFE, 0xBF08),  # IT EQ before initializer.
                           (0xFC, _unconditional(0xFC, 0x10E)),
                           (0xFC, _unconditional(0xFC, 0x104))):
            image = _switch_image()
            _put16(image, site, word)
            with self.subTest(site=site, word=word):
                self.assertIsNone(_jump_switch(image, 0x1C0))

    def test_switch_without_a_source_function_entry_rejects_cleanly(self):
        image = _switch_image()
        _put16(image, 0xF0, 0x46C0)
        self.assertIsNone(_jump_switch(image, 0x1C0))

    def test_proves_same_counter_init_increment_truncate_and_backedge(self):
        image = bytearray(0x1c0)
        header, sample, row = 0x40, 0x80, a.ARM_REG_R4
        pc = sample + 2
        words = [0x3401, 0x0624, 0x0e24, 0x2c06,
                 _conditional(pc + 8, pc + 0x20, 10),
                 _unconditional(pc + 10, header)]
        for index, word in enumerate(words):
            _put16(image, pc + 2 * index, word)
        self.assertEqual(_row_footer(image, header, sample, row), {
            "increment": pc, "compare": pc + 6, "bound_branch": pc + 8,
            "exit": pc + 0x20, "backedge": pc + 10})
        _put16(image, pc, 0x3501)  # increment R5 instead of the row counter
        self.assertIsNone(_row_footer(image, header, sample, row))

        for address, word in ((pc + 6, 0x2c05),
                              (pc + 10, _unconditional(pc + 10, header + 2))):
            changed = bytearray(0x1c0)
            for index, source in enumerate(words):
                _put16(changed, pc + 2 * index,
                       word if pc + 2 * index == address else source)
            self.assertIsNone(_row_footer(changed, header, sample, row))

    def test_predicated_footer_cannot_prove_the_counter_recurrence(self):
        image = bytearray(0x1c0)
        header, sample, row = 0x40, 0x80, a.ARM_REG_R4
        _put16(image, sample + 2, 0xbf08)  # IT EQ can skip the increment.
        pc = sample + 4
        words = (0x3401, 0x0624, 0x0e24, 0x2c06,
                 _conditional(pc + 8, pc + 0x20, 10),
                 _unconditional(pc + 10, header))
        for index, word in enumerate(words):
            _put16(image, pc + 2 * index, word)
        self.assertIsNone(_row_footer(image, header, sample, row))
        self.assertFalse(_cfg_preserves_register(image, sample + 2, pc, row))

    def test_source_executes_four_by_six_numeric_lookup(self):
        result = _matrix_lookup(_lookup_image(), 0x100, 0x120,
                                a.ARM_REG_R7, 0x160)
        self.assertIsNotNone(result)
        self.assertEqual(result[2], 0x180)
        self.assertEqual(result[3][:6], list(b"123456"))

    def test_rejects_bad_column_source_stride_index_and_duplicate_digit(self):
        for image in (_lookup_image(stride=5),
                      _lookup_image(wrong_index=True),
                      _lookup_image(wrong_raw=True),
                      _lookup_image(duplicate_key=True),
                      _lookup_image(outside_table=True)):
            self.assertIsNone(_matrix_lookup(
                image, 0x100, 0x120, a.ARM_REG_R7, 0x160))


if __name__ == "__main__":
    unittest.main()
