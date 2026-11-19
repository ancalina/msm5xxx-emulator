"""Independent synthetic evidence for byte-wide, active-low keypad rows."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.input.byte_rows import (
    byte_row_property,
    find_byte_row_scanners,
)
from msm5xxx_emulator.detection.devices.input.event_projection import (
    _matrix_input_position,
)
from msm5xxx_emulator.detection.devices.input.row_execution import _row_outputs


def _put16(image, at, value):
    struct.pack_into("<H", image, at, value)


def _put32(image, at, value):
    struct.pack_into("<I", image, at, value)


def _bl(image, at, target):
    delta = target - at - 4
    _put16(image, at, 0xF000 | ((delta >> 12) & 0x7ff))
    _put16(image, at + 2, 0xF800 | ((delta >> 1) & 0x7ff))


def _branch(image, at, cond, target):
    delta = (target - at - 4) // 2
    assert -128 <= delta <= 127
    _put16(image, at, 0xD000 | cond << 8 | (delta & 255))


def _jump(image, at, target):
    delta = (target - at - 4) // 2
    assert -1024 <= delta <= 1023
    _put16(image, at, 0xE000 | (delta & 0x7ff))


def _irq(image, at, enable):
    """Small, valid interrupt-state helper used by scanner call sites."""
    _put16(image, at, 0x4778)  # Thumb entry returns through LR.
    _put16(image, at + 2, 0)
    words = (0xE10F0000,
             0xE3C010C0 if enable else 0xE38010C0,
             0xE121F001, 0xE20000C0, 0xE12FFF1E)
    for n, word in enumerate(words):
        _put32(image, at + 4 + 4 * n, word)


def _fixture(*, clear=True, masks=None, row_order=None, sense=0x03000694,
             lookup=None, event_base=0x1600, clobber_row=False):
    """Emit a one-port scanner with generated labels and literal references."""
    image = bytearray(0x2400)
    port = 0x03000724
    masks = tuple(masks or (0x3f ^ (1 << row) for row in range(6)))
    row_order = tuple(row_order or range(6))
    col_map = bytearray(16)
    for raw, col in zip((14, 13, 11, 7), range(4)):
        col_map[raw] = col
    if lookup is not None:
        col_map[:] = lookup
    image[0x1500:0x1510] = col_map
    image[event_base:event_base + 24] = bytes(
        (ord("1"), ord("4"), ord("7"), ord("*"), ord("2"), ord("5"),
         ord("8"), ord("0"), ord("3"), ord("6"), ord("9"), ord("#"),
         0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c))

    pool = 0x500
    literals = {}

    def lit(at, reg, value):
        nonlocal pool
        slot = literals.get(value)
        if slot is None:
            slot = pool
            pool += 4
            literals[value] = slot
            _put32(image, slot, value)
        delta = slot - ((at + 4) & ~3)
        assert 0 <= delta <= 1020 and delta % 4 == 0
        _put16(image, at, 0x4800 | reg << 8 | delta // 4)

    # Function starts at 0x200. It initializes row zero, clears all six
    # active-low outputs, then checks the separate byte sense input.
    _put16(image, 0x200, 0xB520)  # PUSH {r5,lr}
    _put16(image, 0x202, 0x2500)  # row counter r5 = 0
    _bl(image, 0x204, 0x1000)     # mask interrupts
    clear_call = 0x208
    _put16(image, 0x208, 0x2000 if clear else 0x203f)
    lit(0x20a, 1, port)
    _put16(image, 0x20c, 0x7008)  # STRB r0,[r1]
    _bl(image, 0x20e, 0x1020)     # restore interrupts
    lit(0x212, 0, sense - 4)
    _put16(image, 0x214, 0x7900)  # LDRB r0,[r0,#4]
    _put16(image, 0x216, 0x0700)
    _put16(image, 0x218, 0x0f00)
    _put16(image, 0x21a, 0x280f)
    _branch(image, 0x21c, 0, 0x230)
    _jump(image, 0x21e, 0x230)

    loop = 0x230
    _put16(image, loop, 0x2d06)    # CMP r5,#6
    _branch(image, loop + 2, 2, 0x2a0)  # BHS to sample
    _bl(image, loop + 4, 0x1000)
    dispatch = loop + 8
    for row in range(6):
        _put16(image, dispatch + 4 * row, 0x2d00 | row)
        # Filled after the six row arms have been placed.
        _put16(image, dispatch + 4 * row + 2, 0xd000)
    arms = 0x260
    for i, row in enumerate(row_order):
        arm = arms + i * 8
        _put16(image, arm, 0x2000 | masks[i])
        lit(arm + 2, 1, port)
        _put16(image, arm + 4, 0x7008)
        _jump(image, arm + 6, 0x290)
        _branch(image, dispatch + 4 * row + 2, 0, arm)
    _bl(image, 0x290, 0x1020)
    if clobber_row:
        _put16(image, 0x294, 0x2500)  # Incorrectly replace row r5 before lookup.
        _jump(image, 0x296, 0x2a0)
    else:
        _jump(image, 0x294, 0x2a0)

    # One-byte sense sample and the column*6+row address into a 24-cell map.
    sense_site = 0x2a0
    lit(sense_site - 2, 0, sense - 4)
    for off, word in enumerate((0x7900, 0x0700, 0x0f00, 0x280f)):
        _put16(image, sense_site + 2 * off, word)
    cursor = sense_site + 10
    lit(cursor, 2, 0x1500); cursor += 2
    _put16(image, cursor, 0x5c10); cursor += 2  # LDRB r0,[r2,r0]
    _put16(image, cursor, 0x2106); cursor += 2  # column stride 6
    _put16(image, cursor, 0x4348); cursor += 2  # MULS r0,r1
    _put16(image, cursor, 0x1940); cursor += 2  # ADDS r0,r0,r5
    lit(cursor, 2, event_base); cursor += 2
    event_load = cursor
    _put16(image, cursor, 0x5c13); cursor += 2  # LDRB r3,[r2,r0]

    # Byte wraparound keeps the row counter in [0,5], including the compiler
    # form that increments through a temporary before narrowing to one byte.
    footer = cursor
    _put16(image, footer, 0x1c6e)  # ADDS r6,r5,#1
    _put16(image, footer + 2, 0x0635)  # LSLS r5,r6,#24
    _put16(image, footer + 4, 0x0e2d)  # LSRS r5,r5,#24
    _put16(image, footer + 6, 0x2d06)  # CMP r5,#6
    _branch(image, footer + 8, 11, loop)  # BLT row loop
    _put16(image, footer + 10, 0x4770)
    _branch(image, sense_site + 8, 0, footer)

    _irq(image, 0x1000, False)
    _irq(image, 0x1020, True)
    return image, {"port": port, "loop": loop, "sense": sense_site,
                   "presence": 0x214, "clear_call": clear_call,
                   "event_load": event_load, "footer": footer,
                   "event_base": event_base}


class ByteRowScannerTests(unittest.TestCase):
    def setUp(self):
        self.config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                                      ram_size=0x00800000, flash_size=0x2400,
                                      board_status_input=None)

    def test_six_row_byte_scan_maps_numeric_contacts(self):
        image, points = _fixture()
        profiles = find_byte_row_scanners(image, self.config)
        self.assertEqual(len(profiles), 1)
        profile = profiles[0]
        self.assertEqual((profile["rows"], profile["columns"]), (6, 4))
        self.assertEqual(profile["sense_address"], 0x03000694)
        self.assertEqual(profile["row_ports"], [points["port"]])
        self.assertEqual(profile["row_masks"], [0x3f])
        self.assertEqual(profile["row_wire_order"], list(range(6)))
        self.assertEqual(profile["single_key_column_sense"], [14, 13, 11, 7])
        self.assertEqual(profile["event_codes"][:12], list(b"147*2580369#"))
        owner = SimpleNamespace(matrix_input_profile=profile)
        for column in range(4):
            for row in range(6):
                address = points["event_base"] + column * 6 + row
                self.assertEqual(image[address], profile["event_codes"][column * 6 + row])
                event = profile["event_codes"][column * 6 + row]
                if event in b"123456789*0#":
                    self.assertEqual(_matrix_input_position(owner, event, event),
                                     (event, row, column))
        prop, admitted = byte_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-gpio="))
        self.assertEqual(admitted, profile)

    def test_row_output_byte_memory_is_preserved_and_unknown_writes_reject(self):
        code = bytearray(0x80)
        # Store and reload a source-owned shadow byte before driving the GPIO.
        _put16(code, 0, 0x203f)  # MOVS r0,#0x3f
        _put16(code, 2, 0x4903)  # LDR r1, shadow address
        _put16(code, 4, 0x7008)  # STRB r0,[r1]
        _put16(code, 6, 0x7808)  # LDRB r0,[r1]
        _put16(code, 8, 0x4a02)  # LDR r2, GPIO address
        _put16(code, 10, 0x7010) # STRB r0,[r2]
        _put16(code, 12, 0x46c0)
        _put32(code, 16, 0x20000020)
        _put32(code, 20, 0x03000724)
        result = _row_outputs(code, 0, 12, {}, -0x10000, 0,
                              byte_memory=((0x20000020, 1),),
                              byte_ports=(0x03000724,))
        self.assertIsNotNone(result)
        self.assertEqual(result[0][0x03000724].one & 255, 0x3f)
        bad = bytearray(code)
        _put32(bad, 16, 0x20000021)
        self.assertIsNone(_row_outputs(bad, 0, 12, {}, -0x10000, 0,
                                       byte_memory=((0x20000020, 1),),
                                       byte_ports=(0x03000724,)))

    def test_rejects_missing_clear_wrong_row_mask_order_and_byte_sense(self):
        cases = (
            _fixture(clear=False)[0],
            _fixture(masks=(0x3c, 0x3d, 0x3b, 0x37, 0x2f, 0x1f))[0],
            _fixture(row_order=(1, 1, 2, 3, 4, 5))[0],
            _fixture(sense=0x03000690)[0],
        )
        for image in cases:
            with self.subTest(image=image[0x200:0x220]):
                self.assertEqual(find_byte_row_scanners(image, self.config), [])

    def test_rejects_row_counter_clobbered_after_gpio_selection(self):
        image, _ = _fixture(clobber_row=True)
        self.assertEqual(find_byte_row_scanners(image, self.config), [])

    def test_rejects_bad_numeric_table_and_ambiguous_digit_mapping(self):
        bad_lookup = bytearray(16)
        image, _ = _fixture(lookup=bad_lookup)
        self.assertEqual(find_byte_row_scanners(image, self.config), [])
        image, points = _fixture()
        image[points["event_base"] + 1] = ord("1")
        self.assertEqual(find_byte_row_scanners(image, self.config), [])

    def test_reports_permuted_physical_row_order(self):
        image, _ = _fixture(row_order=(3, 0, 1, 2, 4, 5))
        profiles = find_byte_row_scanners(image, self.config)
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["row_wire_order"], [1, 2, 3, 0, 4, 5])

    def test_property_checks_status_conflict_and_source_target_bounds(self):
        image, _ = _fixture()
        self.config.board_status_input = SimpleNamespace(
            address=0x03000724, mask=1, default=1)
        self.assertEqual(byte_row_property(image, self.config), (None, None))
        self.config.board_status_input = None
        self.config.flash_size = 0x100
        self.assertEqual(byte_row_property(image, self.config), (None, None))

    def test_shared_released_status_column_is_owned_by_matrix(self):
        image, _ = _fixture()
        self.config.board_status_input = SimpleNamespace(
            address=0x03000694, mask=4, default=4)
        prop, profile = byte_row_property(image, self.config)
        self.assertTrue(prop.startswith("matrix-gpio="))
        self.assertEqual(profile["shared_released_column"], {
            "address": 0x03000694, "mask": 4, "default": 4})

    def test_rejects_status_column_outside_low_nibble_or_low_default(self):
        image, _ = _fixture()
        for mask, default in ((0x10, 0x10), (4, 0)):
            with self.subTest(mask=mask, default=default):
                self.config.board_status_input = SimpleNamespace(
                    address=0x03000694, mask=mask, default=default)
                self.assertEqual(byte_row_property(image, self.config), (None, None))


if __name__ == "__main__":
    unittest.main()
