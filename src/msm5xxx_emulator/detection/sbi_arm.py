"""ARMv4 typed SBI bootstrap consumer; no peripheral values from filenames."""
from __future__ import annotations

import struct


def _immediate(word: int) -> int:
    value, rotate = word & 255, ((word >> 8) & 15) * 2
    return ((value >> rotate) | (value << (32 - rotate))) & 0xFFFFFFFF


def arm_sbi_bootstrap_at(image: bytes, at: int) -> bool:
    """Close both busy loops and every producer of the six bootstrap writes."""
    # Unconditional, non-flag-setting data operations and immediate transfers.
    operations = (
        ('mov', 1, 0, 0x45), ('mov', 0, 0, 0x03000000),
        ('strb', 1, 0, 0x780), ('mov', 1, 0, 0xC5),
        ('mov', 0, 0, 0x03000000), ('strb', 1, 0, 0x780),
        ('mov', 1, 0, 0x5F), ('add', 1, 1, 0x800),
        ('add', 0, 0, 0x700), ('strh', 1, 0, 0x84),
        ('sub', 1, 1, 0x440), ('strh', 1, 0, 0x8C),
        ('mov', 1, 0, 0), ('mov', 0, 0, 0x03000000),
        ('strb', 1, 0, 0x790), ('mov', 1, 0, 1),
        ('mov', 0, 0, 0x03000000), ('strb', 1, 0, 0x790),
        ('mov', 0, 0, 0x700), ('add', 0, 0, 0x03000000),
        ('ldrh', 0, 0, 0x80), ('and', 0, 0, 1), ('cmp', 0, 0, 1),
        ('bne', 0, 0, 0x64), ('b', 0, 0, 0x48),
        ('mov', 0, 0, 0x900), ('mov', 1, 0, 0x700),
        ('add', 1, 1, 0x03000000), ('strh', 0, 1, 0x8C),
        ('mov', 0, 0, 0x700), ('add', 0, 0, 0x03000000),
        ('ldrh', 0, 0, 0x80), ('and', 0, 0, 1), ('cmp', 0, 0, 1),
        ('bne', 0, 0, 0x90), ('b', 0, 0, 0x74),
    )
    if at < 0 or at & 3 or at + 4 * len(operations) > len(image):
        return False
    data_op = {'and': 0, 'sub': 2, 'add': 4, 'cmp': 10, 'mov': 13}
    for index, (kind, rd, rn, value) in enumerate(operations):
        word = struct.unpack_from('<I', image, at + index * 4)[0]
        if kind in data_op:
            expected = 0xE2000000 | data_op[kind] << 21 | rn << 16 | rd << 12
            if kind == 'cmp':
                expected |= 1 << 20
            if word & 0xFFFFF000 != expected or _immediate(word) != value:
                return False
        elif kind in ('strh', 'ldrh'):
            expected = 0xE1C000B0 | rn << 16 | rd << 12
            if kind == 'ldrh':
                expected |= 1 << 20
            if (word & 0xFFFFF0F0 != expected
                    or ((word >> 4) & 0xF0 | word & 15) != value):
                return False
        elif kind == 'strb':
            if word != 0xE5C00000 | rn << 16 | rd << 12 | value:
                return False
        else:
            opcode = 0x1A000000 if kind == 'bne' else 0xEA000000
            displacement = word & 0xFFFFFF
            if displacement & 0x800000:
                displacement -= 0x1000000
            if (word & 0xFF000000 != opcode
                    or index * 4 + 8 + displacement * 4 != value):
                return False
    return True


def find_arm_sbi_bootstraps(image: bytes) -> list[int]:
    marker = struct.pack('<I', 0xE3A01045)  # MOV r1, #0x45, ARM immediate.
    entries, at = [], 0
    while (at := image.find(marker, at)) >= 0:
        if arm_sbi_bootstrap_at(image, at):
            entries.append(at)
        at += 4
    return entries
