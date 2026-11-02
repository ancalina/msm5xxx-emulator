"""Find a copied ARM 128x48 monochrome GPIO raster producer."""
from __future__ import annotations

import struct
from .ma5_gpio_irq import _layouts, _Reject
from .arm import thumb_literal_value


def _word(image: bytes, pos: int) -> int:
    return struct.unpack_from('<I', image, pos)[0]


def _imm(word: int) -> int:
    value, rotation = word & 255, ((word >> 8) & 15) * 2
    return ((value >> rotation) | (value << (32 - rotation))) & 0xffffffff if rotation else value


def _mov(image: bytes, pos: int, register: int, value: int) -> bool:
    word = _word(image, pos)
    return word & 0x0ff0f000 == (0x03a00000 | register << 12) and _imm(word) == value


def _cmp(image: bytes, pos: int, register: int, value: int) -> bool:
    word = _word(image, pos)
    return word & 0x0ffff000 == (0x03500000 | register << 16) and _imm(word) == value


def _call(image: bytes, pos: int, target: int) -> bool:
    word = _word(image, pos)
    displacement = word & 0xffffff
    if displacement & 0x800000:
        displacement -= 1 << 24
    return word >> 24 == 0xeb and pos + 8 + 4 * displacement == target


def _strh_r1_at_r2(image: bytes, pos: int) -> bool:
    word = _word(image, pos)
    # ARM STRH r1,[r2,#0], immediate, pre-indexed, no writeback.
    return (word >> 28 == 14 and word >> 25 & 7 == 0
            and word >> 20 & 31 == 28 and word >> 16 & 15 == 2
            and word >> 12 & 15 == 1 and word >> 8 & 15 == 0
            and word >> 4 & 15 == 11 and word & 15 == 0)


def _descriptor(image: bytes, ram_base: int, ram_size: int) -> int | None:
    # Thumb MOVS r0,#128; STR r0,[r1]; MOVS r0,#48; STR r0,[r1,#4],
    # followed by the two one-bit format fields and framebuffer pointer.
    half = (0x2000 | 128, 0x6008, 0x2000 | 48, 0x6048,
            0x2001, 0x6088, 0x60c8)
    anchor = struct.pack('<7H', *half)
    found = []
    start = 0
    while (pos := image.find(anchor, start)) >= 0:
        start = pos + 1
        if pos & 1 or pos + 18 > len(image):
            continue
        load, store = struct.unpack_from('<HH', image, pos + 14)
        if load & 0xff00 != 0x4800 or store != 0x6108:
            continue
        fb = thumb_literal_value(image, pos + 14, 0)
        if type(fb) is int and ram_base <= fb <= ram_base + ram_size - 768:
            found.append(fb)
    return found[0] if len(found) == 1 else None


def find_secondary_gpio_raster(image: bytes, ram_base: int, ram_size: int) -> dict | None:
    if type(ram_base) is not int or type(ram_size) is not int or ram_size < 768:
        return None
    framebuffer = _descriptor(image, ram_base, ram_size)
    if framebuffer is None:
        return None
    results = []
    needle = struct.pack('<I', 0x03800000)
    start = 4
    while (pos := image.find(needle, start, min(len(image), 0x10000))) >= 0:
        start = pos + 1
        if pos & 3 or pos + 8 > len(image):
            continue
        source, length = _word(image, pos - 4), _word(image, pos + 4)
        if not 0xc960 <= length <= 0x20000 or source & 3 or source > len(image) - length:
            continue
        writer, tx = source + 0xc258, source + 0xc8c8
        if not (all(_mov(image, writer + off, reg, val) for off, reg, val in
                    ((0x1c, 10, 128), (0x20, 11, 3), (0x24, 5, 25),
                     (0xc4, 0, 0x52), (0xd0, 0, 0x54)))
                and all(_cmp(image, writer + off, reg, val) for off, reg, val in
                        ((0x88, 1, 8), (0x98, 2, 16), (0xa8, 14, 8),
                         (0xb8, 9, 6), (0x150, 8, 32), (0x160, 4, 50)))
                and _call(image, writer + 0x144, tx)):
            continue
        # ARM halfword stores through r2 at the three data/clock sites.
        if not all(_strh_r1_at_r2(image, tx + off) for off in (0x28, 0x50, 0x68)):
            continue
        ldr = _word(image, tx + 0x10)
        if ldr & 0xfffff000 != 0xe51f0000 | 3 << 12:
            continue
        literal = tx + 0x18 - (ldr & 0xfff)
        if literal < 0 or literal + 4 > len(image):
            continue
        table = _word(image, literal)
        try:
            rows = [row for row in _layouts(image)
                    if row[2] <= table <= row[2] + row[3] - 0x24]
        except _Reject:
            continue
        if len(rows) != 1:
            continue
        row = rows[0]
        table_file = row[1] + table - row[2]
        if tuple(_word(image, table_file + off) for off in (0, 0x10, 0x20)) != (0x03000720, 0x03000724, 0x03000728):
            continue
        results.append({'framebuffer': framebuffer, 'source': source,
                        'clock_pc': 0x0380c930, 'writer_pc': 0x0380c258,
                        'width': 128, 'height': 48})
    return results[0] if len(results) == 1 else None
