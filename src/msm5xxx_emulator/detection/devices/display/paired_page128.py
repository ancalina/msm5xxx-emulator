"""Source admission for an interleaved two-plane page LCD producer."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.detection.fact_patterns import cmp_imm, lsl, match, mov

def _strb(rt: int, rn: int, offset: int = 0) -> int:
    return 0x7000 | offset << 6 | rn << 3 | rt

def _ldrb(rt: int, rn: int, offset: int = 0) -> int:
    return 0x7800 | offset << 6 | rn << 3 | rt

def _add_reg(rd: int, rn: int, rm: int) -> int:
    return 0x1800 | rm << 6 | rn << 3 | rd

# The transfer loop sets page and column, indexes the framebuffer with a
# 256-byte page stride, and emits two bytes per one of 128 logical columns.
_TRANSFER = ((2, mov(0, 0)), (4, mov(5, 16)), (6, mov(4, 0)), (8, lsl(7, 5, 21)), (10, mov(1, 0xb0)), (14, _strb(1, 7)), (16, _strb(5, 7)), (18, _strb(4, 7)), (20,
    mov(1, 0)), (24, lsl(2, 0, 8)), (26, _add_reg(2, 2, 3)), (28, lsl(3, 1, 1)), (30, _add_reg(6, 2, 3)), (34, _add_reg(3, 6, 3)), (36, _ldrb(6, 3, 1)), (38,
    _strb(6, 7, 4)), (40, _ldrb(3, 3, 2)), (42, _strb(3, 7, 4)), (46, cmp_imm(1, 128)), (48, 0xdbf4), (52, cmp_imm(0, 16)), (54, 0xdbe8),)
_CLEAR = ((2, mov(0, 0)), (4, mov(7, 16)), (6, lsl(2, 7, 21)), (8, mov(1, 0)), (10, mov(3, 0xb0)), (14, _strb(3, 2)), (16, _strb(7, 2)), (18, _strb(1, 2)), (20,
    mov(3, 0)), (22, _strb(1, 2, 4)), (24, _strb(1, 2, 4)), (28, cmp_imm(3, 128)), (30, 0xdbfa), (34, cmp_imm(0, 16)), (36, 0xdbf1),)
# Shift carry selects colour bit 1 for the second plane and bit 0 for the
# first. The producer writes those two independent masks to adjacent bytes.
_PIXEL = ((0, mov(5, 255)), (6, 0x08bb), (8, 0xd200), (10, mov(4, 0)), (16, 0x087b), (18, 0xd200), (20, mov(5, 0)), (0x78, _ldrb(1, 3, 1)), (0x84, 0x4039), (0x8a,
    _strb(1, 3, 1)), (0x90, _strb(1, 3, 4)), (0x94, _ldrb(1, 3, 2)), (0xa0, 0x4023), (0xa6, _strb(1, 3, 2)), (0xac, _strb(1, 3, 4)),)

def find_paired_page128(image: bytes) -> dict | None:
    """Find a unique linked producer, full transfer, and clear-loop shape."""
    anchor = struct.pack('<4H', 0xb5f0, mov(0, 0), mov(5, 16), mov(4, 0))
    hits = []
    start = 0
    while (at := image.find(anchor, start)) >= 0:
        start = at + 1
        pixel, clear = at - 0xb38, at + 0xa98
        if at & 1 or not all(match(image,[(base + off, word) for off, word in shape]) for base, shape in ((at, _TRANSFER), (pixel, _PIXEL), (clear, _CLEAR))):
            continue
        base = facts_for(image).thumb_literal_value(at + 22, 3)
        offset = facts_for(image).thumb_literal_value(at + 32, 3)
        pixel_offset = facts_for(image).thumb_literal_value(pixel + 0x70, 3)
        if (base is None or offset is None or offset != pixel_offset or not 0x01000000 <= base + offset <= 0x01800000 - 4098):
            continue
        hits.append((at, pixel, clear))
    if len(hits) != 1:
        return None
    at, pixel, clear = hits[0]
    return {'class_name': 'interleaved-page128-v1', 'width': 128, 'height': 128, 'bits_per_pixel': 2, 'first_plane_low': True, 'logical_y_reverse': False,
        'command_port': 0x02000000, 'data_port': 0x02000004, 'access_width': 1, 'column_bias': 0, 'column_capacity': 256, 'main_pages': list(range(16)),
        'icon_page': None, 'required_pages': 16, 'init_row_bytes': 256, 'source_intervals':[(pixel, pixel + 0xae), (at, at + 0x3a), (clear, clear + 0x28)]}
