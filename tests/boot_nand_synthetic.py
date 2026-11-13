"""Small hand-assembled instruction and fact samples for boot NAND tests."""
from __future__ import annotations

import struct



def put16(image: bytearray, offset: int, value: int) -> None:
    struct.pack_into('<H', image, offset, value)


def put32(image: bytearray, offset: int, value: int) -> None:
    struct.pack_into('<I', image, offset, value)


def arm_mov_r0(value: int) -> int:
    if not 0 <= value <= 255:
        raise ValueError('sample immediate must fit one ARM MOV byte')
    return 0xE3A00000 | value


def arm_bx_lr() -> int:
    return 0xE12FFF1E


def constant_image(value: int) -> bytes:
    image = bytearray(16)
    put32(image, 0, arm_mov_r0(value))
    put32(image, 4, arm_bx_lr())
    return bytes(image)


def plan_image() -> bytes:
    """Return a small ordinary synthetic image with a callable ARM stub."""
    image = bytearray(32 * 528)
    put32(image, 0x100, arm_mov_r0(0x2a))
    put32(image, 0x104, arm_bx_lr())
    return bytes(image)
