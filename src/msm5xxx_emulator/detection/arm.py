"""Small ARMv4T instruction decoders used by firmware detection."""
from __future__ import annotations

import struct


def arm_vector_score(image: bytes, offset: int = 0) -> int:
    if offset < 0 or offset + 32 > len(image):
        return 0
    words = struct.unpack_from("<8I", image, offset)
    score = 0
    for index, word in enumerate(words):
        if word >> 28 == 0xF:
            continue
        if word & 0x0E000000 == 0x0A000000:
            displacement = (word & 0x00FFFFFF) << 2
            if displacement & 0x02000000:
                displacement -= 0x04000000
            target = (offset + index * 4 + 8 + displacement) & 0xFFFFFFFF
            if target < len(image) or 0x01000000 <= target < 0x04000000:
                score += 1
            continue
        if (((word >> 26) & 3) != 1 or word & (1 << 25)
                or not word & (1 << 24) or word & ((1 << 22) | (1 << 21))
                or not word & (1 << 20) or ((word >> 16) & 15) != 15
                or ((word >> 12) & 15) != 15):
            continue
        displacement = word & 0xFFF
        if not word & (1 << 23):
            displacement = -displacement
        literal = offset + index * 4 + 8 + displacement
        if not 0 <= literal <= len(image) - 4:
            continue
        target = struct.unpack_from("<I", image, literal)[0]
        if target < len(image) or 0x01000000 <= target < 0x04000000:
            score += 1
    return score


def thumb_bl_target(image: bytes, address: int) -> int | None:
    if not 0 <= address <= len(image) - 4:
        return None
    high, low = struct.unpack_from("<2H", image, address)
    if high & 0xF800 != 0xF000 or low & 0xF800 != 0xF800:
        return None
    displacement = ((high & 0x7FF) << 12) | ((low & 0x7FF) << 1)
    if displacement & (1 << 22):
        displacement -= 1 << 23
    return address + 4 + displacement


def arm_b_target(image: bytes, address: int) -> int | None:
    if not 0 <= address <= len(image) - 4:
        return None
    return arm_b_word_target(struct.unpack_from("<I", image, address)[0], address)


def arm_b_word_target(word: int, address: int) -> int | None:
    if word & 0xFF000000 != 0xEA000000:
        return None
    displacement = (word & 0xFFFFFF) << 2
    if displacement & (1 << 25):
        displacement -= 1 << 26
    return address + 8 + displacement


def thumb_literal_value(image: bytes, position: int, register: int) -> int | None:
    if not 0 <= position <= len(image) - 2:
        return None
    word = struct.unpack_from("<H", image, position)[0]
    if word & 0xF800 != 0x4800 or word >> 8 & 7 != register:
        return None
    literal = ((position + 4) & ~3) + (word & 0xFF) * 4
    if literal + 4 > len(image):
        return None
    return struct.unpack_from("<I", image, literal)[0]
