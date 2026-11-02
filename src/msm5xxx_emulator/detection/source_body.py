"""Bounded Thumb compiler contracts with explicit call and literal ownership."""

from __future__ import annotations

import hashlib
import struct

from .arm import thumb_bl_target, thumb_literal_value


def match_thumb_contract(
    image: bytes, entry: int, contract: dict, immutable_limit: int
) -> dict | None:
    """Match a complete body; normalize only declared PC-relative operands."""
    bound = min(len(image), immutable_limit)
    size = contract["size"]
    if entry is None or entry & 1 or not 0 <= entry <= bound - size:
        return None
    normalized = bytearray(image[entry : entry + size])
    calls, literals, pools = {}, {}, []
    for offset in range(0, size, 2):
        word = struct.unpack_from("<H", normalized, offset)[0]
        if word & 0xF800 == 0xF000:
            if offset not in contract["calls"]:
                return None
            target = thumb_bl_target(image, entry + offset)
            if target is None or not 0 <= target < bound - 2:
                return None
            calls[offset] = target
            normalized[offset : offset + 4] = b"\0" * 4
        elif word & 0xF800 == 0x4800:
            register = word >> 8 & 7
            if contract["literals"].get(offset) != register:
                return None
            pool = ((entry + offset + 4) & ~3) + (word & 255) * 4
            if not 0 <= pool <= bound - 4:
                return None
            literals[offset] = thumb_literal_value(image, entry + offset, register)
            pools.append((pool, pool + 4))
            normalized[offset] = 0
    if (
        set(calls) != set(contract["calls"])
        or set(literals) != set(contract["literals"])
        or hashlib.sha256(normalized).hexdigest() != contract["sha256"]
    ):
        return None
    return dict(calls=calls, literals=literals, pools=pools, code=(entry, entry + size))
