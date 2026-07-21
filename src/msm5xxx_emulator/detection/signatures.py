"""Shared byte-signature scanning."""
from __future__ import annotations

def find_all(image: bytes, signature: bytes) -> list[int]:
    found: list[int] = []
    offset = 0
    while (offset := image.find(signature, offset)) >= 0:
        found.append(offset)
        offset += 1
    return found
