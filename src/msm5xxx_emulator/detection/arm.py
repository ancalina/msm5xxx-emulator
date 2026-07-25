"""Small ARMv4T instruction decoders used by firmware detection."""
from __future__ import annotations

import hashlib
import re
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


def _thumb_function_start(image: bytes, position: int) -> int:
    for current in range(position & ~1, max(-1, position - 0x400), -2):
        if struct.unpack_from("<H", image, current)[0] & 0xFE00 == 0xB400:
            return current
    return position


def _thumb_fingerprint(image: bytes, start: int) -> tuple[str, int, str]:
    normalized: list[int] = []
    end = min(start + 0x300, len(image))
    boundary = "cap" if start + 0x300 <= len(image) else "image-end"
    current = start
    while current + 2 <= end:
        instruction = current
        raw_word = struct.unpack_from("<H", image, current)[0]
        word = raw_word
        if word & 0xF800 == 0x4800:
            word &= 0xFF00
        elif word & 0xF000 == 0xD000:
            word &= 0xFF00
        elif word & 0xF800 == 0xE000:
            word = 0xE000
        elif word & 0xF800 == 0xF000 and current + 4 <= end:
            normalized.extend((0xF000, 0xF800))
            current += 4
            continue
        normalized.append(word)
        current += 2
        register = raw_word >> 3 & 0xF
        previous = (
            struct.unpack_from("<H", image, instruction - 2)[0]
            if instruction >= start + 2 else 0
        )
        if (raw_word == 0x4770 or raw_word & 0xFF00 == 0xBD00
                or (raw_word & 0xFF87 == 0x4700 and register < 8
                    and previous & 0xFF00 == 0xBC00
                    and previous & 1 << register)):
            boundary = "linear-return"
            break
        high_operation = raw_word >> 8 & 3
        high_destination = (raw_word & 7) | (raw_word >> 4 & 8)
        if (raw_word & 0xFF87 == 0x4700
                or (raw_word & 0xFC00 == 0x4400
                    and high_operation in (0, 2)
                    and high_destination == 15)):
            boundary = "indirect-branch"
            break
    encoded = struct.pack(f"<{len(normalized)}H", *normalized)
    return hashlib.sha256(encoded).hexdigest()[:16], current - start, boundary


def _thumb_successors(image: bytes, current: int, end: int) -> tuple[int, ...]:
    limit = min(end, len(image))
    if not 0 <= current <= limit - 2:
        return ()
    word = struct.unpack_from("<H", image, current)[0]
    if word & 0xFF00 in (0xBE00, 0xDE00):
        return ()
    if word & 0xFF87 == 0x4700 or word & 0xFF00 == 0xBD00:
        return ()
    if (word & 0xFC00 == 0x4400 and (word >> 8 & 3) in (0, 2)
            and ((word & 7) | (word >> 4 & 8)) == 15):
        return ()
    if (word & 0xF800 == 0xF000 and current + 4 <= limit
            and struct.unpack_from("<H", image, current + 2)[0]
            & 0xF800 == 0xF800):
        return (current + 4,)
    if word & 0xF000 == 0xD000 and (word & 0x0F00) < 0x0E00:
        delta = (word & 0xFF) << 1
        return (
            current + 2,
            current + 4 + (delta - 0x200 if delta & 0x100 else delta),
        )
    if word & 0xF800 == 0xE000:
        delta = (word & 0x7FF) << 1
        return (current + 4 + (
            delta - 0x1000 if delta & 0x800 else delta
        ),)
    return (current + 2,)


def _thumb_reachable(image: bytes, start: int, end: int) -> set[int]:
    """Return bounded Thumb instruction offsets reachable without taking calls."""
    pending = [start]
    reached: set[int] = set()
    while pending:
        current = pending.pop()
        if current in reached or not start <= current < end or current & 1:
            continue
        reached.add(current)
        pending.extend(_thumb_successors(image, current, end))
    return reached


def _thumb_writes_register(word: int, register: int) -> bool:
    if word < 0x2000:
        return word & 7 == register
    if word < 0x4000:
        return word & 0xF800 != 0x2800 and word >> 8 & 7 == register
    if word < 0x4400:
        return (word >> 6 & 0xF) not in (8, 10, 11) and word & 7 == register
    if word < 0x4800:
        operation = word >> 8 & 3
        destination = (word & 7) | (word >> 4 & 8)
        return operation in (0, 2) and destination == register
    if word < 0x5000:
        return word >> 8 & 7 == register
    if word < 0x6000:
        return (word >> 9 & 7) >= 3 and word & 7 == register
    if word < 0x9000:
        return bool(word & 0x0800) and word & 7 == register
    if word < 0xA000:
        return bool(word & 0x0800) and word >> 8 & 7 == register
    if word < 0xB000:
        return word >> 8 & 7 == register
    if word & 0xFE00 == 0xBC00:
        return bool(word & 1 << register)
    if word & 0xFF00 in (0xB200, 0xBA00):
        return word & 7 == register
    if 0xC000 <= word < 0xD000:
        base = word >> 8 & 7
        return base == register or bool(word & 0x0800 and word & 1 << register)
    return False


def _thumb_path_preserves_register(
        image: bytes, start: int, goal: int, end: int, register: int) -> bool:
    limit = min(end, len(image))
    pending = [start]
    reached: set[int] = set()
    while pending:
        current = pending.pop()
        if (current in reached or not 0 <= current <= limit - 2
                or current < start or current & 1):
            continue
        if current == goal:
            return True
        reached.add(current)
        word = struct.unpack_from("<H", image, current)[0]
        is_call = (
            word & 0xF800 == 0xF000 and current + 4 <= limit
            and struct.unpack_from("<H", image, current + 2)[0]
            & 0xF800 == 0xF800
        )
        is_register_call = word & 0xFF87 == 0x4780
        if (((is_call or is_register_call) and register <= 3)
                or _thumb_writes_register(word, register)):
            continue
        pending.extend(_thumb_successors(image, current, end))
    return False


def _thumb_callable_entry(
        image: bytes, prologue: int,
        inbound_entries: set[int] | None = None) -> int:
    """Recover one evidenced PC-literal prelude before a Thumb PUSH."""
    entry = prologue - 2
    if entry < 0:
        return prologue
    load = struct.unpack_from("<H", image, entry)[0]
    if load & 0xF800 != 0x4800:
        return prologue
    register = load >> 8 & 7
    referenced = (
        entry in inbound_entries
        if inbound_entries is not None
        else (entry | 1).to_bytes(4, "little") in image
    )
    if not referenced and inbound_entries is None:
        for match in re.finditer(
                rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]",
                image, re.S):
            callsite = match.start()
            if not callsite & 1 and thumb_bl_target(image, callsite) == entry:
                referenced = True
                break
    if not referenced:
        return prologue
    for current in range(prologue + 2, min(prologue + 0x20, len(image) - 1), 2):
        word = struct.unpack_from("<H", image, current)[0]
        if 0x5000 <= word < 0x9000 and (word >> 3) & 7 == register:
            return entry
        if (_thumb_writes_register(word, register)
                or not _thumb_successors(image, current, len(image))):
            return prologue
    return prologue
