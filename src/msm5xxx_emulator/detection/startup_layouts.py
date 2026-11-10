"""Shared reset-copy layouts and their bounded source spans."""
from __future__ import annotations

import struct

from .facts import facts_for
from .fact_bodies import normalized_body, thumb_body
from .values import CodeAddress

class StartupLayoutError(Exception):
    pass

_BOOT_COPY_EXPECTED = bytes.fromhex("0120004908700020087000480068004909684018061c00480068051c00480068041cb44208d204e0281d051c201d041cf7e728682060f7e70120004908700020087000480068004909684018061c00480068051c00480068041cb44208d204e0281d051c201d041cf7e728682060f7e70120004908700020087000480068004909684018061c00480068051c00480068041cb44208d204e0281d051c201d041cf7e728682060f7e7012000490870002008707047")
_BOOT_COPY_LITERAL_OFFSETS = (2, 10, 14, 22, 28, 58, 66, 70, 78, 84, 114, 122, 126, 134, 140, 170)

def _boot_copy_span(image: bytes, entry: int) -> dict:
    size = len(_BOOT_COPY_EXPECTED)
    if entry & 1 or not 0 <= entry <= len(image) - size:
        raise StartupLayoutError("boot_copy-shape-unmatched")
    body = thumb_body(facts_for(image), entry, size, call_offsets=(), literal_offsets=_BOOT_COPY_LITERAL_OFFSETS,)
    if body is None or any(target & 1 or not 0 <= target <= len(image) - 2 for _, target in body.calls):
        raise StartupLayoutError("boot_copy-shape-unmatched")
    code = bytearray(body.normalized)
    literals = {offset: value for offset, _, value, _ in body.literals}
    dependencies = [[entry, size]] + [[pool, 4] for _, _, _, pool in body.literals]
    if code != _BOOT_COPY_EXPECTED:
        raise StartupLayoutError("boot_copy-shape-unmatched")
    return { "entry": entry, "size": size, "calls": dict(body.calls), "literals": literals, "pins": {}, "dependencies": dependencies, }

def boot_copy(image: bytes) -> tuple[list[tuple], list[list[int]]]:
    # Finite ARM reset/word-copy class. The copy consumes only three descriptor words.
    if len(image) < 4:
        return [],[]
    branch = struct.unpack_from('<I', image)[0]
    if branch >> 24 != 0xEA:
        return [],[]
    delta = branch & 0xFFFFFF
    reset = 8 + ((delta - 0x1000000 if delta & 0x800000 else delta) << 2)
    expected = bytes.fromhex('00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000000050e35b00001ad7f021e300d09fe5dbf021e300d09fe5d3f021e300d09fe500409fe5010014e300e09f1500e09f0514ff2fe17847000000b09fe500c09be500b09fe500409be54057a0e308b0a0e30070a0e30080a0e30090a0e300a0a0e34069a0e3206046e28007a5e88007a5e8206056e2fbffff2a0120a0e300309fe5003093e50020c3e50020a0e30020c3e501b04be200005be3f0ffff1a00b09fe500c08be500b09fe500408be500409fe5010014e300e09f1500e09f0514ff2fe178470000')
    if not 0 <= reset <= len(image) - len(expected):
        return [],[]
    literal_offsets = (0, 8, 12, 24, 32, 36, 48, 56, 60, 84, 92, 100, 104, 112, 116, 128, 136, 196, 228, 236, 244, 252, 256)
    body = normalized_body(facts_for(image), CodeAddress(reset, 'arm'), len(expected), limit=len(image), arm_literals=literal_offsets)
    if body is None or body.normalized != expected or any(pool & 3 for _, _, pool, _ in body.literals):
        return [], []
    values = {offset: value for offset, _, _, value in body.literals}
    deps = [[0, 4], [reset, len(expected)]] + [[pool, 4] for _, _, pool, _ in body.literals]
    for first in (0, 0x18, 0x30, 0x68, 0xF4):
        callee = values[first]
        if not 0 <= (callee & ~1) <= len(image) - 2 or (not callee & 1 and callee & 3):
            return [],[]
        deps.append([callee & ~1, 2])
        if (values[first + 8] != ((reset + first + 20) | 1) or values[first + 12] != reset + first + 24):
            return [],[]
    pointer = values[0xF4]
    if not pointer & 1:
        return [],[]
    try:
        copier = _boot_copy_span(image, pointer - 1)
    except StartupLayoutError:
        return [],[]
    deps.extend(copier['dependencies'])
    literals = copier['literals']
    # Middle copy loads source/target/size through a single adjacent three-word row.
    source_pointer, target_pointer, size_pointer = literals[0x4E], literals[0x42], literals[0x46]
    if (target_pointer != source_pointer + 4 or size_pointer != source_pointer + 8 or literals[0x54] != target_pointer):
        return [],[]
    if any(literals[o] != 0x03000700 for o in (2, 0x3A, 0x72, 0xAA)):
        return [],[]
    for address in {v for o, v in literals.items() if o not in (2, 0x3A, 0x72, 0xAA)}:
        if address & 3 or not 0 <= address <= len(image) - 4:
            return [],[]
        deps.append([address, 4])
    source, target, size = struct.unpack_from('<3I', image, source_pointer)
    # Reset's literal-free clear loop proves 01000000..01800000 independently.
    if (source & 3 or target != 0x01000000 or not size or size & 3 or size > 0x800000 or source > len(image) - size):
        return [],[]
    # The first copy precedes this initialized span; the final copy must not
    # overwrite any of the independently cleared SDRAM after the middle copy.
    for source_offset, target_offset, size_offset, repeat_offset, final in ((0x16, 0xA, 0xE, 0x1C, False), (0x86, 0x7A, 0x7E, 0x8C, True)):
        pointer = literals[source_offset]
        if (literals[target_offset] != pointer + 4 or literals[size_offset] != pointer + 8 or literals[repeat_offset] != pointer + 4 or not 0 <= pointer <= len(image)
            - 12):
            return [],[]
        other_source, other_target, other_size = struct.unpack_from('<3I', image, pointer)
        if (not other_size or (other_source | other_target | other_size) & 3 or other_source > len(image) - other_size or other_target + other_size >
            0x100000000):
            return [],[]
        end = 0x01800000 if final else target + size
        if max(other_target, target) < min(other_target + other_size, end):
            return [],[]
        deps.append([pointer, 12])
    deps.append([source_pointer, 12])
    return [(source_pointer, source, target, size, 0x01800000)], deps

def layouts(image: bytes) -> list[tuple]:
    image = bytes(image) if isinstance(image, bytearray) else image
    result = []
    for offset in range(0, min(len(image) - 20, 0x40000) + 1, 4):
        source, target, size, bss, zero = struct.unpack_from('<5I', image, offset)
        if (0 < size <= 0x800000 and source <= len(image) - size and 0x01000000 <= target < 0x02000000 and target + size == bss and 0 <= zero <= 0x2000000 and
            bss + zero <= 0x02000000):
            result.append((offset, source, target, size, bss + zero))
    boot, _ = boot_copy(image)
    if boot:
        row = boot[0]
        if any(max(old[2], row[2]) < min(old[2] + old[3], row[2] + row[3]) for old in result):
            raise StartupLayoutError('bootstrap-initialized-overlap')
        # Preserve higher independently initialized rows; discard the uncovered tail.
        higher = [old[2] for old in result if row[2] + row[3] <= old[2] < row[4]]
        end = min(higher, default=row[4])
        if any(max(old[2], row[2]) < min(old[4], end) for old in result):
            raise StartupLayoutError('bootstrap-scatter-overlap')
        boot = [(*row[:4], end)]
    return result + boot
