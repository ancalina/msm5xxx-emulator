"""Bind a watchdog to its rebuild caller and copied stop-feeding primitive.

The ordinary watchdog performs the reset. Neither a guest PC nor a filesystem
marker is patched. Flash geometry and command admission remain independent.
"""

from __future__ import annotations

import re
import struct

from .watchdog import _shape, _ram
from .gap_intel import _irq_veneer

# Two bounded delay/pet loops, followed by erase, FFF0 program and reset calls.
_FIXED = {
    0: 0x267F,
    2: 0x9200,
    4: 0x227F,
    6: 0x1C33,
    8: 0x2100,
    10: 0x2000,
    0x10: 0x251F,
    0x12: 0x02ED,
    0x14: 0x1C2A,
    0x16: 0x2102,
    0x20: 0x247D,
    0x22: 0x00E4,
    0x24: 0x1C20,
    0x2E: 0x3F01,
    0x30: 0xD1F8,
    0x34: 0x1C33,
    0x36: 0x9200,
    0x38: 0x227F,
    0x3A: 0x2100,
    0x3C: 0x2000,
    0x42: 0x1C2A,
    0x44: 0x2102,
    0x4E: 0x1C20,
    0x58: 0x3F01,
    0x5A: 0xD1F8,
    0x66: 0x6A00,
    0x68: 0x0840,
    0x6A: 0x390F,
}
_LITERALS = {0x18: 0, 0x1E: 7, 0x32: 2, 0x46: 0, 0x4C: 7, 0x5C: 0, 0x62: 0, 0x64: 1}
_CALLS = (0x0C, 0x1A, 0x26, 0x2A, 0x3E, 0x48, 0x50, 0x54, 0x5E, 0x6C, 0x70)


def _veneer(image: bytes, entry: int) -> int | None:
    if entry & 3 or not 0 <= entry <= len(image) - 16:
        return None
    head, load, branch, target = struct.unpack_from("<4I", image, entry)
    if (head, load, branch) != (0x46C04778, 0xE59FC000, 0xE12FFF1C) or not target & 1:
        return None
    return target & ~1


def _copied_source(image: bytes, address: int, size: int):
    # An isolated zero-BSS bootstrap copy is deliberately separate from the
    # general application linker recognizer, whose stricter rules stay intact.
    matches = []
    for table in range(0, min(len(image) - 20, 0x20000) + 1, 4):
        source, target, length, end, bss = struct.unpack_from("<5I", image, table)
        if (
            table < source <= table + 0x40
            and 0 < length <= 0x200000
            and source + length <= len(image)
            and _ram(target)
            and _ram(end - 1)
            and target + length == end
            and bss == 0
            and target <= address <= end - size
        ):
            matches.append((source + address - target, table, source, target, length))
    return matches[0] if len(matches) == 1 else None


def find_rebuild_reset_owner(image: bytes, service: int) -> dict[str, int] | None:
    candidates = []
    for match in re.finditer(re.escape(struct.pack("<2H", 0x267F, 0x9200)), image):
        entry = match.start()
        shape = _shape(image, entry, 0x74, _FIXED, _LITERALS, _CALLS)
        if shape is None:
            continue
        values, calls = shape
        if (
            calls[0x2A] != service
            or calls[0x54] != service
            or calls[0x0C] != calls[0x3E]
            or calls[0x1A] != calls[0x48]
            or calls[0x26] != calls[0x50]
            or values[0x1E] != 3000
            or values[0x4C] != 5000
            or values[0x32] != 0xFFFF
            or values[0x64] != 0xFFFF
            or values[0x5C] != 0x7FF000
            or not _ram(values[0x62])
            or not _ram(values[0x62] + 0x20)
            or any(not 0 <= values[offset] < len(image) - 4 for offset in (0x18, 0x46))
        ):
            continue
        reset, erase, program = (
            _veneer(image, calls[offset]) for offset in (0x70, 0x5E, 0x6C)
        )
        if None in (reset, erase, program) or len({reset, erase, program}) != 3:
            continue
        mapped = _copied_source(image, reset, 0x20)
        if mapped is None:
            continue
        reset_source, table, source, target, length = mapped
        if not (
            target <= erase <= target + length - 16
            and target <= program <= target + length - 16
        ):
            continue
        # Both flash helpers consume word addresses; the program helper also
        # preserves the halfword payload in r4 before selecting a physical bank.
        program_shape = _shape(
            image,
            source + program - target,
            16,
            {
                0: 0xB5F8,
                2: 0x1C0C,
                4: 0x0047,
                6: 0x2555,
                8: 0x26AA,
                10: 0x2301,
                12: 0x05DB,
                14: 0x429F,
            },
            {},
            (),
        )
        erase_shape = _shape(
            image,
            source + erase - target,
            14,
            {
                0: 0xB5FC,
                2: 0x2403,
                4: 0x0047,
                6: 0x2301,
                8: 0x05DB,
                10: 0x429F,
                12: 0xD211,
            },
            {},
            (),
        )
        reset_shape = _shape(
            image,
            reset_source,
            0x1C,
            {
                2: 0xB500,
                4: 0x7800,
                6: 0x2800,
                8: 0xD004,
                10: 0x2001,
                0x10: 0xBC08,
                0x12: 0x4718,
                0x18: 0xE7FF,
                0x1A: 0xE7FE,
            },
            {0: 0},
            (0x0C, 0x14),
        )
        if (
            program_shape is None
            or erase_shape is None
            or reset_shape is None
            or not _ram(reset_shape[0][0])
            or not _irq_veneer(image, reset_shape[1][0x14], False)
        ):
            continue
        candidates.append(
            dict(
                rebuild_owner=entry,
                reset_veneer=calls[0x70],
                reset_source=reset_source,
                copy_table=table,
                copy_source=source,
                copy_target=target,
                copy_size=length,
                erase_word_address=values[0x5C],
                marker=0xFFF0,
                erase_veneer=calls[0x5E],
                program_veneer=calls[0x6C],
            )
        )
    return candidates[0] if len(candidates) == 1 else None
