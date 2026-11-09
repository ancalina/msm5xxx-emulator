"""Closed Thumb carry-bit scanner grammar with paired events and refresh gate."""
from __future__ import annotations

import re
import struct

from ..core.config import BoardStatusInput
from .arm import thumb_bl_target, thumb_literal_value
from .registry import device_domain
from .facts import CodeAddress, facts_for
from capstone import arm as a


def _gate_frame(image: bytes, entry: int, guard: int, end: int) -> bool:
    """Close the prefix and preserve its saved frame on every normal exit."""
    facts = facts_for(image)
    region = facts.function_region(CodeAddress(entry + 2),
                                   stop_before=(CodeAddress(guard), CodeAddress(end)),
                                   budget=512, symbolic_registers={})
    if (not region.complete or CodeAddress(guard) not in region.scope_exits
            or region.back_edges or facts.unmodelled_memory(region) != ()
            or any(pc.address != end and not entry < pc.address <= guard
                   for pc in region.instructions)
            or any(access.operation == 'write' for access in region.symbolic_accesses)
            or any(not facts.view.covers(target.address, 2 if target.isa == 'thumb' else 4,
                                         phase=target.phase, bank=target.bank)
                   for _, target in region.calls)):
        return False
    return all(facts.reaching_definitions(region, site, a.ARM_REG_SP,
                                          include_entry=True) == (None,)
               for site in region.scope_exits)


def _refresh_gate(image: bytes, inhibit: int) -> bool:
    # A nonzero inhibit byte takes a direct branch to a preserved-register return.
    for match in re.finditer(re.escape(b'\x00\x78\x00\x28\x00\xd0'), image):
        pc = match.start() - 2
        if pc < 0 or pc & 1 or thumb_literal_value(image, pc, 0) != inhibit:
            continue
        if pc + 10 > len(image):
            continue
        jump = struct.unpack_from('<H', image, pc + 8)[0]
        if jump & 0xF800 != 0xE000 or jump & 0x400:
            continue
        end = pc + 12 + (jump & 0x7FF) * 2
        if image[end:end + 6] != bytes.fromhex('f0bc08bc1847'):
            continue
        if any(image[p:p + 4] == b'\xf0\xb5\x06\x1c'
               and _gate_frame(image, p, pc, end)
               for p in range(max(0, pc - 0x100), pc, 2)):
            return True
    return False


def direct_scanner_at(image: bytes, start: int) -> tuple[BoardStatusInput | None, str]:
    """Prove a HIGH-open carry-bit scanner with one/two-scan acceptance.

    The complete compiler layout is closed except relocated literal loads and BL,
    the selected input bit, and a bounded optional wake-request byte offset.
    """
    if start < 0 or start & 1 or start + 0xA2 > len(image):
        return None, ''

    def word(offset: int) -> int:
        return struct.unpack_from('<H', image, start + offset)[0]

    if word(2) != 0xB5B0 or word(4) != 0x7800:
        return None, ''
    shift = word(6)
    if shift & 0xF83F != 0x0800 or not 1 <= (shift >> 6) & 31 <= 8:
        return None, ('carry-bit-selector-invalid'
                      if (address := thumb_literal_value(image, start, 0)) is not None
                      and 0x03000000 <= address < 0x03800000 else '')
    bit = ((shift >> 6) & 31) - 1
    # Every branch closes its destination; the counter/store paths cannot drift.
    sections = {
        8: (0xD301, 0x2001, 0xE000, 0x2000, 0x2700, 0x2300, 0x2401, 0x2800),
        0x1E: (0xD01E, 0x7810, 0x2800, 0xD139, 0x7808, 0x2800, 0xD136),
        0x2E: (0x7800, 0x2800, 0xD132, 0x79A8, 0x3001, 0x0600,
               0x0E00, 0x71A8, 0x2801, 0xDB2B, 0x71AC, 0x71EB, 0x2001,
               0x7010, 0x716B, 0x7A28, 0x275F, 0x2800, 0xD002, 0x1DE8, 0x3009),
        0x5A: (0x722B, 0xE01A, 0x7968, 0x2800, 0xD11A, 0x7808, 0x2800, 0xD117),
        0x6C: (0x7800, 0x2800, 0xD113),
        0x74: (0x7800, 0x2800, 0xD10F, 0x79E8, 0x3001, 0x0600, 0x0E00,
               0x71E8, 0x2802, 0xDB08, 0x71EC, 0x71AB, 0x716C, 0x7013,
               0x722C, 0x2760, 0x1C38),
        0x9A: (0x1C38, 0xBCB0, 0xBC08, 0x4718),
    }
    for offset, expected in sections.items():
        if any(word(offset + index * 2) != value for index, value in enumerate(expected)):
            return None, 'direct-scanner-control-mismatch'
    wake = word(0x58)
    if wake & 0xF83F != 0x7004 or not 9 <= ((wake >> 6) & 31) <= 31:
        return None, 'wake-store-mismatch'
    address = thumb_literal_value(image, start, 0)
    state = thumb_literal_value(image, start + 0x1C, 5)
    literals = [thumb_literal_value(image, start + off, reg)
                for off, reg in ((0x18, 1), (0x1A, 2), (0x2C, 0), (0x6A, 0), (0x72, 0))]
    if address is None or not 0x03000000 <= address < 0x03800000:
        return None, 'gpio-literal-invalid'
    if (state is None or not 0x01000000 <= state < 0x01800000 - 48
            or any(value is None or not 0x01000000 <= value < 0x01800000 for value in literals)
            or literals[2] != literals[3] or literals[2] != literals[0] + 1
            or len({state + 5, state + 6, state + 7, state + 8,
                    literals[0], literals[1], literals[2], literals[4]}) != 8):
        return None, 'direct-scanner-state-invalid'
    event = thumb_bl_target(image, start + 0x96)
    if event is None or not 0 <= event < len(image):
        return None, 'event-call-invalid'
    if not _refresh_gate(image, state + 8):
        return None, 'display-inhibit-guard-mismatch'
    if not device_domain('board_contact').periodic_caller(image, start):
        return None, 'periodic-callback-unproven'
    mask = 1 << bit
    return BoardStatusInput(address, mask, mask), ''
