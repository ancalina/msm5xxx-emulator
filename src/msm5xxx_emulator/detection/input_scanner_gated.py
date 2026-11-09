"""Fail-closed gated byte scanner with paired event/display-state evidence."""
from __future__ import annotations

import struct

from ..core.config import BoardStatusInput
from .arm import thumb_bl_target, thumb_literal_value
from .facts import SymbolicValue
from .input_scanner import _selector_at_join
from .registry import device_domain


def _preserves_selector(image: bytes, entry: int, join: int) -> bool:
    selector = SymbolicValue.arg(7)
    return _selector_at_join(image, entry, join, selector) == selector


def gated_scanner_at(image: bytes, start: int) -> tuple[BoardStatusInput | None, str]:
    """Prove HIGH/override-open selection, 1/5 counters, 95/96 and display gate."""
    def word(pc):
        return struct.unpack_from('<H', image, pc)[0]

    def exact(pc, *values):
        return image[pc:pc + len(values) * 2] == struct.pack('<' + 'H' * len(values), *values)

    def ram(value, room=0):
        return value is not None and 0x01000000 <= value < 0x01800000 - room

    def literal(pc, reg):
        return thumb_literal_value(image, pc, reg)

    if start + 36 > len(image):
        return None, ''
    mask = word(start + 6) & 255
    if (not mask or mask & (mask - 1)
            or not exact(start + 4, 0x7800, 0x2300 | mask)
            or not exact(start + 10, 0x4018, 0x3610, 0x2800, 0xD100)
            or word(start + 18) & 0xF800 != 0xE000):
        return None, ''
    address = literal(start + 2, 0)
    if (address is None or not 0x03000000 <= address < 0x03800000
            or literal(start + 8, 6) != address):
        return None, 'gated-gpio-literal-invalid'
    low = start + 22 + (word(start + 18) & 2047) * 2
    limit = min(start + 0x400, len(image) - 2)
    if not start + 36 < low < limit - 4:
        return None, 'gated-input-branch-invalid'
    override = literal(start + 20, 5)
    if (not ram(override) or not exact(start + 22, 0x7828, 0x2800, 0xD001,
                                     0x2700, 0xE000, 0x2701)
            or not exact(low + 2, 0x2700)):
        return None, 'gated-selector-invalid'
    joins = [pc for pc in range(low + 4, limit - 0x112, 2)
             if exact(pc + 4, 0x2400, 0x18C5)
             and exact(pc + 10, 0x2F00)
             and exact(pc + 16, 0xD029)]
    if len(joins) != 1:
        return None, 'gated-join-not-unique'
    j = joins[0]
    if (not _preserves_selector(image, start + 34, j)
            or not _preserves_selector(image, low + 4, j)):
        return None, 'gated-selector-clobbered'
    state = literal(low, 4)
    display = literal(j + 8, 0)
    gate = literal(j + 14, 2)
    inhibit = literal(j + 12, 1)
    if (not all(ram(x, 12) for x in (state, display, gate, inhibit))
            or literal(start + 34, 4) != state
            or literal(j + 0x2C, 7) != state
            or literal(j + 0x66, 7) != state
            or literal(j + 0x22, 1) != inhibit + 1
            or literal(j + 0x74, 1) != inhibit + 1):
        return None, 'gated-state-literals-mismatch'
    # The same state+9/+10 counters feed complementary accepted transitions.
    fragments = (
        (0x12, (0x7893, 0x2B00, 0xD000, 0xE07A)),
        (0x1A, (0x7809, 0x2900, 0xD000, 0xE076)),
        (0x24, (0x7809, 0x2900, 0xD000, 0xE071)),
        (0x2E, (0x7A79, 0x3101, 0x0609, 0x0E09, 0x7279, 0x2901, 0xDA00, 0xE068)),
        (0x3E, (0x2101, 0x7279, 0x72BB, 0x7091, 0x723B, 0x71C1, 0x245F, 0x1C20)),
        (0x68, (0x7A3E, 0x2E00, 0xD150, 0x7809, 0x2900, 0xD14D)),
        (0x76, (0x7809, 0x2900, 0xD149)),
        (0x90, (0x7AB9, 0x3101, 0x0609, 0x0E09, 0x72B9, 0x2905, 0xDB38,
                0x2101, 0x72B9, 0x2300, 0x727B, 0x7239, 0x7093, 0x71C3)),
        (0xAE, (0x2460,)),
        (0x54, (0x7800, 0x2800, 0xD100, 0xE059, 0x7B29, 0x2001)),
        (0x64, (0xE054,)),
        (0x7E, (0x7809, 0x2900, 0xD145)),
        (0x86, (0x3150, 0x1859, 0x7889, 0x2900, 0xD03F)),
        (0xB0, (0x7800, 0x2800, 0xD003, 0x7B29, 0x2001)),
        (0xC0, (0x7800, 0x2800, 0xD11E, 0x2001)),
        (0xD2, (0x2310, 0x780A)),
        (0xD8, (0x439A, 0x700A, 0x7809, 0x3F10, 0x7039, 0x2800, 0xD101)),
        (0xF0, (0x7811, 0x0849, 0x0049, 0x7011, 0x7811, 0x7139, 0x2800, 0xD101)),
        (0x104, (0x1C20,)),
        (0x10A, (0x20FF,)),
        (0x110, (0x1C20, 0xBCF0, 0xBC08, 0x4718)),
    )
    if not all(exact(j + off, *values) for off, values in fragments):
        return None, 'gated-counter-transition-mismatch'
    # Every remaining body slot is a typed RAM literal or an in-image call.
    ram_literals = ((0, 3), (0x52, 0), (0x7C, 1), (0xAC, 0),
                    (0xBE, 0), (0xD0, 1), (0xEE, 2))
    if (not all(ram(literal(j + off, reg)) for off, reg in ram_literals)
            or literal(j + 0x84, 1) != literal(j + 2, 0)
            or literal(j + 0x52, 0) != literal(j + 0xAC, 0)
            or literal(j + 0xD6, 7) != address
            or (index := literal(j + 2, 0)) is None
            or not 0 < index < 0x100000
            or not ram(literal(j, 3) + index, 0x60)
            or len({state + 8, state + 9, state + 10, gate + 2, display + 7,
                    override, inhibit, inhibit + 1}) != 8):
        return None, 'gated-tail-literals-mismatch'
    calls = (0x60, 0xBA, 0xC8, 0xCC, 0xE6, 0xEA, 0x100)
    targets = {off: thumb_bl_target(image, j + off) for off in calls}
    if (any(target is None or not 0 <= target < len(image) for target in targets.values())
            or targets[0x60] != targets[0xBA]
            or targets[0xCC] != targets[0xEA]
            or targets[0xE6] != targets[0x100]):
        return None, 'gated-tail-calls-mismatch'
    event = thumb_bl_target(image, j + 0x4E)
    if (event is None or not 0 <= event < len(image) - 18
            or thumb_bl_target(image, j + 0x106) != event
            or thumb_bl_target(image, j + 0x10C) != event
            or not exact(event, 0xB590, 0x1C07)
            or literal(event + 4, 0) != state
            or not exact(event + 6, 0x79C1, 0x2900, 0xD101, 0x2F60)
            or not exact(event + 14, 0xD138)):
        return None, 'gated-event-consumer-mismatch'
    if not device_domain('board_contact').periodic_caller(image, start, callback_window=0x80,
                            callback_push=0xB5F0, timer_registers=(5,)):
        return None, 'gated-periodic-callback-unproven'
    return BoardStatusInput(address, mask, mask), ''
