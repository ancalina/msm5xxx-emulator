"""Bounded Thumb GPIO scanner grammar with display-inhibit data-flow evidence."""
from __future__ import annotations

import re
import struct

from ..core.config import BoardStatusInput
from .arm import thumb_bl_target, thumb_literal_value
from capstone import arm as a
from .facts import CodeAddress, SymbolicValue, facts_for
from .registry import device_domain


def _words(*values: int) -> bytes:
    return struct.pack('<' + 'H' * len(values), *values)


def _selector_at_join(image: bytes, entry: int, join: int,
                      initial: SymbolicValue | None = None) -> SymbolicValue | None:
    """Query the selector over a closed, forward setup region."""
    if not 0 <= entry <= join < len(image) or (entry | join) & 1:
        return None
    facts = facts_for(image)
    region = facts.function_region(
        CodeAddress(entry), stop_before=CodeAddress(join), budget=512,
        symbolic_registers={a.ARM_REG_R7: initial} if initial is not None else {})
    if (not region.complete or region.back_edges
            or any(not entry <= pc.address <= join for pc in region.instructions)
            or any(not facts.view.covers(target.address, 2 if target.isa == 'thumb' else 4,
                                         phase=target.phase, bank=target.bank)
                   for _, target in region.calls)):
        return None
    return facts.register_value(region, CodeAddress(join), a.ARM_REG_R7)


def _selector_paths(image: bytes, entry: int, join: int) -> set[int | None]:
    value = _selector_at_join(image, entry, join)
    return {value.value} if value is not None and value.kind == 'const' else {None}



def scanner_at(image: bytes, start: int) -> tuple[BoardStatusInput | None, str]:
    """Admit a selector-driven 2/3-scan, 95/96-event display switch grammar."""
    def word(pc: int) -> int:
        return struct.unpack_from('<H', image, pc)[0]

    def matches(pc: int, *values: int) -> bool:
        return image[pc:pc + 2 * len(values)] == _words(*values)

    # GPIO base is r4, leaving the input Boolean in callee-saved r7 across setup.
    if start + 20 > len(image):
        return None, ''
    mask = word(start + 6) & 255
    if (not mask or mask & (mask - 1)
            or not matches(start + 4, 0x7820, 0x2300 | mask, 0x4018, 0x2800 | mask)):
        return None, ''
    address = thumb_literal_value(image, start + 2, 4)
    if address is None or not 0x03000000 <= address < 0x03800000:
        return None, 'gpio-literal-invalid'
    limit = min(start + 0x400, len(image) - 2)
    joins = [p for p in range(start + 12, limit - 14, 2)
             if matches(p, 0x1C39, 0x2701, 0x2400, 0x2500, 0x2900)
             and word(p + 12) & 0xFF00 == 0xD000]
    if len(joins) != 1:
        return None, 'selector-join-not-unique'
    join = joins[0]
    branches = [p for p in range(start + 12, start + 20, 2)
                if word(p) & 0xFF00 == 0xD100
                and all(word(q) & 0xF800 == 0x4800
                        for q in range(start + 12, p, 2))]
    if len(branches) != 1 or word(branches[0]) & 128:
        return None, 'input-branch-invalid'
    branch = branches[0]
    low = branch + 4 + (word(branch) & 255) * 2
    if (_selector_paths(image, branch + 2, join) != {1}
            or _selector_paths(image, low, join) != {0}):
        return None, 'selector-flow-unproven'
    state = thumb_literal_value(image, join + 10, 0)
    closed = join + 16 + (word(join + 12) & 255) * 2
    if (word(join + 12) & 128
            or state is None or not 0x01000000 <= state < 0x01800000 - 9
            or not join < closed < limit - 56):
        return None, 'debounce-state-invalid'
    # The two counters and state gates are tied to the same RAM object.
    if (not matches(join + 14, 0x7941, 0x2900)
            or not matches(join + 20, 0x79C1, 0x3101, 0x0609, 0x0E09, 0x71C1, 0x2902)
            or not matches(closed, 0x1C06, 0x7980, 0x2800)
            or not matches(closed + 8, 0x7A30, 0x3001, 0x0600, 0x0E00, 0x7230, 0x2803)):
        return None, 'debounce-counters-mismatch'
    transitions = [p for p in range(join + 34, closed - 18, 2)
                   if matches(p, 0x1C39, 0x71C1, 0x7205, 0x7141, 0x7185,
                              0x7245, 0x1C07, 0x245F, 0x2000)]
    if len(transitions) != 1 or not matches(closed + 28, 0x7237, 0x71F5, 0x71B7,
                                           0x7175, 0x2460, 0x2001, 0x7277):
        return None, 'paired-state-events-mismatch'
    opened = transitions[0]
    power = thumb_bl_target(image, opened + 18)
    if power is None or not 0 <= power < len(image) or power != thumb_bl_target(image, closed + 42):
        return None, 'paired-power-calls-mismatch'
    end = closed + 54
    if (not matches(end, 0x1C20, 0xBDF0)
            or not matches(closed + 46, 0x7237, 0x1C20)
            or (event := thumb_bl_target(image, closed + 50)) is None
            or not 0 <= event < len(image)):
        return None, 'event-return-mismatch'
    for pc, opcode in ((join + 18, 0xD1), (join + 32, 0xDB),
                       (closed + 6, 0xD1), (closed + 20, 0xDB)):
        if (word(pc) >> 8 != opcode or word(pc) & 128
                or pc + 4 + (word(pc) & 255) * 2 != end):
            return None, 'debounce-exit-mismatch'
    jump = word(closed - 2)
    if (jump & 0xF800 != 0xE000
            or closed + 2 + (jump & 2047) * 2 != end):
        return None, 'open-flush-exit-mismatch'
    # Open path explicitly requests a flush; its guard reads exactly state+9.
    flush = thumb_bl_target(image, closed - 6)
    if flush is None or not 0 <= flush < len(image) - 20 or not matches(closed - 8, 0x2001):
        return None, 'flush-call-missing'
    if (not matches(flush, 0xB5F0)
            or thumb_literal_value(image, flush + 2, 1) != state + 9
            or not matches(flush + 4, 0x7809, 0x2900, 0xD003)
            or (override := thumb_literal_value(image, flush + 10, 1)) is None
            or not 0x01000000 <= override < 0x01800000 - 4
            or not matches(flush + 12, 0x7909, 0x2900)
            or word(flush + 16) & 0xFF80 != 0xD000):
        return None, 'display-inhibit-guard-mismatch'
    exit_pc = flush + 20 + (word(flush + 16) & 255) * 2
    for _ in range(3):
        if not flush < exit_pc < min(flush + 0x400, len(image) - 2):
            return None, 'display-inhibit-exit-invalid'
        if matches(exit_pc, 0xBDF0):
            break
        jump = word(exit_pc)
        if jump & 0xF800 != 0xE000:
            return None, 'display-inhibit-exit-invalid'
        delta = jump & 2047
        if delta & 1024:
            delta -= 2048
        exit_pc += 4 + delta * 2
    else:
        return None, 'display-inhibit-exit-invalid'
    if not any(matches(pc, 0x1C20) and thumb_bl_target(image, pc + 2) == event
               for pc in range(opened + 22, closed - 8, 2)):
        return None, 'open-event-call-missing'
    if not device_domain('board_contact').periodic_caller(image, start):
        return None, 'periodic-callback-unproven'
    return BoardStatusInput(address, mask, mask), ''
