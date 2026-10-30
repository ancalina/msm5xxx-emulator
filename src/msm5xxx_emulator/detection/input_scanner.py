"""Bounded Thumb GPIO scanner grammar with display-inhibit data-flow evidence."""
from __future__ import annotations

import re
import struct

from ..core.config import BoardStatusInput
from .arm import thumb_bl_target, thumb_literal_value


def _words(*values: int) -> bytes:
    return struct.pack('<' + 'H' * len(values), *values)


def _selector_paths(image: bytes, entry: int, join: int) -> set[int | None]:
    """Explore forward setup branches; calls preserve the callee-saved selector r7.

    Only the small Thumb setup instruction vocabulary is admitted. Unknown writes,
    loops, exits, and malformed calls reject rather than guessing a selector.
    """
    pending = [(entry, None)]
    seen = set()
    results = set()
    while pending:
        pc, value = pending.pop()
        if pc == join:
            results.add(value)
            continue
        if not entry <= pc < join:
            return {None}
        if (pc, value) in seen:
            continue
        seen.add((pc, value))
        w = struct.unpack_from('<H', image, pc)[0]
        if w & 0xF800 == 0xF000:
            target = thumb_bl_target(image, pc)
            if target is None or not 0 <= target < len(image):
                return {None}
            pending.append((pc + 4, value))
            continue
        if w & 0xF000 == 0xD000 and (w >> 8) & 15 < 14:
            delta = w & 255
            if delta & 128:
                delta -= 256
            dest = pc + 4 + delta * 2
            if dest <= pc:
                return {None}
            pending.extend(((dest, value), (pc + 2, value)))
            continue
        if w & 0xF800 == 0xE000:
            delta = w & 2047
            if delta & 1024:
                delta -= 2048
            dest = pc + 4 + delta * 2
            if dest <= pc:
                return {None}
            pending.append((dest, value))
            continue
        if w & 0xF800 == 0x2000:  # MOVS immediate
            if (w >> 8) & 7 == 7:
                value = w & 255
        elif w & 0xF800 == 0x4800:  # literal load
            if (w >> 8) & 7 == 7:
                value = None
        elif w & 0xF800 == 0x2800 or w & 0xF800 == 0x7000:
            pass  # compare or byte store
        elif w & 0xF800 == 0x7800 or w & 0xE000 == 0:
            if w & 7 == 7:
                value = None
        elif w & 0xFC00 == 0x4000:
            if w & 7 == 7:
                value = None
        else:
            return {None}
        pending.append((pc + 2, value))
    return results


def _periodic_caller(image: bytes, scanner: int) -> bool:
    """Tie a direct caller to a repeating clock-registration argument grammar."""
    callbacks = set()
    for call in re.finditer(rb"(?=.[\xf0-\xf7].[\xf8-\xff])", image, re.S):
        pc = call.start()
        if pc & 1 or thumb_bl_target(image, pc) != scanner:
            continue
        # A callback invokes the scanner near its entry (guards may return early).
        for entry in range(pc - 2, max(-1, pc - 0x40), -2):
            w = struct.unpack_from('<H', image, entry)[0]
            if w & 0xFF00 == 0xB500:
                callbacks.add(entry | 1)
                break
    if not callbacks:
        return False
    # repeat=1 on stack; equal nonzero initial/repeat periods in r2/r3;
    # timer object in r0; callback literal in r1; direct clock-service call.
    registration = re.compile(
        rb"\x01\x22\x00\x92(.)\x22(.)\x23[\x20\x28]\x1c.\x49", re.S)
    for match in registration.finditer(image):
        pc = match.start()
        if pc & 1 or match[1] != match[2] or match[1] == b'\x00':
            continue
        callback = thumb_literal_value(image, pc + 10, 1)
        service = thumb_bl_target(image, pc + 12)
        if callback in callbacks and service is not None and 0 <= service < len(image):
            return True
    return False


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
    if not _periodic_caller(image, start):
        return None, 'periodic-callback-unproven'
    return BoardStatusInput(address, mask, mask), ''
