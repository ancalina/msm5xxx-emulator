"""Fail-closed recognition of a Thumb watchdog pulse and its periodic owner.

This deliberately recognizes one compiler grammar, not arbitrary GPIO pulses.
The scheduled wait argument is 100; 30 s is an emulator policy margin, not a
recovered physical timeout or a bound on every interrupt-disabled operation.
"""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value

SIGNATURE = "thumb-shadow-pulse-dog-task-v1"
DEFAULT_TIMEOUT_MS = 30_000

# ARMv4T instruction contracts. Literal displacements and BL displacements are
# decoded separately. No image addresses, identity strings, or model IDs occur.
_SERVICE = {
    2: 0xB590, 4: 0x7800, 6: 0x2800, 8: 0xD11E,
    0x10: 0x2207, 0x12: 0x01D2, 0x14: 0x188F, 0x16: 0x8839,
    0x1C: 0x4019, 0x20: 0x4311, 0x22: 0x8039, 0x24: 0x8839,
    0x26: 0x7021, 0x28: 0x2800, 0x2A: 0xD101,
    0x34: 0x8839, 0x38: 0x4019, 0x3A: 0x8039,
    0x3C: 0x8839, 0x3E: 0x7021, 0x40: 0x2800, 0x42: 0xD101,
    0x48: 0xBC90, 0x4A: 0xBC08, 0x4C: 0x4718,
}
_SERVICE_LITERALS = {0: 0, 0xE: 1, 0x18: 3, 0x1A: 4, 0x36: 3}
_SERVICE_CALLS = (0xA, 0x2C, 0x30, 0x44)
_TASK = {
    0: 0xB5F0, 6: 0x2501, 0xA: 0x036D, 0xC: 0x2700,
    0xE: 0x2264, 0x10: 0x200D, 0x12: 0x02C0,
    0x1A: 0x1C04, 0x20: 0x0BE0, 0x22: 0xD301,
    0x28: 0x0BA0, 0x2A: 0xD307, 0x2C: 0x2108, 0x2E: 0x1C30,
    0x34: 0x1C29, 0x3C: 0x3701, 0x3E: 0x043F,
    0x42: 0x0C3F, 0x44: 0x429F, 0x46: 0xDBE2,
    0x4C: 0x6950, 0x4E: 0x43C0, 0x50: 0x4008, 0x52: 0xD013,
    0x58: 0x1C39, 0x5A: 0x30F0, 0x64: 0x6950,
    0x66: 0x43C0, 0x68: 0x4008, 0x6A: 0xD007,
    0x72: 0x1C39, 0x74: 0x30FB, 0x7A: 0xE7C7,
    0x7C: 0x2000, 0x7E: 0x6150, 0x80: 0xE7C4,
}
_TASK_LITERALS = {
    8: 6, 0x14: 1, 0x36: 0, 0x40: 3, 0x48: 2, 0x4A: 1,
    0x54: 7, 0x56: 0, 0x60: 2, 0x62: 1, 0x70: 0,
}
_TASK_CALLS = (2, 0x16, 0x1C, 0x24, 0x30, 0x38, 0x5C, 0x6C, 0x76)
# Wrapper: save signal mask r0 in r7; pass timer r1 and delay r2 to
# timer setter; then wait on the saved signal mask. Both calls must resolve.
_WAIT = {0: 0xB580, 2: 0x1C07, 4: 0x1C08, 6: 0x1C11,
         0xC: 0x1C38, 0x12: 0xBC80, 0x14: 0xBC08, 0x16: 0x4718}
_WAIT_CALLS = (8, 0xE)


def _shape(image: bytes, entry: int, size: int, fixed: dict[int, int],
           literals: dict[int, int], calls: tuple[int, ...]):
    if entry & 1 or not 0 <= entry <= len(image) - size:
        return None
    if any(struct.unpack_from("<H", image, entry + off)[0] != op
           for off, op in fixed.items()):
        return None
    values = {off: thumb_literal_value(image, entry + off, reg)
              for off, reg in literals.items()}
    targets = {off: thumb_bl_target(image, entry + off) for off in calls}
    if any(v is None for v in values.values()) or any(
            v is None or v & 1 or not 0 <= v < len(image) - 2
            for v in targets.values()):
        return None
    return values, targets


def _ram(value: int) -> bool:
    return 0x01000000 <= value < 0x03000000


def find_watchdog_profile(image: bytes) -> tuple[dict[str, object] | None, str]:
    """Return a unique closed service/task pair, or explain rejection.

    All code and dog.c literals must be directly represented in this image;
    unresolved overlays or differing compiler/control-flow classes are rejected.
    """
    services = {}
    # Anchor is PUSH {r4,r7,lr}; alignment and the entire routine are checked.
    for match in re.finditer(re.escape(struct.pack("<H", 0xB590)), image):
        entry = match.start() - 2
        shape = _shape(image, entry, 0x4E, _SERVICE,
                       _SERVICE_LITERALS, _SERVICE_CALLS)
        if shape is None:
            continue
        values, calls = shape
        op = struct.unpack_from("<H", image, entry + 0x1E)[0]
        mask = op & 0xFF
        if (op & 0xFF00 != 0x2200 or not mask or mask & (mask - 1)
                or values[0x18] != 0xFFFF ^ mask
                or values[0x36] != values[0x18]
                or not _ram(values[0]) or not _ram(values[0xE] + 0x380)
                or (values[0xE] + 0x380) & 1
                or not 0x03000000 <= values[0x1A] < 0x04000000
                or calls[0xA] != calls[0x30]
                or calls[0x2C] != calls[0x44]
                or calls[0xA] == calls[0x2C]):
            continue
        services[entry] = (values, mask)
    if not services:
        return None, ("watchdog-service-grammar-unclosed" if b"dog.c\0" in image
                      else "no-watchdog-service")
    candidates = []
    for match in re.finditer(re.escape(struct.pack("<H", 0xB5F0)), image):
        task = match.start()
        shape = _shape(image, task, 0x82, _TASK, _TASK_LITERALS, _TASK_CALLS)
        if shape is None:
            continue
        values, calls = shape
        if calls[0x1C] not in services:
            continue
        wait = _shape(image, calls[0x16], 0x18, _WAIT, {}, _WAIT_CALLS)
        if wait is None or wait[1][8] == wait[1][0xE]:
            continue
        dog = values[0x54]
        if (not 0 <= dog <= len(image) - 6 or image[dog:dog + 6] != b"dog.c\0"
                or calls[0x5C] != calls[0x76]
                or values[0x48] != values[0x60]
                or not _ram(values[0x48])
                or not 0 < values[0x40] <= 0xFFFF
                or values[0x56] != values[0x70]):
            continue
        candidates.append((task, calls[0x1C]))
    if len(candidates) != 1:
        return None, ("watchdog-owner-ambiguous" if candidates
                      else "watchdog-periodic-owner-unclosed")
    task, service = candidates[0]
    values, mask = services[service]
    return {
        "signature": SIGNATURE,
        "image_size": len(image),
        "register": values[0x1A], "mask": mask,
        "timeout_ms": DEFAULT_TIMEOUT_MS,
        "service_address": service, "task_address": task,
        "suppression_address": values[0],
        "shadow_address": values[0xE] + 0x380,
        "wait_argument": 100,
    }, "watchdog-service-and-periodic-dog-owner-closed"
