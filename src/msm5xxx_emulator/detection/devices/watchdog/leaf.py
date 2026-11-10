"""Byte-pulse watchdog service with a closed 39-report periodic owner."""

from __future__ import annotations
import struct
from msm5xxx_emulator.detection.contracts import BodySpec
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.devices.watchdog.rules import _ram, _WAIT_SPEC, DEFAULT_TIMEOUT_MS

_SERVICE = {2: 30720, 4: 10240, 6: 53508, 10: 8193, 12: 28680, 14: 8192, 16: 28680, 18: 18288}
_TASK = { 0: 0xB5F0, 6: 0x2501, 10: 0x036D, 12: 0x2700, 14: 0x2264, 16: 0x200D, 18: 0x02C0, 26: 0x1C04, 32: 0x0BE0, 34: 0xD301, 40: 0x0BA0, 42: 0xD307, 44:
    0x2108, 46: 0x1C30, 52: 0x1C29, 60: 0x3701, 62: 0x043F, 64: 0x0C3F, 66: 0x2F0A, 68: 0xDBE3, 72: 0x2700, 76: 0x22FF, 78: 0x311C, 80: 0x5DC8, 82: 0x3801, 84:
    0x0600, 86: 0x0E00, 88: 0x55C8, 90: 0xD110, 92: 0x00F8, 94: 0x1BC0, 96: 0x1900, 98: 0x7980, 100: 0x2800, 102: 0xDD09, 108: 0x00F8, 112: 0x1BC0, 114: 0x1901,
    116: 0x2000, 122: 0xE7C7, 124: 0x55CA, 126: 0x3701, 128: 0x043F, 130: 0x0C3F, 132: 0x2F27, 134: 0xD3E3, 136: 0xE7C0, }
_LITERALS = {8: 6, 20: 1, 54: 0, 70: 1, 74: 4, 110: 4}
_CALLS = (2, 22, 28, 36, 48, 56, 104, 118)
_SERVICE_SPEC = BodySpec.thumb(20, _SERVICE, {0: 0, 8: 1})
_TASK_SPEC = BodySpec.thumb(138, _TASK, _LITERALS, _CALLS)
_INIT_SPEC = BodySpec.thumb(0x6C, { 0: 0xB5F0, 4: 0x2201, 6: 0x02D2, 8: 0x1C30, 16: 0x2108, 24: 0x2000, 26: 0x22FF, 30: 0x1DF4, 32: 0x3415, 34: 0x1C11, 36:
    0x00C3, 38: 0x1A1B, 40: 0x19DB, 42: 0x799B, 44: 0x2B00, 46: 0xD000, 48: 0x1C19, 50: 0x5421, 52: 0x3001, 54: 0x0400, 56: 0x0C00, 58: 0x2827, 60: 0xD3F1, 62:
    0x2164, 64: 0x1C30, 74: 0x2400, 76: 0x2519, 78: 0x02ED, 80: 0x1C28, 86: 0x1C07, 88: 0x0B00, 90: 0xD308, 96: 0x2164, 98: 0x1C30, 104: 0x3401, 106: 0x0424, },
    {2: 6, 10: 1, 18: 0, 28: 7}, (12, 20, 0x42, 0x46, 0x52, 0x5C, 0x64),)

def find_leaf_watchdog_profile(image: bytes):
    facts = facts_for(image)
    services = {}
    service_anchor = struct.pack("<3H", 0x7800, 0x2800, 0xD104)
    for anchor in facts.string_candidates(service_anchor):
        entry = anchor - 2
        body = _SERVICE_SPEC.match(facts, entry)
        if body is None:
            continue
        values = body.values
        if (_ram(values[0]) and 0x03000000 <= values[8] < 0x04000000 and values[0] != values[8]):
            services[entry] = values
    if not services:
        return None
    candidates = []
    for task in facts.string_candidates(struct.pack("<H", 0xB5F0)):
        body = _TASK_SPEC.match(facts, task)
        if body is None:
            continue
        values, calls = body.values, body.targets
        service = calls[28]
        if service not in services:
            continue
        timer, table = values[20], values[74]
        wait = _WAIT_SPEC.match(facts, calls[22])
        if (wait is None or wait.targets[8] == wait.targets[14] or not _ram(timer) or timer & 3 or not _ram(timer + 28 + 39) or values[70] != timer or values[110]
            != table or not 0 <= table <= len(image) - 39 * 7 or not _ram(values[8]) or not _ram(values[54]) or calls[104] == service or calls[118] == service):
            continue
        # Init feeds the same leaf before and inside its timed startup wait.
        init = calls[2]
        init_body = _INIT_SPEC.match(facts, init)
        if init_body is None:
            continue
        initial_values, startup_calls = init_body.values, init_body.targets
        if (initial_values[2] != timer or initial_values[28] != table or initial_values[18] != values[8] or not _ram(initial_values[10])):
            continue
        setter = wait.targets[8]
        if (startup_calls[0x42] != setter or startup_calls[0x64] != setter or startup_calls[0x46] != service or startup_calls[0x5C] != service or startup_calls[0x52]
            != wait.targets[14]):
            continue
        candidates.append(dict(signature="thumb-byte-leaf-dog39-task-v1", image_size=len(image), register= services[service][8], mask=1, timeout_ms=DEFAULT_TIMEOUT_MS,
            service_address=service, task_address= task, suppression_address=services[service][0], shadow_address=None, wait_argument=100, report_count =39,
            report_stride=7,))
    if len(candidates) != 1:
        return None
    # This compiler class also owns a source-closed rebuild/reset path.  It
    # narrows the generic periodic grammar without changing unrelated boards.
    from msm5xxx_emulator.detection.devices.watchdog.rebuild import find_rebuild_reset_owner
    profile = candidates[0]
    owner = find_rebuild_reset_owner(image, profile["service_address"])
    if owner is None:
        return None
    profile["signature"] = "thumb-byte-leaf-dog39-rebuild-reset-v1"
    profile["rebuild_reset_owner"] = owner
    return profile
