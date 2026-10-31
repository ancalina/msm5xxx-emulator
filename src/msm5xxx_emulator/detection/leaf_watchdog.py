"""Byte-pulse watchdog service with a closed 39-report periodic owner."""

from __future__ import annotations

import re
import struct
from .watchdog import _shape, _ram, _WAIT, _WAIT_CALLS, DEFAULT_TIMEOUT_MS

_SERVICE = {
    2: 0x7800,
    4: 0x2800,
    6: 0xD104,
    10: 0x2001,
    12: 0x7008,
    14: 0x2000,
    16: 0x7008,
    18: 0x4770,
}
_TASK = {
    0: 0xB5F0,
    6: 0x2501,
    10: 0x036D,
    12: 0x2700,
    14: 0x2264,
    16: 0x200D,
    18: 0x02C0,
    26: 0x1C04,
    32: 0x0BE0,
    34: 0xD301,
    40: 0x0BA0,
    42: 0xD307,
    44: 0x2108,
    46: 0x1C30,
    52: 0x1C29,
    60: 0x3701,
    62: 0x043F,
    64: 0x0C3F,
    66: 0x2F0A,
    68: 0xDBE3,
    72: 0x2700,
    76: 0x22FF,
    78: 0x311C,
    80: 0x5DC8,
    82: 0x3801,
    84: 0x0600,
    86: 0x0E00,
    88: 0x55C8,
    90: 0xD110,
    92: 0x00F8,
    94: 0x1BC0,
    96: 0x1900,
    98: 0x7980,
    100: 0x2800,
    102: 0xDD09,
    108: 0x00F8,
    112: 0x1BC0,
    114: 0x1901,
    116: 0x2000,
    122: 0xE7C7,
    124: 0x55CA,
    126: 0x3701,
    128: 0x043F,
    130: 0x0C3F,
    132: 0x2F27,
    134: 0xD3E3,
    136: 0xE7C0,
}
_LITERALS = {8: 6, 20: 1, 54: 0, 70: 1, 74: 4, 110: 4}
_CALLS = (2, 22, 28, 36, 48, 56, 104, 118)


def find_leaf_watchdog_profile(image: bytes):
    services = {}
    for match in re.finditer(
        re.escape(struct.pack("<3H", 0x7800, 0x2800, 0xD104)), image
    ):
        entry = match.start() - 2
        shape = _shape(image, entry, 20, _SERVICE, {0: 0, 8: 1}, ())
        if shape is None:
            continue
        values, _ = shape
        if (
            _ram(values[0])
            and 0x03000000 <= values[8] < 0x04000000
            and values[0] != values[8]
        ):
            services[entry] = values
    if not services:
        return None
    candidates = []
    for match in re.finditer(re.escape(struct.pack("<H", 0xB5F0)), image):
        task = match.start()
        shape = _shape(image, task, 138, _TASK, _LITERALS, _CALLS)
        if shape is None:
            continue
        values, calls = shape
        service = calls[28]
        if service not in services:
            continue
        timer, table = values[20], values[74]
        wait = _shape(image, calls[22], 24, _WAIT, {}, _WAIT_CALLS)
        if (
            wait is None
            or wait[1][8] == wait[1][14]
            or not _ram(timer)
            or timer & 3
            or not _ram(timer + 28 + 39)
            or values[70] != timer
            or values[110] != table
            or not 0 <= table <= len(image) - 39 * 7
            or not _ram(values[8])
            or not _ram(values[54])
            or calls[104] == service
            or calls[118] == service
        ):
            continue
        # Init feeds the same leaf before and inside its timed startup wait.
        init = calls[2]
        init_shape = _shape(
            image,
            init,
            0x6C,
            {
                0: 0xB5F0,
                4: 0x2201,
                6: 0x02D2,
                8: 0x1C30,
                16: 0x2108,
                24: 0x2000,
                26: 0x22FF,
                30: 0x1DF4,
                32: 0x3415,
                34: 0x1C11,
                36: 0x00C3,
                38: 0x1A1B,
                40: 0x19DB,
                42: 0x799B,
                44: 0x2B00,
                46: 0xD000,
                48: 0x1C19,
                50: 0x5421,
                52: 0x3001,
                54: 0x0400,
                56: 0x0C00,
                58: 0x2827,
                60: 0xD3F1,
                62: 0x2164,
                64: 0x1C30,
                74: 0x2400,
                76: 0x2519,
                78: 0x02ED,
                80: 0x1C28,
                86: 0x1C07,
                88: 0x0B00,
                90: 0xD308,
                96: 0x2164,
                98: 0x1C30,
                104: 0x3401,
                106: 0x0424,
            },
            {2: 6, 10: 1, 18: 0, 28: 7},
            (12, 20, 0x42, 0x46, 0x52, 0x5C, 0x64),
        )
        if init_shape is None:
            continue
        initial_values, startup_calls = init_shape
        if (
            initial_values[2] != timer
            or initial_values[28] != table
            or initial_values[18] != values[8]
            or not _ram(initial_values[10])
        ):
            continue
        setter = wait[1][8]
        if (
            startup_calls[0x42] != setter
            or startup_calls[0x64] != setter
            or startup_calls[0x46] != service
            or startup_calls[0x5C] != service
            or startup_calls[0x52] != wait[1][14]
        ):
            continue
        candidates.append(
            dict(
                signature="thumb-byte-leaf-dog39-task-v1",
                image_size=len(image),
                register=services[service][8],
                mask=1,
                timeout_ms=DEFAULT_TIMEOUT_MS,
                service_address=service,
                task_address=task,
                suppression_address=services[service][0],
                shadow_address=None,
                wait_argument=100,
                report_count=39,
                report_stride=7,
            )
        )
    if len(candidates) != 1:
        return None
    # This compiler class also owns a source-closed rebuild/reset path.  It
    # narrows the generic periodic grammar without changing unrelated boards.
    from .watchdog_rebuild import find_rebuild_reset_owner

    profile = candidates[0]
    owner = find_rebuild_reset_owner(image, profile["service_address"])
    if owner is None:
        return None
    profile["signature"] = "thumb-byte-leaf-dog39-rebuild-reset-v1"
    profile["rebuild_reset_owner"] = owner
    return profile
