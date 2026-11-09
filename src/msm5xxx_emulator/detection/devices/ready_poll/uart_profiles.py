"""UART consumer refinements for ready-poll source members."""
from __future__ import annotations

import re
import struct
from ...arm import thumb_bl_target, thumb_literal_value
from ...facts import CodeAddress, facts_for
from .helpers import *
from .semantic import *

def _find_control_uart_rx_empty_profile(
        image: bytes, control: dict[str, object]) -> dict[str, object] | None:
    """Require the exact post-control UART empty-read return helper."""
    entries = control.get("entries")
    status_address = control.get("status_address")
    pulse_address = control.get("pulse_address")
    if (not isinstance(entries, list) or len(entries) != 1
            or type(entries[0]) is not int
            or type(status_address) is not int
            or type(pulse_address) is not int):
        return None
    entry = entries[0]
    calls = facts_for(image).call_candidates()
    candidates: list[int] = []
    for read in range(0, len(image) - 36 + 1, 2):
        words = struct.unpack_from("<18H", image, read)
        if (words[0] & 0xF800 != 0x4800 or words[0] >> 8 & 7
                or words[1:5] != (0x3830, 0x7900, 0x0840, 0xD200)
                or _conditional_target(read + 8, words[4]) != read + 12
                or words[5] & 0xF800 != 0xE000
                or words[6] & 0xF800 != 0x4800 or words[6] >> 8 & 7
                or words[7:10] != (0x3830, 0x7A02, 0x2001)
                or words[10] & 0xF800 != 0x4800
                or words[10] >> 8 & 7 != 1):
            continue
        if (facts_for(image).thumb_literal_value(read, 0) != status_address + 0x2C
                or facts_for(image).thumb_literal_value(read + 12, 0)
                   != status_address + 0x2C):
            continue
        has_add = words[11] & 0xFF00 == 0x3100
        store = 12 if has_add else 11
        if (words[store:store + 3] != (0x7008, 0x2000, 0x7008)
                or words[store + 3] & 0xF800 != 0xE000
                or _unconditional_target(read + 10, words[5])
                   != read + (store + 4) * 2
                or _unconditional_target(read + (store + 3) * 2,
                                         words[store + 3]) != read
                or not _thumb_return_at(image, read + (store + 4) * 2)):
            continue
        pulse = facts_for(image).thumb_literal_value(read + 20, 1)
        if pulse is None or pulse + (words[11] & 0xFF if has_add else 0) != pulse_address:
            continue
        helper = next((candidate for candidate in range(
            read - 2, max(-2, read - 0x140), -2
        ) if struct.unpack_from("<H", image, candidate)[0] & 0xFF00
                       == 0xB500), None)
        control_calls = [
            callsite for callsite, target in calls
            if helper is not None and helper <= callsite < read and target == entry
        ]
        helper_calls = [
            callsite for callsite, target in calls if target == helper
        ]
        if (len(control_calls) != 1 or len(helper_calls) != 1
                or not _supplied(image, helper, read + 36)):
            continue
        candidates.append(read)
    if len(candidates) != 1:
        return None
    return {
        **control,
        "signature": "thumb-byte-ready-pulse-control-uart-empty-v1",
        "uart_rx_empty_read_pc_offset": candidates[0] + 4 - entry,
    }



__all__ = [name for name in globals() if name.startswith("_")]
