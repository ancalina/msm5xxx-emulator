"""LCD and source-member aggregation for ready-poll protocols."""
from __future__ import annotations

import re
import struct
from ...arm import thumb_bl_target, thumb_literal_value
from ...facts import facts_for
from .helpers import *
from .semantic import *
from .uart_profiles import *

def _find_lcd_halfword_ready_poll_profile(
        image: bytes) -> dict[str, object] | None:
    """Find the exact LCD command/status helper and its closed busy loop."""
    helpers: set[int] = set()
    cursor = 0
    while True:
        helper = image.find(_LCD_HALFWORD_HELPER, cursor)
        if helper < 0:
            break
        cursor = helper + 2
        if not helper & 1 and _supplied(image, helper, helper + len(_LCD_HALFWORD_HELPER)):
            helpers.add(helper)
    if not helpers:
        return None

    calls = facts_for(image).call_candidates()
    candidates: list[int] = []
    tail = (0x2006, 0x2105, 0x05C9, 0x8108, 0x818A, 0xBC08, 0x4718)
    for callsite, target in calls:
        entry = callsite - 2
        wrapper = entry - 8
        if (wrapper < 0 or entry + 24 > len(image)
                or target not in helpers or not _supplied(image, wrapper, entry + 24)):
            continue
        words = struct.unpack_from("<12H", image, entry)
        prefix = struct.unpack_from("<4H", image, wrapper)
        wrapper_called = any(
            called_target == wrapper
            and not wrapper <= caller < entry + 24
            for caller, called_target in calls
        )
        if (prefix != (0x0200, 0x4308, 0x1C02, 0xB500)
                or not wrapper_called
                or words[0] != 0x2008
                or words[3] != 0x0900
                or words[4] & 0xFF00 != 0xD200
                or _conditional_target(entry + 8, words[4]) != entry
                or words[5:] != tail):
            continue
        candidates.append(facts_for(image).thumb_call_target(callsite))
    if len(candidates) != 1:
        return None
    return {
        "signature": "thumb-lcd-halfword-busy-clear-v1",
        "admission": "experimental-only",
        "status_address": 0x0280000C,
        "mask": 0x08,
        "command_address": 0x02800008,
        "command_value": 0x08,
        "status_read_pc_offset": 6,
        "command_write_pc_offset": 4,
        "entries": candidates,
    }


def _extract_ready_poll_profile(image: bytes) -> dict[str, object] | None:
    """Return one unambiguous firmware-proven ready-poll class."""
    compact = _find_compact_ready_poll_profile(image)
    if compact is not None:
        uart = _find_uart_csr_sr_rx_empty_profile(image, compact)
        if uart is not None:
            compact = uart
    rotated = _find_rotated_ready_poll_profile(image)
    if rotated is not None:
        members = rotated.get("variants", [rotated])
        if any(member[field] != rotated[field]
               for member in members
               for field in ("status_address", "mask", "pulse_address")):
            return None
        upgraded = [
            _find_rotated_uart_csr_sr_profile(image, member) or member
            for member in members
        ]
        if "variants" in rotated:
            rotated = {**rotated, "variants": upgraded}
        else:
            rotated = upgraded[0]
    if compact is not None and rotated is not None:
        fields = ("status_address", "mask", "pulse_address")
        if any(compact[field] != rotated[field] for field in fields):
            return None
        rotated = {
            "signature": "thumb-byte-ready-pulse-variants-v1",
            "admission": "temporary-evidence-gated",
            **{field: compact[field] for field in fields},
            "variants": [*compact.get("variants", [compact]),
                         *rotated.get("variants", [rotated])],
        }
        compact = None
    control = _find_control_ready_poll_profile(image)
    if control is not None:
        control_uart = _find_control_uart_rx_empty_profile(image, control)
        if control_uart is not None:
            control = control_uart
    profiles = [
        profile for profile in (
            compact,
            rotated,
            control,
        ) if profile is not None
    ]
    if not profiles:
        lcd = _find_lcd_halfword_ready_poll_profile(image)
        if lcd is not None:
            profiles.append(lcd)
    return profiles[0] if len(profiles) == 1 else None


def find_ready_poll_profile(image: bytes) -> dict[str, object] | None:
    """Return a fresh profile copy from the immutable-image cache."""
    context = facts_for(image)
    profile = context.memo('ready-poll-profile', (),
                           lambda: _extract_ready_poll_profile(context.image))
    return _copy_profile(profile) if profile is not None else None


def _copy_profile(profile: dict[str, object]) -> dict[str, object]:
    return {key: [_copy_profile(item) if isinstance(item, dict) else item
                  for item in value] if isinstance(value, list) else value
            for key, value in profile.items()}


def find_arm_tx_empty_ready_poll_profile(image: bytes) -> dict[str, object] | None:
    """Close an ARM byte TX-empty poll and both watchdog pulse producers."""
    # ARMv4 immediate addressing, explicit byte accesses, backward loop and
    # conditional exit. Bit3 is TX empty; no RX-available bit is asserted.
    program = (
        0xE3A00403,  # MOV r0, #0x03000000
        0xE5D007B4,  # LDRB r0, [r0, #0x7b4]
        0xE3100008,  # TST r0, #8
        0x1A000006,  # BNE return
        0xE3A00001, 0xE3A01403, 0xE5C10600,
        0xE3A01000, 0xE3A00403, 0xE5C01600,
        0xEAFFFFF4, 0xE1A0F00E,  # B loop; MOV pc, lr
    )
    marker = struct.pack('<2I', *program[:2])
    entries, cursor = [], 0
    while (cursor := image.find(marker, cursor)) >= 0:
        at = cursor
        cursor += 4
        if (at & 3 or at + 4 * len(program) > len(image)
                or not _supplied(image, at, at + 4 * len(program))
                or struct.unpack_from('<12I', image, at) != program):
            continue
        # Calls prove this is executable code owned by the boot UART path.
        callers = 0
        for call in range(0, len(image) - 3, 4):
            word = struct.unpack_from('<I', image, call)[0]
            if word >> 24 != 0xEB:
                continue
            delta = word & 0xFFFFFF
            if delta & 0x800000:
                delta -= 0x1000000
            callers += call + 8 + delta * 4 == at
        if callers >= 2:
            entries.append(at)
    if len(entries) != 1:
        return None
    return {
        'signature': 'arm-byte-tx-empty-pulse-v1',
        'admission': 'temporary-evidence-gated',
        'status_address': 0x030007B4, 'mask': 8,
        'pulse_address': 0x03000600,
        'status_read_pc_offset': 4,
        'pulse_set_pc_offset': 0x18, 'pulse_clear_pc_offset': 0x24,
        'entries': entries,
    }



__all__ = [name for name in globals() if name.startswith("_") or name in {"find_ready_poll_profile", "find_arm_tx_empty_ready_poll_profile"}]
