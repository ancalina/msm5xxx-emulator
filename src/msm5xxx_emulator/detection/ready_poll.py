"""Firmware-proven ready-poll protocol classes."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value


_READ_SHIFT = b"\x00\x79\x00\x09"  # LDRB r0,[r0,#4]; LSRS r0,r0,#4
_READ_SHIFT_CONTROL = b"\x09\x79\x09\x09"  # r1 variant with control write
_UART_FRAMED_READ = b"\x01\x79\x48\x08"  # LDRB r1,[r0,#4]; LSRS r0,r1,#1
_ROTATED_READY_POLL = bytes.fromhex(
    "90b400200122064f044901e00a7008703c792309fad390bc70470000"
)
_LCD_HALFWORD_HELPER = bytes.fromhex("0521c905088188897047")
_THUMB_BL = re.compile(rb".[\xf0-\xf7].[\xf8-\xff]", re.S)


def _conditional_target(address: int, word: int) -> int:
    displacement = (word & 0xFF) * 2
    if displacement & 0x100:
        displacement -= 0x200
    return address + 4 + displacement


def _unconditional_target(address: int, word: int) -> int:
    displacement = (word & 0x7FF) * 2
    if displacement & 0x800:
        displacement -= 0x1000
    return address + 4 + displacement


def _thumb_return_at(image: bytes, address: int) -> bool:
    """Accept only the short return forms used by a closed Thumb helper."""
    if not 0 <= address <= len(image) - 2:
        return False
    word = struct.unpack_from("<H", image, address)[0]
    if word == 0x4770 or word & 0xFF00 == 0xBD00:
        return True
    if (word & 0xFF00 != 0xBC00
            or address + 4 > len(image)):
        return False
    return struct.unpack_from("<H", image, address + 2)[0] & 0xFF87 == 0x4700


def _uart_status_base_at(
        image: bytes, read: int, status_address: int) -> bool:
    """Match `LDRB r0,[r0,#4]` after one literal status-base producer."""
    if thumb_literal_value(image, read - 2, 0) == status_address - 4:
        return True
    if read < 4:
        return False
    add = struct.unpack_from("<H", image, read - 2)[0]
    base = thumb_literal_value(image, read - 4, 0)
    return (base is not None and add & 0xFF00 == 0x3000
            and base + (add & 0xFF) == status_address - 4)


def _uart_rx_empty_pulse_at(
        image: bytes, start: int, end: int, entry: int,
        read: int, pulse_address: int) -> bool:
    """Require a one/zero pulse and backward busy edge after the RX poll."""
    limit = min(end, start + 0x30)
    for current in range(start, limit, 2):
        if current + 12 > len(image):
            break
        words = struct.unpack_from("<6H", image, current)
        if (words[0] != 0x2001
                or thumb_literal_value(image, current + 2, 1)
                   != pulse_address
                or words[2:5] != (0x7008, 0x2000, 0x7008)
                or words[5] & 0xF800 != 0xE000):
            continue
        target = _unconditional_target(current + 10, words[5])
        if entry <= target <= read:
            return True
    return False


def _uart_framed_rx_empty_offset(
        image: bytes, calls: list[tuple[int, int]], compact_entry: int,
        status_address: int, pulse_address: int, primary_read: int,
) -> int | None:
    """Close a two-call framed receiver that consumes the paired RX FIFO."""
    candidates: list[int] = []
    cursor = 4
    while True:
        read = image.find(_UART_FRAMED_READ, cursor)
        if read < 0 or read >= len(image) - 24:
            break
        cursor = read + 2
        if read & 1:
            continue
        if read == primary_read:
            continue
        words = struct.unpack_from("<12H", image, read)
        if (words[:2] != (0x7901, 0x0848)
                or words[2] & 0xFF00 != 0xD300
                or _conditional_target(read + 4, words[2]) != read + 12
                or words[3:7] != (0x1C08, 0xBC80, 0x46F7, 0x2001)
                or words[7] & 0xF800 != 0x4800
                or words[8] != 0x7000 | ((words[7] >> 8 & 7) << 3)
                or words[9] != 0x2000 or words[10] != words[8]
                or words[11] & 0xF800 != 0xE000
                or not _uart_status_base_at(image, read, status_address)
                or thumb_literal_value(
                    image, read + 14, words[7] >> 8 & 7
                ) != pulse_address):
            continue
        start = max(0, read - 0x100)
        helper_entry = next((candidate for candidate in range(
            read - 2, start - 1, -2
        ) if struct.unpack_from("<H", image, candidate)[0] == 0xB480), None)
        if (helper_entry is None
                or not helper_entry <= _unconditional_target(
                    read + 22, words[11]
                ) <= read):
            continue
        callers = [callsite for callsite, target in calls
                   if target == helper_entry]
        if (len(callers) != 2 or max(callers) - min(callers) > 0x20):
            continue
        data_reads = [
            data for data in range(max(callers) + 4,
                                   min(len(image) - 2, max(callers) + 0x80),
                                   2)
            if struct.unpack_from("<H", image, data)[0] == 0x7A00
            and thumb_literal_value(image, data - 2, 0) == status_address - 4
        ]
        if (len(data_reads) != 1
                or not all(helper_entry < callsite < data_reads[0]
                           for callsite in callers)):
            continue
        candidates.append(read)
    if len(candidates) != 1:
        return None
    return candidates[0] - compact_entry


def _find_uart_csr_sr_rx_empty_profile(
        image: bytes, compact: dict[str, object]) -> dict[str, object] | None:
    """Close a paired TX-empty helper and RX-empty drain helper at one alias."""
    entries = compact.get("entries")
    status_address = compact.get("status_address")
    pulse_address = compact.get("pulse_address")
    if (not isinstance(entries, list) or len(entries) != 1
            or any(type(entry) is not int for entry in entries)
            or type(status_address) is not int or type(pulse_address) is not int):
        return None
    compact_entry = entries[0]
    calls = [
        (match.start(), target)
        for match in _THUMB_BL.finditer(image)
        if (match.start() & 1) == 0
        and (target := thumb_bl_target(image, match.start())) is not None
    ]
    called_entries = {target for _callsite, target in calls}
    candidates: list[int] = []
    for read in range(4, len(image) - 6, 2):
        words = struct.unpack_from("<3H", image, read)
        condition = words[2] & 0x0F00
        if (words[:2] != (0x7900, 0x0840)
                or words[2] & 0xF000 != 0xD000
                or condition not in (0x0200, 0x0300)
                or not _uart_status_base_at(image, read, status_address)):
            continue
        start = max(0, read - 0x100)
        helper_entry = next((candidate for candidate in range(
            read - 2, start - 1, -2
        ) if struct.unpack_from("<H", image, candidate)[0] & 0xFF00
                         == 0xB500), None)
        if (helper_entry is None or helper_entry not in called_entries
                or not any(helper_entry <= callsite < read
                           and target == compact_entry
                           for callsite, target in calls)):
            continue
        if condition == 0x0200:  # BCS: RX-ready takes the busy path.
            if read + 8 > len(image):
                continue
            busy = _conditional_target(read + 4, words[2])
            exit_word = struct.unpack_from("<H", image, read + 6)[0]
            if exit_word & 0xF800 != 0xE000:
                continue
            exit_address = _unconditional_target(read + 6, exit_word)
        else:  # BCC: RX-empty takes the return path.
            busy = read + 6
            exit_address = _conditional_target(read + 4, words[2])
        if (not helper_entry <= busy < exit_address
                or not _thumb_return_at(image, exit_address)
                or not _uart_rx_empty_pulse_at(
                    image, busy, exit_address, helper_entry,
                    read, pulse_address
                )):
            continue
        candidates.append(read)
    if len(candidates) != 1:
        return None
    profile: dict[str, object] = {
        "signature": "thumb-uart-csr-sr-rx-empty-v1",
        "admission": "temporary-evidence-gated",
        "status_address": status_address,
        "mask": 0x08,
        "pulse_address": pulse_address,
        "status_read_pc_offset": 2,
        "pulse_set_pc_offset": 0x0C,
        "pulse_clear_pc_offset": 0x10,
        "uart_rx_empty_read_pc_offset": candidates[0] - compact_entry,
        "entries": entries,
    }
    framed_offset = _uart_framed_rx_empty_offset(
        image, calls, compact_entry, status_address, pulse_address,
        candidates[0],
    )
    if framed_offset is not None:
        profile["uart_rx_empty_frame_read_pc_offset"] = framed_offset
    return profile


def _find_compact_ready_poll_profile(
        image: bytes) -> dict[str, object] | None:
    """Find exact byte-status/BHS/pulse loops sharing one hardware contract."""
    candidates: list[tuple[int, tuple[int, int, int]]] = []
    cursor = 0
    while True:
        marker = image.find(_READ_SHIFT, cursor)
        if marker < 0:
            break
        cursor = marker + 2
        entry = marker - 2
        if entry < 0 or entry & 1 or entry + 22 > len(image):
            continue
        words = struct.unpack_from("<11H", image, entry)
        if (words[0] & 0xF800 != 0x4800
                or words[3] & 0xFF00 != 0xD200
                or _conditional_target(entry + 6, words[3]) != entry + 20
                or words[4] != 0x2001
                or words[5] & 0xF800 != 0x4800
                or words[6] != 0x7008
                or words[7] != 0x2000
                or words[8] != 0x7008
                or words[9] & 0xF800 != 0xE000
                or _unconditional_target(entry + 18, words[9]) > entry
                or words[10] not in (0x46F7, 0x4770)):
            continue
        status_literal = ((entry + 4) & ~3) + (words[0] & 0xFF) * 4
        pulse_literal = ((entry + 14) & ~3) + (words[5] & 0xFF) * 4
        if max(status_literal, pulse_literal) + 4 > len(image):
            continue
        status_base = struct.unpack_from("<I", image, status_literal)[0]
        pulse_address = struct.unpack_from("<I", image, pulse_literal)[0]
        status_address = status_base + 4
        contract = (status_address, 0x08, pulse_address)
        if (not 0x03000000 <= status_address < 0x04000000
                or not 0x03000000 <= pulse_address < 0x04000000
                or status_address == pulse_address):
            continue
        candidates.append((entry, contract))
    targets = {entry for entry, _contract in candidates}
    called = {
        target for match in _THUMB_BL.finditer(image)
        if (callsite := match.start()) % 2 == 0
        and (target := thumb_bl_target(image, callsite)) in targets
    }
    candidates = [candidate for candidate in candidates
                  if candidate[0] in called]
    entries = [entry for entry, _contract in candidates]
    contracts = {contract for _entry, contract in candidates}
    if not entries or len(contracts) != 1:
        return None
    status_address, mask, pulse_address = contracts.pop()
    return {
        "signature": "thumb-lsrs-bhs-pulse-v1",
        "status_address": status_address,
        "mask": mask,
        "pulse_address": pulse_address,
        "entries": entries,
    }


def _find_rotated_ready_poll_profile(
        image: bytes) -> dict[str, object] | None:
    """Find the exact register-rotated ready/pulse loop class."""
    candidates: list[tuple[int, tuple[int, int, int]]] = []
    cursor = 0
    while True:
        entry = image.find(_ROTATED_READY_POLL, cursor)
        if entry < 0:
            break
        cursor = entry + 2
        if entry & 1 or entry + 36 > len(image):
            continue
        pulse_address, status_base = struct.unpack_from("<2I", image, entry + 28)
        contract = (status_base + 4, 0x08, pulse_address)
        if (not 0x03000000 <= contract[0] < 0x04000000
                or not 0x03000000 <= pulse_address < 0x04000000
                or contract[0] == pulse_address):
            continue
        candidates.append((entry, contract))
    targets = {entry for entry, _contract in candidates}
    called = {
        target for match in _THUMB_BL.finditer(image)
        if (callsite := match.start()) % 2 == 0
        and (target := thumb_bl_target(image, callsite)) in targets
    }
    candidates = [candidate for candidate in candidates
                  if candidate[0] in called]
    entries = [entry for entry, _contract in candidates]
    contracts = {contract for _entry, contract in candidates}
    if len(entries) != 1 or len(contracts) != 1:
        return None
    status_address, mask, pulse_address = contracts.pop()
    return {
        "signature": "thumb-lsrs-bcc-pulse-rotated-v1",
        "admission": "temporary-evidence-gated",
        "status_address": status_address,
        "mask": mask,
        "pulse_address": pulse_address,
        "status_read_pc_offset": 0x10,
        "pulse_set_pc_offset": 0x0C,
        "pulse_clear_pc_offset": 0x0E,
        "entries": entries,
    }


def _find_control_ready_poll_profile(
        image: bytes) -> dict[str, object] | None:
    """Find the closed byte-ready/pulse/control loop class."""
    candidates: list[tuple[int, tuple[int, int, int, int, int]]] = []
    cursor = 0
    while True:
        marker = image.find(_READ_SHIFT_CONTROL, cursor)
        if marker < 0:
            break
        cursor = marker + 2
        entry = marker - 4
        if entry < 0 or entry & 1 or entry + 48 > len(image):
            continue
        words = struct.unpack_from("<20H", image, entry)
        if (words[0] != 0x2000
                or words[1] & 0xFF00 != 0x4900
                or words[2] != 0x7909
                or words[3] != 0x0909
                or words[4] & 0xFF00 != 0xD200
                or _conditional_target(entry + 8, words[4]) != entry + 38
                or words[5:9] != (0x1C01, 0x1C42, 0x1C10, 0x0849)
                or words[9] & 0xFF00 != 0xD300
                or _conditional_target(entry + 18, words[9]) != entry + 2
                or words[10] != 0x2101
                or words[11] & 0xFF00 != 0x4A00
                or words[12:16] != (0x7011, 0x2100, 0x7011, 0x2120)
                or words[16] & 0xFF00 != 0x4A00
                or words[17] != 0x7311
                or words[18] & 0xF800 != 0xE000
                or _unconditional_target(entry + 36, words[18]) != entry + 2
                or words[19] != 0x4770):
            continue
        status_literal = ((entry + 6) & ~3) + (words[1] & 0xFF) * 4
        pulse_literal = ((entry + 26) & ~3) + (words[11] & 0xFF) * 4
        control_literal = ((entry + 36) & ~3) + (words[16] & 0xFF) * 4
        if max(status_literal, pulse_literal, control_literal) + 4 > len(image):
            continue
        status_base = struct.unpack_from("<I", image, status_literal)[0]
        pulse_address = struct.unpack_from("<I", image, pulse_literal)[0]
        control_base = struct.unpack_from("<I", image, control_literal)[0]
        status_address = status_base + 4
        control_address = control_base + 12
        contract = (status_address, 0x08, pulse_address,
                    control_address, 0x20)
        if (status_base != control_base
                or not 0x03000000 <= status_address < 0x04000000
                or not 0x03000000 <= pulse_address < 0x04000000
                or not 0x03000000 <= control_address < 0x04000000
                or len({status_address, pulse_address, control_address}) != 3):
            continue
        candidates.append((entry, contract))
    targets = {entry for entry, _contract in candidates}
    called = {
        target for match in _THUMB_BL.finditer(image)
        if (callsite := match.start()) % 2 == 0
        and (target := thumb_bl_target(image, callsite)) in targets
    }
    candidates = [candidate for candidate in candidates
                  if candidate[0] in called]
    entries = [entry for entry, _contract in candidates]
    contracts = {contract for _entry, contract in candidates}
    if not entries or len(contracts) != 1:
        return None
    status_address, mask, pulse_address, control_address, control_value = (
        contracts.pop()
    )
    return {
        "signature": "thumb-byte-ready-pulse-control-v1",
        "admission": "temporary-evidence-gated",
        "status_address": status_address,
        "mask": mask,
        "pulse_address": pulse_address,
        "control_address": control_address,
        "control_value": control_value,
        "status_read_pc_offset": 4,
        "pulse_set_pc_offset": 0x18,
        "pulse_clear_pc_offset": 0x1C,
        "control_pc_offset": 0x22,
        "entries": entries,
    }


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
    calls = [
        (match.start(), target)
        for match in _THUMB_BL.finditer(image)
        if (match.start() & 1) == 0
        and (target := thumb_bl_target(image, match.start())) is not None
    ]
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
        if (thumb_literal_value(image, read, 0) != status_address + 0x2C
                or thumb_literal_value(image, read + 12, 0)
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
        pulse = thumb_literal_value(image, read + 20, 1)
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
        if len(control_calls) != 1 or len(helper_calls) != 1:
            continue
        candidates.append(read)
    if len(candidates) != 1:
        return None
    return {
        **control,
        "signature": "thumb-byte-ready-pulse-control-uart-empty-v1",
        "uart_rx_empty_read_pc_offset": candidates[0] + 4 - entry,
    }


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
        if not helper & 1:
            helpers.add(helper)
    if not helpers:
        return None

    calls = [
        (match.start(), target)
        for match in _THUMB_BL.finditer(image)
        if (match.start() & 1) == 0
        and (target := thumb_bl_target(image, match.start())) is not None
    ]
    candidates: list[int] = []
    tail = (0x2006, 0x2105, 0x05C9, 0x8108, 0x818A, 0xBC08, 0x4718)
    for callsite, target in calls:
        entry = callsite - 2
        wrapper = entry - 8
        if (wrapper < 0 or entry + 24 > len(image)
                or target not in helpers):
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
        candidates.append(thumb_bl_target(image, callsite))
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


def find_ready_poll_profile(image: bytes) -> dict[str, object] | None:
    """Return one unambiguous firmware-proven ready-poll class."""
    compact = _find_compact_ready_poll_profile(image)
    if compact is not None:
        uart = _find_uart_csr_sr_rx_empty_profile(image, compact)
        if uart is not None:
            compact = uart
    rotated = _find_rotated_ready_poll_profile(image)
    if compact is not None and rotated is not None:
        fields = ("status_address", "mask", "pulse_address")
        if any(compact[field] != rotated[field] for field in fields):
            return None
        if compact["signature"] == "thumb-uart-csr-sr-rx-empty-v1":
            return None
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
