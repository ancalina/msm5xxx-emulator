"""Firmware-proven ready-poll protocol classes."""
from __future__ import annotations

import re
import struct
from bisect import bisect_left, bisect_right
from types import SimpleNamespace

from capstone import CS_GRP_RET
from capstone import arm as a

from ...arm import thumb_bl_target, thumb_literal_value  # Compatibility exports.
from ...facts import CodeAddress, facts_for, source_prefix
from ...contracts import BodySpec


READY_POLL_SITE_LIMIT = 8

_READ_SHIFT = b"\x00\x79\x00\x09"  # LDRB r0,[r0,#4]; LSRS r0,r0,#4
_READ_SHIFT_CONTROL = b"\x09\x79\x09\x09"  # r1 variant with control write
_UART_RX_EMPTY_READ = re.compile(rb"\x00\x79\x40\x08")
_UART_FRAMED_READ = b"\x01\x79\x48\x08"  # LDRB r1,[r0,#4]; LSRS r0,r1,#1
_UART_CLOCK_RX_DRAIN = bytes.fromhex(
    "ff201071302010731020107310732020107310730120107304211173"
)
_LCD_HALFWORD_HELPER = bytes.fromhex("0521c905088188897047")
_THUMB_BL = re.compile(rb".[\xf0-\xf7].[\xf8-\xff]", re.S)
_UART_CLOCK_SETUP_PREFIX = re.compile(
    rb"\x80\xb5" + _THUMB_BL.pattern
    + rb".\x49\x1d\x22\x52\x01\x89\x18\x0a\x89.\x4b\x1a\x40"
      rb"\x0a\x81\x09\x89.\x4a\x11\x82\x00\x28\x01\xd1"
    + _THUMB_BL.pattern + _THUMB_BL.pattern
    + rb".\x49\xc0\x20\x90\x31\x08\x71\xaf\x20\x08\x72"
      rb"\x80\x20\x08\x73.\x49\x19\x20\xa0\x31\x08\x70"
      rb".\x49\x00\x20\x80\x31\x08\x70\x88\x81\x1e\x20\x08\x81"
      rb".\x49\x00\x20\x60\x31\x88\x81", re.S,
)

def _supplied(image: bytes, begin: int, end: int) -> bool:
    return facts_for(image).view.covers(begin, end - begin, phase='reset', bank='primary')


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
    if facts_for(image).thumb_literal_value(read - 2, 0) == status_address - 4:
        return True
    if read < 4:
        return False
    arithmetic = struct.unpack_from("<H", image, read - 2)[0]
    base = facts_for(image).thumb_literal_value(read - 4, 0)
    if base is None or arithmetic & 0xFF00 not in (0x3000, 0x3800):
        return False
    immediate = arithmetic & 0xFF
    derived = base + immediate if arithmetic & 0xFF00 == 0x3000 else base - immediate
    return derived == status_address - 4


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
                or facts_for(image).thumb_literal_value(current + 2, 1)
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
                or facts_for(image).thumb_literal_value(
                    read + 14, words[7] >> 8 & 7
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
            and facts_for(image).thumb_literal_value(data - 2, 0) == status_address - 4
        ]
        if (len(data_reads) != 1
                or not all(helper_entry < callsite < data_reads[0]
                           for callsite in callers)
                or not _supplied(image, helper_entry, max(read + 24, data_reads[0] + 2))):
            continue
        candidates.append(read)
    if len(candidates) != 1:
        return None
    return candidates[0] - compact_entry


def _find_single_uart_csr_sr_rx_empty_profile(
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
    calls = facts_for(image).call_candidates()
    called_entries = {target for _callsite, target in calls}
    candidates: list[int] = []
    for match in _UART_RX_EMPTY_READ.finditer(image, 4):
        read = match.start()
        if read & 1 or read >= len(image) - 6:
            continue
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
                or not _supplied(image, helper_entry, exit_address + (
                    4 if struct.unpack_from('<H', image, exit_address)[0] & 0xFF00 == 0xBC00
                    else 2))
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


def _find_uart_csr_sr_rx_empty_profile(
        image: bytes, compact: dict[str, object]) -> dict[str, object] | None:
    """Upgrade independently proven members while retaining unmatched base loops."""
    entries = compact.get("entries")
    if not isinstance(entries, list) or not entries or any(type(e) is not int for e in entries):
        return None
    if len(entries) == 1:
        return _find_single_uart_csr_sr_rx_empty_profile(image, compact)
    members = []
    upgraded = False
    for entry in entries:
        member = {**compact, "entries": [entry]}
        uart = _find_single_uart_csr_sr_rx_empty_profile(image, member)
        members.append(uart or member)
        upgraded |= uart is not None
    if not upgraded:
        return None
    return {
        "signature": "thumb-byte-ready-pulse-variants-v1",
        "admission": "temporary-evidence-gated",
        **{field: compact[field] for field in ("status_address", "mask", "pulse_address")},
        "variants": members,
    }



__all__ = [name for name in globals() if name.startswith("_") or name in {"thumb_bl_target", "thumb_literal_value"}]
