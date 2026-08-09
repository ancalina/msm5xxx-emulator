"""Firmware-proven ready-poll protocol classes."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target


_READ_SHIFT = b"\x00\x79\x00\x09"  # LDRB r0,[r0,#4]; LSRS r0,r0,#4
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


def find_ready_poll_profile(image: bytes) -> dict[str, object] | None:
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
