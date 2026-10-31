"""Source-closed copied x16 NAND class: 512-byte pages, 32 pages, 1024 blocks."""
from __future__ import annotations

import hashlib
import struct

from .arm import thumb_bl_target
from .middle_nand_contracts import CONTRACTS


def _middle_reset(image: bytes, at: int, end: int) -> bool:
    # Decode the command producer operands; no firmware body is embedded.
    if at & 1 or at + 10 > end:
        return False
    mov_value, mov_base, shift, store, ret = struct.unpack_from('<5H', image, at)
    return (mov_value >> 11 == 4 and (mov_value >> 8) & 7 == 0
            and mov_value & 255 == 255
            and mov_base >> 11 == 4 and (mov_base >> 8) & 7 == 1
            and mov_base & 255 == 13
            and shift >> 11 == 0 and (shift >> 6) & 31 == 21
            and (shift >> 3) & 7 == 1 and shift & 7 == 1
            and store >> 11 == 14 and (store >> 6) & 31 == 0
            and (store >> 3) & 7 == 1 and store & 7 == 0
            and ret >> 7 == 0x8E and (ret >> 3) & 15 == 14 and ret & 7 == 0)


_IRAM = 0x03800000


def _match(image, reset, owner, contract):
    functions, targets, pointer_offset, ready_address, ready_mask = contract
    source, end = owner
    descriptor = None
    intervals = []
    for role, (relative, size, digest, calls, literals, adr) in functions.items():
        entry = reset + relative
        if entry & 1 or not source <= entry < entry + size <= end:
            return None
        code = bytearray(image[entry:entry + size])
        for offset, callee in calls:
            target = thumb_bl_target(image, entry + offset)
            if (target != reset + targets[callee]
                    or not source <= target < end - 1):
                return None
            struct.pack_into('<HH', code, offset, 0xF000, 0xF800)
        for offset, register, literal_role in literals:
            instruction = struct.unpack_from('<H', code, offset)[0]
            if instruction & 0xF800 != 0x4800 or (instruction >> 8) & 7 != register:
                return None
            pool = ((entry + offset + 4) & ~3) + (instruction & 255) * 4
            if not source <= pool <= end - 4:
                return None
            value = struct.unpack_from('<I', image, pool)[0]
            if literal_role == 'watchdog_pulse':
                if value != 0x03001080:
                    return None
            elif literal_role == 'status_retry_bound_20000':
                if value != 20000:
                    return None
            elif literal_role == 'ready_descriptor':
                if (value & 3 or descriptor is not None and descriptor != value
                        or not _IRAM <= value < value + pointer_offset + 4 <= _IRAM + end - source):
                    return None
                descriptor = value
            else:
                return None
            struct.pack_into('<H', code, offset, instruction & 0xFF00)
            intervals.append((pool, pool + 4))
        for offset in adr:
            instruction = struct.unpack_from('<H', code, offset)[0]
            target = ((entry + offset + 4) & ~3) + (instruction & 255) * 4
            if instruction & 0xF800 != 0xA000 or not source <= target < end:
                return None
        if hashlib.sha256(code).hexdigest() != digest:
            return None
        intervals.append((entry, entry + size))
    if descriptor is None:
        return None
    gpio_pointer = source + descriptor - _IRAM + pointer_offset
    if struct.unpack_from('<I', image, gpio_pointer)[0] != ready_address:
        return None
    return {
        'signature': 'copied-middle-x16-small-page-v1',
        'data': 0x01800000, 'address': 0x01900000, 'command': 0x01A00000,
        'data_size': 0x1000000, 'page_size': 512, 'pages_per_block': 32,
        'bus_width': 2, 'ready_address': ready_address, 'ready_mask': ready_mask,
        'ready_width': 2, 'source_interval': (source, end),
        'copy_target': _IRAM, 'reset': reset,
        'code_intervals': tuple(sorted(intervals)),
        'semantic_limit': 'main-area protocol; original NAND contents and OOB are not supplied',
    }


def find_middle_nand_profile(image: bytes) -> dict | None:
    """Require one copied producer graph and its source-owned GPIO descriptor.

    Erase-sweep and split-transfer contracts independently close 16 MiB,
    32-page erase blocks, 512-byte pages and halfword payloads. Relocation
    fields are decoded and checked before instruction-hash normalization.
    """
    if not isinstance(image, bytes) or not 0x7F0000 <= len(image) <= 0x800000:
        return None
    witnesses = []
    for table in range(0, min(0x10000, len(image) - 12), 4):
        source, target, size = struct.unpack_from('<III', image, table)
        if (source != table + 12 or target != _IRAM
                or not 0x1000 <= size <= 0x20000
                or source + size > len(image)):
            continue
        owner = (source, source + size)
        at = source
        while (at := image.find(struct.pack('<H', 0x20FF), at, owner[1])) >= 0:
            if _middle_reset(image, at, owner[1]):
                for contract in CONTRACTS:
                    profile = _match(image, at, owner, contract)
                    if profile is not None and _reset_copies_table(image, table):
                        profile['copy_table'] = table
                        witnesses.append(profile)
            at += 2
    return witnesses[0] if len(witnesses) == 1 else None


def _reset_copies_table(image: bytes, table: int) -> bool:
    """Close the reset-vector -> ARM gate -> Thumb copier -> table chain."""
    from .middle_nand_bootstrap_contracts import BOOTSTRAPS

    def branch(instruction, address):
        displacement = instruction & 0xFFFFFF
        if displacement & 0x800000:
            displacement -= 0x1000000
        return address + 8 + displacement * 4

    vector = struct.unpack_from('<I', image)[0]
    if vector & 0xFF000000 != 0xEA000000:
        return False
    root = branch(vector, 0)
    for table_relative, functions in BOOTSTRAPS:
        if root + table_relative != table:
            continue
        valid = True
        for role, (relative, size, digest, literals, branches) in functions.items():
            entry = root + relative
            if not 0 <= entry <= len(image) - size:
                valid = False
                break
            code = bytearray(image[entry:entry + size])
            for offset, register, kind, value in literals:
                if role == 'copier':
                    instruction = struct.unpack_from('<H', code, offset)[0]
                    if instruction & 0xF800 != 0x4800 or (instruction >> 8) & 7 != register:
                        valid = False
                        break
                    pool = ((entry + offset + 4) & ~3) + (instruction & 255) * 4
                    struct.pack_into('<H', code, offset, instruction & 0xFF00)
                else:
                    instruction = struct.unpack_from('<I', code, offset)[0]
                    if (instruction & 0x0F7F0000 != 0x051F0000
                            or (instruction >> 12) & 15 != register):
                        valid = False
                        break
                    displacement = instruction & 0xFFF
                    pool = entry + offset + 8 + (displacement if instruction & 0x800000 else -displacement)
                    struct.pack_into('<I', code, offset, instruction & ~0xFFF)
                expected = value + (root if kind == 'root' else table if kind == 'table' else 0)
                if not 0 <= pool <= len(image) - 4 or struct.unpack_from('<I', image, pool)[0] != expected:
                    valid = False
                    break
            if not valid:
                break
            for offset, target, condition, link in branches:
                instruction = struct.unpack_from('<I', code, offset)[0]
                if (instruction & 0x0E000000 != 0x0A000000
                        or instruction >> 28 != condition
                        or bool(instruction & 0x1000000) != link
                        or branch(instruction, entry + offset) != root + target):
                    valid = False
                    break
                struct.pack_into('<I', code, offset, instruction & 0xFF000000)
            if not valid or hashlib.sha256(code).hexdigest() != digest:
                valid = False
                break
        if valid:
            return True
    return False
