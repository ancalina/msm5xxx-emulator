"""Table-driven row outputs and a four-column multikey scan loop."""
from __future__ import annotations

import re
import struct

from capstone import arm

from msm5xxx_emulator.detection.arm import _thumb_function_start, _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.startup_layouts import layouts
from .startup_copy import reset_linked_input_copy


GRAMMAR = "table-row-halfword-seven-v1"


def _word(image, pc):
    return struct.unpack_from("<H", image, pc)[0] if 0 <= pc <= len(image) - 2 else -1


def _literal(image, pc, register):
    if _word(image, pc) & 0xff00 != 0x4800 | register << 8:
        return None
    return facts_for(image).thumb_literal_value(pc, register)


def _branch(image, pc, condition):
    op = _word(image, pc)
    if op >> 8 != 0xd0 | condition:
        return None
    delta = op & 255
    return pc + 4 + 2 * (delta - 256 if delta & 128 else delta)


def _clear(image, entry, descriptor, preserve, lock, unlock):
    """The same shadow mask and output pointer drive the all-row scan."""
    words = {0: 0xb500, 10: 0x8b8a, 12: 0x401a, 14: 0x838a,
             16: 0x8b8a, 18: 0x6909, 20: 0x800a, 22: 0x2800,
             30: 0xbc08, 32: 0x4718}
    facts = facts_for(image)
    return (all(_word(image, entry + off) == value for off, value in words.items())
            and _literal(image, entry + 6, 1) == descriptor
            and _literal(image, entry + 8, 3) == preserve
            and facts.thumb_call_target(entry + 2) == lock
            and facts.thumb_call_target(entry + 26) == unlock
            and _branch(image, entry + 24, 1) == entry + 30)


def _presence(image, start, end, descriptor, clear):
    facts = facts_for(image)
    found = []
    for pc in range(max(4, start - 0x100), start - 4, 2):
        reg = _word(image, pc) & 7
        if (reg not in (0, 1) or _word(image, pc) != 0x8800 | reg << 3 | reg
                or _word(image, pc + 2) != 0x0700 | reg << 3 | reg
                or _word(image, pc + 4) != 0x0f00 | reg << 3 | reg
                or _word(image, pc + 6) != 0x280f | reg << 8):
            continue
        # One harmless register move may separate the pointer and sense load.
        move = _word(image, pc - 2)
        pointer = pc - (4 if move & 0xffc7 == 0x1c00 else 2)
        op = _word(image, pointer)
        if op & 0xffc7 != 0x6b40 | reg:
            continue
        base = op >> 3 & 7
        dependencies = []
        if pointer == pc - 4 and move != 0x1c00 | base << 3:
            continue
        if _literal(image, pointer - 2, base) != descriptor:
            if base < 4:
                continue
            entry = _thumb_function_start(image, pointer)
            exits = {CodeAddress(pointer)}
            for branch_pc in range(entry, pointer, 2):
                op = _word(image, branch_pc)
                if op & 0xf800 == 0xe000 or op & 0xf000 == 0xd000:
                    exits.update(CodeAddress(target) for target in
                        _thumb_successors(image, branch_pc, len(image))
                        if not entry <= target < pointer)
            region = facts.function_region(CodeAddress(entry),
                stop_before=tuple(sorted(exits, key=lambda address: address.address)), budget=1024)
            value = facts.register_value(region, CodeAddress(pointer), arm.ARM_REG_R0 + base)
            if not region.complete or value is None or value.kind != "const" or value.value != descriptor:
                continue
            dependencies.extend((item.address, facts.decode(item).size)
                                for item in region.instructions)
            dependencies.extend((item.pool, 4) for item in region.literals)
        else:
            literal_pc = pointer - 2
            dependencies.append((((literal_pc + 4) & ~3) +
                                 (_word(image, literal_pc) & 255) * 4, 4))
        if not any(facts.thumb_call_target(call) == clear
                   for call in range(max(0, pointer - 12), pointer, 2)):
            continue
        # A no-key path exits the scan, either directly or through a short hop.
        target = _branch(image, pc + 8, 0)
        if target is None:
            if _branch(image, pc + 8, 1) != pc + 12:
                continue
            branch = _word(image, pc + 10)
            if branch & 0xf800 != 0xe000:
                continue
            delta = branch & 2047
            target = pc + 14 + 2 * (delta - 2048 if delta & 1024 else delta)
        if target < end:
            continue
        found.append((pc, dependencies))
    return found[0] if len(found) == 1 else None


def find_table_row_scanners(image: bytes) -> list[dict]:
    """Close row table, copy layout, pull-up polarity and column/event loops."""
    found = []
    facts = facts_for(image)
    copies = None
    for match in re.finditer(rb"\x00\x88\x00\x07\x00\x0f\x0f\x28", image):
        sense = match.start()
        if sense & 1 or _word(image, sense - 2) != 0x6b40:
            continue
        descriptor = _literal(image, sense - 4, 0)
        if descriptor is None or descriptor & 3:
            continue
        start = sense - 42
        words = {4: 0x8b91, 6: 0x4019, 12: 0x5a9a, 16: 0x439a,
                 18: 0x4311, 22: 0x8391, 24: 0x8b91, 26: 0x6912,
                 28: 0x8011, 30: 0x2800}
        shift = _word(image, start + 10)
        row = shift >> 3 & 7
        if (shift & 0xffc7 != 0x0042 or row not in (5, 6)
                or not all(_word(image, start + off) == value for off, value in words.items())
                or _literal(image, start, 2) != descriptor
                or _literal(image, start + 20, 2) != descriptor
                or _branch(image, start + 32, 1) != sense - 4
                or _word(image, start - 6) != 0x2000 | row << 8):
            continue
        preserve = _literal(image, start + 2, 3)
        table = _literal(image, start + 8, 3)
        if preserve is None or table is None or _literal(image, start + 14, 3) != preserve:
            continue
        mask = preserve ^ 0xffffffff
        if not 0 < mask <= 0xffff or mask.bit_count() != 7:
            continue
        lock = facts.thumb_call_target(start - 4)
        unlock = facts.thumb_call_target(start + 34)
        end = sense + 72
        expected = (0x3001 | row << 8, 0x0600 | row << 3 | row,
                    0x0e00 | row << 3 | row, 0x2807 | row << 8)
        if (tuple(_word(image, end + off) for off in (0, 2, 4, 6)) != expected
                or _branch(image, end + 8, 11) != start - 4
                or any(target is None or target & 1 or not 0 <= target <= len(image) - 2
                       for target in (lock, unlock))):
            continue
        clear = facts.thumb_call_target(end + 10)
        if clear is None or not _clear(image, clear, descriptor, preserve, lock, unlock):
            continue
        presence_result = _presence(image, start, end, descriptor, clear)
        if presence_result is None:
            continue
        presence, presence_dependencies = presence_result
        # Each low column bit indexes event[column * 7 + row]. The stack
        # buffer receives the actual event byte, including multiple contacts.
        decode = sense + 10
        words = {0: 0x0702, 2: 0x0f12, 4: 0x9203, 6: 0x2000,
                 8: 0x2101, 10: 0x9a03, 12: 0x4081, 14: 0x4391,
                 18: 0x00c1, 22: 0x1a09, 26: 0x1889,
                 28: 0x5c0b | row << 6, 42: 0x548b,
                 48: 0x3001, 50: 0x0600, 52: 0x0e00, 54: 0x2804}
        if (not all(_word(image, decode + off) == value for off, value in words.items())
                or _branch(image, decode + 16, 0) != decode + 44
                or _branch(image, decode + 56, 11) != decode + 8
                or _branch(image, sense + 8, 0) != end
                or _word(image, decode + 24) & 0xff00 != 0x3a00):
            continue
        event_end = _literal(image, decode + 20, 2)
        if event_end is None:
            continue
        events_at = event_end - (_word(image, decode + 24) & 255)
        if not 0 <= events_at <= len(image) - 28:
            continue
        events = list(image[events_at:events_at + 28])
        if any(events.count(event) != 1 for event in b"123456789*0#"):
            continue
        if copies is None:
            copies = layouts(image)
        mapped = [copy for copy in copies
                  if copy[2] <= descriptor <= copy[2] + copy[3] - 0x38
                  and copy[2] <= table <= copy[2] + copy[3] - 14]
        if len(mapped) != 1:
            continue
        copy_at, source, target, size, _ = mapped[0]
        descriptor_rom = source + descriptor - target
        rows_rom = source + table - target
        if (not 0 <= descriptor_rom <= len(image) - 0x38
                or not 0 <= rows_rom <= len(image) - 14
                or [struct.unpack_from("<I", image, descriptor_rom + off)[0]
                    for off in (0x10, 0x34)] != [0x03000724, 0x0300072c]):
            continue
        row_values = struct.unpack_from("<7H", image, rows_rom)
        bits = [bit for bit in range(16) if mask & 1 << bit]
        if [mask & ~value for value in row_values] != [1 << bit for bit in bits]:
            continue
        dependencies = [(start - 6, end + 14 - (start - 6)),
                        (presence - 6, 20), (clear, 34), (copy_at, 20),
                        (descriptor_rom, 0x38), (rows_rom, 14), (events_at, 28),
                        (lock, 2), (unlock, 2)]
        dependencies.extend(presence_dependencies)
        for pc in (clear + 6, clear + 8):
            dependencies.append((((pc + 4) & ~3) +
                                 (_word(image, pc) & 255) * 4, 4))
        for pc in range(start, end + 14, 2):
            op = _word(image, pc)
            if op & 0xf800 == 0x4800:
                dependencies.append((((pc + 4) & ~3) + (op & 255) * 4, 4))
        found.append({"grammar": GRAMMAR, "rows": 7, "columns": 4,
            "descriptor": descriptor, "presence_site": presence, "sense_site": sense,
            "sense_address": 0x0300072c,
            "row_loop": start - 4, "event_load_site": decode + 28,
            "row_select_mask": mask, "row_select_bits": bits,
            "no_key": 15, "single_key_column_sense": [14, 13, 11, 7],
            "table": table, "event_table": events_at, "event_codes": events,
            "copy_source": source, "copy_target": target, "copy_size": size,
            "descriptor_source": descriptor_rom, "rows_source": rows_rom,
            "token_cells": [{"token": chr(event), "event": event,
                "row": events.index(event) % 7, "column": events.index(event) // 7}
                for event in b"123456789*0#"], "dependencies": dependencies})
    return found


def table_row_property(image, config, *, status_descriptor_claimed=False):
    if status_descriptor_claimed or getattr(config, "load_address", None) != 0:
        return None, None
    profiles = find_table_row_scanners(image)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    if (not config.ram_base <= profile["descriptor"] <= config.ram_base + config.ram_size - 0x38
            or any(not 0 <= at <= min(len(image), config.flash_size) - size
                   for at, size in profile["dependencies"])):
        return None, None
    copy = reset_linked_input_copy(image,
        ((profile["descriptor"], 0x38), (profile["table"], 14)),
        ram_base=config.ram_base, ram_size=config.ram_size,
        flash_size=config.flash_size)
    if (copy is None or (copy.source, copy.target, copy.size) !=
            (profile["copy_source"], profile["copy_target"], profile["copy_size"])
            or copy.source_address(profile["descriptor"], 0x38) != profile["descriptor_source"]
            or copy.source_address(profile["table"], 14) != profile["rows_source"]):
        return None, None
    profile["dependencies"] = sorted(set(profile["dependencies"]) | set(copy.evidence))
    fields = ("descriptor", "presence_site", "sense_site", "row_select_mask")
    return "matrix-halfword=" + ":".join(f"{profile[key]:x}" for key in fields), profile
