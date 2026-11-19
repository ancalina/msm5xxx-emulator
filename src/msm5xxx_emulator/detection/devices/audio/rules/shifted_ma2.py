"""Register/page and byte-FIFO linkage at a shifted pair of bus ports."""
from __future__ import annotations

import re
import struct

from msm5xxx_emulator.detection.facts import facts_for


SOURCE_CLASS = "shifted-paired-port-command-v1"


def _word(image, pc):
    return struct.unpack_from("<H", image, pc)[0] if 0 <= pc <= len(image) - 2 else -1


def _base(image, pc, register):
    move, shift = _word(image, pc), _word(image, pc + 2)
    if (move & 0xff00 != 0x2000 | register << 8 or shift & 0xf83f != register << 3 | register):
        return None
    return (move & 255) << (shift >> 6 & 31)


def _literal(image, pc, register):
    if _word(image, pc) & 0xff00 != 0x4800 | register << 8:
        return None
    return facts_for(image).thumb_literal_value(pc, register)


def _words(image, entry, fields):
    return all(_word(image, entry + offset) == value for offset, value in fields.items())


def find_shifted_ma2(image):
    facts = facts_for(image)
    found = []
    # A returned byte from port +6, with the complete Thumb return sequence.
    anchor = struct.pack("<4H", 0x79b8, 0xbc80, 0xbc08, 0x4718)
    position = 0
    while (read_site := image.find(anchor, position)) >= 0:
        position = read_site + 1
        reader = read_site - 0x10
        pair, block, bank = reader - 0x84, reader - 0x4c, reader + 0x1c
        if reader & 1 or pair < 0 or bank > len(image) - 0x18:
            continue
        if not _words(image, pair, {0: 0xb5b0, 2: 0x1c04, 4: 0x1c0d, 0xa: 0x1c07,
                0xc: 0x0620, 0xe: 0x0e00, 0x16: 0x7048, 0x18: 0x7120,
                0x1e: 0x71a5, 0x20: 0x2f00, 0x22: 0xd101,
                0x2c: 0xbcb0, 0x2e: 0xbc08, 0x30: 0x4718}):
            continue
        if not _words(image, block, {0: 0xb5f0, 2: 0x1c07, 4: 0x1c0c, 6: 0x1c15,
                0xc: 0x1c06, 0x10: 0x7047, 0x16: 0x7107, 0x1c: 0x2700,
                0x1e: 0xe009, 0x20: 0x7820, 0x22: 0x3401, 0x28: 0x7188,
                0x2e: 0x3701, 0x30: 0x043f, 0x32: 0x0c3f, 0x34: 0x42af,
                0x36: 0xdbf3, 0x38: 0x2e00, 0x3a: 0xd101,
                0x40: 0xbcf0, 0x42: 0xbc08, 0x44: 0x4718}):
            continue
        if not _words(image, reader, {0: 0xb580, 8: 0x7048, 0xa: 0x7138}):
            continue
        if not _words(image, bank, {0: 0xb580, 2: 0x07c7, 4: 0x0fff, 6: 0x1c39,
                8: 0x200f, 0x10: 0x7007, 0x12: 0xbc80, 0x14: 0xbc08, 0x16: 0x4718}):
            continue
        base = _base(image, pair + 0x12, 4)
        state = _literal(image, pair + 0x10, 1)
        if (base is None or not 0x02000000 <= base <= 0x02fffff8 or state is None
                or not 0x01000000 <= state <= 0x02000000 - 4
                or any(_base(image, pc, reg) != base for pc, reg in
                       ((block + 0x12, 0), (block + 0x24, 1), (reader + 4, 7)))
                or any(_literal(image, pc, reg) != state for pc, reg in
                       ((block + 0xe, 0), (reader + 2, 1), (bank + 0xe, 0)))
                or facts.thumb_call_target(bank + 0xa) != pair):
            continue
        lock, unlock = facts.thumb_call_target(pair + 6), facts.thumb_call_target(pair + 0x24)
        write_delay, read_delay = facts.thumb_call_target(pair + 0x1a), facts.thumb_call_target(pair + 0x28)
        stream_delay = facts.thumb_call_target(block + 0x2a)
        if (any(target is None or target & 1 or not 0 <= target <= len(image) - 2
                for target in (lock, unlock, write_delay, read_delay, stream_delay))
                or facts.thumb_call_target(block + 8) != lock
                or facts.thumb_call_target(block + 0x3c) != unlock
                or facts.thumb_call_target(block + 0x18) != write_delay
                or facts.thumb_call_target(reader + 0xc) != read_delay
                or any(_word(image, target) != 0x4770 for target in (write_delay, stream_delay))):
            continue
        delay_call = None
        if _word(image, read_delay) != 0x4770:
            delay_call = facts.thumb_call_target(read_delay + 2)
            if (not _words(image, read_delay, {0: 0xb500, 0xa: 0xbc08, 0xc: 0x4718})
                    or delay_call is None or not 0 <= delay_call <= len(image) - 2
                    or facts.thumb_call_target(read_delay + 6) != delay_call):
                continue
        restores = []
        low, high = bank, min(len(image), bank + 0x4000)
        for match in re.finditer(rb"(?=.[\xf0-\xf7].[\xf8-\xff])", image[low:high], re.S):
            call = low + match.start()
            restore = call - 6
            if call & 1 or facts.thumb_call_target(call) != bank:
                continue
            if (not _words(image, restore, {0: 0xb580, 4: 0x78b8, 0xa: 0x78f8,
                    0x10: 0x7078, 0x12: 0x7878, 0x14: 0x7108,
                    0x16: 0xbc80, 0x18: 0xbc08, 0x1a: 0x4718})
                    or _literal(image, restore + 2, 7) != state
                    or _base(image, restore + 0xc, 1) != base):
                continue
            save = restore - 0x10
            if (_literal(image, save, 1) != state or not _words(image, save,
                    {2: 0x7808, 4: 0x7088, 6: 0x7848, 8: 0x70c8, 0xa: 0x4770})):
                continue
            restores.append(restore)
        if len(restores) != 1:
            continue
        restore = restores[0]
        nor = {(pair, 0x32), (block, 0x46), (reader, 0x18), (bank, 0x18),
               (restore - 0x10, 0xc), (restore, 0x1c), *((target, 2) for target in
               (lock, unlock, write_delay, read_delay, stream_delay))}
        if delay_call is not None:
            nor.update(((read_delay, 14), (delay_call, 2)))
        for entry, size in tuple(nor):
            for pc in range(entry, entry + size, 2):
                op = _word(image, pc)
                if op & 0xf800 == 0x4800:
                    nor.add((((pc + 4) & ~3) + (op & 255) * 4, 4))
        found.append({"family": "ma2", "grammar": "ma2-command-v1",
            "source_class": SOURCE_CLASS, "static_status": "accepted", "reject_reason": None,
            "base": base + 4, "data_offset": 2,
            "begin": pair + 0x18, "end": restore + 0x16,
            "register_writer": pair, "fifo_writer": block, "register_reader": reader,
            "page_selector": bank, "index_restore": restore,
            "sites": {"write_0": [pair + 0x18, block + 0x16, reader + 0xa, restore + 0x14],
                      "write_2": [pair + 0x1e, block + 0x28], "read_2": [reader + 0x10]},
            "block_write_offsets": [block + 0x28],
            "nor_dependencies": sorted(nor), "ram_dependencies": [[state, 4]]})
    return found[0] if len(found) == 1 else None
