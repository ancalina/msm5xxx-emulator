"""Candidate vector relocation table extraction."""
from __future__ import annotations

import struct

from capstone import arm as a

from .arm import arm_b_word_target
from .facts import CodeAddress, FirmwareFacts
from .startup_models import VectorCopyRow

def vector_copy_rows(facts: FirmwareFacts, ram_base: int, ram_size: int
                     ) -> tuple[VectorCopyRow, ...]:
    """Find candidate four-word rows referenced by ARM vector 0x18.

    These rows describe a possible relocation; the query does not claim the
    reset path executes a copy.
    """
    if (type(ram_base) is not int or type(ram_size) is not int
            or ram_base < 0 or ram_size <= 0
            or ram_base + ram_size > 0x100000000):
        return ()
    vector_targets = {target.address for site, target in facts.vectors()
                      if site.address == 0x18 and site.isa == 'arm'}
    candidates = []
    for target in vector_targets:
        if not ram_base <= target < ram_base + ram_size:
            continue
        for pointer_site in facts.pointer_candidates(target):
            table = pointer_site - 4
            if table < 0 or table & 3:
                continue
            raw = facts.view.read(table, 16, phase='reset', bank='primary')
            if raw is None:
                continue
            source, table_target, size, end = struct.unpack('<4I', raw)
            if (table_target != target or not 0x100 <= size <= 0x200000
                    or end != target + size or end > 0x100000000
                    or source <= table + 0x20 or source + size > len(facts.image)
                    or not ram_base <= target <= end <= ram_base + ram_size):
                continue
            instruction = facts.decode(CodeAddress(source, 'arm'))
            if (instruction is None or instruction.id != a.ARM_INS_B
                    or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                continue
            source_word = facts.view.read(source, 4,
                                          phase='reset', bank='primary')
            if source_word is None:
                continue
            word = struct.unpack('<I', source_word)[0]
            wrapper = arm_b_word_target(word, target)
            if wrapper is None or not 0 <= wrapper < len(facts.image):
                continue
            candidates.append(VectorCopyRow(table, source, target, size, end,
                                            wrapper))
    return tuple(dict.fromkeys(candidates))

