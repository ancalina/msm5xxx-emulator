"""Bounded CFG and argument-flow helpers for input source proofs."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


def bounded_thumb_cfg(image, start, limit, *, max_instructions=768):
    """Decode only a bounded Thumb helper CFG, including conditional arms."""
    facts = facts_for(image)
    pending, seen, edges, instructions = [start], set(), {}, {}
    while pending and len(seen) < max_instructions:
        pc = pending.pop()
        if pc in seen or pc & 1 or not start <= pc < limit:
            continue
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if ins is None:
            return None
        seen.add(pc)
        instructions[pc] = ins
        successors = _thumb_successors(image, pc, limit)
        edges[pc] = set(successors)
        pending.extend(successors)
    return None if pending else (instructions, edges)


def queue_stores_argument(image, entry, config):
    """Close a direct callee's r0 event argument to a byte store."""
    facts = facts_for(image)
    cfg = bounded_thumb_cfg(image, entry, min(len(image), config.flash_size, entry + 0x100))
    if cfg is None:
        return False
    instructions, edges = cfg
    pending = [(entry, frozenset((a.ARM_REG_R0,)))]; seen = set()
    while pending and len(seen) < 1024:
        pc, origins = pending.pop()
        key = (pc, origins)
        if key in seen or pc not in instructions:
            continue
        seen.add(key)
        ins = instructions[pc]
        if (ins.id == a.ARM_INS_STRB and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg in origins
                and ins.operands[1].type == a.ARM_OP_MEM):
            return tuple((address, item.size) for address, item in sorted(instructions.items()))
        new_origins = set(origins)
        if ins.id in (a.ARM_INS_MOV, a.ARM_INS_ADD) and len(ins.operands) >= 2:
            dest = ins.operands[0].reg if ins.operands[0].type == a.ARM_OP_REG else None
            src = ins.operands[1].reg if ins.operands[1].type == a.ARM_OP_REG else None
            preserve = src in origins and (ins.id == a.ARM_INS_MOV
                or (len(ins.operands) == 3 and ins.operands[2].type == a.ARM_OP_IMM
                    and ins.operands[2].imm == 0))
            if dest is not None:
                new_origins.discard(dest)
                if preserve:
                    new_origins.add(dest)
        else:
            try:
                _, written = ins.regs_access()
            except Exception:
                continue
            new_origins.difference_update(written)
        if ins.id == a.ARM_INS_BL:
            new_origins.difference_update((a.ARM_REG_R0, a.ARM_REG_R1,
                                           a.ARM_REG_R2, a.ARM_REG_R3))
        pending.extend((successor, frozenset(new_origins)) for successor in edges.get(pc, ()))
    return False
