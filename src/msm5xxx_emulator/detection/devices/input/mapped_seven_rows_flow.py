"""Bounded source control and event-flow checks for seven-row scans."""
from __future__ import annotations

from collections import deque

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .row_execution import _Bits, _irq, _row_outputs


def _branch_target(image, pc):
    ins = facts_for(image).decode(CodeAddress(pc))
    if (ins is None or ins.id != a.ARM_INS_B or len(ins.operands) != 1
            or ins.operands[0].type != a.ARM_OP_IMM):
        return None
    return ins.operands[0].imm


def _row_loop(image, entry, sample, row_register):
    """Require a zeroed counter, its seven bound, and a proved backedge."""
    facts = facts_for(image)
    zero = None
    for pc in range(max(0, entry - 0x80), entry, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is not None and ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == row_register
                and ins.operands[1].type == a.ARM_OP_IMM
                and ins.operands[1].imm == 0):
            zero = pc
    if zero is None:
        return None
    footer = None
    for pc in range(sample + 2, min(sample + 0x180, len(image) - 8), 2):
        increment = facts.decode(CodeAddress(pc))
        if (increment is None or increment.id != a.ARM_INS_ADD
                or not increment.operands
                or increment.operands[0].type != a.ARM_OP_REG
                or increment.operands[0].reg != row_register):
            continue
        amount = increment.operands[-1]
        if amount.type != a.ARM_OP_IMM or amount.imm != 1:
            continue
        for compare_pc in range(pc + increment.size, min(pc + 20, len(image) - 4), 2):
            compare = facts.decode(CodeAddress(compare_pc))
            branch = facts.decode(CodeAddress(compare_pc + 2))
            if (compare is None or compare.id != a.ARM_INS_CMP or len(compare.operands) != 2
                    or compare.operands[0].type != a.ARM_OP_REG
                    or compare.operands[0].reg != row_register
                    or compare.operands[1].type != a.ARM_OP_IMM
                    or compare.operands[1].imm != 7
                    or branch is None or branch.id != a.ARM_INS_B):
                continue
            target = _branch_target(image, compare_pc + 2)
            backedge = None
            if (branch.cc in (a.ARM_CC_LO, a.ARM_CC_LT)
                    and target is not None and target <= entry):
                backedge = (compare_pc + 2, target)
            elif branch.cc in (a.ARM_CC_GE, a.ARM_CC_HS):
                for back in range(compare_pc + branch.size,
                                  min(compare_pc + branch.size + 8, len(image) - 2), 2):
                    back_target = _branch_target(image, back)
                    if back_target is not None and back_target <= entry:
                        backedge = (back, back_target)
                        break
            if backedge is not None:
                footer = (zero, pc, compare_pc, compare_pc + 2, *backedge)
                break
        if footer is not None:
            break
    return footer


def _event_handoff(image, load_pc, register, sink_limit, *,
                   proven_calls=None, proof_sites=None):
    """Follow the loaded event into a source buffer or event call argument."""
    facts = facts_for(image)
    source = facts.decode(CodeAddress(load_pc))
    if (source is None or source.id != a.ARM_INS_LDRB or len(source.operands) != 2
            or source.operands[0].type != a.ARM_OP_REG
            or source.operands[0].reg != register):
        return None
    limit = min(len(image) - 2, load_pc + sink_limit)
    pending = deque([(load_pc + 2, frozenset({a.ARM_REG_SP}))])
    seen = set()
    while pending:
        pc, aliases = pending.popleft()
        state = (pc, aliases)
        if state in seen or not load_pc < pc < limit:
            continue
        seen.add(state)
        ins = facts.decode(CodeAddress(pc))
        if ins is None:
            continue
        if (ins.id == a.ARM_INS_STRB and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == register
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base in aliases):
            return pc
        if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS, a.ARM_INS_ADD)
                and len(ins.operands) in (2, 3)
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == a.ARM_REG_R0
                and ins.operands[1].type == a.ARM_OP_REG
                and ins.operands[1].reg == register
                and (len(ins.operands) == 2 or ins.operands[2].type == a.ARM_OP_IMM
                     and ins.operands[2].imm == 0)):
            call = facts.decode(CodeAddress(pc + ins.size))
            if call is not None and call.id == a.ARM_INS_BL:
                return pc
        try:
            _, written = ins.regs_access()
        except Exception:
            continue
        if register in written:
            continue
        next_aliases = set(aliases)
        if ins.operands and ins.operands[0].type == a.ARM_OP_REG:
            destination = ins.operands[0].reg
            next_aliases.discard(destination)
            if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    and len(ins.operands) == 2
                    and ins.operands[1].type == a.ARM_OP_REG
                    and ins.operands[1].reg in aliases):
                next_aliases.add(destination)
        if ins.id == a.ARM_INS_BX or (ins.id == a.ARM_INS_POP
                and any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC
                        for op in ins.operands)):
            continue
        try:
            _, written = ins.regs_access()
        except Exception:
            continue
        if ins.id not in (a.ARM_INS_BL, a.ARM_INS_B) and a.ARM_REG_PC in written:
            continue
        if ins.id == a.ARM_INS_BL:
            target = facts.thumb_call_target(pc)
            spans = _irq(image, target)
            if spans is not None and register in range(a.ARM_REG_R4, a.ARM_REG_R12):
                if proof_sites is not None:
                    proof_sites.update(spans)
            elif target in (proven_calls or {}):
                if proof_sites is not None:
                    proof_sites.update(proven_calls[target])
            elif (target is None or target & 1 or target >= len(image)
                    or not _callee_preserves_register(image, target, register)):
                continue
            successors = (pc + ins.size,)
        elif ins.id == a.ARM_INS_B:
            successors = _thumb_successors(image, pc, len(image))
        else:
            successors = (pc + ins.size,)
        pending.extend((target, frozenset(next_aliases)) for target in successors)
    return None


def _clear_commit_helper(image, entry, descriptor, descriptor_rom,
                         event_register, event_values, port, row_mask):
    """Prove a clear/commit helper preserves an event across linked IRQ calls."""
    facts = facts_for(image)
    if entry is None or entry & 1 or entry > len(image) - 2:
        return None
    prologue = facts.decode(CodeAddress(entry))
    if (prologue is None or prologue.id != a.ARM_INS_PUSH
            or {op.reg for op in prologue.operands if op.type == a.ARM_OP_REG}
            != {a.ARM_REG_LR}):
        return None
    for pop_pc in range(entry + prologue.size + 2,
                        min(len(image) - 4, entry + 0x100), 2):
        restore = facts.decode(CodeAddress(pop_pc))
        ret = facts.decode(CodeAddress(pop_pc + 2))
        if (restore is None or restore.id != a.ARM_INS_POP or len(restore.operands) != 1
                or restore.operands[0].type != a.ARM_OP_REG
                or ret is None or ret.id != a.ARM_INS_BX
                or len(ret.operands) != 1 or ret.operands[0].type != a.ARM_OP_REG
                or ret.operands[0].reg != restore.operands[0].reg):
            continue
        dependencies = {(entry, prologue.size), (pop_pc, 4)}
        valid = True
        for value in sorted(set(event_values)):
            event = _Bits.constant(value)
            result = _row_outputs(image, entry + prologue.size, pop_pc,
                {event_register: event}, descriptor, descriptor_rom,
                initial_stack={}, preserved_registers={event_register: value})
            if result is None:
                valid = False
                break
            outputs, sites = result
            driven = outputs.get(port)
            if (driven is None or (driven.zero | driven.one) & row_mask != row_mask
                    or (driven.zero & row_mask != row_mask
                        and driven.one & row_mask != row_mask)):
                valid = False
                break
            dependencies.update(sites)
        if valid:
            return dependencies
    return None


def _proven_clear_calls(image, load_pc, sink_limit, descriptor, descriptor_rom,
                        event_register, event_values, port, row_mask):
    facts = facts_for(image)
    calls = {}
    end = min(len(image) - 4, load_pc + sink_limit)
    for pc in range(load_pc + 2, end, 2):
        ins = facts.decode(CodeAddress(pc))
        if ins is None or ins.id != a.ARM_INS_BL:
            continue
        target = facts.thumb_call_target(pc)
        spans = _clear_commit_helper(image, target, descriptor, descriptor_rom,
            event_register, event_values, port, row_mask)
        if spans is not None:
            calls[target] = spans
    return calls


def _callee_preserves_register(image, entry, register):
    """Prove bounded returns preserve a register and restore the entry link."""
    facts = facts_for(image)
    pending = [(entry, 0, frozenset())]  # 0: untouched; 1: one exact frame saved
    visited = set()
    returns = 0
    while pending and len(visited) < 256:
        pc, state, saved = pending.pop()
        if (pc, state, saved) in visited or pc & 1 or not 0 <= pc < len(image) - 1:
            return False
        visited.add((pc, state, saved))
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if ins is None:
            return False
        if ins.id == a.ARM_INS_BL:
            return False
        is_push = ins.id == a.ARM_INS_PUSH
        is_pop = ins.id == a.ARM_INS_POP
        registers = frozenset(op.reg for op in ins.operands
                              if op.type == a.ARM_OP_REG)
        modeled_push = (is_push and state == 0 and register in registers
                        and a.ARM_REG_LR in registers)
        modeled_pop = (is_pop and state == 1 and register in registers
                       and a.ARM_REG_PC in registers
                       and registers == (saved - {a.ARM_REG_LR})
                       | {a.ARM_REG_PC})
        if modeled_push:
            next_state, next_saved = 1, registers
        elif modeled_pop:
            next_state, next_saved = 2, saved
        else:
            next_state, next_saved = state, saved
            try:
                _, written = ins.regs_access()
            except Exception:
                return False
            if register in written or a.ARM_REG_LR in written:
                return False
        # Permit only the exact modeled save and restore to write SP. This
        # also rejects extra PUSH/POP and indirect writes such as LDM to SP.
        try:
            _, written = ins.regs_access()
        except Exception:
            return False
        if a.ARM_REG_SP in written and not (modeled_push or modeled_pop):
            return False
        if state == 1 and not is_pop:
            # No store may alias the saved event/link slots through a copied
            # SP value or another base register, so do not permit stores here.
            if ins.mnemonic.startswith(("str", "stm", "push", "swp")):
                return False
        is_return = (ins.id == a.ARM_INS_BX and ins.operands
                     and ins.operands[0].type == a.ARM_OP_REG
                     and ins.operands[0].reg == a.ARM_REG_LR)
        is_return |= is_pop and a.ARM_REG_PC in registers
        if is_return:
            if (is_pop and next_state != 2
                    or ins.id == a.ARM_INS_BX and next_state != 0):
                return False
            returns += 1
            continue
        if ins.id == a.ARM_INS_BX or (is_pop and any(
                op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC
                for op in ins.operands)):
            return False
        successors = _thumb_successors(image, pc, len(image))
        if not successors:
            return False
        if any(target <= pc for target in successors):
            return False
        pending.extend((target, next_state, next_saved) for target in successors)
    return not pending and returns > 0


def _scan_control_flow(image, start, limit, dispatch, arms):
    """Build a bounded CFG, expanding the row switch at its proved table."""
    facts = facts_for(image)
    successors = {}
    pending = [start]
    while pending:
        pc = pending.pop()
        if pc in successors or pc < start or pc >= limit or pc & 1:
            continue
        ins = facts.decode(CodeAddress(pc))
        if ins is None:
            continue
        if pc == dispatch + 6 and arms:
            targets = arms
        elif ins.id == a.ARM_INS_BL:
            targets = (pc + ins.size,)
        elif ins.id == a.ARM_INS_B:
            targets = _thumb_successors(image, pc, len(image))
        elif ins.id == a.ARM_INS_BX or (ins.id == a.ARM_INS_POP
                and any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC
                        for op in ins.operands)):
            targets = ()
        else:
            try:
                _, written = ins.regs_access()
            except Exception:
                targets = ()
            else:
                targets = () if a.ARM_REG_PC in written else (pc + ins.size,)
        edges = tuple(target for target in targets if start <= target < limit and target % 2 == 0)
        successors[pc] = edges
        pending.extend(edges)
        if len(successors) > 4096:
            return None
    if start not in successors:
        return None
    reachable = set()
    todo = [start]
    while todo:
        pc = todo.pop()
        if pc in reachable:
            continue
        reachable.add(pc)
        todo.extend(successors.get(pc, ()))
    predecessors = {pc: set() for pc in reachable}
    for pc in reachable:
        for target in successors.get(pc, ()):
            if target in predecessors:
                predecessors[target].add(pc)
    dominators = {pc: set(reachable) for pc in reachable}
    dominators[start] = {start}
    changed = True
    while changed:
        changed = False
        for pc in reachable - {start}:
            parents = predecessors[pc]
            common = set.intersection(*(dominators[parent] for parent in parents)) if parents else set()
            value = {pc} | common
            if value != dominators[pc]:
                dominators[pc] = value
                changed = True
    return successors, reachable, dominators


def _path_exists(edges, start, target):
    pending = [start]
    seen = set()
    while pending:
        pc = pending.pop()
        if pc == target:
            return True
        if pc in seen:
            continue
        seen.add(pc)
        pending.extend(edges.get(pc, ()))
    return False
