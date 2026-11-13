"""Evidence for a reset-linked inactive external boot interface."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue
from .observations import _reset_called, _reset_helper_source_spans


def find_boot_presence(image: bytes):
    """Find the existing reset-linked halfword presence interface."""
    facts = facts_for(image)
    for target in _reset_called(image) or ():
        if not target & 1:
            continue
        function = facts.function(CodeAddress(target & ~1), budget=1024)
        if not function.complete or function.unresolved or function.truncated:
            continue
        writes = [use for use in function.accesses if use.operation == 'write'
                  and use.address == 0x09000000 and use.width in (2, 4)
                  and use.predicate == a.ARM_CC_AL]
        halfword_setup = {0xe040, 0x2000} <= {use.value for use in writes if use.width == 2}
        if not halfword_setup and not any(use.width == 4 for use in writes):
            continue
        for read in function.accesses:
            if (read.operation, read.address, read.width) != ('read', 0x09000070, 2):
                continue
            at = read.instruction.address
            code = [facts.decode(CodeAddress(at + offset)) for offset in (0, 2, 4, 6, 8)]
            if any(ins is None or ins.size != 2 for ins in code):
                continue
            read_ins, left, right, compare, branch = code
            register = read_ins.operands[0].reg
            if (left.id != a.ARM_INS_LSL or right.id != a.ARM_INS_LSR
                    or any(len(ins.operands) != 3 or ins.operands[0].reg != register
                           or ins.operands[1].reg != register
                           or ins.operands[2].type != a.ARM_OP_IMM or ins.operands[2].imm != 27
                           for ins in (left, right))
                    or compare.id != a.ARM_INS_CMP or compare.operands[0].reg != register
                    or compare.operands[1].type != a.ARM_OP_IMM or compare.operands[1].imm != 0x1f
                    or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_EQ
                    or branch.operands[0].type != a.ARM_OP_IMM):
                continue
            skip = CodeAddress(branch.operands[0].imm, 'thumb')
            absent = facts.function(skip, budget=32)
            returns = [pc for pc in absent.instructions if _is_return(facts.decode(pc))]
            if not returns:
                scratch_return = _scratch_pop_return(facts, function, absent)
                if scratch_return is not None:
                    returns = [scratch_return]
            if (not absent.complete or absent.unresolved or absent.truncated
                    or absent.calls or absent.accesses or not returns
                    or any(facts.register_value(absent, pc, a.ARM_REG_R0, follow_stack=True)
                           != SymbolicValue.const(0) for pc in returns)):
                continue
            if not any(function.dominates(use.instruction, read.instruction)
                       and (use.width == 4 or halfword_setup and use.value == 0xe040)
                       for use in writes):
                continue
            if halfword_setup and not any(use.value == 0x2000 and use.instruction.address > at for use in writes):
                continue
            first = min(pc.address for pc in (*function.instructions, *absent.instructions))
            end = max(pc.address + facts.decode(pc).size
                      for pc in (*function.instructions, *absent.instructions))
            return {'value': 0x1f, 'read_mask': 0x1f, 'sites': [{
                'at': at, 'branch': at + 8,
                'span': [first, end - first], 'extra_spans': [
                    *[[literal.pool, 4] for literal in (*function.literals, *absent.literals)],
                    *_reset_helper_source_spans(image, target)]}]}
    return None


def _is_return(ins):
    if ins is None:
        return False
    if (ins.id == a.ARM_INS_BX and ins.operands
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == a.ARM_REG_LR):
        return True
    return (ins.id == a.ARM_INS_POP and any(
        operand.type == a.ARM_OP_REG and operand.reg == a.ARM_REG_PC
        for operand in ins.operands))


def _scratch_pop_return(facts, parent, absent):
    """Recognize a zero-return tail that pops saved LR into a scratch reg."""
    instructions = set(absent.instructions)
    if (not absent.complete or absent.unresolved or absent.truncated
            or absent.calls or absent.accesses or not instructions):
        return None
    push = facts.decode(parent.entry)
    if push is None or push.id != a.ARM_INS_PUSH:
        return None
    saved = [operand.reg for operand in push.operands
             if operand.type == a.ARM_OP_REG]
    callee_saved = tuple(range(a.ARM_REG_R4, a.ARM_REG_R11 + 1))
    if (not saved or saved[-1] != a.ARM_REG_LR
            or saved != sorted(saved[:-1]) + [a.ARM_REG_LR]
            or any(reg not in callee_saved for reg in saved[:-1])):
        return None

    def direct_branch(pc):
        ins = facts.decode(pc)
        if (ins is None or ins.id != a.ARM_INS_B or ins.cc != a.ARM_CC_AL
                or len(ins.operands) != 1 or ins.operands[0].type != a.ARM_OP_IMM):
            return None
        return CodeAddress(ins.operands[0].imm, 'thumb',
                           absent.entry.phase, absent.entry.bank)

    zero_pc = direct_branch(absent.entry)
    if zero_pc is None:
        return None
    zero = facts.decode(zero_pc)
    if (zero is None or zero.mnemonic != 'movs' or len(zero.operands) != 2
            or zero.operands[0].type != a.ARM_OP_REG
            or zero.operands[0].reg != a.ARM_REG_R0
            or zero.operands[1].type != a.ARM_OP_IMM
            or zero.operands[1].imm != 0):
        return None
    tail_pc = CodeAddress(zero_pc.address + zero.size, 'thumb',
                          absent.entry.phase, absent.entry.bank)
    epilogue_pc = direct_branch(tail_pc)
    if epilogue_pc is None:
        return None
    first_pop = facts.decode(epilogue_pc)
    if first_pop is None or first_pop.id != a.ARM_INS_POP:
        return None
    popped = [operand.reg for operand in first_pop.operands
              if operand.type == a.ARM_OP_REG]
    if popped != saved[:-1]:
        return None
    scratch_pc = CodeAddress(epilogue_pc.address + first_pop.size, 'thumb',
                             absent.entry.phase, absent.entry.bank)
    scratch_pop = facts.decode(scratch_pc)
    if (scratch_pop is None or scratch_pop.id != a.ARM_INS_POP
            or len(scratch_pop.operands) != 1
            or scratch_pop.operands[0].type != a.ARM_OP_REG):
        return None
    scratch = scratch_pop.operands[0].reg
    if scratch in saved or scratch in (a.ARM_REG_LR, a.ARM_REG_PC, a.ARM_REG_SP):
        return None
    return_pc = CodeAddress(scratch_pc.address + scratch_pop.size, 'thumb',
                            absent.entry.phase, absent.entry.bank)
    bx = facts.decode(return_pc)
    if (bx is None or bx.id != a.ARM_INS_BX or len(bx.operands) != 1
            or bx.operands[0].type != a.ARM_OP_REG
            or bx.operands[0].reg != scratch):
        return None
    if instructions != {absent.entry, zero_pc, tail_pc, epilogue_pc,
                        scratch_pc, return_pc}:
        return None
    expected_epilogue = {epilogue_pc, scratch_pc}
    pushes = []
    for pc in parent.instructions:
        ins = facts.decode(pc)
        if ins.id == a.ARM_INS_PUSH:
            pushes.append(pc)
            if pc != parent.entry:
                return None
        elif ins.id == a.ARM_INS_POP:
            registers = [operand.reg for operand in ins.operands
                         if operand.type == a.ARM_OP_REG]
            if pc in expected_epilogue:
                continue
            if registers != saved[:-1] + [a.ARM_REG_PC]:
                return None
        elif any((operand.type == a.ARM_OP_REG
                  and operand.reg == a.ARM_REG_SP)
                 or (operand.type == a.ARM_OP_MEM
                     and operand.mem.base == a.ARM_REG_SP)
                 for operand in ins.operands):
            return None
    if pushes != [parent.entry]:
        return None
    return return_pc


def _source_span(facts, function, source):
    if not function.instructions:
        return None
    begin = min(pc.address for pc in function.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    spans = [[source + begin - facts.base, end - begin]]
    spans.extend([source + literal.pool - facts.base, 4]
                 for literal in function.literals)
    return {'span': spans[0], 'extra_spans': spans[1:]}


def _reset_linked_functions(facts, reset, *, max_functions=256):
    """Walk reset-linked calls and code targets, allowing a partial reset root."""
    pending = [(reset, (reset,))]
    visited = {reset.entry}
    while pending and len(visited) <= max_functions:
        function, path = pending.pop(0)
        yield function, path
        if (function.entry != reset.entry
                and (not function.complete or function.unresolved or function.truncated)):
            continue
        links = {callee for _, callee in function.calls}
        links.update(function.flow_targets)
        for callee in sorted(links, key=lambda item: (item.address, item.isa)):
            if callee in visited or not facts.view.covers(
                    callee.address, 2 if callee.isa == 'thumb' else 4,
                    phase=callee.phase, bank=callee.bank):
                continue
            visited.add(callee)
            child = facts.function(callee, budget=1024)
            pending.append((child, (*path, child)))


def _dominates_local(function, source, target):
    instructions = set(function.instructions)
    if source not in instructions or target not in instructions or function.truncated:
        return False
    edges = {}
    for start, end in function.control_edges:
        if start in instructions and end in instructions:
            edges.setdefault(start, set()).add(end)

    def reaches(blocked=None):
        pending = [function.entry]
        seen = set()
        while pending:
            current = pending.pop()
            if current == blocked or current in seen:
                continue
            if current == target:
                return True
            seen.add(current)
            pending.extend(edges.get(current, ()))
        return False

    return reaches() and not reaches(source)


def _presence_shape(facts, function, *, require_zero_suffix):
    if not function.instructions or function.truncated:
        return None
    instruction_set = set(function.instructions)
    for access in function.accesses:
        if (access.operation, access.address, access.width) != ('read', 0x48000050, 4):
            continue
        at = access.instruction.address
        sequence = [CodeAddress(at + off, access.instruction.isa,
                                access.instruction.phase, access.instruction.bank)
                    for off in (0, 2, 4, 6, 8)]
        if any(pc not in instruction_set for pc in sequence):
            continue
        load, left, right, compare, branch = [facts.decode(pc) for pc in sequence]
        if any(ins is None or ins.size != 2 for ins in
               (load, left, right, compare, branch)):
            continue
        register = load.operands[0].reg if len(load.operands) == 2 else None
        if (load.id != a.ARM_INS_LDR or register is None
                or left.id != a.ARM_INS_LSL or right.id != a.ARM_INS_LSR
                or any(len(ins.operands) != 3 or ins.operands[0].reg != register
                       or ins.operands[1].reg != register
                       or ins.operands[2].type != a.ARM_OP_IMM
                       or ins.operands[2].imm != 27 for ins in (left, right))
                or compare.id != a.ARM_INS_CMP
                or compare.operands[0].reg != register
                or compare.operands[1].type != a.ARM_OP_IMM
                or compare.operands[1].imm != 31
                or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_EQ
                or not branch.operands or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        target = CodeAddress(branch.operands[0].imm & ~1, 'thumb',
                             function.entry.phase, function.entry.bank)
        absent = facts.function(target, budget=128)
        if require_zero_suffix:
            returns = [pc for pc in absent.instructions
                       if _is_return(facts.decode(pc))]
            if (not absent.complete or absent.unresolved or absent.truncated
                    or not returns or any(
                        facts.register_value(absent, pc, a.ARM_REG_R0,
                                             follow_stack=True) != SymbolicValue.const(0)
                        for pc in returns)):
                continue
        setup = [use for use in function.accesses
                 if use.operation == 'write' and use.width in (2, 4)
                 and 0x48000000 <= use.address < 0x48000050
                 and use.instruction.address < at]
        if not setup or not any(_dominates_local(function, use.instruction,
                                                  access.instruction)
                                for use in setup):
            continue
        return target, absent, at, at + 8
    return None


def find_word_boot_presence(facts, reset, source=0):
    """Prove reset uses the low-five-bit all-ones inactive-interface result."""
    if not reset.instructions:
        return None
    candidates = [(function, path if len(path) > 1 else None)
                  for function, path in _reset_linked_functions(facts, reset)]
    candidates[0] = (reset, None)
    for function, path in candidates:
        linked = path is not None
        if linked and (not function.complete or function.unresolved or function.truncated):
            continue
        shape = _presence_shape(facts, function, require_zero_suffix=linked)
        if shape is None:
            continue
        absent_target, absent, read_at, branch_at = shape
        owners = list(path[:-1]) if path else []
        evidence = [item for item in (
            _source_span(facts, reset, source),
            _source_span(facts, function, source),
            _source_span(facts, absent, source),
            *(_source_span(facts, owner, source) for owner in owners),
        ) if item is not None]
        return {'value': 31, 'read_mask': 31, 'address': 0x48000050,
                'branch_target': absent_target.address,
                'span': evidence[1]['span'],
                'extra_spans': [span for item in evidence
                                for span in (item.get('extra_spans', [])
                                    + [item['span']]) if span != evidence[1]['span']],
                'sites': [{'at': source + read_at - facts.base,
                           'branch': source + branch_at - facts.base}]}
    return None
