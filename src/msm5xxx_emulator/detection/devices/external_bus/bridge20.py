"""Linked indexed-controller bridge and status-poll evidence."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, source_prefix

_PREFIX_LIMIT = 0x1200000
_OWNER_LIMIT = 0x200


def _span(facts, function):
    start = min(pc.address for pc in function.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {'span': [start, end - start], 'extra_spans': [
        [literal.pool, 4] for literal in function.literals]}


def _owners(facts, site):
    for address in range(max(0, site - _OWNER_LIMIT) & ~1, site, 2):
        instruction = facts.decode(CodeAddress(address, 'thumb'))
        if (instruction is None or instruction.id != a.ARM_INS_PUSH
                or not any(operand.type == a.ARM_OP_REG
                           and operand.reg == a.ARM_REG_LR
                           for operand in instruction.operands)):
            continue
        function = facts.function(CodeAddress(address, 'thumb'), budget=512)
        if (function.complete and not function.unresolved and not function.truncated
                and CodeAddress(site, 'thumb') in function.instructions):
            yield function


def _status_poll(facts, target):
    poll = facts.function(CodeAddress(target.address, target.isa,
                                      target.phase, target.bank), budget=512,
                          initial_registers={a.ARM_REG_R0: 4})
    if not poll.complete or poll.unresolved or poll.truncated:
        return None
    reads = [use for use in poll.accesses if use.operation == 'read'
             and use.address == 0x20000002 and use.width == 2
             and use.predicate == a.ARM_CC_AL]
    if not reads:
        return None
    for read in reads:
        load = facts.decode(read.instruction)
        if load is None or not load.operands or load.operands[0].type != a.ARM_OP_REG:
            continue
        for pc in poll.instructions:
            if not read.instruction.address < pc.address <= read.instruction.address + 4:
                continue
            test = facts.decode(pc)
            if (test is None or test.id not in (a.ARM_INS_TST, a.ARM_INS_AND)
                    or test.id == a.ARM_INS_AND and not test.update_flags
                    or len(test.operands) != 2
                    or {operand.reg for operand in test.operands
                        if operand.type == a.ARM_OP_REG}
                    != {a.ARM_REG_R0, load.operands[0].reg}):
                continue
            if not any(source == branch.address and target <= read.instruction.address
                       for source, target in poll.back_edges
                       for branch in (facts.decode(CodeAddress(source, pc.isa)),)
                       if branch is not None and branch.id == a.ARM_INS_B
                       and branch.cc == a.ARM_CC_NE
                       and branch.address == pc.address + test.size):
                continue
            return poll
    return None


def _indexed_getter(facts, target):
    getter = facts.function(CodeAddress(target.address, target.isa,
                                        target.phase, target.bank), budget=512,
                            initial_registers={a.ARM_REG_R0: 0})
    if not getter.complete or getter.unresolved or getter.truncated:
        return None
    writes = [use for use in getter.accesses if use.operation == 'write'
              and use.address == 0x20000000 and use.width == 2
              and use.predicate == a.ARM_CC_AL]
    reads = [use for use in getter.accesses if use.operation == 'read'
             and use.address == 0x20000004 and use.width == 2
             and use.predicate == a.ARM_CC_AL]
    if not reads or not any(use.value == 1 and use.instruction.address < reads[0].instruction.address
                            for use in writes):
        return None
    if not any(use.instruction.address > reads[-1].instruction.address for use in writes):
        return None
    for call in getter.call_sites:
        if dict(call.registers).get(a.ARM_REG_R0) != 4:
            continue
        poll = _status_poll(facts, call.target)
        if poll is not None:
            return getter, poll
    return None


def _id_check(function, facts, reference):
    literal_registers = {literal.register for literal in function.literals
                         if literal.value == 0x7068}
    if (a.ARM_REG_R3 not in literal_registers
            or reference.instruction not in function.instructions):
        return None
    comparisons = []
    for pc in function.instructions:
        instruction = facts.decode(pc)
        if (instruction is None or instruction.id != a.ARM_INS_CMP
                or len(instruction.operands) != 2
                or instruction.operands[0].type != a.ARM_OP_REG
                or instruction.operands[0].reg != a.ARM_REG_R0
                or instruction.operands[1].type != a.ARM_OP_REG
                or instruction.operands[1].reg != a.ARM_REG_R3):
            continue
        branch = facts.decode(CodeAddress(pc.address + instruction.size, pc.isa,
                                          pc.phase, pc.bank))
        if (branch is not None and branch.id == a.ARM_INS_B
                and branch.cc in (a.ARM_CC_EQ, a.ARM_CC_NE)
                and branch.operands and branch.operands[0].type == a.ARM_OP_IMM):
            comparisons.append((pc.address, branch.address))
    return comparisons[0] if comparisons else None


def find_bridge20(image: bytes):
    """Find code that identifies and polls the indexed 0x7068 controller."""
    prefix = source_prefix(image, _PREFIX_LIMIT)
    if not prefix:
        return None
    facts = facts_for(prefix)
    references = [reference for reference in facts.literal_references(0x7068)
                  if reference.instruction.isa == 'thumb'
                  and reference.instruction.address < _PREFIX_LIMIT]
    calls = facts.call_candidates('thumb')
    for reference in references:
        for owner in _owners(facts, reference.instruction.address):
            check = _id_check(owner, facts, reference)
            if check is None:
                continue
            compare_at, _ = check
            getter_calls = [call for call in owner.call_sites
                            if call.site.address < compare_at
                            and dict(call.registers).get(a.ARM_REG_R0) == 0]
            for call in getter_calls:
                linked = _indexed_getter(facts, call.target)
                if linked is None:
                    continue
                getter, poll = linked
                if not any(target == call.target.address for _, target in calls):
                    continue
                return {'controller_id': 0x7068,
                        'command_port': 0x20000000,
                        'status_port': 0x20000002,
                        'data_port': 0x20000004,
                        'data_aperture': 2,
                        'evidence': [_span(facts, owner), _span(facts, getter),
                                     _span(facts, poll)]}
    return None
