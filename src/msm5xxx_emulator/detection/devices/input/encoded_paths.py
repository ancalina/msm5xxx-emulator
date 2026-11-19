"""Bounded control-flow proofs shared by encoded keypad source rules."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue


def _is(ins, ident, operands=None):
    if ins is None or ins.id != ident:
        return False
    if operands is None:
        return True
    return len(ins.operands) == len(operands) and all(
        got.type == want[0] and (want[1] is None or got.reg == want[1])
        and (want[2] is None or got.imm == want[2])
        and (want[3] is None or got.mem.base == want[3])
        and (want[4] is None or got.mem.disp == want[4])
        for got, want in zip(ins.operands, operands)
    )


def _constant(value):
    if type(value) is int:
        return value
    if getattr(value, "kind", None) == "const":
        return value.value
    return None


def _path_reaches(edges, start, target):
    pending, seen = [start], set()
    while pending:
        pc = pending.pop()
        if pc == target:
            return True
        if pc in seen:
            continue
        seen.add(pc)
        pending.extend(edges.get(pc, ()))
    return False


def _active_low_contact(facts, region, branch, numeric_start: int, key_tokens):
    """Prove the low-contact arm emits a separate event into the dispatcher."""
    low_start = branch.address + branch.size
    edges = {}
    for source, destination in region.control_edges:
        if source.isa == destination.isa == "thumb":
            edges.setdefault(source.address, set()).add(destination.address)
    reachable, pending = set(), [low_start]
    while pending:
        pc = pending.pop()
        if pc in reachable:
            continue
        reachable.add(pc)
        pending.extend(edges.get(pc, ()))
    if numeric_start in reachable:
        return None

    candidates = []
    for pc in sorted(reachable):
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if (ins is None or ins.id != a.ARM_INS_MOV or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[0].reg != a.ARM_REG_R7
                or ins.operands[1].type != a.ARM_OP_IMM):
            continue
        event = ins.operands[1].imm & 0xFF
        next_ins = facts.decode(CodeAddress(pc + ins.size, "thumb"))
        if (event == 0 or event in key_tokens or not _is(next_ins, a.ARM_INS_B)
                or next_ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or not next_ins.operands or next_ins.operands[0].type != a.ARM_OP_IMM):
            continue
        dispatch_entry = next_ins.operands[0].imm
        if dispatch_entry not in reachable:
            continue
        dispatch = facts.function(CodeAddress(dispatch_entry, "thumb"), budget=512,
            initial_registers={a.ARM_REG_R7: SymbolicValue.const(event)})
        if not dispatch.complete or dispatch.truncated or dispatch.unresolved:
            continue
        # The shared state machine reads R7, then forwards this event in R1.
        event_tests = [site for site in dispatch.instructions
            if (lambda test: test is not None and test.id == a.ARM_INS_CMP
                and len(test.operands) == 2 and test.operands[0].type == a.ARM_OP_REG
                and test.operands[0].reg == a.ARM_REG_R7)(facts.decode(site))]
        dispatch_calls = []
        for call in dispatch.call_sites:
            if _constant(dict(call.registers).get(a.ARM_REG_R1)) != event:
                continue
            target = call.target
            thumb = facts.decode(target) if target.isa == "thumb" else None
            arm = facts.decode(CodeAddress(target.address + 4, "arm")) if thumb else None
            if (not _is(thumb, a.ARM_INS_BX,
                        ((a.ARM_OP_REG, a.ARM_REG_PC, None, None, None),))
                    or not _is(arm, a.ARM_INS_LDR,
                        ((a.ARM_OP_REG, a.ARM_REG_PC, None, None, None),
                         (a.ARM_OP_MEM, None, None, a.ARM_REG_PC, -4)))):
                continue
            dispatch_calls.append((call.site.address, target.address))
        if event_tests and len(dispatch_calls) == 1:
            candidates.append({"event": event, "event_site": pc,
                "dispatch_entry": dispatch_entry,
                "dispatch_site": dispatch_calls[0][0],
                "dispatch_stub": dispatch_calls[0][1],
                "dependencies": ((dispatch_calls[0][1], 2),
                    (dispatch_calls[0][1] + 4, 4))})
    return candidates[0] if len(candidates) == 1 else None
