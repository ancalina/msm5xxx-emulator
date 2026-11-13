"""Halfword selector/data helpers for an external register bank."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue

PORTS = (0x18080000, 0x180C0000)


def find_indexed_18(image: bytes):
    facts = facts_for(image)
    candidates = facts.literal_access_candidates(((PORTS[0], PORTS[0] + 2),), limit=0x10000)
    helpers = {"read": [], "write": []}
    for candidate in candidates:
        if candidate.load.isa != "thumb" or candidate.operation != "write" or candidate.width != 2:
            continue
        entry = candidate.load
        function = facts.function(entry, budget=16, symbolic_registers={
            a.ARM_REG_R0: SymbolicValue.arg(0),
            a.ARM_REG_R1: SymbolicValue.arg(1),
        })
        if (not function.complete or function.unresolved or function.truncated
                or function.calls or len(function.instructions) != 5):
            continue
        code = [facts.decode(pc) for pc in function.instructions]
        if (any(ins is None or ins.size != 2 for ins in code)
                or [pc.address for pc in function.instructions] != list(range(entry.address, entry.address + 10, 2))
                or code[-1].id != a.ARM_INS_BX
                or code[-1].operands[0].reg != a.ARM_REG_LR):
            continue
        uses = [use for use in function.symbolic_accesses
                if use.instruction not in {literal.instruction for literal in function.literals}]
        if len(uses) != 2:
            continue
        selector, data = uses
        if (selector.operation != "write" or selector.width != 2
                or selector.address != SymbolicValue.const(PORTS[0])
                or selector.value != SymbolicValue.arg(0)
                or data.width != 2 or data.address != SymbolicValue.const(PORTS[1])):
            continue
        if data.operation == "write" and data.value != SymbolicValue.arg(1):
            continue
        if data.operation == "read" and (code[3].id != a.ARM_INS_LDRH
                or code[3].operands[0].reg != a.ARM_REG_R0):
            continue
        helpers[data.operation].append(function)
    if not helpers["read"] or not helpers["write"]:
        return None
    # A shared caller must use both operations on the same constant selector.
    # The helpers alone could otherwise be unused data or unrelated routines.
    calls = facts.call_candidates("thumb")
    for reader in helpers["read"]:
        for writer in helpers["write"]:
            for call, target in calls:
                if target != reader.entry.address:
                    continue
                for owner in range(call - 2, max(-1, call - 0x200), -2):
                    ins = facts.decode(CodeAddress(owner, "thumb"))
                    if (ins is None or ins.id != a.ARM_INS_PUSH
                            or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR for op in ins.operands)):
                        continue
                    function = facts.function(CodeAddress(owner, "thumb"), budget=256)
                    if not function.complete or function.unresolved or function.truncated:
                        break
                    reads = [c for c in function.call_sites if c.target == reader.entry]
                    writes = [c for c in function.call_sites if c.target == writer.entry]
                    linked = any(type(dict(r.registers).get(a.ARM_REG_R0)) is int
                                 and 0 <= dict(r.registers)[a.ARM_REG_R0] <= 0xffff
                                 and dict(r.registers)[a.ARM_REG_R0] == dict(w.registers).get(a.ARM_REG_R0)
                                 and r.site.address < w.site.address
                                 and function.linear_path(r.site, w.site, allowed_calls=(r.site,)) is not None
                                 for r in reads for w in writes)
                    if linked:
                        evidence = []
                        for body in (reader, writer, function):
                            first = min(pc.address for pc in body.instructions)
                            end = max(pc.address + facts.decode(pc).size for pc in body.instructions)
                            evidence.append({"span": [first, end - first],
                                             "extra_spans": [[literal.pool, 4] for literal in body.literals]})
                        return {"evidence": evidence}
                    break
    return None
