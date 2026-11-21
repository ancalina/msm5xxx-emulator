"""Halfword selector/data helpers for an external register bank."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue

REQUIRES = {'indexed44_writer': ('display.indexed44_writer', None)}

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


def _increment_clear_counts(facts, body, data_port):
    """Prove a solid clear with two zero-based, incrementing bound loops."""

    loops = []
    for source, target in body.back_edges:
        branch = facts.decode(CodeAddress(source))
        compare = facts.decode(CodeAddress(source - 2))
        increment = facts.decode(CodeAddress(source - 4))
        initial = facts.decode(CodeAddress(target - 2))
        if (any(ins is None for ins in (branch, compare, increment, initial))
                or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_LO
                or compare.id != a.ARM_INS_CMP or len(compare.operands) != 2
                or compare.operands[0].type != a.ARM_OP_REG
                or compare.operands[1].type != a.ARM_OP_IMM
                or not 1 < compare.operands[1].imm <= 256):
            continue
        register = compare.operands[0].reg
        if (increment.id != a.ARM_INS_ADD or len(increment.operands) != 2
                or increment.operands[0].reg != register
                or increment.operands[1].type != a.ARM_OP_IMM
                or increment.operands[1].imm != 1
                or initial.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                or len(initial.operands) != 2
                or initial.operands[0].reg != register
                or initial.operands[1].type != a.ARM_OP_IMM
                or initial.operands[1].imm != 0):
            continue
        # Only the final increment may change this loop's counter.
        if any(register in facts.decode(pc).regs_access()[1]
               for pc in body.instructions
               if target <= pc.address < source - 4):
            continue
        loops.append((target, source, compare.operands[1].imm))
    for store in indexed44_writer._writes(body, data_port):
        if store.value != 0xffff:
            continue
        for inner in loops:
            for outer in loops:
                if (outer[0] < inner[0] <= store.instruction.address
                        < inner[1] < outer[1]):
                    return inner[2], outer[2]
    return None



def _indexed44_update_request(facts, calls, command, data):
    """Prove poll-bit8-then-OR-bit8 command0A semantics in a called leaf."""
    import struct

    targets = {target for _, target in calls}
    candidates = set()
    for register in range(8):
        for site in facts.string_candidates(struct.pack('<H', 0x200a | register << 8)):
            if site - 4 in targets:
                candidates.add(site - 4)
    request = SymbolicValue('op', 'or', (SymbolicValue.arg(0), SymbolicValue.const(0x100)))
    matched = []
    for target in sorted(candidates):
        body = facts.function(CodeAddress(target), budget=32,
            symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
        uses = body.symbolic_accesses
        if (not indexed44_writer._body_ok(body) or body.calls or len(uses) != 4
                or any(use.width != 2 or use.predicate != a.ARM_CC_AL for use in uses)):
            continue
        first, poll, second, write = uses
        if (tuple(use.operation for use in uses) != ('write', 'read', 'write', 'write')
                or first.address != SymbolicValue.const(command)
                or second.address != first.address
                or first.value != SymbolicValue.const(0x0a)
                or second.value != first.value
                or poll.address != SymbolicValue.const(data)
                or write.address != poll.address or write.value != request):
            continue
        load = facts.decode(poll.instruction)
        shift = facts.decode(CodeAddress(poll.instruction.address + 2))
        branch = facts.decode(CodeAddress(poll.instruction.address + 4))
        if (load.id != a.ARM_INS_LDRH or shift is None or branch is None
                or shift.id != a.ARM_INS_LSL or len(shift.operands) != 3
                or shift.operands[0].reg != load.operands[0].reg
                or shift.operands[1].reg != load.operands[0].reg
                or shift.operands[2].type != a.ARM_OP_IMM
                or shift.operands[2].imm != 23
                or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_MI
                or body.back_edges != ((branch.address, first.instruction.address),)):
            continue
        matched.append(body)
    return tuple(matched)


def find_indexed44_incrementing(image: bytes):
    """Admit an indexed panel from its counted clear and RAM pixel writer.

    This complements the decrementing-loop/132-stride source recognizer;
    the geometry and row stride are obtained from these source instructions.
    """

    facts = facts_for(image)

    def detect():
        calls, windows = indexed44_writer._window_candidates(facts)
        profiles = []
        for target, (window, command, data, x, y) in windows.items():
            if (command, data) != (0x18000000, 0x18000010):
                continue
            update = _indexed44_update_request(facts, calls, command, data)
            if not update:
                continue
            owners = {}
            for site, called in calls:
                if called == target:
                    for body in indexed44_writer._owners(facts, site):
                        owners[body.entry.address] = body
            for clear in owners.values():
                counts = _increment_clear_counts(facts, clear, data)
                commands = indexed44_writer._writes(clear, command)
                if (counts is None
                        or not indexed44_writer._has_cursor_stream(tuple(use.value for use in commands))
                        or not any(use.value == x | (y << 8)
                                   for use in indexed44_writer._writes(clear, data))):
                    continue
                width, height = counts
                if x + width > 256 or y + height > 256:
                    continue
                clear_calls = [call for call in clear.call_sites
                               if call.target.address == target
                               and tuple(dict(call.registers).get(reg) for reg in (
                                   a.ARM_REG_R0, a.ARM_REG_R1,
                                   a.ARM_REG_R2, a.ARM_REG_R3))
                               == (0, width - 1, 0, height - 1)]
                if not clear_calls:
                    continue
                for blitter in owners.values():
                    if not indexed44_writer._has_cursor_stream(tuple(
                            use.value for use in indexed44_writer._writes(blitter, command))):
                        continue
                    code = [(pc, facts.decode(pc)) for pc in blitter.instructions]
                    if not any(ins.id == a.ARM_INS_ADD
                               and len(ins.operands) == 2
                               and ins.operands[1].type == a.ARM_OP_IMM
                               and ins.operands[1].imm == width * 2
                               for _, ins in code):
                        continue
                    loads = [pc for pc, ins in code if ins.id == a.ARM_INS_LDRH]
                    if not any(indexed44_writer._pixel_store_consumes(blitter, facts, pc, command, data)
                               for pc in loads):
                        continue
                    profiles.append({
                        'protocol': 'indexed44-rgb565',
                        'width': width, 'height': height,
                        'x_origin': x, 'y_origin': y,
                        'command_port': command, 'data_port': data,
                        'update_register': 0x0a, 'update_busy_mask': 0x100,
                        'evidence': [indexed44_writer._span(facts, body)
                                     for body in (window, clear, blitter, *update)],
                    })
                    break
        keys = {(p['width'], p['height'], p['x_origin'], p['y_origin'])
                for p in profiles}
        return profiles[0] if len(keys) == 1 else None

    return facts.memo('indexed44-incrementing-writer', (), detect)
