"""Source CFG proof for halfword-offset computed row dispatch."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .source_flow import closed_input_region


def _reg(op):
    return op.reg if op.type == a.ARM_OP_REG else None


def _imm(op):
    return op.imm if op.type == a.ARM_OP_IMM else None


def _jump_switch(image: bytes, sample: int, *, rows: int = 6,
                 terminal_sites=()):
    """Resolve the unique bounded switch whose counter is initialized on all paths."""
    facts = facts_for(image)
    found = []
    lo = max(0, sample - 0x500)
    for pc in range(lo, sample, 2):
        dispatch = facts.decode(CodeAddress(pc))
        if (dispatch is None or dispatch.id != a.ARM_INS_ADD
                or len(dispatch.operands) not in (2, 3)
                or _reg(dispatch.operands[0]) != a.ARM_REG_PC):
            continue
        offset_reg = _reg(dispatch.operands[-1])
        if offset_reg is None:
            continue
        scale = facts.decode(CodeAddress(pc - 2))
        load = facts.decode(CodeAddress(pc - 4))
        add_index = facts.decode(CodeAddress(pc - 6))
        adr = facts.decode(CodeAddress(pc - 8))
        if (scale is None or scale.id != a.ARM_INS_ADD
                or len(scale.operands) != 3
                or _reg(scale.operands[0]) != offset_reg
                or _reg(scale.operands[1]) != offset_reg
                or _reg(scale.operands[2]) != offset_reg
                or load is None or load.id != a.ARM_INS_LDRH
                or len(load.operands) != 2
                or _reg(load.operands[0]) != offset_reg
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.base != offset_reg
                or load.operands[1].mem.index == 0
                or add_index is None or add_index.id != a.ARM_INS_ADD
                or len(add_index.operands) != 3
                or _reg(add_index.operands[0]) != offset_reg
                or _reg(add_index.operands[1]) != offset_reg
                or _reg(add_index.operands[2]) != load.operands[1].mem.index
                or adr is None or adr.id != a.ARM_INS_ADR
                or len(adr.operands) != 2
                or _reg(adr.operands[0]) != offset_reg
                or add_index.operands[2].reg != load.operands[1].mem.index):
            continue
        row_reg = load.operands[1].mem.index
        table_base = ((pc - 8 + 4) & ~3) + adr.operands[1].imm
        table = table_base + load.operands[1].mem.disp
        if table & 1 or not 0 <= table <= len(image) - 2 * rows:
            continue
        entries = tuple(int.from_bytes(image[table + 2*i:table + 2*i + 2], "little")
                        for i in range(rows))
        arms = tuple(pc + 4 + 2 * value for value in entries)
        if len(set(arms)) != rows or any(not pc < arm < sample or arm & 1 for arm in arms):
            continue
        if table + 2 * rows > min(arms):
            continue
        branch_pc = pc - 10
        branch = facts.decode(CodeAddress(branch_pc))
        compare_pc = branch_pc - 2
        compare = facts.decode(CodeAddress(compare_pc))
        init_pc = branch_pc - 4
        init = facts.decode(CodeAddress(init_pc))
        if (branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_HS
                or compare is None or compare.id != a.ARM_INS_CMP
                or len(compare.operands) != 2
                or _reg(compare.operands[0]) != row_reg
                or _imm(compare.operands[1]) != rows
                or init is None or init.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                or len(init.operands) != 2 or _reg(init.operands[0]) != row_reg
                or _imm(init.operands[1]) != 0):
            continue
        target = _imm(branch.operands[0]) if branch.operands else None
        if target is None or target in arms or not pc < target < sample:
            continue

        # Cut the proven dispatch and common sample from the function. This
        # preserves full CFG coverage of the initializer and guard prefix.
        entry = _thumb_function_start(image, pc)
        if entry is None or entry >= pc:
            continue
        push = facts.decode(CodeAddress(entry))
        if (push is None or push.id != a.ARM_INS_PUSH
                or push.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
            continue
        try:
            probe = facts.function_region(CodeAddress(entry),
                stop_before=(CodeAddress(pc), CodeAddress(sample)), budget=1024)
        except (ValueError, RuntimeError):
            continue
        returns = []
        for site in probe.scope_escapes:
            ins = facts.decode(site)
            if (ins is None or ins.id != a.ARM_INS_BX
                    or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                returns = []
                break
            returns.append(site)
        if probe.scope_escapes and not returns:
            continue
        try:
            terminal_sites = tuple(terminal_sites)
        except TypeError:
            continue
        terminal_addresses = []
        successors = {}
        for source, destination in probe.control_edges:
            successors.setdefault(source, set()).add(destination)
        for value in terminal_sites:
            if (type(value) is not int or value & 1 or value <= sample
                    or value in (pc, init_pc, compare_pc, branch_pc, *arms)):
                terminal_addresses = []
                break
            endpoint = CodeAddress(value)
            if endpoint not in probe.instructions:
                terminal_addresses = []
                break
            incoming = [(source, facts.decode(source))
                        for source, destination in probe.control_edges
                        if destination == endpoint]
            if not any(source.address < pc and ins is not None
                       and ins.id == a.ARM_INS_B for source, ins in incoming):
                terminal_addresses = []
                break
            pending_sites, seen_sites = [endpoint], set()
            reaches_scan = False
            while pending_sites:
                current = pending_sites.pop()
                if current in seen_sites:
                    continue
                seen_sites.add(current)
                if current in (CodeAddress(pc), CodeAddress(sample),
                        CodeAddress(init_pc), CodeAddress(compare_pc),
                        CodeAddress(branch_pc)) or current in {
                            CodeAddress(arm) for arm in arms}:
                    reaches_scan = True
                    break
                pending_sites.extend(successors.get(current, ()))
            if reaches_scan:
                terminal_addresses = []
                break
            terminal_addresses.append(endpoint)
        if terminal_sites and not terminal_addresses:
            continue
        endpoints = (CodeAddress(pc), CodeAddress(sample),
                     *terminal_addresses, *returns)
        prefix = closed_input_region(image if isinstance(image, bytes)
            else bytes(image), entry,
            tuple(endpoint.address for endpoint in endpoints), budget=1024)
        if prefix is None:
            continue
        if (not prefix.complete or prefix.unresolved or prefix.truncated
                or prefix.scope_escapes or any(target not in set(prefix.instructions)
                    for _, target in prefix.control_edges)):
            continue
        if (not prefix.complete or prefix.unresolved or prefix.truncated
                or prefix.entry != CodeAddress(entry)
                or CodeAddress(pc) not in prefix.instructions
                or CodeAddress(init_pc) not in prefix.instructions
                or CodeAddress(compare_pc) not in prefix.instructions
                or CodeAddress(branch_pc) not in prefix.instructions):
            continue
        # The source ISA here is Thumb-1. We do not infer IT block state from
        # stateless decoding; any reachable IT in the prefix makes predicate
        # execution ambiguous. The relevant writes and CMP are unconditional.
        decoded = [facts.decode(site) for site in prefix.instructions]
        if (any(ins is None or ins.id == a.ARM_INS_IT for ins in decoded)
                or any(facts.decode(CodeAddress(at)).cc not in
                       (a.ARM_CC_AL, a.ARM_CC_INVALID)
                       for at in (init_pc, compare_pc))
                or facts.decode(CodeAddress(branch_pc)).cc != a.ARM_CC_HS):
            continue
        if not all(prefix.dominates(CodeAddress(source), CodeAddress(pc))
                   for source in (init_pc, compare_pc, branch_pc)):
            continue
        # No flag-setting instruction may intervene between this CMP and BHS;
        # their adjacent source PCs and CFG edge identify the guard dependency.
        if (branch_pc != compare_pc + compare.size
                or (CodeAddress(compare_pc), CodeAddress(branch_pc))
                   not in prefix.control_edges):
            continue
        found.append({"dispatch": pc, "header": compare_pc,
            "counter_init": init_pc, "guard_target": target,
            "row_register": row_reg, "table": table, "arms": arms,
            "entry": entry,
            "dependencies": {(table, 2 * rows),
                (entry, pc + 2 - entry)}})
    return found[0] if len(found) == 1 else None
