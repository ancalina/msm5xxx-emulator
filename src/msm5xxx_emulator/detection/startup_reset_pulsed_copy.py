"""CFG proof for literal-linked word copies with a fixed MMIO byte pulse."""
from __future__ import annotations

from capstone import arm as a

from .facts import CodeAddress
from .startup_reset_ldm_copy import _const, _field_origin


def _reg(ins, index):
    if ins is None or index >= len(ins.operands):
        return None
    operand = ins.operands[index]
    return operand.reg if operand.type == a.ARM_OP_REG else None


def _imm(ins, index):
    if ins is None or index >= len(ins.operands):
        return None
    operand = ins.operands[index]
    return operand.imm if operand.type == a.ARM_OP_IMM else None


def _field_end(facts, function, fields, compare_site, end_reg,
               destination_cell, size_cell, cut_edges):
    definitions = facts.reaching_definitions(
        function, compare_site, end_reg, cut_edges=cut_edges)
    if definitions is None or len(definitions) != 1:
        return None
    add_site = definitions[0]
    add = facts.decode(add_site)
    if (add is None or add.id != a.ARM_INS_ADD
            or add.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or len(add.operands) != 3 or _reg(add, 0) != end_reg
            or any(op.shift.type or op.subtracted for op in add.operands)):
        return None
    origins = tuple(_field_origin(
        facts, function, fields, add_site, _reg(add, index), ())
        for index in (1, 2))
    if None in origins or set(origins) != {destination_cell, size_cell}:
        return None
    return add_site


def _closed_returns(facts, function, instructions, edges, preheader):
    reachable, pending, terminals = set(), [function.entry], set()
    while pending:
        current = pending.pop()
        if current in reachable or current not in instructions:
            continue
        reachable.add(current)
        successors = edges.get(current, set())
        if not successors:
            terminals.add(current)
        for successor in successors:
            if successor in instructions:
                pending.append(successor)
            else:
                terminals.add(current)
    return bool(terminals) and all(
        function.dominates(preheader, terminal) for terminal in terminals)


def pulsed_word_loop_proof(facts, function, fields, source_cell,
                           destination_cell, size_cell, source, destination,
                           size, nor_end, target_ranges):
    """Prove one scalar word copy loop with ordered high/low byte pulses.

    The closed loop is preheader -> CMP -> BLO body/exit. Its body performs
    LDR source; STR target; STRB 1 to a fixed MMIO port; STRB 0 to that same
    port; increment both cursors by four; then returns to CMP. No other body
    operations or control edges are admitted.
    """
    if (not function.complete or function.truncated or function.unresolved
            or type(source_cell) is not int
            or (destination_cell, size_cell) !=
                (source_cell + 4, source_cell + 8)
            or any(type(value) is not int for value in
                   (source, destination, size, nor_end))
            or source_cell < 0 or source_cell + 12 > nor_end or nor_end <= 0
            or any(type(lo) is not int or type(hi) is not int
                   or lo < 0 or hi <= lo or hi > 0x100000000
                   for lo, hi in target_ranges)
            or size <= 0 or size & 3 or source < 0
            or source & 3 or destination & 3
            or source + size > nor_end
            or destination + size >= 0x100000000
            or not (source + size <= destination
                    or destination + size <= source)
            or not any(lo <= destination and destination + size <= hi
                       for lo, hi in target_ranges)):
        return None
    instructions = {site: facts.decode(site) for site in function.instructions}
    if any(ins is None or site.address < 0 or site.address + ins.size > nor_end
           for site, ins in instructions.items()):
        return None
    if any(type(literal.pool) is not int or literal.pool < 0
           or literal.pool + 4 > nor_end for literal in function.literals):
        return None
    edges, predecessors = {}, {}
    for left, right in function.control_edges:
        edges.setdefault(left, set()).add(right)
        predecessors.setdefault(right, set()).add(left)

    def following(site):
        ins = instructions.get(site)
        return (CodeAddress(site.address + ins.size, site.isa, site.phase, site.bank)
                if ins is not None else None)

    for compare_site, compare in instructions.items():
        if (compare is None or compare_site.isa != "thumb"
                or compare.id != a.ARM_INS_CMP
                or compare.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(compare.operands) != 2):
            continue
        destination_reg, end_reg = _reg(compare, 0), _reg(compare, 1)
        gprs = {a.ARM_REG_R0 + index for index in range(13)}
        branch_site = following(compare_site)
        branch = instructions.get(branch_site)
        if (destination_reg not in gprs or end_reg not in gprs
                or destination_reg == end_reg
                or compare.size != 2 or branch is None or branch.size != 2
                or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_LO or len(branch.operands) != 1
                or _imm(branch, 0) is None):
            continue
        body_site = CodeAddress(_imm(branch, 0), compare_site.isa,
                                compare_site.phase, compare_site.bank)
        load_site = body_site
        load = instructions.get(load_site)
        store_site = following(load_site)
        store = instructions.get(store_site)
        high_site = following(store_site)
        high_store = instructions.get(high_site)
        low_site = following(high_site)
        low_store = instructions.get(low_site)
        source_step_site = following(low_site)
        source_step = instructions.get(source_step_site)
        destination_step_site = following(source_step_site)
        destination_step = instructions.get(destination_step_site)
        if (load is None or load.size != 2 or load.id != a.ARM_INS_LDR
                or load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(load.operands) != 2
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.base is None
                or load.operands[1].mem.index
                or load.operands[1].mem.disp != 0 or load.writeback
                or store is None or store.size != 2 or store.id != a.ARM_INS_STR
                or store.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(store.operands) != 2
                or store.operands[1].type != a.ARM_OP_MEM
                or store.operands[1].mem.base != destination_reg
                or store.operands[1].mem.index
                or store.operands[1].mem.disp != 0 or store.writeback
                or high_store is None or high_store.size != 2
                or high_store.id != a.ARM_INS_STRB
                or high_store.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or low_store is None or low_store.size != 2
                or low_store.id != a.ARM_INS_STRB
                or low_store.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or source_step is None or source_step.size != 2
                or source_step.id != a.ARM_INS_ADD
                or source_step.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(source_step.operands) != 2
                or _reg(source_step, 0) != load.operands[1].mem.base
                or _imm(source_step, 1) != 4
                or destination_step is None or destination_step.size != 2
                or destination_step.id != a.ARM_INS_ADD
                or destination_step.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(destination_step.operands) != 2
                or _reg(destination_step, 0) != destination_reg
                or _imm(destination_step, 1) != 4
                or following(destination_step_site) != compare_site):
            continue
        source_reg = load.operands[1].mem.base
        value_reg = _reg(load, 0)
        stored_reg = _reg(store, 0)
        high_reg, high_port = _reg(high_store, 0), None
        low_reg, low_port = _reg(low_store, 0), None
        if (high_store.operands[1].type != a.ARM_OP_MEM
                or low_store.operands[1].type != a.ARM_OP_MEM
                or high_store.operands[1].mem.base is None
                or low_store.operands[1].mem.base is None
                or high_store.operands[1].mem.index
                or low_store.operands[1].mem.index
                or high_store.operands[1].mem.disp != 0
                or low_store.operands[1].mem.disp != 0
                or high_store.writeback or low_store.writeback):
            continue
        high_port = high_store.operands[1].mem.base
        low_port = low_store.operands[1].mem.base
        port = high_port
        if (source_reg not in gprs or value_reg not in gprs
                or stored_reg != value_reg or port not in gprs
                or low_port != port or high_reg not in gprs
                or low_reg not in gprs
                or len({source_reg, destination_reg, end_reg, value_reg,
                        high_reg, low_reg, port}) != 7):
            continue
        exit_site = following(branch_site)
        preheaders = [
            site for site in predecessors.get(compare_site, ())
            if site != destination_step_site
            and instructions.get(site) is not None
            and instructions[site].size == 2
            and instructions[site].id == a.ARM_INS_B
            and instructions[site].cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            and _imm(instructions[site], 0) == compare_site.address
        ]
        if len(preheaders) != 1:
            continue
        preheader = preheaders[0]
        if (predecessors.get(compare_site) !=
                {preheader, destination_step_site}
                or predecessors.get(exit_site) != {branch_site}
                or predecessors.get(body_site) != {branch_site}
                or predecessors.get(store_site) != {load_site}
                or predecessors.get(high_site) != {store_site}
                or predecessors.get(low_site) != {high_site}
                or predecessors.get(source_step_site) != {low_site}
                or predecessors.get(destination_step_site) != {source_step_site}
                or edges.get(preheader) != {compare_site}
                or edges.get(compare_site) != {branch_site}
                or edges.get(branch_site) != {body_site, exit_site}
                or edges.get(load_site) != {store_site}
                or edges.get(store_site) != {high_site}
                or edges.get(high_site) != {low_site}
                or edges.get(low_site) != {source_step_site}
                or edges.get(source_step_site) != {destination_step_site}
                or edges.get(destination_step_site) != {compare_site}
                or (branch_site.address, body_site.address)
                    not in function.back_edges
                or exit_site not in instructions
                or not function.dominates(compare_site, branch_site)
                or not function.dominates(compare_site, body_site)
                or not function.dominates(compare_site, destination_step_site)):
            continue
        if (facts.reaching_definitions(function, branch_site,
                                       a.ARM_REG_CPSR) != (compare_site,)):
            continue
        cut_edges = ((destination_step_site, compare_site),)
        if (_field_origin(facts, function, fields, body_site, source_reg,
                          cut_edges) != source_cell
                or _field_origin(facts, function, fields, body_site,
                                 destination_reg, cut_edges) != destination_cell
                or facts.reaching_definitions(function, store_site, value_reg,
                                              cut_edges=cut_edges) != (load_site,)):
            continue
        if (_const(facts, function, body_site, source_reg, cut_edges) != source
                or _const(facts, function, body_site, destination_reg,
                          cut_edges) != destination):
            continue
        end_site = _field_end(facts, function, fields, compare_site, end_reg,
                              destination_cell, size_cell, cut_edges)
        if (end_site is None
                or _const(facts, function, compare_site, end_reg,
                          cut_edges) != destination + size):
            continue
        pulse_values = (
            (high_site, high_reg, 1),
            (low_site, low_reg, 0),
        )
        for pulse_site, pulse_reg, expected in pulse_values:
            if (facts.reaching_definitions(
                    function, pulse_site, pulse_reg,
                    cut_edges=cut_edges) is None
                    or len(facts.reaching_definitions(
                        function, pulse_site, pulse_reg,
                        cut_edges=cut_edges)) != 1
                    or _const(facts, function, pulse_site, pulse_reg,
                              cut_edges) != expected):
                break
        else:
            port_defs_high = facts.reaching_definitions(
                function, high_site, port, cut_edges=cut_edges)
            port_defs_low = facts.reaching_definitions(
                function, low_site, port, cut_edges=cut_edges)
            port_value_high = _const(facts, function, high_site, port,
                                     cut_edges)
            port_value_low = _const(facts, function, low_site, port,
                                    cut_edges)
            port_address = port_value_high
            if (port_defs_high is None or len(port_defs_high) != 1
                    or port_defs_high != port_defs_low
                    or port_address != port_value_low
                    or port_address is None
                    or not 0x03000600 <= port_address < 0x03000780
                    or port_address < nor_end
                    or any(lo <= port_address < hi for lo, hi in target_ranges)
                    or source <= port_address < source + size
                    or destination <= port_address < destination + size
                    or not _closed_returns(
                        facts, function, instructions, edges, preheader)):
                continue
            evidence = {(source_cell, 12), (source, size)}
            evidence.update((site.address, ins.size)
                            for site, ins in instructions.items())
            evidence.update((literal.pool, 4)
                            for literal in function.literals)
            evidence.update((site.address, facts.decode(site).size)
                            for uses in fields.values() for site in uses)
            return size, tuple(sorted(evidence)), exit_site
    return None
