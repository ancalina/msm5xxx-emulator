"""CFG proof for literal-linked Thumb LDMIA/STMIA word-copy loops."""
from __future__ import annotations

from capstone import arm as a

from .facts import CodeAddress


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


def _field_origin(facts, function, fields, site, register, cut_edges):
    """Resolve a register only through a unique field load or plain MOV alias."""
    active = set()
    while register is not None and len(active) < 12:
        key = (site, register)
        if key in active:
            return None
        active.add(key)
        definitions = facts.reaching_definitions(
            function, site, register, cut_edges=cut_edges)
        if definitions is None or len(definitions) != 1:
            return None
        definition = definitions[0]
        ins = facts.decode(definition)
        if (ins is None or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or _reg(ins, 0) != register):
            return None
        for cell, uses in fields.items():
            if definition in uses and ins.id == a.ARM_INS_LDR:
                return cell
        if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                and len(ins.operands) == 2
                and not ins.operands[1].shift.type
                and not ins.operands[1].subtracted):
            register, site = _reg(ins, 1), definition
            continue
        if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                and _imm(ins, 2) == 0
                and not ins.operands[1].shift.type
                and not ins.operands[1].subtracted):
            register, site = _reg(ins, 1), definition
            continue
        return None
    return None


def _const(facts, function, site, register, cut_edges):
    value = facts.register_value(function, site, register,
                                 cut_edges=cut_edges)
    return value.value if value.kind == "const" and type(value.value) is int else None


def ldm_word_loop_proof(facts, function, fields, source_cell,
                        destination_cell, size_cell, source, destination,
                        size, nor_end, target_ranges):
    """Prove an exact LDMIA/STMIA one-word loop over adjacent copy fields.

    The accepted CFG is preheader -> CMP -> BLO body/exit, with body
    LDMIA source!,{value}; STMIA target!,{value}; back to CMP. The bound must
    be a uniquely defined, field-linked destination + size sum. Only a single
    general-register transfer list is accepted, so each cursor advances four.
    """
    if (not function.complete or function.truncated or function.unresolved
            or type(source_cell) is not int
            or (destination_cell, size_cell) !=
                (source_cell + 4, source_cell + 8)
            or any(type(value) is not int for value in
                   (source, destination, size, nor_end))
            or source_cell < 0 or source_cell + 12 > nor_end
            or nor_end <= 0
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
    if any(type(item.pool) is not int or item.pool < 0
           or item.pool + 4 > nor_end for item in function.literals):
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
        target_reg, end_reg = _reg(compare, 0), _reg(compare, 1)
        gprs = {a.ARM_REG_R0 + index for index in range(13)}
        branch_site = following(compare_site)
        branch = instructions.get(branch_site)
        if (target_reg not in gprs or end_reg not in gprs
                or target_reg == end_reg
                or branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_LO or len(branch.operands) != 1
                or _imm(branch, 0) is None):
            continue
        body_site = CodeAddress(_imm(branch, 0), compare_site.isa,
                                compare_site.phase, compare_site.bank)
        load = instructions.get(body_site)
        store_site = following(body_site)
        store = instructions.get(store_site)
        if (load is None or load.id != a.ARM_INS_LDM
                or load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or load.size != 2
                or not load.writeback or len(load.operands) != 2
                or store is None or store.id != a.ARM_INS_STM
                or store.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or store.size != 2
                or not store.writeback or len(store.operands) != 2
                or following(store_site) != compare_site):
            continue
        source_reg, target_store_reg = _reg(load, 0), _reg(store, 0)
        value_reg, stored_reg = _reg(load, 1), _reg(store, 1)
        if (source_reg not in gprs or target_store_reg != target_reg
                or value_reg not in gprs or stored_reg != value_reg
                or source_reg in (target_reg, end_reg, value_reg)
                or target_reg in (end_reg, value_reg)
                or value_reg == end_reg):
            continue
        # These Thumb encodings carry exactly one transfer register. Reject
        # any decoded list expansion or mode/operand variant.
        if (len(load.operands) != 2 or len(store.operands) != 2
                or not load.writeback or not store.writeback):
            continue
        exit_site = following(branch_site)
        preheaders = [
            site for site in predecessors.get(compare_site, ())
            if site != store_site and instructions.get(site) is not None
            and instructions[site].id == a.ARM_INS_B
            and instructions[site].cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            and _imm(instructions[site], 0) == compare_site.address
        ]
        if len(preheaders) != 1:
            continue
        preheader = preheaders[0]
        if (edges.get(preheader) != {compare_site}
                or edges.get(compare_site) != {branch_site}
                or edges.get(branch_site) != {body_site, exit_site}
                or predecessors.get(exit_site) != {branch_site}
                or edges.get(body_site) != {store_site}
                or edges.get(store_site) != {compare_site}
                or predecessors.get(compare_site) != {preheader, store_site}
                or predecessors.get(body_site) != {branch_site}
                or predecessors.get(store_site) != {body_site}
                or (branch_site.address, body_site.address)
                    not in function.back_edges
                or exit_site not in instructions
                or not function.dominates(compare_site, branch_site)
                or not function.dominates(compare_site, body_site)
                or not function.dominates(compare_site, store_site)):
            continue
        reachable, pending = set(), [function.entry]
        terminals = set()
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
        if (not terminals
                or any(not function.dominates(preheader, terminal)
                       for terminal in terminals)):
            continue
        if facts.reaching_definitions(function, branch_site,
                                      a.ARM_REG_CPSR) != (compare_site,):
            continue
        cut_edges = ((store_site, compare_site),)
        if (_field_origin(facts, function, fields, body_site, source_reg,
                          cut_edges) != source_cell
                or _field_origin(facts, function, fields, body_site, target_reg,
                                 cut_edges) != destination_cell
                or facts.reaching_definitions(function, store_site, value_reg,
                                              cut_edges=cut_edges) != (body_site,)):
            continue
        if (_const(facts, function, body_site, source_reg, cut_edges) != source
                or _const(facts, function, body_site, target_reg,
                          cut_edges) != destination):
            continue
        end_defs = facts.reaching_definitions(function, compare_site, end_reg,
                                              cut_edges=cut_edges)
        if end_defs is None or len(end_defs) != 1:
            continue
        add_site = end_defs[0]
        add = instructions.get(add_site)
        if (add is None or add.id != a.ARM_INS_ADD
                or add.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(add.operands) != 3 or _reg(add, 0) != end_reg
                or any(op.shift.type or op.subtracted for op in add.operands)):
            continue
        origins = (_field_origin(facts, function, fields, add_site,
                                 _reg(add, 1), ()),
                   _field_origin(facts, function, fields, add_site,
                                 _reg(add, 2), ()))
        if None in origins or set(origins) != {destination_cell, size_cell}:
            continue
        if _const(facts, function, compare_site, end_reg,
                  cut_edges) != destination + size:
            continue
        evidence = {(source_cell, 12), (source, size)}
        evidence.update((site.address, ins.size)
                        for site, ins in instructions.items())
        evidence.update((literal.pool, 4) for literal in function.literals)
        evidence.update((site.address, facts.decode(site).size)
                        for uses in fields.values() for site in uses)
        return size, tuple(sorted(evidence)), exit_site
    return None
