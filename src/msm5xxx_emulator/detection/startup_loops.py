"""Local loop shape and recurrence proofs for startup memory transfers."""
from __future__ import annotations
from capstone import arm as a
from .facts import CodeAddress, FirmwareFacts, FunctionFacts, LiteralAccessCandidate
from .startup_cfg import (_definition_reaches, _dominates_iteration, _field_reaches_value, _increment_sites, _loop_iteration_cut, _loop_nodes,
    _loop_writes_are_safe, _memory_register, _pc_literal_load, _use_register, _zero_destination)

def _loop_has_evaluated_bound(facts, function, nodes, decoded, end_base_references, size_references, cursor_register, cut_edge):
    """Prove a row-derived base-plus-size bound, including simple shifts."""
    for branch_pc in nodes:
        branch = decoded.get(branch_pc)
        if (branch is None or branch.id != a.ARM_INS_B or branch.cc not in (a.ARM_CC_LO, a.ARM_CC_HS) or not branch.operands or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        taken = CodeAddress(branch.operands[0].imm & 0xFFFFFFFF, branch_pc.isa, branch_pc.phase, branch_pc.bank)
        fallthrough = CodeAddress(branch_pc.address + branch.size, branch_pc.isa, branch_pc.phase, branch_pc.bank)
        edges = set(function.control_edges)
        if ((branch_pc, taken) not in edges or (branch_pc, fallthrough) not in edges or taken not in nodes or fallthrough in nodes):
            continue
        compare_pc = next((pc for pc in nodes if pc.address + getattr(decoded.get(pc), 'size', 0) == branch_pc.address), None)
        compare = decoded.get(compare_pc)
        if (compare is None or compare.id != a.ARM_INS_CMP or len(compare.operands) != 2 or compare.operands[0].type != a.ARM_OP_REG or compare.operands[0].reg
            != cursor_register or compare.operands[1].type != a.ARM_OP_REG or (compare_pc, branch_pc) not in edges):
            continue
        bound_register = compare.operands[1].reg
        origins = facts.register_origins(function, compare_pc, bound_register, cut_edges=(tuple(CodeAddress(address, compare_pc.isa, compare_pc.phase,
            compare_pc.bank) for address in cut_edge),))
        if origins is None or len(origins) != 1:
            continue
        add_pc, destination = origins[0]
        add = facts.decode(add_pc)
        if (destination != bound_register or add is None or add.id != a.ARM_INS_ADD or add.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or len(add.operands) != 3
            or add.operands[0].type != a.ARM_OP_REG or add.operands[0].reg != bound_register or any(item.type != a.ARM_OP_REG for item in add.operands[1:])):
            continue
        left, right = (item.reg for item in add.operands[1:])
        base_linked = _field_reaches_value(facts, function, add_pc, left, end_base_references, cut_edge)
        size_linked = _field_reaches_value(facts, function, add_pc, right, size_references, cut_edge)
        if not (base_linked and size_linked):
            base_linked = _field_reaches_value(facts, function, add_pc, right, end_base_references, cut_edge)
            size_linked = _field_reaches_value(facts, function, add_pc, left, size_references, cut_edge)
        if not (base_linked and size_linked):
            continue
        base_value = facts.register_value(function, add_pc, left)
        size_value = facts.register_value(function, add_pc, right)
        if (base_value.kind != 'const' or size_value.kind != 'const' or type(base_value.value) is not int or type(size_value.value) is not int):
            base_value = facts.register_value(function, add_pc, right)
            size_value = facts.register_value(function, add_pc, left)
        if (base_value.kind == 'const' and size_value.kind == 'const' and type(base_value.value) is int and type (size_value.value) is int and base_value.value
            + size_value.value <= 0xFFFFFFFF):
            return True
    return False

def _pointer_loop(facts: FirmwareFacts, function: FunctionFacts, references: tuple[LiteralAccessCandidate, ...], *, pointer_field: int, end_pointer_field: int,
    size_field: int, zero_body: bool, protected_ranges: tuple[tuple[int, int], ...], extra_write_ranges: tuple[tuple[int, int], ...] = (), all_matches: bool =
    False, continuation_edges: tuple[tuple[int, int], ...] = (), only_edges: tuple[tuple[int, int], ...] = ()):
    """Prove a bounded word copy or zero loop over fields in one row."""
    matches = []
    field_references = {}
    for field in (pointer_field, end_pointer_field, size_field):
        field_references[field] = tuple(item for item in references if item.address == field and item.load in function.instructions and item.use in function.instructions
            and _use_register(facts, item) is not None)
        if not field_references[field]:
            return () if all_matches else None
    decoded = {pc: facts.decode(pc) for pc in function.instructions}
    for edge in function.back_edges:
        if only_edges and edge not in only_edges:
            continue
        continuation = edge in continuation_edges
        nodes = _loop_nodes(function, edge)
        if not nodes:
            continue
        iteration = _loop_iteration_cut(function, nodes, edge)
        if iteration is None:
            continue
        cut_edge, recurrence_address = iteration
        branch_pc = next((pc for pc in function.instructions if pc.address == edge[0]), None)
        recurrence_pc = next((pc for pc in function.instructions if pc.address == recurrence_address), None)
        branch = decoded.get(branch_pc)
        if (branch is None or branch.id != a.ARM_INS_B or branch.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID, a.ARM_CC_LO, a.ARM_CC_HS)):
            continue
        loop_condition = _loop_condition(facts, function, edge, allow_reverse=True)
        if loop_condition is None:
            continue
        loop_cursor = loop_condition[4]
        rotated = recurrence_pc != branch_pc
        def reaches_recurrence(site):
            return _dominates_iteration(function, nodes, site, cut_edge)
        memory_ops = []
        for pc in nodes:
            instruction = decoded.get(pc)
            load = (_memory_register(instruction, a.ARM_INS_LDR) or _memory_register(instruction, a.ARM_INS_LDM))
            store = (_memory_register(instruction, a.ARM_INS_STR) or _memory_register(instruction, a.ARM_INS_STM))
            if load is not None:
                memory_ops.append(('load', pc, instruction, load))
            if store is not None:
                memory_ops.append(('store', pc, instruction, store))
        if zero_body:
            for kind, store_pc, store_ins, (value_register, cursor_register) in memory_ops:
                if kind != 'store' or cursor_register != loop_cursor:
                    continue
                zero_sites = [pc for pc in function.instructions if pc.address < store_pc.address and _zero_destination(decoded.get(pc)) is not None and
                    _definition_reaches(facts, function, pc, store_pc, value_register, cut_edge)]
                increments = _increment_sites(facts, function, nodes, decoded, cursor_register, field_references[pointer_field], cut_edge, recurrence_pc,
                    rotated=rotated, require_field_origin=not continuation)
                if (store_ins.id != a.ARM_INS_STR or kind != 'store' or not zero_sites or not reaches_recurrence (store_pc) or _loop_writes_are_safe(function,
                    nodes, store_pc, protected_ranges, extra_write_ranges) is None or not continuation and not any(_definition_reaches(facts, function, ref.use,
                    store_pc, cursor_register, cut_edge) for ref in field_references[pointer_field]) or not increments or not (_loop_has_bound(facts, function,
                    nodes, decoded, field_references[end_pointer_field], field_references[size_field], cursor_register, cut_edge) or _loop_has_evaluated_bound(facts,
                    function, nodes, decoded, field_references[end_pointer_field], field_references[size_field], cursor_register, cut_edge))):
                    continue
                if all_matches:
                    condition = _loop_condition(facts, function, edge)
                    if condition is None or condition[1].address != edge[1]:
                        continue
                if not _strict_loop_recurrence(facts, function, edge, zero_body=True, cursor_references= field_references[pointer_field], continuation=continuation,
                    allow_reverse=True, protected_ranges=protected_ranges, extra_write_ranges=extra_write_ranges):
                    continue
                matches.append(edge)
            continue
        for _, load_pc, load_ins, (value_register, source_register) in memory_ops:
            if load_ins.id not in (a.ARM_INS_LDR, a.ARM_INS_LDM):
                continue
            for _, store_pc, store_ins, (stored_register, target_register) in memory_ops:
                if (store_ins.id not in (a.ARM_INS_STR, a.ARM_INS_STM) or target_register != loop_cursor or stored_register != value_register or not
                    reaches_recurrence(load_pc) or not reaches_recurrence(store_pc) or _loop_writes_are_safe(function, nodes, store_pc, protected_ranges,
                    extra_write_ranges) is None or not continuation and not any(_definition_reaches(facts, function, ref.use, load_pc, source_register, cut_edge)
                    for ref in field_references[pointer_field]) or not continuation and not any(_definition_reaches(facts, function, ref.use, store_pc,
                    target_register, cut_edge) for ref in field_references[end_pointer_field]) or not _definition_reaches(facts, function, load_pc, store_pc,
                    value_register, cut_edge)):
                    continue
                increments = { register for register, field in ((source_register, pointer_field), (target_register, end_pointer_field),) if _increment_sites(facts,
                    function, nodes, decoded, register, field_references[field], cut_edge, recurrence_pc, rotated=recurrence_pc != branch_pc,
                    require_field_origin=not continuation) }
                if (increments != {source_register, target_register} or not (_loop_has_bound(facts, function, nodes, decoded, field_references[end_pointer_field],
                    field_references[size_field], target_register, cut_edge) or _loop_has_evaluated_bound(facts, function, nodes, decoded, field_references[end_pointer_field],
                    field_references[size_field], target_register, cut_edge))):
                    continue
                if all_matches:
                    condition = _loop_condition(facts, function, edge)
                    if condition is None or condition[1].address != edge[1]:
                        continue
                if not _strict_loop_recurrence(facts, function, edge, zero_body=False, cursor_references= field_references[end_pointer_field], source_references=field_references[pointer_field],
                    continuation=continuation, allow_reverse=True, protected_ranges=protected_ranges, extra_write_ranges=extra_write_ranges):
                    continue
                matches.append(edge)
    if all_matches:
        return tuple(dict.fromkeys(matches))
    return matches[0] if matches else None

def _loop_has_bound(facts, function, nodes, decoded, end_base_references, size_references, cursor_register, cut_edge):
    edges = set(function.control_edges)
    for branch_pc in nodes:
        branch = decoded.get(branch_pc)
        if (branch is None or branch.id != a.ARM_INS_B or branch.cc not in (a.ARM_CC_LO, a.ARM_CC_HS) or not branch.operands or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        taken_address = branch.operands[0].imm & 0xFFFFFFFF
        taken = CodeAddress(taken_address, branch_pc.isa, branch_pc.phase, branch_pc.bank)
        fallthrough = CodeAddress(branch_pc.address + branch.size, branch_pc.isa, branch_pc.phase, branch_pc.bank)
        if (branch_pc, taken) not in edges or (branch_pc, fallthrough) not in edges:
            continue
        if branch.cc == a.ARM_CC_LO:
            if taken not in nodes or fallthrough in nodes:
                continue
        elif taken in nodes or fallthrough not in nodes:
            continue
        compare_pc = next((pc for pc in nodes if pc.address + getattr(decoded.get(pc), 'size', 0) == branch_pc.address), None)
        compare = decoded.get(compare_pc)
        if (compare is None or compare.id != a.ARM_INS_CMP or compare.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or len(compare.operands) != 2 or any(operand.type
            != a.ARM_OP_REG for operand in compare.operands) or compare.operands[0].reg != cursor_register or (compare_pc, branch_pc) not in edges):
            continue
        end_register = compare.operands[1].reg
        for base_ref in end_base_references:
            base_register = _use_register(facts, base_ref)
            if base_register is None:
                continue
            for size_ref in size_references:
                size_register = _use_register(facts, size_ref)
                if size_register is None:
                    continue
                for add_pc, instruction in decoded.items():
                    if (instruction is None or instruction.id != a.ARM_INS_ADD or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or len(instruction.operands)
                        != 3):
                        continue
                    destination, left, right = instruction.operands
                    end_origins = facts.register_origins(function, compare_pc, end_register, cut_edges=(tuple(CodeAddress(address, compare_pc.isa, compare_pc.phase,
                        compare_pc.bank) for address in cut_edge),))
                    if (destination.type != a.ARM_OP_REG or end_origins is None or (add_pc, destination.reg) not in end_origins or left.type != a.ARM_OP_REG or
                        right.type != a.ARM_OP_REG or (left.reg, right.reg) not in ((base_register, size_register), (size_register, base_register)) or not
                        _definition_reaches(facts, function, base_ref.use, add_pc, base_register, cut_edge) or not _definition_reaches(facts, function, size_ref.use,
                        add_pc, size_register, cut_edge) or not any(_definition_reaches(facts, function, ref.use, compare_pc, cursor_register, cut_edge) for ref
                        in end_base_references)):
                        continue
                    return True
    return False

def _loop_condition(facts, function, edge, *, allow_reverse=False):
    """Locate the closed unsigned loop test and its outside fallthrough."""
    nodes = _loop_nodes(function, edge)
    if not nodes:
        return None
    edges = set(function.control_edges)
    matches = []
    for branch_pc in nodes:
        branch = facts.decode(branch_pc)
        if (branch is None or branch.id != a.ARM_INS_B or branch.cc not in ((a.ARM_CC_LO, a.ARM_CC_HS) if allow_reverse else (a.ARM_CC_LO,)) or not branch.operands
            or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        taken = CodeAddress(branch.operands[0].imm & 0xFFFFFFFF, branch_pc.isa, branch_pc.phase, branch_pc.bank)
        fallthrough = CodeAddress(branch_pc.address + branch.size, branch_pc.isa, branch_pc.phase, branch_pc.bank)
        if ((branch_pc, taken) not in edges or (branch_pc, fallthrough) not in edges):
            continue
        if branch.cc == a.ARM_CC_LO:
            if taken not in nodes or fallthrough in nodes:
                continue
            outside = fallthrough
        else:
            if taken in nodes or fallthrough not in nodes:
                continue
            outside = taken
        compare_pc = next((pc for pc in nodes if pc.address + getattr(facts.decode(pc), 'size', 0) == branch_pc.address), None)
        compare = facts.decode(compare_pc) if compare_pc is not None else None
        if (compare is None or compare.id != a.ARM_INS_CMP or compare.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or len(compare.operands) != 2 or any(item.type
            != a.ARM_OP_REG for item in compare.operands) or (compare_pc, branch_pc) not in edges):
            continue
        flag_definitions = facts.reaching_definitions(function, branch_pc, a.ARM_REG_CPSR)
        if flag_definitions != (compare_pc,):
            continue
        matches.append((nodes, compare_pc, branch_pc, outside, compare.operands[0].reg, compare.operands[1].reg))
    return matches[0] if len(matches) == 1 else None

def _constant_register_value(facts, function, use, register):
    value = facts.register_value(function, use, register)
    return value.value if value.kind == 'const' and type(value.value) is int else None

def _returns_to_link(instruction):
    if instruction is None:
        return False
    operands = instruction.operands
    if (instruction.id == a.ARM_INS_BX and len(operands) == 1 and operands[0].type == a.ARM_OP_REG and operands[0].reg == a.ARM_REG_LR):
        return True
    if (instruction.id == a.ARM_INS_MOV and len(operands) == 2 and operands[0].type == a.ARM_OP_REG and operands[0].reg == a.ARM_REG_PC and operands[1].type ==
        a.ARM_OP_REG and operands[1].reg == a.ARM_REG_LR):
        return True
    if instruction.id == a.ARM_INS_POP:
        return any(item.type == a.ARM_OP_REG and item.reg == a.ARM_REG_PC for item in operands)
    return False

def _ordered_transfer_completion(facts, function, loops):
    returns = tuple(pc for pc in function.instructions if _returns_to_link(facts.decode(pc)))
    if len(returns) != 1:
        return None
    completion = returns[0]
    if any(item.exit is None or not function.dominates(item.exit, completion) for item in loops):
        return None
    return completion

def _strict_loop_recurrence(facts, function, edge, *, zero_body, cursor_references=(), source_references=(), continuation=False, allow_reverse=False,
    protected_ranges=(), extra_write_ranges=()):
    """Require one invariant-bound test and one ordered stride update per loop."""
    condition = _loop_condition(facts, function, edge, allow_reverse=allow_reverse)
    if condition is None:
        return False
    nodes, compare_pc, branch_pc, _, cursor_register, bound_register = condition
    iteration = _loop_iteration_cut(function, nodes, edge)
    if iteration is None:
        return False
    recurrence_pc = next((pc for pc in function.instructions if pc.address == iteration[1]), None)
    if recurrence_pc is None:
        return False
    cut = tuple(CodeAddress(address, recurrence_pc.isa, recurrence_pc.phase, recurrence_pc.bank) for address in iteration[0])
    successors = {}
    for source, target in function.control_edges:
        if source in nodes and target in nodes and (source, target) != cut:
            successors.setdefault(source,[]).append(target)
    active, visited = set(), set()
    def acyclic(pc):
        if pc in active:
            return False
        if pc in visited:
            return True
        active.add(pc)
        if not all(acyclic(target) for target in successors.get(pc, ())):
            return False
        active.remove(pc)
        visited.add(pc)
        return True
    if not all(acyclic(pc) for pc in nodes):
        return False
    if bound_register == cursor_register:
        return False
    for pc in nodes:
        ins = facts.decode(pc)
        if ins is None:
            return False
        try:
            _, writes = ins.regs_access()
        except Exception:
            return False
        if bound_register in writes:
            return False
    decoded = {pc: facts.decode(pc) for pc in nodes}
    rotated = iteration[1] != edge[0]
    updates = _increment_sites(facts, function, nodes, decoded, cursor_register, cursor_references, iteration[0], recurrence_pc, rotated=rotated,
        require_field_origin=not continuation)
    cursor_writes = tuple(pc for pc in nodes if _writes_register(decoded.get(pc), cursor_register))
    if (len(updates) != 1 or cursor_writes != updates or not function.dominates(updates[0], recurrence_pc)):
        return False
    update = updates[0]
    loads = tuple((pc, (_memory_register(ins, a.ARM_INS_LDR) or _memory_register(ins, a.ARM_INS_LDM))) for pc, ins in decoded.items() if (_memory_register(ins,
        a.ARM_INS_LDR) or _memory_register(ins, a.ARM_INS_LDM)) is not None and not _pc_literal_load(ins))
    all_stores = tuple((pc, (_memory_register(ins, a.ARM_INS_STR) or _memory_register(ins, a.ARM_INS_STM))) for pc, ins in decoded.items() if (_memory_register(ins,
        a.ARM_INS_STR) or _memory_register(ins, a.ARM_INS_STM)) is not None)
    stores = tuple((pc, memory) for pc, memory in all_stores if memory[1] == cursor_register)
    memory_sites = tuple(pc for pc, ins in decoded.items() if ins is not None and ins.id in (a.ARM_INS_LDR, a.ARM_INS_LDRB, a.ARM_INS_LDRH, a.ARM_INS_STR, a.ARM_INS_STRB,
        a.ARM_INS_STRH, a.ARM_INS_LDM, a.ARM_INS_STM))
    selected_memory = {pc for pc, _ in loads + stores}
    unsupported_memory = facts.unmodelled_memory(function)
    if (unsupported_memory is None or any(pc in nodes and pc not in selected_memory for pc in unsupported_memory)):
        return False
    extra_memory = set(memory_sites) - selected_memory
    if extra_memory:
        if any(any(access.instruction == site and access.operation == 'read' for access in function.symbolic_accesses) and not _pc_literal_load(facts.decode(site))
            for site in extra_memory):
            return False
        if len(stores) != 1 or _loop_writes_are_safe(function, nodes, stores[0][0], protected_ranges, extra_write_ranges) is None:
            return False
    if len(stores) != 1:
        return False
    if zero_body:
        if loads or stores[0][1][1] != cursor_register:
            return False
        store_pc, (value_register, _) = stores[0]
        value_writes = tuple(pc for pc in nodes if _writes_register(decoded.get(pc), value_register))
        zeros = tuple(pc for pc in function.instructions if _zero_destination(facts.decode(pc)) == value_register and _definition_reaches(facts, function, pc,
            store_pc, value_register, iteration[0]))
        loop_zeros = tuple(pc for pc in zeros if pc in nodes)
        if ((zeros and not any(function.dominates(zero, store_pc) for zero in zeros)) or not function.dominates(store_pc, update)):
            return False
        if loop_zeros:
            if (len(loop_zeros) != 1 or not function.dominates(loop_zeros[0], store_pc) or any(not (function.dominates(store_pc, write) or function.dominates(write,
                loop_zeros[0])) for write in value_writes if write != loop_zeros[0])):
                return False
        elif value_writes:
            return False
        if not loop_zeros and _constant_register_value(facts, function, store_pc, value_register) != 0:
            return False
    else:
        if len(loads) != 1 or len(stores) != 1:
            return False
        load_pc, loaded = loads[0]
        store_pc, stored = stores[0]
        if (loaded[0] != stored[0] or stored[1] != cursor_register or loaded[1] == cursor_register or not function.dominates(load_pc, store_pc) or not function.dominates(store_pc,
            update)):
            return False
        source_updates = tuple(pc for pc in nodes if (ins := decoded[pc]) is not None and _writes_register(ins, loaded[1]))
        source_steps = _increment_sites(facts, function, nodes, decoded, loaded[1], source_references, iteration[0], recurrence_pc, rotated=rotated,
            require_field_origin=not continuation)
        if (len(source_steps) != 1 or source_updates != source_steps or not function.dominates(source_updates[0], recurrence_pc) or (source_updates[0] !=
            load_pc and not function.dominates(store_pc, source_updates[0]))):
            return False
    return True

def _writes_register(instruction, register):
    if instruction is None:
        return False
    try:
        _, writes = instruction.regs_access()
    except Exception:
        return False
    return register in writes
