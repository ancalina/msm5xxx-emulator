"""Source link between a low sideband byte and the scanner's byte queue."""
from __future__ import annotations

from collections import deque

from capstone import CS_GRP_CALL, CS_GRP_JUMP
from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .branch_conditions import (add_flags, compare_flags, condition_holds,
                                move_flags, refine_flags, unknown_flags)


def _reg(operand):
    return operand.reg if operand.type == a.ARM_OP_REG else None


def _imm(operand):
    return operand.imm if operand.type == a.ARM_OP_IMM else None


def _add(ins, dst, src, value):
    return (ins is not None and ins.id == a.ARM_INS_ADD
            and len(ins.operands) == 3
            and _reg(ins.operands[0]) == dst
            and _reg(ins.operands[1]) == src
            and _imm(ins.operands[2]) == value)


def _numeric_store(facts, image, load_pc, sink_pc, event_register,
                   event_codes):
    """Prove [SP+4+old_count] and the matching byte-count increment."""
    if (not isinstance(event_codes, (list, tuple)) or len(event_codes) != 24
            or any(type(value) is not int or not 0 <= value <= 255
                   for value in event_codes)):
        return None
    load, store = facts.decode(CodeAddress(load_pc)), facts.decode(CodeAddress(sink_pc))
    if (load is None or load.id != a.ARM_INS_LDRB or len(load.operands) != 2
            or _reg(load.operands[0]) != event_register
            or store is None or store.id != a.ARM_INS_STRB
            or len(store.operands) != 2
            or _reg(store.operands[0]) != event_register
            or store.operands[1].type != a.ARM_OP_MEM
            or not store.operands[1].mem.index):
        return None
    mem = store.operands[1].mem
    index = mem.index
    base_add, index_copy, count_copy = (facts.decode(CodeAddress(sink_pc - d))
                                        for d in (2, 6, 4))
    if (not _add(base_add, _reg(base_add.operands[0]) if base_add else -1,
                 a.ARM_REG_SP, 4)
            or _reg(base_add.operands[0]) != mem.base
            or index_copy is None or index_copy.id != a.ARM_INS_ADD
            or len(index_copy.operands) != 3
            or _reg(index_copy.operands[0]) != index
            or _imm(index_copy.operands[2]) != 0
            or count_copy is None or count_copy.id != a.ARM_INS_ADD
            or len(count_copy.operands) != 3
            or _imm(count_copy.operands[2]) != 0):
        return None
    count_register = _reg(count_copy.operands[0])
    increment_register = _reg(count_copy.operands[1])
    base_register = _reg(base_add.operands[0])
    if (_reg(index_copy.operands[1]) != count_register
            or increment_register is None
            or len({event_register, count_register, index,
                    increment_register, base_register}) < 4
            or event_register in (count_register, index, increment_register,
                                  base_register)
            or count_register in (index, increment_register, base_register)
            or index in (increment_register, base_register)):
        return None
    # A source-level ADD + one followed by byte normalization feeds the
    # in-place count update. The index copy still observes the old count.
    patterns = []
    for pc in range(max(load_pc + 2, sink_pc - 20), sink_pc - 8, 2):
        add = facts.decode(CodeAddress(pc))
        if (add is None or add.id != a.ARM_INS_ADD or len(add.operands) != 3
                or _reg(add.operands[0]) != increment_register
                or _reg(add.operands[1]) != count_register
                or _imm(add.operands[2]) != 1):
            continue
        lsl, lsr = facts.decode(CodeAddress(pc + 2)), facts.decode(CodeAddress(pc + 4))
        update = facts.decode(CodeAddress(pc + 8))
        if (lsl is not None and lsl.id == a.ARM_INS_LSL
                and len(lsl.operands) == 3
                and _reg(lsl.operands[0]) == increment_register
                and _reg(lsl.operands[1]) == increment_register
                and _imm(lsl.operands[2]) == 24
                and lsr is not None and lsr.id == a.ARM_INS_LSR
                and len(lsr.operands) == 3
                and _reg(lsr.operands[0]) == increment_register
                and _reg(lsr.operands[1]) == increment_register
                and _imm(lsr.operands[2]) == 24
                and update is count_copy):
            patterns.append(pc)
    if len(patterns) != 1 or mem.disp != 0:
        return None
    increment_pc = patterns[0]
    if (index_copy.address != increment_pc + 6
            or count_copy.address != increment_pc + 8
            or base_add.address != increment_pc + 10
            or sink_pc != increment_pc + 12):
        return None
    # This block is a straight-line Thumb source sequence. Reject IT or any
    # conditional instruction that could skip the live event/count update.
    for pc in range(load_pc, sink_pc + 2, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is None or ins.size != 2
                or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or ins.id in (a.ARM_INS_IT, a.ARM_INS_B, a.ARM_INS_BL,
                              a.ARM_INS_BX, a.ARM_INS_POP, a.ARM_INS_PUSH)):
            return None
        try:
            _, writes = ins.regs_access()
        except Exception:
            return None
        allowed = {}
        if pc == load_pc:
            allowed[event_register] = True
        if pc in (increment_pc, increment_pc + 2, increment_pc + 4):
            allowed[increment_register] = True
        if pc == index_copy.address:
            allowed[index] = True
        if pc == count_copy.address:
            allowed[count_register] = True
        if pc == base_add.address:
            allowed[mem.base] = True
        critical = {event_register, count_register, index, mem.base,
                    increment_register}
        if (critical & set(writes)) - set(allowed):
            return None
        if pc != sink_pc and (ins.id in (a.ARM_INS_STR, a.ARM_INS_STRB,
                a.ARM_INS_STRH, a.ARM_INS_STM, a.ARM_INS_STMDA,
                a.ARM_INS_STMDB, a.ARM_INS_STMIB, a.ARM_INS_PUSH)):
            return None
        if (pc != sink_pc and any(op.type == a.ARM_OP_MEM
                                  for op in ins.operands)
                and ins.id not in (a.ARM_INS_LDR, a.ARM_INS_LDRB,
                                   a.ARM_INS_LDRH)):
            return None
    if load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
        return None
    return {"store_site": sink_pc, "load_site": load_pc,
            "buffer_offset": 4, "index_register": index,
            "count_register": count_register,
            "increment_site": patterns[0],
            "dependencies": {(load_pc, sink_pc + 2 - load_pc)}}


def _consumer_path(facts, image, terminal, count_register, exit_flags):
    """Find a call-free source path from an event exit to a guarded read."""
    limit = min(len(image) - 2, terminal + 0x400)
    candidates = []
    for pc in range(terminal, limit, 2):
        read = facts.decode(CodeAddress(pc))
        base_add = facts.decode(CodeAddress(pc - 2))
        if (read is None or read.size != 2 or read.id != a.ARM_INS_LDRB or len(read.operands) != 2
                or read.operands[1].type != a.ARM_OP_MEM
                or _reg(read.operands[0]) is None
                or not a.ARM_REG_R0 <= _reg(read.operands[0]) <= a.ARM_REG_R7
                or not read.operands[1].mem.index
                or base_add is None or base_add.size != 2 or base_add.id != a.ARM_INS_ADD
                or len(base_add.operands) != 3
                or _reg(base_add.operands[0]) != read.operands[1].mem.base
                or _reg(base_add.operands[1]) != a.ARM_REG_SP
                or _imm(base_add.operands[2]) != 4
                or read.operands[1].mem.disp != 0):
            continue
        index = read.operands[1].mem.index
        guard = None
        for cmp_pc in range(pc + 2, min(pc + 0x100, len(image) - 4), 2):
            cmp = facts.decode(CodeAddress(cmp_pc))
            branch = facts.decode(CodeAddress(cmp_pc + 2))
            if (cmp is not None and cmp.id == a.ARM_INS_CMP
                    and len(cmp.operands) == 2
                    and index != count_register
                    and _reg(cmp.operands[0]) == index
                    and _reg(cmp.operands[1]) == count_register
                    and branch is not None and branch.id == a.ARM_INS_B
                    and branch.cc in (a.ARM_CC_LO, a.ARM_CC_LT)
                    and branch.operands and branch.operands[0].imm == pc - 2):
                guard = (cmp_pc, cmp_pc + 2)
                break
        if guard is not None:
            candidates.append((pc, index, base_add.address, guard))
    if len(candidates) != 1:
        return None
    read_pc, index, base_pc, (cmp_pc, branch_pc) = candidates[0]
    try:
        region = facts.function_region(CodeAddress(terminal),
            stop_before=(CodeAddress(read_pc),), budget=1024)
    except (ValueError, RuntimeError):
        return None
    if (region.unresolved or region.truncated
            or CodeAddress(read_pc) not in region.scope_before):
        return None
    successors = {}
    for source, destination in region.control_edges:
        successors.setdefault(source, set()).add(destination)
    call_sites = {site for site, _target in region.calls}
    start = CodeAddress(terminal)
    goal = CodeAddress(read_pc)
    start_regs = {count_register: 1, a.ARM_REG_SP: ("sp", 0)}
    # Each work item carries constants/stack identity, partial NZCV, whether
    # index zero has been established, and the selected source route.
    pending = deque([(start, start_regs, exit_flags, False, (start,))])
    seen = set()
    path = None
    while pending:
        current, registers, flags, index_ready, route = pending.popleft()
        state_key = (current, tuple(sorted(registers.items())), flags,
                     index_ready)
        if state_key in seen:
            continue
        seen.add(state_key)
        if len(seen) > 4096:
            return None
        if current == goal:
            if registers.get(index) == 0 and registers.get(count_register) == 1 and index_ready:
                path = route
                break
            continue
        if current in call_sites:
            continue
        ins = facts.decode(current)
        if (ins is None or ins.id == a.ARM_INS_IT
                or ins.id in (a.ARM_INS_BX, a.ARM_INS_BLX,
                              a.ARM_INS_BL)):
            continue
        if ins.id != a.ARM_INS_B and ins.cc not in (
                a.ARM_CC_AL, a.ARM_CC_INVALID):
            continue
        try:
            _, writes = ins.regs_access()
        except Exception:
            continue
        if count_register in writes or a.ARM_REG_SP in writes:
            continue
        if index_ready and index in writes:
            reinitialize = (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                and len(ins.operands) == 2
                and _reg(ins.operands[0]) == index
                and _imm(ins.operands[1]) == 0)
            if not reinitialize:
                continue
        if (ins.id in (a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH,
                a.ARM_INS_STM, a.ARM_INS_STMDA, a.ARM_INS_STMDB,
                a.ARM_INS_STMIB, a.ARM_INS_PUSH, a.ARM_INS_SWP)
                or any(op.type == a.ARM_OP_MEM for op in ins.operands)
                   and ins.id not in (a.ARM_INS_LDR, a.ARM_INS_LDRB,
                                      a.ARM_INS_LDRH)):
            continue
        next_registers = dict(registers)
        next_flags = flags
        next_index_ready = index_ready

        def operand_value(op):
            if op.type == a.ARM_OP_IMM:
                return op.imm
            if op.type == a.ARM_OP_REG:
                if op.reg == a.ARM_REG_PC:
                    return current.address + 4
                return next_registers.get(op.reg)
            return None

        if ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(ins.operands) == 2:
            dst = _reg(ins.operands[0])
            value = operand_value(ins.operands[1])
            if dst is not None:
                if ins.operands[1].type == a.ARM_OP_REG and any(
                        op.shift.type or op.subtracted for op in ins.operands):
                    value = None
                next_registers[dst] = value
                if dst == index:
                    next_index_ready = value == 0
            if ins.update_flags:
                next_flags = move_flags(value, flags)
        elif ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB) and len(ins.operands) in (2, 3):
            dst = _reg(ins.operands[0])
            source = _reg(ins.operands[1]) if len(ins.operands) == 3 else dst
            right = operand_value(ins.operands[-1])
            left = next_registers.get(source)
            if any(op.shift.type or op.subtracted for op in ins.operands):
                left = right = None
            if isinstance(left, tuple) and left[0] == "sp" and type(right) is int:
                value = ("sp", left[1] + (right if ins.id == a.ARM_INS_ADD else -right))
            elif type(left) is int and type(right) is int:
                value = ((left + right) if ins.id == a.ARM_INS_ADD
                         else (left - right)) & 0xffffffff
            else:
                value = None
            if dst is not None:
                next_registers[dst] = value
                if dst == index:
                    next_index_ready = value == 0
            if ins.update_flags:
                next_flags = (add_flags(left, right) if ins.id == a.ARM_INS_ADD
                              else compare_flags(left, right))
        elif ins.id == a.ARM_INS_CMP and len(ins.operands) == 2:
            next_flags = compare_flags(operand_value(ins.operands[0]),
                                       operand_value(ins.operands[1]))
        elif ins.id in (a.ARM_INS_LDR, a.ARM_INS_LDRB, a.ARM_INS_LDRH,
                        a.ARM_INS_LDRSB, a.ARM_INS_LDRSH):
            if ins.operands and _reg(ins.operands[0]) is not None:
                next_registers[_reg(ins.operands[0])] = None
        else:
            for register in writes:
                if register in next_registers:
                    next_registers[register] = None
            if ins.update_flags or a.ARM_REG_CPSR in writes:
                next_flags = unknown_flags()
            if index in writes:
                next_index_ready = False

        if index in writes and ins.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS,
                                              a.ARM_INS_ADD, a.ARM_INS_SUB):
            next_index_ready = False
        edges = successors.get(current, ())
        if ins.id == a.ARM_INS_B and ins.operands:
            outcome = condition_holds(ins.cc, flags)
            target = ins.operands[0].imm
            taken_flags = refine_flags(ins.cc, flags, True)
            fallthrough_flags = refine_flags(ins.cc, flags, False)
            for edge in edges:
                taken = edge.address == target
                domain = taken_flags if taken else fallthrough_flags
                if (outcome is True and not taken
                        or outcome is False and taken):
                    continue
                if domain:
                    pending.append((edge, dict(next_registers), domain,
                                    next_index_ready, route + (edge,)))
            continue
        elif ins.id != a.ARM_INS_B and (
                ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP)):
            # Do not linearize an unmodeled control-transfer instruction.
            continue
        for target in edges:
            pending.append((target, dict(next_registers), next_flags,
                            next_index_ready, route + (target,)))
    if path is None:
        return None
    path_sites = {site.address for site in path}
    if not {base_pc, cmp_pc, branch_pc}.issubset(path_sites):
        return None
    selected_base = facts.decode(CodeAddress(base_pc))
    if (_reg(facts.decode(CodeAddress(read_pc)).operands[0]) in
            (count_register, index)
            or selected_base is None
            or selected_base.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
        return None
    zero_positions = []
    for position, site in enumerate(path):
        ins = facts.decode(site)
        if (ins is not None and ins.id in (a.ARM_INS_MOVS, a.ARM_INS_MOV)
                and len(ins.operands) == 2
                and _reg(ins.operands[0]) == index
                and _imm(ins.operands[1]) == 0):
            zero_positions.append((position, site.address))
    if not zero_positions:
        return None
    init_position, init_site = zero_positions[-1]
    # The selected path carries the count, stack frame, and queued byte
    # intact. Stores are rejected conservatively because no unrelated write
    # may alias this frame's [SP+4] queue slot.
    for position, site in enumerate(path):
        ins = facts.decode(site)
        if ins is None:
            return None
        if ins.id == a.ARM_INS_IT:
            return None
        if ins.id != a.ARM_INS_B and ins.cc not in (
                a.ARM_CC_AL, a.ARM_CC_INVALID):
            return None
        try:
            _, writes = ins.regs_access()
        except Exception:
            return None
        index_reinit = (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            and len(ins.operands) == 2
            and _reg(ins.operands[0]) == index
            and _imm(ins.operands[1]) == 0)
        if (count_register in writes or a.ARM_REG_SP in writes
                or position > init_position and site.address != read_pc
                and index in writes and not index_reinit):
            return None
        if ins.id in (a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH,
                a.ARM_INS_STM, a.ARM_INS_STMDA, a.ARM_INS_STMDB,
                a.ARM_INS_STMIB, a.ARM_INS_PUSH, a.ARM_INS_SWP):
            return None
        if any(op.type == a.ARM_OP_MEM for op in ins.operands) and ins.id not in (
                a.ARM_INS_LDR, a.ARM_INS_LDRB, a.ARM_INS_LDRH):
            return None
    return {"terminal": terminal, "read_site": read_pc,
            "base_site": base_pc, "index_register": index,
            "count_register": count_register,
            "count_guard": cmp_pc, "guard_branch": branch_pc,
            "index_init": init_site,
            "path": tuple(site.address for site in path),
            "dependencies": {(site.address, facts.decode(site).size)
                             for site in path}}


def prove_halfword_event_buffer(image: bytes, *, event_load: int,
                                event_sink: int, event_register: int,
                                event_codes, event_code: int, handoff):
    """Link the low-contact byte, numeric buffer, count, and consumer read."""
    if not isinstance(image, bytes) or not isinstance(handoff, dict):
        return None
    facts = facts_for(image)
    numeric = _numeric_store(facts, image, event_load, event_sink,
                             event_register, event_codes)
    if numeric is None:
        return None
    routes = handoff.get("event_routes")
    terminals = handoff.get("terminal_sites")
    if not isinstance(routes, tuple) or not isinstance(terminals, tuple):
        return None
    aux_routes = []
    for route in routes:
        if (not isinstance(route, tuple) or len(route) != 8
                or route[0] not in terminals):
            continue
        (target, store_site, count_site, count_register, branch_pc,
         stored_byte, stored_offset, exit_flags) = route
        if type(exit_flags) is not int or not 0 < exit_flags <= 0xffff:
            continue
        store, count_init = (facts.decode(CodeAddress(at))
                             for at in (store_site, count_site))
        if (store is not None and store.id == a.ARM_INS_STRB
                and len(store.operands) == 2
                and _reg(store.operands[0]) is not None
                and store.operands[1].type == a.ARM_OP_MEM
                and stored_offset == 4
                and not store.operands[1].mem.index
                and count_init is not None
                and count_init.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                and len(count_init.operands) == 2
                and _reg(count_init.operands[0]) == count_register
                and _imm(count_init.operands[1]) == 1
                and count_register == numeric["count_register"]):
            if stored_byte != event_code:
                continue
            aux_routes.append((target, store_site, count_site, branch_pc,
                               _reg(store.operands[0]), exit_flags))
    if len(aux_routes) != 1:
        return None
    target, store_site, count_site, branch_pc, event_reg, exit_flags = aux_routes[0]
    # The sideband event may be a separate scanner-state value rather than a
    # member of the keypad ROM map; its tracked byte still shares the queue.
    consumer = _consumer_path(facts, image, target,
                              numeric["count_register"], exit_flags)
    if consumer is None:
        return None
    deps = set(numeric["dependencies"])
    deps.update(consumer["dependencies"])
    deps.update(((store_site, 2), (count_site, 2), (branch_pc, 2)))
    return {"buffer_offset": 4, "count_register": numeric["count_register"] - a.ARM_REG_R0,
            "numeric_store": event_sink, "sideband_store": store_site,
            "consumer_read": consumer["read_site"],
            "consumer_index_register": consumer["index_register"] - a.ARM_REG_R0,
            "consumer_count_guard": consumer["count_guard"],
            "consumer_event_register": (_reg(facts.decode(
                CodeAddress(consumer["read_site"])).operands[0])
                - a.ARM_REG_R0),
            "consumer_terminal": target,
            "dependencies": sorted(deps)}
