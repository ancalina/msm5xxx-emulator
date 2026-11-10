"""Bounded ARM and Thumb control-flow and data-flow traversal."""
from __future__ import annotations
from .fact_models import Literal
from .fact_models import FunctionFacts, BranchCondition, CallSiteFacts, MemoryAccess, SymbolicAccess
from .function_results import finish_function
from .function_states import join
from .instruction_values import adr_target, instruction_values
from .values import (CodeAddress, SymbolicValue, UNKNOWN_VALUE, _FLAGS, _FLAG_ORIGIN_MASK_REGISTER, _FLAG_ORIGIN_REGISTER, _ORIGIN_C, _ORIGIN_N, _ORIGIN_V,
    _ORIGIN_Z, _RECENT_POP_REGISTER, _condition_flag_mask, _condition_holds, _contains_symbolic_load, _symbolic_cost, _symbolic_load, _symbolic_operation)
from capstone import arm as a
from collections import deque
from dataclasses import replace
import capstone as cs

def analyze_function(self, entry: CodeAddress, budget=1024, *, initial_memory: bool = False, initial_registers= None, symbolic_registers=None,
    stop_at_initial_return=False, follow_back_edges=True, _stop_after=frozenset(), _stop_before=frozenset()) -> FunctionFacts:
    """Analyze one bounded CFG with conservative interworking/data flow.

    Initial-memory constants are opt-in because writable RAM snapshots are
    not general execution facts. Any store or opaque call invalidates that
    memory state for the rest of the path; joins retain it only when every
    incoming path still has a valid initial image.
    """
    budget = min(int(budget), 8192)
    if budget <= 0:
        raise ValueError('function budget must be positive')
    initial_registers = dict(initial_registers or {})
    symbolic_requested = symbolic_registers is not None or any(isinstance(value, SymbolicValue) for value in initial_registers.values())
    for register, value in tuple(initial_registers.items()):
        if not isinstance(value, SymbolicValue):
            continue
        count, depth = _symbolic_cost(value)
        if count > 48 or depth > 8:
            raise ValueError('symbolic input exceeds expression budget')
        if value.kind == 'const':
            initial_registers[register] = value.value
        elif value.kind == 'unknown':
            initial_registers[register] = UNKNOWN_VALUE
    symbolic_registers = dict(symbolic_registers or {})
    if any(type(register) is not int or not isinstance(value, SymbolicValue) or value.kind != 'arg' for register, value in symbolic_registers.items()):
        raise ValueError('symbolic registers must map register IDs to argument values')
    if set(initial_registers) & set(symbolic_registers):
        raise ValueError('a register cannot have both concrete and symbolic initial values')
    initial_registers.update(symbolic_registers)
    symbolic_mode = symbolic_requested
    entry_return = initial_registers.get(a.ARM_REG_LR)
    key = (entry, budget, initial_memory, tuple(sorted(initial_registers.items())), stop_at_initial_return, symbolic_mode, follow_back_edges, _stop_after,
        _stop_before)
    with self._lock:
        if key in self._functions:
            return self._functions[key]
        states = {entry: (initial_registers, True, {}, (), {})}
        pending = deque([entry])
        instructions: dict[CodeAddress, CodeAddress] = {}
        calls: dict[CodeAddress, tuple[tuple[CodeAddress, CodeAddress], ...]] = {}
        literals: dict[CodeAddress, Literal] = {}
        accesses: dict[CodeAddress, MemoryAccess] = {}
        symbolic_accesses: dict[CodeAddress, SymbolicAccess] = {}
        call_sites: dict[CodeAddress, CallSiteFacts] = {}
        branch_conditions: dict[CodeAddress, BranchCondition] = {}
        edges: set[tuple[int, int]] = set()
        stacks: dict[CodeAddress, tuple[int, int, int]] = {}
        unresolved: set[CodeAddress] = set()
        flow_targets: dict[CodeAddress, set[CodeAddress]] = {}
        control_edges: dict[CodeAddress, tuple[CodeAddress, ...]] = {}
        loop_frontiers = set()
        scope_exits, scope_escapes = set(), set()
        steps = 0
        symbolic_budget_exhausted = [False]
        def pc_key(pc: CodeAddress):
            return pc.address, pc.isa, pc.phase, pc.bank
        def advance_memory_version(version, site):
            if not symbolic_mode or version is None:
                return version
            if len(version) >= 32:
                symbolic_budget_exhausted[0] = True
                return None
            return version + (site,)
        def record_symbolic(access):
            previous = symbolic_accesses.get(access.instruction)
            if previous is None:
                symbolic_accesses[access.instruction] = access
                return
            address = previous.address if previous.address == access.address else UNKNOWN_VALUE
            value = previous.value if previous.value == access.value else UNKNOWN_VALUE
            symbolic_accesses[access.instruction] = replace(previous, address=address, value=value)
        while pending and steps < budget:
            pc = pending.popleft()
            steps += 1
            at, ins = pc.address, self.decode(pc)
            calls.pop(pc, None)
            call_sites.pop(pc, None)
            literals.pop(pc, None)
            accesses.pop(pc, None)
            stacks.pop(pc, None)
            flow_targets.pop(pc, None)
            control_edges.pop(pc, None)
            scope_exits.discard(pc)
            scope_escapes.discard(pc)
            pc_flow_targets: set[CodeAddress] = set()
            if ins is None:
                unresolved.add(pc)
                continue
            unresolved.discard(pc)
            instructions[pc] = pc
            if pc in _stop_before:
                scope_exits.add(pc)
                control_edges[pc] = ()
                continue
            before, memory_valid, pending_conditions, memory_version, before_sources = states[pc]
            condition = _condition_holds(ins.cc, before)
            if condition is False:
                successor = CodeAddress(at + ins.size, pc.isa, pc.phase, pc.bank)
                control_edges[pc] = (successor,)
                incoming = (dict(before), memory_valid, dict(pending_conditions), memory_version, dict(before_sources))
                if successor not in states:
                    states[successor] = incoming
                    pending.append(successor)
                else:
                    merged, changed = join(states[successor], incoming)
                    if changed:
                        states[successor] = merged
                        pending.append(successor)
                continue
            regs = dict(before)
            register_sources = dict(before_sources)
            popped_return_register = regs.pop(_RECENT_POP_REGISTER, None)
            pending_conditions = dict(pending_conditions)
            regs[a.ARM_REG_PC] = ((at + 4) & ~3 if pc.isa == 'thumb' else at + 8)
            operands = ins.operands
            literal = self.literal(pc)
            (value, memory_constant, address_expression, flag_expression, source_value, source_operation, flags) = instruction_values(self, pc, operands, regs,
                register_sources, initial_memory, memory_valid, symbolic_budget_exhausted, ins)
            assigned = {}
            source_assigned = {}
            flag_origin = None
            flag_origin_mask = 0
            unshifted = not any(op.shift.type for op in operands)
            if (ins.id in (a.ARM_INS_TST, a.ARM_INS_TEQ) and len(operands) == 2 and unshifted):
                left, right = value(operands[0]), value(operands[1])
                if symbolic_mode and not any(op.shift.type for op in operands):
                    flag_origin = flag_expression('tst' if ins.id == a.ARM_INS_TST else 'teq', (source_value(operands[0], left), source_value(operands[1], right)))
                    if flag_origin is not None:
                        flag_origin_mask = _ORIGIN_N | _ORIGIN_Z
            elif (ins.id in (a.ARM_INS_CMP, a.ARM_INS_CMN) and len(operands) == 2 and unshifted):
                left, right = value(operands[0]), value(operands[1])
                if symbolic_mode:
                    flag_origin = flag_expression('cmp' if ins.id == a.ARM_INS_CMP else 'cmn', (source_value(operands[0], left), source_value(operands[1], right)))
                    if flag_origin is not None:
                        flag_origin_mask = (_ORIGIN_N | _ORIGIN_Z | _ORIGIN_C | _ORIGIN_V)
            if literal is not None:
                literals[pc] = literal
                assigned[literal.register] = literal.value
            elif ins.id == a.ARM_INS_ADR and len(operands) == 2:
                assigned[operands[0].reg] = adr_target(ins, at, pc.isa)
            elif ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(operands) == 2:
                assigned[operands[0].reg] = value(operands[1])
                if symbolic_mode:
                    source = source_value(operands[1], value(operands[1]))
                    if isinstance(source, SymbolicValue) and _contains_symbolic_load(source):
                        source_assigned[operands[0].reg] = source
            elif ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB, a.ARM_INS_AND, a.ARM_INS_ORR, a.ARM_INS_EOR, a.ARM_INS_LSL, a.ARM_INS_LSR) and len(operands) in (2, 3):
                left, right = ((value(operands[0]), value(operands[1])) if len(operands) == 2 else (value(operands[1]), value(operands[2])))
                if left is not None and right is not None:
                    operation = { a.ARM_INS_ADD: 'add', a.ARM_INS_SUB: 'sub', a.ARM_INS_AND: 'and', a.ARM_INS_ORR: 'or', a.ARM_INS_EOR: 'xor', a.ARM_INS_LSL:
                        'lsl', a.ARM_INS_LSR: 'lsr', }[ins.id]
                    source_operands = ((operands[0], operands[1]) if len(operands) == 2 else (operands[1], operands[2]))
                    source_inputs = (source_value(source_operands[0], left), source_value(source_operands[1], right))
                    if any(op.shift.type for op in operands):
                        assigned[operands[0].reg] = None
                    else:
                        if (ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR) and operands[-1].type == a.ARM_OP_REG):
                            right = _symbolic_operation('and', right, 0xFF, budget_exhausted= symbolic_budget_exhausted)
                        assigned[operands[0].reg] = _symbolic_operation(operation, left, right, budget_exhausted=symbolic_budget_exhausted)
                        if symbolic_mode:
                            source = source_operation(operation, source_inputs)
                            if source is not None:
                                source_assigned[operands[0].reg] = source
                    if (symbolic_mode and ins.update_flags and not any(op.shift.type for op in operands)):
                        flag_origin = flag_expression(operation, source_inputs)
                        if flag_origin is not None:
                            flag_origin_mask = _ORIGIN_N | _ORIGIN_Z
                        if symbolic_mode and ins.update_flags:
                            flag_origin = flag_expression(operation, (left, right))
            loads = {a.ARM_INS_LDR: 4, a.ARM_INS_LDRB: 1, a.ARM_INS_LDRH: 2}
            stores_ins = {a.ARM_INS_STR: 4, a.ARM_INS_STRB: 1, a.ARM_INS_STRH: 2}
            symbolic_loads = {**loads, a.ARM_INS_LDRSB: 1, a.ARM_INS_LDRSH: 2}
            signed_loads = {a.ARM_INS_LDRSB, a.ARM_INS_LDRSH}
            memory_operand = next((op.mem for op in operands if op.type == a.ARM_OP_MEM), None)
            # Unknown destinations can alias any initialized RAM descriptor.
            # Stack and multiple-register stores have no MEM operand in
            # some Capstone versions, so include them explicitly.
            did_store = (ins.id in stores_ins or ins.mnemonic.startswith(('stm', 'push', 'swp', 'str', 'vst')) or memory_operand is not None and ins.id not in
                loads and ins.id not in (a.ARM_INS_LDRSB, a.ARM_INS_LDRSH))
            memory_read = (ins.id in loads or symbolic_mode and ins.id in signed_loads)
            memory_write = ins.id in stores_ins
            if memory_read or memory_write:
                width = (symbolic_loads if memory_read else stores_ins)[ins.id]
                operation = 'read' if memory_read else 'write'
                address_expr = (address_expression(memory_operand) if memory_operand is not None else UNKNOWN_VALUE)
                base = (regs.get(memory_operand.base) if memory_operand is not None else None)
                concrete_address = ((base + memory_operand.disp) & 0xFFFFFFFF if type(base) is int and not memory_operand.index else None)
                access_value = value(operands[0]) if memory_write else None
                # Preserve the legacy concrete access surface exactly.
                if concrete_address is not None and ins.id in loads | stores_ins:
                    accesses[pc] = MemoryAccess(pc, operation, concrete_address, width, access_value if type(access_value) is int else None, (at,), ins.cc,)
                if memory_read:
                    raw = (memory_constant(concrete_address, width) if concrete_address is not None else None)
                    if raw is not None:
                        loaded = int.from_bytes(raw, 'little', signed=ins.id in signed_loads) & 0xFFFFFFFF
                        if operands and operands[0].type == a.ARM_OP_REG:
                            assigned[operands[0].reg] = loaded
                        value_expr = SymbolicValue.const(loaded)
                    else:
                        value_expr = (_symbolic_load(address_expr, width, ins.id in signed_loads, pc, memory_version, budget_exhausted=symbolic_budget_exhausted,)
                            if symbolic_mode else UNKNOWN_VALUE)
                        if (value_expr is not UNKNOWN_VALUE and operands and operands[0].type == a.ARM_OP_REG):
                            assigned[operands[0].reg] = value_expr
                    if (symbolic_mode and not (isinstance(value_expr, SymbolicValue) and value_expr.kind == 'const') and operands and operands[0].type == a.ARM_OP_REG):
                        # This source-only node is not used as a loaded
                        # value; value_expr retains memory-version identity.
                        source = SymbolicValue('load', operands=(address_expr,), width=width, signed=ins.id in signed_loads, site=pc,)
                        count, depth = _symbolic_cost(source)
                        if count > 48 or depth > 8:
                            symbolic_budget_exhausted[0] = True
                        else:
                            source_assigned[operands[0].reg] = source
                    if symbolic_mode:
                        record_symbolic(SymbolicAccess(pc, operation, address_expr if address_expr is not None else UNKNOWN_VALUE, width, value_expr, ins.cc,))
                elif symbolic_mode:
                    value_expr = (SymbolicValue.const(access_value) if type(access_value) is int else access_value if isinstance(access_value, SymbolicValue)
                        else UNKNOWN_VALUE)
                    record_symbolic(SymbolicAccess(pc, operation, address_expr if address_expr is not None else UNKNOWN_VALUE, width, value_expr, ins.cc,))
                if memory_write:
                    did_store = True
            cpsr_fields = (a.ARM_SYSREG_CPSR_C | a.ARM_SYSREG_CPSR_X | a.ARM_SYSREG_CPSR_S | a.ARM_SYSREG_CPSR_F)
            is_msr_control = (ins.id == a.ARM_INS_MSR and operands and operands[0].type == a.ARM_OP_SYSREG and operands[0].reg & a.ARM_SYSREG_CPSR_C and not
                operands[0].reg & ~cpsr_fields)
            if is_msr_control:
                mode_value = value(operands[-1])
                valid_modes = {0x10, 0x11, 0x12, 0x13, 0x17, 0x1B, 0x1F}
                old_mode = regs.get(-1)
                new_mode = mode_value & 31 if type(mode_value) is int else None
                if new_mode not in valid_modes:
                    new_mode = None
                unconditional = condition is True
                assigned[-1] = new_mode if unconditional else None
                if not unconditional or old_mode is None or new_mode is None:
                    regs.pop(a.ARM_REG_SP, None)
                    regs.pop(a.ARM_REG_LR, None)
                    register_sources.pop(a.ARM_REG_SP, None)
                    register_sources.pop(a.ARM_REG_LR, None)
                    for register in (a.ARM_REG_R8, a.ARM_REG_R9, a.ARM_REG_R10, a.ARM_REG_R11, a.ARM_REG_R12):
                        regs.pop(register, None)
                        register_sources.pop(register, None)
                    regs.pop(-1, None)
                elif old_mode != new_mode:
                    regs.pop(a.ARM_REG_SP, None)
                    regs.pop(a.ARM_REG_LR, None)
                    register_sources.pop(a.ARM_REG_SP, None)
                    register_sources.pop(a.ARM_REG_LR, None)
                    if old_mode == 0x11 or new_mode == 0x11:
                        for register in (a.ARM_REG_R8, a.ARM_REG_R9, a.ARM_REG_R10, a.ARM_REG_R11, a.ARM_REG_R12):
                            regs.pop(register, None)
                            register_sources.pop(register, None)
            try:
                _, written = ins.regs_access()
            except cs.CsError:
                calls.pop(pc, None)
                literals.pop(pc, None)
                accesses.pop(pc, None)
                stacks.pop(pc, None)
                unresolved.add(pc)
                continue
            for register in written:
                regs.pop(register, None)
                register_sources.pop(register, None)
            if a.ARM_REG_CPSR in written:
                for flag in _FLAGS:
                    regs.pop(flag, None)
            if condition is True:
                regs.update(flags)
            updates_status = (ins.update_flags or ins.id in (a.ARM_INS_CMP, a.ARM_INS_CMN, a.ARM_INS_TST, a.ARM_INS_TEQ))
            if (a.ARM_REG_CPSR in written or updates_status) and symbolic_mode:
                regs[_FLAG_ORIGIN_REGISTER] = (flag_origin if condition is True and flag_origin is not None else UNKNOWN_VALUE)
                regs[_FLAG_ORIGIN_MASK_REGISTER] = (flag_origin_mask if condition is True and flag_origin is not None else 0)
            complementary = {1: 2, 2: 1, 3: 4, 4: 3, 5: 6, 6: 5, 7: 8, 8: 7, 9: 10, 10: 9, 11: 12, 12: 11, 13: 14, 14: 13}
            # Pair complementary predicated constant writes only while the
            # condition flags remain unchanged and control stays linear.
            if updates_status or a.ARM_REG_CPSR in written or ins.group(cs.CS_GRP_JUMP):
                pending_conditions.clear()
            pairable = ({register for register, constant in assigned.items() if constant is not None and ins.cc in complementary} if condition is None and ins.cc
                in complementary else set())
            for register in written:
                if register not in pairable:
                    pending_conditions = {key: val for key, val in pending_conditions.items() if key[0] != register}
            for register, constant in assigned.items():
                shifted = any(op.shift.type for op in operands)
                if (constant is not None and not shifted and condition is True):
                    regs[register] = constant
                elif (constant is not None and not shifted and ins.cc in complementary):
                    previous = pending_conditions.get((register, complementary[ins.cc]))
                    if previous == constant:
                        regs[register] = constant
                        pending_conditions = {key: val for key, val in pending_conditions.items() if key[0] != register}
                    else:
                        regs.pop(register, None)
                        pending_conditions[(register, ins.cc)] = constant
                else:
                    regs.pop(register, None)
            if condition is True:
                register_sources.update(source_assigned)
            if (a.ARM_REG_SP in written and condition is True and type(regs.get(-1)) is int and type(regs.get(a.ARM_REG_SP)) is int):
                stacks[pc] = (at, regs[-1], regs[a.ARM_REG_SP])
            if (ins.id == a.ARM_INS_POP and condition is True and len(operands) == 1 and operands[0].type == a.ARM_OP_REG and operands[0].reg != a.ARM_REG_PC):
                regs[_RECENT_POP_REGISTER] = operands[0].reg
            if (symbolic_mode and ins.id == a.ARM_INS_B and ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                origin = before.get(_FLAG_ORIGIN_REGISTER)
                origin_mask = before.get(_FLAG_ORIGIN_MASK_REGISTER, 0)
                required_flags = _condition_flag_mask(ins.cc)
                branch_conditions[pc] = BranchCondition(pc, ins.cc, origin if isinstance(origin, SymbolicValue) and origin is not UNKNOWN_VALUE and type(origin_mask)
                    is int and origin_mask & required_flags == required_flags else None,)
            if pc in _stop_after:
                if condition is True:
                    scope_exits.add(pc)
                    control_edges[pc] = ()
                    continue
                scope_escapes.add(pc)
            successors: list[CodeAddress] = []
            fallthrough = CodeAddress(at + ins.size, pc.isa, pc.phase, pc.bank)
            conditional = condition is None
            if ins.group(cs.CS_GRP_CALL):
                target = None
                target_isa = pc.isa
                if operands and operands[0].type == a.ARM_OP_IMM:
                    target = operands[0].imm & 0xFFFFFFFF
                    if ins.id == a.ARM_INS_BLX:
                        target_isa = 'arm' if pc.isa == 'thumb' else 'thumb'
                elif (ins.id == a.ARM_INS_BLX and operands and operands[0].type == a.ARM_OP_REG):
                    pointer = regs.get(operands[0].reg)
                    if type(pointer) is int:
                        target = pointer & 0xFFFFFFFE
                        target_isa = 'thumb' if pointer & 1 else 'arm'
                if target is None:
                    unresolved.add(pc)
                else:
                    calls[pc] = ((pc, CodeAddress(target, target_isa, pc.phase, pc.bank)),)
                    registers = tuple((register, before.get(register))
                                      for register in (
                                          *(getattr(a, f'ARM_REG_R{i}')
                                            for i in range(13)), a.ARM_REG_SP))
                    call_sites[pc] = CallSiteFacts(pc, CodeAddress(target, target_isa, pc.phase, pc.bank), registers)
                successors.append(fallthrough)
                for register in (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3, a.ARM_REG_R12, a.ARM_REG_LR, a.ARM_REG_CPSR):
                    regs.pop(register, None)
                    register_sources.pop(register, None)
                regs.pop(a.ARM_REG_PC, None)
                regs.pop(-1, None)
                for flag in _FLAGS:
                    regs.pop(flag, None)
                regs.pop(_FLAG_ORIGIN_REGISTER, None)
                regs.pop(_FLAG_ORIGIN_MASK_REGISTER, None)
                memory_valid = False
                memory_version = advance_memory_version(memory_version, pc)
            elif ins.group(cs.CS_GRP_INT):
                unresolved.add(pc)
            elif ins.group(cs.CS_GRP_JUMP) or a.ARM_REG_PC in written:
                immediate = (operands[0].imm & 0xFFFFFFFF if operands and operands[0].type == a.ARM_OP_IMM else None)
                target = None
                target_isa = pc.isa
                is_return = False
                if immediate is not None:
                    target = immediate
                elif ins.id == a.ARM_INS_BX and operands and operands[0].type == a.ARM_OP_REG:
                    reg = operands[0].reg
                    is_return = reg == a.ARM_REG_LR or reg == popped_return_register
                    pointer = regs.get(reg)
                    if reg == a.ARM_REG_PC:
                        pointer = ((at + 4) & ~3 if pc.isa == 'thumb' else at + 8)
                    if type(pointer) is int:
                        target = pointer & 0xFFFFFFFE
                        target_isa = 'thumb' if pointer & 1 else 'arm'
                        if stop_at_initial_return and pointer == entry_return:
                            is_return = True
                            target = None
                    if reg != a.ARM_REG_LR and type(regs.get(a.ARM_REG_LR)) is int:
                        return_pointer = regs[a.ARM_REG_LR]
                        pc_flow_targets.add(CodeAddress(return_pointer & ~1, 'thumb' if return_pointer & 1 else 'arm', pc.phase, pc.bank))
                elif (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(operands) == 2 and operands[0].type == a.ARM_OP_REG and operands[0].reg == a.ARM_REG_PC):
                    reg = operands[1].reg if operands[1].type == a.ARM_OP_REG else None
                    is_return = reg == a.ARM_REG_LR
                    pointer = value(operands[1])
                    if type(pointer) is int:
                        target = pointer & ~3 if pc.isa == 'arm' else pointer & ~1
                        if stop_at_initial_return and pointer == entry_return:
                            is_return = True
                            target = None
                elif ins.id == a.ARM_INS_POP:
                    is_return = True
                if conditional:
                    successors.append(fallthrough)
                if target is not None:
                    successor = CodeAddress(target, target_isa, pc.phase, pc.bank)
                    successors.append(successor)
                    pc_flow_targets.add(successor)
                    if target <= at:
                        edges.add((at, target))
                elif not is_return:
                    unresolved.add(pc)
            else:
                successors.append(fallthrough)
            if (_stop_after or _stop_before) and not successors:
                scope_escapes.add(pc)
            if did_store:
                memory_valid = False
                memory_version = advance_memory_version(memory_version, pc)
            if pc_flow_targets:
                flow_targets[pc] = pc_flow_targets
            control_edges[pc] = tuple(successors)
            for target in successors:
                if not follow_back_edges and target.address <= at:
                    loop_frontiers.add((pc, target))
                    continue
                outgoing = ({reg: val for reg, val in regs.items() if reg != a.ARM_REG_PC}, memory_valid, dict(pending_conditions), advance_memory_version(memory_version,
                    pc) if target.address <= at else memory_version, dict(register_sources))
                if target not in states:
                    states[target] = outgoing
                    pending.append(target)
                else:
                    merged, changed = join(states[target], outgoing)
                    if changed:
                        states[target] = merged
                        pending.append(target)
        result = finish_function(entry=entry, instructions=instructions, calls=calls, literals=literals, accesses=accesses, edges=edges, stacks=stacks,
            unresolved=unresolved, pending=pending, flow_targets= flow_targets, control_edges=control_edges, symbolic_accesses=symbolic_accesses, call_sites=
            call_sites, branch_conditions=branch_conditions, loop_frontiers=loop_frontiers, scope_exits= scope_exits, scope_escapes=scope_escapes,
            initial_registers=initial_registers, pc_key=pc_key, symbolic_budget_exhausted=symbolic_budget_exhausted, _stop_after=_stop_after, _stop_before=
            _stop_before,)
        self._functions[key] = result
        self._function_ids.add(id(result))
        return result
