"""Shared CFG, memory-effect, and reaching-definition primitives."""
from __future__ import annotations

from capstone import arm as a

from .facts import (CodeAddress, FirmwareFacts, FunctionFacts,
                    LiteralAccessCandidate)
from .startup_models import StartupSideEffectWrite

def _memory_register(instruction, operation):
    if (instruction is not None and instruction.id == operation
            and operation in (a.ARM_INS_LDM, a.ARM_INS_STM)
            and instruction.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            and instruction.size == 2 and instruction.writeback
            and len(instruction.operands) == 2):
        encoded = int.from_bytes(instruction.bytes, 'little')
        base, transferred = instruction.operands
        if (encoded & 0xf000 != 0xc000
                or bool(encoded & 0x0800) != (operation == a.ARM_INS_LDM)
                or base.type != a.ARM_OP_REG
                or transferred.type != a.ARM_OP_REG
                or base.reg == transferred.reg
                or instruction.reg_name(base.reg) not in
                    {f'r{index}' for index in range(8)}
                or instruction.reg_name(transferred.reg) not in
                    {f'r{index}' for index in range(8)}):
            return None
        return transferred.reg, base.reg
    if (instruction is None or instruction.id != operation
            or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or len(instruction.operands) != 2):
        return None
    destination, memory = instruction.operands
    if (destination.type != a.ARM_OP_REG or memory.type != a.ARM_OP_MEM
            or memory.mem.index or memory.mem.disp or memory.mem.base in
            (a.ARM_REG_PC, a.ARM_REG_INVALID) or instruction.writeback):
        return None
    return destination.reg, memory.mem.base

def _pc_literal_load(instruction):
    return (instruction is not None and instruction.id == a.ARM_INS_LDR
            and len(instruction.operands) == 2
            and instruction.operands[0].type == a.ARM_OP_REG
            and instruction.operands[1].type == a.ARM_OP_MEM
            and instruction.operands[1].mem.base == a.ARM_REG_PC
            and not instruction.operands[1].mem.index
            and not instruction.writeback)

def _add_immediate(instruction, register, immediate):
    if (instruction is None or instruction.id != a.ARM_INS_ADD
            or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
        return False
    operands = instruction.operands
    if len(operands) == 2:
        return (operands[0].type == a.ARM_OP_REG
                and operands[0].reg == register
                and operands[1].type == a.ARM_OP_IMM
                and operands[1].imm == immediate)
    return (len(operands) == 3
            and operands[0].type == a.ARM_OP_REG
            and operands[0].reg == register
            and operands[1].type == a.ARM_OP_REG
            and operands[1].reg == register
            and operands[2].type == a.ARM_OP_IMM
            and operands[2].imm == immediate)

def _increment_sites(facts, function, nodes, decoded, register,
                     field_references, cut_edge, branch_pc, *, rotated=False,
                     require_field_origin=True):
    """Find a proven +4 cursor update, including a temporary plus ADD#0."""
    result = []
    for pc in nodes:
        instruction = decoded.get(pc)
        multiple = (_memory_register(instruction, a.ARM_INS_LDM)
                    or _memory_register(instruction, a.ARM_INS_STM))
        if (multiple is not None and multiple[1] == register
                and (not require_field_origin or any(_definition_reaches(
                    facts, function, ref.use, pc, register, cut_edge)
                    for ref in field_references))
                and ((function.linear_path(pc, branch_pc) is not None)
                     if rotated else function.dominates(pc, branch_pc))):
            result.append(pc)
            continue
        if (instruction is None or instruction.id != a.ARM_INS_ADD
                or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(instruction.operands) not in (2, 3)):
            continue
        if len(instruction.operands) == 2:
            destination, immediate = instruction.operands
            if (destination.type == a.ARM_OP_REG and destination.reg == register
                    and immediate.type == a.ARM_OP_IMM and immediate.imm == 4
                    and (not require_field_origin or any(_definition_reaches(
                        facts, function, ref.use, pc, register, cut_edge)
                            for ref in field_references))
                    and function.dominates(pc, branch_pc)):
                result.append(pc)
            continue
        destination, source, immediate = instruction.operands
        if (destination.type != a.ARM_OP_REG
                or source.type != a.ARM_OP_REG or source.reg != register
                or immediate.type != a.ARM_OP_IMM or immediate.imm != 4
                or require_field_origin and not any(_definition_reaches(
                    facts, function, ref.use, pc, register, cut_edge)
                           for ref in field_references)):
            continue
        if destination.reg == register:
            if ((function.linear_path(pc, branch_pc) is not None) if rotated
                    else function.dominates(pc, branch_pc)):
                result.append(pc)
            continue
        for alias_pc in nodes:
            alias = decoded.get(alias_pc)
            if (alias is None or alias.id != a.ARM_INS_ADD
                    or alias.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                    or len(alias.operands) != 3):
                continue
            out, alias_source, amount = alias.operands
            if (out.type == a.ARM_OP_REG and out.reg == register
                    and alias_source.type == a.ARM_OP_REG
                    and alias_source.reg == destination.reg
                    and amount.type == a.ARM_OP_IMM and amount.imm == 0
                    and (function.linear_path(pc, alias_pc) is not None
                         if rotated else function.dominates(pc, alias_pc))
                    and ((function.linear_path(alias_pc, branch_pc) is not None)
                         if rotated else function.dominates(alias_pc, branch_pc))
                    and _definition_reaches(facts, function, pc, alias_pc,
                                            destination.reg, cut_edge)):
                result.append(alias_pc)
    return tuple(result)

def _loop_nodes(function: FunctionFacts, edge: tuple[int, int]):
    branch_address, header_address = edge
    by_address = {pc.address: pc for pc in function.instructions}
    branch, header = by_address.get(branch_address), by_address.get(header_address)
    if branch is None or header is None:
        return None
    successors = {}
    predecessors = {}
    for source, target in function.control_edges:
        successors.setdefault(source, []).append(target)
        predecessors.setdefault(target, []).append(source)
    cut = (branch, header)
    forward = set()
    pending = [header]
    while pending:
        pc = pending.pop()
        if pc in forward:
            continue
        forward.add(pc)
        pending.extend(target for target in successors.get(pc, ())
                       if (pc, target) != cut and target not in forward)
    backward = set()
    pending = [branch]
    while pending:
        pc = pending.pop()
        if pc in backward:
            continue
        backward.add(pc)
        pending.extend(source for source in predecessors.get(pc, ())
                       if (source, pc) != cut and source not in backward)
    nodes = forward & backward
    return nodes if header in nodes and branch in nodes and (branch, header) in function.control_edges else None

def _loop_iteration_cut(function: FunctionFacts, nodes,
                        back_edge: tuple[int, int]):
    """Return the unique internal edge that ends one first-iteration pass.

    Some loops branch back to their body while their shared compare is rotated
    after the body. In that form, the first pass enters the compare from outside
    the loop and returns from the body through a different internal edge.
    """
    incoming = {}
    for source, target in function.control_edges:
        if target not in nodes:
            continue
        if source not in nodes:
            incoming.setdefault(target, []).append((source, target))
    if len(incoming) != 1:
        return None
    entry = next(iter(incoming))
    recurrence = tuple((source, target)
                       for source, target in function.control_edges
                       if source in nodes and target == entry)
    if len(recurrence) != 1:
        return None
    edge = recurrence[0]
    sample = next(iter(nodes))
    selected = tuple(CodeAddress(address, sample.isa, sample.phase, sample.bank)
                     for address in back_edge)
    if edge == selected:
        return ((edge[0].address, edge[1].address), edge[0].address)
    if selected not in function.control_edges:
        return None
    return ((edge[0].address, edge[1].address), edge[0].address)

def _dominates_iteration(function, nodes, site, cut_edge):
    """Check whether every first-iteration path to the latch crosses site."""
    incoming = tuple((source, target) for source, target in function.control_edges
                     if target in nodes and source not in nodes)
    if len(incoming) != 1:
        return False
    start = incoming[0][1]
    sample = start
    cut = tuple(CodeAddress(address, sample.isa, sample.phase, sample.bank)
                for address in cut_edge)
    edges = {}
    for source, target in function.control_edges:
        if source in nodes and target in nodes and (source, target) != cut:
            edges.setdefault(source, []).append(target)
    recurrence_address = cut[0]

    def reaches_recurrence(blocked):
        pending, seen = [start], set()
        while pending:
            current = pending.pop()
            if current == blocked or current in seen:
                continue
            if current == recurrence_address:
                return True
            seen.add(current)
            pending.extend(edges.get(current, ()))
        return False

    return (site in nodes and not reaches_recurrence(site)
            and reaches_recurrence(None))

def _use_register(facts: FirmwareFacts,
                  reference: LiteralAccessCandidate) -> int | None:
    result = _memory_register(facts.decode(reference.use), a.ARM_INS_LDR)
    return result[0] if result is not None else None

def _move_zero(instruction, register):
    return (instruction is not None
            and instruction.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            and instruction.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            and len(instruction.operands) == 2
            and instruction.operands[0].type == a.ARM_OP_REG
            and instruction.operands[0].reg == register
            and instruction.operands[1].type == a.ARM_OP_IMM
            and instruction.operands[1].imm == 0)

def _zero_destination(instruction):
    if (instruction is None
            or instruction.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or len(instruction.operands) != 2
            or instruction.operands[0].type != a.ARM_OP_REG
            or instruction.operands[1].type != a.ARM_OP_IMM
            or instruction.operands[1].imm != 0):
        return None
    return instruction.operands[0].reg

def _loop_writes_are_safe(function, nodes, selected_store, protected_ranges,
                          extra_write_ranges=()):
    """Return explicit allowed extra stores, or None if one is unsafe."""
    if any(site in nodes for site, _ in function.calls):
        return None
    instructions = {
        CodeAddress(instruction.address, instruction.isa,
                    instruction.phase, instruction.bank): instruction
        for instruction in function.instructions
    }
    allowed = []
    for access in function.symbolic_accesses:
        if access.operation != 'write' or access.instruction not in nodes:
            continue
        if access.instruction == selected_store:
            continue
        if access.address.kind != 'const':
            return None
        lo, hi = access.address.value, access.address.value + access.width
        if any(max(lo, start) < min(hi, end) for start, end in protected_ranges):
            return None
        if not any(start <= lo and hi <= end
                   for start, end in extra_write_ranges):
            return None
        value = (access.value.value if access.value is not None
                 and access.value.kind == 'const' else None)
        instruction = instructions.get(access.instruction)
        if instruction is None:
            return None
        allowed.append(StartupSideEffectWrite(
            CodeAddress(instruction.address, instruction.isa,
                        instruction.phase, instruction.bank),
            lo, access.width, value))
    return tuple(sorted(set(allowed), key=lambda item: (
        item.instruction.address, item.address, item.width, item.value or 0)))

def _definition_reaches(facts: FirmwareFacts, function: FunctionFacts,
                        definition: CodeAddress, use: CodeAddress,
                        register: int, cut_edge: tuple[int, int]) -> bool:
    edge = tuple(CodeAddress(address, use.isa, use.phase, use.bank)
                 for address in cut_edge)
    origins = facts.register_origins(function, use, register,
                                     cut_edges=(edge,))
    return (origins is not None and len(origins) == 1
            and origins[0][0] == definition)

def _field_reaches_value(facts, function, use, register, field_references,
                         cut_edge, active=frozenset()):
    """Follow bounded arithmetic definitions back to one supplied table field."""
    key = (use, register)
    if key in active or len(active) >= 24:
        return False
    definitions = facts.reaching_definitions(
        function, use, register,
        cut_edges=(tuple(CodeAddress(address, use.isa, use.phase, use.bank)
                         for address in cut_edge),))
    if not definitions:
        return False
    field_uses = {item.use for item in field_references}
    for definition in definitions:
        if definition in field_uses:
            continue
        instruction = facts.decode(definition)
        if (instruction is None
                or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or instruction.id not in (
                    a.ARM_INS_MOV, a.ARM_INS_MOVS, a.ARM_INS_ADD,
                    a.ARM_INS_SUB, a.ARM_INS_AND, a.ARM_INS_ORR,
                    a.ARM_INS_EOR, a.ARM_INS_LSL, a.ARM_INS_LSR)
                or not instruction.operands
                or instruction.operands[0].type != a.ARM_OP_REG
                or instruction.operands[0].reg != register):
            return False
        sources = tuple(item.reg for item in instruction.operands[1:]
                        if item.type == a.ARM_OP_REG)
        if not sources or not any(
                _field_reaches_value(facts, function, definition, source,
                                     field_references, cut_edge,
                                     active | {key})
                for source in sources):
            return False
    return True

