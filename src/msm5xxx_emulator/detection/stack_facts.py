"""Relative stack-frame facts for a complete, locally owned function CFG."""
from __future__ import annotations
from dataclasses import dataclass
from capstone import CS_GRP_INT, CS_GRP_RET
from capstone import arm as a
from .facts import CodeAddress, FirmwareFacts, FunctionFacts

_UNCONDITIONAL = (a.ARM_CC_AL, a.ARM_CC_INVALID)
_SCALAR_WIDTHS = { a.ARM_INS_LDR: ("read", 4), a.ARM_INS_LDRB: ("read", 1), a.ARM_INS_LDRH: ("read", 2), a.ARM_INS_LDRSB: ("read", 1), a.ARM_INS_LDRSH: ("read",
    2), a.ARM_INS_STR: ("write", 4), a.ARM_INS_STRB: ("write", 1), a.ARM_INS_STRH: ("write", 2), }
_ARCH_REGS = {getattr(a, f"ARM_REG_R{index}"): index for index in range(13)}
_ARCH_REGS.update({a.ARM_REG_SP: 13, a.ARM_REG_LR: 14, a.ARM_REG_PC: 15})

@dataclass(frozen=True, slots=True)
class StackAccess:
    """One scalar or register-list access, relative to the entry SP."""

    site: CodeAddress
    operation: str
    offset: int
    width: int
    register: int

@dataclass(frozen=True, slots=True)
class StackFrame:
    """A complete SP-relative analysis; it makes no physical-SP claim."""

    entry: CodeAddress
    offsets: tuple[tuple[CodeAddress, int], ...]
    accesses: tuple[StackAccess, ...]
    exit_offsets: tuple[tuple[CodeAddress, int], ...]
    balanced: bool
    complete: bool
    stopped_offsets: tuple[tuple[CodeAddress, int], ...] = ()

    def offset_at(self, site: CodeAddress) -> int | None:
        return dict(self.offsets).get(site)

def _register_list(instruction) -> tuple[int, ...] | None:
    if not instruction.operands or any(operand.type != a.ARM_OP_REG for operand in instruction.operands):
        return None
    registers = tuple(operand.reg for operand in instruction.operands)
    if (len(registers) != len(set(registers)) or any(register not in _ARCH_REGS or register == a.ARM_REG_SP for register in registers)):
        return None
    return tuple(sorted(registers, key=_ARCH_REGS.__getitem__))

def _stack_adjustment(instruction) -> int | None:
    if (instruction.id not in (a.ARM_INS_ADD, a.ARM_INS_SUB) or instruction.cc not in _UNCONDITIONAL or instruction.writeback):
        return None
    operands = instruction.operands
    if len(operands) == 2:
        destination, amount = operands
        if destination.type != a.ARM_OP_REG or destination.reg != a.ARM_REG_SP:
            return None
    elif len(operands) == 3:
        destination, source, amount = operands
        if (destination.type != a.ARM_OP_REG or destination.reg != a.ARM_REG_SP or source.type != a.ARM_OP_REG or source.reg != a.ARM_REG_SP):
            return None
    else:
        return None
    if amount.type != a.ARM_OP_IMM or amount.imm < 0:
        return None
    if any(operand.shift.type for operand in operands):
        return None
    return amount.imm if instruction.id == a.ARM_INS_ADD else -amount.imm

def _return_instruction(instruction) -> bool:
    if instruction.group(CS_GRP_RET):
        return True
    operands = instruction.operands
    # This helper is used only for terminals of an owned, complete CFG.
    # Unknown BX registers make that CFG incomplete; a popped return register
    # is also a normal ARMv4T return and has no outgoing control edge.
    if (instruction.id == a.ARM_INS_BX and operands and operands[0].type == a.ARM_OP_REG):
        return True
    if (instruction.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(operands) == 2 and operands[0].type == a.ARM_OP_REG and operands[0].reg == a.ARM_REG_PC and
        operands[1].type == a.ARM_OP_REG and operands[1].reg == a.ARM_REG_LR):
        return True
    return (instruction.id == a.ARM_INS_POP and any(operand.type == a.ARM_OP_REG and operand.reg == a.ARM_REG_PC for operand in operands))

def _step(facts: FirmwareFacts, site: CodeAddress, offset: int):
    instruction = facts.decode(site)
    if instruction is None:
        return None
    if (instruction.id in (a.ARM_INS_MSR, getattr(a, "ARM_INS_CPS", -1)) or instruction.group(CS_GRP_INT)):
        return None
    accesses = []
    if instruction.id in (a.ARM_INS_PUSH, a.ARM_INS_POP):
        if instruction.cc not in _UNCONDITIONAL:
            return None
        registers = _register_list(instruction)
        if not registers:
            return None
        size = 4 * len(registers)
        if instruction.id == a.ARM_INS_PUSH:
            next_offset = offset - size
            accesses.extend(StackAccess(site, "write", next_offset + index * 4, 4, register) for index, register in enumerate(registers))
        else:
            accesses.extend(StackAccess(site, "read", offset + index * 4, 4, register) for index, register in enumerate(registers))
            next_offset = offset + size
        return next_offset, tuple(accesses)
    adjustment = _stack_adjustment(instruction)
    try:
        _, written = instruction.regs_access()
    except Exception:
        return None
    if a.ARM_REG_SP in written:
        if adjustment is None:
            return None
        return offset + adjustment, ()
    if adjustment is not None:
        # An ADD/SUB that computes a non-SP destination is not an SP change.
        return None
    memory = [operand for operand in instruction.operands if operand.type == a.ARM_OP_MEM and operand.mem.base == a.ARM_REG_SP]
    if not memory:
        return offset, ()
    if (len(memory) != 1 or len(instruction.operands) != 2 or instruction.writeback or instruction.id not in _SCALAR_WIDTHS or instruction.cc not in
        _UNCONDITIONAL or memory[0].mem.index not in (0, a.ARM_REG_INVALID)):
        return None
    operation, width = _SCALAR_WIDTHS[instruction.id]
    register = instruction.operands[0]
    if register.type != a.ARM_OP_REG or register.reg == a.ARM_REG_SP:
        return None
    return offset, (StackAccess(site, operation, offset + memory[0].mem.disp, width, register.reg),)

def _extract(facts: FirmwareFacts, function: FunctionFacts) -> StackFrame | None:
    nodes = set(function.instructions)
    if (not function.complete or function.truncated or function.unresolved or function.entry not in nodes or not nodes or any(site not in nodes or target not in
        nodes for site, target in function.control_edges)):
        return None
    successors: dict[CodeAddress, set[CodeAddress]] = {}
    for source, target in function.control_edges:
        successors.setdefault(source, set()).add(target)
    for site in nodes:
        instruction = facts.decode(site)
        if instruction is None:
            return None
        # A status/control-register write can switch to a banked SP.
        if site not in function.scope_before and (instruction.id in (a.ARM_INS_MSR, getattr(a, "ARM_INS_CPS", - 1)) or instruction.group(CS_GRP_INT)):
            return None
    offsets = {function.entry: 0}
    pending = [function.entry]
    accesses: dict[tuple[CodeAddress, str, int], StackAccess] = {}
    returns: dict[CodeAddress, int] = {}
    stopped: dict[CodeAddress, int] = {}
    boundaries = set(function.scope_before) | set(function.scope_exits)
    while pending:
        site = pending.pop()
        current = offsets[site]
        if site in function.scope_before:
            stopped[site] = current
            continue
        stepped = _step(facts, site, current)
        if stepped is None:
            return None
        after, local_accesses = stepped
        for item in local_accesses:
            accesses[(item.site, item.operation, item.register)] = item
        targets = successors.get(site, set())
        if not targets:
            if site in boundaries:
                stopped[site] = current
                continue
            if not _return_instruction(facts.decode(site)):
                return None
            returns[site] = after
            continue
        for target in targets:
            previous = offsets.get(target)
            if previous is None:
                offsets[target] = after
                pending.append(target)
            elif previous != after:
                # This also rejects nonzero stack growth around loop back-edges.
                return None
    ordered_offsets = tuple(sorted(offsets.items(), key=lambda item: (item[0].address, item[0].isa, item[0].phase, item[0].bank)))
    ordered_accesses = tuple(sorted(accesses.values(), key=lambda item: (item.site.address, item.site.isa, item.site.phase, item.site.bank, item.offset, item.operation,
        _ARCH_REGS[item.register])))
    exit_offsets = tuple(sorted(returns.items(), key=lambda item: (item[0].address, item[0].isa, item[0].phase, item[0].bank)))
    stopped_offsets = tuple(sorted(stopped.items(), key=lambda item: (item[0].address, item[0].isa, item[0].phase, item[0].bank)))
    balanced = (bool(exit_offsets) and not boundaries and all(offset == 0 for _, offset in exit_offsets))
    return StackFrame(function.entry, ordered_offsets, ordered_accesses, exit_offsets, balanced, True, stopped_offsets)

def stack_frame(facts: FirmwareFacts, function: FunctionFacts) -> StackFrame | None:
    """Return a cached relative stack proof, or ``None`` if it is not closed."""
    if not isinstance(facts, FirmwareFacts) or not isinstance(function, FunctionFacts):
        return None
    with facts._lock:
        if id(function) not in facts._function_ids:
            return None
    return facts.memo("stack-frame", id(function), lambda: _extract(facts, function))
