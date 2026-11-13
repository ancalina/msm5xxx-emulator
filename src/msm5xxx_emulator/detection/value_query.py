"""Bounded values at register uses over an existing, owned local CFG."""
from dataclasses import dataclass
from capstone import arm as a
from .values import (CodeAddress, SymbolicValue, UNKNOWN_VALUE, _FLAGS, _condition_holds, _symbolic_operation, evaluate_value, _evaluate_flags,)
from .instruction_values import adr_target

_OPERATIONS = { a.ARM_INS_ADD: 'add', a.ARM_INS_SUB: 'sub', a.ARM_INS_AND: 'and', a.ARM_INS_ORR: 'or', a.ARM_INS_EOR: 'xor', a.ARM_INS_LSL: 'lsl', a.ARM_INS_LSR:
    'lsr', a.ARM_INS_ASR: 'asr', }
_LOADS = {a.ARM_INS_LDR: (4, False), a.ARM_INS_LDRB: (1, False), a.ARM_INS_LDRH: (2, False), a.ARM_INS_LDRSB: (1, True), a.ARM_INS_LDRSH: (2, True)}

@dataclass(frozen=True, slots=True)
class ReadSource:
    site: CodeAddress
    address: SymbolicValue
    width: int
    signed: bool

@dataclass(frozen=True, slots=True)
class BranchPredicate:
    """One branch condition derived from a unique local flag producer."""

    branch: CodeAddress
    producer: CodeAddress
    condition: int
    operation: str
    operands: tuple[SymbolicValue, ...]
    shift: int | None
    read_sources: tuple[ReadSource, ...]

    def evaluate(self, read_values=None, *, arguments=None):
        """Evaluate using explicit values for the named source loads."""
        read_values = read_values or {}
        values = tuple(evaluate_value(item, reads=read_values, arguments=arguments) for item in self.operands)
        if any(item is None for item in values):
            return None
        flags = _evaluate_flags(self.operation, values, self.shift)
        if flags is None:
            return None
        return _condition_holds(self.condition, dict(zip(_FLAGS, flags)))

def _read_sources(value):
    found = {}
    def visit(item):
        if item.kind == 'load' and item.site is not None:
            address = item.operands[0] if item.operands else UNKNOWN_VALUE
            source = ReadSource(item.site, address, item.width, item.signed)
            found[(source.site, source.address, source.width, source.signed)] = source
        for child in item.operands:
            visit(child)
    visit(value)
    return tuple(found[key] for key in sorted(found, key=lambda item: (item[0].address, item[0].isa, item[0].phase, item[0].bank, item[2], item[3])))

def branch_predicate(facts, function, branch, *, cut_edges=()):
    """Build a branch condition from its unique reaching flag producer.

    Load expressions retain their exact instruction site, width and address.
    Callers that substitute a device value must validate those fields first.
    """
    from capstone import CS_GRP_JUMP
    if branch not in function.instructions:
        return None
    ins = facts.decode(branch)
    if (ins is None or ins.id != a.ARM_INS_B or ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID) or not ins.group(CS_GRP_JUMP)):
        return None
    producers = facts.reaching_definitions(function, branch, a.ARM_REG_CPSR, cut_edges=cut_edges)
    if producers is None or len(producers) != 1:
        return None
    producer = producers[0]
    flag_ins = facts.decode(producer)
    if flag_ins is None or flag_ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
        return None
    operands = flag_ins.operands
    operation = None
    expressions = ()
    shift = None
    if flag_ins.id in (a.ARM_INS_CMP, a.ARM_INS_CMN, a.ARM_INS_TST, a.ARM_INS_TEQ):
        if len(operands) != 2 or any(op.shift.type or op.subtracted for op in operands):
            return None
        operation = { a.ARM_INS_CMP: 'cmp', a.ARM_INS_CMN: 'cmn', a.ARM_INS_TST: 'tst', a.ARM_INS_TEQ: 'teq', }[flag_ins.id]
        expressions = tuple(SymbolicValue.const(op.imm & 0xFFFFFFFF) if op.type == a.ARM_OP_IMM else facts.register_value(function, producer, op.reg, cut_edges=cut_edges)
            if op.type == a.ARM_OP_REG else UNKNOWN_VALUE for op in operands)
    elif (flag_ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB, a.ARM_INS_AND, a.ARM_INS_ORR, a.ARM_INS_EOR) and flag_ins.update_flags and len(operands) in (2, 3)):
        if (operands[0].type != a.ARM_OP_REG or any(op.shift.type or op.subtracted for op in operands)):
            return None
        operation = _OPERATIONS[flag_ins.id]
        expressions = tuple(SymbolicValue.const(op.imm & 0xFFFFFFFF) if op.type == a.ARM_OP_IMM else facts.register_value(function, producer, op.reg, cut_edges=cut_edges)
            if op.type == a.ARM_OP_REG else UNKNOWN_VALUE for op in operands[-2:])
    elif flag_ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(operands) == 2:
        if operands[0].type != a.ARM_OP_REG or operands[1].shift.type:
            return None
        operation = 'mov'
        source = operands[1]
        expressions = ((SymbolicValue.const(source.imm & 0xFFFFFFFF),) if source.type == a.ARM_OP_IMM else (facts.register_value(function, producer, source.reg,
            cut_edges=cut_edges),) if source.type == a.ARM_OP_REG else (UNKNOWN_VALUE,))
    elif flag_ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR, a.ARM_INS_ASR):
        operation = {a.ARM_INS_LSL: 'lsl', a.ARM_INS_LSR: 'lsr', a.ARM_INS_ASR: 'asr'}[flag_ins.id]
        if (len(operands) == 3 and operands[0].type == a.ARM_OP_REG and operands[1].type == a.ARM_OP_REG and operands[2].type == a.ARM_OP_IMM):
            source_reg, shift = operands[1].reg, operands[2].imm
        elif (len(operands) == 2 and operands[0].type == a.ARM_OP_REG and operands[1].type == a.ARM_OP_REG and operands[1].shift.type):
            source_reg = operands[1].reg
            shift_type = operands[1].shift.type
            shift = operands[1].shift.value
            expected_shift = {a.ARM_SFT_LSL: 'lsl', a.ARM_SFT_LSR: 'lsr', a.ARM_SFT_ASR: 'asr'}.get(shift_type)
            if expected_shift != operation:
                return None
        else:
            return None
        expressions = (facts.register_value(function, producer, source_reg, cut_edges=cut_edges),)
        if not 0 <= shift <= 32:
            return None
    else:
        return None
    if any(not isinstance(value, SymbolicValue) or value is UNKNOWN_VALUE or value.kind == 'unknown' for value in expressions):
        return None
    reads = tuple({(source.site, source.address, source.width, source.signed): source for value in expressions for source in _read_sources(value)}.values())
    reads = tuple(sorted(reads, key=lambda item: (item.site.address, item.site.isa, item.site.phase, item.site.bank, item.width, item.signed)))
    return BranchPredicate(branch, producer, ins.cc, operation, expressions, shift, reads)

def register_value(facts, function, use, register, *, cut_edges=(), follow_stack=False, allowed_calls=()):
    """Return a constant or expression whose unknown reads retain source sites.

    Load expressions describe dependencies, not equality of memory across
    executions. Only immutable supplied mappings fold to constants. Copies,
    zero fills and other writable initial state remain opaque here.
    """
    with facts._lock:
        if id(function) not in facts._function_ids:
            return UNKNOWN_VALUE
    removed = frozenset(cut_edges)
    allowed = frozenset(allowed_calls)
    def extract():
        values, nodes = {}, set(function.instructions)
        def operation(name, left, right):
            result = _symbolic_operation(name, left, right)
            return SymbolicValue.const(result) if type(result) is int else result
        def operand(op, site, active):
            if op.shift.type or op.subtracted:
                return UNKNOWN_VALUE
            if op.type == a.ARM_OP_IMM:
                return SymbolicValue.const(op.imm)
            if op.type == a.ARM_OP_REG:
                return visit(site, op.reg, active)
            return UNKNOWN_VALUE
        def stack_load(site, register, width, signed, active):
            frame = facts.stack_frame(function)
            if frame is None or not frame.complete:
                return UNKNOWN_VALUE
            reads = tuple(item for item in frame.accesses if item.site == site and item.operation == 'read' and item.register == register and item.width ==
                width)
            if len(reads) != 1:
                return UNKNOWN_VALUE
            read = reads[0]
            stores = {}
            for access in frame.accesses:
                if access.operation == 'write':
                    stores.setdefault(access.site,[]).append(access)
            stack_sites = {access.site for access in frame.accesses}
            unmodelled = set(facts.unmodelled_memory(function) or ()) - stack_sites
            calls = {callsite for callsite, _ in function.calls}
            def defines(pc):
                instruction = facts.decode(pc)
                if (instruction is None or pc in unmodelled or instruction.id == a.ARM_INS_SVC or pc not in allowed and (pc in calls or instruction.id in (a.ARM_INS_BL,
                    a.ARM_INS_BLX))):
                    return None
                overlapping = tuple(item for item in stores.get(pc, ()) if item.offset < read.offset + width and read.offset < item.offset + item.width)
                if overlapping:
                    if (len(overlapping) != 1 or overlapping[0].offset > read.offset or overlapping[0].offset + overlapping[0].width < read.offset + width or
                        instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                        return None
                    return True
                if (instruction.id in (a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH) and pc not in stack_sites):
                    # A non-frame store may alias the frame until a caller
                    # supplies a stronger memory-region/effect contract.
                    return None
                return False
            definitions = facts._reaching_sites(function, site, removed, False, defines)
            if not definitions:
                return UNKNOWN_VALUE
            alternatives = []
            for definition in definitions:
                candidates = tuple(item for item in stores.get(definition, ()) if item.offset <= read.offset and read.offset + width <= item.offset + item.width)
                if len(candidates) != 1:
                    return UNKNOWN_VALUE
                stored = candidates[0]
                if stored.register == a.ARM_REG_PC:
                    return UNKNOWN_VALUE
                value = visit(definition, stored.register, active)
                value = operation('lsr', value, SymbolicValue.const((read.offset - stored.offset) * 8))
                bits = width * 8
                value = operation('and', value, SymbolicValue.const((1 << bits) - 1))
                if signed and bits < 32:
                    sign = SymbolicValue.const(1 << (bits - 1))
                    value = operation('sub', operation('xor', value, sign), sign)
                alternatives.append(value)
            return (alternatives[0] if alternatives and all(item == alternatives[0] for item in alternatives) else UNKNOWN_VALUE)
        def load(ins, site, active):
            if len(ins.operands) != 2 or ins.operands[1].type != a.ARM_OP_MEM:
                return UNKNOWN_VALUE
            memory = ins.operands[1]
            if memory.mem.index or memory.shift.type or memory.subtracted:
                return UNKNOWN_VALUE
            if follow_stack and memory.mem.base == a.ARM_REG_SP:
                width, signed = _LOADS[ins.id]
                return stack_load(site, ins.operands[0].reg, width, signed, active)
            address = operation('add', visit(site, memory.mem.base, active), SymbolicValue.const(memory.mem.disp))
            if address is UNKNOWN_VALUE:
                return UNKNOWN_VALUE
            width, signed = _LOADS[ins.id]
            if address.kind == 'const':
                start = address.value
                mappings = facts.view.mappings
                end, cursor = start + width, start
                while cursor < end:
                    hits = [item for item in mappings if item.phase == site.phase and item.bank == site.bank and item.guest_base <= cursor < item.guest_base +
                        item.size]
                    if len(hits) != 1 or hits[0].kind not in ('direct', 'alias'):
                        break
                    cursor = min(end, hits[0].guest_base + hits[0].size)
                if cursor == end:
                    raw = facts.view.read(start, width, phase=site.phase, bank=site.bank)
                    if raw is not None:
                        return SymbolicValue.const(int.from_bytes(raw, 'little', signed=signed))
            return SymbolicValue('load', operands=(address,), width=width, signed=signed, site=site)
        def definition_value(site, reg, active):
            ins = facts.decode(site)
            if ins is None or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                return UNKNOWN_VALUE
            ops = ins.operands
            if follow_stack and ins.id == a.ARM_INS_POP:
                return stack_load(site, reg, 4, False, active)
            if not ops or ops[0].type != a.ARM_OP_REG or ops[0].reg != reg:
                return UNKNOWN_VALUE
            if ins.id in _LOADS:
                return load(ins, site, active)
            if ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(ops) == 2:
                return operand(ops[1], site, active)
            if ins.id == a.ARM_INS_ADR:
                target = adr_target(ins, site.address, site.isa)
                return (SymbolicValue.const(target) if target is not None else UNKNOWN_VALUE)
            if ins.id == a.ARM_INS_MVN and len(ops) == 2:
                return operation('xor', operand(ops[1], site, active), SymbolicValue.const(0xFFFFFFFF))
            if ins.id in _OPERATIONS and len(ops) in (2, 3):
                left, right = ops[-2:]
                result_right = operand(right, site, active)
                if ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR, a.ARM_INS_ASR) and right.type == a.ARM_OP_REG:
                    result_right = operation('and', result_right, SymbolicValue.const(0xFF))
                return operation(_OPERATIONS[ins.id], operand(left, site, active), result_right)
            return UNKNOWN_VALUE
        def visit(site, reg, active):
            key = (site, reg)
            if key in values:
                return values[key]
            if site not in nodes or key in active or len(active) >= 64:
                return UNKNOWN_VALUE
            if reg == a.ARM_REG_PC:
                return SymbolicValue.const((site.address + 4) & ~3 if site.isa == 'thumb' else site.address + 8)
            definitions = facts.reaching_definitions(function, site, reg, cut_edges=removed, include_entry=True)
            if definitions is None:
                return UNKNOWN_VALUE
            initial = dict(function.initial_registers).get(reg)
            initial = (SymbolicValue.const(initial) if type(initial) is int else initial if isinstance(initial, SymbolicValue) else UNKNOWN_VALUE)
            alternatives = tuple(initial if pc is None else definition_value(pc, reg, active | {key}) for pc in definitions)
            result = (alternatives[0] if alternatives and all(value == alternatives[0] for value in alternatives) else UNKNOWN_VALUE)
            values[key] = result
            return result
        return visit(use, register, frozenset())
    return facts.memo('register-value', (id(function), use, register, removed, follow_stack, allowed), extract)
