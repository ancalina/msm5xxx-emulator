"""Per-instruction operand and symbolic lineage evaluation."""
from __future__ import annotations

from .values import (
    SymbolicValue, UNKNOWN_VALUE, _FLAG_C, _FLAG_N, _FLAG_V, _FLAG_Z, _FLAGS,
    _contains_symbolic_load, _symbolic_cost,
    _symbolic_operation,
)
from capstone import arm as a


def instruction_values(self, pc, operands, regs, register_sources,
                       initial_memory, memory_valid, symbolic_budget_exhausted,
                       instruction):
    def value(op):
        if op.type == a.ARM_OP_IMM:
            return op.imm & 0xFFFFFFFF
        if op.type == a.ARM_OP_REG:
            return regs.get(op.reg)
        return None


    def memory_constant(address: int, size: int) -> bytes | None:
        cursor, end = address, address + size
        while cursor < end:
            hits = [mapping for mapping in self.view.mappings
                    if mapping.phase == pc.phase and mapping.bank == pc.bank
                    and mapping.guest_base <= cursor
                    < mapping.guest_base + mapping.size]
            if len(hits) != 1:
                return None
            mapping = hits[0]
            immutable = mapping.kind in ('direct', 'alias')
            initial_rw = (initial_memory and memory_valid
                          and mapping.kind in ('copy', 'zero'))
            if not immutable and not initial_rw:
                return None
            cursor = min(end, mapping.guest_base + mapping.size)
        return self.view.read(address, size, phase=pc.phase, bank=pc.bank)


    def address_expression(memory):
        memory_field = next((op for op in operands
                             if op.type == a.ARM_OP_MEM), None)
        if memory_field is not None and (memory_field.subtracted
                                           or memory_field.shift.type):
            return UNKNOWN_VALUE
        base = regs.get(memory.base)
        if type(base) is int:
            base = SymbolicValue.const(base)
        if base is None or base is UNKNOWN_VALUE:
            return UNKNOWN_VALUE
        result = base
        if memory.index:
            index = regs.get(memory.index)
            if index is None or index is UNKNOWN_VALUE:
                return UNKNOWN_VALUE
            if type(index) is int:
                index = SymbolicValue.const(index)
            if not isinstance(index, SymbolicValue):
                return UNKNOWN_VALUE
            shift = getattr(memory, 'lshift', 0)
            if shift:
                return UNKNOWN_VALUE
            result = _symbolic_operation(
                'add', result, index,
                budget_exhausted=symbolic_budget_exhausted)
        displacement = SymbolicValue.const(memory.disp)
        result = _symbolic_operation('add', result, displacement,
                                     budget_exhausted=symbolic_budget_exhausted)
        return SymbolicValue.const(result) if type(result) is int else result


    def flag_expression(name, values):
        normalized = []
        for item in values:
            if type(item) is int:
                item = SymbolicValue.const(item)
            if not isinstance(item, SymbolicValue) or item is UNKNOWN_VALUE:
                return None
            normalized.append(item)
        if not any(_contains_symbolic_load(item) for item in normalized):
            return None
        operation = name.split(':')[-1]
        left, right = normalized if len(normalized) == 2 else (None, None)
        left_constant = (left.value if isinstance(left, SymbolicValue)
                         and left.kind == 'const' else None)
        right_constant = (right.value if isinstance(right, SymbolicValue)
                          and right.kind == 'const' else None)
        if ((operation == 'tst' and (left_constant == 0 or right_constant == 0))
                or (operation in ('teq', 'cmp') and left == right)):
            return None
        expression = SymbolicValue('op', f'flags:{name}', tuple(normalized),
                                   site=pc)
        count, depth = _symbolic_cost(expression)
        if count > 48 or depth > 8:
            symbolic_budget_exhausted[0] = True
            return None
        return expression


    def source_value(operand, actual):
        if operand.type == a.ARM_OP_REG:
            source = register_sources.get(operand.reg)
            if source is not None:
                return source
        return actual


    def source_operation(name, values):
        normalized = []
        for item in values:
            if type(item) is int:
                item = SymbolicValue.const(item)
            if not isinstance(item, SymbolicValue) or item is UNKNOWN_VALUE:
                return None
            normalized.append(item)
        if not any(_contains_symbolic_load(item) for item in normalized):
            return None
        left, right = normalized if len(normalized) == 2 else (None, None)
        left_constant = (left.value if isinstance(left, SymbolicValue)
                         and left.kind == 'const' else None)
        right_constant = (right.value if isinstance(right, SymbolicValue)
                          and right.kind == 'const' else None)
        if ((name == 'tst' and (left_constant == 0 or right_constant == 0))
                or (name in ('teq', 'cmp', 'sub', 'xor') and left == right)
                or (name == 'and' and (left_constant == 0 or right_constant == 0))
                or (name == 'or' and (left_constant == 0xFFFFFFFF
                                      or right_constant == 0xFFFFFFFF))
                or (name in ('lsl', 'lsr') and right_constant is not None
                    and right_constant >= 32)):
            return None
        expression = SymbolicValue('op', name, tuple(normalized), site=pc)
        count, depth = _symbolic_cost(expression)
        if count > 48 or depth > 8:
            symbolic_budget_exhausted[0] = True
            return None
        return expression

    status = concrete_status_flags(instruction, operands, value, regs)
    return (value, memory_constant, address_expression, flag_expression,
            source_value, source_operation, status)


def concrete_status_flags(instruction, operands, value, previous):
    """Compute known ARM32 status bits for supported flag-setting operations."""
    def unknown(keys):
        return {flag: UNKNOWN_VALUE for flag in keys}

    def preserved(excluded):
        return {flag: previous[flag] for flag in _FLAGS
                if flag in excluded and type(previous.get(flag)) is int}

    def logical_carry(result):
        if len(instruction.bytes) == 4 and len(operands) >= 2:
            word = int.from_bytes(instruction.bytes, 'little')
            if word & (1 << 25):
                rotation = ((word >> 8) & 0xF) * 2
                return result >> 31 if rotation else previous.get(_FLAG_C)
        return previous.get(_FLAG_C)

    ins_id = instruction.id
    shifted = any(operand.shift.type for operand in operands)
    if ins_id in (a.ARM_INS_CMP, a.ARM_INS_CMN):
        if len(operands) != 2 or shifted:
            return unknown(_FLAGS)
        left, right = value(operands[0]), value(operands[1])
        if type(left) is not int or type(right) is not int:
            return unknown(_FLAGS)
        left &= 0xFFFFFFFF
        right &= 0xFFFFFFFF
        subtract = ins_id == a.ARM_INS_CMP
        total = left - right if subtract else left + right
        result = total & 0xFFFFFFFF
        return {
            _FLAG_N: result >> 31,
            _FLAG_Z: int(result == 0),
            _FLAG_C: int(left >= right if subtract else total > 0xFFFFFFFF),
            _FLAG_V: (((left ^ right) if subtract else ~(left ^ right))
                      & (left ^ result)) >> 31 & 1,
        }
    if ins_id in (a.ARM_INS_TST, a.ARM_INS_TEQ):
        if len(operands) != 2 or shifted:
            return {**unknown((_FLAG_N, _FLAG_Z, _FLAG_C)),
                    **preserved({_FLAG_V})}
        left, right = value(operands[0]), value(operands[1])
        if type(left) is not int or type(right) is not int:
            return {**unknown((_FLAG_N, _FLAG_Z, _FLAG_C)),
                    **preserved({_FLAG_V})}
        result = (left & right if ins_id == a.ARM_INS_TST
                  else left ^ right) & 0xFFFFFFFF
        flags = {_FLAG_N: result >> 31, _FLAG_Z: int(result == 0)}
        carry = logical_carry(result)
        flags[_FLAG_C] = carry if type(carry) is int else UNKNOWN_VALUE
        flags.update(preserved({_FLAG_V}))
        return flags

    if not instruction.update_flags:
        return {}

    if ins_id in (a.ARM_INS_ADD, a.ARM_INS_SUB):
        if len(operands) not in (2, 3):
            return unknown(_FLAGS)
        if shifted:
            return unknown(_FLAGS)
        left, right = ((value(operands[0]), value(operands[1]))
                       if len(operands) == 2 else
                       (value(operands[1]), value(operands[2])))
        if type(left) is not int or type(right) is not int:
            return unknown(_FLAGS)
        left &= 0xFFFFFFFF
        right &= 0xFFFFFFFF
        subtract = ins_id == a.ARM_INS_SUB
        total = left - right if subtract else left + right
        result = total & 0xFFFFFFFF
        return {
            _FLAG_N: result >> 31,
            _FLAG_Z: int(result == 0),
            _FLAG_C: int(left >= right if subtract else total > 0xFFFFFFFF),
            _FLAG_V: (((left ^ right) if subtract else ~(left ^ right))
                      & (left ^ result)) >> 31 & 1,
        }

    if ins_id in (a.ARM_INS_LSL, a.ARM_INS_LSR):
        if len(operands) != 3:
            return {**unknown((_FLAG_N, _FLAG_Z, _FLAG_C)),
                    **preserved({_FLAG_V})}
        source, amount_value = value(operands[1]), value(operands[2])
        if type(source) is not int or type(amount_value) is not int:
            return {**unknown((_FLAG_N, _FLAG_Z, _FLAG_C)),
                    **preserved({_FLAG_V})}
        source &= 0xFFFFFFFF
        register_amount = operands[2].type == a.ARM_OP_REG
        amount = amount_value & (0xFF if register_amount else 0xFFFFFFFF)
        if amount == 0 and register_amount:
            result = source
            carry = previous.get(_FLAG_C)
        else:
            if ins_id == a.ARM_INS_LSR and amount == 0:
                amount = 32
            if ins_id == a.ARM_INS_LSL:
                result = 0 if amount >= 32 else (source << amount) & 0xFFFFFFFF
                carry = 0 if amount > 32 else (source & 1) if amount == 32 else (
                    (source >> (32 - amount)) & 1 if 0 < amount < 32 else
                    previous.get(_FLAG_C))
            else:
                result = 0 if amount >= 32 else source >> amount
                carry = 0 if amount > 32 else (source >> 31) & 1 if amount == 32 else (
                    (source >> (amount - 1)) & 1 if 0 < amount < 32 else
                    previous.get(_FLAG_C))
        flags = {_FLAG_N: result >> 31, _FLAG_Z: int(result == 0)}
        flags[_FLAG_C] = carry if type(carry) is int else UNKNOWN_VALUE
        flags.update(preserved({_FLAG_V}))
        return flags

    if ins_id in (a.ARM_INS_AND, a.ARM_INS_ORR, a.ARM_INS_EOR,
                  a.ARM_INS_MOV, a.ARM_INS_MOVS):
        if (ins_id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                and len(operands) == 2):
            result = value(operands[1])
        elif len(operands) in (2, 3):
            left, right = ((value(operands[0]), value(operands[1]))
                           if len(operands) == 2 else
                           (value(operands[1]), value(operands[2])))
            if type(left) is not int or type(right) is not int:
                return preserved({_FLAG_V})
            if ins_id == a.ARM_INS_AND:
                result = left & right
            elif ins_id == a.ARM_INS_ORR:
                result = left | right
            else:
                result = left ^ right
        else:
            return {**unknown((_FLAG_N, _FLAG_Z, _FLAG_C)),
                    **preserved({_FLAG_V})}
        if type(result) is not int:
            return {**unknown((_FLAG_N, _FLAG_Z, _FLAG_C)),
                    **preserved({_FLAG_V})}
        result &= 0xFFFFFFFF
        flags = {_FLAG_N: result >> 31, _FLAG_Z: int(result == 0)}
        carry = None
        if len(operands) == 2 and operands[1].type == a.ARM_OP_IMM:
            carry = logical_carry(result)
        if type(carry) is int:
            flags[_FLAG_C] = carry
        flags.update(preserved({_FLAG_V}))
        return flags
    # A flag-setting instruction with an unmodelled result must invalidate
    # status bits it may have changed, rather than keeping a stale predicate.
    if ins_id in (a.ARM_INS_AND, a.ARM_INS_ORR, a.ARM_INS_EOR,
                  a.ARM_INS_BIC, a.ARM_INS_MOV, a.ARM_INS_MVN,
                  a.ARM_INS_LSL, a.ARM_INS_LSR, a.ARM_INS_ASR,
                  a.ARM_INS_ROR, a.ARM_INS_TST, a.ARM_INS_TEQ):
        return {**unknown((_FLAG_N, _FLAG_Z, _FLAG_C)),
                **preserved({_FLAG_V})}
    return unknown(_FLAGS)


def adr_target(instruction, address, isa):
    operands = instruction.operands
    if (instruction.id != a.ARM_INS_ADR or len(operands) != 2
            or operands[0].type != a.ARM_OP_REG
            or operands[1].type != a.ARM_OP_IMM):
        return None
    pc_value = ((address + 4) & ~3) if isa == 'thumb' else address + 8
    return (pc_value + operands[1].imm) & 0xFFFFFFFF
