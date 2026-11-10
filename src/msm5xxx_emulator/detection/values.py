"""Immutable analysis values and shared 32-bit arithmetic/flag semantics."""
from __future__ import annotations
from dataclasses import dataclass
from capstone import arm as a

# Analysis-only flags; architectural register IDs are nonnegative.
_FLAG_N, _FLAG_Z, _FLAG_C, _FLAG_V = -2, -3, -4, -5
_FLAG_ORIGIN_REGISTER = -7
_FLAG_ORIGIN_MASK_REGISTER = -8
_ORIGIN_N = 1
_ORIGIN_Z = 2
_ORIGIN_C = 4
_ORIGIN_V = 8
_FLAGS = (_FLAG_N, _FLAG_Z, _FLAG_C, _FLAG_V)

def _condition_flag_mask(condition):
    return { a.ARM_CC_EQ: _ORIGIN_Z, a.ARM_CC_NE: _ORIGIN_Z, a.ARM_CC_MI: _ORIGIN_N, a.ARM_CC_PL: _ORIGIN_N, a.ARM_CC_HS: _ORIGIN_C, a.ARM_CC_LO: _ORIGIN_C, a.ARM_CC_VS:
        _ORIGIN_V, a.ARM_CC_VC: _ORIGIN_V, a.ARM_CC_HI: _ORIGIN_C | _ORIGIN_Z, a.ARM_CC_LS: _ORIGIN_C | _ORIGIN_Z, a.ARM_CC_GE: _ORIGIN_N | _ORIGIN_V, a.ARM_CC_LT:
        _ORIGIN_N | _ORIGIN_V, a.ARM_CC_GT: _ORIGIN_N | _ORIGIN_V | _ORIGIN_Z, a.ARM_CC_LE: _ORIGIN_N | _ORIGIN_V | _ORIGIN_Z, }.get(condition, 0)
_RECENT_POP_REGISTER = -6

def _condition_holds(condition, registers):
    if condition in (a.ARM_CC_AL, a.ARM_CC_INVALID):
        return True
    requirements, predicate = { a.ARM_CC_EQ: ((_FLAG_Z,), lambda z: z == 1), a.ARM_CC_NE: ((_FLAG_Z,), lambda z: z == 0), a.ARM_CC_MI: ((_FLAG_N,), lambda n: n
        == 1), a.ARM_CC_PL: ((_FLAG_N,), lambda n: n == 0), a.ARM_CC_HS: ((_FLAG_C,), lambda c: c == 1), a.ARM_CC_LO: ((_FLAG_C,), lambda c: c == 0), a.ARM_CC_VS:
        ((_FLAG_V,), lambda v: v == 1), a.ARM_CC_VC: ((_FLAG_V,), lambda v: v == 0), a.ARM_CC_HI: ((_FLAG_C, _FLAG_Z), lambda c, z: c == 1 and z == 0), a.ARM_CC_LS:
        ((_FLAG_C, _FLAG_Z), lambda c, z: c == 0 or z == 1), a.ARM_CC_GE: ((_FLAG_N, _FLAG_V), lambda n, v: n == v), a.ARM_CC_LT: ((_FLAG_N, _FLAG_V), lambda n,
        v: n != v), a.ARM_CC_GT: ((_FLAG_N, _FLAG_V, _FLAG_Z), lambda n, v, z: n == v and z == 0), a.ARM_CC_LE: ((_FLAG_N, _FLAG_V, _FLAG_Z), lambda n, v, z: n
        != v or z == 1), }.get(condition, ((), None))
    return (predicate(*(registers[flag] for flag in requirements)) if predicate is not None and all(type(registers.get(flag)) is int for flag in requirements)
        else None)

@dataclass(frozen=True, slots=True)
class CodeAddress:
    address: int
    isa: str = 'thumb'
    phase: str = 'reset'
    bank: str = 'primary'

@dataclass(frozen=True, slots=True)
class SymbolicValue:
    """Small immutable value used only by explicitly symbolic function queries."""

    kind: str
    value: int | str | None = None
    operands: tuple['SymbolicValue', ...] = ()
    width: int = 0
    signed: bool = False
    site: CodeAddress | None = None
    memory_version: tuple[CodeAddress, ...] | None = None

    @classmethod
    def const(cls, value: int) -> 'SymbolicValue':
        return cls('const', int(value) & 0xFFFFFFFF)

    @classmethod
    def arg(cls, index: int) -> 'SymbolicValue':
        if type(index) is not int or index < 0:
            raise ValueError('symbolic argument index must be nonnegative')
        return cls('arg', index)

UNKNOWN_VALUE = SymbolicValue('unknown')

def _symbolic_cost(value: SymbolicValue) -> tuple[int, int]:
    if value.kind != 'op' and value.kind != 'load':
        return 1, 1
    counts = [_symbolic_cost(item) for item in value.operands]
    return 1 + sum(count for count, _ in counts), 1 + max((depth for _, depth in counts), default=0)

def _contains_symbolic_load(value: SymbolicValue) -> bool:
    return (value.kind == 'load' or any(_contains_symbolic_load(item) for item in value.operands))

def _symbolic_operation(operation: str, left, right, *, budget_exhausted=None):
    """Fold constants, otherwise build one bounded expression node."""
    if left is None or right is None or left is UNKNOWN_VALUE or right is UNKNOWN_VALUE:
        return UNKNOWN_VALUE
    if type(left) is int:
        left = SymbolicValue.const(left)
    if type(right) is int:
        right = SymbolicValue.const(right)
    if not isinstance(left, SymbolicValue) or not isinstance(right, SymbolicValue):
        return UNKNOWN_VALUE
    if left.kind == right.kind == 'const':
        a_value, b_value = left.value, right.value
        operations = { 'add': lambda: a_value + b_value, 'sub': lambda: a_value - b_value, 'and': lambda: a_value & b_value, 'or': lambda: a_value | b_value,
            'xor': lambda: a_value ^ b_value, 'lsl': lambda: a_value << min(b_value, 32), 'lsr': lambda: a_value >> min(b_value, 32), }
        folded = operations[operation]() & 0xFFFFFFFF
        if type(a_value) is int and type(b_value) is int:
            return folded
        return SymbolicValue.const(folded)
    # Preserve dependencies while removing exact 32-bit arithmetic identities.
    # No equality of separate loads or mutable memory is assumed here.
    if right.kind == 'const':
        constant = right.value
        if constant == 0 and operation in ('add', 'sub', 'or', 'xor', 'lsl', 'lsr'):
            return left
        if operation == 'and':
            if constant == 0xFFFFFFFF:
                return left
            if constant == 0:
                return SymbolicValue.const(0)
        if operation in ('lsl', 'lsr') and type(constant) is int and constant >= 32:
            return SymbolicValue.const(0)
    if left.kind == 'const':
        if left.value == 0 and operation in ('add', 'or', 'xor'):
            return right
        if operation == 'and':
            if left.value == 0xFFFFFFFF:
                return right
            if left.value == 0:
                return SymbolicValue.const(0)
    operands = (left, right)
    if operation in ('add', 'and', 'or', 'xor') and repr(operands[0]) > repr(operands[1]):
        operands = operands[::-1]
    result = SymbolicValue('op', operation, operands)
    count, depth = _symbolic_cost(result)
    if count > 48 or depth > 8:
        if budget_exhausted is not None:
            budget_exhausted[0] = True
        return UNKNOWN_VALUE
    return result

def _symbolic_load(address: SymbolicValue, width: int, signed: bool, site: CodeAddress, memory_version: tuple[CodeAddress, ...] | None, *, budget_exhausted=None) -> SymbolicValue:
    if address is UNKNOWN_VALUE or memory_version is None:
        return UNKNOWN_VALUE
    result = SymbolicValue('load', operands=(address,), width=width, signed=signed, site=site, memory_version= memory_version)
    count, depth = _symbolic_cost(result)
    if count > 48 or depth > 8:
        if budget_exhausted is not None:
            budget_exhausted[0] = True
        return UNKNOWN_VALUE
    return result

def evaluate_value(value: SymbolicValue, *, arguments=None, reads=None) -> int | None:
    """Evaluate a bounded expression with explicit argument/read substitutions.

    Argument keys are symbolic argument indices, not architectural register
    numbers. Read keys identify instruction sites; supplying a value asserts
    neither memory invariance nor that the corresponding instruction executes.
    """
    arguments, reads = arguments or {}, reads or {}
    remaining = 48
    def visit(item, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 8 or not isinstance(item, SymbolicValue):
            return None
        if item.kind == 'const':
            return item.value & 0xFFFFFFFF if type(item.value) is int else None
        if item.kind == 'arg':
            result = arguments.get(item.value) if type(item.value) is int else None
            return result & 0xFFFFFFFF if type(result) is int else None
        if item.kind == 'load':
            if item.site is None or item.width not in (1, 2, 4):
                return None
            result = reads.get(item.site)
            if type(result) is not int:
                return None
            bits = 8 * item.width
            result &= (1 << bits) - 1
            if item.signed and result & (1 << (bits - 1)):
                result -= 1 << bits
            return result & 0xFFFFFFFF
        if (item.kind != 'op' or item.value not in ('add', 'sub', 'and', 'or', 'xor', 'lsl', 'lsr') or len(item.operands) != 2):
            return None
        operands = tuple(visit(child, depth + 1) for child in item.operands)
        if any(child is None for child in operands):
            return None
        result = _symbolic_operation(item.value, *operands)
        return result if type(result) is int else None
    return visit(value, 0)

def _evaluate_flags(operation, values, shift):
    mask = 0xFFFFFFFF
    if operation in ('cmp', 'sub') and len(values) == 2:
        left, right = values
        result = (left - right) & mask
        return (result >> 31, int(result == 0), int(left >= right), int(bool(((left ^ right) & (left ^ result)) & 0x80000000)))
    if operation in ('cmn', 'add') and len(values) == 2:
        left, right = values
        result = (left + right) & mask
        return (result >> 31, int(result == 0), int(left + right > mask), int(bool((~(left ^ right) & (left ^ result)) & 0x80000000)))
    if operation in ('tst', 'teq', 'and', 'or', 'xor') and len(values) == 2:
        left, right = values
        result = (left & right if operation in ('tst', 'and') else left | right if operation == 'or' else left ^ right) & mask
        return result >> 31, int(result == 0), None, None
    if operation == 'mov' and len(values) == 1:
        result = values[0] & mask
        return result >> 31, int(result == 0), None, None
    if operation in ('lsl', 'lsr', 'asr') and len(values) == 1 and shift is not None:
        source = values[0] & mask
        amount = shift
        if amount == 0:
            result, carry = source, None
        elif operation == 'lsl':
            if amount > 32:
                return None
            result = 0 if amount == 32 else (source << amount) & mask
            carry = (source >> (32 - amount)) & 1
        elif operation == 'lsr':
            if amount > 32:
                return None
            result = 0 if amount == 32 else source >> amount
            carry = (source >> (amount - 1)) & 1
        else:
            if amount > 32:
                return None
            signed_source = source - (1 << 32) if source & 0x80000000 else source
            result = ((signed_source >> min(amount, 32)) & mask)
            carry = (source >> (min(amount, 32) - 1)) & 1
        return result >> 31, int(result == 0), carry, None
    return None
