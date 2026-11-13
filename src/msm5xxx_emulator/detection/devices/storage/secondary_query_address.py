"""Prove a secondary-NOR selector's query address and initialization."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.values import SymbolicValue


def _const_int(value):
    if type(value) is int:
        return value
    if isinstance(value, SymbolicValue) and value.kind == 'const':
        return value.value
    return None


def _load_from(value, address):
    return (isinstance(value, SymbolicValue) and value.kind == 'load'
            and value.width == 4 and len(value.operands) == 1
            and isinstance(value.operands[0], SymbolicValue)
            and value.operands[0].kind == 'const'
            and value.operands[0].value == address)


def _address_with_zero_base(value, base_address):
    """Evaluate write addresses that depend only on the initialized base slot."""
    if _const_int(value) is not None:
        return _const_int(value)
    if _load_from(value, base_address):
        return 0
    if (not isinstance(value, SymbolicValue) or value.kind != 'op'
            or len(value.operands) != 2):
        return None
    left = _address_with_zero_base(value.operands[0], base_address)
    right = _address_with_zero_base(value.operands[1], base_address)
    if left is None or right is None:
        return None
    operations = {
        'add': lambda: left + right,
        'sub': lambda: left - right,
        'and': lambda: left & right,
        'or': lambda: left | right,
        'xor': lambda: left ^ right,
        'lsl': lambda: left << min(right, 32),
        'lsr': lambda: left >> min(right, 32),
    }
    operation = operations.get(value.value)
    return operation() & 0xFFFFFFFF if operation is not None else None


def _scaled_descriptor_begin(value, object_address, global_address,
                             query_address):
    """Match (descriptor.begin * 2) + the selector's bank-base field."""
    if (not isinstance(value, SymbolicValue) or value.kind != 'op'
            or value.value != 'add' or len(value.operands) != 2):
        return False
    for scaled, base in (value.operands, value.operands[::-1]):
        if not _load_from(base, global_address + 8):
            continue
        descriptor_load = (
            isinstance(scaled, SymbolicValue) and scaled.kind == 'op'
            and scaled.value == 'lsl' and len(scaled.operands) == 2
            and isinstance(scaled.operands[1], SymbolicValue)
            and scaled.operands[1].kind == 'const'
            and scaled.operands[1].value == 1
            and _load_from(scaled.operands[0], object_address + 0xB0))
        if not descriptor_load and _const_int(scaled) != query_address:
            continue
        return True
    return False


def selector_query_address(candidate, facts, query_pointer, *, with_spans=False):
    """Prove the linked selector probes descriptor.begin plus initialized base."""
    lifecycle = candidate.get('lifecycle')
    consumer = candidate.get('sector_prefix_consumer')
    if not isinstance(lifecycle, dict) or not isinstance(consumer, dict):
        return None
    selector = lifecycle.get('selector')
    constructor = lifecycle.get('constructor')
    object_address = candidate.get('selected_object')
    global_address = consumer.get('global_address')
    if (any(type(value) is not int or value < 0 or value & 1
            for value in (selector, constructor))
            or any(type(value) is not int or value < 0
                   for value in (object_address, global_address))
            or type(query_pointer) is not int or query_pointer < 0
            or not query_pointer & 1):
        return None
    selector_body = facts.function(CodeAddress(selector, 'thumb'), budget=2048,
                                   symbolic_registers={})
    constructor_body = facts.function(CodeAddress(constructor, 'thumb'), budget=2048,
                                      symbolic_registers={})
    if any(not body.complete or body.unresolved or body.truncated
           for body in (selector_body, constructor_body)):
        return None
    calls = []
    query_thunks = {}
    for call in selector_body.call_sites:
        if call.target.isa != 'thumb':
            continue
        thunk = facts.decode(call.target)
        if (thunk is None or thunk.id != a.ARM_INS_BX or len(thunk.operands) != 1
                or thunk.operands[0].type != a.ARM_OP_REG
                or thunk.operands[0].reg != a.ARM_REG_R1):
            continue
        registers = dict(call.registers)
        if _const_int(registers.get(a.ARM_REG_R1)) != query_pointer:
            continue
        address = facts.register_value(selector_body, call.site, a.ARM_REG_R0)
        query_address = candidate.get('address')
        field_reads = [access for access in selector_body.symbolic_accesses
                       if access.operation == 'read' and access.width == 4
                       and isinstance(access.address, SymbolicValue)
                       and access.address.kind == 'const'
                       and access.address.value == object_address + 0xB0
                       and isinstance(access.value, SymbolicValue)
                       and access.value.kind == 'const'
                       and access.value.value * 2 == query_address
                       and selector_body.dominates(access.instruction, call.site)]
        if (type(query_address) is int
                and _scaled_descriptor_begin(address, object_address,
                                             global_address, query_address)
                and len(field_reads) == 1):
            calls.append((call.site, address))
            query_thunks[call.site] = (call.target.address,
                                       call.target.address + thunk.size)
    if len(calls) != 1:
        return None
    selector_call = calls[0][0]
    proof_spans = {query_thunks[selector_call]}
    constructor_calls = [site for site, target in constructor_body.calls
                         if target.isa == 'thumb' and target.address == selector]
    if len(constructor_calls) != 1:
        return None
    constructor_call = constructor_calls[0]
    base_writes = [access for access in constructor_body.symbolic_accesses
                   if access.operation == 'write' and access.width == 4
                   and isinstance(access.address, SymbolicValue)
                   and access.address.kind == 'const'
                   and access.address.value == global_address + 8
                   and access.instruction.address < constructor_call.address]
    if (len(base_writes) != 1
            or not isinstance(base_writes[0].value, SymbolicValue)
            or base_writes[0].value.kind != 'const'
            or base_writes[0].value.value != 0
            or not constructor_body.dominates(base_writes[0].instruction,
                                               constructor_call)):
        return None
    for site, target in constructor_body.calls:
        if not (base_writes[0].instruction.address < site.address
                < constructor_call.address):
            continue
        intervening = facts.function(target, budget=512,
                                     symbolic_registers={})
        if (not intervening.complete or intervening.unresolved
                or intervening.truncated or intervening.calls
                or facts.unmodelled_memory(intervening) != ()):
            return None
        proof_spans.update((pc.address, pc.address + facts.decode(pc).size)
                           for pc in intervening.instructions)
        proof_spans.update((literal.pool, literal.pool + 4)
                           for literal in intervening.literals)
        for access in intervening.symbolic_accesses:
            if access.operation != 'write':
                continue
            address = _address_with_zero_base(access.address, global_address + 8)
            if address is None:
                # An unknown write effect could overwrite the initialized base.
                return None
            width = access.width
            if address < global_address + 12 and global_address + 8 < address + width:
                return None
    if type(candidate.get('address')) is not int:
        return None
    if with_spans:
        return candidate['address'], tuple(sorted(proof_spans))
    return candidate['address']


