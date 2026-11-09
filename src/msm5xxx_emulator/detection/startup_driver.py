"""Shared local state-initializer ownership queries."""
from __future__ import annotations

from .facts import CodeAddress

def _state_initializer(facts, state_address):
    """Find closed code that initializes the state immediately before a descriptor."""
    references = facts.literal_references(
        state_address, phase='reset', bank='primary')
    for literal in references:
        entry = literal.instruction
        if entry.isa != 'thumb':
            continue
        function = facts.function(entry, budget=1024, symbolic_registers={})
        if not function.complete or not any(
                item.instruction == entry and item.value == state_address
                and item.pool == literal.pool
                for item in function.literals):
            continue
        for access in function.symbolic_accesses:
            if (access.operation == 'write' and access.width == 4
                    and access.address.kind == 'const'
                    and access.address.value == state_address
                    and access.value is not None
                    and access.value.kind == 'const'
                    and access.value.value == 0
                    and function.dominates(entry, access.instruction)):
                return function
    return None

def _initializer_has_direct_caller(facts, initializer, state_address):
    lower = max(facts.base, initializer.entry.address - 16)
    call_candidates = facts.call_candidates('thumb')
    for callsite, target in call_candidates:
        if not lower <= target <= initializer.entry.address:
            continue
        caller = facts.function(CodeAddress(callsite, 'thumb'), budget=1024)
        if caller.complete and (CodeAddress(callsite, 'thumb'),
                                CodeAddress(target, 'thumb')) in caller.calls:
            function = facts.function(CodeAddress(target, 'thumb'), budget=1024,
                                      symbolic_registers={})
            if (function.complete and any(
                    item.value == state_address for item in function.literals)
                    and any(access.operation == 'write' and access.width == 4
                            and access.address.kind == 'const'
                            and access.address.value == state_address
                            for access in function.symbolic_accesses)):
                return True
    return False

def _callbacks_share_state(facts, callbacks, state_address):
    for entry in callbacks.values():
        function = facts.function(entry, budget=4096, symbolic_registers={})
        if (not function.complete or not any(
                item.value == state_address for item in function.literals)
                or not any(
                    access.address.kind == 'const'
                    and state_address <= access.address.value < state_address + 16
                    for access in function.symbolic_accesses)):
            return False
    return True

