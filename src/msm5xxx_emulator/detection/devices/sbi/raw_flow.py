"""Fact-based SBI raw-input transaction admission and property formatting."""
from __future__ import annotations
from dataclasses import dataclass
from itertools import product
from capstone import CS_GRP_JUMP, CS_GRP_RET
from capstone import arm as a
from ...facts import CodeAddress, SymbolicValue, evaluate_value
from .protocol import _native_status, BASE as SBI_BASE, SBI_SIZE

_UNCONDITIONAL = (a.ARM_CC_AL, a.ARM_CC_INVALID)
_ARG_REGS = (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3)
_SELECTORS = (0, 0x40, 0x60)
_BOOTSTRAP_FIELDS = ('signature', 'admission', 'accepted', 'base_address', 'bootstrap', 'validation', 'entries')

@dataclass(frozen=True, slots=True)
class _Effect:
    site: CodeAddress
    operation: str
    address: int
    width: int
    value: int | tuple[int, ...] | None

def _constant(value):
    return value.value if isinstance(value, SymbolicValue) and value.kind == 'const' else value

def _typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (left.keys() == right.keys() and all(_typed_equal(left[key], right[key]) for key in left))
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(_typed_equal(a, b) for a, b in zip(left, right))
    return left == right

def bootstrap_profile_matches(image, profile):
    """Check a configured bootstrap profile against its source bytes."""
    if not isinstance(profile, dict) or not isinstance(image, (bytes, bytearray, memoryview)):
        return False
    from .bootstrap import find_sbi_bootstrap_profile
    actual = find_sbi_bootstrap_profile(bytes(image))
    return (actual is not None and all(_typed_equal(profile.get(key), actual.get(key)) for key in _BOOTSTRAP_FIELDS))

def _stack_access(facts, site):
    ins = facts.decode(site)
    return bool(ins and (ins.id in (a.ARM_INS_PUSH, a.ARM_INS_POP) or any(op.type == a.ARM_OP_MEM and op.mem.base == a.ARM_REG_SP for op in ins.operands)))

def _closed_dataflow(facts, function, nodes=None):
    if not function.complete or function.truncated or function.unresolved:
        return False
    active = set(function.instructions) if nodes is None else set(nodes)
    if any(site in active and not _stack_access(facts, site) for site in (facts.unmodelled_memory(function) or ())):
        return False
    for access in function.symbolic_accesses:
        if access.instruction not in active or access.operation not in ('read', 'write'):
            continue
        if access.address.kind == 'const':
            continue
        if _stack_access(facts, access.instruction):
            continue
        return False
    return True

def _selector_cut_edges(facts, function, selector):
    cuts = set()
    for site in function.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_B or ins.cc in _UNCONDITIONAL or not ins.operands or ins.operands[0].type != a.ARM_OP_IMM):
            continue
        predicate = facts.branch_predicate(function, site)
        if predicate is None or predicate.read_sources:
            continue
        if not any(value.kind == 'arg' for value in predicate.operands):
            continue
        taken = predicate.evaluate(arguments={0: selector})
        if taken is None:
            continue
        target = ins.operands[0].imm & 0xFFFFFFFF
        fallthrough = site.address + ins.size
        cuts.add((site, CodeAddress(fallthrough if taken else target, site.isa, site.phase, site.bank)))
    return frozenset(cuts)

def _load_sites(value):
    result = {}
    def visit(item):
        if item.kind == 'load' and item.site is not None:
            result[item.site] = item
        for child in item.operands:
            visit(child)
    visit(value)
    return tuple(result.values())

def _possible_values(facts, function, value, cut_edges=(), active=frozenset(), allowed_calls=()):
    if value.kind == 'const':
        return (value.value,)
    if value.kind == 'load':
        address = value.operands[0] if value.operands else None
        if address is None or address.kind != 'const' or value.site in active:
            return None
        definitions = facts.memory_definitions(function, value.site, address.value, width=value.width, cut_edges=cut_edges, include_entry=True, allowed_calls=allowed_calls)
        if definitions is None:
            return tuple(range(256)) if value.width == 1 else None
        values = set()
        for definition in definitions:
            if definition is None:
                if value.width != 1:
                    return None
                values.update(range(256))
                continue
            ins = facts.decode(definition)
            if (ins is None or not ins.operands or ins.operands[0].type != a.ARM_OP_REG or ins.id not in (a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH)):
                return None
            stored = facts.register_value(function, definition, ins.operands[0].reg, cut_edges=cut_edges)
            if stored.kind == 'unknown':
                return None
            candidates = _possible_values(facts, function, stored, cut_edges, active | {value.site}, allowed_calls)
            if candidates is None:
                return None
            values.update(candidates)
        return tuple(sorted(values))
    if value.kind != 'op':
        return None
    loads = _load_sites(value)
    value_sets = []
    for item in loads:
        candidates = _possible_values(facts, function, item, cut_edges, active, allowed_calls)
        if candidates is None:
            return None
        value_sets.append((item.site, candidates))
    count = 1
    for _, candidates in value_sets:
        count *= len(candidates)
        if count > 65536:
            return None
    result = set()
    for values in product(*(candidates for _, candidates in value_sets)):
        mapping = {site: candidate for (site, _), candidate in zip(value_sets, values)}
        item = evaluate_value(value, reads=mapping)
        if item is None:
            return None
        result.add(item)
        if len(result) > 65536:
            return None
    return tuple(sorted(result))

def _peripheral_accesses(function):
    return tuple(access for access in function.symbolic_accesses if access.address.kind == 'const' and SBI_BASE <= access.address.value < SBI_BASE + SBI_SIZE)

def _function_return_sites(facts, function):
    result = []
    for site in function.instructions:
        ins = facts.decode(site)
        if ins is None:
            continue
        try:
            _, writes = ins.regs_access()
        except Exception:
            continue
        move_return = (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(ins.operands) == 2 and ins.operands[0].type == a.ARM_OP_REG and ins.operands[0].reg ==
            a.ARM_REG_PC and ins.operands[1].type == a.ARM_OP_REG and ins.operands[1].reg == a.ARM_REG_LR)
        if (a.ARM_REG_PC in writes and (ins.group(CS_GRP_RET) or ins.id in (a.ARM_INS_BX, a.ARM_INS_POP) or move_return)):
            result.append(site)
    return tuple(result)

def _poll_contract(facts, entry, control, read_full):
    function = facts.function(entry, budget=256, symbolic_registers={})
    if not _closed_dataflow(facts, function):
        return None
    peripheral = _peripheral_accesses(function)
    if (len(peripheral) != 1 or peripheral[0].operation != 'read' or peripheral[0].address.value != SBI_BASE or peripheral[0].width != 2):
        return None
    read = peripheral[0]
    calls = dict(function.calls)
    delay_calls = set()
    for site, target in function.calls:
        child = facts.function(target, budget=64, symbolic_registers={})
        if (not _closed_dataflow(facts, child) or child.calls or _peripheral_accesses(child)):
            return None
        delay_calls.add(site)
    expected_status = _native_status(control) | (2 if read_full else 0)
    branches = []
    for branch_site in function.instructions:
        ins = facts.decode(branch_site)
        if (ins is None or ins.id != a.ARM_INS_B or ins.cc in _UNCONDITIONAL or not ins.group(CS_GRP_JUMP)):
            continue
        predicate = facts.branch_predicate(function, branch_site)
        if predicate is None or len(predicate.read_sources) != 1:
            continue
        source = predicate.read_sources[0]
        if (source.site != read.instruction or source.address.kind != 'const' or source.address.value != SBI_BASE or source.width != 2):
            continue
        selected = predicate.evaluate({read.instruction: expected_status})
        if selected is None:
            continue
        target = ins.operands[0].imm & 0xFFFFFFFF
        fallthrough = branch_site.address + ins.size
        exit_pc = target if selected else fallthrough
        retry_pc = fallthrough if selected else target
        selected_path = None
        for return_site in _function_return_sites(facts, function):
            selected_path = function.linear_path(CodeAddress(exit_pc, branch_site.isa, branch_site.phase, branch_site.bank), return_site, allowed_calls=delay_calls)
            if selected_path is not None:
                break
        retry_start = CodeAddress(retry_pc, branch_site.isa, branch_site.phase, branch_site.bank)
        return_sites = _function_return_sites(facts, function)
        if (selected_path is None or len(function.back_edges) != 1 or function.back_edges[0][1] != read.instruction.address):
            continue
        repeat_source = CodeAddress(function.back_edges[0][0], branch_site.isa, branch_site.phase, branch_site.bank)
        if not function.dominates(branch_site, repeat_source):
            continue
        repeat = ((repeat_source, read.instruction),)
        ordered = facts.ordered_events(function, (read.instruction, branch_site, *return_sites), repeat_edges= repeat)
        expected_order = (read.instruction, branch_site, *return_sites)
        if ordered != expected_order:
            continue
        branches.append((read, branch_site, selected, (retry_start,)))
    return (function, branches[0]) if len(branches) == 1 else None

def _owner_function(facts, site):
    """Find one nearby saved-link-register function owning a direct call."""
    starts = []
    lower = max(facts.base, site.address - 0x200)
    for address in range((lower + 1) & ~1, site.address, 2):
        candidate = CodeAddress(address, site.isa, site.phase, site.bank)
        ins = facts.decode(candidate)
        if ins is None or ins.id != a.ARM_INS_PUSH:
            continue
        try:
            reads, _ = ins.regs_access()
        except Exception:
            continue
        if a.ARM_REG_LR not in reads:
            continue
        function = facts.function(candidate, budget=512, symbolic_registers={register: SymbolicValue.arg(index) for index, register in enumerate(_ARG_REGS)})
        if function.complete and site in function.instructions:
            starts.append((address, function))
    if not starts:
        return None
    nearest = max(address for address, _ in starts)
    matches = [function for address, function in starts if address == nearest]
    return matches[0] if len(matches) == 1 else None

def _callsite(function, site):
    return next((call for call in function.call_sites if call.site == site), None)

def _stable_stack_cuts(facts, function, use, register):
    """Cut iterations only when one dominating stack write remains invariant."""
    definitions = facts.reaching_definitions(function, use, register)
    if definitions is None or len(definitions) != 1 or definitions[0] is None:
        return ()
    load_site = definitions[0]
    load = facts.decode(load_site)
    frame = facts.stack_frame(function)
    if (load is None or frame is None or not frame.complete or load.id not in (a.ARM_INS_LDR, a.ARM_INS_LDRB, a.ARM_INS_LDRH, a.ARM_INS_LDRSB, a.ARM_INS_LDRSH)):
        return ()
    reads = tuple(access for access in frame.accesses if access.site == load_site and access.operation == 'read' and access.register == register)
    if len(reads) != 1:
        return ()
    read = reads[0]
    writes = tuple(access for access in frame.accesses if access.operation == 'write' and access.offset < read.offset + read.width and read.offset < access.offset
        + access.width)
    if len(writes) != 1 or not function.dominates(writes[0].site, load_site):
        return ()
    writer = writes[0].site
    if facts.ordered_events(function, (writer,)) != (writer,):
        return ()
    return tuple((CodeAddress(source, use.isa, use.phase, use.bank), CodeAddress(target, use.isa, use.phase, use.bank)) for source, target in function.back_edges
        if function.dominates(writer, CodeAddress(source, use.isa, use.phase, use.bank)) and function.dominates(writer, CodeAddress(target, use.isa, use.phase,
        use.bank)))

def _source_selector(facts, raw_entry):
    calls = [(CodeAddress(site, 'thumb'), target) for site, target in facts.call_candidates('thumb') if target == raw_entry.address]
    owners = []
    for site, _ in calls:
        owner = _owner_function(facts, site)
        if owner is not None:
            owners.append((owner, site))
    if len({(owner.entry, site) for owner, site in owners}) != 1:
        return None
    filter_fn, raw_call = owners[0]
    raw_site = _callsite(filter_fn, raw_call)
    if raw_site is None:
        return None
    outer = [(CodeAddress(site, 'thumb'), target) for site, target in facts.call_candidates('thumb') if target == filter_fn.entry.address]
    values = []
    for site, _ in outer:
        owner = _owner_function(facts, site)
        call = _callsite(owner, site) if owner is not None else None
        arguments = dict(call.registers) if call is not None else {}
        selector = _constant(arguments.get(a.ARM_REG_R0))
        if type(selector) is int and selector in _SELECTORS:
            values.append((selector, owner, site))
    if len(values) != 1:
        return None
    selector, caller, outer_call = values[0]
    outer_site = _callsite(caller, outer_call)
    if outer_site is None:
        return None
    filter_fn = facts.function(filter_fn.entry, budget=512, initial_registers=dict(outer_site.registers), symbolic_registers={})
    if not filter_fn.complete or raw_call not in filter_fn.instructions:
        return None
    cuts = _stable_stack_cuts(facts, filter_fn, raw_call, a.ARM_REG_R0)
    forwarded = facts.register_value(filter_fn, raw_call, a.ARM_REG_R0, cut_edges=cuts, follow_stack=True)
    if evaluate_value(forwarded, arguments={0: selector}) != selector:
        return None
    return selector, filter_fn, raw_call, caller, outer_call

def _argument_indices(value):
    result = set()
    def visit(item):
        if item.kind == 'arg':
            result.add(item.value)
        for child in item.operands:
            visit(child)
    visit(value)
    return result

def _argument_values(facts, caller, call, selector, allowed_calls=()):
    values = dict(call.registers)
    result = {}
    cuts = _selector_cut_edges(facts, caller, selector)
    for register, value in values.items():
        if type(value) is int:
            result[register] = (value,)
        elif isinstance(value, SymbolicValue):
            result[register] = _possible_values(facts, caller, value, cuts, allowed_calls=allowed_calls)
        else:
            result[register] = None
    return result

def _callee_effects(facts, caller, call, selector):
    arguments = {register: SymbolicValue.arg(index) for index, register in enumerate(_ARG_REGS)}
    callee = facts.function(call.target, budget=256, initial_registers=arguments, symbolic_registers={})
    if (not _closed_dataflow(facts, callee) or callee.calls or callee.back_edges):
        return None
    accesses = _peripheral_accesses(callee)
    if not accesses:
        if callee.calls or any(access.operation == 'write' for access in callee.symbolic_accesses):
            return None
        return ()
    if (not accesses or any(access.operation != 'write' or access.predicate not in _UNCONDITIONAL for access in accesses)):
        return None
    if any(access.operation == 'write' and (access.address.kind != 'const' or not SBI_BASE <= access.address.value < SBI_BASE + SBI_SIZE) for access in callee.symbolic_accesses):
        return None
    returns = _function_return_sites(facts, callee)
    effect_sites = tuple(access.instruction for access in accesses)
    ordered = facts.ordered_events(callee, (*effect_sites, *returns))
    if (not returns or len(set(effect_sites)) != len(effect_sites) or ordered != (*effect_sites, *returns)):
        return None
    allowed_calls = _closed_call_sites(facts, caller)
    call_values = _argument_values(facts, caller, call, selector, allowed_calls)
    effects = []
    for access in accesses:
        indices = _argument_indices(access.value)
        if any(index >= len(_ARG_REGS) or call_values.get(_ARG_REGS[index]) is None for index in indices):
            return None
        combinations = [({},)]
        indexed = sorted(indices)
        choices = [call_values[_ARG_REGS[index]] for index in indexed]
        if any(len(choice) > 256 for choice in choices):
            return None
        count = 1
        for choice in choices:
            count *= len(choice)
        if count > 65536:
            return None
        output_values = set()
        for choice in product(*choices):
            concrete = dict(zip(indexed, choice))
            value = evaluate_value(access.value, arguments=concrete)
            if value is None:
                return None
            output_values.add(value)
        effects.append(_Effect(access.instruction, access.operation, access.address.value, access.width, tuple(sorted(output_values))))
    return tuple(sorted(effects, key=lambda item: item.site.address))

def _closed_call_sites(facts, function, active=frozenset()):
    safe = set()
    for site, target in function.calls:
        if target in active:
            return None
        callee = facts.function(target, budget=256, initial_registers={a.ARM_REG_R0: SymbolicValue.arg(0), a.ARM_REG_R1: SymbolicValue.arg(1), a.ARM_REG_R2:
            SymbolicValue.arg(2), a.ARM_REG_R3: SymbolicValue.arg(3)}, symbolic_registers={})
        if not _closed_dataflow(facts, callee):
            return None
        for access in callee.symbolic_accesses:
            if access.operation == 'write' and (access.address.kind != 'const' or not SBI_BASE <= access.address.value < SBI_BASE + SBI_SIZE):
                return None
        nested = _closed_call_sites(facts, callee, active | {target})
        if nested is None:
            return None
        safe.add(site)
        safe.update(nested)
    return frozenset(safe)
