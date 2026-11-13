"""Source proofs for byte, halfword and word transfer helper chains."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.startup_facts import _loop_iteration_cut, _loop_nodes
from msm5xxx_emulator.detection.values import SymbolicValue


_ABI_REGISTERS = (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2)
_ABI_ARGS = tuple(SymbolicValue.arg(index) for index in range(3))
_ARGUMENT_LIMIT = 8


def _iteration_cuts(function):
    result = []
    for edge in function.back_edges:
        nodes = _loop_nodes(function, edge)
        if not nodes:
            continue
        cut = _loop_iteration_cut(function, nodes, edge)
        if cut is None:
            return None
        result.append(tuple(CodeAddress(address, function.entry.isa,
                                        function.entry.phase, function.entry.bank)
                            for address in cut[0]))
    return tuple(result)


def _count_argument(facts, function, at, register):
    """Require the counted loop's initial value to be its third ABI argument."""
    aligned = facts.function(function.entry, budget=1024,
        initial_registers={a.ARM_REG_R0: 0x10000000,
                           a.ARM_REG_R1: 0x11000000,
                           a.ARM_REG_R2: SymbolicValue.arg(2),
                           a.ARM_REG_R3: 0,
                           a.ARM_REG_SP: 0x13010000},
        symbolic_registers={})
    cuts = _iteration_cuts(aligned)
    site = CodeAddress(at, function.entry.isa,
                       function.entry.phase, function.entry.bank)
    return (aligned.complete and not aligned.unresolved and not aligned.truncated
            and site in aligned.instructions and cuts is not None
            and facts.register_value(aligned, site, register,
                cut_edges=cuts, follow_stack=True) == SymbolicValue.arg(2))


def _value_key(value):
    if not isinstance(value, SymbolicValue):
        return None
    if value.kind in ('arg', 'const'):
        return value.kind, value.value
    operands = tuple(_value_key(item) for item in value.operands)
    if any(item is None for item in operands):
        return None
    if value.kind == 'load':
        return 'load', value.width, operands[0]
    if value.kind == 'op':
        if value.value == 'add':
            operands = tuple(item for item in operands if item != ('const', 0))
            if len(operands) == 1:
                return operands[0]
            operands = tuple(sorted(operands, key=repr))
        return 'op', value.value, operands
    return None


def _argument_roots(value):
    key = _value_key(value)
    if key is None:
        return None
    roots = set()
    pending = [key]
    while pending:
        item = pending.pop()
        if item[0] == 'arg':
            roots.add(item[1])
        elif item[0] == 'op':
            pending.extend(item[2])
        elif item[0] == 'load':
            pending.append(item[2])
    return roots


def _transfers(facts, function):
    """Describe balanced one-load/one-store loops already structurally bounded."""
    decoded = {pc.address: facts.decode(pc) for pc in function.instructions}
    result = []
    for branch, target in function.back_edges:
        branch_ins = decoded.get(branch)
        if (branch_ins is None or branch_ins.id != a.ARM_INS_B
                or branch_ins.cc != a.ARM_CC_NE):
            continue
        loop = [ins for address, ins in decoded.items()
                if ins is not None and target <= address <= branch]
        if any(target <= site.address <= branch for site, _ in function.calls):
            continue
        transfers = []
        for ins in loop:
            if ins.id in (a.ARM_INS_LDRH, a.ARM_INS_STRH,
                          a.ARM_INS_LDR, a.ARM_INS_STR):
                if len(ins.operands) != 2 or ins.operands[1].type != a.ARM_OP_MEM:
                    continue
                memory = ins.operands[1].mem
                width = 2 if ins.id in (a.ARM_INS_LDRH, a.ARM_INS_STRH) else 4
                if not memory.index and memory.disp == 0:
                    transfers.append((width, ins.id in (a.ARM_INS_LDRH, a.ARM_INS_LDR),
                                      memory.base, False, ins.operands[0].reg,
                                      CodeAddress(ins.address, function.entry.isa,
                                                  function.entry.phase, function.entry.bank)))
            elif ins.id in (a.ARM_INS_LDM, a.ARM_INS_STM) and ins.writeback:
                if len(ins.operands) == 2 and ins.operands[1].type == a.ARM_OP_REG:
                    transfers.append((4, ins.id == a.ARM_INS_LDM,
                                      ins.operands[0].reg, True, ins.operands[1].reg,
                                      CodeAddress(ins.address, function.entry.isa,
                                                  function.entry.phase, function.entry.bank)))
        loads = [item for item in transfers if item[1]]
        stores = [item for item in transfers if not item[1]]
        widths = {item[0] for item in transfers}
        if (len(widths) != 1 or len(loads) != 1 or len(stores) != 1
                or loads[0][4] != stores[0][4]):
            continue
        if ({item[2] for item in loads} & {item[2] for item in stores}
                or loads[0][4] in {item[2] for item in transfers}):
            continue
        if any(item[3] for item in transfers) and not all(item[3] for item in transfers):
            continue
        width = next(iter(widths))
        if not any(item[3] for item in transfers):
            load_bases = {item[2] for item in loads}
            store_bases = {item[2] for item in stores}
            stepped = {}
            bad_write = False
            for ins in loop:
                try:
                    changed = set(ins.regs_access()[1]) & (load_bases | store_bases)
                except Exception:
                    changed = set()
                if not changed:
                    continue
                ops = ins.operands
                if (ins.id == a.ARM_INS_ADD and len(ops) == 2
                        and ops[0].type == a.ARM_OP_REG
                        and ops[1].type == a.ARM_OP_IMM and ops[1].imm == width):
                    stepped[ops[0].reg] = stepped.get(ops[0].reg, 0) + width
                elif (ins.id == a.ARM_INS_ADD and len(ops) == 3
                      and ops[0].type == a.ARM_OP_REG
                      and ops[1].type == a.ARM_OP_REG and ops[0].reg == ops[1].reg
                      and ops[2].type == a.ARM_OP_IMM and ops[2].imm == width):
                    stepped[ops[0].reg] = stepped.get(ops[0].reg, 0) + width
                else:
                    bad_write = True
            if (bad_write or any(stepped.get(reg) != width
                                 for reg in load_bases | store_bases)):
                continue
        result.append((width, loads[0], stores[0], branch, target, decoded))
    return result


def _data_flows_to_store(facts, function, load, store, cuts):
    if (not function.dominates(load[5], store[5])
            or function.linear_path(load[5], store[5]) is None):
        return False
    origins = facts.register_origins(function, store[5], store[4],
                                     cut_edges=cuts)
    return origins == ((load[5], load[4]),)


def _loop_counter_is_arg2(facts, function, candidate):
    _width, load, store, branch, target, decoded = candidate
    decrements, increments = [], []
    for ins in decoded.values():
        if ins is None or ins.id not in (a.ARM_INS_SUB, a.ARM_INS_ADD):
            continue
        ops = ins.operands
        if (len(ops) == 2 and ops[0].type == a.ARM_OP_REG
                and ops[1].type == a.ARM_OP_IMM):
            destination = source = ops[0].reg
            immediate = ops[1].imm
        elif (len(ops) == 3 and ops[0].type == a.ARM_OP_REG
              and ops[1].type == a.ARM_OP_REG and ops[2].type == a.ARM_OP_IMM):
            destination, source, immediate = ops[0].reg, ops[1].reg, ops[2].imm
        else:
            continue
        if destination != source or immediate != 1:
            continue
        if ins.id == a.ARM_INS_SUB and target <= ins.address <= branch:
            if ins.update_flags and ins.address + ins.size == branch:
                decrements.append((destination, ins.address))
        elif ins.id == a.ARM_INS_ADD and ins.address < target:
            increments.append((destination, ins.address))
    for register, decrement in decrements:
        if register in (load[2], store[2], load[4]):
            continue
        if not function.dominates(CodeAddress(decrement, function.entry.isa,
                                             function.entry.phase, function.entry.bank),
                                 load[5]):
            continue
        for initial_register, increment in increments:
            if (initial_register == register
                    and function.dominates(CodeAddress(increment, function.entry.isa,
                                                       function.entry.phase, function.entry.bank),
                                           CodeAddress(decrement, function.entry.isa,
                                                       function.entry.phase, function.entry.bank))
                    and _count_argument(facts, function, increment, register)):
                return True
    return False


def _concrete_int(value):
    if type(value) is int:
        return value & 0xFFFFFFFF
    if isinstance(value, SymbolicValue) and value.kind == 'const':
        return value.value
    return None


def _copy_leaf(facts, function, concrete_function, outer_concrete_args):
    """Prove one copy leaf's width, pointer roles, count and loaded value."""
    if not function.complete or function.unresolved or function.truncated:
        return None
    candidates = _transfers(facts, function)
    if not candidates:
        return None
    cuts = _iteration_cuts(function)
    concrete_cuts = _iteration_cuts(concrete_function)
    if cuts is None or concrete_cuts is None:
        return None
    good_units = set()
    for candidate in candidates:
        width, load, store, _branch, _target, _decoded = candidate
        source_value = facts.register_value(function, load[5], load[2],
                                            cut_edges=cuts, follow_stack=True)
        destination_value = facts.register_value(function, store[5], store[2],
                                                 cut_edges=cuts, follow_stack=True)
        source_roots = _argument_roots(source_value)
        destination_roots = _argument_roots(destination_value)
        if (source_roots is None or destination_roots is None
                or 0 not in source_roots or 1 in source_roots
                or not source_roots <= {0, 2}
                or 1 not in destination_roots or 0 in destination_roots
                or not destination_roots <= {1, 2}):
            continue
        concrete_source = _concrete_int(facts.register_value(
            concrete_function, load[5], load[2], cut_edges=concrete_cuts,
            follow_stack=True))
        concrete_destination = _concrete_int(facts.register_value(
            concrete_function, store[5], store[2], cut_edges=concrete_cuts,
            follow_stack=True))
        if (concrete_source != outer_concrete_args[0]
                or concrete_destination != outer_concrete_args[1]):
            continue
        if (not _data_flows_to_store(facts, function, load, store, cuts)
                or not _loop_counter_is_arg2(facts, function, candidate)):
            continue
        good_units.add(width)
    return next(iter(good_units)) if len(good_units) == 1 else None


def direct_copy_unit(facts, function) -> int | None:
    """Compatibility check for a direct R0=source, R1=destination copy leaf."""
    entry = function.entry
    seeded = facts.function(entry, budget=1024,
        initial_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                           a.ARM_REG_R1: SymbolicValue.arg(1),
                           a.ARM_REG_R2: SymbolicValue.arg(2)},
        symbolic_registers={})
    concrete = facts.function(entry, budget=1024,
        initial_registers={a.ARM_REG_R0: 0x10000000,
                           a.ARM_REG_R1: 0x11000000,
                           a.ARM_REG_R2: 8, a.ARM_REG_R3: 0,
                           a.ARM_REG_SP: 0x13010000},
        symbolic_registers={})
    return _copy_leaf(facts, seeded, concrete, (0x10000000, 0x11000000, 8))


def find_copy_units(facts, entry):
    """Find code-linked copy widths from an outer (source,dest,count) ABI."""
    if not isinstance(entry, CodeAddress) or entry.isa != 'thumb':
        return {}
    found = {}
    active = set()

    root_concrete_args = (0x10000000, 0x11000000, 8)

    def visit(address, args, concrete_args, depth):
        if depth > _ARGUMENT_LIMIT or address in active:
            return {}
        key = (address, tuple(_value_key(value) for value in args))
        if key in active:
            return {}
        active.add(key)
        try:
            initial = dict(zip(_ABI_REGISTERS, args))
            body = facts.function(address, budget=1024,
                                  initial_registers=initial,
                                  symbolic_registers={})
            concrete_body = facts.function(address, budget=1024,
                initial_registers={a.ARM_REG_R0: concrete_args[0],
                                   a.ARM_REG_R1: concrete_args[1],
                                   a.ARM_REG_R2: concrete_args[2],
                                   a.ARM_REG_R3: 0,
                                   a.ARM_REG_SP: 0x13010000},
                symbolic_registers={})
            if (not body.complete or body.unresolved or body.truncated
                    or not concrete_body.complete or concrete_body.unresolved
                    or concrete_body.truncated):
                return {}
            direct = _copy_leaf(facts, body, concrete_body,
                                root_concrete_args)
            if direct is not None:
                return {direct: [body]}
            result = {}
            cuts = _iteration_cuts(body)
            concrete_cuts = _iteration_cuts(concrete_body)
            if cuts is None or concrete_cuts is None:
                return {}
            for call in body.call_sites:
                if call.target.isa != 'thumb':
                    continue
                site_args = dict(call.registers)
                child_args = tuple(site_args.get(register) for register in _ABI_REGISTERS)
                if any(not isinstance(value, SymbolicValue)
                       or _value_key(value) is None for value in child_args):
                    continue
                # A child must receive one pointer sourced from each outer
                # pointer and the original count; wrappers may exchange R0/R1.
                roots = tuple(_argument_roots(value) for value in child_args)
                if (any(value is None for value in roots)
                        or not any(0 in value and 1 not in value for value in roots[:2])
                        or not any(1 in value and 0 not in value for value in roots[:2])
                        or _value_key(child_args[2]) != ('arg', 2)):
                    continue
                concrete_args_at_call = tuple(_concrete_int(
                    facts.register_value(concrete_body, call.site, register,
                        cut_edges=concrete_cuts, follow_stack=True))
                    for register in _ABI_REGISTERS)
                if any(value is None for value in concrete_args_at_call):
                    continue
                for unit, chain in visit(call.target, child_args,
                                         concrete_args_at_call, depth + 1).items():
                    result.setdefault(unit, []).extend([body, *chain])
            return result
        finally:
            active.remove(key)

    return visit(entry, _ABI_ARGS, root_concrete_args, 0)
