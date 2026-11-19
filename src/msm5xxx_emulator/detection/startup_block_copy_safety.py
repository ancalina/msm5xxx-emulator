"""Write and stack safety checks for reset-installed block helpers."""
from capstone import arm as a


def _path_nodes(function, start, target):
    """Return CFG nodes on paths from start to target, or None if unclosed."""
    if not function.dominates(start, target):
        return None
    forward, reverse = {}, {}
    for left, right in function.control_edges:
        forward.setdefault(left, set()).add(right)
        reverse.setdefault(right, set()).add(left)

    def closure(graph, first):
        pending, found = [first], set()
        while pending:
            current = pending.pop()
            if current in found:
                continue
            found.add(current)
            pending.extend(graph.get(current, ()))
        return found

    return closure(forward, start) & closure(reverse, target)


def _effect_ranges(effect):
    """Normalize one bounded write or a tuple of bounded writes."""
    if (isinstance(effect, tuple) and len(effect) == 2
            and all(type(value) is int for value in effect)):
        return (effect,)
    if not isinstance(effect, (tuple, list)) or not effect:
        return None
    if any(not isinstance(row, (tuple, list)) or len(row) != 2
           or any(type(value) is not int for value in row)
           for row in effect):
        return None
    return tuple(tuple(row) for row in effect)


def _overlaps(left, length, right, right_length):
    return left < right + right_length and right < left + length


def _path_preserves_copy(facts, function, start, target, installed_start,
                         installed_size, proven_call_effects):
    """Reject unknown calls or stores that could alter installed helper code."""
    if (not function.complete or function.truncated or function.unresolved
            or target not in {site for site, _callee in function.calls}):
        return False
    nodes = _path_nodes(function, start, target)
    if nodes is None:
        return False
    calls = {site for site, _callee in function.calls}
    writes = {access.instruction: access for access in function.accesses
              if access.operation == 'write'}
    # Include the first post-loop instruction; it can overwrite the helper.
    for site in nodes - {target}:
        if site in calls:
            ranges = _effect_ranges(proven_call_effects.get(site))
            if ranges is None or any(
                    length <= 0 or _overlaps(address, length, installed_start,
                                             installed_size)
                    for address, length in ranges):
                return False
            continue
        instruction = facts.decode(site)
        if instruction is None:
            return False
        is_store = (instruction.id in (a.ARM_INS_STR, a.ARM_INS_STRB,
                                       a.ARM_INS_STRH, a.ARM_INS_STM,
                                       a.ARM_INS_STRT, a.ARM_INS_STRBT,
                                       a.ARM_INS_SWP, a.ARM_INS_SWPB,
                                       a.ARM_INS_PUSH)
                    or instruction.mnemonic.startswith(
                        ('str', 'stm', 'swp', 'vst', 'push')))
        if not is_store:
            continue
        access = writes.get(site)
        # An unlocated PUSH is an unknown stack write, not an exemption.
        if access is None:
            return False
        if _overlaps(access.address, access.width, installed_start,
                     installed_size):
            return False
    ranges = _effect_ranges(proven_call_effects.get(target))
    if ranges is None or any(
            length <= 0 or _overlaps(address, length, installed_start,
                                     installed_size)
            for address, length in ranges):
        return False
    return True


def _call_stack_effect(sp, ram_base, ram_end, installed_start,
                       installed_size, destination, destination_length,
                       stack_size=48):
    """Prove a callee's register-save frame is bounded and non-aliasing."""
    if (type(sp) is not int or type(stack_size) is not int or stack_size <= 0
            or sp - stack_size < ram_base or sp > ram_end):
        return None
    start = sp - stack_size
    if (_overlaps(start, stack_size, installed_start, installed_size)
            or _overlaps(start, stack_size, destination, destination_length)):
        return None
    return (start, stack_size)


def _stack_pointer_at_call(facts, function, target, initial_sp,
                           balanced_calls=()):
    """Propagate constant SP through every complete path to a callsite."""
    instructions = set(function.instructions)
    if (not function.complete or function.truncated or function.unresolved
            or function.entry not in instructions or target not in instructions
            or type(initial_sp) is not int):
        return None
    edges = {}
    for source, destination in function.control_edges:
        if source not in instructions or destination not in instructions:
            return None
        edges.setdefault(source, set()).add(destination)
    call_sites = {site for site, _callee in function.calls}
    balanced = set(balanced_calls)
    incoming = {function.entry: {initial_sp}}
    pending = [function.entry]
    queued = {function.entry}
    target_values = set()
    while pending:
        site = pending.pop()
        queued.discard(site)
        values = incoming.get(site, set())
        if site == target:
            target_values.update(values)
            continue
        if site in call_sites and site not in balanced:
            return None
        instruction = facts.decode(site)
        if instruction is None:
            return None
        try:
            _, written = instruction.regs_access()
        except Exception:
            return None
        delta = 0
        if instruction.id in (a.ARM_INS_PUSH, a.ARM_INS_POP):
            if instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                return None
            registers = tuple(op.reg for op in instruction.operands
                              if op.type == a.ARM_OP_REG)
            if not registers or a.ARM_REG_SP in registers:
                return None
            delta = (-4 if instruction.id == a.ARM_INS_PUSH else 4) * len(registers)
        elif instruction.id in (a.ARM_INS_ADD, a.ARM_INS_SUB):
            operands = instruction.operands
            if (len(operands) == 2 and operands[0].type == a.ARM_OP_REG
                    and operands[0].reg == a.ARM_REG_SP
                    and operands[1].type == a.ARM_OP_IMM
                    and instruction.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                magnitude = operands[1].imm
                if magnitude < 0:
                    return None
                delta = magnitude if instruction.id == a.ARM_INS_ADD else -magnitude
            elif (len(operands) == 3 and operands[0].type == a.ARM_OP_REG
                    and operands[0].reg == a.ARM_REG_SP):
                if (operands[1].type != a.ARM_OP_REG
                        or operands[1].reg != a.ARM_REG_SP
                        or operands[2].type != a.ARM_OP_IMM
                        or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                    return None
                magnitude = operands[2].imm
                if magnitude < 0:
                    return None
                delta = magnitude if instruction.id == a.ARM_INS_ADD else -magnitude
            elif a.ARM_REG_SP in written:
                return None
        elif a.ARM_REG_SP in written:
            return None
        next_values = {value + delta for value in values}
        if any(value <= 0 or value >= 0x100000000 for value in next_values):
            return None
        successors = edges.get(site, set())
        if not successors:
            return None
        for successor in successors:
            merged = incoming.setdefault(successor, set())
            before = len(merged)
            merged.update(next_values)
            if len(merged) > 16:
                return None
            if len(merged) != before and successor not in queued:
                pending.append(successor)
                queued.add(successor)
    return next(iter(target_values)) if len(target_values) == 1 else None
