"""Bounded reset-rooted call and concrete interworking transfers."""
from __future__ import annotations

from dataclasses import dataclass
from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.startup_entry import _manual_wrapper


@dataclass(frozen=True)
class ResetCallContext:
    entry: CodeAddress
    initial_registers: tuple[tuple[int, int], ...]
    evidence: tuple[tuple[int, int], ...]
    stack_proven: bool
    depth: int


def _stack_at_transfer(facts, function, transfer, ram_base, ram_end):
    for address, mode, pointer in function.mode_stacks:
        if mode != 0x13 or type(pointer) is not int or not ram_base < pointer <= ram_end:
            continue
        site = next((item for item in function.instructions
                     if item.address == address and item.isa == transfer.isa), None)
        if site is None:
            continue
        path = function.linear_path(site, transfer)
        if not function.dominates(site, transfer) and path is None:
            continue
        literal = facts.literal(site)
        if literal is None or literal.register != a.ARM_REG_SP or literal.value != pointer:
            continue
        scan = path[1:] if path is not None else tuple(
            item for item in function.instructions if address < item.address < transfer.address)
        safe = True
        for item in scan:
            ins = facts.decode(item)
            if ins is None or ins.id in (a.ARM_INS_MSR, getattr(a, "ARM_INS_CPS", -1)):
                safe = False
                break
            try:
                _, written = ins.regs_access()
            except Exception:
                safe = False
                break
            if a.ARM_REG_SP in written:
                safe = False
                break
        if safe:
            return True, ((address, 4), (literal.pool, 4))
    return False, ()


def reset_stack_at_transfer(facts, function, transfer, ram_base, ram_end):
    """Return a dominating SVC stack pointer for a reset-linked transfer."""
    proven, spans = _stack_at_transfer(facts, function, transfer, ram_base, ram_end)
    if not proven:
        return None
    return next((pointer for address, mode, pointer in function.mode_stacks
                 if mode == 0x13 and (address, 4) in spans), None)


def reset_call_contexts(facts, root: CodeAddress, *, ram_base: int, ram_end: int,
                        max_contexts: int = 128, max_depth: int = 6,
                        instruction_budget: int = 1024,
                        initial_registers=None, stack_proven: bool = False,
                        route_spans=()):
    """Follow direct calls and concrete BX register values from one reset root."""
    if (not isinstance(root, CodeAddress) or type(max_contexts) is not int
            or not 1 <= max_contexts <= 128 or max_depth != 6
            or instruction_budget != 1024):
        return ()
    initial = tuple(sorted((reg, value) for reg, value in
                           dict(initial_registers or {}).items()
                           if type(value) is int))
    route = tuple(route_spans) or ((root.address, 4),)
    pending = [(root, initial, route, bool(stack_proven), 0)]
    seen = set()
    results = []
    while pending and len(seen) < max_contexts:
        entry, regs_tuple, route, inherited_stack, depth = pending.pop(0)
        if depth > max_depth:
            continue
        regs_tuple = tuple(sorted((reg, value) for reg, value in regs_tuple
                                  if type(value) is int))
        key = (entry, regs_tuple, inherited_stack)
        if key in seen:
            continue
        seen.add(key)
        initial = dict(regs_tuple)
        function = facts.function(entry, budget=instruction_budget,
                                  initial_registers=initial, symbolic_registers={})
        if not function.instructions or function.truncated:
            continue
        spans = set(route)
        for site in function.instructions:
            ins = facts.decode(site)
            if ins is not None:
                spans.add((site.address, ins.size))
        spans.update((literal.pool, 4) for literal in function.literals)
        results.append(ResetCallContext(entry, regs_tuple, tuple(sorted(spans)),
                                        inherited_stack, depth))
        if len(results) >= max_contexts:
            break
        calls = {site: target for site, target in function.calls}
        call_facts = {item.site: item for item in function.call_sites}
        for transfer, target in function.control_edges:
            if transfer.isa != "arm" or target.isa != "thumb":
                continue
            wrapper = _manual_wrapper(facts, function, transfer, target)
            if wrapper is None:
                continue
            _load, literal, return_words, returns = wrapper
            stack, stack_spans = _stack_at_transfer(
                facts, function, transfer, ram_base, ram_end)
            wrapper_spans = {(literal.pool, 4), *stack_spans,
                             (transfer.address, 4), (target.address, 4)}
            wrapper_spans.update((pool, 4) for pool, _ in return_words)
            pending.append((target, (), tuple(sorted(set(spans) | wrapper_spans)),
                            inherited_stack or stack, depth + 1))
            for returned in returns:
                if returned.isa == target.isa:
                    pending.append((returned, (), tuple(sorted(set(spans) |
                                    wrapper_spans | {(returned.address, 4)})),
                                    inherited_stack or stack, depth + 1))
        for site, target in calls.items():
            if depth == max_depth:
                continue
            details = call_facts.get(site)
            arguments = ()
            if details is not None:
                arguments = tuple((reg, value) for reg, value in details.registers[:4]
                                  if reg in (a.ARM_REG_R0, a.ARM_REG_R1,
                                             a.ARM_REG_R2, a.ARM_REG_R3)
                                  and type(value) is int)
            stack, stack_spans = _stack_at_transfer(
                facts, function, site, ram_base, ram_end)
            pending.append((target, arguments,
                            tuple(sorted(set(spans) | set(stack_spans) |
                                         {(site.address, 4), (target.address, 4)})),
                            inherited_stack or stack, depth + 1))
        if depth == max_depth:
            continue
        for source, target in function.control_edges:
            ins = facts.decode(source)
            if (ins is None or ins.id != a.ARM_INS_BX or len(ins.operands) != 1
                    or ins.operands[0].type != a.ARM_OP_REG
                    or target == source or target not in set(function.flow_targets)):
                continue
            reg = ins.operands[0].reg
            if reg == a.ARM_REG_PC:
                value = (source.address + 4) & ~3
            else:
                value = facts.register_value(function, source, reg)
            if type(value) is not int:
                # Re-query the abstract state at the transfer; only a concrete
                # code address in a register can create a new root.
                value = dict(function.initial_registers).get(reg)
            if type(value) is not int or (value & ~1) != target.address:
                continue
            stack, stack_spans = _stack_at_transfer(
                facts, function, source, ram_base, ram_end)
            pending.append((target, (), tuple(sorted(set(spans) |
                            set(stack_spans) |
                            {(source.address, ins.size), (target.address, 4)})),
                            inherited_stack or stack, depth + 1))
    return tuple(results)
