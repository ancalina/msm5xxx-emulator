"""Finalize immutable function observations after bounded traversal."""
from __future__ import annotations

from .fact_models import FunctionFacts
from dataclasses import replace


def finish_function(*,
    _stop_after,
    _stop_before,
    accesses,
    branch_conditions,
    call_sites,
    calls,
    control_edges,
    edges,
    entry,
    flow_targets,
    initial_registers,
    instructions,
    literals,
    loop_frontiers,
    pc_key,
    pending,
    scope_escapes,
    scope_exits,
    stacks,
    symbolic_accesses,
    symbolic_budget_exhausted,
    unresolved,
):
    proof = tuple(sorted(
        {pc.address for pc in instructions}
        | {literal.pool for literal in literals.values()}
    ))
    ordered_instructions = tuple(sorted(instructions.values(), key=pc_key))
    all_calls = tuple(sorted(
        (call for group in calls.values() for call in group),
        key=lambda pair: pc_key(pair[0]),
    ))
    ordered_literals = tuple(sorted(literals.values(), key=lambda item: pc_key(item.instruction)))
    ordered_accesses = tuple(replace(access, evidence=proof)
                             for access in sorted(accesses.values(), key=lambda item: pc_key(item.instruction)))
    ordered_stacks = tuple(stacks[pc] for pc in sorted(stacks, key=pc_key))
    ordered_unresolved = tuple(sorted(unresolved, key=pc_key))
    result = FunctionFacts(
        entry, ordered_instructions, all_calls, ordered_literals,
        ordered_accesses, tuple(sorted(edges)), ordered_stacks,
        ordered_unresolved, (not pending and not unresolved
                             and not symbolic_budget_exhausted[0]
                             and not loop_frontiers and not scope_escapes
                             and (not (_stop_after or _stop_before) or bool(scope_exits))),
        tuple(sorted({target for targets in flow_targets.values()
                      for target in targets}, key=pc_key)),
        tuple(sorted(symbolic_accesses.values(),
                     key=lambda item: pc_key(item.instruction))),
        tuple(sorted(((source, target) for source, targets in control_edges.items()
                      for target in targets),
                     key=lambda pair: (pc_key(pair[0]), pc_key(pair[1])))),
        tuple(call_sites[pc] for pc in sorted(call_sites, key=pc_key)),
        tuple(branch_conditions[pc]
              for pc in sorted(branch_conditions, key=pc_key)),
        tuple(sorted(loop_frontiers, key=lambda pair: (
            pc_key(pair[0]), pc_key(pair[1])))),
        bool(pending or symbolic_budget_exhausted[0]),
        tuple(sorted(scope_exits, key=pc_key)),
        tuple(sorted(scope_escapes, key=pc_key)),
        tuple(sorted(initial_registers.items())),
        tuple(sorted(scope_exits & _stop_before, key=pc_key)),
    )
    return result
