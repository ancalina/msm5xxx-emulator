"""Ordered copy, clear, and bounded reset-prefix transfer proofs."""
from __future__ import annotations

import struct
from dataclasses import replace

from capstone import CS_GRP_INT
from capstone import arm as a

from .facts import (CodeAddress, FirmwareFacts, FunctionFacts,
                    LiteralAccessCandidate)
from .startup_cfg import (
    _definition_reaches, _loop_nodes, _loop_writes_are_safe,
    _memory_register,
)
from .startup_loops import (
    _constant_register_value, _loop_condition, _loop_iteration_cut,
    _ordered_transfer_completion, _pointer_loop, _strict_loop_recurrence,
    _returns_to_link, _writes_register,
)
from .startup_models import (
    CopyLoopTransfer, OrderedCopyTransfer, ResetPrefixProof,
    StartupSideEffectWrite, VectorCopyRow,
)

def prove_reset_prefix_completion(
        facts: FirmwareFacts, reset_entry: CodeAddress,
        transfer: OrderedCopyTransfer, *, budget: int = 8192
        ) -> ResetPrefixProof | None:
    """Prove a bounded reset path to a callable cross-ISA handoff.

    This establishes only that the selected copy completion precedes the
    located handoff in the bounded reset CFG. It does not certify unrelated
    reset branches or prove that the handoff target consumes copied state.
    """
    if (not isinstance(reset_entry, CodeAddress)
            or not isinstance(transfer, OrderedCopyTransfer)
            or transfer.completion is None
            or transfer.entry.phase != reset_entry.phase
            or transfer.entry.bank != reset_entry.bank):
        return None
    function = facts.function(reset_entry, budget=budget,
                              stop_at_initial_return=True)
    if (not function.complete or function.truncated or function.unresolved
            or transfer.entry not in function.instructions
            or transfer.completion not in function.instructions
            or not function.dominates(reset_entry, transfer.entry)
            or not function.dominates(transfer.entry, transfer.completion)):
        return None
    handoffs = []
    for site, target in function.control_edges:
        if (site not in function.instructions or target not in function.instructions
                or site.isa == target.isa
                or not function.dominates(transfer.entry, site)
                or not function.dominates(transfer.completion, site)
                or not function.dominates(transfer.entry, target)
                or not function.dominates(transfer.completion, target)):
            continue
        instruction = facts.decode(site)
        if (instruction is None
                or instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or not ((instruction.id == a.ARM_INS_BX
                         and len(instruction.operands) == 1
                         and instruction.operands[0].type == a.ARM_OP_REG)
                        or (instruction.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                            and len(instruction.operands) == 2
                            and instruction.operands[0].type == a.ARM_OP_REG
                            and instruction.operands[0].reg == a.ARM_REG_PC
                            and instruction.operands[1].type == a.ARM_OP_REG))):
            continue
        prologue = facts.decode(target)
        saved_registers = tuple(item.reg for item in prologue.operands
                                if item.type == a.ARM_OP_REG)
        saves_link = (
            prologue is not None
            and ((prologue.id == a.ARM_INS_PUSH
                  and a.ARM_REG_LR in saved_registers)
                 or (prologue.id == a.ARM_INS_STMDB
                     and prologue.writeback
                     and len(prologue.operands) >= 2
                     and prologue.operands[0].type == a.ARM_OP_REG
                     and prologue.operands[0].reg == a.ARM_REG_SP
                     and a.ARM_REG_LR in saved_registers)))
        if not saves_link:
            continue
        callee = facts.function(target, budget=2048,
                                stop_at_initial_return=True)
        returns = tuple(pc for pc in callee.instructions
                        if _returns_to_link(facts.decode(pc)))
        if (not callee.complete or callee.truncated or callee.unresolved
                or len(returns) != 1
                or not callee.dominates(target, returns[0])):
            continue
        handoffs.append((site, target))
    if len(handoffs) != 1:
        return None
    site, target = handoffs[0]
    call_sites = {call_site for call_site, _ in function.calls}
    edge_sources = {source for source, _ in function.control_edges}
    for terminal in set(function.instructions) - edge_sources:
        if not _returns_to_link(facts.decode(terminal)):
            continue
        incoming = {source for source, target_pc in function.control_edges
                    if target_pc == terminal}
        if incoming and incoming <= call_sites:
            # The flattened CFG cannot model opaque nested call-return state.
            continue
        if (not function.dominates(transfer.entry, terminal)
                or not function.dominates(transfer.completion, terminal)):
            return None
    return ResetPrefixProof(reset_entry, transfer.entry,
                            transfer.completion, site, target)

def _stride_exit(initial, bound, stride):
    if (type(initial) is not int or type(bound) is not int
            or type(stride) is not int or stride <= 0
            or not 0 <= initial <= 0xFFFFFFFF
            or not 0 <= bound <= 0xFFFFFFFF):
        return None
    iterations = ((bound - initial + stride - 1) // stride
                  if bound > initial else 0)
    final = initial + iterations * stride
    return (iterations, final) if final <= 0xFFFFFFFF else None

def _loop_transfer(facts, function, edge, context, *, zero_body):
    """Evaluate one proven stride-four loop from its pre-test register state."""
    condition = _loop_condition(facts, function, edge)
    if condition is None:
        return None
    nodes, compare_pc, _, outside, cursor_register, bound_register = condition
    iteration = _loop_iteration_cut(function, nodes, edge)
    if iteration is None:
        return None
    initial = _constant_register_value(facts, context, compare_pc,
                                       cursor_register)
    bound = _constant_register_value(facts, context, compare_pc,
                                     bound_register)
    if initial is None or bound is None:
        return None

    source_register = None
    source_value = None
    if not zero_body:
        decoded = {pc: facts.decode(pc) for pc in nodes}
        source_bases = set()
        for load_pc in nodes:
            loaded = _memory_register(decoded.get(load_pc), a.ARM_INS_LDR)
            if loaded is None:
                continue
            value_register, source_base = loaded
            for store_pc in nodes:
                stored = _memory_register(decoded.get(store_pc), a.ARM_INS_STR)
                if (stored is not None and stored[0] == value_register
                        and stored[1] == cursor_register
                        and _definition_reaches(
                            facts, function, load_pc, store_pc, value_register,
                            iteration[0])):
                    source_bases.add(source_base)
        if len(source_bases) != 1:
            return None
        source_register = next(iter(source_bases))
        source_value = _constant_register_value(facts, context, compare_pc,
                                                source_register)
        if source_value is None:
            return None

    stride = 4
    exit_value = _stride_exit(initial, bound, stride)
    if exit_value is None:
        return None
    iterations, final = exit_value
    source_exit = (_stride_exit(source_value, source_value + iterations * stride,
                                stride)
                   if source_value is not None else None)
    if source_value is not None and source_exit is None:
        return None
    source_final = source_exit[1] if source_exit is not None else None
    return (CopyLoopTransfer(
        edge, compare_pc, cursor_register, source_register,
        initial, bound, stride, iterations, final,
        source_value, source_final, outside), outside)

def _compose_ordered_transfers(entry, row, copy_loops, clear_loops,
                               protected_ranges=(), completion=None):
    copy_spans = tuple((item.initial_source, item.final_source,
                        item.initial_cursor, item.final_cursor)
                       for item in copy_loops)
    clear_spans = tuple((item.initial_cursor, item.final_cursor)
                        for item in clear_loops)
    if (len(copy_spans) < 2 or len(clear_spans) < 2
            or any(None in span or span[1] <= span[0] or span[3] <= span[2]
                   or span[1] - span[0] != span[3] - span[2]
                   for span in copy_spans)
            or any(item[0] != previous[1]
                   for previous, item in zip(copy_spans, copy_spans[1:]))
            or any(item[2] != previous[3]
                   for previous, item in zip(copy_spans, copy_spans[1:]))
            or any(end <= start for start, end in clear_spans)
            or any(item[0] != previous[1]
                   for previous, item in zip(clear_spans, clear_spans[1:]))):
        return None
    copied_source = (copy_spans[0][0], copy_spans[-1][1])
    copied_target = (copy_spans[0][2], copy_spans[-1][3])
    cleared_target = (clear_spans[0][0], clear_spans[-1][1])
    if (copied_source != (row.source, row.source + row.size)
            or copied_target != (row.target, row.end)
            or cleared_target[0] != row.end
            or any(max(lo, start) < min(hi, end)
                   for lo, hi in protected_ranges
                   for start, end in clear_spans)):
        return None
    return OrderedCopyTransfer(entry, copy_loops, clear_loops, copy_spans,
                               clear_spans, copied_source, copied_target,
                               cleared_target, completion)

def prove_ordered_copy_transfer(
        facts: FirmwareFacts, row: VectorCopyRow,
        references: tuple[LiteralAccessCandidate, ...], *,
        entry: CodeAddress, protected_ranges: tuple[tuple[int, int], ...] = (),
        extra_write_ranges: tuple[tuple[int, int], ...] = (),
        ) -> tuple[OrderedCopyTransfer, ...]:
    """Summarize adjacent scalar copy and zero loops with explicit exits.

    This proves local loop transfer and ordered spans. It does not claim that
    reset reaches or executes the function.
    """
    if (not isinstance(row, VectorCopyRow) or not isinstance(entry, CodeAddress)
            or not facts.view.covers(row.table, 20, phase=entry.phase,
                                     bank=entry.bank)
            or facts.view.read(row.table, 16, phase=entry.phase,
                               bank=entry.bank) != struct.pack(
                                   '<4I', row.source, row.target, row.size, row.end)
            or not facts.view.covers(row.source, row.size, phase=entry.phase,
                                     bank=entry.bank)):
        return ()
    tail_raw = facts.view.read(row.table + 16, 4, phase=entry.phase,
                               bank=entry.bank)
    if tail_raw is None:
        return ()
    clear_end = row.end + struct.unpack('<I', tail_raw)[0]
    if clear_end > 0x100000000:
        return ()
    loop_protected = tuple(protected_ranges) + (
        (row.source, row.source + row.size),
        (row.target, row.end), (row.end, clear_end))
    function = facts.function(entry, budget=4096, symbolic_registers={})
    if not function.complete or function.unresolved:
        return ()
    local = tuple(item for item in references
                  if item.operation == 'read' and item.width == 4
                  and item.load in function.instructions
                  and item.use in function.instructions)
    if not local:
        return ()
    all_edges = tuple(function.back_edges)
    copy_edges = _pointer_loop(
        facts, function, local, pointer_field=row.table,
        end_pointer_field=row.table + 4, size_field=row.table + 8,
        zero_body=False, protected_ranges=loop_protected,
        all_matches=True, continuation_edges=all_edges)
    clear_edges = _pointer_loop(
        facts, function, local, pointer_field=row.table + 12,
        end_pointer_field=row.table + 12, size_field=row.table + 16,
        zero_body=True, protected_ranges=loop_protected,
        all_matches=True, continuation_edges=all_edges)
    if len(copy_edges) < 2 or len(clear_edges) < 2:
        return ()
    copy_order = sorted(copy_edges, key=lambda edge: edge[0])
    clear_order = sorted(clear_edges, key=lambda edge: edge[0])

    def validate_cursor_origins(edges):
        for index, edge in enumerate(edges):
            continuation = (edge,) if index else ()
            matched = _pointer_loop(
                facts, function, local,
                pointer_field=(row.table if edges is copy_order else row.table + 12),
                end_pointer_field=(row.table + 4 if edges is copy_order else row.table + 12),
                size_field=(row.table + 8 if edges is copy_order else row.table + 16),
                zero_body=edges is clear_order,
                protected_ranges=loop_protected, all_matches=True,
                continuation_edges=continuation, only_edges=(edge,))
            if edge not in matched:
                return False
            pointer_field = (row.table if edges is copy_order else row.table + 12)
            cursor_field = (row.table + 4
                            if edges is copy_order else row.table + 12)
            if not _strict_loop_recurrence(
                    facts, function, edge, zero_body=edges is clear_order,
                    cursor_references=tuple(item for item in local
                                            if item.address == cursor_field),
                    source_references=tuple(item for item in local
                                            if item.address == pointer_field),
                    continuation=bool(continuation),
                    protected_ranges=loop_protected):
                return False
        return True

    if not validate_cursor_origins(copy_order) or not validate_cursor_origins(clear_order):
        return ()

    def build(edges, *, zero_body, previous_exit=None):
        transfers = []
        for index, edge in enumerate(edges):
            condition = _loop_condition(facts, function, edge,
                                        allow_reverse=True)
            if condition is None:
                return None
            _, compare_pc, _, _, _, _ = condition
            if index == 0 and previous_exit is None:
                start_pc, initial_registers = entry, {}
            elif index == 0:
                start_pc, initial_registers = previous_exit
            else:
                prior, start_pc = transfers[-1]
                initial_registers = {
                    prior.cursor_register: prior.final_cursor,
                }
                if prior.source_register is not None:
                    initial_registers[prior.source_register] = prior.final_source
            context = facts.function_region(
                start_pc, compare_pc, budget=4096,
                initial_registers=initial_registers,
                symbolic_registers={})
            if (not context.complete or context.unresolved
                    or compare_pc not in context.instructions):
                return None
            transfer = _loop_transfer(facts, function, edge, context,
                                      zero_body=zero_body)
            if transfer is None:
                return None
            summary, outside = transfer
            if index:
                prior = transfers[-1][0]
                if summary.initial_cursor != prior.final_cursor:
                    return None
                if summary.source_register is not None and (
                        prior.source_register != summary.source_register
                        or summary.initial_source != prior.final_source):
                    return None
            transfers.append((summary, outside))
        return transfers

    copies = build(copy_order, zero_body=False)
    if not copies:
        return ()
    copy_last, copy_outside = copies[-1]
    zeros = build(
        clear_order, zero_body=True,
        previous_exit=(copy_outside,
                       {copy_last.cursor_register: copy_last.final_cursor}),
    )
    if not zeros:
        return ()
    copy_loops = tuple(item[0] for item in copies)
    clear_loops = tuple(item[0] for item in zeros)
    completion = _ordered_transfer_completion(
        facts, function, copy_loops + clear_loops)
    if completion is None:
        return ()
    transfer = _compose_ordered_transfers(
        entry, row, copy_loops, clear_loops, protected_ranges, completion)
    if (transfer is None
            or transfer.cleared_target[1]
                != clear_end):
        return ()
    closed = _close_ordered_transfer_writes(
        facts, function, transfer, tuple(extra_write_ranges))
    return (closed,) if closed is not None else ()

def _close_ordered_transfer_writes(facts, function, transfer,
                                   extra_write_ranges):
    """Reject unaccounted function writes outside ordered transfer loops."""
    loop_edges = tuple(item.back_edge for item in
                       transfer.copy_loops + transfer.clear_loops)
    loop_nodes = set()
    for edge in loop_edges:
        nodes = _loop_nodes(function, edge)
        if not nodes:
            return None
        loop_nodes.update(nodes)
    if function.calls:
        return None
    if any((instruction := facts.decode(site)) is None
           or instruction.group(CS_GRP_INT)
           for site in function.instructions):
        return None
    terminals = set(function.instructions) - {
        source for source, _ in function.control_edges}
    if not terminals:
        return None
    for loop in transfer.copy_loops + transfer.clear_loops:
        condition = _loop_condition(facts, function, loop.back_edge,
                                    allow_reverse=True)
        if (condition is None
                or any(not function.dominates(condition[3], terminal)
                       for terminal in terminals)):
            return None
    protected = (transfer.copied_source, transfer.copied_target,
                 transfer.cleared_target)
    writes = []
    for loop in transfer.copy_loops + transfer.clear_loops:
        condition = _loop_condition(facts, function, loop.back_edge,
                                    allow_reverse=True)
        if condition is None:
            return None
        nodes, _, _, _, cursor, _ = condition
        stores = tuple(
            pc for pc in nodes
            if (instruction := facts.decode(pc)) is not None
            and (memory := _memory_register(instruction, a.ARM_INS_STR)) is not None
            and memory[1] == cursor)
        if len(stores) != 1:
            return None
        loop_writes = _loop_writes_are_safe(
            function, nodes, stores[0], protected, extra_write_ranges)
        if loop_writes is None:
            return None
        writes.extend(loop_writes)
    for access in function.symbolic_accesses:
        if access.operation != 'write' or access.instruction in loop_nodes:
            continue
        if (access.address.kind != 'const'
                or type(access.address.value) is not int
                or type(access.width) is not int or access.width <= 0
                or access.predicate not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
            return None
        address, end = access.address.value, access.address.value + access.width
        if (end > 0x100000000
                or any(address < hi and lo < end for lo, hi in protected)
                or not any(lo <= address and end <= hi
                           for lo, hi in extra_write_ranges)):
            return None
        value = (access.value.value if access.value is not None
                 and access.value.kind == 'const'
                 and type(access.value.value) is int else None)
        writes.append(StartupSideEffectWrite(
            access.instruction, address, access.width, value))
    unmodelled = facts.unmodelled_memory(function)
    if unmodelled is None or unmodelled:
        return None
    return replace(transfer, side_effect_writes=tuple(sorted(
        set(writes), key=lambda item: (item.instruction.address,
                                       item.address, item.width))))

