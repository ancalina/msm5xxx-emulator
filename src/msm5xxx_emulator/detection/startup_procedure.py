"""Function-wide closure and discovery of proved startup row consumers."""
from __future__ import annotations
import struct
from dataclasses import replace
from capstone import CS_GRP_INT
from capstone import arm as a
from .facts import CodeAddress, FirmwareFacts, LiteralAccessCandidate, ScatterCandidate
from .startup_cfg import (_loop_nodes, _loop_writes_are_safe, _memory_register,)
from .startup_loops import _loop_condition, _pointer_loop
from .startup_models import (CopyConsumerProof, StartupCopyRow, StartupProcedureProof, StartupSideEffectWrite, StartupStackWrite,)
from .startup_return import caller_preserves_entry_lr

def _startup_function(facts, entry, budget, initial_sp, completion):
    options = dict(initial_registers=({a.ARM_REG_SP: initial_sp} if type(initial_sp) is int else {}), symbolic_registers={})
    if completion is not None:
        return facts.function_region(entry, budget=budget, stop_before=completion, **options)
    return facts.function(entry, budget=budget, **options)

def _prove_copy_consumer(facts: FirmwareFacts, row: ScatterCandidate | StartupCopyRow, references: tuple[LiteralAccessCandidate, ...], entry: CodeAddress | None
    = None, extra_write_ranges=(), initial_sp=None, completion=None,) -> tuple[CopyConsumerProof, ...]:
    """Prove local loops consume a supplied copy row and its zero row.

    Five-word scatter rows keep their original contract. Three-word startup
    rows can name a separate two-word zero row, as used by reset tables.
    """
    separate_zero = isinstance(row, StartupCopyRow) and row.zero_table is not None
    zero_target = row.zero_target
    zero_size = row.zero_size
    zero_table = row.zero_table if isinstance(row, StartupCopyRow) else None
    if isinstance(row, StartupCopyRow):
        row_values = (row.table, row.source, row.target, row.size, row.zero_table, zero_target, zero_size)
    else:
        row_values = (row.table, row.source, row.target, row.size, row.zero_target, row.zero_size)
    has_zero = zero_target is not None or zero_size is not None
    if (any(type(value) is not int or value < 0 or value > 0xFFFFFFFF for value in row_values if value is not None) or row.size == 0 or (has_zero and (zero_target
        is None or zero_size is None or zero_size == 0)) or row.source + row.size > len(facts.image) or row.target + row.size > 0xFFFFFFFF or (has_zero and
        zero_target + zero_size > 0xFFFFFFFF)):
        return ()
    if separate_zero:
        copy_bytes = facts.view.read(row.table, 12, phase='reset', bank='primary')
        zero_bytes = facts.view.read(zero_table, 8, phase='reset', bank='primary')
        copy_expected = struct.pack('<3I', row.source, row.target, row.size)
        zero_expected = struct.pack('<2I', zero_target, zero_size)
        if copy_bytes != copy_expected or zero_bytes != zero_expected:
            return ()
        copy_fields = (row.table, row.table + 4, row.table + 8)
        zero_fields = (zero_table, zero_table + 4)
    elif has_zero:
        row_bytes = facts.view.read(row.table, 20, phase='reset', bank='primary')
        expected_row = struct.pack('<5I', row.source, row.target, row.size, zero_target, zero_size)
        if row_bytes != expected_row:
            return ()
        copy_fields = (row.table, row.table + 4, row.table + 8)
        zero_fields = (row.table + 12, row.table + 16)
    else:
        copy_bytes = facts.view.read(row.table, 12, phase='reset', bank='primary')
        copy_expected = struct.pack('<3I', row.source, row.target, row.size)
        if copy_bytes != copy_expected:
            return ()
        copy_fields = (row.table, row.table + 4, row.table + 8)
        zero_fields = ()
    fields = copy_fields + zero_fields
    row_references = tuple(item for item in references if item.operation == 'read' and item.width == 4 and item.address in fields)
    starts = ([entry] if entry is not None else sorted({item.load for item in row_references if item.address == row.table + 4}, key=lambda pc: (pc.address, pc.isa,
        pc.phase, pc.bank)))
    proofs = []
    for start in starts:
        function = _startup_function(facts, start, 4096, initial_sp, completion)
        if not function.complete:
            continue
        local = tuple(item for item in row_references if item.load in function.instructions and item.use in function.instructions)
        if any(not any(item.address == field for item in local) for field in fields):
            continue
        protected = [(row.source, row.source + row.size), (row.target, row.target + row.size)]
        if has_zero:
            protected.append((zero_target, zero_target + zero_size))
        copy_edge = _pointer_loop(facts, function, local, pointer_field=copy_fields[0], end_pointer_field= copy_fields[1], size_field=copy_fields[2], zero_body=False,
            protected_ranges=tuple(protected), extra_write_ranges=extra_write_ranges,)
        zero_edge = None
        if has_zero:
            zero_edge = _pointer_loop(facts, function, local, pointer_field=zero_fields[0], end_pointer_field= zero_fields[0], size_field=zero_fields[1],
                zero_body=True, protected_ranges=tuple(protected), extra_write_ranges=extra_write_ranges,)
        if copy_edge is None or (has_zero and zero_edge is None):
            continue
        side_effects = []
        for edge in (copy_edge, zero_edge):
            if edge is None:
                continue
            condition = _loop_condition(facts, function, edge, allow_reverse=True)
            if condition is None:
                side_effects = None
                break
            nodes, _, _, _, cursor_register, _ = condition
            stores = tuple(pc for pc in nodes if (ins := facts.decode(pc)) is not None and (memory := (_memory_register(ins, a.ARM_INS_STR) or _memory_register(ins,
                a.ARM_INS_STM))) is not None and memory[1] == cursor_register)
            if len(stores) != 1:
                side_effects = None
                break
            writes = _loop_writes_are_safe(function, nodes, stores[0], tuple(protected), extra_write_ranges)
            if writes is None:
                side_effects = None
                break
            side_effects.extend(writes)
        if side_effects is None:
            continue
        proofs.append(CopyConsumerProof(row.table, start, copy_edge, zero_edge, tuple((field, item.use) for field in fields for item in local if item.address ==
            field), tuple(sorted(set(side_effects), key= lambda item: (item.instruction.address, item.address, item.width, item.value if item.value is not None
            else -1))),))
    return tuple(proofs)

def prove_copy_consumer(facts: FirmwareFacts, row: ScatterCandidate, references: tuple[LiteralAccessCandidate, ...], *, extra_write_ranges: tuple[tuple[int, int],
    ...] = (),) -> tuple[CopyConsumerProof, ...]:
    """Return the cached local copy/zero proof for a row and xrefs."""
    if row.zero_target is None or row.zero_size is None:
        return ()
    extra_write_ranges = tuple(extra_write_ranges)
    key = (row, references, extra_write_ranges)
    return facts.memo('startup-copy-consumer', ('five-word', key), lambda: _prove_copy_consumer(facts, row, references, extra_write_ranges=extra_write_ranges))

def prove_startup_copy_consumer(facts: FirmwareFacts, row: StartupCopyRow, references: tuple[LiteralAccessCandidate, ...], *, entry: CodeAddress | None = None,
    extra_write_ranges: tuple[tuple[int, int], ...] = (), initial_sp: int | None = None, completion: CodeAddress | None = None,) -> tuple[CopyConsumerProof, ...]:
    """Prove a three-word copy row and independently located zero row."""
    if not isinstance(row, StartupCopyRow):
        return ()
    if ((row.zero_table is None) != (row.zero_target is None) or (row.zero_table is None) != (row.zero_size is None)):
        return ()
    shape = 'three-word-separate-zero' if row.zero_table is not None else 'three-word-copy-only'
    extra_write_ranges = tuple(extra_write_ranges)
    initial_sp = initial_sp if type(initial_sp) is int else None
    key = (shape, row, references, entry, extra_write_ranges, initial_sp, completion)
    if entry is not None:
        function = _startup_function(facts, entry, 4096, initial_sp, completion)
        if not function.complete:
            return ()
        fields = {row.table, row.table + 4, row.table + 8}
        if row.zero_table is not None:
            fields.update((row.zero_table, row.zero_table + 4))
        direct = tuple(LiteralAccessCandidate(access.instruction, access.instruction, access.instruction.address, access.address.value, access.width, access.operation,
            access.predicate) for access in function.symbolic_accesses if access.operation == 'read' and access.width == 4 and access.address.kind == 'const'
            and access.address.value in fields)
        references = tuple(sorted(set(references + direct), key=lambda item: (item.address, item.load.address, item.use.address)))
    return facts.memo('startup-copy-consumer', key, lambda: _prove_copy_consumer(facts, row, references, entry, extra_write_ranges, initial_sp, completion))

def proven_startup_rows(facts: FirmwareFacts, entry: CodeAddress, *, target_ranges: tuple[tuple[int, int], ...], zero_ranges: tuple[tuple[int, int], ...] | None
    = None, extra_write_ranges: tuple[tuple[int, int], ...] = (), initial_sp: int | None = None, budget: int = 4096, completion: CodeAddress | None = None,) -> tuple[tuple[StartupCopyRow,
    CopyConsumerProof], ...]:
    """Find supplied three-word rows with a locally proven copy consumer.

    A contiguous following pair is included as a zero row only when its
    target continues directly after the copy span and fits a target range.
    This discovers individual rows; callers own family-specific row counts
    and relationships between separate rows. An explicit completion observes
    memory immediately before that call; it makes no post-call memory claim.
    """
    ranges = tuple(sorted((lo, hi) for lo, hi in target_ranges if type(lo) is int and type(hi) is int and 0 <= lo < hi <= 0x100000000))
    zero_ranges = ranges if zero_ranges is None else tuple(sorted((lo, hi) for lo, hi in zero_ranges if type(lo) is int and type(hi) is int and 0 <= lo < hi <=
        0x100000000))
    extra_write_ranges = tuple(sorted((lo, hi) for lo, hi in extra_write_ranges if type(lo) is int and type(hi) is int and 0 <= lo < hi <= 0x100000000))
    initial_sp = (initial_sp if type(initial_sp) is int and 0 <= initial_sp <= 0x100000000 else None)
    if (not isinstance(entry, CodeAddress) or not ranges or budget <= 0):
        return ()
    if completion is not None:
        if not isinstance(completion, CodeAddress):
            return ()
        instruction = facts.decode(completion)
        if (completion == entry or (completion.phase, completion.bank, completion.isa) != (entry.phase, entry.bank, entry.isa) or instruction is None or
            instruction.id not in (a.ARM_INS_BL, a.ARM_INS_BLX)):
            return ()
    def extract():
        function = _startup_function(facts, entry, budget, initial_sp, completion)
        if not function.complete or function.truncated or function.unresolved:
            return ()
        candidates = set()
        for literal in function.literals:
            pointer = literal.value
            if type(pointer) is not int:
                continue
            for backstep in (0, 4, 8):
                table = pointer - backstep
                if table >= 0 and not table & 3:
                    candidates.add(table)
        proven = {}
        for table in sorted(candidates):
            raw = facts.view.read(table, 12, phase=entry.phase, bank=entry.bank)
            if raw is None:
                continue
            source, target, size = struct.unpack('<3I', raw)
            end = target + size
            if (size <= 0 or (source | target | size) & 3 or source + size > 0x100000000 or not facts.view.covers(source, size, phase=entry.phase, bank=entry.bank)
                or not any(lo <= target < end <= hi for lo, hi in ranges)):
                continue
            zero_table = zero_target = zero_size = None
            zero_raw = facts.view.read(table + 12, 8, phase=entry.phase, bank=entry.bank)
            if zero_raw is not None:
                candidate_target, candidate_size = struct.unpack('<2I', zero_raw)
                candidate_end = candidate_target + candidate_size
                if (candidate_size > 0 and not (candidate_target | candidate_size) & 3 and end == candidate_target and any(lo <= candidate_target <
                    candidate_end <= hi for lo, hi in zero_ranges)):
                    zero_table = table + 12
                    zero_target = candidate_target
                    zero_size = candidate_size
            row = StartupCopyRow(table, source, target, size, zero_table, zero_target, zero_size)
            spans = [(table, table + 12)]
            if zero_table is not None:
                spans.append((zero_table, zero_table + 8))
            mapped = facts.view.contiguous_ranges(phase=entry.phase, bank=entry.bank)
            scan_end = max((hi for _, hi in mapped), default=facts.base)
            references = facts.literal_access_candidates(tuple(spans), phase=entry.phase, bank=entry.bank, limit=max(0, scan_end - facts.base))
            consumers = prove_startup_copy_consumer(facts, row, references, entry=entry, extra_write_ranges= extra_write_ranges, initial_sp=initial_sp,
                completion=completion)
            if (len(consumers) == 1 and consumers[0].entry in function.instructions):
                proven[table] = (row, consumers[0])
        # TODO: projections with code-use-order contracts must correlate each
        # consumer before using this address-sorted discovery order.
        ordered = tuple(proven[table] for table in sorted(proven))
        if not ordered:
            return ()
        procedure = _close_startup_procedure(facts, function, ordered, extra_write_ranges, initial_sp, completion)
        if procedure is None:
            return ()
        return tuple((row, replace(proof, procedure=procedure)) for row, proof in ordered)
    return facts.memo('proven-startup-rows', (entry, ranges, zero_ranges, extra_write_ranges, initial_sp, budget, completion), extract)

def _close_startup_procedure(facts, function, proven, extra_write_ranges, initial_sp, completion=None):
    """Close all function writes around the supplied proved row loops."""
    if not function.complete or function.truncated or function.unresolved:
        return None
    loop_edges = tuple(sorted({edge for _, proof in proven for edge in (proof.copy_back_edge, proof.zero_back_edge) if edge is not None}))
    loop_nodes = set()
    for edge in loop_edges:
        nodes = _loop_nodes(function, edge)
        if not nodes:
            return None
        loop_nodes.update(nodes)
    terminals = set(function.instructions) - { source for source, _ in function.control_edges}
    if not terminals:
        return None
    if completion is not None and (terminals != {completion} or function.scope_before != (completion,) or function.scope_escapes):
        return None
    frame = facts.stack_frame(function)
    if (frame is None or not frame.complete or completion is None and not frame.balanced or function.calls and initial_sp is None):
        return None
    helper_code_spans = set()
    for _site, target in function.calls:
        call_ins = facts.decode(_site)
        helper = facts.function(target, budget=16, symbolic_registers={})
        if (call_ins is None or call_ins.id not in (a.ARM_INS_BL, a.ARM_INS_BLX) or not helper.complete or helper.truncated or helper.unresolved or helper.calls
            or helper.back_edges or len(helper.instructions) != 1):
            return None
        helper_ins = facts.decode(helper.entry)
        if (helper_ins is None or helper_ins.id != a.ARM_INS_BX or helper_ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or len(helper_ins.operands) != 1 or
            helper_ins.operands[0].type != a.ARM_OP_REG or helper_ins.operands[0].reg != a.ARM_REG_LR or helper.symbolic_accesses or facts.unmodelled_memory(helper)
            != ()):
            return None
        helper_code_spans.add((helper.entry.address, helper.entry.address + helper_ins.size))
    loop_store_ranges = []
    for row, proof in proven:
        transfers = [(proof.copy_back_edge, (row.target, row.target + row.size))]
        if row.zero_target is not None:
            transfers.append((proof.zero_back_edge, (row.zero_target, row.zero_target + row.zero_size)))
        for edge, span in transfers:
            condition = _loop_condition(facts, function, edge, allow_reverse=True)
            if condition is None:
                return None
            nodes, _, _, _, cursor_register, _ = condition
            stores = tuple(pc for pc in nodes if (instruction := facts.decode(pc)) is not None and (memory := (_memory_register(instruction, a.ARM_INS_STR) or
                _memory_register(instruction, a.ARM_INS_STM))) is not None and memory[1] == cursor_register)
            if len(stores) != 1:
                return None
            loop_store_ranges.append((stores[0], *span))
    if completion is None and not caller_preserves_entry_lr(facts, function, frame, function.calls, terminals, initial_sp, {site for site, _ in function.calls},
        tuple(loop_store_ranges)):
        return None
    if any((instruction := facts.decode(site)) is None or instruction.group(CS_GRP_INT) for site in function.instructions):
        return None
    for edge in loop_edges:
        condition = _loop_condition(facts, function, edge, allow_reverse=True)
        if (condition is None or any(not function.dominates(site, terminal) for site in (condition[1], condition[3]) for terminal in terminals)):
            return None
    protected_spans = []
    for row, _ in proven:
        protected_spans.extend(((row.source, row.source + row.size), (row.target, row.target + row.size)))
        if row.zero_target is not None:
            protected_spans.append((row.zero_target, row.zero_target + row.zero_size))
    protected = tuple(protected_spans)
    side_effects = [item for _, proof in proven for item in proof.side_effect_writes]
    stack_sites = set()
    if frame.accesses and not frame.balanced and completion is None:
        return None
    stack_sites = {access.site for access in frame.accesses}
    # Scalar stores outside the loops must be explicit device writes and must
    # stay clear of every source or destination materialized by these rows.
    for access in function.symbolic_accesses:
        if access.operation != 'write' or access.instruction in loop_nodes:
            continue
        if access.instruction in stack_sites:
            continue
        if (access.address.kind != 'const' or type(access.address.value) is not int or type(access.width) is not int or access.width <= 0 or access.predicate
            not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
            return None
        address = access.address.value
        end = address + access.width
        if end > 0x100000000 or any(address < hi and lo < end for lo, hi in protected):
            return None
        if not any(lo <= address and end <= hi for lo, hi in extra_write_ranges):
            return None
        value = (access.value.value if access.value is not None and access.value.kind == 'const' and type(access.value.value) is int else None)
        side_effects.append(StartupSideEffectWrite(access.instruction, address, access.width, value))
    unmodelled = facts.unmodelled_memory(function)
    if unmodelled is None:
        return None
    # Each local transfer proof already closes its selected memory operations.
    # Single-word LDM/STM remains unsupported by the general scalar model.
    if any(site in loop_nodes and not (_memory_register(facts.decode(site), a.ARM_INS_LDM) or _memory_register(facts.decode(site), a.ARM_INS_STM)) for site in
        unmodelled):
        return None
    if any(site not in loop_nodes and site not in stack_sites for site in unmodelled):
        return None
    stack_writes = []
    unknown_stack_writes = []
    stack_accesses = frame.accesses
    for access in stack_accesses:
        if access.operation != 'write' or access.site in loop_nodes:
            continue
        if initial_sp is None:
            return None
        address = initial_sp + access.offset
        end = address + access.width
        if address < 0 or end > 0x100000000:
            return None
        if any(address < hi and lo < end for lo, hi in protected):
            # A stack write overlapping a source is never safe. A destination
            # is safe only when a later, fully proved zero loop kills it.
            if any(address < hi and lo < end for row, _ in proven for lo, hi in ((row.source, row.source + row.size),)):
                return None
            covering = []
            for row, proof in proven:
                if (row.zero_target is None or proof.zero_back_edge is None or not row.zero_target <= address or end > row.zero_target + row.zero_size):
                    continue
                condition = _loop_condition(facts, function, proof.zero_back_edge, allow_reverse=True)
                if condition is None:
                    continue
                nodes, compare_pc, _, outside, _, _ = condition
                if (access.site not in function.instructions or not function.dominates(access.site, compare_pc) or any(not function.dominates(outside, terminal)
                    for terminal in terminals)):
                    continue
                covering.append((proof.zero_back_edge, outside))
            if len(covering) != 1:
                return None
            stack_writes.append(StartupStackWrite(access.site, address, access.width, access.register, covering[0][0]))
        else:
            # Preserve the effect as unknown so the post-load view cannot
            # expose stale bytes at a stack location written by startup code.
            unknown_stack_writes.append(StartupSideEffectWrite(access.site, address, access.width, None))
    rows = tuple(row for row, _ in proven)
    return StartupProcedureProof(function.entry, rows, loop_edges, tuple(sorted(set(side_effects), key=lambda item: (item.instruction.address, item.address,
        item.width))), tuple(sorted(stack_writes, key=lambda item: (item.instruction.address, item.address, item.width))), tuple(stack_accesses), tuple(sorted(helper_code_spans)),
        tuple(sorted(unknown_stack_writes, key=lambda item: (item.instruction.address, item.address, item.width))), completion)
