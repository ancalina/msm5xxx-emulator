"""Code-linked reset entries with validated interworking and stack state."""
from __future__ import annotations
from dataclasses import dataclass
import struct
from capstone import CS_GRP_CALL, CS_GRP_INT
from capstone import arm as a
from .facts import CodeAddress, FirmwareFacts, FunctionFacts
from .image_view import LoadOperation
from .startup_facts import StartupCopyRow, CopyConsumerProof, proven_startup_rows

@dataclass(frozen=True, slots=True)
class StartupEntryProof:
    """A reset-linked indirect entry and the active mode stack at its handoff."""

    reset_entry: CodeAddress
    transfer: CodeAddress
    target: CodeAddress
    stack_site: CodeAddress
    stack_pointer: int
    processor_mode: int
    source_spans: tuple[tuple[int, int], ...]
    code_spans: tuple[tuple[int, int], ...]
    literal_spans: tuple[tuple[int, int], ...]
    return_targets: tuple[CodeAddress, CodeAddress]

@dataclass(frozen=True, slots=True)
class StartupCopyContext:
    """One reset-linked entry, its concrete stack, and proved copy rows."""

    entry: StartupEntryProof
    function: FunctionFacts
    rows: tuple[tuple[StartupCopyRow, CopyConsumerProof], ...]
    source_spans: tuple[tuple[int, int], ...]

def reset_vector_entry(facts: FirmwareFacts) -> CodeAddress | None:
    """Return the unique executable target of the reset vector at address zero."""
    targets = {target for site, target in facts.vectors() if site.address == facts.base and site.isa == 'arm' and site.phase == 'reset' and site.bank ==
        'primary'}
    return next(iter(targets)) if len(targets) == 1 else None

def _literal(function: FunctionFacts, instruction: CodeAddress):
    matches = tuple(item for item in function.literals if item.instruction == instruction)
    return matches[0] if len(matches) == 1 else None

def _literal_word(facts: FirmwareFacts, site: CodeAddress, instruction):
    if (instruction is None or instruction.id != a.ARM_INS_LDR or len(instruction.operands) != 2 or instruction.operands[1].type != a.ARM_OP_MEM or instruction.operands[1].mem.base
        != a.ARM_REG_PC or instruction.operands[1].mem.index or instruction.writeback):
        return None
    pool = site.address + 8 + instruction.operands[1].mem.disp
    raw = facts.view.read(pool, 4, phase=site.phase, bank=site.bank)
    if raw is None:
        return None
    return pool, struct.unpack('<I', raw)[0]

def _manual_wrapper(facts: FirmwareFacts, function: FunctionFacts, transfer: CodeAddress, target: CodeAddress):
    """Validate LDR/TST/conditional-return-loads/BX around one handoff."""
    if transfer.isa != 'arm' or target.isa not in ('arm', 'thumb'):
        return None
    sites = tuple(CodeAddress(transfer.address - offset, 'arm', transfer.phase, transfer.bank) for offset in (16, 12, 8, 4))
    if any(site not in function.instructions for site in sites):
        return None
    target_load, test_site, first_return, second_return = sites
    load = facts.decode(target_load)
    test = facts.decode(test_site)
    first = facts.decode(first_return)
    second = facts.decode(second_return)
    bx = facts.decode(transfer)
    if (load is None or load.id != a.ARM_INS_LDR or len(load.operands) != 2 or load.operands[0].type != a.ARM_OP_REG or load.operands[1].type != a.ARM_OP_MEM or
        load.operands[1].mem.base != a.ARM_REG_PC or load.operands[1].mem.index or load.writeback):
        return None
    register = load.operands[0].reg
    literal = _literal(function, target_load)
    if (literal is None or literal.register != register or literal.value & 0xFFFFFFFE != target.address or (bool (literal.value & 1) != (target.isa == 'thumb'))):
        return None
    if (test is None or test.id != a.ARM_INS_TST or test.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or len(test.operands) != 2 or test.operands[0].type != a.ARM_OP_REG
        or test.operands[0].reg != register or test.operands[1].type != a.ARM_OP_IMM or test.operands[1].imm != 1):
        return None
    returns = (first, second)
    if (any(ins is None or ins.id != a.ARM_INS_LDR or ins.operands[0].type != a.ARM_OP_REG or ins.operands[0].reg != a.ARM_REG_LR or ins.operands[1].type != a.ARM_OP_MEM
        or ins.operands[1].mem.base != a.ARM_REG_PC or ins.operands[1].mem.index or ins.cc not in (a.ARM_CC_EQ, a.ARM_CC_NE) or ins.writeback for ins in returns)
        or {ins.cc for ins in returns} != {a.ARM_CC_EQ, a.ARM_CC_NE}):
        return None
    return_words = tuple(_literal_word(facts, site, instruction) for site, instruction in ((first_return, first), (second_return, second)))
    if any(item is None for item in return_words):
        return None
    return_targets = []
    for instruction, (pool, pointer) in zip(returns, return_words):
        isa = 'thumb' if pointer & 1 else 'arm'
        if (isa != ('thumb' if instruction.cc == a.ARM_CC_NE else 'arm') or facts.decode(CodeAddress(pointer & ~ 1, isa, transfer.phase, transfer.bank)) is None):
            return None
        return_targets.append(CodeAddress(pointer & ~1, isa, transfer.phase, transfer.bank))
    if (bx is None or bx.id != a.ARM_INS_BX or bx.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or len(bx.operands) != 1 or bx.operands[0].type != a.ARM_OP_REG or
        bx.operands[0].reg != register or (transfer, target) not in function.control_edges):
        return None
    return target_load, literal, return_words, tuple(return_targets)

def _stack_state(facts: FirmwareFacts, function: FunctionFacts, transfer: CodeAddress):
    candidates = []
    for address, mode, stack_pointer in function.mode_stacks:
        site = next((pc for pc in function.instructions if pc.address == address and pc.isa == transfer.isa and pc.phase == transfer.phase and pc.bank ==
            transfer.bank), None)
        if (site is None or type(mode) is not int or type(stack_pointer) is not int or not 0 <= stack_pointer <= 0xFFFFFFFF):
            continue
        path = function.linear_path(site, transfer)
        if path is None or not function.dominates(site, transfer):
            continue
        safe = True
        for pc in path[1:]:
            instruction = facts.decode(pc)
            if instruction is None:
                safe = False
                break
            try:
                _, written = instruction.regs_access()
            except Exception:
                safe = False
                break
            if (a.ARM_REG_SP in written or instruction.id in (a.ARM_INS_MSR, getattr(a, 'ARM_INS_CPS', -1)) or instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_INT)):
                safe = False
                break
        if safe:
            candidates.append((len(path), site, mode, stack_pointer))
    if not candidates:
        return None
    _, site, mode, pointer = min(candidates, key=lambda item: item[0])
    return site, mode, pointer

def manual_interworking_entries(facts: FirmwareFacts, reset_entry: CodeAddress | None = None, *, budget: int = 8192) -> tuple[StartupEntryProof, ...]:
    """Find reset-linked LDR/TST/BX entries with a closed concrete SP source.

    The bounded root analysis follows the decoded control flow through manual
    ARM/Thumb interworking. A candidate is returned only when the root CFG is
    complete and the selected stack write dominates its handoff without a
    later SP or processor-mode write.
    """
    if not isinstance(facts, FirmwareFacts):
        return ()
    if reset_entry is None:
        reset_entry = reset_vector_entry(facts)
    if (not isinstance(facts, FirmwareFacts) or not isinstance(reset_entry, CodeAddress) or budget <= 0):
        return ()
    def extract():
        function = facts.function(reset_entry, budget=budget, stop_at_initial_return=True)
        if (not function.complete or function.truncated or function.unresolved):
            return ()
        results = []
        for transfer, target in function.control_edges:
            if (transfer.isa != 'arm' or target.isa == transfer.isa or not function.dominates(reset_entry, transfer)):
                continue
            wrapper = _manual_wrapper(facts, function, transfer, target)
            if wrapper is None:
                continue
            stack = _stack_state(facts, function, transfer)
            if stack is None:
                continue
            stack_site, mode, stack_pointer = stack
            sp_literal = _literal(function, stack_site)
            if (sp_literal is None or sp_literal.register != a.ARM_REG_SP or sp_literal.value != stack_pointer):
                continue
            target_load, target_literal, return_words, return_targets = wrapper
            literal_spans = { (target_literal.pool, target_literal.pool + 4), (sp_literal.pool, sp_literal.pool + 4), }
            literal_spans.update((pool, pool + 4) for pool, _ in return_words)
            code_spans = { (reset_entry.address, reset_entry.address + 4), (target_load.address, transfer.address + 4), (stack_site.address, stack_site.address
                + 4), }
            spans = code_spans | literal_spans
            results.append(StartupEntryProof(reset_entry, transfer, target, stack_site, stack_pointer, mode, tuple(sorted(spans)), tuple(sorted(code_spans)),
                tuple(sorted(literal_spans)), return_targets))
        return tuple(sorted(set(results), key=lambda item: (item.transfer.address, item.target.address, item.target.isa, item.stack_pointer)))
    return facts.memo('startup-interworking-entries', (reset_entry, budget), extract)

def startup_copy_contexts(facts: FirmwareFacts, *, target_ranges: tuple[tuple[int, int], ...], zero_ranges: tuple[tuple[int, int], ...] | None = None,
    extra_write_ranges: tuple[tuple[int, int], ...] = (), reset_entry: CodeAddress | None = None, budget: int = 4096,) -> tuple[StartupCopyContext, ...]:
    """Bind reset-proved entry stacks to local, function-wide row proofs."""
    if not isinstance(facts, FirmwareFacts) or budget <= 0:
        return ()
    target_ranges = tuple(tuple(item) for item in target_ranges)
    zero_ranges = (None if zero_ranges is None else tuple(tuple(item) for item in zero_ranges))
    extra_write_ranges = tuple(tuple(item) for item in extra_write_ranges)
    key = (reset_entry, target_ranges, zero_ranges, extra_write_ranges, budget)
    def extract():
        contexts = []
        for entry in manual_interworking_entries(facts, reset_entry, budget=max(8192, budget)):
            if entry.target.isa != 'thumb':
                continue
            initial = {a.ARM_REG_SP: entry.stack_pointer}
            function = facts.function(entry.target, budget=budget, initial_registers=initial, symbolic_registers={})
            if (not function.complete or function.truncated or function.unresolved):
                continue
            rows = proven_startup_rows(facts, entry.target, target_ranges=target_ranges, zero_ranges= zero_ranges, extra_write_ranges=extra_write_ranges,
                initial_sp=entry.stack_pointer, budget= budget)
            if not rows:
                continue
            spans = set(entry.source_spans)
            for row, proof in rows:
                spans.add((row.table, row.table + (20 if row.zero_table is not None else 12)))
                spans.add((row.source, row.source + row.size))
                if row.zero_table is not None:
                    spans.add((row.zero_table, row.zero_table + 8))
                if proof.procedure is not None:
                    spans.update(proof.procedure.helper_code_spans)
            for site in function.instructions:
                instruction = facts.decode(site)
                if instruction is None:
                    spans = set()
                    break
                spans.add((site.address, site.address + instruction.size))
            spans.update((item.pool, item.pool + 4) for item in function.literals)
            if spans:
                contexts.append(StartupCopyContext(entry, function, rows, tuple(sorted(spans))))
        return tuple(sorted(contexts, key=lambda item: (item.entry.target.address, item.entry.transfer.address, item.entry.stack_pointer, tuple(row.table for
            row, _ in item.rows))))
    return facts.memo('startup-copy-contexts', key, extract)

def startup_load_operations(rows, *, completion=None) -> tuple[LoadOperation, ...]:
    """Project one explicit memory epoch, retaining unknown stack bytes as holes."""
    rows = tuple(rows)
    procedures = {proof.procedure for _, proof in rows}
    if len(procedures) != 1 or None in procedures:
        raise ValueError('startup rows require one closed procedure')
    procedure = next(iter(procedures))
    if procedure.completion != completion:
        raise ValueError('startup memory epoch requires its explicit completion site')
    if tuple(row for row, _ in rows) != procedure.rows:
        raise ValueError('startup rows do not cover the closed procedure')
    # Discovery order is table order. Without a proved execution order, only
    # mutually independent rows can be projected into the evolving view.
    for index, (row, _) in enumerate(rows):
        writes = [(row.target, row.target + row.size)]
        if row.zero_row is not None:
            writes.append((row.zero_target, row.zero_target + row.zero_size))
        for other, _ in rows[index + 1:]:
            other_writes = [(other.target, other.target + other.size)]
            if other.zero_row is not None:
                other_writes.append((other.zero_target, other.zero_target + other.zero_size))
            conflicts = [(write, span) for write in writes for span in (*other_writes, (other.source, other.source + other.size))]
            conflicts.extend((write, (row.source, row.source + row.size)) for write in other_writes)
            if any(lo < other_hi and other_lo < hi for (lo, hi), (other_lo, other_hi) in conflicts):
                raise ValueError('startup row execution order is not proved')
    operations, protected = [],[]
    for row, proof in rows:
        evidence = (proof.entry.address, row.table, *proof.copy_back_edge)
        if completion is not None:
            evidence += (completion.address,)
        operations.append(LoadOperation('copy', row.source, row.target, row.size, evidence))
        protected.extend(((row.source, row.source + row.size), (row.target, row.target + row.size)))
        if row.zero_row is not None:
            evidence += proof.zero_back_edge
            operations.append(LoadOperation('zero', None, row.zero_target, row.zero_size, evidence))
            protected.append((row.zero_target, row.zero_target + row.zero_size))
    for write in procedure.unknown_stack_writes:
        if any(write.address < hi and lo < write.address + write.width for lo, hi in protected):
            raise ValueError('unknown stack write overlaps a startup transfer')
        operations.append(LoadOperation('invalidate', None, write.address, write.width, (write.instruction.address,)))
    return tuple(operations)
