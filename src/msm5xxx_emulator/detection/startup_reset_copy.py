"""Reset-linked initialized-data copies for device source evidence."""
from __future__ import annotations

from dataclasses import dataclass
import struct
from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.startup_capture import normal_startup_copy
from msm5xxx_emulator.detection.startup_facts import prove_startup_copy_consumer
from msm5xxx_emulator.detection.startup_entry import (
    _manual_wrapper,
    reset_vector_entry,
    startup_copy_contexts,
)
from msm5xxx_emulator.detection.startup_layouts import layouts
from msm5xxx_emulator.detection.startup_models import StartupCopyRow
from msm5xxx_emulator.detection.startup_reset_calls import (
    reset_call_contexts, reset_stack_at_transfer,
)
from msm5xxx_emulator.detection.startup_reset_cfg_copy import (
    linked_thumb_cfg_word_copies,
)


@dataclass(frozen=True)
class ResetLinkedCopy:
    source: int
    target: int
    size: int
    evidence: tuple[tuple[int, int], ...]

    def source_address(self, address: int, size: int = 1) -> int | None:
        offset = address - self.target
        if type(address) is not int or type(size) is not int or size <= 0:
            return None
        if offset < 0 or offset + size > self.size:
            return None
        return self.source + offset


def _linked_thumb_word_copy(facts, image, entry, *, nor_end, ram_base, ram_end,
                            initial_registers=None):
    """Return only loop copies closed by the shared CFG recognizers."""
    function = facts.function(entry, budget=1024,
                              initial_registers=initial_registers or {},
                              symbolic_registers={})
    return linked_thumb_cfg_word_copies(
        facts, function, image, nor_end=nor_end, ram_base=ram_base,
        ram_end=ram_end)

def _path_spans(facts, function, target):
    instructions = set(function.instructions)
    if function.entry not in instructions or target not in instructions:
        return ()
    edges = {}
    for source, destination in function.control_edges:
        edges.setdefault(source, []).append(destination)
    pending, previous = [function.entry], {function.entry: None}
    while pending:
        current = pending.pop(0)
        if current == target:
            break
        for destination in edges.get(current, ()):
            if destination not in previous:
                previous[destination] = current
                pending.append(destination)
    if target not in previous:
        return ()
    path, cursor = [], target
    while cursor is not None:
        instruction = facts.decode(cursor)
        if instruction is None:
            return ()
        path.append((cursor.address, instruction.size))
        cursor = previous[cursor]
    return tuple(reversed(path))


def _path_has_stack(facts, function, path, inherited, ram_base, ram_end):
    by_address = {site.address: site for site in function.instructions}
    path_sites = [by_address[address] for address, _size in path
                  if address in by_address]
    order = {site: index for index, site in enumerate(path_sites)}
    mode_writes = [index for index, site in enumerate(path_sites)
                   if (instruction := facts.decode(site)) is not None
                   and instruction.id in (a.ARM_INS_MSR,
                       getattr(a, "ARM_INS_CPS", -1))]
    last_mode_write = max(mode_writes, default=-1)
    stacks = [(order[site], mode, pointer)
              for address, mode, pointer in function.mode_stacks
              for site in path_sites if site.address == address]
    stacks = [item for item in stacks if item[0] >= last_mode_write]
    if not stacks:
        return inherited and not mode_writes
    index, mode, pointer = max(stacks, key=lambda item: item[0])
    if index == 0:
        return False
    prior = facts.decode(path_sites[index - 1])
    if prior is None or prior.id != a.ARM_INS_MSR:
        return False
    return (mode in (0x13, 0x1f) and type(pointer) is int
            and ram_base < pointer <= ram_end
            and index >= last_mode_write)


def _reset_layout_copies(facts, image, function, route, layout_rows, *, nor_end,
                         ram_base, ram_end, requested, stack_proven):
    instructions = set(function.instructions)
    if not instructions:
        return ()
    matches = []
    for table, source, target, size, _zero_end in layout_rows:
        if (type(table) is not int or type(source) is not int or type(target) is not int
                or type(size) is not int or size <= 0 or source + size > nor_end
                or target < ram_base or target + size > ram_end
                or any(address < target or address + length > target + size
                       for address, length in requested)):
            continue
        references = facts.literal_access_candidates(
            ((table, table + 12),), phase=function.entry.phase,
            bank=function.entry.bank, limit=nor_end)
        references = tuple(item for item in references
                           if item.load in instructions and item.use in instructions)
        if not references:
            continue
        row = StartupCopyRow(table, source, target, size)
        proofs = prove_startup_copy_consumer(facts, row, references)
        for proof in proofs:
            path = _path_spans(facts, function, proof.entry)
            if (not path or not _path_has_stack(
                    facts, function, path, stack_proven, ram_base, ram_end)):
                continue
            consumer = facts.function(proof.entry, budget=2048)
            if (not consumer.complete or consumer.truncated or consumer.unresolved
                    or proof.copy_back_edge not in consumer.back_edges):
                continue
            evidence = set(route)
            evidence.update(path)
            evidence.add((table, 12))
            evidence.add((source, size))
            evidence.update((site.address, facts.decode(site).size)
                            for site in consumer.instructions if facts.decode(site) is not None)
            evidence.update((literal.pool, 4) for literal in consumer.literals)
            evidence.update((item.literal, 4) for item in references)
            matches.append((source, target, size, tuple(sorted(evidence))))
    return tuple(matches)


def reset_linked_copy(image: bytes, spans: tuple[tuple[int, int], ...], *,
                            ram_base: int, ram_size: int,
                            flash_size: int) -> ResetLinkedCopy | None:
    """Map requested RAM bytes through one reset-proved copy fully in NOR/RAM."""
    if (not isinstance(image, (bytes, bytearray)) or type(ram_base) is not int
            or type(ram_size) is not int or type(flash_size) is not int
            or ram_base < 0 or ram_size <= 0 or flash_size <= 0):
        return None
    image = bytes(image)
    ram_end = ram_base + ram_size
    nor_end = min(len(image), flash_size)
    if ram_end > 0x100000000 or nor_end <= 0:
        return None
    requested = tuple(spans)
    if (not requested or any(type(address) is not int or type(size) is not int
            or size <= 0 or address < ram_base or address + size > ram_end
            for address, size in requested)):
        return None

    candidates: dict[tuple[int, int, int], set[tuple[int, int]]] = {}

    def sized(spans):
        result = []
        for start, end in spans:
            if type(start) is not int or type(end) is not int or end <= start:
                return ()
            result.append((start, end - start))
        return tuple(result)

    def add(source, target, size, evidence):
        if (type(source) is not int or type(target) is not int or type(size) is not int
                or source < 0 or target < ram_base or size <= 0
                or source + size > nor_end or target + size > ram_end):
            return
        if any(target > address or address + length > target + size
               for address, length in requested):
            return
        spans = set(evidence)
        spans.add((source, size))
        if any(type(start) is not int or type(length) is not int or start < 0
                or length <= 0 or start + length > nor_end for start, length in spans):
            return
        candidates.setdefault((source, target, size), set()).update(spans)

    # The normal ARM route has a stronger shared closure, including its
    # initialized-data consumer and complete copied ranges.
    try:
        normal = normal_startup_copy(image, ram_base, ram_size)
    except (ValueError, struct.error, IndexError, TypeError):
        normal = None
    if normal is not None:
        root = normal.get("root")
        decision = normal.get("decision")
        route = []
        if type(root) is int and type(decision) is int:
            route.extend(((0, 4), (root, max(4, decision + 12 - root))))
        route.extend(sized(normal.get("startup_code_intervals", ())))
        route.extend(sized(normal.get("startup_literal_intervals", ())))
        route.extend(sized(normal.get("startup_table_intervals", ())))
        for copy in normal.get("copies", ()):
            add(copy.source, copy.target, copy.size, route)

    # Some images enter their normal reset/copy sequence through an ARM branch
    # reached after one or more literal-linked interworking calls. Walk only
    # those reset-reachable wrappers and direct unconditional branches; a
    # globally found startup-shaped routine is not sufficient evidence.
    facts = facts_for(image)
    reset = reset_vector_entry(facts)
    pending: list[tuple[CodeAddress, frozenset[tuple[int, int]], bool]] = []
    if reset is not None:
        pending.append((reset, frozenset(((0, 4), (reset.address, 4))), False))
    seen: dict[CodeAddress, bool] = {}
    tried: set[CodeAddress] = set()
    call_walked: set[CodeAddress] = set()
    call_contexts_used = 0
    layout_rows = None
    while pending and len(seen) < 128:
        entry, route, stack_proven = pending.pop(0)
        if entry in seen and (seen[entry] or not stack_proven):
            continue
        seen[entry] = seen.get(entry, False) or stack_proven

        # Every queued entry is linked from the vector through a decoded
        # wrapper return or a direct unconditional branch. Ask the common
        # startup analyzer to close a full initialized-data consumer here.
        if entry.isa == "arm" and entry not in tried:
            tried.add(entry)
            contexts = startup_copy_contexts(
                facts,
                target_ranges=((ram_base, ram_end), (0x03800000, 0x03a00000)),
                zero_ranges=((ram_base, ram_end),),
                extra_write_ranges=((0x03000600, 0x03000780),),
                reset_entry=entry,
            )
            for context in contexts:
                for row, proof in context.rows:
                    if proof.procedure is None or proof.entry not in context.function.instructions:
                        continue
                    add(row.source, row.target, row.size,
                        (*route, *sized(context.source_spans)))

        function = facts.function(entry, budget=8192,
                                  stop_at_initial_return=True)
        if not function.instructions:
            continue
        if (stack_proven and entry.isa == "thumb" and entry not in call_walked
                and call_contexts_used < 128):
            call_walked.add(entry)
            contexts = reset_call_contexts(
                    facts, entry, ram_base=ram_base, ram_end=ram_end,
                    max_contexts=128 - call_contexts_used,
                    stack_proven=True, route_spans=route)
            call_contexts_used += len(contexts)
            for context in contexts:
                if context.entry.isa != "thumb" or not context.stack_proven:
                    continue
                for source, destination, size, copy_evidence in _linked_thumb_word_copy(
                        facts, image, context.entry, nor_end=nor_end,
                        ram_base=ram_base, ram_end=ram_end,
                        initial_registers=dict(context.initial_registers)):
                    add(source, destination, size,
                        (*context.evidence, *copy_evidence))
        if stack_proven:
            if layout_rows is None:
                layout_rows = tuple(layouts(image))
            for source, destination, size, copy_evidence in _reset_layout_copies(
                    facts, image, function, route, layout_rows, nor_end=nor_end,
                    ram_base=ram_base, ram_end=ram_end, requested=requested,
                    stack_proven=stack_proven):
                add(source, destination, size, copy_evidence)
        instructions = set(function.instructions)
        calls = {site for site, _target in function.calls}
        edges = function.control_edges

        # A manual interworking wrapper records both literal return targets.
        # These are the only indirect transitions followed by this local root
        # walk; arbitrary BX targets do not create reset roots.
        for transfer, target in edges:
            if transfer.isa != "arm" or target.isa == "arm":
                continue
            wrapper = _manual_wrapper(facts, function, transfer, target)
            if wrapper is None:
                continue
            target_load, literal, return_words, returns = wrapper
            wrapper_spans = {
                (target_load.address, transfer.address + 4 - target_load.address),
                (literal.pool, 4),
            }
            wrapper_spans.update((pool, 4) for pool, _ in return_words)
            stack_pointer = reset_stack_at_transfer(
                facts, function, transfer, ram_base, ram_end)
            pending.append((target, frozenset(
                {*route, *wrapper_spans, (target.address, 4)}),
                stack_proven or stack_pointer is not None))
            if target.isa == "thumb":
                if stack_pointer is not None:
                    stack_sources = set()
                    for address, mode, pointer in function.mode_stacks:
                        if mode != 0x13 or pointer != stack_pointer:
                            continue
                        site = next((site for site in function.instructions
                                     if site.address == address and site.isa == transfer.isa), None)
                        literal_sp = facts.literal(site) if site is not None else None
                        if literal_sp is not None:
                            stack_sources.update(((address, 4), (literal_sp.pool, 4)))
                    if transfer.address >= function.entry.address:
                        reset_code = ((function.entry.address,
                                       transfer.address + 4 - function.entry.address),)
                    else:
                        reset_code = ((transfer.address, 4),)
                    for source, destination, size, copy_evidence in _linked_thumb_word_copy(
                            facts, image, target, nor_end=nor_end,
                            ram_base=ram_base, ram_end=ram_end):
                        add(source, destination, size,
                            (*route, *reset_code, *stack_sources,
                             *wrapper_spans, *copy_evidence))
            # The TST selects exactly one LR load: NE for a Thumb target and
            # EQ for an ARM target. The other literal is a dead continuation.
            for returned in returns:
                if returned.isa != target.isa:
                    continue
                pending.append((returned, frozenset(
                    {*route, *wrapper_spans,
                     (returned.address, 4)}),
                    stack_proven or stack_pointer is not None))

        # Follow only the standard Thumb BX PC interworking trampoline to its
        # aligned ARM continuation. Other indirect transfers are not roots.
        for source, target in edges:
            if source.isa != "thumb" or target.isa != "arm":
                continue
            instruction = facts.decode(source)
            if (instruction is None or instruction.id != a.ARM_INS_BX
                    or len(instruction.operands) != 1
                    or instruction.operands[0].type != a.ARM_OP_REG
                    or instruction.operands[0].reg != a.ARM_REG_PC
                    or target.address != ((source.address + 4) & ~3)):
                continue
            pending.append((target, frozenset(
                {*route, (source.address, instruction.size),
                 (target.address, 4)}), stack_proven))

        # Follow forward direct ARM branches, including feasible conditional
        # startup paths. Calls and backward scan loops are handled separately.
        for source, target in edges:
            if source in calls or source.isa != "arm" or target.isa != "arm":
                continue
            instruction = facts.decode(source)
            if (instruction is None or instruction.id != a.ARM_INS_B
                    or target.address <= source.address
                    or target not in instructions):
                continue
            pending.append((target, frozenset(
                {*route, (source.address, instruction.size),
                 (target.address, 4)}), stack_proven))

    if not candidates:
        from .startup_block_copy import reset_linked_block_copies
        for copy in reset_linked_block_copies(image, ram_base, ram_size, flash_size):
            add(copy.source, copy.target, copy.mapped_size, copy.evidence)
    if not candidates:
        from .startup_wrapped_copy import reset_linked_wrapped_copies
        for copy in reset_linked_wrapped_copies(image, ram_base, ram_size, flash_size):
            add(copy.source, copy.target, copy.mapped_size, copy.evidence)
    if len(candidates) != 1:
        return None
    (source, target, size), evidence = next(iter(candidates.items()))
    return ResetLinkedCopy(source, target, size, tuple(sorted(evidence)))
