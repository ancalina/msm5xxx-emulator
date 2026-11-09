"""Static ARM and Thumb SBI bootstrap transaction evidence."""
from __future__ import annotations

import struct
from capstone import arm as a
from ...facts import CodeAddress, facts_for
from .protocol import (BASE, APERTURE, EVENTS, _UNCONDITIONAL, _native_status,
                       compatibility_events, SBI_BOOTSTRAP, SBI_BOOTSTRAP_VALIDATION)

_STATE_WRITES = (a.ARM_INS_MSR, a.ARM_INS_CPS, a.ARM_INS_SETEND)


def _poll_exits_to_write(facts, function, read, write):
    status = _native_status()
    for branch_pc in function.instructions:
        branch = facts.decode(branch_pc)
        if (branch is None or branch.id != a.ARM_INS_B
                or branch.cc in _UNCONDITIONAL or not branch.operands
                or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        predicate = facts.branch_predicate(function, branch_pc)
        if predicate is None or len(predicate.read_sources) != 1:
            continue
        source = predicate.read_sources[0]
        if (source.site != read.instruction or source.width != 2
                or source.signed or source.address.kind != 'const'
                or source.address.value != BASE):
            continue
        taken = predicate.evaluate({read.instruction: status})
        if taken is None:
            continue
        target = branch.operands[0].imm & 0xFFFFFFFF
        fallthrough = branch_pc.address + branch.size
        selected = target if taken else fallthrough
        rejected = fallthrough if taken else target
        try:
            selected_path = function.linear_path(
                CodeAddress(selected, branch_pc.isa, branch_pc.phase, branch_pc.bank),
                write.instruction)
            rejected_path = function.linear_path(
                CodeAddress(rejected, branch_pc.isa, branch_pc.phase, branch_pc.bank),
                read.instruction)
        except (ValueError, TypeError):
            continue
        if (selected_path is not None and rejected_path is not None
                and all(pc not in {access.instruction for access in function.accesses
                                   if access.address == BASE and access.operation == 'read'}
                        for pc in selected_path[:-1])):
            return branch_pc, rejected_path
    return None


def _event_tuple(access):
    return (access.operation, access.address - BASE, access.width, access.value)


def _transaction_nodes(function, start, end):
    """Collect the bounded execution region from the first event to its end."""
    nodes = set(function.instructions)
    if start not in nodes or end not in nodes:
        return None
    edges = {}
    for source, target in function.control_edges:
        if source not in nodes or target not in nodes:
            return None
        edges.setdefault(source, set()).add(target)
    pending, reached = [start], set()
    while pending:
        pc = pending.pop()
        if pc in reached:
            continue
        if pc not in nodes:
            return None
        reached.add(pc)
        if pc == end:
            continue
        successors = edges.get(pc, ())
        if not successors:
            return None
        pending.extend(successors)
    return reached if end in reached else None


def _segment_is_closed(facts, function, start, end, symbolic_function,
                       proven_accesses, poll):
    nodes = _transaction_nodes(function, start, end)
    if nodes is None:
        return False
    unmodelled = facts.unmodelled_memory(symbolic_function)
    if (unmodelled is None or any(site in nodes for site in unmodelled)
            or any(facts.decode(site).id in _STATE_WRITES for site in nodes)):
        return False
    if any(site in nodes for site, _ in function.calls):
        return False
    addresses = {pc.address for pc in nodes}
    active_back_edges = {(source, target) for source, target in function.back_edges
                         if source in addresses and target in addresses}
    poll_branch, rejected_path = poll
    rejected_edges = {(poll_branch.address, rejected_path[0].address)}
    rejected_edges.update((left.address, right.address)
                          for left, right in zip(rejected_path, rejected_path[1:]))
    allowed_back_edges = active_back_edges & rejected_edges
    if active_back_edges != allowed_back_edges or not allowed_back_edges:
        return False
    proven_by_site = {access.instruction: access for access in proven_accesses}
    symbolic_counts = {}
    for access in symbolic_function.symbolic_accesses:
        symbolic_counts[access.instruction] = symbolic_counts.get(access.instruction, 0) + 1
    for access in symbolic_function.symbolic_accesses:
        if access.instruction not in nodes or access.operation not in ('read', 'write'):
            continue
        if access.address.kind == 'const':
            continue
        known = proven_by_site.get(access.instruction)
        if (known is not None and symbolic_counts[access.instruction] == 1
                and known.operation == access.operation
                and known.width == access.width):
            continue
        return False
    return True


def _literal_adjusts_to(facts, function, use, register, expected):
    definitions = facts.reaching_definitions(function, use, register)
    if definitions is None or len(definitions) != 1:
        return False
    update_site, = definitions
    update = facts.decode(update_site)
    if (update is None or update.id not in (a.ARM_INS_ADD, a.ARM_INS_SUB)
            or update.cc not in _UNCONDITIONAL):
        return False
    operands = update.operands
    if (len(operands) == 2 and operands[0].type == a.ARM_OP_REG
            and operands[1].type == a.ARM_OP_IMM):
        destination = source = operands[0].reg
        amount = operands[1].imm
    elif (len(operands) == 3 and operands[0].type == a.ARM_OP_REG
          and operands[1].type == a.ARM_OP_REG
          and operands[2].type == a.ARM_OP_IMM):
        destination, source = operands[0].reg, operands[1].reg
        amount = operands[2].imm
    else:
        return False
    if destination != register or source != register:
        return False
    source_definitions = facts.reaching_definitions(function, update_site, source)
    if source_definitions is None or len(source_definitions) != 1:
        return False
    literal = facts.literal(source_definitions[0])
    if literal is None:
        return False
    value = literal.value + (amount if update.id == a.ARM_INS_ADD else -amount)
    return value == expected


def _event_values_use_literal_arithmetic(facts, function, accesses):
    for index in (2, 3, 7):
        access = accesses[index]
        instruction = facts.decode(access.instruction)
        if (instruction is None or not instruction.operands
                or instruction.operands[0].type != a.ARM_OP_REG
                or not _literal_adjusts_to(
                    facts, function, access.instruction,
                    instruction.operands[0].reg, access.value)):
            return False
    return True


def _events_reload_literal_bases(facts, function, accesses):
    definitions = []
    for access in accesses:
        instruction = facts.decode(access.instruction)
        memory = (next((operand.mem for operand in instruction.operands
                        if operand.type == a.ARM_OP_MEM), None)
                  if instruction is not None else None)
        if memory is None:
            return False
        reaching = facts.reaching_definitions(function, access.instruction, memory.base)
        if reaching is None or len(reaching) != 1 or facts.literal(reaching[0]) is None:
            return False
        definitions.append(reaching[0])
    return len(set(definitions)) == len(accesses)


def _payloads_precede_marker(facts, function, accesses, marker):
    for access in accesses[4:6]:
        instruction = facts.decode(access.instruction)
        if instruction is None or instruction.operands[0].type != a.ARM_OP_REG:
            return False
        definitions = facts.reaching_definitions(
            function, access.instruction, instruction.operands[0].reg)
        if (definitions is None or len(definitions) != 1
                or definitions[0] is None or definitions[0].address >= marker):
            return False
    return True


def _prove_entry(facts, entry: CodeAddress, reported_entry: int):
    whole = facts.function(entry, budget=1024)
    endpoints = (access.instruction for access in whole.accesses
                 if access.operation == 'read' and access.address == BASE
                 and access.width == 2)
    for end in endpoints:
        region = facts.function_region(entry, end, budget=1024)
        if not region.complete or region.truncated:
            continue
        accesses = [access for access in region.accesses
                    if APERTURE[0] <= access.address < APERTURE[1]]
        if tuple(_event_tuple(access) for access in accesses) != EVENTS:
            continue
        if any(access.predicate not in _UNCONDITIONAL for access in accesses):
            continue
        if not all(region.dominates(left.instruction, right.instruction)
                   for left, right in zip(accesses, accesses[1:])):
            continue
        symbolic_region = facts.function_region(accesses[0].instruction, end, budget=1024,
                                                symbolic_registers={})
        poll = _poll_exits_to_write(facts, region, accesses[6], accesses[7])
        if (poll is None or not symbolic_region.complete or symbolic_region.truncated
                or not _segment_is_closed(facts, region, accesses[0].instruction,
                                          accesses[-1].instruction,
                                          symbolic_region, accesses, poll)):
            continue
        last_write = accesses[5]
        store = facts.decode(last_write.instruction)
        poll_instruction = facts.decode(poll[0])
        source_defs = (facts.reaching_definitions(
            region, last_write.instruction,
            next((op.mem.base for op in store.operands if op.type == a.ARM_OP_MEM), -1))
            if store is not None else None)
        direct_literal = (source_defs is not None and len(source_defs) == 1
                          and (literal := facts.literal(source_defs[0])) is not None
                          and literal.value == BASE + 0x10)
        repeat_pc_matches = (entry.isa == 'thumb'
                             and accesses[0].instruction.address
                             == facts.base + reported_entry + 4)
        adjusted_literal = (source_defs is not None and len(source_defs) == 1
                            and last_write.address == BASE + 0x10
                            and store is not None
                            and _literal_adjusts_to(
                                facts, region, last_write.instruction,
                                next((op.mem.base for op in store.operands
                                      if op.type == a.ARM_OP_MEM), -1),
                                BASE + 0x10))
        if repeat_pc_matches and direct_literal:
            layout = 'thumb-sbi-bootstrap-direct-literal-v1'
        elif (entry.isa == 'thumb' and _payloads_precede_marker(
                facts, region, accesses, facts.base + reported_entry)):
            layout = 'thumb-sbi-bootstrap-preserved-register-v1'
        elif (entry.isa == 'thumb'
              and _event_values_use_literal_arithmetic(facts, region, accesses)):
            layout = 'thumb-sbi-bootstrap-literal-arithmetic-v1'
        elif (entry.isa == 'thumb' and poll_instruction is not None
              and poll_instruction.cc in (a.ARM_CC_HS, a.ARM_CC_LO)):
            layout = 'thumb-sbi-bootstrap-carry-loop-v1'
        elif (entry.isa == 'thumb'
              and _events_reload_literal_bases(facts, region, accesses)):
            layout = 'thumb-sbi-bootstrap-reloaded-literal-v1'
        elif repeat_pc_matches and adjusted_literal:
            layout = 'thumb-sbi-bootstrap-add-literal-v1'
        elif entry.isa == 'arm':
            layout = 'arm-sbi-bootstrap-immediate-v1'
        else:
            layout = 'thumb-sbi-bootstrap-facts-v1'
        return reported_entry, layout
    return None


def _marker_has_base_store(facts, entry, marker_register):
    """Boundedly link the marker value to a store through a BASE producer."""
    isa = entry.isa
    delta = 2 if isa == 'thumb' else 4
    constants = {}
    literal_registers = set()
    for _ in range(5):
        site = CodeAddress(entry.address + delta, isa, entry.phase, entry.bank)
        instruction = facts.decode(site)
        if instruction is None or instruction.cc not in _UNCONDITIONAL:
            return False
        operands = instruction.operands
        if instruction.id == a.ARM_INS_STRB:
            if (len(operands) != 2 or operands[0].type != a.ARM_OP_REG
                    or operands[0].reg != marker_register
                    or operands[1].type != a.ARM_OP_MEM):
                return False
            memory = operands[1].mem
            return (memory.index in (0, a.ARM_REG_INVALID)
                    and memory.base in constants
                    and constants[memory.base] + memory.disp == BASE
                    and (isa != 'thumb' or memory.base in literal_registers))
        if instruction.id == a.ARM_INS_LDR:
            literal = facts.literal(site)
            if (literal is None or len(operands) != 2
                    or operands[0].type != a.ARM_OP_REG
                    or operands[0].reg == marker_register):
                return False
            constants[literal.register] = literal.value
            literal_registers.add(literal.register)
        elif (instruction.id == a.ARM_INS_MOV and len(operands) == 2
              and operands[0].type == a.ARM_OP_REG
              and operands[0].reg != marker_register
              and operands[1].type == a.ARM_OP_IMM):
            constants[operands[0].reg] = operands[1].imm
            literal_registers.discard(operands[0].reg)
        elif instruction.id in (a.ARM_INS_ADD, a.ARM_INS_SUB):
            if (len(operands) == 2 and operands[0].type == a.ARM_OP_REG
                    and operands[1].type == a.ARM_OP_IMM):
                destination = source = operands[0].reg
                immediate = operands[1].imm
            elif (len(operands) == 3 and operands[0].type == a.ARM_OP_REG
                  and operands[1].type == a.ARM_OP_REG
                  and operands[2].type == a.ARM_OP_IMM):
                destination, source = operands[0].reg, operands[1].reg
                immediate = operands[2].imm
            else:
                return False
            if (destination != source or destination == marker_register
                    or source not in constants
                    or any(operand.shift.type or operand.subtracted
                           for operand in operands)):
                return False
            constants[destination] += (immediate if instruction.id == a.ARM_INS_ADD
                                       else -immediate)
        else:
            return False
        delta += instruction.size
    return False


def _linear_prefix_entry(facts, marker):
    """Nominate supplied straight-line producers before an inline transaction."""
    step = 2 if marker.isa == 'thumb' else 4
    cursor = max(facts.base, marker.address - 0x100)
    start = cursor
    while cursor < marker.address:
        instruction = facts.decode(CodeAddress(cursor, marker.isa,
                                               marker.phase, marker.bank))
        if instruction is None:
            cursor += step
            start = cursor
            continue
        cursor += instruction.size
        if (instruction.cc not in _UNCONDITIONAL
                or instruction.id in (*_STATE_WRITES, a.ARM_INS_B, a.ARM_INS_BL,
                                       a.ARM_INS_BLX, a.ARM_INS_BX, a.ARM_INS_SVC)
                or a.ARM_REG_PC in instruction.regs_access()[1]):
            start = cursor
    return (CodeAddress(start, marker.isa, marker.phase, marker.bank)
            if cursor == marker.address and start < marker.address else None)


def _local_marker_entry(facts, marker, isa):
    """Prove a local transaction marker after a cheap code-derived prefilter."""
    entry = CodeAddress(facts.base + marker, isa)
    instruction = facts.decode(entry)
    marker_register = a.ARM_REG_R1 if isa == 'arm' else (
        instruction.operands[0].reg if instruction is not None
        and instruction.operands and instruction.operands[0].type == a.ARM_OP_REG
        else -1)
    if (instruction is None or instruction.id != a.ARM_INS_MOV
            or len(instruction.operands) != 2
            or instruction.operands[0].type != a.ARM_OP_REG
            or instruction.operands[0].reg != marker_register
            or instruction.operands[1].type != a.ARM_OP_IMM
            or instruction.operands[1].imm != 0x45
            or not _marker_has_base_store(facts, entry, marker_register)):
        return None
    proof = _prove_entry(facts, entry, marker)
    prefix = _linear_prefix_entry(facts, entry) if proof is None else None
    return proof or (_prove_entry(facts, prefix, marker) if prefix is not None else None)


def _marker_candidates(image, facts, isa):
    if isa == 'thumb':
        markers = tuple(bytes((0x45, 0x20 | register)) for register in range(8))
        alignment = 2
    else:
        markers = (struct.pack('<I', 0xE3A01045),)
        alignment = 4
    positions = set()
    for marker in markers:
        cursor = 0
        while (cursor := image.find(marker, cursor)) >= 0:
            if cursor % alignment == 0:
                positions.add(cursor)
            cursor += alignment
    for literal in facts.literal_references(0x45):
        if literal.instruction.isa == isa:
            positions.add(literal.instruction.address - facts.base)
    return sorted(positions)


def _owner_starts(facts, marker, isa):
    starts = set()
    lower = max(0, marker - 0x1000)
    for _, target in facts.call_candidates(isa):
        if lower <= target <= marker and target % (4 if isa == 'arm' else 2) == 0:
            starts.add(CodeAddress(target, isa))
    for _, target in facts.vectors():
        if lower <= target.address <= marker and target.isa == isa:
            starts.add(target)
    if isa == 'thumb':
        # Require an SBI base producer before analysing whole candidate owners.
        # Rounded base literals also cover constant offset arithmetic.
        ranges = (APERTURE, (BASE & ~0xff, (BASE & ~0xff) + 1),
                  (BASE & ~0xfff, (BASE & ~0xfff) + 1))
        references = facts.memo('sbi-discovery-base-xrefs', (), lambda:
                                tuple(item.instruction.address for item in
                                      facts.literal_references_in(ranges)
                                      if item.instruction.isa == isa))
        starts = {start for start in starts
                  if any(0 <= address - start.address < 0x1000
                         for address in references)}
    return starts


def find_bootstraps(image: bytes, isa: str):
    if isa not in ('arm', 'thumb'):
        raise ValueError('unsupported instruction set')
    facts = facts_for(image)
    def extract():
        matches = set()
        for marker in _marker_candidates(image, facts, isa):
            if proof := _local_marker_entry(facts, marker, isa):
                matches.add(proof)
            starts = _owner_starts(facts, marker, isa)
            for start in starts:
                reported = marker if isa == 'thumb' else start.address - facts.base
                if proof := _prove_entry(facts, start, reported):
                    matches.add(proof)
        return tuple(sorted(matches))
    return facts.memo('sbi-bootstrap-matches', isa, extract)


def bootstrap_layout_at(image: bytes, position: int) -> str | None:
    matches = [layout for entry, layout in find_bootstraps(image, 'thumb')
               if entry == position]
    return matches[0] if len(matches) == 1 else None


def find_sbi_bootstrap_profile(image: bytes) -> dict[str, object] | None:
    """Admit one source-bounded SBI bootstrap transaction."""
    matches = list(find_bootstraps(image, 'thumb'))
    if not matches:
        matches = list(find_bootstraps(image, 'arm'))
    if len(matches) != 1:
        return None
    entry, layout = matches[0]
    bootstrap, validation = compatibility_events()
    return {
        "signature": "thumb-sbi-bootstrap-only-v1",
        "admission": "temporary-evidence-gated",
        "accepted": True,
        "base_address": BASE,
        "bootstrap": bootstrap,
        "validation": validation,
        "entries": [entry],
        "layout": layout,
    }


def arm_sbi_bootstrap_at(image: bytes, at: int) -> bool:
    return any(entry == at for entry, _ in find_bootstraps(image, 'arm'))


def find_arm_sbi_bootstraps(image: bytes) -> list[int]:
    return [entry for entry, _ in find_bootstraps(image, 'arm')]
