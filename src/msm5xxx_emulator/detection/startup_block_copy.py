"""Reset-rooted block-copy proofs for firmware-specific startup stages.

This module recognizes a literal-linked paired LDM/STM copy and calls through
an already installed copy helper.  Addresses and geometry come from the
decoded reset path and its data, never from image identity.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct

from capstone import arm as a

from .facts import CodeAddress, facts_for
from .startup_entry import manual_interworking_entries, reset_vector_entry
from .startup_block_copy_patterns import (
    arm_memcpy_body as _arm_memcpy_body,
    arm_memset_body as _arm_memset_body,
)
from .startup_block_copy_safety import (
    _call_stack_effect, _path_preserves_copy, _stack_pointer_at_call,
)


@dataclass(frozen=True, slots=True)
class ResetLinkedBlockCopy:
    source: int
    target: int
    size: int
    evidence: tuple[tuple[int, int], ...]
    written_size: int | None = None

    @property
    def mapped_size(self):
        return self.size if self.written_size is None else self.written_size


def _literal_cells(facts, function, image, flash_end):
    """Find adjacent literal-addressed words actually loaded by the routine."""
    literal_by_site = {item.instruction: item for item in function.literals}
    loads = {}
    for site in function.instructions:
        instruction = facts.decode(site)
        literal = literal_by_site.get(site)
        if (instruction is None or instruction.id != a.ARM_INS_LDR
                or len(instruction.operands) != 2
                or instruction.operands[0].type != a.ARM_OP_REG
                or literal is None or literal.value < 0
                or literal.value + 4 > flash_end):
            continue
        pointer = instruction.operands[0].reg
        # Require a reached dereference of that exact pointer register, with
        # the loaded value obtained from the same ROM word.
        for access in function.accesses:
            if access.operation != 'read' or access.address != literal.value:
                continue
            use = facts.decode(access.instruction)
            if (use is None or use.id != a.ARM_INS_LDR
                    or len(use.operands) != 2
                    or use.operands[0].type != a.ARM_OP_REG
                    or use.operands[1].type != a.ARM_OP_MEM
                    or use.operands[1].mem.base != pointer
                    or use.operands[1].mem.index != 0
                    or use.operands[1].mem.disp != 0
                    or not _register_load_survives(
                        facts, function, site, pointer, access.instruction)):
                continue
            value = struct.unpack_from('<I', image, literal.value)[0]
            loads.setdefault(literal.value, []).append(
                (access.instruction, use.operands[0].reg, value,
                 site, pointer))
    result = []
    for cell, entries in loads.items():
        if cell + 8 not in loads or cell + 4 not in loads:
            continue
        sources = [(site, reg, value) for site, reg, value, _, _ in entries]
        destinations = [(site, reg, value) for site, reg, value, _, _ in loads[cell + 4]]
        sizes = [(site, reg, value) for site, reg, value, _, _ in loads[cell + 8]]
        for source in sources:
            for destination in destinations:
                for size in sizes:
                    result.append((cell, source, destination, size))
    return tuple(result)


def _register_load_survives(facts, function, source, reg, target):
    """Prove one loaded field reaches a use without any CFG clobber path."""
    ins = facts.decode(source)
    if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
            or ins.operands[0].type != a.ARM_OP_REG
            or ins.operands[0].reg != reg
            or not function.dominates(source, target)):
        return False
    edges = {}
    for left, right in function.control_edges:
        edges.setdefault(left, set()).add(right)
    calls = {site for site, _callee in function.calls}
    pending, seen = [source], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == target:
            continue
        # A call has an opaque AAPCS clobber set unless its body and the
        # preserved register are separately proved. These short setup paths
        # do not carry such a preservation proof, so reject the path.
        if current in calls:
            return False
        for following in edges.get(current, ()):
            if following not in function.instructions:
                return False
            instruction = facts.decode(following)
            if instruction is None:
                return False
            if following == target:
                seen.add(target)
                continue
            try:
                _, written = instruction.regs_access()
            except Exception:
                return False
            if reg in written:
                return False
            pending.append(following)
    return target in seen


def _register_definition_survives(facts, function, source, reg, target):
    """Prove a register definition is unchanged along every path to a use."""
    ins = facts.decode(source)
    if ins is None or not function.dominates(source, target):
        return False
    try:
        _, writes = ins.regs_access()
    except Exception:
        return False
    if reg not in writes:
        return False
    edges = {}
    for left, right in function.control_edges:
        edges.setdefault(left, set()).add(right)
    calls = {site for site, _callee in function.calls}
    pending, seen = [source], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == target:
            continue
        if current in calls:
            return False
        for following in edges.get(current, ()):
            if following not in function.instructions:
                return False
            if following == target:
                seen.add(target)
                continue
            instruction = facts.decode(following)
            if instruction is None:
                return False
            try:
                _, written = instruction.regs_access()
            except Exception:
                return False
            if reg in written:
                return False
            pending.append(following)
    return target in seen


def _signed_transfer_extent(source, destination, size, actual, flash_end):
    """Bounds required for the firmware's signed target<end loop test."""
    return (type(source) is int and type(destination) is int
            and type(size) is int and type(actual) is int
            and type(flash_end) is int and size > 0 and actual >= size
            and source >= 0 and destination >= 0
            and source + actual <= flash_end
            and source + actual < 0x80000000
            and destination + size < 0x80000000
            and destination + actual < 0x80000000)


def _paired_copy_proofs(facts, image, entry, *, flash_end, ram_base, ram_end,
                        initial_sp, extra_ram_ranges=()):
    """Prove a ROM descriptor and a five-word LDMIA/STMIA loop."""
    function = facts.function(
        entry, budget=2048,
        initial_registers={a.ARM_REG_SP: initial_sp}, symbolic_registers={})
    if (not function.complete or function.truncated or function.unresolved
            or not function.instructions):
        return ()
    decoded = [(site, facts.decode(site)) for site in function.instructions]
    decoded = [(site, ins) for site, ins in decoded if ins is not None]
    matches = {}
    for cell, source_field, destination_field, size_field in _literal_cells(
            facts, function, image, flash_end):
        source_site, source_reg, source = source_field
        destination_site, destination_reg, destination = destination_field
        size_site, size_reg, size = size_field
        allowed_ranges = ((ram_base, ram_end), *extra_ram_ranges)
        if (size <= 0 or source & 3 or destination & 3 or size & 3
                or source < 0 or source + size > flash_end
                or not any(start <= destination < end
                           for start, end in allowed_ranges)):
            continue
        for index, (load_site, load) in enumerate(decoded):
            if (load.id != a.ARM_INS_LDM or not load.writeback
                    or len(load.operands) < 2
                    or load.operands[0].type != a.ARM_OP_REG
                    or any(item.type != a.ARM_OP_REG for item in load.operands[1:])):
                continue
            source_cursor = load.operands[0].reg
            register_list = tuple(item.reg for item in load.operands[1:])
            if load.mnemonic not in ('ldm', 'ldmia'):
                continue
            if (source_cursor != source_reg or len(register_list) != 5
                    or len(set(register_list)) != 5
                    or any(reg in register_list for reg in (
                        a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2,
                        a.ARM_REG_SP, a.ARM_REG_LR, a.ARM_REG_PC))):
                continue
            if not _register_load_survives(
                    facts, function, source_site, source_reg, load_site):
                continue
            if index + 3 >= len(decoded):
                continue
            store_site, store = decoded[index + 1]
            compare_site, compare = decoded[index + 2]
            branch_site, branch = decoded[index + 3]
            if (store.id != a.ARM_INS_STM or not store.writeback
                    or store.mnemonic not in ('stm', 'stmia')
                    or len(store.operands) < 2
                    or store.operands[0].type != a.ARM_OP_REG
                    or any(item.type != a.ARM_OP_REG for item in store.operands[1:])
                    or tuple(item.reg for item in store.operands[1:]) != register_list
                    or store.operands[0].reg != destination_reg
                    or not _register_load_survives(
                        facts, function, destination_site, destination_reg, store_site)
                    or compare.id != a.ARM_INS_CMP
                    or len(compare.operands) != 2
                    or compare.operands[0].type != a.ARM_OP_REG
                    or compare.operands[0].reg != store.operands[0].reg
                    or compare.operands[1].type != a.ARM_OP_REG
                    or branch.id != a.ARM_INS_B
                    or branch.cc != a.ARM_CC_LT
                    or len(branch.operands) != 1
                    or branch.operands[0].type != a.ARM_OP_IMM
                    or branch.operands[0].imm != load_site.address):
                continue
            # LDM/STM's decoded register-list mask is the second operand's
            # integer value. Bound the actual writes, including the final
            # complete burst when the source length is not burst-aligned.
            burst = 4 * len(register_list)
            if (burst <= 0 or burst > 64
                    or len({source_reg, destination_reg, size_reg}) != 3):
                continue
            actual = ((size + burst - 1) // burst) * burst
            if (not _signed_transfer_extent(
                        source, destination, size, actual, flash_end)
                    or not any(start <= destination
                               and destination + actual <= end
                               for start, end in allowed_ranges)):
                continue
            # The compared end pointer must be initialized as dst + declared
            # size, and the guard must be after a complete store burst.
            end_reg = compare.operands[1].reg
            if (source_cursor == destination_reg or end_reg in register_list
                    or len({source_cursor, destination_reg, end_reg}) != 3
                    or any(reg in register_list for reg in
                           (source_cursor, destination_reg, end_reg, size_reg))):
                continue
            end_defs = []
            for site, ins in decoded[:index]:
                if ins.id != a.ARM_INS_ADD or len(ins.operands) != 3:
                    continue
                if (all(op.type == a.ARM_OP_REG for op in ins.operands)
                        and ins.operands[0].reg == end_reg
                        and ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                        and not any(op.shift.type for op in ins.operands)
                        and {ins.operands[1].reg, ins.operands[2].reg}
                            == {destination_reg, size_reg}
                        and end_reg not in register_list
                        and function.dominates(site, load_site)
                        and _register_load_survives(
                            facts, function, destination_site, destination_reg, site)
                        and _register_load_survives(
                            facts, function, size_site, size_reg, site)):
                    end_defs.append(site)
            if len(set(end_defs)) != 1:
                continue
            end_def = end_defs[0]
            if not _register_definition_survives(
                    facts, function, end_def, end_reg, compare_site):
                continue
            if not (function.dominates(load_site, store_site)
                    and function.dominates(store_site, branch_site)):
                continue
            if not (load_site.address + load.size == store_site.address
                    and store_site.address + store.size == compare_site.address
                    and compare_site.address + compare.size == branch_site.address
                    and (compare_site, branch_site) in function.control_edges
                    and (load_site, store_site) in function.control_edges
                    and (store_site, compare_site) in function.control_edges):
                continue
            exit_site = CodeAddress(branch_site.address + branch.size,
                                    branch_site.isa, branch_site.phase,
                                    branch_site.bank)
            successors = {right for left, right in function.control_edges
                          if left == branch_site}
            if successors != {load_site, exit_site}:
                continue
            if not (load_site.address < store_site.address
                    and store_site.address < compare_site.address
                    and compare_site.address < branch_site.address):
                continue
            evidence = set((site.address, ins.size) for site, ins in decoded)
            evidence.update(((cell, 12), (source, actual)))
            evidence.update((literal.pool, 4) for literal in function.literals)
            matches[(source, destination, size)] = (exit_site, actual,
                                                     tuple(sorted(evidence)))
    return tuple((source, destination, size, exit_site, actual, evidence)
                 for (source, destination, size), (exit_site, actual, evidence)
                 in matches.items())


def _paired_copy(facts, image, entry, **kwargs):
    """Return the public row view of a locally proven paired copy."""
    return tuple((source, target, size, evidence)
                 for source, target, size, _exit, _actual, evidence
                 in _paired_copy_proofs(facts, image, entry, **kwargs))


def _call_registers(function, site):
    records = [dict(item.registers) for item in function.call_sites
               if item.site == site]
    if len(records) != 1:
        return None
    registers = records[0]
    values = tuple(registers.get(reg) for reg in
                   (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2))
    return values if all(type(value) is int for value in values) else None


def _call_register_values(function, site, registers):
    records = [dict(item.registers) for item in function.call_sites
               if item.site == site]
    if len(records) != 1:
        return None
    values = tuple(records[0].get(register) for register in registers)
    return values if all(type(value) is int for value in values) else None


def _helper_stack_size(facts, proof):
    """Derive the callee's save area from its proved PUSH instruction."""
    if proof is None or not proof[0].instructions:
        return None
    instruction = facts.decode(proof[0].instructions[0])
    if instruction is None or instruction.id != a.ARM_INS_PUSH:
        return None
    registers = tuple(op.reg for op in instruction.operands
                      if op.type == a.ARM_OP_REG)
    return 4 * len(registers) if registers else None


def _copied_helper_entry(facts, function, call_target, block_copy):
    """Resolve a literal interworking veneer into installed source code."""
    if call_target.isa != 'thumb':
        return None
    branch = facts.decode(call_target)
    if (branch is None or branch.id != a.ARM_INS_BX
            or branch.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or branch.size != 2
            or len(branch.operands) != 1
            or branch.operands[0].type != a.ARM_OP_REG
            or branch.operands[0].reg != a.ARM_REG_PC):
        return None
    arm_pc = (call_target.address + 4) & ~3
    load_site = CodeAddress(arm_pc, 'arm', call_target.phase, call_target.bank)
    load = facts.decode(load_site)
    literal = facts.literal(load_site)
    if (load is None or load.id != a.ARM_INS_LDR or len(load.operands) != 2
            or load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or load.writeback
            or load.operands[0].type != a.ARM_OP_REG
            or load.operands[1].type != a.ARM_OP_MEM
            or load.operands[1].mem.base != a.ARM_REG_PC
            or load.operands[1].mem.index != 0 or literal is None):
        return None
    register = load.operands[0].reg
    evidence = {(call_target.address, branch.size), (arm_pc, load.size),
                (literal.pool, 4)}
    helper = literal.value
    if register == a.ARM_REG_PC:
        if helper & 3:
            return None
        isa = 'arm'
    else:
        if not a.ARM_REG_R0 <= register <= a.ARM_REG_R12:
            return None
        exchange_site = CodeAddress(arm_pc + 4, 'arm', call_target.phase,
                                    call_target.bank)
        exchange = facts.decode(exchange_site)
        if (exchange is None or exchange.id != a.ARM_INS_BX
                or exchange.size != 4
                or exchange.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(exchange.operands) != 1
                or exchange.operands[0].type != a.ARM_OP_REG
                or exchange.operands[0].reg != register):
            return None
        isa = 'thumb' if helper & 1 else 'arm'
        helper &= ~1
        if isa == 'arm' and helper & 3:
            return None
        evidence.add((exchange_site.address, exchange.size))
    offset = helper - block_copy.target
    if offset < 0 or offset >= block_copy.mapped_size:
        return None
    source = block_copy.source + offset
    if source & (1 if isa == 'thumb' else 3):
        return None
    return (CodeAddress(source, isa, call_target.phase, call_target.bank),
            tuple(sorted(evidence)))


def _copied_helper_source(facts, function, call_target, block_copy):
    """Resolve the ARM-state subset used by the paired block-copy proof."""
    resolved = _copied_helper_entry(facts, function, call_target, block_copy)
    if resolved is None or resolved[0].isa != 'arm':
        return None
    return resolved[0].address, resolved[1]


def reset_linked_block_copies(image: bytes, ram_base: int, ram_size: int,
                              flash_size: int, *,
                              auxiliary_ram_ranges=((0x03800000, 0x03A00000),)
                              ) -> tuple[ResetLinkedBlockCopy, ...]:
    """Return copies proven from a reset-linked paired block routine.

    Results include the direct block copy whose descriptor is read by a
    reset-entry function and later calls through Thumb to ARM veneers to code
    installed by that copy. Unsupported routes return no rows; this helper
    never treats image layouts as source evidence.
    """
    if (type(image) is not bytes or type(ram_base) is not int
            or type(ram_size) is not int or type(flash_size) is not int
            or ram_base < 0 or ram_size <= 0 or flash_size <= 0):
        return ()
    ram_end = ram_base + ram_size
    flash_end = min(len(image), flash_size)
    if ram_end > 0x100000000 or flash_end <= 0:
        return ()
    auxiliary = tuple(auxiliary_ram_ranges)
    if any(type(start) is not int or type(end) is not int
           or start < 0 or end <= start or end > 0x100000000
           for start, end in auxiliary):
        return ()
    # Analysis cannot borrow code or literal bytes beyond the active NOR
    # mapping even when the caller supplied a longer backing buffer.
    source_image = image[:flash_end]
    facts = facts_for(source_image)
    reset = reset_vector_entry(facts)
    if reset is None:
        return ()
    results = {}
    for proof in manual_interworking_entries(facts, reset):
        if proof.target.isa != 'thumb' or proof.processor_mode != 0x13:
            continue
        copies = _paired_copy_proofs(
            facts, source_image, proof.target, flash_end=flash_end,
            ram_base=ram_base, ram_end=ram_end,
            initial_sp=proof.stack_pointer, extra_ram_ranges=auxiliary)
        for source, target, size, exit_site, actual, evidence in copies:
            # This helper proves the reset-installed auxiliary code stage.
            # Ordinary configured-RAM rows are handled by the established
            # startup-copy recognizers and cannot serve as this code mapping.
            written = actual
            if not any(start <= target and target + written <= end
                       for start, end in auxiliary):
                continue
            route_evidence = set()
            for start, end in proof.source_spans:
                if (type(start) is not int or type(end) is not int
                        or start < 0 or end <= start or end > flash_end):
                    route_evidence = set()
                    break
                route_evidence.add((start, end - start))
            if not route_evidence:
                continue
            root = ResetLinkedBlockCopy(
                source, target, size,
                tuple(sorted(set(evidence) | route_evidence)), written)
            results[(source, target, size)] = root
            function = facts.function(
                proof.target, budget=2048,
                initial_registers={a.ARM_REG_SP: proof.stack_pointer},
                symbolic_registers={})
            if (not function.complete or function.truncated
                    or function.unresolved or not function.instructions):
                continue
            calls = sorted(((site, destination) for site, destination in function.calls
                            if destination.isa == 'thumb'), key=lambda item: item[0].address)
            verified_calls = {}
            effects = {}
            for call_site, call_target in calls:
                if not function.dominates(exit_site, call_site):
                    continue
                resolved = _copied_helper_source(facts, function, call_target, root)
                if resolved is None:
                    continue
                helper_source, helper_evidence = resolved
                if helper_source + 4 > flash_end:
                    continue
                helper_entry = CodeAddress(helper_source, 'arm',
                                           call_target.phase, call_target.bank)
                helper_proof = _arm_memcpy_body(facts, helper_entry, root)
                if helper_proof is not None:
                    arguments = _call_registers(function, call_site)
                    if arguments is None:
                        continue
                    src, dst, length = arguments[1], arguments[0], arguments[2]
                    if (src < 0 or src & 3 or dst & 3 or length & 3
                            or dst < ram_base or length <= 0
                            or src + length > flash_end or dst + length > ram_end):
                        continue
                    call_sp = _stack_pointer_at_call(
                        facts, function, call_site, proof.stack_pointer, effects)
                    spill = _call_stack_effect(
                        call_sp, ram_base, ram_end, target, written, dst, length,
                        _helper_stack_size(facts, helper_proof))
                    if spill is None:
                        continue
                    helper, helper_evidence_code = helper_proof
                    verified_calls[call_site] = (
                        src, dst, length, helper_evidence, helper_evidence_code)
                    effects[call_site] = ((dst, length), spill)
                    continue
                fill_proof = _arm_memset_body(facts, helper_entry, root)
                if fill_proof is None:
                    continue
                fill_args = _call_register_values(
                    function, call_site, (a.ARM_REG_R0, a.ARM_REG_R1))
                if fill_args is None:
                    continue
                fill_destination, fill_length = fill_args
                if (fill_destination & 3 or fill_length <= 0 or fill_length & 3
                        or fill_destination < ram_base
                        or fill_destination + fill_length > ram_end):
                    continue
                call_sp = _stack_pointer_at_call(
                    facts, function, call_site, proof.stack_pointer, effects)
                spill = _call_stack_effect(
                    call_sp, ram_base, ram_end, target, written,
                    fill_destination, fill_length,
                    _helper_stack_size(facts, fill_proof))
                if spill is None:
                    continue
                effects[call_site] = ((fill_destination, fill_length), spill)
            for call_site, (src, dst, length, helper_evidence,
                            helper_evidence_code) in verified_calls.items():
                if not _path_preserves_copy(
                        facts, function, exit_site, call_site, target, written,
                        effects):
                    continue
                evidence2 = set(root.evidence) | set(helper_evidence)
                evidence2.update(helper_evidence_code)
                evidence2.add((src, length))
                if any(type(start) is not int or type(length) is not int
                       or start < 0 or length <= 0 or start + length > flash_end
                       for start, length in evidence2):
                    continue
                results[(src, dst, length)] = ResetLinkedBlockCopy(
                    src, dst, length, tuple(sorted(evidence2)), length)
    return tuple(results[key] for key in sorted(results))
