"""Closed CFG proof for literal-linked Thumb word-copy loops."""
from __future__ import annotations

import struct
from capstone import arm as a

from .facts import CodeAddress
from .startup_reset_cfg_models import LinkedThumbWordCopy
from .startup_reset_ldm_copy import ldm_word_loop_proof
from .startup_reset_pulsed_copy import pulsed_word_loop_proof
from .startup_reset_chunked_copy import chunked_word_loop_proof


def _instruction(facts, function, site):
    return facts.decode(site) if site in function.instructions else None


def _reg(ins, index):
    if ins is None or index >= len(ins.operands):
        return None
    operand = ins.operands[index]
    return operand.reg if operand.type == a.ARM_OP_REG else None


def _imm(ins, index):
    if ins is None or index >= len(ins.operands):
        return None
    operand = ins.operands[index]
    return operand.imm if operand.type == a.ARM_OP_IMM else None


def _literal_field_uses(facts, function, nor_end):
    """Return only direct field loads whose pointer is a reaching literal."""
    literal_at = {item.instruction: item for item in function.literals}
    uses = {}
    sites = sorted(function.instructions, key=lambda item: item.address)
    for index, site in enumerate(sites):
        ins = _instruction(facts, function, site)
        literal = literal_at.get(site)
        if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or _reg(ins, 0) is None or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.base != a.ARM_REG_PC
                or ins.operands[1].mem.index or literal is None
                or type(literal.value) is not int or literal.value < 0
                or literal.value + 4 > nor_end):
            continue
        pointer, cell = _reg(ins, 0), literal.value
        for use in sites[index + 1:index + 8]:
            if (use.isa != site.isa or use.phase != site.phase
                    or use.bank != site.bank):
                break
            if use.address - site.address > 20:
                break
            load = _instruction(facts, function, use)
            if load is None:
                break
            if (load.id == a.ARM_INS_LDR and len(load.operands) == 2
                    and _reg(load, 0) is not None
                    and load.operands[1].type == a.ARM_OP_MEM
                    and load.operands[1].mem.base == pointer
                    and load.operands[1].mem.index == 0
                    and load.operands[1].mem.disp == 0
                    and not load.writeback
                    and facts.reaching_definitions(function, use, pointer)
                        == (site,)):
                uses.setdefault(cell, set()).add(use)
                continue
            try:
                _, writes = load.regs_access()
            except Exception:
                break
            if pointer in writes:
                break
    return uses


def _origin_cell(facts, function, field_uses, use, register, *, cut_edges=(), active=frozenset()):
    """Trace one unique register origin through literal-cell loads and copies."""
    key = (use, register)
    if key in active or len(active) >= 12:
        return None
    definitions = facts.reaching_definitions(
        function, use, register, cut_edges=cut_edges)
    if definitions is None or len(definitions) != 1:
        return None
    definition = definitions[0]
    ins = _instruction(facts, function, definition)
    if (ins is None or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or _reg(ins, 0) != register):
        return None
    for cell, sites in field_uses.items():
        if definition in sites and ins.id == a.ARM_INS_LDR:
            return cell
    source = None
    if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            and len(ins.operands) == 2
            and not ins.operands[1].shift.type
            and not ins.operands[1].subtracted):
        source = _reg(ins, 1)
    elif (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
          and _reg(ins, 1) is not None and _imm(ins, 2) == 0
          and not ins.operands[1].shift.type
          and not ins.operands[1].subtracted):
        source = _reg(ins, 1)
    elif (ins.id == a.ARM_INS_LSR and len(ins.operands) == 3
          and _reg(ins, 1) is not None and _imm(ins, 2) == 1
          and not ins.operands[1].shift.type
          and not ins.operands[1].subtracted):
        source = _reg(ins, 1)
    if source is None:
        return None
    return _origin_cell(facts, function, field_uses, definition, source,
                        active=active | {key})


def _alias_input(ins, output):
    if (ins is None or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or _reg(ins, 0) != output):
        return None
    if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            and len(ins.operands) == 2
            and not ins.operands[1].shift.type
            and not ins.operands[1].subtracted):
        return _reg(ins, 1)
    if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
            and _imm(ins, 2) == 0 and not ins.operands[1].shift.type
            and not ins.operands[1].subtracted):
        return _reg(ins, 1)
    return None


def _constant(facts, function, site, register, cut_edges):
    value = facts.register_value(function, site, register,
                                 cut_edges=cut_edges)
    return value.value if value.kind == "const" and type(value.value) is int else None


def _closed_end(facts, function, fields, compare_site, end_register,
                destination_cell, size_cell, cut_edges):
    """Tie the comparison bound to the literal destination and size fields."""
    end_value = _constant(facts, function, compare_site, end_register,
                          cut_edges)
    definitions = facts.reaching_definitions(
        function, compare_site, end_register, cut_edges=cut_edges)
    if end_value is None or definitions is None or len(definitions) != 1:
        return None
    end_site = definitions[0]
    end_ins = facts.decode(end_site)
    if (end_ins is None or end_ins.cc not in
            (a.ARM_CC_AL, a.ARM_CC_INVALID)):
        return None
    sum_site = end_site
    if _alias_input(end_ins, end_register) is not None:
        source = _alias_input(end_ins, end_register)
        sums = facts.reaching_definitions(function, end_site, source)
        if sums is None or len(sums) != 1:
            return None
        sum_site = sums[0]
    add = facts.decode(sum_site)
    if (add is None or add.id != a.ARM_INS_ADD
            or add.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or len(add.operands) != 3 or _reg(add, 0) is None
            or any(op.shift.type or op.subtracted for op in add.operands)):
        return None
    origins = [_origin_cell(facts, function, fields, sum_site,
                            _reg(add, index)) for index in (1, 2)]
    if None in origins or set(origins) != {destination_cell, size_cell}:
        return None
    return end_value, sum_site


def _evidence(facts, function, source, written_size, source_cell):
    evidence = {(source_cell, 12), (source, written_size)}
    # `code_sites` includes each instruction used for control, data flow,
    # aliases, and the end calculation. Reaching definitions may pass through
    # additional setup code, so retain all instructions in the closed function.
    for site in function.instructions:
        instruction = facts.decode(site)
        size = getattr(instruction, "size", None)
        if type(size) is int:
            evidence.add((site.address, size))
    return tuple(sorted(evidence))


def _copy_loop_origins(facts, function, fields, source_cell,
                       destination_cell, source_register,
                       destination_register, compare_site, body_site,
                       cut_edges):
    for site in (compare_site, body_site):
        source_value = _constant(facts, function, site, source_register,
                                 cut_edges)
        destination_value = _constant(facts, function, site,
                                      destination_register, cut_edges)
        if (source_value is None or destination_value is None
                or _origin_cell(facts, function, fields, site,
                                source_register, cut_edges=cut_edges)
                    != source_cell
                or _origin_cell(facts, function, fields, site,
                                destination_register,
                                cut_edges=cut_edges) != destination_cell):
            continue
        return source_value, destination_value
    return None


def _postincrement_loop_proof(facts, function, fields, source_cell,
                              destination_cell, size_cell, source, destination,
                              size, nor_end, target_ranges):
    """Prove LDR/STR then paired in-place +4 updates and a backedge."""
    if size <= 0 or source < 0:
        return None
    instructions = {site: facts.decode(site) for site in function.instructions}
    edges = {}
    for left, right in function.control_edges:
        edges.setdefault(left, set()).add(right)

    def following(site):
        ins = instructions.get(site)
        if ins is None:
            return None
        return CodeAddress(site.address + ins.size, site.isa,
                           site.phase, site.bank)

    for body_site, load in instructions.items():
        if (body_site.isa != "thumb" or load is None
                or load.id != a.ARM_INS_LDR
                or load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(load.operands) != 2 or _reg(load, 0) is None
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.base is None
                or load.operands[1].mem.index
                or load.operands[1].mem.disp != 0 or load.writeback):
            continue
        source_register, value_register = load.operands[1].mem.base, _reg(load, 0)
        store_site = following(body_site)
        store = instructions.get(store_site)
        source_step_site = following(store_site)
        source_step = instructions.get(source_step_site)
        destination_step_site = following(source_step_site)
        destination_step = instructions.get(destination_step_site)
        compare_site = following(destination_step_site)
        compare = instructions.get(compare_site)
        branch_site = following(compare_site)
        branch = instructions.get(branch_site)
        if (store is None or store.id != a.ARM_INS_STR
                or store.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(store.operands) != 2
                or _reg(store, 0) != value_register
                or store.operands[1].type != a.ARM_OP_MEM
                or store.operands[1].mem.base is None
                or store.operands[1].mem.index
                or store.operands[1].mem.disp != 0 or store.writeback):
            continue
        destination_register = store.operands[1].mem.base
        if (source_step is None or source_step.id != a.ARM_INS_ADD
                or source_step.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(source_step.operands) not in (2, 3)
                or _reg(source_step, 0) != source_register
                or (len(source_step.operands) == 2
                    and _imm(source_step, 1) != 4)
                or (len(source_step.operands) == 3
                    and (_reg(source_step, 1) != source_register
                         or _imm(source_step, 2) != 4))
                or destination_step is None
                or destination_step.id != a.ARM_INS_ADD
                or destination_step.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(destination_step.operands) not in (2, 3)
                or _reg(destination_step, 0) != destination_register
                or (len(destination_step.operands) == 2
                    and _imm(destination_step, 1) != 4)
                or (len(destination_step.operands) == 3
                    and (_reg(destination_step, 1) != destination_register
                         or _imm(destination_step, 2) != 4))):
            continue
        if (compare is None or compare.id != a.ARM_INS_CMP
                or compare.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(compare.operands) != 2
                or _reg(compare, 0) != destination_register
                or _reg(compare, 1) is None
                or branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_LO
                or len(branch.operands) != 1
                or _imm(branch, 0) != body_site.address):
            continue
        exit_site = following(branch_site)
        loop_sites = (body_site, store_site, source_step_site,
                      destination_step_site, compare_site, branch_site)
        if (edges.get(body_site) != {store_site}
                or edges.get(store_site) != {source_step_site}
                or edges.get(source_step_site) != {destination_step_site}
                or edges.get(destination_step_site) != {compare_site}
                or edges.get(compare_site) != {branch_site}
                or edges.get(branch_site) != {body_site, exit_site}
                or (branch_site.address, body_site.address)
                    not in function.back_edges
                # The comparison and branch also have a first-iteration
                # predecessor from the preheader, so the body cannot dominate
                # those two nodes. The body must dominate every operation in
                # the actual transfer/update block.
                or not all(function.dominates(body_site, site)
                           for site in (store_site, source_step_site,
                                        destination_step_site))):
            continue
        if (facts.reaching_definitions(function, branch_site,
                                       a.ARM_REG_CPSR) != (compare_site,)
                or facts.reaching_definitions(function, store_site,
                                               value_register) != (body_site,)):
            continue
        cuts = ((branch_site, body_site),)
        initial = _copy_loop_origins(
            facts, function, fields, source_cell, destination_cell,
            source_register, destination_register, compare_site,
            body_site, cuts)
        if initial != (source, destination):
            continue
        bound = _closed_end(
            facts, function, fields, compare_site, _reg(compare, 1),
            destination_cell, size_cell, cuts)
        if bound is None or bound[0] <= destination:
            continue
        written_size = ((bound[0] - destination + 3) // 4) * 4
        if (source + written_size > nor_end
                or not any(start <= destination
                           and destination + written_size <= end
                           for start, end in target_ranges)):
            continue
        evidence = _evidence(facts, function, source, written_size,
                             source_cell)
        return written_size, evidence, exit_site
    return None


def _loop_proof(facts, function, fields, source_cell, destination_cell,
                size_cell, source, destination, size, nor_end,
                target_ranges):
    if size <= 0 or source < 0:
        return None
    edges = {}
    for left, right in function.control_edges:
        edges.setdefault(left, set()).add(right)
    instruction_by_site = {site: facts.decode(site)
                           for site in function.instructions}

    def following(site):
        ins = instruction_by_site.get(site)
        if ins is None:
            return None
        return CodeAddress(site.address + ins.size, site.isa,
                           site.phase, site.bank)

    for compare_site, compare in instruction_by_site.items():
        if (compare is None or compare.id != a.ARM_INS_CMP
                or compare_site.isa != "thumb"
                or compare.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(compare.operands) != 2):
            continue
        destination_register, end_register = _reg(compare, 0), _reg(compare, 1)
        branch_site = following(compare_site)
        branch = instruction_by_site.get(branch_site)
        if (destination_register is None or end_register is None
                or branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_HS or len(branch.operands) != 1
                or _imm(branch, 0) is None):
            continue
        body_branch_site = following(branch_site)
        body_branch = instruction_by_site.get(body_branch_site)
        if (body_branch is None or body_branch.id != a.ARM_INS_B
                or body_branch.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(body_branch.operands) != 1):
            continue
        body_site = CodeAddress(_imm(body_branch, 0), compare_site.isa,
                                compare_site.phase, compare_site.bank)
        load = instruction_by_site.get(body_site)
        if (load is None or load.id != a.ARM_INS_LDR
                or load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(load.operands) != 2 or _reg(load, 0) is None
                or load.operands[1].type != a.ARM_OP_MEM
                or _reg(load, 1) is not None
                or load.operands[1].mem.base is None
                or load.operands[1].mem.index or load.operands[1].mem.disp != 0
                or load.writeback):
            continue
        source_register, value_register = load.operands[1].mem.base, _reg(load, 0)
        store_site = following(body_site)
        store = instruction_by_site.get(store_site)
        if (store is None or store.id != a.ARM_INS_STR
                or store.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(store.operands) != 2
                or _reg(store, 0) != value_register
                or store.operands[1].type != a.ARM_OP_MEM
                or store.operands[1].mem.base != destination_register
                or store.operands[1].mem.index or store.operands[1].mem.disp != 0
                or store.writeback):
            continue
        body_exit_site = following(store_site)
        body_exit = instruction_by_site.get(body_exit_site)
        if (body_exit is None or body_exit.id != a.ARM_INS_B
                or body_exit.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(body_exit.operands) != 1):
            continue
        source_step_site = CodeAddress(_imm(body_exit, 0), compare_site.isa,
                                       compare_site.phase, compare_site.bank)
        source_step = instruction_by_site.get(source_step_site)
        source_alias_site = following(source_step_site)
        source_alias = instruction_by_site.get(source_alias_site)
        destination_step_site = following(source_alias_site)
        destination_step = instruction_by_site.get(destination_step_site)
        destination_alias_site = following(destination_step_site)
        destination_alias = instruction_by_site.get(destination_alias_site)
        back_site = following(destination_alias_site)
        back = instruction_by_site.get(back_site)
        source_temp = _reg(source_step, 0)
        destination_temp = _reg(destination_step, 0)
        if (source_step is None or source_step.id != a.ARM_INS_ADD
                or source_step.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(source_step.operands) != 3
                or _reg(source_step, 1) != source_register
                or _imm(source_step, 2) != 4
                or source_temp is None
                or _alias_input(source_alias, source_register) != source_temp
                or destination_step is None
                or destination_step.id != a.ARM_INS_ADD
                or destination_step.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(destination_step.operands) != 3
                or _reg(destination_step, 1) != destination_register
                or _imm(destination_step, 2) != 4
                or destination_temp is None
                or _alias_input(destination_alias, destination_register)
                    != destination_temp
                or back is None or back.id != a.ARM_INS_B
                or back.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(back.operands) != 1
                or _imm(back, 0) != compare_site.address):
            continue
        if (edges.get(compare_site) != {branch_site}
                or edges.get(branch_site) != {body_branch_site,
                    CodeAddress(_imm(branch, 0), compare_site.isa,
                                compare_site.phase, compare_site.bank)}
                or edges.get(body_branch_site) != {body_site}
                or edges.get(body_site) != {store_site}
                or edges.get(store_site) != {body_exit_site}
                or edges.get(body_exit_site) != {source_step_site}
                or edges.get(source_step_site) != {source_alias_site}
                or edges.get(source_alias_site) != {destination_step_site}
                or edges.get(destination_step_site) != {destination_alias_site}
                or edges.get(destination_alias_site) != {back_site}
                or edges.get(back_site) != {compare_site}
                or (back_site.address, compare_site.address)
                    not in function.back_edges):
            continue
        loop_nodes = {compare_site, branch_site, body_branch_site, body_site,
                      store_site, body_exit_site, source_step_site,
                      source_alias_site, destination_step_site,
                      destination_alias_site, back_site}
        if CodeAddress(_imm(branch, 0), compare_site.isa,
                       compare_site.phase, compare_site.bank) in loop_nodes:
            continue
        if not all(function.dominates(compare_site, site) for site in
                   (branch_site, body_branch_site, body_site, store_site,
                    body_exit_site, source_step_site, source_alias_site,
                    destination_step_site, destination_alias_site, back_site)):
            continue
        if facts.reaching_definitions(function, branch_site, a.ARM_REG_CPSR) != (compare_site,):
            continue
        if facts.reaching_definitions(function, store_site, value_register) != (body_site,):
            continue
        cut_edges = ((back_site, compare_site),)
        initial_source = _constant(facts, function, body_site,
                                   source_register, cut_edges)
        initial_destination = _constant(facts, function, compare_site,
                                        destination_register, cut_edges)
        initial_end = _constant(facts, function, compare_site,
                                end_register, cut_edges)
        if (initial_source != source or initial_destination != destination
                or initial_end is None or initial_end <= destination):
            continue
        written_size = ((initial_end - destination + 3) // 4) * 4
        if (written_size <= 0 or source + written_size > nor_end
                or not any(start <= destination
                           and destination + written_size <= end
                           for start, end in target_ranges)):
            continue
        if (_origin_cell(facts, function, fields, body_site, source_register,
                         cut_edges=cut_edges) != source_cell
                or _origin_cell(facts, function, fields, compare_site,
                                destination_register, cut_edges=cut_edges)
                    != destination_cell):
            continue
        end_defs = facts.reaching_definitions(
            function, compare_site, end_register, cut_edges=cut_edges)
        if end_defs is None or len(end_defs) != 1:
            continue
        end_site = end_defs[0]
        end_ins = instruction_by_site.get(end_site)
        end_input = _alias_input(end_ins, end_register)
        if end_input is None:
            continue
        sum_defs = facts.reaching_definitions(function, end_site, end_input)
        if sum_defs is None or len(sum_defs) != 1:
            continue
        sum_site = sum_defs[0]
        add = instruction_by_site.get(sum_site)
        if (add is None or add.id != a.ARM_INS_ADD
                or add.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(add.operands) != 3 or _reg(add, 0) != end_input
                or any(op.shift.type or op.subtracted for op in add.operands)):
            continue
        origins = []
        for index in (1, 2):
            register = _reg(add, index)
            if register is None:
                origins = []
                break
            origins.append(_origin_cell(facts, function, fields, sum_site,
                                        register))
        if None in origins or set(origins) != {destination_cell, size_cell}:
            continue
        code_sites = (compare_site, branch_site, body_branch_site, body_site,
                      store_site, body_exit_site, source_step_site,
                      source_alias_site, destination_step_site,
                      destination_alias_site, back_site, end_site, sum_site)
        evidence = {(source_cell, 12), (source, size)}
        evidence.update((site.address, instruction_by_site[site].size)
                        for site in code_sites)
        evidence.update((literal.pool, 4)
                        for literal in function.literals)
        evidence.update((site.address, instruction_by_site[site].size)
                        for sites in fields.values() for site in sites)
        evidence.discard((source, size))
        evidence.add((source, written_size))
        exit_site = CodeAddress(_imm(branch, 0), compare_site.isa,
                                compare_site.phase, compare_site.bank)
        return written_size, tuple(sorted(evidence)), exit_site
    return None


def linked_thumb_cfg_word_copies(facts, function, image, *, nor_end,
                                 ram_base=None, ram_end=None,
                                 auxiliary_ram_ranges=(), detailed=False,
                                 ram_ranges=None):
    """Prove adjacent source/destination/length fields and their word loops."""
    if (type(image) not in (bytes, bytearray)
            or not function.complete or function.truncated or function.unresolved
            or type(nor_end) is not int or nor_end <= 0
            or nor_end > len(image)
            or type(detailed) is not bool):
        return ()
    if ram_ranges is None:
        if (type(ram_base) is not int or type(ram_end) is not int
                or ram_base < 0 or ram_end <= ram_base):
            return ()
        ranges = ((ram_base, ram_end), *tuple(auxiliary_ram_ranges))
    else:
        if auxiliary_ram_ranges:
            return ()
        ranges = tuple(ram_ranges)
        if not ranges:
            return ()
    if any(type(start) is not int or type(end) is not int
           or start < 0 or end <= start or end > 0x100000000
           for start, end in ranges):
        return ()
    if any(left[0] < right[1] and right[0] < left[1]
           for index, left in enumerate(ranges)
           for right in ranges[index + 1:]):
        return ()
    fields = _literal_field_uses(facts, function, nor_end)
    immutable = {(site.address, instruction.size)
                 for site in function.instructions
                 if (instruction := facts.decode(site)) is not None}
    immutable.update((literal.pool, 4) for literal in function.literals)
    immutable.update((cell, 4) for cell in fields)
    results = {}
    for source_cell in sorted(fields):
        destination_cell, size_cell = source_cell + 4, source_cell + 8
        if destination_cell not in fields or size_cell not in fields:
            continue
        if source_cell + 12 > nor_end:
            continue
        source, destination, size = struct.unpack_from("<III", image,
                                                       source_cell)
        for prove_loop in (ldm_word_loop_proof, pulsed_word_loop_proof,
                           chunked_word_loop_proof, _loop_proof,
                           _postincrement_loop_proof):
            proof = prove_loop(facts, function, fields, source_cell,
                destination_cell, size_cell, source, destination, size,
                nor_end, ranges)
            if proof is not None:
                written_size, evidence, loop_exit = proof
                if any(start < destination + written_size and destination < start + extent
                       for start, extent in (*immutable, (source, written_size))):
                    continue
                record = LinkedThumbWordCopy(source, destination, written_size,
                                             evidence, loop_exit, function)
                results[(source, destination, written_size)] = record
    if detailed:
        return tuple(results.values())
    return tuple((record.source, record.target, record.written_size,
                  record.evidence) for record in results.values())
