"""Source proof for flat halfword upload catalogs selected through reset data."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.fact_memory_map import detect_linker_memory_map
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, source_prefix
from msm5xxx_emulator.detection.startup_facts import _loop_iteration_cut, _loop_nodes
from msm5xxx_emulator.detection.values import SymbolicValue

from .signal_copy import direct_copy_unit
from .signal_flat_copy import _reversed_halfword_copy
from .signal_flat_selector import (
    _copied_catalogs, _flat_object, _word, bind_flat_catalogs,
)
from .signal_tables import _merged_pages


def _span(facts, body):
    if not body.instructions:
        return None
    start = min(pc.address for pc in body.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in body.instructions)
    return {'span': [start - facts.base, end - start],
            'extra_spans': [[literal.pool - facts.base, 4]
                            for literal in body.literals]}


def _iteration_cut(body):
    if len(body.back_edges) != 1:
        return None
    edge = body.back_edges[0]
    nodes = _loop_nodes(body, edge)
    if not nodes:
        return None
    cut = _loop_iteration_cut(body, nodes, edge)
    if cut is None:
        return None
    return tuple(CodeAddress(address, body.entry.isa, body.entry.phase,
                             body.entry.bank) for address in cut[0])


def _flat_parser(facts, entry):
    """Recognize the object+8/count and eight-byte destination/count loop."""
    body = facts.function(entry, budget=256)
    if (not body.complete or body.unresolved or body.truncated
            or len(body.calls) != 1 or len(body.back_edges) != 1):
        return None
    code = {pc.address: facts.decode(pc) for pc in body.instructions}
    ordered = [code[pc.address] for pc in body.instructions]
    cut = _iteration_cut(body)
    if cut is None:
        return None
    cuts = (cut,)

    # The paired load publishes payload and rows from the object. The parser
    # then rewinds the object cursor and reads its inclusive last row index.
    pair_loads = [ins for ins in ordered if ins.id == a.ARM_INS_LDM
                  and ins.writeback and len(ins.operands) >= 2
                  and ins.operands[0].type == a.ARM_OP_REG
                  and ins.operands[0].reg == a.ARM_REG_R0]
    if len(pair_loads) != 1:
        return None
    pair = pair_loads[0]
    pair_regs = tuple(op.reg for op in pair.operands[1:]
                      if op.type == a.ARM_OP_REG)
    if len(pair_regs) != 2 or pair_regs[0] == pair_regs[1]:
        return None
    payload_reg, rows_reg = pair_regs
    bound_reads = [ins for ins in ordered if ins.id == a.ARM_INS_LDRH
                   and len(ins.operands) == 2
                   and ins.operands[1].type == a.ARM_OP_MEM
                   and ins.operands[1].mem.base == a.ARM_REG_R0
                   and ins.operands[1].mem.disp == 8]
    restore = [ins for ins in ordered if ins.id == a.ARM_INS_SUB
               and len(ins.operands) == 2
               and ins.operands[0].type == a.ARM_OP_REG
               and ins.operands[0].reg == a.ARM_REG_R0
               and ins.operands[1].type == a.ARM_OP_IMM
               and ins.operands[1].imm == 8]
    if (len(bound_reads) != 1 or len(restore) != 1
            or not pair.address < restore[0].address < bound_reads[0].address):
        return None
    bound_read_pc = CodeAddress(bound_reads[0].address, entry.isa,
                                entry.phase, entry.bank)
    if facts.register_origins(body, bound_read_pc, a.ARM_REG_R0) != (
            (CodeAddress(restore[0].address, entry.isa, entry.phase,
                         entry.bank), a.ARM_REG_R0),):
        return None
    if (not body.dominates(CodeAddress(pair.address, entry.isa,
                                       entry.phase, entry.bank),
                           CodeAddress(restore[0].address, entry.isa,
                                       entry.phase, entry.bank))
            or not body.dominates(CodeAddress(restore[0].address, entry.isa,
                                              entry.phase, entry.bank),
                                  bound_read_pc)):
        return None

    call_site, wrapper = body.calls[0]
    wrapper_body = facts.function(wrapper, budget=64, symbolic_registers={
        a.ARM_REG_R0: SymbolicValue.arg(0),
        a.ARM_REG_R1: SymbolicValue.arg(1),
        a.ARM_REG_R2: SymbolicValue.arg(2),
    })
    if (not wrapper_body.complete or wrapper_body.unresolved
            or wrapper_body.truncated):
        return None
    if wrapper_body.calls:
        if len(wrapper_body.call_sites) != 1:
            return None
        copy_call = wrapper_body.call_sites[0]
        transfer = _reversed_halfword_copy(facts, wrapper_body)
        if transfer is None:
            return None
        copy_body = transfer['leaf']
        unit = transfer['unit']
    else:
        if wrapper_body.calls or len(wrapper_body.call_sites) != 0:
            return None
        copy_body = wrapper_body
        unit = direct_copy_unit(facts, copy_body)
        if unit not in (2, 4):
            return None

    instructions = {ins.address: ins for ins in ordered}
    call = instructions.get(call_site.address)
    call_pc = CodeAddress(call_site.address, entry.isa, entry.phase, entry.bank)
    if (call is None or call.id not in (a.ARM_INS_BL, a.ARM_INS_BLX)
            or not body.dominates(CodeAddress(pair.address, entry.isa,
                                              entry.phase, entry.bank), call_pc)):
        return None
    scaled_rows = [(ins.operands[0].reg, ins.operands[1].reg)
                   for ins in ordered if ins.id == a.ARM_INS_LSL
                   and len(ins.operands) == 3
                   and ins.operands[0].type == a.ARM_OP_REG
                   and ins.operands[1].type == a.ARM_OP_REG
                   and ins.operands[2].type == a.ARM_OP_IMM
                   and ins.operands[2].imm == 3]
    if len(scaled_rows) != 1:
        return None
    scaled_reg, index_reg = scaled_rows[0]
    row_bases = []
    for ins in ordered:
        if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_REG
                and ins.operands[2].type == a.ARM_OP_REG
                and {ins.operands[1].reg, ins.operands[2].reg}
                    == {rows_reg, scaled_reg}):
            row_bases.append(ins.operands[0].reg)
    if len(row_bases) != 1:
        return None
    count_loads, destination_loads = [], []
    for ins in ordered:
        if (ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or ins.operands[1].type != a.ARM_OP_MEM):
            continue
        mem = ins.operands[1].mem
        if mem.base == row_bases[0] and mem.disp == 4 and not mem.index:
            count_loads.append(ins.operands[0].reg)
        elif (mem.base == rows_reg and mem.disp == 0
              and mem.index == scaled_reg):
            destination_loads.append(ins.operands[0].reg)
        elif (mem.base == row_bases[0] and mem.disp == 0
              and not mem.index):
            destination_loads.append(ins.operands[0].reg)
    if len(count_loads) != 1 or len(destination_loads) != 1:
        return None
    count_load = next(ins for ins in ordered if ins.id == a.ARM_INS_LDR
                      and len(ins.operands) == 2
                      and ins.operands[0].type == a.ARM_OP_REG
                      and ins.operands[0].reg == count_loads[0]
                      and ins.operands[1].type == a.ARM_OP_MEM
                      and ins.operands[1].mem.base == row_bases[0]
                      and ins.operands[1].mem.disp == 4
                      and not ins.operands[1].mem.index)
    destination_load = next(ins for ins in ordered if ins.id == a.ARM_INS_LDR
                            and len(ins.operands) == 2
                            and ins.operands[0].type == a.ARM_OP_REG
                            and ins.operands[0].reg == destination_loads[0]
                            and ins.operands[1].type == a.ARM_OP_MEM
                            and ((ins.operands[1].mem.base == rows_reg
                                  and ins.operands[1].mem.index == scaled_reg
                                  and ins.operands[1].mem.disp == 0)
                                 or (ins.operands[1].mem.base == row_bases[0]
                                     and not ins.operands[1].mem.index
                                     and ins.operands[1].mem.disp == 0)))
    count_reg = count_loads[0]
    destination_reg = destination_loads[0]
    if (destination_reg != a.ARM_REG_R1
            or not body.dominates(CodeAddress(count_load.address, entry.isa,
                                               entry.phase, entry.bank), call_pc)
            or not body.dominates(CodeAddress(destination_load.address,
                                               entry.isa, entry.phase, entry.bank),
                                  call_pc)):
        return None

    count_origins = facts.register_origins(body, call_pc, a.ARM_REG_R2,
                                           cut_edges=cuts)
    destination_origins = facts.register_origins(
        body, call_pc, a.ARM_REG_R1, cut_edges=cuts)
    source_origins = facts.register_origins(body, call_pc, a.ARM_REG_R0,
                                            cut_edges=cuts)
    expected_count = ((CodeAddress(count_load.address, entry.isa,
                                   entry.phase, entry.bank), count_reg),)
    expected_destination = ((CodeAddress(destination_load.address, entry.isa,
                                         entry.phase, entry.bank),
                             destination_reg),)
    expected_source = ((CodeAddress(pair.address, entry.isa, entry.phase,
                                    entry.bank), payload_reg),)
    if (count_origins != expected_count
            or destination_origins != expected_destination
            or source_origins != expected_source):
        return None

    # The payload cursor is advanced by exactly the selected row's count in
    # transfer units before the loop repeats.
    scales = [ins for ins in ordered if ins.id == a.ARM_INS_LSL
              and len(ins.operands) == 3
              and ins.operands[0].type == a.ARM_OP_REG
              and ins.operands[1].type == a.ARM_OP_REG
              and ins.operands[1].reg == count_reg
              and ins.operands[2].type == a.ARM_OP_IMM
              and ins.operands[2].imm == unit.bit_length() - 1]
    if len(scales) != 1:
        return None
    scaled_register = scales[0].operands[0].reg
    if facts.register_origins(
            body, CodeAddress(scales[0].address, entry.isa, entry.phase,
                              entry.bank), count_reg, cut_edges=cuts) != expected_count:
        return None
    payload_updates = []
    for ins in ordered:
        if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == payload_reg
                and ins.operands[1].type == a.ARM_OP_REG
                and ins.operands[1].reg == scaled_register):
            payload_updates.append(ins)
        elif (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
              and ins.operands[0].type == a.ARM_OP_REG
              and ins.operands[0].reg == payload_reg
              and ins.operands[1].type == a.ARM_OP_REG
              and ins.operands[2].type == a.ARM_OP_REG
              and {ins.operands[1].reg, ins.operands[2].reg}
                   == {payload_reg, scaled_register}):
            payload_updates.append(ins)
    branch_at, branch_target = body.back_edges[0]
    branch = code.get(branch_at)
    branch_pc = CodeAddress(branch_at, entry.isa, entry.phase, entry.bank)
    loop_nodes = _loop_nodes(body, body.back_edges[0])
    if len(payload_updates) != 1:
        return None
    update_pc = CodeAddress(payload_updates[0].address, entry.isa,
                            entry.phase, entry.bank)
    # The initial bound check can branch to the loop condition before the
    # first copy.  Prove the update is in the repeated body, follows the copy
    # call, and has a closed straight path to that condition instead of
    # requiring it to dominate the condition from function entry.
    if (update_pc not in loop_nodes or call_pc not in loop_nodes
            or not body.dominates(call_pc, update_pc)
            or body.linear_path(update_pc, branch_pc) is None):
        return None
    compare = code.get(branch_at - 2)
    if (branch is None or branch.id != a.ARM_INS_B
            or branch.cc not in (a.ARM_CC_LS, a.ARM_CC_HS)
            or compare is None or compare.id != a.ARM_INS_CMP):
        return None
    if len(compare.operands) != 2:
        return None
    compare_left = (compare.operands[0].reg
                    if compare.operands[0].type == a.ARM_OP_REG else None)
    compare_right = (compare.operands[1].reg
                     if compare.operands[1].type == a.ARM_OP_REG else None)
    bound_reg = bound_reads[0].operands[0].reg
    stack_bound_stores = [ins for ins in ordered if ins.id == a.ARM_INS_STR
                          and len(ins.operands) == 2
                          and ins.operands[0].type == a.ARM_OP_REG
                          and ins.operands[0].reg == bound_reg
                          and ins.operands[1].type == a.ARM_OP_MEM
                          and ins.operands[1].mem.base == a.ARM_REG_SP
                          and not ins.operands[1].mem.index]
    if len(stack_bound_stores) != 1:
        return None
    bound_store = stack_bound_stores[0]
    bound_store_pc = CodeAddress(bound_store.address, entry.isa,
                                 entry.phase, entry.bank)
    bound_origins = facts.register_origins(body, bound_store_pc, bound_reg,
                                          cut_edges=cuts)
    if bound_origins != ((CodeAddress(bound_reads[0].address, entry.isa,
                                      entry.phase, entry.bank), bound_reg),):
        return None
    stack_slot_stores = [ins for ins in ordered if ins.id in
                         (a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH)
                         and len(ins.operands) == 2
                         and ins.operands[1].type == a.ARM_OP_MEM
                         and ins.operands[1].mem.base == a.ARM_REG_SP
                         and not ins.operands[1].mem.index
                         and ins.operands[1].mem.disp
                             == bound_store.operands[1].mem.disp]
    if stack_slot_stores != [bound_store]:
        return None
    stack_bound_loads = [ins for ins in ordered if ins.id == a.ARM_INS_LDR
                         and len(ins.operands) == 2
                         and ins.operands[0].type == a.ARM_OP_REG
                         and ins.operands[1].type == a.ARM_OP_MEM
                         and ins.operands[1].mem.base == a.ARM_REG_SP
                         and not ins.operands[1].mem.index
                         and ins.operands[1].mem.disp
                             == bound_store.operands[1].mem.disp]
    if len(stack_bound_loads) != 1:
        return None
    bound_load = stack_bound_loads[0]
    if (not (bound_store.address < branch_target <= bound_load.address
             < compare.address)
            or not body.dominates(bound_store_pc,
                CodeAddress(branch_target, entry.isa, entry.phase, entry.bank))
            or not body.dominates(CodeAddress(bound_load.address, entry.isa,
                                              entry.phase, entry.bank),
                                  CodeAddress(compare.address, entry.isa,
                                              entry.phase, entry.bank))):
        return None
    compare_bound = bound_load.operands[0].reg
    index_reg = scaled_rows[0][1]
    if branch.cc == a.ARM_CC_LS:
        inclusive = compare_left == index_reg and compare_right == compare_bound
    else:
        inclusive = compare_left == compare_bound and compare_right == index_reg
    if not inclusive:
        return None
    index_initializers = [ins for ins in ordered if ins.id in (a.ARM_INS_MOV,
                           a.ARM_INS_MOVS, a.ARM_INS_EOR)
                          and ins.address < branch_target
                          and ins.operands and ins.operands[0].type == a.ARM_OP_REG
                          and ins.operands[0].reg == index_reg]
    increments = [ins for ins in ordered if branch_target <= ins.address < branch_at
                  and ins.id == a.ARM_INS_ADD
                  and len(ins.operands) == 2
                  and ins.operands[0].type == a.ARM_OP_REG
                  and ins.operands[0].reg == index_reg
                  and ins.operands[1].type == a.ARM_OP_IMM
                  and ins.operands[1].imm == 1]
    if len(increments) != 1:
        return None
    index_zeroes = [ins for ins in index_initializers
                    if ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    and len(ins.operands) == 2
                    and ins.operands[1].type == a.ARM_OP_IMM
                    and ins.operands[1].imm == 0]
    index_writes = []
    for ins in ordered:
        if not branch_target <= ins.address <= branch_at:
            continue
        try:
            writes = set(ins.regs_access()[1])
        except Exception:
            return None
        if index_reg in writes:
            index_writes.append(ins)
    index_wraps = []
    for ins in ordered:
        if (ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR)
                and len(ins.operands) == 3
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == index_reg
                and ins.operands[1].type == a.ARM_OP_REG
                and ins.operands[1].reg == index_reg
                and ins.operands[2].type == a.ARM_OP_IMM
                and ins.operands[2].imm == 16):
            index_wraps.append(ins)
    allowed_index_writes = list(increments)
    if index_wraps:
        if (len(index_wraps) != 2
                or index_wraps[0].id != a.ARM_INS_LSL
                or index_wraps[1].id != a.ARM_INS_LSR
                or index_wraps[0].address != increments[0].address
                    + increments[0].size
                or index_wraps[1].address != index_wraps[0].address
                    + index_wraps[0].size
                or index_wraps[1].address >= branch_at):
            return None
        allowed_index_writes.extend(index_wraps)
        allowed_index_writes.sort(key=lambda ins: ins.address)
    if (len(increments) != 1 or len(index_zeroes) != 1
            or index_writes != allowed_index_writes
            or not body.dominates(CodeAddress(index_zeroes[0].address,
                                               entry.isa, entry.phase,
                                               entry.bank),
                                  CodeAddress(branch_target, entry.isa,
                                              entry.phase, entry.bank))):
        return None

    # The parser owner must itself be reached by code which obtains this
    # object from a structurally identified field in a selected record.
    consumers = []
    for source, target in facts.call_candidates('thumb'):
        if target != entry.address:
            continue
        for start in range(max(0, source - 0x600) & ~1, source, 2):
            owner = facts.decode(CodeAddress(start, 'thumb'))
            if (owner is None or owner.id != a.ARM_INS_PUSH
                    or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR
                               for op in owner.operands)):
                continue
            caller = facts.function(CodeAddress(start, 'thumb'), budget=512)
            if (caller.complete and not caller.unresolved and not caller.truncated
                    and CodeAddress(source, 'thumb') in caller.instructions):
                instructions = {facts.decode(pc).address: facts.decode(pc)
                                for pc in caller.instructions}
                call_owner = instructions.get(source)
                if call_owner is None:
                    continue
                call_pc = CodeAddress(source, 'thumb')
                origins = facts.register_origins(caller, call_pc,
                                                 a.ARM_REG_R0)
                if origins is None or len(origins) != 1:
                    continue
                load = facts.decode(origins[0][0])
                if (load is not None and load.id == a.ARM_INS_LDR
                        and len(load.operands) == 2
                        and load.operands[1].type == a.ARM_OP_MEM
                        and load.operands[1].mem.index == 0):
                    memory = load.operands[1].mem
                    field_pc = CodeAddress(origins[0][0].address,
                                           caller.entry.isa,
                                           caller.entry.phase,
                                           caller.entry.bank)
                    if not caller.dominates(field_pc, CodeAddress(
                            source, 'thumb', caller.entry.phase,
                            caller.entry.bank)):
                        continue
                    cuts = _iteration_cut(caller)
                    base_origins = (facts.register_origins(
                        caller, origins[0][0], memory.base,
                        cut_edges=(cuts,) if cuts else ())
                        if cuts is not None else facts.register_origins(
                            caller, origins[0][0], memory.base))
                    consumers.append({'parser': entry, 'field': memory.disp,
                                      'entry': caller.entry,
                                      'callsite': call_pc,
                                      'field_load': origins[0][0],
                                      'record_base': memory.base,
                                      'record_base_origins': base_origins,
                                      'record_base_value': facts.register_value(
                                          caller, origins[0][0], memory.base,
                                          cut_edges=(cuts,) if cuts else (),
                                          follow_stack=True),
                                      'caller_body': caller})
    fields = sorted({consumer['field'] for consumer in consumers})
    if not fields:
        return None
    evidence = [_span(facts, body), _span(facts, wrapper_body),
                _span(facts, copy_body)]
    evidence.extend(_span(facts, consumer['caller_body'])
                    for consumer in consumers)
    evidence.extend({'span': [consumer['field_load'].address - facts.base, 4]}
                    for consumer in consumers)
    return {'parser': entry, 'wrapper': wrapper, 'field_offsets': fields,
            'consumers': consumers, 'unit': unit,
            'evidence': [item for item in evidence if item is not None]}


def _parser_candidate(facts, address):
    for offset in range(0, 24, 2):
        ins = facts.decode(CodeAddress(address + offset, 'thumb'))
        if (ins is not None and ins.id == a.ARM_INS_LDM and ins.writeback
                and ins.operands and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == a.ARM_REG_R0):
            return True
    return False


def find_flat_signal_memory(image: bytes, *, code_limit: int | None = None):
    """Find reset-published flat upload tables and derive their RAM extents."""
    if (not isinstance(image, bytes) or len(image) < 0x100
            or (code_limit is not None and
                (type(code_limit) is not int or not 0x100 <= code_limit <= len(image)))):
        return None
    linker, status = detect_linker_memory_map(image)
    if status != 'accepted' or linker is None:
        return None
    code = image if code_limit is None else source_prefix(image, code_limit)
    facts = facts_for(code)
    protocols = {}
    seen_targets = set()
    for _site, target in facts.call_candidates('thumb'):
        if target & 1 or target in seen_targets:
            continue
        seen_targets.add(target)
        entry = CodeAddress(target, 'thumb')
        if not _parser_candidate(facts, target):
            continue
        protocol = _flat_parser(facts, entry)
        if protocol is not None:
            protocols[entry] = protocol
    if not protocols:
        return None
    field_units = {}
    for protocol in protocols.values():
        for field in protocol['field_offsets']:
            field_units.setdefault(field, set()).add(protocol['unit'])
    field_units = {field: tuple(sorted(units))
                   for field, units in field_units.items()}
    catalogs = _copied_catalogs(image, linker, field_units)
    if not catalogs:
        return None
    consumers = [consumer for protocol in protocols.values()
                 for consumer in protocol['consumers']]
    bound = bind_flat_catalogs(image, facts, linker, catalogs, consumers)
    if bound is None:
        return None
    selected_catalog = bound['catalog']
    selected_pointers = set(bound['records'])
    selected_fields = set(bound['consumer_fields'])
    selected = {}
    for pointer, links in selected_catalog['records']:
        if pointer not in selected_pointers:
            continue
        for field, nested, parsed in links:
            if field in selected_fields:
                selected[nested] = (pointer, field, parsed, selected_catalog)
    if len(selected) < 3:
        return None
    intervals = [span for _nested, (_pointer, _field, parsed, _catalog)
                 in selected.items() for span in parsed['intervals']]
    ranges = _merged_pages(intervals)
    if not 1 <= len(ranges) <= 8:
        return None
    evidence = []
    for protocol in protocols.values():
        evidence.extend(protocol['evidence'])
    evidence.extend(bound['evidence'])
    for region in linker['regions']:
        if region.get('kind') == 'rw-copy' and any(
                catalog['region'] is region for catalog in (selected_catalog,)):
            reset_evidence = region.get('evidence', {})
            entry = reset_evidence.get('table_offset')
            if type(entry) is int:
                evidence.append({'span': [entry, 20]})
            for reference in reset_evidence.get('references', ()):
                instruction = reference.get('instruction')
                literal = reference.get('literal')
                if type(instruction) is int:
                    evidence.append({'span': [instruction, 4]})
                if type(literal) is int:
                    evidence.append({'span': [literal, 4]})
    evidence.append({'span': selected_catalog['span']})
    for _nested, (parent, field, parsed, _catalog) in selected.items():
        nested = _word(image, parent + field)
        evidence.extend(({'span': [parent, field + 4]},
                         {'span': [nested, 10]},
                         {'span': parsed['rows_span']},
                         {'span': parsed['payload_span']}))
    unique = []
    seen_spans = set()
    for item in evidence:
        span = tuple(item.get('span', ()))
        extra = tuple(tuple(value) for value in item.get('extra_spans', ()))
        key = (span, extra)
        if key not in seen_spans:
            seen_spans.add(key)
            unique.append(item)
    return {'version': 1,
            'ranges': [{'base': low, 'length': high - low}
                       for low, high in ranges],
            'units': sorted({parsed['unit'] for _pointer, _field, parsed, _catalog
                             in selected.values()}),
            'evidence': unique}
