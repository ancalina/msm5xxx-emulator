"""Bind copied flat-upload catalogs to a code-linked indexed selector."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress
from .signal_tables import _DESTINATION_FAMILIES


def _word(image: bytes, offset: int) -> int | None:
    if offset < 0 or offset > len(image) - 4:
        return None
    return struct.unpack_from('<I', image, offset)[0]


def _flat_object(image: bytes, address: int, unit: int):
    """Read a bounded flat-upload object and its destination rows."""
    if (unit not in (2, 4) or address & 3 or address < 0
            or address > len(image) - 10):
        return None
    payload, rows = struct.unpack_from('<II', image, address)
    last_index = struct.unpack_from('<H', image, address + 8)[0]
    if (payload & (unit - 1) or last_index > 0x40 or rows & 3
            or rows > len(image) - (last_index + 1) * 8):
        return None
    intervals = []
    total = 0
    for index in range(last_index + 1):
        destination, count = struct.unpack_from('<II', image, rows + index * 8)
        if (not count or count > 0x100000 or destination & (unit - 1)
                or not any(low <= destination < high
                           for low, high in _DESTINATION_FAMILIES)):
            return None
        end = destination + count * unit
        if end > 0x100000000:
            return None
        intervals.append((destination, end))
        total += count * unit
    if payload > len(image) - total:
        return None
    row_end = rows + (last_index + 1) * 8
    if not (payload + total <= rows or row_end <= payload):
        return None
    return {'payload': payload, 'rows': rows, 'last_index': last_index,
            'unit': unit, 'intervals': intervals,
            'payload_span': [payload, total],
            'rows_span': [rows, row_end - rows]}


def _copied_catalogs(image: bytes, linker: dict,
                     field_units: dict[int, tuple[int, ...]]):
    """Find copied pointer arrays whose records contain parsed objects."""
    catalogs = []
    for region in linker.get('regions', ()):
        if region.get('kind') != 'rw-copy':
            continue
        source, size = region.get('load'), region.get('size')
        if (type(source) is not int or type(size) is not int
                or source < 0 or size < 4 or source + size > len(image)):
            continue
        valid = []
        for offset in range(source, source + size - 3, 4):
            pointer = _word(image, offset)
            links = []
            if pointer is not None:
                for field, units in field_units.items():
                    nested = _word(image, pointer + field) if pointer % 4 == 0 else None
                    if nested is None:
                        continue
                    for unit in units:
                        parsed = _flat_object(image, nested, unit)
                        if parsed is not None:
                            links.append((field, nested, parsed))
            valid.append((pointer, links))
        start = 0
        while start < len(valid):
            if not valid[start][1]:
                start += 1
                continue
            stop = start + 1
            while stop < len(valid) and valid[stop][1]:
                stop += 1
            if stop - start >= 3:
                records = valid[start:stop]
                catalogs.append({'span': [source + start * 4, len(records) * 4],
                                 'records': records, 'region': region})
            start = stop
    return catalogs


def _u32(image: bytes, address: int):
    if type(address) is not int or address < 0 or address > len(image) - 4:
        return None
    return struct.unpack_from('<I', image, address)[0]


def _span(facts, body):
    if not body.instructions:
        return None
    start = min(pc.address for pc in body.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in body.instructions)
    return {'span': [start - facts.base, end - start],
            'extra_spans': [[item.pool - facts.base, 4]
                            for item in body.literals]}


def _owners(facts, site, *, limit=0x1000):
    for address in range(max(facts.base, site - limit) & ~1, site, 2):
        pc = CodeAddress(address, 'thumb')
        ins = facts.decode(pc)
        if (ins is None or ins.id != a.ARM_INS_PUSH
                or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR
                           for op in ins.operands)):
            continue
        body = facts.function(pc, budget=1024)
        if (body.complete and not body.unresolved and not body.truncated
                and CodeAddress(site, 'thumb') in body.instructions):
            yield body


def _copied_input(facts, selector, entry, image):
    """Find a direct call that supplies a statically addressed selector record."""
    result = []
    for site, target in facts.call_candidates('thumb'):
        if target != entry.address:
            continue
        for caller in _owners(facts, site):
            calls = [call for call in caller.call_sites
                     if call.site.address == site and call.target.address == target]
            if len(calls) != 1:
                continue
            registers = dict(calls[0].registers)
            record = registers.get(a.ARM_REG_R1)
            origins = facts.register_origins(
                caller, CodeAddress(site, 'thumb'), a.ARM_REG_R1)
            if type(record) is not int or len(origins) != 1:
                continue
            literal = facts.literal(origins[0][0])
            if (literal is None or literal.value != record
                    or record < 0 or record > len(image) - 4):
                continue
            result.append((record, caller, origins[0][0]))
    return result


def _selector_shape(facts, body, consumers):
    """Prove one bounds-checked indexed pointer load reaches a consumer."""
    code = {pc.address: facts.decode(pc) for pc in body.instructions}
    consumer_calls = [call for call in body.call_sites
                     if call.target.address in consumers]
    if not consumer_calls:
        return None

    # A table pointer is loaded at +8 from a selector structure. The same
    # structure supplies the lower index and entry count at +0 and +4.
    for array_load in code.values():
        if (array_load is None or array_load.id != a.ARM_INS_LDR
                or len(array_load.operands) != 2
                or array_load.operands[1].type != a.ARM_OP_MEM
                or array_load.operands[1].mem.index
                or array_load.operands[1].mem.disp != 8):
            continue
        selector_reg = array_load.operands[1].mem.base
        array_reg = array_load.operands[0].reg
        low_loads = [ins for ins in code.values() if ins is not None
                     and ins.id == a.ARM_INS_LDR
                     and len(ins.operands) == 2
                     and ins.operands[1].type == a.ARM_OP_MEM
                     and ins.operands[1].mem.base == selector_reg
                     and not ins.operands[1].mem.index
                     and ins.operands[1].mem.disp == 0]
        count_loads = [ins for ins in code.values() if ins is not None
                       and ins.id == a.ARM_INS_LDR
                       and len(ins.operands) == 2
                       and ins.operands[1].type == a.ARM_OP_MEM
                       and ins.operands[1].mem.base == selector_reg
                       and not ins.operands[1].mem.index
                       and ins.operands[1].mem.disp == 4]
        if not low_loads or not count_loads:
            continue
        low_reg = low_loads[0].operands[0].reg
        count_reg = count_loads[0].operands[0].reg
        selector_sources = []
        # The structure pointer must come from a field of the input record
        # supplied in R1 at this function's linked call site.
        context_regs = {a.ARM_REG_R1}
        for ins in code.values():
            if (ins is not None and ins.id in (a.ARM_INS_ADD, a.ARM_INS_MOV,
                                                a.ARM_INS_MOVS)
                    and len(ins.operands) >= 2
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[1].type == a.ARM_OP_REG
                    and ins.operands[1].reg == a.ARM_REG_R1):
                if (ins.id != a.ARM_INS_ADD or len(ins.operands) != 3
                        or ins.operands[2].type == a.ARM_OP_IMM
                        and ins.operands[2].imm == 0):
                    context_regs.add(ins.operands[0].reg)
        for ins in code.values():
            if (ins is not None and ins.id == a.ARM_INS_LDR
                    and len(ins.operands) == 2
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[0].reg == selector_reg
                    and ins.operands[1].type == a.ARM_OP_MEM
                    and ins.operands[1].mem.base in context_regs
                    and not ins.operands[1].mem.index):
                selector_sources.append((ins.operands[1].mem.disp, ins))
        if not selector_sources:
            continue

        for index_load in code.values():
            if (index_load is None or index_load.id != a.ARM_INS_LDR
                    or len(index_load.operands) != 2
                    or index_load.operands[0].type != a.ARM_OP_REG
                    or index_load.operands[1].type != a.ARM_OP_MEM):
                continue
            memory = index_load.operands[1].mem
            if (memory.base != array_reg or not memory.index or memory.disp):
                continue
            scaled_reg = memory.index
            shifts = [ins for ins in code.values() if ins is not None
                      and ins.id == a.ARM_INS_LSL
                      and len(ins.operands) == 3
                      and ins.operands[0].type == a.ARM_OP_REG
                      and ins.operands[0].reg == scaled_reg
                      and ins.operands[2].type == a.ARM_OP_IMM
                      and ins.operands[2].imm == 2]
            if not shifts:
                continue
            index_reg = shifts[0].operands[1].reg
            index_subtracts = [ins for ins in code.values() if ins is not None
                               and ins.id == a.ARM_INS_SUB
                               and len(ins.operands) == 3
                               and ins.operands[0].type == a.ARM_OP_REG
                               and ins.operands[0].reg == index_reg
                               and ins.operands[1].type == a.ARM_OP_REG
                               and ins.operands[1].reg == a.ARM_REG_R0
                               and ins.operands[2].type == a.ARM_OP_REG
                               and ins.operands[2].reg == low_reg]
            check_subtracts = [ins for ins in code.values() if ins is not None
                               and ins.id == a.ARM_INS_SUB
                               and len(ins.operands) == 3
                               and ins.operands[1].type == a.ARM_OP_REG
                               and ins.operands[1].reg == a.ARM_REG_R0
                               and ins.operands[2].type == a.ARM_OP_REG
                               and ins.operands[2].reg == low_reg]
            if not index_subtracts or not check_subtracts:
                continue
            bound_checks = []
            for subtract in check_subtracts:
                check_reg = subtract.operands[0].reg
                compares = [ins for ins in code.values() if ins is not None
                            and ins.id == a.ARM_INS_CMP
                            and len(ins.operands) == 2
                            and ins.operands[0].type == a.ARM_OP_REG
                            and ins.operands[0].reg == check_reg
                            and ins.operands[1].type == a.ARM_OP_REG
                            and ins.operands[1].reg == count_reg]
                for compare in compares:
                    branch = code.get(compare.address + compare.size)
                    if (branch is None or branch.id != a.ARM_INS_B
                            or branch.cc != a.ARM_CC_HS
                            or not branch.operands
                            or branch.operands[0].type != a.ARM_OP_IMM):
                        continue
                    guard = CodeAddress(branch.address, body.entry.isa,
                                        body.entry.phase, body.entry.bank)
                    load_pc = CodeAddress(index_load.address, body.entry.isa,
                                          body.entry.phase, body.entry.bank)
                    if not body.dominates(guard, load_pc):
                        continue
                    bound_checks.append((subtract, compare, branch))
            if not bound_checks:
                continue
            selected_reg = index_load.operands[0].reg
            linked_consumers = []
            for consumer in consumer_calls:
                origins = facts.register_origins(body, consumer.site,
                                                  a.ARM_REG_R0)
                if (len(origins) != 1
                        or origins[0][0].address != index_load.address):
                    continue
                consumer_pc = CodeAddress(consumer.site.address,
                                          consumer.site.isa,
                                          consumer.site.phase,
                                          consumer.site.bank)
                if not all(body.dominates(CodeAddress(branch.address,
                                body.entry.isa, body.entry.phase,
                                body.entry.bank), consumer_pc)
                           for _subtract, _compare, branch in bound_checks):
                    continue
                linked_consumers.append(consumer)
            if linked_consumers:
                selector_sources_before_bound = []
                for field, selector_load in selector_sources:
                    low_pc = CodeAddress(low_loads[0].address,
                                         body.entry.isa,
                                         body.entry.phase,
                                         body.entry.bank)
                    start_pc = CodeAddress(selector_load.address,
                                           body.entry.isa,
                                           body.entry.phase,
                                           body.entry.bank)
                    path = body.linear_path(start_pc, low_pc)
                    if path is None:
                        continue
                    clobbered = False
                    for pc in path[1:]:
                        ins = code.get(pc.address)
                        if ins is None:
                            clobbered = True
                            break
                        try:
                            written = set(ins.regs_access()[1])
                        except Exception:
                            written = set()
                        if ins.address != low_loads[0].address and selector_reg in written:
                            clobbered = True
                            break
                    if not clobbered:
                        selector_sources_before_bound.append((field, selector_load))
                if not selector_sources_before_bound:
                    continue
                selector_field, selector_load = selector_sources_before_bound[0]
                linked_entries = sorted({call.target.address
                                          for call in linked_consumers})
                return {'array_reg': array_reg,
                        'selected_reg': selected_reg,
                        'index_load': CodeAddress(index_load.address,
                            body.entry.isa, body.entry.phase, body.entry.bank),
                        'selector_reg': selector_reg,
                        'selector_field': selector_field,
                        'selector_load': CodeAddress(selector_load.address,
                            body.entry.isa, body.entry.phase, body.entry.bank),
                        'low_reg': low_reg, 'count_reg': count_reg,
                        'low_load': CodeAddress(low_loads[0].address,
                            body.entry.isa, body.entry.phase, body.entry.bank),
                        'count_load': CodeAddress(count_loads[0].address,
                            body.entry.isa, body.entry.phase, body.entry.bank),
                        'checks': bound_checks,
                        'consumer_entry': linked_entries[0],
                        'consumer_entries': linked_entries,
                        'consumer_calls': [call.site for call in linked_consumers]}
    return None


def bind_flat_catalogs(image: bytes, facts, linker: dict, catalogs,
                       consumers):
    """Bind catalogs to a reset-copied array consumed by a bounds-checked call.

    ``consumers`` are parser-owner records. Each record supplies either a
    ``caller_body`` FunctionFacts object or a ``caller_entry`` CodeAddress.
    The selector must load its selected pointer and pass that value as R0 to
    one of those consumers.
    """
    if not isinstance(image, bytes) or not isinstance(linker, dict):
        return None
    consumer_entries = set()
    consumer_fields: dict[int, set[int]] = {}
    for item in consumers:
        if not isinstance(item, dict):
            continue
        body = item.get('caller_body')
        entry = getattr(body, 'entry', None) or item.get('caller_entry')
        if isinstance(entry, CodeAddress):
            consumer_entries.add(entry.address)
            field = item.get('field')
            if type(field) is int and field >= 0:
                consumer_fields.setdefault(entry.address, set()).add(field)
    if not consumer_entries:
        return None

    call_index = facts.call_candidates('thumb')
    selector_entries = sorted({site for site, target in call_index
                               if target in consumer_entries})
    for selector_call in selector_entries:
        selector_owners = tuple(_owners(facts, selector_call))
        for selector_body in selector_owners:
            shape = _selector_shape(facts, selector_body, consumer_entries)
            if shape is None:
                continue
            inputs = _copied_input(facts, selector_body, selector_body.entry,
                                   image)
            for record, input_body, input_literal in inputs:
                selector_address = _u32(image, record + shape['selector_field'])
                if (selector_address is None or selector_address & 3
                        or selector_address > len(image) - 12):
                    continue
                low, count, array_address = struct.unpack_from(
                    '<III', image, selector_address)
                if low > 0x100000 or not 1 <= count <= 0x40:
                    continue
                for catalog in catalogs:
                    span = catalog.get('span') if isinstance(catalog, dict) else None
                    region = catalog.get('region') if isinstance(catalog, dict) else None
                    if (not isinstance(span, (list, tuple)) or len(span) != 2
                            or not isinstance(region, dict)):
                        continue
                    source, size = span
                    load, execute, region_size = (region.get('load'),
                                                  region.get('exec'),
                                                  region.get('size'))
                    records = catalog.get('records')
                    if (type(source) is not int or type(size) is not int
                            or type(load) is not int or type(execute) is not int
                            or type(region_size) is not int
                            or source < load or source + size > load + region_size
                            or size != count * 4 or not isinstance(records, list)
                            or len(records) != count):
                        continue
                    runtime = execute + source - load
                    if array_address != runtime:
                        continue
                    pointers = [record_item[0] for record_item in records]
                    if any(type(pointer) is not int for pointer in pointers):
                        continue
                    if [ _u32(image, source + index * 4)
                         for index in range(count)] != pointers:
                        continue
                    consumer_entries = set(shape.get(
                        'consumer_entries', (shape['consumer_entry'],)))
                    required_fields = set().union(*(
                        consumer_fields.get(entry, set())
                        for entry in consumer_entries))
                    if not required_fields or any(
                            not any(link[0] in required_fields
                                    for link in record_item[1])
                            for record_item in records):
                        continue
                    code_evidence = [_span(facts, selector_body),
                                     _span(facts, input_body)]
                    evidence = [item for item in code_evidence if item]
                    evidence.extend(({'span': [record, shape['selector_field'] + 4]},
                                     {'span': [selector_address, 12]},
                                     {'span': span}))
                    map_evidence = region.get('evidence', {})
                    table = map_evidence.get('table_offset')
                    if type(table) is int:
                        evidence.append({'span': [table, 20]})
                    for reference in map_evidence.get('references', ()):
                        for field in ('instruction', 'literal'):
                            address = reference.get(field)
                            if type(address) is int:
                                evidence.append({'span': [address, 4]})
                    evidence.append({'span': [facts.literal(input_literal).pool,
                                               4]})
                    return {'catalog': catalog,
                            'records': pointers,
                            'consumer_entry': shape['consumer_entry'],
                            'consumer_entries': sorted(consumer_entries),
                            'consumer_fields': sorted(required_fields),
                            'runtime_base': runtime,
                            'low': low, 'count': count,
                            'selector': selector_body.entry,
                            'selector_field': shape['selector_field'],
                            'evidence': evidence}
    return None
