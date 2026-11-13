"""Source evidence for memory windows populated by firmware upload tables."""
from __future__ import annotations

import struct
from itertools import product

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, source_prefix
from msm5xxx_emulator.detection.values import SymbolicValue
from .signal_tables import (_DESTINATION_FAMILIES, _merged_pages)
from .signal_flat_memory import find_flat_signal_memory
from .signal_copy import (_iteration_cuts, direct_copy_unit as _copy_unit,
                          find_copy_units as _copy_units)


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def _row_intervals(data: bytes, row_at: int, last_index: int, unit: int):
    if last_index > 0x40 or row_at & 3 or row_at > len(data) - (last_index + 1) * 8:
        return None
    result = []
    for index in range(last_index + 1):
        destination, count = struct.unpack_from('<II', data, row_at + index * 8)
        if count == 0 or count > 0x100000:
            return None
        if not any(lo <= destination < hi for lo, hi in _DESTINATION_FAMILIES):
            return None
        end = destination + count * unit
        if end > 0x100000000:
            return None
        result.append((destination, end))
    return result


def _table_candidate(data: bytes, table_at: int, units_hint=None):
    """Decode a compact descriptor registry ending at its final payload."""
    for groups in (4, 3):
        if units_hint is not None and (len(units_hint) != groups
                or any(type(unit) is not int or unit not in (2, 4) for unit in units_hint)):
            continue
        if table_at > len(data) - groups * 12:
            continue
        descriptors = [struct.unpack_from('<III', data, table_at + i * 12)
                       for i in range(groups)]
        if any(payload >= table_at or rows >= table_at or last > 0x40
               for payload, rows, last in descriptors):
            continue
        variants = (tuple(units_hint),) if units_hint is not None else product((2, 4), repeat=groups)
        for units in variants:
            all_intervals = []
            valid = True
            for index, ((payload, rows, last), unit) in enumerate(zip(descriptors, units)):
                spans = _row_intervals(data, rows, last, unit)
                expected_end = (descriptors[index + 1][0] if index + 1 < groups
                                else table_at)
                alignment = units[index + 1] if index + 1 < groups else 4
                end = payload + sum(hi - lo for lo, hi in spans or ())
                if (spans is None or payload % unit
                        or any(lo % unit for lo, _ in spans)
                        or (end + alignment - 1) & ~(alignment - 1) != expected_end):
                    valid = False
                    break
                all_intervals.extend(spans)
            if valid:
                ranges = _merged_pages(all_intervals)
                if 1 <= len(ranges) <= 8:
                    return {'table': table_at, 'unit': unit,
                            'units': units,
                            'descriptors': descriptors, 'ranges': ranges,
                            'intervals': all_intervals}
    return None


def _value_key(value):
    if not isinstance(value, SymbolicValue):
        return None
    if value.kind in ('arg', 'const'):
        return value.kind, value.value
    operands = tuple(_value_key(item) for item in value.operands)
    if any(item is None for item in operands):
        return None
    if value.kind == 'load':
        return 'load', value.width, operands[0]
    if value.kind == 'op':
        if value.value == 'add':
            operands = tuple(item for item in operands if item != ('const', 0))
            if len(operands) == 1:
                return operands[0]
            operands = tuple(sorted(operands, key=repr))
        return 'op', value.value, operands
    return None


def _row_parser(facts, entry, unit):
    """Bind descriptor fields and row stride to the copy call's arguments."""
    body = facts.function(entry, budget=512,
        symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
    if (not body.complete or body.unresolved or body.truncated
            or len(body.calls) != 1 or len(body.back_edges) != 1):
        return False
    cuts = _iteration_cuts(body)
    if cuts is None:
        return False
    call, _ = body.calls[0]
    code = {pc.address: facts.decode(pc) for pc in body.instructions}
    arg = ('arg', 0)
    fields = {0: arg, 4: ('op', 'add', tuple(sorted((arg, ('const', 4)), key=repr))),
              8: ('op', 'add', tuple(sorted((arg, ('const', 8)), key=repr)))}
    reads = {}
    for use in body.symbolic_accesses:
        if use.operation != 'read':
            continue
        for offset, address in fields.items():
            if use.width == (2 if offset == 8 else 4) and _value_key(use.address) == address:
                reads[offset] = use.instruction
    if set(reads) != {0, 4, 8}:
        return False
    payload_register = facts.decode(reads[0]).operands[0].reg
    table_register = facts.decode(reads[4]).operands[0].reg
    origin = facts.register_origins(body, call, a.ARM_REG_R0, cut_edges=cuts)
    if origin != ((reads[0], payload_register),):
        return False
    destination = facts.register_origins(body, call, a.ARM_REG_R1, cut_edges=cuts)
    count = facts.register_origins(body, call, a.ARM_REG_R2, cut_edges=cuts)
    if not destination or len(destination) != 1 or not count or len(count) != 1:
        return False
    destination_load = facts.decode(destination[0][0])
    count_load = facts.decode(count[0][0])
    if (destination_load.id != a.ARM_INS_LDR or count_load.id != a.ARM_INS_LDR
            or len(destination_load.operands) != 2 or len(count_load.operands) != 2
            or destination_load.operands[1].type != a.ARM_OP_MEM
            or count_load.operands[1].type != a.ARM_OP_MEM):
        return False
    dest_memory = destination_load.operands[1].mem
    count_memory = count_load.operands[1].mem
    if (dest_memory.base != table_register or not dest_memory.index
            or dest_memory.disp or count_memory.index or count_memory.disp != 4):
        return False
    row_offsets = [ins for ins in code.values() if ins.id == a.ARM_INS_LSL
        and len(ins.operands) == 3 and ins.operands[0].reg == dest_memory.index
        and ins.operands[1].type == a.ARM_OP_REG
        and ins.operands[2].type == a.ARM_OP_IMM and ins.operands[2].imm == 3]
    row_pointers = [ins for ins in code.values() if ins.id == a.ARM_INS_ADD
        and len(ins.operands) == 3 and ins.operands[0].reg == count_memory.base
        and all(op.type == a.ARM_OP_REG for op in ins.operands)
        and {op.reg for op in ins.operands[1:]} == {table_register, dest_memory.index}]
    if not row_offsets or not row_pointers:
        return False
    branch_address, _ = body.back_edges[0]
    branch = code[branch_address]
    compare = code.get(branch_address - 2)
    if (branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_LS
            or compare is None or compare.id != a.ARM_INS_CMP
            or len(compare.operands) != 2
            or any(op.type != a.ARM_OP_REG for op in compare.operands)):
        return False
    index_register = compare.operands[0].reg
    if not any(ins.operands[1].reg == index_register for ins in row_offsets):
        return False
    limit = facts.register_value(body, CodeAddress(compare.address),
        compare.operands[1].reg, cut_edges=cuts, follow_stack=True, allowed_calls=(call,))
    if _value_key(limit) != ('load', 2, fields[8]):
        return False
    shift = unit.bit_length() - 1
    path = body.linear_path(CodeAddress(call.address + facts.decode(call).size),
                            CodeAddress(compare.address))
    if path is None:
        return False
    after = [facts.decode(pc) for pc in path]
    scales = [ins for ins in after if ins.id == a.ARM_INS_LSL
        and len(ins.operands) == 3 and ins.operands[1].reg == count[0][1]
        and ins.operands[2].type == a.ARM_OP_IMM and ins.operands[2].imm == shift]
    return (any(ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                and ins.operands[0].reg == payload_register
                and all(op.type == a.ARM_OP_REG for op in ins.operands)
                and {op.reg for op in ins.operands[1:]}
                    == {payload_register, scale.operands[0].reg}
                for scale in scales for ins in after)
            and any(ins.id == a.ARM_INS_ADD and len(ins.operands) == 2
                and ins.operands[0].reg == index_register
                and ins.operands[1].type == a.ARM_OP_IMM and ins.operands[1].imm == 1
                for ins in after))


def _upload_protocols(facts):
    """Discover wrappers that index an object array and dispatch row parsers."""
    calls = facts.call_candidates('thumb')
    targets = sorted({target for _site, target in calls if target & 1 == 0})
    protocols = []
    for address in targets:
        entry = CodeAddress(address, 'thumb')
        head = [facts.decode(CodeAddress(address + offset, 'thumb'), cache=False)
                for offset in (0, 2, 4, 6)]
        if (any(ins is None for ins in head) or head[0].id != a.ARM_INS_PUSH
                or head[1].id != a.ARM_INS_CMP
                or len(head[1].operands) != 2
                or head[1].operands[0].reg != a.ARM_REG_R1
                or head[1].operands[1].type != a.ARM_OP_IMM
                or head[1].operands[1].imm != 0
                or head[2].id != a.ARM_INS_B):
            continue
        body = facts.function(entry, budget=128)
        if not body.complete or body.unresolved or body.truncated:
            continue
        instructions = {pc.address: facts.decode(pc) for pc in body.instructions}
        has_object_array = any(
            ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
            and ins.operands[1].type == a.ARM_OP_MEM
            and ins.operands[1].mem.base == a.ARM_REG_R1
            and ins.operands[1].mem.disp == 0x20
            for ins in instructions.values())
        if not has_object_array:
            continue
        field_calls = []
        for site, parser in body.calls:
            previous = instructions.get(site.address - 2)
            if (previous is None or previous.id != a.ARM_INS_LDR
                    or len(previous.operands) != 2
                    or previous.operands[0].reg != a.ARM_REG_R0
                    or previous.operands[1].type != a.ARM_OP_MEM):
                continue
            field_calls.append((previous.operands[1].mem.disp, parser))
        if len(field_calls) < 3:
            continue
        units, evidence = [], [_span(facts, body)]
        valid = True
        for offset, parser in field_calls:
            parser_body = facts.function(parser, budget=512)
            if (not parser_body.complete or parser_body.unresolved
                    or parser_body.truncated or len(parser_body.calls) != 1):
                valid = False
                break
            providers = _copy_units(facts, parser_body.calls[0][1])
            if len(providers) != 1:
                valid = False
                break
            unit, functions = next(iter(providers.items()))
            if not _row_parser(facts, parser, unit):
                valid = False
                break
            units.append((offset, unit, parser))
            evidence.append(_span(facts, parser_body))
            evidence.extend(_span(facts, function) for function in functions)
        if not valid or len({item[0] for item in units}) != len(units):
            continue
        ordered = sorted(units)
        if not any(unit == 2 for _offset, unit, _parser in ordered):
            continue
        if not any(unit == 4 for _offset, unit, _parser in ordered):
            continue
        caller_sites = [site for site, target in calls if target == address]
        caller_functions = [owner for site in caller_sites for owner in _owners(facts, site)]
        if not caller_functions:
            continue
        evidence.extend(_span(facts, owner) for owner in caller_functions)
        protocols.append({'fields': [item[0] for item in ordered],
                          'units': [item[1] for item in ordered],
                          'entry': entry,
                          'evidence': [item for item in evidence if item is not None]})
    return protocols


def _owners(facts, site, *, limit=0x800):
    for address in range(max(0, site - limit) & ~1, site, 2):
        ins = facts.decode(CodeAddress(address, 'thumb'))
        if (ins is None or ins.id != a.ARM_INS_PUSH
                or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR
                           for op in ins.operands)):
            continue
        function = facts.function(CodeAddress(address, 'thumb'), budget=1024)
        if function.complete and CodeAddress(site, 'thumb') in function.instructions:
            yield function


def _span(facts, function):
    if not function.instructions:
        return None
    start = min(pc.address for pc in function.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {'span': [start - facts.base, end - start],
            'extra_spans': [[lit.pool - facts.base, 4] for lit in function.literals]}


def _object_linked_tables(data: bytes, fields: list[int]):
    """Yield descriptor registries named by a structurally matching object."""
    max_field = max(fields, default=0)
    stop = len(data) - max_field - 4
    for object_at in range(0, stop, 4):
        table_at = _u32(data, object_at + fields[0])
        distance = object_at - table_at
        if distance not in (3 * 12, 4 * 12):
            continue
        count = distance // 12
        if count > len(fields):
            continue
        if any(_u32(data, object_at + fields[index]) != table_at + index * 12
               for index in range(count)):
            continue
        yield table_at, object_at, count


def find_signal_memory(image: bytes, *, code_limit: int | None = None):
    """Find linked upload descriptors and derive page-rounded write ranges.

    Descriptor rows establish byte extents; the selected-object field layout
    links the registry to the code-proven descriptor parser and copy protocol.
    """
    if (not isinstance(image, bytes) or len(image) < 0x100
            or (code_limit is not None and
                (type(code_limit) is not int or not 0x100 <= code_limit <= len(image)))):
        return None
    def select():
        profile = _find_signal_memory(image, code_limit)
        return profile if profile is not None else find_flat_signal_memory(
            image, code_limit=code_limit)

    return facts_for(image).memo('signal-memory-upload-profile', (code_limit,), select)


def _find_signal_memory(source: bytes, code_limit: int | None):
    """Extract one upload profile within the immutable source fact context."""
    code_source = source if code_limit is None else source_prefix(source, code_limit)
    facts = facts_for(code_source)
    protocols = _upload_protocols(facts)
    if not protocols:
        return None

    matches = {}
    for protocol in protocols:
        fields = protocol['fields']
        for table_at, object_at, count in _object_linked_tables(source, fields):
            candidate = _table_candidate(source, table_at,
                                         tuple(protocol['units'][:count]))
            if (candidate is None or len(candidate['descriptors']) != count
                    or candidate['units'] != tuple(protocol['units'][:count])):
                continue
            evidence = [*protocol['evidence'],
                        {'span': [table_at, count * 12]},
                        {'span': [object_at, max(fields[:count]) + 4]}]
            for index, (payload, row, last) in enumerate(candidate['descriptors']):
                payload_end = (candidate['descriptors'][index + 1][0]
                               if index + 1 < count else table_at)
                evidence.extend(({'span': [payload, payload_end - payload]},
                                 {'span': [row, (last + 1) * 8]}))
            matches[table_at] = {'ranges': candidate['ranges'],
                                 'units': candidate['units'],
                                 'evidence': evidence}
    if not matches:
        return None
    ranges = [item for match in matches.values() for item in match['ranges']]
    union = _merged_pages(ranges)
    if not 1 <= len(union) <= 8:
        return None
    evidence = []
    widths = set()
    for table_at, match in sorted(matches.items()):
        widths.update(match['units'])
        evidence.extend(match['evidence'])
    if widths != {2, 4}:
        return None
    return {'version': 1,
            'ranges': [{'base': lo, 'length': hi - lo} for lo, hi in union],
            'units': sorted(widths), 'evidence': evidence}
