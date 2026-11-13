"""Source proof for 43/42 coordinate windows and their halfword pixel stream."""
from __future__ import annotations

from bisect import bisect_left
import struct

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


_RAM = (0x10000000, 0x20000000)


def _valid(body):
    return bool(body.instructions) and body.complete and not body.unresolved and not body.truncated


def _span(facts, body):
    first = min(pc.address for pc in body.instructions)
    last = max(pc.address + facts.decode(pc).size for pc in body.instructions)
    return {'span': [first, last - first], 'extra_spans': [
        [literal.pool, 4] for literal in body.literals]}


def _call_owners(facts, site):
    """Find complete function bodies containing a direct callsite."""
    found = {}
    for entry in range(max(0, site - 0x800) & ~1, site, 2):
        ins = facts.decode(CodeAddress(entry, 'thumb'))
        if (ins is None or ins.id != a.ARM_INS_PUSH
                or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR
                           for op in ins.operands)):
            continue
        body = facts.function(CodeAddress(entry, 'thumb'), budget=768)
        if _valid(body) and CodeAddress(site, 'thumb') in body.instructions:
            found[entry] = body
    return tuple(sorted(found.values(), key=lambda body: len(body.instructions)))


def _selector_positions(facts):
    selectors = {}
    for command in (0x42, 0x43):
        positions = []
        for register in range(8):
            positions.extend(facts.string_candidates(
                struct.pack('<H', 0x2000 | (register << 8) | command)))
        selectors[command] = sorted(positions)
    return selectors


def _candidate_setters(facts, calls, selectors):
    targets = sorted({target for _, target in calls})
    candidates = {}
    for target in targets:
        possible = True
        for command in (0x42, 0x43):
            positions = selectors[command]
            index = bisect_left(positions, target)
            if index == len(positions) or positions[index] >= target + 0x100:
                possible = False
                break
        if not possible:
            continue
        body = facts.function(CodeAddress(target, 'thumb'), budget=160,
                              initial_registers={a.ARM_REG_R0: 3,
                                                 a.ARM_REG_R1: 5,
                                                 a.ARM_REG_R2: 7,
                                                 a.ARM_REG_R3: 11})
        if not _valid(body) or body.calls:
            continue
        writes = [use for use in body.accesses
                  if use.operation == 'write' and use.width == 2]
        if len(writes) != 6 or len({use.address for use in writes}) != 1:
            continue
        port = writes[0].address
        values = tuple(use.value for use in writes)
        y_offset = values[4] - 5 if len(values) == 6 and type(values[4]) is int else None
        if (port != 0x18000000
                or values[:4] != (0x43, 3, 7, 0x42)
                or y_offset is None or not 0 <= y_offset <= 255
                or type(values[5]) is not int
                or values[5] - 11 != y_offset
                or any(use.predicate != a.ARM_CC_AL for use in writes)):
            continue
        candidates[target] = (body, port, y_offset)
    return candidates


def _edges(body):
    back_edges = set(body.back_edges)
    return tuple((source, target) for source, target in body.control_edges
                 if (source.address, target.address) in back_edges)


def _counted_rectangle(facts, body, data_port, width, height, *, source_copy):
    """Find nested BHS decrement loops covering a matching halfword stream."""
    if (not _valid(body) or width is not None and width <= 1
            or height is not None and height <= 1):
        return None
    code = {pc.address: facts.decode(pc) for pc in body.instructions}
    loops = []
    cuts = _edges(body)
    for branch_at, target in body.back_edges:
        branch = code.get(branch_at)
        decrement = code.get(branch_at - 2)
        if (branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_HS or decrement is None
                or decrement.id != a.ARM_INS_SUB or not decrement.update_flags
                or len(decrement.operands) != 2
                or decrement.operands[0].type != a.ARM_OP_REG
                or decrement.operands[1].type != a.ARM_OP_IMM
                or decrement.operands[1].imm != 1):
            continue
        loops.append((target, branch_at, decrement.operands[0].reg))
    stores = [use for use in body.accesses if use.operation == 'write'
              and use.width == 2 and use.address == data_port
              and use.predicate == a.ARM_CC_AL]
    for store in stores:
        ins = code.get(store.instruction.address)
        if (ins is None or ins.id != a.ARM_INS_STRH or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.disp != 2):
            continue
        value_reg = ins.operands[0].reg
        for outer in loops:
            for inner in loops:
                if not (outer[0] < inner[0] <= store.instruction.address
                        <= inner[1] < outer[1]):
                    continue
                inner_initial = facts.register_value(
                    body, CodeAddress(inner[0], body.entry.isa,
                                      body.entry.phase, body.entry.bank),
                    inner[2], cut_edges=cuts)
                outer_initial = facts.register_value(
                    body, CodeAddress(outer[0], body.entry.isa,
                                      body.entry.phase, body.entry.bank),
                    outer[2], cut_edges=cuts)
                inner_count = _constant(inner_initial)
                outer_count = _constant(outer_initial)
                if (width is not None
                        and (inner_count is None or inner_count + 1 != width)
                        or height is not None
                        and (outer_count is None or outer_count + 1 != height)):
                    continue
                if source_copy:
                    loads = []
                    for pc in body.instructions:
                        load = code[pc.address]
                        if (load is not None and load.id == a.ARM_INS_LDRH
                                and len(load.operands) == 2
                                and load.operands[0].type == a.ARM_OP_REG
                                and load.operands[0].reg == value_reg
                                and load.operands[1].type == a.ARM_OP_MEM
                                and load.operands[1].mem.disp == 0
                                and not load.operands[1].mem.index
                                and load.address < store.instruction.address):
                            loads.append(load)
                    if len(loads) != 1:
                        continue
                    load = loads[0]
                    source = load.operands[1].mem.base
                    load_pc = CodeAddress(load.address, body.entry.isa,
                                          body.entry.phase, body.entry.bank)
                    if (source == value_reg or facts.register_origins(
                            body, store.instruction, value_reg,
                            cut_edges=cuts) != ((load_pc, value_reg),)):
                        continue
                    if body.linear_path(CodeAddress(
                            load.address, body.entry.isa, body.entry.phase,
                            body.entry.bank), store.instruction) is None:
                        continue
                    inner_nodes = range(inner[0], inner[1] + 1, 2)
                    pointer_steps = [candidate for address in inner_nodes
                                     if (candidate := code.get(address)) is not None
                                     and candidate.id == a.ARM_INS_ADD
                                     and len(candidate.operands) == 2
                                     and candidate.operands[0].type == a.ARM_OP_REG
                                     and candidate.operands[0].reg == source
                                     and candidate.operands[1].type == a.ARM_OP_IMM
                                     and candidate.operands[1].imm == 2]
                    if len(pointer_steps) != 1 or pointer_steps[0].address <= store.instruction.address:
                        continue
                    row_setup = [candidate for address in range(outer[0], inner[0], 2)
                                 if (candidate := code.get(address)) is not None
                                 and candidate.id == a.ARM_INS_ADD
                                 and len(candidate.operands) == 3
                                 and candidate.operands[0].type == a.ARM_OP_REG
                                 and candidate.operands[0].reg == source
                                 and candidate.operands[1].type == a.ARM_OP_REG
                                 and candidate.operands[2].type == a.ARM_OP_IMM
                                 and candidate.operands[2].imm == 0]
                    if len(row_setup) != 1:
                        continue
                    row_base = row_setup[0].operands[1].reg
                    literals = [literal for literal in body.literals
                                if literal.register == row_base
                                and _RAM[0] <= literal.value < _RAM[1]
                                and literal.instruction.address < row_setup[0].address]
                    if (len(literals) != 1
                            or facts.register_origins(
                                body, CodeAddress(row_setup[0].address,
                                    body.entry.isa, body.entry.phase,
                                    body.entry.bank), row_base,
                                cut_edges=cuts) !=
                            ((literals[0].instruction, row_base),)
                            or facts.register_origins(body, load_pc, source,
                                cut_edges=cuts) !=
                            ((literals[0].instruction, row_base),)):
                        continue
                    outer_dec = code.get(outer[1] - 2)
                    if outer_dec is None:
                        continue
                    stride_path = body.linear_path(
                        CodeAddress(inner[1] + 2, body.entry.isa,
                                     body.entry.phase, body.entry.bank),
                        CodeAddress(outer_dec.address, body.entry.isa,
                                    body.entry.phase, body.entry.bank))
                    if stride_path is None:
                        continue
                    stride = 0
                    for pc in stride_path:
                        candidate = code.get(pc.address)
                        if (candidate is not None and candidate.id == a.ARM_INS_ADD
                                and len(candidate.operands) == 2
                                and candidate.operands[0].type == a.ARM_OP_REG
                                and candidate.operands[0].reg == row_base
                                and candidate.operands[1].type == a.ARM_OP_IMM):
                            stride += candidate.operands[1].imm
                    if stride != width * 2:
                        continue
                else:
                    origins = facts.register_origins(
                        body, store.instruction, value_reg, cut_edges=cuts)
                    if (origins is None or len(origins) != 1
                            or origins[0][0].address >= outer[0]):
                        continue
                    loop_addresses = set(range(outer[0], outer[1] + 1, 2))
                    if any(value_reg in (candidate.regs_access()[1])
                           for address in loop_addresses
                           if (candidate := code.get(address)) is not None
                           and candidate.address != store.instruction.address):
                        continue
                return store.instruction
    return None


def _callsite(body, site, target):
    return next((call for call in body.call_sites
                 if call.site.address == site and call.target.address == target), None)


def _source_callers(facts, calls, target):
    found = {}
    for site, callee in calls:
        if callee != target:
            continue
        for body in _call_owners(facts, site):
            call = _callsite(body, site, target)
            if call is not None:
                found[(body.entry.address, site)] = (body, call)
    return tuple(found.values())


def _constant(value):
    if type(value) is int:
        return value
    if getattr(value, 'kind', None) == 'const':
        return value.value
    return None


def _caller_dimensions(facts, calls, clear_entry):
    results = []
    for caller, call in _source_callers(facts, calls, clear_entry):
        regs = dict(call.registers)
        args = tuple(_constant(regs.get(reg)) for reg in
                     (a.ARM_REG_R0, a.ARM_REG_R1,
                      a.ARM_REG_R2, a.ARM_REG_R3))
        if any(type(value) is not int for value in args):
            continue
        x0, y0, width, height = args
        if (not 0 <= x0 < 256 or not 0 <= y0 < 256
                or not 1 < width <= 255 or not 1 < height <= 255):
            continue
        results.append((caller, call.site.address, x0, y0, width, height))
    return results


def _window_profile(facts, setter, port, body, y_offset, initial_registers=None):
    evaluated = facts.function(body.entry, budget=768,
                               initial_registers=initial_registers or {})
    if not _valid(evaluated):
        return None
    calls = [(site, target) for site, target in evaluated.calls
             if target.address == setter]
    if len(calls) != 1:
        return None
    site, _ = calls[0]
    call = _callsite(evaluated, site.address, setter)
    if call is None:
        return None
    values = tuple(_constant(dict(call.registers).get(reg)) for reg in
                   (a.ARM_REG_R0, a.ARM_REG_R1,
                    a.ARM_REG_R2, a.ARM_REG_R3))
    if any(type(value) is not int for value in values):
        return None
    window = facts.function(CodeAddress(setter, 'thumb'), budget=160,
                            initial_registers={reg: value for reg, value in zip(
                                (a.ARM_REG_R0, a.ARM_REG_R1,
                                 a.ARM_REG_R2, a.ARM_REG_R3), values)})
    writes = [use for use in window.accesses if use.operation == 'write'
              and use.address == port and use.width == 2]
    produced = tuple(use.value for use in writes)
    x0, y0, x1, y1 = values
    if (not _valid(window) or produced != (0x43, x0, x1,
                                           0x42, y0 + y_offset,
                                           y1 + y_offset)
            or x1 < x0 or y1 < y0):
        return None
    return (x0, y0 + y_offset, x1 - x0 + 1, y1 - y0 + 1,
            window, site.address, evaluated)


def _evidence(facts, bodies, sites=()):
    result = []
    for body in bodies:
        item = _span(facts, body)
        item['extra_spans'].extend([[site, 4] for site in sites])
        result.append(item)
    return result


def find_window43(image: bytes):
    """Return a source-linked 43/42 viewport and halfword blitter profile."""
    facts = facts_for(image)
    selectors = _selector_positions(facts)
    left_positions, right_positions = selectors[0x42], selectors[0x43]
    if not any((index := bisect_left(right_positions, left + 1))
               < len(right_positions) and right_positions[index] < left + 0x100
               for left in left_positions) and not any(
                   (index := bisect_left(left_positions, right + 1))
                   < len(left_positions) and left_positions[index] < right + 0x100
                   for right in right_positions):
        return None
    calls = facts.call_candidates('thumb')
    setters = _candidate_setters(facts, calls, selectors)
    found = []
    for setter, (setter_body, port, y_offset) in setters.items():
        data_port = port + 2
        setter_callers = _source_callers(facts, calls, setter)
        clear_candidates = {}
        for body, call in setter_callers:
            if _counted_rectangle(facts, body, data_port, None, None,
                                  source_copy=False) is None:
                continue
            clear_candidates[body.entry.address] = body
        for clear_entry, clear_body in clear_candidates.items():
            for caller, clear_site, x0, y0, width, height in _caller_dimensions(
                    facts, calls, clear_entry):
                if _counted_rectangle(facts, facts.function(
                        clear_body.entry, budget=512,
                        initial_registers={a.ARM_REG_R0: x0,
                                           a.ARM_REG_R1: y0,
                                           a.ARM_REG_R2: width,
                                           a.ARM_REG_R3: height}),
                        data_port, width, height, source_copy=False) is None:
                    continue
                clear_eval = facts.function(clear_body.entry, budget=512,
                    initial_registers={a.ARM_REG_R0: x0, a.ARM_REG_R1: y0,
                                       a.ARM_REG_R2: width, a.ARM_REG_R3: height})
                clear_store = _counted_rectangle(facts, clear_eval,
                    data_port, width, height, source_copy=False)
                clear_window = _window_profile(facts, setter, port, clear_body,
                    y_offset, {a.ARM_REG_R0: x0, a.ARM_REG_R1: y0,
                               a.ARM_REG_R2: width, a.ARM_REG_R3: height})
                if (clear_window is None or clear_store is None
                        or not clear_eval.dominates(
                            CodeAddress(clear_window[5], 'thumb'), clear_store)):
                    continue
                window = clear_window[:4]
                if window != (x0, y0 + y_offset, width, height):
                    continue
                if (not 0 <= window[0] <= 256 - width
                        or not 0 <= window[1] <= 256 - height):
                    continue
                blitters = []
                for blit_body, blit_call in setter_callers:
                    evaluated = facts.function(blit_body.entry, budget=768)
                    if not _valid(evaluated):
                        continue
                    site = blit_call.site.address
                    profile = _window_profile(facts, setter, port, blit_body,
                                               y_offset)
                    if profile is None or profile[:4] != window:
                        continue
                    blit_store = _counted_rectangle(facts, evaluated,
                        data_port, width, height, source_copy=True)
                    if (blit_store is None or not evaluated.dominates(
                            CodeAddress(profile[5], 'thumb'), blit_store)):
                        continue
                    blitters.append((evaluated, site, profile[4]))
                if not blitters:
                    continue
                evidence = _evidence(facts,
                    (caller, clear_body, clear_window[4], setter_body,
                     *(part for item in blitters for part in (item[0], item[2]))),
                    (clear_site, clear_window[5],
                     *(site for _, site, _ in blitters)))
                found.append({'width': width, 'height': height,
                              'x_origin': window[0], 'y_origin': window[1],
                              'data_port': data_port, 'protocol': 'window43',
                              'evidence': evidence})
    keys = {(item['width'], item['height'], item['x_origin'],
             item['y_origin'], item['data_port']) for item in found}
    if len(keys) != 1:
        return None
    return {**found[0], 'evidence': [span for item in found
                                     for span in item['evidence']]}
