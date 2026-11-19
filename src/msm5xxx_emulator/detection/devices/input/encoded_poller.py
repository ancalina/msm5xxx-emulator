"""Source grammar for inline two-port encoded keypad pollers."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for
from .encoded_paths import _active_low_contact, _constant, _is, _path_reaches
from .encoded_ports import (_clean_register_path, _descriptor_sources,
                            _event_triplets, _half, _pointer_origin,
                            _producer_callback)

INLINE_GRAMMAR = "encoded-inline-two-port-keypad-v1"
_KEYS = b"123456789*0#"


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


def _following(site, facts):
    ins = facts.decode(site)
    return (CodeAddress(site.address + ins.size, site.isa, site.phase, site.bank)
            if ins is not None else None)


def _instruction_dependencies(facts, function, image_end):
    spans = set()
    for site in function.instructions:
        ins = facts.decode(site)
        if ins is None or site.address + ins.size > image_end:
            return None
        spans.add((site.address, ins.size))
    for literal in function.literals:
        if (literal.pool < 0 or literal.pool + 4 > image_end
                or type(literal.pool) is not int):
            return None
        spans.add((literal.pool, 4))
    return spans


def _descriptor_use(facts, function, site, register, descriptor, offset):
    value = facts.register_value(function, CodeAddress(site, "thumb"), register)
    if (getattr(value, "kind", None) != "load" or value.site is None
            or len(value.operands) != 1
            or _constant(value.operands[0]) != descriptor + offset):
        return None
    source = facts.decode(value.site)
    if (source is None or source.id != a.ARM_INS_LDR
            or len(source.operands) != 2
            or source.operands[1].type != a.ARM_OP_MEM
            or source.operands[1].mem.index
            or source.operands[1].mem.disp != offset):
        return None
    base = source.operands[1].mem.base
    pointer = facts.register_value(function, value.site, base)
    if _constant(pointer) != descriptor:
        return None
    return value.site.address


def _aux_gate(facts, function, descriptor):
    gates = []
    for site in function.instructions:
        read = facts.decode(site)
        if (not _is(read, a.ARM_INS_LDRH) or len(read.operands) != 2
                or read.operands[1].type != a.ARM_OP_MEM
                or read.operands[1].mem.disp != 0
                or read.operands[1].mem.index):
            continue
        value_reg = _reg(read, 0)
        pointer_reg = read.operands[1].mem.base
        source_site = _descriptor_use(facts, function, site.address,
                                      pointer_reg, descriptor, 0x24)
        shift_site = _following(site, facts)
        shift = facts.decode(shift_site) if shift_site is not None else None
        branch_site = _following(shift_site, facts) if shift_site else None
        branch = facts.decode(branch_site) if branch_site else None
        if (source_site is None or shift is None or shift.id != a.ARM_INS_LSR
                or shift.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(shift.operands) != 3 or _reg(shift, 0) != value_reg
                or _reg(shift, 1) != value_reg or _imm(shift, 2) != 1
                or branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_HS or branch.size != 2):
            continue
        low_event_site = _following(branch_site, facts)
        low_event = facts.decode(low_event_site) if low_event_site else None
        low_branch_site = _following(low_event_site, facts) if low_event_site else None
        low_branch = facts.decode(low_branch_site) if low_branch_site else None
        if (low_event is None or low_event.id != a.ARM_INS_MOV
                or len(low_event.operands) != 2
                or _reg(low_event, 0) != a.ARM_REG_R7
                or _imm(low_event, 1) is None
                or low_branch is None or low_branch.id != a.ARM_INS_B
                or low_branch.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(low_branch.operands) != 1
                or _imm(low_branch, 0) is None):
            continue
        gates.append({"read": site.address, "source": source_site,
                      "branch": branch, "event": _imm(low_event, 1) & 0xFF,
                      "dispatch": _imm(low_branch, 0)})
    return gates[0] if len(gates) == 1 else None


def _idle_read(facts, function, descriptor, dispatch):
    found = []
    for site in function.instructions:
        read = facts.decode(site)
        if (not _is(read, a.ARM_INS_LDRH) or len(read.operands) != 2
                or read.operands[1].type != a.ARM_OP_MEM
                or read.operands[1].mem.disp != 0
                or read.operands[1].mem.index):
            continue
        read_site = site.address
        value_reg = _reg(read, 0)
        if _descriptor_use(facts, function, read_site,
                read.operands[1].mem.base, descriptor, 0x34) is None:
            continue
        seq = [facts.decode(CodeAddress(read_site + 2 * i, "thumb"))
               for i in range(1, 5)]
        if (not _is(seq[0], a.ARM_INS_LSL) or _reg(seq[0], 0) != value_reg
                or _reg(seq[0], 1) != value_reg or _imm(seq[0], 2) != 28
                or not _is(seq[1], a.ARM_INS_LSR)
                or _reg(seq[1], 0) != value_reg or _reg(seq[1], 1) != value_reg
                or _imm(seq[1], 2) != 28
                or not _is(seq[2], a.ARM_INS_CMP)
                or _reg(seq[2], 0) != value_reg or _imm(seq[2], 1) != 0xF
                or not _is(seq[3], a.ARM_INS_B) or seq[3].cc != a.ARM_CC_EQ
                or _imm(seq[3], 0) != dispatch):
            continue
        found.append(read_site)
    return found[0] if len(found) == 1 else None


def _pack_sites(image, function):
    # Byte-level encoding is checked only inside a bounded, source-derived
    # function after descriptor reads are found; it closes the narrowing math.
    words = (0x8811, 0x231E, 0x4019, 0x0109, 0x227F, 0x8800,
             0x0252, 0x4311, 0x06C0, 0x0EC0, 0x4308, 0x0601, 0x0E09)
    sites = [site.address for site in function.instructions
             if site.isa == "thumb" and site.address + 2 * len(words) <= len(image)
             and tuple(_half(image, site.address + 2 * i)
                       for i in range(len(words))) == words]
    return sites[0] if len(sites) == 1 else None


def _table_lookup(image, facts, region, dispatch):
    instructions = sorted(site.address for site in region.instructions
                          if site.isa == "thumb")
    if not instructions:
        return None
    edges, predecessors = {}, {}
    for source, target in region.control_edges:
        edges.setdefault(source.address, set()).add(target.address)
        predecessors.setdefault(target.address, set()).add(source.address)
    start, end = instructions[0], min(len(image), instructions[-1] + 4)
    found = []
    def at(pc, delta):
        return facts.decode(CodeAddress(pc + delta, "thumb"))

    def branch_target(pc, ins, condition=None):
        if (ins is None or ins.id != a.ARM_INS_B or ins.size != 2
                or len(ins.operands) != 1 or _imm(ins, 0) is None
                or (condition is not None and ins.cc != condition)
                or (condition is None and ins.cc not in
                    (a.ARM_CC_AL, a.ARM_CC_INVALID))):
            return None
        return _imm(ins, 0)

    def reg_mem(ins, register, base, displacement):
        return bool(ins is not None and ins.id == a.ARM_INS_LDRB
            and len(ins.operands) == 2 and _reg(ins, 0) == register
            and ins.operands[1].type == a.ARM_OP_MEM
            and ins.operands[1].mem.base == base
            and ins.operands[1].mem.disp == displacement
            and not ins.operands[1].mem.index)

    for pc in instructions:
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if not _is(ins, a.ARM_INS_LDR) or not ins.operands:
            continue
        literal = facts.literal(CodeAddress(pc, "thumb"))
        if literal is None or literal.register != a.ARM_REG_R2:
            continue
        table = literal.value
        if table < 0 or table + 19 * 3 > len(image):
            continue
        mov_index = at(pc, 2)
        shift_double = at(pc, 4)
        add_index = at(pc, 6)
        add_table = at(pc, 8)
        code_load = at(pc, 10)
        compare = at(pc, 12)
        mismatch = at(pc, 14)
        match_shift = at(pc, 16)
        match_add_index = at(pc, 18)
        match_add_table = at(pc, 20)
        event_load = at(pc, 22)
        match_branch = at(pc, 24)
        increment = at(pc, 26)
        narrow_lsl = at(pc, 28)
        narrow_lsr = at(pc, 30)
        bound_cmp = at(pc, 32)
        bound = at(pc, 34)
        if (not _is(mov_index, a.ARM_INS_MOV) or _reg(mov_index, 0) != a.ARM_REG_R0
                or _imm(mov_index, 1) != 0
                or not _is(shift_double, a.ARM_INS_LSL)
                or _reg(shift_double, 0) != a.ARM_REG_R3
                or _reg(shift_double, 1) != a.ARM_REG_R0
                or _imm(shift_double, 2) != 1
                or not _is(add_index, a.ARM_INS_ADD)
                or (_reg(add_index, 0), _reg(add_index, 1), _reg(add_index, 2))
                    != (a.ARM_REG_R3, a.ARM_REG_R3, a.ARM_REG_R0)
                or not _is(add_table, a.ARM_INS_ADD)
                or (_reg(add_table, 0), _reg(add_table, 1), _reg(add_table, 2))
                    != (a.ARM_REG_R3, a.ARM_REG_R3, a.ARM_REG_R2)
                or not reg_mem(code_load, a.ARM_REG_R3, a.ARM_REG_R3, 1)
                or not _is(compare, a.ARM_INS_CMP)
                or (_reg(compare, 0), _reg(compare, 1))
                    != (a.ARM_REG_R3, a.ARM_REG_R1)
                or branch_target(pc + 14, mismatch, a.ARM_CC_NE) != pc + 26
                or not _is(match_shift, a.ARM_INS_LSL)
                or (_reg(match_shift, 0), _reg(match_shift, 1),
                    _imm(match_shift, 2)) !=
                    (a.ARM_REG_R3, a.ARM_REG_R0, 1)
                or not _is(match_add_index, a.ARM_INS_ADD)
                or (_reg(match_add_index, 0), _reg(match_add_index, 1),
                    _reg(match_add_index, 2)) !=
                    (a.ARM_REG_R0, a.ARM_REG_R3, a.ARM_REG_R0)
                or not _is(match_add_table, a.ARM_INS_ADD)
                or (_reg(match_add_table, 0), _reg(match_add_table, 1),
                    _reg(match_add_table, 2)) !=
                    (a.ARM_REG_R0, a.ARM_REG_R0, a.ARM_REG_R2)
                or not reg_mem(event_load, a.ARM_REG_R7, a.ARM_REG_R0, 2)
                or branch_target(pc + 24, match_branch) != dispatch
                or not _is(increment, a.ARM_INS_ADD)
                or _reg(increment, 0) != a.ARM_REG_R0
                or _imm(increment, 1) != 1
                or not _is(narrow_lsl, a.ARM_INS_LSL)
                or (_reg(narrow_lsl, 0), _reg(narrow_lsl, 1),
                    _imm(narrow_lsl, 2)) != (a.ARM_REG_R0, a.ARM_REG_R0, 24)
                or not _is(narrow_lsr, a.ARM_INS_LSR)
                or (_reg(narrow_lsr, 0), _reg(narrow_lsr, 1),
                    _imm(narrow_lsr, 2)) != (a.ARM_REG_R0, a.ARM_REG_R0, 24)
                or not _is(bound_cmp, a.ARM_INS_CMP)
                or (_reg(bound_cmp, 0), _imm(bound_cmp, 1)) !=
                    (a.ARM_REG_R0, 0x13)
                or branch_target(pc + 34, bound, a.ARM_CC_LT) != pc + 4
                or edges.get(pc) != {pc + 2}
                or edges.get(pc + 2) != {pc + 4}
                or edges.get(pc + 4) != {pc + 6}
                or edges.get(pc + 6) != {pc + 8}
                or edges.get(pc + 8) != {pc + 10}
                or edges.get(pc + 10) != {pc + 12}
                or edges.get(pc + 12) != {pc + 14}
                or edges.get(pc + 14) != {pc + 16, pc + 26}
                or edges.get(pc + 16) != {pc + 18}
                or edges.get(pc + 18) != {pc + 20}
                or edges.get(pc + 20) != {pc + 22}
                or edges.get(pc + 22) != {pc + 24}
                or edges.get(pc + 24) != {dispatch}
                or edges.get(pc + 26) != {pc + 28}
                or edges.get(pc + 28) != {pc + 30}
                or edges.get(pc + 30) != {pc + 32}
                or edges.get(pc + 32) != {pc + 34}
                or edges.get(pc + 34) != {pc + 4, pc + 36}
                or predecessors.get(pc + 2) != {pc}
                or predecessors.get(pc + 4) != {pc + 2, pc + 34}
                or predecessors.get(pc + 16) != {pc + 14}
                or predecessors.get(pc + 26) != {pc + 14}
                or facts.reaching_definitions(
                    region, CodeAddress(pc + 14, "thumb"), a.ARM_REG_CPSR)
                    != (CodeAddress(pc + 12, "thumb"),)
                or facts.reaching_definitions(
                    region, CodeAddress(pc + 34, "thumb"), a.ARM_REG_CPSR)
                    != (CodeAddress(pc + 32, "thumb"),)
                or (pc + 34, pc + 4) not in region.back_edges
                or not region.dominates(CodeAddress(pc, "thumb"),
                                        CodeAddress(pc + 22, "thumb"))
                or not _clean_register_path(facts, region, pc,
                                            pc + 12, a.ARM_REG_R1)):
            continue
        table_data = _event_triplets(image, table)
        if table_data is None:
            continue
        found.append({"table": table, "pointer": literal.pool,
            **table_data, "event_load": pc + 22,
            "match_start": pc + 24, "lookup_site": pc,
            "dependencies": {(table, 57), (literal.pool, 4)}})
    return found[0] if len(found) == 1 else None


def _numeric_producer(facts, image, dispatch, key_tokens):
    region = facts.function(CodeAddress(dispatch, "thumb"), budget=1024,
        initial_registers={a.ARM_REG_R7: SymbolicValue.arg(0)})
    if not region.complete or region.truncated or region.unresolved:
        return None
    producers = []
    for call in region.call_sites:
        site, target = call.site, call.target
        if target.isa != "thumb" or site.address < 2:
            continue
        move = facts.decode(CodeAddress(site.address - 2, "thumb"))
        if (move is None or move.id != a.ARM_INS_ADD or len(move.operands) != 3
                or _reg(move, 0) != a.ARM_REG_R0
                or _reg(move, 1) != a.ARM_REG_R7 or _imm(move, 2) != 0):
            continue
        if dict(call.registers).get(a.ARM_REG_R0) != SymbolicValue.arg(0):
            continue
        if not _clean_register_path(facts, region, dispatch, site.address - 2,
                                    a.ARM_REG_R7):
            continue
        evidence = _producer_callback(image, facts, target.address)
        if evidence is not None:
            producers.append({"site": site.address, "target": target.address,
                              "evidence": evidence, "region": region})
    return producers[0] if len(producers) == 1 else None


def _inline_aux_dispatch(facts, gate, producer):
    """Close the poller's stateful auxiliary-event path into its callback."""
    dispatch = gate["dispatch"]
    event = gate["event"]
    region = facts.function(CodeAddress(dispatch, "thumb"), budget=512,
        initial_registers={a.ARM_REG_R7: SymbolicValue.const(event)})
    if not region.complete or region.truncated or region.unresolved:
        return None
    edges = {}
    for source, target in region.control_edges:
        if source.isa == target.isa == "thumb":
            edges.setdefault(source.address, set()).add(target.address)

    matches = []
    for call in region.call_sites:
        if (call.target.isa != "thumb" or call.target.address != producer["target"]
                or _constant(dict(call.registers).get(a.ARM_REG_R0)) != event):
            continue
        move_site = call.site.address - 2
        move = facts.decode(CodeAddress(move_site, "thumb"))
        if (move is None or move.id != a.ARM_INS_ADD or len(move.operands) != 3
                or (_reg(move, 0), _reg(move, 1), _imm(move, 2)) !=
                   (a.ARM_REG_R0, a.ARM_REG_R7, 0)
                or not _clean_register_path(facts, region, dispatch, move_site,
                                            a.ARM_REG_R7)):
            continue
        state_tests = []
        for site in region.instructions:
            branch = facts.decode(site)
            if (branch is None or branch.id != a.ARM_INS_B
                    or branch.cc != a.ARM_CC_NE or branch.size != 2
                    or len(branch.operands) != 1 or _imm(branch, 0) is None):
                continue
            compare_site = site.address - 2
            compare = facts.decode(CodeAddress(compare_site, "thumb"))
            read_site = compare_site - 2
            read = facts.decode(CodeAddress(read_site, "thumb"))
            if (not _is(compare, a.ARM_INS_CMP)
                    or (_reg(compare, 0), _reg(compare, 1)) !=
                       (a.ARM_REG_R7, a.ARM_REG_R1)
                    or not _is(read, a.ARM_INS_LDRB)
                    or len(read.operands) != 2 or _reg(read, 0) != a.ARM_REG_R1
                    or read.operands[1].type != a.ARM_OP_MEM
                    or read.operands[1].mem.index):
                continue
            fallthrough = site.address + branch.size
            if (edges.get(compare_site) != {site.address}
                    or edges.get(site.address) != {fallthrough, _imm(branch, 0)}
                    or not region.dominates(CodeAddress(fallthrough, "thumb"),
                                            CodeAddress(move_site, "thumb"))
                    or not _clean_register_path(facts, region, dispatch,
                                                move_site, a.ARM_REG_R7)):
                continue
            compare_defs = facts.reaching_definitions(
                region, CodeAddress(compare_site, "thumb"), a.ARM_REG_R1)
            if compare_defs != (CodeAddress(read_site, "thumb"),):
                continue
            state_tests.append((site.address, read_site, compare_site))
        if len(state_tests) == 1:
            branch_site, read_site, compare_site = state_tests[0]
            matches.append({"event": event, "event_site": gate["source"],
                "dispatch_entry": dispatch, "dispatch_site": call.site.address,
                "dispatch_stub": producer["evidence"]["stub"],
                "dependencies": ((read_site, 4), (compare_site, 4),
                    (branch_site, 2), (move_site, 2),
                    *producer["evidence"]["dependencies"])})
    return matches[0] if len(matches) == 1 else None


def _candidate_precheck(facts, literal, descriptor):
    ins = facts.decode(literal.instruction)
    if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
            or ins.operands[0].type != a.ARM_OP_REG
            or ins.operands[1].type != a.ARM_OP_MEM
            or ins.operands[1].mem.base != a.ARM_REG_PC
            or literal.value != descriptor):
        return False
    base = ins.operands[0].reg
    for pc in range(literal.instruction.address + ins.size,
                    literal.instruction.address + 36, 2):
        use = facts.decode(CodeAddress(pc, "thumb"))
        if (use is not None and use.id == a.ARM_INS_LDR
                and len(use.operands) == 2
                and use.operands[1].type == a.ARM_OP_MEM
                and use.operands[1].mem.base == base
                and use.operands[1].mem.disp in (0x24, 0x34)):
            continue
        if use is not None and use.id in (a.ARM_INS_B, a.ARM_INS_BX,
                                          a.ARM_INS_BL, a.ARM_INS_BLX):
            break
    else:
        return False
    seen = set()
    for pc in range(literal.instruction.address + ins.size,
                    literal.instruction.address + 36, 2):
        use = facts.decode(CodeAddress(pc, "thumb"))
        if (use is not None and use.id == a.ARM_INS_LDR
                and len(use.operands) == 2
                and use.operands[1].type == a.ARM_OP_MEM
                and use.operands[1].mem.base == base):
            seen.add(use.operands[1].mem.disp)
    return {0x24, 0x34} <= seen


def _inline_profile(image, facts, entry, descriptor, descriptor_sources,
                    flash_size, *, ram_base=None, ram_size=None):
    whole = facts.function(CodeAddress(entry, "thumb"), budget=1024,
                           initial_registers={})
    if (whole.entry.address != entry or not whole.instructions
            or not whole.complete or whole.truncated or whole.unresolved):
        return None
    gate = _aux_gate(facts, whole, descriptor)
    if gate is None:
        return None
    idle_site = _idle_read(facts, whole, descriptor, gate["dispatch"])
    if idle_site is None:
        return None
    row_site = _pack_sites(image, whole)
    if row_site is None:
        return None
    row_ins = facts.decode(CodeAddress(row_site, "thumb"))
    sense_site = row_site + 10
    sense_ins = facts.decode(CodeAddress(sense_site, "thumb"))
    if (row_ins is None or sense_ins is None
            or _descriptor_use(facts, whole, row_site,
                 row_ins.operands[1].mem.base, descriptor, 0x24) is None
            or _descriptor_use(facts, whole, sense_site,
                 sense_ins.operands[1].mem.base, descriptor, 0x34) is None):
        return None
    if len({row_site, sense_site, idle_site, gate["read"], descriptor}) != 5:
        return None
    scan = facts.function(CodeAddress(gate["read"], "thumb"), budget=1024,
        initial_registers={},
        _stop_before=frozenset({CodeAddress(gate["dispatch"], "thumb")}))
    if (not scan.complete or scan.truncated or scan.unresolved
            or scan.scope_exits != (CodeAddress(gate["dispatch"], "thumb"),)
            or any(CodeAddress(site, "thumb") not in scan.instructions
                   for site in (idle_site, row_site, sense_site))):
        return None
    scan_edges = {}
    for source, target in scan.control_edges:
        if source.isa == target.isa == "thumb":
            scan_edges.setdefault(source.address, set()).add(target.address)
    high_start = _imm(gate["branch"], 0)
    low_start = gate["branch"].address + gate["branch"].size
    if (high_start is None
            or not _path_reaches(scan_edges, high_start, row_site)
            or _path_reaches(scan_edges, low_start, row_site)):
        return None
    if not scan.dominates(CodeAddress(gate["read"], "thumb"),
                          CodeAddress(row_site, "thumb")):
        return None
    lookup = _table_lookup(image, facts, scan, gate["dispatch"])
    if lookup is None:
        return None
    if not scan.dominates(CodeAddress(idle_site, "thumb"),
                          CodeAddress(lookup["lookup_site"], "thumb")):
        return None
    last_pack_site = row_site + 24
    compare_site = lookup["lookup_site"] + 12
    if (not scan.dominates(CodeAddress(row_site, "thumb"),
                           CodeAddress(lookup["lookup_site"], "thumb"))
            or not scan.dominates(CodeAddress(last_pack_site, "thumb"),
                                  CodeAddress(lookup["lookup_site"], "thumb"))
            or facts.reaching_definitions(scan, CodeAddress(compare_site, "thumb"),
                                          a.ARM_REG_R1) !=
               (CodeAddress(last_pack_site, "thumb"),)):
        return None
    contact = _active_low_contact(facts, scan, gate["branch"], row_site,
                                  {ord(key) for key in lookup["key_to_code"]})
    producer = _numeric_producer(facts, image, gate["dispatch"],
                                 {ord(key) for key in lookup["key_to_code"]})
    if producer is None:
        return None
    state_ranges = producer["evidence"]["state_ranges"]
    if ram_base is not None or ram_size is not None:
        if (type(ram_base) is not int or type(ram_size) is not int
                or ram_base < 0 or ram_size <= 0
                or ram_base + ram_size > 0x100000000
                or any(address < ram_base or address + size > ram_base + ram_size
                       for address, size in state_ranges)):
            return None
    if contact is None:
        contact = _inline_aux_dispatch(facts, gate, producer)
    if (contact is None or contact["event"] != gate["event"]
            or contact["dispatch_entry"] != gate["dispatch"]):
        return None

    dependencies = set(lookup["dependencies"])
    dependencies.update((source, 0x38) for source in descriptor_sources)
    dispatch_region = facts.function(CodeAddress(gate["dispatch"], "thumb"),
        budget=512, initial_registers={a.ARM_REG_R7:
                                      SymbolicValue.const(gate["event"])})
    for region in (whole, scan, producer["region"], dispatch_region):
        spans = _instruction_dependencies(facts, region, min(len(image), flash_size))
        if spans is None:
            return None
        dependencies.update(spans)
    dependencies.update(contact["dependencies"])
    dependencies.update(producer["evidence"]["dependencies"])
    return {"grammar": INLINE_GRAMMAR, "inline": True,
        "descriptor": descriptor, "descriptor_sources": descriptor_sources,
        "row_port": 0x03000728, "sense_port": 0x0300072C,
        "row_mask": 0x0E, "sense_mask": 0x1F, "idle_nibble": 0x0F,
        "pack": "((p24&0x1e)<<4)|(p34&0x1f)",
        "row_read_site": row_site, "sense_read_site": sense_site,
        "idle_site": idle_site, "aux_read_site": gate["read"],
        "presence_site": idle_site, "backing_gate_site": gate["read"],
        "presence_expected": 1, "presence_mask": 0x01,
        "event_table": lookup["table"],
        "event_table_pointer": lookup["pointer"],
        "event_records": lookup["records"], "event_codes": lookup["codes"],
        "event_tokens": lookup["tokens"],
        "key_to_code": lookup["key_to_code"],
        "event_load_site": lookup["event_load"], "event_register": 7,
        "aux_active_level": 0, "aux_idle_level": 1,
        "aux_event_site": contact["event_site"],
        "aux_event": contact["event"],
        "aux_dispatch_entry": contact["dispatch_entry"],
        "aux_dispatch_site": contact["dispatch_site"],
        "aux_dispatch_stub": contact["dispatch_stub"],
        "producer": producer["target"],
        "producer_call_site": producer["site"],
        "callback_stub": producer["evidence"]["stub"],
        "producer_state_addresses": producer["evidence"]["state_addresses"],
        "producer_state_ranges": state_ranges,
        "dependencies": sorted(dependencies)}


def find_inline_encoded_port_profiles(image, *, flash_size, ram_base,
                                      ram_size):
    """Discover inline pollers from descriptor-backed instruction references."""
    if (not isinstance(image, (bytes, bytearray)) or len(image) < 0x1000
            or type(flash_size) is not int or flash_size <= 0
            or type(ram_base) is not int or type(ram_size) is not int
            or ram_base < 0 or ram_size <= 0
            or ram_base + ram_size > 0x100000000):
        return []
    image = bytes(image)
    end = min(len(image), flash_size)
    facts = facts_for(image)
    sources = _descriptor_sources(image, flash_size)
    if not sources:
        return []
    candidates = set()
    for literal in facts.literal_references_in(((ram_base, ram_base + ram_size),)):
        descriptor = literal.value
        if (literal.instruction.isa != "thumb"
                or descriptor & 3
                or not ram_base <= descriptor <= ram_base + ram_size - 0x38
                or not _candidate_precheck(facts, literal, descriptor)):
            continue
        entry = _thumb_function_start(image, literal.instruction.address)
        if entry is not None and entry < end:
            candidates.add((entry, descriptor))
    profiles = []
    for entry, descriptor in sorted(candidates):
        profile = _inline_profile(image, facts, entry, descriptor, sources,
            flash_size, ram_base=ram_base, ram_size=ram_size)
        if profile is not None:
            profiles.append(profile)
    return profiles
