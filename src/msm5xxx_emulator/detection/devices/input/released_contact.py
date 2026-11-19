"""Linked proof for a released active-low auxiliary matrix contact."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start, _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .contact_paths import bounded_thumb_cfg, queue_stores_argument
from .startup_copy import reset_linked_input_copy

_MATRIX_GRAMMARS = {
    "sparse-halfword-six-row-v1",
    "sparse-halfword-seven-row-v1",
    "table-row-halfword-seven-v1",
    "mapped-halfword-seven-row-v1",
}

def _valid_matrix(matrix):
    return (type(matrix) is dict and matrix.get("grammar") in _MATRIX_GRAMMARS
            and matrix.get("columns") == 4 and matrix.get("no_key") == 15
            and matrix.get("single_key_column_sense") == [14, 13, 11, 7]
            and type(matrix.get("descriptor")) is int
            and type(matrix.get("sense_address")) is int
            and matrix["sense_address"] in (0x0300066c, 0x0300072c)
            and matrix["descriptor"] & 3 == 0)

def _mem(ins, op_index, base, disp, *, index=0):
    operands = () if ins is None else ins.operands
    return (len(operands) > op_index
            and operands[op_index].type == a.ARM_OP_MEM
            and operands[op_index].mem.base == base
            and operands[op_index].mem.index == index
            and operands[op_index].mem.disp == disp)

def _imm(ins, op_index, value):
    operands = () if ins is None else ins.operands
    return (len(operands) > op_index
            and operands[op_index].type == a.ARM_OP_IMM
            and operands[op_index].imm == value)

def _status_reads(image, matrix, config):
    """Yield descriptor-linked p+34 halfword bit-4 tests in bounded NOR."""
    facts = facts_for(image)
    end = min(len(image), config.flash_size)
    refs = facts.literal_references(matrix["descriptor"])
    for reference in refs:
        if reference.instruction.isa != "thumb":
            continue
        pc = reference.instruction.address
        if not 0 <= pc < end - 12:
            continue
        first = facts.decode(CodeAddress(pc, "thumb"))
        if first is None or first.id != a.ARM_INS_LDR or len(first.operands) != 2:
            continue
        if first.operands[0].type != a.ARM_OP_REG or first.operands[1].type != a.ARM_OP_MEM:
            continue
        if first.operands[1].mem.base != a.ARM_REG_PC:
            continue
        descriptor_reg = first.operands[0].reg
        literal = facts.literal(CodeAddress(pc, "thumb"))
        if literal is None or literal.register != descriptor_reg or literal.value != matrix["descriptor"]:
            continue
        pointer = facts.decode(CodeAddress(pc + first.size, "thumb"))
        if (pointer is None or pointer.id != a.ARM_INS_LDR
                or len(pointer.operands) != 2
                or pointer.operands[0].type != a.ARM_OP_REG
                or pointer.operands[0].reg != descriptor_reg
                or not _mem(pointer, 1, descriptor_reg, 0x34)):
            continue
        read_pc = pc + first.size + pointer.size
        read = facts.decode(CodeAddress(read_pc, "thumb"))
        mask = facts.decode(CodeAddress(read_pc + 2, "thumb"))
        bitop = facts.decode(CodeAddress(read_pc + 4, "thumb"))
        if (read is None or read.id != a.ARM_INS_LDRH or len(read.operands) != 2
                or read.operands[0].type != a.ARM_OP_REG
                or not _mem(read, 1, read.operands[0].reg, 0)
                or mask is None or mask.id != a.ARM_INS_MOV
                or len(mask.operands) != 2 or mask.operands[0].type != a.ARM_OP_REG
                or not _imm(mask, 1, 0x10)
                or bitop is None or bitop.id != a.ARM_INS_AND
                or len(bitop.operands) < 2
                or bitop.operands[0].type != a.ARM_OP_REG
                or bitop.operands[0].reg != mask.operands[0].reg):
            continue
        read_reg = read.operands[0].reg
        if read_reg not in {op.reg for op in bitop.operands[:2]
                            if op.type == a.ARM_OP_REG}:
            continue
        branch_pc = read_pc + 6
        # Only literal loads may intervene between the bit test and BNE.
        while branch_pc < read_pc + 16:
            candidate = facts.decode(CodeAddress(branch_pc, "thumb"))
            if candidate is None:
                break
            if candidate.id == a.ARM_INS_B and candidate.cc == a.ARM_CC_NE:
                break
            if (candidate.id != a.ARM_INS_LDR or len(candidate.operands) != 2
                    or candidate.operands[0].type != a.ARM_OP_REG
                    or candidate.operands[1].type != a.ARM_OP_MEM
                    or candidate.operands[1].mem.base != a.ARM_REG_PC
                    or facts.literal(CodeAddress(branch_pc, "thumb")) is None):
                break
            branch_pc += candidate.size
        branch = facts.decode(CodeAddress(branch_pc, "thumb"))
        if branch is None or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_NE:
            continue
        target = _thumb_successors(image, branch_pc, end)
        if len(target) != 2:
            continue
        yield pc, read_pc, branch_pc, tuple(target), descriptor_reg

def _state_counter_proof(image, matrix, branch_pc, targets, config):
    """Require a linked RAM state object with high reset and low counters."""
    facts = facts_for(image)
    entry = _thumb_function_start(image, branch_pc)
    if entry is None:
        return None
    cfg = bounded_thumb_cfg(image, entry, min(len(image), config.flash_size, entry + 0x400))
    if cfg is None:
        return None
    insns, edges = cfg
    pcs = sorted(insns)
    if not pcs or branch_pc not in pcs:
        return None
    ram_start, ram_end = config.ram_base, config.ram_base + config.ram_size
    states = set()
    for pc in pcs:
        ins = insns[pc]
        if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.base != a.ARM_REG_PC):
            continue
        literal = facts.literal(CodeAddress(pc, "thumb"))
        value = literal.value if literal is not None and literal.register == ins.operands[0].reg else None
        if type(value) is int and ram_start <= value < ram_end and pc == branch_pc - 2:
            states.add((ins.operands[0].reg, value, pc))
    stores = []
    loads = []
    for pc, ins in insns.items():
        if ins is None or len(ins.operands) < 2:
            continue
        if ins.id == a.ARM_INS_STRB and ins.operands[1].type == a.ARM_OP_MEM:
            stores.append((pc, ins, ins.operands[0].reg if ins.operands[0].type == a.ARM_OP_REG else None))
        if ins.id == a.ARM_INS_LDRB and ins.operands[1].type == a.ARM_OP_MEM:
            loads.append((pc, ins))
    state_candidates = []
    for state_reg, state, load_pc in states:
        written = {ins.operands[1].mem.disp for pc, ins, _ in stores
                   if ins.operands[1].mem.base == state_reg}
        read = {ins.operands[1].mem.disp for pc, ins in loads
                if ins.operands[1].mem.base == state_reg}
        pairs = [(offset, offset + 1) for offset in range(0x20)
                 if {offset, offset + 1} <= written & read]
        if pairs:
            state_candidates.append((state_reg, state, load_pc, pairs))
    if len(state_candidates) != 1:
        return None
    state_reg, state, state_load, counter_pairs = state_candidates[0]
    counter_offsets = {offset for pair in counter_pairs for offset in pair}
    stores = [item for item in stores if item[1].operands[1].mem.base == state_reg
              and item[1].operands[1].mem.disp in counter_offsets]
    loads = [(pc, ins) for pc, ins in loads if ins.operands[1].mem.base == state_reg
             and ins.operands[1].mem.disp in counter_offsets]
    if not stores or not loads:
        return None
    def reachable(start, stop=None):
        pending, seen = [start], set()
        while pending and len(seen) < 4096:
            pc = pending.pop()
            if pc == stop:
                return seen, True
            if pc in seen:
                continue
            seen.add(pc)
            pending.extend(target for target in edges.get(pc, ())
                           if target >= pc and target > branch_pc)
        return seen, False
    # Cut scanner backedges so the two status arms stay distinct.
    arms = [reachable(start, stop=branch_pc)[0] for start in targets]
    def zero_registers(path):
        return {ins.operands[0].reg for pc in path if (ins := insns.get(pc)) is not None
                and ins.id == a.ARM_INS_MOV and len(ins.operands) == 2
                and ins.operands[1].type == a.ARM_OP_IMM and ins.operands[1].imm == 0}
    def reset_offsets(path):
        result = set()
        for zero_pc in path:
            zero_ins = insns.get(zero_pc)
            if (zero_ins is None or zero_ins.id != a.ARM_INS_MOV
                    or len(zero_ins.operands) != 2
                    or zero_ins.operands[0].type != a.ARM_OP_REG
                    or zero_ins.operands[1].type != a.ARM_OP_IMM
                    or zero_ins.operands[1].imm != 0):
                continue
            zero_reg = zero_ins.operands[0].reg
            result.update(ins.operands[1].mem.disp for pc, ins, reg in stores
                          if pc in path and zero_pc < pc <= zero_pc + 0x20
                          and reg == zero_reg and ins.operands[1].mem.base == state_reg)
        return result
    high_paths = [path for path in arms
                  if any(set(pair) <= reset_offsets(path) for pair in counter_pairs)]
    def increments_counter(path, pair):
        for pc in path:
            ins = insns.get(pc)
            if (ins is None or ins.id != a.ARM_INS_ADD or len(ins.operands) < 2
                    or ins.operands[0].type != a.ARM_OP_REG
                    or not any(op.type == a.ARM_OP_IMM and op.imm == 1 for op in ins.operands[1:])):
                continue
            reg = ins.operands[0].reg
            if any(store_pc in path and store_reg == reg
                   and store_ins.operands[1].mem.base == state_reg
                   and store_ins.operands[1].mem.disp in pair
                   for store_pc, store_ins, store_reg in stores):
                return True
        return False
    low_paths = [path for path in arms
                 if any(increments_counter(path, pair) for pair in counter_pairs)]
    if len(high_paths) != 1 or len(low_paths) != 1 or high_paths[0] is low_paths[0]:
        return None
    high = high_paths[0]
    low = low_paths[0]
    zero_regs = zero_registers(high)
    reset_offsets = {ins.operands[1].mem.disp for pc, ins, reg in stores
                     if pc in high and reg in zero_regs and ins.operands[1].type == a.ARM_OP_MEM}
    matching_pairs = [pair for pair in counter_pairs if set(pair) <= reset_offsets]
    if not matching_pairs:
        return None
    thresholds = set()
    threshold_sites = {}
    threshold_load_sites = {}
    threshold_offsets = {5: matching_pairs[0][0], 10: matching_pairs[0][1]}
    for pc in low:
        ins = insns.get(pc)
        if ins is None:
            continue
        if (ins.id == a.ARM_INS_CMP and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_IMM
                and ins.operands[1].imm in threshold_offsets):
            threshold = ins.operands[1].imm
            expected_offset = threshold_offsets[threshold]
            linked_load = False
            cursor = pc - 2
            for _ in range(4):
                prior = insns.get(cursor)
                if prior is None:
                    break
                if (prior.id == a.ARM_INS_LDRB and prior.operands[0].type == a.ARM_OP_REG
                        and prior.operands[0].reg == ins.operands[0].reg
                        and _mem(prior, 1, state_reg, expected_offset)):
                    linked_load = True
                    threshold_load_sites[threshold] = cursor
                    break
                try:
                    _, writes = prior.regs_access()
                except Exception:
                    break
                if ins.operands[0].reg in writes:
                    break
                cursor -= prior.size
            if linked_load:
                thresholds.add(threshold)
                threshold_sites.setdefault(threshold, []).append(pc)
    incremented_offsets = set()
    incremented_store_sites = set()
    low_entry = next((target for target in targets if target in low), None)
    pending_states = [] if low_entry is None else [(low_entry, ())]
    visited_states = set()
    while pending_states and len(visited_states) < 4096:
        pc, raw_origins = pending_states.pop()
        if pc not in low:
            continue
        origins = dict(raw_origins)
        key = (pc, tuple(sorted(origins.items())))
        if key in visited_states:
            continue
        visited_states.add(key)
        ins = insns.get(pc)
        if ins is None:
            continue
        destination = None
        if (ins.id == a.ARM_INS_LDRB and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == state_reg
                and ins.operands[1].mem.disp in counter_offsets):
            destination = ins.operands[0].reg
            origins[destination] = (ins.operands[1].mem.disp, False)
        elif (ins.id == a.ARM_INS_ADD and len(ins.operands) >= 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg in origins
                and any(op.type == a.ARM_OP_IMM and op.imm == 1 for op in ins.operands[1:])):
            destination = ins.operands[0].reg
            offset, _ = origins[destination]
            origins[destination] = (offset, True)
        elif (ins.id == a.ARM_INS_MOV and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_REG):
            destination = ins.operands[0].reg
            source = ins.operands[1].reg
            if source in origins:
                origins[destination] = origins[source]
        if (ins.id == a.ARM_INS_STRB and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == state_reg
                and ins.operands[0].reg in origins):
            offset, incremented = origins[ins.operands[0].reg]
            if incremented and offset == ins.operands[1].mem.disp:
                incremented_offsets.add(offset)
                incremented_store_sites.add(pc)
        try:
            _, writes = ins.regs_access()
        except Exception:
            continue
        for reg in writes:
            if reg != destination:
                origins.pop(reg, None)
        pending_states.extend((successor, tuple(sorted(origins.items())))
                              for successor in edges.get(pc, ()) if successor in low)
    matching_pairs = [pair for pair in matching_pairs
                      if set(pair) <= incremented_offsets
                      and threshold_offsets[5] == pair[0]
                      and threshold_offsets[10] == pair[1]]
    if not matching_pairs or not {5, 10} <= thresholds:
        return None
    reset_counter_sites = {}
    for offset in matching_pairs[0]:
        candidates = [pc for pc, ins, reg in stores if pc in high and reg in zero_regs
                      and ins.operands[1].mem.base == state_reg
                      and ins.operands[1].mem.disp == offset]
        if candidates:
            reset_counter_sites[offset] = max(candidates)
    return {"counter_state": state, "thresholds": [5, 10],
            "threshold_sites": threshold_sites,
            "threshold_load_sites": threshold_load_sites,
            "reset_counter_sites": reset_counter_sites,
            "all_counter_stores": [(pc, ins.operands[1].mem.disp)
                                    for pc, ins, _ in stores
                                    if ins.operands[1].mem.base == state_reg],
            "reset_sites": sorted(pc for pc, ins, reg in stores if pc in high and reg in zero_regs),
            "counter_sites": sorted(incremented_store_sites),
            "function_entry": entry, "function_sites": pcs,
            "edges": edges, "high_path": high, "low_path": low,
            "counter_offsets": matching_pairs[0],
            "ram_dependencies": [(state, matching_pairs[0][1] + 1)]}

def _event_queue_proof(image, function_sites, threshold_sites, edges,
                       threshold_load_sites, reset_counter_sites, counter_offsets, all_counter_stores,
                       high_path, low_path, config):
    """Find event 0x5e held into a direct queue call that stores its argument."""
    facts = facts_for(image)
    sites = set(function_sites)
    instructions = {pc: facts.decode(CodeAddress(pc, "thumb")) for pc in sites}
    event_sites = [pc for pc, ins in instructions.items()
                   if ins is not None and ins.id == a.ARM_INS_MOV
                   and len(ins.operands) == 2 and ins.operands[0].type == a.ARM_OP_REG
                   and ins.operands[1].type == a.ARM_OP_IMM and ins.operands[1].imm == 0x5e]
    if len(event_sites) != 1:
        return None
    event_pc = event_sites[0]
    if event_pc not in low_path:
        return None
    def reaches(start, goal):
        pending, seen = [start], set()
        while pending and len(seen) < 4096:
            pc = pending.pop()
            if pc == goal:
                return True
            if pc in seen:
                continue
            seen.add(pc)
            pending.extend(edges.get(pc, ()))
        return False
    gate_sites = {}
    # Both debounce comparisons must independently gate the event.
    for threshold in (5, 10):
        gates = []
        for compare_pc in threshold_sites.get(threshold, ()):
            compare = instructions.get(compare_pc)
            branch_pc = compare_pc + (compare.size if compare is not None else 2)
            branch = instructions.get(branch_pc)
            if branch is None or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_NE:
                continue
            successors = _thumb_successors(image, branch_pc, min(len(image), config.flash_size))
            if len(successors) == 2:
                gate = [reaches(successors[0], event_pc), reaches(successors[1], event_pc)]
                if sum(gate) == 1:
                    gates.append((compare_pc, branch_pc))
        if len(gates) != 1:
            return None
        gate_sites[threshold] = gates[0]
    # A reset arm can reach shared code only while both reloaded bytes stay zero.
    if event_pc in high_path:
        for threshold, offset in ((5, counter_offsets[0]), (10, counter_offsets[1])):
            load_pc = threshold_load_sites.get(threshold)
            reset_pc = reset_counter_sites.get(offset)
            compare_pc = gate_sites[threshold][0]
            if (load_pc is None or reset_pc is None or compare_pc is None
                    or not (reset_pc < load_pc < compare_pc)
                    or any(reset_pc < pc < load_pc and store_offset == offset
                           for pc, store_offset in all_counter_stores)):
                return None
    event_reg = instructions[event_pc].operands[0].reg
    pending = [(next_pc, frozenset((event_reg,)))
               for next_pc in edges.get(event_pc, ())]
    seen, candidates = set(), []
    while pending and len(seen) < 2048:
        current, origins = pending.pop()
        key = (current, origins)
        if key in seen or current not in instructions:
            continue
        seen.add(key)
        ins = instructions[current]
        if ins.id == a.ARM_INS_BL:
            if a.ARM_REG_R0 in origins:
                queue = facts.thumb_call_target(current)
                queue_sites = (queue_stores_argument(image, queue, config)
                               if queue is not None and 0 <= queue < min(len(image), config.flash_size)
                               else False)
                if queue_sites:
                    candidates.append((current, queue, queue_sites))
        new_origins = set(origins)
        if ins.id in (a.ARM_INS_MOV, a.ARM_INS_ADD) and len(ins.operands) >= 2:
            dest = ins.operands[0].reg if ins.operands[0].type == a.ARM_OP_REG else None
            src = ins.operands[1].reg if ins.operands[1].type == a.ARM_OP_REG else None
            preserve = (src in origins and (ins.id == a.ARM_INS_MOV
                or (len(ins.operands) == 3 and ins.operands[2].type == a.ARM_OP_IMM
                    and ins.operands[2].imm == 0)))
            if dest is not None:
                new_origins.discard(dest)
                if preserve:
                    new_origins.add(dest)
        else:
            try:
                _, written = ins.regs_access()
            except Exception:
                continue
            new_origins.difference_update(written)
        if ins.id == a.ARM_INS_BL:
            new_origins.difference_update((a.ARM_REG_R0, a.ARM_REG_R1,
                                           a.ARM_REG_R2, a.ARM_REG_R3))
        pending.extend((successor, frozenset(new_origins)) for successor in edges.get(current, ()))
    if pending or len(candidates) != 1:
        return None
    queue_site, queue, queue_sites = candidates[0]
    return {"event_site": event_pc, "queue_site": queue_site,
            "queue_sink": queue, "event_register": event_reg,
            "queue_sites": queue_sites}

def released_contact_property(image, config, matrix):
    """Return a native status-contact property only with same-copy proof.
    The contact is the independent active-low bit 4 on the selected matrix's
    sense port. A high reading is statically established as inactive by the
    linked debounce helper. The helper does not infer a physical label.
    """
    if (not isinstance(image, (bytes, bytearray)) or not _valid_matrix(matrix)
            or getattr(config, "load_address", None) != 0
            or type(getattr(config, "flash_size", None)) is not int
            or type(getattr(config, "ram_base", None)) is not int
            or type(getattr(config, "ram_size", None)) is not int):
        return None, None
    image = bytes(image)
    nor_end = min(len(image), config.flash_size)
    descriptor = matrix["descriptor"]
    if not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38:
        return None, None
    matches = []
    for literal_pc, read_pc, branch_pc, targets, _ in _status_reads(image, matrix, config):
        status_entry = _thumb_function_start(image, literal_pc)
        if status_entry is None or status_entry >= nor_end:
            continue
        counters = _state_counter_proof(image, matrix, branch_pc, targets, config)
        if counters is None:
            continue
        event = _event_queue_proof(image, counters["function_sites"], counters["threshold_sites"],
                                   counters["edges"], counters["threshold_load_sites"],
                                   counters["reset_counter_sites"], counters["counter_offsets"],
                                   counters["all_counter_stores"],
                                   counters["high_path"],
                                   counters["low_path"], config)
        if event is None:
            continue
        copy = reset_linked_input_copy(
            image, ((descriptor, 0x38),),
            ram_base=config.ram_base, ram_size=config.ram_size,
            flash_size=config.flash_size)
        if copy is None or copy.source_address(descriptor, 0x38) is None:
            continue
        descriptor_source = copy.source_address(descriptor, 0x38)
        if descriptor_source + 0x38 > nor_end:
            continue
        pointer_a, pointer_b = struct.unpack_from("<I", image, descriptor_source + 8)[0], struct.unpack_from("<I", image, descriptor_source + 0x34)[0]
        if pointer_a != matrix["sense_address"] or pointer_b != matrix["sense_address"]:
            continue
        dependencies = set(copy.evidence)
        dependencies.add((descriptor_source, 0x38))
        dependencies.add((status_entry, max(event["queue_site"] + 4 - status_entry, 2)))
        dependencies.add((event["queue_sink"], 2))
        dependencies.update((pc, facts_for(image).decode(CodeAddress(pc, "thumb")).size)
                            for pc in counters["function_sites"]
                            if facts_for(image).decode(CodeAddress(pc, "thumb")) is not None)
        for pc in counters["function_sites"]:
            literal = facts_for(image).literal(CodeAddress(pc, "thumb"))
            if literal is not None:
                dependencies.add((literal.pool, 4))
        dependencies.update(event["queue_sites"])
        for pc, _ in event["queue_sites"]:
            literal = facts_for(image).literal(CodeAddress(pc, "thumb"))
            if literal is not None:
                dependencies.add((literal.pool, 4))
        if any(start < 0 or size <= 0 or start + size > nor_end for start, size in dependencies):
            continue
        matches.append({
            "grammar": "released-matrix-contact-v1", "descriptor": descriptor,
            "descriptor_source": descriptor_source, "sense_address": matrix["sense_address"],
            "status_site": read_pc, "status_branch": branch_pc,
            "inactive_level": 0x10, "active_low_mask": 0x10,
            "counter_state": counters["counter_state"],
            "counter_offsets": counters["counter_offsets"],
            "thresholds": counters["thresholds"], "event": 0x5e,
            "event_site": event["event_site"], "queue_site": event["queue_site"],
            "queue_sink": event["queue_sink"], "copy_source": copy.source,
            "copy_target": copy.target, "copy_size": copy.size,
            "dependencies": sorted(dependencies),
            "ram_dependencies": counters["ram_dependencies"],
        })
    if len(matches) != 1:
        return None, None
    profile = matches[0]
    if any(not 0 <= start <= nor_end - size for start, size in profile["dependencies"]):
        return None, None
    prop = f"experimental-matrix-contact={profile['status_site']:x}:10"
    return prop, profile
