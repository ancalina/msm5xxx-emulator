"""Source-derived five-column halfword keypad scanners."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .mapped_seven_rows_flow import _callee_preserves_register, _event_handoff
from .row_execution import _Bits, _region_values, _row_outputs, _word
from .source_flow import closed_input_region
from .startup_copy import reset_linked_input_copy
from .five_column_flow import (event_map, no_thumb_it, preserves_register,
    saved_frame_calls, unconditional)

GRAMMAR = "halfword-five-column-rows-v1"
_COLUMN_SENSE = (0x1e, 0x1d, 0x1b, 0x17, 0x0f)
_ROW_PORTS = (0x03000660, 0x03000664, 0x03000668,
              0x03000720, 0x03000724, 0x03000728)
_KEYS = b"123456789*0#"


def _values(image, entry, use):
    """Collect constants only from a closed, source-reachable entry prefix."""
    values = _region_values(image, entry, use)
    if values is not None:
        return values
    stops = {use}
    for pc in range(entry, use, 2):
        op = _word(image, pc)
        if op & 0xf800 == 0xe000 or op & 0xf000 == 0xd000:
            from msm5xxx_emulator.detection.arm import _thumb_successors
            stops.update(target for target in _thumb_successors(image, pc, len(image))
                         if not entry <= target < use)
    region = closed_input_region(image, entry, tuple(sorted(stops)))
    if region is None:
        return None
    facts = facts_for(image)
    result = {}
    for index in range(8):
        register = a.ARM_REG_R0 + index
        value = facts.register_value(region, CodeAddress(use), register)
        if value is not None and value.kind == "const":
            result[register] = _Bits.constant(value.value)
    return result


def _sample(image, pc):
    """Return the halfword destination for a low-five-bit sense read."""
    facts = facts_for(image)
    load = facts.decode(CodeAddress(pc))
    if (load is None or load.id != a.ARM_INS_LDRH or len(load.operands) != 2
            or load.operands[0].type != a.ARM_OP_REG
            or load.operands[1].type != a.ARM_OP_MEM
            or load.operands[1].mem.index):
        return None
    register = load.operands[0].reg
    expected = (0x0000 | 27 << 6 | (register - a.ARM_REG_R0) << 3 | (register - a.ARM_REG_R0),
                0x0800 | 27 << 6 | (register - a.ARM_REG_R0) << 3 | (register - a.ARM_REG_R0),
                0x281f | (register - a.ARM_REG_R0) << 8)
    if tuple(_word(image, pc + offset) for offset in (2, 4, 6)) != expected:
        return None
    # LSLS/LSRS #27 keeps exactly the low five sense bits.
    if (_word(image, pc + 2) != 27 << 6 | (register - a.ARM_REG_R0) << 3 | (register - a.ARM_REG_R0)
            or _word(image, pc + 4) != 0x0800 | 27 << 6 | (register - a.ARM_REG_R0) << 3 | (register - a.ARM_REG_R0)):
        return None
    return register


def _sample_sites(image):
    """Search binary signatures first, decoding only plausible low-five reads."""
    found = set()
    for number in range(8):
        signature = struct.pack("<3H",
            27 << 6 | number << 3 | number,
            0x0800 | 27 << 6 | number << 3 | number,
            0x281f | number << 8)
        at = image.find(signature)
        while at >= 0:
            sample_pc = at - 2
            if sample_pc >= 0 and sample_pc & 1 == 0 and _sample(image, sample_pc) is not None:
                found.add(sample_pc)
            at = image.find(signature, at + 2)
    return sorted(found)


def _descriptor_reads(image, function_start, function_end, config, function):
    """Find D+0x34 pointer loads and their halfword reads by register flow."""
    facts = facts_for(image)
    reads = []
    descriptors = set()
    for pc in range(function_start, function_end - 2, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.disp != 0x34
                or ins.operands[1].mem.index):
            continue
        if _thumb_function_start(image, pc) != function_start:
            continue
        descriptor_reg = ins.operands[1].mem.base
        values = _values(image, function_start, pc)
        descriptor = values.get(descriptor_reg, _Bits()).value() if values is not None else None
        if (descriptor is None or descriptor & 3
                or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38):
            continue
        pointer_reg = ins.operands[0].reg
        # A short gap is accepted only when CFG dominance and register flow
        # preserve the descriptor pointer through the intervening instructions.
        for read_pc in (pc + 2, pc + 4, pc + 6):
            read = facts.decode(CodeAddress(read_pc))
            if (read is not None and read.id == a.ARM_INS_LDRH and len(read.operands) == 2
                    and read.operands[1].type == a.ARM_OP_MEM
                    and read.operands[1].mem.base == pointer_reg
                    and not read.operands[1].mem.index and not read.operands[1].mem.disp):
                if (not function.dominates(CodeAddress(pc), CodeAddress(read_pc))
                        or not _no_intervening_write(image, function, facts,
                            pointer_reg, pc + ins.size, read_pc)):
                    continue
                reads.append((read_pc, descriptor, read.operands[0].reg, pc))
                descriptors.add(descriptor)
                break
    if len(descriptors) != 1:
        return (), None
    descriptor = next(iter(descriptors))
    return tuple(sorted({item[0] for item in reads if item[1] == descriptor})), descriptor


def _path_exists(function, start, target, *, blocked=()):
    edges = {}
    for source, destination in function.control_edges:
        edges.setdefault(source.address, set()).add(destination.address)
    pending, seen = [start], set()
    blocked = set(blocked)
    while pending:
        pc = pending.pop()
        if pc == target:
            return True
        if pc in seen or pc in blocked:
            continue
        seen.add(pc)
        pending.extend(edges.get(pc, ()))
    return False


def _writes(facts, site, register):
    ins = facts.decode(site)
    if ins is None:
        return True
    try:
        _, written = ins.regs_access()
    except Exception:
        return True
    return register in written


def _counter_normalizer(image, facts, register, start, end):
    """Accept no-op or a source-visible byte zero-extension after increment."""
    sequence = []
    pc = start
    while pc < end:
        ins = facts.decode(CodeAddress(pc))
        if ins is None or ins.size != 2:
            return False
        operands = ins.operands
        if (not unconditional(ins) or ins.id not in (a.ARM_INS_LSL, a.ARM_INS_LSR)
                or len(operands) != 3
                or operands[0].type != a.ARM_OP_REG or operands[0].reg != register
                or operands[1].type != a.ARM_OP_REG or operands[1].reg != register
                or operands[2].type != a.ARM_OP_IMM or operands[2].imm != 24):
            return False
        sequence.append(ins.id)
        pc += ins.size
    return not sequence or sequence == [a.ARM_INS_LSL, a.ARM_INS_LSR]


def _no_intervening_write(image, function, facts, register, start, target,
                          *, require_path=True, callee_prover=None):
    """Paths reaching target preserve a definition, including proved callees."""
    edges = {}
    reverse = {}
    for source, destination in function.control_edges:
        edges.setdefault(source.address, set()).add(destination.address)
        reverse.setdefault(destination.address, set()).add(source.address)
    can_reach, pending = {target}, [target]
    while pending:
        pc = pending.pop()
        for predecessor in reverse.get(pc, ()):
            if predecessor not in can_reach:
                can_reach.add(predecessor)
                pending.append(predecessor)
    if start not in can_reach:
        return not require_path
    pending, seen = [start], set()
    while pending:
        pc = pending.pop()
        if pc == target:
            continue
        if pc in seen:
            continue
        seen.add(pc)
        if pc not in can_reach:
            continue
        ins = facts.decode(CodeAddress(pc))
        if ins is None or _writes(facts, CodeAddress(pc), register):
            return False
        if ins.id == a.ARM_INS_BLX:
            return False
        if ins.id == a.ARM_INS_BL:
            callee = facts.thumb_call_target(pc)
            prover = callee_prover or _callee_preserves_register
            if (callee is None or callee & 1 or callee >= len(image)
                    or not prover(image, callee, register)):
                return False
        successors = edges.get(pc, set())
        pending.extend(successor for successor in successors
                        if successor in can_reach)
    return True


def _loop_header(image, function, entry, sample, counter, count):
    """Find the source row-bound check at the loop entry, before its switch."""
    facts = facts_for(image)
    sites = {site.address: site for site in function.instructions}
    for pc in range(entry, min(entry + 12, sample), 2):
        if pc not in sites or pc + 2 not in sites:
            continue
        compare = facts.decode(sites[pc])
        branch_site = sites[pc + 2]
        branch = facts.decode(branch_site)
        if (compare is None or compare.id != a.ARM_INS_CMP or not unconditional(compare)
                or len(compare.operands) != 2
                or compare.operands[0].type != a.ARM_OP_REG
                or compare.operands[0].reg != counter
                or compare.operands[1].type != a.ARM_OP_IMM
                or compare.operands[1].imm not in (count - 2, count - 1, count)
                or branch is None or branch.id != a.ARM_INS_B
                or branch.cc not in (a.ARM_CC_GE, a.ARM_CC_HS)
                or not branch.operands or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        target = branch.operands[0].imm
        if (entry <= target <= sample
                and _path_exists(function, target, sample)):
            return pc, branch_site.address
    return None


def _footer(image, function, sample_pc, entry):
    """Close a zero-based bounded loop's counter definition, update, and CFG edge."""
    facts = facts_for(image)
    sites = {site.address: site for site in function.instructions}
    if (not function.complete or function.unresolved or function.truncated
            or not no_thumb_it(facts, function)
            or entry not in sites or sample_pc not in sites
            or not function.dominates(CodeAddress(entry), CodeAddress(sample_pc))):
        return None
    matches = []
    for pc in range(sample_pc + 2, min(sample_pc + 0x180, len(image) - 10), 2):
        if pc not in sites:
            continue
        increment_site = sites[pc]
        inc = facts.decode(increment_site)
        if (inc is None or inc.id != a.ARM_INS_ADD or not unconditional(inc)
                or len(inc.operands) not in (2, 3)
                or inc.operands[0].type != a.ARM_OP_REG):
            continue
        counter = inc.operands[0].reg
        if (inc.operands[-1].type != a.ARM_OP_IMM or inc.operands[-1].imm != 1
                or len(inc.operands) == 3
                and (inc.operands[1].type != a.ARM_OP_REG
                     or inc.operands[1].reg != counter)):
            continue
        for cmp_pc in range(pc + inc.size, min(pc + 20, len(image) - 4), 2):
            if cmp_pc not in sites or cmp_pc + 2 not in sites:
                continue
            compare_site = sites[cmp_pc]
            branch_site = sites[cmp_pc + 2]
            compare = facts.decode(compare_site)
            branch = facts.decode(branch_site)
            if (compare is None or compare.id != a.ARM_INS_CMP or not unconditional(compare)
                    or len(compare.operands) != 2
                    or compare.operands[0].type != a.ARM_OP_REG
                    or compare.operands[0].reg != counter
                    or compare.operands[1].type != a.ARM_OP_IMM
                    or compare.operands[1].imm not in (5, 6)
                    or branch is None or branch.id != a.ARM_INS_B or not branch.operands
                    or branch.operands[0].type != a.ARM_OP_IMM):
                continue
            target = branch.operands[0].imm
            if branch.cc in (a.ARM_CC_LO, a.ARM_CC_LT):
                backedge, backedge_site = target, branch_site.address
                count = compare.operands[1].imm
            elif branch.cc in (a.ARM_CC_GE, a.ARM_CC_HS):
                backedge = backedge_site = None
                fallthrough = branch_site.address + branch.size
                op_site = sites.get(fallthrough)
                op = facts.decode(op_site) if op_site is not None else None
                if (op is not None and op.id == a.ARM_INS_B
                        and op.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                        and op.operands and op.operands[0].type == a.ARM_OP_IMM
                        and (branch_site, op_site) in function.control_edges):
                    backedge = op.operands[0].imm
                    backedge_site = op_site.address
                count = compare.operands[1].imm
            else:
                continue
            init_sites = []
            for init_address, init_site in sites.items():
                if not function.dominates(init_site, CodeAddress(entry)):
                    continue
                init = facts.decode(init_site)
                if (init is not None and init.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                        and unconditional(init)
                        and len(init.operands) == 2
                        and init.operands[0].type == a.ARM_OP_REG
                        and init.operands[0].reg == counter
                        and init.operands[1].type == a.ARM_OP_IMM
                        and init.operands[1].imm == 0
                        and _no_intervening_write(image, function, facts, counter,
                            init_address + init.size, entry)):
                    init_sites.append(init_site)
            if (backedge == entry and backedge_site in sites
                    and (CodeAddress(backedge_site), CodeAddress(entry)) in function.control_edges
                    and (backedge_site, entry) in function.back_edges
                    and count in (5, 6) and len(init_sites) == 1
                    and _loop_header(image, function, entry, sample_pc,
                                     counter, count) is not None
                    and function.dominates(CodeAddress(entry), increment_site)
                    and function.dominates(CodeAddress(entry), CodeAddress(sample_pc))
                    and function.dominates(CodeAddress(sample_pc), increment_site)
                    and function.dominates(increment_site, compare_site)
                    and function.dominates(compare_site, branch_site)
                    and function.dominates(branch_site, sites[backedge_site])
                    and function.dominates(CodeAddress(sample_pc), sites[backedge_site])
                    and not _writes(facts, branch_site, counter)
                    and _counter_normalizer(image, facts, counter,
                        increment_site.address + inc.size, compare_site.address)):
                matches.append((counter, count, increment_site.address, cmp_pc,
                                branch_site.address, backedge_site, init_sites[0].address))
    return matches[0] if len(matches) == 1 else None


def _row_wires(outputs):
    if not outputs:
        return None
    ports = sorted(set().union(*(output.keys() for output in outputs)))
    if not 1 <= len(ports) <= 2 or any(port not in _ROW_PORTS for port in ports):
        return None
    masks = []
    for port in ports:
        zeros = ones = 0
        for output in outputs:
            if port not in output:
                return None
            zeros |= output[port].zero
            ones |= output[port].one
        masks.append(zeros & ones & 0xffff)
    wires = [(port, 1 << bit) for port, mask in zip(ports, masks)
             for bit in range(16) if mask & (1 << bit)]
    if len(wires) != len(outputs) or any(not mask for mask in masks):
        return None
    order = []
    for output in outputs:
        if any((output[port].zero | output[port].one) & mask != mask
               for port, mask in zip(ports, masks)):
            return None
        low = [index for index, (port, wire) in enumerate(wires)
               if output[port].zero & wire]
        if len(low) != 1:
            return None
        order.append(low[0])
    if sorted(order) != list(range(len(outputs))):
        return None
    return ports, masks, order


def _scan(image, config):
    facts = facts_for(image)
    found = []
    for sample_pc in _sample_sites(image):
        sample_register = _sample(image, sample_pc)
        if sample_register is None:
            continue
        function_start = _thumb_function_start(image, sample_pc)
        function = facts.function(CodeAddress(function_start), budget=4096)
        if (not function.complete or function.unresolved or function.truncated
                or not no_thumb_it(facts, function)):
            continue
        # A normal call to a different function bounds the scanner. Stop at a
        # modest source span; it also prevents unrelated later D+0x34 reads.
        function_end = min(len(image), sample_pc + 0x500)
        reads, descriptor = _descriptor_reads(image, function_start, function_end,
                                               config, function)
        if descriptor is None:
            continue
        copy = reset_linked_input_copy(image, ((descriptor, 0x38),),
            ram_base=config.ram_base, ram_size=config.ram_size,
            flash_size=config.flash_size)
        if copy is None:
            continue
        descriptor_source = copy.source_address(descriptor, 0x38)
        if descriptor_source is None or not 0 <= descriptor_source <= min(len(image), config.flash_size) - 0x38:
            continue
        words = {offset: struct.unpack_from("<I", image, descriptor_source + offset)[0]
                 for offset in (0x00, 0x10, 0x20, 0x34)}
        if (words[0x00] not in _ROW_PORTS or words[0x34] != 0x0300072c
                or words[0x10] not in _ROW_PORTS or words[0x20] not in _ROW_PORTS):
            continue
        no_key = facts.decode(CodeAddress(sample_pc + 8))
        if (no_key is None or no_key.id != a.ARM_INS_B or no_key.cc != a.ARM_CC_EQ
                or not no_key.operands or no_key.operands[0].type != a.ARM_OP_IMM):
            continue
        no_key_target = no_key.operands[0].imm
        # A footer's backward transfer identifies the loop entry. It must be
        # paired with an increment and an exact 5/6 row bound.
        candidates = set()
        for pc in range(sample_pc + 10, min(sample_pc + 0x100, len(image) - 2), 2):
            ins = facts.decode(CodeAddress(pc))
            if (ins is not None and ins.id == a.ARM_INS_B
                    and ins.operands and ins.operands[0].type == a.ARM_OP_IMM
                    and sample_pc - 0x400 <= ins.operands[0].imm < sample_pc):
                candidates.add(ins.operands[0].imm)
        for entry in sorted(candidates):
            footer = _footer(image, function, sample_pc, entry)
            if footer is None:
                continue
            (row_register, row_count, increment, compare, loop_branch,
             backedge_site, initializer) = footer
            loop_branch_ins = facts.decode(CodeAddress(loop_branch))
            if (loop_branch_ins is None or loop_branch_ins.id != a.ARM_INS_B
                    or not loop_branch_ins.operands
                    or loop_branch_ins.operands[0].type != a.ARM_OP_IMM):
                continue
            if loop_branch_ins.cc in (a.ARM_CC_GE, a.ARM_CC_HS):
                loop_exit = loop_branch_ins.operands[0].imm
            elif loop_branch_ins.cc in (a.ARM_CC_LT, a.ARM_CC_LO):
                loop_exit = loop_branch + loop_branch_ins.size
            else:
                continue
            if not _path_exists(function, no_key_target, increment,
                                blocked=(sample_pc + 10,)):
                continue
            if row_count not in (5, 6):
                continue
            entry_values = _values(image, function_start, entry)
            if entry_values is None or entry_values.get(row_register, _Bits()).value() != 0:
                continue
            descriptor_registers = [register for register, value in entry_values.items()
                                    if value.value() == descriptor]
            if not descriptor_registers:
                continue
            outputs, code_dependencies = [], set()
            for row in range(row_count):
                # Seed only source-proved D aliases and the tested row value;
                # filter/status state remains unknown to the executor.
                registers = dict(entry_values)
                registers.update({register: _Bits.constant(descriptor)
                                  for register in descriptor_registers})
                registers[row_register] = _Bits.constant(row)
                result = _row_outputs(image, entry, sample_pc, registers,
                    descriptor, descriptor_source,
                    preserved_registers={row_register: row})
                if result is None:
                    break
                outputs.append(result[0])
                code_dependencies.update(result[1])
            if len(outputs) != row_count:
                continue
            wiring = _row_wires(outputs)
            if wiring is None:
                continue
            row_ports, row_masks, row_order = wiring
            if any(port not in (words[0x00], words[0x10], words[0x20]) for port in row_ports):
                continue
            # A prior low-five read through the same descriptor is the
            # presence site; other D+0x34 reads remain explicit evidence.
            prior = [site for site in reads if site < entry and _sample(image, site) is not None]
            if not prior:
                continue
            presence_site = max(prior)
            sample_values = _values(image, function_start, sample_pc + 2)
            if sample_values is None:
                continue
            sample_descriptors = tuple(register for register, value in sample_values.items()
                                       if value.value() == descriptor)
            event_candidates = []
            for load_pc in range(sample_pc + 10, min(no_key_target, sample_pc + 0x100), 2):
                ins = facts.decode(CodeAddress(load_pc))
                if (ins is None or ins.id != a.ARM_INS_LDRB or len(ins.operands) != 2
                        or ins.operands[0].type != a.ARM_OP_REG
                        or ins.operands[1].type != a.ARM_OP_MEM
                        or not ins.operands[1].mem.index):
                    continue
                mapping = event_map(image, sample_pc, load_pc, row_register,
                    row_count, sample_register, loop_exit, descriptor,
                    descriptor_source, _COLUMN_SENSE, _KEYS,
                    descriptor_registers=sample_descriptors,
                    extra_sense_reads=tuple((site, words[0x34]) for site in reads
                                           if sample_pc < site < load_pc))
                if mapping is None:
                    continue
                table, events, dependencies = mapping
                event_register = ins.operands[0].reg
                proof_sites = set()
                proven_calls = saved_frame_calls(image, function, load_pc,
                    min(len(image), load_pc + 0x180), event_register,
                    events, descriptor, descriptor_source)
                sink = _event_handoff(image, load_pc, event_register, 0x180,
                    proven_calls=proven_calls, proof_sites=proof_sites)
                if sink is None:
                    continue
                if not _no_intervening_write(image, function, facts,
                        row_register, load_pc, increment, require_path=False,
                        callee_prover=preserves_register):
                    continue
                # A key path may leave the scanner without incrementing, but
                # cannot reenter its row body or bypass the row bound.
                if any(_path_exists(function, load_pc, target, blocked=(increment,))
                       for target in (entry, sample_pc, backedge_site)):
                    continue
                event_candidates.append((load_pc, event_register, sink, table,
                                         events, dependencies, proof_sites))
            if len(event_candidates) != 1:
                continue
            (event_load, event_register, sink, table, events,
             lookup_dependencies, sink_dependencies) = event_candidates[0]
            if not all(_thumb_function_start(image, site) == function_start
                       for site in (presence_site, entry, event_load, sink)):
                continue
            # Keep every descriptor-owned halfword read, including prechecks.
            all_reads = tuple(site for site in reads if function_start <= site < sink)
            if len(all_reads) > 8:
                continue
            dependencies = set(code_dependencies) | set(lookup_dependencies) | set(sink_dependencies)
            dependencies.update(copy.evidence)
            dependencies.update(((descriptor_source, 0x38), (table, 5 * row_count),
                                 (function_start, sink + 2 - function_start),
                                 (presence_site, 10), (sample_pc, 8),
                                 (sample_pc + 8, 2), (increment, 2),
                                 (compare, 2), (loop_branch, 2),
                                 (backedge_site, 2), (initializer, 2)))
            dependencies.update((max(function_start, site - 4), 6) for site in all_reads)
            found.append({"grammar": GRAMMAR, "rows": row_count, "columns": 5,
                "descriptor": descriptor, "descriptor_source": descriptor_source,
                "presence_site": presence_site, "sense_site": sample_pc,
                "read_sites": list(all_reads), "row_counter_register": row_register - a.ARM_REG_R0,
                "row_loop": entry, "event_load_site": event_load,
                "event_register": event_register - a.ARM_REG_R0,
                "event_sink_site": sink, "event_table": table, "event_codes": events,
                "row_ports": row_ports, "row_masks": row_masks,
                "row_wire_order": row_order, "sense_address": words[0x34],
                "no_key": 31, "single_key_column_sense": list(_COLUMN_SENSE),
                "dependencies": sorted(dependencies)})
    unique = {(profile["descriptor"], profile["presence_site"],
               profile["sense_site"], profile["event_load_site"]): profile
              for profile in found}
    return list(unique.values())


def five_column_row_property(image, config, *, status_descriptor_claimed=False):
    """Return a source-bounded five-column row property and physical profile."""
    if status_descriptor_claimed or getattr(config, "load_address", None) != 0:
        return None, None
    profiles = _scan(image, config)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    if any(not 0 <= start <= min(len(image), config.flash_size) - size
           for start, size in profile["dependencies"]):
        return None, None
    copy = reset_linked_input_copy(image, ((profile["descriptor"], 0x38),),
        ram_base=config.ram_base, ram_size=config.ram_size,
        flash_size=config.flash_size)
    if (copy is None or copy.source_address(profile["descriptor"], 0x38)
            != profile["descriptor_source"]):
        return None, None
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address in [profile["sense_address"], *profile["row_ports"]]:
        return None, None
    ports = list(zip(profile["row_ports"], profile["row_masks"]))
    ports.extend([(0, 0)] * (2 - len(ports)))
    fields = [profile["descriptor"], profile["presence_site"], profile["sense_site"]]
    fields.extend(value for pair in ports for value in pair)
    fields.extend(site for site in profile["read_sites"]
                  if site not in (profile["presence_site"], profile["sense_site"]))
    profile["source_sites"] = [{"presence_site": profile["presence_site"],
        "sense_site": profile["sense_site"], "event_load_site": profile["event_load_site"],
        "event_sink_site": profile["event_sink_site"], "read_sites": list(profile["read_sites"])}]
    return "matrix-halfword-five-wires=" + ":".join(f"{value:x}" for value in fields), profile
