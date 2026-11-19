"""Reset-owned six-row keypad scans using halfword-offset row switches."""
from __future__ import annotations

import struct

from capstone import CS_GRP_CALL, CS_GRP_JUMP
from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .halfword_jump_flow import (
    _contact_read, _jump_switch, _matrix_lookup, _prove_computed_rows,
)
from .halfword_event_buffer import prove_halfword_event_buffer
from .branch_conditions import (add_flags, compare_flags, condition_holds,
                                flag_mask, move_flags, refine_flags,
                                unknown_flags)
from .row_execution import _Bits, _region_values
from .startup_copy import reset_linked_input_copy


GRAMMAR = "halfword-offset-six-row-v1"
_SENSES = (14, 13, 11, 7)
_PORTS = (0x03000720, 0x03000724, 0x03000728)


def _nibble_samples(image: bytes, start: int = 0, end: int | None = None):
    """Find low-nibble LDRH samples by decoded register dataflow shape."""
    found = []
    facts = facts_for(image)
    end = len(image) - 10 if end is None else min(end, len(image) - 10)
    for pc in range(max(0, start), end, 2):
        load_word, left_word, right_word, compare_word = struct.unpack_from(
            "<4H", image, pc)
        register = load_word & 7
        if (load_word & 0xf800 != 0x8800
                or left_word & 0xf800 != 0
                or left_word >> 6 & 31 != 28
                or left_word & 7 != register
                or left_word >> 3 & 7 != register
                or right_word & 0xf800 != 0x0800
                or right_word >> 6 & 31 != 28
                or right_word & 7 != register
                or right_word >> 3 & 7 != register
                or compare_word & 0xf8ff != 0x280f
                or compare_word >> 8 & 7 != register):
            continue
        load, left, right, compare = (facts.decode(CodeAddress(pc + off))
                                      for off in (0, 2, 4, 6))
        if (load is None or load.id != a.ARM_INS_LDRH
                or len(load.operands) != 2
                or load.operands[0].type != a.ARM_OP_REG
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.index
                or load.operands[1].mem.disp
                or left is None or left.id != a.ARM_INS_LSL
                or len(left.operands) != 3
                or left.operands[0].reg != load.operands[0].reg
                or left.operands[1].reg != load.operands[0].reg
                or left.operands[2].type != a.ARM_OP_IMM
                or left.operands[2].imm != 28
                or right is None or right.id != a.ARM_INS_LSR
                or len(right.operands) != 3
                or right.operands[0].reg != load.operands[0].reg
                or right.operands[1].reg != load.operands[0].reg
                or right.operands[2].type != a.ARM_OP_IMM
                or right.operands[2].imm != 28
                or compare is None or compare.id != a.ARM_INS_CMP
                or len(compare.operands) != 2
                or compare.operands[0].reg != load.operands[0].reg
                or compare.operands[1].type != a.ARM_OP_IMM
                or compare.operands[1].imm != 15):
            continue
        found.append(pc)
    return found


def _descriptor_at(image: bytes, read_pc: int, config):
    """Resolve D+0x34 through the live pointer register and reset copy."""
    facts = facts_for(image)
    pointer = facts.decode(CodeAddress(read_pc - 2))
    read = facts.decode(CodeAddress(read_pc))
    if (pointer is None or pointer.id != a.ARM_INS_LDR
            or len(pointer.operands) != 2
            or pointer.operands[0].type != a.ARM_OP_REG
            or pointer.operands[1].type != a.ARM_OP_MEM
            or pointer.operands[1].mem.disp != 0x34
            or read is None or read.id != a.ARM_INS_LDRH
            or len(read.operands) != 2
            or read.operands[1].type != a.ARM_OP_MEM
            or read.operands[1].mem.base != pointer.operands[0].reg
            or read.operands[1].mem.disp or read.operands[1].mem.index):
        return None
    entry = _thumb_function_start(image, read_pc)
    if entry is None:
        return None
    values = _region_values(image, entry, read_pc - 2)
    descriptor_reg = pointer.operands[1].mem.base
    descriptor = values.get(descriptor_reg, _Bits()).value() if values is not None else None
    if (descriptor is None or descriptor & 3
            or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38):
        return None
    copy = reset_linked_input_copy(image, ((descriptor, 0x38),),
        ram_base=config.ram_base, ram_size=config.ram_size,
        flash_size=config.flash_size)
    if copy is None:
        return None
    source = copy.source_address(descriptor, 0x38)
    if source is None or not 0 <= source <= min(len(image), config.flash_size) - 0x38:
        return None
    words = {offset: struct.unpack_from("<I", image, source + offset)[0]
             for offset in (0, 8, 0x10, 0x20, 0x34)}
    if (words[0] not in _PORTS or words[8] != 0x0300072C
            or words[0x10] not in _PORTS or words[0x20] not in _PORTS
            or any(words[offset] not in _PORTS for offset in (0, 0x10, 0x20))):
        return None
    evidence = {(entry, read_pc + 10 - entry)}
    pc = entry
    while pc < read_pc:
        ins = facts.decode(CodeAddress(pc))
        if ins is None:
            break
        literal = facts.literal(CodeAddress(pc))
        if (literal is not None and literal.register == descriptor_reg
                and literal.value == descriptor):
            evidence.update(((pc, ins.size), (literal.pool, 4)))
        pc += ins.size
    return descriptor, descriptor_reg, copy, source, words, values, evidence


def _contact_candidates(image: bytes, start: int, end: int,
                        descriptor: int, descriptor_source: int):
    """Find a separate field-proven bit-4 contact read in the same scanner."""
    facts = facts_for(image)
    found = []
    for pc in range(max(0, start), min(end, len(image) - 8), 2):
        ins = facts.decode(CodeAddress(pc))
        if ins is not None and ins.id == a.ARM_INS_LDRH:
            profile = _contact_read(image, pc, descriptor, descriptor_source)
            if profile is not None:
                event = _contact_event_code(image, profile["branch_site"],
                                            with_metadata=True)
                if event is not None:
                    profile["event_code"] = event[0]
                    profile["dependencies"].update(event[1])
                    profile["event_handoff"] = event[2]
                    found.append(profile)
    return found


def _contact_event_code(image: bytes, branch_site: int, *,
                        with_metadata=False):
    """Track the low-contact event byte through its local stack staging."""
    facts = facts_for(image)
    gate_branch = facts.decode(CodeAddress(branch_site))
    gate_compare = facts.decode(CodeAddress(branch_site - 2))
    if (gate_branch is None or gate_branch.id != a.ARM_INS_B
            or gate_branch.cc != a.ARM_CC_NE
            or gate_compare is None or gate_compare.id != a.ARM_INS_CMP
            or len(gate_compare.operands) != 2
            or gate_compare.operands[1].type != a.ARM_OP_IMM
            or gate_compare.operands[1].imm != 0):
        return None
    # This helper starts on the branch fallthrough, which is the active-low
    # contact path. BNE not taken proves CMP equality, hence compare(0, 0).
    entry_flags = refine_flags(a.ARM_CC_NE, compare_flags(0, 0), False)
    if not entry_flags:
        return None
    start = branch_site + 2
    limit = min(start + 0x60, len(image) - 2)
    # Each state carries concrete small constants, SP-relative aliases and a
    # private stack-byte map. Unknown peripheral reads remain unknown.
    pending = [(start, {a.ARM_REG_SP: ("sp", 0)}, {}, entry_flags,
                 None, None, None)]
    seen, outputs, dependencies = set(), set(), set()
    branch_exits, event_routes = set(), set()
    steps = 0
    while pending:
        pc, registers, memory, flags, store_site, count_site, count_register = pending.pop()
        key = (pc, tuple(sorted(registers.items())), tuple(sorted(memory.items())),
               flags, store_site, count_site, count_register)
        if key in seen:
            continue
        seen.add(key)
        steps += 1
        if steps > 512:
            return None
        if not start <= pc < limit:
            continue
        ins = facts.decode(CodeAddress(pc))
        if ins is None or ins.size != 2:
            return None
        if (ins.id == a.ARM_INS_IT or
                ins.id != a.ARM_INS_B and ins.cc not in
                (a.ARM_CC_AL, a.ARM_CC_INVALID)):
            return None
        if ins.id in (a.ARM_INS_BX, a.ARM_INS_BL, a.ARM_INS_BLX):
            return None
        dependencies.add((pc, ins.size))
        operands = ins.operands

        def value(op):
            if op.type == a.ARM_OP_IMM:
                return op.imm
            if op.type == a.ARM_OP_REG:
                return registers.get(op.reg)
            return None

        next_registers, next_memory = dict(registers), dict(memory)
        next_flags, successor = flags, pc + ins.size
        next_store, next_count_site, next_count_register = (
            store_site, count_site, count_register)
        if ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(operands) == 2:
            if any(op.shift.type or op.subtracted for op in operands):
                return None
            result = value(operands[1])
            next_registers[operands[0].reg] = result
            if ins.update_flags:
                next_flags = move_flags(result, flags)
            if (operands[1].type == a.ARM_OP_IMM and operands[1].imm == 1
                    and a.ARM_REG_R0 <= operands[0].reg <= a.ARM_REG_R7):
                next_count_site = pc
                next_count_register = operands[0].reg
        elif ins.id == a.ARM_INS_ADD and len(operands) in (2, 3):
            if any(op.shift.type or op.subtracted for op in operands):
                return None
            if len(operands) == 2:
                left, right = next_registers.get(operands[0].reg), value(operands[1])
            else:
                left, right = value(operands[1]), value(operands[2])
            if isinstance(left, tuple) and isinstance(right, int):
                result = ("sp", left[1] + right)
            elif isinstance(left, int) and isinstance(right, int):
                result = (left + right) & 0xffffffff
            else:
                result = None
            next_registers[operands[0].reg] = result
            if ins.update_flags:
                next_flags = add_flags(left, right)
        elif ins.id == a.ARM_INS_LDRB and len(operands) == 2:
            mem = operands[1].mem
            base = registers.get(mem.base)
            offset = (base[1] + mem.disp if isinstance(base, tuple)
                      and base[0] == "sp" and not mem.index else None)
            next_registers[operands[0].reg] = next_memory.get(offset) if offset is not None else None
        elif ins.id == a.ARM_INS_STRB and len(operands) == 2:
            mem = operands[1].mem
            base = registers.get(mem.base)
            offset = (base[1] + mem.disp if isinstance(base, tuple)
                      and base[0] == "sp" and not mem.index else None)
            if offset is not None:
                stored = registers.get(operands[0].reg)
                next_memory[offset] = stored
                if offset == 4 and type(stored) is int and 0 <= stored <= 255:
                    outputs.add(stored)
                    next_store = pc
            else:
                # An unresolved byte destination may alias the queue slot.
                next_memory.pop(4, None)
        elif ins.id == a.ARM_INS_CMP and len(operands) == 2:
            left, right = value(operands[0]), value(operands[1])
            next_flags = compare_flags(left, right)
        elif ins.id == a.ARM_INS_B and operands:
            target = operands[0].imm
            def record_taken_exit(exit_flags):
                if target < start or target >= limit:
                    branch_exits.add((target, pc))
                    if (store_site is not None and count_site is not None
                            and count_register is not None
                            and type(memory.get(4)) is int
                            and registers.get(count_register) == 1):
                        event_routes.add((target, store_site, count_site,
                                          count_register, pc, memory[4], 4,
                                          flag_mask(exit_flags)))
            if ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                record_taken_exit(flags)
                successor = target
            else:
                condition = condition_holds(ins.cc, flags)
                taken_flags = refine_flags(ins.cc, flags, True)
                fallthrough_flags = refine_flags(ins.cc, flags, False)
                if condition is not False and taken_flags:
                    record_taken_exit(taken_flags)
                    pending.append((target, dict(next_registers),
                                    dict(next_memory), taken_flags,
                                    next_store, next_count_site,
                                    next_count_register))
                if condition is True:
                    continue
                next_flags = fallthrough_flags
        elif ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP):
            return None
        elif any(op.type == a.ARM_OP_MEM for op in operands):
            # No unmodeled store may silently preserve a stale stack-byte fact.
            if ins.id not in (a.ARM_INS_LDR, a.ARM_INS_LDRH,
                              a.ARM_INS_LDRB, a.ARM_INS_LDRSH,
                              a.ARM_INS_LDRSB):
                next_memory.pop(4, None)
            try:
                _, written = ins.regs_access()
            except Exception:
                return None
            if ins.update_flags or a.ARM_REG_CPSR in written:
                next_flags = None
            if any(register in written for register in next_registers):
                continue
        else:
            # A source instruction that can affect the modeled byte/address
            # state must be understood before following this path.
            try:
                _, written = ins.regs_access()
            except Exception:
                continue
            if ins.update_flags or a.ARM_REG_CPSR in written:
                next_flags = None
            if any(register in written for register in next_registers):
                continue
        if start <= successor < limit:
            pending.append((successor, next_registers, next_memory, next_flags,
                            next_store, next_count_site, next_count_register))
    if len(outputs) != 1:
        return None
    if not with_metadata:
        return next(iter(outputs)), dependencies
    event_value = next(iter(outputs))
    event_routes = {route for route in event_routes if route[5] == event_value}
    return next(iter(outputs)), dependencies, {
        "terminal_sites": tuple(sorted({target for target, _ in branch_exits
                                         if 0 <= target < len(image) and not target & 1})),
        "branch_exits": tuple(sorted(branch_exits)),
        "event_routes": tuple(sorted(event_routes)),
    }


def _event_loads(image: bytes, start: int, row_register: int):
    facts = facts_for(image)
    found = []
    for pc in range(start, min(start + 0x200, len(image) - 2), 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is not None and ins.id == a.ARM_INS_LDRB
                and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.index == row_register
                and not ins.writeback):
            found.append(pc)
    return found


def _scan_profiles(image: bytes, config):
    facts = facts_for(image)
    samples = _nibble_samples(image)
    found = []
    for presence in samples:
        left = _descriptor_at(image, presence, config)
        if left is None:
            continue
        (descriptor, descriptor_reg, copy, descriptor_source, words,
         entry_values, entry_evidence) = left
        if entry_values.get(a.ARM_REG_R4, _Bits()).value() != 0:
            continue
        entry = _thumb_function_start(image, presence)
        if entry is None:
            continue
        later = [pc for pc in samples if presence + 0x20 <= pc < presence + 0x600
                 and _thumb_function_start(image, pc) == entry]
        contacts = _contact_candidates(image, entry, presence, descriptor,
                                       descriptor_source)
        if len(contacts) != 1:
            continue
        for sample in later:
            pointer = facts.decode(CodeAddress(sample - 2))
            sample_load = facts.decode(CodeAddress(sample))
            if (pointer is None or pointer.id != a.ARM_INS_LDR
                    or len(pointer.operands) != 2
                    or pointer.operands[1].type != a.ARM_OP_MEM
                    or pointer.operands[1].mem.base != descriptor_reg
                    or pointer.operands[1].mem.disp != 0x34
                    or sample_load is None or sample_load.id != a.ARM_INS_LDRH
                    or len(sample_load.operands) != 2
                    or sample_load.operands[1].type != a.ARM_OP_MEM
                    or sample_load.operands[1].mem.base != pointer.operands[0].reg
                    or sample_load.operands[1].mem.disp
                    or sample_load.operands[1].mem.index):
                continue
            contact = contacts[0]
            handoff = contact.get("event_handoff", {})
            terminal_sites = tuple(site for site in handoff.get(
                "terminal_sites", ()) if sample < site < len(image))
            switch = _jump_switch(image, sample,
                                  terminal_sites=terminal_sites)
            if switch is None:
                continue
            proofs = []
            for event_load in _event_loads(image, sample + 2,
                                           switch["row_register"]):
                proof = _prove_computed_rows(image, descriptor,
                    descriptor_source, descriptor_reg, presence, sample,
                    event_load, contact["read_site"],
                    terminal_sites=terminal_sites)
                if proof is not None:
                    proof["contact"]["event_code"] = contact["event_code"]
                    proof["contact"]["dependencies"].update(
                        contact["dependencies"])
                    buffer = prove_halfword_event_buffer(image,
                        event_load=proof["event_load_site"],
                        event_sink=proof["event_sink_site"],
                        event_register=proof["event_register"] + a.ARM_REG_R0,
                        event_codes=proof["event_codes"],
                        event_code=contact["event_code"], handoff=handoff)
                    if buffer is None:
                        continue
                    proof["event_buffer"] = buffer
                    proof["dependencies"] = sorted(
                        set(proof["dependencies"])
                        | set(buffer["dependencies"]))
                    proofs.append(proof)
            if len(proofs) != 1:
                continue
            proof = proofs[0]
            # Both reads must use the copied D+0x34 alias, and descriptor,
            # row table and event data are independently source-bounded.
            if (proof["event_table"] < 0
                    or proof["event_table"] + 24 > min(len(image), config.flash_size)
                    or proof["row_ports"] != sorted(proof["row_ports"])
                    or any(port not in _PORTS for port in proof["row_ports"])):
                continue
            dependencies = set(copy.evidence)
            dependencies.update(proof["dependencies"])
            dependencies.update(entry_evidence)
            dependencies.add((descriptor_source, 0x38))
            dependencies.add((proof["event_table"], 24))
            found.append({"grammar": GRAMMAR, "descriptor": descriptor,
                "descriptor_source": descriptor_source,
                "copy_source": copy.source, "copy_target": copy.target,
                "copy_size": copy.size, "presence_site": presence,
                "sense_site": sample, "event_load_site": proof["event_load_site"],
                "event_register": proof["event_register"],
                "event_sink_site": proof["event_sink_site"],
                "event_table": proof["event_table"],
                "event_codes": proof["event_codes"], "rows": 6,
                "columns": 4, "no_key": 15,
                "single_key_column_sense": list(_SENSES),
                "row_counter_register": proof["row_counter_register"],
                "row_loop": proof["row_loop"],
                "row_ports": proof["row_ports"],
                "row_masks": proof["row_masks"],
                "row_wire_order": proof["row_wire_order"],
                "sense_address": words[0x34],
                "contact": proof["contact"],
                "contact_event_handoff": handoff,
                "event_buffer": proof["event_buffer"],
                "dependencies": sorted(dependencies)})
    unique = {(item["descriptor"], item["presence_site"], item["sense_site"],
               item["event_load_site"]): item for item in found}
    return list(unique.values())


def halfword_jump_row_property(image: bytes, config, *,
                               status_descriptor_claimed=False):
    """Return a property only for one reset-linked, source-closed scanner."""
    if (status_descriptor_claimed
            or getattr(config, "load_address", None) != 0):
        return None, None
    profiles = _scan_profiles(image, config)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    limit = min(len(image), config.flash_size)
    if any(type(at) is not int or type(size) is not int or size <= 0
           or not 0 <= at <= limit - size
           for at, size in profile["dependencies"]):
        return None, None
    if (profile["descriptor"] & 3
            or not config.ram_base <= profile["descriptor"]
            <= config.ram_base + config.ram_size - 0x38):
        return None, None
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address in [*profile["row_ports"],
                                                  profile["sense_address"]]:
        return None, None
    contact = profile.get("contact")
    if contact is not None:
        contact["dependencies"] = sorted(contact.get("dependencies", ()))
    ports = list(zip(profile["row_ports"], profile["row_masks"]))
    ports.extend([(0, 0)] * (2 - len(ports)))
    fields = [profile["descriptor"], profile["presence_site"],
              profile["sense_site"], *[value for pair in ports for value in pair]]
    prop = "matrix-halfword-wires=" + ":".join(f"{value:x}" for value in fields)
    contact = profile.get("contact")
    if contact is not None:
        profile["released_contact"] = {
            "status_site": contact["read_site"],
            "mask": 0x10,
            "address": profile["sense_address"],
            "released_level": 0x10,
            "active_low_mask": 0x10,
            "sense_address": profile["sense_address"],
            "dependencies": sorted(contact.get("dependencies", ())),
        }
        profile["contact_property"] = f"experimental-matrix-contact={contact['read_site']:x}:10"
        prop += "," + profile["contact_property"]
    return prop, profile
