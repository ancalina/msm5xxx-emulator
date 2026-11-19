"""Source closure for an active-low matrix status byte staged on the stack."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start, _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .contact_paths import bounded_thumb_cfg
from .startup_copy import reset_linked_input_copy


_GRAMMARS = {"sparse-halfword-six-row-v1", "sparse-halfword-seven-row-v1",
             "table-row-halfword-seven-v1", "mapped-halfword-seven-row-v1"}


def _memory(ins, index, base, displacement):
    return (len(ins.operands) > index
            and ins.operands[index].type == a.ARM_OP_MEM
            and ins.operands[index].mem.base == base
            and ins.operands[index].mem.index == 0
            and ins.operands[index].mem.disp == displacement)


def _immediate(ins, index, value):
    return (len(ins.operands) > index
            and ins.operands[index].type == a.ARM_OP_IMM
            and ins.operands[index].imm == value)


def _status_sites(image, matrix, config):
    """Find exact p+34 halfword reads whose bit 4 feeds an HS branch."""
    facts = facts_for(image)
    nor_end = min(len(image), config.flash_size)
    for literal_ref in facts.literal_references(matrix["descriptor"]):
        site = literal_ref.instruction.address
        if literal_ref.instruction.isa != "thumb" or not 0 <= site < nor_end - 12:
            continue
        pointer = facts.decode(CodeAddress(site, "thumb"))
        if (pointer is None or pointer.id != a.ARM_INS_LDR or len(pointer.operands) != 2
                or pointer.operands[0].type != a.ARM_OP_REG
                or pointer.operands[1].type != a.ARM_OP_MEM
                or pointer.operands[1].mem.base != a.ARM_REG_PC
                or facts.literal(CodeAddress(site, "thumb")) is None
                or facts.literal(CodeAddress(site, "thumb")).value != matrix["descriptor"]):
            continue
        descriptor_reg = pointer.operands[0].reg
        load_pointer_pc = None
        for candidate_pc in range(site + pointer.size, min(site + 0x20, nor_end - 2), 2):
            candidate = facts.decode(CodeAddress(candidate_pc, "thumb"))
            if (candidate is not None and candidate.id == a.ARM_INS_LDR
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == a.ARM_OP_REG
                    and _memory(candidate, 1, descriptor_reg, 0x34)):
                load_pointer_pc = candidate_pc
                break
            if candidate is None:
                break
            if candidate.id in (a.ARM_INS_B, a.ARM_INS_BL, a.ARM_INS_BX):
                break
            try:
                _, writes = candidate.regs_access()
            except Exception:
                break
            if descriptor_reg in writes:
                break
        if load_pointer_pc is None:
            continue
        load_pointer = facts.decode(CodeAddress(load_pointer_pc, "thumb"))
        pointer_reg = load_pointer.operands[0].reg
        read_pc = None
        for candidate_pc in range(load_pointer_pc + load_pointer.size,
                                   min(load_pointer_pc + 0x12, nor_end - 2), 2):
            candidate = facts.decode(CodeAddress(candidate_pc, "thumb"))
            if (candidate is not None and candidate.id == a.ARM_INS_LDRH
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == a.ARM_OP_REG
                    and _memory(candidate, 1, pointer_reg, 0)):
                read_pc = candidate_pc
                break
            if candidate is None:
                break
            if candidate.id in (a.ARM_INS_B, a.ARM_INS_BL, a.ARM_INS_BX):
                break
            try:
                _, writes = candidate.regs_access()
            except Exception:
                break
            if pointer_reg in writes:
                break
        if read_pc is None:
            continue
        read = facts.decode(CodeAddress(read_pc, "thumb"))
        shift_pc = read_pc + read.size
        shift = facts.decode(CodeAddress(shift_pc, "thumb"))
        branch_pc = shift_pc + (shift.size if shift is not None else 2)
        branch = facts.decode(CodeAddress(branch_pc, "thumb"))
        if (shift is None or shift.id != a.ARM_INS_LSR
                or len(shift.operands) != 3
                or shift.operands[0].type != a.ARM_OP_REG
                or shift.operands[0].reg != read.operands[0].reg
                or shift.operands[1].type != a.ARM_OP_REG
                or shift.operands[1].reg != read.operands[0].reg
                or not _immediate(shift, 2, 5) or not shift.update_flags
                or branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_HS):
            continue
        successors = _thumb_successors(image, branch_pc, nor_end)
        if len(successors) != 2:
            continue
        target = branch.operands[0].imm if branch.operands else None
        high = target if target in successors else None
        if high is None:
            continue
        low = next((address for address in successors if address != high), None)
        if low is not None:
            yield read_pc, branch_pc, high, low


def _clear_helper(image, entry, descriptor, config):
    """Require a descriptor-backed read/clear/write of the row shadow."""
    facts = facts_for(image)
    cfg = bounded_thumb_cfg(image, entry,
                            min(len(image), config.flash_size, entry + 0x100))
    if cfg is None:
        return None
    instructions, _edges = cfg
    edges = _edges
    def reaches(start, goal):
        pending, seen = [start], set()
        while pending and len(seen) < 512:
            pc = pending.pop()
            if pc == goal:
                return True
            if pc in seen:
                continue
            seen.add(pc)
            pending.extend(edges.get(pc, ()))
        return False
    literals = {pc: facts.literal(CodeAddress(pc, "thumb")) for pc in instructions}
    for pc, load_base in instructions.items():
        literal = literals[pc]
        if (load_base.id != a.ARM_INS_LDR or len(load_base.operands) != 2
                or load_base.operands[0].type != a.ARM_OP_REG
                or load_base.operands[1].type != a.ARM_OP_MEM
                or load_base.operands[1].mem.base != a.ARM_REG_PC
                or literal is None or literal.value != descriptor):
            continue
        pointer_reg = load_base.operands[0].reg
        for load_pc, load in instructions.items():
            if (load.id != a.ARM_INS_LDRH or len(load.operands) != 2
                    or load.operands[0].type != a.ARM_OP_REG
                    or not _memory(load, 1, pointer_reg, 0x0c)
                    or not reaches(pc + load_base.size, load_pc)):
                continue
            value_reg = load.operands[0].reg
            for clear_pc, clear in instructions.items():
                if (clear.id != a.ARM_INS_BIC or len(clear.operands) < 2
                        or clear.operands[0].type != a.ARM_OP_REG
                        or clear.operands[0].reg != value_reg
                        or not (load_pc < clear_pc)
                        or not reaches(load_pc + load.size, clear_pc)):
                    continue
                for store_pc, store in instructions.items():
                    if (clear_pc < store_pc and store.id == a.ARM_INS_STRH
                            and len(store.operands) == 2
                            and store.operands[0].type == a.ARM_OP_REG
                            and store.operands[0].reg == value_reg
                            and _memory(store, 1, pointer_reg, 0x0c)
                            and reaches(clear_pc + clear.size, store_pc)):
                        preserved = True
                        for candidate_pc in instructions:
                            if (not load_pc < candidate_pc < clear_pc
                                    and not clear_pc < candidate_pc < store_pc):
                                continue
                            if candidate_pc == clear_pc:
                                continue
                            candidate_ins = instructions[candidate_pc]
                            if candidate_ins.id in (a.ARM_INS_B, a.ARM_INS_BL,
                                                     a.ARM_INS_BX):
                                preserved = False
                                break
                            try:
                                _, writes = candidate_ins.regs_access()
                            except Exception:
                                preserved = False
                                break
                            if value_reg in writes:
                                preserved = False
                                break
                        if not preserved:
                            continue
                        return tuple((address, ins.size)
                                     for address, ins in sorted(instructions.items()))
    return None


def _frame_size(image, entry, instructions):
    """Measure a bounded PUSH/SUB prologue and require a local byte slot."""
    facts = facts_for(image)
    push = facts.decode(CodeAddress(entry, "thumb"))
    word = struct.unpack_from("<H", image, entry)[0]
    if push is None or push.id != a.ARM_INS_PUSH or word & 0xfe00 != 0xb400:
        return None
    size = 4 * (word & 0x1ff).bit_count()
    pc = entry + push.size
    for _ in range(4):
        ins = instructions.get(pc)
        if ins is None:
            break
        word = struct.unpack_from("<H", image, pc)[0]
        if word & 0xff80 == 0xb080:
            size += (word & 0x7f) * 4
            pc += ins.size
            continue
        try:
            _, writes = ins.regs_access()
        except Exception:
            return None
        if a.ARM_REG_SP in writes:
            return None
        break
    return size if size > 0 else None


def _consumer_reads_byte(image, entry, config):
    facts = facts_for(image)
    end = min(len(image), config.flash_size, entry + 0x20)
    pc, spans = entry, []
    while pc < end:
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if ins is None:
            return None
        spans.append((pc, ins.size))
        if (ins.id == a.ARM_INS_LDRB and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and _memory(ins, 1, a.ARM_REG_R0, 0)):
            return tuple(spans)
        if ins.id in (a.ARM_INS_B, a.ARM_INS_BX, a.ARM_INS_POP):
            return None
        pc += ins.size
    return None


def _stack_event_calls(image, instructions, edges, low, frame_size, config):
    """Track the 0x73 byte from an immediate through a stack argument to BL."""
    facts = facts_for(image)
    # Values are either ('imm', value) or ('sp', byte_offset); each slot keeps
    # the producing store site so a later write cannot silently replace it.
    pending = [(low, (), ())]
    seen = set()
    calls = set()
    all_calls = set()
    while pending and len(seen) < 4096:
        pc, regs_tuple, slots_tuple = pending.pop()
        ins = instructions.get(pc)
        if ins is None:
            continue
        regs, slots = dict(regs_tuple), dict(slots_tuple)
        key = (pc, tuple(sorted(regs.items())), tuple(sorted(slots.items())))
        if key in seen:
            continue
        seen.add(key)
        if ins.id == a.ARM_INS_BL:
            pointer = regs.get(a.ARM_REG_R0)
            if pointer is not None and pointer[0] == "sp":
                offset = pointer[1]
                target = facts.thumb_call_target(pc)
                if type(offset) is int and 0 <= offset < frame_size:
                    all_calls.add((pc, target, offset))
                    stored = slots.get(offset)
                    if stored is not None and stored[0] == 0x73:
                        call_spans = _consumer_reads_byte(image, target, config)
                        if call_spans:
                            calls.add((pc, target, offset, stored[1], call_spans))
        mem = ins.operands[1] if len(ins.operands) > 1 else None
        if (ins.id == a.ARM_INS_STRB and len(ins.operands) == 2
                and mem.type == a.ARM_OP_MEM):
            source = ins.operands[0].reg if ins.operands[0].type == a.ARM_OP_REG else None
            base_value = (("sp", 0) if mem.mem.base == a.ARM_REG_SP
                          else regs.get(mem.mem.base))
            if base_value is not None and base_value[0] == "sp":
                offset = base_value[1] + mem.mem.disp
                if 0 <= offset < frame_size:
                    value = regs.get(source)
                    slots[offset] = (value[1], pc) if value is not None and value[0] == "imm" else (None, pc)
        assigned = None
        if (ins.id == a.ARM_INS_MOV and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_IMM):
            assigned = (ins.operands[0].reg, ("imm", ins.operands[1].imm))
        elif (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
              and ins.operands[0].type == a.ARM_OP_REG
              and ins.operands[1].type == a.ARM_OP_REG
              and ins.operands[1].reg == a.ARM_REG_SP
              and ins.operands[2].type == a.ARM_OP_IMM):
            assigned = (ins.operands[0].reg, ("sp", ins.operands[2].imm))
        elif (ins.id == a.ARM_INS_MOV and len(ins.operands) == 2
              and ins.operands[0].type == a.ARM_OP_REG
              and ins.operands[1].type == a.ARM_OP_REG):
            source = (("sp", 0) if ins.operands[1].reg == a.ARM_REG_SP
                      else regs.get(ins.operands[1].reg))
            if source is not None:
                assigned = (ins.operands[0].reg, source)
        try:
            _, writes = ins.regs_access()
        except Exception:
            continue
        if (a.ARM_REG_SP in writes
                and any(value[0] == 0x73 for value in slots.values())):
            continue
        for reg in writes:
            if reg != a.ARM_REG_SP:
                regs.pop(reg, None)
        if assigned is not None:
            regs[assigned[0]] = assigned[1]
        if ins.id == a.ARM_INS_BL:
            for reg in (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3):
                regs.pop(reg, None)
        pending.extend((successor, tuple(sorted(regs.items())), tuple(sorted(slots.items())))
                       for successor in edges.get(pc, ()))
    if pending or len(calls) != 1:
        return None
    call_pc, consumer, offset, store_pc, consumer_spans = next(iter(calls))
    if (call_pc, consumer, offset) not in all_calls:
        return None
    return {"call_site": call_pc, "consumer": consumer, "stack_offset": offset,
            "event_store": store_pc, "consumer_sites": consumer_spans}


def stack_contact_property(image, config, matrix):
    """Prove the released bit-4 path and its nonnumeric stack event."""
    if (not isinstance(image, (bytes, bytearray)) or type(matrix) is not dict
            or matrix.get("grammar") not in _GRAMMARS or matrix.get("columns") != 4
            or matrix.get("rows") not in (6, 7) or matrix.get("no_key") != 15
            or matrix.get("single_key_column_sense") != [14, 13, 11, 7]
            or matrix.get("sense_address") not in (0x0300066c, 0x0300072c)
            or type(matrix.get("descriptor")) is not int
            or type(matrix.get("presence_site")) is not int
            or type(matrix.get("sense_site")) is not int
            or type(matrix.get("event_codes")) is not list
            or len(matrix["event_codes"]) != matrix["rows"] * 4
            or any(type(event) is not int or not 0 <= event <= 0xff
                   for event in matrix["event_codes"])
            or 0x73 in matrix["event_codes"]
            or getattr(config, "load_address", None) != 0
            or type(getattr(config, "flash_size", None)) is not int
            or type(getattr(config, "ram_base", None)) is not int
            or type(getattr(config, "ram_size", None)) is not int
            or config.ram_base < 0 or config.ram_size <= 0 or config.flash_size <= 0):
        return None, None
    image = bytes(image)
    nor_end = min(len(image), config.flash_size)
    descriptor = matrix["descriptor"]
    ram_end = config.ram_base + config.ram_size
    matrix_ram = matrix.get("ram_dependencies", ())
    if (type(matrix_ram) not in (list, tuple)
            or any(type(span) not in (list, tuple) or len(span) != 2
                   or type(span[0]) is not int or type(span[1]) is not int
                   or span[1] <= 0 or not config.ram_base <= span[0]
                   or span[0] + span[1] > ram_end for span in matrix_ram)):
        return None, None
    matrix_dependencies = matrix.get("dependencies", ())
    if (type(matrix_dependencies) not in (list, tuple)
            or any(type(span) not in (list, tuple) or len(span) != 2
                   or type(span[0]) is not int or type(span[1]) is not int
                   or span[0] < 0 or span[1] <= 0
                   or span[0] + span[1] > nor_end
                   for span in matrix_dependencies)):
        return None, None
    if (type(descriptor) is not int or descriptor & 3
            or not config.ram_base <= descriptor <= ram_end - 0x38):
        return None, None
    facts = facts_for(image)
    matches = []
    for read_pc, branch_pc, high, low in _status_sites(image, matrix, config):
        entry = _thumb_function_start(image, read_pc)
        if entry is None or entry >= nor_end:
            continue
        cfg = bounded_thumb_cfg(image, entry, min(nor_end, entry + 0x800))
        if cfg is None:
            continue
        instructions, edges = cfg
        if branch_pc not in instructions:
            continue
        frame_size = _frame_size(image, entry, instructions)
        if frame_size is None or frame_size > config.ram_size:
            continue
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
        if not (reaches(high, matrix["presence_site"])
                and reaches(high, matrix["sense_site"])):
            continue
        high_reachable = set()
        pending = [high]
        while pending and len(high_reachable) < 4096:
            pc = pending.pop()
            if pc in high_reachable:
                continue
            high_reachable.add(pc)
            pending.extend(edges.get(pc, ()))
        clear_calls = []
        for pc in sorted(high_reachable):
            ins = instructions.get(pc)
            if ins is None or ins.id != a.ARM_INS_BL:
                continue
            target = facts.thumb_call_target(pc)
            spans = (_clear_helper(image, target, descriptor, config)
                     if target is not None else None)
            if (spans is not None and pc < matrix["presence_site"]
                    and reaches(pc + ins.size, matrix["presence_site"])):
                clear_calls.append((pc, target, spans))
        if len(clear_calls) != 1:
            continue
        event = _stack_event_calls(image, instructions, edges, low, frame_size, config)
        if event is None:
            continue
        copy = reset_linked_input_copy(image, ((descriptor, 0x38),),
            ram_base=config.ram_base, ram_size=config.ram_size,
            flash_size=config.flash_size)
        if copy is None:
            continue
        descriptor_source = copy.source_address(descriptor, 0x38)
        if descriptor_source is None or descriptor_source + 0x38 > nor_end:
            continue
        p8, p34 = (struct.unpack_from("<I", image, descriptor_source + offset)[0]
                   for offset in (8, 0x34))
        if p8 != matrix["sense_address"] or p34 != matrix["sense_address"]:
            continue
        dependencies = set(copy.evidence)
        dependencies.add((descriptor_source, 0x38))
        for pc, ins in instructions.items():
            dependencies.add((pc, ins.size))
            literal = facts.literal(CodeAddress(pc, "thumb"))
            if literal is not None:
                dependencies.add((literal.pool, 4))
        clear_pc, clear_target, clear_spans = clear_calls[0]
        dependencies.update(clear_spans)
        dependencies.add((clear_pc, 4))
        dependencies.add((clear_target, 2))
        dependencies.update(event["consumer_sites"])
        dependencies.add((event["call_site"], 4))
        for pc, _size in event["consumer_sites"]:
            literal = facts.literal(CodeAddress(pc, "thumb"))
            if literal is not None:
                dependencies.add((literal.pool, 4))
        dependencies.update(tuple(span) for span in matrix_dependencies)
        if any(type(start) is not int or type(size) is not int or start < 0
               or size <= 0 or start + size > nor_end for start, size in dependencies):
            continue
        ram_dependencies = sorted({(descriptor, 0x38),
                                   *((int(start), int(size))
                                     for start, size in matrix_ram)})
        matches.append({
            "grammar": "stack-matrix-contact-v1", "descriptor": descriptor,
            "descriptor_source": descriptor_source,
            "sense_address": matrix["sense_address"], "status_site": read_pc,
            "status_branch": branch_pc, "inactive_level": 0x10,
            "active_low_mask": 0x10, "event": 0x73,
            "event_store": event["event_store"], "stack_offset": event["stack_offset"],
            "stack_frame_size": frame_size, "consumer_site": event["call_site"],
            "consumer": event["consumer"], "clear_site": clear_pc,
            "clear_helper": clear_target, "presence_site": matrix["presence_site"],
            "sense_site": matrix["sense_site"], "copy_source": copy.source,
            "copy_target": copy.target, "copy_size": copy.size,
            "dependencies": sorted(dependencies),
            "ram_dependencies": ram_dependencies,
        })
    if len(matches) != 1:
        return None, None
    profile = matches[0]
    return f"experimental-matrix-contact={profile['status_site']:x}:10", profile
