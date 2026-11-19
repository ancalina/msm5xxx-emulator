"""Static evidence for the MSM5000 two-channel tone generator."""
from __future__ import annotations
from bisect import bisect_left
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.values import CodeAddress
from capstone import arm as a
import struct
import re
from msm5xxx_emulator.detection.devices.audio.rules import find_audio_transport

# Both independently disassembled converters use this exact table. Matching all
# four literal-pool constants plus the writer's ten ordered byte stores is the
# signature; MMIO addresses alone are not sufficient evidence.
_DIVIDERS = (307500, 2152500, 4305000, 8610000)
_WRITES = (0x030006C8, 0x030006DC, 0x030006BC, 0x030006B8, 0x030006C4, 0x030006C0, 0x030006D0, 0x030006CC, 0x030006D8, 0x030006D4,)

def _values_in_window(refs, ref_pcs, pc):
    """Return literal values with reference PCs in ``[pc, pc + 0x80)``."""
    first = bisect_left(ref_pcs, pc)
    end = bisect_left(ref_pcs, pc + 0x80)
    return {value for _, value in refs[first:end]}

def _literal_values(image: bytes) -> set[int]:
    return {value for value in _DIVIDERS if image.find(struct.pack("<I", value)) >= 0}

def _tone_converter_entries(image: bytes) -> set[int]:
    """Return call targets whose code loads all four divider constants."""
    needed = set(_DIVIDERS)
    if _literal_values(image) != needed:
        return set()
    n = len(image)
    refs: list[tuple[int, int]] = []
    for match in re.finditer(rb'(?=([\x00-\xff][\x48-\x4f]))', image):
        pc = match.start()
        if pc & 1:
            continue
        insn = image[pc] | image[pc + 1] << 8
        literal = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
        if literal + 4 <= n:
            value = struct.unpack_from("<I", image, literal)[0]
            if value in needed:
                refs.append((pc, value))
    entries: set[int] = set()
    ordered_refs = sorted(refs)
    ref_pcs = [pc for pc, _ in ordered_refs]
    for pc, _ in refs:
        used = _values_in_window(ordered_refs, ref_pcs, pc)
        if used == needed:
            # Use the nearest Thumb function prologue preceding these literal
            # loads. The recovered converter starts 0x36 bytes before its
            # first table reference in both independently analyzed builds.
            for target in range(pc & ~1, max(-1, pc - 0x50), -2):
                if target + 2 <= n:
                    push = struct.unpack_from("<H", image, target)[0]
                    if push & 0xFE00 == 0xB400 and push & 0x100:
                        entries.add(target)
                        break
    return entries

def _thumb_tone_writer(image: bytes) -> list[int]:
    """Find a contiguous Thumb STRB sequence targeting the ten tone bytes.

    The firmware's writer loads the three MMIO base literals, then emits the
    ten stores in this order. Resolve only PC-relative LDR literals and
    immediate STRB instructions, and require all ten stores within 0x80 bytes.
    """
    n = len(image)
    converter_entries = _tone_converter_entries(image)
    if not converter_entries:
        return []
    literals: set[int] = set()
    for value in (0x030006B0, 0x030006C0, 0x030006D0):
        needle = struct.pack("<I", value)
        offset = image.find(needle)
        while offset >= 0:
            literals.add(offset)
            offset = image.find(needle, offset + 1)
    if not literals:
        return []
    # Find only PC-relative LDRs that refer to one of the three tone bases.
    # The regular expression scans in optimized C; the short Thumb decoder
    # then runs only around those references.
    windows: set[tuple[int, int]] = set()
    for match in re.finditer(rb'(?=([\x00-\xff][\x48-\x4f]))', image):
        pc = match.start()
        if pc & 1:
            continue
        insn = image[pc] | image[pc + 1] << 8
        literal = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
        if literal in literals:
            windows.add((max(0, pc - 0x100) & ~1, min(n - 1, pc + 0x100) & ~1))
    hits: list[int] = []
    for start, stop in sorted(windows):
        regs: dict[int, int] = {}
        stores: list[tuple[int, int]] = []
        for pc in range(start, stop, 2):
            insn = image[pc] | image[pc + 1] << 8
            if insn & 0xF800 == 0x4800:
                reg = insn >> 8 & 7
                literal = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
                if literal + 4 <= n:
                    regs[reg] = struct.unpack_from("<I", image, literal)[0]
                else:
                    regs.pop(reg, None)
            elif insn & 0xF800 == 0x7000:
                base = insn >> 3 & 7
                if base in regs:
                    addr = regs[base] + (insn >> 6 & 0x1F)
                    if addr in _WRITES:
                        stores.append((pc, addr))
                        stores = stores[-len(_WRITES):]
                        if (len(stores) == len(_WRITES) and tuple(a for _, a in stores) == _WRITES and pc - stores[0][0] < 0x80):
                            writer_store_start = stores[0][0]
                            calls_converter = False
                            for call in range(max(0, writer_store_start - 0x200), writer_store_start - 2, 2):
                                target = facts_for(image).thumb_call_target(call)
                                if target in converter_entries:
                                    calls_converter = True
                                    break
                            if calls_converter:
                                hits.append(writer_store_start)
                    else:
                        stores.clear()
            else:
                op = insn & 0xF800
                if op in (0x2000, 0x2800, 0x3000, 0x3800, 0x4000, 0x5000, 0x6000, 0x6800, 0x8000, 0x8800, 0x9000, 0x9800, 0xA000, 0xA800, 0xC000, 0xC800):
                    regs.pop(insn >> 8 & 7, None)
    return sorted(set(hits))

def _ordered_writer_cfg(facts, function) -> tuple[int, ...] | None:
    """Require every closed path through a writer to emit the ordered bytes."""
    if not function.complete or function.unresolved or function.scope_escapes or not function.instructions:
        return None
    nodes = set(function.instructions)
    successors: dict[CodeAddress, set[CodeAddress]] = {node: set() for node in nodes}
    for source, target in function.control_edges:
        if source not in nodes or target not in nodes:
            return None
        successors[source].add(target)

    # A CFG cycle could avoid the stores forever while a separate path returns.
    indegree = {node: 0 for node in nodes}
    for targets in successors.values():
        for target in targets:
            indegree[target] += 1
    pending = [node for node, degree in indegree.items() if degree == 0]
    topological = []
    while pending:
        node = pending.pop()
        topological.append(node)
        for target in successors[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    if len(topological) != len(nodes) or function.entry not in nodes:
        return None

    writes = {access.instruction: access for access in function.accesses
              if access.operation == "write" and access.address in _WRITES}
    progress: dict[CodeAddress, set[int]] = {function.entry: {0}}
    for node in topological:
        if node not in progress:
            return None
        access = writes.get(node)
        next_states = set()
        for index in progress[node]:
            if access is not None:
                if access.width != 1 or access.predicate not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                    return None
                expected = _WRITES if index < len(_WRITES) else _WRITES + (0x030006C8, 0x030006DC)
                if index < len(expected):
                    if access.address != expected[index]:
                        return None
                    index += 1
                else:
                    # This profile owns one complete write sequence. A later
                    # write to an owned tone byte could change the final
                    # hardware state, so it cannot be hidden by truncating the
                    # projected site list below.
                    return None
            next_states.add(index)
        targets = successors[node]
        if not targets:
            # Some setters return early when the requested tone is unchanged
            # or disabled. Any path that starts the register sequence must
            # still complete it.
            if any(index not in (0, len(_WRITES), len(_WRITES) + 2) for index in next_states):
                return None
            continue
        for target in targets:
            progress.setdefault(target, set()).update(next_states)
    ordered_stores = tuple(access.instruction.address for access in function.accesses
                            if access.instruction in writes)
    ordered_addresses = tuple(access.address for access in function.accesses
                              if access.instruction in writes)
    # MemoryAccesses are unique by instruction and sorted by address in facts.
    if len(ordered_stores) not in (len(_WRITES), len(_WRITES) + 2):
        return None
    if len(ordered_stores) == len(_WRITES) + 2:
        if ordered_addresses[-2:] != (0x030006C8, 0x030006DC):
            return None
        if not _control_enable_store_links(facts, function, writes):
            return None
    return ordered_stores

def _control_enable_store_links(facts, function, writes) -> bool:
    """Tie each trailing control byte to a staged selector with bit 6 set."""
    decoded = [(pc, facts.decode(pc)) for pc in function.instructions]
    decoded = [(pc, ins) for pc, ins in decoded if ins is not None]

    def reg_name(operand):
        return operand.reg if operand.type == a.ARM_OP_REG else None

    stack_aliases = []
    aliases = {}
    for _, ins in decoded:
        if ins.id == a.ARM_INS_ADD and len(ins.operands) == 3 and ins.operands[0].type == a.ARM_OP_REG and ins.operands[1].type == a.ARM_OP_REG and ins.operands[1].reg == a.ARM_REG_SP and ins.operands[2].type == a.ARM_OP_IMM:
            aliases[ins.operands[0].reg] = ins.operands[2].imm
            stack_aliases.append(dict(aliases))
        else:
            stack_aliases.append(dict(aliases))
            try:
                for register in ins.regs_access()[1]:
                    aliases.pop(register, None)
            except Exception:
                aliases.clear()

    def stack_slot(operand, index):
        if operand.type != a.ARM_OP_MEM or operand.mem.index:
            return None
        if operand.mem.base == a.ARM_REG_SP:
            return operand.mem.disp
        if operand.mem.base in stack_aliases[index]:
            return stack_aliases[index][operand.mem.base] + operand.mem.disp
        return None

    def reg_written(ins, register):
        try:
            written = ins.regs_access()[1]
        except Exception:
            return True
        return register in written

    def enabled_register(register, before):
        for i in range(before - 1, -1, -1):
            ins = decoded[i][1]
            if ins.id == a.ARM_INS_ORR and len(ins.operands) >= 2 and reg_name(ins.operands[0]) == register:
                other = reg_name(ins.operands[-1])
                if other is None:
                    return False
                inputs = (register, other)
                constant_inputs = []
                selector_inputs = []
                for candidate in inputs:
                    found_constant = False
                    for prior in range(i - 1, -1, -1):
                        prev = decoded[prior][1]
                        if (prev.id == a.ARM_INS_MOV and len(prev.operands) == 2
                                and reg_name(prev.operands[0]) == candidate
                                and prev.operands[1].type == a.ARM_OP_IMM
                                and prev.operands[1].imm == 0x40):
                            found_constant = True
                            break
                        if reg_written(prev, candidate):
                            break
                    if found_constant:
                        constant_inputs.append(candidate)
                    found_selector = False
                    for prior in range(i - 1, -1, -1):
                        prev = decoded[prior][1]
                        if prev.id == a.ARM_INS_LDRB and len(prev.operands) == 2 and reg_name(prev.operands[0]) == candidate:
                            found_selector = True
                            break
                        if reg_written(prev, candidate):
                            break
                    if found_selector:
                        selector_inputs.append(candidate)
                return any(constant != selector for constant in constant_inputs for selector in selector_inputs)
            if reg_written(ins, register):
                return False
        return False

    for address in (0x030006C8, 0x030006DC):
        stores = [access for access in writes.values() if access.address == address]
        if len(stores) != 2:
            return False
        final_pc = max((access.instruction for access in stores), key=lambda pc: pc.address)
        final = next((pc for pc, ins in decoded if pc == final_pc), None)
        if final is None:
            return False
        final_ins = facts.decode(final)
        if final_ins.id != a.ARM_INS_STRB or len(final_ins.operands) != 2:
            return False
        payload_reg = reg_name(final_ins.operands[0])
        if payload_reg is None:
            return False
        final_index = next(i for i, (pc, _) in enumerate(decoded) if pc == final)
        direct = enabled_register(payload_reg, final_index)
        for i in range(final_index - 1, -1, -1):
            ins = decoded[i][1]
            if ((ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                 and ins.operands[2].type == a.ARM_OP_IMM and ins.operands[2].imm == 0)
                    or (ins.id == a.ARM_INS_MOV and len(ins.operands) == 2)) and reg_name(ins.operands[0]) == payload_reg and reg_name(ins.operands[1]) is not None:
                direct = enabled_register(reg_name(ins.operands[1]), i)
                break
            if reg_written(ins, payload_reg):
                break
        if direct:
            continue
        load_match = None
        for i in range(final_index - 1, -1, -1):
            pc, ins = decoded[i]
            if ins.id not in (a.ARM_INS_LDR, a.ARM_INS_LDRB) or len(ins.operands) != 2:
                continue
            slot = stack_slot(ins.operands[1], i)
            if reg_name(ins.operands[0]) == payload_reg and slot is not None:
                load_match = (i, slot, ins.id)
                break
            if reg_written(ins, payload_reg):
                break
        if load_match is None:
            return False
        load_index, slot, load_id = load_match
        if load_id not in (a.ARM_INS_LDR, a.ARM_INS_LDRB):
            return False
        staged_reg = None
        for i in range(load_index - 1, -1, -1):
            pc, ins = decoded[i]
            if ins.id not in (a.ARM_INS_STR, a.ARM_INS_STRB) or len(ins.operands) != 2:
                continue
            if stack_slot(ins.operands[1], i) == slot:
                staged_reg = reg_name(ins.operands[0])
                break
        if staged_reg is None:
            return False
        stage_index = next((i for i in range(load_index - 1, -1, -1)
                            if decoded[i][1].id in (a.ARM_INS_STR, a.ARM_INS_STRB)
                            and len(decoded[i][1].operands) == 2
                            and stack_slot(decoded[i][1].operands[1], i) == slot), None)
        if stage_index is None:
            return False
        enabled = enabled_register(staged_reg, stage_index)
        if not enabled:
            return False
    return True

def _source_dependencies(facts, *functions) -> list[dict[str, int]] | None:
    """Return compact, bounded source ranges used by a linked proof."""
    spans: list[tuple[int, int]] = []
    for function in functions:
        for pc in function.instructions:
            instruction = facts.decode(pc)
            if instruction is None:
                return None
            spans.append((pc.address, pc.address + instruction.size))
        spans.extend((literal.pool, literal.pool + 4) for literal in function.literals)
    if not spans or any(start < 0 or end > len(facts.image) or end <= start for start, end in spans):
        return None
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [{"offset": start, "size": end - start} for start, end in merged]

def _linked_tone_writers(image: bytes) -> list[dict[str, object]]:
    """Close a tone writer through its CFG and a called divider converter."""
    facts = facts_for(image)
    base_values = (0x030006B0, 0x030006C0, 0x030006D0)
    base_pools = {offset for value in base_values
                  for offset in _all_offsets(image, struct.pack("<I", value))}
    if not base_pools:
        return []
    candidates: set[int] = set()
    for match in re.finditer(rb'(?=([\x00-\xff][\x48-\x4f]))', image):
        pc = match.start()
        if pc & 1:
            continue
        insn = image[pc] | image[pc + 1] << 8
        pool = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
        if pool not in base_pools:
            continue
        for start in range(max(0, pc - 0x100) & ~1, pc + 1, 2):
            halfword = image[start] | image[start + 1] << 8
            if halfword & 0xFE00 == 0xB400 and halfword & 0x100:
                candidates.add(start)
    linked = []
    for entry in sorted(candidates):
        writer = facts.function(CodeAddress(entry, "thumb"), budget=1024)
        if not any(literal.value in base_values for literal in writer.literals):
            continue
        stores = _ordered_writer_cfg(facts, writer)
        if stores is None:
            continue
        first_store = CodeAddress(stores[0], "thumb")
        for callsite, target in writer.calls:
            if target.address < 0 or target.address >= len(image):
                continue
            converter = facts.function(target, budget=1024)
            if (not converter.complete or converter.unresolved or converter.scope_escapes
                    or not set(_DIVIDERS).issubset({literal.value for literal in converter.literals})
                    or not writer.dominates(callsite, first_store)):
                continue
            dependencies = _source_dependencies(facts, writer, converter)
            if dependencies is None:
                continue
            linked.append({
                "writer_offset": entry,
                "converter_offset": target.address,
                "writer_store_offsets": list(stores),
                "source_dependencies": dependencies,
            })
            break
    return linked

def _all_offsets(image: bytes, needle: bytes) -> list[int]:
    found = []
    offset = image.find(needle)
    while offset >= 0:
        found.append(offset)
        offset = image.find(needle, offset + 1)
    return found

def find_tone_generator(image: bytes) -> dict[str, object]:
    """Return evidence for the known two-channel MSM5000 tone block."""
    values = _literal_values(image)
    missing = [value for value in _DIVIDERS if value not in values]
    writers = _thumb_tone_writer(image)
    result: dict[str, object] = { "family": "msm5000-two-channel-tone", "grammar": "divider-table-plus-ten-strb-v1", "static_status": "rejected",
        "reject_reason": None, "converter_constants": list(_DIVIDERS), "writer_offsets": writers, }
    if missing:
        result["reject_reason"] = "converter-constant-set-incomplete"
    elif len(writers) != 1:
        linked = _linked_tone_writers(image) if not writers else []
        if len(linked) == 1:
            result.update(linked[0])
            result["grammar"] = ("linked-divider-cfg-plus-control-strb-v1"
                                 if len(linked[0]["writer_store_offsets"]) == len(_WRITES) + 2
                                 else "linked-divider-cfg-plus-ten-strb-v1")
            result["static_status"] = "accepted"
            result["reject_reason"] = None
        elif linked:
            result["reject_reason"] = "tone-writer-ambiguous"
        else:
            result["reject_reason"] = "tone-writer-ambiguous" if writers else "tone-writer-none"
    else:
        result["static_status"] = "accepted"
        result["writer_offset"] = writers[0]
    return result

def tone_admission(image: bytes, audio_transport: dict[str, object] | None = None,) -> dict[str, object]:
    """Fail closed when an admitted Yamaha or opaque transport owns audio."""
    tone = find_tone_generator(image)
    transport = (audio_transport if audio_transport is not None else find_audio_transport(image))
    if (tone["static_status"] == "accepted" and transport.get("static_status") == "accepted"):
        return { **tone, "static_status": "rejected", "reject_reason": "admitted-audio-transport-present", "audio_transport": transport, }
    return tone
