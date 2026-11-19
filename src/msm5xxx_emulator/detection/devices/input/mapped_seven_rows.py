"""Source-linked seven-row halfword keypad scans with two nibble decoders."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .mapped_seven_rows_flow import (
    _callee_preserves_register,
    _proven_clear_calls,
    _event_handoff,
    _path_exists,
    _row_loop,
    _scan_control_flow,
)
from .row_execution import _Bits, _region_values, _row_outputs, _word
from .startup_copy import reset_linked_input_copy


GRAMMAR = "mapped-halfword-seven-row-v1"
_SENSES = (14, 13, 11, 7)
_GPIO_PORTS = (0x03000720, 0x03000724)


def _sample_sites(image):
    """Find low-nibble halfword samples by their decoded register flow."""
    candidates = set()
    for register in range(8):
        signature = struct.pack("<HHHH", 0x8800 | register << 3 | register,
            0x0700 | register << 3 | register,
            0x0f00 | register << 3 | register,
            0x280f | register << 8)
        offset = image.find(signature)
        while offset >= 0:
            if offset % 2 == 0:
                candidates.add(offset)
            offset = image.find(signature, offset + 2)
    facts = facts_for(image)
    found = []
    for pc in sorted(candidates):
        load = facts.decode(CodeAddress(pc))
        if load is not None and load.id == a.ARM_INS_LDRH:
            found.append(pc)
    return found


def _descriptor_for_sample(image, sample, config):
    facts = facts_for(image)
    entry = _thumb_function_start(image, sample)
    values = _region_values(image, entry, sample)
    if values is None:
        return ()
    candidates = []
    for register, bits in values.items():
        descriptor = bits.value()
        if (descriptor is None or descriptor & 3
                or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38):
            continue
        # The pointer loaded at +0x34 is the sampled halfword source.
        linked = False
        for pc in range(max(entry, sample - 8), sample, 2):
            ins = facts.decode(CodeAddress(pc))
            if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                    or ins.operands[0].type != a.ARM_OP_REG
                    or ins.operands[1].type != a.ARM_OP_MEM
                    or ins.operands[1].mem.base != register
                    or ins.operands[1].mem.disp != 0x34
                    or values.get(register, _Bits()).value() != descriptor):
                continue
            if any((load := facts.decode(CodeAddress(later))) is not None
                   and load.id == a.ARM_INS_LDRH and len(load.operands) == 2
                   and load.operands[1].type == a.ARM_OP_MEM
                   and load.operands[1].mem.base == ins.operands[0].reg
                   for later in (pc + 2, pc + 4)):
                linked = True
                break
        if not linked:
            continue
        copy = reset_linked_input_copy(image, ((descriptor, 0x38),),
            ram_base=config.ram_base, ram_size=config.ram_size,
            flash_size=config.flash_size)
        if copy is None:
            continue
        source = copy.source_address(descriptor, 0x38)
        if source is None or source + 0x38 > len(image):
            continue
        words = {offset: int.from_bytes(image[source + offset:source + offset + 4], "little")
                 for offset in (0, 0x0c, 0x10, 0x1c, 0x34)}
        if words[0x34] != 0x0300072c:
            continue
        if words[0] == 0x03000720:
            port, shadow_offset = words[0], 0x0c
        elif words[0x10] == 0x03000724:
            port, shadow_offset = words[0x10], 0x1c
        else:
            continue
        candidates.append((descriptor, register, copy, source, port, shadow_offset))
    unique = {(item[0], item[2].source, item[2].target, item[2].size): item
              for item in candidates}
    return tuple(unique.values())


def _dispatch_entries(image, sample):
    """Close computed-PC row switches from their instruction operands."""
    facts = facts_for(image)
    found = []
    for pc in range(max(0, sample - 0x400), sample, 2):
        add = facts.decode(CodeAddress(pc))
        if (add is None or add.id != a.ARM_INS_ADD or len(add.operands) not in (2, 3)
                or add.operands[0].type != a.ARM_OP_REG
                or add.operands[0].reg != a.ARM_REG_PC):
            continue
        index_register = add.operands[1].reg if len(add.operands) == 2 else add.operands[2].reg
        if add.operands[1].type != a.ARM_OP_REG or (len(add.operands) == 3
                and add.operands[2].type != a.ARM_OP_REG):
            continue
        entry = pc - 6
        adr, load, shift = (facts.decode(CodeAddress(entry + offset)) for offset in (0, 2, 4))
        if (adr is None or adr.id != a.ARM_INS_ADR
                or load is None or load.id != a.ARM_INS_LDRB
                or len(load.operands) != 2 or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.base != adr.operands[0].reg
                or load.operands[0].reg != index_register
                or shift is None or shift.id != a.ARM_INS_LSL
                or shift.operands[0].reg != index_register
                or shift.operands[1].reg != index_register
                or shift.operands[2].type != a.ARM_OP_IMM
                or shift.operands[2].imm != 1):
            continue
        # The computed arm table contains seven distinct byte offsets.
        base = ((entry + 4) & ~3) + adr.operands[1].imm
        table = base + load.operands[1].mem.disp
        offsets = image[table:table + 7] if 0 <= table <= len(image) - 7 else b""
        arms = [pc + 4 + value * 2 for value in offsets]
        if (len(offsets) != 7 or len(set(arms)) != 7
                or any(not pc + 2 <= arm < sample for arm in arms)):
            continue
        found.append((entry, load.operands[1].mem.index, table, tuple(arms)))
    return found


def _sample_pointer_register(image, sample):
    facts = facts_for(image)
    read = facts.decode(CodeAddress(sample))
    if read is None or read.id != a.ARM_INS_LDRH or len(read.operands) != 2:
        return None
    pointer = read.operands[1].mem.base
    for pc in range(sample - 8, sample, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is not None and ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == pointer
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.disp == 0x34):
            return ins.operands[1].mem.base
    return None


def _rowmap_entries(image, sample, copy):
    """Find reset-owned halfword row maps read by an indexed load."""
    facts = facts_for(image)
    target_lo, target_hi = copy.target, copy.target + copy.size
    found = []
    for pc in range(max(0, sample - 0x100), sample, 2):
        load = facts.decode(CodeAddress(pc))
        if (load is None or load.id != a.ARM_INS_LDRH or len(load.operands) != 2
                or load.operands[1].type != a.ARM_OP_MEM
                or not load.operands[1].mem.index):
            continue
        base_reg = load.operands[1].mem.base
        for literal_pc in range(max(0, pc - 12), pc, 2):
            literal = facts.literal(CodeAddress(literal_pc))
            if (literal is None or literal.register != base_reg
                    or not target_lo <= literal.value <= target_hi - 14
                    or literal.value & 1):
                continue
            source = copy.source_address(literal.value, 14)
            if source is None or source & 1 or source + 14 > len(image):
                continue
            table = tuple(int.from_bytes(image[source + i * 2:source + i * 2 + 2], "little")
                          for i in range(7))
            if len(set(table)) != 7:
                continue
            for candidate in range(max(0, pc - 0x40), pc, 2):
                ins = facts.decode(CodeAddress(candidate))
                if ins is not None and ins.id == a.ARM_INS_BL:
                    found.append((candidate, literal.value, source, 14))
    return found


def _wire_layout(outputs):
    if len(outputs) != 7 or not outputs:
        return None
    ports = sorted(set().union(*(out.keys() for out in outputs)))
    if len(ports) != 1 or ports[0] not in _GPIO_PORTS:
        return None
    port = ports[0]
    zeros = ones = 0
    for output in outputs:
        if port not in output:
            return None
        zeros |= output[port].zero
        ones |= output[port].one
    mask = zeros & ones & 0xffff
    wires = [1 << bit for bit in range(16) if mask & 1 << bit]
    if len(wires) != 7:
        return None
    order = []
    for output in outputs:
        value = output[port]
        if (value.zero | value.one) & mask != mask:
            return None
        selected = [index for index, wire in enumerate(wires) if value.zero & wire]
        if len(selected) != 1:
            return None
        order.append(selected[0])
    if sorted(order) != list(range(7)):
        return None
    return [port], [mask], order


def _indexed_event_loads(image, sample):
    facts = facts_for(image)
    found = []
    for pc in range(sample + 2, min(sample + 0x180, len(image) - 2), 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is not None and ins.id == a.ARM_INS_LDRB and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.index):
            found.append((pc, ins.operands[0].reg))
    return found


def find_mapped_seven_row_scanners(image, config):
    if getattr(config, "load_address", None) != 0:
        return []
    facts = facts_for(image)
    samples = _sample_sites(image)
    found = []
    for presence in samples:
        for descriptor, descriptor_reg, copy, descriptor_rom, port, shadow_offset in _descriptor_for_sample(
                image, presence, config):
            later = [site for site in samples if presence + 0x40 <= site < presence + 0x500]
            for sample in later:
                # Reconfirm this sample reads the same linked D+0x34 halfword.
                sample_pointer = _sample_pointer_register(image, sample)
                if sample_pointer is None:
                    continue
                entries = [(entry, reg, None) for entry, reg, _, _ in _dispatch_entries(image, sample)]
                # A copied halfword row map is another source-proven selector form.
                for entry, row_target, row_source, row_size in _rowmap_entries(image, sample, copy):
                    entries.append((entry, None, (row_target, row_source, row_size)))
                accepted = []
                for entry, dispatch_reg, rowmap in entries:
                    row_arms = next((arms for candidate, _, _, arms in
                                     _dispatch_entries(image, sample) if candidate == entry), ())
                    row_regs = (dispatch_reg,) if dispatch_reg is not None else tuple(
                        a.ARM_REG_R0 + i for i in range(4, 8))
                    for row_register in row_regs:
                        outputs, dependencies, ram_dependencies = [], set(copy.evidence), set()
                        copied_row = None if rowmap is None else (None, rowmap[1], rowmap[0], rowmap[2])
                        for row in range(7):
                            initial = {row_register: _Bits.constant(row)}
                            result = _row_outputs(image, entry, sample, initial, descriptor,
                                descriptor_rom, copied_row=copied_row,
                                ram_dependencies=ram_dependencies,
                                capture_registers={sample_pointer})
                            if result is None:
                                break
                            if result[2][sample_pointer].value() != descriptor:
                                break
                            outputs.append(result[0])
                            dependencies.update(result[1])
                        if len(outputs) != 7:
                            continue
                        wiring = _wire_layout(outputs)
                        loop = _row_loop(image, entry, sample, row_register)
                        if wiring is None or loop is None:
                            continue
                        row_ports, row_masks, row_order = wiring
                        # Require the actual low-nibble samples to be tied to D.
                        event_profiles = []
                        sample_read = facts.decode(CodeAddress(sample))
                        if (sample_read is None or sample_read.id != a.ARM_INS_LDRH
                                or not sample_read.operands
                                or sample_read.operands[0].type != a.ARM_OP_REG):
                            continue
                        for event_load, event_register in _indexed_event_loads(image, sample):
                            table_addresses, lookup_dependencies = [], set()
                            valid = True
                            for raw in _SENSES:
                                for row in range(7):
                                    initial = {sample_read.operands[0].reg: _Bits.constant(raw),
                                               row_register: _Bits.constant(row)}
                                    result = _row_outputs(image, sample + 2, event_load,
                                        initial, descriptor, descriptor_rom,
                                        capture_load=True, capture_end=min(len(image) - 2,
                                            event_load + 0x100),
                                        copied_row=copied_row,
                                        ram_dependencies=ram_dependencies)
                                    if result is None:
                                        valid = False
                                        break
                                    table_addresses.append(result[0])
                                    lookup_dependencies.update(result[1])
                                if not valid:
                                    break
                            if not valid or len(table_addresses) != 28:
                                continue
                            table = table_addresses[0]
                            if table_addresses != list(range(table, table + 28)):
                                continue
                            if not 0 <= table <= min(len(image), config.flash_size) - 28:
                                continue
                            events = list(image[table:table + 28])
                            if any(events.count(key) != 1 for key in b"123456789*0#"):
                                continue
                            call_proofs = _proven_clear_calls(image, event_load, 0x100,
                                descriptor, descriptor_rom, event_register, events,
                                row_ports[0], row_masks[0])
                            call_evidence = set()
                            sink = _event_handoff(image, event_load, event_register, 0x100,
                                proven_calls=call_proofs, proof_sites=call_evidence)
                            if sink is None:
                                continue
                            function_start = _thumb_function_start(image, presence)
                            if (_thumb_function_start(image, sample) != function_start
                                    or _thumb_function_start(image, event_load) != function_start
                                    or _thumb_function_start(image, sink) != function_start):
                                continue
                            limit = min(len(image) - 2, max(sink + 4, sample + 0x180))
                            cfg = _scan_control_flow(image, function_start, limit,
                                entry, row_arms)
                            if cfg is None:
                                continue
                            edges, reachable, dominators = cfg
                            if any(site not in reachable for site in
                                   (presence, entry, sample, event_load, sink, *loop)):
                                continue
                            if (presence not in dominators[entry]
                                    or loop[0] not in dominators[entry]
                                    or loop[0] not in dominators[sample]
                                    or sample not in dominators[loop[1]]
                                    or sample not in dominators[loop[2]]
                                    or event_load not in reachable):
                                continue
                            if not _path_exists(edges, loop[5], entry):
                                continue
                            if not _path_exists(edges, sample + 2, event_load):
                                continue
                            event_profiles.append((event_load, event_register, sink,
                                table, events, lookup_dependencies, call_evidence))
                        if len(event_profiles) != 1:
                            continue
                        event_load, event_register, sink, table, events, lookup_dependencies, call_evidence = event_profiles[0]
                        dependencies.update(lookup_dependencies)
                        dependencies.update(call_evidence)
                        dependencies.update(((table, 28), (descriptor_rom, 0x38),
                                             (loop[0], sample + 2 - loop[0]),
                                             (function_start, sink + 2 - function_start)))
                        if rowmap is not None:
                            dependencies.add((rowmap[1], rowmap[2]))
                            ram_dependencies.update((rowmap[0] + i * 2, 2) for i in range(7))
                        accepted.append({"grammar": GRAMMAR, "rows": 7, "columns": 4,
                            "descriptor": descriptor, "descriptor_source": descriptor_rom,
                            "presence_site": presence, "sense_site": sample,
                            "event_load_site": event_load, "event_register": event_register - a.ARM_REG_R0,
                            "event_sink_site": sink, "event_table": table, "event_codes": events,
                            "row_ports": row_ports, "row_masks": row_masks,
                            "sense_address": 0x0300072c,
                            "row_wire_order": row_order, "no_key": 15,
                            "single_key_column_sense": list(_SENSES),
                            "hardware_only": True,
                            "firmware_filtering": "retained",
                            "row_loop": entry, "row_counter_register": row_register - a.ARM_REG_R0,
                            "row_shadow_offset": shadow_offset, "rowmap": rowmap,
                            "dependencies": sorted(dependencies),
                            "ram_dependencies": sorted(ram_dependencies)})
                if len(accepted) == 1:
                    found.extend(accepted)
    # Multiple source paths may report the same physical scan; keep one only.
    unique = {(item["descriptor"], item["presence_site"], item["sense_site"],
               item["event_load_site"]): item for item in found}
    return list(unique.values())


def mapped_seven_row_property(image, config, *, status_descriptor_claimed=False):
    if status_descriptor_claimed:
        return None, None
    profiles = find_mapped_seven_row_scanners(image, config)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    if any(not 0 <= at <= min(len(image), config.flash_size) - size
           for at, size in profile["dependencies"]):
        return None, None
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address in [*profile["row_ports"], 0x0300072c]:
        return None, None
    ports = list(zip(profile["row_ports"], profile["row_masks"]))
    ports.extend([(0, 0)] * (2 - len(ports)))
    fields = [profile["descriptor"], profile["presence_site"], profile["sense_site"],
              *[value for pair in ports for value in pair]]
    value = "matrix-halfword-wires=" + ":".join(f"{item:x}" for item in fields)
    profile["source_sites"] = [{key: profile[key] for key in
        ("presence_site", "sense_site", "event_load_site", "event_register")}]
    profile["source_sites"][0]["event_sink_site"] = profile["event_sink_site"]
    return value, profile
