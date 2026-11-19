"""Linked two-port keypad source grammar for encoded numeric key events."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.arm import _thumb_function_start
from .startup_copy import reset_linked_input_copy
from .encoded_callback import _producer_callback
from .encoded_paths import _active_low_contact, _constant, _is

GRAMMAR = "encoded-two-port-keypad-v1"
_KEYS = b"123456789*0#"


def _half(image: bytes, pc: int) -> int:
    return struct.unpack_from("<H", image, pc)[0]


def _literal(facts, pc, register, value=None):
    item = facts.literal(CodeAddress(pc, "thumb"))
    return item if item is not None and item.register == register and (
        value is None or item.value == value) else None


def _pointer_origin(facts, function, read_site: int, register: int,
                   descriptor: int, field_offset: int, source_site: int):
    """Match a live MMIO pointer to a particular descriptor-field load."""
    value = facts.register_value(function, CodeAddress(read_site, "thumb"), register)
    if (getattr(value, "kind", None) != "load" or value.site is None
            or value.site.address != source_site or len(value.operands) != 1
            or _constant(value.operands[0]) != descriptor + field_offset):
        return False
    return True


def _event_triplets(image: bytes, table: int):
    """Decode exactly nineteen unique code/event records, including all keys."""
    if type(table) is not int or table < 0 or table + 19 * 3 > len(image):
        return None
    records = [tuple(image[table + i * 3:table + i * 3 + 3])
               for i in range(19)]
    identities, codes, tokens = ([record[0] for record in records],
                                 [record[1] for record in records],
                                 [record[2] for record in records])
    key_to_code = {chr(token): code for code, token in zip(codes, tokens)
                   if token in _KEYS}
    if (len(set(identities)) != 19 or len(set(codes)) != 19
            or len(set(tokens)) != 19 or set(key_to_code) != set(chr(k) for k in _KEYS)):
        return None
    return {"records": records, "codes": codes, "tokens": tokens,
            "key_to_code": key_to_code}


def _clean_register_path(facts, function, start: int, target: int, register: int):
    """Require a CFG path from the matched token to its consumer without clobber."""
    edges = {}
    for source, destination in function.control_edges:
        if source.isa == destination.isa == "thumb":
            edges.setdefault(source.address, set()).add(destination.address)
    pending, seen = [start], set()
    while pending:
        pc = pending.pop()
        if pc == target:
            return True
        if pc in seen:
            continue
        seen.add(pc)
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if ins is None:
            continue
        try:
            _, writes = ins.regs_access()
        except Exception:
            continue
        if register in writes:
            continue
        pending.extend(edges.get(pc, ()))
    return False


def _helper_profiles(image: bytes, facts):
    """Find the small arithmetic helper from its complete instruction grammar."""
    # The second register port is folded into an eight-bit code; the constant
    # high mask is intentionally retained because it is part of the source.
    grammar = (0x6A41, 0x8809, 0x231E, 0x4019, 0x6B40, 0x0109,
               0x227F, 0x8800, 0x0252, 0x4311, 0x06C0, 0x0EC0,
               0x4308, 0x4770)
    found = []
    suffix = struct.pack("<" + "H" * len(grammar), *grammar)
    pos = image.find(suffix)
    while pos >= 0:
        pc = pos - 2
        if (pc < 0 or pc & 1 or _half(image, pc) & 0xFF00 != 0x4800
                or pc + 2 * (len(grammar) + 1) > len(image)):
            pos = image.find(suffix, pos + 1)
            continue
        literal = _literal(facts, pc, a.ARM_REG_R0)
        if literal is None or not 0x01000000 <= literal.value < 0x02000000 or literal.value & 3:
            pos = image.find(suffix, pos + 1)
            continue
        found.append({"helper": pc, "descriptor": literal.value,
                      "helper_literal": literal.pool,
                      "helper_code": (pc, 30)})
        pos = image.find(suffix, pos + 1)
    return found


def _helper_read_provenance(facts, helper: int, descriptor: int):
    """Close both helper MMIO pointers to the descriptor's +0x24/+0x34 fields."""
    function = facts.function(CodeAddress(helper, "thumb"), budget=128)
    row = facts.decode(CodeAddress(helper + 4, "thumb"))
    sense = facts.decode(CodeAddress(helper + 16, "thumb"))
    if (row is None or sense is None or len(row.operands) < 2
            or len(sense.operands) < 2
            or row.operands[1].type != a.ARM_OP_MEM
            or sense.operands[1].type != a.ARM_OP_MEM):
        return False
    row_base, sense_base = row.operands[1].mem.base, sense.operands[1].mem.base
    return (_pointer_origin(facts, function, helper + 4, row_base,
                            descriptor, 0x24, helper + 2)
            and _pointer_origin(facts, function, helper + 16, sense_base,
                                descriptor, 0x34, helper + 10))


def _decode_helper_caller(image, facts, callsite, descriptor):
    """Require caller-side backing/presence gates, idle test and key lookup."""
    entry = _thumb_function_start(image, callsite)
    if entry is None:
        return None
    region = facts.function(CodeAddress(entry, "thumb"), budget=2048)
    if not region.complete or region.truncated or region.unresolved:
        return None
    instructions = sorted((site.address for site in region.instructions
                           if site.isa == "thumb"))
    if not instructions or callsite not in instructions:
        return None
    start, end = max(0, instructions[0]), min(len(image), instructions[-1] + 4)
    if end - start > 0x1000:
        return None

    # Resolve the p24 descriptor load and the p24 bit-0 gate. This gate is
    # source state and must remain live at run time; it is not an output mask.
    presence = []
    gate_branches = []
    backing_gates = []
    row_reads = []
    sense_reads = []
    idle_reads = []
    for pc in instructions:
        if pc + 20 > end:
            continue
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if not _is(ins, a.ARM_INS_LDR) or len(ins.operands) != 2:
            continue
        dst, mem = ins.operands
        if (dst.type != a.ARM_OP_REG or mem.type != a.ARM_OP_MEM
                or mem.mem.disp != 0x24 or mem.mem.index):
            continue
        # A register read immediately follows the descriptor field load, and
        # the 31-bit shift pair extracts bit zero before a conditional branch.
        loadpc = pc + ins.size
        ld = facts.decode(CodeAddress(loadpc, "thumb"))
        if not _is(ld, a.ARM_INS_LDRH):
            continue
        shift1 = facts.decode(CodeAddress(loadpc + ld.size, "thumb"))
        shift2 = facts.decode(CodeAddress(loadpc + ld.size + 2, "thumb"))
        branch = facts.decode(CodeAddress(loadpc + ld.size + 6, "thumb"))
        interposed = facts.decode(CodeAddress(loadpc + ld.size + 4, "thumb"))
        if not (_is(shift1, a.ARM_INS_LSL) and shift1.operands[-1].imm == 31
                and _is(shift2, a.ARM_INS_LSR) and shift2.operands[-1].imm == 31
                and _is(interposed, a.ARM_INS_LDR)
                and _is(branch, a.ARM_INS_B) and branch.cc == a.ARM_CC_NE):
            continue
        # Resolve the base at this use; a stale earlier literal is not enough.
        base_reg = mem.mem.base
        if _constant(facts.register_value(region, CodeAddress(pc, "thumb"), base_reg)) == descriptor:
            presence.append(loadpc)
            row_reads.append(pc)
            backing_gates.append(loadpc)
            gate_branches.append(branch)

    # The low nibble of p34 is the idle sentinel. Retain the unmodified read.
    for pc in instructions:
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if not _is(ins, a.ARM_INS_LDR) or len(ins.operands) != 2:
            continue
        dst, mem = ins.operands
        if (dst.type != a.ARM_OP_REG or mem.type != a.ARM_OP_MEM
                or mem.mem.disp != 0x34 or mem.mem.index):
            continue
        base_reg = mem.mem.base
        read = facts.decode(CodeAddress(pc + ins.size, "thumb"))
        if not _is(read, a.ARM_INS_LDRH):
            continue
        shifts = [facts.decode(CodeAddress(pc + ins.size + 2 * n, "thumb"))
                  for n in range(1, 5)]
        if (len(shifts) == 4 and _is(shifts[0], a.ARM_INS_LSL)
                and shifts[0].operands[-1].imm == 28
                and _is(shifts[1], a.ARM_INS_LSR)
                and shifts[1].operands[-1].imm == 28
                and _is(shifts[2], a.ARM_INS_CMP)
                and shifts[2].operands[-1].imm == 15
                and _is(shifts[3], a.ARM_INS_B)
                and shifts[3].cc == a.ARM_CC_EQ):
            # Link p34 and p24 through their live descriptor-base values.
            if (_constant(facts.register_value(region, CodeAddress(pc, "thumb"), base_reg)) == descriptor
                    and any(facts.decode(CodeAddress(p, "thumb")).operands[1].mem.base == base_reg
                            for p in row_reads)):
                sense_reads.append(pc)
                idle_reads.append(pc + ins.size)

    if (len(set(presence)) != 1 or len(set(backing_gates)) != 1
            or len(set(sense_reads)) != 1 or len(set(row_reads)) != 1
            or len(set(idle_reads)) != 1 or len(set(gate_branches)) != 1
            or gate_branches[0].operands[0].imm != sense_reads[0]):
        return None

    # The poller repeats the helper's pack arithmetic after its live gates.
    # These ordered operations prove which two halfword instructions feed the
    # table lookup: p24 supplies bits 1..4, p34 supplies bits 0..4.
    pack_words = (0x8811, 0x231E, 0x4019, 0x0109, 0x227F, 0x8800,
                  0x0252, 0x4311, 0x06C0, 0x0EC0, 0x4308, 0x0601, 0x0E09)
    pack_sites = [pc for pc in instructions
                  if pc + 2 * len(pack_words) <= end
                  and tuple(_half(image, pc + 2 * i) for i in range(len(pack_words))) == pack_words]
    if len(pack_sites) != 1:
        return None
    row_code_read, sense_code_read = pack_sites[0], pack_sites[0] + 10
    row_decode = facts.decode(CodeAddress(row_code_read, "thumb"))
    sense_decode = facts.decode(CodeAddress(sense_code_read, "thumb"))
    idle_decode = facts.decode(CodeAddress(idle_reads[0], "thumb"))
    backing_decode = facts.decode(CodeAddress(backing_gates[0], "thumb"))
    if (row_decode is None or sense_decode is None or idle_decode is None
            or backing_decode is None
            or not _pointer_origin(facts, region, row_code_read,
                row_decode.operands[1].mem.base, descriptor, 0x24, row_reads[0])
            or not _pointer_origin(facts, region, sense_code_read,
                sense_decode.operands[1].mem.base, descriptor, 0x34, sense_reads[0])
            or not _pointer_origin(facts, region, idle_reads[0],
                idle_decode.operands[1].mem.base, descriptor, 0x34, sense_reads[0])
            or not _pointer_origin(facts, region, backing_gates[0],
                backing_decode.operands[1].mem.base, descriptor, 0x24, row_reads[0])):
        return None

    # Locate a direct three-byte-record search: code at byte +1, output at
    # byte +2, bounded to 19 entries. The literal denotes table+0x3c.
    lookups = []
    for pc in instructions:
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if not _is(ins, a.ARM_INS_LDR) or not ins.operands:
            continue
        literal = facts.literal(CodeAddress(pc, "thumb"))
        if literal is None or literal.register != a.ARM_REG_R2:
            continue
        table_end = literal.value - 0x3C
        if table_end < 0 or table_end + 19 * 3 > len(image):
            continue
        seq = tuple(_half(image, pc + n * 2) for n in range(1, 19))
        # Three-byte stride, compare byte +1, return byte +2, and 19 bound.
        if (seq[:7] != (0x2000, 0x3A3C, 0x0043, 0x181B,
                        0x189B, 0x785B, 0x428B)
                or seq[8:12] != (0x0043, 0x1818, 0x1880, 0x7887)
                or seq[16] != 0x2813):
            continue
        mismatch = facts.decode(CodeAddress(pc + 16, "thumb"))
        matched_skip = facts.decode(CodeAddress(pc + 26, "thumb"))
        bound_branch = facts.decode(CodeAddress(pc + 36, "thumb"))
        event_load = facts.decode(CodeAddress(pc + 24, "thumb"))
        if (not _is(mismatch, a.ARM_INS_B) or mismatch.cc != a.ARM_CC_NE
                or not mismatch.operands or mismatch.operands[0].imm != pc + 28
                or not _is(matched_skip, a.ARM_INS_B)
                or matched_skip.operands[0].imm != pc + 38
                or not _is(bound_branch, a.ARM_INS_B)
                or bound_branch.cc != a.ARM_CC_LT
                or bound_branch.operands[0].imm != pc + 6
                or not _is(event_load, a.ARM_INS_LDRB)
                or event_load.operands[0].reg != a.ARM_REG_R7
                or event_load.operands[1].mem.base != a.ARM_REG_R0
                or event_load.operands[1].mem.disp != 2):
            continue
        # Three-byte stepping and the 19-entry bound must be in the same
        # function. The triplets themselves are checked below.
        later = image[pc + 16:min(end, pc + 100)]
        if len(later) < 38:
            continue
        table = _event_triplets(image, table_end)
        if table is None:
            continue
        records, codes, tokens = table["records"], table["codes"], table["tokens"]
        # The full table is admitted only when the direct event producer call
        # receives the found event in r0 from the decoded r7 state.
        producer_calls = []
        for site in instructions:
            target = facts.thumb_call_target(site)
            if target is None:
                continue
            if site >= pc + 16 and site < end:
                producer_calls.append((site, target))
        linked = []
        for site, target in producer_calls:
            if site < 4:
                continue
            move = facts.decode(CodeAddress(site - 2, "thumb"))
            if (_is(move, a.ARM_INS_ADD) and len(move.operands) == 3
                    and move.operands[0].reg == a.ARM_REG_R0
                    and move.operands[1].reg == a.ARM_REG_R7
                    and move.operands[2].type == a.ARM_OP_IMM
                    and move.operands[2].imm == 0):
                linked.append((site, target))
        if len(linked) != 1:
            continue
        if not _clean_register_path(facts, region, matched_skip.operands[0].imm,
                                    linked[0][0] - 2, a.ARM_REG_R7):
            continue
        producer_evidence = _producer_callback(image, facts, linked[0][1])
        if producer_evidence is None:
            continue
        contact = _active_low_contact(facts, region, gate_branches[0],
            row_code_read, {ord(key) for key in table["key_to_code"]})
        if contact is None:
            continue
        lookups.append({"table": table_end, "table_pointer": literal.pool,
                        "records": records, "codes": codes, "tokens": tokens,
                        "key_to_code": table["key_to_code"],
                        "event_load_site": pc + 24, "event_register": 7,
                        "aux_contact": contact,
                        "producer": linked[0][1],
                        "producer_evidence": producer_evidence})

    if len(lookups) != 1:
        return None
    lookup = lookups[0]
    dependencies = {(lookup["table"], 57), (lookup["table_pointer"], 4),
                    (presence[0] - 2, 14), (sense_reads[0], 12),
                    (row_code_read, 26),
                    (callsite, 4)}
    dependencies.update(lookup["aux_contact"]["dependencies"])
    dependencies.update(lookup["producer_evidence"]["dependencies"])
    for site in instructions:
        if start <= site < end:
            ins = facts.decode(CodeAddress(site, "thumb"))
            if ins is None:
                return None
            dependencies.add((site, ins.size))
            literal = facts.literal(CodeAddress(site, "thumb"))
            if literal is not None:
                dependencies.add((literal.pool, 4))
    return {"presence_site": idle_reads[0], "backing_gate_site": backing_gates[0],
            "row_read_site": row_code_read, "sense_read_site": sense_code_read,
            "caller_idle_site": idle_reads[0],
            "backing_read_site": backing_gates[0],
            "event_table": lookup["table"],
            "event_table_pointer": lookup["table_pointer"],
            "event_records": lookup["records"], "event_codes": lookup["codes"],
            "event_tokens": lookup["tokens"],
            "key_to_code": lookup["key_to_code"],
            "event_load_site": lookup["event_load_site"],
            "event_register": lookup["event_register"],
            "aux_read_site": backing_gates[0],
            "aux_event_site": lookup["aux_contact"]["event_site"],
            "aux_event": lookup["aux_contact"]["event"],
            "aux_dispatch_entry": lookup["aux_contact"]["dispatch_entry"],
            "aux_dispatch_site": lookup["aux_contact"]["dispatch_site"],
            "aux_dispatch_stub": lookup["aux_contact"]["dispatch_stub"],
            "producer": lookup["producer"],
            "callback_stub": lookup["producer_evidence"]["stub"],
            "producer_state_addresses": lookup["producer_evidence"]["state_addresses"],
            "producer_state_ranges": lookup["producer_evidence"]["state_ranges"],
            "dependencies": sorted(dependencies)}


def _descriptor_sources(image: bytes, flash_size: int):
    """Locate unique copied descriptor bytes whose fields feed both ports."""
    result = []
    marker = struct.pack("<I", 0x03000728)
    end = min(len(image), flash_size)
    pos = image.find(marker, 0, end)
    while pos >= 0:
        descriptor_source = pos - 0x24
        if (descriptor_source >= 0 and descriptor_source % 4 == 0
                and descriptor_source + 0x38 <= end
                and struct.unpack_from("<I", image, descriptor_source + 0x34)[0] == 0x0300072C):
            result.append(descriptor_source)
        pos = image.find(marker, pos + 1, end)
    return result


def find_encoded_port_profiles(image: bytes, *, flash_size: int | None = None,
                               ram_base: int | None = None,
                               ram_size: int | None = None):
    """Return structurally closed two-port keypad profiles, without identity selectors."""
    if not isinstance(image, (bytes, bytearray)) or len(image) < 0x1000:
        return []
    image = bytes(image)
    flash_size = len(image) if flash_size is None else flash_size
    if type(flash_size) is not int or flash_size <= 0:
        return []
    facts = facts_for(image)
    calls = facts.call_candidates("thumb")
    call_index = {}
    for site, target in calls:
        call_index.setdefault(target, []).append(site)
    profiles = []
    for helper in _helper_profiles(image, facts):
        caller_sites = call_index.get(helper["helper"], ())
        for callsite in caller_sites:
            caller = _decode_helper_caller(image, facts, callsite,
                                           helper["descriptor"])
            if (caller is None or not _helper_read_provenance(
                    facts, helper["helper"], helper["descriptor"])):
                continue
            read_sites = (helper["helper"] + 4, helper["helper"] + 16,
                          caller["presence_site"], caller["row_read_site"],
                          caller["sense_read_site"], caller["backing_gate_site"])
            if len(set(read_sites)) != len(read_sites):
                continue
            descriptor_sources = _descriptor_sources(image, flash_size)
            if not descriptor_sources:
                continue
            dependencies = set(caller["dependencies"])
            dependencies.update((source, 0x38) for source in descriptor_sources)
            dependencies.update((helper["helper_code"], (helper["helper_literal"], 4)))
            profiles.append({"grammar": GRAMMAR,
                "descriptor": helper["descriptor"],
                "descriptor_sources": descriptor_sources,
                "row_port": 0x03000728, "sense_port": 0x0300072C,
                "row_mask": 0x0E, "sense_mask": 0x1F,
                "idle_nibble": 0x0F, "pack": "((p24&0x1e)<<4)|(p34&0x1f)",
                "helper": helper["helper"], "helper_call": callsite,
                "presence_site": caller["presence_site"],
                "backing_gate_site": caller["backing_gate_site"],
                "presence_expected": 1,
                "presence_mask": 0x01,
                "row_read_site": helper["helper"] + 4,
                "sense_read_site": helper["helper"] + 16,
                "packed_row_read_site": caller["row_read_site"],
                "packed_sense_read_site": caller["sense_read_site"],
                "event_table": caller["event_table"],
                "event_records": caller["event_records"],
                "event_codes": caller["event_codes"],
                "event_tokens": caller["event_tokens"],
                "key_to_code": caller["key_to_code"],
                "event_load_site": caller["event_load_site"],
                "event_register": caller["event_register"],
                "aux_read_site": caller["aux_read_site"],
                "aux_active_level": 0,
                "aux_idle_level": 1,
                "aux_event_site": caller["aux_event_site"],
                "aux_event": caller["aux_event"],
                "aux_dispatch_entry": caller["aux_dispatch_entry"],
                "aux_dispatch_site": caller["aux_dispatch_site"],
                "aux_dispatch_stub": caller["aux_dispatch_stub"],
                "producer": caller["producer"],
                "callback_stub": caller["callback_stub"],
                "producer_state_addresses": caller["producer_state_addresses"],
                "producer_state_ranges": caller["producer_state_ranges"],
                "dependencies": sorted(dependencies)})
    if profiles or type(ram_base) is not int or type(ram_size) is not int:
        return profiles
    # Keep existing helper-backed profiles preferred. The inline form is a
    # separate grammar with a different, five-site native contract.
    from .encoded_poller import find_inline_encoded_port_profiles
    return find_inline_encoded_port_profiles(
        image, flash_size=flash_size, ram_base=ram_base, ram_size=ram_size)


def encoded_ports_property(image, config, *, status_descriptor_claimed=False):
    """Admit raw encoded ports only when the entire descriptor is reset-copied."""
    if status_descriptor_claimed or getattr(config, "load_address", None) != 0:
        return None, None
    rb, rs = getattr(config, "ram_base", None), getattr(config, "ram_size", None)
    flash = getattr(config, "flash_size", None)
    profiles = find_encoded_port_profiles(image, flash_size=flash,
                                          ram_base=rb, ram_size=rs)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    state_ranges = profile.get("producer_state_ranges", ())
    if (type(rb) is not int or type(rs) is not int or type(flash) is not int
            or not rb <= profile["descriptor"] <= rb + rs - 0x38
            or len(state_ranges) != 2
            or any(type(at) is not int or type(size) is not int or size <= 0
                   or not rb <= at <= rb + rs - size
                   for at, size in state_ranges)
            or any(type(at) is not int or type(size) is not int or size <= 0
                   or not 0 <= at <= min(flash, len(image)) - size
                   for at, size in profile["dependencies"])):
        return None, None
    copy = reset_linked_input_copy(image, ((profile["descriptor"], 0x38),),
        ram_base=rb, ram_size=rs, flash_size=flash)
    mapped_source = (copy.source_address(profile["descriptor"], 0x38)
                     if copy is not None else None)
    if copy is None or mapped_source not in profile["descriptor_sources"]:
        return None, None
    profile["descriptor_source"] = mapped_source
    profile["dependencies"] = sorted(set(profile["dependencies"]) |
                                      set(copy.evidence))
    if profile.get("inline"):
        fields = (profile["descriptor"], profile["row_read_site"],
                  profile["sense_read_site"], profile["idle_site"],
                  profile["aux_read_site"])
    else:
        fields = (profile["descriptor"], profile["row_read_site"],
                  profile["sense_read_site"], profile["presence_site"],
                  profile["packed_row_read_site"],
                  profile["packed_sense_read_site"],
                  profile["aux_read_site"])
    property_value = "matrix-encoded-ports=" + ":".join(
        f"{value:x}" for value in fields)
    return property_value, profile
