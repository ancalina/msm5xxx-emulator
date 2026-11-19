"""Source-linked six-row scanners backed by external GPIO-style latches."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for
from .external_rows_cells import _flat_event_stage, _raw_cell_stage
from .external_rows_flow import (_constant, _event_handlers,
    _global_presence, _handlers_share_row_index, _has_low_five_sample,
    _register_lineage, _loop_records, _written_address,
    _writes_register)

_SENSE_MASK = 0x1f
_OUTPUT_MASK = 0x8850
_SELECTOR_MASK = 0x3


def _u32(image: bytes, address: int, base: int) -> int | None:
    offset = address - base
    if offset < 0 or offset > len(image) - 4:
        return None
    return struct.unpack_from("<I", image, offset)[0]


def _row_wire_order(values: tuple[int, ...]) -> list[int] | None:
    """Map each logical row to its ascending physical output-wire index."""
    if len(values) != 6 or any(type(value) is not int or value < 0 for value in values):
        return None
    selected = []
    for value in values:
        low = value & _OUTPUT_MASK
        high = (value >> 16) & _SELECTOR_MASK
        if value & ~(_OUTPUT_MASK | (_SELECTOR_MASK << 16)):
            return None
        wires = [bit for bit in range(32) if low & (1 << bit)]
        wires.extend(16 + bit for bit in range(2) if high & (1 << bit))
        if len(wires) != 1:
            return None
        selected.append(wires[0])
    if len(set(selected)) != 6:
        return None
    physical_wires = sorted(selected)
    return [physical_wires.index(wire) for wire in selected]


def _event_codes(image: bytes, address: int, base: int) -> list[int] | None:
    offset = address - base
    if offset < 0 or offset > len(image) - 30:
        return None
    codes = list(image[offset:offset + 30])
    # Firmware event bytes are table data. Require a numeric-key alphabet as
    # well as control/letter entries, avoiding incidental zero-filled regions.
    if not set(b"0123456789*#") <= set(codes):
        return None
    return codes


def _descriptor_candidates(image: bytes, base: int) -> set[int]:
    """Find ROM descriptors whose fields are actually referenced by code."""
    facts = facts_for(image, base=base)
    candidates = set()
    # Literal references establish that candidate records participate in code;
    # the MMIO values alone are only a structure lead, never admission.
    needle = struct.pack("<I", 0x09000070)
    offset = 0
    while True:
        offset = image.find(needle, offset)
        if offset < 0:
            break
        if (offset & 3) == 0 and offset >= 0x34:
            descriptor = base + offset - 0x34
            if (_u32(image, descriptor + 0x20, base) == 0x09000000
                    and _u32(image, descriptor + 0x2c, base) == 0x09000004
                    and facts.literal_references(descriptor)):
                candidates.add(descriptor)
        offset += 1
    return candidates


def _same_row_counter(first, second):
    return first == second


def _register_unchanged(function, facts, register, start, end):
    return not any(_writes_register(facts, site, register)
                   for site in function.instructions
                   if start.address < site.address < end.address)


def _row_index_live(function, facts, lineage_use, index_register,
                    expected_root, final_load):
    """Close each index copy to its use and keep the row counter live to load."""
    current, before = index_register, lineage_use.address
    intermediates = []
    for _ in range(6):
        definition = next((site for site in sorted(
            (item for item in function.instructions if item.address < before),
            key=lambda item: item.address, reverse=True)
            if _writes_register(facts, site, current)), None)
        if definition is None:
            return False
        ins = facts.decode(definition)
        if current == expected_root:
            return (function.dominates(definition, final_load)
                    and _register_unchanged(function, facts, current,
                                            definition, final_load)
                    and all(function.dominates(producer, consumer)
                            and _register_unchanged(function, facts, register,
                                                    producer, consumer)
                            for register, producer, consumer in intermediates))
        if (ins is None or not ins.operands
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[0].reg != current):
            return False
        if (ins.id == a.ARM_INS_LSL and len(ins.operands) == 3
                and ins.operands[-1].type == a.ARM_OP_IMM
                and ins.operands[-1].imm == 2
                and ins.operands[1].type == a.ARM_OP_REG):
            source = ins.operands[1].reg
        elif (ins.id in (a.ARM_INS_MOV, a.ARM_INS_ADD)
              and any(op.type == a.ARM_OP_REG for op in ins.operands[1:])
              and all(op.type == a.ARM_OP_REG or
                      op.type == a.ARM_OP_IMM and op.imm == 0
                      for op in ins.operands[1:])):
            sources = [op.reg for op in ins.operands[1:]
                       if op.type == a.ARM_OP_REG]
            if len(sources) != 1:
                return False
            source = sources[0]
        else:
            return False
        intermediates.append((current, definition, CodeAddress(before)))
        current, before = source, definition.address
    return False


def _linked_tables(image, function, facts, pointer, base):
    """Require pointer-derived row and event accesses at their real uses."""
    row_firsts, row_seconds, event_proofs = [], [], []
    sites = sorted(function.instructions, key=lambda site: site.address)
    for site in sites:
        sub = facts.decode(site)
        if (sub is None or sub.id != a.ARM_INS_SUB or len(sub.operands) not in (2, 3)
                or sub.operands[0].type != a.ARM_OP_REG
                or sub.operands[-1].type != a.ARM_OP_IMM):
            continue
        source_register = sub.operands[0].reg
        if _constant(facts.register_value(function, site, source_register)) != pointer:
            continue
        target = pointer - sub.operands[-1].imm
        if target & 1 == 0:
            offset = target - base
            if 0 <= offset <= len(image) - 24:
                rows = tuple(struct.unpack_from("<I", image, offset + 4 * i)[0]
                             for i in range(6))
                order = _row_wire_order(rows)
                for use in sites:
                    if not site.address < use.address <= site.address + 12:
                        continue
                    ins = facts.decode(use)
                    if (ins is None or ins.id != a.ARM_INS_LDRH or len(ins.operands) != 2
                            or ins.operands[1].type != a.ARM_OP_MEM
                            or ins.operands[1].mem.base != source_register
                            or not ins.operands[1].mem.index):
                        continue
                    row_lineage = _register_lineage(
                        function, facts, use, ins.operands[1].mem.index)
                    index_register = ins.operands[1].mem.index
                    if (order is not None and row_lineage is not None
                            and _row_index_live(function, facts, use,
                                index_register, row_lineage[0], use)
                            and function.dominates(site, use)
                            and function.linear_path(site, use) is not None
                            and _register_unchanged(function, facts,
                                                    source_register, site, use)
                            and _register_unchanged(function, facts,
                                                    index_register, site, use)):
                        row_firsts.append((target, rows, order, use,
                                           row_lineage[0]))
                        break
                for add_site in sites:
                    if not site.address < add_site.address <= site.address + 40:
                        continue
                    add = facts.decode(add_site)
                    if (add is None or add.id != a.ARM_INS_ADD
                            or len(add.operands) != 3
                            or add.operands[0].type != a.ARM_OP_REG
                            or source_register not in {
                                operand.reg for operand in add.operands[1:]
                                if operand.type == a.ARM_OP_REG}):
                        continue
                    result_register = add.operands[0].reg
                    row_sources = [operand.reg for operand in add.operands[1:]
                                   if operand.type == a.ARM_OP_REG
                                   and operand.reg != source_register]
                    if len(row_sources) != 1:
                        continue
                    row_lineage = _register_lineage(
                        function, facts, add_site, row_sources[0])
                    if row_lineage is None:
                        continue
                    for load_site in sites:
                        if not add_site.address < load_site.address <= add_site.address + 4:
                            continue
                        load = facts.decode(load_site)
                        if (load is not None and load.id == a.ARM_INS_LDRH
                                and len(load.operands) == 2
                                and load.operands[1].type == a.ARM_OP_MEM
                                and load.operands[1].mem.base == result_register
                                and load.operands[1].mem.disp == 2):
                            row_register = row_sources[0]
                            if (function.dominates(site, add_site)
                                    and function.dominates(add_site, load_site)
                                    and function.linear_path(site, add_site) is not None
                                    and function.linear_path(add_site, load_site) is not None
                                    and _row_index_live(function, facts, add_site,
                                        row_register, row_lineage[0], load_site)
                                    and _register_unchanged(function, facts,
                                        source_register, site, add_site)
                                    and _register_unchanged(function, facts,
                                        row_register, add_site, load_site)
                                    and _register_unchanged(function, facts,
                                        result_register, add_site, load_site)):
                                row_seconds.append((target, rows, order, load_site,
                                                    row_lineage[0]))
                            break
        events = _event_codes(image, target, base)
        if events is not None:
            # The table base must flow from this subtraction through an ADD
            # into a byte-indexed load, rather than merely coexisting nearby.
            for use in sites:
                if not site.address < use.address <= site.address + 16:
                    continue
                add = facts.decode(use)
                if (add is None or add.id != a.ARM_INS_ADD or len(add.operands) != 3
                        or add.operands[0].type != a.ARM_OP_REG
                        or source_register not in {operand.reg for operand in add.operands[1:]
                                                    if operand.type == a.ARM_OP_REG}):
                    continue
                result_register = add.operands[0].reg
                for load_site in sites:
                    if not use.address < load_site.address <= use.address + 6:
                        continue
                    load = facts.decode(load_site)
                    if (load is not None and load.id == a.ARM_INS_LDRB
                            and len(load.operands) == 2
                            and load.operands[1].type == a.ARM_OP_MEM
                            and load.operands[1].mem.base == result_register
                            and load.operands[1].mem.index):
                        index_register = load.operands[1].mem.index
                        if (function.dominates(site, use)
                                and function.dominates(use, load_site)
                                and function.linear_path(site, use) is not None
                                and function.linear_path(use, load_site) is not None
                                and _register_unchanged(function, facts,
                                    source_register, site, use)
                                and _register_unchanged(function, facts,
                                    result_register, use, load_site)
                                and _register_unchanged(function, facts,
                                    index_register, use, load_site)):
                            event_proofs.append((target, events, load_site))
                        break
    row_proofs = set()
    for target, rows, order, first_load, row_reg in row_firsts:
        if not _tainted_port_store(function, facts, first_load, 0x09000000, _OUTPUT_MASK):
            continue
        for other_target, other_rows, _, second_load, other_row_reg in row_seconds:
            if (other_target == target and other_rows == rows
                    and _same_row_counter(other_row_reg, row_reg)
                    and _tainted_port_store(function, facts, second_load,
                                            0x09000004, _SELECTOR_MASK)):
                row_proofs.add((target, rows, tuple(order), first_load.address,
                                second_load.address, row_reg))
    event_proofs = {(target, tuple(events), load.address)
                    for target, events, load in event_proofs}
    if len(row_proofs) != 1 or len(event_proofs) != 1:
        return None
    row_address, rows, order, first_load, second_load, row_reg = next(iter(row_proofs))
    event_address, events, raw_event_load = next(iter(event_proofs))
    return (row_address, rows, list(order), event_address, list(events),
            first_load, second_load, row_reg, raw_event_load)


def _reg_sources(ins):
    sources = {operand.reg for operand in ins.operands[1:]
               if operand.type == a.ARM_OP_REG}
    if (len(ins.operands) == 2 and ins.operands[0].type == a.ARM_OP_REG
            and ins.id in (a.ARM_INS_AND, a.ARM_INS_ORR, a.ARM_INS_LSL,
                           a.ARM_INS_LSR)):
        sources.add(ins.operands[0].reg)
    return sources


def _effective_address(function, facts, site, mem):
    base_value = _constant(facts.register_value(function, site, mem.base))
    if base_value is None:
        return None
    index_value = (_constant(facts.register_value(function, site, mem.index))
                   if mem.index else 0)
    if index_value is None:
        return None
    return (base_value + mem.disp + index_value) & 0xffffffff


def _tainted_port_store(function, facts, seed, port, mask):
    """Tie one row half to a masked, shadow-preserving RMW and port store."""
    port_stores = {access.instruction for access in function.accesses
                   if access.operation == "write" and access.address == port}
    if not port_stores:
        return False
    sites = sorted(function.instructions, key=lambda site: site.address)
    seed_ins = facts.decode(seed)
    if (seed_ins is None or seed_ins.id != a.ARM_INS_LDRH
            or not seed_ins.operands
            or seed_ins.operands[0].type != a.ARM_OP_REG):
        return False
    states = {name: set() for name in (
        "tuple", "tuple_shift", "tuple_masked", "shadow", "shadow_shift",
        "shadow_cleared", "inverse", "combined")}
    shadow_writes = set()
    combine_site = None
    address_to_site = {site.address: site for site in sites}

    def apply(site, ins, *, tuple_seed=False):
        """Use pre-instruction taints, kill writes, then add derived outputs."""
        nonlocal combine_site
        if ins is None:
            return False
        if ins.id in (a.ARM_INS_B, a.ARM_INS_BL, a.ARM_INS_BLX,
                      a.ARM_INS_BX, a.ARM_INS_POP):
            return False
        try:
            _, written = ins.regs_access()
        except Exception:
            return False
        written = set(written)
        if tuple_seed:
            output = seed_ins.operands[0].reg
            for taint in states.values():
                taint.discard(output)
            states["tuple"].add(output)
            return True
        if not ins.operands or ins.operands[0].type != a.ARM_OP_REG:
            for taint in states.values():
                taint.difference_update(written)
            return True

        dest = ins.operands[0].reg
        sources = _reg_sources(ins)
        prior = {name: set(value) for name, value in states.items()}
        new = {name: set() for name in states}
        if (ins.id in (a.ARM_INS_LDR, a.ARM_INS_LDRH)
                and len(ins.operands) == 2
                and ins.operands[1].type == a.ARM_OP_MEM):
            address = _effective_address(function, facts, site, ins.operands[1].mem)
            if address is not None and 0x10000000 <= address < 0x20000000:
                new["shadow"].add(dest)
        if ins.id == a.ARM_INS_MVN and any(
                _constant(facts.register_value(function, site, reg)) == mask
                for reg in sources):
            new["inverse"].add(dest)
        if ins.id == a.ARM_INS_AND and len(ins.operands) >= 2:
            if (sources & prior["tuple"] and any(
                    _constant(facts.register_value(function, site, reg)) == mask
                    for reg in sources - prior["tuple"])):
                new["tuple_masked"].add(dest)
            if (sources & prior["shadow"] and
                    (sources & prior["inverse"] or any(
                        _constant(facts.register_value(function, site, reg))
                        == ((~mask) & 0xffffffff)
                        for reg in sources - prior["shadow"]))):
                new["shadow_cleared"].add(dest)
        if (mask == _SELECTOR_MASK and ins.id == a.ARM_INS_LSL
                and len(ins.operands) == 3
                and ins.operands[-1].type == a.ARM_OP_IMM
                and ins.operands[-1].imm == 30 and sources & prior["tuple"]):
            following = address_to_site.get(site.address + 2)
            next_ins = facts.decode(following) if following is not None else None
            if (next_ins is not None and next_ins.id == a.ARM_INS_LSR
                    and next_ins.operands[0].reg == dest
                    and next_ins.operands[1].reg == dest
                    and next_ins.operands[-1].imm == 30):
                new["tuple_shift"].add(dest)
        if (mask == _SELECTOR_MASK and ins.id == a.ARM_INS_LSR
                and len(ins.operands) == 3
                and ins.operands[-1].type == a.ARM_OP_IMM
                and ins.operands[-1].imm == 30 and sources & prior["tuple_shift"]):
            new["tuple_masked"].add(dest)
        if (mask == _SELECTOR_MASK and ins.id == a.ARM_INS_LSR
                and len(ins.operands) == 3
                and ins.operands[-1].type == a.ARM_OP_IMM
                and ins.operands[-1].imm == 2 and sources & prior["shadow"]):
            following = address_to_site.get(site.address + 2)
            next_ins = facts.decode(following) if following is not None else None
            if (next_ins is not None and next_ins.id == a.ARM_INS_LSL
                    and next_ins.operands[0].reg == dest
                    and next_ins.operands[1].reg == dest
                    and next_ins.operands[-1].imm == 2):
                new["shadow_shift"].add(dest)
        if (mask == _SELECTOR_MASK and ins.id == a.ARM_INS_LSL
                and len(ins.operands) == 3
                and ins.operands[-1].type == a.ARM_OP_IMM
                and ins.operands[-1].imm == 2 and sources & prior["shadow_shift"]):
            new["shadow_cleared"].add(dest)
        if ins.id == a.ARM_INS_ORR and len(ins.operands) >= 2:
            if sources & prior["tuple_masked"] and sources & prior["shadow_cleared"]:
                new["combined"].add(dest)

        is_store = ins.id in (a.ARM_INS_STR, a.ARM_INS_STRH)
        data_reg = (ins.operands[0].reg if is_store and ins.operands
                    and ins.operands[0].type == a.ARM_OP_REG else None)
        if (is_store and data_reg in prior["combined"]
                and len(ins.operands) == 2
                and ins.operands[1].type == a.ARM_OP_MEM):
            address = _effective_address(function, facts, site, ins.operands[1].mem)
            if address is not None and 0x10000000 <= address < 0x20000000:
                shadow_writes.add((site, data_reg))

        # Register writes invalidate old facts even when the instruction is an
        # unrelated MOV/load. Re-add only facts proven from its pre-state.
        for taint in states.values():
            taint.difference_update(written)
        for name, registers in new.items():
            states[name].update(registers)
        if new["combined"]:
            combine_site = site
        return True

    for site in sites:
        if seed.address - 16 <= site.address < seed.address:
            if not apply(site, facts.decode(site)):
                # A call or control-flow edge ends the bounded shadow prelude.
                states["shadow"].clear()
                states["shadow_shift"].clear()
                states["shadow_cleared"].clear()
                states["inverse"].clear()
        if site == seed:
            apply(site, seed_ins, tuple_seed=True)
            break
    for site in sites:
        if site.address <= seed.address:
            continue
        ins = facts.decode(site)
        if not apply(site, ins):
            break
        if site in port_stores:
            if (ins is None or ins.id not in (a.ARM_INS_STR, a.ARM_INS_STRH)
                    or not ins.operands or ins.operands[0].type != a.ARM_OP_REG):
                continue
            data_reg = ins.operands[0].reg
            if (data_reg not in states["combined"] or combine_site is None
                    or not any(store.address < site.address and register == data_reg
                               and store.address > combine_site.address
                               for store, register in shadow_writes)):
                continue
            return True
    return False



def find_external_row_scanners(image: bytes, load_address: int = 0) -> list[dict[str, object]]:
    """Recover externally-latched 6x5 matrix hardware from linked code/data.

    Descriptor, row-vector, and event-table addresses are discovered through
    literal references and scanner dataflow. This intentionally does not use
    target identity or fixed scanner addresses.
    """
    if load_address != 0:
        return []
    facts = facts_for(image, base=load_address)
    found = {}
    for descriptor in _descriptor_candidates(image, load_address):
        entries = {_thumb_function_start(
            image, literal.instruction.address - load_address)
            for literal in facts.literal_references(descriptor)}
        for entry in sorted(entries):
            if entry < 0 or entry & 1:
                continue
            function = facts.function(
                CodeAddress(load_address + entry), budget=4096,
                symbolic_registers={a.ARM_REG_R0 + index:
                                    SymbolicValue.arg(index)
                                    for index in range(13)})
            if (not function.complete or function.unresolved or function.truncated
                    or not _has_low_five_sample(function, facts)):
                continue
            for literal_item in function.literals:
                pointer = literal_item.value
                if not 0 < pointer < len(image):
                    continue
                linked = _linked_tables(image, function, facts, pointer,
                                        load_address)
                if linked is None:
                    continue
                (row_address, rows, order, event_address, events,
                 row_low_load, row_high_load, row_register,
                 raw_event_load) = linked
                loops = _loop_records(function, facts)
                raw_stage = _raw_cell_stage(
                    image, function, facts, CodeAddress(row_low_load),
                    CodeAddress(raw_event_load), pointer, event_address, loops)
                if raw_stage is None:
                    continue
                handlers = _event_handlers(function, facts)
                if (handlers is None or raw_stage["row_register"] != row_register
                        or not _handlers_share_row_index(
                            handlers, facts, row_register)):
                    continue
                flat_stage = _flat_event_stage(function, facts, pointer,
                    event_address, handlers, row_register, loops)
                if flat_stage is None:
                    continue
                if not _global_presence(function, facts):
                    continue
                read_sites = sorted({
                    access.instruction.address for access in function.accesses
                    if access.operation == "read" and access.address == 0x09000070
                } | {
                    access.instruction.address
                    for access in function.symbolic_accesses
                    if access.operation == "read"
                    and access.address.kind == "const"
                    and access.address.value == 0x09000070
                })
                if len(read_sites) < 2:
                    continue
                if not _written_address(function, 0x09000000, "write"):
                    continue
                if not _written_address(function, 0x09000004, "write"):
                    continue
                profile = {
                    "grammar": "external-latches-six-row-low5-v1",
                    "function": load_address + entry,
                    "descriptor": descriptor,
                    "rows": 6, "columns": 5,
                    "sense_address": 0x09000070,
                    "sense_mask": _SENSE_MASK, "no_key": _SENSE_MASK,
                    "presence_site": read_sites[0],
                    "sense_site": read_sites[-1],
                    "read_sites": read_sites,
                    "active_output_level": 1,
                    "row_ports": [0x09000000, 0x09000004],
                    "row_masks": [_OUTPUT_MASK, _SELECTOR_MASK],
                    "row_values": [list((value & _OUTPUT_MASK,
                                          (value >> 16) & _SELECTOR_MASK))
                                   for value in rows],
                    "row_wire_order": order,
                    "event_table": event_address,
                    "event_codes": events,
                    "event_table_formula": "event_codes[column * 6 + row]",
                    "single_key_column_sense": [0x1e, 0x1d, 0x1b, 0x17, 0x0f],
                    "source_sites": [
                        {"event_load_site": handler["event_load"],
                         "event_register": handler["event_register"],
                         "auxiliary_register": handler["auxiliary_register"],
                         "auxiliary_value": handler["auxiliary_value"]}
                        for handler in handlers],
                    "raw_event_table_load": raw_event_load,
                    "event_table_load_sites": flat_stage["sink_event_loads"],
                    "dependencies": [(descriptor - load_address, 0x38),
                                     (row_address - load_address, 24),
                                     (event_address - load_address, 30),
                                     (entry, max(site.address for site in function.instructions)
                                      - entry + 2),
                                     *[(item.pool - load_address, 4)
                                       for item in function.literals],
                                     *[(at, size) for at, size in
                                       raw_stage["sense_dependencies"]]],
                    "event_handlers": handlers,
                }
                found[entry] = profile
    return [found[entry] for entry in sorted(found)]


def external_row_property(image: bytes, config):
    if (getattr(config, "load_address", None) != 0
            or type(getattr(config, "flash_size", None)) is not int
            or type(getattr(config, "ram_base", None)) is not int
            or type(getattr(config, "ram_size", None)) is not int):
        return None, None
    profiles = find_external_row_scanners(image, config.load_address)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    if any(at < 0 or at + size > min(len(image), config.flash_size)
           for at, size in profile["dependencies"]):
        return None, None
    fields = [profile["sense_address"], profile["sense_mask"],
              profile["active_output_level"], profile["row_ports"][0],
              profile["row_masks"][0], profile["row_ports"][1],
              profile["row_masks"][1]]
    return "matrix-external-wires=" + ":".join(f"{v:x}" for v in fields), profile
