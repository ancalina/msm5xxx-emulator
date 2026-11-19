"""Byte-wide GPIO row scans with source-derived physical contacts."""
from __future__ import annotations

import re

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start, _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .row_execution import _Bits, _clear_outputs, _region_values, _row_outputs, _word
from .sparse_rows import _scan_loop
from .source_flow import closed_input_region
from .startup_copy import reset_linked_input_copy

GRAMMAR = "byte-row-six-keypad-v1"
_PORTS = (0x03000660, 0x03000664, 0x03000668, 0x0300066c,
          0x03000720, 0x03000724, 0x03000728)


def _entry_values(image, entry, loop):
    values = _region_values(image, entry, loop)
    if values is not None:
        return values
    stops = {loop}
    for pc in range(entry, loop, 2):
        word = _word(image, pc)
        if word & 0xf800 == 0xe000 or word & 0xf000 == 0xd000:
            stops.update(target for target in _thumb_successors(image, pc, len(image))
                         if not entry <= target < loop)
    region = closed_input_region(image, entry, tuple(sorted(stops)))
    if region is None:
        return None
    facts = facts_for(image)
    values = {}
    for number in range(8):
        register = a.ARM_REG_R0 + number
        value = facts.register_value(region, CodeAddress(loop), register)
        if value is not None and value.kind == "const":
            values[register] = _Bits.constant(value.value)
    return values


def _ram_literals(image, start, end, config):
    facts = facts_for(image)
    values = set()
    for pc in range(start, end, 2):
        literal = facts.literal(CodeAddress(pc))
        if literal is not None and config.ram_base <= literal.value < config.ram_base + config.ram_size:
            values.add(literal.value)
    return values


def _copied_rows(image, loop, sense, row, config):
    """An indexed RAM row map needs its complete reset-owned six-byte span."""
    facts = facts_for(image)
    tables = set()
    for pc in range(loop + 2, sense, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is None or ins.id != a.ARM_INS_LDRB or len(ins.operands) != 2
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.index != a.ARM_REG_R0 + row
                or ins.operands[1].mem.disp):
            continue
        register = ins.operands[1].mem.base
        literal = facts.literal(CodeAddress(pc - 2))
        prior = facts.decode(CodeAddress(pc - 2))
        if (literal is not None and prior is not None
                and prior.operands[0].type == a.ARM_OP_REG
                and prior.operands[0].reg == register
                and config.ram_base <= literal.value <= config.ram_base + config.ram_size - 6):
            tables.add(literal.value)
    if not tables:
        return None, None
    if len(tables) != 1:
        return False, None
    table = tables.pop()
    copy = reset_linked_input_copy(image, ((table, 6),),
        ram_base=config.ram_base, ram_size=config.ram_size,
        flash_size=config.flash_size)
    return (table, copy) if copy is not None else (False, None)


def _row_wires(outputs, *, width=8, descending=True):
    """Only pins that alternate between known high and low are row wires."""
    ports = sorted(set().union(*(output.keys() for output in outputs)), reverse=descending)
    masks = []
    for port in ports:
        zeros = ones = 0
        for output in outputs:
            if port not in output:
                return None
            zeros |= output[port].zero
            ones |= output[port].one
        masks.append(zeros & ones & ((1 << width) - 1))
    selected = [(port, mask) for port, mask in zip(ports, masks) if mask]
    if not 1 <= len(selected) <= 3:
        return None
    pins = [(port, 1 << bit) for port, mask in selected
            for bit in range(width) if mask & 1 << bit]
    if len(pins) != 6:
        return None
    order = []
    for output in outputs:
        if any((output[port].zero | output[port].one) & mask != mask
               for port, mask in selected):
            return None
        low = [index for index, (port, bit) in enumerate(pins)
               if output[port].zero & bit]
        if len(low) != 1:
            return None
        order.append(low[0])
    if sorted(order) != list(range(6)):
        return None
    return selected, order


def _presence(image, entry, loop, address, masks, byte_memory):
    facts = facts_for(image)
    candidates = []
    for pc in range(entry + 2, loop - 8, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is None or ins.id != a.ARM_INS_LDRB or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.index or ins.operands[1].mem.disp != 4):
            continue
        destination = ins.operands[0].reg - a.ARM_REG_R0
        base = ins.operands[1].mem.base - a.ARM_REG_R0
        if not 0 <= destination <= 7 or not 0 <= base <= 7:
            continue
        literal = facts.thumb_literal_value(pc - 2, base)
        if literal != address - 4 or tuple(_word(image, pc + offset) for offset in (2, 4, 6)) != (
                0x0700 | destination << 3 | destination,
                0x0f00 | destination << 3 | destination, 0x280f | destination << 8):
            continue
        proof = _clear_outputs(image, facts.thumb_call_target(pc - 6), masks,
            byte_memory=byte_memory, byte_ports=_PORTS)
        if proof is None:
            # One-bank scanners clear and commit their shadow inline.
            for start in range(max(entry, pc - 80), pc - 2, 2):
                if facts.thumb_call_target(start) is None:
                    continue
                initial = _region_values(image, entry, start)
                if initial is None:
                    continue
                result = _row_outputs(image, start, pc, initial, -0x10000, 0,
                    byte_memory=byte_memory, byte_ports=_PORTS)
                if result is not None and all(port in result[0] and result[0][port].zero & mask == mask
                                              for port, mask in masks):
                    proof = result[1]
                    break
        if proof is not None:
            candidates.append((pc, proof))
    return candidates[0] if len(candidates) == 1 else None


def find_byte_row_scanners(image, config):
    facts = facts_for(image)
    found = []
    for match in re.finditer(rb"\x00\x79\x00\x07\x00\x0f\x0f\x28", image):
        sense = match.start()
        if sense & 1:
            continue
        literal = facts.thumb_literal_value(sense - 2, 0)
        if literal is None or literal + 4 != 0x03000694:
            continue
        scan = _scan_loop(image, sense)
        if scan is None:
            continue
        row, slot, rows, end, finish, loop, event_load, events_at, lookup_dependencies = scan
        if slot is not None or rows != 6:
            continue
        entry = _thumb_function_start(image, loop)
        initial = _entry_values(image, entry, loop)
        if initial is None or initial.get(a.ARM_REG_R0 + row, _Bits()).value() != 0:
            continue
        table, copy = _copied_rows(image, loop, sense, row, config)
        if table is False:
            continue
        shadows = _ram_literals(image, loop, sense, config)
        if table is not None:
            shadows = {address for address in shadows if not table <= address < table + 6}
        byte_memory = tuple((address, 1) for address in sorted(shadows))
        outputs, dependencies, ram_dependencies = [], set(lookup_dependencies), set()
        dependencies.update((prefix_literal.pool, 4) for pc in range(entry, loop, 2)
                            if (prefix_literal := facts.literal(CodeAddress(pc))) is not None)
        for index in range(6):
            registers = dict(initial)
            registers[a.ARM_REG_R0 + row] = _Bits.constant(index)
            result = _row_outputs(image, loop, sense, registers, -0x10000, 0,
                byte_memory=byte_memory, byte_ports=_PORTS,
                preserved_registers={a.ARM_REG_R0 + row: index},
                copied_row=None if copy is None else (None, copy.source, copy.target, copy.size),
                ram_dependencies=ram_dependencies)
            if result is None:
                break
            outputs.append(result[0])
            dependencies.update(result[1])
        if len(outputs) != 6:
            continue
        wiring = _row_wires(outputs)
        if wiring is None:
            continue
        ports, order = wiring
        presence = _presence(image, entry, loop, literal + 4, ports, byte_memory)
        if presence is None:
            continue
        dependencies.update(presence[1])
        dependencies.update(((entry, finish - entry), (events_at, 24)))
        if copy is not None:
            dependencies.update(copy.evidence)
            if any(copy.source_address(address, size) is None for address, size in ram_dependencies):
                continue
        found.append({"grammar": GRAMMAR, "rows": 6, "columns": 4,
            "sense_address": literal + 4, "presence_site": presence[0], "sense_site": sense,
            "event_load_site": event_load, "event_register": _word(image, event_load) & 7,
            "event_table": events_at, "event_codes": list(image[events_at:events_at + 24]),
            "row_ports": [port for port, _ in ports], "row_masks": [mask for _, mask in ports],
            "row_wire_order": order, "row_loop": loop, "no_key": 15,
            "single_key_column_sense": [14, 13, 11, 7],
            "dependencies": sorted(dependencies), "ram_dependencies": sorted(ram_dependencies),
            "byte_shadows": sorted(shadows)})
    return found


def byte_row_property(image, config, *, status_descriptor_claimed=False):
    if status_descriptor_claimed or getattr(config, "load_address", None) != 0:
        return None, None
    profiles = find_byte_row_scanners(image, config)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    if any(not 0 <= at <= min(len(image), config.flash_size) - size
           for at, size in profile["dependencies"]):
        return None, None
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address == profile["sense_address"]:
        # The one-bank model computes the same electrical plane at every read.
        # A separately detected high-idle column therefore needs one owner.
        if (len(profile["row_ports"]) != 1 or type(status.mask) is not int
                or not 0 < status.mask <= 15 or status.default != status.mask):
            return None, None
        profile["shared_released_column"] = {
            "address": status.address, "mask": status.mask, "default": status.default}
    elif status is not None and status.address in profile["row_ports"]:
        return None, None
    fields = [profile["sense_address"], profile["presence_site"], profile["sense_site"]]
    for port, mask in zip(profile["row_ports"], profile["row_masks"]):
        fields.extend((port, mask))
    fields.extend([0, 0] * (3 - len(profile["row_ports"])))
    return "matrix-gpio=" + ":".join(f"{value:x}" for value in fields), profile
