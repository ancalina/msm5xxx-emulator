"""Descriptor-owned row dispatch with byte counter and column lookup."""
from __future__ import annotations

import re

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start, _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .byte_rows import _row_wires
from .row_execution import _Bits, _clear_outputs, _row_outputs, _word
from .source_flow import closed_input_region
from .startup_copy import reset_linked_input_copy

GRAMMAR = "descriptor-dispatch-six-row-v1"


def _branch(image, pc):
    targets = [target for target in _thumb_successors(image, pc, len(image)) if target != pc + 2]
    return targets[0] if len(targets) == 1 else None


def _counter_loop(image, sense, state_register):
    """Same byte field is zeroed, incremented and bounded before row dispatch."""
    matches = []
    for footer in range(sense + 16, min(sense + 112, len(image) - 14), 2):
        load = _word(image, footer)
        if load & 0xf83f != 0x7800 | state_register << 3:
            continue
        offset = load >> 6 & 31
        if tuple(_word(image, footer + off) for off in (2, 4, 6, 8)) != (
                0x3001, load ^ 0x0800, load, 0x2806):
            continue
        finish = footer + 14
        if (_word(image, footer + 10) & 0xff00 != 0xda00
                or _branch(image, footer + 10) != finish
                or _word(image, footer + 12) & 0xf800 != 0xe000):
            continue
        dispatch = _branch(image, footer + 12)
        if dispatch is None or not sense - 0x400 <= dispatch < sense:
            continue
        if (_word(image, dispatch) != 0x2806
                or _word(image, sense + 14) & 0xff00 != 0xd000
                or _branch(image, sense + 14) != footer):
            continue
        matches.append((offset, footer, finish, dispatch))
    return matches[0] if len(matches) == 1 else None


def _prefix(image, entry, dispatch, footer, finish):
    stops = {dispatch, finish}
    allowed = lambda pc: entry <= pc < dispatch or footer + 6 <= pc < finish
    for start, end in ((entry, dispatch), (footer + 6, finish)):
        for pc in range(start, end, 2):
            word = _word(image, pc)
            if word & 0xf800 == 0xe000 or word & 0xf000 == 0xd000:
                stops.update(target for target in _thumb_successors(image, pc, len(image))
                             if not allowed(target))
    return closed_input_region(image, entry, tuple(sorted(stops)))


def _constant(facts, region, pc, register):
    value = facts.register_value(region, CodeAddress(pc), register)
    return value.value if value is not None and value.kind == "const" else None


def _counter_zero(image, region, dispatch, state_register, counter_offset, state):
    facts = facts_for(image)
    candidates = []
    for site in region.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_STRB or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.base != a.ARM_REG_R0 + state_register
                or ins.operands[1].mem.index or ins.operands[1].mem.disp != counter_offset):
            continue
        if (_constant(facts, region, site.address, ins.operands[0].reg) == 0
                and _constant(facts, region, site.address, ins.operands[1].mem.base) == state
                and region.dominates(site, CodeAddress(dispatch))):
            candidates.append(site)
    return candidates[0].address if len(candidates) == 1 else None


def _contact_gate(image, region, descriptor_register, descriptor, state,
                  event_offset, zero_site, presence, clear_helper):
    """An independent low contact fills the same event field with 0x73."""
    facts = facts_for(image)
    matches = []
    for site in region.instructions:
        read = site.address
        if (read >= presence or _word(image, read - 2) != 0x6b40 | (descriptor_register - a.ARM_REG_R0) << 3
                or tuple(_word(image, read + off) for off in (0, 2)) != (0x8800, 0x0940)
                or _word(image, read + 4) & 0xff00 != 0xd200
                or _word(image, read + 6) != 0x2073
                or _constant(facts, region, read - 2, descriptor_register) != descriptor):
            continue
        store = facts.decode(CodeAddress(read + 8))
        if (store is None or store.id != a.ARM_INS_STRB or len(store.operands) != 2
                or store.operands[0].type != a.ARM_OP_REG or store.operands[0].reg != a.ARM_REG_R0
                or store.operands[1].type != a.ARM_OP_MEM or store.operands[1].mem.index
                or store.operands[1].mem.disp != event_offset
                or _constant(facts, region, read + 8, store.operands[1].mem.base) != state):
            continue
        high = _branch(image, read + 4)
        if high is None or not high < presence or facts.thumb_call_target(presence - 6) != clear_helper:
            continue
        high_region = facts.function_region(CodeAddress(high),
            stop_before=(CodeAddress(presence - 2),), budget=128)
        if (not high_region.complete or CodeAddress(read + 8) in high_region.instructions
                or not high_region.dominates(CodeAddress(presence - 6), CodeAddress(presence - 2))):
            continue
        gates = []
        for use in region.instructions:
            ins = facts.decode(use)
            if (ins is None or ins.id != a.ARM_INS_LDRB or len(ins.operands) != 2
                    or ins.operands[0].type != a.ARM_OP_REG or ins.operands[0].reg != a.ARM_REG_R0
                    or ins.operands[1].type != a.ARM_OP_MEM or ins.operands[1].mem.index
                    or ins.operands[1].mem.disp != event_offset
                    or _constant(facts, region, use.address, ins.operands[1].mem.base) != state
                    or _word(image, use.address + 2) != 0x2800
                    or _word(image, use.address + 4) & 0xff00 != 0xd000
                    or _branch(image, use.address + 4) != use.address + 8
                    or _word(image, use.address + 6) & 0xf800 != 0xe000
                    or CodeAddress(_branch(image, use.address + 6)) not in region.scope_before
                    or not region.dominates(use, CodeAddress(zero_site))
                    or not region.dominates(CodeAddress(use.address + 8), CodeAddress(zero_site))):
                continue
            gates.append(use.address)
        if len(gates) == 1:
            matches.append({"grammar": "state-event-matrix-contact-v1", "status_site": read,
                "inactive_level": 0x10, "active_low_mask": 0x10, "event": 0x73,
                "event_store": read + 8, "event_field": state + event_offset,
                "numeric_gate": gates[0], "clear_helper": clear_helper})
    return matches[0] if len(matches) == 1 else None


def _event_lookup(image, sense, finish, state, counter_offset):
    matches = []
    for load in range(sense + 16, finish, 2):
        if _word(image, load) & 0xfe00 != 0x5c00:
            continue
        addresses, dependencies = [], set()
        for raw in (14, 13, 11, 7):
            for row in range(6):
                result = _row_outputs(image, sense + 2, load,
                    {a.ARM_REG_R0: _Bits.constant(raw),
                     a.ARM_REG_R4: _Bits.constant(state)}, -0x10000, 0,
                    capture_load=True, capture_end=finish,
                    byte_memory=((state, 0x20),),
                    initial_memory={state + counter_offset: _Bits.constant(row)})
                if result is None:
                    break
                addresses.append(result[0])
                dependencies.update(result[1])
            if len(addresses) % 6:
                break
        if len(addresses) != 24 or addresses != list(range(addresses[0], addresses[0] + 24)):
            continue
        events = list(image[addresses[0]:addresses[0] + 24])
        if all(events.count(event) == 1 for event in b"123456789*0#"):
            matches.append((load, addresses[0], events, dependencies))
    return matches[0] if len(matches) == 1 else None


def find_dispatch_row_scanners(image, config):
    facts = facts_for(image)
    found = []
    for match in re.finditer(rb"\x00\x88\x00\x07\x00\x0f", image):
        sense = match.start()
        pointer, sample = _word(image, sense - 2), _word(image, sense + 6)
        if (sense & 1 or pointer & 0xffc7 != 0x6b40 or sample & 0xf807 != 0x7000
                or tuple(_word(image, sense + off) for off in (8, 10, 12)) != (0x0600, 0x0e00, 0x280f)):
            continue
        descriptor_register = a.ARM_REG_R0 + (pointer >> 3 & 7)
        state_register = sample >> 3 & 7
        # The lookup executor keeps this source-owned byte structure in r4.
        if state_register != 4:
            continue
        loop = _counter_loop(image, sense, state_register)
        if loop is None:
            continue
        counter_offset, footer, finish, dispatch = loop
        if counter_offset == sample >> 6 & 31:
            continue
        entry = _thumb_function_start(image, dispatch)
        region = _prefix(image, entry, dispatch, footer, finish)
        if region is None:
            continue
        descriptor = _constant(facts, region, dispatch, descriptor_register)
        state = _constant(facts, region, dispatch, a.ARM_REG_R4)
        if (descriptor is None or descriptor & 3 or state is None
                or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38
                or not config.ram_base <= state <= config.ram_base + config.ram_size - 0x20
                or state < descriptor + 0x38 and descriptor < state + 0x20):
            continue
        zero_site = _counter_zero(image, region, dispatch, state_register, counter_offset, state)
        if zero_site is None:
            continue
        copy = reset_linked_input_copy(image, ((descriptor, 0x38),),
            ram_base=config.ram_base, ram_size=config.ram_size, flash_size=config.flash_size)
        if copy is None:
            continue
        descriptor_rom = copy.source_address(descriptor, 0x38)
        if descriptor_rom is None:
            continue
        sense_address = int.from_bytes(image[descriptor_rom + 0x34:descriptor_rom + 0x38], "little")
        if sense_address not in (0x0300066c, 0x0300072c):
            continue
        initial = {}
        for number in range(8):
            register = a.ARM_REG_R0 + number
            value = _constant(facts, region, dispatch, register)
            if value is not None:
                initial[register] = _Bits.constant(value)
        outputs, dependencies = [], set(copy.evidence)
        for row in range(6):
            registers = dict(initial)
            registers[a.ARM_REG_R0] = _Bits.constant(row)
            result = _row_outputs(image, dispatch, sense, registers, descriptor, descriptor_rom,
                preserved_registers={a.ARM_REG_R4: state, descriptor_register: descriptor})
            if result is None:
                break
            outputs.append(result[0])
            dependencies.update(result[1])
        if len(outputs) != 6:
            continue
        wiring = _row_wires(outputs, width=16, descending=False)
        if wiring is None:
            continue
        ports, order = wiring
        bank = sense_address - 12
        if len(ports) > 2 or any(port not in (bank, bank + 4, bank + 8) for port, _ in ports):
            continue
        lookup = _event_lookup(image, sense, finish, state, counter_offset)
        if lookup is None:
            continue
        event_load, events_at, events, lookup_dependencies = lookup
        dependencies.update(lookup_dependencies)
        presences = []
        for pc in range(entry + 2, dispatch - 8, 2):
            if (_word(image, pc - 2) != pointer
                    or tuple(_word(image, pc + off) for off in (0, 2, 4)) != (0x8800, 0x0700, 0x0f00)
                    or _constant(facts, region, pc - 2, descriptor_register) != descriptor):
                continue
            proof = _clear_outputs(image, facts.thumb_call_target(pc - 6), ports,
                descriptor=descriptor, descriptor_rom=descriptor_rom)
            if proof is not None:
                presences.append((pc, proof))
        if len(presences) != 1:
            continue
        contact = None
        store = facts.decode(CodeAddress(event_load + 2))
        if (store is not None and store.id == a.ARM_INS_STRB and len(store.operands) == 2
                and store.operands[0].type == a.ARM_OP_REG
                and store.operands[0].reg == a.ARM_REG_R0 + (_word(image, event_load) & 7)
                and store.operands[1].type == a.ARM_OP_MEM
                and store.operands[1].mem.base == a.ARM_REG_R4
                and not store.operands[1].mem.index
                and int.from_bytes(image[descriptor_rom + 8:descriptor_rom + 12], "little") == sense_address):
            contact = _contact_gate(image, region, descriptor_register, descriptor, state,
                store.operands[1].mem.disp, zero_site, presences[0][0],
                facts.thumb_call_target(presences[0][0] - 6))
        dependencies.update(presences[0][1])
        dependencies.update((site.address, facts.decode(site).size) for site in region.instructions)
        dependencies.update((literal.pool, 4) for literal in region.literals)
        dependencies.update(((events_at, 24), (descriptor_rom, 0x38), (dispatch, finish - dispatch)))
        found.append({"grammar": GRAMMAR, "rows": 6, "columns": 4,
            "descriptor": descriptor, "descriptor_source": descriptor_rom,
            "sense_address": sense_address, "presence_site": presences[0][0], "sense_site": sense,
            "row_ports": [port for port, _ in ports], "row_masks": [mask for _, mask in ports],
            "row_wire_order": order, "event_codes": events, "event_table": events_at,
            "event_load_site": event_load, "event_register": _word(image, event_load) & 7,
            "row_loop": dispatch, "counter_address": state + counter_offset,
            "released_contact": contact,
            "no_key": 15, "single_key_column_sense": [14, 13, 11, 7],
            "dependencies": sorted(dependencies)})
    return found


def dispatch_row_property(image, config, *, status_descriptor_claimed=False):
    if status_descriptor_claimed or getattr(config, "load_address", None) != 0:
        return None, None
    profiles = find_dispatch_row_scanners(image, config)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    if any(not 0 <= at <= min(len(image), config.flash_size) - size
           for at, size in profile["dependencies"]):
        return None, None
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address in [profile["sense_address"], *profile["row_ports"]]:
        return None, None
    ports = list(zip(profile["row_ports"], profile["row_masks"]))
    ports.extend([(0, 0)] * (2 - len(ports)))
    fields = [profile["descriptor"], profile["presence_site"], profile["sense_site"],
              *[value for port in ports for value in port]]
    value = "matrix-halfword-wires=" + ":".join(f"{value:x}" for value in fields)
    if profile["released_contact"] is not None:
        value += f",experimental-matrix-contact={profile['released_contact']['status_site']:x}:10"
    return value, profile
