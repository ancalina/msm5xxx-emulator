"""Instruction-derived row wiring for a descriptor-owned halfword keypad."""
from __future__ import annotations

import re
import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start, _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.startup_layouts import layouts
from .row_execution import _Bits, _region_values, _row_clear_helper, _row_outputs, _word
from .sparse_presence import nibble_read_sites, presence_for_loop, released_contact
from .startup_copy import reset_linked_input_copy


GRAMMAR = "sparse-halfword-six-row-v1"
_GRAMMARS = {6: GRAMMAR, 7: "sparse-halfword-seven-row-v1"}
def _row_footer(image, end):
    """Return a normalized register or stack row-counter backedge."""
    first = _word(image, end)
    slot = None
    increment = end
    temporary = None
    if first & 0xf800 == 0x9800:
        row = first >> 8 & 7
        slot = (first & 255) * 4
        if slot > 0xfc:
            return None
        increment += 2
    else:
        if first & 0xfe00 == 0x1c00 and first >> 6 & 7 == 1:
            row, temporary = first >> 3 & 7, first & 7
        else:
            row = first >> 8 & 7
        if row not in (4, 5, 6, 7):
            return None
    expected = (0x3001 | row << 8, 0x0600 | row << 3 | row,
                0x0e00 | row << 3 | row) if temporary is None else (
                0x1c40 | row << 3 | temporary,
                0x0600 | temporary << 3 | row, 0x0e00 | row << 3 | row)
    if tuple(_word(image, increment + off) for off in (0, 2, 4)) != expected:
        return None
    compare = increment + 6
    if slot is not None:
        if _word(image, compare) != 0x9000 | row << 8 | slot // 4:
            return None
        compare += 2
    rows = _word(image, compare) & 255
    if rows not in _GRAMMARS or _word(image, compare) != 0x2800 | row << 8 | rows:
        return None
    branch = compare + 2
    op = _word(image, branch)
    finish = branch + 2
    if op & 0xff00 != 0xdb00:
        finish = branch + 4
        if (op & 0xff00 != 0xda00 or finish not in _thumb_successors(image, branch, len(image))
                or _word(image, branch + 2) & 0xf800 != 0xe000):
            return None
        branch += 2
    targets = [target for target in _thumb_successors(image, branch, len(image)) if target != branch + 2]
    return (row, slot, rows, finish, targets[0]) if len(targets) == 1 else None


def _stack_counter_initialized(image, entry, loop, row, slot):
    """The zero store must dominate entry to the stack-counter loop."""
    if (_word(image, loop - 4) != 0x2000 | row << 8
            or _word(image, loop - 2) != 0x9000 | row << 8 | slot // 4
            or _word(image, loop) != 0x9800 | row << 8 | slot // 4):
        return False
    exits = set()
    for pc in range(entry, loop, 2):
        word = _word(image, pc)
        if word & 0xf800 == 0xe000 or word & 0xf000 == 0xd000:
            exits.update(CodeAddress(target) for target in _thumb_successors(image, pc, len(image))
                         if target != loop and not entry <= target < loop)
    region = facts_for(image).function_region(CodeAddress(entry), stop_at=(CodeAddress(loop),),
        stop_before=tuple(sorted(exits, key=lambda pc: pc.address)), budget=2048)
    if not region.complete:
        return False
    edges = {}
    for source, target in region.control_edges:
        edges.setdefault(source.address, set()).add(target.address)
    def reaches(blocked=None):
        pending, seen = [entry], set()
        while pending:
            pc = pending.pop()
            if pc == blocked or pc in seen:
                continue
            if pc == loop:
                return True
            seen.add(pc)
            pending.extend(edges.get(pc, ()))
        return False
    return reaches() and not reaches(loop - 4) and not reaches(loop - 2)


def _scan_loop(image, sense, compare_offset=6):
    """Prove the row backedge and every column/row lookup address."""
    facts = facts_for(image)
    matches = []
    for end in range(sense + compare_offset + 6,
                     min(sense + 128, len(image) - 16), 2):
        footer = _row_footer(image, end)
        if footer is None:
            continue
        row, slot, rows, finish, loop = footer
        if not sense - 0x400 <= loop < sense:
            continue
        branch_site = sense + compare_offset + 2
        no_key = _word(image, branch_site)
        if no_key & 0xff00 != 0xd000 or end not in _thumb_successors(image, branch_site, len(image)):
            continue
        for load in range(sense + 10, end - 1, 2):
            if _word(image, load) & 0xfe00 != 0x5c00:
                continue
            addresses, dependencies = [], set()
            valid = True
            for raw in (14, 13, 11, 7):
                for index in range(rows):
                    initial = {a.ARM_REG_R0: _Bits.constant(raw)}
                    if slot is None:
                        initial[a.ARM_REG_R0 + row] = _Bits.constant(index)
                    result = _row_outputs(image, sense + 2, load, initial, -0x10000, 0,
                        capture_load=True, capture_end=finish,
                        initial_stack=None if slot is None else {slot: index})
                    if result is None:
                        valid = False
                        break
                    address = result[0]
                    if not 0 <= address < len(image):
                        valid = False
                        break
                    addresses.append(address)
                    dependencies.update(result[1])
                if not valid:
                    break
            if (valid and len(addresses) == 4 * rows
                    and addresses == list(range(addresses[0], addresses[0] + 4 * rows))):
                events = list(image[addresses[0]:addresses[0] + 4 * rows])
                if all(events.count(event) == 1 for event in b"123456789*0#"):
                    matches.append((row, slot, rows, end, finish, loop, load, addresses[0], dependencies))
    return matches[0] if len(matches) == 1 else None


def _find_sparse_row_scanners(image: bytes, config=None, *, alternate=False):
    facts = facts_for(image)
    found = []
    copies = None
    candidates = [(match.start(), 6) for match in
                  re.finditer(rb"\x00\x88\x00\x07\x00\x0f\x0f\x28", image)]
    if alternate:
        extra = set()
        for seed, offset in candidates:
            seed_scan = _scan_loop(image, seed, offset)
            if seed_scan is None:
                continue
            seed_loop = seed_scan[5]
            seed_entry = _thumb_function_start(image, seed_loop)
            if seed_entry is None:
                continue
            seed_values = _region_values(image, seed_entry, seed_loop)
            pointer = _word(image, seed - 2)
            descriptor_register = a.ARM_REG_R0 + (pointer >> 3 & 7)
            descriptor = (seed_values.get(descriptor_register, _Bits()).value()
                          if seed_values is not None else None)
            if descriptor is None:
                continue
            function = facts.function(CodeAddress(seed_entry, "thumb"), budget=2048)
            if not function.complete or function.unresolved:
                continue
            for sample in nibble_read_sites(facts, function, descriptor):
                offset = sample["compare_site"] - sample["read_site"]
                site = sample["read_site"]
                if (offset in (6, 8) and _scan_loop(image, site, offset) is not None):
                    extra.add((site, offset))
        candidates = sorted(set(candidates) | extra)
    for sense, compare_offset in candidates:
        pointer = _word(image, sense - 2)
        if sense & 1 or pointer & 0xffc7 != 0x6b40:
            continue
        descriptor_register = a.ARM_REG_R0 + (pointer >> 3 & 7)
        scan = _scan_loop(image, sense, compare_offset)
        if scan is None:
            continue
        row, row_slot, rows, end, finish, loop, event_load, events_at, lookup_dependencies = scan
        event_instruction = facts.decode(CodeAddress(event_load, "thumb"))
        event_register_id = (event_instruction.operands[0].reg
            if event_instruction is not None and event_instruction.id == a.ARM_INS_LDRB
            and event_instruction.operands
            and event_instruction.operands[0].type == a.ARM_OP_REG else None)
        if event_register_id is None or not a.ARM_REG_R0 <= event_register_id <= a.ARM_REG_R7:
            continue
        event_register = event_register_id - a.ARM_REG_R0
        events = list(image[events_at:events_at + 4 * rows])
        entry = _thumb_function_start(image, loop)
        if entry is None:
            continue
        function = facts.function(CodeAddress(entry, "thumb"), budget=2048)
        if alternate and (not function.complete or function.unresolved):
            continue
        initial = _region_values(image, entry, loop)
        descriptor = initial.get(descriptor_register, _Bits()).value() if initial is not None else None
        direct_descriptor = facts.thumb_literal_value(sense - 4, pointer >> 3 & 7)
        if initial is not None and direct_descriptor is not None:
            descriptor = direct_descriptor
        if descriptor is None or descriptor & 3:
            continue
        compare = loop if row_slot is None else loop + 2
        row_bounds = (0x2800 | (rows - 1) | row << 8,
                      0x2800 | rows | row << 8)
        if (row_slot is None and _word(image, compare) not in row_bounds
                and _row_clear_helper(image, facts.thumb_call_target(loop),
                                      descriptor) is not None):
            # Some scans clear/commit row-select shadow state before testing
            # the zero-based row counter. The linked helper preserves that
            # counter and its ABI is modeled by _row_outputs.
            compare += 4
        if _word(image, compare) not in row_bounds:
            continue
        if row_slot is None:
            if initial.get(a.ARM_REG_R0 + row, _Bits()).value() != 0:
                continue
        elif not _stack_counter_initialized(image, entry, loop, row, row_slot):
            continue
        if copies is None and not alternate:
            copies = layouts(image)
        mapped = ([] if alternate else
                  [copy for copy in copies if copy[2] <= descriptor <= copy[2] + copy[3] - 0x38])
        reset_copy = None
        if len(mapped) == 1:
            copy_at, source, target, size, _ = mapped[0]
            descriptor_rom = source + descriptor - target
        elif not mapped and config is not None:
            # Some reset-linked consumers copy initialized data through a
            # code-proved Thumb loop that the shared startup layout model does
            # not describe. Resolve this descriptor directly from its linked
            # reset route; do not infer a copy from the descriptor's contents.
            reset_copy = reset_linked_input_copy(
                image, ((descriptor, 0x38),),
                ram_base=config.ram_base, ram_size=config.ram_size,
                flash_size=config.flash_size)
            if reset_copy is None:
                continue
            source, target, size = reset_copy.source, reset_copy.target, reset_copy.size
            copy_at = source
            descriptor_rom = reset_copy.source_address(descriptor, 0x38)
        else:
            continue
        if descriptor_rom is None:
            continue
        if not 0 <= descriptor_rom <= len(image) - 0x38:
            continue
        sense_address = struct.unpack_from("<I", image, descriptor_rom + 0x34)[0]
        if sense_address not in (0x0300066c, 0x0300072c):
            continue
        samples = nibble_read_sites(facts, function, descriptor) if alternate else ()
        contact = None
        if alternate and config is not None:
            contact = released_contact(
                image, facts, function, descriptor, descriptor_rom,
                sense_address, samples, config.ram_base,
                config.ram_base + config.ram_size,
                min(config.flash_size, len(image)),
                event_register=event_register, event_load_site=event_load)
            if contact is None:
                continue
        bank = sense_address - 12
        outputs, ram_dependencies = [], set()
        dependencies = {(copy_at, 20), (descriptor_rom, 0x38),
            (events_at, 4 * rows), (entry, finish - entry)}
        if contact is not None:
            dependencies.update(contact["dependencies"])
        if reset_copy is not None:
            dependencies.update(reset_copy.evidence)
        dependencies.update(lookup_dependencies)
        for pc in range(entry, finish, 2):
            word = _word(image, pc)
            if word & 0xf800 == 0x4800:
                dependencies.add((((pc + 4) & ~3) + (word & 255) * 4, 4))
            callee = facts.thumb_call_target(pc)
            if callee is not None:
                dependencies.add((callee, 2))
        for index in range(rows):
            registers = dict(initial)
            if row_slot is None:
                registers[a.ARM_REG_R0 + row] = _Bits.constant(index)
            result = _row_outputs(image, loop, sense, registers, descriptor, descriptor_rom,
                preserved_registers={a.ARM_REG_R0 + row: index} if row_slot is None else None,
                initial_stack=None if row_slot is None else {row_slot: index},
                copied_row=(copy_at, source, target, size), ram_dependencies=ram_dependencies)
            if result is None:
                break
            outputs.append(result[0]); dependencies.update(result[1])
        if len(outputs) != rows:
            continue
        ports = sorted(set().union(*(output.keys() for output in outputs)))
        if (not 1 <= len(ports) <= 2 or any(port not in (bank, bank + 4, bank + 8) for port in ports)
                or any(set(output) != set(ports) for output in outputs)):
            continue
        masks = [0 for _ in ports]
        for output in outputs:
            for index, port in enumerate(ports):
                masks[index] |= output[port].zero & 0xffff
        wires = [(port, 1 << bit) for port, mask in zip(ports, masks) for bit in range(16) if mask & 1 << bit]
        if len(wires) != rows:
            continue
        order = []
        for output in outputs:
            if any((output[port].zero | output[port].one) & mask != mask for port, mask in zip(ports, masks)):
                break
            selected = [index for index, (port, bit) in enumerate(wires) if output[port].zero & bit]
            if len(selected) != 1:
                break
            order.append(selected[0])
        if sorted(order) != list(range(rows)):
            continue
        if alternate:
            presence = presence_for_loop(facts, function, samples, loop)
            if presence is None:
                continue
            presences = [presence]
        else:
            presences = []
            for pc in range(entry + 2, loop - 6, 2):
                load, pointer_load = _word(image, pc), _word(image, pc - 2)
                destination = load & 7
                if (load & 0xffc0 == 0x8800 and pointer_load & 0xffc0 == 0x6b40
                        and (pointer_load & 7) == (load >> 3 & 7)
                        and tuple(_word(image, pc + off) for off in (2, 4, 6)) == (
                            0x0700 | destination << 3 | destination,
                            0x0f00 | destination << 3 | destination,
                            0x280f | destination << 8)):
                    values = _region_values(image, entry, pc - 2)
                    register = a.ARM_REG_R0 + (pointer_load >> 3 & 7)
                    if values is not None and values.get(register, _Bits()).value() == descriptor:
                        presences.append(pc)
            if len(presences) != 1:
                continue
        while len(ports) < 2:
            ports.append(0); masks.append(0)
        found.append({"grammar": _GRAMMARS[rows], "rows": rows, "columns": 4,
            "descriptor": descriptor, "presence_site": presences[0], "sense_site": sense, "sense_address": sense_address,
            "row_loop": loop, "event_load_site": event_load, "event_register": event_register,
            "row_counter": {"register": row} if row_slot is None else {"stack_offset": row_slot},
            "row_ports": ports, "row_masks": masks, "row_wire_order": order,
            "event_codes": events, "event_table": events_at, "no_key": 15,
            "single_key_column_sense": [14, 13, 11, 7],
            "copy_source": source, "copy_target": target, "copy_size": size,
            "descriptor_source": descriptor_rom,
            "dependencies": sorted(dependencies), "ram_dependencies": sorted(ram_dependencies),
            **({"released_contact": contact,
                "state_ranges": contact["state_ranges"]} if contact is not None else {})})
    return found


def find_sparse_row_scanners(image: bytes, config=None):
    found = _find_sparse_row_scanners(image, config)
    return found if found else _find_sparse_row_scanners(image, config, alternate=True)


def _coalesce_wire_profiles(profiles):
    """Multiple scan paths must describe identical numeric physical contacts."""
    if not profiles or len(profiles) > 4:
        return None
    if len(profiles) == 1:
        return profiles[0]
    profiles = sorted(profiles, key=lambda profile: (profile["presence_site"], profile["sense_site"]))
    first = profiles[0]
    def cells(profile):
        wires = [(port, 1 << bit) for port, mask in zip(profile["row_ports"], profile["row_masks"])
                 for bit in range(16) if mask & 1 << bit]
        result = {}
        for event in b"123456789*0#":
            index = profile["event_codes"].index(event)
            row, column = index % profile["rows"], index // profile["rows"]
            port, bit = wires[profile["row_wire_order"][row]]
            result[event] = (port, bit, profile["single_key_column_sense"][column])
        return result
    fields = ("grammar", "descriptor", "sense_address", "rows", "columns", "row_ports", "row_masks")
    if any(any(profile[field] != first[field] for field in fields) or cells(profile) != cells(first)
           for profile in profiles[1:]):
        return None
    if any(profile.get("released_contact") != first.get("released_contact")
           for profile in profiles[1:]):
        return None
    points = [profile[key] for profile in profiles for key in ("presence_site", "sense_site")]
    if len(set(points)) != len(points):
        return None
    return {**first,
        "source_sites": [{key: profile[key] for key in ("presence_site", "sense_site", "event_load_site", "event_register")}
                         for profile in profiles],
        "dependencies": sorted({tuple(span) for profile in profiles for span in profile["dependencies"]}),
        "ram_dependencies": sorted({tuple(span) for profile in profiles for span in profile["ram_dependencies"]}),
        **({"state_ranges": first["state_ranges"]}
           if first.get("state_ranges") is not None else {})}


def sparse_row_property(image, config, *, status_descriptor_claimed=False):
    if status_descriptor_claimed or getattr(config, "load_address", None) != 0:
        return None, None
    candidates = find_sparse_row_scanners(image, config)
    profile = _coalesce_wire_profiles(candidates)
    if profile is None:
        return None, None
    if (not config.ram_base <= profile["descriptor"] <= config.ram_base + config.ram_size - 0x38
            or any(not 0 <= at <= min(config.flash_size, len(image)) - size for at, size in profile["dependencies"])
            or any(not config.ram_base <= at <= config.ram_base + config.ram_size - size
                   for at, size in profile["ram_dependencies"])
            or any(not config.ram_base <= at <= config.ram_base + config.ram_size - size
                   for at, size in profile.get("state_ranges", ()))):
        return None, None
    required = [(profile["descriptor"], 0x38), *profile["ram_dependencies"]]
    copy = reset_linked_input_copy(image, tuple(required),
        ram_base=config.ram_base, ram_size=config.ram_size,
        flash_size=config.flash_size)
    if (copy is None or (copy.source, copy.target, copy.size) !=
            (profile["copy_source"], profile["copy_target"], profile["copy_size"])
            or copy.source_address(profile["descriptor"], 0x38) != profile["descriptor_source"]
            or any(copy.source_address(address, size) != profile["copy_source"] + address - profile["copy_target"]
                   for address, size in profile["ram_dependencies"])):
        return None, None
    profile["dependencies"] = sorted(set(profile["dependencies"]) | set(copy.evidence))
    fields = [profile["descriptor"], profile["presence_site"], profile["sense_site"],
              profile["row_ports"][0], profile["row_masks"][0], profile["row_ports"][1], profile["row_masks"][1]]
    for source in profile.get("source_sites", ())[1:]:
        fields.extend((source["presence_site"], source["sense_site"]))
    value = "matrix-halfword-wires=" + ":".join(f"{field:x}" for field in fields)
    contact = profile.get("released_contact")
    if contact is not None:
        value += f",experimental-matrix-contact={contact['status_site']:x}:10"
    return value, profile
