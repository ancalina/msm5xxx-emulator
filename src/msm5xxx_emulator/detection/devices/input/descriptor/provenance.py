from __future__ import annotations

def _row_state(image: bytes, start: int, end: int) -> tuple[int, int, int, str] | None:
    """Recover only one exact byte read/increment/write scan-index state."""
    from . import _last_literal, struct
    found: list[tuple[int, int, int]] = []
    for current in range(start, end - 1, 2):
        load = struct.unpack_from("<H", image, current)[0]
        if load & 0xF800 != 0x7800:
            continue
        base, value = load >> 3 & 7, load & 7
        offset = load >> 6 & 0x1F
        if not any(struct.unpack_from("<H", image, probe)[0] == 0x3001 | value << 8 for probe in range(current + 2, min(current + 0x12, end), 2)):
            continue
        if not any(struct.unpack_from("<H", image, probe)[0] == 0x7000 | offset << 6 | base << 3 | value for probe in range(current + 2, min(current + 0x18, end),
            2)):
            continue
        address = _last_literal(image, start, current, base)
        if address is not None:
            found.append((address, offset, current))
    return (*found[0], "ldrb-state-increment-store") if len(found) == 1 else None

def _sense_roles(image: bytes, start: int, end: int, descriptor: int, row_site: int) -> tuple[list[int], list[int]]:
    """Separate a pre-loop no-key guard from D+34 reads inside the six-row loop."""
    from . import _descending_row_register, _descriptor_pointer, _thumb_reachable, _thumb_successors, struct
    global_sites: list[int] = []
    row_sites: list[int] = []
    senses = [current for current in range(start, end - 3, 2) if ((load := struct.unpack_from("<H", image, current)[0]) & 0xF800 == 0x6800 and (load >> 6 & 0x1F)
        * 4 == 0x34 and (halfword := struct.unpack_from("<H", image, current + 2,)[0]) & 0xF800 == 0x8800 and halfword >> 3 & 7 == load & 7)]
    if _descriptor_pointer(image, start, senses) != descriptor:
        return global_sites, row_sites
    def closes_six_row_loop(sense: int) -> bool:
        if _descending_row_register(image, start, end, sense) is not None:
            return True
        for compare in range(sense + 4, min(sense + 0x80, end), 2):
            word = struct.unpack_from("<H", image, compare)[0]
            if word & 0xF800 != 0x2800 or word & 0xFF != 6:
                continue
            for branch in (compare + 2, compare + 4):
                for target in _thumb_successors(image, branch, end):
                    if (target == branch + 2 or not start <= target <= row_site):
                        continue
                    reachable = _thumb_reachable(image, target, compare + 2)
                    if sense in reachable and compare in reachable:
                        return True
        return False
    for current in senses:
        load = struct.unpack_from("<H", image, current)[0]
        value = load & 7
        no_key_guard = any(struct.unpack_from("<H", image, probe)[0] == 0x2800 | value << 8 | 0x1F for probe in range(current + 4, min(current + 0x30, end), 2))
        if no_key_guard and current < row_site:
            global_sites.append(current)
        if current >= row_site and closes_six_row_loop(current):
            row_sites.append(current)
    return global_sites, row_sites

def _row_register(image: bytes, start: int, end: int, row_sites: list[int]) -> int | None:
    """Require one local counter to index and close the exact six-row loop."""
    from . import _descending_row_register, _thumb_path_preserves_register, _thumb_reachable, _thumb_successors, struct
    if not row_sites:
        return None
    if (register := _descending_row_register(image, start, end, min(row_sites))) is not None:
        return register
    candidates: list[int] = []
    first = min(row_sites)
    for register in range(8):
        normalize = (0x0600 | register << 3 | register, 0x0E00 | register << 3 | register,)
        for increment in range(first, end - 9, 2):
            if struct.unpack_from("<5H", image, increment)[:4] != (0x3001 | register << 8, *normalize, 0x2806 | register << 8):
                continue
            branch = increment + 8
            branch_word = struct.unpack_from("<H", image, branch)[0]
            targets = [target for target in _thumb_successors(image, branch, end) if target != branch + 2]
            loop_start = (targets[0] if len(targets) == 1 and targets[0] <= first else None)
            if (loop_start is None and branch_word & 0xF000 == 0xD000 and (branch_word & 0x0F00) < 0x0E00 and branch + 4 <= end):
                back = branch + 2
                back_word = struct.unpack_from("<H", image, back)[0]
                back_targets = [target for target in _thumb_successors(image, back, end) if target != back + 2]
                if (back_word & 0xF800 == 0xE000 and len(back_targets) == 1 and back_targets[0] <= first):
                    loop_start = back_targets[0]
            if loop_start is None or not start <= loop_start <= first:
                continue
            reachable = _thumb_reachable(image, loop_start, increment)
            if (not all(site in reachable for site in row_sites) or not any(struct.unpack_from("<H", image, site)[0] & 0xFE00 == 0x5C00 and struct.unpack_from("<H",
                image, site)[0] >> 6 & 7 == register for site in reachable)):
                continue
            zeroes = [site for site in range(start, loop_start, 2) if struct.unpack_from("<H", image, site)[0] == 0x2000 | register << 8 and
                _thumb_path_preserves_register(image, site + 2, loop_start, end, register)]
            if zeroes:
                candidates.append(register)
                break
    return candidates[0] if len(candidates) == 1 else None

def find_lg_descriptor_keypad_candidates(image: bytes, load_address: int = 0, _anchors: tuple[dict[str, object], ...] | None = None,) -> list[dict[str, object]]:
    """Recover static LG low5 descriptor-to-raw candidates; never transport."""
    from . import DESCRIPTOR_MMIO_ROLES, LG_DESCRIPTOR_RAW_FINGERPRINT, _descriptor_mmio_provenance, _descriptor_pointer, _event_table, _low5_senses, _observed_lg_mappings, _row_bounds, _table_base, _thumb_callable_entry, _thumb_inbound_entries, defaultdict, facts_for, find_descriptor_scan_anchors
    found: list[dict[str, object]] = []
    for anchor in (_anchors if _anchors is not None else find_descriptor_scan_anchors(image, load_address)):
        prologue = int(anchor["function"]) - load_address
        end = min(prologue + 0x900, len(image) - 3)
        senses = _low5_senses(image, prologue, end)
        descriptor = _descriptor_pointer(image, prologue,[sense_site for sense_site, _ in senses],)
        if descriptor is None or not senses or not {5, 6}.issubset(_row_bounds(image, prologue, end)):
            continue
        columns = [(site, register, _table_base(image, prologue, end, register)) for site, register in senses]
        columns = [(site, table) for site, _, table in columns if table is not None]
        # The scanner can reread D+34; the final table-indexed read is its decode.
        if not columns:
            continue
        sense_site, column = columns[-1]
        event_table = _event_table(image, prologue, end)
        if event_table is None:
            continue
        calls: dict[int, list[int]] = defaultdict(list)
        for callsite in range(prologue, end, 2):
            target = facts_for(image).thumb_call_target(callsite)
            if target is not None and prologue - 0x400 <= target < prologue:
                calls[target].append(callsite)
        raw_sinks = [(target, sites) for target, sites in calls.items() if len(sites) >= 8]
        if len(raw_sinks) != 1:
            continue
        raw_sink, callsites = raw_sinks[0]
        entry = _thumb_callable_entry(image, prologue, _thumb_inbound_entries(image, {prologue - 2}))
        table_address, table = column
        active_senses = [0x1F ^ (1 << bit) for bit in range(5)]
        inverted = [next(value for value in active_senses if table[value] == column) for column in range(5)]
        events_address, events = event_table
        provenance = _descriptor_mmio_provenance(image, descriptor)
        candidate = { "grammar": LG_DESCRIPTOR_RAW_FINGERPRINT, "grammar_fingerprint": LG_DESCRIPTOR_RAW_FINGERPRINT, "evidence": "static-scan-to-raw-enqueue",
            "function": load_address + entry, "prologue": load_address + prologue, "callable_entry_evidence": "inbound-pre-push" if entry != prologue else
            "push", "descriptor_pointer": descriptor, "sense_site": load_address + sense_site, "sense_sites":[load_address + site for site, _ in senses],
            "sense_pointer_offset": 0x34, "sense_bits": 5, "no_key": 0x1F, "rows": 6, "columns": 5, "column_table": load_address + table_address, "column_map":
            table, "single_key_column_sense": inverted, "column_sense_map": "firmware-table-derived", "event_table": load_address + events_address,
            "event_codes": events, "event_table_formula": "event_codes[column * 6 + row]", "raw_enqueue": load_address + raw_sink, "raw_enqueue_callsite":
            load_address + callsites[0], "raw_enqueue_callsites":[load_address + site for site in callsites], "absolute_roles": ({"control":
            DESCRIPTOR_MMIO_ROLES[0], "row_drive": DESCRIPTOR_MMIO_ROLES[0x20], "sense": DESCRIPTOR_MMIO_ROLES[0x34]} if provenance else None),
            "descriptor_mmio_provenance": provenance["kind"] if provenance else None, "semantic_limit":
            "static candidate only; physical transport remains unproven", }
        mappings = _observed_lg_mappings(events)
        if mappings:
            candidate["provisional_mappings"] = mappings
        found.append(candidate)
    return found

def resolve_lg_descriptor_input(image: bytes, load_address: int = 0) -> tuple[dict[str, object] | None, str, list[dict[str, object]]]:
    """Accept exactly one fully cross-checked static candidate, no timer/runtime."""
    from . import ASCII_KEY_EVENTS, LG_DESCRIPTOR_RAW, _raw_consumer_metadata, _row_order, _row_register, _row_state, _sense_roles, facts_for, find_descriptor_ram_scan_shapes, find_descriptor_scan_anchors, find_lg_descriptor_keypad_candidates
    anchors = tuple(find_descriptor_scan_anchors(image, load_address))
    shapes = find_descriptor_ram_scan_shapes(image, load_address, anchors)
    accepted, rejected = [],[]
    for candidate in find_lg_descriptor_keypad_candidates(image, load_address, anchors):
        reasons: list[str] = []
        matching = [shape for shape in shapes if (shape["row_bounds"] ==[5, 6] or shape.get("row_order_evidence") == "direct-descending-loop") and shape["descriptor_pointer"]
            == candidate["descriptor_pointer"] and shape["sense_site"] == candidate["sense_site"] and abs(int(shape["function"]) - int(candidate["prologue"]))
            <= 2]
        if candidate["descriptor_mmio_provenance"] is None:
            reasons.append("descriptor-mmio-provenance-missing")
        if len(matching) != 1:
            reasons.append("matching-ram-shape-not-unique")
            row_order = None
        else:
            start = int(matching[0]["function"]) - load_address
            row_order = _row_order(image, start, start + int(matching[0]["fingerprint_size"]), int(candidate["sense_site"]) - load_address,)
            if row_order is None:
                reasons.append("row-order-not-proven")
        events = candidate["event_codes"]
        if any(events.count(event) != 1 for event in ASCII_KEY_EVENTS):
            reasons.append("numeric-events-not-unique")
        sites = candidate["raw_enqueue_callsites"]
        if not sites or any(facts_for(image).thumb_call_target(site - load_address) != candidate["raw_enqueue"] - load_address for site in sites):
            reasons.append("raw-enqueue-callsites-not-exact")
        if reasons:
            rejected.append({"function": candidate["function"], "grammar": candidate["grammar"], "reasons": reasons})
        else:
            candidate = {**candidate, "family": LG_DESCRIPTOR_RAW, "row_order": row_order[0], "row_order_evidence": row_order[1]}
            consumer = _raw_consumer_metadata(image, int(candidate["raw_enqueue"]), list(candidate["event_codes"]), load_address,)
            if consumer is not None:
                candidate.update(consumer)
            global_sites, row_sites = _sense_roles(image, start, start + int(matching[0]["fingerprint_size"]), int(candidate["descriptor_pointer"]), int(candidate["sense_site"])
                - load_address)
            candidate.update({"global_sense_sites":[site + load_address for site in global_sites], "row_sense_sites":[site + load_address for site in row_sites]})
            row_register = _row_register(image, start, start + int(matching[0]["fingerprint_size"]), row_sites)
            if row_register is not None:
                candidate["row_register"] = row_register
                candidate["row_register_evidence"] = ("five-indexed-descending-ldrb-six-row-backedge" if row_order[1] == "direct-descending-loop" else
                    "zero-indexed-ldrb-six-row-backedge")
            state = _row_state(image, start, start + int(matching[0]["fingerprint_size"]))
            if state is not None:
                candidate.update({"row_state_address": state[0], "row_state_offset": state[1], "row_state_site": state[2] + load_address, "row_state_evidence":
                    state[3]})
            accepted.append(candidate)
    if len(accepted) == 1:
        return accepted[0], "accepted", rejected
    if len(accepted) > 1:
        rejected.extend({"function": candidate["function"], "grammar": candidate["grammar"], "reasons":["multiple-accepted-scanners"]} for candidate in accepted)
        return None, "ambiguous", rejected
    return None, "rejected" if rejected else "not-found", rejected
