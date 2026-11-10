from __future__ import annotations

def _samsung_raw_saved_consumer_metadata(image: bytes, event_sink: int, event_codes: list[int], load_address: int,) -> dict[str, object] | None:
    """Recover semantic ring32 variants using r4/r7 across the task call."""
    from . import SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE, _thumb_reachable, _thumb_reachable_preserving_register, _thumb_successors, facts_for, find_all, struct
    end = min(len(image), event_sink + 0x100)
    reachable = _thumb_reachable(image, event_sink, end)
    stores = [current for current in reachable if current >= event_sink + 2 and struct.unpack_from("<2H", image, current - 2) == (0x1880, 0x7087)]
    pairs: list[tuple[int, int]] = []
    for store in stores:
        rings = [value for current in range(max(event_sink, store - 0x80), store, 2) if struct.unpack_from("<H", image, current)[0] & 0xFF00 == 0x4A00 and (value
            := facts_for(image).thumb_literal_value(current, 2)) is not None and 0x01000000 <= value < 0x04000000]
        if len(rings) == 1:
            pairs.append((store, rings[0]))
    if len(pairs) != 1:
        return None
    store, ring = pairs[0]
    dequeues = []
    for body in find_all(image, bytes.fromhex("50781178884201d10020")):
        dequeue = body - 2
        if dequeue < 0 or dequeue & 1 or dequeue + 28 > len(image):
            continue
        words = struct.unpack_from("<14H", image, dequeue)
        if (facts_for(image).thumb_literal_value(dequeue, 2) == ring and words[1:6] == (0x7850, 0x7811, 0x4288, 0xD101, 0x2000) and words[6] in (0x46F7, 0x4770)
            and words[7:13] == (0x1888, 0x3101, 0x06C9, 0x0EC9, 0x7880, 0x7011) and words[13] in (0x46F7, 0x4770)):
            dequeues.append(dequeue)
    if len(dequeues) != 1:
        return None
    dequeue = dequeues[0]
    tasks: list[tuple[int, int, int]] = []
    for register, move in ((4, 0x1C04), (7, 0x1C07)):
        for position in find_all(image, struct.pack("<H", move)):
            call = position - 4
            if (call < 0 or call & 1 or call + 12 > len(image) or facts_for(image).thumb_call_target(call) != dequeue or struct.unpack_from("<H", image, call +
                6)[0] & 0xFF00 != 0xD000):
                continue
            task = facts_for(image).thumb_call_target(call + 8)
            if task is None or not 0 <= task <= len(image) - 2 or task & 1:
                continue
            branches = _thumb_successors(image, call + 6, len(image))
            if set(branches) != {call + 8, call + 12}:
                continue
            compare_base = 0x2800 | register << 8
            compared = { struct.unpack_from("<H", image, current)[0] & 0xFF for current in _thumb_reachable_preserving_register(image, task, min(len(image),
                task + 0x1000), register) if struct.unpack_from("<H", image, current)[0] & 0xFF00 == compare_base and struct.unpack_from("<H", image, current)[0]
                & 0xFF in event_codes }
            if len(compared) >= 3:
                tasks.append((call, task, register))
    if len(tasks) != 1:
        return None
    call, task, register = tasks[0]
    return { "raw_ring": ring, "raw_ring_capacity": 32, "raw_enqueue_store": load_address + store, "raw_enqueue_register": 7, "raw_dequeue": load_address +
        dequeue, "raw_dequeue_return": load_address + call + 4, "raw_task_entry": load_address + task, "raw_task_register": register, "raw_consumer_evidence":
        SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE, }

def _samsung_consumer_route_handler(image: bytes, metadata: dict[str, object], load_address: int) -> tuple[int, str] | None:
    """Recover the r7 handler already closed by Samsung raw-consumer evidence."""
    from . import SAMSUNG_RAW_CONSUMER_EVIDENCE, SAMSUNG_RAW_R7_CONSUMER_EVIDENCE, _thumb_successors, struct
    entry = metadata.get("raw_task_entry")
    register = metadata.get("raw_task_register")
    evidence = metadata.get("raw_consumer_evidence")
    if type(entry) is not int or type(register) is not int:
        return None
    entry -= load_address
    if not 0 <= entry <= len(image) - 2 or entry & 1:
        return None
    if register == 7:
        if evidence != SAMSUNG_RAW_R7_CONSUMER_EVIDENCE:
            return None
        return entry, evidence
    if register != 0 or evidence != SAMSUNG_RAW_CONSUMER_EVIDENCE:
        return None
    if (entry + 6 > len(image) or struct.unpack_from("<2H", image, entry) != (0x1C07, 0xD000) or struct.unpack_from("<H", image, entry + 4)[0] & 0xF800 !=
        0xE000):
        return None
    targets = _thumb_successors(image, entry + 4, len(image))
    if len(targets) != 1:
        return None
    handler = targets[0]
    if not 0 <= handler <= len(image) - 2 or handler & 1:
        return None
    return handler, evidence

def _samsung_route_match(image: bytes, compare: int, end: int) -> tuple[str, int] | None:
    """Follow r7 equality through an immediate conditional or one plain B."""
    from . import _thumb_successors, struct
    current = compare + 2
    for hop in range(2):
        if not 0 <= current <= end - 2:
            return None
        word = struct.unpack_from("<H", image, current)[0]
        condition = word & 0xFF00
        if condition in (0xD000, 0xD100):
            successors = _thumb_successors(image, current, end)
            fallthrough = current + 2
            targets = [target for target in successors if target != fallthrough]
            if len(successors) != 2 or len(targets) != 1:
                return None
            matched = targets[0] if condition == 0xD000 else fallthrough
            if not 0 <= matched <= end - 2:
                return None
            return ("eq" if condition == 0xD000 else "ne"), matched
        if hop or word & 0xF800 != 0xE000:
            return None
        targets = _thumb_successors(image, current, end)
        if len(targets) != 1:
            return None
        current = targets[0]
    return None

def _samsung_consumer_route_metadata(image: bytes, metadata: dict[str, object], load_address: int) -> dict[str, object]:
    """Fingerprint closed r7 event routes without assigning key semantics."""
    from . import _SAMSUNG_CONSUMER_ROUTE_EVENTS, _SAMSUNG_CONSUMER_ROUTE_EVIDENCE, _SAMSUNG_CONSUMER_ROUTE_LIMIT, _samsung_consumer_route_handler, _samsung_route_match, _thumb_fingerprint, _thumb_reachable_preserving_register, hashlib, json, struct
    recovered = _samsung_consumer_route_handler(image, metadata, load_address)
    if recovered is None:
        return { "consumer_route_status": "not-closed", "consumer_route_reject_reason": "handler-unclosed", }
    handler, handoff = recovered
    end = min(len(image), handler + _SAMSUNG_CONSUMER_ROUTE_LIMIT)
    reachable = _thumb_reachable_preserving_register(image, handler, end, 7)
    event_fingerprints: dict[str, str] = {}
    for event in _SAMSUNG_CONSUMER_ROUTE_EVENTS:
        occurrences: list[tuple[str, str, int, str]] = []
        for compare in sorted(reachable):
            if struct.unpack_from("<H", image, compare)[0] != (0x2F00 | event):
                continue
            match = _samsung_route_match(image, compare, end)
            if match is None:
                return {
                    "consumer_route_status": "not-closed",
                    "consumer_route_reject_reason": (
                        f"event-{event:02x}-condition-unclosed"
                    ),
                }
            condition, route = match
            fingerprint, size, boundary = _thumb_fingerprint(image, route)
            occurrences.append((condition, fingerprint, size, boundary))
        if not occurrences:
            return {
                "consumer_route_status": "not-closed",
                "consumer_route_reject_reason": f"event-{event:02x}-missing",
            }
        encoded = json.dumps(sorted(occurrences), separators=(",", ":")).encode()
        event_fingerprints[f"0x{event:02X}"] = hashlib.sha256(encoded).hexdigest()
    encoded = json.dumps({"handoff": handoff, "events": event_fingerprints}, sort_keys=True, separators=(",", ":"),).encode()
    return { "consumer_route_status": "closed", "consumer_route_evidence": _SAMSUNG_CONSUMER_ROUTE_EVIDENCE, "consumer_route_fingerprint": hashlib.sha256(encoded).hexdigest(),
        "consumer_route_event_fingerprints": event_fingerprints, }

def _thumb_inbound_entries(image: bytes, entries: set[int]) -> set[int]:
    """Find pointers and direct BL edges with a bounded candidate count."""
    from . import THUMB_BL, facts_for
    inbound: set[int] = set()
    remaining = set(entries)
    for entry in tuple(remaining):
        if (entry | 1).to_bytes(4, "little") in image:
            inbound.add(entry)
            remaining.remove(entry)
    if not remaining:
        return inbound
    for match in THUMB_BL.finditer(image):
        callsite = match.start()
        if callsite & 1:
            continue
        target = facts_for(image).thumb_call_target(callsite)
        if target in remaining:
            inbound.add(target)
            remaining.remove(target)
            if not remaining:
                break
    return inbound

def _find_n330_5x6_scanners(image: bytes, load_address: int) -> list[dict[str, object]]:
    """Recover the closed temporary N330 producer grammar."""
    from . import N330_5X6_ENTRY, N330_5X6_FINGERPRINT, N330_GLOBAL_SENSE, N330_PRESS_PREFIX, N330_RELEASE_PREFIX, N330_ROW_SENSE, PRODUCER_FEATURES, SAMSUNG_DUAL_PLANE_RING32, _matches_relocated_thumb_bl, classify_matrix_event_sink, facts_for, struct
    found: list[dict[str, object]] = []
    start = 0
    while True:
        scanner = image.find(N330_5X6_ENTRY[:12], start)
        if scanner < 0:
            return found
        start = scanner + 1
        press = scanner + 0x3EC
        release = scanner + 0x472
        press_call = press + len(N330_PRESS_PREFIX)
        release_call = release + len(N330_RELEASE_PREFIX)
        if (not _matches_relocated_thumb_bl(image, scanner, N330_5X6_ENTRY, 0x0C) or image[scanner + 0x6A: scanner + 0x6A + len(N330_GLOBAL_SENSE)] !=
            N330_GLOBAL_SENSE or image[scanner + 0xF8:scanner + 0xF8 + len(N330_ROW_SENSE)] != N330_ROW_SENSE or not _matches_relocated_thumb_bl(image, press,
            N330_PRESS_PREFIX, 0x1A) or image[release:release_call] != N330_RELEASE_PREFIX):
            continue
        queue = facts_for(image).thumb_call_target(press_call)
        if queue is None or facts_for(image).thumb_call_target(release_call) != queue:
            continue
        producer = classify_matrix_event_sink(image, queue)
        if (producer["family"] != SAMSUNG_DUAL_PLANE_RING32 and not all(producer.get("features", {}).get(feature) for feature in PRODUCER_FEATURES[SAMSUNG_DUAL_PLANE_RING32])):
            continue
        literals = (scanner + 0x6A0, scanner + 0x90C)
        if any(literal + 4 > len(image) for literal in literals):
            continue
        pointers = tuple(struct.unpack_from("<I", image, literal)[0] for literal in literals)
        table = pointers[0] - load_address
        if (len(set(pointers)) != 1 or table < 0 or table + 30 > len(image)):
            continue
        events = list(image[table:table + 30])
        if events.count(0) != 5 or events[-5:] !=[0] * 5:
            continue
        found.append({ "grammar": "n330-5x6-dual-plane-ring32-v1", "grammar_fingerprint": N330_5X6_FINGERPRINT, "evidence":
            "relocation-normalized-entry+press-release+table-xrefs", "function": load_address + scanner, "sense_site": load_address + scanner + 0xFC,
            "global_sense_sites":[load_address + scanner + 0x6E], "row_sense_sites":[load_address + scanner + 0xFC], "register": 0x09000070, "register_size": 4,
            "register_reset": 0x1F, "row_register": 5, "rows": 6, "columns": 5, "sense_mask": 0x1F, "no_key": 0x1F, "single_key_column_sense":[0x1E, 0x1D, 0x1B,
            0x17, 0x0F], "dynamic_mapped_sense": True, "mmio_map_start": 0x09000000, "mmio_map_size": 0x1000, "event_table": pointers[0], "event_table_bytes":
            events, "event_codes": events, "event_table_formula": "event_codes[column * 6 + row]", "event_table_literal_xrefs":[load_address + literal for
            literal in literals], "event_sink_callsite": load_address + press_call, "event_sink": load_address + queue, "event_sink_family":
            SAMSUNG_DUAL_PLANE_RING32, "event_sink_validation": "required-dual-plane-queue-features", "press_event_load": load_address + press,
            "release_event_load": load_address + release, "release_callsite": load_address + release_call, "release_grammar":
            "event-plus-0x80; invalid fallback=0x80", })

def find_direct_matrix_scanners(image: bytes, load_address: int = 0) -> list[dict[str, object]]:
    """Find a direct-MMIO six-row keypad decode-to-call grammar."""
    from . import DIRECT_MATRIX_FINGERPRINT, DIRECT_MATRIX_TAIL, MAX_DIRECT_MATRIX_TAILS, SINGLE_KEY_COLUMN_SENSE, UNCLASSIFIED, _find_n330_5x6_scanners, _samsung_sideband_51_family_metadata, _samsung_sideband_51_metadata, _thumb_callable_entry, _thumb_fingerprint, _thumb_function_start, _thumb_inbound_entries, _thumb_path_preserves_register, _thumb_reachable, _thumb_successors, facts_for, struct, validate_matrix_event_sink
    found: dict[int, dict[str, object]] = {}
    sites: list[int] = []
    for match in DIRECT_MATRIX_TAIL.finditer(image):
        if not match.start() & 1:
            sites.append(match.start())
            if len(sites) > MAX_DIRECT_MATRIX_TAILS:
                return []
    prologues = { site: _thumb_function_start(image, site) for site in sites }
    possible_entries = { prologue - 2 for prologue in prologues.values() if (prologue >= 2 and struct.unpack_from("<H", image, prologue - 2)[0] & 0xF800 ==
        0x4800) }
    inbound_entries = _thumb_inbound_entries(image, possible_entries)
    for site in sites:
        table_load = struct.unpack_from("<H", image, site + 24)[0]
        if table_load & 0xFE00 != 0x5C00 or table_load >> 3 & 7:
            continue
        row_register = table_load >> 6 & 7
        key_register = table_load & 7
        if row_register in (0, 1, 3):
            continue
        prologue = prologues[site]
        start = _thumb_callable_entry(image, prologue, inbound_entries)
        no_key_branch = struct.unpack_from("<H", image, site + 10)[0]
        branch_delta = (no_key_branch & 0xFF) << 1
        if branch_delta & 0x100:
            branch_delta -= 0x200
        row_increment = site + 14 + branch_delta
        if not site + 26 <= row_increment <= len(image) - 12:
            continue
        increment_words = struct.unpack_from("<3H", image, row_increment)
        normalize_row = (0x0600 | row_register << 3 | row_register, 0x0E00 | row_register << 3 | row_register,)
        same_register_increment = (0x3001 | row_register << 8, *normalize_row,)
        temporary_r0_increment = (0x1C40 | row_register << 3, 0x0600 | row_register, normalize_row[1],)
        if increment_words not in (same_register_increment, temporary_r0_increment):
            continue
        if (struct.unpack_from("<H", image, row_increment + 6)[0] != 0x2806 | row_register << 8):
            continue
        def valid_loop_target(target: int) -> bool:
            return (start + 2 <= target < site and struct.unpack_from("<H", image, target - 2)[0] == (0x2000 | row_register << 8))
        branch = row_increment + 8
        branch_word = struct.unpack_from("<H", image, branch)[0]
        branch_targets = [target for target in _thumb_successors(image, branch, len(image)) if target != branch + 2]
        row_loop_start = None
        row_loop_shape = None
        if (branch_word & 0xFF00 == 0xDB00 and len(branch_targets) == 1 and valid_loop_target(branch_targets[0])):
            row_loop_start = branch_targets[0]
            row_loop_shape = "conditional-back"
        elif (branch_word & 0xFF00 == 0xDA00 and len(branch_targets) == 1 and branch + 2 < branch_targets[0] < min(site + 0x120, len(image))):
            back_branch = branch + 2
            back_word = struct.unpack_from("<H", image, back_branch)[0]
            back_targets = [target for target in _thumb_successors(image, back_branch, len(image)) if target != back_branch + 2]
            if (back_word & 0xF800 == 0xE000 and len(back_targets) == 1 and valid_loop_target(back_targets[0])):
                row_loop_start = back_targets[0]
                row_loop_shape = "guard-then-back"
        if row_loop_start is None:
            continue
        if site not in _thumb_reachable(image, row_loop_start, row_increment):
            continue
        move_to_r0 = 0x1C00 | key_register << 3
        sink_calls: list[tuple[int, int]] = []
        sink_search_end = min(site + 0x120, len(image) - 3)
        reachable = _thumb_reachable(image, site + 26, sink_search_end)
        for current in reachable:
            word = struct.unpack_from("<H", image, current)[0]
            if word != move_to_r0 or current + 6 > sink_search_end:
                continue
            target = facts_for(image).thumb_call_target(current + 2)
            if (target is not None and 0 <= target < len(image) and _thumb_path_preserves_register(image, site + 26, current, sink_search_end, key_register)):
                sink_calls.append((current + 2, target))
        if len(sink_calls) != 1:
            continue
        sink_callsite, sink = sink_calls[0]
        register_base = facts_for(image).thumb_literal_value(site, 0)
        column_table_address = facts_for(image).thumb_literal_value(site + 12, 1)
        column_table = (column_table_address - load_address if column_table_address is not None else -1)
        if (register_base is None or register_base != 0x03000690 or not 0x18 <= column_table <= len(image) - 0x10):
            continue
        fingerprint, function_size, boundary = _thumb_fingerprint(image, start)
        event_table = column_table - 0x18
        column_map = list(image[column_table:column_table + 0x10])
        if[column_map[value] for value in SINGLE_KEY_COLUMN_SENSE] != list(range(4)):
            continue
        producer = validate_matrix_event_sink(image, sink_callsite, sink)
        family = str(producer["family"])
        found[start] = { "grammar": "direct-low-nibble-6-row-v1", "grammar_fingerprint": DIRECT_MATRIX_FINGERPRINT, "evidence": "static-scan-to-call",
            "function": load_address + start, "prologue": load_address + prologue, "callable_entry_evidence": ("pc-literal+inbound-reference+post-push-consumer"
            if start != prologue else "push"), "sense_site": load_address + site, "register": register_base + 4, "row_register": row_register, "key_register":
            key_register, "event_sink_callsite": load_address + sink_callsite, "event_sink": load_address + sink, "event_sink_family": None if family ==
            UNCLASSIFIED else family, "event_sink_validation": ("required-queue-features" if family != UNCLASSIFIED else "argument-edge-only"), "row_init":
            load_address + row_loop_start - 2, "row_loop_start": load_address + row_loop_start, "row_loop_shape": row_loop_shape, "rows": 6, "columns": 4,
            "sense_bits": 4, "no_key": 0xF, "column_table": column_table_address, "column_map": column_map, "single_key_column_sense": list(SINGLE_KEY_COLUMN_SENSE),
            "event_table": load_address + event_table, "event_codes": list(image[event_table:event_table + 0x18]), "event_table_formula":
            "event_codes[column * 6 + row]", "fingerprint": fingerprint, "fingerprint_size": function_size, "fingerprint_scope": "linear-prefix",
            "fingerprint_boundary": boundary, }
        sideband = _samsung_sideband_51_metadata(image, start, sink, load_address)
        if not sideband:
            sideband = _samsung_sideband_51_family_metadata(image, start, site, sink, load_address)
        found[start].update(sideband)
    return ([_ for _ in _find_n330_5x6_scanners(image, load_address)] +[found[start] for start in sorted(found)])

def resolve_direct_matrix_input(image: bytes, load_address: int = 0) -> tuple[dict[str, object] | None, str, list[dict[str, object]]]:
    """Resolve one safe profile and retain exact candidate reject reasons."""
    from . import ASCII_KEY_EVENTS, SAMSUNG_DUAL_PLANE_RING32, SAMSUNG_RING32, _same_image_keyemu_ok_mapping, _same_image_ring32_confirm_mapping, _same_image_selected_confirm_mapping, _samsung_consumer_route_metadata, _samsung_flags_sideband_51_metadata, _samsung_raw_consumer_metadata, _samsung_raw_r7_consumer_metadata, _samsung_raw_saved_consumer_metadata, detect_keyemu_semantics, find_direct_matrix_scanners
    scanners = find_direct_matrix_scanners(image, load_address)
    accepted: list[dict[str, object]] = []
    rejected: list[dict[str, object]] = []
    for scanner in scanners:
        events = scanner["event_codes"]
        reasons: list[str] = []
        if any(producer.get("event") in events for producer in scanner.get("sideband_producers", ()) if isinstance(producer, dict)):
            reasons.append("sideband-event-conflicts-with-matrix")
        if scanner["event_sink_family"] is None:
            reasons.append("event-sink-family-unclassified")
        if scanner["event_sink_family"] != SAMSUNG_DUAL_PLANE_RING32:
            if any(events.count(event) == 0 for event in ASCII_KEY_EVENTS):
                reasons.append("numeric-event-missing")
            if any(events.count(event) > 1 for event in ASCII_KEY_EVENTS):
                reasons.append("numeric-event-duplicated")
        if reasons:
            rejected.append({ "function": scanner["function"], "grammar_fingerprint": scanner["grammar_fingerprint"], "reasons": reasons, })
        else:
            if scanner["event_sink_family"] == SAMSUNG_RING32:
                metadata = _samsung_raw_consumer_metadata(image, int(scanner["event_sink"]) - load_address, load_address,)
                if metadata is None:
                    metadata = _samsung_raw_r7_consumer_metadata(image, int(scanner["event_sink"]) - load_address, list(events), load_address,)
                if metadata is None:
                    metadata = _samsung_raw_saved_consumer_metadata(image, int(scanner["event_sink"]) - load_address, list(events), load_address,)
                if metadata is not None:
                    scanner.update(metadata)
                    scanner.update(_samsung_consumer_route_metadata(image, metadata, load_address,))
                    if scanner.get("sideband_detection_status") != "accepted":
                        sideband = _samsung_flags_sideband_51_metadata(image, scanner, load_address)
                        if sideband:
                            scanner.update(sideband)
                else:
                    scanner["consumer_route_status"] = "raw-consumer-not-closed"
            accepted.append(scanner)
    if len(accepted) == 1:
        profile = accepted[0]
        mappings = _same_image_keyemu_ok_mapping(profile, detect_keyemu_semantics(image, load_address))
        if not mappings and profile["event_sink_family"] == SAMSUNG_RING32:
            mappings, ok_metadata = _same_image_ring32_confirm_mapping(image, profile, load_address,)
            if not mappings:
                original_reasons = ok_metadata.get("ok_mapping_reject_reasons",[])
                mappings, selected_metadata = _same_image_selected_confirm_mapping(image, profile, load_address,)
                if not mappings:
                    selected_metadata["ok_mapping_reject_reasons"] = (original_reasons + selected_metadata["ok_mapping_reject_reasons"])
                ok_metadata = selected_metadata
            profile.update(ok_metadata)
        if mappings:
            profile["provisional_mappings"] = mappings
        return profile, "accepted", rejected
    if len(accepted) > 1:
        rejected.extend({ "function": scanner["function"], "grammar_fingerprint": scanner["grammar_fingerprint"], "reasons":["multiple-accepted-scanners"], }
            for scanner in accepted)
        return None, "ambiguous", rejected
    return None, "rejected" if rejected else "not-found", rejected

def detect_direct_matrix_input(image: bytes, load_address: int = 0) -> dict[str, object] | None:
    """Return one queue-closed scanner with an unambiguous numeric layout."""
    from . import resolve_direct_matrix_input
    return resolve_direct_matrix_input(image, load_address)[0]

def _distributed_word(image: bytes, pc: int) -> int:
    from . import struct
    return struct.unpack_from('<H', image, pc)[0] if 0 <= pc <= len(image) - 2 else -1
