from __future__ import annotations
from msm5xxx_emulator.detection.fact_bodies import thumb_body

def _same_image_selected_confirm_mapping(image: bytes, profile: dict[str, object], load_address: int,) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    """Temporary functional activation, with no physical OK name claim."""
    from . import SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE, SAMSUNG_RING32, _SAMSUNG_SELECTED_CONFIRM_CALLS, _SAMSUNG_SELECTED_CONFIRM_CONTRACTS, _SAMSUNG_SELECTED_CONFIRM_R7_CALLS, _SAMSUNG_SELECTED_CONFIRM_R7_CONTRACTS, _thumb_reachable_preserving_register, facts_for, find_all, hashlib, struct
    def reject(reason: str):
        return {}, {"ok_mapping_status": "rejected", "ok_mapping_reject_reasons":["selected-confirm-" + reason] }
    register = profile.get("raw_task_register")
    contracts = (_SAMSUNG_SELECTED_CONFIRM_R7_CONTRACTS if register == 7 else _SAMSUNG_SELECTED_CONFIRM_CONTRACTS)
    calls = (_SAMSUNG_SELECTED_CONFIRM_R7_CALLS if register == 7 else _SAMSUNG_SELECTED_CONFIRM_CALLS)
    def shape(at: int | None, name: str) -> bool:
        size, digest = contracts[name]
        links = calls.get(name, ())
        if at is None or at & 1:
            return False
        body = thumb_body(facts_for(image), at, size, literal_offsets=(), call_fill=bytes.fromhex('00f000f8'))
        if body is None or body.sha256 != digest:
            return False
        targets = dict(body.calls)
        return all(0 <= at + delta <= len(image)-2 and targets.get(offset) == at + delta for offset, delta in links)
    def ram(value: int | None, size: int = 4) -> bool:
        return (type(value) is int and not value & 3 and 0x01000000 <= value <= 0x04000000 - size)
    def literal(at: int, register: int) -> int | None:
        return facts_for(image).thumb_literal_value(at, register)
    if (profile.get("grammar") != "direct-low-nibble-6-row-v1" or (profile.get("rows"), profile.get("columns")) != (6, 4) or profile.get("event_sink_family") !=
        SAMSUNG_RING32 or profile.get("raw_consumer_evidence") != SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE or type(register) is not int or register not in (4, 7)):
        return reject("scanner-consumer-unclosed")
    events = profile.get("event_codes", ())
    if not isinstance(events, (list, tuple)) or events.count(0x53) != 1:
        return reject("namespace-not-unique")
    fields = [profile.get(key) for key in ("raw_dequeue", "raw_dequeue_return", "raw_task_entry", "raw_ring")]
    if any(type(value) is not int for value in fields):
        return reject("raw-task-unclosed")
    dequeue, returned, task, raw_ring = fields
    dequeue, returned, task = (value - load_address for value in (dequeue, returned, task))
    # Saved-task metadata binds dequeue to the preserved event register and task.
    # Its loop forwards that same register to the class-qualified producer.
    if not ram(raw_ring, 0x24) or literal(dequeue, 2) != raw_ring:
        return reject("scanner-ring-mismatch")
    if (not shape(returned - (0x12 if register == 7 else 0x26), "forward") or facts_for(image).thumb_call_target (returned - 4) != dequeue or facts_for(image).thumb_call_target(returned
        + 4) != task or returned - 0xA not in _thumb_reachable_preserving_register(image, task, min(len(image), task + 0x1000), register)):
        return reject("saved-raw-forward-unclosed")
    producer = facts_for(image).thumb_call_target(returned - 8)
    if not shape(producer, "producer"):
        return reject("secondary-producer-unclosed")
    ring = literal(producer + 2, 4)
    if not ram(ring, 0x48) or ring == raw_ring:
        return reject("secondary-ring-unclosed")
    anchor = "164c683c19e0" if register == 7 else "184c683c19e0"
    secondary = [at for at in find_all(image, bytes.fromhex(anchor)) if shape(at, "secondary") and literal(at, 4) == ring + 0x68]
    if len(secondary) != 1:
        return reject("secondary-consumer-missing-or-ambiguous")
    secondary = secondary[0]
    app = facts_for(image).thumb_call_target(secondary + 0x36)
    if not shape(app, "app_entry"):
        return reject("application-entry-unclosed")
    if register == 7:
        publication = app + 0x78
        if (not shape(app + 0x26, "app_global") or not shape(publication, "publication") or not shape(app + 0xC6, "global_read")):
            return reject("publication-unclosed")
        global_key = literal(app + 0x26, 5)
        if (not ram(global_key) or literal(app + 0xC6, 5) != global_key or literal(app + 0xC8, 1) != global_key):
            return reject("application-global-mismatch")
        epilogue = facts_for(image).thumb_call_target(publication + 0x1C)
        if epilogue is None or not shape(epilogue - 0x158, "outer_state"):
            return reject("outer-dispatch-unclosed")
        table = epilogue - 0x140
        if (table < 0 or table + 30 > len(image) or image[table:table + 30] != bytes.fromhex("0f1245151821242d69303669393c693f272a33484b4e515c5f5462576542") or
            not ram(literal(epilogue - 0x158, 6), 0x10)):
            return reject("outer-state-table-unclosed")
        selected_call = table + 2 * image[table + 9]
        handler = facts_for(image).thumb_call_target(selected_call)
        if not shape(selected_call, "selected_call") or not shape(handler, "handler_entry"):
            return reject("selected-handler-unclosed")
        raw_arm, selection, bridge = handler + 0x29A, handler + 0x4A8, handler + 0x144
        if (not shape(raw_arm, "raw_arm") or not shape(selection, "selection") or not shape(bridge, "state_bridge")):
            return reject("selected-event-arm-unclosed")
        event = struct.unpack_from("<H", image, raw_arm + 0x5E)[0] & 0xFF
        owner, local, ui = literal(selection, 0), literal(handler + 2, 7), literal(bridge, 1)
        if (event != 0x53 or not ram(owner, 0x4C) or local != owner + 0x30 or not ram(ui, 0x14) or literal(raw_arm, 0) != global_key or literal(selection + 2, 2)
            != global_key):
            return reject("selected-owner-global-mismatch")
        descriptors = [literal(selection + offset, 3) for offset in (6, 0x38, 0x44, 0x54, 0x60, 0x6E, 0x7A)]
        if any(not ram(value, 0x1C) for value in descriptors) or len(set(descriptors)) != 7:
            return reject("selected-descriptor-unclosed")
        if (bridge + 0x26 > len(image) or struct.unpack_from("<H", image, bridge + 0x24)[0] != 0x6A):
            return reject("selected-state-table-unclosed")
        selected_entry = bridge + 0x1E + 2 * 0x6A
        if (not shape(selected_entry, "selected_entry") or literal(selected_entry + 0x44, 6) != local or literal (selected_entry + 2, 1) != ui):
            return reject("selected-state-entry-unclosed")
        tail = facts_for(image).thumb_call_target(selection + 0x9A)
        if (tail is None or tail < 0 or tail + 4 > len(image) or image[tail:tail + 2] != bytes.fromhex("3872")):
            return reject("selected-state-tail-unclosed")
        # Eight exact original branches join this class's shared return path.
        links = ((2, -0x734), (-0x734, -0xECE), (-0xECE, -0x14B6), (-0x14B6, -0x17C4), (-0x17C4, -0x1F86), (- 0x1F86, -0x2706), (-0x2706, -0x2EFA), (-0x2EFA, -0x2F98))
        for site_offset, target_offset in links:
            site, target = tail + site_offset, tail + target_offset
            if not (0 <= site <= len(image) - 2 and 0 <= target <= len(image) - 2):
                return reject("selected-state-tail-unclosed")
            word = struct.unpack_from("<H", image, site)[0]
            displacement = word & 0x7FF
            if displacement & 0x400:
                displacement -= 0x800
            if word & 0xF800 != 0xE000 or site + 4 + 2 * displacement != target:
                return reject("selected-state-tail-unclosed")
        returned_tail = facts_for(image).thumb_call_target(tail - 0x2F98)
        if (returned_tail is None or not shape(returned_tail, "tail_return") or facts_for(image).thumb_call_target(returned_tail + 6) != bridge):
            return reject("selected-state-bridge-mismatch")
        child = facts_for(image).thumb_call_target(raw_arm + 0x10)
        if not shape(child, "child"):
            return reject("selected-child-install-unclosed")
        if[literal(child + offset, register) for offset, register in ((0x86, 1), (0x14, 6), (0x2E, 1), (0x48, 1), (0x68, 1), (0x58, 1), (0xAC, 1))] != descriptors:
            return reject("selected-descriptor-mismatch")
        if any(literal(child + offset, register) != value for offset, register, value in ((8, 1, global_key), (0x12, 2, owner), (0x132, 2, owner), (0x1E6, 1,
            owner))):
            return reject("selected-child-owner-global-mismatch")
        return {5: {"event": event, "semantic_status": "temporary-evidence-gated-provisional", "functional_only": True, "rule":
            "same-image-selected-functional-confirm-v1", "evidence": "saved-raw-forward+secondary-ring+global-state-dispatch+selected-child-install",
            "raw_dequeue": load_address + dequeue, "application": load_address + app, "consumer": load_address + handler}}, { "ok_mapping_status":
            "accepted-provisional", "ok_mapping_reject_reasons":[]}
    publication = app + 0x4E
    if not shape(publication, "publication") or not shape(app + 0x9A, "global_read"):
        return reject("publication-unclosed")
    global_key = literal(publication + 0xA, 1)
    if (not ram(global_key) or literal(publication + 0x1C, 1) != global_key or literal(app + 0x9A, 1) != global_key):
        return reject("application-global-mismatch")
    outer = facts_for(image).thumb_call_target(publication + 0x16)
    if outer is None or not shape(outer + 0x2E, "outer_state"):
        return reject("outer-dispatch-unclosed")
    switch, table = outer + 0xEC, outer + 0xFC
    if (not shape(switch, "outer_switch") or table + 34 > len(image) or image[table:table + 34] != bytes.fromhex ("111447171a1d2029732c3573383b73413e23262f324a4d505b5e53675661646a6f44")
        or not ram(literal(outer + 0x2E, 5), 0x10)):
        return reject("outer-state-table-unclosed")
    selected_call = table + 2 * image[table + 9]  # state 0x0B, table index 9
    handler = facts_for(image).thumb_call_target(selected_call)
    if not shape(selected_call, "selected_call") or not shape(handler, "handler_entry"):
        return reject("selected-handler-unclosed")
    raw_arm, selection = handler + 0x310, handler + 0x544
    if not shape(raw_arm, "raw_arm") or not shape(selection, "selection"):
        return reject("selected-event-arm-unclosed")
    event = struct.unpack_from("<H", image, raw_arm + 0x5E)[0] & 0xFF
    owner, local, ui = literal(selection, 2), literal(handler + 2, 7), literal(handler + 6, 6)
    if (event != 0x53 or not ram(owner, 0x44) or not ram(local, 0x10) or local != owner + 0x20 or not ram(ui, 0x14) or literal(raw_arm, 0) != global_key or
        literal(selection + 2, 6) != global_key):
        return reject("selected-owner-global-mismatch")
    descriptors = [literal(selection + offset, register) for offset, register in ((6, 3), (0x38, 2), (0x44, 2), (0x54, 2), (0x60, 2))]
    if any(not ram(value, 0x1C) for value in descriptors) or len(set(descriptors)) != 5:
        return reject("selected-descriptor-unclosed")
    tail = facts_for(image).thumb_call_target(selection + 0x72)
    if not shape(tail, "tail") or not shape(tail + 0x70, "tail_return"):
        return reject("selected-state-tail-unclosed")
    bridge = facts_for(image).thumb_call_target(tail + 0x76)
    if (bridge != handler + 0x176 or not shape(bridge, "state_bridge") or literal(bridge, 2) != ui):
        return reject("selected-state-bridge-mismatch")
    inner_table = bridge + 0x22
    if (inner_table + 6 > len(image) or struct.unpack_from("<H", image, inner_table + 4)[0] != 0x86):
        return reject("selected-state-table-unclosed")
    selected_entry = bridge + 0x1E + 2 * 0x86
    if not shape(selected_entry, "selected_entry") or literal(selected_entry, 6) != local:
        return reject("selected-state-entry-unclosed")
    child = facts_for(image).thumb_call_target(raw_arm + 0x12)
    if not shape(child, "child"):
        return reject("selected-child-install-unclosed")
    if[literal(child + offset, register) for offset, register in ((0x78, 1), (0x14, 6), (0x30, 1), (0x4A, 1), (0x5A, 1))] != descriptors:
        return reject("selected-descriptor-mismatch")
    if any(literal(child + offset, register) != value for offset, register, value in ((0x12, 2, owner), (0x1C, 0, global_key), (0xF6, 2, owner), (0x1A2, 2,
        owner))):
        return reject("selected-child-owner-global-mismatch")
    return {5: {"event": event, "semantic_status": "temporary-evidence-gated-provisional", "functional_only": True, "rule":
        "same-image-selected-functional-confirm-v1", "evidence": "saved-raw-forward+secondary-ring+global-state-dispatch+selected-child-install", "raw_dequeue":
        load_address + dequeue, "application": load_address + app, "consumer": load_address + handler}}, { "ok_mapping_status": "accepted-provisional",
        "ok_mapping_reject_reasons":[]}

def _producer_feature_names(word: int) -> tuple[str, ...]:
    names: list[str] = []
    opcode = word & 0xF800
    shift = word >> 6 & 0x1F
    if opcode == 0x2800 and word & 0xFF == 0xFF:
        names.append("compare_0xff")
    if word == 0x2F60:
        names.append("compare_0x60")
    if opcode == 0 and shift == 27:
        names.append("ring32_lsl27")
    if opcode == 0x0800 and shift == 27:
        names.append("ring32_lsr27")
    if opcode == 0 and shift == 24:
        names.append("ring256_lsl24")
    if opcode == 0x0800 and shift == 24:
        names.append("ring256_lsr24")
    if opcode == 0x7000:
        displacement = shift
        if word & 7 == 7 and displacement == 2:
            names.append("event_store_offset_2")
        if word & 7 == 7 and displacement == 4:
            names.append("event_store_offset_4")
        if displacement == 1:
            names.append("byte_write_index_store")
    if opcode == 0x8800:
        displacement = shift * 2
        if displacement == 0:
            names.append("halfword_read_index")
        if displacement == 2:
            names.append("halfword_write_index")
    if opcode == 0x8000 and shift * 2 == 2:
        names.append("halfword_write_index_store")
    return tuple(names)

def _thumb_linear_return(image: bytes, current: int, start: int) -> bool:
    from . import struct
    word = struct.unpack_from("<H", image, current)[0]
    if word == 0x4770 or word & 0xFF00 == 0xBD00:
        return True
    if word & 0xFF87 != 0x4700 or current < start + 2:
        return False
    register = word >> 3 & 0xF
    previous = struct.unpack_from("<H", image, current - 2)[0]
    return (register < 8 and previous & 0xFF00 == 0xBC00 and bool(previous & 1 << register))

def classify_matrix_event_sink(image: bytes, event_sink: int, limit: int = 0x300) -> dict[str, object]:
    """Classify queue features present on one reachable path to a return."""
    from . import PRODUCER_FEATURES, SAMSUNG_DUAL_PLANE_RING32, UNCLASSIFIED, _producer_feature_names, _thumb_linear_return, _thumb_successors, struct
    if (event_sink < 0 or event_sink & 1 or event_sink + 4 > len(image) or limit <= 0):
        return {"family": UNCLASSIFIED, "features": {}}
    end = min(len(image), event_sink + limit) & ~1
    names = tuple(dict.fromkeys(name for required in PRODUCER_FEATURES.values() for name in required))
    feature_bits = {name: 1 << index for index, name in enumerate(names)}
    required_masks = { family: sum(feature_bits[name] for name in required) for family, required in PRODUCER_FEATURES.items() }
    features: dict[str, set[int]] = {}
    pending = [(event_sink, 0)]
    reached: set[tuple[int, int]] = set()
    return_masks: list[int] = []
    furthest = event_sink
    state_limit = max(256, (end - event_sink) * 16)
    while pending and len(reached) < state_limit:
        current, mask = pending.pop()
        state = (current, mask)
        if (state in reached or current < event_sink or current >= end or current & 1):
            continue
        reached.add(state)
        furthest = max(furthest, current + 2)
        word = struct.unpack_from("<H", image, current)[0]
        current_names: list[str] = []
        if current == event_sink + 2 and word == 0x1C07:
            current_names.append("event_arg_r0_to_r7")
        if current == event_sink + 2 and word == 0x1C04:
            current_names.append("event_arg_r0_to_r4")
        if current == event_sink + 6 and word == 0x1C0D:
            current_names.append("event_aux_r1_to_r5")
        if word == 0x7084:
            current_names.append("dual_plane_event_store")
        if word == 0x7085:
            current_names.append("dual_plane_aux_store")
        current_names.extend(_producer_feature_names(word))
        for name in current_names:
            features.setdefault(name, set()).add(current)
            mask |= feature_bits[name]
        if _thumb_linear_return(image, current, event_sink):
            return_masks.append(mask)
            continue
        pending.extend((successor, mask) for successor in _thumb_successors(image, current, end))
    boundary = ("state-limit" if pending else "linear-return" if return_masks else "cap" if event_sink + limit <= len(image) else "image-end")
    family = UNCLASSIFIED
    if boundary == "linear-return":
        dual_plane_required = required_masks[SAMSUNG_DUAL_PLANE_RING32]
        if any(mask & dual_plane_required == dual_plane_required for mask in return_masks):
            family = SAMSUNG_DUAL_PLANE_RING32
        else:
            family = next((candidate for candidate, required in required_masks.items() if candidate != SAMSUNG_DUAL_PLANE_RING32 and any(mask & required ==
                required for mask in return_masks)), UNCLASSIFIED)
    return { "family": family, "boundary": boundary, "bytes": furthest - event_sink, "features": { name: sorted(offsets) for name, offsets in features.items() },
        }

def validate_matrix_event_sink(image: bytes, callsite: int, event_sink: int) -> dict[str, object]:
    """Require the recovered direct argument edge before queue classification."""
    from . import UNCLASSIFIED, classify_matrix_event_sink, facts_for
    if facts_for(image).thumb_call_target(callsite) != event_sink:
        return {"family": UNCLASSIFIED, "features": {}}
    return classify_matrix_event_sink(image, event_sink)

def _samsung_raw_consumer_metadata(image: bytes, event_sink: int, load_address: int) -> dict[str, object] | None:
    """Recover one complete Samsung byte-ring observer chain."""
    from . import SAMSUNG_RAW_CONSUMER_EVIDENCE, SAMSUNG_RAW_DEQUEUE, SAMSUNG_RAW_ENQUEUE_TAIL, SAMSUNG_RAW_RECEIVER_TAIL, facts_for, find_all
    tail = event_sink + 0x4A
    if (event_sink < 0 or event_sink & 1 or image[tail:tail + len(SAMSUNG_RAW_ENQUEUE_TAIL)] != SAMSUNG_RAW_ENQUEUE_TAIL):
        return None
    ring = facts_for(image).thumb_literal_value(tail, 0)
    if ring is None or not 0x01000000 <= ring < 0x04000000:
        return None
    dequeues = [position for position in find_all(image, SAMSUNG_RAW_DEQUEUE) if not position & 1 and facts_for(image).thumb_literal_value(position, 2) == ring]
    if len(dequeues) != 1:
        return None
    dequeue = dequeues[0]
    receivers = [tail - 4 for tail in find_all(image, SAMSUNG_RAW_RECEIVER_TAIL) if tail >= 4 and not (tail - 4) & 1 and facts_for(image).thumb_call_target(tail
        - 4) == dequeue]
    if len(receivers) != 1:
        return None
    receiver = receivers[0]
    return { "raw_ring": ring, "raw_ring_capacity": 32, "raw_enqueue_store": load_address + event_sink + 0x5E, "raw_enqueue_register": 7, "raw_dequeue":
        load_address + dequeue, "raw_dequeue_return": load_address + dequeue + 0x1A, "raw_task_entry": load_address + receiver + 4, "raw_task_register": 0,
        "raw_consumer_evidence": SAMSUNG_RAW_CONSUMER_EVIDENCE, }

def _samsung_raw_r7_consumer_metadata(image: bytes, event_sink: int, event_codes: list[int], load_address: int,) -> dict[str, object] | None:
    """Recover an exact r7 dequeue-task observer without assigning key meaning."""
    from . import SAMSUNG_RAW_DEQUEUE, SAMSUNG_RAW_R7_CONSUMER_EVIDENCE, SAMSUNG_RAW_R7_MOVE, _thumb_reachable, _thumb_reachable_preserving_register, _thumb_successors, facts_for, find_all, struct
    if event_sink < 0 or event_sink & 1:
        return None
    enqueue_end = min(len(image), event_sink + 0x70)
    rings = [facts_for(image).thumb_literal_value(current, 0) for current in range(event_sink + 0x40, enqueue_end - 1, 2) if struct.unpack_from("<H", image,
        current)[0] & 0xF800 == 0x4800 and struct.unpack_from("<H", image, current)[0] >> 8 & 7 == 0]
    rings = [ring for ring in rings if ring is not None and 0x01000000 <= ring < 0x04000000]
    if len(rings) != 1:
        return None
    ring = rings[0]
    stores = [current for current in range(event_sink + 0x40, enqueue_end - 1, 2) if (struct.unpack_from("<H", image, current)[0] & 0xF800 == 0x7000 and struct.unpack_from("<H",
        image, current)[0] & 7 == 7 and struct.unpack_from("<H", image, current)[0] >> 6 & 0x1F == 2)]
    if (len(stores) != 1 or stores[0] not in _thumb_reachable(image, event_sink, enqueue_end)):
        return None
    dequeues = [position for position in find_all(image, SAMSUNG_RAW_DEQUEUE) if not position & 1 and facts_for(image).thumb_literal_value(position, 2) == ring]
    if len(dequeues) != 1:
        return None
    dequeue = dequeues[0]
    tasks: list[tuple[int, int]] = []
    for move in find_all(image, SAMSUNG_RAW_R7_MOVE):
        call = move - 4
        if (call < 0 or call & 1 or facts_for(image).thumb_call_target(call) != dequeue or call + 10 > len(image) or struct.unpack_from("<H", image, call + 4)[0]
            != 0x1C07 or struct.unpack_from("<H", image, call + 6)[0] & 0xFF00 != 0xD000 or struct.unpack_from("<H", image, call + 8)[0] & 0xF800 != 0xE000):
            continue
        branches = _thumb_successors(image, call + 8, len(image))
        if len(branches) != 1:
            continue
        task = branches[0]
        end = min(len(image), task + 0x1000)
        consumers: dict[int, set[int]] = {}
        for current in _thumb_reachable_preserving_register(image, task, end, 7):
            word = struct.unpack_from("<H", image, current)[0]
            if (word & 0xFF00 != 0x2F00 or word & 0xFF not in event_codes or current + 4 > len(image)):
                continue
            successors = _thumb_successors(image, current + 2, len(image))
            target = next((item for item in successors if item != current + 4), None)
            if (target is None or target + 6 > len(image) or struct.unpack_from("<H", image, target)[0] != 0x1C38):
                continue
            consumer = facts_for(image).thumb_call_target(target + 2)
            if consumer is not None:
                consumers.setdefault(consumer, set()).add(word & 0xFF)
        closed = [consumer for consumer, events in consumers.items() if len(events) >= 3]
        if len(closed) == 1:
            tasks.append((call, task))
    if len(tasks) != 1:
        return None
    call, task = tasks[0]
    return { "raw_ring": ring, "raw_ring_capacity": 32, "raw_enqueue_store": load_address + stores[0], "raw_enqueue_register": 7, "raw_dequeue": load_address +
        dequeue, "raw_dequeue_return": load_address + call + 4, "raw_task_entry": load_address + task, "raw_task_register": 7, "raw_consumer_evidence":
        SAMSUNG_RAW_R7_CONSUMER_EVIDENCE, }
