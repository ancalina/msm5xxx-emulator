from __future__ import annotations

def find_search2_transport_profile(image: bytes, tick_position: int,) -> dict[str, object]:
    """Bind an experimental primary-NOR transport; never invent RF samples."""
    from . import _MAX_FUNCTION_BYTES, _literal, rex_5ms_registration_targets, _search2_task_tail, _thumb_function_start, _thumb_reachable, _u16, detect_search2_result_shape, facts_for, find_rex_5ms_irq_route, re, struct
    result: dict[str, object] = { "signature": "thumb-search2-six-word-four-pair-v1", "accepted": False, "active": False, "semantic_limit":
        "transport topology only; RF samples and timing require an explicit backend", }
    def reject(reason: str) -> dict[str, object]:
        return {**result, "reject_reason": reason}
    packed = bytes.fromhex("8e80049a8a80039a8a808c80c2088a803a7a400392021043" "ba7a120210437a7a10438880")
    writers = []
    at = 0
    while (at := image.find(packed, at)) >= 0:
        if not at & 1 and at >= 20:
            base = _literal(image, at - 2, 1, 0)
            tables = [_literal(image, at - delta, 1, 0) for delta in (20, 16)]
            entry = _thumb_function_start(image, at)
            if (base == 0x03000800 and entry < at and at in _thumb_reachable(image, entry, min(len(image), entry + _MAX_FUNCTION_BYTES)) and _u16(image, at - 18)
                == 0x5A0A and _u16(image, at - 12) == 0x5A0A and all(t is not None and 0 <= t <= len(image) - 1024 for t in tables)):
                values = [struct.unpack_from("<512H", image, t) for t in tables]
                if (all(0 < v < 0x8000 for table in values for v in table) and len(set(zip(*values))) == 512):
                    writers.append((at, entry, base, tables))
        at += 2
    if len(writers) != 1:
        return reject(f"search2-writer-cardinality:{len(writers)}")
    writer, entry, base, tables = writers[0]
    consumers = []
    for match in re.finditer(rb"[\x00-\xff]\xb5[\x00-\xff][\x4c-\x4f]", image):
        if match.start() & 1 or _literal(image, match.start() + 2, image[match.start() + 3] & 7, 0) != base:
            continue
        consumer = detect_search2_result_shape(image, match.start())
        if (consumer["confidence"] == "static-shape" and consumer["word_pair_record_offsets"] == (44, 36)):
            consumers.append(consumer)
    if len(consumers) != 1:
        return reject(f"search2-consumer-cardinality:{len(consumers)}")
    consumer = consumers[0]
    calls: dict[int, list[int]] = {}
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if not pc & 1 and (target := facts_for(image).thumb_call_target(pc)) is not None:
            calls.setdefault(target,[]).append(pc)
    tasks = []
    for call in calls.get(consumer["entry_file_offset"],[]):
        task = _thumb_function_start(image, call)
        info = _literal(image, task + 4, 1, 0)
        if (call != task + 0x4A or _u16(image, task) != 0xB5F0 or not _search2_task_tail(image, task, base) or info is None or _literal(image, consumer["entry_file_offset"]
            + 0x12, 4, 0) != info or _literal(image, task + 0x42, 1, 0) != info or image[task + 0x3E:task + 0x42] != bytes.fromhex("a00805d3") or image[task +
            0x44:task + 0x4A] != bytes.fromhex("0878002801d0")):
            continue
        tasks.append(task)
    if len(set(tasks)) != 1:
        return reject(f"search2-task-cardinality:{len(set(tasks))}")
    task = tasks[0]
    loop = consumer["loop_file_offset"]
    pending = _literal(image, writer + 44, 0, 0)
    queue_put = facts_for(image).thumb_call_target(writer + 46)
    queue_get = facts_for(image).thumb_call_target(loop - 12)
    if (pending is None or not 0x01000000 <= pending < 0x02000000 or _literal(image, loop - 14, 0, 0) != pending or _u16(image, writer + 42) != 0x1C39 or _u16(image,
        loop - 4) != 0x6A03 or queue_put is None or not 0 <= queue_put < len(image) or queue_get is None or not 0 <= queue_get < len(image)):
        return reject("search2-pending-queue-unclosed")
    if tick_position & 1 or not 0 <= tick_position < len(image):
        return reject("search2-timer-entry-invalid")
    route = find_rex_5ms_irq_route(image, tick_position)
    registrations = rex_5ms_registration_targets(image, tick_position)
    if route is None or len(registrations) != 3 or len(set(registrations)) != 1:
        return reject("search2-controller-route-unclosed")
    registrar = registrations[0]
    callbacks = []
    for call in calls.get(task,[]):
        callback = _thumb_function_start(image, call)
        if (call == callback + 0x16 and _u16(image, callback) == 0xB580 and image[callback + 4:callback + 8] == bytes.fromhex("00780028") and _literal(image,
            callback + 0xA, 0, 0) == base and image[callback + 0xC:callback + 0x16] == bytes.fromhex("007a8707bf0fb80801d3") and _literal(image, callback + 0x1E,
            1, 0) == task | 1 and _u16(image, callback + 0x20) == 0x2006 and facts_for(image).thumb_call_target(callback + 0x22) == registrar and facts_for(image).thumb_call_target(callback
            + 0x2C) == task):
            callbacks.append(callback)
    if len(set(callbacks)) != 1:
        return reject(f"search2-callback-cardinality:{len(set(callbacks))}")
    callback = callbacks[0]
    initial = []
    for call in calls.get(registrar,[]):
        if (_u16(image, call - 2) == 0x2006 and _literal(image, call - 4, 1, 0) == callback | 1):
            initial.append(call)
    if len(initial) != 1:
        return reject(f"search2-registration-cardinality:{len(initial)}")
    wrapper, handler, handler_slot, timer_slot, status, enable, mask = route
    descriptor_table = struct.unpack_from("<I", image, handler + 0x168)[0]
    if descriptor_table + 28 * 28 + 20 != timer_slot:
        return reject("search2-descriptor-table-mismatch")
    prefix = struct.pack("<3I", status, enable, mask)
    if image.count(prefix) != 1:
        return reject("search2-descriptor-template-ambiguous")
    timer_template = image.find(prefix)
    search_template = timer_template - (28 - 6) * 28
    if search_template < 0:
        return reject("search2-descriptor-template-outside-primary")
    timer_row = struct.unpack_from("<7I", image, timer_template)
    row = struct.unpack_from("<7I", image, search_template)
    if (row[:2] != (status, enable) or row[3:] != timer_row[3:] or row[2] != 0x80 or row[2] == mask):
        return reject("search2-interrupt-descriptor-mismatch")
    return {**result, "accepted": True, "reject_reason": None, "aperture": base, "writer_entry": entry, "write_sites": tuple(writer + delta for delta in (0, 4,
        8, 10, 14, 34)), "mask_tables": tuple(tables), "consumer": consumer, "task": task, "callback": callback, "registration": initial[0], "pending_queue":
        pending, "queue_put": queue_put, "queue_get": queue_get, "irq_wrapper": wrapper, "irq_handler": handler, "irq_handler_slot": handler_slot, "irq_status":
        status, "irq_enable": enable, "irq_mask": row[2], "irq_callback_slot": descriptor_table + 6 * 28 + 20}

def _search1_result_at(image: bytes, at: int) -> dict[str, object] | None:
    from . import _add_reg, _literal, _load_store, _u16, struct
    if at < 64 or at & 1 or at + 24 > len(image):
        return None
    w = struct.unpack_from("<12H", image, at)
    first, energy = _load_store(w[0]), _load_store(w[1])
    if not first or first[0] != "strb" or first[3] != 8:
        return None
    _, index, base, _ = first
    if not energy or energy[0] != "ldrh" or energy[2:] != (base, 4):
        return None
    value, address = energy[1], w[2] & 7
    add = _add_reg(w[3])
    if (w[2] & 0xFFC0 != 0x0040 or (w[2] >> 3) & 7 != index or not add or add[:2] != (address, address)):
        return None
    record = add[2]
    if (len({index, base, value, address, record}) != 5 or _load_store(w[4]) != ("strh", value, address, 44) or _load_store(w[5]) != ("ldrh", value, base, 12)
        or w[6] != (0x3001 | index << 8) or w[7] != (0x0400 | index << 3 | index) or w[8] != (0x1400 | index << 3 | index) or w[9] != (0x2804 | index << 8) or
        _load_store(w[10]) != ("strh", value, address, 36) or w[11] != 0xDBF3 or _u16(image, at - 2) != (0x2000 | index << 8)):
        return None
    bindings = []
    for load in range(at - 64, at - 2, 2):
        if _literal(image, load, base, 0) != 0x03000040:
            continue
        valid = True
        for pc in range(load + 2, at, 2):
            op = _u16(image, pc)
            access = _load_store(op)
            if access:
                valid &= not (access[0].startswith("ldr") and access[1] == base)
            elif op & 0xF800 in (0x4800, 0x2000):
                valid &= (op >> 8) & 7 != base
            else:
                valid = False
        if valid:
            bindings.append(load)
    if len(bindings) != 1:
        return None
    return {"loop_file_offset": at, "base_literal_load": bindings[0], "aperture": 0x03000040, "selector_offset": 8, "energy_offset": 4, "index_offset": 12,
        "peak_count": 4, "record_offsets":[44, 36], "access_width": 2, "registers": {"index": index, "base": base, "value": value, "address": address, "record":
        record}}

def _find_search1_result(image: bytes) -> dict[str, object] | None:
    from . import _search1_result_at, re
    matches = [shape for m in re.finditer(b"\xf3\xdb", image) if (shape := _search1_result_at(image, m.start() - 22))]
    return matches[0] if len(matches) == 1 else None

def _find_search1_writer(image: bytes, profile: dict) -> dict[str, object] | None:
    from . import _find_search1_result, _function, _literal, _thumb_function_start, _u16, facts_for, re
    consumer = _find_search1_result(image)
    if not consumer or not profile["accepted"]:
        return None
    entry = _thumb_function_start(image, consumer["loop_file_offset"])
    pending = _literal(image, entry + 2, 0, 0)
    if (pending is None or not 0x01000000 <= pending < 0x02000000 or facts_for(image).thumb_call_target(entry + 4) != profile["queue_get"]):
        return None
    stores = ((0, 0x40), (4, 0x44), (10, 0x10), (16, 0x3C), (42, 4), (46, 8), (52, 12), (56, 0x14), (118, 0x18), (122, 0x1C), (138, 0x20), (142, 0x24), (144,
        0x28), (148, 0x2C), (166, 0x30), (170, 0x34), (174, 0x38))
    opcodes = (0x700A, 0x7108, 0x7010, 0x7308, 0x7101, 0x7201, 0x7301, 0x7110, 0x7211, 0x7310, 0x7003, 0x7102, 0x7201, 0x7301, 0x7008, 0x7108, 0x7208)
    matches = []
    for match in re.finditer(bytes.fromhex("0a7000120871787a"), image):
        first = match.start()
        if first & 1 or first < 4 or first + 176 > len(image):
            continue
        if any(_u16(image, first + delta) != op for (delta, _), op in zip(stores, opcodes)):
            continue
        if any(_literal(image, first + delta, reg, 0) != address for delta, reg, address in ((-4, 1, 0x03000040), (8, 2, 0x03000010), (14, 1, 0x03000030), (112,
            2, 0x03000010), (134, 0, 0x03000020), (152, 1, 0x03000030))):
            continue
        if (image[first + 38:first + 42] != bytes.fromhex("03200006") or[_literal(image, first + d, 1, 0) for d in (124, 130)] != list(profile["mask_tables"])):
            continue
        writer = _thumb_function_start(image, first)
        body = _function(image, writer)
        if not body:
            continue
        puts = [pc for pc in body[0] if facts_for(image).thumb_call_target(pc) == profile["queue_put"] and _literal(image, pc - 4, 0, 0) == pending and _u16(image,
            pc - 2) == 0x1C39]
        if len(puts) != 1:
            continue
        matches.append({"writer_entry": writer, "first_store": first, "last_store": first + 174, "stores":[{ "pc": first + delta, "address": 0x03000000 + offset,
            "width": 1} for delta, offset in stores], "pending_queue": pending, "consumer_entry": entry, "consumer": consumer})
    return matches[0] if len(matches) == 1 else None

_S1_SITES = (0, 4, 10, 16, 78, 82, 88, 94, 170, 174, 190, 194, 196, 200, 212, 216, 220)
_S1_OFFSETS = (64, 68, 16, 60, 4, 8, 12, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56)
_S1_OPS = (28682, 28936, 28688, 29448, 28931, 29187, 29443, 28952, 29201, 29456, 28675, 28930, 29185, 29441, 28680, 28936, 29192)
_S1_BLOCKS = {22: 'cb8d107883420bd1032809d03b79032b06d0088e032803d0052b01d0052814d1', 56: 'fc2345882b40bd7aad07ad0f2b4343804388', 74: '03200006', 80: 'bb8a', 84:
    'bb8a1b0a', 90: 'f88a', 96: '10780623c88538790886'}

def _find_conditional_search1_writer(image, shared):
    from . import _S1_BLOCKS, _S1_OFFSETS, _S1_OPS, _S1_SITES, _find_search1_result, _function, _literal, _thumb_function_start, _u16, facts_for, re
    if shared.get('accepted') is not True:
        return None
    consumer = _find_search1_result(image)
    if consumer is None:
        return None
    entry = _thumb_function_start(image, consumer['loop_file_offset'])
    pending = _literal(image, entry + 2, 0, 0)
    if pending is None or not 16777216 <= pending <= 33554420 or facts_for(image).thumb_call_target(entry + 4) != shared['queue_get']:
        return None
    matches = []
    for match in re.finditer(bytes.fromhex('0a7000120871787a'), image):
        first = match.start()
        if first & 1 or first < 4 or first + 222 > len(image):
            continue
        if any((_u16(image, first + d) != op for d, op in zip(_S1_SITES, _S1_OPS))):
            continue
        if any((image[first + d:first + d + len(bytes.fromhex(raw))] != bytes.fromhex(raw) for d, raw in _S1_BLOCKS.items())):
            continue
        if any((_literal(image, first + d, reg, 0) != value for d, reg, value in ((-4, 1, 50331712), (8, 2, 50331664), (14, 1, 50331696), (92, 3, 50331664), (168,
            2, 50331664), (186, 0, 50331680), (204, 1, 50331696)))):
            continue
        if[_literal(image, first + d, 1, 0) for d in (176, 182)] != list(shared['mask_tables']):
            continue
        cache = _literal(image, first + 18, 1, 0)
        current = _literal(image, first + 20, 2, 0)
        shadow = _literal(image, first + 54, 0, 0)
        if any((v is None or not 16777216 <= v <= 33554432 - span for v, span in ((cache, 50), (current, 1), (shadow, 4)))):
            continue
        ranges = ((cache, cache + 50), (current, current + 1), (shadow, shadow + 4))
        if any((a < d and c < z for i, (a, z) in enumerate(ranges) for c, d in ranges[i + 1:])):
            continue
        writer = _thumb_function_start(image, first)
        body = _function(image, writer)
        if writer != first - 84 or body is None or body[1] != writer + 388 or (_u16(image, writer) != 46584) or (_u16(image, writer + 388) != 48632) or (facts_for(image).thumb_call_target(writer
            + 4) != shared['queue_get']) or (not set((first + d for d in _S1_SITES)).issubset(body[0])):
            continue
        owner = _literal(image, entry + 12, 5, 0)
        if owner is None or not 16777216 <= owner <= 33554412 or _literal(image, writer + 12, 6, 0) != owner:
            continue
        puts = [pc for pc in body[0] if facts_for(image).thumb_call_target(pc) == shared['queue_put'] and _literal(image, pc - 4, 0, 0) == pending and (_u16(image,
            pc - 2) == 7225)]
        if len(puts) != 1:
            continue
        matches.append({'writer_entry': writer, 'first_store': first, 'last_store': first + 220, 'grammar': 'conditional-config-cache-v1',
            'optional_config_lanes':[4, 5, 6, 7], 'stores':[{'pc': first + d, 'address': 50331648 + off, 'width': 1} for d, off in zip(_S1_SITES, _S1_OFFSETS)],
            'pending_queue': pending, 'consumer_entry': entry, 'consumer': consumer, 'cache_address': cache, 'current_address': current, 'shadow_address':
            shadow, 'evidence_status': 'temporary-one-witness-class, runtime activation requires native gate'})
    return matches[0] if len(matches) == 1 else None

def find_search1_transport_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind the byte-program/selected-result class; leave native activation off."""
    from . import _find_conditional_search1_writer, _find_search1_writer, find_search2_transport_profile
    result = {"signature": "thumb-search1-byte-program-selected-four-pair-v1", "accepted": False, "active": False, "semantic_limit":
        "static command/queue/result class; RF and timing need a backend"}
    shared = find_search2_transport_profile(image, tick_position)
    if not shared["accepted"]:
        return {**result, "reject_reason": "search1-shared-route:" + shared["reject_reason"]}
    writer = _find_search1_writer(image, shared)
    if writer is None:
        writer = _find_conditional_search1_writer(image, shared)
    if writer is None:
        return {**result, "reject_reason": "search1-command-result-link-unclosed"}
    return {**result, **writer, "accepted": True, "reject_reason": None, "shared_search2_profile": shared}

def _finger_quality_at(image: bytes, read: int) -> dict[str, object] | None:
    from . import _function, _literal, _thumb_function_start, _thumb_writes_register, _u16
    if read<64 or read&1 or read+68>len(image):return None
    prefix={-56:0x2101,-54:0x4081,-50:0x7219,-46:0x8a0d,-44:0x2148, -42:0x4341,-40:0x1909,-38:0x1dcb,-36:0x3339, -34:0x801d,-30:0x7a2d,-28:0x709d}
    tail={0:0x899b,2:0x9301,6:0xae01,8:0x7836,10:0x78ab,12:0x401e, 14:0xab01,16:0x701e,18:0x785b,20:0x878b,22: 0x786d,24:0x9e01, 26:0x40ae,30:0x1c33,32:0x42ab,34:0x9601,36:0xd800,38:0x9d01,
        40:0x9501,42:0xab01,44: 0x785b,46:0x2508,48:0x4085,50:0x874b, 52:0x1c2b,54:0x4013,56:0x3001,58:0x0400,60:0x0c00,62:0x870b, 64: 0x42b8,66:0xdbc1}
    if any(_u16(image,read+d)!=op for d,op in (prefix|tail).items()):return None
    if any(_literal(image,read+d,r,0)!=value for d,r,value in [(-52,3,0x3000070),(-48,1,0x30000a0),(-32,5, 0x30000b0), (-2,3,0x3000080),(28,5,0xffff)]):return None
    if any(_thumb_writes_register(_u16(image,pc),1) for pc in range(read-32,read-2,2)):return None
    scale=_literal(image,read+4,5,0)
    if scale is None or not 0x1000000<=scale<=0x1fffffc:return None
    entry=_thumb_function_start(image,read);body=_function(image,entry)
    if not body or read not in body[0] or _u16(image,entry+2)!=0x1c04:return None
    if _literal(image,entry+28,0,0)!=0x30000e0 or _u16(image,entry+30)!=0x7902:return None
    return {'signature':'thumb-selected-finger-rssi-u16-scale-u8-v1','active':False, 'entry':entry,'loop':read- 56,'selector_store':read-50,'rss_word_read':read,
        'rss_address':0x300008c,'rss_width':2,'quality_store': read+50,'stride':72, 'quality_offset':58,'raw_upper_offset':60,'lock_flags_offset':56,
        'position_low_address':0x30000b0,'position_high_address':0x30000b8, 'scale_shift_address':scale+1, 'low_mask_address':scale+2, 'semantic_limit':
        'static selected-bank/read/scale/record dataflow only; physical energy, lock and RF timing unclosed'}

def _find_finger_quality(image: bytes) -> dict[str, object] | None:
    from . import _finger_quality_at, re
    shapes= [s for m in re.finditer(bytes.fromhex('9b890193'),image) if (s:=_finger_quality_at(image,m.start()))]
    return shapes[0] if len(shapes)==1 else None

def find_finger_transport_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Find a selected-bank receiver class; keep activation explicit."""
    from . import _find_finger_quality, find_search2_transport_profile
    result = {"signature": "thumb-selected-finger-rssi-u16-scale-u8-v1", "accepted": False, "active": False, "semantic_limit":
        "static RSSI/position dataflow; physical energy and timing need a backend"}
    shared = find_search2_transport_profile(image, tick_position)
    if not shared["accepted"]:
        return {**result, "reject_reason": "finger-shared-route:" + shared["reject_reason"]}
    reader = _find_finger_quality(image)
    if reader is None:
        return {**result, "reject_reason": "finger-selected-reader-unclosed"}
    return {**result, **reader, "accepted": True, "reject_reason": None, "mask_tables": shared["mask_tables"], "bank_count": 4, "shared_search2_profile": shared}

def find_decoder_init_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind a bounded initialization-IRQ probe, not a decoded radio channel."""
    from . import _literal, _thumb_function_start, _u16, facts_for, find_rex_5ms_irq_route, find_search2_transport_profile, re, struct
    result = {"signature": "thumb-decoder-six-halfword-init-v1", "accepted": False, "active": False, "semantic_limit":
        "one initialization IRQ only; no decoded samples, clock calibration or service"}
    def reject(reason):
        return {**result, "reject_reason": reason}
    reader_pattern = re.compile(rb"\x00\xb5.\x4a\x00\x21\x11\x83\x06\x22\x01\x1c.\x48....\x00\xbd", re.S)
    copy_code = bytes.fromhex("90b5002304e004881f1c7f00cc5301339342f8db90bd")
    readers = []
    for match in reader_pattern.finditer(image):
        at = match.start()
        helper = facts_for(image).thumb_call_target(at + 14)
        if (not at & 1 and helper is not None and image[helper:helper + len(copy_code)] == copy_code and _literal(image, at + 2, 2, 0) == 0x03000a40 and
            _literal(image, at + 12, 0, 0) == 0x03000a70):
            readers.append((at, helper))
    if len(readers) != 1:
        return reject(f"decoder-reader-cardinality:{len(readers)}")
    reader, helper = readers[0]
    transport = find_search2_transport_profile(image, tick_position)
    route = find_rex_5ms_irq_route(image, tick_position)
    if not transport["accepted"] or route is None:
        return reject("decoder-controller-route-unclosed")
    calls = {}
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if not pc & 1 and (target := facts_for(image).thumb_call_target(pc)) is not None:
            calls.setdefault(target,[]).append(pc)
    reader_calls = calls.get(reader,[])
    if len(reader_calls) != 1:
        return reject(f"decoder-isr-cardinality:{len(reader_calls)}")
    isr = _thumb_function_start(image, reader_calls[0])
    if _u16(image, isr) != 0xb5b0 or reader_calls[0] != isr + 0x56:
        return reject("decoder-isr-shape")
    registrar = facts_for(image).thumb_call_target(transport["registration"])
    registrations = [pc for pc in calls.get(registrar,[]) if _u16(image, pc - 2) == 0x2005 and _literal(image, pc - 4, 1, 0) == (isr | 1)]
    if len(registrations) != 1:
        return reject(f"decoder-registration-cardinality:{len(registrations)}")
    registration = registrations[0]
    initializer = facts_for(image).thumb_call_target(registration + 10)
    if initializer is None:
        return reject("decoder-initializer-call")
    write = initializer + 0x34
    if (image[write - 10:write - 8] != bytes.fromhex("b988") or image[write - 6:write + 2] != bytes.fromhex("1940b980b9882181") or not _literal(image, write - 8,
        3, 0) == 0xfff8 or not _literal(image, write - 0x24, 4, 0) == 0x03000a00 or image[initializer + 0x12:initializer + 0x1e] != bytes.fromhex("194040231943b980b9882181")):
        return reject("decoder-sync-init-shape")
    prefix = struct.pack("<3I", transport["irq_status"], transport["irq_enable"], route[-1])
    if image.count(prefix) != 1:
        return reject("decoder-descriptor-template-ambiguous")
    timer_at = image.find(prefix)
    row_at = timer_at - (28 - 5) * 28
    if row_at < 0:
        return reject("decoder-descriptor-outside-primary")
    row = struct.unpack_from("<7I", image, row_at)
    timer = struct.unpack_from("<7I", image, timer_at)
    mask = row[2]
    if (row[:2] != timer[:2] or row[3:] != timer[3:] or not mask or mask > 0xffff or mask & (mask - 1) or mask in (route[-1], transport["irq_mask"])):
        return reject("decoder-descriptor-mismatch")
    return {**result, "accepted": True, "reject_reason": None, "reader": reader, "copy_helper": helper, "data_words": 6, "descriptor_template": row_at,
        "initializer": initializer, "init_write": write, "isr": isr, "registration": registration, "irq_callback_slot": transport["irq_callback_slot"] - 28,
        "irq_status": row[0], "irq_enable": row[1], "irq_mask": mask}
