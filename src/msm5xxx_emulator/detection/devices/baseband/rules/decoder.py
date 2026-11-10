from __future__ import annotations

def find_combiner_clock_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Couple the latched phase getter and roll ISR to the decoder controller."""
    from . import _literal, _thumb_function_start, _u16, facts_for, find_decoder_init_profile, re, struct
    result = {"signature": "thumb-combiner-latched-phase-v1", "accepted": False, "active": False, "semantic_limit":
        "static clock topology; epoch/SLAM and fractional physical calibration unverified"}
    def reject(reason):
        return {**result, "reject_reason": reason}
    def fixed(value):
        return re.escape(bytes.fromhex(value))
    pattern = re.compile(fixed("08b5") + b"...." + fixed("0104090c") + b"." + fixed("4800220271027a00ab1a70007b5870002901d1") + b"...." + fixed("00a8008808bd"),
        re.S)
    getters = [m.start() for m in pattern.finditer(image) if not m.start() & 1 and _literal(image, m.start() + 10, 0, 0) == 0x030000f0]
    if len(getters) != 1:
        return reject(f"combiner-position-getter-cardinality:{len(getters)}")
    getter = getters[0]
    decoder = find_decoder_init_profile(image, tick_position)
    if not decoder["accepted"]:
        return reject("combiner-decoder-controller-unclosed")
    registrar = facts_for(image).thumb_call_target(decoder["registration"])
    candidates = {}
    for m in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = m.start()
        if pc & 1 or _u16(image, pc - 2) != 0x2001 or facts_for(image).thumb_call_target(pc) != registrar:
            continue
        pointer = _literal(image, pc - 4, 1, 0)
        if pointer is None or not pointer & 1:
            continue
        callback = pointer - 1
        if (facts_for(image).thumb_call_target(callback + 0x1aa) == getter and facts_for(image).thumb_call_target(callback + 0x2a4) == getter):
            candidates.setdefault(callback,[]).append(pc)
    if len(candidates) != 1:
        return reject(f"combiner-roll-isr-cardinality:{len(candidates)}")
    callback = next(iter(candidates))
    row_at = decoder["descriptor_template"] - 4 * 28
    if row_at < 0:
        return reject("combiner-roll-descriptor-outside-primary")
    row = struct.unpack_from("<7I", image, row_at)
    other = struct.unpack_from("<7I", image, decoder["descriptor_template"])
    mask = row[2]
    if (row[:2] != other[:2] or row[3:] != other[3:] or not mask or mask > 0xffff or mask & (mask - 1) or mask == other[2]):
        return reject("combiner-roll-descriptor-mismatch")
    first_shape = bytes.fromhex("48220092f81d01302a1c18230021061c")
    second_shape = bytes.fromhex("1822009200234821301c2a1c")
    consumers = []
    at = 0
    queue = _literal(image, decoder["isr"] + 0x5e, 0, 0)
    queue_get = facts_for(image).thumb_call_target(decoder["isr"] + 0xc)
    while (at := image.find(first_shape, at)) >= 0:
        entry = _thumb_function_start(image, at)
        if (at == entry + 0x16 and image[entry + 0x42:entry + 0x4e] == second_shape and facts_for(image).thumb_call_target(entry + 0x26) is not None and
            facts_for(image).thumb_call_target(entry + 0x26) == facts_for(image).thumb_call_target(entry + 0x4e) and queue is not None and _literal(image, entry
            + 0x64, 0, 0) == queue and queue_get is not None and facts_for(image).thumb_call_target(entry + 0x66) == queue_get):
            consumers.append(entry)
        at += 2
    if len(consumers) != 1:
        return reject(f"decoder-pipeline-consumer-cardinality:{len(consumers)}")
    return {**result, "accepted": True, "reject_reason": None, "sync_consumer": consumers[0], "decoder_pipeline_bits": 24, "position_getter": getter, "roll_isr":
        callback, "registrations": candidates[callback], "irq_mask": mask, "descriptor_template": row_at, "irq_callback_slot": decoder["irq_callback_slot"] - 4
        * 28}

def find_paging_decoder_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind the paging IRQ/read/carry class; decoded source activation stays explicit."""
    from . import _literal, _thumb_function_start, _u16, facts_for, find_combiner_clock_profile, find_decoder_init_profile, re
    result = {"signature": "thumb-paging-two-subframe-head72-v1", "accepted": False, "active": False, "semantic_limit":
        "static paging transport; ideal metrics and physical timing remain provisional"}
    def reject(reason):
        return {**result, "reject_reason": reason}
    def code(at, value):
        expected = bytes.fromhex(value)
        return at >= 0 and image[at:at + len(expected)] == expected
    decoder = find_decoder_init_profile(image, tick_position)
    clock = find_combiner_clock_profile(image, tick_position)
    if not decoder["accepted"] or not clock["accepted"]:
        return reject("paging-shared-decoder-clock-unclosed")
    readers = []
    pattern = rb"\x00\xb5.\x4a\x00\x21\x11\x83.\x49\x0a\x88\x01\x1c.\x48....\x00\xbd"
    for match in re.finditer(pattern, image, re.S):
        at = match.start()
        count = _literal(image, at + 8, 1, 0)
        if (not at & 1 and _literal(image, at + 2, 2, 0) == 0x03000a40 and _literal(image, at + 14, 0, 0) == 0x03000a70 and facts_for(image).thumb_call_target(at
            + 16) == decoder["copy_helper"] and count is not None and 0x01000000 <= count <= 0x01fffffe and not count & 1):
            readers.append((at, count))
    if len(readers) != 1:
        return reject(f"paging-reader-cardinality:{len(readers)}")
    reader, count = readers[0]
    calls = {}
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if not pc & 1 and (target := facts_for(image).thumb_call_target(pc)) is not None:
            calls.setdefault(target,[]).append(pc)
    if len(calls.get(reader,[])) != 1:
        return reject("paging-isr-cardinality")
    isr = _thumb_function_start(image, calls[reader][0])
    shift = 0
    if (calls[reader][0] == isr + 0x160 and _u16(image,isr)==0xb5fc and code(isr+0x15a,"f81d0130061c") and code(isr+0x1ba,"0220b880") and code(isr+0x140,"fcbd")
        and code(isr+0x1ec,"a8e7")):
        returned = facts_for(image).thumb_call_target(isr+0x1e8)
        if returned is None or not code(returned,"f746"):
            return reject("paging-return-helper-unclosed")
        shift = 2
    elif (calls[reader][0] != isr + 0x162 or _u16(image, isr) != 0xb5fc or not code(isr + 0x15c, "f81d0130061c") or not code(isr + 0x1bc, "0220b880")):
        return reject("paging-isr-reader-shape")
    status = facts_for(image).thumb_call_target(isr + 0xda - shift)
    initializer = facts_for(image).thumb_call_target(isr + 0x1e2 - shift)
    if status is None or initializer is None:
        return reject("paging-isr-callees")
    if (not code(status + 4, "09881183") or not code(status + 10, "118a417009120170118a4180f746") or _literal(image, status, 1, 0) != count or _literal(image,
        status + 2, 2, 0) != 0x03000a40 or _literal(image, status + 8, 2, 0) != 0x03000a60):
        return reject("paging-status-wordcount-shape")
    if (not code(initializer, "b0b5071c") or not code(initializer + 0x14, "194020231943a180a1882981") or not code(initializer + 0x2c, "a188") or not code(initializer
        + 0x30, "1940a180a1882981") or _literal(image, initializer + 0x12, 5, 0) != 0x03000a00 or _literal(image, initializer + 0xe, 3, 0) != 0xff9f or _literal(image,
        initializer + 0x2e, 3, 0) != 0xfff8):
        return reject("paging-20ms-initializer-shape")
    mode = facts_for(image).thumb_call_target(initializer + 4)
    if (mode is None or not code(mode, "00b5") or _literal(image, mode + 2, 1, 0) != count or not code(mode + 4, "002803d0012804d1062000e00c20088004e0")):
        return reject("paging-rate-wordcount-shape")
    registrar = facts_for(image).thumb_call_target(decoder["registration"])
    registrations = [pc for pc in calls.get(registrar,[]) if _u16(image, pc - 2) == 0x2005 and _literal(image, pc - 4, 1, 0) == (isr | 1)]
    if len(registrations) != 1:
        return reject("paging-slot5-registration-cardinality")
    sync = clock["sync_consumer"]
    bitcopy = facts_for(image).thumb_call_target(sync + 0x26)
    queue_get = facts_for(image).thumb_call_target(decoder["isr"] + 0xc)
    queue = _literal(image, isr + 0x1c0 - shift, 0, 0)
    if queue is None or not 0x01000000 <= queue <= 0x01fffff4:
        return reject("paging-consumer-queue-unclosed")
    consumers = []
    for match in re.finditer(re.escape(bytes.fromhex("a2880021281c00926388321c")), image):
        entry = match.start() - 0x46
        cache = _literal(image, entry + 0x1a, 0, 0)
        if (entry < 0 or entry & 1 or _u16(image, entry) != 0xb5f8 or cache is None or not 0x01000000 <= cache <= 0x01ffff00 or _literal(image, entry + 0xc, 6,
            0) != cache + 0x22 or any(_literal(image, entry + delta, reg, 0) != cache for delta, reg in ((0x28, 1), (0x30, 0), (0x3e, 0), (0x52, 7), (0x96, 7)))
            or not code(entry + 0xe, "f51f113dec1d2f34") or not code(entry + 0x18, "f91d") or not code(entry + 0x1c, "01311822281c") or not code(entry + 0x7a,
            "62880023281c0092a188321c") or facts_for(image).thumb_call_target(entry + 0x54) != bitcopy or facts_for(image).thumb_call_target(entry + 0x86) !=
            bitcopy or facts_for(image).thumb_call_target(entry + 0xc6) != queue_get or _literal(image, entry + 0xc4, 0, 0) != queue):
            continue
        layouts = []
        for layout in re.finditer(re.escape(bytes.fromhex("c02000e060204887")), image):
            at = layout.start()
            if (not at & 1 and _literal(image, at - 6, 1, 0) == cache and _literal(image, at + 8, 5, 0) == cache + 0x40 and _literal(image, at + 12, 1, 0) ==
                cache and code(at + 10, "4820") and code(at + 14, "a880488f483868804e8f70080004000c8887")):
                layouts.append(at)
        if len(layouts) == 1:
            consumers.append((entry, cache, layouts[0]))
    if len(consumers) != 1:
        return reject(f"paging-head72-consumer-cardinality:{len(consumers)}")
    consumer, cache, layout = consumers[0]
    return {**result, "accepted": True, "reject_reason": None, "isr": isr, "reader": reader, "status_reader": status, "initializer": initializer, "init_write":
        initializer + 0x36, "wordcount_address": count, "consumer": consumer, "registration": registrations[0], "copy_helper": decoder["copy_helper"],
        "bitcopy_helper": bitcopy, "mode_initializer": mode, "pipeline_cache": cache, "pipeline_layout": layout, "head_bits": 72, "frame_bits":[192, 96],
        "data_words":[12, 6], "descriptor_template": decoder["descriptor_template"], "irq_callback_slot": decoder["irq_callback_slot"], "irq_status": decoder["irq_status"],
        "irq_enable": decoder["irq_enable"], "irq_mask": decoder["irq_mask"]}

def find_search1_abort_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind the original shared-owner teardown; leave cancellation activation explicit."""
    from . import _literal, _u16, facts_for, find_search1_transport_profile, re
    result = {"signature": "thumb-search1-shared-owner-zero-abort-v1", "accepted": False, "active": False, "semantic_limit":
        "static original teardown only; cancellation needs a backend"}
    transport = find_search1_transport_profile(image, tick_position)
    if not transport["accepted"]:
        return {**result, "reject_reason": "search1-abort-transport-unclosed"}
    shared = transport["shared_search2_profile"]
    owner = _literal(image, transport["consumer_entry"] + 0xc, 5, 0)
    control = _literal(image, shared["task"] + 4, 1, 0)
    if (owner is None or not 0x01000000 <= owner <= 0x01ffffec or control is None or not 0x01000000 <= control <= 0x01fffffe):
        return {**result, "reject_reason": "search1-abort-owner-unclosed"}
    fixed = { 0: 0xb5f0, 4: 0x2700, 6: 0x7920, 0xc: 0x2800, 0xe: 0xd102, 0x10: 0x7828, 0x12: 0x2800, 0x14: 0xd01e, 0x16: 0x706f, 0x1c: 0x7829, 0x1e: 0x0400,
        0x20: 0x0c00, 0x22: 0x2900, 0x24: 0xd007, 0x28: 0x2302, 0x2a: 0x880a, 0x2c: 0x431a, 0x2e: 0x7032, 0x30: 0x8809, 0x32: 0x4319, 0x34: 0x7031, 0x36: 0x7921,
        0x38: 0x2900, 0x3a: 0xd002, 0x3e: 0x700f, 0x40: 0x710f, 0x42: 0x2800, 0x44: 0xd101, 0x4c: 0x2009, 0x4e: 0x8008, 0x50: 0x7127, 0x52: 0x702f, 0x54: 0x7a30,
        0x5a: 0x2001, 0x5c: 0x7068, 0x60: 0x2101, 0x62: 0x1c28, 0x6e: 0x2101, 0x70: 0x02c9, 0x72: 0x1c28, 0x78: 0x6027, 0x7a: 0xbdf0, }
    matches = []
    pattern = rb"\xf0\xb5.\x4c\x00\x27\x20\x79"
    for match in re.finditer(pattern, image, re.S):
        at = match.start()
        if (at & 1 or at + 0x7c > len(image) or any(_u16(image, at + delta) != op for delta, op in fixed.items()) or _literal(image, at + 2, 4, 0) != owner or
            _literal(image, at + 0xa, 5, 0) != control or _literal(image, at + 8, 6, 0) != 0x03000800 or _literal(image, at + 0x3c, 1, 0) != 0x03000040 or
            _literal(image, at + 0x4a, 1, 0) != 0x04800020):
            continue
        shadow = _literal(image, at + 0x26, 1, 0)
        timer = _literal(image, at + 0x68, 0, 0)
        tcb = _literal(image, at + 0x5e, 5, 0)
        clear_signal = facts_for(image).thumb_call_target(at + 0x64)
        calls = [facts_for(image).thumb_call_target(at + delta) for delta in (0x18, 0x46, 0x56, 0x64, 0x6a, 0x74)]
        if (shadow is None or not 0x01000000 <= shadow <= 0x01fffffe or timer is None or not 0x01000000 <= timer <= 0x01ffffec or tcb is None or not 0x01000000
            <= tcb <= 0x01fffffc or facts_for(image).thumb_call_target(at + 0x74) != clear_signal or any(target is None or not 0 <= target < len(image) for
            target in calls)):
            continue
        matches.append(at)
    if len(matches) != 1:
        return {**result, "reject_reason": f"search1-abort-cardinality:{len(matches)}"}
    entry = matches[0]
    return {**result, "accepted": True, "reject_reason": None, "entry": entry, "first_store": entry + 0x3e, "second_store": entry + 0x40, "owner_address": owner,
        "control_address": control}

_TX_INIT_CALLBACK_SHAPES = ((bytes.fromhex("f0b5004c0121208801302080201d071c00000000004e0125307800282ed0002000000000707800280ad001281ad1381c000000000121381c00000000657516e00420000000000048007800000000301d00000000004906200870004904200000000004e0f52080000049000000000025357010210048000000003de0004f6575f81d19300079002833d0012000000000f87a00000000f87a012200217873f81d1e30000000003878032825d13e1c4037787a002820d00025004c7d72207863781b02184318d00048a070030ae370201d00000000387a0130607300000000a073f07ae073201c0000000025702b0a637002e00020000000000048042100000000f0bd"),
    (16, 32, 48, 56, 66, 74, 80, 94, 106, 118, 140, 146, 162, 208, 218, 230, 244, 252), (2, 20, 70, 84, 90, 104, 116, 124, 184, 198, 248)), (bytes.fromhex("f0b5004c0121208801302080201d071c00000000004e0125307800282dd0002000000000707800280ad001281ad1381c000000000121381c00000000657515e00420000000000048007800000000301d00000000004906200870004904200000000003e000490048000000000025357010210048000000003de0004f6575f81d19300079002833d0012000000000f87a00000000f87a012200217873f81d1e30000000003878032825d13e1c4037787a002820d00025004c7d72207863781b02184318d00048a070030ae370201d00000000387a0130607300000000a073f07ae073201c0000000025702b0a637002e00020000000000048042100000000f0bd"),
    (16, 32, 48, 56, 66, 74, 80, 94, 104, 116, 138, 144, 160, 206, 216, 228, 242, 250), (2, 20, 70, 84, 90, 100, 102, 114, 122, 182, 196, 246)),)
_TX_INIT_CONTROL_SHAPE = (bytes.fromhex("f0b50049004ecc1dcf1dff37ff343a345a370028004d18d1000000003988004b1940398039882980002801d10000000000000000e18a004b194001231943e182e18ab18100282ad127e000000000004910230a781a430a700978004a1173002801d10000000000000000e18a004b194001231943e182e18ab181002801d100000000000000003988004b194004231943398039882980002801d100000000f0bd"),
    (24, 44, 48, 74, 98, 102, 126, 130, 154), (2, 4, 20, 30, 54, 78, 90, 108, 136))

def _tx_init_code_matches(image: bytes, entry: int, shape: tuple) -> bool:
    from . import facts_for
    expected, calls, literals = shape
    if entry & 1 or not 0 <= entry <= len(image) - len(expected):
        return False
    actual = bytearray(image[entry:entry + len(expected)])
    for offset in calls:
        target = facts_for(image).thumb_call_target(entry + offset)
        if target is None or not 0 <= target < len(image):
            return False
        actual[offset:offset + 4] = b"\0" * 4
    for offset in literals:
        actual[offset] = 0
    return actual == expected

def find_tx_init_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind a local encoder initialization IRQ class; never activate or time it."""
    from . import _MAX_FUNCTION_BYTES, _TX_INIT_CALLBACK_SHAPES, _TX_INIT_CONTROL_SHAPE, _literal, _thumb_function_start, _thumb_reachable, _tx_init_code_matches, _u16, facts_for, find_decoder_init_profile, re, struct
    result = {"signature": "thumb-tx-init-slot4-armed-control-v1", "accepted": False, "active": False, "semantic_limit":
        "static local initialization only; timing, RF and device completion unproven"}
    decoder = find_decoder_init_profile(image, tick_position)
    if not decoder["accepted"]:
        return {**result, "reject_reason": "tx-init-controller-unclosed"}
    registrar = facts_for(image).thumb_call_target(decoder["registration"])
    descriptor = decoder["descriptor_template"] - 28
    slot = decoder["irq_callback_slot"] - 28
    if descriptor < 0 or slot < 0x01000000 + 20:
        return {**result, "reject_reason": "tx-init-descriptor-outside-primary"}
    row = struct.unpack_from("<7I", image, descriptor)
    other = struct.unpack_from("<7I", image, decoder["descriptor_template"])
    if row[:2] != other[:2] or row[3:] != other[3:] or row[2] != 8:
        return {**result, "reject_reason": "tx-init-descriptor-mismatch"}
    def ram(value, size):
        return value is not None and 0x01000000 <= value <= 0x02000000 - size
    matches = []
    for match in re.finditer(rb"\xf0\xb5.\x4c\x01\x21\x20\x88\x01\x30\x20\x80", image, re.S):
        entry = match.start()
        for shape in _TX_INIT_CALLBACK_SHAPES:
            if not _tx_init_code_matches(image, entry, shape):
                continue
            short = len(shape[0]) == 0x100
            # The shorter diagnostic block moves all following code by two bytes.
            after = lambda offset: entry + offset - (2 if short else 0)
            counter = _literal(image, entry + 2, 4, 0)
            armed = _literal(image, entry + 0x14, 6, 0)
            tcb = _literal(image, after(0x74), 0, 0)
            control = facts_for(image).thumb_call_target(entry + 0x20)
            signal = facts_for(image).thumb_call_target(after(0x76))
            if (not ram(counter, 0x140) or not ram(armed, 2) or not ram(counter - 0xa4, 0x1e4) or armed != counter - 12 or not ram(tcb, 0x18) or _literal(image,
                entry + 0x46, 0, 0) != counter + 0x13c or not ram(_literal(image, entry + 0x54, 1, 0), 1) or _literal(image, after(0x7c), 7, 0) != counter -
                0xa4 or _literal(image, after(0xb8), 4, 0) != counter - 0x58 or _literal(image, after(0xc6), 0, 0) != 0x1013 or _literal(image, after(0xf8), 0,
                0) != tcb or facts_for(image).thumb_call_target(entry + 0x38) != facts_for(image).thumb_call_target(entry + 0x10) or facts_for (image).thumb_call_target(entry
                + 0x5e) != registrar or facts_for(image).thumb_call_target(after (0x8c)) != control or facts_for(image).thumb_call_target(after(0xf4)) !=
                control or facts_for(image).thumb_call_target(after(0xfc)) != signal or not _tx_init_code_matches(image, control, _TX_INIT_CONTROL_SHAPE)):
                continue
            alternate = _literal(image, entry + 0x5a, 1, 0)
            if (alternate is None or not alternate & 1 or alternate >= len(image) or (short and _literal(image, entry + 0x66, 0, 0) != 0x3da)):
                continue
            # Bind the signal OR/store and its lock to the control helper's lock.
            if (image[signal:signal + 6] != bytes.fromhex("f0b50e1c071c") or image[signal + 10:signal + 20] != bytes.fromhex("fc68051c201c3043f860") or
                facts_for(image).thumb_call_target(signal + 6) != facts_for(image).thumb_call_target(control + 0x18)):
                continue
            shadow = _literal(image, control + 2, 1, 0)
            input_shadow = _literal(image, control + 0x4e, 1, 0)
            if (not ram(shadow, 0x180) or not ram(input_shadow, 1) or _literal(image, control + 4, 6, 0) != 0x030002a0 or _literal(image, control + 0x14, 5, 0)
                != 0x030002c0 or _literal(image, control + 0x1e, 3, 0) != 0xfff3 or _literal(image, control + 0x36, 3, 0) != 0xfffc or _literal(image, control +
                0x5a, 2, 0) != 0x03000670 or _literal(image, control + 0x6c, 3, 0) != 0xfffc or _literal(image, control + 0x88, 3, 0) != 0xfff3):
                continue
            registrations = []
            for call in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
                pc = call.start()
                if (pc & 1 or _u16(image, pc - 2) != 0x2004 or _literal(image, pc - 4, 1, 0) != entry | 1 or facts_for(image).thumb_call_target(pc) != registrar):
                    continue
                start = _thumb_function_start(image, pc)
                if pc in _thumb_reachable(image, start, min(len(image), start + _MAX_FUNCTION_BYTES)):
                    registrations.append(pc)
            if len(registrations) != 1:
                continue
            pc = registrations[0]
            if (image[pc + 4:pc + 6] != bytes.fromhex("0124") or _literal(image, pc + 6, 7, 0) != armed or _literal(image, pc + 8, 6, 0) != tcb or image[pc + 10:pc
                + 16] != bytes.fromhex("1021301c7c70") or image[pc + 20:pc + 24] != bytes.fromhex("3c701020")):
                continue
            code_dependencies = ((entry, len(shape[0])), (control, len(_TX_INIT_CONTROL_SHAPE[0])), (registrar, 0x6e), (signal, 20), *((call - 4, 28) for call
                in registrations))
            ram_dependencies = ((slot - 20, 24), (armed, 16), (tcb, 0x18), (counter, 0x140), (shadow, 0x180), (input_shadow, 1))
            if (any(not 0 <= address <= len(image) - size for address, size in code_dependencies) or any(not ram (address, size) for address, size in
                ram_dependencies)):
                continue
            matches.append({"callback": entry, "callback_size": len(shape[0]), "callback_slot": slot, "armed_flag": armed, "tx_tcb": tcb, "counter_address":
                counter, "descriptor_template": descriptor, "irq_status": row[0], "irq_enable": row[1], "irq_mask": row[2], "registrations": tuple(registrations),
                "registrar": registrar, "control_helper": control, "control_shadow": shadow, "input_shadow": input_shadow, "signal_setter": signal,
                "alternate_callback": alternate & ~1, "first_flag_load": entry + 0x18, "flag_clear_store": after(0x70), "signal10_call": after(0x76),
                "signal4_call": after(0xfc), "code_dependencies": code_dependencies, "ram_dependencies": ram_dependencies})
    if len(matches) != 1:
        return {**result, "reject_reason": f"tx-init-class-cardinality:{len(matches)}"}
    return {**result, **matches[0], "accepted": True, "reject_reason": None}

_TX_FRAME_DATA_SHAPE = (bytes.fromhex('f0b5004e051c307b0c1c171c0138032803d90049004800000000042f03d90049004800000000004e0049327b9000401840380121b940c06b401801380004000cf8400604360c0048032180181038c91b002cc07b0cd0004b1201d2188b00d318da1f093a203b5b8a1278004f3b8000e00022004f004c3b7b004fdb00df194b00ff18203f3f8ba781004f004c3f7bff003f19fb18203b1b8b004c2382004f004b3f7bdb19103bdb7b8900000108435901084311020843071c000000000049004bca891a40004b3b401a43ca81c989004a9183002801d1000000000048007b022804dd012000000000012009e0002000000000002000000000002000000000002000000000291c321c004800000000f0bd'),
    (22, 34, 184, 214, 228, 238, 244, 250, 256, 266), (2, 18, 20, 30, 32, 38, 40, 70, 86, 106, 114, 116, 120, 136, 138, 152, 156, 158, 188, 190, 196, 206, 218,
    264))
_TX_FRAME_TABLE = bytes.fromhex('1800000024000000180000002400000000000000000000000800b0090c00130f0600c0010800b0090a00640f0c00130f0600c0090600c0090800b0090c00130f0600c0090800b0090a00640f0c00130f0600009c0600009c0800009b0c0030f1100067c8100067c8100067c8100067c8000000000000000000000000000000000000000000000000001500150015001500000000000000000000000000000000000880000000000045144514451445140100020200010001')
_TX_FRAME_FIXED_WRITER = bytes.fromhex('b0b5002357087c0006e0cf5c5d1c6b1c4d5d2d022f4307809c42f6dc520801d3c95c0180b0bd')

def find_tx_frame_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind an explicit local frame IRQ/FIFO class without selecting timing."""
    from . import _TX_FRAME_DATA_SHAPE, _TX_FRAME_FIXED_WRITER, _TX_FRAME_TABLE, _literal, _tx_init_code_matches, facts_for, find_tx_init_profile
    init = find_tx_init_profile(image, tick_position)
    result = {**init, "signature": "thumb-tx-frame-slot4-fixed-fifo-v1", "accepted": False, "active": False, "semantic_limit":
        "temporary explicit local frame IRQ/FIFO input class only; period and phase provisional; auxiliary callees, codec, RF and output completion unproven" }
    if not init["accepted"]:
        return result
    callback = init["callback"]
    data_call = callback + (0xa2 if init["callback_size"] == 0x102 else 0xa0)
    data = facts_for(image).thumb_call_target(data_call)
    if data is None or not _tx_init_code_matches(image, data, _TX_FRAME_DATA_SHAPE):
        return {**result, "reject_reason": "tx-frame-data-shape-unclosed"}
    writer = facts_for(image).thumb_call_target(data + 0x10a)
    if (writer is None or image[writer:writer + 38] != _TX_FRAME_FIXED_WRITER or _literal(image, data + 0x108, 0, 0) != 0x03000298):
        return {**result, "reject_reason": "tx-frame-fixed-writer-unclosed"}
    mode = _literal(image, data + 2, 6, 0)
    shadow = _literal(image, data + 0xbc, 1, 0)
    working = init["counter_address"] - 0xa4
    if (mode is None or mode & 3 or not 0x01000000 <= mode <= 0x02000000 - 16 or shadow != init["control_shadow"] + 0x140 or any(_literal(image, data + at,
        register, 0) != mode for at, register in ((0x26, 6), (0x72, 7), (0x88, 7), (0x9c, 7), (0xda, 0))) or _literal(image, callback + (0x7c if init["callback_size"]
        == 0x102 else 0x7a), 7, 0) != working):
        return {**result, "reject_reason": "tx-frame-state-alias-unclosed"}
    table = _literal(image, data + 0x28, 1, 0)
    if (table is None or table & 3 or table < 8 or image[table:table + len(_TX_FRAME_TABLE)] != _TX_FRAME_TABLE or any(_literal(image, data + at, register, 0)
        != table + offset for at, register, offset in ((0x46, 0, 0xb4), (0x56, 3, 0x10), (0x78, 7, 0x70), (0x8a, 4, 0x90), (0x9e, 3, 0xb0))) or _literal(image,
        data + 0x12, 1, 0) != table - 8 or _literal(image, data + 0x1e, 1, 0) != table - 8):
        return {**result, "reject_reason": "tx-frame-table-unclosed"}
    diagnostic = _literal(image, data + 0x14, 0, 0)
    # Diagnostic record IDs vary independently of the device protocol.
    if (diagnostic is None or not 0 <= diagnostic < 0xffff or _literal(image, data + 0x20, 0, 0) != diagnostic + 1 or any(_literal(image, data + at, register, 0)
        != value for at, register, value in ((0x6a, 7, 0x030002a0), (0x74, 4, 0x03000220), (0x98, 4, 0x03000220), (0xbe, 3, 0xf083), (0xc4, 3, 0xf7c), (0xce, 2,
        0x03000280))) or facts_for(image).thumb_call_target(data + 0x16) != facts_for(image).thumb_call_target (data + 0x22) or facts_for(image).thumb_call_target(data
        + 0xe4) != facts_for(image).thumb_call_target(data + 0xee) or facts_for(image).thumb_call_target(data + 0xb8) != facts_for(image).thumb_call_target(init["control_helper"]
        + 0x18) or facts_for(image).thumb_call_target(data + 0xd6) != facts_for(image).thumb_call_target(init["control_helper"] + 0x2c)):
        return {**result, "reject_reason": "tx-frame-call-literal-alias-unclosed"}
    targets = tuple(dict.fromkeys(facts_for(image).thumb_call_target(data + at) for at in _TX_FRAME_DATA_SHAPE[1]))
    pools = tuple((((data + at + 4) & ~3) + (image[data + at] * 4), 4) for at in _TX_FRAME_DATA_SHAPE[2])
    # Two-byte target spans express map bounds only, not auxiliary semantics.
    code = init["code_dependencies"] + ((data, 0x110), (writer, 38), (table - 8, len(_TX_FRAME_TABLE) + 8)) + pools + tuple((target, 2) for target in targets)
    ram = init["ram_dependencies"] + ((working, 0xa4), (mode, 16), (shadow, 16))
    if (any(not 0 <= address <= len(image) - size for address, size in code) or any(not 0x01000000 <= address <= 0x02000000 - size for address, size in ram)):
        return {**result, "reject_reason": "tx-frame-dependency-unmapped"}
    return {**result, "accepted": True, "reject_reason": None, "data_helper": data, "data_call": data_call, "fixed_writer": writer, "fifo_port": 0x03000298,
        "mode_base": mode, "mode_address": mode + 12, "mode_literal_load": data + 2, "mode_byte_load": data + 6, "mode_range": (1, 4), "working_base": working,
        "working_buffer": working + 0x25, "table": table, "table_size": len(_TX_FRAME_TABLE), "maximum_buffer_bytes": 18, "unclosed_auxiliary_calls": tuple(facts_for(image).thumb_call_target(data
        + at) for at in (0x16, 0xe4, 0xf4, 0xfa, 0x100)), "code_dependencies": code, "ram_dependencies": ram}

_TRAFFIC_READER_SHAPE = (bytes.fromhex("f0b5041c171c0048c9000818c51f093d002a004e01d0012f0cd1287a40083083287b40080204120c211c004800000000002f01d0022f0dd1687a40083083687b40080204120ce11d1d31004800000000002f01d0032f0dd1a87a40083083a87b40080204120ce11d2f31004800000000002f01d0042f0bd1e87a40083083e87b40080204120ce11d3931004800000000f0bd"),
    (44, 76, 108, 140), (6, 18, 42, 74, 106, 138))
_TRAFFIC_METRICS_SHAPE = (bytes.fromhex("b0b5004ac0008018c21f093a507a004b4008023818830048078a0f713f120f70078a0f81977a7f08023f1f83078a4f713f124f70078a4f81d77a7f08023f1f83078a8f713f128f70078a8f81d77ad27b7f085208ba181a83028aca711212ca70008ac881487940004871887980008871c879c000c871b0bd"),
    (), (2, 14, 22))
_TRAFFIC_INIT_SHAPE = (bytes.fromhex("b0b5071c0000000000000000004c004ba188004d194020231943a180a1882981002801d10000000000000000a188004b1940a180a1882981002801d100000000004d004c032f0cdb00000000218a004b1940022319432182218a298000280cd109e000000000218a004b19402182218a2980002801d100000000004800000000002807d1381c000000000121381c00000000b0bd00210172004a0773011c101c00000000b0bd"),
    (4, 8, 36, 40, 60, 72, 98, 118, 124, 134, 142, 160), (12, 14, 18, 46, 64, 66, 78, 104, 122, 152))
_TRAFFIC_REGISTRATION_SHAPE = (bytes.fromhex("00484078000000000048012100000000004905200000000004e0"), (4, 12, 20), (0, 8, 16))
