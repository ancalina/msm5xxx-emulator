from __future__ import annotations

def find_rex_5ms_irq_route(image: bytes, tick_position: int, map_position=None, *, candidate_only_mapper: bool = False,) -> tuple[int, int, int, int, int, int,
    int] | None:
    """Bind one 5 ms callback; candidate-only mapping requires a pure mapper."""
    from . import REX_INTFREE_SIGNATURE, REX_INTLOCK_SIGNATURE, REX_IRQ_DRAIN_PATTERN, REX_IRQ_HANDLER_RUNTIME_SIZE, REX_IRQ_WRAPPER_SIGNATURE, rex_5ms_registration_targets, facts_for, rex_5ms_callback_at, rex_timer_advance_at, struct, trampm5_consumer_at
    runtime = map_position or (lambda position: position)
    tick_address = runtime(tick_position)
    if tick_address is None:
        return None
    delta = tick_address - tick_position
    def runtime_code(position: int) -> int | None:
        address = runtime(position)
        return address if address == position + delta else None
    walker = rex_5ms_callback_at(image, tick_position)
    if (walker is None or runtime_code(walker) is None or not rex_timer_advance_at(image, walker)):
        return None
    callback_targets = tuple(facts_for(image).thumb_call_target(tick_position + item) for item in (2, 14, 20, 42, 50, 58))
    if any(target is None or not 0 <= target < len(image) or runtime_code(target) is None for target in callback_targets):
        return None
    lock = facts_for(image).thumb_call_target(walker + 4)
    expiry = facts_for(image).thumb_call_target(walker + 42)
    unlock = facts_for(image).thumb_call_target(walker + 64)
    if (lock is None or expiry is None or unlock is None or any(runtime_code(target) is None for target in (lock, expiry, unlock)) or callback_targets[0] !=
        lock or callback_targets[3] != walker or callback_targets[5] != unlock or image[lock:lock + len(REX_INTLOCK_SIGNATURE)] != REX_INTLOCK_SIGNATURE or
        image[unlock: unlock + len(REX_INTFREE_SIGNATURE)] != REX_INTFREE_SIGNATURE or not 0 <= expiry <= len(image) - 60):
        return None
    expiry_words = struct.unpack_from("<30H", image, expiry)
    if not (expiry_words[:3] == (0xB5F0, 0x1C0E, 0x1C07) and facts_for(image).thumb_call_target(expiry + 6) == lock and expiry_words[5:12] == (0x68FC, 0x1C05,
        0x1C20, 0x4330, 0x60F8, 0x6938, 0x4030,) and expiry_words[12] & 0xFF00 == 0xD000 and expiry_words[13:16] == (0x2000, 0x6138, 0x4807) and expiry_words[16:21]
        == (0x6979, 0x6882, 0x6952, 0x4291, 0xD902,) and expiry_words[21] == 0x6087 and (target := facts_for(image).thumb_call_target(expiry + 44)) is not None
        and 0 <= target < len(image) and runtime_code(target) is not None and expiry_words[24:26] == (0x2D00, 0xD101) and facts_for(image).thumb_call_target(expiry
        + 52) == unlock and expiry_words[28:] == (0x1C20, 0xBDF0)):
        return None
    consumers: list[tuple[int, int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\x90\xb5\x08\x48", offset)) >= 0:
        result = trampm5_consumer_at(image, offset)
        if result is not None:
            consumers.append((offset, *result))
        offset += 2
    if len(consumers) != 1:
        return None
    consumer, q_get, thunk, queue = consumers[0]
    if any(runtime_code(target) is None for target in (consumer, q_get, thunk)):
        return None
    enqueue_matches: list[int] = []
    enqueue_layouts = ((bytes.fromhex("04043879240c002809d0"), 24, 32, 46, 54, 62, 0x48), (bytes.fromhex("04043879240c002808d0"), 22, 30, 44, 52, 60, 0x4C),)
    offset = 0
    while (offset := image.find(b"\x90\xb5\x07\x1c", offset)) >= 0:
        for (signature, get_at, unlock_a, unlock_b, put_stub_at, put_at, queue_at) in enqueue_layouts:
            q_put = facts_for(image).thumb_call_target(offset + put_at)
            enqueue_targets = tuple(facts_for(image).thumb_call_target(offset + item) for item in (get_at, put_stub_at, put_at))
            if (offset + queue_at + 4 <= len(image) and runtime_code(offset) is not None and image[offset + 8: offset + 18] == signature and facts_for(image).thumb_call_target(offset
                + 4) == lock and facts_for(image).thumb_call_target(offset + unlock_a) == unlock and facts_for(image).thumb_call_target(offset + unlock_b) ==
                unlock and all(target is not None and 0 <= target < len(image) and runtime_code(target) is not None for target in enqueue_targets) and q_put is
                not None and runtime_code(q_put) is not None and image[q_put:q_put + 6] == b"\x90\xb5\x0c\x1c\x07\x1c" and facts_for(image).thumb_call_target(q_put
                + 6) == lock and struct.unpack_from("<I", image, offset + queue_at)[0] == queue):
                enqueue_matches.append(offset)
        offset += 2
    if len(enqueue_matches) != 1:
        return None
    enqueue = enqueue_matches[0]
    producer = callback_targets[4]
    if (producer is None or not 0 <= producer <= len(image) - 0x54 or runtime_code(producer) is None or image[producer:producer + 6] !=
        b"\xf8\xb5\x0c\x1c\x07\x1c" or not all((target := facts_for(image).thumb_call_target(producer + item)) is not None and 0 <= target < len(image) and
        runtime_code(target) is not None for item in (6, 42, 68)) or facts_for(image).thumb_call_target(producer + 6) != lock or image[producer + 10:producer +
        42] != bytes.fromhex("0004000c00907868002824d08168091b81601de07868041c0069a168451a201c") or image[producer + 46:producer + 68] != bytes.fromhex("6069e668002808d02061a060207e002800d16061201c")
        or image[producer + 72:producer + 80] != bytes.fromhex("a562e01d15306662") or facts_for(image).thumb_call_target(producer + 80) != enqueue):
        return None
    candidates: list[tuple[int, int, int, int, int, int, int]] = []
    for match in REX_IRQ_DRAIN_PATTERN.finditer(image):
        tail = match.start()
        handler = tail - 0x34
        if (handler < 0 or image[handler:handler + 4] != b"\xf0\xb5\x86\xb0" or facts_for(image).thumb_call_target(tail + 16) != consumer or handler +
            REX_IRQ_HANDLER_RUNTIME_SIZE > len(image)):
            continue
        (summary, status, nesting, summary_high, groups, descriptors, enable) = struct.unpack_from("<7I", image, handler + 0x154)
        if (summary_high != summary + 8 or descriptors != summary + 0xC or groups != descriptors + 0x1D * 0x1C or status & 3 or enable != status + 8 or not
            0x03000000 <= status < 0x04000000 or struct.unpack_from ("<I", image, handler + 0x170)[0] != enable + 4):
            continue
        handler_address = runtime_code(handler)
        if handler_address is None:
            continue
        default_position = handler - 0x38
        default_address = (runtime_code(default_position) if 0 <= default_position < len(image) else None)
        if default_address is None:
            continue
        handler_literal = handler + 0x1D4
        if (struct.unpack_from("<I", image, handler_literal)[0] != handler_address | 1 or struct.unpack_from("<I", image, handler_literal + 4)[0] != queue):
            continue
        registration = handler_literal - 0x22
        if (runtime_code(registration) is None or facts_for(image).thumb_literal_value(registration, 1) != handler_address | 1 or struct.unpack_from("<H", image,
            registration + 2)[0] != 0x2000):
            continue
        setter = facts_for(image).thumb_call_target(registration + 4)
        if (setter is None or not 0 <= setter <= len(image) - 20 or runtime_code(setter) is None):
            continue
        if not (image[setter:setter + 2] == b"\x02\x1c" and image[setter + 4:setter + 8] == b"\x01\xd1\xc1\x60" and image[setter + 8:setter + 14] ==
            b"\xf7\x46\x01\x61\xf7\x46"):
            continue
        root = facts_for(image).thumb_literal_value(setter + 2, 0)
        if root is None or nesting != root + 0x14:
            continue
        wrappers: list[int] = []
        wrapper_body = REX_IRQ_WRAPPER_SIGNATURE[4:]
        wrapper = 0
        while (wrapper := image.find(wrapper_body, wrapper)) >= 0:
            entry = wrapper - 4
            wrapper_address = runtime_code(wrapper)
            entry_address = runtime_code(entry)
            if (entry >= 0 and not entry & 3 and not wrapper & 3 and wrapper_address is not None and entry_address is not None and not wrapper_address & 3 and
                not entry_address & 3 and wrapper + 0x25C <= len(image) and image[entry:wrapper] == REX_IRQ_WRAPPER_SIGNATURE[:4] and tuple(struct.unpack_from("<I",
                image, wrapper + item)[0] for item in (0x240, 0x244, 0x250, 0x254)) == (nesting, root + 0xC, root + 4, root + 8) and tuple(struct.unpack_from("<I",
                image, wrapper + item)[0] for item in (0x248, 0x24C, 0x258)) == (wrapper_address + 0x3C, wrapper_address + 0x40, wrapper_address + 0x168)):
                wrappers.append(entry)
            wrapper += 4
        if len(wrappers) != 1:
            continue
        registration_targets = rex_5ms_registration_targets(image, tick_address, runtime_code, candidate_only_mapper=candidate_only_mapper,)
        if (len(registration_targets) != 3 or len(set(registration_targets)) != 1):
            continue
        registrar = registration_targets[0]
        if (not 0 <= registrar <= len(image) - 0x70 or runtime_code(registrar) is None):
            continue
        words = struct.unpack_from("<23H", image, registrar)
        registrar_lock = facts_for(image).thumb_call_target(registrar + 6)
        if not (words[:3] == (0xB5F0, 0x1C04, 0x1C0F) and registrar_lock == lock and runtime_code(registrar_lock) is not None and image[registrar_lock:registrar_lock
            + len(REX_INTLOCK_SIGNATURE)] == REX_INTLOCK_SIGNATURE and words[5:7] == (0x1C05, 0x2F00) and words[8:14] == (0xD100, 0x1C37, 0x2C00, 0xDB01, 0x2C1D,
            0xDB03) and words[18:20] == (0x201C, 0x4360) and words[21:23] == (0x1840, 0x6147) and facts_for(image).thumb_literal_value(registrar + 40, 1) ==
            descriptors):
            if not (words[8:13] == (0xD100, 0x1C37, 0x2C00, 0xDB01, 0x2C1D) and words[13] == 0xDB04 and facts_for(image).thumb_literal_value(registrar + 42, 1)
                == descriptors):
                continue
        if (facts_for(image).thumb_literal_value(registrar + 14, 6) != default_address | 1):
            continue
        initializer = struct.pack("<8I", status, enable, 0x0200, summary, summary + 4, default_address | 1, 0, 4,)
        if image.count(initializer) != 1:
            continue
        indirect_calls = tuple(facts_for(image).thumb_call_target(handler + item) for item in (0xEA, 0x112))
        if (image[handler + 0xE8:handler + 0xEA] != b"\x78\x69" or image[handler + 0x110:handler + 0x112] != b"\x78\x69" or any(target is None or not 0 <=
            target < len(image) or runtime_code(target) is None or image[target:target + 2] != b"\x00\x47" for target in indirect_calls)):
            continue
        wrapper_address = runtime_code(wrappers[0])
        if wrapper_address is None:
            continue
        candidates.append((wrapper_address, handler_address, root + 0xC, descriptors + 0x1C * 0x1C + 0x14, status, enable, 0x0200,))
    return candidates[0] if len(candidates) == 1 else None

def find_rex_5ms_sleep_timer(image: bytes) -> tuple[int, int, int] | None:
    """Find a unique post-sleep hook and its proven 5 ms IRQ callback."""
    from . import REX_5MS_WRAPPER_ANCHOR, rex_5ms_callback_at, rex_sleep_call_at, rex_timer_advance_at
    sleep_calls: list[int] = []
    offset = 0
    sleep_anchor = bytes.fromhex("2078012806d1")
    while (offset := image.find(sleep_anchor, offset)) >= 0:
        call = rex_sleep_call_at(image, offset - 2)
        if call is not None:
            sleep_calls.append(call)
        offset += 2
    tick_callbacks: list[int] = []
    offset = 0
    while (offset := image.find(REX_5MS_WRAPPER_ANCHOR, offset)) >= 0:
        callback = offset - 24
        target = rex_5ms_callback_at(image, callback)
        if target is not None and rex_timer_advance_at(image, target):
            tick_callbacks.append(callback)
        offset += 2
    sleep_calls = list(dict.fromkeys(sleep_calls))
    tick_callbacks = list(dict.fromkeys(tick_callbacks))
    if len(sleep_calls) == len(tick_callbacks) == 1:
        # The controller BL must execute.  Hook its return address, then invoke
        # the firmware-installed callback before the following CMP runs.
        return sleep_calls[0] + 4, tick_callbacks[0], 5
    return None

def _legacy_timer_registration_at(image: bytes, scanner: int, callback_literal: int,) -> dict[str, int] | None:
    """Close one old timer registrar call's complete Thumb argument ABI."""
    from . import facts_for, struct
    if (callback_literal < 0x24 or callback_literal + 6 > len(image) or facts_for(image).thumb_literal_value(callback_literal, 1) != scanner | 1 or struct.unpack_from("<2H",
        image, callback_literal - 6) != (0x2219, 0x2319) or not any(struct.unpack_from("<2H", image, flag) == (0x2201, 0x9200) for flag in range(callback_literal
        - 16, callback_literal - 6, 2))):
        return None
    registrar = facts_for(image).thumb_call_target(callback_literal + 2)
    if registrar is None:
        return None
    setup = struct.unpack_from("<H", image, callback_literal - 2)[0]
    timer: int | None = None
    if setup & 0xFFC7 == 0x1C00 and not setup & 7:
        register = setup >> 3 & 7
        loads = [position for position in range(callback_literal - 0x24, callback_literal - 2, 2) if facts_for(image).thumb_literal_value(position, register) is
            not None]
        if len(loads) != 1:
            return None
        timer = facts_for(image).thumb_literal_value(loads[0], register)
        first = struct.unpack_from("<H", image, loads[0] + 2)[0]
        if (first >> 8 & 7 == register and first & 0xF800 in (0x3000, 0x3800)):
            timer += (first & 0xFF) * (1 if first & 0xF800 == 0x3000 else -1)
        elif (register >= 4 and callback_literal == loads[0] + 0x12 and first == (0x1C20 | register << 3) and facts_for(image).thumb_call_target(loads[0] + 4)
            is not None and struct.unpack_from("<2H", image, loads[0] + 8) == (0x2201, 0x9200)):
            pass
        elif (register >= 4 and callback_literal == loads[0] + 0x16 and first & 0xF800 == 0x7000 and (adjust := struct.unpack_from("<H", image, loads[0] + 4)[0])
            >> 8 & 7 == register and adjust & 0xF800 in (0x3000, 0x3800) and adjust & 0xFF and struct.unpack_from("<H", image, loads[0] + 6)[0] == (0x1C20 |
            register << 3) and facts_for(image).thumb_call_target(loads[0] + 8) is not None and struct.unpack_from("<2H", image, loads[0] + 12) == (0x2201,
            0x9200)):
            timer += (adjust & 0xFF) * (1 if adjust & 0xF800 == 0x3000 else -1)
        else:
            return None
    elif setup & 0xF800 == 0x3800:
        literal = facts_for(image).thumb_literal_value(callback_literal - 8, 0)
        if literal is None:
            return None
        timer = literal - (setup & 0xFF)
    if timer is None:
        return None
    return { "callback_literal_file_offset": ((callback_literal + 4) & ~3) + (struct.unpack_from("<H", image, callback_literal)[0] & 0xFF) * 4,
        "registration_callsite_file_offset": callback_literal + 2, "timer_object": timer, "registrar_file_offset": registrar, "initial": 0x19, "reload": 0x19,
        "stack_flag": 1, }

def find_rex_legacy_5ms_timer_bridge(image: bytes, scanner_file_offset: int, file_to_runtime=lambda position: position, runtime_to_file=lambda address: address,) -> dict[str,
    object] | None:
    """Return only a callback-specific, fully closed legacy 5 ms timer ABI."""
    from . import THUMB_BL_PATTERN, _legacy_timer_registration_at, facts_for, rex_legacy_5ms_callback_at, rex_timer_callback_drain_at, struct
    scanner = scanner_file_offset
    if scanner < 0 or scanner & 1 or scanner >= len(image):
        return None
    def runtime(position: int) -> int | None:
        address = file_to_runtime(position)
        return (address if isinstance(address, int) and address >= 0 and runtime_to_file(address) == position else None)
    scanner_runtime = runtime(scanner)
    outers: list[tuple[int, int, int]] = []
    for prefix in (b"\x80\xb5", b"\x90\xb5"):
        offset = 0
        while (offset := image.find(prefix, offset)) >= 0:
            walkers = rex_legacy_5ms_callback_at(image, offset)
            if walkers is not None and runtime(offset) is not None:
                outers.append((offset, *walkers))
            offset += 2
    if scanner_runtime is None or len(outers) != 1:
        return None
    outer, rex_walker, software = outers[0]
    if any(runtime(position) is None for position in (outer, rex_walker, software)):
        return None
    registration_sites: set[int] = set()
    literal = image.find(struct.pack("<I", scanner | 1))
    while literal >= 0:
        for position in range(max(0, literal - 0x400) & ~1, min(len(image) - 2, literal + 2), 2):
            if facts_for(image).thumb_literal_value(position, 1) == scanner | 1:
                registration_sites.add(position)
        literal = image.find(struct.pack("<I", scanner | 1), literal + 1)
    registrations = [result for position in registration_sites if (result := _legacy_timer_registration_at(image, scanner, position)) is not None]
    if len(registrations) != 1:
        return None
    registration = registrations[0]
    registrar = registration["registrar_file_offset"]
    if runtime(registrar) is None:
        return None
    if (software + 0x56 > len(image) or struct.unpack_from("<2H", image, software + 0x4E) != (0x1DF8, 0x3019)):
        return None
    expiry_callsite = software + 0x52
    veneer = facts_for(image).thumb_call_target(expiry_callsite)
    if veneer is None or runtime(veneer) is None:
        return None
    dispatcher_runtime = runtime(veneer)
    dispatcher_file = veneer
    if (veneer + 16 <= len(image) and struct.unpack_from("<2H", image, veneer) == (0x4778, 0x46C0) and struct.unpack_from("<2I", image, veneer + 4) == (0xE59FC000,
        0xE12FFF1C)):
        dispatcher_runtime = struct.unpack_from("<I", image, veneer + 12)[0] & ~1
        dispatcher_file = runtime_to_file(dispatcher_runtime)
    if (not isinstance(dispatcher_file, int) or not 0 <= dispatcher_file <= len(image) - 0x50 or runtime(dispatcher_file) != dispatcher_runtime):
        return None
    drains: list[tuple[int, int]] = []
    offset = 0
    while (offset := image.find(b"\x80\xb5", offset)) >= 0:
        queue = rex_timer_callback_drain_at(image, offset)
        if queue is not None and runtime(offset) is not None:
            drains.append((offset, queue))
        offset += 2
    if len(drains) != 1:
        return None
    drain, queue = drains[0]
    puts = [(site + 4, target) for site in range(dispatcher_file, min(dispatcher_file + 0x80, len(image) - 6), 2) if (struct.unpack_from("<H", image, site)[0]
        == 0x1C39 and facts_for(image).thumb_literal_value(site + 2, 0) == queue and (target := facts_for(image).thumb_call_target(site + 4)) is not None and
        runtime(target) is not None)]
    if len(puts) != 1:
        return None
    def drains_until_empty(caller: int) -> bool:
        if (caller + 8 > len(image) or facts_for(image).thumb_call_target(caller) != drain or struct.unpack_from ("<H", image, caller + 4)[0] != 0x2800 or
            runtime(caller) is None):
            return False
        branch = struct.unpack_from("<H", image, caller + 6)[0]
        if branch & 0xFF00 != 0xD100:
            return False
        displacement = (branch & 0xFF) * 2
        if displacement & 0x100:
            displacement -= 0x200
        return caller + 10 + displacement == caller
    loops = [caller for match in THUMB_BL_PATTERN.finditer(image) if not (caller := match.start()) & 1 and drains_until_empty(caller)]
    if len(loops) != 1:
        return None
    addresses = (scanner, outer, rex_walker, software, registrar, registration["callback_literal_file_offset"], expiry_callsite, veneer, dispatcher_file, puts[0][0],
        puts[0][1], drain, loops[0])
    if any(runtime(position) is None for position in addresses):
        return None
    return { "signature": "legacy-rex-5ms-scanner-timer-v1", "tick_ms": 5, "scanner": scanner_runtime, "scanner_file_offset": scanner, "callback":
        scanner_runtime | 1, "outer_callback": runtime(outer), "outer_callback_file_offset": outer, "outer_callback_pointer": runtime(outer) | 1, "rex_walker":
        runtime (rex_walker), "rex_walker_file_offset": rex_walker, "software_timer": runtime(software), "software_timer_file_offset": software, "timer_object":
        registration["timer_object"], "registrar": runtime(registrar), "registrar_file_offset": registrar, "registration_callsite": runtime(registration["registration_callsite_file_offset"]),
        "registration_callsite_file_offset": registration["registration_callsite_file_offset"], "callback_literal": runtime(registration["callback_literal_file_offset"]),
        "callback_literal_file_offset": registration["callback_literal_file_offset"], "initial": 0x19, "reload": 0x19, "stack_flag": 1,
        "software_expiry_enqueue_callsite": runtime(expiry_callsite), "software_expiry_enqueue_callsite_file_offset": expiry_callsite, "enqueue_target": runtime(veneer),
        "enqueue_target_file_offset": veneer, "dispatcher": dispatcher_runtime, "dispatcher_file_offset": dispatcher_file, "dispatcher_qput_callsite": runtime(puts[0][0]),
        "dispatcher_qput_callsite_file_offset": puts[0][0], "qput": runtime(puts[0][1]), "qput_file_offset": puts[0][1], "callback_queue": queue, "drain":
        runtime(drain), "drain_file_offset": drain, "drain_loop_caller": runtime(loops[0]), "drain_loop_caller_file_offset": loops[0], "drain_loop_signature":
        "BL drain; CMP R0,#0; BNE back", }

def _relocated_thumb_file_target(image: bytes, callsite: int, file_to_runtime, runtime_to_file,) -> int | None:
    """Map one PC-relative Thumb BL target through executable copies."""
    from . import facts_for
    raw_target = facts_for(image).thumb_call_target(callsite)
    caller = file_to_runtime(callsite)
    if (not isinstance(raw_target, int) or not isinstance(caller, int) or not 0 <= caller <= 0xFFFFFFFF):
        return None
    address = caller + raw_target - callsite
    if not 0 <= address <= 0xFFFFFFFF:
        return None
    target = runtime_to_file(address)
    return (target if isinstance(target, int) and 0 <= target < len(image) and file_to_runtime(target) == address else None)
