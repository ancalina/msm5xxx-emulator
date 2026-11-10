from __future__ import annotations

def find_rex_static_controller_callback_candidate(image: bytes, *, ram_base: int, ram_size: int,) -> dict[str, object] | None:
    """Return a telemetry-only old-controller callback topology, if closed.

    This proves only static descriptor, handler, registrar, and timer-list
    topology.  It deliberately does not claim a pending-bit source, inject an
    IRQ, or promote a handset phase.
    """
    from . import REX_LEGACY_5MS_CALLBACK_SIZE, _c80_full_handler_span, _controller_callback_advance, _controller_registrar_at, _controller_two_bank_handler_at, _find_rex_620_static_controller_callback_candidate, _legacy_620_vector_copy, _nand_backed_veneer_chain, _normalized_thumb_sha256, _ram_contains, arm_b_word_target, facts_for, rex_legacy_5ms_callback_shape_at, struct
    if len(image) < 0x100:
        return None
    seeds: list[tuple[int, tuple[int, ...]]] = []
    for status, enable in ((0x03000C80, 0x03000C94), (0x03000FB0, 0x03000FC4)):
        prefix = struct.pack("<3I", status, enable, 0x200)
        offset = 0
        while (offset := image.find(prefix, offset)) >= 0:
            if offset + 28 <= len(image):
                seed = struct.unpack_from("<7I", image, offset)
                if (seed[4] == seed[3] + 6 and _ram_contains(seed[3], 4, ram_base, ram_size) and seed[5] & 1 and (seed[5] & ~1) < len(image) and seed[6] == 0):
                    seeds.append((offset, seed))
            offset += 1
    if not seeds:
        return _find_rex_620_static_controller_callback_candidate(image, ram_base=ram_base, ram_size=ram_size)
    fb0 = seeds[0][1][0] == 0x03000FB0
    index = 0x1B if fb0 else 0x1E
    control = 0x030006E0 if fb0 else 0x030007A0
    signature = ("static-fb0-controller-callback-v1" if fb0 else "static-c80-controller-callback-v1")
    semantic_limit = ("static topology only; native pending, IRQ, and idle remain unproven")
    def rejected(reason: str) -> dict[str, object]:
        return { "signature": signature, "accepted": False, "active": False, "semantic_limit": semantic_limit, "reject_reason": reason, }
    vector_target = arm_b_word_target(struct.unpack_from("<I", image, 0x18)[0], 0x18)
    vector_copy = _legacy_620_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
    vector_source_chain = (_nand_backed_veneer_chain(image, ram_base=ram_base, ram_size=ram_size) if not fb0 and vector_copy is None else None)
    if vector_source_chain is not None:
        vector_target = vector_source_chain["copy_target"]
        vector_copy = (vector_source_chain["copy_source"], vector_target, vector_source_chain["copy_size"], vector_source_chain["wrapper"],)
    if (vector_target is None or not _ram_contains(vector_target, 4, ram_base, ram_size)):
        return rejected("raw-vector-outside-ram")
    if vector_copy is None:
        return rejected("copied-vector-route-not-closed")
    if len(seeds) != 1:
        return rejected("descriptor-seed-ambiguous")
    descriptor_file_offset, seed = seeds[0]
    status, enable, mask, masks, _unused, default, _reserved = seed
    handler = (default & ~1) + (0x64 if fb0 else 0x68)
    if not _controller_two_bank_handler_at(image, handler, masks, status):
        return rejected("two-bank-handler-not-closed")
    handler_validation_size = (0x182 if fb0 else 0x150 if struct.unpack_from("<H", image, handler + 2)[0] == 0xB087 else 0x100)
    group_row_size = (10 if fb0 or handler_validation_size == 0x150 else 12 if _normalized_thumb_sha256(image, handler, 0x100) == ("e2d286a40ba316e36638235247203ba5ab1800c3f1b50149a9a36be770d40f17",
        (0x04, 0x34, 0x94, 0xBA, 0xF6),) else None)
    registrations: list[tuple[int, int, int, int]] = []
    registration_positions: list[int] = []
    prefix = b"\x02\x20\x08\x70"
    offset = 0
    while (offset := image.find(prefix, offset)) >= 0:
        registration = offset + len(prefix) + 2
        if not registration & 1 and 8 <= registration <= len(image) - 6:
            registration_positions.append(registration)
        offset += 1
    for registration in registration_positions:
        if (struct.unpack_from("<H", image, registration)[0] != (0x2000 | index) or facts_for(image).thumb_literal_value(registration - 2, 1) is None or
            facts_for(image).thumb_literal_value(registration - 8, 1) != control or struct.unpack_from("<2H", image, registration - 6) != (0x2002, 0x7008)):
            continue
        callback_pointer = facts_for(image).thumb_literal_value(registration - 2, 1)
        registrar = facts_for(image).thumb_call_target(registration + 2)
        if (callback_pointer is None or not callback_pointer & 1 or registrar is None):
            continue
        callback = callback_pointer & ~1
        table = _controller_registrar_at(image, registrar, default, fb0=fb0)
        advance = _controller_callback_advance(image, callback)
        if (table is not None and _ram_contains(table, 4, ram_base, ram_size) and advance is not None):
            registrations.append((registration, callback, registrar, advance))
    if len(registrations) != 1:
        return rejected(f"row{index:02x}-callback-route-not-unique")
    registration, callback, registrar, advance = registrations[0]
    table = _controller_registrar_at(image, registrar, default, fb0=fb0)
    if table is None or not _ram_contains(table, 4, ram_base, ram_size):
        return rejected("registrar-not-closed")
    if fb0:
        source, destination, size, _wrapper = vector_copy
        # Body hashes erase BL immediates, so every erased target needs bounds.
        calls = [(handler, (0x30, 0x92, 0xB6, 0xEE, 0x106, 0x142, 0x148, 0x15A)), (registrar, (0x06, 0x1C, 0x26, 0x76))]
        if any(target is None or not 0 <= target <= len(image) - 2 for body, offsets in calls for delta in offsets for target in (facts_for(image).thumb_call_target(body
            + delta),)):
            return rejected("fb0-call-target-outside-image")
        mask_helper = facts_for(image).thumb_call_target(registrar + 0x06)
        restore_helper = facts_for(image).thumb_call_target(registrar + 0x76)
        # Thumb BX PC enters ARM; preserve the exact CPSR I/F mask return ABI.
        for target, instruction in ((mask_helper, 0xE38010C0), (restore_helper, 0xE3C010C0)):
            expected = b"\x78\x47\x00\x00" + struct.pack("<5I", 0xE10F0000, instruction, 0xE121F001, 0xE20000C0, 0xE12FFF1E,)
            if target & 3 or image[target:target + len(expected)] != expected:
                return rejected("fb0-mask-restore-abi-not-closed")
        diagnostic = facts_for(image).thumb_call_target(handler + 0x148)
        # Close only this callable body and its callee bounds, not nested queue
        # or diagnostic semantics. Registrar error calls likewise have bounds only.
        if (_normalized_thumb_sha256(image, diagnostic, 0x26) != ("1f121709790fffac7e869f0e87027b3541ff08d8ac602ff7bd155e06b07b05b4", (0x04, 0x12),) or any(target
            is None or not 0 <= target <= len(image) - 2 for delta in (0x04, 0x12) for target in (facts_for(image).thumb_call_target(diagnostic + delta),))):
            return rejected("fb0-diagnostic-body-not-closed")
        row = table + index * 0x1C
        if (table != masks + 0x0C or not _ram_contains(masks, 12, destination, size) or not _ram_contains(row, 28, destination, size) or source + row -
            destination != descriptor_file_offset or facts_for(image).thumb_call_target(registrar + 0x06) != facts_for(image).thumb_call_target(handler + 0x142)
            or facts_for(image).thumb_call_target(registrar + 0x06) != facts_for(image).thumb_call_target(handler + 0x15A) or facts_for(image).thumb_call_target(registrar
            + 0x76) != facts_for(image).thumb_call_target (handler + 0x30) or facts_for(image).thumb_call_target(registrar + 0x76) != facts_for(image).thumb_call_target(handler
            + 0x92)):
            return rejected("copied-descriptor-relations-not-closed")
    wrapper_prefix = struct.pack("<4I", 0xE24EE004, 0xE92D540F, 0xE14F0000, 0xE92D0001)
    wrappers: list[tuple[int, int, int]] = []
    position = 0
    while (position := image.find(wrapper_prefix, position)) >= 0:
        if not position & 3 and position + 0x34 <= len(image):
            instruction = struct.unpack_from("<I", image, position + 0x28)[0]
            if instruction & 0xFFFFF000 == 0xE59F3000:
                literal = position + 0x30 + (instruction & 0xFFF)
                if literal + 4 <= len(image):
                    wrappers.append((position, struct.unpack_from("<I", image, literal)[0], literal + 4 - position))
        position += 4
    if len(wrappers) != 1:
        return rejected("irq-wrapper-not-unique")
    wrapper, handler_slot, wrapper_size = wrappers[0]
    if vector_copy is not None and vector_copy[3] != wrapper:
        return rejected("copied-vector-wrapper-mismatch")
    if not _ram_contains(handler_slot, 8, ram_base, ram_size):
        return rejected("handler-slot-outside-ram")
    def literal_loads(value: int, register: int) -> set[int]:
        loads: set[int] = set()
        literal = image.find(struct.pack("<I", value))
        while literal >= 0:
            for candidate in range(max(0, literal - 0x400) & ~1, min(len(image) - 2, literal + 2), 2):
                if facts_for(image).thumb_literal_value(candidate, register) == value:
                    loads.add(candidate)
            literal = image.find(struct.pack("<I", value), literal + 1)
        return loads
    setters: list[tuple[int, int]] = []
    for position in literal_loads(handler | 1, 1):
        if struct.unpack_from("<H", image, position + 2)[0] != 0x2000:
            continue
        setter = facts_for(image).thumb_call_target(position + 4)
        if (setter is not None and setter + 16 <= len(image) and struct.unpack_from("<6H", image, setter) == (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
            setter = struct.unpack_from("<I", image, setter + 12)[0] & ~1
        if setter is None or setter + 14 > len(image):
            continue
        words = struct.unpack_from("<7H", image, setter)
        base = facts_for(image).thumb_literal_value(setter, 2)
        first = (words[3] >> 6 & 0x1F) * 4
        second = (words[5] >> 6 & 0x1F) * 4
        if (words[1:3] == (0x2800, 0xD101) and words[3] & 0xF83F == 0x6011 and words[4] == 0x4770 and words[5] & 0xF83F == 0x6011 and words[6] == 0x4770 and
            base is not None and base + first == handler_slot and second == first + 4):
            setters.append((position, setter))
    if len(setters) != 1:
        return rejected("handler-setter-not-unique")
    callback_slot = (table if fb0 else masks + 0x0C) + index * 0x1C + 0x14
    if not _ram_contains(callback_slot, 4, ram_base, ram_size):
        return rejected(f"row{index:02x}-callback-slot-invalid")
    callback_shape = rex_legacy_5ms_callback_shape_at(image, callback)
    if callback_shape is None:
        return rejected("legacy-callback-validator-not-closed")
    if not fb0:
        full_span = _c80_full_handler_span(image, handler, masks, wrapper, ram_base, ram_size)
        if full_span == 0:
            return rejected("controller-handler-full-span-not-closed")
        if full_span is not None:
            handler_validation_size = full_span
        if full_span == 0x188:
            # Compact group-10 body is closed above; its copied tick row must
            # also bind the group consumer to this descriptor and registrar.
            source, destination, size, _wrapper = vector_copy
            group = masks + 0x374
            row = masks + 12 + index * 0x1C
            group_rom = source + group - destination
            if (_controller_registrar_at(image, registrar, default, group_base=True) == masks + 12 and _ram_contains(masks, 12, destination, size) and
                _ram_contains(row, 28, destination, size) and _ram_contains(group, 40, destination, size) and source + row - destination ==
                descriptor_file_offset and 0 <= group_rom <= len(image) - 40 and image[handler + 0x48:handler + 0x4C] == bytes.fromhex("05980a23") and image[handler
                + 0x4E:handler + 0x54] == bytes.fromhex("584340180090") and image[group_rom + 30:group_rom + 40] == struct.pack("<4H2B", mask, 0, mask, 4, index,
                index)):
                group_row_size = 10
    return {
        "signature": signature,
        "accepted": True,
        "active": False,
        "semantic_limit": (
            f"exact group-{group_row_size} two-bank W1C route with a "
            "5-unit service callback; physical clock fidelity remains "
            "approximated"
            if group_row_size is not None else semantic_limit
        ),
        "controller_class": (
            "legacy-fb0-index1b-delta5-controller-candidate-v1" if fb0 else
            "legacy-c80-index1e-delta5-controller-candidate-v1"
        ),
        "descriptor_file_offset": descriptor_file_offset,
        "status": status,
        "status_banks": (status, status + 4),
        "enable": enable,
        "enable_banks": (enable, enable + 4),
        "mask": mask,
        "mask_table": masks,
        "default_callback": default,
        "handler_file_offset": handler,
        "registration_file_offset": registration,
        "callback_file_offset": callback,
        "registrar_file_offset": registrar,
        "descriptor_table": table,
        "timer_advance_file_offset": advance,
        "vector": 0x18,
        "vector_target": vector_target,
        "vector_copy_source": vector_copy[0] if vector_copy else None,
        "vector_copy_size": vector_copy[2] if vector_copy else None,
        **({"vector_source_chain": vector_source_chain}
           if vector_source_chain is not None else {}),
        "wrapper_file_offset": wrapper,
        "handler_slot": handler_slot,
        "handler_registration_file_offset": setters[0][0],
        "handler_setter_file_offset": setters[0][1],
        "callback_slot": callback_slot,
        "clear_banks": (status, status + 4),
        "controller_write_banks": (enable, enable + 4),
        "controller_aperture": (status, enable + 6),
        "handler_validation_size": handler_validation_size,
        "wrapper_validation_size": wrapper_size,
        "callback_delta": 5,
        "callback_validation_size": REX_LEGACY_5MS_CALLBACK_SIZE,
        "callback_validation_shape": callback_shape,
        **({
            "promotion": "experimental-only" if fb0 else "temporary-evidence-gated",
            "status_bank_count": 2,
            "group_row_size": group_row_size,
            "pending_read_semantics": "latched-read",
            "pending_ack_semantics": "write-one-to-clear",
            "time_tick_status_bank": status,
            "time_tick_clear_bank": status,
            "time_tick_mask": mask,
            **({"time_tick_control_address": control} if fb0 else {}),
        } if group_row_size is not None else {}),
    }

def _find_rex_direct_c40_controller_observation(image: bytes,) -> dict[str, object] | None:
    """Return one closed C40 TIME_TICK observation."""
    from . import arm_b_word_target, facts_for, struct
    status, enable, mask = 0x03000C40, 0x03000C54, 0x0200
    prefix = struct.pack("<3I", status, enable, mask)
    descriptors: list[tuple[int, int]] = []
    offset = 0
    while (offset := image.find(prefix, offset)) >= 0:
        if offset + 16 <= len(image):
            shadow = struct.unpack_from("<I", image, offset + 12)[0]
            if 0x01000000 <= shadow < 0x02000000 and not shadow & 1:
                descriptors.append((offset, shadow))
        offset += 1
    if not descriptors:
        return None
    limit = ("static controller and one-shot route only; native pending, " "cadence, repeat IRQ, and idle remain unproven")
    def rejected(reason: str, **details: object) -> dict[str, object]:
        return { "signature": "static-c40-selector0-delta5-controller-v1", "accepted": False, "active": False, "promotion": "telemetry-only", "semantic_limit":
            limit, "reject_reason": reason, **details, }
    if len(descriptors) != 1:
        return rejected("c40-descriptor-not-unique", descriptor_count=len(descriptors))
    descriptor, shadow = descriptors[0]
    if len(image) < 0x1C or arm_b_word_target(struct.unpack_from("<I", image, 0x18)[0], 0x18) != 0x01380000:
        return rejected("runtime-vector-target-mismatch", descriptor_file_offset=descriptor, mask_shadow=shadow)
    arms: list[int] = []
    offset = 0
    while (offset := image.find(b"\x02\x20\x08\x70", offset)) >= 0:
        position = offset - 2
        offset += 1
        if (position < 0 or position & 1 or position + 6 > len(image) or struct.unpack_from("<H", image, position)[0] & 0xF800 != 0x4800 or struct.unpack_from("<H",
            image, position)[0] & 0x0700 != 0x0100 or facts_for(image).thumb_literal_value(position, 1) != 0x030006E0):
            continue
        arms.append(position)
    if len(arms) != 1:
        return rejected("time-tick-arm-not-unique", descriptor_file_offset=descriptor, arm_count=len(arms))
    handlers: list[tuple[int, int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\xf0\xb5", offset)) >= 0:
        position = offset
        offset += 1
        if position & 1 or position + 0x3D0 > len(image):
            continue
        if (facts_for(image).thumb_literal_value(position + 0x0A, 6) != shadow or facts_for(image).thumb_literal_value(position + 0x0C, 7) != status):
            continue
        tick, tail = position + 0x112, position + 0x396
        if (struct.unpack_from("<2H", image, tick) != (0x0A8A, 0xD30A) or facts_for(image).thumb_literal_value(tick + 4, 0) is None or struct.unpack_from("<H",
            image, tick + 6)[0] != 0x6980 or facts_for(image).thumb_call_target(tick + 8) != 0x1254 or struct.unpack_from("<2H", image, tick + 0x14) != (0x2001,
            0x0240) or (branch := struct.unpack_from("<H", image, tick + 0x18)[0]) & 0xF800 != 0xE000 or tick + 0x1C + (((branch & 0x7FF) << 1) - (0x1000 if
            branch & 0x400 else 0)) != position + 0x2BC or facts_for(image).thumb_literal_value(position + 0x2BC, 1) != status or struct.unpack_from("<H", image,
            position + 0x2BE)[0] != 0x8008 or facts_for(image).thumb_literal_value(tail, 2) != shadow or facts_for(image).thumb_literal_value(tail + 2, 1) !=
            status or struct.unpack_from("<8H", image, tail + 4) != (0x8810, 0x880B, 0x4018, 0x0400, 0x4E15, 0x0C00, 0x8430, 0x8852) or struct.unpack_from("<H",
            image, position + 0x3CE)[0] != 0xBDF0):
            continue
        table = facts_for(image).thumb_literal_value(tick + 4, 0)
        assert table is not None
        if 0x01000000 <= table < 0x02000000:
            handlers.append((position, table, table + 0x18, position + 0x2BC))
    if len(handlers) != 1:
        return rejected("c40-handler-not-unique", descriptor_file_offset=descriptor, mask_shadow=shadow, handler_count=len(handlers))
    handler, table, callback_slot, w1c = handlers[0]
    if callback_slot - shadow != 0x208:
        return rejected("callback-slot-mask-shadow-mismatch", descriptor_file_offset=descriptor, mask_shadow= shadow)
    wrapper_prefix = struct.pack("<4I", 0xE24EE004, 0xE92D540F, 0xE14F0000, 0xE92D0001)
    wrappers: list[tuple[int, int]] = []
    offset = 0
    while (offset := image.find(wrapper_prefix, offset)) >= 0:
        if not offset & 3 and offset + 0x34 <= len(image):
            instruction = struct.unpack_from("<I", image, offset + 0x28)[0]
            if instruction & 0xFFFFF000 == 0xE59F3000:
                literal = offset + 0x30 + (instruction & 0xFFF)
                if literal + 4 <= len(image):
                    slot = struct.unpack_from("<I", image, literal)[0]
                    if 0x01000000 <= slot < 0x02000000 and not slot & 3:
                        wrappers.append((offset, slot))
        offset += 4
    if len(wrappers) != 1:
        return rejected("irq-wrapper-not-unique", descriptor_file_offset=descriptor, mask_shadow=shadow, wrapper_count=len(wrappers))
    def dispatcher_at(position: int) -> bool:
        if position < 0 or position + 0x66 > len(image):
            return False
        words = struct.unpack_from("<51H", image, position)
        entry = words[0x12]
        target = (position + 0x28 + ((entry & 0x7FF) << 1) - (0x1000 if entry & 0x400 else 0))
        return (words[:3] == (0xB5F0, 0x1C05, 0x1C0F) and words[3] & 0xF800 == 0xF000 and words[4] & 0xF800 == 0xF800 and words[5:7] == (0x1C04, 0x2F00) and
            words[7] & 0xF800 == 0x4800 and words[8:10] == (0xD100, 0x1C37) and facts_for(image).thumb_literal_value(position + 0x14, 1) == table + 0x7C and
            entry & 0xF800 == 0xE000 and target == position + 0x64 and words[0x32] == 0x6187)
    registrations: list[tuple[int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\x49", offset)) >= 0:
        position = offset - 1
        offset += 1
        if position < 0 or position & 1 or position >= len(image) - 8:
            continue
        callback = facts_for(image).thumb_literal_value(position, 1)
        if (callback is None or not callback & 1 or struct.unpack_from("<H", image, position + 2)[0] != 0x2000):
            continue
        dispatcher = facts_for(image).thumb_call_target(position + 4)
        if dispatcher is not None and dispatcher_at(dispatcher):
            registrations.append((position, callback & ~1, dispatcher))
    if not registrations or len({item[1] for item in registrations}) != 1 \
            or len({item[2] for item in registrations}) != 1:
        return rejected("selector0-registration-not-unique", descriptor_file_offset=descriptor, mask_shadow= shadow, registration_count=len(registrations))
    registration, callback, dispatcher = registrations[0]
    # The registered callback itself, not an unrelated global call, advances
    # the same active timer list by five units.
    def walker_at(position: int) -> bool:
        if position < 0 or position + 0x24 > len(image):
            return False
        words = struct.unpack_from("<18H", image, position)
        return (words[:3] == (0xB5F8, 0x1C0C, 0x1C07) and words[3] & 0xF800 == 0xF000 and words[4] & 0xF800 == 0xF800 and words[5:8] == (0x9000, 0x6878, 0x2800)
            and words[8] & 0xFF00 == 0xD000 and words[9:12] == (0x6881, 0x1B09, 0x6081) and words[12] & 0xF800 == 0xE000 and words[13:] == (0x6878, 0x1C04,
            0x6900, 0x68A1, 0x1A45))
    delta_call = callback + 0x32
    walker = (facts_for(image).thumb_call_target(delta_call) if callback + 0x36 <= len(image) else None)
    if (callback + 0x36 > len(image) or struct.unpack_from("<H", image, callback)[0] != 0xB590 or struct.unpack_from("<H", image, callback + 0x30)[0] != 0x2105
        or walker is None or not walker_at(walker)):
        walker_count = sum(walker_at(position) for position in range(0, len(image) - 0x24 + 1, 2))
        return rejected("callback-delta5-walker-not-closed", descriptor_file_offset=descriptor, mask_shadow= shadow, callback_file_offset=callback, walker_count=walker_count)
    clients: list[int] = []
    client_prefix = struct.pack("<4H", 0x2201, 0x9200, 0x2219, 0x2319)
    offset = 0
    while (offset := image.find(client_prefix, offset)) >= 0:
        position = offset
        offset += 1
        if (not position & 1 and position < len(image) - 14 and any(facts_for(image).thumb_call_target(call) is not None for call in range(position + 8,
            position + 14, 2))):
            clients.append(position)
    if len(clients) != 1:
        return rejected("periodic-25-client-not-unique", descriptor_file_offset=descriptor, mask_shadow=shadow, periodic_25_count=len(clients))
    wrapper, handler_slot = wrappers[0]
    return { "signature": "static-c40-selector0-delta5-controller-v1", "accepted": True, "active": False, "promotion": "telemetry-only", "semantic_limit": limit,
        "controller_class": "c40-two-bank-selector0-delta5-v1", "descriptor_file_offset": descriptor, "mask_shadow": shadow, "status_banks": (status, status + 4),
        "enable_banks": (enable, enable + 4), "mask": mask, "selector": 0, "callback_slot": callback_slot, "descriptor_table": table, "registration_file_offset":
        registration, "dispatcher_file_offset": dispatcher, "callback_file_offset": callback, "handler_file_offset": handler, "w1c_file_offset": w1c,
        "wrapper_file_offset": wrapper, "handler_slot": handler_slot, "vector": 0x18, "vector_target": 0x01380000, "timer_walker_file_offset": walker,
        "delta5_call_file_offset": delta_call, "periodic_25_client_file_offset": clients[0], "time_tick_control_file_offset": arms[0],
        "time_tick_control_address": 0x030006E0, "time_tick_arm_value": 2, "time_tick_period_ms": 5, }
