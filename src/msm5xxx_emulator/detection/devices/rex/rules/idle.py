from __future__ import annotations

def find_rex_legacy_5ms_irq_route(image: bytes, bridge: dict[str, object], file_to_runtime=lambda position: position, runtime_to_file=lambda address: address, *,
    allow_b590_registrar: bool = False,) -> dict[str, object] | None:
    """Close one old-LG controller descriptor route for a legacy timer bridge.

    This deliberately proves code/data topology only.  It does not assign a
    peripheral polarity or arrange host IRQ delivery.
    """
    from . import REX_IRQ_HANDLER_RUNTIME_SIZE, REX_IRQ_WRAPPER_RUNTIME_SIZE, _relocated_thumb_file_target, arm_b_word_target, facts_for, struct
    outer = bridge.get("outer_callback_file_offset")
    loop = bridge.get("drain_loop_caller_file_offset")
    drain = bridge.get("drain_file_offset")
    if (not isinstance(outer, int) or not isinstance(loop, int) or not isinstance(drain, int) or not 0 <= outer < len(image) or not 0 <= loop < len(image) or
        not 0 <= drain < len(image)):
        return None
    def runtime(position: int) -> int | None:
        address = file_to_runtime(position)
        return (address if isinstance(address, int) and address >= 0 and runtime_to_file(address) == position else None)
    def resolve_thumb(target: int | None) -> int | None:
        """Resolve a direct Thumb target or the exact BX-PC ARM veneer."""
        if target is None or not 0 <= target < len(image):
            return None
        if (target + 12 <= len(image) and struct.unpack_from("<6H", image, target) == (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
            address = struct.unpack_from("<I", image, target + 12)[0] & ~1
            mapped = runtime_to_file(address)
            if (isinstance(mapped, int) and 0 <= mapped < len(image) and runtime(mapped) == address):
                return mapped
            return None
        if runtime(target) is not None:
            return target
        return None
    outer_runtime = runtime(outer)
    if outer_runtime is None:
        return None
    def literal_loads(value: int, register: int) -> set[int]:
        """Bound Thumb-LDR search to actual little-endian literal pools."""
        loads: set[int] = set()
        literal = image.find(struct.pack("<I", value))
        while literal >= 0:
            for candidate in range(max(0, literal - 0x400) & ~1, min(len(image) - 2, literal + 2), 2):
                if facts_for(image).thumb_literal_value(candidate, register) == value:
                    loads.add(candidate)
            literal = image.find(struct.pack("<I", value), literal + 1)
        return loads
    registrations: list[tuple[int, int, int]] = []
    for position in literal_loads(outer_runtime | 1, 1):
        index_word = struct.unpack_from("<H", image, position + 2)[0]
        target = resolve_thumb(facts_for(image).thumb_call_target(position + 4))
        if index_word & 0xFF00 == 0x2000 and target is not None:
            index = index_word & 0xFF
            if index in (0x1E, 0x2B):
                registrations.append((position, index, target))
    if len(registrations) != 3 or len({item[1:] for item in registrations}) != 1:
        return None
    registration, index, registrar = registrations[0]
    if (registrar + 0x70 > len(image) or runtime(registrar) is None):
        return None
    words = struct.unpack_from("<56H", image, registrar)
    b590_registrar = (allow_b590_registrar and index == 0x2B and words[:3] == (0xB590, 0x1C04, 0x1C0F) and words[5:47] == (0x4917, 0x2F00, 0xD100, 0x1C0F,
        0x221C, 0x4B15, 0x4362, 0x18D2, 0x2C00, 0xD102, 0x4B14, 0x621F, 0xE000, 0x6157, 0x428F, 0xD104, 0x68D1, 0x880B, 0x8917, 0x43BB, 0xE00A, 0x68D1, 0x880B,
        0x8911, 0x400B, 0xD106, 0x6813, 0x8019, 0x68D1, 0x880B, 0x8917, 0x433B, 0x800B, 0x68D1, 0x6913, 0x8809, 0x881B, 0x6852, 0x4019, 0x8011, 0x2800, 0xD101,)
        and words[49:52] == (0xBC90, 0xBC08, 0x4718) and all(words[call] & 0xF800 == 0xF000 and words[call + 1] & 0xF800 == 0xF800 and facts_for(image).thumb_call_target(registrar
        + call * 2) is not None for call in (3, 47)))
    global_slot = None
    if b590_registrar:
        descriptor_base = facts_for(image).thumb_literal_value(registrar + 20, 3)
        default_callback = facts_for(image).thumb_literal_value(registrar + 10, 1)
        global_slot = facts_for(image).thumb_literal_value(registrar + 30, 3)
    else:
        if not (words[:3] == (0xB5F0, 0x1C04, 0x1C0F) and words[5:14] == (0x1C05, 0x2F00, words[7], 0xD100, 0x1C37, 0x2C00, 0xDB01, 0x2C00 | (0x1F if index ==
            0x1E else 0x2C), words[13],)):
            return None
        store = 0x630F if index == 0x1E else 0x620F
        layouts = [(multiply, descriptor_load) for multiply, descriptor_load, stores in ((21, 44, 28), (20, 42, 27), (19, 40, 26),) if words[multiply:multiply +
            4] == (0x201C, words[multiply + 1], 0x4360, 0x1840) and words[stores:stores + 3] == (store, 0xE000, 0x6147)]
        if len(layouts) != 1:
            return None
        descriptor_base = facts_for(image).thumb_literal_value(registrar + layouts[0][1], 1)
        default_callback = facts_for(image).thumb_literal_value(registrar + 14, 6)
    if descriptor_base is None or default_callback is None:
        return None
    seed_prefix = struct.pack("<3I", 0x03000C80, 0x03000C94, 0x200)
    seeds: list[tuple[int, tuple[int, ...]]] = []
    offset = 0
    while (offset := image.find(seed_prefix, offset)) >= 0:
        if offset + 28 <= len(image):
            seed = struct.unpack_from("<7I", image, offset)
            if seed[6] == 0 and seed[3] and seed[4] and seed[5]:
                seeds.append((offset, seed))
        offset += 1
    if len(seeds) != 1:
        return None
    seed_position, seed = seeds[0]
    table_seed_base = seed_position - index * 0x1C
    group_offsets = (0xC, 6) if index == 0x1E else (0x10, 8)
    if (table_seed_base < 0 or seed[3:5] != (descriptor_base - group_offsets[0], descriptor_base - group_offsets[1],) or default_callback != seed[5] or (b590_registrar
        and global_slot != seed[4] + 0x4B8)):
        return None
    row_size = 10 if index == 0x1E else 14
    group_row = (struct.pack("<4H2B", 0x200, 0, 0x200, 4, index, index) if row_size == 10 else struct.pack("<6H2B", 0x200, 0, 0, 0x200, 4, 0xE000, index, index))
    group_start = table_seed_base + (index + 1) * 0x1C + 4
    group_final = group_start + 3 * row_size
    if (group_final + row_size > len(image) or image[group_final:group_final + row_size] != group_row):
        return None
    handlers: list[int] = []
    variants = (((0x17E, 0xB087), (0x150, 0xB086)) if index == 0x1E else ((0x214, 0xB08A), (0x1E6, 0xB089)))
    for delta, prologue in variants:
        handler = loop - delta
        if (handler < 0 or handler + REX_IRQ_HANDLER_RUNTIME_SIZE > len(image) or runtime(handler) is None or struct.unpack_from("<2H", image, handler) != (0xB5F0,
            prologue) or struct.pack("<H", 0x6978) not in image[handler:handler + 0x180]):
            continue
        literals = {facts_for(image).thumb_literal_value(site, register) for site in range(handler, handler + 0x180, 2) for register in range(8) if facts_for(image).thumb_literal_value(site,
            register) is not None}
        if not {seed[0], descriptor_base}.issubset(literals):
            continue
        callback_sites = [site for site in range(handler, handler + 0x180 - 4, 2) if struct.unpack_from("<H", image, site)[0] == 0x6978 and (target :=
            _relocated_thumb_file_target(image, site + 2, file_to_runtime, runtime_to_file)) is not None and target <= len(image) - 16 and image[target:target +
            2] in (b"\x00\x47", b"\x78\x47")]
        if not callback_sites:
            continue
        if not (_relocated_thumb_file_target(image, loop, file_to_runtime, runtime_to_file) == drain and struct.unpack_from("<2H", image, loop + 4) == (0x2800,
            0xD1FB)):
            continue
        handlers.append(handler)
    if len(handlers) != 1:
        return None
    handler = handlers[0]
    wrapper_prefix = struct.pack("<4I", 0xE24EE004, 0xE92D540F, 0xE14F0000, 0xE92D0001)
    wrappers: list[tuple[int, int]] = []
    position = 0
    while (position := image.find(wrapper_prefix, position)) >= 0:
        if position + REX_IRQ_WRAPPER_RUNTIME_SIZE <= len(image):
            instruction = struct.unpack_from("<I", image, position + 0x28)[0]
            if instruction & 0xFFFFF000 == 0xE59F3000:
                literal = position + 0x30 + (instruction & 0xFFF)
                if literal + 4 <= len(image) and runtime(position) is not None:
                    wrappers.append((position, struct.unpack_from("<I", image, literal)[0]))
        position += 4
    if len(wrappers) != 1:
        return None
    wrapper, callback_slot = wrappers[0]
    if callback_slot < 0x01000000:
        return None
    setters: list[tuple[int, int]] = []
    handler_runtime = runtime(handler)
    for position in literal_loads(handler_runtime | 1, 1):
        if struct.unpack_from("<H", image, position + 2)[0] != 0x2000:
            continue
        setter = resolve_thumb(facts_for(image).thumb_call_target(position + 4))
        if setter is None or setter + 14 > len(image):
            continue
        setter_words = struct.unpack_from("<7H", image, setter)
        base = facts_for(image).thumb_literal_value(setter, 2)
        first_store, second_store = setter_words[3], setter_words[5]
        first_offset = (first_store >> 6 & 0x1F) * 4
        second_offset = (second_store >> 6 & 0x1F) * 4
        if (setter_words[1:3] == (0x2800, 0xD101) and first_store & 0xF83F == 0x6011 and setter_words[4] == 0x4770 and second_store & 0xF83F == 0x6011 and
            setter_words[6] == 0x4770 and base is not None and base + first_offset == callback_slot and second_offset == first_offset + 4):
            setters.append((position, setter))
    if len(setters) != 1:
        return None
    vector = (struct.unpack_from("<I", image, 0x18)[0] if len(image) >= 0x1C else 0)
    vector_address = runtime(0x18)
    vector_target = (arm_b_word_target(vector, vector_address) if vector_address is not None else None)
    if vector_target is None:
        return None
    wrapper_literal = wrapper + 0x30 + (struct.unpack_from("<I", image, wrapper + 0x28)[0] & 0xFFF)
    wrapper_validation_size = wrapper_literal + 4 - wrapper
    handler_validation_size = loop - handler + 8
    return { "signature": "legacy-rex-5ms-irq-route-v1", "controller_class": ("legacy-c80-two-bank-group10-v1" if index == 0x1E else
        "legacy-c80-three-bank-group14-v1"), "outer_callback": outer_runtime, "wrapper": runtime(wrapper), "wrapper_file_offset": wrapper, "handler": runtime(handler),
        "handler_file_offset": handler, "handler_slot": callback_slot, "callback_slot": descriptor_base + index * 0x1C + 0x14, "status": seed[0],
        "controller_field": seed[1], "enable": seed[1], "mask": seed[2], "vector_target": vector_target, "vector": 0x18, "registrar": runtime(registrar),
        "registrar_file_offset": registrar, "registration": runtime(registration), "registration_file_offset": registration, "handler_registration": runtime(setters[0][0]),
        "handler_registration_file_offset": setters[0][0], "handler_setter": runtime(setters[0][1]), "handler_setter_file_offset": setters[0][1], "index": index,
        "group_row_size": row_size, "status_bank_count": 2 if index == 0x1E else 3, "status_banks": ((seed[0], seed[0] + 4) if index == 0x1E else (seed[0], seed[0]
        + 4, seed[0] + 0x30)), "clear_banks": ((seed[0], seed[0] + 4) if index == 0x1E else (seed[0], seed[0] + 4, seed[1] + 0x38)), "controller_write_banks": ((seed[1],
        seed[1] + 4) if index == 0x1E else (seed[1], seed[1] + 4, seed[1] + 0x30)), "controller_aperture": (seed[0], seed[1] + (6 if index == 0x1E else 0x3A)),
        "rom_seed": seed_position, "handler_runtime_size": REX_IRQ_HANDLER_RUNTIME_SIZE, "wrapper_runtime_size": REX_IRQ_WRAPPER_RUNTIME_SIZE,
        "handler_validation_size": handler_validation_size, "wrapper_validation_size": wrapper_validation_size, "drain": runtime(drain), "drain_file_offset":
        drain, "drain_loop": runtime(loop), "drain_loop_file_offset": loop, }

def find_rex_static_overlay_controller_callback_candidate(image: bytes, file_to_runtime, runtime_to_file, *, ram_base: int, ram_size: int,) -> dict[str, object] | None:
    """Close a copied C80 callback route without an input descriptor."""
    from . import REX_LEGACY_5MS_CALLBACK_SIZE, THUMB_BL_PATTERN, _ram_contains, _relocated_thumb_file_target, arm_b_word_target, find_rex_legacy_5ms_irq_route, rex_legacy_5ms_callback_at, rex_legacy_5ms_callback_shape_at, rex_timer_callback_drain_at, struct
    if struct.pack("<3I", 0x03000C80, 0x03000C94, 0x0200) not in image:
        return None
    def mapped(position: int) -> bool:
        address = file_to_runtime(position)
        return (isinstance(address, int) and runtime_to_file(address) == position)
    outers: list[int] = []
    for prefix in (b"\x80\xb5", b"\x90\xb5"):
        position = 0
        while (position := image.find(prefix, position)) >= 0:
            if (rex_legacy_5ms_callback_at(image, position) is not None and mapped(position)):
                outers.append(position)
            position += 2
    drains: list[int] = []
    position = 0
    while (position := image.find(b"\x80\xb5", position)) >= 0:
        if (rex_timer_callback_drain_at(image, position) is not None and mapped(position)):
            drains.append(position)
        position += 2
    if len(outers) != 1 or len(drains) != 1:
        return None
    drain = drains[0]
    loops = [site for match in THUMB_BL_PATTERN.finditer(image) if not (site := match.start()) & 1 and site + 8 <= len(image) and _relocated_thumb_file_target(image,
        site, file_to_runtime, runtime_to_file) == drain and struct.unpack_from("<2H", image, site + 4) == (0x2800, 0xD1FB)]
    if len(loops) != 1:
        return None
    bridge = { "outer_callback_file_offset": outers[0], "drain_file_offset": drain, "drain_loop_caller_file_offset": loops[0], }
    route = find_rex_legacy_5ms_irq_route(image, bridge, file_to_runtime, runtime_to_file, allow_b590_registrar =True,)
    semantic_limit = ("first-bank 5 ms TIME_TICK delivery only; other controller banks and " "handset idle remain unproven")
    if route is None:
        return { "signature": "static-c80-overlay-controller-callback-v1", "accepted": False, "active": False, "semantic_limit": semantic_limit, "reject_reason":
            "legacy-overlay-irq-route-not-closed", }
    status = route.get("status")
    enable = route.get("enable")
    handler_slot = route.get("handler_slot")
    callback_slot = route.get("callback_slot")
    vector_target = route.get("vector_target")
    wrapper = route.get("wrapper")
    vector_source = (runtime_to_file(vector_target) if isinstance(vector_target, int) else None)
    if (not isinstance(wrapper, int) or not isinstance(vector_source, int) or not 0 <= vector_source <= len(image) - 4 or file_to_runtime(vector_source) !=
        vector_target or arm_b_word_target(struct.unpack_from("<I", image, vector_source)[0], vector_target,) != wrapper):
        return { "signature": "static-c80-overlay-controller-callback-v1", "accepted": False, "active": False, "semantic_limit": semantic_limit, "reject_reason":
            "legacy-overlay-vector-route-not-closed", }
    required = { "controller_class": "legacy-c80-three-bank-group14-v1", "index": 0x2B, "mask": 0x0200, "status_bank_count": 3, "group_row_size": 14, }
    if (any(route.get(key) != value for key, value in required.items()) or not isinstance(status, int) or enable != status + 0x14 or route.get("status_banks")
        != (status, status + 4, status + 0x30) or route.get("clear_banks") != (status, status + 4, enable + 0x38) or route.get("controller_write_banks") != (enable,
        enable + 4, enable + 0x30) or route.get("controller_aperture") != (status, enable + 0x3A) or not isinstance(handler_slot, int) or not isinstance(callback_slot,
        int) or not isinstance(vector_target, int) or not _ram_contains(handler_slot, 4, ram_base, ram_size) or not _ram_contains(callback_slot, 4, ram_base,
        ram_size) or not _ram_contains(vector_target, 4, ram_base, ram_size)):
        return { "signature": "static-c80-overlay-controller-callback-v1", "accepted": False, "active": False, "semantic_limit": semantic_limit, "reject_reason":
            "legacy-overlay-controller-metadata-invalid", }
    callback_shape = rex_legacy_5ms_callback_shape_at(image, outers[0])
    if callback_shape is None:
        return None
    return { **route, "signature": "static-c80-overlay-controller-callback-v1", "accepted": True, "active": False, "promotion": "temporary-evidence-gated",
        "semantic_limit": semantic_limit, "pending_read_semantics": "latched-read", "time_tick_status_bank": status, "time_tick_clear_bank": status,
        "time_tick_mask": 0x0200, "wrapper_runtime_address": route["wrapper"], "handler_runtime_address": route["handler"], "callback_file_offset": outers[0],
        "callback_runtime_address": route["outer_callback"], "callback_validation_size": REX_LEGACY_5MS_CALLBACK_SIZE, "callback_validation_shape":
        callback_shape, "callback_delta": 5, }

def _thumb_adr_target(image: bytes, position: int, register: int) -> int | None:
    from . import struct
    if not 0 <= position <= len(image) - 2:
        return None
    word = struct.unpack_from("<H", image, position)[0]
    if word & 0xF800 != 0xA000 or word >> 8 & 7 != register:
        return None
    return ((position + 4) & ~3) + (word & 0xFF) * 4

def _uis_idle_event_prefix_at(image: bytes, position: int) -> bool:
    from . import struct
    if not 0 <= position <= len(image) - 32:
        return False
    words = struct.unpack_from("<16H", image, position)
    return (words[0] in (0xB5F8, 0xB5FC) and words[1] == 0x1C04 and words[2] & 0xFF00 == 0x4800 and words[3] == 0x1C0F and words[4] & 0xFF00 == 0x4900 and words[5]
        & 0xF83F == 0x6800 and words[6] == 0x1C15 and words[7] & 0xF83F == 0x6008 and words[8] & 0xFF00 == 0x4900 and words[9] & 0xFF00 == 0x4A00 and words[10]
        == 0x2000 and words[11] & 0xFF00 == 0x4E00 and words[12:] == (0x1889, 0x73C8, 0x7830, 0x2800))

def _uis_idle_draw_prefix_at(image: bytes, position: int) -> bool:
    from . import struct
    if not 0 <= position <= len(image) - 26:
        return False
    words = struct.unpack_from("<13H", image, position)
    return (words[:2] == (0xB5F0, 0x1C0D) and words[2] & 0xFF00 == 0x4900 and words[3:7] == (0x1C04, 0x2000, 0x6248, 0x203F) and words[7] & 0xFF00 == 0x4900 and
        words[8:12] == (0x0100, 0x1808, 0x7800, 0x2800) and words[12] & 0xFF00 == 0xD000)

def _uis_idle_draw_pair(image: bytes, calls: list[tuple[int, int | None]], file_to_runtime,) -> tuple[int, int] | None:
    """Return the registered event/draw pair for one closed idle UI class."""
    from . import UIS_IDLE_DRAW_BODY_DELTAS, UIS_IDLE_DRAW_MARKER, _thumb_adr_target, _uis_idle_draw_prefix_at, _uis_idle_event_prefix_at, facts_for, struct
    marker = image.find(UIS_IDLE_DRAW_MARKER)
    if marker < 0 or image.find(UIS_IDLE_DRAW_MARKER, marker + 1) >= 0:
        return None
    helpers: list[tuple[int, int]] = []
    for site, target in calls:
        if (target is None or not marker - 0x80 <= target < marker or target + 4 > len(image)):
            continue
        first, second = struct.unpack_from("<2H", image, target)
        if first & 0xF800 != 0x4800 or second != 0xB500:
            continue
        references = [position for position in range(target, marker, 2) if _thumb_adr_target(image, position, 0) == marker]
        if len(references) == 1:
            helpers.append((site, target))
    if len(helpers) != 1:
        return None
    draw_call, _helper = helpers[0]
    draws = [position for position in range(max(0, draw_call - 0xC0), draw_call + 1, 2) if _uis_idle_draw_prefix_at(image, position)]
    if len(draws) != 1:
        return None
    draw = draws[0]
    event_calls = [site for site, target in calls if (target == draw and image[site - 4:site] == b"\x29\x1c\x38\x1c" and image[site + 4:site + 8] ==
        b"\xff\x27\x01\x37")]
    if len(event_calls) != 1:
        return None
    event_call = event_calls[0]
    events = [position for position in range(max(0, event_call - 0x140), event_call + 1, 2) if (draw - position in UIS_IDLE_DRAW_BODY_DELTAS and
        _uis_idle_event_prefix_at(image, position))]
    if len(events) != 1:
        return None
    event = events[0]
    registration = event - 0x40
    runtime_event = file_to_runtime(event)
    if (type(runtime_event) is not int or registration < 0 or image[registration:registration + 2] != b"\x00\xb5" or struct.unpack_from("<H", image,
        registration + 2)[0] & 0xFF00 != 0x4900 or struct.unpack_from("<H", image, registration + 4)[0] != 0x2001 or facts_for(image).thumb_literal_value(registration
        + 2, 1) != runtime_event | 1 or not any(site == registration + 6 and target is not None for site, target in calls) or sum(target == registration for
        _site, target in calls) != 1):
        return None
    return event, draw

def find_uis_idle_pair(image: bytes, file_to_runtime=lambda position: position, runtime_to_file=lambda address: address,) -> tuple[int, int] | None:
    """Return one closed firmware UI-idle entry/body pair, if unambiguous."""
    from . import THUMB_BL_PATTERN, UIS_IDLE_BODY_DELTA, UIS_IDLE_BODY_PREFIX, UIS_IDLE_COMPACT_BODY_DELTA, UIS_IDLE_COMPACT_BODY_PREFIX, UIS_IDLE_COMPACT_ENTRY_PREFIX, UIS_IDLE_ENTRY_PREFIX, _relocated_thumb_file_target, _uis_idle_draw_pair
    calls = [(site, _relocated_thumb_file_target(image, site, file_to_runtime, runtime_to_file)) for match in THUMB_BL_PATTERN.finditer(image) if not (site :=
        match.start()) & 1]
    profiles = ((UIS_IDLE_ENTRY_PREFIX, UIS_IDLE_BODY_DELTA, UIS_IDLE_BODY_PREFIX, 2, 1), (UIS_IDLE_COMPACT_ENTRY_PREFIX, UIS_IDLE_COMPACT_BODY_DELTA,
        UIS_IDLE_COMPACT_BODY_PREFIX, 1, 1),)
    candidates: list[tuple[int, int]] = []
    for entry_prefix, body_delta, body_prefix, entry_calls, body_calls in profiles:
        offset = 0
        while (entry := image.find(entry_prefix, offset)) >= 0:
            body = entry + body_delta
            if (image[body:body + len(body_prefix)] == body_prefix and sum(target == entry for _site, target in calls) == entry_calls and sum(target == body for
                _site, target in calls) == body_calls):
                candidates.append((entry, body))
            offset = entry + 1
    draw_pair = _uis_idle_draw_pair(image, calls, file_to_runtime)
    if draw_pair is not None and draw_pair not in candidates:
        candidates.append(draw_pair)
    return candidates[0] if len(candidates) == 1 else None
