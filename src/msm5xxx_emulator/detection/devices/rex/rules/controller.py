from __future__ import annotations

def _find_rex_620_static_controller_callback_candidate(image: bytes, *, ram_base: int, ram_size: int,) -> dict[str, object] | None:
    """Close the early 0x620 two-bank route as telemetry-only evidence."""
    from . import REX_5MS_ARM_PATTERN, REX_LEGACY_5MS_CALLBACK_SIZE, _controller_callback_advance, _legacy_620_vector_copy, _normalized_thumb_sha256, _ram_contains, rex_5ms_registration_targets, facts_for, rex_legacy_5ms_callback_shape_at, struct
    prefix = struct.pack("<3I", 0x03000620, 0x03000628, 0x0200)
    seeds: list[tuple[int, tuple[int, ...]]] = []
    offset = 0
    while (offset := image.find(prefix, offset)) >= 0:
        if offset + 28 <= len(image):
            seed = struct.unpack_from("<7I", image, offset)
            if (_ram_contains(seed[3], 4, ram_base, ram_size) and seed[4] == seed[3] + 4 and seed[5] & 1 and (seed[5] & ~1) < len(image) and seed[6] == 0):
                seeds.append((offset, seed))
        offset += 1
    if not seeds:
        return None
    semantic_limit = ("static topology only; native pending read-consume cadence and idle " "remain unproven")
    def rejected(reason: str) -> dict[str, object]:
        return { "signature": "static-msm5000-620-controller-callback-v1", "accepted": False, "active": False, "promotion": "experimental-only",
            "semantic_limit": semantic_limit, "reject_reason": reason, }
    vector_copy = _legacy_620_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
    if vector_copy is None:
        return rejected("copied-vector-route-not-closed")
    vector_source, vector_target, vector_size, copied_wrapper = vector_copy
    if len(seeds) != 1:
        return rejected("descriptor-seed-ambiguous")
    descriptor_file_offset, seed = seeds[0]
    if not (vector_source <= descriptor_file_offset and descriptor_file_offset + 0x1C <= vector_source + vector_size):
        return rejected("descriptor-outside-vector-copy")
    descriptor_runtime = (vector_target + descriptor_file_offset - vector_source)
    status, enable, mask, masks, _second_masks, default, _reserved = seed
    handler = (default & ~1) + 0x38
    handler_shape = _normalized_thumb_sha256(image, handler, 0x178)
    handler_profiles = {
        (
            "9744e7fc7fa096c976f16773d8cd66e80a64fd42d0ac9621be8ae6e7ef21cf1e",
            (0x30, 0x90, 0xD4, 0xFE, 0x13A, 0x140, 0x152),
        ): (
            "legacy-msm5000-620-two-bank-read-consume-v1", 12,
            0x72,
            ("ccae3c22bdad57f1592f7712387f3fcbf0c2ec820f612347d95d577bfd7a910b",
             (0x06, 0x22, 0x68)),
            0x28, "consume-on-read", "temporary-evidence-gated",
        ),
        (
            "4a21a10a9d44e4f1edf1bfe706aed5fe31b180ca271feacc5eeffe34bb4f7644",
            (0x30, 0x90, 0xD4, 0xFE, 0x13A, 0x140, 0x152),
        ): (
            "legacy-msm5000-620-two-bank-read-consume-group10-v1", 10,
            # End at BX r3; the following default-handler literal is checked below.
            0x70,
            ("ed69c76589103931751b1e00818205148bf4438831add7bd61dbb82fa787eb37",
             (0x06, 0x20, 0x66)),
            0x26, "consume-on-read", "temporary-evidence-gated",
        ),
        (
            "6b60312309feaba3b622488c656ee3318fa6cd5e41c547d782cabcdf18cf21bf",
            (0x30, 0x90, 0xB6, 0xE0, 0x11C, 0x122, 0x134, 0x172),
        ): (
            "legacy-msm5000-620-two-bank-w1c-8call-v1", 12,
            0x72,
            ("ce302dcd02951cbb4ffd5a27c1062a597ddabac1e9cf78d6aa442a149a4d371d",
             (0x06, 0x20, 0x66)),
            0x26, "latched-read", "temporary-evidence-gated",
        ),
        (
            "e06e290bb2f091c2127bfe2b68bd184380b49cfa724f6ae1eaeddf9e746cb963",
            (0x30, 0x90, 0xB6, 0xE0, 0x11C, 0x122, 0x134, 0x172),
        ): (
            "legacy-msm5000-620-two-bank-w1c-8call-v1", 12,
            0x72,
            ("3d9f4975eaafa7a4a146d486608be5bbdd5a5f7add9d604a19ec85f89c408a9b",
             (0x06, 0x20, 0x66)),
            0x26, "latched-read", "temporary-evidence-gated",
        ),
    }
    handler_size = 0x178
    profile = handler_profiles.get(handler_shape)
    # Complete callback-then-W1C dispatchers, ending at BX r3.
    # Both walk three priority groups; the row stride is part of the code shape.
    # Unlike the older profiles, exclude the following literal pool.
    w1c_shape = _normalized_thumb_sha256(image, handler, 0x15A)
    w1c_stride = { "02d8707640c6924c3eeec04593f88735bef9fdaa0492d998d84e4dd38d40093d": 10, "532cb58afa8601af64bd4617afc6a1b117192629555c8c734eddd29bb2cff230":
        12, }.get(w1c_shape[0]) if w1c_shape is not None and w1c_shape[1] == (0x30, 0x90, 0xB6, 0xE0, 0x11C, 0x122, 0x134) else None
    if profile is None and w1c_stride is not None:
        handler_size = 0x15A
        profile = (
            f"legacy-msm5000-620-two-bank-w1c-group{w1c_stride}-v1", w1c_stride,
            0x70,
            ("ed69c76589103931751b1e00818205148bf4438831add7bd61dbb82fa787eb37",
             (0x06, 0x20, 0x66)),
            0x26, "latched-read", "temporary-evidence-gated",
        )
        calls = {offset: facts_for(image).thumb_call_target(handler + offset) for offset in (0x30, 0x90, 0xB6, 0xE0, 0x11C, 0x122, 0x134)}
        trampoline = calls[0xB6]
        if (any(p is None or p & 1 or not 0 <= p <= len(image) - 2 for p in calls.values()) or image[trampoline: trampoline + 2] != b"\x00\x47" or calls[0xE0]
            != trampoline or calls[0x30] != calls[0x90] or calls[0x11C] != calls[0x134]):
            return rejected("two-bank-w1c-call-route-not-closed")
        for offset, instruction in ((0x30, 0xE3C010C0), (0x11C, 0xE38010C0)):
            helper = calls[offset]
            # Interworking helpers either tag LR explicitly or return directly
            # with BX LR; both preserve the caller's Thumb return state.
            bodies = [bytes.fromhex("78470000") + struct.pack("<" + "I" * len(words), *words) for words in ((0xE38EE001, 0xE10F0000, instruction, 0xE121F001,
                0xE20000C0, 0xE12FFF1E), (0xE10F0000, instruction, 0xE121F001, 0xE20000C0, 0xE12FFF1E))]
            if helper & 3 or not any(image[helper:helper + len(expected)] == expected for expected in bodies):
                return rejected("two-bank-w1c-irq-lock-not-closed")
        if any(not _ram_contains(facts_for(image).thumb_literal_value(handler + offset, register) or 0, 2, ram_base, ram_size) for offset, register in ((0x34, 0),
            (0x14A, 1))):
            return rejected("two-bank-w1c-state-outside-ram")
    if profile is None:
        return rejected("two-bank-read-consume-handler-not-closed")
    (controller_class, group_row_size, registrar_size, registrar_expected, table_at, pending_read_semantics, promotion) = profile
    if pending_read_semantics == "latched-read":
        semantic_limit = ("two-peer clear/write route with a 5-unit service callback; " "physical tick source remains approximated")
        if handler_size == 0x15A:
            semantic_limit = ("closed callback-then-W1C route with a 5-unit service callback; " "physical tick source remains approximated; idle unproven")
        literal_checks = ((0x00, 2, masks), (0x0E, 7, status), (0x12, 2, masks), (0x48, 1, descriptor_runtime + 0x1C), (0x6C, 2, masks), (0x70, 7, status), (0x9C,
            1, masks), (0xA4, 3, status), (0xC8, 1, status), (0xCE, 3, status), (0xF2, 1, status), (0x12A, 7, masks), (0x13E, 1, status),)
    else:
        if promotion == "temporary-evidence-gated":
            semantic_limit = ("ordered status-read, callback, return, and next-tick cadence " "closed for this exact handler class; handset idle remains "
                "unproven")
        literal_checks = ((0x00, 2, masks), (0x0E, 7, status), (0x12, 2, masks), (0x6C, 2, masks), (0x70, 7, status), (0x9C, 1, masks), (0xA4, 3, status), (0xBA,
            1, status), (0xCA, 1, status), (0xE6, 1, status), (0xEC, 3, status), (0x110, 1, status), (0x148, 7, masks), (0x15C, 1, status),)
    if any(facts_for(image).thumb_literal_value(handler + relative, register) != value for relative, register, value in literal_checks):
        return rejected("two-bank-read-consume-literals-not-closed")
    if handler_size == 0x15A:
        # The dispatcher walks three groups of the proven stride. Source 28 must be
        # reachable in the bank-0 timer group, with no competing membership.
        groups_at = descriptor_file_offset + 0x1C
        if groups_at + 3 * group_row_size > vector_source + vector_size:
            return rejected("two-bank-w1c-groups-outside-vector-copy")
        groups = [struct.unpack_from("<4H2B", image, groups_at + row * group_row_size) for row in range(3)]
        if (groups[2] != (mask, 0, mask, 0, 0x1C, 0x1C) or any(group[0] & mask or not 0 <= group[4] <= group[5] < 0x1C for group in groups[:2])):
            return rejected("two-bank-w1c-timer-group-not-closed")
    ticks: list[tuple[int, int, int, int]] = []
    for match in REX_5MS_ARM_PATTERN.finditer(image):
        arm = match.start()
        callback_pointer = facts_for(image).thumb_literal_value(arm + 6, 1)
        registrar = facts_for(image).thumb_call_target(arm + 10)
        if (arm & 1 or callback_pointer is None or not callback_pointer & 1 or registrar is None or facts_for(image).thumb_literal_value(arm, 1) != 0x030006E0
            or struct.unpack_from("<2H", image, arm + 2) != (0x2002, 0x7008) or struct.unpack_from("<H", image, arm + 8)[0] != 0x201C):
            continue
        callback = callback_pointer & ~1
        advance = _controller_callback_advance(image, callback)
        registrations = rex_5ms_registration_targets(image, callback)
        registrar_shape = _normalized_thumb_sha256(image, registrar, registrar_size)
        table = facts_for(image).thumb_literal_value(registrar + table_at, 1)
        if (advance is not None and len(registrations) == 3 and set(registrations) == {registrar} and registrar_shape == registrar_expected and facts_for(image).thumb_literal_value(registrar
            + 0x0E, 6) == default and isinstance(table, int) and _ram_contains(table, 4, ram_base, ram_size)):
            ticks.append((callback, advance, registrar, table))
    if len(ticks) != 1:
        return rejected("row1c-callback-route-not-unique")
    callback, advance, registrar, table = ticks[0]
    if table != masks + 8:
        return rejected("descriptor-table-mask-relation-mismatch")
    callback_slot = table + 0x1C * 0x1C + 0x14
    if descriptor_runtime != callback_slot - 0x14:
        return rejected("descriptor-runtime-row-relation-mismatch")
    if facts_for(image).thumb_literal_value(handler + 0x48, 1) != callback_slot + 8:
        return rejected("handler-callback-table-not-closed")
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
    if copied_wrapper != wrapper:
        return rejected("copied-vector-wrapper-mismatch")
    if not _ram_contains(handler_slot, 8, ram_base, ram_size):
        return rejected("handler-slot-outside-ram")
    if not _ram_contains(callback_slot, 4, ram_base, ram_size):
        return rejected("row1c-callback-slot-invalid")
    return { "signature": "static-msm5000-620-controller-callback-v1", "controller_class": controller_class, "accepted": True, "active": False, "promotion":
        promotion, "semantic_limit": semantic_limit, "vector": 0x18, "vector_target": vector_target, "vector_copy_source": vector_source, "vector_copy_size":
        vector_size, "status": status, "enable": enable, "mask": mask, "status_banks": (status, status + 4), **({"clear_banks": (status, status + 4),
        "pending_ack_semantics": "write-one-to-clear"} if pending_read_semantics == "latched-read" else {"mask_set_banks": (status, status + 4)}),
        "mask_output_banks": (enable, enable + 4), "controller_aperture": (status, enable + 8), "status_bank_count": 2, "group_row_size": group_row_size,
        "pending_read_semantics": pending_read_semantics, "descriptor_file_offset": descriptor_file_offset, "descriptor_runtime_address": descriptor_runtime,
        "mask_table": masks, "handler_file_offset": handler, "handler_validation_size": handler_size, "registrar_file_offset": registrar, "callback_file_offset":
        callback, "callback_validation_size": REX_LEGACY_5MS_CALLBACK_SIZE, "callback_validation_shape": rex_legacy_5ms_callback_shape_at(image, callback),
        "callback_delta": 5, "timer_advance_file_offset": advance, "wrapper_file_offset": wrapper, "wrapper_validation_size": wrapper_size, "handler_slot":
        handler_slot, "callback_slot": callback_slot, "time_tick_control_address": 0x030006E0, }

def _nand_backed_veneer_chain(image: bytes, *, ram_base: int, ram_size: int):
    """Require both the direct NAND producer and the copied vector chain."""
    from . import find_nor_veneer_vector_copy, find_static_middle_nand_profile
    if find_static_middle_nand_profile(image) is None:
        return None
    return find_nor_veneer_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
