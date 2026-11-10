from __future__ import annotations

def _copied_c40_handler_slots(image: bytes, wrapper: int) -> tuple[int, ...]:
    """Return adjacent RAM slots dereferenced by one ARM IRQ wrapper."""
    from . import struct
    found: set[int] = set()
    for pc in range(wrapper, min(len(image) - 4, wrapper + 0x300), 4):
        word = struct.unpack_from("<I", image, pc)[0]
        if (word >> 28 != 0xE or word & 0x0E5F0000 != 0x041F0000 or not word & 1 << 20 or word & (1 << 22 | 1 << 21)):
            continue
        register = word >> 12 & 15
        literal = pc + 8 + ((word & 0xFFF) if word & 1 << 23 else -(word & 0xFFF))
        if not 0 <= literal <= len(image) - 4:
            continue
        slot = struct.unpack_from("<I", image, literal)[0]
        if not 0x01000000 <= slot < 0x01800000:
            continue
        dereference = branch = False
        for at in range(pc + 4, min(len(image) - 4, pc + 0x30), 4):
            instruction = struct.unpack_from("<I", image, at)[0]
            dereference |= ((instruction & 0x0FFF0FFF) == (0x05900000 | register << 16))
            if (instruction & 0x0FFFFFF0 == 0x012FFF10 and instruction & 15 == register):
                branch = True
                break
        if dereference and branch:
            found.add(slot)
    slots = tuple(sorted(found))
    return slots if len(slots) == 2 and slots[1] == slots[0] + 4 else ()

def _copied_c40_delta5_callback_at(image: bytes, position: int) -> bool:
    """Validate shared five-unit callback semantics without fixing layout."""
    from . import struct
    if position < 0 or position + 0x80 > len(image):
        return False
    words = struct.unpack_from("<64H", image, position)
    return (words[0] & 0xFF00 == 0xB500 and words.count(0x2105) >= 2 and 0x2005 in words and any(words[index: index + 2] == (0x3905, 0x6001) for index in range(len(words)
        - 1)))

def _copied_c40_time_tick_registrations(image: bytes,) -> list[tuple[int, int, int, int, int]]:
    """Return arm, callback, registrar, callback base, selector-0 slot."""
    from . import _copied_c40_delta5_callback_at, facts_for, struct
    found: list[tuple[int, int, int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\x02\x20\x08\x70", offset)) >= 0:
        arm = offset - 2
        offset += 1
        if (arm < 0 or arm & 1 or arm + 14 > len(image) or facts_for(image).thumb_literal_value(arm, 1) != 0x030006E0 or struct.unpack_from("<H", image, arm + 6)[0]
            & 0xFF00 != 0x4900 or struct.unpack_from("<H", image, arm + 8)[0] != 0x2000):
            continue
        callback_pointer = facts_for(image).thumb_literal_value(arm + 6, 1)
        registrar = facts_for(image).thumb_call_target(arm + 10)
        if (callback_pointer is None or not callback_pointer & 1 or registrar is None or registrar + 0x48 > len(image)):
            continue
        callback = callback_pointer & ~1
        words = struct.unpack_from("<10H", image, registrar)
        if (words[:3] != (0xB5F0, 0x1C05, 0x1C0F) or words[5] != 0x1C04 or words[6] & 0xF800 != 0x4800 or words[6] >> 8 & 7 != 6 or words[7:10] != (0x2F00,
            0xD100, 0x1C37) or struct.unpack_from("<H", image, registrar + 0x46)[0] != 0x664F):
            continue
        callback_base = facts_for(image).thumb_literal_value(registrar + 0x14, 0)
        if (callback_base is None or not 0x01000018 <= callback_base < 0x01800000 or not _copied_c40_delta5_callback_at(image, callback)):
            continue
        found.append((arm, callback, registrar, callback_base, callback_base - 0x18))
    return found

def _find_rex_copied_c40_controller_observation(image: bytes,) -> dict[str, object] | None:
    """Close copied-vector C40 topology while keeping runtime disabled."""
    from . import _copied_c40_handler_slots, _copied_c40_time_tick_registrations, arm_b_word_target, struct
    if (len(image) < 0x100 or arm_b_word_target(struct.unpack_from("<I", image, 0x18)[0], 0x18) != 0x01000000):
        return None
    status, enable, mask = 0x03000C40, 0x03000C54, 0x0200
    prefix = struct.pack("<3I", status, enable, mask)
    descriptors: list[tuple[int, int]] = []
    offset = 0
    while (offset := image.find(prefix, offset)) >= 0:
        if offset + 16 <= len(image):
            shadow = struct.unpack_from("<I", image, offset + 12)[0]
            if 0x01000000 <= shadow < 0x01800000 and not shadow & 3:
                descriptors.append((offset, shadow))
        offset += 1
    if not descriptors:
        return None
    limit = ("static copied-vector topology only; native pending, cadence, " "repeat IRQ, and idle remain unproven")
    def rejected(reason: str, **details: object) -> dict[str, object]:
        return { "signature": "static-c40-copied-vector-selector0-v1", "accepted": False, "active": False, "promotion": "telemetry-only", "semantic_limit":
            limit, "reject_reason": reason, **details, }
    if len(descriptors) != 1:
        return rejected("c40-descriptor-not-unique", descriptor_count=len(descriptors))
    descriptor, shadow = descriptors[0]
    copies: list[tuple[int, int]] = []
    for at in range(0, min(len(image) - 16, 0x20000) + 1, 4):
        source, target, size, bss = struct.unpack_from("<4I", image, at)
        if (target == 0x01000000 and 0x100 <= size <= 0x200000 and bss == target + size and source > at + 0x20 and source + size <= len(image)):
            copies.append((source, size))
    if len(copies) != 1:
        return rejected("copied-vector-source-not-unique", copy_count=len(copies))
    source, copy_size = copies[0]
    if not source <= descriptor < source + copy_size:
        return rejected("descriptor-outside-vector-copy")
    descriptor_runtime = 0x01000000 + descriptor - source
    if descriptor_runtime != shadow + 8:
        return rejected("descriptor-shadow-relation-mismatch", descriptor_runtime=descriptor_runtime, mask_shadow=shadow)
    wrapper = arm_b_word_target(struct.unpack_from("<I", image, source)[0], 0x01000000)
    if wrapper is None or not 0 <= wrapper <= len(image) - 4:
        return rejected("copied-vector-target-not-in-image")
    slots = _copied_c40_handler_slots(image, wrapper)
    if not slots:
        return rejected("handler-slot-not-unique")
    anchor = struct.pack("<3I", descriptor_runtime, 0x03000C60, 0x03000FD0)
    handler_tables: list[tuple[int, int]] = []
    offset = 0
    while (offset := image.find(anchor, offset)) >= 0:
        if offset + 16 <= len(image):
            handler = struct.unpack_from("<I", image, offset + 12)[0]
            if (handler & 1 and handler < len(image) and image[handler & ~1:(handler & ~1) + 2] == b"\xF0\xB5"):
                handler_tables.append((offset, handler & ~1))
        offset += 1
    if len(handler_tables) != 1:
        return rejected("c40-handler-table-not-unique", handler_table_count=len(handler_tables))
    registrations = _copied_c40_time_tick_registrations(image)
    if len(registrations) != 1:
        return rejected("selector0-time-tick-registration-not-unique", registration_count=len(registrations))
    arm, callback, registrar, callback_base, callback_slot = registrations[0]
    return { "signature": "static-c40-copied-vector-selector0-v1", "accepted": True, "active": False, "promotion": "telemetry-only", "semantic_limit": limit,
        "controller_class": "c40-copied-vector-selector0-delta5-v1", "descriptor_file_offset": descriptor, "descriptor_runtime_address": descriptor_runtime,
        "mask_shadow": shadow, "status_banks": (status, status + 4), "enable_banks": (enable, enable + 4), "mask": mask, "selector": 0, "vector": 0x18,
        "vector_target": 0x01000000, "vector_copy_source": source, "vector_copy_size": copy_size, "wrapper_file_offset": wrapper, "handler_slot": slots[0],
        "handler_file_offset": handler_tables[0][1], "handler_table_file_offset": handler_tables[0][0], "callback_base": callback_base, "callback_slot":
        callback_slot, "callback_file_offset": callback, "registrar_file_offset": registrar, "time_tick_control_file_offset": arm, "time_tick_control_address":
        0x030006E0, "time_tick_arm_value": 2, "time_tick_period_ms": 5, }

def find_rex_static_c40_controller_observation(image: bytes,) -> dict[str, object] | None:
    """Return direct or copied-vector C40 telemetry, failing closed."""
    from . import _find_rex_copied_c40_controller_observation, _find_rex_direct_c40_controller_observation
    direct = _find_rex_direct_c40_controller_observation(image)
    if (direct is None or direct.get("accepted") or direct.get("reject_reason") != "runtime-vector-target-mismatch"):
        return direct
    copied = _find_rex_copied_c40_controller_observation(image)
    return copied if copied is not None else direct

def legacy_software_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate the paired callback-work timer list used by old LG BSPs."""
    from . import struct
    if position < 0 or position + 56 > len(image):
        return False
    words = struct.unpack_from("<28H", image, position)
    return (image[position:position + 6] == b"\xf8\xb5\x04\x1c\x0f\x1c" and words[8:12] == (0x6860, 0x2800, 0xD025, 0x6881) and words[12:16] == (0x1BC9, 0x6081,
        0xE01E, 0x6867) and words[16:20] == (0x6938, 0x68B9, 0x1A46, 0x1C38) and words[24:28] == (0x2800, 0xD008, 0x6138, 0x60B8))

def _legacy_rex_timer_target(image: bytes, position: int) -> int | None:
    from . import facts_for, legacy_rex_timer_advance_at
    if legacy_rex_timer_advance_at(image, position):
        return position
    if (position < 0 or position + 10 > len(image) or image[position:position + 2] != b"\x00\xb5" or image[position + 6:position + 10] != b"\x08\xbc\x18\x47"):
        return None
    walker = facts_for(image).thumb_call_target(position + 2)
    return (walker if walker is not None and legacy_rex_timer_advance_at(image, walker) else None)

def _legacy_software_timer_target(image: bytes, position: int) -> int | None:
    """Resolve an old software-timer walker through one exact ARM veneer."""
    from . import legacy_software_timer_advance_at, struct
    if legacy_software_timer_advance_at(image, position):
        return position
    if (position < 0 or position + 16 > len(image) or struct.unpack_from("<6H", image, position) != (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
        return None
    walker = struct.unpack_from("<I", image, position + 12)[0] & ~1
    return (walker if legacy_software_timer_advance_at(image, walker) else None)

def rex_legacy_5ms_callback_shape_at(image: bytes, position: int) -> tuple[int, int] | None:
    """Return local BL indexes for one old dual-list 5-unit callback."""
    from . import REX_LEGACY_5MS_CALLBACK_SIZE, struct
    if position < 0 or position + REX_LEGACY_5MS_CALLBACK_SIZE > len(image):
        return None
    words = struct.unpack_from("<34H", image, position)
    if words[0] == 0xB580:
        rex_call, software_call = 21, 25
        fixed = { 3: 0x0407, 4: 0x0C3F, 5: 0x2105, 12: 0x0880, 13: 0xD301, 15: 0xE000, 17: 0x6808, 18: 0x3805, 19: 0x6008, 20: 0x2005, 23: 0x2105, 27: 0x2F00,
            28: 0xD101, 31: 0xBC80, 32: 0xBC08, 33: 0x4718, }
        literal_indexes = (6, 9, 14, 16, 24)
    elif words[0] == 0xB590:
        rex_call, software_call = 22, 26
        fixed = { 3: 0x0407, 4: 0x0C3F, 6: 0x2105, 7: 0x1C20, 13: 0x0880, 14: 0xD301, 16: 0xE000, 18: 0x6808, 19: 0x3805, 20: 0x6008, 21: 0x2005, 24: 0x2105, 28:
            0x2F00, 29: 0xD101, }
        literal_indexes = (5, 10, 15, 17, 25)
    else:
        return None
    if (any(words[index] != value for index, value in fixed.items()) or any(words[index] & 0xF800 != 0x4800 for index in literal_indexes) or any(words[index] &
        0xF800 != 0xF000 or words[index + 1] & 0xF800 != 0xF800 for index in (rex_call, software_call))):
        return None
    return rex_call, software_call

def rex_legacy_5ms_callback_at(image: bytes, position: int) -> tuple[int, int] | None:
    """Return closed REX/software walkers from one old 5-unit callback."""
    from . import _legacy_rex_timer_target, _legacy_software_timer_target, facts_for, rex_legacy_5ms_callback_shape_at
    calls = rex_legacy_5ms_callback_shape_at(image, position)
    if calls is None:
        return None
    rex = facts_for(image).thumb_call_target(position + calls[0] * 2)
    software = facts_for(image).thumb_call_target(position + calls[1] * 2)
    software = (_legacy_software_timer_target(image, software) if software is not None else None)
    if (rex is None or software is None or _legacy_rex_timer_target(image, rex) is None):
        return None
    return rex, software

def rex_timer_callback_drain_at(image: bytes, position: int) -> int | None:
    """Validate one callback-work queue drain and return its queue address."""
    from . import REX_TIMER_CALLBACK_DRAIN_SIZE, facts_for, struct
    if position < 0 or position + REX_TIMER_CALLBACK_DRAIN_SIZE > len(image):
        return None
    words = struct.unpack_from("<20H", image, position)
    if not (words[0] == 0xB580 and words[1] & 0xF800 == 0x4800 and words[2] & 0xF800 == 0xF000 and words[3] & 0xF800 == 0xF800 and words[4:9] == (0x1C07, 0xD00A,
        0x68F8, 0x6939, 0x68BA) and words[9] & 0xF800 == 0xF000 and words[10] & 0xF800 == 0xF800 and words[11:20] == (0x2000, 0x7138, 0x2001, 0xBC80, 0xBC08,
        0x4718, 0x2000, 0xE7FA, 0x0000,)):
        return None
    queue = facts_for(image).thumb_literal_value(position + 2, 0)
    return queue if queue is not None and 0x01000000 <= queue < 0x02000000 else None

def rex_5ms_callback_at(image: bytes, position: int) -> int | None:
    """Validate the complete IRQ callback and return its timer-walker target."""
    from . import REX_5MS_CALLBACK_SIZE, facts_for, struct
    if position < 0 or position + REX_5MS_CALLBACK_SIZE > len(image):
        return None
    words = struct.unpack_from("<32H", image, position)
    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000 and words[index + 1] & 0xF800 == 0xF800)
    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800 and words[index] >> 8 & 7 == register)
    if not (words[0] == 0xB580 and bl(1) and words[3:6] == (0x0407, 0x0C3F, 0x2105) and literal(6, 0) and bl(7) and literal(9, 0) and bl(10) and words[12:14] ==
        (0x0880, 0xD301) and literal(14, 0) and words[15] == 0xE000 and literal(16, 0) and words[17:21] == (0x6801, 0x3905, 0x6001, 0x2005) and bl(21) and
        literal(23, 0) and words[24] == 0x2105 and bl(25) and words[27:29] == (0x2F00, 0xD101) and bl(29) and words[31] == 0xBD80):
        return None
    return facts_for(image).thumb_call_target(position + 42)

def rex_sleep_call_at(image: bytes, position: int) -> int | None:
    """Return the sleep-controller BL in one validated MSM5000 idle loop."""
    from . import struct
    if position < 0 or position + 56 > len(image):
        return None
    words = struct.unpack_from("<28H", image, position)
    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000 and words[index + 1] & 0xF800 == 0xF800)
    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800 and words[index] >> 8 & 7 == register)
    if not (literal(0, 4) and words[1:4] == (0x7820, 0x2801, 0xD106) and literal(4, 0) and words[5:8] == (0x7800, 0x2801, 0xD102) and literal(8, 0) and words[9:12]
        == (0x7800, 0xE000, 0x2008) and bl(12) and bl(14) and words[16:21] == (0x2104, 0x1C07, 0x2009, 0x05C0, 0x7822) and bl(21) and words[23] == 0x2F00 and
        words[24] & 0xFF00 == 0xD100 and bl(25) and words[27] & 0xF800 == 0xE000):
        return None
    return position + 42

def trampm5_consumer_at(image: bytes, position: int) -> tuple[int, int, int] | None:
    """Validate one old trampm5 consumer and return q_get, thunk, queue."""
    from . import TRAMPM5_CONSUMER_SIZE, facts_for, struct
    if position < 0 or position + TRAMPM5_CONSUMER_SIZE > len(image):
        return None
    words = struct.unpack_from("<17H", image, position)
    if not (words[0] == 0xB590 and words[1] == 0x4808 and words[4:10] == (0x2400, 0x1C07, 0x2800, 0xD006, 0x68F8, 0x68B9) and words[12:] == (0x713C, 0x2001,
        0xBD90, 0x1C20, 0xBD90)):
        return None
    targets = (facts_for(image).thumb_call_target(position + 4), facts_for(image).thumb_call_target(position + 20))
    if any(target is None or target & 1 or not 0 <= target < len(image) for target in targets):
        return None
    if image[int(targets[1]):int(targets[1]) + 2] != b"\x08\x47":
        return None
    queue = facts_for(image).thumb_literal_value(position + 2, 0)
    if (queue is None or queue & 3 or not 0x00800000 <= queue < 0x08000000):
        return None
    return int(targets[0]), int(targets[1]), queue

def find_trampm5_consumer(image: bytes) -> int | None:
    """Find one unique old trampm5 queue consumer."""
    from . import trampm5_consumer_at
    matches: list[int] = []
    offset = 0
    while (offset := image.find(b"\x90\xb5", offset)) >= 0:
        if not offset & 1 and trampm5_consumer_at(image, offset) is not None:
            matches.append(offset)
        offset += 2
    return matches[0] if len(matches) == 1 else None

def find_rex_5ms_irq_arm(image: bytes, tick_position: int) -> int | None:
    """Find one MMIO byte arm bound to this 5 ms callback registrar."""
    from . import REX_5MS_ARM_PATTERN, rex_5ms_registration_targets, facts_for, struct
    registration_targets = rex_5ms_registration_targets(image, tick_position)
    if (len(registration_targets) != 3 or len(set(registration_targets)) != 1):
        return None
    registrar = registration_targets[0]
    arms: list[int] = []
    for match in REX_5MS_ARM_PATTERN.finditer(image):
        arm_position = match.start()
        position = arm_position + 10
        if (arm_position & 1 or position >= len(image) - 4):
            continue
        arm = facts_for(image).thumb_literal_value(arm_position, 1)
        if (facts_for(image).thumb_call_target(position) == registrar and arm is not None and 0x03000000 <= arm < 0x04000000 and struct.unpack_from("<2H", image,
            arm_position + 2) == (0x2002, 0x7008) and facts_for(image).thumb_literal_value(arm_position + 6, 1) == tick_position | 1 and struct.unpack_from("<H",
            image, arm_position + 8)[0] == 0x201C):
            arms.append(arm)
    return arms[0] if len(arms) == 1 else None
