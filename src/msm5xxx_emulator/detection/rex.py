"""Firmware REX timer, IRQ, and idle detection."""
from __future__ import annotations

import re
import struct

from .arm import arm_b_word_target, thumb_bl_target, thumb_literal_value


REX_TICK_SIGNATURE = bytes.fromhex("00b500f08ffb08bc1847")
REX_5MS_WRAPPER_ANCHOR = bytes.fromhex(
    "800801d30a4800e00a480168053901600520"
)
REX_5MS_CALLBACK_SIZE = 64
REX_TIMER_ADVANCE_SIZE = 70
REX_LEGACY_5MS_CALLBACK_SIZE = 68
REX_TIMER_CALLBACK_DRAIN_SIZE = 40


REX_IRQ_WRAPPER_SIGNATURE = bytes.fromhex(
    "04e04ee20f542de900004fe101002de92c029fe5b010d0e1011081e2b010c0e1"
    "9ff021e300402de918329fe5003093e5010013e310e29f1510e29f0513ff2fe1"
)
REX_IRQ_WRAPPER_RUNTIME_SIZE = 0x260
REX_IRQ_HANDLER_RUNTIME_SIZE = 0x1DC
TRAMPM5_CONSUMER_SIZE = 40
REX_INTLOCK_SIGNATURE = bytes.fromhex(
    "7847000001e08ee300000fe1c01080e301f021e1c00000e2"
)
REX_INTFREE_SIGNATURE = bytes.fromhex(
    "7847000001e08ee300000fe1c010c0e301f021e1c00000e2"
)
REX_IRQ_DRAIN_PATTERN = re.compile(
    rb"\x08\x43\x1f\xd1.{4}\x47\x48\x00\x88\x01\x28\x03\xd1"
    rb".{4}\x00\x28\xfb\xd1", re.S,
)
THUMB_BL_PATTERN = re.compile(
    rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", re.S,
)
REX_5MS_REGISTRATION_PATTERN = re.compile(
    rb"[\x00-\xff][\x49-\x4f]\x1c\x20", re.S,
)
REX_5MS_ARM_PATTERN = re.compile(
    rb"[\x00-\xff][\x49-\x4f]\x02\x20\x08\x70"
    rb"[\x00-\xff][\x49-\x4f]\x1c\x20"
    rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", re.S,
)


def _rex_5ms_registration_targets(
        image: bytes, tick_address: int, runtime_code=None, *,
        candidate_only_mapper: bool = False,
) -> list[int]:
    """Return timer-registrar targets; candidate-only mapping requires purity."""
    targets: list[int] = []
    candidates = {
        match.start() for match in REX_5MS_REGISTRATION_PATTERN.finditer(image)
        if not match.start() & 1 and match.start() < len(image) - 8
    }
    positions = (
        sorted(candidates)
        if runtime_code is None or candidate_only_mapper
        else range(0, len(image) - 8, 2)
    )
    for position in positions:
        mapped = runtime_code(position) if runtime_code is not None else position
        if (mapped is None or position not in candidates
                or thumb_literal_value(image, position, 1)
                != tick_address | 1):
            continue
        target = thumb_bl_target(image, position + 4)
        if (target is not None and 0 <= target < len(image)
                and (runtime_code is None or runtime_code(target) is not None)):
            targets.append(target)
    return targets


def rex_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate an MSM5000 REX active-timer list walker."""
    if position < 0 or position + REX_TIMER_ADVANCE_SIZE > len(image):
        return False
    words = struct.unpack_from("<35H", image, position)

    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000
                and words[index + 1] & 0xF800 == 0xF800)

    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800
                and words[index] >> 8 & 7 == register)

    return (
        words[:2] == (0xB5F0, 0x1C04)
        and bl(2)
        and words[4] == 0x1C07
        and literal(5, 0)
        and words[6:11] == (0x2600, 0x6805, 0xE011, 0x68A8, 0x42A0)
        and words[11] & 0xFF00 == 0xD800
        and words[12:21] == (
            0x60AE, 0xCD03, 0x3D08, 0x6008, 0x6868,
            0x6829, 0x6048, 0x68E8, 0x6929,
        )
        and bl(21)
        and words[23:27] == (0xE001, 0x1B00, 0x60A8, 0x682D)
        and literal(27, 0)
        and words[28] == 0x4285
        and words[29] & 0xFF00 == 0xD100
        and words[30:32] == (0x2F00, 0xD101)
        and bl(32)
        and words[34] == 0xBDF0
    )


def legacy_rex_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate the older register-renamed REX active-timer walker."""
    if position < 0 or position + 0x38 > len(image):
        return False
    return (
        image[position:position + 2] == b"\xf0\xb5"
        and b"\xa0\x42" in image[position:position + 0x30]
        and b"\x00\x20\xb8\x60" in image[position:position + 0x38]
    )


def _controller_timer_advance_at(image: bytes, position: int) -> bool:
    """Close the legacy walker to its timer callback fanout call."""
    if (not legacy_rex_timer_advance_at(image, position)
            or position + 0x60 > len(image)):
        return False
    calls = [offset for offset in range(position, position + 0x58, 2)
             if struct.unpack_from("<2H", image, offset)[:2] == (0x68F8, 0x6939)
             and thumb_bl_target(image, offset + 4) is not None]
    return len(calls) == 1


def _controller_two_bank_handler_at(
        image: bytes, position: int, masks: int, status: int,
) -> bool:
    """Validate the common C80 two-bank mask/dispatch controller shape."""
    if position < 0 or position + 0x100 > len(image):
        return False
    words = struct.unpack_from("<28H", image, position)

    def literal(index: int, register: int, value: int) -> bool:
        return thumb_literal_value(image, position + index * 2, register) == value

    if not (
        words[0] == 0xB5F0
        and words[1] & 0xFFF0 == 0xB080
        and words[2] & 0xF800 == 0xF000
        and words[3] & 0xF800 == 0xF800
        and literal(4, 2, masks)
        and words[5:9] == (0x88D1, 0x9102, 0x8911, 0x9101)
        and literal(9, 7, status)
        and words[10] == 0x8838
        and literal(11, 2, masks)
        and words[12:25] == (
            0x8813, 0x9902, 0x4019, 0x4001, 0x9104, 0x88B8,
            0x8853, 0x9901, 0x4019, 0x4008, 0x9904, 0x9003,
            0x4308,
        )
        and words[25] & 0xFF00 == 0xD100
        and thumb_bl_target(image, position + 26 * 2) is not None
    ):
        return False

    # A second bank pass must consume both the same RAM masks and status.
    later = range(position + 0x70, position + 0x100, 2)
    if (not any(thumb_literal_value(image, offset, register) == masks
                for offset in later for register in range(8))
            or not any(thumb_literal_value(image, offset, register) == status
                       for offset in later for register in range(8))):
        return False

    def callback_thunk(target: int | None) -> bool:
        if target is None or target + 2 > len(image):
            return False
        if image[target:target + 2] == b"\x00\x47":
            return True
        if (target + 16 > len(image)
                or struct.unpack_from("<6H", image, target)
                != (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
            return False
        indirect = struct.unpack_from("<I", image, target + 12)[0]
        return (indirect & 1
                and indirect + 1 <= len(image)
                and image[indirect & ~1:(indirect & ~1) + 2] == b"\x00\x47")

    # Close descriptor callback loads to a BX R0 thunk, then require one
    # handled-mask writeback through the same status literal.
    dispatches = 0
    for offset in later:
        if struct.unpack_from("<H", image, offset)[0] != 0x6978:
            continue
        target = thumb_bl_target(image, offset + 2)
        if callback_thunk(target):
            dispatches += 1
    if dispatches < 2:
        return False
    for load in later:
        for register in range(8):
            if thumb_literal_value(image, load, register) != status:
                continue
            for store in range(load + 2, min(position + 0x100, load + 0x12), 2):
                word = struct.unpack_from("<H", image, store)[0]
                if (word & 0xF800 == 0x8000
                        and word >> 3 & 7 == register
                        and (word >> 6 & 0x1F) * 2 in (0, 4)):
                    return True
    return False


def _controller_registrar_at(
        image: bytes, position: int, default: int,
) -> int | None:
    """Validate row-0x1c registration and return its descriptor-table base."""
    if position < 0 or position + 0x44 > len(image):
        return None
    words = struct.unpack_from("<34H", image, position)
    if not (
        words[0] & 0xFFF0 == 0xB5F0
        and words[1:3] == (0x1C04, 0x1C0F)
        and words[3] & 0xF800 == 0xF000
        and words[4] & 0xF800 == 0xF800
        and words[5:7] == (0x1C05, 0x2F00)
        and words[7] & 0xF800 == 0x4800
        and words[7] >> 8 & 7 == 6
        and words[8:13] == (0xD100, 0x1C37, 0x2C00, 0xDB01, 0x2C1F)
        and words[13] & 0xFF00 == 0xDB00
        and words[14] & 0xF800 == 0xF000
        and words[15] & 0xF800 == 0xF800
        and thumb_literal_value(image, position + 14, 6) == default
    ):
        return None
    rows = [index for index in range(16, 25)
            if (words[index] == 0x201C
                and words[index + 1] & 0xF800 == 0x4800
                and words[index + 1] >> 8 & 7 == 1
                and words[index + 2:index + 10] == (
                    0x4360, 0x1840, 0x2C00, 0xD102, words[index + 6],
                    0x630F, 0xE000, 0x6147,
                )
                and words[index + 6] & 0xF800 == 0x4800
                and words[index + 6] >> 8 & 7 == 1)]
    if len(rows) != 1:
        return None
    descriptor = thumb_literal_value(image, position + (rows[0] + 6) * 2, 1)
    return (descriptor if descriptor is not None
            and 0x01000000 <= descriptor < 0x02000000 else None)


def _controller_callback_advance(
        image: bytes, position: int,
) -> int | None:
    """Return the unique direct 5-unit legacy timer advance from callback."""
    if position < 0 or position + 0x40 > len(image):
        return None
    advances: list[int] = []
    for offset in range(position, position + 0x38, 2):
        if (struct.unpack_from("<3H", image, offset)
                != (0x3805, 0x6008, 0x2005)):
            continue
        advance = thumb_bl_target(image, offset + 6)
        if (advance is not None
                and struct.unpack_from("<H", image, offset + 10)[0] == 0x2105
                and _controller_timer_advance_at(image, advance)):
            advances.append(advance)
    return advances[0] if len(advances) == 1 else None


def find_rex_static_controller_callback_candidate(
        image: bytes,
) -> dict[str, object] | None:
    """Return a telemetry-only old-controller callback topology, if closed.

    This proves only static descriptor, handler, registrar, and timer-list
    topology.  It deliberately does not claim a pending-bit source, inject an
    IRQ, or promote a handset phase.
    """
    if len(image) < 0x100:
        return None
    prefix = struct.pack("<3I", 0x03000C80, 0x03000C94, 0x200)
    seeds: list[tuple[int, tuple[int, ...]]] = []
    offset = 0
    while (offset := image.find(prefix, offset)) >= 0:
        if offset + 28 <= len(image):
            seed = struct.unpack_from("<7I", image, offset)
            if (seed[3] >= 0x01000000 and seed[4] == seed[3] + 6
                    and seed[5] & 1 and (seed[5] & ~1) < len(image)
                    and seed[6] == 0):
                seeds.append((offset, seed))
        offset += 1
    if not seeds:
        return None

    semantic_limit = (
        "static topology only; native pending, IRQ, and idle remain unproven"
    )

    def rejected(reason: str) -> dict[str, object]:
        return {
            "signature": "static-c80-controller-callback-v1",
            "accepted": False,
            "active": False,
            "semantic_limit": semantic_limit,
            "reject_reason": reason,
        }

    if (arm_b_word_target(struct.unpack_from("<I", image, 0x18)[0], 0x18)
            != 0x01000000):
        return rejected("raw-vector-not-01000000")
    if len(seeds) != 1:
        return rejected("descriptor-seed-ambiguous")
    descriptor_file_offset, seed = seeds[0]
    status, enable, mask, masks, _unused, default, _reserved = seed
    handler = (default & ~1) + 0x68
    if not _controller_two_bank_handler_at(image, handler, masks, status):
        return rejected("two-bank-handler-not-closed")

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
        if (struct.unpack_from("<H", image, registration)[0] != 0x201E
                or thumb_literal_value(image, registration - 2, 1) is None
                or thumb_literal_value(image, registration - 8, 1) != 0x030007A0
                or struct.unpack_from("<2H", image, registration - 6)
                != (0x2002, 0x7008)):
            continue
        callback_pointer = thumb_literal_value(image, registration - 2, 1)
        registrar = thumb_bl_target(image, registration + 2)
        if (callback_pointer is None or not callback_pointer & 1
                or registrar is None):
            continue
        callback = callback_pointer & ~1
        table = _controller_registrar_at(image, registrar, default)
        advance = _controller_callback_advance(image, callback)
        if table is not None and advance is not None:
            registrations.append((registration, callback, registrar, advance))
    if len(registrations) != 1:
        return rejected("row1e-callback-route-not-unique")
    registration, callback, registrar, advance = registrations[0]
    table = _controller_registrar_at(image, registrar, default)
    if table is None:
        return rejected("registrar-not-closed")
    wrapper_prefix = struct.pack("<4I", 0xE24EE004, 0xE92D540F,
                                 0xE14F0000, 0xE92D0001)
    wrappers: list[tuple[int, int, int]] = []
    position = 0
    while (position := image.find(wrapper_prefix, position)) >= 0:
        if not position & 3 and position + 0x34 <= len(image):
            instruction = struct.unpack_from("<I", image, position + 0x28)[0]
            if instruction & 0xFFFFF000 == 0xE59F3000:
                literal = position + 0x30 + (instruction & 0xFFF)
                if literal + 4 <= len(image):
                    wrappers.append((position, struct.unpack_from(
                        "<I", image, literal)[0], literal + 4 - position))
        position += 4
    if len(wrappers) != 1:
        return rejected("irq-wrapper-not-unique")
    wrapper, handler_slot, wrapper_size = wrappers[0]
    if not 0x01000000 <= handler_slot < 0x02000000:
        return rejected("handler-slot-outside-ram")

    def literal_loads(value: int, register: int) -> set[int]:
        loads: set[int] = set()
        literal = image.find(struct.pack("<I", value))
        while literal >= 0:
            for candidate in range(max(0, literal - 0x400) & ~1,
                                   min(len(image) - 2, literal + 2), 2):
                if thumb_literal_value(image, candidate, register) == value:
                    loads.add(candidate)
            literal = image.find(struct.pack("<I", value), literal + 1)
        return loads

    setters: list[tuple[int, int]] = []
    for position in literal_loads(handler | 1, 1):
        if struct.unpack_from("<H", image, position + 2)[0] != 0x2000:
            continue
        setter = thumb_bl_target(image, position + 4)
        if (setter is not None and setter + 16 <= len(image)
                and struct.unpack_from("<6H", image, setter)
                == (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
            setter = struct.unpack_from("<I", image, setter + 12)[0] & ~1
        if setter is None or setter + 14 > len(image):
            continue
        words = struct.unpack_from("<7H", image, setter)
        base = thumb_literal_value(image, setter, 2)
        first = (words[3] >> 6 & 0x1F) * 4
        second = (words[5] >> 6 & 0x1F) * 4
        if (words[1:3] == (0x2800, 0xD101)
                and words[3] & 0xF83F == 0x6011
                and words[4] == 0x4770
                and words[5] & 0xF83F == 0x6011
                and words[6] == 0x4770
                and base is not None and base + first == handler_slot
                and second == first + 4):
            setters.append((position, setter))
    if len(setters) != 1:
        return rejected("handler-setter-not-unique")
    callback_slot = masks + 0x0C + 0x1E * 0x1C + 0x14
    if not 0x01000000 <= callback_slot < 0x02000000:
        return rejected("row1e-callback-slot-invalid")
    callback_shape = rex_legacy_5ms_callback_shape_at(image, callback)
    if callback_shape is None:
        return rejected("legacy-callback-validator-not-closed")
    return {
        "signature": "static-c80-controller-callback-v1",
        "accepted": True,
        "active": False,
        "semantic_limit": semantic_limit,
        "controller_class": (
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
        "vector_target": 0x01000000,
        "wrapper_file_offset": wrapper,
        "handler_slot": handler_slot,
        "handler_registration_file_offset": setters[0][0],
        "handler_setter_file_offset": setters[0][1],
        "callback_slot": callback_slot,
        "clear_banks": (status, status + 4),
        "controller_write_banks": (enable, enable + 4),
        "controller_aperture": (status, enable + 6),
        "handler_validation_size": 0x100,
        "wrapper_validation_size": wrapper_size,
        "callback_delta": 5,
        "callback_validation_size": REX_LEGACY_5MS_CALLBACK_SIZE,
        "callback_validation_shape": callback_shape,
    }


def find_rex_static_c40_controller_observation(
        image: bytes,
) -> dict[str, object] | None:
    """Return one closed C40 TIME_TICK observation."""
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

    limit = ("static controller and one-shot route only; native pending, "
             "cadence, repeat IRQ, and idle remain unproven")

    def rejected(reason: str, **details: object) -> dict[str, object]:
        return {
            "signature": "static-c40-selector0-delta5-controller-v1",
            "accepted": False, "active": False, "promotion": "telemetry-only",
            "semantic_limit": limit, "reject_reason": reason, **details,
        }

    if len(descriptors) != 1:
        return rejected("c40-descriptor-not-unique", descriptor_count=len(descriptors))
    descriptor, shadow = descriptors[0]
    if len(image) < 0x1C or arm_b_word_target(
            struct.unpack_from("<I", image, 0x18)[0], 0x18) != 0x01380000:
        return rejected("runtime-vector-target-mismatch",
                        descriptor_file_offset=descriptor, mask_shadow=shadow)
    arms: list[int] = []
    offset = 0
    while (offset := image.find(b"\x02\x20\x08\x70", offset)) >= 0:
        position = offset - 2
        offset += 1
        if (position < 0 or position & 1 or position + 6 > len(image)
                or struct.unpack_from("<H", image, position)[0] & 0xF800 != 0x4800
                or struct.unpack_from("<H", image, position)[0] & 0x0700 != 0x0100
                or thumb_literal_value(image, position, 1) != 0x030006E0):
            continue
        arms.append(position)
    if len(arms) != 1:
        return rejected("time-tick-arm-not-unique", descriptor_file_offset=descriptor,
                        arm_count=len(arms))

    handlers: list[tuple[int, int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\xf0\xb5", offset)) >= 0:
        position = offset
        offset += 1
        if position & 1 or position + 0x3D0 > len(image):
            continue
        if (thumb_literal_value(image, position + 0x0A, 6) != shadow
                or thumb_literal_value(image, position + 0x0C, 7) != status):
            continue
        tick, tail = position + 0x112, position + 0x396
        if (struct.unpack_from("<2H", image, tick) != (0x0A8A, 0xD30A)
                or thumb_literal_value(image, tick + 4, 0) is None
                or struct.unpack_from("<H", image, tick + 6)[0] != 0x6980
                or thumb_bl_target(image, tick + 8) != 0x1254
                or struct.unpack_from("<2H", image, tick + 0x14)
                != (0x2001, 0x0240)
                or (branch := struct.unpack_from("<H", image, tick + 0x18)[0])
                & 0xF800 != 0xE000
                or tick + 0x1C + (((branch & 0x7FF) << 1)
                                   - (0x1000 if branch & 0x400 else 0))
                != position + 0x2BC
                or thumb_literal_value(image, position + 0x2BC, 1) != status
                or struct.unpack_from("<H", image, position + 0x2BE)[0] != 0x8008
                or thumb_literal_value(image, tail, 2) != shadow
                or thumb_literal_value(image, tail + 2, 1) != status
                or struct.unpack_from("<8H", image, tail + 4)
                != (0x8810, 0x880B, 0x4018, 0x0400,
                    0x4E15, 0x0C00, 0x8430, 0x8852)
                or struct.unpack_from("<H", image, position + 0x3CE)[0] != 0xBDF0):
            continue
        table = thumb_literal_value(image, tick + 4, 0)
        assert table is not None
        if 0x01000000 <= table < 0x02000000:
            handlers.append((position, table, table + 0x18, position + 0x2BC))
    if len(handlers) != 1:
        return rejected("c40-handler-not-unique", descriptor_file_offset=descriptor,
                        mask_shadow=shadow, handler_count=len(handlers))
    handler, table, callback_slot, w1c = handlers[0]
    if callback_slot - shadow != 0x208:
        return rejected("callback-slot-mask-shadow-mismatch",
                        descriptor_file_offset=descriptor, mask_shadow=shadow)

    wrapper_prefix = struct.pack("<4I", 0xE24EE004, 0xE92D540F,
                                 0xE14F0000, 0xE92D0001)
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
        return rejected("irq-wrapper-not-unique", descriptor_file_offset=descriptor,
                        mask_shadow=shadow, wrapper_count=len(wrappers))

    def dispatcher_at(position: int) -> bool:
        if position < 0 or position + 0x66 > len(image):
            return False
        words = struct.unpack_from("<51H", image, position)
        entry = words[0x12]
        target = (position + 0x28 + ((entry & 0x7FF) << 1)
                  - (0x1000 if entry & 0x400 else 0))
        return (
            words[:3] == (0xB5F0, 0x1C05, 0x1C0F)
            and words[3] & 0xF800 == 0xF000
            and words[4] & 0xF800 == 0xF800
            and words[5:7] == (0x1C04, 0x2F00)
            and words[7] & 0xF800 == 0x4800
            and words[8:10] == (0xD100, 0x1C37)
            and thumb_literal_value(image, position + 0x14, 1) == table + 0x7C
            and entry & 0xF800 == 0xE000
            and target == position + 0x64
            and words[0x32] == 0x6187
        )

    registrations: list[tuple[int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\x49", offset)) >= 0:
        position = offset - 1
        offset += 1
        if position < 0 or position & 1 or position >= len(image) - 8:
            continue
        callback = thumb_literal_value(image, position, 1)
        if (callback is None or not callback & 1
                or struct.unpack_from("<H", image, position + 2)[0] != 0x2000):
            continue
        dispatcher = thumb_bl_target(image, position + 4)
        if dispatcher is not None and dispatcher_at(dispatcher):
            registrations.append((position, callback & ~1, dispatcher))
    if not registrations or len({item[1] for item in registrations}) != 1 \
            or len({item[2] for item in registrations}) != 1:
        return rejected("selector0-registration-not-unique",
                        descriptor_file_offset=descriptor, mask_shadow=shadow,
                        registration_count=len(registrations))
    registration, callback, dispatcher = registrations[0]

    # The registered callback itself, not an unrelated global call, advances
    # the same active timer list by five units.
    def walker_at(position: int) -> bool:
        if position < 0 or position + 0x24 > len(image):
            return False
        words = struct.unpack_from("<18H", image, position)
        return (
            words[:3] == (0xB5F8, 0x1C0C, 0x1C07)
            and words[3] & 0xF800 == 0xF000
            and words[4] & 0xF800 == 0xF800
            and words[5:8] == (0x9000, 0x6878, 0x2800)
            and words[8] & 0xFF00 == 0xD000
            and words[9:12] == (0x6881, 0x1B09, 0x6081)
            and words[12] & 0xF800 == 0xE000
            and words[13:] == (0x6878, 0x1C04, 0x6900, 0x68A1, 0x1A45)
        )

    delta_call = callback + 0x32
    walker = (
        thumb_bl_target(image, delta_call)
        if callback + 0x36 <= len(image) else None
    )
    if (callback + 0x36 > len(image)
            or struct.unpack_from("<H", image, callback)[0] != 0xB590
            or struct.unpack_from("<H", image, callback + 0x30)[0] != 0x2105
            or walker is None or not walker_at(walker)):
        walker_count = sum(
            walker_at(position)
            for position in range(0, len(image) - 0x24 + 1, 2)
        )
        return rejected("callback-delta5-walker-not-closed",
                        descriptor_file_offset=descriptor, mask_shadow=shadow,
                        callback_file_offset=callback, walker_count=walker_count)
    clients: list[int] = []
    client_prefix = struct.pack("<4H", 0x2201, 0x9200, 0x2219, 0x2319)
    offset = 0
    while (offset := image.find(client_prefix, offset)) >= 0:
        position = offset
        offset += 1
        if (not position & 1 and position < len(image) - 14
                and any(thumb_bl_target(image, call) is not None
                        for call in range(position + 8, position + 14, 2))):
            clients.append(position)
    if len(clients) != 1:
        return rejected("periodic-25-client-not-unique",
                        descriptor_file_offset=descriptor, mask_shadow=shadow,
                        periodic_25_count=len(clients))
    wrapper, handler_slot = wrappers[0]
    return {
        "signature": "static-c40-selector0-delta5-controller-v1",
        "accepted": True, "active": False, "promotion": "telemetry-only",
        "semantic_limit": limit,
        "controller_class": "c40-two-bank-selector0-delta5-v1",
        "descriptor_file_offset": descriptor, "mask_shadow": shadow,
        "status_banks": (status, status + 4), "enable_banks": (enable, enable + 4),
        "mask": mask, "selector": 0, "callback_slot": callback_slot,
        "descriptor_table": table, "registration_file_offset": registration,
        "dispatcher_file_offset": dispatcher, "callback_file_offset": callback,
        "handler_file_offset": handler, "w1c_file_offset": w1c,
        "wrapper_file_offset": wrapper, "handler_slot": handler_slot,
        "vector": 0x18, "vector_target": 0x01380000,
        "timer_walker_file_offset": walker,
        "delta5_call_file_offset": delta_call,
        "periodic_25_client_file_offset": clients[0],
        "time_tick_control_file_offset": arms[0],
        "time_tick_control_address": 0x030006E0,
        "time_tick_arm_value": 2,
        "time_tick_period_ms": 5,
    }


def legacy_software_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate the paired callback-work timer list used by old LG BSPs."""
    if position < 0 or position + 56 > len(image):
        return False
    words = struct.unpack_from("<28H", image, position)
    return (
        image[position:position + 6] == b"\xf8\xb5\x04\x1c\x0f\x1c"
        and words[8:12] == (0x6860, 0x2800, 0xD025, 0x6881)
        and words[12:16] == (0x1BC9, 0x6081, 0xE01E, 0x6867)
        and words[16:20] == (0x6938, 0x68B9, 0x1A46, 0x1C38)
        and words[24:28] == (0x2800, 0xD008, 0x6138, 0x60B8)
    )


def _legacy_rex_timer_target(image: bytes, position: int) -> int | None:
    if legacy_rex_timer_advance_at(image, position):
        return position
    if (position < 0 or position + 10 > len(image)
            or image[position:position + 2] != b"\x00\xb5"
            or image[position + 6:position + 10] != b"\x08\xbc\x18\x47"):
        return None
    walker = thumb_bl_target(image, position + 2)
    return (
        walker if walker is not None
        and legacy_rex_timer_advance_at(image, walker) else None
    )


def _legacy_software_timer_target(image: bytes, position: int) -> int | None:
    """Resolve an old software-timer walker through one exact ARM veneer."""
    if legacy_software_timer_advance_at(image, position):
        return position
    if (position < 0 or position + 16 > len(image)
            or struct.unpack_from("<6H", image, position)
            != (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
        return None
    walker = struct.unpack_from("<I", image, position + 12)[0] & ~1
    return (walker if legacy_software_timer_advance_at(image, walker)
            else None)


def rex_legacy_5ms_callback_shape_at(
        image: bytes, position: int
) -> tuple[int, int] | None:
    """Return local BL indexes for one old dual-list 5-unit callback."""
    if position < 0 or position + REX_LEGACY_5MS_CALLBACK_SIZE > len(image):
        return None
    words = struct.unpack_from("<34H", image, position)
    if words[0] == 0xB580:
        rex_call, software_call = 21, 25
        fixed = {
            3: 0x0407, 4: 0x0C3F, 5: 0x2105,
            12: 0x0880, 13: 0xD301, 15: 0xE000,
            17: 0x6808, 18: 0x3805, 19: 0x6008, 20: 0x2005,
            23: 0x2105, 27: 0x2F00, 28: 0xD101,
            31: 0xBC80, 32: 0xBC08, 33: 0x4718,
        }
        literal_indexes = (6, 9, 14, 16, 24)
    elif words[0] == 0xB590:
        rex_call, software_call = 22, 26
        fixed = {
            3: 0x0407, 4: 0x0C3F, 6: 0x2105, 7: 0x1C20,
            13: 0x0880, 14: 0xD301, 16: 0xE000,
            18: 0x6808, 19: 0x3805, 20: 0x6008, 21: 0x2005,
            24: 0x2105, 28: 0x2F00, 29: 0xD101,
        }
        literal_indexes = (5, 10, 15, 17, 25)
    else:
        return None
    if (any(words[index] != value for index, value in fixed.items())
            or any(words[index] & 0xF800 != 0x4800
                   for index in literal_indexes)
            or any(
                words[index] & 0xF800 != 0xF000
                or words[index + 1] & 0xF800 != 0xF800
                for index in (rex_call, software_call)
            )):
        return None
    return rex_call, software_call


def rex_legacy_5ms_callback_at(
        image: bytes, position: int
) -> tuple[int, int] | None:
    """Return closed REX/software walkers from one old 5-unit callback."""
    calls = rex_legacy_5ms_callback_shape_at(image, position)
    if calls is None:
        return None
    rex = thumb_bl_target(image, position + calls[0] * 2)
    software = thumb_bl_target(image, position + calls[1] * 2)
    software = (_legacy_software_timer_target(image, software)
                if software is not None else None)
    if (rex is None or software is None
            or _legacy_rex_timer_target(image, rex) is None):
        return None
    return rex, software


def rex_timer_callback_drain_at(image: bytes, position: int) -> int | None:
    """Validate one callback-work queue drain and return its queue address."""
    if position < 0 or position + REX_TIMER_CALLBACK_DRAIN_SIZE > len(image):
        return None
    words = struct.unpack_from("<20H", image, position)
    if not (
        words[0] == 0xB580
        and words[1] & 0xF800 == 0x4800
        and words[2] & 0xF800 == 0xF000
        and words[3] & 0xF800 == 0xF800
        and words[4:9] == (0x1C07, 0xD00A, 0x68F8, 0x6939, 0x68BA)
        and words[9] & 0xF800 == 0xF000
        and words[10] & 0xF800 == 0xF800
        and words[11:20] == (
            0x2000, 0x7138, 0x2001, 0xBC80, 0xBC08,
            0x4718, 0x2000, 0xE7FA, 0x0000,
        )
    ):
        return None
    queue = thumb_literal_value(image, position + 2, 0)
    return queue if queue is not None and 0x01000000 <= queue < 0x02000000 else None


def rex_5ms_callback_at(image: bytes, position: int) -> int | None:
    """Validate the complete IRQ callback and return its timer-walker target."""
    if position < 0 or position + REX_5MS_CALLBACK_SIZE > len(image):
        return None
    words = struct.unpack_from("<32H", image, position)

    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000
                and words[index + 1] & 0xF800 == 0xF800)

    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800
                and words[index] >> 8 & 7 == register)

    if not (
        words[0] == 0xB580
        and bl(1)
        and words[3:6] == (0x0407, 0x0C3F, 0x2105)
        and literal(6, 0) and bl(7)
        and literal(9, 0) and bl(10)
        and words[12:14] == (0x0880, 0xD301)
        and literal(14, 0)
        and words[15] == 0xE000
        and literal(16, 0)
        and words[17:21] == (0x6801, 0x3905, 0x6001, 0x2005)
        and bl(21)
        and literal(23, 0)
        and words[24] == 0x2105
        and bl(25)
        and words[27:29] == (0x2F00, 0xD101)
        and bl(29)
        and words[31] == 0xBD80
    ):
        return None
    return thumb_bl_target(image, position + 42)


def rex_sleep_call_at(image: bytes, position: int) -> int | None:
    """Return the sleep-controller BL in one validated MSM5000 idle loop."""
    if position < 0 or position + 56 > len(image):
        return None
    words = struct.unpack_from("<28H", image, position)

    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000
                and words[index + 1] & 0xF800 == 0xF800)

    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800
                and words[index] >> 8 & 7 == register)

    if not (
        literal(0, 4)
        and words[1:4] == (0x7820, 0x2801, 0xD106)
        and literal(4, 0)
        and words[5:8] == (0x7800, 0x2801, 0xD102)
        and literal(8, 0)
        and words[9:12] == (0x7800, 0xE000, 0x2008)
        and bl(12) and bl(14)
        and words[16:21] == (0x2104, 0x1C07, 0x2009, 0x05C0, 0x7822)
        and bl(21)
        and words[23] == 0x2F00
        and words[24] & 0xFF00 == 0xD100
        and bl(25)
        and words[27] & 0xF800 == 0xE000
    ):
        return None
    return position + 42


def trampm5_consumer_at(
        image: bytes, position: int) -> tuple[int, int, int] | None:
    """Validate one old trampm5 consumer and return q_get, thunk, queue."""
    if position < 0 or position + TRAMPM5_CONSUMER_SIZE > len(image):
        return None
    words = struct.unpack_from("<17H", image, position)
    if not (
        words[0] == 0xB590
        and words[1] == 0x4808
        and words[4:10] == (0x2400, 0x1C07, 0x2800,
                            0xD006, 0x68F8, 0x68B9)
        and words[12:] == (0x713C, 0x2001, 0xBD90, 0x1C20, 0xBD90)
    ):
        return None
    targets = (thumb_bl_target(image, position + 4),
               thumb_bl_target(image, position + 20))
    if any(target is None or target & 1 or not 0 <= target < len(image)
           for target in targets):
        return None
    if image[int(targets[1]):int(targets[1]) + 2] != b"\x08\x47":
        return None
    queue = thumb_literal_value(image, position + 2, 0)
    if (queue is None or queue & 3
            or not 0x00800000 <= queue < 0x08000000):
        return None
    return int(targets[0]), int(targets[1]), queue


def find_trampm5_consumer(image: bytes) -> int | None:
    """Find one unique old trampm5 queue consumer."""
    matches: list[int] = []
    offset = 0
    while (offset := image.find(b"\x90\xb5", offset)) >= 0:
        if not offset & 1 and trampm5_consumer_at(image, offset) is not None:
            matches.append(offset)
        offset += 2
    return matches[0] if len(matches) == 1 else None


def find_rex_5ms_irq_arm(image: bytes, tick_position: int) -> int | None:
    """Find one MMIO byte arm bound to this 5 ms callback registrar."""
    registration_targets = _rex_5ms_registration_targets(
        image, tick_position
    )
    if (len(registration_targets) != 3
            or len(set(registration_targets)) != 1):
        return None
    registrar = registration_targets[0]
    arms: list[int] = []
    for match in REX_5MS_ARM_PATTERN.finditer(image):
        arm_position = match.start()
        position = arm_position + 10
        if (arm_position & 1 or position >= len(image) - 4):
            continue
        arm = thumb_literal_value(image, arm_position, 1)
        if (thumb_bl_target(image, position) == registrar
                and arm is not None and 0x03000000 <= arm < 0x04000000
                and struct.unpack_from("<2H", image, arm_position + 2)
                == (0x2002, 0x7008)
                and thumb_literal_value(image, arm_position + 6, 1)
                == tick_position | 1
                and struct.unpack_from("<H", image, arm_position + 8)[0]
                == 0x201C):
            arms.append(arm)
    return arms[0] if len(arms) == 1 else None


def find_rex_5ms_irq_route(
        image: bytes, tick_position: int, map_position=None, *,
        candidate_only_mapper: bool = False,
) -> tuple[int, int, int, int, int, int, int] | None:
    """Bind one 5 ms callback; candidate-only mapping requires a pure mapper."""
    runtime = map_position or (lambda position: position)
    tick_address = runtime(tick_position)
    if tick_address is None:
        return None
    delta = tick_address - tick_position

    def runtime_code(position: int) -> int | None:
        address = runtime(position)
        return address if address == position + delta else None

    walker = rex_5ms_callback_at(image, tick_position)
    if (walker is None or runtime_code(walker) is None
            or not rex_timer_advance_at(image, walker)):
        return None
    callback_targets = tuple(
        thumb_bl_target(image, tick_position + item)
        for item in (2, 14, 20, 42, 50, 58)
    )
    if any(target is None or not 0 <= target < len(image)
           or runtime_code(target) is None
           for target in callback_targets):
        return None
    lock = thumb_bl_target(image, walker + 4)
    expiry = thumb_bl_target(image, walker + 42)
    unlock = thumb_bl_target(image, walker + 64)
    if (lock is None or expiry is None or unlock is None
            or any(runtime_code(target) is None
                   for target in (lock, expiry, unlock))
            or callback_targets[0] != lock
            or callback_targets[3] != walker
            or callback_targets[5] != unlock
            or image[lock:lock + len(REX_INTLOCK_SIGNATURE)]
            != REX_INTLOCK_SIGNATURE
            or image[unlock:unlock + len(REX_INTFREE_SIGNATURE)]
            != REX_INTFREE_SIGNATURE
            or not 0 <= expiry <= len(image) - 60):
        return None
    expiry_words = struct.unpack_from("<30H", image, expiry)
    if not (
        expiry_words[:3] == (0xB5F0, 0x1C0E, 0x1C07)
        and thumb_bl_target(image, expiry + 6) == lock
        and expiry_words[5:12] == (
            0x68FC, 0x1C05, 0x1C20, 0x4330, 0x60F8, 0x6938, 0x4030,
        )
        and expiry_words[12] & 0xFF00 == 0xD000
        and expiry_words[13:16] == (0x2000, 0x6138, 0x4807)
        and expiry_words[16:21] == (
            0x6979, 0x6882, 0x6952, 0x4291, 0xD902,
        )
        and expiry_words[21] == 0x6087
        and (target := thumb_bl_target(image, expiry + 44)) is not None
        and 0 <= target < len(image)
        and runtime_code(target) is not None
        and expiry_words[24:26] == (0x2D00, 0xD101)
        and thumb_bl_target(image, expiry + 52) == unlock
        and expiry_words[28:] == (0x1C20, 0xBDF0)
    ):
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
    if any(runtime_code(target) is None
           for target in (consumer, q_get, thunk)):
        return None

    enqueue_matches: list[int] = []
    enqueue_layouts = (
        (bytes.fromhex("04043879240c002809d0"), 24, 32, 46, 54, 62, 0x48),
        (bytes.fromhex("04043879240c002808d0"), 22, 30, 44, 52, 60, 0x4C),
    )
    offset = 0
    while (offset := image.find(b"\x90\xb5\x07\x1c", offset)) >= 0:
        for (signature, get_at, unlock_a, unlock_b,
             put_stub_at, put_at, queue_at) in enqueue_layouts:
            q_put = thumb_bl_target(image, offset + put_at)
            enqueue_targets = tuple(
                thumb_bl_target(image, offset + item)
                for item in (get_at, put_stub_at, put_at)
            )
            if (offset + queue_at + 4 <= len(image)
                    and runtime_code(offset) is not None
                    and image[offset + 8:offset + 18] == signature
                    and thumb_bl_target(image, offset + 4) == lock
                    and thumb_bl_target(image, offset + unlock_a) == unlock
                    and thumb_bl_target(image, offset + unlock_b) == unlock
                    and all(target is not None and 0 <= target < len(image)
                            and runtime_code(target) is not None
                            for target in enqueue_targets)
                    and q_put is not None
                    and runtime_code(q_put) is not None
                    and image[q_put:q_put + 6] == b"\x90\xb5\x0c\x1c\x07\x1c"
                    and thumb_bl_target(image, q_put + 6) == lock
                    and struct.unpack_from("<I", image, offset + queue_at)[0]
                    == queue):
                enqueue_matches.append(offset)
        offset += 2
    if len(enqueue_matches) != 1:
        return None
    enqueue = enqueue_matches[0]
    producer = callback_targets[4]
    if (producer is None or not 0 <= producer <= len(image) - 0x54
            or runtime_code(producer) is None
            or image[producer:producer + 6] != b"\xf8\xb5\x0c\x1c\x07\x1c"
            or not all((target := thumb_bl_target(image, producer + item))
                       is not None and 0 <= target < len(image)
                       and runtime_code(target) is not None
                       for item in (6, 42, 68))
            or thumb_bl_target(image, producer + 6) != lock
            or image[producer + 10:producer + 42] != bytes.fromhex(
                "0004000c00907868002824d08168091b81601de07868041c0069a168451a201c"
            )
            or image[producer + 46:producer + 68] != bytes.fromhex(
                "6069e668002808d02061a060207e002800d16061201c"
            )
            or image[producer + 72:producer + 80]
            != bytes.fromhex("a562e01d15306662")
            or thumb_bl_target(image, producer + 80) != enqueue):
        return None

    candidates: list[tuple[int, int, int, int, int, int, int]] = []
    for match in REX_IRQ_DRAIN_PATTERN.finditer(image):
        tail = match.start()
        handler = tail - 0x34
        if (handler < 0
                or image[handler:handler + 4] != b"\xf0\xb5\x86\xb0"
                or thumb_bl_target(image, tail + 16) != consumer
                or handler + REX_IRQ_HANDLER_RUNTIME_SIZE > len(image)):
            continue
        (summary, status, nesting, summary_high, groups,
         descriptors, enable) = struct.unpack_from(
            "<7I", image, handler + 0x154
        )
        if (summary_high != summary + 8
                or descriptors != summary + 0xC
                or groups != descriptors + 0x1D * 0x1C
                or status & 3 or enable != status + 8
                or not 0x03000000 <= status < 0x04000000
                or struct.unpack_from("<I", image, handler + 0x170)[0]
                != enable + 4):
            continue
        handler_address = runtime_code(handler)
        if handler_address is None:
            continue
        default_position = handler - 0x38
        default_address = (runtime_code(default_position)
                           if 0 <= default_position < len(image) else None)
        if default_address is None:
            continue
        handler_literal = handler + 0x1D4
        if (struct.unpack_from("<I", image, handler_literal)[0]
                != handler_address | 1
                or struct.unpack_from("<I", image, handler_literal + 4)[0]
                != queue):
            continue
        registration = handler_literal - 0x22
        if (runtime_code(registration) is None
                or thumb_literal_value(image, registration, 1)
                != handler_address | 1
                or struct.unpack_from("<H", image, registration + 2)[0]
                != 0x2000):
            continue
        setter = thumb_bl_target(image, registration + 4)
        if (setter is None or not 0 <= setter <= len(image) - 20
                or runtime_code(setter) is None):
            continue
        if not (
            image[setter:setter + 2] == b"\x02\x1c"
            and image[setter + 4:setter + 8] == b"\x01\xd1\xc1\x60"
            and image[setter + 8:setter + 14]
            == b"\xf7\x46\x01\x61\xf7\x46"
        ):
            continue
        root = thumb_literal_value(image, setter + 2, 0)
        if root is None or nesting != root + 0x14:
            continue

        wrappers: list[int] = []
        wrapper_body = REX_IRQ_WRAPPER_SIGNATURE[4:]
        wrapper = 0
        while (wrapper := image.find(wrapper_body, wrapper)) >= 0:
            entry = wrapper - 4
            wrapper_address = runtime_code(wrapper)
            entry_address = runtime_code(entry)
            if (entry >= 0 and not entry & 3 and not wrapper & 3
                    and wrapper_address is not None
                    and entry_address is not None
                    and not wrapper_address & 3 and not entry_address & 3
                    and wrapper + 0x25C <= len(image)
                    and image[entry:wrapper] == REX_IRQ_WRAPPER_SIGNATURE[:4]
                    and tuple(struct.unpack_from("<I", image, wrapper + item)[0]
                              for item in (0x240, 0x244, 0x250, 0x254))
                    == (nesting, root + 0xC, root + 4, root + 8)
                    and tuple(struct.unpack_from(
                        "<I", image, wrapper + item
                    )[0] for item in (0x248, 0x24C, 0x258))
                    == (wrapper_address + 0x3C, wrapper_address + 0x40,
                        wrapper_address + 0x168)):
                wrappers.append(entry)
            wrapper += 4
        if len(wrappers) != 1:
            continue

        registration_targets = _rex_5ms_registration_targets(
            image, tick_address, runtime_code,
            candidate_only_mapper=candidate_only_mapper,
        )
        if (len(registration_targets) != 3
                or len(set(registration_targets)) != 1):
            continue
        registrar = registration_targets[0]
        if (not 0 <= registrar <= len(image) - 0x70
                or runtime_code(registrar) is None):
            continue
        words = struct.unpack_from("<23H", image, registrar)
        registrar_lock = thumb_bl_target(image, registrar + 6)
        if not (
            words[:3] == (0xB5F0, 0x1C04, 0x1C0F)
            and registrar_lock == lock
            and runtime_code(registrar_lock) is not None
            and image[registrar_lock:registrar_lock + len(REX_INTLOCK_SIGNATURE)]
            == REX_INTLOCK_SIGNATURE
            and words[5:7] == (0x1C05, 0x2F00)
            and words[8:14] == (0xD100, 0x1C37, 0x2C00,
                                0xDB01, 0x2C1D, 0xDB03)
            and words[18:20] == (0x201C, 0x4360)
            and words[21:23] == (0x1840, 0x6147)
            and thumb_literal_value(image, registrar + 40, 1) == descriptors
        ):
            if not (
                words[8:13] == (0xD100, 0x1C37, 0x2C00,
                                 0xDB01, 0x2C1D)
                and words[13] == 0xDB04
                and thumb_literal_value(image, registrar + 42, 1)
                == descriptors
            ):
                continue
        if (thumb_literal_value(image, registrar + 14, 6)
                != default_address | 1):
            continue
        initializer = struct.pack(
            "<8I", status, enable, 0x0200, summary, summary + 4,
            default_address | 1, 0, 4,
        )
        if image.count(initializer) != 1:
            continue
        indirect_calls = tuple(
            thumb_bl_target(image, handler + item) for item in (0xEA, 0x112)
        )
        if (image[handler + 0xE8:handler + 0xEA] != b"\x78\x69"
                or image[handler + 0x110:handler + 0x112] != b"\x78\x69"
                or any(target is None or not 0 <= target < len(image)
                       or runtime_code(target) is None
                       or image[target:target + 2] != b"\x00\x47"
                       for target in indirect_calls)):
            continue
        wrapper_address = runtime_code(wrappers[0])
        if wrapper_address is None:
            continue
        candidates.append((
            wrapper_address, handler_address, root + 0xC,
            descriptors + 0x1C * 0x1C + 0x14,
            status, enable, 0x0200,
        ))
    return candidates[0] if len(candidates) == 1 else None


def find_rex_5ms_sleep_timer(image: bytes) -> tuple[int, int, int] | None:
    """Find a unique post-sleep hook and its proven 5 ms IRQ callback."""
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


def _legacy_timer_registration_at(
        image: bytes, scanner: int, callback_literal: int,
) -> dict[str, int] | None:
    """Close one old timer registrar call's complete Thumb argument ABI."""
    if (callback_literal < 0x24 or callback_literal + 6 > len(image)
            or thumb_literal_value(image, callback_literal, 1) != scanner | 1
            or struct.unpack_from("<2H", image, callback_literal - 6)
            != (0x2219, 0x2319)
            or not any(struct.unpack_from("<2H", image, flag)
                       == (0x2201, 0x9200)
                       for flag in range(callback_literal - 16,
                                         callback_literal - 6, 2))):
        return None
    registrar = thumb_bl_target(image, callback_literal + 2)
    if registrar is None:
        return None
    setup = struct.unpack_from("<H", image, callback_literal - 2)[0]
    timer: int | None = None
    if setup & 0xFFC7 == 0x1C00 and not setup & 7:
        register = setup >> 3 & 7
        loads = [position for position in range(callback_literal - 0x24,
                                                callback_literal - 2, 2)
                 if thumb_literal_value(image, position, register) is not None]
        if len(loads) != 1:
            return None
        timer = thumb_literal_value(image, loads[0], register)
        first = struct.unpack_from("<H", image, loads[0] + 2)[0]
        if (first >> 8 & 7 == register
                and first & 0xF800 in (0x3000, 0x3800)):
            timer += (first & 0xFF) * (
                1 if first & 0xF800 == 0x3000 else -1)
        elif (register >= 4 and callback_literal == loads[0] + 0x12
              and first == (0x1C20 | register << 3)
              and thumb_bl_target(image, loads[0] + 4) is not None
              and struct.unpack_from("<2H", image, loads[0] + 8)
              == (0x2201, 0x9200)):
            pass
        elif (register >= 4 and callback_literal == loads[0] + 0x16
              and first & 0xF800 == 0x7000
              and (adjust := struct.unpack_from("<H", image, loads[0] + 4)[0])
              >> 8 & 7 == register
              and adjust & 0xF800 in (0x3000, 0x3800)
              and adjust & 0xFF
              and struct.unpack_from("<H", image, loads[0] + 6)[0]
              == (0x1C20 | register << 3)
              and thumb_bl_target(image, loads[0] + 8) is not None
              and struct.unpack_from("<2H", image, loads[0] + 12)
              == (0x2201, 0x9200)):
            timer += (adjust & 0xFF) * (
                1 if adjust & 0xF800 == 0x3000 else -1)
        else:
            return None
    elif setup & 0xF800 == 0x3800:
        literal = thumb_literal_value(image, callback_literal - 8, 0)
        if literal is None:
            return None
        timer = literal - (setup & 0xFF)
    if timer is None:
        return None
    return {
        "callback_literal_file_offset": ((callback_literal + 4) & ~3)
        + (struct.unpack_from("<H", image, callback_literal)[0] & 0xFF) * 4,
        "registration_callsite_file_offset": callback_literal + 2,
        "timer_object": timer,
        "registrar_file_offset": registrar,
        "initial": 0x19,
        "reload": 0x19,
        "stack_flag": 1,
    }


def find_rex_legacy_5ms_timer_bridge(
        image: bytes, scanner_file_offset: int,
        file_to_runtime=lambda position: position,
        runtime_to_file=lambda address: address,
) -> dict[str, object] | None:
    """Return only a callback-specific, fully closed legacy 5 ms timer ABI."""
    scanner = scanner_file_offset
    if scanner < 0 or scanner & 1 or scanner >= len(image):
        return None

    def runtime(position: int) -> int | None:
        address = file_to_runtime(position)
        return (address if isinstance(address, int) and address >= 0
                and runtime_to_file(address) == position else None)

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
    if any(runtime(position) is None
           for position in (outer, rex_walker, software)):
        return None

    registration_sites: set[int] = set()
    literal = image.find(struct.pack("<I", scanner | 1))
    while literal >= 0:
        for position in range(max(0, literal - 0x400) & ~1,
                              min(len(image) - 2, literal + 2), 2):
            if thumb_literal_value(image, position, 1) == scanner | 1:
                registration_sites.add(position)
        literal = image.find(struct.pack("<I", scanner | 1), literal + 1)
    registrations = [result for position in registration_sites
                     if (result := _legacy_timer_registration_at(
                         image, scanner, position)) is not None]
    if len(registrations) != 1:
        return None
    registration = registrations[0]
    registrar = registration["registrar_file_offset"]
    if runtime(registrar) is None:
        return None

    if (software + 0x56 > len(image)
            or struct.unpack_from("<2H", image, software + 0x4E)
            != (0x1DF8, 0x3019)):
        return None
    expiry_callsite = software + 0x52
    veneer = thumb_bl_target(image, expiry_callsite)
    if veneer is None or runtime(veneer) is None:
        return None
    dispatcher_runtime = runtime(veneer)
    dispatcher_file = veneer
    if (veneer + 16 <= len(image)
            and struct.unpack_from("<2H", image, veneer) == (0x4778, 0x46C0)
            and struct.unpack_from("<2I", image, veneer + 4)
            == (0xE59FC000, 0xE12FFF1C)):
        dispatcher_runtime = struct.unpack_from("<I", image, veneer + 12)[0] & ~1
        dispatcher_file = runtime_to_file(dispatcher_runtime)
    if (not isinstance(dispatcher_file, int)
            or not 0 <= dispatcher_file <= len(image) - 0x50
            or runtime(dispatcher_file) != dispatcher_runtime):
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

    puts = [(site + 4, target) for site in range(
                dispatcher_file,
                min(dispatcher_file + 0x80, len(image) - 6), 2)
            if (struct.unpack_from("<H", image, site)[0] == 0x1C39
                and thumb_literal_value(image, site + 2, 0) == queue
                and (target := thumb_bl_target(image, site + 4)) is not None
                and runtime(target) is not None)]
    if len(puts) != 1:
        return None
    def drains_until_empty(caller: int) -> bool:
        if (caller + 8 > len(image)
                or thumb_bl_target(image, caller) != drain
                or struct.unpack_from("<H", image, caller + 4)[0] != 0x2800
                or runtime(caller) is None):
            return False
        branch = struct.unpack_from("<H", image, caller + 6)[0]
        if branch & 0xFF00 != 0xD100:
            return False
        displacement = (branch & 0xFF) * 2
        if displacement & 0x100:
            displacement -= 0x200
        return caller + 10 + displacement == caller

    loops = [caller for match in THUMB_BL_PATTERN.finditer(image)
             if not (caller := match.start()) & 1
             and drains_until_empty(caller)]
    if len(loops) != 1:
        return None

    addresses = (scanner, outer, rex_walker, software, registrar,
                 registration["callback_literal_file_offset"], expiry_callsite,
                 veneer, dispatcher_file, puts[0][0], puts[0][1], drain,
                 loops[0])
    if any(runtime(position) is None for position in addresses):
        return None
    return {
        "signature": "legacy-rex-5ms-scanner-timer-v1",
        "tick_ms": 5,
        "scanner": scanner_runtime,
        "scanner_file_offset": scanner,
        "callback": scanner_runtime | 1,
        "outer_callback": runtime(outer),
        "outer_callback_file_offset": outer,
        "outer_callback_pointer": runtime(outer) | 1,
        "rex_walker": runtime(rex_walker),
        "rex_walker_file_offset": rex_walker,
        "software_timer": runtime(software),
        "software_timer_file_offset": software,
        "timer_object": registration["timer_object"],
        "registrar": runtime(registrar),
        "registrar_file_offset": registrar,
        "registration_callsite": runtime(registration[
            "registration_callsite_file_offset"]),
        "registration_callsite_file_offset": registration[
            "registration_callsite_file_offset"],
        "callback_literal": runtime(registration[
            "callback_literal_file_offset"]),
        "callback_literal_file_offset": registration[
            "callback_literal_file_offset"],
        "initial": 0x19,
        "reload": 0x19,
        "stack_flag": 1,
        "software_expiry_enqueue_callsite": runtime(expiry_callsite),
        "software_expiry_enqueue_callsite_file_offset": expiry_callsite,
        "enqueue_target": runtime(veneer),
        "enqueue_target_file_offset": veneer,
        "dispatcher": dispatcher_runtime,
        "dispatcher_file_offset": dispatcher_file,
        "dispatcher_qput_callsite": runtime(puts[0][0]),
        "dispatcher_qput_callsite_file_offset": puts[0][0],
        "qput": runtime(puts[0][1]),
        "qput_file_offset": puts[0][1],
        "callback_queue": queue,
        "drain": runtime(drain),
        "drain_file_offset": drain,
        "drain_loop_caller": runtime(loops[0]),
        "drain_loop_caller_file_offset": loops[0],
        "drain_loop_signature": "BL drain; CMP R0,#0; BNE back",
    }


def find_rex_legacy_5ms_irq_route(
        image: bytes, bridge: dict[str, object],
        file_to_runtime=lambda position: position,
        runtime_to_file=lambda address: address,
) -> dict[str, object] | None:
    """Close one old-LG controller descriptor route for a legacy timer bridge.

    This deliberately proves code/data topology only.  It does not assign a
    peripheral polarity or arrange host IRQ delivery.
    """
    outer = bridge.get("outer_callback_file_offset")
    loop = bridge.get("drain_loop_caller_file_offset")
    drain = bridge.get("drain_file_offset")
    if (not isinstance(outer, int) or not isinstance(loop, int)
            or not isinstance(drain, int) or not 0 <= outer < len(image)
            or not 0 <= loop < len(image) or not 0 <= drain < len(image)):
        return None

    def runtime(position: int) -> int | None:
        address = file_to_runtime(position)
        return (address if isinstance(address, int) and address >= 0
                and runtime_to_file(address) == position else None)

    def resolve_thumb(target: int | None) -> int | None:
        """Resolve a direct Thumb target or the exact BX-PC ARM veneer."""
        if target is None or not 0 <= target < len(image):
            return None
        if (target + 12 <= len(image)
                and struct.unpack_from("<6H", image, target)
                == (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
            address = struct.unpack_from("<I", image, target + 12)[0] & ~1
            mapped = runtime_to_file(address)
            if (isinstance(mapped, int) and 0 <= mapped < len(image)
                    and runtime(mapped) == address):
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
            for candidate in range(max(0, literal - 0x400) & ~1,
                                   min(len(image) - 2, literal + 2), 2):
                if thumb_literal_value(image, candidate, register) == value:
                    loads.add(candidate)
            literal = image.find(struct.pack("<I", value), literal + 1)
        return loads

    registrations: list[tuple[int, int, int]] = []
    for position in literal_loads(outer_runtime | 1, 1):
        index_word = struct.unpack_from("<H", image, position + 2)[0]
        target = resolve_thumb(thumb_bl_target(image, position + 4))
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
    if not (
            words[:3] == (0xB5F0, 0x1C04, 0x1C0F)
            and words[5:14] == (
                0x1C05, 0x2F00, words[7], 0xD100, 0x1C37, 0x2C00,
                0xDB01, 0x2C00 | (0x1F if index == 0x1E else 0x2C),
                words[13],
            )):
        return None
    store = 0x630F if index == 0x1E else 0x620F
    layouts = [
        (multiply, descriptor_load)
        for multiply, descriptor_load, stores in (
            (21, 44, 28), (20, 42, 27),
        )
        if words[multiply:multiply + 4]
        == (0x201C, words[multiply + 1], 0x4360, 0x1840)
        and words[stores:stores + 3] == (store, 0xE000, 0x6147)
    ]
    if len(layouts) != 1:
        return None
    descriptor_base = thumb_literal_value(image, registrar + layouts[0][1], 1)
    if descriptor_base is None:
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
    if (table_seed_base < 0
            or seed[3:5] != (
                descriptor_base - group_offsets[0],
                descriptor_base - group_offsets[1],
            )
            or thumb_literal_value(image, registrar + 14, 6) != seed[5]):
        return None
    row_size = 10 if index == 0x1E else 14
    group_row = (struct.pack("<4H2B", 0x200, 0, 0x200, 4, index, index)
                 if row_size == 10 else struct.pack(
                     "<6H2B", 0x200, 0, 0, 0x200, 4, 0xE000, index, index))
    group_start = table_seed_base + (index + 1) * 0x1C + 4
    group_final = group_start + 3 * row_size
    if (group_final + row_size > len(image)
            or image[group_final:group_final + row_size] != group_row):
        return None

    handlers: list[int] = []
    variants = (
        ((0x17E, 0xB087), (0x150, 0xB086))
        if index == 0x1E else ((0x214, 0xB08A),)
    )
    for delta, prologue in variants:
        handler = loop - delta
        if (handler < 0 or handler + REX_IRQ_HANDLER_RUNTIME_SIZE > len(image)
                or runtime(handler) is None
                or struct.unpack_from("<2H", image, handler)
                != (0xB5F0, prologue)
                or struct.pack("<H", 0x6978) not in image[handler:handler + 0x180]):
            continue
        literals = {thumb_literal_value(image, site, register)
                    for site in range(handler, handler + 0x180, 2)
                    for register in range(8)
                    if thumb_literal_value(image, site, register) is not None}
        if not {seed[0], descriptor_base}.issubset(literals):
            continue
        callback_sites = [site for site in range(handler, handler + 0x180 - 4, 2)
                          if struct.unpack_from("<H", image, site)[0] == 0x6978
                          and (target := thumb_bl_target(image, site + 2)) is not None
                          and 0 <= target <= len(image) - 16
                          and image[target:target + 2] in (b"\x00\x47", b"\x78\x47")]
        if not callback_sites:
            continue
        if not (thumb_bl_target(image, loop) == drain
                and struct.unpack_from("<2H", image, loop + 4) == (0x2800, 0xD1FB)):
            continue
        handlers.append(handler)
    if len(handlers) != 1:
        return None
    handler = handlers[0]

    wrapper_prefix = struct.pack("<4I", 0xE24EE004, 0xE92D540F,
                                 0xE14F0000, 0xE92D0001)
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
        setter = resolve_thumb(thumb_bl_target(image, position + 4))
        if setter is None or setter + 14 > len(image):
            continue
        setter_words = struct.unpack_from("<7H", image, setter)
        base = thumb_literal_value(image, setter, 2)
        first_store, second_store = setter_words[3], setter_words[5]
        first_offset = (first_store >> 6 & 0x1F) * 4
        second_offset = (second_store >> 6 & 0x1F) * 4
        if (setter_words[1:3] == (0x2800, 0xD101)
                and first_store & 0xF83F == 0x6011
                and setter_words[4] == 0x4770
                and second_store & 0xF83F == 0x6011
                and setter_words[6] == 0x4770
                and base is not None
                and base + first_offset == callback_slot
                and second_offset == first_offset + 4):
            setters.append((position, setter))
    if len(setters) != 1:
        return None

    vector = (
        struct.unpack_from("<I", image, 0x18)[0]
        if len(image) >= 0x1C else 0
    )
    vector_address = runtime(0x18)
    vector_target = (
        arm_b_word_target(vector, vector_address)
        if vector_address is not None else None
    )
    if vector_target is None:
        return None
    wrapper_literal = wrapper + 0x30 + (struct.unpack_from("<I", image, wrapper + 0x28)[0] & 0xFFF)
    wrapper_validation_size = wrapper_literal + 4 - wrapper
    handler_validation_size = loop - handler + 8
    return {
        "signature": "legacy-rex-5ms-irq-route-v1",
        "controller_class": (
            "legacy-c80-two-bank-group10-v1" if index == 0x1E
            else "legacy-c80-three-bank-group14-v1"
        ),
        "outer_callback": outer_runtime,
        "wrapper": runtime(wrapper), "wrapper_file_offset": wrapper,
        "handler": runtime(handler), "handler_file_offset": handler,
        "handler_slot": callback_slot, "callback_slot": descriptor_base + index * 0x1C + 0x14,
        "status": seed[0], "controller_field": seed[1], "enable": seed[1], "mask": seed[2],
        "vector_target": vector_target, "vector": 0x18,
        "registrar": runtime(registrar), "registrar_file_offset": registrar,
        "registration": runtime(registration), "registration_file_offset": registration,
        "handler_registration": runtime(setters[0][0]), "handler_registration_file_offset": setters[0][0],
        "handler_setter": runtime(setters[0][1]), "handler_setter_file_offset": setters[0][1],
        "index": index, "group_row_size": row_size,
        "status_bank_count": 2 if index == 0x1E else 3,
        "status_banks": (
            (seed[0], seed[0] + 4) if index == 0x1E
            else (seed[0], seed[0] + 4, seed[0] + 0x30)
        ),
        "clear_banks": (
            (seed[0], seed[0] + 4) if index == 0x1E
            else (seed[0], seed[0] + 4, seed[1] + 0x38)
        ),
        "controller_write_banks": (
            (seed[1], seed[1] + 4) if index == 0x1E
            else (seed[1], seed[1] + 4, seed[1] + 0x30)
        ),
        "controller_aperture": (
            seed[0], seed[1] + (6 if index == 0x1E else 0x3A)
        ),
        "rom_seed": seed_position,
        "handler_runtime_size": REX_IRQ_HANDLER_RUNTIME_SIZE,
        "wrapper_runtime_size": REX_IRQ_WRAPPER_RUNTIME_SIZE,
        "handler_validation_size": handler_validation_size,
        "wrapper_validation_size": wrapper_validation_size,
        "drain": runtime(drain), "drain_file_offset": drain,
        "drain_loop": runtime(loop), "drain_loop_file_offset": loop,
    }


def find_rex_idle_address(image: bytes) -> int | None:
    """Find the final idle BL in one validated Qualcomm REX signal loop."""
    candidates: list[int] = []

    def unconditional_target(address: int, word: int) -> int | None:
        if word & 0xF800 != 0xE000:
            return None
        displacement = (word & 0x7FF) * 2
        if displacement & 0x800:
            displacement -= 0x1000
        return address + 4 + displacement

    fixed = {
        0: 0x0BC1, 1: 0xD306, 2: 0x2108, 6: 0x2101, 7: 0x0389,
        8: 0xE007, 9: 0x0B81, 10: 0xD309, 11: 0x2108,
        15: 0x2101, 16: 0x0349, 21: 0x0A80,
        22: 0xD302,
    }
    anchor = struct.pack("<3H", fixed[0], fixed[1], fixed[2])
    offset = 0
    while (offset := image.find(anchor, offset)) >= 0:
        if offset & 1 or offset + 52 > len(image):
            offset += 1
            continue
        words = struct.unpack_from("<26H", image, offset)
        if any(words[index] != value for index, value in fixed.items()):
            offset += 2
            continue
        if any(words[index] & 0xFFC7 != 0x1C00 for index in (3, 12, 17)):
            offset += 2
            continue
        def backward_branch(index: int) -> bool:
            target = unconditional_target(
                offset + index * 2, words[index]
            )
            return target is not None and target <= offset
        if not all(backward_branch(index) for index in (20, 25)):
            offset += 2
            continue
        if any(not (words[index] & 0xF800 == 0xF000
                    and words[index + 1] & 0xF800 == 0xF800)
               for index in (4, 13, 18, 23)):
            offset += 2
            continue
        idle = offset + 52
        last_bl: int | None = None
        for address in range(idle, min(len(image), idle + 0x80), 2):
            word = struct.unpack_from("<H", image, address)[0]
            following = (struct.unpack_from("<H", image, address + 2)[0]
                         if address + 4 <= len(image) else 0)
            if word & 0xF800 == 0xF000 and following & 0xF800 == 0xF800:
                last_bl = address
                continue
            if word & 0xF800 != 0xE000:
                continue
            displacement = (word & 0x7FF) * 2
            if displacement & 0x800:
                displacement -= 0x1000
            if address + 4 + displacement <= offset:
                if last_bl is not None and last_bl + 4 == address:
                    candidates.append(last_bl)
                break
        offset += 2

    # Newer MSM5500 REX uses a distinct four-stage signal loop. Require its
    # complete setup, bit 1/15/14/10 stages, and every same-loop backedge.
    setup_fixed = {
        0: 0xB5B0, 1: 0x4D21, 2: 0x4C21, 3: 0x2201,
        4: 0x1C29, 5: 0x1C20, 8: 0x2201, 9: 0x0252,
        10: 0x1DE0, 11: 0x3015, 12: 0x491B, 15: 0x1DE0,
        16: 0x3015, 21: 0x1C22, 22: 0x210F, 23: 0x2001,
        26: 0x27FF, 27: 0x37A0, 28: 0xE007, 29: 0x1C28,
        32: 0x0841, 33: 0xD307, 34: 0x200F,
        37: 0x1C39, 38: 0x1C20,
    }
    stage_fixed = {
        0: 0x0BC1, 1: 0xD304, 4: 0x2101, 5: 0x0389,
        7: 0x0B81, 8: 0xD307, 11: 0x2101, 12: 0x0349,
        13: 0x1C28, 17: 0x0A80, 18: 0xD302,
    }
    anchor = struct.pack("<2H", stage_fixed[0], stage_fixed[1])
    offset = 0
    while (offset := image.find(anchor, offset)) >= 0:
        function = offset - 84
        if offset & 1 or function < 0 or offset + 50 > len(image):
            offset += 1
            continue
        setup = struct.unpack_from("<42H", image, function)
        stages = struct.unpack_from("<25H", image, offset)

        def bl(words: tuple[int, ...], index: int) -> bool:
            return (words[index] & 0xF800 == 0xF000
                    and words[index + 1] & 0xF800 == 0xF800)

        if (any(setup[index] != value
                for index, value in setup_fixed.items())
                or any(stages[index] != value
                       for index, value in stage_fixed.items())
                or not all(bl(setup, index)
                           for index in (6, 13, 17, 19, 24, 30, 35, 39))
                or not all(bl(stages, index)
                           for index in (2, 9, 14, 19, 22))):
            offset += 2
            continue
        loop = offset - 26
        if (unconditional_target(function + 82, setup[41]) != loop
                or unconditional_target(offset + 12, stages[6])
                != offset + 26
                or any(unconditional_target(offset + index * 2,
                                             stages[index]) != loop
                       for index in (16, 21, 24))):
            offset += 2
            continue
        idle = offset + 44
        target = thumb_bl_target(image, idle)
        if target is None or not 0 <= target < len(image):
            offset += 2
            continue
        callers = [
            match.start() for match in THUMB_BL_PATTERN.finditer(image)
            if not match.start() & 1
            and thumb_bl_target(image, match.start()) == target
        ]
        if callers == [idle]:
            candidates.append(idle)
        offset += 2
    candidates = sorted(set(candidates))
    return candidates[0] if len(candidates) == 1 else None
