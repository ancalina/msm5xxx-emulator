"""Firmware REX timer, IRQ, and idle detection."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value


REX_TICK_SIGNATURE = bytes.fromhex("00b500f08ffb08bc1847")
REX_5MS_WRAPPER_ANCHOR = bytes.fromhex(
    "800801d30a4800e00a480168053901600520"
)
REX_5MS_CALLBACK_SIZE = 64
REX_TIMER_ADVANCE_SIZE = 70


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


def rex_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate the old REX delta-timer list walker used by MSM5000 BSPs."""
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
    registration_targets: list[int] = []
    for position in range(0, len(image) - 8, 2):
        if (thumb_literal_value(image, position, 1) == tick_position | 1
                and struct.unpack_from("<H", image, position + 2)[0]
                == 0x201C):
            target = thumb_bl_target(image, position + 4)
            if target is not None and 0 <= target < len(image):
                registration_targets.append(target)
    if (len(registration_targets) != 3
            or len(set(registration_targets)) != 1):
        return None
    registrar = registration_targets[0]
    arms: list[int] = []
    for position in range(10, len(image) - 4, 2):
        arm = thumb_literal_value(image, position - 10, 1)
        if (thumb_bl_target(image, position) == registrar
                and arm is not None and 0x03000000 <= arm < 0x04000000
                and struct.unpack_from("<2H", image, position - 8)
                == (0x2002, 0x7008)
                and thumb_literal_value(image, position - 4, 1)
                == tick_position | 1
                and struct.unpack_from("<H", image, position - 2)[0]
                == 0x201C):
            arms.append(arm)
    return arms[0] if len(arms) == 1 else None


def find_rex_5ms_irq_route(
        image: bytes, tick_position: int,
        map_position=None) -> tuple[int, int, int, int, int, int, int] | None:
    """Bind one 5 ms callback to its complete old Qualcomm IRQ route."""
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

        registration_targets: list[int] = []
        for position in range(0, len(image) - 8, 2):
            if (runtime_code(position) is not None
                    and thumb_literal_value(image, position, 1)
                    == tick_address | 1
                    and struct.unpack_from("<H", image, position + 2)[0]
                    == 0x201C):
                target = thumb_bl_target(image, position + 4)
                if (target is not None and 0 <= target < len(image)
                        and runtime_code(target) is not None):
                    registration_targets.append(target)
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


def find_rex_idle_address(image: bytes) -> int | None:
    """Find the final idle BL in the old Qualcomm REX signal loop."""
    candidates: list[int] = []
    fixed = {
        0: 0x0BC1, 1: 0xD306, 2: 0x2108, 6: 0x2101, 7: 0x0389,
        8: 0xE007, 9: 0x0B81, 10: 0xD309, 11: 0x2108,
        15: 0x2101, 16: 0x0349, 20: 0xE7D8, 21: 0x0A80,
        22: 0xD302, 25: 0xE7D3,
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
    return candidates[0] if len(candidates) == 1 else None
