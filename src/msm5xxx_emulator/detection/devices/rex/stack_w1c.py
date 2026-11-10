"""Source-closed stack-based 0x620 W1C timer route.

The CPU executes the original handler and callbacks, including optional
service paths whose remote devices remain unqualified. Only controller/timer
ownership is established here. Physical tick cadence is
a temporary 5 ms approximation; this does not establish handset idle."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
import hashlib
from msm5xxx_emulator.detection.devices.rex.rules import (_normalized_thumb_sha256, _legacy_620_vector_copy, rex_5ms_registration_targets, REX_5MS_ARM_PATTERN)

def find_stack_w1c_irq_profile(image: bytes, ram_base: int, ram_size: int) -> dict[str, object] | None:
    """Bind copied vector, dispatcher, registrar, installed callback and delta-5 walk."""
    if type(ram_base) is not int or type(ram_size) is not int or ram_base < 0 or (ram_size <= 0) or (ram_base + ram_size > 4294967296):
        return None
    def rawshape(at, n, digest):
        return type(at) is int and (not at & 1) and (0 <= at <= len(image) - n) and (hashlib.sha256(image[at:at + n]).hexdigest() == digest)
    def ram(at, n=4):
        return isinstance(at, int) and ram_base <= at <= ram_base + ram_size - n
    def shape(at, n, digest, calls):
        return _normalized_thumb_sha256(image, at, n) == (digest, tuple(calls))
    def word(at):
        return struct.unpack_from('<I', image, at)[0] if 0 <= at <= len(image) - 4 else None
    def half(at):
        return struct.unpack_from('<H', image, at)[0] if 0 <= at <= len(image) - 2 else None
    def lit(at, off, reg):
        return facts_for(image).thumb_literal_value(at + off, reg)
    def call(at, off):
        return facts_for(image).thumb_call_target(at + off)
    def rom(at, n=2):
        return isinstance(at, int) and at % 2 == 0 and (0 <= at <= len(image) - n)
    def refs(at, rows):
        return all((lit(at, off, reg) == value for off, reg, value in rows))
    vec = _legacy_620_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
    if vec is None:
        return None
    source, target, length, wrapper = vec
    if source & 3 or target & 3 or length & 3:
        return None
    seeds = []
    needle = struct.pack('<3I', 50333216, 50333224, 512)
    at = 0
    while (at := image.find(needle, at)) >= 0:
        if at % 4 == 0 and source <= at <= source + length - 28:
            seed = struct.unpack_from('<7I', image, at)
            if ram(seed[3], 12) and seed[4] == seed[3] + 4 and seed[5] & 1 and (seed[6] == 0):
                seeds.append((at, seed))
        at += 1
    if len(seeds) != 1:
        return None
    raw, seed = seeds[0]
    status, enable, mask, masks, _, default, _ = seed
    handler = (default & ~1) + 56
    if not shape(handler, 342, 'a4acd8ad963be9f347edac0009155d17861136f833f78e810d55c00e0c06c435', (58, 70, 88, 202, 236, 276, 336)):
        return None
    table = lit(handler, 216, 1)
    counter = lit(handler, 110, 0)
    if not ram(table, 29 * 28) or table & 3 or table - masks not in (8, 12) or (not ram(counter, 2)) or counter & 1:
        return None
    descriptor = target + raw - source
    slot = descriptor + 20
    groups = descriptor + 28
    if descriptor != table + 28 * 28 or not ram(table, 29 * 28):
        return None
    depth = lit(handler, 62, 0)
    if not ram(depth, 2) or not refs(handler,[(4, 2, masks), (14, 2, masks), (20, 7, status), (80, 7, masks), (98, 1, status), (110, 0, counter), (132, 1,
        groups), (170, 2, masks), (174, 7, status), (216, 1, table), (222, 3, enable), (252, 1, status), (262, 3, enable + 4), (292, 1, status)]):
        return None
    unlock, lock, trampoline = (call(handler, 58), call(handler, 88), call(handler, 236))
    if any((not rom(at) for at in [unlock, lock, trampoline])):
        return None
    if call(handler, 202) != unlock or call(handler, 336) != lock or call(handler, 276) != trampoline or (half(trampoline) != 18176):
        return None
    for helper, instruction in [(lock, 3816820928), (unlock, 3821015232)]:
        if helper & 3:
            return None
        expected = struct.pack('<2H6I', 18296, 0, 3817791489, 3775856640, instruction, 3777097729, 3791651008, 3778019102)
        if image[helper:helper + len(expected)] != expected:
            return None
    gr = raw + 28
    if gr + 36 > source + length:
        return None
    rows = [struct.unpack_from('<4H2B', image, gr + i * 12) for i in range(3)]
    if rows[2] != (mask, 0, mask, 0, 28, 28) or any((r[0] & mask or not 0 <= r[4] <= r[5] < 28 for r in rows[:2])):
        return None
    ticks = []
    for match in REX_5MS_ARM_PATTERN.finditer(image):
        at = match.start()
        cb = lit(at, 6, 1)
        reg = call(at, 10)
        if lit(at, 0, 1) != 50333408 or half(at + 2) != 8194 or half(at + 4) != 28680 or (half(at + 8) != 8220) or (cb is None) or (not cb & 1) or (not rom(reg)):
            continue
        cb &= ~1
        registrar_ok = shape(reg, 92, 'd407f54fa55e821e625e761230bbe0baf3176d339f73a497cac728600b335710', (6, 86)) and refs(reg,[(10, 1, default), (22, 3, table)]) and (call(reg,
            86) == unlock) or (shape(reg, 122, 'e13e6e1b08b7e0d44251c0bca9fdc1a5f745d185473857501424481590d698f7', (6, 28, 44, 116)) and refs(reg,[(12, 6,
            default), (52, 1, table)]) and (call(reg, 116) == unlock)) or (shape(reg, 114, 'c0a5c7102cf5857b5cae562801cf89c99d6b71ae7ac39633d06f5bde21631a30', (6,
            28, 36, 108)) and refs(reg,[(12, 6, default), (44, 1, table)]) and (call(reg, 108) == unlock))
        if not registrar_ok or call(reg, 6) != lock:
            continue
        short = shape(cb, 64, '409a4528354e167eba0e5f46586c66af77a903eb33b5dceec96fce95e1a424aa', (2, 14, 20, 42, 50, 58))
        long = shape(cb, 96, '8b9327acc5052d2fec3a67c6a947a169d214c02346b4d689b0d9d0c9021c3676', (2, 14, 20, 42, 70, 82, 90))
        if not (short or long):
            continue
        last_literal, last_call, unlock_call = (46, 50, 58) if short else (78, 82, 90)
        if call(cb, 2) != lock or call(cb, unlock_call) != unlock or rex_5ms_registration_targets(image, cb) !=[reg] * 3:
            continue
        if any((not ram(lit(cb, off, 0)) for off in [12, 18, 28, 32, last_literal])) or not ram(lit(cb, 12, 0), 8):
            continue
        if long and (not ram(lit(cb, 46, 0), 1) or not ram(lit(cb, 54, 7), 1) or (not rom(call(cb, 70)))):
            continue
        if lit(cb, 28, 0) != lit(cb, 32, 0) + 4:
            continue
        walker = call(cb, 42)
        advance = call(cb, 14)
        if not rom(walker) or not rom(advance):
            continue
        if not shape(walker, 70, '4b4c45533dff4f596d1a6b6f61536596f25b1664a9508f2008c43d3047f83045', (4, 42, 64)):
            continue
        if call(walker, 4) != lock or call(walker, 64) != unlock or (not rom(call(walker, 42))):
            continue
        if not ram(lit(walker, 10, 0)) or lit(walker, 10, 0) != lit(walker, 54, 0) + 20:
            continue
        simple = shape(advance, 34, '80d4b4d5bad63603c84a0304a82720ac074769f4d8e97b8ee0b4dead72ec4687', ())
        extended = shape(advance, 114, '414366991cb3c9cd242b0910e8e111ddacccc5ac078f7f58b9dc41fc0937f6b7', (54, 70, 100))
        if not (simple or extended):
            continue
        if extended and (call(advance, 54) != lock or call(advance, 100) != unlock or (not rom(call(advance, 70))) or (not refs(advance,[(38, 6, lit(cb, 28, 0)),
            (62, 5, 50331888), (74, 0, lit(cb, 12, 0))]))):
            continue
        if any((not rom(call(cb, off)) for off in [20, last_call])):
            continue
        ticks.append((cb, reg))
    if len(ticks) != 1:
        return None
    callback, registrar = ticks[0]
    if wrapper % 4 or not rom(wrapper, 96):
        return None
    if tuple((word(wrapper + i * 4) for i in range(4))) != (3796819972, 3912061967, 3780050944, 3912040449):
        return None
    def arm_literal(at, reg):
        op = word(at)
        if op is None or op & 4294963200 != 3852402688 | reg << 12:
            return None
        return word(at + 8 + (op & 4095))
    handler_slot = arm_literal(wrapper + 40, 3)
    if not ram(handler_slot, 8) or handler_slot & 3 or depth & 1 or (arm_literal(wrapper + 16, 0) != depth):
        return None
    if tuple((word(wrapper + off) for off in [44, 48, 60])) != (3851628544, 3809673217, 3778019091):
        return None
    installs = []
    for at in range(0, len(image) - 4, 2):
        if lit(at, 0, 1) != handler | 1 or half(at + 2) != 8192:
            continue
        setter = call(at, 4)
        init = at - 62
        if not rom(setter, 14) or init < 0:
            continue
        expected = {0: 7170, 4: 53505, 8: 18167, 12: 59388}
        base = lit(setter, 2, 0)
        first, second = (half(setter + 6), half(setter + 10))
        if any((half(setter + off) != v for off, v in expected.items())) or type(base) is not int or first & 63551 != 24577 or (second & 63551 != 24577):
            continue
        first_offset = (first >> 6 & 31) * 4
        second_offset = (second >> 6 & 31) * 4
        if base + first_offset != handler_slot or second_offset != first_offset + 4:
            continue
        if not shape(init, 84, '8d320800092ad7384096c95aeea7a590e53cc2a96ccfc781d7af2f33eac8721b', (2, 8, 26, 30, 42, 58, 66, 72, 78)):
            continue
        if not refs(init,[(16, 5, status), (46, 0, 65535), (62, 1, handler | 1)]):
            continue
        if any((call(init, off) != lock for off in [2, 8, 30])) or any((call(init, off) != unlock for off in [26, 42, 58])):
            continue
        irq_enable = call(init, 72)
        queue_init = call(init, 78)
        queue_head = lit(init, 76, 0)
        deferred = call(handler, 70)
        if not rawshape(irq_enable, 32, '47327dedbdf12a9a56d5e073a3a2a246775f60b9479cff81809afe5da09fd720') or irq_enable & 3:
            continue
        if not rawshape(queue_init, 10, 'f42a71d6606ae7c6cad153363b723042235660f3b4fced601ca374f84f843394'):
            continue
        if not ram(queue_head, 12) or queue_head & 3 or (not rom(deferred, 4)) or (lit(deferred, 2, 0) != queue_head) or (not ram(lit(init, 12, 6))):
            continue
        if not shape(deferred, 34, '47e9aa4734e6d418b4dda033d6499fa6610307d3b2aea3e7faaa3882dfa9cb08', (4, 20)):
            continue
        pop = call(deferred, 4)
        invoke = call(deferred, 20)
        if not rom(invoke) or half(invoke) != 18184:
            continue
        if not shape(pop, 52, '92633ae4a9cb441d8528744f9d69cbda66d8318c6ed88ded50e9dd56f4a57b14', (6, 44)) or call(pop, 6) != lock or call(pop, 44) != unlock:
            continue
        shadow = lit(init, 12, 6)
        if not ram(shadow, 0x18) or shadow & 3:
            continue
        installs.append(setter)
    if len(installs) != 1:
        return None
    return dict(status=status, enable=enable, arm=50333408, mask=mask, interval_ns=5000000, handler=handler, callback=callback, registrar=registrar,
        handler_slot=handler_slot, callback_slot=slot, physical_cadence='temporary-5ms-approximation')
