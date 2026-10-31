"""Source-closed stack-based 0x620 W1C timer route.

The CPU executes the original handler and callbacks. Physical tick cadence is
a temporary 5 ms approximation; this does not establish handset idle."""
from __future__ import annotations
import struct
from .arm import thumb_literal_value, thumb_bl_target
from .rex import _normalized_thumb_sha256, _legacy_620_vector_copy, _rex_5ms_registration_targets, REX_5MS_ARM_PATTERN

def find_stack_w1c_irq_profile(image: bytes, ram_base: int, ram_size: int) -> dict[str, object] | None:
    """Bind copied vector, dispatcher, registrar, installed callback and delta-5 walk."""
    if type(ram_base) is not int or type(ram_size) is not int or ram_base < 0 or (ram_size <= 0) or (ram_base + ram_size > 0x100000000):
        return None

    def ram(at, n=4):
        return isinstance(at, int) and ram_base <= at <= ram_base + ram_size - n

    def shape(at, n, digest, calls):
        return _normalized_thumb_sha256(image, at, n) == (digest, tuple(calls))

    def word(at):
        return struct.unpack_from('<I', image, at)[0] if 0 <= at <= len(image) - 4 else None

    def half(at):
        return struct.unpack_from('<H', image, at)[0] if 0 <= at <= len(image) - 2 else None

    def lit(at, off, reg):
        return thumb_literal_value(image, at + off, reg)

    def call(at, off):
        return thumb_bl_target(image, at + off)

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
    needle = struct.pack('<3I', 0x3000620, 0x3000628, 0x200)
    at = 0
    while (at := image.find(needle, at)) >= 0:
        if at % 4 == 0 and source <= at <= source + length - 0x1c:
            seed = struct.unpack_from('<7I', image, at)
            if ram(seed[3], 12) and seed[4] == seed[3] + 4 and seed[5] & 1 and (seed[6] == 0):
                seeds.append((at, seed))
        at += 1
    if len(seeds) != 1:
        return None
    raw, seed = seeds[0]
    status, enable, mask, masks, _, default, _ = seed
    handler = (default & ~1) + 0x38
    if not shape(handler, 0x156, 'a4acd8ad963be9f347edac0009155d17861136f833f78e810d55c00e0c06c435', (0x3a, 0x46, 0x58, 0xca, 0xec, 0x114, 0x150)):
        return None
    table = masks + 12
    descriptor = target + raw - source
    slot = descriptor + 0x14
    groups = descriptor + 0x1c
    if descriptor != table + 0x1c * 0x1c or not ram(table, 0x1d * 0x1c):
        return None
    depth = lit(handler, 0x3e, 0)
    if not ram(depth, 2) or not refs(handler, [
        (4, 2, masks),
        (14, 2, masks),
        (0x14, 7, status),
        (0x50, 7, masks),
        (0x62, 1, status),
        (0x6e, 0, masks + 8),
        (0x84, 1, groups),
        (0xaa, 2, masks),
        (0xae, 7, status),
        (0xd8, 1, table),
        (0xde, 3, enable),
        (0xfc, 1, status),
        (0x106, 3, enable + 4),
        (0x124, 1, status),
        ]):
        return None
    unlock, lock, trampoline = (call(handler, 0x3a), call(handler, 0x58), call(handler, 0xec))
    if any((not rom(at) for at in [unlock, lock, trampoline])):
        return None
    if call(handler, 0xca) != unlock or call(handler, 0x150) != lock or call(handler, 0x114) != trampoline or (half(trampoline) != 0x4700):
        return None
    for helper, instruction in [(lock, 0xe38010c0), (unlock, 0xe3c010c0)]:
        if helper & 3:
            return None
        expected = struct.pack('<2H6I', 0x4778, 0, 0xe38ee001, 0xe10f0000, instruction, 0xe121f001, 0xe20000c0, 0xe12fff1e)
        if image[helper:helper + len(expected)] != expected:
            return None
    gr = raw + 0x1c
    if gr + 0x24 > source + length:
        return None
    rows = [struct.unpack_from('<4H2B', image, gr + i * 12) for i in range(3)]
    if rows[2] != (mask, 0, mask, 0, 0x1c, 0x1c) or any((r[0] & mask or not 0 <= r[4] <= r[5] < 0x1c for r in rows[:2])):
        return None
    ticks = []
    for match in REX_5MS_ARM_PATTERN.finditer(image):
        at = match.start()
        cb = lit(at, 6, 1)
        reg = call(at, 10)
        if lit(at, 0, 1) != 0x30006e0 or half(at + 2) != 0x2002 or half(at + 4) != 0x7008 or (half(at + 8) != 0x201c) or (cb is None) or (not cb & 1) or (not rom(reg)):
            continue
        cb &= ~1
        if not shape(reg, 0x5c, 'd407f54fa55e821e625e761230bbe0baf3176d339f73a497cac728600b335710', (6, 0x56)):
            continue
        if not refs(reg, [(10, 1, default), (0x16, 3, table)]) or call(reg, 6) != lock or call(reg, 0x56) != unlock:
            continue
        if not shape(cb, 0x40, '409a4528354e167eba0e5f46586c66af77a903eb33b5dceec96fce95e1a424aa', (2, 14, 0x14, 0x2a, 0x32, 0x3a)):
            continue
        if call(cb, 2) != lock or call(cb, 0x3a) != unlock or _rex_5ms_registration_targets(image, cb) != [reg] * 3:
            continue
        if any((not ram(lit(cb, off, 0)) for off in [12, 0x12, 0x1c, 0x20, 0x2e])):
            continue
        if lit(cb, 0x1c, 0) != lit(cb, 0x20, 0) + 4:
            continue
        walker = call(cb, 0x2a)
        advance = call(cb, 14)
        if not rom(walker) or not rom(advance):
            continue
        if not shape(walker, 0x46, '4b4c45533dff4f596d1a6b6f61536596f25b1664a9508f2008c43d3047f83045', (4, 0x2a, 0x40)):
            continue
        if call(walker, 4) != lock or call(walker, 0x40) != unlock or (not rom(call(walker, 0x2a))):
            continue
        if not ram(lit(walker, 10, 0)) or lit(walker, 10, 0) != lit(walker, 0x36, 0) + 0x14:
            continue
        if not shape(advance, 0x72, '414366991cb3c9cd242b0910e8e111ddacccc5ac078f7f58b9dc41fc0937f6b7', (0x36, 0x46, 0x64)):
            continue
        if call(advance, 0x36) != lock or call(advance, 0x64) != unlock or (not rom(call(advance, 0x46))):
            continue
        if not refs(advance, [(0x26, 6, lit(cb, 0x1c, 0)), (0x3e, 5, 0x30000f0), (0x4a, 0, lit(cb, 12, 0))]):
            continue
        if any((not rom(call(cb, off)) for off in [0x14, 0x32])):
            continue
        ticks.append((cb, reg))
    if len(ticks) != 1:
        return None
    callback, registrar = ticks[0]
    if wrapper % 4 or not rom(wrapper, 0x60):
        return None
    if tuple((word(wrapper + i * 4) for i in range(4))) != (0xe24ee004, 0xe92d540f, 0xe14f0000, 0xe92d0001):
        return None

    def arm_literal(at, reg):
        op = word(at)
        if op is None or op & 0xfffff000 != 0xe59f0000 | reg << 12:
            return None
        return word(at + 8 + (op & 0xfff))
    handler_slot = arm_literal(wrapper + 0x28, 3)
    if not ram(handler_slot, 8) or handler_slot & 3 or depth & 1 or (arm_literal(wrapper + 0x10, 0) != depth):
        return None
    if tuple((word(wrapper + off) for off in [0x2c, 0x30, 0x3c])) != (0xe5933000, 0xe3130001, 0xe12fff13):
        return None
    installs = []
    for at in range(0, len(image) - 4, 2):
        if lit(at, 0, 1) != handler | 1 or half(at + 2) != 0x2000:
            continue
        setter = call(at, 4)
        init = at - 0x3e
        if not rom(setter, 14) or init < 0:
            continue
        expected = {0: 0x1c02, 4: 0xd101, 6: 0x60c1, 8: 0x46f7, 10: 0x6101, 12: 0xe7fc}
        if any((half(setter + off) != v for off, v in expected.items())) or lit(setter, 2, 0) != handler_slot - 12:
            continue
        if not shape(init, 0x62, '4beaa748979259b8d690dc68b95c74e4fa01a7ac615e463af87d3f3c91133049', (2, 8, 0x1a, 0x1e, 0x2a, 0x3a, 0x42, 0x48, 0x4e)):
            continue
        if not refs(init, [(0x10, 5, status), (0x2e, 0, 0xffff), (0x3e, 1, handler | 1)]):
            continue
        if any((call(init, off) != lock for off in [2, 8, 0x1e])) or any((call(init, off) != unlock for off in [0x1a, 0x2a, 0x3a])):
            continue
        installs.append(setter)
    if len(installs) != 1:
        return None
    return dict(status=status, enable=enable, arm=0x30006e0, mask=mask, interval_ns=5_000_000, handler=handler, callback=callback, registrar=registrar, handler_slot=handler_slot, callback_slot=slot, physical_cadence='temporary-5ms-approximation')
