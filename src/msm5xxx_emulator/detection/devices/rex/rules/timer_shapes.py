from __future__ import annotations
import re

REX_TICK_SIGNATURE = bytes.fromhex("00b500f08ffb08bc1847")
REX_5MS_WRAPPER_ANCHOR = bytes.fromhex("800801d30a4800e00a480168053901600520")
REX_5MS_CALLBACK_SIZE = 64
REX_TIMER_ADVANCE_SIZE = 70
REX_LEGACY_5MS_CALLBACK_SIZE = 68
REX_TIMER_CALLBACK_DRAIN_SIZE = 40
UIS_IDLE_ENTRY_PREFIX = bytes.fromhex("f0b5b4b009a92120")
UIS_IDLE_BODY_PREFIX = bytes.fromhex("9748974a40780026")
UIS_IDLE_BODY_DELTA = 0x15E
UIS_IDLE_COMPACT_ENTRY_PREFIX = bytes.fromhex("f0b5acb000200a90")
UIS_IDLE_COMPACT_BODY_PREFIX = bytes.fromhex("be48be4d40780021")
UIS_IDLE_COMPACT_BODY_DELTA = 0xFE
UIS_IDLE_DRAW_MARKER = (b"[Idle_IdleP_OnDraw]Draw Idle Image in Enter Refresh\0")
UIS_IDLE_DRAW_BODY_DELTAS = (0x8B8, 0x908)
UIS_IDLE_BODY_DELTAS = (UIS_IDLE_COMPACT_BODY_DELTA, UIS_IDLE_BODY_DELTA, *UIS_IDLE_DRAW_BODY_DELTAS,)
REX_IRQ_WRAPPER_SIGNATURE = bytes.fromhex("04e04ee20f542de900004fe101002de92c029fe5b010d0e1011081e2b010c0e1"
    "9ff021e300402de918329fe5003093e5010013e310e29f1510e29f0513ff2fe1")
REX_IRQ_WRAPPER_RUNTIME_SIZE = 0x260
REX_IRQ_HANDLER_RUNTIME_SIZE = 0x1DC
TRAMPM5_CONSUMER_SIZE = 40
REX_INTLOCK_SIGNATURE = bytes.fromhex("7847000001e08ee300000fe1c01080e301f021e1c00000e2")
REX_INTFREE_SIGNATURE = bytes.fromhex("7847000001e08ee300000fe1c010c0e301f021e1c00000e2")
REX_IRQ_DRAIN_PATTERN = re.compile(rb"\x08\x43\x1f\xd1.{4}\x47\x48\x00\x88\x01\x28\x03\xd1" rb".{4}\x00\x28\xfb\xd1", re.S,)
THUMB_BL_PATTERN = re.compile(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", re.S,)
REX_5MS_REGISTRATION_PATTERN = re.compile(rb"[\x00-\xff][\x49-\x4f]\x1c\x20", re.S,)
REX_5MS_ARM_PATTERN = re.compile(rb"[\x00-\xff][\x49-\x4f]\x02\x20\x08\x70" rb"[\x00-\xff][\x49-\x4f]\x1c\x20" rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]",
    re.S,)

def rex_5ms_registration_targets(image: bytes, tick_address: int, runtime_code=None, *, candidate_only_mapper: bool = False,) -> list[int]:
    """Return timer-registrar targets; candidate-only mapping requires purity."""
    from . import REX_5MS_REGISTRATION_PATTERN, facts_for
    targets: list[int] = []
    candidates = { match.start() for match in REX_5MS_REGISTRATION_PATTERN.finditer(image) if not match.start() & 1 and match.start() < len(image) - 8 }
    positions = (sorted(candidates) if runtime_code is None or candidate_only_mapper else range(0, len(image) - 8, 2))
    for position in positions:
        mapped = runtime_code(position) if runtime_code is not None else position
        if (mapped is None or position not in candidates or facts_for(image).thumb_literal_value(position, 1) != tick_address | 1):
            continue
        target = facts_for(image).thumb_call_target(position + 4)
        if (target is not None and 0 <= target < len(image) and (runtime_code is None or runtime_code(target) is not None)):
            targets.append(target)
    return targets

def rex_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate an MSM5000 REX active-timer list walker."""
    from . import REX_TIMER_ADVANCE_SIZE, struct
    if position < 0 or position + REX_TIMER_ADVANCE_SIZE > len(image):
        return False
    words = struct.unpack_from("<35H", image, position)
    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000 and words[index + 1] & 0xF800 == 0xF800)
    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800 and words[index] >> 8 & 7 == register)
    return (words[:2] == (0xB5F0, 0x1C04) and bl(2) and words[4] == 0x1C07 and literal(5, 0) and words[6:11] == (0x2600, 0x6805, 0xE011, 0x68A8, 0x42A0) and
        words[11] & 0xFF00 == 0xD800 and words[12:21] == (0x60AE, 0xCD03, 0x3D08, 0x6008, 0x6868, 0x6829, 0x6048, 0x68E8, 0x6929,) and bl(21) and words[23:27]
        == (0xE001, 0x1B00, 0x60A8, 0x682D) and literal(27, 0) and words[28] == 0x4285 and words[29] & 0xFF00 == 0xD100 and words[30:32] == (0x2F00, 0xD101) and
        bl(32) and words[34] == 0xBDF0)

def legacy_rex_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate the older register-renamed REX active-timer walker."""
    if position < 0 or position + 0x38 > len(image):
        return False
    return (image[position:position + 2] == b"\xf0\xb5" and b"\xa0\x42" in image[position:position + 0x30] and b"\x00\x20\xb8\x60" in image[position:position +
        0x38])

def _controller_timer_advance_at(image: bytes, position: int) -> bool:
    """Close the legacy walker to its timer callback fanout call."""
    from . import facts_for, legacy_rex_timer_advance_at, struct
    if (not legacy_rex_timer_advance_at(image, position) or position + 0x60 > len(image)):
        return False
    calls = [offset for offset in range(position, position + 0x58, 2) if struct.unpack_from("<2H", image, offset)[:2] == (0x68F8, 0x6939) and facts_for(image).thumb_call_target(offset
        + 4) is not None]
    return len(calls) == 1

def _controller_two_bank_handler_at(image: bytes, position: int, masks: int, status: int,) -> bool:
    """Validate isolated C80/FB0 two-bank mask/dispatch shapes."""
    from . import _normalized_thumb_sha256, facts_for, struct
    if status == 0x03000FB0:
        # Exact body; relocated calls are bounded and relevant ABIs closed below.
        if _normalized_thumb_sha256(image, position, 0x182) != ("a4a7b1ec46eb3f925c0c0ec155e143760ebdcfff7303475242d879917c9e6225", (0x30, 0x92, 0xB6, 0xEE,
            0x106, 0x142, 0x148, 0x15A),):
            return False
        literals = ((0, 2, masks), (0x12, 2, masks), (0x6C, 2, masks), (0x150, 7, masks), (0x9E, 1, masks + 0x0C), (0x48, 1, masks + 0x0C + 0x1B * 0x1C + 0x20))
        ports = ((0x0E, 1), (0x84, 1), (0xA4, 3), (0xC8, 1), (0xCE, 3), (0xE8, 1), (0x118, 1), (0x164, 1))
        thunks = [facts_for(image).thumb_call_target(position + delta) for delta in (0xB6, 0xEE, 0x106)]
        return (all(facts_for(image).thumb_literal_value(position + delta, register) == value for delta, register, value in literals) and all(facts_for(image).thumb_literal_value(position
            + delta, register) == status - 0x10 for delta, register in ports) and len(set(thunks)) == 1 and thunks[0] is not None and 0 <= thunks[0] <= len(image)
            - 2 and image[thunks[0]:thunks[0] + 2] == b"\x00\x47")
    if position < 0 or position + 0x100 > len(image):
        return False
    words = struct.unpack_from("<33H", image, position)
    def literal(index: int, register: int, value: int) -> bool:
        return facts_for(image).thumb_literal_value(position + index * 2, register) == value
    common = (words[0] == 0xB5F0 and words[1] & 0xFFF0 == 0xB080 and words[2] & 0xF800 == 0xF000 and words[3] & 0xF800 == 0xF800 and literal(4, 2, masks) and
        words[5:9] == (0x88D1, 0x9102, 0x8911, 0x9101) and literal (9, 7, status) and words[10] == 0x8838 and literal(11, 2, masks) and words[12:25] == (0x8813,
        0x9902, 0x4019, 0x4001, 0x9104, 0x88B8, 0x8853, 0x9901, 0x4019, 0x4008, 0x9904, 0x9003, 0x4308,) and words[25] & 0xFF00 == 0xD100 and facts_for(image).thumb_call_target(position
        + 26 * 2) is not None)
    group10 = (words[:2] == (0xB5F0, 0xB087) and words[2] & 0xF800 == 0xF000 and words[3] & 0xF800 == 0xF800 and literal(4, 7, masks) and words[5:11] == (0x201B,
        0x88F9, 0x0140, 0x9102, 0x8939, 0x9101) and literal (11, 1, masks + 0x0C) and words[12:14] == (0x1840, 0x9006) and literal(14, 7, status) and words[15]
        == 0x8838 and literal(16, 3, masks) and words[17:30] == (0x881A, 0x9902, 0x4011, 0x4001, 0x9104, 0x88B8, 0x885A, 0x9901, 0x4011, 0x4008, 0x9904, 0x9003,
        0x4308,) and words[30] & 0xFF00 == 0xD100 and facts_for (image).thumb_call_target(position + 31 * 2) is not None and _normalized_thumb_sha256(image,
        position, 0x150) == ("b1b2c73d6bebf0bf1262d1258f2c1bf0787b25cfba27bfc9f24566fc9676f627", (0x04, 0x3E, 0x9E, 0xC2, 0xFE, 0x116),))
    if not (common or group10):
        return False
    # A second bank pass must consume both the same RAM masks and status.
    later = range(position + 0x70, position + 0x100, 2)
    if (not any(facts_for(image).thumb_literal_value(offset, register) == masks for offset in later for register in range(8)) or not any(facts_for(image).thumb_literal_value(offset,
        register) == status for offset in later for register in range(8))):
        return False
    def callback_thunk(target: int | None) -> bool:
        if target is None or target + 2 > len(image):
            return False
        if image[target:target + 2] == b"\x00\x47":
            return True
        if (target + 16 > len(image) or struct.unpack_from("<6H", image, target) != (0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F)):
            return False
        indirect = struct.unpack_from("<I", image, target + 12)[0]
        return (indirect & 1 and indirect + 1 <= len(image) and image[indirect & ~1:(indirect & ~1) + 2] == b"\x00\x47")
    # Close descriptor callback loads to a BX R0 thunk, then require one
    # handled-mask writeback through the same status literal.
    dispatches = 0
    for offset in later:
        if struct.unpack_from("<H", image, offset)[0] != 0x6978:
            continue
        target = facts_for(image).thumb_call_target(offset + 2)
        if callback_thunk(target):
            dispatches += 1
    if dispatches < 2:
        return False
    for load in later:
        for register in range(8):
            if facts_for(image).thumb_literal_value(load, register) != status:
                continue
            for store in range(load + 2, min(position + 0x100, load + 0x12), 2):
                word = struct.unpack_from("<H", image, store)[0]
                if (word & 0xF800 == 0x8000 and word >> 3 & 7 == register and (word >> 6 & 0x1F) * 2 in (0, 4)):
                    return True
    return False

def _controller_registrar_at(image: bytes, position: int, default: int, *, fb0: bool = False, group_base: bool = False,) -> int | None:
    """Validate registration; preserve the historical special-slot default."""
    from . import _normalized_thumb_sha256, facts_for, struct
    if fb0:
        if (_normalized_thumb_sha256(image, position, 0x80) != ("cdeb88a1799aec812a625e545d713c23322c8b8ae0e593621109b7d2c6532ee8", (0x06, 0x1C, 0x26, 0x76),)
            or facts_for(image).thumb_literal_value(position + 0x0E, 6) != default):
            return None
        table = facts_for(image).thumb_literal_value(position + 0x2C, 1)
        if (table is None or facts_for(image).thumb_literal_value(position + 0x36, 1) != table + 0x1B * 0x1C):
            return None
        return table
    if position < 0 or position + 0x44 > len(image):
        return None
    words = struct.unpack_from("<34H", image, position)
    direct_error = (words[14] & 0xF800 == 0xF000 and words[15] & 0xF800 == 0xF800)
    shifted_error = (words[13] == 0xDB04 and words[14:16] == (0x2045, 0x00C0) and words[16] & 0xF800 == 0x4800 and words[16] >> 8 & 7 == 1 and words[17] &
        0xF800 == 0xF000 and words[18] & 0xF800 == 0xF800)
    if not (words[0] & 0xFFF0 == 0xB5F0 and words[1:3] == (0x1C04, 0x1C0F) and words[3] & 0xF800 == 0xF000 and words[4] & 0xF800 == 0xF800 and words[5:7] == (0x1C05,
        0x2F00) and words[7] & 0xF800 == 0x4800 and words[7] >> 8 & 7 == 6 and words[8:13] == (0xD100, 0x1C37, 0x2C00, 0xDB01, 0x2C1F) and words[13] & 0xFF00 ==
        0xDB00 and (direct_error or shifted_error) and facts_for(image).thumb_literal_value(position + 14, 6) == default):
        return None
    rows = [index for index in range(16, 25) if (words[index] == 0x201C and words[index + 1] & 0xF800 == 0x4800 and words[index + 1] >> 8 & 7 == 1 and words[index
        + 2:index + 10] == (0x4360, 0x1840, 0x2C00, 0xD102, words[index + 6], 0x630F, 0xE000, 0x6147,) and words[index + 6] & 0xF800 == 0x4800 and words[index +
        6] >> 8 & 7 == 1)]
    if len(rows) != 1:
        return None
    return facts_for(image).thumb_literal_value(position + (rows[0] + (1 if group_base else 6)) * 2, 1)

def _controller_callback_advance(image: bytes, position: int,) -> int | None:
    """Return the unique direct 5-unit legacy timer advance from callback."""
    from . import _controller_timer_advance_at, facts_for, struct
    if position < 0 or position + 0x40 > len(image):
        return None
    advances: list[int] = []
    for offset in range(position, position + 0x38, 2):
        if (struct.unpack_from("<3H", image, offset) != (0x3805, 0x6008, 0x2005)):
            continue
        advance = facts_for(image).thumb_call_target(offset + 6)
        if (advance is not None and struct.unpack_from("<H", image, offset + 10)[0] == 0x2105 and _controller_timer_advance_at(image, advance)):
            advances.append(advance)
    return advances[0] if len(advances) == 1 else None

def _c80_full_handler_span(image: bytes, handler: int, masks: int, wrapper: int, ram_base: int, ram_size: int) -> int | None:
    """Close known complete bodies before extending native PC ownership."""
    from . import _normalized_thumb_sha256, _ram_contains, facts_for, struct
    sd = _normalized_thumb_sha256(image, handler, 0x150) == ("b1b2c73d6bebf0bf1262d1258f2c1bf0787b25cfba27bfc9f24566fc9676f627", (4, 0x3E, 0x9E, 0xC2, 0xFE,
        0x116))
    compact = _normalized_thumb_sha256(image, handler, 0x100) == ("3f1f01622095fd32e398eb2feebe581a7fa27b5dc2274fa48791b7e36dc77f7f", (4, 0x34, 0x94, 0xB8, 0xF4))
    if not (sd or compact):
        return None
    size = 0x1B6 if sd else 0x188
    calls = ((4, 0x3E, 0x9E, 0xC2, 0xFE, 0x116, 0x164, 0x178, 0x17E, 0x190) if sd else (4, 0x34, 0x94, 0xB8, 0xF4, 0x10C, 0x14A, 0x150, 0x162))
    digest = ("9553279ed5fa0394656a19decfb07d0bcaf1921b82c97f3b5b49dab82ec8051a" if sd else "a07151a844355b265996fb4d3d3954052f38505481b84c6bcd2393c8163185c2")
    if _normalized_thumb_sha256(image, handler, size) != (digest, calls):
        return 0
    def target(delta: int) -> int | None:
        p = facts_for(image).thumb_call_target(handler + delta)
        return p if p is not None and 0 <= p <= len(image) - 2 else None
    def unwrap(p: int | None) -> int | None:
        if p is None or not 0 <= p <= len(image) - 2:
            return None
        if image[p:p + 12] == bytes.fromhex("7847c04600c09fe51cff2fe1"):
            if p & 3 or p + 16 > len(image):
                return None
            pointer = struct.unpack_from("<I", image, p + 12)[0]
            p = pointer & ~1 if pointer & 1 else -1
        return p if 0 <= p <= len(image) - 2 else None
    def body(p: int | None, expected: bytes) -> bool:
        return p is not None and p + len(expected) <= len(image) and image[p:p + len(expected)] == expected
    if any(target(d) is None for d in calls):
        return 0
    unlocked, locked = ((0x3E, 0x9E), (0x178, 0x190)) if sd else ((0x34, 0x94), (0x14A, 0x162))
    for offsets, instruction in ((unlocked, 0xE3C010C0), (locked, 0xE38010C0)):
        helper = unwrap(target(offsets[0]))
        if (helper is None or helper & 3 or target(offsets[0]) != target(offsets[1]) or not body(helper, bytes.fromhex("78470000") + struct.pack("<5I",
            0xE10F0000, instruction, 0xE121F001, 0xE20000C0, 0xE12FFF1E))):
            return 0
    fanout = (0xC2, 0xFE, 0x116) if sd else (0xB8, 0xF4, 0x10C)
    if len({target(d) for d in fanout}) != 1 or not body(unwrap(target(fanout[0])), b"\x00\x47"):
        return 0
    header = unwrap(target(4))
    if not body(header, bytes.fromhex("02480921c08cc90508717047")) or not _ram_contains(facts_for(image).thumb_literal_value(header, 0) or 0, 0x28, ram_base,
        ram_size):
        return 0
    if sd and not body(target(0x164), b"\x70\x47"):
        optional = target(0x164)
        if optional is None or _normalized_thumb_sha256(image, optional, 0x7C) != ("feaa334a720859ccfd0dc331ce590ba84be9bc96e3a795b2ef8ce943828b47c5", (0x36,
            0x76)):
            return 0
        state = facts_for(image).thumb_literal_value(optional, 1)
        callees = [facts_for(image).thumb_call_target(optional + d) for d in (0x36, 0x76)]
        # Close this callable body and bounded shared target, not its service semantics.
        if (state is None or state & 1 or not _ram_contains(state, 0x38, ram_base, ram_size) or callees[0] != callees[1] or any(callee is None or callee & 1 or
            not 0 <= callee <= len(image) - 2 for callee in callees)):
            return 0
    drain = target(0x17E if sd else 0x150)
    if (drain != handler - 0x2C or not body(drain, b"\x80\xb5") or not body(drain + 8, bytes.fromhex("071c0ad0f8683969ba68")) or not body(unwrap(facts_for(image).thumb_call_target(drain
        + 18)), b"\x10\x47") or not body(drain + 22, bytes.fromhex("00203871012080bc08bc1847")) or not _ram_contains(facts_for(image).thumb_literal_value(drain
        + 2, 0) or 0, 8, ram_base, ram_size)):
        return 0
    literals = ([(8,7,masks),(0x16,1,masks+12),(0x20,3,masks),(0x56,1,masks+0x374), (0x7A,2,masks),(0xAA,1,masks +12),(0x146,2,masks+0x380),(0x186,7,masks)] if
        sd else[(8,2,masks),(0x16,2,masks),(0x4C,1,masks+0x374), (0x70,2,masks),(0xA0,1,masks+12),(0x158,7,masks)])
    ports = ([(0x1C,7),(0x7E,7),(0xB0,3),(0xD4,1),(0xDA,3),(0xF8,1),(0x128,1),(0x19A,1)] if sd else[(0x12,7),(0x74,7),(0xA6,3),(0xCA,1),(0xD0,3),(0xEE,1),(0x11E,1),(0x16C,1)])
    if any(facts_for(image).thumb_literal_value(handler+d, r) != v for d,r,v in literals) or any(facts_for(image).thumb_literal_value(handler+d, r) !=
        0x03000C80 for d,r in ports):
        return 0
    depth = facts_for(image).thumb_literal_value(handler + (0x42 if sd else 0x38), 0)
    statistic = facts_for(image).thumb_literal_value(handler + (0x1A6 if sd else 0x178), 1)
    if (not _ram_contains(depth or 0, 2, ram_base, ram_size) or not _ram_contains(statistic or 0, 2, ram_base, ram_size) or not 0 <= wrapper <= len(image)-0x5C):
        return 0
    for delta, expected in ((0x14, "b010d0e1011081e2b010c0e1"), (0x50, "b010d0e1011051e2b010c0e1")):
        word = struct.unpack_from("<I", image, wrapper + delta - 4)[0]
        p = wrapper + delta + 4 + (word & 0xFFF)
        if (word & 0xFFFFF000 != 0xE59F0000 or p > len(image)-4 or struct.unpack_from("<I", image, p)[0] != depth or not body(wrapper+delta, bytes.fromhex(expected))):
            return 0
    if sd and not _ram_contains(facts_for(image).thumb_literal_value(handler+0x15A, 0) or 0, 0x20, ram_base, ram_size):
        return 0
    return size

def _ram_contains(address: int, size: int, base: int, length: int) -> bool:
    end = base + length
    return (0 <= base < end <= 0x100000000 and size > 0 and base <= address <= end - size)

def _legacy_620_vector_copy(image: bytes, *, ram_base: int, ram_size: int,) -> tuple[int, int, int, int] | None:
    """Return the unique copied vector source, target, size, and wrapper."""
    from . import _ram_contains, arm_b_word_target, struct
    if len(image) < 0x20:
        return None
    target = arm_b_word_target(struct.unpack_from("<I", image, 0x18)[0], 0x18)
    if target is None or not _ram_contains(target, 4, ram_base, ram_size):
        return None
    copies: list[tuple[int, int, int]] = []
    needle = struct.pack("<I", target)
    position = 0
    while (position := image.find(needle, position)) >= 0:
        offset = position - 4
        position += 1
        if offset < 0 or offset & 3 or offset + 16 > len(image):
            continue
        source, candidate, size, end = struct.unpack_from("<4I", image, offset)
        if (candidate == target and 0x100 <= size <= 0x200000 and end == target + size and source > offset + 0x20 and source + size <= len(image) and
            _ram_contains(candidate, size, ram_base, ram_size)):
            copies.append((source, target, size))
    if len(copies) != 1:
        return None
    source, target, size = copies[0]
    wrapper = arm_b_word_target(struct.unpack_from("<I", image, source)[0], target)
    return ((source, target, size, wrapper) if wrapper is not None and 0 <= wrapper <= len(image) - 4 else None)
