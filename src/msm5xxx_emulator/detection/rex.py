"""Firmware REX timer, IRQ, and idle detection."""
from __future__ import annotations

import hashlib
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
UIS_IDLE_ENTRY_PREFIX = bytes.fromhex("f0b5b4b009a92120")
UIS_IDLE_BODY_PREFIX = bytes.fromhex("9748974a40780026")
UIS_IDLE_BODY_DELTA = 0x15E
UIS_IDLE_COMPACT_ENTRY_PREFIX = bytes.fromhex("f0b5acb000200a90")
UIS_IDLE_COMPACT_BODY_PREFIX = bytes.fromhex("be48be4d40780021")
UIS_IDLE_COMPACT_BODY_DELTA = 0xFE
UIS_IDLE_DRAW_MARKER = (
    b"[Idle_IdleP_OnDraw]Draw Idle Image in Enter Refresh\0"
)
UIS_IDLE_DRAW_BODY_DELTAS = (0x8B8, 0x908)
UIS_IDLE_BODY_DELTAS = (
    UIS_IDLE_COMPACT_BODY_DELTA,
    UIS_IDLE_BODY_DELTA,
    *UIS_IDLE_DRAW_BODY_DELTAS,
)


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
    """Validate isolated C80/FB0 two-bank mask/dispatch shapes."""
    if status == 0x03000FB0:
        # Exact body; relocated calls are bounded and relevant ABIs closed below.
        if _normalized_thumb_sha256(image, position, 0x182) != (
            "a4a7b1ec46eb3f925c0c0ec155e143760ebdcfff7303475242d879917c9e6225",
            (0x30, 0x92, 0xB6, 0xEE, 0x106, 0x142, 0x148, 0x15A),
        ):
            return False
        literals = ((0, 2, masks), (0x12, 2, masks), (0x6C, 2, masks),
                    (0x150, 7, masks), (0x9E, 1, masks + 0x0C),
                    (0x48, 1, masks + 0x0C + 0x1B * 0x1C + 0x20))
        ports = ((0x0E, 1), (0x84, 1), (0xA4, 3), (0xC8, 1),
                 (0xCE, 3), (0xE8, 1), (0x118, 1), (0x164, 1))
        thunks = [thumb_bl_target(image, position + delta)
                  for delta in (0xB6, 0xEE, 0x106)]
        return (
            all(thumb_literal_value(image, position + delta, register) == value
                for delta, register, value in literals)
            and all(thumb_literal_value(image, position + delta, register)
                    == status - 0x10 for delta, register in ports)
            and len(set(thunks)) == 1 and thunks[0] is not None
            and 0 <= thunks[0] <= len(image) - 2
            and image[thunks[0]:thunks[0] + 2] == b"\x00\x47"
        )
    if position < 0 or position + 0x100 > len(image):
        return False
    words = struct.unpack_from("<33H", image, position)

    def literal(index: int, register: int, value: int) -> bool:
        return thumb_literal_value(image, position + index * 2, register) == value

    common = (
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
    )
    group10 = (
        words[:2] == (0xB5F0, 0xB087)
        and words[2] & 0xF800 == 0xF000
        and words[3] & 0xF800 == 0xF800
        and literal(4, 7, masks)
        and words[5:11] == (0x201B, 0x88F9, 0x0140, 0x9102, 0x8939, 0x9101)
        and literal(11, 1, masks + 0x0C)
        and words[12:14] == (0x1840, 0x9006)
        and literal(14, 7, status)
        and words[15] == 0x8838
        and literal(16, 3, masks)
        and words[17:30] == (
            0x881A, 0x9902, 0x4011, 0x4001, 0x9104, 0x88B8,
            0x885A, 0x9901, 0x4011, 0x4008, 0x9904, 0x9003,
            0x4308,
        )
        and words[30] & 0xFF00 == 0xD100
        and thumb_bl_target(image, position + 31 * 2) is not None
        and _normalized_thumb_sha256(image, position, 0x150) == (
            "b1b2c73d6bebf0bf1262d1258f2c1bf0787b25cfba27bfc9f24566fc9676f627",
            (0x04, 0x3E, 0x9E, 0xC2, 0xFE, 0x116),
        )
    )
    if not (common or group10):
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
        image: bytes, position: int, default: int, *, fb0: bool = False,
        group_base: bool = False,
) -> int | None:
    """Validate registration; preserve the historical special-slot default."""
    if fb0:
        if (_normalized_thumb_sha256(image, position, 0x80) != (
                "cdeb88a1799aec812a625e545d713c23322c8b8ae0e593621109b7d2c6532ee8",
                (0x06, 0x1C, 0x26, 0x76),
            ) or thumb_literal_value(image, position + 0x0E, 6) != default):
            return None
        table = thumb_literal_value(image, position + 0x2C, 1)
        if (table is None or thumb_literal_value(image, position + 0x36, 1)
                != table + 0x1B * 0x1C):
            return None
        return table
    if position < 0 or position + 0x44 > len(image):
        return None
    words = struct.unpack_from("<34H", image, position)
    direct_error = (
        words[14] & 0xF800 == 0xF000
        and words[15] & 0xF800 == 0xF800
    )
    shifted_error = (
        words[13] == 0xDB04
        and words[14:16] == (0x2045, 0x00C0)
        and words[16] & 0xF800 == 0x4800
        and words[16] >> 8 & 7 == 1
        and words[17] & 0xF800 == 0xF000
        and words[18] & 0xF800 == 0xF800
    )
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
        and (direct_error or shifted_error)
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
    return thumb_literal_value(image, position + (rows[0] + (1 if group_base else 6)) * 2, 1)


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


def _normalized_thumb_sha256(
        image: bytes, position: int, length: int,
) -> tuple[str, tuple[int, ...]] | None:
    """Hash one exact Thumb body while ignoring relocated BL immediates."""
    if position < 0 or position + length > len(image):
        return None
    normalized = bytearray(image[position:position + length])
    calls: list[int] = []
    for offset in range(0, length - 3, 2):
        if thumb_bl_target(image, position + offset) is None:
            continue
        calls.append(offset)
        normalized[offset:offset + 4] = b"\0" * 4
    return hashlib.sha256(normalized).hexdigest(), tuple(calls)


def _c80_full_handler_span(image: bytes, handler: int, masks: int,
                           wrapper: int, ram_base: int, ram_size: int) -> int | None:
    """Close known complete bodies before extending native PC ownership."""
    sd = _normalized_thumb_sha256(image, handler, 0x150) == (
        "b1b2c73d6bebf0bf1262d1258f2c1bf0787b25cfba27bfc9f24566fc9676f627",
        (4, 0x3E, 0x9E, 0xC2, 0xFE, 0x116))
    compact = _normalized_thumb_sha256(image, handler, 0x100) == (
        "3f1f01622095fd32e398eb2feebe581a7fa27b5dc2274fa48791b7e36dc77f7f",
        (4, 0x34, 0x94, 0xB8, 0xF4))
    if not (sd or compact):
        return None
    size = 0x1B6 if sd else 0x188
    calls = ((4, 0x3E, 0x9E, 0xC2, 0xFE, 0x116, 0x164, 0x178, 0x17E, 0x190)
             if sd else (4, 0x34, 0x94, 0xB8, 0xF4, 0x10C, 0x14A, 0x150, 0x162))
    digest = ("9553279ed5fa0394656a19decfb07d0bcaf1921b82c97f3b5b49dab82ec8051a"
              if sd else "a07151a844355b265996fb4d3d3954052f38505481b84c6bcd2393c8163185c2")
    if _normalized_thumb_sha256(image, handler, size) != (digest, calls):
        return 0

    def target(delta: int) -> int | None:
        p = thumb_bl_target(image, handler + delta)
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
        if (helper is None or helper & 3 or target(offsets[0]) != target(offsets[1])
                or not body(helper,
                bytes.fromhex("78470000") + struct.pack("<5I", 0xE10F0000, instruction, 0xE121F001, 0xE20000C0, 0xE12FFF1E))):
            return 0
    fanout = (0xC2, 0xFE, 0x116) if sd else (0xB8, 0xF4, 0x10C)
    if len({target(d) for d in fanout}) != 1 or not body(unwrap(target(fanout[0])), b"\x00\x47"):
        return 0
    header = unwrap(target(4))
    if not body(header, bytes.fromhex("02480921c08cc90508717047")) or not _ram_contains(
            thumb_literal_value(image, header, 0) or 0, 0x28, ram_base, ram_size):
        return 0
    if sd and not body(target(0x164), b"\x70\x47"):
        optional = target(0x164)
        if optional is None or _normalized_thumb_sha256(image, optional, 0x7C) != (
                "feaa334a720859ccfd0dc331ce590ba84be9bc96e3a795b2ef8ce943828b47c5",
                (0x36, 0x76)):
            return 0
        state = thumb_literal_value(image, optional, 1)
        callees = [thumb_bl_target(image, optional + d) for d in (0x36, 0x76)]
        # Close this callable body and bounded shared target, not its service semantics.
        if (state is None or state & 1 or not _ram_contains(state, 0x38, ram_base, ram_size)
                or callees[0] != callees[1] or any(
                    callee is None or callee & 1 or not 0 <= callee <= len(image) - 2
                    for callee in callees)):
            return 0
    drain = target(0x17E if sd else 0x150)
    if (drain != handler - 0x2C or not body(drain, b"\x80\xb5")
            or not body(drain + 8, bytes.fromhex("071c0ad0f8683969ba68"))
            or not body(unwrap(thumb_bl_target(image, drain + 18)), b"\x10\x47")
            or not body(drain + 22, bytes.fromhex("00203871012080bc08bc1847"))
            or not _ram_contains(thumb_literal_value(image, drain + 2, 0) or 0, 8, ram_base, ram_size)):
        return 0
    literals = ([(8,7,masks),(0x16,1,masks+12),(0x20,3,masks),(0x56,1,masks+0x374),
                 (0x7A,2,masks),(0xAA,1,masks+12),(0x146,2,masks+0x380),(0x186,7,masks)]
                if sd else [(8,2,masks),(0x16,2,masks),(0x4C,1,masks+0x374),
                            (0x70,2,masks),(0xA0,1,masks+12),(0x158,7,masks)])
    ports = ([(0x1C,7),(0x7E,7),(0xB0,3),(0xD4,1),(0xDA,3),(0xF8,1),(0x128,1),(0x19A,1)]
             if sd else [(0x12,7),(0x74,7),(0xA6,3),(0xCA,1),(0xD0,3),(0xEE,1),(0x11E,1),(0x16C,1)])
    if any(thumb_literal_value(image, handler+d, r) != v for d,r,v in literals) or any(
            thumb_literal_value(image, handler+d, r) != 0x03000C80 for d,r in ports):
        return 0
    depth = thumb_literal_value(image, handler + (0x42 if sd else 0x38), 0)
    statistic = thumb_literal_value(image, handler + (0x1A6 if sd else 0x178), 1)
    if (not _ram_contains(depth or 0, 2, ram_base, ram_size)
            or not _ram_contains(statistic or 0, 2, ram_base, ram_size)
            or not 0 <= wrapper <= len(image)-0x5C):
        return 0
    for delta, expected in ((0x14, "b010d0e1011081e2b010c0e1"), (0x50, "b010d0e1011051e2b010c0e1")):
        word = struct.unpack_from("<I", image, wrapper + delta - 4)[0]
        p = wrapper + delta + 4 + (word & 0xFFF)
        if (word & 0xFFFFF000 != 0xE59F0000 or p > len(image)-4
                or struct.unpack_from("<I", image, p)[0] != depth
                or not body(wrapper+delta, bytes.fromhex(expected))):
            return 0
    if sd and not _ram_contains(thumb_literal_value(image, handler+0x15A, 0) or 0, 0x20, ram_base, ram_size):
        return 0
    return size


def _ram_contains(address: int, size: int, base: int, length: int) -> bool:
    end = base + length
    return (0 <= base < end <= 0x100000000 and size > 0
            and base <= address <= end - size)


def _legacy_620_vector_copy(
        image: bytes, *, ram_base: int, ram_size: int,
) -> tuple[int, int, int, int] | None:
    """Return the unique copied vector source, target, size, and wrapper."""
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
        if (candidate == target and 0x100 <= size <= 0x200000
                and end == target + size and source > offset + 0x20
                and source + size <= len(image)
                and _ram_contains(candidate, size, ram_base, ram_size)):
            copies.append((source, target, size))
    if len(copies) != 1:
        return None
    source, target, size = copies[0]
    wrapper = arm_b_word_target(struct.unpack_from("<I", image, source)[0],
                                target)
    return ((source, target, size, wrapper) if wrapper is not None
            and 0 <= wrapper <= len(image) - 4 else None)


def _find_rex_620_static_controller_callback_candidate(
        image: bytes, *, ram_base: int, ram_size: int,
) -> dict[str, object] | None:
    """Close the early 0x620 two-bank route as telemetry-only evidence."""
    prefix = struct.pack("<3I", 0x03000620, 0x03000628, 0x0200)
    seeds: list[tuple[int, tuple[int, ...]]] = []
    offset = 0
    while (offset := image.find(prefix, offset)) >= 0:
        if offset + 28 <= len(image):
            seed = struct.unpack_from("<7I", image, offset)
            if (_ram_contains(seed[3], 4, ram_base, ram_size)
                    and seed[4] == seed[3] + 4
                    and seed[5] & 1 and (seed[5] & ~1) < len(image)
                    and seed[6] == 0):
                seeds.append((offset, seed))
        offset += 1
    if not seeds:
        return None

    semantic_limit = (
        "static topology only; native pending read-consume cadence and idle "
        "remain unproven"
    )

    def rejected(reason: str) -> dict[str, object]:
        return {
            "signature": "static-msm5000-620-controller-callback-v1",
            "accepted": False,
            "active": False,
            "promotion": "experimental-only",
            "semantic_limit": semantic_limit,
            "reject_reason": reason,
        }

    vector_copy = _legacy_620_vector_copy(
        image, ram_base=ram_base, ram_size=ram_size
    )
    if vector_copy is None:
        return rejected("copied-vector-route-not-closed")
    vector_source, vector_target, vector_size, copied_wrapper = vector_copy
    if len(seeds) != 1:
        return rejected("descriptor-seed-ambiguous")
    descriptor_file_offset, seed = seeds[0]
    if not (vector_source <= descriptor_file_offset
            and descriptor_file_offset + 0x1C
            <= vector_source + vector_size):
        return rejected("descriptor-outside-vector-copy")
    descriptor_runtime = (
        vector_target + descriptor_file_offset - vector_source
    )
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
    w1c_stride = {
        "02d8707640c6924c3eeec04593f88735bef9fdaa0492d998d84e4dd38d40093d": 10,
        "532cb58afa8601af64bd4617afc6a1b117192629555c8c734eddd29bb2cff230": 12,
    }.get(w1c_shape[0]) if w1c_shape is not None and w1c_shape[1] == (
        0x30, 0x90, 0xB6, 0xE0, 0x11C, 0x122, 0x134) else None
    if profile is None and w1c_stride is not None:
        handler_size = 0x15A
        profile = (
            f"legacy-msm5000-620-two-bank-w1c-group{w1c_stride}-v1", w1c_stride,
            0x70,
            ("ed69c76589103931751b1e00818205148bf4438831add7bd61dbb82fa787eb37",
             (0x06, 0x20, 0x66)),
            0x26, "latched-read", "temporary-evidence-gated",
        )
        calls = {offset: thumb_bl_target(image, handler + offset)
                 for offset in (0x30, 0x90, 0xB6, 0xE0, 0x11C, 0x122, 0x134)}
        trampoline = calls[0xB6]
        if (any(p is None or p & 1 or not 0 <= p <= len(image) - 2
                for p in calls.values())
                or image[trampoline:trampoline + 2] != b"\x00\x47"
                or calls[0xE0] != trampoline
                or calls[0x30] != calls[0x90]
                or calls[0x11C] != calls[0x134]):
            return rejected("two-bank-w1c-call-route-not-closed")
        for offset, instruction in ((0x30, 0xE3C010C0), (0x11C, 0xE38010C0)):
            helper = calls[offset]
            # Interworking helpers either tag LR explicitly or return directly
            # with BX LR; both preserve the caller's Thumb return state.
            bodies = [bytes.fromhex("78470000") + struct.pack(
                "<" + "I" * len(words), *words) for words in (
                    (0xE38EE001, 0xE10F0000, instruction,
                     0xE121F001, 0xE20000C0, 0xE12FFF1E),
                    (0xE10F0000, instruction, 0xE121F001,
                     0xE20000C0, 0xE12FFF1E))]
            if helper & 3 or not any(
                    image[helper:helper + len(expected)] == expected
                    for expected in bodies):
                return rejected("two-bank-w1c-irq-lock-not-closed")
        if any(not _ram_contains(
                thumb_literal_value(image, handler + offset, register) or 0,
                2, ram_base, ram_size)
               for offset, register in ((0x34, 0), (0x14A, 1))):
            return rejected("two-bank-w1c-state-outside-ram")
    if profile is None:
        return rejected("two-bank-read-consume-handler-not-closed")
    (controller_class, group_row_size, registrar_size,
     registrar_expected, table_at, pending_read_semantics,
     promotion) = profile
    if pending_read_semantics == "latched-read":
        semantic_limit = (
            "two-peer clear/write route with a 5-unit service callback; "
            "physical tick source remains approximated"
        )
        if handler_size == 0x15A:
            semantic_limit = (
                "closed callback-then-W1C route with a 5-unit service callback; "
                "physical tick source remains approximated; idle unproven"
            )
        literal_checks = (
            (0x00, 2, masks), (0x0E, 7, status), (0x12, 2, masks),
            (0x48, 1, descriptor_runtime + 0x1C),
            (0x6C, 2, masks), (0x70, 7, status), (0x9C, 1, masks),
            (0xA4, 3, status), (0xC8, 1, status), (0xCE, 3, status),
            (0xF2, 1, status), (0x12A, 7, masks), (0x13E, 1, status),
        )
    else:
        if promotion == "temporary-evidence-gated":
            semantic_limit = (
                "ordered status-read, callback, return, and next-tick cadence "
                "closed for this exact handler class; handset idle remains "
                "unproven"
            )
        literal_checks = (
            (0x00, 2, masks), (0x0E, 7, status), (0x12, 2, masks),
            (0x6C, 2, masks), (0x70, 7, status), (0x9C, 1, masks),
            (0xA4, 3, status), (0xBA, 1, status), (0xCA, 1, status),
            (0xE6, 1, status), (0xEC, 3, status), (0x110, 1, status),
            (0x148, 7, masks), (0x15C, 1, status),
        )
    if any(thumb_literal_value(image, handler + relative, register) != value
           for relative, register, value in literal_checks):
        return rejected("two-bank-read-consume-literals-not-closed")

    if handler_size == 0x15A:
        # The dispatcher walks three groups of the proven stride. Source 28 must be
        # reachable in the bank-0 timer group, with no competing membership.
        groups_at = descriptor_file_offset + 0x1C
        if groups_at + 3 * group_row_size > vector_source + vector_size:
            return rejected("two-bank-w1c-groups-outside-vector-copy")
        groups = [struct.unpack_from("<4H2B", image, groups_at + row * group_row_size)
                  for row in range(3)]
        if (groups[2] != (mask, 0, mask, 0, 0x1C, 0x1C)
                or any(group[0] & mask or not 0 <= group[4] <= group[5] < 0x1C
                       for group in groups[:2])):
            return rejected("two-bank-w1c-timer-group-not-closed")

    ticks: list[tuple[int, int, int, int]] = []
    for match in REX_5MS_ARM_PATTERN.finditer(image):
        arm = match.start()
        callback_pointer = thumb_literal_value(image, arm + 6, 1)
        registrar = thumb_bl_target(image, arm + 10)
        if (arm & 1 or callback_pointer is None or not callback_pointer & 1
                or registrar is None
                or thumb_literal_value(image, arm, 1) != 0x030006E0
                or struct.unpack_from("<2H", image, arm + 2)
                != (0x2002, 0x7008)
                or struct.unpack_from("<H", image, arm + 8)[0] != 0x201C):
            continue
        callback = callback_pointer & ~1
        advance = _controller_callback_advance(image, callback)
        registrations = _rex_5ms_registration_targets(image, callback)
        registrar_shape = _normalized_thumb_sha256(
            image, registrar, registrar_size
        )
        table = thumb_literal_value(image, registrar + table_at, 1)
        if (advance is not None
                and len(registrations) == 3
                and set(registrations) == {registrar}
                and registrar_shape == registrar_expected
                and thumb_literal_value(image, registrar + 0x0E, 6) == default
                and isinstance(table, int)
                and _ram_contains(table, 4, ram_base, ram_size)):
            ticks.append((callback, advance, registrar, table))
    if len(ticks) != 1:
        return rejected("row1c-callback-route-not-unique")
    callback, advance, registrar, table = ticks[0]
    if table != masks + 8:
        return rejected("descriptor-table-mask-relation-mismatch")
    callback_slot = table + 0x1C * 0x1C + 0x14
    if descriptor_runtime != callback_slot - 0x14:
        return rejected("descriptor-runtime-row-relation-mismatch")
    if thumb_literal_value(image, handler + 0x48, 1) != callback_slot + 8:
        return rejected("handler-callback-table-not-closed")

    wrapper_prefix = struct.pack(
        "<4I", 0xE24EE004, 0xE92D540F, 0xE14F0000, 0xE92D0001
    )
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
    if copied_wrapper != wrapper:
        return rejected("copied-vector-wrapper-mismatch")
    if not _ram_contains(handler_slot, 8, ram_base, ram_size):
        return rejected("handler-slot-outside-ram")
    if not _ram_contains(callback_slot, 4, ram_base, ram_size):
        return rejected("row1c-callback-slot-invalid")

    return {
        "signature": "static-msm5000-620-controller-callback-v1",
        "controller_class": controller_class,
        "accepted": True,
        "active": False,
        "promotion": promotion,
        "semantic_limit": semantic_limit,
        "vector": 0x18,
        "vector_target": vector_target,
        "vector_copy_source": vector_source,
        "vector_copy_size": vector_size,
        "status": status,
        "enable": enable,
        "mask": mask,
        "status_banks": (status, status + 4),
        **({"clear_banks": (status, status + 4),
            "pending_ack_semantics": "write-one-to-clear"}
           if pending_read_semantics == "latched-read" else
           {"mask_set_banks": (status, status + 4)}),
        "mask_output_banks": (enable, enable + 4),
        "controller_aperture": (status, enable + 8),
        "status_bank_count": 2,
        "group_row_size": group_row_size,
        "pending_read_semantics": pending_read_semantics,
        "descriptor_file_offset": descriptor_file_offset,
        "descriptor_runtime_address": descriptor_runtime,
        "mask_table": masks,
        "handler_file_offset": handler,
        "handler_validation_size": handler_size,
        "registrar_file_offset": registrar,
        "callback_file_offset": callback,
        "callback_validation_size": REX_LEGACY_5MS_CALLBACK_SIZE,
        "callback_validation_shape":
            rex_legacy_5ms_callback_shape_at(image, callback),
        "callback_delta": 5,
        "timer_advance_file_offset": advance,
        "wrapper_file_offset": wrapper,
        "wrapper_validation_size": wrapper_size,
        "handler_slot": handler_slot,
        "callback_slot": callback_slot,
        "time_tick_control_address": 0x030006E0,
    }


def find_rex_static_controller_callback_candidate(
        image: bytes, *, ram_base: int, ram_size: int,
) -> dict[str, object] | None:
    """Return a telemetry-only old-controller callback topology, if closed.

    This proves only static descriptor, handler, registrar, and timer-list
    topology.  It deliberately does not claim a pending-bit source, inject an
    IRQ, or promote a handset phase.
    """
    if len(image) < 0x100:
        return None
    seeds: list[tuple[int, tuple[int, ...]]] = []
    for status, enable in ((0x03000C80, 0x03000C94),
                           (0x03000FB0, 0x03000FC4)):
        prefix = struct.pack("<3I", status, enable, 0x200)
        offset = 0
        while (offset := image.find(prefix, offset)) >= 0:
            if offset + 28 <= len(image):
                seed = struct.unpack_from("<7I", image, offset)
                if (seed[4] == seed[3] + 6
                        and _ram_contains(seed[3], 4, ram_base, ram_size)
                        and seed[5] & 1 and (seed[5] & ~1) < len(image)
                        and seed[6] == 0):
                    seeds.append((offset, seed))
            offset += 1
    if not seeds:
        return _find_rex_620_static_controller_callback_candidate(
            image, ram_base=ram_base, ram_size=ram_size
        )

    fb0 = seeds[0][1][0] == 0x03000FB0
    index = 0x1B if fb0 else 0x1E
    control = 0x030006E0 if fb0 else 0x030007A0
    signature = ("static-fb0-controller-callback-v1" if fb0 else
                 "static-c80-controller-callback-v1")
    semantic_limit = (
        "static topology only; native pending, IRQ, and idle remain unproven"
    )

    def rejected(reason: str) -> dict[str, object]:
        return {
            "signature": signature,
            "accepted": False,
            "active": False,
            "semantic_limit": semantic_limit,
            "reject_reason": reason,
        }

    vector_target = arm_b_word_target(
        struct.unpack_from("<I", image, 0x18)[0], 0x18
    )
    vector_copy = _legacy_620_vector_copy(
        image, ram_base=ram_base, ram_size=ram_size
    )
    if (vector_target is None
            or not _ram_contains(vector_target, 4, ram_base, ram_size)):
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
    handler_validation_size = (
        0x182 if fb0 else
        0x150 if struct.unpack_from("<H", image, handler + 2)[0] == 0xB087
        else 0x100
    )
    group_row_size = (
        10 if fb0 or handler_validation_size == 0x150 else
        12 if _normalized_thumb_sha256(image, handler, 0x100) == (
            "e2d286a40ba316e36638235247203ba5ab1800c3f1b50149a9a36be770d40f17",
            (0x04, 0x34, 0x94, 0xBA, 0xF6),
        ) else None
    )

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
        if (struct.unpack_from("<H", image, registration)[0] != (0x2000 | index)
                or thumb_literal_value(image, registration - 2, 1) is None
                or thumb_literal_value(image, registration - 8, 1) != control
                or struct.unpack_from("<2H", image, registration - 6)
                != (0x2002, 0x7008)):
            continue
        callback_pointer = thumb_literal_value(image, registration - 2, 1)
        registrar = thumb_bl_target(image, registration + 2)
        if (callback_pointer is None or not callback_pointer & 1
                or registrar is None):
            continue
        callback = callback_pointer & ~1
        table = _controller_registrar_at(image, registrar, default, fb0=fb0)
        advance = _controller_callback_advance(image, callback)
        if (table is not None
                and _ram_contains(table, 4, ram_base, ram_size)
                and advance is not None):
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
        calls = [(handler, (0x30, 0x92, 0xB6, 0xEE, 0x106, 0x142, 0x148, 0x15A)),
                 (registrar, (0x06, 0x1C, 0x26, 0x76))]
        if any(target is None or not 0 <= target <= len(image) - 2
               for body, offsets in calls for delta in offsets
               for target in (thumb_bl_target(image, body + delta),)):
            return rejected("fb0-call-target-outside-image")
        mask_helper = thumb_bl_target(image, registrar + 0x06)
        restore_helper = thumb_bl_target(image, registrar + 0x76)
        # Thumb BX PC enters ARM; preserve the exact CPSR I/F mask return ABI.
        for target, instruction in ((mask_helper, 0xE38010C0),
                                    (restore_helper, 0xE3C010C0)):
            expected = b"\x78\x47\x00\x00" + struct.pack(
                "<5I", 0xE10F0000, instruction, 0xE121F001,
                0xE20000C0, 0xE12FFF1E,
            )
            if target & 3 or image[target:target + len(expected)] != expected:
                return rejected("fb0-mask-restore-abi-not-closed")
        diagnostic = thumb_bl_target(image, handler + 0x148)
        # Close only this callable body and its callee bounds, not nested queue
        # or diagnostic semantics. Registrar error calls likewise have bounds only.
        if (_normalized_thumb_sha256(image, diagnostic, 0x26) != (
                "1f121709790fffac7e869f0e87027b3541ff08d8ac602ff7bd155e06b07b05b4",
                (0x04, 0x12),
            ) or any(target is None or not 0 <= target <= len(image) - 2
                     for delta in (0x04, 0x12)
                     for target in (thumb_bl_target(image, diagnostic + delta),))):
            return rejected("fb0-diagnostic-body-not-closed")
        row = table + index * 0x1C
        if (table != masks + 0x0C
                or not _ram_contains(masks, 12, destination, size)
                or not _ram_contains(row, 28, destination, size)
                or source + row - destination != descriptor_file_offset
                or thumb_bl_target(image, registrar + 0x06)
                != thumb_bl_target(image, handler + 0x142)
                or thumb_bl_target(image, registrar + 0x06)
                != thumb_bl_target(image, handler + 0x15A)
                or thumb_bl_target(image, registrar + 0x76)
                != thumb_bl_target(image, handler + 0x30)
                or thumb_bl_target(image, registrar + 0x76)
                != thumb_bl_target(image, handler + 0x92)):
            return rejected("copied-descriptor-relations-not-closed")
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
    if vector_copy is not None and vector_copy[3] != wrapper:
        return rejected("copied-vector-wrapper-mismatch")
    if not _ram_contains(handler_slot, 8, ram_base, ram_size):
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
    callback_slot = (table if fb0 else masks + 0x0C) + index * 0x1C + 0x14
    if not _ram_contains(callback_slot, 4, ram_base, ram_size):
        return rejected(f"row{index:02x}-callback-slot-invalid")
    callback_shape = rex_legacy_5ms_callback_shape_at(image, callback)
    if callback_shape is None:
        return rejected("legacy-callback-validator-not-closed")
    if not fb0:
        full_span = _c80_full_handler_span(image, handler, masks, wrapper,
                                          ram_base, ram_size)
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
            if (_controller_registrar_at(image, registrar, default, group_base=True) == masks + 12
                    and _ram_contains(masks, 12, destination, size)
                    and _ram_contains(row, 28, destination, size)
                    and _ram_contains(group, 40, destination, size)
                    and source + row - destination == descriptor_file_offset
                    and 0 <= group_rom <= len(image) - 40
                    and image[handler + 0x48:handler + 0x4C]
                    == bytes.fromhex("05980a23")
                    and image[handler + 0x4E:handler + 0x54]
                    == bytes.fromhex("584340180090")
                    and image[group_rom + 30:group_rom + 40]
                    == struct.pack("<4H2B", mask, 0, mask, 4, index, index)):
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


def _find_rex_direct_c40_controller_observation(
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


def _copied_c40_handler_slots(image: bytes, wrapper: int) -> tuple[int, ...]:
    """Return adjacent RAM slots dereferenced by one ARM IRQ wrapper."""
    found: set[int] = set()
    for pc in range(wrapper, min(len(image) - 4, wrapper + 0x300), 4):
        word = struct.unpack_from("<I", image, pc)[0]
        if (word >> 28 != 0xE or word & 0x0E5F0000 != 0x041F0000
                or not word & 1 << 20 or word & (1 << 22 | 1 << 21)):
            continue
        register = word >> 12 & 15
        literal = pc + 8 + ((word & 0xFFF) if word & 1 << 23
                            else -(word & 0xFFF))
        if not 0 <= literal <= len(image) - 4:
            continue
        slot = struct.unpack_from("<I", image, literal)[0]
        if not 0x01000000 <= slot < 0x01800000:
            continue
        dereference = branch = False
        for at in range(pc + 4, min(len(image) - 4, pc + 0x30), 4):
            instruction = struct.unpack_from("<I", image, at)[0]
            dereference |= ((instruction & 0x0FFF0FFF)
                            == (0x05900000 | register << 16))
            if (instruction & 0x0FFFFFF0 == 0x012FFF10
                    and instruction & 15 == register):
                branch = True
                break
        if dereference and branch:
            found.add(slot)
    slots = tuple(sorted(found))
    return slots if len(slots) == 2 and slots[1] == slots[0] + 4 else ()


def _copied_c40_delta5_callback_at(image: bytes, position: int) -> bool:
    """Validate shared five-unit callback semantics without fixing layout."""
    if position < 0 or position + 0x80 > len(image):
        return False
    words = struct.unpack_from("<64H", image, position)
    return (
        words[0] & 0xFF00 == 0xB500
        and words.count(0x2105) >= 2
        and 0x2005 in words
        and any(words[index:index + 2] == (0x3905, 0x6001)
                for index in range(len(words) - 1))
    )


def _copied_c40_time_tick_registrations(
        image: bytes,
) -> list[tuple[int, int, int, int, int]]:
    """Return arm, callback, registrar, callback base, selector-0 slot."""
    found: list[tuple[int, int, int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\x02\x20\x08\x70", offset)) >= 0:
        arm = offset - 2
        offset += 1
        if (arm < 0 or arm & 1 or arm + 14 > len(image)
                or thumb_literal_value(image, arm, 1) != 0x030006E0
                or struct.unpack_from("<H", image, arm + 6)[0] & 0xFF00
                   != 0x4900
                or struct.unpack_from("<H", image, arm + 8)[0] != 0x2000):
            continue
        callback_pointer = thumb_literal_value(image, arm + 6, 1)
        registrar = thumb_bl_target(image, arm + 10)
        if (callback_pointer is None or not callback_pointer & 1
                or registrar is None or registrar + 0x48 > len(image)):
            continue
        callback = callback_pointer & ~1
        words = struct.unpack_from("<10H", image, registrar)
        if (words[:3] != (0xB5F0, 0x1C05, 0x1C0F)
                or words[5] != 0x1C04
                or words[6] & 0xF800 != 0x4800
                or words[6] >> 8 & 7 != 6
                or words[7:10] != (0x2F00, 0xD100, 0x1C37)
                or struct.unpack_from("<H", image, registrar + 0x46)[0]
                   != 0x664F):
            continue
        callback_base = thumb_literal_value(image, registrar + 0x14, 0)
        if (callback_base is None
                or not 0x01000018 <= callback_base < 0x01800000
                or not _copied_c40_delta5_callback_at(image, callback)):
            continue
        found.append((arm, callback, registrar, callback_base,
                      callback_base - 0x18))
    return found


def _find_rex_copied_c40_controller_observation(
        image: bytes,
) -> dict[str, object] | None:
    """Close copied-vector C40 topology while keeping runtime disabled."""
    if (len(image) < 0x100
            or arm_b_word_target(struct.unpack_from("<I", image, 0x18)[0], 0x18)
            != 0x01000000):
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

    limit = ("static copied-vector topology only; native pending, cadence, "
             "repeat IRQ, and idle remain unproven")

    def rejected(reason: str, **details: object) -> dict[str, object]:
        return {
            "signature": "static-c40-copied-vector-selector0-v1",
            "accepted": False, "active": False, "promotion": "telemetry-only",
            "semantic_limit": limit, "reject_reason": reason, **details,
        }

    if len(descriptors) != 1:
        return rejected("c40-descriptor-not-unique",
                        descriptor_count=len(descriptors))
    descriptor, shadow = descriptors[0]
    copies: list[tuple[int, int]] = []
    for at in range(0, min(len(image) - 16, 0x20000) + 1, 4):
        source, target, size, bss = struct.unpack_from("<4I", image, at)
        if (target == 0x01000000 and 0x100 <= size <= 0x200000
                and bss == target + size and source > at + 0x20
                and source + size <= len(image)):
            copies.append((source, size))
    if len(copies) != 1:
        return rejected("copied-vector-source-not-unique",
                        copy_count=len(copies))
    source, copy_size = copies[0]
    if not source <= descriptor < source + copy_size:
        return rejected("descriptor-outside-vector-copy")
    descriptor_runtime = 0x01000000 + descriptor - source
    if descriptor_runtime != shadow + 8:
        return rejected("descriptor-shadow-relation-mismatch",
                        descriptor_runtime=descriptor_runtime, mask_shadow=shadow)
    wrapper = arm_b_word_target(
        struct.unpack_from("<I", image, source)[0], 0x01000000
    )
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
            if (handler & 1 and handler < len(image)
                    and image[handler & ~1:(handler & ~1) + 2] == b"\xF0\xB5"):
                handler_tables.append((offset, handler & ~1))
        offset += 1
    if len(handler_tables) != 1:
        return rejected("c40-handler-table-not-unique",
                        handler_table_count=len(handler_tables))
    registrations = _copied_c40_time_tick_registrations(image)
    if len(registrations) != 1:
        return rejected("selector0-time-tick-registration-not-unique",
                        registration_count=len(registrations))
    arm, callback, registrar, callback_base, callback_slot = registrations[0]
    return {
        "signature": "static-c40-copied-vector-selector0-v1",
        "accepted": True, "active": False, "promotion": "telemetry-only",
        "semantic_limit": limit,
        "controller_class": "c40-copied-vector-selector0-delta5-v1",
        "descriptor_file_offset": descriptor,
        "descriptor_runtime_address": descriptor_runtime,
        "mask_shadow": shadow,
        "status_banks": (status, status + 4),
        "enable_banks": (enable, enable + 4),
        "mask": mask, "selector": 0,
        "vector": 0x18, "vector_target": 0x01000000,
        "vector_copy_source": source, "vector_copy_size": copy_size,
        "wrapper_file_offset": wrapper, "handler_slot": slots[0],
        "handler_file_offset": handler_tables[0][1],
        "handler_table_file_offset": handler_tables[0][0],
        "callback_base": callback_base, "callback_slot": callback_slot,
        "callback_file_offset": callback,
        "registrar_file_offset": registrar,
        "time_tick_control_file_offset": arm,
        "time_tick_control_address": 0x030006E0,
        "time_tick_arm_value": 2, "time_tick_period_ms": 5,
    }


def find_rex_static_c40_controller_observation(
        image: bytes,
) -> dict[str, object] | None:
    """Return direct or copied-vector C40 telemetry, failing closed."""
    direct = _find_rex_direct_c40_controller_observation(image)
    if (direct is None or direct.get("accepted")
            or direct.get("reject_reason") != "runtime-vector-target-mismatch"):
        return direct
    copied = _find_rex_copied_c40_controller_observation(image)
    return copied if copied is not None else direct


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


def _relocated_thumb_file_target(
        image: bytes, callsite: int, file_to_runtime, runtime_to_file,
) -> int | None:
    """Map one PC-relative Thumb BL target through executable copies."""
    raw_target = thumb_bl_target(image, callsite)
    caller = file_to_runtime(callsite)
    if (not isinstance(raw_target, int) or not isinstance(caller, int)
            or not 0 <= caller <= 0xFFFFFFFF):
        return None
    address = caller + raw_target - callsite
    if not 0 <= address <= 0xFFFFFFFF:
        return None
    target = runtime_to_file(address)
    return (target if isinstance(target, int) and 0 <= target < len(image)
            and file_to_runtime(target) == address else None)


def find_rex_legacy_5ms_irq_route(
        image: bytes, bridge: dict[str, object],
        file_to_runtime=lambda position: position,
        runtime_to_file=lambda address: address,
        *, allow_b590_registrar: bool = False,
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
    b590_registrar = (
        allow_b590_registrar and index == 0x2B
        and words[:3] == (0xB590, 0x1C04, 0x1C0F)
        and words[5:47] == (
            0x4917, 0x2F00, 0xD100, 0x1C0F, 0x221C, 0x4B15,
            0x4362, 0x18D2, 0x2C00, 0xD102, 0x4B14, 0x621F,
            0xE000, 0x6157, 0x428F, 0xD104, 0x68D1, 0x880B,
            0x8917, 0x43BB, 0xE00A, 0x68D1, 0x880B, 0x8911,
            0x400B, 0xD106, 0x6813, 0x8019, 0x68D1, 0x880B,
            0x8917, 0x433B, 0x800B, 0x68D1, 0x6913, 0x8809,
            0x881B, 0x6852, 0x4019, 0x8011, 0x2800, 0xD101,
        )
        and words[49:52] == (0xBC90, 0xBC08, 0x4718)
        and all(
            words[call] & 0xF800 == 0xF000
            and words[call + 1] & 0xF800 == 0xF800
            and thumb_bl_target(image, registrar + call * 2) is not None
            for call in (3, 47)
        )
    )
    global_slot = None
    if b590_registrar:
        descriptor_base = thumb_literal_value(image, registrar + 20, 3)
        default_callback = thumb_literal_value(image, registrar + 10, 1)
        global_slot = thumb_literal_value(image, registrar + 30, 3)
    else:
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
        descriptor_base = thumb_literal_value(
            image, registrar + layouts[0][1], 1
        )
        default_callback = thumb_literal_value(image, registrar + 14, 6)
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
    if (table_seed_base < 0
            or seed[3:5] != (
                descriptor_base - group_offsets[0],
                descriptor_base - group_offsets[1],
            )
            or default_callback != seed[5]
            or (b590_registrar and global_slot != seed[4] + 0x4B8)):
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
        if index == 0x1E else ((0x214, 0xB08A), (0x1E6, 0xB089))
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
                          and (target := _relocated_thumb_file_target(
                              image, site + 2, file_to_runtime,
                              runtime_to_file)) is not None
                          and target <= len(image) - 16
                          and image[target:target + 2] in (b"\x00\x47", b"\x78\x47")]
        if not callback_sites:
            continue
        if not (_relocated_thumb_file_target(
                    image, loop, file_to_runtime, runtime_to_file) == drain
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


def find_rex_static_overlay_controller_callback_candidate(
        image: bytes, file_to_runtime, runtime_to_file, *,
        ram_base: int, ram_size: int,
) -> dict[str, object] | None:
    """Close a copied C80 callback route without an input descriptor."""
    if struct.pack("<3I", 0x03000C80, 0x03000C94, 0x0200) not in image:
        return None

    def mapped(position: int) -> bool:
        address = file_to_runtime(position)
        return (isinstance(address, int)
                and runtime_to_file(address) == position)

    outers: list[int] = []
    for prefix in (b"\x80\xb5", b"\x90\xb5"):
        position = 0
        while (position := image.find(prefix, position)) >= 0:
            if (rex_legacy_5ms_callback_at(image, position) is not None
                    and mapped(position)):
                outers.append(position)
            position += 2
    drains: list[int] = []
    position = 0
    while (position := image.find(b"\x80\xb5", position)) >= 0:
        if (rex_timer_callback_drain_at(image, position) is not None
                and mapped(position)):
            drains.append(position)
        position += 2
    if len(outers) != 1 or len(drains) != 1:
        return None
    drain = drains[0]
    loops = [site for match in THUMB_BL_PATTERN.finditer(image)
             if not (site := match.start()) & 1
             and site + 8 <= len(image)
             and _relocated_thumb_file_target(
                 image, site, file_to_runtime, runtime_to_file) == drain
             and struct.unpack_from("<2H", image, site + 4)
             == (0x2800, 0xD1FB)]
    if len(loops) != 1:
        return None
    bridge = {
        "outer_callback_file_offset": outers[0],
        "drain_file_offset": drain,
        "drain_loop_caller_file_offset": loops[0],
    }
    route = find_rex_legacy_5ms_irq_route(
        image, bridge, file_to_runtime, runtime_to_file,
        allow_b590_registrar=True,
    )
    semantic_limit = (
        "first-bank 5 ms TIME_TICK delivery only; other controller banks and "
        "handset idle remain unproven"
    )
    if route is None:
        return {
            "signature": "static-c80-overlay-controller-callback-v1",
            "accepted": False,
            "active": False,
            "semantic_limit": semantic_limit,
            "reject_reason": "legacy-overlay-irq-route-not-closed",
        }
    status = route.get("status")
    enable = route.get("enable")
    handler_slot = route.get("handler_slot")
    callback_slot = route.get("callback_slot")
    vector_target = route.get("vector_target")
    wrapper = route.get("wrapper")
    vector_source = (runtime_to_file(vector_target)
                     if isinstance(vector_target, int) else None)
    if (not isinstance(wrapper, int)
            or not isinstance(vector_source, int)
            or not 0 <= vector_source <= len(image) - 4
            or file_to_runtime(vector_source) != vector_target
            or arm_b_word_target(
                struct.unpack_from("<I", image, vector_source)[0],
                vector_target,
            ) != wrapper):
        return {
            "signature": "static-c80-overlay-controller-callback-v1",
            "accepted": False,
            "active": False,
            "semantic_limit": semantic_limit,
            "reject_reason": "legacy-overlay-vector-route-not-closed",
        }
    required = {
        "controller_class": "legacy-c80-three-bank-group14-v1",
        "index": 0x2B,
        "mask": 0x0200,
        "status_bank_count": 3,
        "group_row_size": 14,
    }
    if (any(route.get(key) != value for key, value in required.items())
            or not isinstance(status, int) or enable != status + 0x14
            or route.get("status_banks")
               != (status, status + 4, status + 0x30)
            or route.get("clear_banks")
               != (status, status + 4, enable + 0x38)
            or route.get("controller_write_banks")
               != (enable, enable + 4, enable + 0x30)
            or route.get("controller_aperture")
               != (status, enable + 0x3A)
            or not isinstance(handler_slot, int)
            or not isinstance(callback_slot, int)
            or not isinstance(vector_target, int)
            or not _ram_contains(handler_slot, 4, ram_base, ram_size)
            or not _ram_contains(callback_slot, 4, ram_base, ram_size)
            or not _ram_contains(vector_target, 4, ram_base, ram_size)):
        return {
            "signature": "static-c80-overlay-controller-callback-v1",
            "accepted": False,
            "active": False,
            "semantic_limit": semantic_limit,
            "reject_reason": "legacy-overlay-controller-metadata-invalid",
        }
    callback_shape = rex_legacy_5ms_callback_shape_at(image, outers[0])
    if callback_shape is None:
        return None
    return {
        **route,
        "signature": "static-c80-overlay-controller-callback-v1",
        "accepted": True,
        "active": False,
        "promotion": "temporary-evidence-gated",
        "semantic_limit": semantic_limit,
        "pending_read_semantics": "latched-read",
        "time_tick_status_bank": status,
        "time_tick_clear_bank": status,
        "time_tick_mask": 0x0200,
        "wrapper_runtime_address": route["wrapper"],
        "handler_runtime_address": route["handler"],
        "callback_file_offset": outers[0],
        "callback_runtime_address": route["outer_callback"],
        "callback_validation_size": REX_LEGACY_5MS_CALLBACK_SIZE,
        "callback_validation_shape": callback_shape,
        "callback_delta": 5,
    }


def _thumb_adr_target(image: bytes, position: int, register: int) -> int | None:
    if not 0 <= position <= len(image) - 2:
        return None
    word = struct.unpack_from("<H", image, position)[0]
    if word & 0xF800 != 0xA000 or word >> 8 & 7 != register:
        return None
    return ((position + 4) & ~3) + (word & 0xFF) * 4


def _uis_idle_event_prefix_at(image: bytes, position: int) -> bool:
    if not 0 <= position <= len(image) - 32:
        return False
    words = struct.unpack_from("<16H", image, position)
    return (
        words[0] in (0xB5F8, 0xB5FC)
        and words[1] == 0x1C04
        and words[2] & 0xFF00 == 0x4800
        and words[3] == 0x1C0F
        and words[4] & 0xFF00 == 0x4900
        and words[5] & 0xF83F == 0x6800
        and words[6] == 0x1C15
        and words[7] & 0xF83F == 0x6008
        and words[8] & 0xFF00 == 0x4900
        and words[9] & 0xFF00 == 0x4A00
        and words[10] == 0x2000
        and words[11] & 0xFF00 == 0x4E00
        and words[12:] == (0x1889, 0x73C8, 0x7830, 0x2800)
    )


def _uis_idle_draw_prefix_at(image: bytes, position: int) -> bool:
    if not 0 <= position <= len(image) - 26:
        return False
    words = struct.unpack_from("<13H", image, position)
    return (
        words[:2] == (0xB5F0, 0x1C0D)
        and words[2] & 0xFF00 == 0x4900
        and words[3:7] == (0x1C04, 0x2000, 0x6248, 0x203F)
        and words[7] & 0xFF00 == 0x4900
        and words[8:12] == (0x0100, 0x1808, 0x7800, 0x2800)
        and words[12] & 0xFF00 == 0xD000
    )


def _uis_idle_draw_pair(
        image: bytes, calls: list[tuple[int, int | None]], file_to_runtime,
) -> tuple[int, int] | None:
    """Return the registered event/draw pair for one closed idle UI class."""
    marker = image.find(UIS_IDLE_DRAW_MARKER)
    if marker < 0 or image.find(UIS_IDLE_DRAW_MARKER, marker + 1) >= 0:
        return None
    helpers: list[tuple[int, int]] = []
    for site, target in calls:
        if (target is None or not marker - 0x80 <= target < marker
                or target + 4 > len(image)):
            continue
        first, second = struct.unpack_from("<2H", image, target)
        if first & 0xF800 != 0x4800 or second != 0xB500:
            continue
        references = [
            position for position in range(target, marker, 2)
            if _thumb_adr_target(image, position, 0) == marker
        ]
        if len(references) == 1:
            helpers.append((site, target))
    if len(helpers) != 1:
        return None
    draw_call, _helper = helpers[0]
    draws = [
        position for position in range(max(0, draw_call - 0xC0), draw_call + 1, 2)
        if _uis_idle_draw_prefix_at(image, position)
    ]
    if len(draws) != 1:
        return None
    draw = draws[0]
    event_calls = [
        site for site, target in calls
        if (target == draw and image[site - 4:site] == b"\x29\x1c\x38\x1c"
            and image[site + 4:site + 8] == b"\xff\x27\x01\x37")
    ]
    if len(event_calls) != 1:
        return None
    event_call = event_calls[0]
    events = [
        position
        for position in range(max(0, event_call - 0x140), event_call + 1, 2)
        if (draw - position in UIS_IDLE_DRAW_BODY_DELTAS
            and _uis_idle_event_prefix_at(image, position))
    ]
    if len(events) != 1:
        return None
    event = events[0]
    registration = event - 0x40
    runtime_event = file_to_runtime(event)
    if (type(runtime_event) is not int or registration < 0
            or image[registration:registration + 2] != b"\x00\xb5"
            or struct.unpack_from("<H", image, registration + 2)[0] & 0xFF00
               != 0x4900
            or struct.unpack_from("<H", image, registration + 4)[0] != 0x2001
            or thumb_literal_value(image, registration + 2, 1)
               != runtime_event | 1
            or not any(site == registration + 6 and target is not None
                       for site, target in calls)
            or sum(target == registration for _site, target in calls) != 1):
        return None
    return event, draw


def find_uis_idle_pair(
        image: bytes,
        file_to_runtime=lambda position: position,
        runtime_to_file=lambda address: address,
) -> tuple[int, int] | None:
    """Return one closed firmware UI-idle entry/body pair, if unambiguous."""
    calls = [
        (site, _relocated_thumb_file_target(
            image, site, file_to_runtime, runtime_to_file))
        for match in THUMB_BL_PATTERN.finditer(image)
        if not (site := match.start()) & 1
    ]
    profiles = (
        (UIS_IDLE_ENTRY_PREFIX, UIS_IDLE_BODY_DELTA,
         UIS_IDLE_BODY_PREFIX, 2, 1),
        (UIS_IDLE_COMPACT_ENTRY_PREFIX, UIS_IDLE_COMPACT_BODY_DELTA,
         UIS_IDLE_COMPACT_BODY_PREFIX, 1, 1),
    )
    candidates: list[tuple[int, int]] = []
    for entry_prefix, body_delta, body_prefix, entry_calls, body_calls in profiles:
        offset = 0
        while (entry := image.find(entry_prefix, offset)) >= 0:
            body = entry + body_delta
            if (image[body:body + len(body_prefix)] == body_prefix
                    and sum(target == entry for _site, target in calls)
                    == entry_calls
                    and sum(target == body for _site, target in calls)
                    == body_calls):
                candidates.append((entry, body))
            offset = entry + 1
    draw_pair = _uis_idle_draw_pair(image, calls, file_to_runtime)
    if draw_pair is not None and draw_pair not in candidates:
        candidates.append(draw_pair)
    return candidates[0] if len(candidates) == 1 else None


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


# Complete compiler bodies; BL targets and PC-relative literals are closed below.
_ROW0_BODIES = {
    "callback": bytes.fromhex(
        "80b5d54501daf9f009fdf9f0a9fc07043f0c0f480521fff757fd0e48d8f03afd0223184004d00c4801680539016003e0"
        "0a480168053901600520d8f07ffd08480521fff773fb002f01d1f9f097fc80bd"
    ),
    "arm": bytes.fromhex(
        "00b5d54501daf9f0d7fc08480022002169f05eff0020064908608880022005490870054900208ef043f800bd"
    ),
    "registrar": bytes.fromhex(
        "f0b5d54501da6bf07ffc041c0f1c6bf01dfc061c414d002f00d12f1c404841491b2c47d201a31b5d5b009f440d0f1113"
        "1517191b1d1f21232527292b2d2f313d3b393735333f4100876345e0c76343e0076441e047643fe087643de007653be0"
        "476539e0876537e0c76535e0076633e0476631e087662fe0c7662de007672be0476729e0876727e0c76725e00f6023e0"
        "4f6021e0cf611fe08f611de04f611be00f6119e0cf6017e08f6015e00f6213e04f6211e065f738f91b480088042807dc"
        "042805dc211c194800230022cbf7a4f8174918489ff714fa200117494018af4206d1c1680289d2430b881a400a800be0"
        "c1680a8801890a4006d102681180c16802890b881a430a80c168098840680180002e01d16bf0a8fbf0bd"
    ),
    "init": bytes.fromhex(
        "f0b5d54501da6bf0cffc6bf06ffc061c6bf06cfc0027134d2f81134c2785002801d16bf071fc6bf061fc6f81a7850028"
        "01d16bf069fc27870c482084a084002e01d16bf061fc0a4900204af0bdfe094901204af0b9fe00206bf064fc064855f0"
        "97fff0bd"
    ),
    "copy": bytes.fromhex(
        "80b4012224490a7000200870234b1f68234e3668be19234f3d681c68b44206d202e004350434f9e72b682360f9e70a70"
        "08701d4b1f681d4e3668be191c68b44204d201e00434fae72060fbe70a700870174b1f68174e3668be19174f3d681c68"
        "b44206d202e004350434f9e72b682360f9e70a700870114b1f68114e3668be191c68b44204d201e00434fae72060fbe7"
        "0a70087080bcf746"
    ),
    "core": bytes.fromhex(
        "04e04ee293f021e308d04de200102de910d04de20f002de90d10a0e192f021e328e081e560a29fe500a09ae55c329fe5"
        "003093e5010013e354e29f1554e29f0513ff2fe17847000000c04fe193f021e344129fe5001091e540229fe5000092e5"
        "000051e10700001a0cf068e10cf061e104a090e50f00bde810d08de20010bde804d08de20080fde8001082e504d04de2"
        "00d080e500c08de528e08de524d08de2f0000de904a091e500d091e50010bde80cf068e10cf061e1ffd0fde8"
    ),
    "walker": bytes.fromhex(
        "f0b5d54501da20f06bff071c0d4804680d4d0026ac4214d001e02468fae7a068b8420bd8a66020686168086060682168"
        "48602169e068fff76bff01e0c01ba060ebe7f0bd"
    ),
    "signal": bytes.fromhex(
        "f0b5d54501da20f0e3ff071c0c1c20f081ff051cf868061c2043f860386920400ad00020386179690648826852699142"
        "02d9876020f020ff002d01d120f078ff301cf0bd"
    ),
    "scheduler": bytes.fromhex(
        "7847000001e08ee300200fe1800082e300f021e11f0002e2120050e31a00000a88119fe5001091e584319fe5000093e5"
        "000051e11400000a001083e50030a0e1080091e5010080e2080081e500402de908d04de2f0002de910d04de2202082e3"
        "04002de900d083e50100a0e104a090e500d090e50100bde800f068e100f061e10d00a0e12cd08de2ffd0d0e802f028e1"
        "02f021e11eff2fe14b4b1847"
    ),
    "accumulator": bytes.fromhex(
        "0904090c8288511881807d22d2008188914207db7d23db00c91a8180016801310160f4e7f746"
    ),
    "software": bytes.fromhex(
        "f0b5d54501dafaf073f9071c0d1c81b0faf010f90004000c00907c68002c25d0a068401ba060a06801281fda7c682069"
        "a168451a201cfff7bdffe6686069002809d02061a060207e002801d100206061201cfff777ff26636563e01d15308ef0"
        "75fd7c68002c00d100e0dce70098002801d1faf0edf801b0f0bd"
    ),
    "handler_prefix": bytes.fromhex(
        "f0b5d54501da6bf077fecc4ccc4fcd4dcd4e3088cd4a118c08400004000c288504239843011c7088928c10400004000c"
        "6885084373d0288dff21"
    ),
    "handler_row": bytes.fromhex(
        "0121490201400cd0a06b66f736feb8890130b881012040028c4a00e004e1108401e1"
    ),
    "handler_end": bytes.fromhex(
        "fff751fe002800d06ee6388801303880f0bd"
    ),
    "setter": bytes.fromhex(
        "034a002801d1d16000e01161f7460000"
    ),
    "default": bytes.fromhex(
        "0248418f01314187f746"
    ),
    "drain": bytes.fromhex(
        "90b5d54501da6bf08ffe084856f0a6f9071c0024002806d0b869796966f7c8fe3c74012090bd201cfce7"
    ),
}

# Short diagnostic branch and compact expiry fields form one closed subform.
_ROW0_BODIES.update({
    "zero64": bytes.fromhex("0270130a4370130c8370130ec37001710b0a43710b0c83710b0ec371f746"),
    "irq_enable": bytes.fromhex("7847000001e08ee300100fe1000050e38010c1034010c11301f021e11eff2fe1"),
    "drain_compact": bytes.fromhex("90b5d54501da5af03ff8084847f06cfc071c0024002806d0f868b96863f73efd3c71012090bd201cfce7"),
    "registrar_compact": bytes.fromhex(
        "f0b5d54501da59f041fe041c0f1c59f0dffd061c3b4d002f00d12f1c3a483b491b2c47d201a31b5d5b009f440d0f1113"
        "1517191b1d1f21232527292b2d2f313d3b393735333f4100876339e0c76337e0076435e0476433e0876431e007652fe0"
        "47652de087652be0c76529e0076627e0476625e0876623e0c76621e007671fe047671de087671be0c76719e00f6017e0"
        "4f6015e0cf6113e08f6111e04f610fe00f610de0cf600be08f6009e00f6207e04f6205e061f78cff15a11848a6f7acfb"
        "200117494018af4206d1c1680289d2430b881a400a800be0c1680a8801890a4006d102681180c16802890b881a430a80"
        "c168098840680180002e01d159f076fdf0bd"
    ),
    "software_compact": bytes.fromhex(
        "f0b5d54501dae0f037ff071c0d1c81b0e0f0d4fe0004000c00907c68002c25d0a068401ba060a06801281fda7c682069"
        "a168451a201cfff7bdffe6686069002809d02061a060207e002801d100206061201cfff777ff6662a562e01d153087f0"
        "57f97c68002c00d100e0dce70098002801d1e0f0b1fe01b0f0bd"
    ),
})

# Direct expiry-list and deferred-queue callees retain the matched field layout.
_ROW0_BODIES.update({
    "expiry_insert": bytes.fromhex(
        "80b5d54501dafaf0d1f9071cfaf070f90104090c14484068002818d001e04068fae7bb68826893420eda026857600268"
        "3a60786007608268bb68d21a8260002901d1faf063f980bd9a1aba60e7e70748826b5760826b3a6000227a6087630029"
        "01d1faf053f9eee7"
    ),
    "expiry_remove": bytes.fromhex(
        "80b5d54501dafaf099f9071cfaf038f90204120c39687868002900d04860002805d001608168bb68c918816003e00029"
        "01d005488163002078603860002a01d1faf02cf980bd"
    ),
    "submit": bytes.fromhex(
        "90b5d54501da6bf0cdfb071c6bf06cfb0404240c387c002814d012480088032807dc032805dc1048002300220021cbf7"
        "41f80e490e489ff79ff9002c01d16bf061fb90bd01203874002c01d16bf05afb391c381c55f0a1fe391c064855f0a4fe"
        "efe7"
    ),
    "queue_init": bytes.fromhex(
        "0060406000218160c1600182f746"
    ),
    "link_init": bytes.fromhex(
        "00220a604a608860ca60081cf746"
    ),
    "push": bytes.fromhex(
        "90b5d54501da15f0f9fc071c0c1c15f097fc2760e7607968616079680c607c60398a01313982002801d115f097fc90bd"
    ),
    "pop": bytes.fromhex(
        "90b5d54501da15f0e1fc071c15f080fc3c68398a002908dd2168396021684f60398a013939820021e160002801d115f0"
        "7dfca06890bd"
    ),
    "expiry_insert_compact": bytes.fromhex(
        "80b5d54501dae0f095ff071ce0f034ff0104090c14484068002818d001e04068fae7bb68826893420eda026857600268"
        "3a60786007608268bb68d21a8260002901d1e0f027ff80bd9a1aba60e7e70748c26a5760c26a3a6000227a60c7620029"
        "01d1e0f017ffeee7"
    ),
    "expiry_remove_compact": bytes.fromhex(
        "80b5d54501dae0f05dff071ce0f0fcfe0204120c39687868002900d04860002805d001608168bb68c918816003e00029"
        "01d00548c162002078603860002a01d1e0f0f0fe80bd"
    ),
    "submit_compact": bytes.fromhex(
        "90b5d54501da59f0affd071c59f04efd0404240c3879002809d0794632390b48a6f756fb002c01d159f04efd90bd0120"
        "3871002c01d159f047fd391c381c47f0aaf9391c024847f0aaf9efe7"
    ),
    "queue_init_compact": bytes.fromhex(
        "0060406000210181f746"
    ),
    "link_init_compact": bytes.fromhex(
        "081c00210160f746"
    ),
    "push_compact": bytes.fromhex(
        "90b5d54501da12f0e0fb071c0c1c12f07efb276079680c607c60398901313981002801d112f081fb90bd"
    ),
    "pop_compact": bytes.fromhex(
        "90b5d54501da12f0cbfb071c002412f069fb011c38683a89002a0add03683b600368bb4200d17f60013a3a8100220260"
        "041c002901d112f063fb201c90bd"
    ),
})


def _row0_thumb(image: bytes, at: int, shape: str):
    body = _ROW0_BODIES[shape]
    if at < 0 or at & 1 or at + len(body) > len(image):
        return None
    calls, literals, variable = {}, {}, set()
    for offset in range(0, len(body) - 1, 2):
        if thumb_bl_target(body, offset) is not None:
            target = thumb_bl_target(image, at + offset)
            if target is None or not 0 <= target <= len(image) - 2:
                return None
            calls[offset] = target
            variable.update(range(offset, offset + 4))
        word = struct.unpack_from('<H', body, offset)[0]
        if word & 0xF800 == 0x4800:
            value = thumb_literal_value(image, at + offset, word >> 8 & 7)
            if value is None:
                return None
            literals[offset] = value
            variable.add(offset)
    if any(image[at + offset] != value for offset, value in enumerate(body)
           if offset not in variable):
        return None
    return calls, literals


def _row0_arm_literal(image: bytes, at: int, register: int) -> int | None:
    if at < 0 or at & 3 or at + 4 > len(image):
        return None
    word = struct.unpack_from('<I', image, at)[0]
    literal = at + 8 + (word & 0xFFF)
    if (word & 0x0FFFF000 != 0x059F0000 | register << 12
            or literal > len(image) - 4):
        return None
    return struct.unpack_from('<I', image, literal)[0]


def _row0_positions(image: bytes, shape: str):
    prefix = _ROW0_BODIES[shape][:4]
    start = 0
    while (at := image.find(prefix, start)) >= 0:
        start = at + 1
        matched = _row0_thumb(image, at, shape)
        if matched is not None:
            yield at, matched


def find_rex_legacy_row0_profile(
        image: bytes, ram_base: int, ram_size: int, overlays=(),
) -> tuple[dict | None, str]:
    """Close one copied-vector, typed row0 IRQ route; no idle injection hook.

    Five logical units with a 1000-unit carry support a virtual 5 ms policy,
    not a physical oscillator measurement. The caller enforces primary load0.
    """
    if (type(ram_base) is not int or type(ram_size) is not int
            or not _ram_contains(ram_base, 4, ram_base, ram_size)):
        return None, 'row0-ram-range-invalid'
    overlays = tuple(overlays)
    if any(any(type(getattr(item, name, None)) is not int
                   for name in ('source', 'target', 'size'))
           or item.source < 0 or item.target < 0 or item.size <= 0
           for item in overlays):
        return None, 'row0-overlay-invalid'
    callbacks = list(_row0_positions(image, 'callback'))
    if not callbacks:
        return None, 'row0-callback-none'
    copied = _legacy_620_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
    if copied is None:
        return None, 'row0-vector-copy-unclosed'
    source, target, size, core = copied
    if (core & 3 or image[core:core + len(_ROW0_BODIES['core'])]
            != _ROW0_BODIES['core']):
        return None, 'row0-core-unclosed'
    tuple_bytes = struct.pack('<4I', source, target, size, target + size)
    fields, start = [], 0
    while (position := image.find(tuple_bytes, start)) >= 0:
        start = position + 1
        if not position & 3:
            fields.append(position)
    if len(fields) != 1:
        return None, 'row0-copy-fields-ambiguous'
    field = fields[0]
    producers = [at for at, (_, values) in _row0_positions(image, 'copy')
                 if (values.get(0x50), values.get(0x54), values.get(0x5A))
                 == (field + 4, field + 8, field)]
    if len(producers) != 1:
        return None, 'row0-copy-producer-unclosed'

    def ram(address, length=4):
        return type(address) is int and _ram_contains(address, length, ram_base, ram_size)

    def copied_offset(address, length):
        if not ram(address, length) or not target <= address <= target + size - length:
            return None
        # Supplied CopyLayouts take precedence over the fallback tuple map.
        covering = [item for item in overlays
                    if item.target < address + length and address < item.target + item.size]
        if covering and (len(covering) != 1 or covering[0].target > address
                         or address + length > covering[0].target + covering[0].size
                         or covering[0].source + address - covering[0].target
                            != source + address - target):
            return None
        return source + address - target

    if copied_offset(target, 4) is None:
        return None, 'row0-overlay-copy-conflict'
    arms = list(_row0_positions(image, 'arm'))
    initializers = list(_row0_positions(image, 'init'))
    results = []
    reason = 'row0-callback-links-unclosed'
    for callback, (calls, literals) in callbacks:
        guard, lock, free = calls[6], calls[0xA], calls[0x4A]
        if (image[lock:lock + 28] != REX_INTLOCK_SIGNATURE + bytes.fromhex('1eff2fe1')
                or image[free:free + 28] != REX_INTFREE_SIGNATURE + bytes.fromhex('1eff2fe1')
                or image[calls[0x16]:calls[0x16] + 38] != _ROW0_BODIES['accumulator']
                or image[calls[0x1C]:calls[0x1C] + 4] != bytes.fromhex('c068f746')
                or any(not ram(value, 16 if offset == 0x1A else 8)
                       for offset, value in literals.items())):
            continue
        walker_at, software_at = calls[0x3A], calls[0x42]
        walker = _row0_thumb(image, walker_at, 'walker')
        software_shape = ('software' if _row0_thumb(image, software_at, 'software')
                          is not None else 'software_compact')
        software = _row0_thumb(image, software_at, software_shape)
        if (walker is None or software is None or walker[0][6] != guard
                or software[0][6] != guard or software[0][0x10] != lock
                or software[0][0x72] != free
                or any(not ram(value) for value in walker[1].values())):
            continue
        compact = software_shape == 'software_compact'
        suffix = '_compact' if compact else ''
        remove = _row0_thumb(image, software[0][0x36], 'expiry_remove' + suffix)
        insert = _row0_thumb(image, software[0][0x52], 'expiry_insert' + suffix)
        context = literals[0x3E]
        if (remove is None or insert is None
                or remove[0][6] != guard or insert[0][6] != guard
                or remove[0][0xC] != lock or insert[0][0xC] != lock
                or remove[0][0x40] != free
                or any(insert[0][offset] != free for offset in (0x42, 0x62))
                or (remove[1][0x32], insert[1][0x14], insert[1][0x4E])
                    != (context, context, context)
                or context & 3 or not ram(context, 0x30 if compact else 0x3C)):
            continue
        signal = _row0_thumb(image, walker[0][0x36], 'signal')
        if (signal is None or signal[0][6] != guard or signal[0][0xE] != lock
                or signal[0][0x3C] != free):
            continue
        state = signal[1][0x28]
        scheduler = signal[0][0x34]
        if (not ram(state, 20)
                or image[scheduler:scheduler + len(_ROW0_BODIES['scheduler'])]
                    != _ROW0_BODIES['scheduler']
                or _row0_arm_literal(image, scheduler + 0x20, 1) != state + 8
                or _row0_arm_literal(image, scheduler + 0x28, 3) != state + 4
                or _row0_arm_literal(image, core + 0x24, 10) != state
                or _row0_arm_literal(image, core + 0x2C, 3) != state + 12
                or _row0_arm_literal(image, core + 0x38, 14) != core + 0x44
                or _row0_arm_literal(image, core + 0x3C, 14) != core + 0x48
                or _row0_arm_literal(image, core + 0x50, 1) != state + 8
                or _row0_arm_literal(image, core + 0x58, 2) != state + 4):
            continue
        for arm_at, (arm_calls, arm_literals) in arms:
            if (arm_calls[6] != guard
                    or image[arm_calls[0x10]:arm_calls[0x10] + 30] != _ROW0_BODIES['zero64']
                    or arm_literals[0x22] != callback | 1
                    or arm_literals[0x1E] != 0x030006E0
                    or arm_literals[0x16] != literals[0x12]
                    or not ram(arm_literals[0xA], 8)):
                continue
            registrar_at = arm_calls[0x26]
            compact = software_shape == 'software_compact'
            registrar_shape = 'registrar_compact' if compact else 'registrar'
            registrar = _row0_thumb(image, registrar_at, registrar_shape)
            descriptor_literal, free_call = (0xC2, 0xFC) if compact else (0xDA, 0x114)
            if (registrar is None or registrar[0][6] != guard
                    or registrar[0][0xE] != lock or registrar[0][free_call] != free):
                continue
            values = registrar[1]
            descriptors, slots, short, default = (values[descriptor_literal], values[0x1C],
                                                   values[0x1E], values[0x14])
            slot = slots + 0x38
            descriptor_offset = copied_offset(descriptors, 27 * 16)
            slot_offset = copied_offset(slot, 4)
            default_body = _row0_thumb(image, default & ~1, 'default')
            if (descriptors & 3 or slots != descriptors + 0x178
                    or short != descriptors + 0x1F8
                    or descriptor_offset is None or slot_offset is None
                    or not default & 1 or default_body is None
                    or not ram(default_body[1][0], 0x3C)
                    or struct.unpack_from('<I', image, slot_offset)[0] != default):
                reason = 'row0-descriptor-copy-unclosed'
                continue
            records = [struct.unpack_from('<4I', image, descriptor_offset + index * 16)
                       for index in range(27)]
            expected = (0x03000620, 0x03000628, 0x200, descriptors - 8)
            if (records[0] != expected or not ram(descriptors - 8, 6)
                    or [i for i, record in enumerate(records)
                        if record[:3] == expected[:3]] != [0]):
                reason = 'row0-descriptor-tuple-ambiguous'
                continue
            for initializer_at, (init_calls, init_literals) in initializers:
                handler = init_literals[0x46] & ~1
                setter = _row0_thumb(image, init_calls[0x4A], 'setter')
                prefix = _row0_thumb(image, handler, 'handler_prefix')
                row = _row0_thumb(image, handler + 0x102, 'handler_row')
                end = _row0_thumb(image, handler + 0x32A, 'handler_end')
                if (init_calls[6] != guard or init_calls[0xA] != lock
                        or init_calls[0x10] != lock or init_calls[0x26] != lock
                        or any(init_calls[offset] != free for offset in (0x22, 0x32, 0x42))
                        or init_calls[0x4A] != init_calls[0x52]
                        or image[init_calls[0x58]:init_calls[0x58] + 32]
                            != _ROW0_BODIES['irq_enable']
                        or init_literals[0x1A] != 0x03000600
                        or init_literals[0x38] != 0xFFFF
                        or not ram(init_literals[0x16], 12)
                        or not ram(init_literals[0x5C], 0xA if compact else 0x14)
                        or not init_literals[0x4E] & 1
                        or not 0 <= init_literals[0x4E] & ~1 < len(image)
                        or setter is None or setter[1][0] != state
                        or not init_literals[0x46] & 1
                        or prefix is None or prefix[0][6] != guard
                        or (prefix[1][0xA], prefix[1][0xE], prefix[1][0x10], prefix[1][0x14])
                            != (slots, short, descriptors - 8, 0x03000600)
                        or not ram(prefix[1][0xC], 0x3C)
                        or row is None or image[row[0][0xA]:row[0][0xA] + 2] != b'\x00\x47'
                        or row[1][0x18] != 0x03000600 or end is None):
                    continue
                drain = _row0_thumb(image, end[0][0],
                                    'drain_compact' if compact else 'drain')
                if (drain is None or drain[0][6] != guard
                        or image[drain[0][0x1C]:drain[0][0x1C] + 2] != b'\x08\x47'
                        or not ram(drain[1][0xA], 8)):
                    continue
                submit = _row0_thumb(image, software[0][0x5E], 'submit' + suffix)
                pop = _row0_thumb(image, drain[0][0xC], 'pop' + suffix)
                queue_init = _row0_thumb(image, init_calls[0x5E], 'queue_init' + suffix)
                if submit is None or pop is None or queue_init is None:
                    continue
                link_call, push_call, queue_literal = ((0x3E, 0x46, 0x44) if compact
                                                       else (0x54, 0x5C, 0x5A))
                link_init = _row0_thumb(image, submit[0][link_call], 'link_init' + suffix)
                push = _row0_thumb(image, submit[0][push_call], 'push' + suffix)
                queue = drain[1][0xA]
                if (link_init is None or push is None
                        or submit[0][6] != guard or submit[0][0xC] != lock
                        or any(submit[0][offset] != free for offset in
                               ((0x28, 0x36) if compact else (0x3E, 0x4C)))
                        or push[0][6] != guard or push[0][0xE] != lock
                        or push[0][0x24 if compact else 0x2A] != free
                        or pop[0][6] != guard or pop[0][0xE if compact else 0xC] != lock
                        or pop[0][0x36 if compact else 0x2E] != free
                        or (submit[1][queue_literal], init_literals[0x5C]) != (queue, queue)
                        or queue & 3 or not ram(queue, 0xA if compact else 0x14)):
                    continue
                results.append({
                    'class_name': 'legacy-row0-stackchecked-irq-v1',
                    'callback_file_offset': callback,
                    'timer_walker_file_offset': walker_at,
                    'route': (core, handler, state + 12, slot,
                              0x03000620, 0x03000628, 0x200),
                    'arm_address': 0x030006E0, 'mask': 0x200,
                    'logical_delta': 5, 'logical_carry': 1000,
                    'virtual_interval_ns': 5_000_000, 'idle_address': None,
                    'links': {'arm_file_offset': arm_at,
                              'registrar_file_offset': registrar_at,
                              'initializer_file_offset': initializer_at,
                              'descriptor_file_offset': descriptor_offset,
                              'descriptor_address': descriptors,
                              'copy_file_offset': producers[0],
                              'copy_source': source, 'copy_target': target,
                              'copy_size': size, 'software_walker_file_offset': software_at,
                              'accumulator_file_offset': calls[0x16],
                              'expiry_layout': 'compact' if compact else 'extended',
                              'expiry_context': context, 'deferred_queue': queue,
                              'remove_file_offset': software[0][0x36],
                              'insert_file_offset': software[0][0x52],
                              'submit_file_offset': software[0][0x5E],
                              'pop_file_offset': drain[0][0xC],
                              'queue_init_file_offset': init_calls[0x5E]},
                })
    if len(results) != 1:
        return None, 'row0-profile-ambiguous' if results else reason
    return results[0], 'accepted'
