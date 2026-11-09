"""Instruction and literal shapes for external device support.

Detectors use instruction words, loaded literals, and control-flow linkage.
They return a profile and an acceptance reason, or None and a rejection reason.
"""
from __future__ import annotations

import struct

from capstone import arm as a

from .facts import CodeAddress, facts_for, source_prefix

PAGE = 0x1000
_HIGH_RAM_TEST_PREFIX = bytes.fromhex("54019fe5000090e50110a0e30020a0e3")
_EXTENTS = (0x1FFFFF, 0x3FFDFF, 0x3FFFFF, 0x7FFDFF, 0x7FFFFF)
_RAM_PATTERN = (0x10, 0x55AA0F, 0xAA0F, 0x55, 0x030006D0)
_UART_BASE = 0x03000B10
_DOG = 0x030006D0
_GPIO720 = 0x03000720
_STATUS_BASE = 0x0B000400



def _u16(image: bytes, at: int) -> int:
    return struct.unpack_from("<H", image, at)[0]


def _u32(image: bytes, at: int) -> int:
    return struct.unpack_from("<I", image, at)[0]


def _find_all(image: bytes, needle: bytes, limit: int | None = None) -> list[int]:
    end = len(image) if limit is None else min(len(image), limit)
    if not needle:
        return list(range(max(0, end)))
    facts = facts_for(image)
    return [at - facts.base for at in facts.string_candidates(needle)
            if facts.base <= at and at + len(needle) <= facts.base + end]


def _thumb_literal(image: bytes, at: int, register: int) -> int | None:
    if at < 0 or at + 2 > len(image) or at & 1:
        return None
    return facts_for(image).thumb_literal_value(at, register)


def _thumb_b_target(word: int, at: int) -> int | None:
    if word & 0xF800 != 0xE000:
        return None
    delta = (word & 0x7FF) << 1
    if delta & 0x800:
        delta -= 0x1000
    return at + 4 + delta


def _thumb_bl_target(image: bytes, at: int) -> int | None:
    if at < 0 or at + 4 > len(image) or at & 1:
        return None
    return facts_for(image).thumb_call_target(at)


def _movs_imm(word: int, immediate: int) -> int | None:
    """Destination register of ``MOVS Rd, #immediate``, else None."""
    if word & 0xF800 == 0x2000 and (word & 0xFF) == immediate:
        return (word >> 8) & 7
    return None


def _is_lsl_reg(word: int, register: int, shift: int) -> bool:
    return word == ((shift & 31) << 6) | (register << 3) | register


# External panel bus offsets routed into the LCD trace stream.
_EXTERNAL_LCD_STORE_OFFSETS = frozenset((0, 1, 2, 3, 4, 0x78, 0x80, 0x82, 0xFA))


def _is_narrow_store(word: int, base: int) -> bool:
    """``STRB``/``STRH Rt, [Rn, #imm]`` with Rn == base."""
    if ((word >> 3) & 7) != base:
        return False
    return word & 0xF800 in (0x7000, 0x8000)


def _narrow_store_offset(word: int, base: int) -> int | None:
    if ((word >> 3) & 7) != base:
        return None
    imm5 = (word >> 6) & 31
    if word & 0xF800 == 0x7000:
        return imm5
    if word & 0xF800 == 0x8000:
        return imm5 * 2
    return None


def _reset_called(image: bytes) -> set[int] | None:
    """Thumb/ARM targets of the reset helper's interworking BX, or None."""
    if len(image) < 8:
        return None
    vector = _u32(image, 0)
    if vector & 0xFF000000 != 0xEA000000:
        return None
    displacement = (vector & 0xFFFFFF) << 2
    if displacement & 0x02000000:
        displacement -= 0x04000000
    reset = 8 + displacement
    if not 0 <= reset < min(len(image) - 24, 0x10000):
        return None
    called: set[int] = set()
    for pc in range(reset, min(reset + 0x400, len(image) - 24), 4):
        words = struct.unpack_from("<5I", image, pc)
        if not (words[0] & 0xFFFFF000 == 0xE59F4000
                and words[1] == 0xE3140001
                and words[2] & 0xFFFFF000 == 0x159FE000
                and words[3] & 0xFFFFF000 == 0x059FE000
                and words[4] == 0xE12FFF14):
            continue
        literal = pc + 8 + (words[0] & 0xFFF)
        return_literal = pc + 20 + (words[3] & 0xFFF)
        if not (literal <= len(image) - 4 and return_literal <= len(image) - 4
                and _u32(image, return_literal) == pc + 24):
            continue
        target = _u32(image, literal)
        if target & 1:
            thumb_return = pc + 16 + (words[2] & 0xFFF)
            if (thumb_return > len(image) - 4
                    or _u32(image, thumb_return) != (pc + 20) | 1
                    or _u16(image, pc + 20) != 0x4778):
                continue
        called.add(target)
    return called


# Body LDR sites whose pool word is the address of a descriptor field.
# The instruction sequence fixes the descriptor loads; pool words carry
# the table location and vary between firmware layouts.
_BODY_FIELD_PTRS = (
    (0, 0), (0x10, 8), (0x40, 24), (0x6C, 4),
    (0x80, 4), (0xF4, 12), (0x108, 16), (0x11C, 20),
)


def _table_from_body(image: bytes, position: int) -> int | None:
    """Descriptor address from the body's own field-pointer literals.

    Firmware layouts may place data between the descriptor and body, so
    the table is not always adjacent. The first LDR's pool word is the
    descriptor address; the other seven must point at corresponding fields.
    """
    table = None
    for offset, field in _BODY_FIELD_PTRS:
        if position + offset + 4 > len(image):
            return None
        instruction = _u32(image, position + offset)
        # LDR Rd, [PC, #imm12]
        if instruction & 0x0F7F0000 != 0x051F0000:
            return None
        literal = position + offset + 8 + (instruction & 0xFFF)
        if literal > len(image) - 4 or literal & 3:
            return None
        pointer = _u32(image, literal)
        if table is None:
            table = pointer
        if pointer != table + field or pointer & 3:
            return None
    if table is None or table < 0 or table + 28 > len(image):
        return None
    return table


def _arm_branch_delta(instruction: int) -> int:
    displacement = (instruction & 0x00FFFFFF) << 2
    return displacement - 0x04000000 if displacement & 0x02000000 else displacement


def _arm_immediate(instruction: int) -> int:
    value = instruction & 0xFF
    rotation = ((instruction >> 8) & 0xF) * 2
    if not rotation:
        return value
    return ((value >> rotation) | (value << (32 - rotation))) & 0xFFFFFFFF


def _ram_test_body_shape(image: bytes, position: int) -> bool:
    """Check the walking-bit loop, readback compare, and threshold branch."""
    if position < 0 or position + 0x3C > len(image):
        return False
    words = [_u32(image, position + offset) for offset in range(0, 0x3C, 4)]
    # The PC-relative loads at offsets 0 and 0x10 are validated against
    # the descriptor table separately.
    if words[1] != 0xE5900000 or words[2] != 0xE3A01001 or words[3] != 0xE3A02000:
        return False
    if words[5] != 0xE5933000 or words[6] != 0xE0834000:
        return False
    if words[7] != 0xE5801000 or words[8] != 0xE5842000:
        return False
    if words[9] != 0xE5903000 or words[10] != 0xE1530001:
        return False
    failure_branch = words[11]
    if failure_branch & 0xFF000000 != 0x1A000000:
        return False
    failure_target = position + 11 * 4 + 8 + _arm_branch_delta(failure_branch)
    if not position + 0x3C <= failure_target <= position + 0x178:
        return False
    if words[12] != 0xE1A01081:
        return False
    threshold = words[13]
    if threshold & 0xFFFFF000 != 0xE3510000 or _arm_immediate(threshold) != 0x00008000:
        return False
    bound_branch = words[14]
    if bound_branch & 0xFF000000 != 0xDA000000:
        return False
    bound_target = position + 14 * 4 + 8 + _arm_branch_delta(bound_branch)
    return bound_target == position + 0x1C


def _high_ram_layout(image: bytes, position: int) -> tuple[int, int] | None:
    layouts = []
    if position >= 28 and _u32(image, position - 28) == 0x14000000:
        layouts.append((position - 28, position))
    if (position >= 60 and not position & 3
            and image[position - 20:position] == bytes.fromhex(
                "5c019fe558019fe554019fe554019fe554019fe5")
            and _u32(image, position - 60) == 0x14000000):
        table, entry = position - 60, position - 20
        valid = True
        for offset, field in ((0, 28), (4, 28), (8, 28), (12, 32), (16, 36)):
            instruction = _u32(image, entry + offset)
            literal = entry + offset + 8 + (instruction & 0xFFF)
            if (literal > len(image) - 4
                    or _u32(image, literal) != table + field):
                valid = False
                break
        if valid:
            layouts.append((table, entry))
    if len(layouts) != 1:
        return None
    return layouts[0]


def _reset_copy_covers_upper_half(image: bytes, called: set[int],
                                  base: int, size: int) -> bool:
    shapes = (
        (0x4800, 0x6804, 0x4800, 0x6800, 0x1826, 0x4800,
         0x6805, 0xE001, 0xCD01, 0xC401, 0x42B4, 0xD3FB),
        (0x4A00, 0x6814, 0x4A00, 0x6812, 0x18A6, 0x4A00,
         0x6815, 0xE001, 0xCD04, 0xC404, 0x42B4, 0xD3FB),
    )
    for target in called:
        if not target & 1:
            continue
        start = target & ~1
        for pc in range(start, min(start + 0x400, len(image) - 23), 2):
            words = struct.unpack_from("<12H", image, pc)
            normalized = tuple(word & 0xFF00 if i in (0, 2, 5) else word
                               for i, word in enumerate(words))
            if normalized not in shapes:
                continue
            register = (words[0] >> 8) & 7
            pointers = [_thumb_literal(image, pc + offset, register)
                        for offset in (0, 4, 10)]
            if any(p is None or p & 3 or p > len(image) - 4 for p in pointers):
                continue
            destination_ptr, length_ptr, source_ptr = pointers
            if length_ptr != destination_ptr + 4 or source_ptr != destination_ptr - 4:
                continue
            destination, length, source = (
                _u32(image, p) for p in pointers)
            if (not (destination | length | source) & 3 and length > 0
                    and source + length <= len(image)
                    and base + size // 2 <= destination
                    < destination + length <= base + size):
                return True
    return False


def _cs_store_sites(image: bytes) -> list[int]:
    """Thumb tail that writes the 0x0A000080 chip-select block.

    The two pool loads are the only varying immediates. Both must be the
    chip-select pointer, and the same pointer is stored through earlier
    in the function at offset +0x20.
    """
    sites = []
    anchor = bytes.fromhex("01210904")
    start = 0
    while True:
        at = image.find(anchor, start)
        if at < 0:
            break
        start = at + 2
        if at & 1 or at + 16 > len(image):
            continue
        words = struct.unpack_from("<8H", image, at)
        if words[2] & 0xF800 != 0x4800 or (words[2] >> 8) & 7 != 2:
            continue
        if words[3] != 0x6311 or words[4] != 0x2107:
            continue
        if words[5] & 0xF800 != 0x4800 or (words[5] >> 8) & 7 != 2:
            continue
        if words[6] != 0x3230 or words[7] != 0x7211:
            continue
        if (_thumb_literal(image, at + 4, 2) != 0x0A000080
                or _thumb_literal(image, at + 10, 2) != 0x0A000080):
            continue
        window = image[max(0, at - 0x80):at]
        linked = False
        for back in range(0, len(window) - 4, 2):
            pc = max(0, at - 0x80) + back
            if pc & 1:
                continue
            load = _u16(image, pc)
            store = _u16(image, pc + 2)
            if (load & 0xF800 == 0x4800 and (load >> 8) & 7 == 2
                    and store == 0x6211
                    and _thumb_literal(image, pc, 2) == 0x0A000080):
                linked = True
                break
        if linked:
            sites.append(at)
    return sites


def _cs_ctrl_sites(image: bytes) -> list[int]:
    """Program the 0x0A000080 chip-select block from reset.

    The closed shape stores zero through +0x20, +0x28 and +0x24, then
    reloads the same pointer, adds 0x40, and stores a config word at
    +0x10. One image inserts ``MOVS r0, #0`` between the first store
    and the other two. This is the block the 0x0A000000 window has to
    accept when the later ``movs #1; lsl #16`` tail is absent.
    """
    sites = []
    for needle in (bytes.fromhex("086288624862"),
                   bytes.fromhex("0862002088624862")):
        start = 0
        while True:
            at = image.find(needle, start)
            if at < 0:
                break
            start = at + 2
            if at & 1 or at < 2:
                continue
            load = at - 2
            if (_u16(image, load) & 0xF800 != 0x4800
                    or (_u16(image, load) >> 8) & 7 != 1):
                continue
            if _thumb_literal(image, load, 1) != 0x0A000080:
                continue
            window_end = min(len(image) - 6, at + 0x30)
            linked = False
            for pc in range(at + 2, window_end, 2):
                word = _u16(image, pc)
                if not (word & 0xF800 == 0x4800 and (word >> 8) & 7 == 1
                        and _thumb_literal(image, pc, 1) == 0x0A000080):
                    continue
                add = _u16(image, pc + 2)
                store = _u16(image, pc + 4)
                # ADDS r1, #0x40; STR Rt, [r1, #0x10]
                if (add == 0x3140 and store & 0xF800 == 0x6000
                        and (store >> 3) & 7 == 1
                        and (store >> 6) & 31 == 4):
                    linked = True
                    break
            if linked:
                sites.append(load)
    return sites


def detect_external_ram(image: bytes) -> tuple[dict | None, str]:
    """Reset-linked 0x14000000 readback test.

    The readback body is the closed ARM walking-bit test. Its descriptor
    base is 0x14000000 and the watchdog literal is 0x030006D0. The
    result proves a RAM extent. Chip-select programming is detected
    separately and never implies that this RAM bank exists.
    """
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-ram-image-not-bytes"
    ram_hits = []
    called = _reset_called(image)
    for position in _find_all(source_prefix(image, 0x10000), _HIGH_RAM_TEST_PREFIX):
        if position + 0x178 > len(image) or position & 3:
            continue
        if not _ram_test_body_shape(image, position):
            continue
        layout = _high_ram_layout(image, position)
        if layout is None:
            # Table recovered from the body literals. Accept a direct
            # reset call of the body, a call of the five-LDR trampoline
            # 20 bytes before it, or the reset copy that lands in the
            # upper half (entry stays the body for that last case).
            table = _table_from_body(image, position)
            if table is None or called is None:
                continue
            if position in called or (position - 20) in called:
                entry = position if position in called else position - 20
            else:
                entry = position
            layout = (table, entry)
        table, entry = layout
        base, extent, stride, word, half, byte, watchdog = struct.unpack_from(
            "<7I", image, table)
        if (base != 0x14000000 or extent not in _EXTENTS
                or (stride, word, half, byte, watchdog) != _RAM_PATTERN):
            continue
        valid = True
        for offset, field in ((0, 0), (0x10, 8), (0x40, 24), (0x6C, 4),
                              (0x80, 4), (0xF4, 12), (0x108, 16), (0x11C, 20)):
            instruction = _u32(image, position + offset)
            literal = position + offset + 8 + (instruction & 0xFFF)
            if (literal > len(image) - 4
                    or _u32(image, literal) != table + field):
                valid = False
                break
        if not valid or called is None:
            continue
        size = (extent + PAGE) & ~(PAGE - 1)
        linked = entry in called or (
            entry == position and _reset_copy_covers_upper_half(
                image, called, base, size))
        if linked:
            ram_hits.append({
                "kind": "ram-test",
                "table": table,
                "entry": entry,
                "body": position,
                "base": base,
                "extent": extent,
                "size": size,
            })
    if len(ram_hits) > 1:
        return None, "external-ram-ram-test-ambiguous"
    if len(ram_hits) == 1:
        return {
            "behaviour": "external_ram",
            "reason": "accepted",
            "ram_test": ram_hits[0],
        }, "accepted"
    if called is None:
        return None, "external-ram-reset-unlinked"
    return None, "external-ram-shape-absent"


def detect_external_cs0a(image: bytes) -> tuple[dict | None, str]:
    """Detect linked configuration writes through the 0x0A000080 block."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-cs0a-image-not-bytes"
    sites = ([{"kind": "chip-select", "at": at} for at in _cs_store_sites(image)]
             + [{"kind": "controller-config", "at": at} for at in _cs_ctrl_sites(image)])
    reset_called = _reset_called(image)
    if reset_called:
        accesses = _literal_window_accesses_many(
            source_prefix(image, 0x10000), (0x0A000000,)
        )[0x0A000000]
        wanted = {0x0A0000A0, 0x0A0000B0}
        linked: dict[int, list[dict]] = {}
        for target in reset_called:
            if not target & 1:
                continue
            entry = target & ~1
            end = _thumb_reset_function_end(image, entry)
            if end is None:
                continue
            linked[target] = [item for item in accesses
                              if item["operation"] == "write" and item["thumb"]
                              and item["address"] in wanted
                              and entry <= item["load"] < end]
        for target, found in linked.items():
            if {item["address"] for item in found} >= wanted:
                guards = _reset_helper_source_spans(image, target)
                entry = target & ~1
                end = _thumb_reset_function_end(image, entry)
                for item in found:
                    sites.append({
                        "kind": "literal-access", **item,
                        "span": [item["load"],
                                 item["use"] + item["instruction_width"] - item["load"]],
                        "extra_spans": [[item["literal"], 4],
                                        [entry, end - entry], *guards],
                    })
    if not sites:
        return None, "external-cs0a-controller-write-absent"
    return {"sites": sites}, "accepted"


def _literal_window_accesses_many(
    image: bytes, bases: tuple[int, ...], size: int = 0x1000,
) -> dict[int, list[dict]]:
    """Find narrow literal-linked accesses for all windows in one scan."""
    result = {base: [] for base in bases}
    ranges = tuple((base, base + size) for base in bases)
    facts = facts_for(bytes(image))
    candidates = facts.literal_access_candidates(ranges, limit=len(image))
    for candidate in candidates:
        literal = facts.literal(candidate.load)
        if literal is None:
            continue
        pointer = literal.value
        selected = next((base for base, end in ranges if base <= pointer < end), None)
        if (selected is None
                or not selected <= candidate.address
                or candidate.address + candidate.width > selected + size):
            continue
        result[selected].append({
            "load": candidate.load.address,
            "use": candidate.use.address,
            "literal": candidate.literal,
            "thumb": candidate.load.isa == "thumb",
            "instruction_width": 2 if candidate.load.isa == "thumb" else 4,
            "address": candidate.address,
            "access_size": candidate.width,
            "operation": candidate.operation,
        })
    for accesses in result.values():
        accesses.sort(key=lambda item: (item["load"], item["use"], item["instruction_width"]))
    return result


def _literal_window_accesses(image: bytes, base: int, size: int = 0x1000) -> list[dict]:
    """Compatibility wrapper for one literal-linked window."""
    return _literal_window_accesses_many(image, (base,), size)[base]


def detect_external_cs09(image: bytes) -> tuple[dict | None, str]:
    """Detect data access outside the single-byte strap read at +0x70."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-cs09-image-not-bytes"
    accesses = [item for item in _literal_window_accesses_many(
        image, (0x09000000,))[0x09000000]
                if not (item["operation"] == "read"
                        and item["address"] == 0x09000070
                        and item["access_size"] == 1)]
    if not accesses:
        return None, "external-cs09-access-absent"
    return {"accesses": accesses}, "accepted"


def detect_external_windows(image: bytes) -> tuple[dict | None, str]:
    """Return only literal-linked accesses for independently used windows."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-window-image-not-bytes"
    bases = (0x08C00000, 0x1A000000, 0x0B000000,
             0x18000000, 0x1C000000)
    found = _literal_window_accesses_many(image, bases)
    found[0x08C00000].extend(_thumb_shifted_08c_stores(image))
    found[0x08C00000].sort(
        key=lambda item: (item["load"], item["use"], item["instruction_width"]))
    profiles = {f"{base:08x}": found[base] for base in bases}
    if not any(profiles.values()):
        return None, "external-window-access-absent"
    return profiles, "accepted"


def _thumb_shifted_08c_stores(image: bytes) -> list[dict]:
    """Find closed MOVS/LSLS/STR accesses through the 0x08C00000 window."""
    accesses = []
    for register in range(8):
        mov = 0x2000 | (register << 8) | 0x23
        shift = (22 << 6) | (register << 3) | register
        for at in _find_all(image, struct.pack("<2H", mov, shift)):
            if at & 1 or at + 6 > len(image):
                continue
            store = _u16(image, at + 4)
            if (store & 0xF800 != 0x6000
                    or (store >> 3) & 7 != register):
                continue
            offset = ((store >> 6) & 31) * 4
            if offset not in (4, 0x0C):
                continue
            accesses.append({
                "load": at, "use": at + 4, "literal": None,
                "thumb": True, "instruction_width": 2,
                "address": 0x08C00000 + offset,
                "access_size": 4, "operation": "write",
                "construction": "thumb-shifted-base",
            })
    return accesses


def detect_gpio_ready_bit21(image: bytes) -> tuple[dict | None, str]:
    """Select the GPIO bit-21 input only when its exact poll is present."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "gpio-ready-image-not-bytes"
    spins = _bit21_spins(image)
    if not spins:
        return None, "gpio-ready-bit21-poll-absent"
    return {"sites": spins, "gpio": _GPIO720, "bit": 21}, "accepted"


def detect_external_panel_writers(image: bytes) -> tuple[dict | None, str]:
    """Detect command stores independently of GPIO-ready polling."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-panel-image-not-bytes"
    writers = _external_lcd_writers(image)
    if not writers:
        return None, "external-panel-writer-absent"
    return {"writers": writers}, "accepted"


def _bit3_polls(image: bytes) -> list[dict]:
    """Infinite poll of UART status +4 bit 3, kicking 0x030006D0."""
    polls = []
    for at in _find_all(image, bytes.fromhex("00790007")):
        # The back-branch is a halfword at at+16, so the image must
        # cover at+18. at+16 alone stops one byte short.
        if at < 2 or at & 1 or at + 18 > len(image):
            continue
        words = struct.unpack_from("<9H", image, at - 2)
        load, _ldrb, _lsl, branch, mov1, dog, kick1, zero, kick0 = words
        if load & 0xF800 != 0x4800 or (load >> 8) & 7 != 0:
            continue
        if _thumb_literal(image, at - 2, 0) != _UART_BASE:
            continue
        if branch & 0xFF00 != 0xD400 or mov1 != 0x2001:
            continue
        if dog & 0xF800 != 0x4800 or (dog >> 8) & 7 != 1:
            continue
        # ``at`` is the LDRB. The watchdog LDR is the sixth halfword
        # (at+8); at+6 is ``MOVS r0, #1``.
        if _thumb_literal(image, at + 8, 1) != _DOG:
            continue
        if kick1 != 0x7008 or zero != 0x2000 or kick0 != 0x7008:
            continue
        back = _u16(image, at + 16)
        if _thumb_b_target(back, at + 16) != at - 2:
            continue
        polls.append({"at": at - 2, "watchdog": _DOG})
    return polls


def _uart_cr_inits(image: bytes) -> list[int]:
    """``MOVS r0, #0x20`` then two ``STRB r0, [r1, #0xC]`` to 0x03000B1C.

    The command register is base+0xC. With the pool literal 0x03000B10
    that store address is 0x03000B1C (the init the boot path actually
    executes). r1 is either loaded between the MOV and the stores, or
    loaded earlier in the same straight-line sequence.
    """
    sites = []
    start = 0
    while True:
        at = image.find(b"\x20\x20", start)
        if at < 0:
            break
        start = at + 2
        if at & 1:
            continue
        gap = None
        if at + 6 <= len(image) and image[at + 2:at + 6] == b"\x08\x73\x08\x73":
            gap = 0
        elif (at + 8 <= len(image) and image[at + 4:at + 8] == b"\x08\x73\x08\x73"
              and _u16(image, at + 2) & 0xF800 == 0x4800
              and (_u16(image, at + 2) >> 8) & 7 == 1
              and _thumb_literal(image, at + 2, 1) == _UART_BASE):
            gap = 2
        if gap is None:
            continue
        if gap == 2:
            sites.append(at)
            continue
        base_load = None
        for back in range(at - 2, max(-1, at - 0x30), -2):
            word = _u16(image, back)
            if word & 0xF800 == 0x4800 and (word >> 8) & 7 == 1:
                if _thumb_literal(image, back, 1) == _UART_BASE:
                    base_load = back
                break
            # A write to r1 breaks the reaching definition.
            if (word & 0xF800 == 0x2000 and (word >> 8) & 7 == 1
                    or word & 0xFF00 == 0x4900):
                break
        if base_load is not None:
            sites.append(at)
    return sites


def _push_lr(image: bytes, at: int) -> int | None:
    for pc in range(at, max(-1, at - 0x120), -2):
        if pc < 0 or pc + 2 > len(image):
            continue
        word = _u16(image, pc)
        if word & 0xFE00 == 0xB400 and word & 0x0100:
            return pc
    return None


def detect_boot_uart(image: bytes) -> tuple[dict | None, str]:
    """Boot UART whose CR init and bit-3 poll share one function.

    Status is the byte at 0x03000B14. ``LSLS #28`` / ``BMI`` treats bit 3
    as ready. While it is clear the loop kicks 0x030006D0 and branches to
    itself. The ``MOV #0x20`` / ``STRB [base, #0xC]`` pair (twice) is the
    command-register init in that same function, either in line ahead of
    the poll or ahead of a BL into the poll.
    """
    if not isinstance(image, (bytes, bytearray)):
        return None, "boot-uart-image-not-bytes"
    polls = _bit3_polls(image)
    inits = _uart_cr_inits(image)
    if not polls:
        return None, "boot-uart-bit3-poll-absent"
    if not inits:
        return None, "boot-uart-cr-init-absent"
    linked = []
    poll_at = {item["at"] for item in polls}
    for init in inits:
        for poll in poll_at:
            if 0 < poll - init <= 0x20:
                linked.append({"init": init, "poll": poll, "link": "fall-through"})
                break
        else:
            push = _push_lr(image, init)
            if push is None:
                continue
            for pc in range(push, min(init + 2, len(image) - 4), 2):
                target = _thumb_bl_target(image, pc)
                if target is None:
                    continue
                if any(abs(target - poll) <= 16 for poll in poll_at):
                    linked.append({
                        "init": init, "poll": target, "link": "bl", "bl": pc,
                    })
                    break
    if not linked:
        return None, "boot-uart-init-poll-unlinked"
    return {
        "behaviour": "boot_uart",
        "reason": "accepted",
        "links": linked,
        "polls": [item["at"] for item in polls],
        "inits": inits,
    }, "accepted"


def _reset_push(image: bytes, at: int, called: set[int]) -> int | None:
    """Nearest ``PUSH`` of ``lr`` at or before ``at`` that reset actually calls."""
    for pc in range(at, max(-1, at - 0x180), -2):
        if pc < 0 or pc + 2 > len(image):
            continue
        word = _u16(image, pc)
        if word & 0xFE00 == 0xB400 and word & 0x0100:
            if pc in called or (pc | 1) in called:
                return pc
    return None


def detect_boot_strap(image: bytes) -> tuple[dict | None, str]:
    """``LDRB`` of 0x09000070, ``LSLS #29``, forward ``BMI``.

    Bit 2 set skips the download chip-select block. The preset byte 0x04
    is what makes that branch taken on the normal boot path. The address
    is either the pool literal itself or ``literal + ADDS imm8`` in the
    same register, with an immediate adjustment such as 0x10.
    """
    if not isinstance(image, (bytes, bytearray)):
        return None, "boot-strap-image-not-bytes"
    hits = []
    for register in range(8):
        ldrb = 0x7800 | (register << 3) | register
        shift = (29 << 6) | (register << 3) | register
        needle = struct.pack("<2H", ldrb, shift)
        for at in _find_all(image, needle):
            if at < 2 or at & 1 or at + 6 > len(image):
                continue
            load_at = at - 2
            if _u16(image, load_at) == 0x46C0 and load_at >= 2:
                load_at -= 2
            if _thumb_literal(image, load_at, register) != 0x09000070:
                load_at = None
                add = _u16(image, at - 2)
                if (at >= 4 and add & 0xFF00 == (0x3000 | (register << 8))
                        and (add & 0xFF)):
                    base = _thumb_literal(image, at - 4, register)
                    if (base is not None
                            and (base + (add & 0xFF)) & 0xFFFFFFFF == 0x09000070):
                        load_at = at - 4
            if load_at is None:
                continue
            branch = _u16(image, at + 4)
            if branch & 0xFF00 != 0xD400:
                continue
            imm8 = branch & 0xFF
            if not 0 < imm8 < 0x80:
                continue
            hits.append({
                "at": load_at,
                "register": register,
                "branch": at + 4,
                "target": at + 4 + 4 + (imm8 << 1),
            })
    if not hits:
        return None, "boot-strap-bit2-test-absent"
    return {"behaviour": "boot_strap", "reason": "accepted", "sites": hits}, "accepted"


def _thumb_cond_b_target(word: int, at: int) -> int | None:
    if word & 0xF000 != 0xD000 or word >> 8 & 0xF in (0xE, 0xF):
        return None
    delta = (word & 0xFF) << 1
    if delta & 0x100:
        delta -= 0x200
    return at + 4 + delta


def _thumb_literal_pool(image: bytes, at: int, register: int) -> int | None:
    if at < 0 or at + 2 > len(image) or at & 1:
        return None
    facts = facts_for(image)
    literal = facts.literal(CodeAddress(facts.base + at))
    return (literal.pool - facts.base if literal is not None
            and literal.register == a.ARM_REG_R0 + register and 0 <= register <= 7 else None)


def _thumb_literal_loads_of(image: bytes, value: int, register: int,
                            code_limit: int = 0x100000) -> list[int]:
    facts = facts_for(image)
    limit = facts.base + min(len(image), code_limit)
    references = (item for item in facts.literal_references(value)
                  if item.instruction.isa == 'thumb'
                  and item.register == a.ARM_REG_R0 + register and 0 <= register <= 7
                  and facts.base <= item.pool <= limit - 4
                  and max(facts.base, item.pool - 0x400) <= item.instruction.address < item.pool)
    return [item.instruction.address - facts.base
            for item in sorted(references, key=lambda item: (item.pool, item.instruction.address))]


def _thumb_writes_register(word: int, register: int) -> bool | None:
    """Return whether a narrow Thumb instruction may replace a register."""
    if word & 0xF800 == 0x4800:  # LDR literal
        return (word >> 8) & 7 == register
    if word & 0xE000 == 0x0000:  # shifts and add/subtract register forms
        return word & 7 == register
    if word & 0xE000 == 0x2000:  # immediate MOV/CMP/ADD/SUB
        operation = (word >> 11) & 3
        if operation == 1:  # CMP does not write Rd
            return False
        return (word >> 8) & 7 == register
    if word & 0xFC00 == 0x4000:  # ALU register operations
        operation = (word >> 6) & 0xF
        if operation == 0xA:  # CMP
            return False
        return word & 7 == register
    if word & 0xFC00 == 0x4400:  # high-register ADD/CMP/MOV/BX
        operation = (word >> 8) & 3
        if operation in (1, 3):  # CMP and BX
            return False
        destination = ((word >> 4) & 8) | (word & 7)
        return destination == register
    if word & 0xF800 in (0x6000, 0x6800, 0x7000, 0x7800,
                         0x8000, 0x8800):
        return (word & 7) == register and bool(word & 0x0800)
    if word & 0xF000 == 0x5000:  # register-offset load/store
        operation = (word >> 9) & 7
        return (word >> 0) & 7 == register and operation >= 3
    if word & 0xF000 == 0xC000:  # STM/LDM also update their base register.
        return ((word >> 8) & 7) == register or bool(
            word & 0x0800 and word & (1 << register))
    if word & 0xFE00 == 0xB400:  # PUSH
        return False
    if word & 0xFE00 == 0xBC00:  # POP
        return bool(word & (1 << register))
    if word & 0xF800 in (0xE000, 0xF000, 0xF800) or word & 0xF000 == 0xD000:
        if word & 0xF800 in (0xF000, 0xF800):
            return register < 4  # BL preserves r4-r7 under the Thumb ABI.
        return None if word & 0xF800 == 0xE000 else False
    if word & 0xF000 == 0xA000:  # PC-relative ADD
        return (word >> 8) & 7 == register
    if word & 0xFF00 == 0xB000:  # SP adjustment
        return False
    return None


def _reset_helper_source_spans(image: bytes, wanted: int) -> list[list[int]]:
    """Return the reset vector and helper literals that transfer to wanted."""
    if len(image) < 8:
        return []
    vector = _u32(image, 0)
    if vector & 0xFF000000 != 0xEA000000:
        return []
    delta = (vector & 0xFFFFFF) << 2
    if delta & 0x02000000:
        delta -= 0x04000000
    reset = 8 + delta
    if not 0 <= reset < min(len(image) - 24, 0x10000):
        return []
    for pc in range(reset, min(reset + 0x400, len(image) - 24), 4):
        words = struct.unpack_from("<5I", image, pc)
        if not (words[0] & 0xFFFFF000 == 0xE59F4000
                and words[1] == 0xE3140001
                and words[2] & 0xFFFFF000 == 0x159FE000
                and words[3] & 0xFFFFF000 == 0x059FE000
                and words[4] == 0xE12FFF14):
            continue
        target_pool = pc + 8 + (words[0] & 0xFFF)
        return_pool = pc + 20 + (words[3] & 0xFFF)
        if (target_pool > len(image) - 4 or return_pool > len(image) - 4
                or _u32(image, return_pool) != pc + 24
                or _u32(image, target_pool) != wanted):
            continue
        spans = [[0, 4], [pc, 20], [target_pool, 4], [return_pool, 4]]
        if wanted & 1:
            thumb_return_pool = pc + 16 + (words[2] & 0xFFF)
            if (thumb_return_pool > len(image) - 4
                    or _u32(image, thumb_return_pool) != (pc + 20) | 1
                    or _u16(image, pc + 20) != 0x4778):
                continue
            spans.extend(([pc + 20, 2], [thumb_return_pool, 4]))
        return spans
    return []


def _thumb_reset_function_end(image: bytes, entry: int) -> int | None:
    """End of a short reset-called Thumb routine with a closed return."""
    start = entry & ~1
    for pc in range(start, min(start + 0x800, len(image) - 2), 2):
        word = _u16(image, pc)
        if word == 0x4770 or (word & 0xFE00 == 0xBC00 and word & 0x0100):
            return pc + 2
    return None


def _thumb_nearest_push_lr(image: bytes, at: int, distance: int = 0x800) -> int | None:
    for pc in range(at - 2, max(-1, at - distance), -2):
        if _u16(image, pc) & 0xFE00 == 0xB400 and _u16(image, pc) & 0x0100:
            return pc
    return None


def _thumb_calls_to(image: bytes, target: int) -> list[int]:
    facts = facts_for(image)
    return [site - facts.base for site, destination in facts.call_candidates('thumb')
            if destination == facts.base + target]


def _status_zero_branch(image: bytes, entry: int, status_address: int) -> dict | None:
    start = entry & ~1
    for literal_at in range(start, min(start + 8, len(image) - 2), 2):
        if _thumb_literal(image, literal_at, 0) != status_address:
            continue
        for load_at in range(literal_at + 2, min(literal_at + 0x20, len(image) - 2), 2):
            load = _u16(image, load_at)
            if (load & 0xF800 != 0x7800 or (load >> 3) & 7 != 0
                    or (load >> 6) & 0x1F != 1):
                continue
            value_register = load & 7
            compare_at = None
            for pc in range(load_at + 2, min(load_at + 0x30, len(image) - 2), 2):
                word = _u16(image, pc)
                if _thumb_writes_register(word, value_register):
                    break
                if word == (0x2800 | value_register << 8):
                    compare_at = pc
                    break
            if compare_at is None:
                continue
            branch_at = compare_at + 2
            branch = _u16(image, branch_at)
            target = _thumb_cond_b_target(branch, branch_at)
            if (branch & 0xFF00 != 0xD000 or target is None
                    or target <= branch_at + 2 or target >= start + 0x200):
                continue
            return {
                "entry": start, "literal": _thumb_literal_pool(image, literal_at, 0),
                "literal_at": literal_at, "load": load_at,
                "branch": branch_at, "branch_target": target,
                "span": [start, max(branch_at + 2, target + 2) - start],
            }
    return None


def _status_panel_branch(image: bytes, entry: int, status_address: int) -> dict | None:
    start = entry & ~1
    literal_at = start
    if _thumb_literal(image, literal_at, 0) != status_address:
        return None
    if literal_at + 12 > len(image):
        return None
    expected = (0x7841, 0x2003, 0x06C0, 0x2900)
    if struct.unpack_from("<4H", image, literal_at + 2) != expected:
        return None
    branch_at = literal_at + 10
    branch = _u16(image, branch_at)
    low = _thumb_cond_b_target(branch, branch_at)
    if branch & 0xFF00 != 0xD000 or low is None:
        return None
    high_words = struct.unpack_from("<4H", image, branch_at + 2)
    if high_words[:3] != (0x2151, 0x7001, 0x2100):
        return None
    skip = _thumb_b_target(high_words[3], branch_at + 8)
    if skip != low + 2 or low <= branch_at + 8 or low + 6 > len(image):
        return None
    if struct.unpack_from("<3H", image, low) != (0x21AF, 0x7001, 0x4770):
        return None
    return {
        "entry": start, "literal": _thumb_literal_pool(image, literal_at, 0),
        "branch": branch_at, "branch_target": low,
        "span": [start, low + 6 - start],
    }


def detect_boot_gpio_bit9(image: bytes) -> tuple[dict | None, str]:
    """Detect a reset-linked GPIO bit-9 status path selecting the low panel branch."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "boot-gpio-bit9-image-not-bytes"
    called = _reset_called(image)
    if not called:
        return None, "boot-gpio-bit9-reset-unlinked"

    hits = {}
    for register in range(8):
        shift = (22 << 6) | (register << 3) | register
        for shift_at in _find_all(image, struct.pack("<H", shift), 0x100000):
            if shift_at & 1 or shift_at < 4 or shift_at + 12 > len(image):
                continue
            if _u16(image, shift_at - 2) != (0x6800 | register << 3 | register):
                continue
            first_load = _u16(image, shift_at - 4)
            if (first_load & 0xF800 != 0x6800 or first_load & 7 != register
                    or (first_load >> 6) & 0x1F != 1):
                continue
            base_register = (first_load >> 3) & 7
            status_literal_at = shift_at + 2
            status_register = (_u16(image, status_literal_at) >> 8) & 7
            if _thumb_literal(image, status_literal_at, status_register) is None:
                continue
            if _u16(image, shift_at + 4) != (0x0800 | 31 << 6 | register << 3 | register):
                continue
            subtract = _u16(image, shift_at + 6)
            if subtract & 0xFF00 != (0x3800 | status_register << 8) or subtract & 0xFF != 12:
                continue
            store_at = shift_at + 8
            store = _u16(image, store_at)
            if (store & 0xF800 != 0x7000 or (store >> 3) & 7 != status_register
                    or store & 7 != register or (store >> 6) & 0x1F != 1):
                continue
            status_word = _thumb_literal(image, status_literal_at, status_register)
            if status_word is None or status_word < 12:
                continue
            status_address = status_word - 12

            function = _thumb_nearest_push_lr(image, shift_at, 0x200)
            if function is None or function > shift_at - 4:
                continue
            descriptor_load = None
            descriptor = None
            for pc in range(shift_at - 4, function - 1, -2):
                word = _u16(image, pc)
                if word & 0xF800 == 0x4800 and (word >> 8) & 7 == base_register:
                    descriptor_load = pc
                    descriptor = _thumb_literal(image, pc, base_register)
                    break
                writes = _thumb_writes_register(word, base_register)
                if writes is None or writes:
                    descriptor_load = None
                    break
            if descriptor_load is None or descriptor is None or descriptor > len(image) - 8:
                continue
            if _u32(image, descriptor + 4) != _GPIO720:
                continue

            first_bl = store_at + 2
            second_bl = first_bl + 4
            status_target = _thumb_bl_target(image, first_bl)
            panel_target = _thumb_bl_target(image, second_bl)
            if status_target is None or panel_target is None:
                continue
            status_check = _status_zero_branch(image, status_target, status_address)
            panel = _status_panel_branch(image, panel_target, status_address)
            if status_check is None or panel is None:
                continue

            for caller in _thumb_calls_to(image, function):
                reset_entry = _thumb_nearest_push_lr(image, caller, 0x1000)
                if reset_entry is None or not any(
                        target in (reset_entry, reset_entry | 1) for target in called):
                    continue
                reset_guards = _reset_helper_source_spans(image, reset_entry | 1)
                if not reset_guards:
                    continue
                pools = []
                for pc, reg in ((descriptor_load, base_register),
                                (status_literal_at, status_register),
                                (status_check["literal_at"], 0),
                                (panel_target, 0)):
                    pool = _thumb_literal_pool(image, pc, reg)
                    if pool is not None:
                        pools.append([pool, 4])
                evidence = {
                    "span": [function, second_bl + 4 - function],
                    "extra_spans": [*pools, [descriptor + 4, 4],
                                    status_check["span"], panel["span"],
                                    [caller, 4], [reset_entry, caller + 4 - reset_entry],
                                    *reset_guards],
                    "reader": shift_at - 4,
                    "store": store_at,
                    "status_branch": status_check["branch"],
                    "panel_branch": panel["branch"],
                }
                hits[(function, caller)] = evidence
    for site in _boot_gpio_bit9_panel_sites(image, called):
        hits[(site["reader"], site["caller"])] = site
    if not hits:
        return None, "boot-gpio-bit9-reset-linked-status-branch-absent"
    return {
        "behaviour": "boot_gpio_bit9",
        "reason": "accepted",
        "gpio": _GPIO720,
        "bit": 9,
        "value": 0,
        "sites": [hits[key] for key in sorted(hits)],
    }, "accepted"


def _boot_gpio_bit9_panel_sites(image: bytes, called: set[int]) -> list[dict]:
    """Find the reset-linked CS18 selector variant with a stored bit-9 branch."""
    results = []
    gpio_literal = struct.pack("<I", _GPIO720)
    for field_at in _find_all(image, gpio_literal):
        descriptor = field_at - 4
        if (field_at & 3 or descriptor < 0 or descriptor > len(image) - 8
                or _u32(image, field_at) != _GPIO720):
            continue
        for entry in _thumb_literal_loads_of(image, descriptor, 0):
            if entry + 20 > len(image) or _u16(image, entry + 2) != 0xB4F0:
                continue
            if struct.unpack_from("<5H", image, entry + 4) != (
                    0x6840, 0x6800, 0x0580, 0x0FC1,
                    _u16(image, entry + 12)):
                continue
            status_load = _u16(image, entry + 12)
            if status_load & 0xF800 != 0x4800 or (status_load >> 8) & 7 != 0:
                continue
            status_address = _thumb_literal(image, entry + 12, 0)
            if (status_address is None or not 0x14000000 <= status_address < 0x15000000
                    or _u16(image, entry + 14) != 0x2603
                    or _u16(image, entry + 16) != 0x06F6):
                continue

            branch_at = None
            low_path = None
            for cmp_at in range(entry + 18, min(entry + 0x40, len(image) - 6), 2):
                if _u16(image, cmp_at) != 0x2900:
                    continue
                if _u16(image, cmp_at + 2) != 0x7081:
                    continue
                branch = _u16(image, cmp_at + 4)
                target = _thumb_cond_b_target(branch, cmp_at + 4)
                if (branch & 0xFF00 != 0xD000 or target is None
                        or target <= cmp_at + 6 or target >= len(image) - 10):
                    continue
                clobbered = False
                for pc in range(entry + 12, cmp_at, 2):
                    writes = _thumb_writes_register(_u16(image, pc), 1)
                    if writes is None or writes:
                        clobbered = True
                        break
                if clobbered:
                    continue
                branch_at, low_path = cmp_at + 4, target
                break
            if branch_at is None or low_path is None:
                continue

            high_path = branch_at + 2
            high_load = _u16(image, high_path)
            if high_load & 0xF800 != 0x4800 or (high_load >> 8) & 7 != 1:
                continue
            high_handler = _thumb_literal(image, high_path, 1)
            if high_handler is None:
                continue
            if struct.unpack_from("<3H", image, high_path + 2) != (
                    0x6041, 0x202C, 0x7030):
                continue
            low_load = _u16(image, low_path)
            if low_load & 0xF800 != 0x4800 or (low_load >> 8) & 7 != 1:
                continue
            if (_thumb_literal(image, low_path, 1) != high_handler
                    or struct.unpack_from("<4H", image, low_path + 2)
                    != (0x3908, 0x6041, 0x20D1, 0x7030)):
                continue

            for wrapper_call in _thumb_calls_to(image, entry):
                wrapper = wrapper_call - 4
                if (wrapper < 0 or _u16(image, wrapper) & 0xFE00 != 0xB400
                        or not _u16(image, wrapper) & 0x0100
                        or _u16(image, wrapper + 2) != 0x1C04
                        or wrapper_call != wrapper + 4):
                    continue
                for caller in _thumb_calls_to(image, wrapper):
                    reset_entry = _thumb_nearest_push_lr(image, caller, 0x1000)
                    if (reset_entry is None or not any(
                            target in (reset_entry, reset_entry | 1) for target in called)):
                        continue
                    reset_guards = _reset_helper_source_spans(image, reset_entry | 1)
                    if not reset_guards:
                        continue
                    descriptor_pool = _thumb_literal_pool(image, entry, 0)
                    status_pool = _thumb_literal_pool(image, entry + 12, 0)
                    high_pool = _thumb_literal_pool(image, high_path, 1)
                    low_pool = _thumb_literal_pool(image, low_path, 1)
                    pools = [[pool, 4] for pool in
                             (descriptor_pool, status_pool, high_pool, low_pool)
                             if pool is not None]
                    caller_end = caller + 4
                    # The direct caller's prologue and branch prove reset
                    # linkage; the wrapper BL proves the intermediate edge.
                    site = {
                        "span": [entry, branch_at + 6 - entry],
                        "extra_spans": [*pools, [descriptor + 4, 4],
                                        [high_path, 8], [low_path, 10],
                                        [wrapper, wrapper_call + 4 - wrapper],
                                        [caller, 4],
                                        [reset_entry, caller_end - reset_entry],
                                        *reset_guards],
                        "reader": entry,
                        "store": branch_at - 2,
                        "status_branch": branch_at,
                        "panel_low_branch": low_path,
                        "caller": caller,
                    }
                    results.append(site)
    return results


def detect_external_status(image: bytes) -> tuple[dict | None, str]:
    """Detect a reset-linked halfword status compare that branches on one.

    The pool literal is 0x0B000400 and the load uses immediate +8. The
    immediate conditional branch and reset call linkage are part of the
    consumer shape; a matching compare in unrelated code does not select a
    status device.
    """
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-status-image-not-bytes"
    called = _reset_called(image)
    if not called:
        return None, "external-status-reset-unlinked"
    hits = []
    for register in range(8):
        ldrh = 0x8900 | (register << 3) | register
        lsl = (24 << 6) | (register << 3) | register
        lsr = (1 << 11) | (24 << 6) | (register << 3) | register
        cmp1 = 0x2800 | (register << 8) | 1
        needle = struct.pack("<4H", ldrh, lsl, lsr, cmp1)
        for at in _find_all(image, needle):
            if at < 2 or at & 1:
                continue
            if _thumb_literal(image, at - 2, register) != _STATUS_BASE:
                continue
            branch_at = at + 8
            if branch_at + 2 > len(image):
                continue
            branch = _u16(image, branch_at)
            branch_target = _thumb_cond_b_target(branch, branch_at)
            # CMP #1 must select a distinct forward path when the input is
            # not one. The taken target remains within the short consumer.
            if (branch & 0xFF00 != 0xD100 or branch_target is None
                    or branch_target <= branch_at + 2
                    or branch_target > at + 0x40):
                continue

            function = _thumb_nearest_push_lr(image, at - 2, 0x1000)
            if function is None:
                continue
            reset_entry = None
            caller = None
            if function in called or (function | 1) in called:
                reset_entry = function
            else:
                for candidate in _thumb_calls_to(image, function):
                    entry = _reset_push(image, candidate, called)
                    if entry is not None:
                        caller, reset_entry = candidate, entry
                        break
            if reset_entry is None:
                continue

            literal = _thumb_literal_pool(image, at - 2, register)
            if literal is None:
                continue
            extras = [[literal, 4], [function, branch_at + 2 - function],
                      *_reset_helper_source_spans(
                image, reset_entry | 1)]
            if caller is not None:
                extras.append([reset_entry, caller + 4 - reset_entry])
            hits.append({
                "at": at - 2, "register": register, "status": 0x0B000408,
                "branch": branch_at, "branch_target": branch_target,
                "function": function, "caller": caller,
                "reset_entry": reset_entry,
                "span": [at - 2, branch_at + 2 - (at - 2)],
                "extra_spans": extras,
            })
    if not hits:
        return None, "external-status-status-read-absent"
    return {"behaviour": "external_status", "reason": "accepted", "sites": hits}, "accepted"


def _shift_stores(image: bytes, immediate: int, shift: int) -> list[dict]:
    """``MOVS Rd, #imm; LSLS Rd, Rd, #shift; STRB/STRH ..., [Rd, #imm]``."""
    hits = []
    for register in range(8):
        lsl = (shift << 6) | (register << 3) | register
        needle = struct.pack("<H", lsl)
        for at in _find_all(image, needle):
            if at & 1 or at < 2:
                continue
            mov_at = None
            for gap in range(0, 4):
                candidate = at - 2 - gap * 2
                if candidate < 0:
                    break
                if _movs_imm(_u16(image, candidate), immediate) == register:
                    mov_at = candidate
                    break
                # Only a MOV immediate to some other register may sit in the gap.
                if _u16(image, candidate) & 0xF800 != 0x2000:
                    break
            if mov_at is None:
                continue
            store_at = None
            for step in range(1, 4):
                pc = at + step * 2
                if pc + 2 > len(image):
                    break
                word = _u16(image, pc)
                if word & 0xF800 == 0x2000:
                    # A MOVS to another register may prepare the stored
                    # value; rewriting the address register invalidates it.
                    if (word >> 8) & 7 == register:
                        break
                elif not _is_narrow_store(word, register):
                    break
                if _is_narrow_store(word, register):
                    store_at = pc
                    break
            if store_at is None:
                continue
            hits.append({
                "mov": mov_at,
                "lsl": at,
                "store": store_at,
                "register": register,
                "address": (immediate << shift) & 0xFFFFFFFF,
            })
    return hits


def _bit21_spins(image: bytes) -> list[dict]:
    """Observe a descriptor-linked bit-21 test that skips a terminal spin."""
    facts = facts_for(image)
    hits = []
    for branch in _find_all(image, bytes.fromhex("00d4fee7")):
        start = branch - 8
        if start < 0 or start & 1:
            continue
        entry = CodeAddress(start)
        literal = facts.literal(entry)
        if literal is None or literal.value & 3:
            continue
        pointer = literal.value
        if not 0 <= pointer <= len(image) - 8:
            continue
        function = facts.function(entry, budget=6)
        for test in facts.bit_tests(function):
            if (test.branch.address != branch or test.target != branch + 4
                    or not test.when_set or test.mask != 1 << 21
                    or test.read.address != _GPIO720 or test.read.width != 4
                    or test.read.instruction.address != branch - 4):
                continue
            if not any(access.instruction.address == start + 2
                       and access.operation == 'read' and access.width == 4
                       and access.address == pointer + 4 for access in function.accesses):
                continue
            hits.append({"at": start, "struct": pointer,
                         "gpio": _GPIO720, "spin": branch + 2})
    return hits


def _external_lcd_writers(image: bytes) -> list[dict]:
    """Return narrow writes whose code or literal resolves to an LCD bus."""
    shifted = [
        item for item in (_shift_stores(image, 7, 26)
                          + _shift_stores(image, 3, 27)
                          + _shift_stores(image, 0xD, 25))
        if _narrow_store_offset(_u16(image, item["store"]), item["register"])
        in _EXTERNAL_LCD_STORE_OFFSETS
    ]
    literal_windows = (0x18000000, 0x1A000000, 0x1C000000)
    accesses = _literal_window_accesses_many(image, literal_windows)
    literal_writers = []
    for base, items in accesses.items():
        for item in items:
            offset = item["address"] - base
            if (item["operation"] != "write" or item["access_size"] > 2
                    or offset not in _EXTERNAL_LCD_STORE_OFFSETS):
                continue
            literal_writers.append({
                "mov": item["load"], "lsl": item["load"],
                "store": item["use"], "register": None,
                "address": base, "effective_address": item["address"],
                "load": item["load"], "use": item["use"],
                "literal": item["literal"], "thumb": item["thumb"],
                "instruction_width": item["instruction_width"],
                "access_size": item["access_size"],
                "operation": item["operation"],
                "construction": "literal-linked",
            })
    for item in shifted:
        item.setdefault("access_size", 1 if _u16(image, item["store"]) & 0xF800 == 0x7000 else 2)
        item.setdefault("effective_address", item["address"] +
                        _narrow_store_offset(_u16(image, item["store"]), item["register"]))
        item.setdefault("operation", "write")
        item.setdefault("construction", "shifted-base")
    return sorted(shifted + literal_writers,
                  key=lambda item: (item["store"], item["address"], item["construction"]))


def detect_external_lcd(image: bytes) -> tuple[dict | None, str]:
    """Detect narrow writes through LCD bus windows or a bit-21 poll."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-lcd-image-not-bytes"
    writers = _external_lcd_writers(image)
    spins = _bit21_spins(image)
    if not writers and not spins:
        return None, "external-lcd-writer-and-bit21-absent"
    return {
        "behaviour": "external_lcd",
        "reason": "accepted",
        "writers": writers,
        "bit21": spins,
    }, "accepted"


