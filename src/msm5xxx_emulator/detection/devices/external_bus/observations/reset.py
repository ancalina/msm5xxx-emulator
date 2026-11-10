from __future__ import annotations

PAGE = 0x1000
_HIGH_RAM_TEST_PREFIX = bytes.fromhex("54019fe5000090e50110a0e30020a0e3")
_EXTENTS = (0x1FFFFF, 0x3FFDFF, 0x3FFFFF, 0x7FFDFF, 0x7FFFFF)
_RAM_PATTERN = (0x10, 0x55AA0F, 0xAA0F, 0x55, 0x030006D0)
_UART_BASE = 0x03000B10
_DOG = 0x030006D0
_GPIO720 = 0x03000720
_STATUS_BASE = 0x0B000400

def _u16(image: bytes, at: int) -> int:
    from . import struct
    return struct.unpack_from("<H", image, at)[0]

def _u32(image: bytes, at: int) -> int:
    from . import struct
    return struct.unpack_from("<I", image, at)[0]

def _find_all(image: bytes, needle: bytes, limit: int | None = None) -> list[int]:
    from . import facts_for
    end = len(image) if limit is None else min(len(image), limit)
    if not needle:
        return list(range(max(0, end)))
    facts = facts_for(image)
    return [at - facts.base for at in facts.string_candidates(needle) if facts.base <= at and at + len(needle) <= facts.base + end]

def _thumb_literal(image: bytes, at: int, register: int) -> int | None:
    from . import facts_for
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
    from . import facts_for
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
    from . import _u16, _u32, struct
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
        if not (words[0] & 0xFFFFF000 == 0xE59F4000 and words[1] == 0xE3140001 and words[2] & 0xFFFFF000 == 0x159FE000 and words[3] & 0xFFFFF000 == 0x059FE000
            and words[4] == 0xE12FFF14):
            continue
        literal = pc + 8 + (words[0] & 0xFFF)
        return_literal = pc + 20 + (words[3] & 0xFFF)
        if not (literal <= len(image) - 4 and return_literal <= len(image) - 4 and _u32(image, return_literal) == pc + 24):
            continue
        target = _u32(image, literal)
        if target & 1:
            thumb_return = pc + 16 + (words[2] & 0xFFF)
            if (thumb_return > len(image) - 4 or _u32(image, thumb_return) != (pc + 20) | 1 or _u16(image, pc + 20) != 0x4778):
                continue
        called.add(target)
    return called

_BODY_FIELD_PTRS = ((0, 0), (0x10, 8), (0x40, 24), (0x6C, 4), (0x80, 4), (0xF4, 12), (0x108, 16), (0x11C, 20),)

def _table_from_body(image: bytes, position: int) -> int | None:
    """Descriptor address from the body's own field-pointer literals.

    Firmware layouts may place data between the descriptor and body, so
    the table is not always adjacent. The first LDR's pool word is the
    descriptor address; the other seven must point at corresponding fields.
    """
    from . import _BODY_FIELD_PTRS, _u32
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
    from . import _arm_branch_delta, _arm_immediate, _u32
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
    from . import _u32
    layouts = []
    if position >= 28 and _u32(image, position - 28) == 0x14000000:
        layouts.append((position - 28, position))
    if (position >= 60 and not position & 3 and image[position - 20:position] == bytes.fromhex("5c019fe558019fe554019fe554019fe554019fe5") and _u32(image,
        position - 60) == 0x14000000):
        table, entry = position - 60, position - 20
        valid = True
        for offset, field in ((0, 28), (4, 28), (8, 28), (12, 32), (16, 36)):
            instruction = _u32(image, entry + offset)
            literal = entry + offset + 8 + (instruction & 0xFFF)
            if (literal > len(image) - 4 or _u32(image, literal) != table + field):
                valid = False
                break
        if valid:
            layouts.append((table, entry))
    if len(layouts) != 1:
        return None
    return layouts[0]

def _reset_copy_covers_upper_half(image: bytes, called: set[int], base: int, size: int) -> bool:
    from . import _thumb_literal, _u32, struct
    shapes = ((0x4800, 0x6804, 0x4800, 0x6800, 0x1826, 0x4800, 0x6805, 0xE001, 0xCD01, 0xC401, 0x42B4, 0xD3FB), (0x4A00, 0x6814, 0x4A00, 0x6812, 0x18A6, 0x4A00,
        0x6815, 0xE001, 0xCD04, 0xC404, 0x42B4, 0xD3FB),)
    for target in called:
        if not target & 1:
            continue
        start = target & ~1
        for pc in range(start, min(start + 0x400, len(image) - 23), 2):
            words = struct.unpack_from("<12H", image, pc)
            normalized = tuple(word & 0xFF00 if i in (0, 2, 5) else word for i, word in enumerate(words))
            if normalized not in shapes:
                continue
            register = (words[0] >> 8) & 7
            pointers = [_thumb_literal(image, pc + offset, register) for offset in (0, 4, 10)]
            if any(p is None or p & 3 or p > len(image) - 4 for p in pointers):
                continue
            destination_ptr, length_ptr, source_ptr = pointers
            if length_ptr != destination_ptr + 4 or source_ptr != destination_ptr - 4:
                continue
            destination, length, source = (_u32(image, p) for p in pointers)
            if (not (destination | length | source) & 3 and length > 0 and source + length <= len(image) and base + size // 2 <= destination < destination +
                length <= base + size):
                return True
    return False

def _cs_store_sites(image: bytes) -> list[int]:
    """Thumb tail that writes the 0x0A000080 chip-select block.

    The two pool loads are the only varying immediates. Both must be the
    chip-select pointer, and the same pointer is stored through earlier
    in the function at offset +0x20.
    """
    from . import _thumb_literal, _u16, struct
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
        if (_thumb_literal(image, at + 4, 2) != 0x0A000080 or _thumb_literal(image, at + 10, 2) != 0x0A000080):
            continue
        window = image[max(0, at - 0x80):at]
        linked = False
        for back in range(0, len(window) - 4, 2):
            pc = max(0, at - 0x80) + back
            if pc & 1:
                continue
            load = _u16(image, pc)
            store = _u16(image, pc + 2)
            if (load & 0xF800 == 0x4800 and (load >> 8) & 7 == 2 and store == 0x6211 and _thumb_literal(image, pc, 2) == 0x0A000080):
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
    from . import _thumb_literal, _u16
    sites = []
    for needle in (bytes.fromhex("086288624862"), bytes.fromhex("0862002088624862")):
        start = 0
        while True:
            at = image.find(needle, start)
            if at < 0:
                break
            start = at + 2
            if at & 1 or at < 2:
                continue
            load = at - 2
            if (_u16(image, load) & 0xF800 != 0x4800 or (_u16(image, load) >> 8) & 7 != 1):
                continue
            if _thumb_literal(image, load, 1) != 0x0A000080:
                continue
            window_end = min(len(image) - 6, at + 0x30)
            linked = False
            for pc in range(at + 2, window_end, 2):
                word = _u16(image, pc)
                if not (word & 0xF800 == 0x4800 and (word >> 8) & 7 == 1 and _thumb_literal(image, pc, 1) == 0x0A000080):
                    continue
                add = _u16(image, pc + 2)
                store = _u16(image, pc + 4)
                # ADDS r1, #0x40; STR Rt, [r1, #0x10]
                if (add == 0x3140 and store & 0xF800 == 0x6000 and (store >> 3) & 7 == 1 and (store >> 6) & 31 == 4):
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
    from . import PAGE, _EXTENTS, _HIGH_RAM_TEST_PREFIX, _RAM_PATTERN, _find_all, _high_ram_layout, _ram_test_body_shape, _reset_called, _reset_copy_covers_upper_half, _table_from_body, _u32, source_prefix, struct
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
        base, extent, stride, word, half, byte, watchdog = struct.unpack_from("<7I", image, table)
        if (base != 0x14000000 or extent not in _EXTENTS or (stride, word, half, byte, watchdog) != _RAM_PATTERN):
            continue
        valid = True
        for offset, field in ((0, 0), (0x10, 8), (0x40, 24), (0x6C, 4), (0x80, 4), (0xF4, 12), (0x108, 16), (0x11C, 20)):
            instruction = _u32(image, position + offset)
            literal = position + offset + 8 + (instruction & 0xFFF)
            if (literal > len(image) - 4 or _u32(image, literal) != table + field):
                valid = False
                break
        if not valid or called is None:
            continue
        size = (extent + PAGE) & ~(PAGE - 1)
        linked = entry in called or (entry == position and _reset_copy_covers_upper_half(image, called, base, size))
        if linked:
            ram_hits.append({ "kind": "ram-test", "table": table, "entry": entry, "body": position, "base": base, "extent": extent, "size": size, })
    if len(ram_hits) > 1:
        return None, "external-ram-ram-test-ambiguous"
    if len(ram_hits) == 1:
        return { "behaviour": "external_ram", "reason": "accepted", "ram_test": ram_hits[0], }, "accepted"
    if called is None:
        return None, "external-ram-reset-unlinked"
    return None, "external-ram-shape-absent"
