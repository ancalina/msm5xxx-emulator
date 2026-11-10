from __future__ import annotations

def detect_external_cs0a(image: bytes) -> tuple[dict | None, str]:
    """Detect linked configuration writes through the 0x0A000080 block."""
    from . import _cs_ctrl_sites, _cs_store_sites, _literal_window_accesses_many, _reset_called, _reset_helper_source_spans, _thumb_reset_function_end, source_prefix
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-cs0a-image-not-bytes"
    sites = ([{"kind": "chip-select", "at": at} for at in _cs_store_sites(image)] +[{"kind": "controller-config", "at": at} for at in _cs_ctrl_sites(image)])
    reset_called = _reset_called(image)
    if reset_called:
        accesses = _literal_window_accesses_many(source_prefix(image, 0x10000), (0x0A000000,))[0x0A000000]
        wanted = {0x0A0000A0, 0x0A0000B0}
        linked: dict[int, list[dict]] = {}
        for target in reset_called:
            if not target & 1:
                continue
            entry = target & ~1
            end = _thumb_reset_function_end(image, entry)
            if end is None:
                continue
            linked[target] = [item for item in accesses if item["operation"] == "write" and item["thumb"] and item["address"] in wanted and entry <= item["load"]
                < end]
        for target, found in linked.items():
            if {item["address"] for item in found} >= wanted:
                guards = _reset_helper_source_spans(image, target)
                entry = target & ~1
                end = _thumb_reset_function_end(image, entry)
                for item in found:
                    sites.append({ "kind": "literal-access", **item, "span":[item["load"], item["use"] + item["instruction_width"] - item["load"]],
                        "extra_spans":[[item["literal"], 4],[entry, end - entry], *guards], })
    if not sites:
        return None, "external-cs0a-controller-write-absent"
    return {"sites": sites}, "accepted"

def _literal_window_accesses_many(image: bytes, bases: tuple[int, ...], size: int = 0x1000,) -> dict[int, list[dict]]:
    """Find narrow literal-linked accesses for all windows in one scan."""
    from . import facts_for
    result = {base:[] for base in bases}
    ranges = tuple((base, base + size) for base in bases)
    facts = facts_for(bytes(image))
    candidates = facts.literal_access_candidates(ranges, limit=len(image))
    for candidate in candidates:
        literal = facts.literal(candidate.load)
        if literal is None:
            continue
        pointer = literal.value
        selected = next((base for base, end in ranges if base <= pointer < end), None)
        if (selected is None or not selected <= candidate.address or candidate.address + candidate.width > selected + size):
            continue
        result[selected].append({ "load": candidate.load.address, "use": candidate.use.address, "literal": candidate.literal, "thumb": candidate.load.isa ==
            "thumb", "instruction_width": 2 if candidate.load.isa == "thumb" else 4, "address": candidate.address, "access_size": candidate.width, "operation":
            candidate.operation, })
    for accesses in result.values():
        accesses.sort(key=lambda item: (item["load"], item["use"], item["instruction_width"]))
    return result

def _literal_window_accesses(image: bytes, base: int, size: int = 0x1000) -> list[dict]:
    """Compatibility wrapper for one literal-linked window."""
    from . import _literal_window_accesses_many
    return _literal_window_accesses_many(image, (base,), size)[base]

def detect_external_cs09(image: bytes) -> tuple[dict | None, str]:
    """Detect data access outside the single-byte strap read at +0x70."""
    from . import _literal_window_accesses_many
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-cs09-image-not-bytes"
    accesses = [item for item in _literal_window_accesses_many(image, (0x09000000,))[0x09000000] if not (item["operation"] == "read" and item["address"] ==
        0x09000070 and item["access_size"] == 1)]
    if not accesses:
        return None, "external-cs09-access-absent"
    return {"accesses": accesses}, "accepted"

def detect_external_windows(image: bytes) -> tuple[dict | None, str]:
    """Return only literal-linked accesses for independently used windows."""
    from . import _literal_window_accesses_many, _thumb_shifted_08c_stores
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-window-image-not-bytes"
    bases = (0x08C00000, 0x1A000000, 0x0B000000, 0x18000000, 0x1C000000)
    found = _literal_window_accesses_many(image, bases)
    found[0x08C00000].extend(_thumb_shifted_08c_stores(image))
    found[0x08C00000].sort(key=lambda item: (item["load"], item["use"], item["instruction_width"]))
    profiles = {f"{base:08x}": found[base] for base in bases}
    if not any(profiles.values()):
        return None, "external-window-access-absent"
    return profiles, "accepted"

def _thumb_shifted_08c_stores(image: bytes) -> list[dict]:
    """Find closed MOVS/LSLS/STR accesses through the 0x08C00000 window."""
    from . import _find_all, _u16, struct
    accesses = []
    for register in range(8):
        mov = 0x2000 | (register << 8) | 0x23
        shift = (22 << 6) | (register << 3) | register
        for at in _find_all(image, struct.pack("<2H", mov, shift)):
            if at & 1 or at + 6 > len(image):
                continue
            store = _u16(image, at + 4)
            if (store & 0xF800 != 0x6000 or (store >> 3) & 7 != register):
                continue
            offset = ((store >> 6) & 31) * 4
            if offset not in (4, 0x0C):
                continue
            accesses.append({ "load": at, "use": at + 4, "literal": None, "thumb": True, "instruction_width": 2, "address": 0x08C00000 + offset, "access_size":
                4, "operation": "write", "construction": "thumb-shifted-base", })
    return accesses

def detect_gpio_ready_bit21(image: bytes) -> tuple[dict | None, str]:
    """Select the GPIO bit-21 input only when its exact poll is present."""
    from . import _GPIO720, _bit21_spins
    if not isinstance(image, (bytes, bytearray)):
        return None, "gpio-ready-image-not-bytes"
    spins = _bit21_spins(image)
    if not spins:
        return None, "gpio-ready-bit21-poll-absent"
    return {"sites": spins, "gpio": _GPIO720, "bit": 21}, "accepted"

def detect_external_panel_writers(image: bytes) -> tuple[dict | None, str]:
    """Detect command stores independently of GPIO-ready polling."""
    from . import _external_lcd_writers
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-panel-image-not-bytes"
    writers = _external_lcd_writers(image)
    if not writers:
        return None, "external-panel-writer-absent"
    return {"writers": writers}, "accepted"

def _bit3_polls(image: bytes) -> list[dict]:
    """Infinite poll of UART status +4 bit 3, kicking 0x030006D0."""
    from . import _DOG, _UART_BASE, _find_all, _thumb_b_target, _thumb_literal, _u16, struct
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
    from . import _UART_BASE, _thumb_literal, _u16
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
        elif (at + 8 <= len(image) and image[at + 4:at + 8] == b"\x08\x73\x08\x73" and _u16(image, at + 2) & 0xF800 == 0x4800 and (_u16(image, at + 2) >> 8) & 7
            == 1 and _thumb_literal(image, at + 2, 1) == _UART_BASE):
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
            if (word & 0xF800 == 0x2000 and (word >> 8) & 7 == 1 or word & 0xFF00 == 0x4900):
                break
        if base_load is not None:
            sites.append(at)
    return sites

def _push_lr(image: bytes, at: int) -> int | None:
    from . import _u16
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
    from . import _bit3_polls, _push_lr, _thumb_bl_target, _uart_cr_inits
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
                    linked.append({ "init": init, "poll": target, "link": "bl", "bl": pc, })
                    break
    if not linked:
        return None, "boot-uart-init-poll-unlinked"
    return { "behaviour": "boot_uart", "reason": "accepted", "links": linked, "polls":[item["at"] for item in polls], "inits": inits, }, "accepted"

def _reset_push(image: bytes, at: int, called: set[int]) -> int | None:
    """Nearest ``PUSH`` of ``lr`` at or before ``at`` that reset actually calls."""
    from . import _u16
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
    from . import _find_all, _thumb_literal, _u16, struct
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
                if (at >= 4 and add & 0xFF00 == (0x3000 | (register << 8)) and (add & 0xFF)):
                    base = _thumb_literal(image, at - 4, register)
                    if (base is not None and (base + (add & 0xFF)) & 0xFFFFFFFF == 0x09000070):
                        load_at = at - 4
            if load_at is None:
                continue
            branch = _u16(image, at + 4)
            if branch & 0xFF00 != 0xD400:
                continue
            imm8 = branch & 0xFF
            if not 0 < imm8 < 0x80:
                continue
            hits.append({ "at": load_at, "register": register, "branch": at + 4, "target": at + 4 + 4 + (imm8 << 1), })
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
    from . import CodeAddress, a, facts_for
    if at < 0 or at + 2 > len(image) or at & 1:
        return None
    facts = facts_for(image)
    literal = facts.literal(CodeAddress(facts.base + at))
    return (literal.pool - facts.base if literal is not None and literal.register == a.ARM_REG_R0 + register and 0 <= register <= 7 else None)

def _thumb_literal_loads_of(image: bytes, value: int, register: int, code_limit: int = 0x100000) -> list[int]:
    from . import a, facts_for
    facts = facts_for(image)
    limit = facts.base + min(len(image), code_limit)
    references = (item for item in facts.literal_references(value) if item.instruction.isa == 'thumb' and item.register == a.ARM_REG_R0 + register and 0 <=
        register <= 7 and facts.base <= item.pool <= limit - 4 and max(facts.base, item.pool - 0x400) <= item.instruction.address < item.pool)
    return [item.instruction.address - facts.base for item in sorted(references, key=lambda item: (item.pool, item.instruction.address))]

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
    if word & 0xF800 in (0x6000, 0x6800, 0x7000, 0x7800, 0x8000, 0x8800):
        return (word & 7) == register and bool(word & 0x0800)
    if word & 0xF000 == 0x5000:  # register-offset load/store
        operation = (word >> 9) & 7
        return (word >> 0) & 7 == register and operation >= 3
    if word & 0xF000 == 0xC000:  # STM/LDM also update their base register.
        return ((word >> 8) & 7) == register or bool(word & 0x0800 and word & (1 << register))
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
    from . import _u16, _u32, struct
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
        if not (words[0] & 0xFFFFF000 == 0xE59F4000 and words[1] == 0xE3140001 and words[2] & 0xFFFFF000 == 0x159FE000 and words[3] & 0xFFFFF000 == 0x059FE000
            and words[4] == 0xE12FFF14):
            continue
        target_pool = pc + 8 + (words[0] & 0xFFF)
        return_pool = pc + 20 + (words[3] & 0xFFF)
        if (target_pool > len(image) - 4 or return_pool > len(image) - 4 or _u32(image, return_pool) != pc + 24 or _u32(image, target_pool) != wanted):
            continue
        spans = [[0, 4],[pc, 20],[target_pool, 4],[return_pool, 4]]
        if wanted & 1:
            thumb_return_pool = pc + 16 + (words[2] & 0xFFF)
            if (thumb_return_pool > len(image) - 4 or _u32(image, thumb_return_pool) != (pc + 20) | 1 or _u16(image, pc + 20) != 0x4778):
                continue
            spans.extend(([pc + 20, 2],[thumb_return_pool, 4]))
        return spans
    return []

def _thumb_reset_function_end(image: bytes, entry: int) -> int | None:
    """End of a short reset-called Thumb routine with a closed return."""
    from . import _u16
    start = entry & ~1
    for pc in range(start, min(start + 0x800, len(image) - 2), 2):
        word = _u16(image, pc)
        if word == 0x4770 or (word & 0xFE00 == 0xBC00 and word & 0x0100):
            return pc + 2
    return None
