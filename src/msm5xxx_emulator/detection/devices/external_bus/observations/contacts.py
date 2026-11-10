from __future__ import annotations

def _thumb_nearest_push_lr(image: bytes, at: int, distance: int = 0x800) -> int | None:
    from . import _u16
    for pc in range(at - 2, max(-1, at - distance), -2):
        if _u16(image, pc) & 0xFE00 == 0xB400 and _u16(image, pc) & 0x0100:
            return pc
    return None

def _thumb_calls_to(image: bytes, target: int) -> list[int]:
    from . import facts_for
    facts = facts_for(image)
    return [site - facts.base for site, destination in facts.call_candidates('thumb') if destination == facts.base + target]

def _status_zero_branch(image: bytes, entry: int, status_address: int) -> dict | None:
    from . import _thumb_cond_b_target, _thumb_literal, _thumb_literal_pool, _thumb_writes_register, _u16
    start = entry & ~1
    for literal_at in range(start, min(start + 8, len(image) - 2), 2):
        if _thumb_literal(image, literal_at, 0) != status_address:
            continue
        for load_at in range(literal_at + 2, min(literal_at + 0x20, len(image) - 2), 2):
            load = _u16(image, load_at)
            if (load & 0xF800 != 0x7800 or (load >> 3) & 7 != 0 or (load >> 6) & 0x1F != 1):
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
            if (branch & 0xFF00 != 0xD000 or target is None or target <= branch_at + 2 or target >= start + 0x200):
                continue
            return { "entry": start, "literal": _thumb_literal_pool(image, literal_at, 0), "literal_at": literal_at, "load": load_at, "branch": branch_at,
                "branch_target": target, "span":[start, max(branch_at + 2, target + 2) - start], }
    return None

def _status_panel_branch(image: bytes, entry: int, status_address: int) -> dict | None:
    from . import _thumb_b_target, _thumb_cond_b_target, _thumb_literal, _thumb_literal_pool, _u16, struct
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
    return { "entry": start, "literal": _thumb_literal_pool(image, literal_at, 0), "branch": branch_at, "branch_target": low, "span":[start, low + 6 - start], }

def detect_boot_gpio_bit9(image: bytes) -> tuple[dict | None, str]:
    """Detect a reset-linked GPIO bit-9 status path selecting the low panel branch."""
    from . import _GPIO720, _boot_gpio_bit9_panel_sites, _find_all, _reset_called, _reset_helper_source_spans, _status_panel_branch, _status_zero_branch, _thumb_bl_target, _thumb_calls_to, _thumb_literal, _thumb_literal_pool, _thumb_nearest_push_lr, _thumb_writes_register, _u16, _u32, struct
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
            if (first_load & 0xF800 != 0x6800 or first_load & 7 != register or (first_load >> 6) & 0x1F != 1):
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
            if (store & 0xF800 != 0x7000 or (store >> 3) & 7 != status_register or store & 7 != register or (store >> 6) & 0x1F != 1):
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
                if reset_entry is None or not any(target in (reset_entry, reset_entry | 1) for target in called):
                    continue
                reset_guards = _reset_helper_source_spans(image, reset_entry | 1)
                if not reset_guards:
                    continue
                pools = []
                for pc, reg in ((descriptor_load, base_register), (status_literal_at, status_register), (status_check["literal_at"], 0), (panel_target, 0)):
                    pool = _thumb_literal_pool(image, pc, reg)
                    if pool is not None:
                        pools.append([pool, 4])
                evidence = { "span":[function, second_bl + 4 - function], "extra_spans":[*pools,[descriptor + 4, 4], status_check["span"], panel["span"],[caller,
                    4],[reset_entry, caller + 4 - reset_entry], *reset_guards], "reader": shift_at - 4, "store": store_at, "status_branch": status_check["branch"],
                    "panel_branch": panel["branch"], }
                hits[(function, caller)] = evidence
    for site in _boot_gpio_bit9_panel_sites(image, called):
        hits[(site["reader"], site["caller"])] = site
    if not hits:
        return None, "boot-gpio-bit9-reset-linked-status-branch-absent"
    return { "behaviour": "boot_gpio_bit9", "reason": "accepted", "gpio": _GPIO720, "bit": 9, "value": 0, "sites":[hits[key] for key in sorted(hits)], }, "accepted"

def _boot_gpio_bit9_panel_sites(image: bytes, called: set[int]) -> list[dict]:
    """Find the reset-linked CS18 selector variant with a stored bit-9 branch."""
    from . import _GPIO720, _find_all, _reset_helper_source_spans, _thumb_calls_to, _thumb_cond_b_target, _thumb_literal, _thumb_literal_loads_of, _thumb_literal_pool, _thumb_nearest_push_lr, _thumb_writes_register, _u16, _u32, struct
    results = []
    gpio_literal = struct.pack("<I", _GPIO720)
    for field_at in _find_all(image, gpio_literal):
        descriptor = field_at - 4
        if (field_at & 3 or descriptor < 0 or descriptor > len(image) - 8 or _u32(image, field_at) != _GPIO720):
            continue
        for entry in _thumb_literal_loads_of(image, descriptor, 0):
            if entry + 20 > len(image) or _u16(image, entry + 2) != 0xB4F0:
                continue
            if struct.unpack_from("<5H", image, entry + 4) != (0x6840, 0x6800, 0x0580, 0x0FC1, _u16(image, entry + 12)):
                continue
            status_load = _u16(image, entry + 12)
            if status_load & 0xF800 != 0x4800 or (status_load >> 8) & 7 != 0:
                continue
            status_address = _thumb_literal(image, entry + 12, 0)
            if (status_address is None or not 0x14000000 <= status_address < 0x15000000 or _u16(image, entry + 14) != 0x2603 or _u16(image, entry + 16) !=
                0x06F6):
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
                if (branch & 0xFF00 != 0xD000 or target is None or target <= cmp_at + 6 or target >= len(image) - 10):
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
            if struct.unpack_from("<3H", image, high_path + 2) != (0x6041, 0x202C, 0x7030):
                continue
            low_load = _u16(image, low_path)
            if low_load & 0xF800 != 0x4800 or (low_load >> 8) & 7 != 1:
                continue
            if (_thumb_literal(image, low_path, 1) != high_handler or struct.unpack_from("<4H", image, low_path + 2) != (0x3908, 0x6041, 0x20D1, 0x7030)):
                continue
            for wrapper_call in _thumb_calls_to(image, entry):
                wrapper = wrapper_call - 4
                if (wrapper < 0 or _u16(image, wrapper) & 0xFE00 != 0xB400 or not _u16(image, wrapper) & 0x0100 or _u16(image, wrapper + 2) != 0x1C04 or
                    wrapper_call != wrapper + 4):
                    continue
                for caller in _thumb_calls_to(image, wrapper):
                    reset_entry = _thumb_nearest_push_lr(image, caller, 0x1000)
                    if (reset_entry is None or not any(target in (reset_entry, reset_entry | 1) for target in called)):
                        continue
                    reset_guards = _reset_helper_source_spans(image, reset_entry | 1)
                    if not reset_guards:
                        continue
                    descriptor_pool = _thumb_literal_pool(image, entry, 0)
                    status_pool = _thumb_literal_pool(image, entry + 12, 0)
                    high_pool = _thumb_literal_pool(image, high_path, 1)
                    low_pool = _thumb_literal_pool(image, low_path, 1)
                    pools = [[pool, 4] for pool in (descriptor_pool, status_pool, high_pool, low_pool) if pool is not None]
                    caller_end = caller + 4
                    # The direct caller's prologue and branch prove reset
                    # linkage; the wrapper BL proves the intermediate edge.
                    site = { "span":[entry, branch_at + 6 - entry], "extra_spans":[*pools,[descriptor + 4, 4],[high_path, 8],[low_path, 10],[wrapper,
                        wrapper_call + 4 - wrapper],[caller, 4],[reset_entry, caller_end - reset_entry], *reset_guards], "reader": entry, "store": branch_at - 2,
                        "status_branch": branch_at, "panel_low_branch": low_path, "caller": caller, }
                    results.append(site)
    return results

def detect_external_status(image: bytes) -> tuple[dict | None, str]:
    """Detect a reset-linked halfword status compare that branches on one.

    The pool literal is 0x0B000400 and the load uses immediate +8. The
    immediate conditional branch and reset call linkage are part of the
    consumer shape; a matching compare in unrelated code does not select a
    status device.
    """
    from . import _STATUS_BASE, _find_all, _reset_called, _reset_helper_source_spans, _reset_push, _thumb_calls_to, _thumb_cond_b_target, _thumb_literal, _thumb_literal_pool, _thumb_nearest_push_lr, _u16, struct
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
            if (branch & 0xFF00 != 0xD100 or branch_target is None or branch_target <= branch_at + 2 or branch_target > at + 0x40):
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
            extras = [[literal, 4],[function, branch_at + 2 - function], *_reset_helper_source_spans(image, reset_entry | 1)]
            if caller is not None:
                extras.append([reset_entry, caller + 4 - reset_entry])
            hits.append({ "at": at - 2, "register": register, "status": 0x0B000408, "branch": branch_at, "branch_target": branch_target, "function": function,
                "caller": caller, "reset_entry": reset_entry, "span":[at - 2, branch_at + 2 - (at - 2)], "extra_spans": extras, })
    if not hits:
        return None, "external-status-status-read-absent"
    return {"behaviour": "external_status", "reason": "accepted", "sites": hits}, "accepted"

def _shift_stores(image: bytes, immediate: int, shift: int) -> list[dict]:
    """``MOVS Rd, #imm; LSLS Rd, Rd, #shift; STRB/STRH ..., [Rd, #imm]``."""
    from . import _find_all, _is_narrow_store, _movs_imm, _u16, struct
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
            hits.append({ "mov": mov_at, "lsl": at, "store": store_at, "register": register, "address": (immediate << shift) & 0xFFFFFFFF, })
    return hits

def _bit21_spins(image: bytes) -> list[dict]:
    """Observe a descriptor-linked bit-21 test that skips a terminal spin."""
    from . import CodeAddress, _GPIO720, _find_all, facts_for
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
            if (test.branch.address != branch or test.target != branch + 4 or not test.when_set or test.mask != 1 << 21 or test.read.address != _GPIO720 or test.read.width
                != 4 or test.read.instruction.address != branch - 4):
                continue
            if not any(access.instruction.address == start + 2 and access.operation == 'read' and access.width == 4 and access.address == pointer + 4 for access
                in function.accesses):
                continue
            hits.append({"at": start, "struct": pointer, "gpio": _GPIO720, "spin": branch + 2})
    return hits

def _external_lcd_writers(image: bytes) -> list[dict]:
    """Return narrow writes whose code or literal resolves to an LCD bus."""
    from . import _EXTERNAL_LCD_STORE_OFFSETS, _literal_window_accesses_many, _narrow_store_offset, _shift_stores, _u16
    shifted = [item for item in (_shift_stores(image, 7, 26) + _shift_stores(image, 3, 27) + _shift_stores(image, 0xD, 25)) if _narrow_store_offset(_u16(image,
        item["store"]), item["register"]) in _EXTERNAL_LCD_STORE_OFFSETS]
    literal_windows = (0x18000000, 0x1A000000, 0x1C000000)
    accesses = _literal_window_accesses_many(image, literal_windows)
    literal_writers = []
    for base, items in accesses.items():
        for item in items:
            offset = item["address"] - base
            if (item["operation"] != "write" or item["access_size"] > 2 or offset not in _EXTERNAL_LCD_STORE_OFFSETS):
                continue
            literal_writers.append({ "mov": item["load"], "lsl": item["load"], "store": item["use"], "register": None, "address": base, "effective_address":
                item["address"], "load": item["load"], "use": item["use"], "literal": item["literal"], "thumb": item["thumb"], "instruction_width": item["instruction_width"],
                "access_size": item["access_size"], "operation": item["operation"], "construction": "literal-linked", })
    for item in shifted:
        item.setdefault("access_size", 1 if _u16(image, item["store"]) & 0xF800 == 0x7000 else 2)
        item.setdefault("effective_address", item["address"] + _narrow_store_offset(_u16(image, item["store"]), item["register"]))
        item.setdefault("operation", "write")
        item.setdefault("construction", "shifted-base")
    return sorted(shifted + literal_writers, key=lambda item: (item["store"], item["address"], item["construction"]))
