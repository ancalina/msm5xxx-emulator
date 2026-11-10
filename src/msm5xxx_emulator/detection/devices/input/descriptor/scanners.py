from __future__ import annotations
import re

LG_DESCRIPTOR_RAW = "lg-descriptor-raw-keypad-v1"
LG_DESCRIPTOR_RAW_FINGERPRINT = "lg-descriptor-low5-6x5-raw-v1"
RAW_CONSUMER_EVIDENCE = "shared-byte-ring32-r0-task-dispatch-v1"
LG_OBSERVED_SEMANTIC_FINGERPRINT = "lg-6x5-unique-event-semantics-v1"
LG_OBSERVED_KEY_EVENTS = { 0: 0x09, 1: 0x85, 2: 0x52, 3: 0x50, 4: 0x87, 5: 0x8D, 6: 0x88, 8: 0x8C, 9: 0x86, 10: 0x8B, 11: 0x31, 12: 0x32, 13: 0x33, 14: 0x34, 15:
    0x35, 16: 0x36, 17: 0x37, 18: 0x38, 19: 0x39, 20: 0x2A, 21: 0x30, 22: 0x23, }
RAW_RING_STORE = re.compile(rb".\x4a\x04\x04\x50\x78\x24\x0c\x13\x78\x41\x1c" rb"\xc9\x06\xc9\x0e\x99\x42.{0,12}\x80\x18(?P<store>\x87\x70)"
    rb"\x50\x78\x01\x30\xc0\x06\xc0\x0e\x50\x70", re.S,)
RAW_DEQUEUE_HEAD = re.compile(rb"\xf0\xb5.\x4c\x86\xb0\x60\x78\x21\x78\x88\x42", re.S)
RAW_THUMB_BL = re.compile(rb".[\xf0-\xf7].[\xf8-\xff]", re.S)
DESCRIPTOR_SCAN_ANCHORS = (("row-drive-register-mask", re.compile(rb".\x8d\x49\x09\x49\x01\x01\x22.\x40\x12\x06\x12\x0e"
    rb".{0,8}\xd2\x43.{0,8}\x11\x43.\x85.\x8d.\x6a\x11\x80", re.S)), ("row-drive-immediate-mask5", re.compile(rb".\x8d\x49\x09\x49\x01.{0,12}\x1f\x23.{0,16}"
    rb".\x85.\x8d.\x6a\x11\x80", re.S)),)
DESCRIPTOR_MMIO_ROLES = { 0x00: 0x03000720, 0x08: 0x0300072C, 0x10: 0x03000724, 0x18: 0x03000730, 0x20: 0x03000728, 0x28: 0x03000734, 0x34: 0x0300072C, }

def find_descriptor_scan_anchors(image: bytes, load_address: int = 0) -> list[dict[str, object]]:
    """Find descriptor row-drive anchors; not a sense/no-key transport."""
    from . import DESCRIPTOR_SCAN_ANCHORS, _thumb_fingerprint, _thumb_function_start
    found: dict[int, dict[str, object]] = {}
    for variant, grammar in DESCRIPTOR_SCAN_ANCHORS:
        for match in grammar.finditer(image):
            site = match.start()
            if site & 1:
                continue
            start = _thumb_function_start(image, site)
            if start in found:
                found[start]["variants"] = sorted({*found[start]["variants"], variant})
                continue
            fingerprint, size, boundary = _thumb_fingerprint(image, start)
            found[start] = { "grammar": "descriptor-row-drive-anchor-v1", "variants":[variant], "function": load_address + start, "anchor": load_address + site,
                "sense_bits": None, "no_key": None, "absolute_register": None, "evidence": "structural-only", "semantic_limit":
                "drive-side only; sense/no-key unresolved", "fingerprint": fingerprint, "fingerprint_size": size, "fingerprint_scope": "linear-prefix",
                "fingerprint_boundary": boundary, }
    return [found[start] for start in sorted(found)]

def find_lg_descriptor_scan_anchors(image: bytes, load_address: int = 0) -> list[dict[str, object]]:
    """Compatibility alias for the cross-vendor descriptor grammar."""
    from . import find_descriptor_scan_anchors
    return find_descriptor_scan_anchors(image, load_address)

def _last_literal(image: bytes, start: int, position: int, register: int) -> int | None:
    from . import facts_for
    for current in range(position - 2, start - 1, -2):
        if current + 2 <= len(image):
            value = facts_for(image).thumb_literal_value(current, register)
            if value is not None:
                return value
    return None

def _descriptor_pointer(image: bytes, start: int, sense_sites: list[int]) -> int | None:
    """Recover one RAM descriptor even when later senses use a register alias."""
    from . import _last_literal, struct
    pointers = { value for site in sense_sites if (value := _last_literal(image, start, site, struct.unpack_from("<H", image, site)[0] >> 3 & 7,)) is not None
        and 0x01000000 <= value < 0x02000000 }
    return next(iter(pointers)) if len(pointers) == 1 else None

def _observed_lg_mappings(events: list[int]) -> dict[int, dict[str, object]]:
    """Publish semantics only when complete observed event set is unique."""
    from . import LG_OBSERVED_KEY_EVENTS, LG_OBSERVED_SEMANTIC_FINGERPRINT
    if any(events.count(event) != 1 for event in LG_OBSERVED_KEY_EVENTS.values()):
        return {}
    return { bit: { "event": event, "rule": "temporary-evidence-gated-unique-event-set", "evidence": "firmware-table-unique-events+observed-key-semantics",
        "semantic_grammar_fingerprint": LG_OBSERVED_SEMANTIC_FINGERPRINT, } for bit, event in LG_OBSERVED_KEY_EVENTS.items() }

def _raw_consumer_metadata(image: bytes, enqueue: int, event_codes: list[int], load_address: int) -> dict[str, object] | None:
    """Recover optional repeated raw-ring/task shape; never gates transport."""
    from . import RAW_CONSUMER_EVIDENCE, RAW_DEQUEUE_HEAD, RAW_RING_STORE, RAW_THUMB_BL, _thumb_reachable, facts_for, struct
    start = enqueue - load_address
    matches = [match for match in RAW_RING_STORE.finditer(image, start, min(len(image), start + 0x300)) if not match.start() & 1]
    if len(matches) != 1:
        return None
    match = matches[0]
    if match.start("store") not in _thumb_reachable(image, start, min(len(image), start + 0x300)):
        return None
    ring = facts_for(image).thumb_literal_value(match.start(), 2)
    if ring is None or not 0x01000000 <= ring < 0x04000000:
        return None
    dequeues = []
    for head in RAW_DEQUEUE_HEAD.finditer(image):
        candidate = head.start()
        if (candidate & 1 or facts_for(image).thumb_literal_value(candidate + 2, 4) != ring):
            continue
        body = image[candidate:min(len(image), candidate + 0x300)]
        if b"\x0a\x19\x97\x78" in body and b"\x38\x1c\x06\xb0\xf0\xbc\x08\xbc\x18\x47" in body:
            dequeues.append(candidate)
    if len(dequeues) != 1:
        return None
    dequeue = dequeues[0]
    wanted = {value for value in event_codes if value in b"1259"}
    tasks = []
    for call in RAW_THUMB_BL.finditer(image):
        site = call.start()
        if site & 1 or facts_for(image).thumb_call_target(site) != dequeue:
            continue
        move = struct.unpack_from("<H", image, site + 4)[0]
        if move & 0xFFF8 != 0x1C00 or move >> 3 & 7:
            continue
        guard = struct.unpack_from("<H", image, site + 6)[0]
        if guard & 0xFF00 != 0xD000:
            continue
        register = move & 7
        dispatch = facts_for(image).thumb_call_target(site + 8)
        if dispatch is None:
            branch = struct.unpack_from("<H", image, site + 8)[0]
            if branch & 0xF800 != 0xE000:
                continue
            delta = (branch & 0x7FF) << 1
            if delta & 0x800:
                delta -= 0x1000
            dispatch = site + 12 + delta
        if not 0 <= dispatch < len(image) - 2:
            continue
        compares = {struct.unpack_from("<H", image, current)[0] & 0xFF for current in range(dispatch, min(len(image) - 1, dispatch + 0x180), 2) if struct.unpack_from("<H",
            image, current)[0] & 0xFF00 == 0x2800 | register << 8}
        if len(wanted) == 4 and wanted <= compares:
            tasks.append((site, dispatch, register))
    if len(tasks) != 1:
        return None
    call, dispatch, register = tasks[0]
    return {"raw_ring": ring, "raw_ring_capacity": 32, "raw_enqueue_store": load_address + match.start("store"), "raw_enqueue_register": 7, "raw_dequeue":
        load_address + dequeue, "raw_dequeue_return": load_address + call + 4, "raw_task_entry": load_address + dispatch, "raw_task_register": register,
        "raw_consumer_evidence": RAW_CONSUMER_EVIDENCE}

def _descriptor_mmio_provenance(image: bytes, descriptor: int) -> dict[str, object] | None:
    from . import DESCRIPTOR_MMIO_ROLES, struct
    def roles(offset: int) -> bool:
        return all(offset + field + 4 <= len(image) and struct.unpack_from("<I", image, offset + field)[0] == value for field, value in DESCRIPTOR_MMIO_ROLES.items())
    def scatter(offset: int) -> dict[str, object] | None:
        source, target, size, bss, bss_size = struct.unpack_from("<5I", image, offset)
        if not (0 <= source < len(image) and 0 < size <= 0x800000 and source + size <= len(image) and 0x01000000 <= target < 0x02000000 and target + size == bss
            and 0 < bss_size <= 0x2000000 and bss + bss_size <= 0x04000000 and target <= descriptor < target + size):
            return None
        descriptor_source = source + descriptor - target
        return ({"kind": "validated-scatter", "source": descriptor_source, "scatter": offset} if roles(descriptor_source) else None)
    if descriptor < len(image) and roles(descriptor):
        return {"kind": "ROM-offset", "source": descriptor}
    for offset in range(0, min(len(image) - 20, 0x40000) + 1, 4):
        if (provenance := scatter(offset)) is not None:
            return provenance
    # Some images place the same startup copy/BSS descriptor after a large
    # boot region.  Its following instruction signature closes the search
    # without scanning every aligned word in the image.
    tail = struct.pack("<3I", 0x43192301, 0x43996001, 0x46F7C006)
    position = image.find(tail, 20)
    while position >= 0:
        offset = position - 20
        if (not offset & 3 and (provenance := scatter(offset)) is not None):
            return provenance
        position = image.find(tail, position + 1)
    return None

def _low5_senses(image: bytes, start: int, end: int, descriptor: int | None = None) -> list[tuple[int, int]]:
    from . import _last_literal, struct
    found: list[tuple[int, int]] = []
    for current in range(start, end - 3, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x6800 or (word >> 6 & 0x1F) * 4 != 0x34:
            continue
        value = word & 7
        if descriptor is not None and _last_literal(image, start, current, word >> 3 & 7) != descriptor:
            continue
        halfword = struct.unpack_from("<H", image, current + 2)[0]
        if halfword & 0xF800 != 0x8800 or halfword >> 3 & 7 != value or (halfword >> 6 & 0x1F):
            continue
        for shift_site in range(current + 4, min(end - 1, current + 0x50), 2):
            left = struct.unpack_from("<H", image, shift_site)[0]
            right = next((struct.unpack_from("<H", image, probe)[0] for probe in range(shift_site + 2, min(end - 1, shift_site + 0x10), 2) if struct.unpack_from("<H",
                image, probe)[0] & 0xF800 == 0x0800), 0)
            if (left & 0xF800 == 0 and left >> 6 & 0x1F == 27 and left & 0x3F == value << 3 | value and right & 0xF800 == 0x0800 and right >> 6 & 0x1F == 27 and
                right & 0x3F == value << 3 | value and any(struct.unpack_from("<H", image, probe)[0] == 0x2800 | value << 8 | 0x1F for probe in range(shift_site
                + 4, min(end - 1, shift_site + 0x20), 2))):
                found.append((current, value))
                break
    return found

def _descriptor_senses(image: bytes, start: int, end: int, descriptor: int | None = None) -> list[tuple[int, int, int]]:
    """The reporter's generic low4/low5 descriptor sense grammar."""
    from . import _last_literal, struct
    found: list[tuple[int, int, int]] = []
    for current in range(start, end - 3, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x6800 or (word >> 6 & 0x1F) * 4 != 0x34:
            continue
        value = word & 7
        halfword = struct.unpack_from("<H", image, current + 2)[0]
        if halfword & 0xF800 != 0x8800 or halfword >> 3 & 7 != value or (halfword >> 6 & 0x1F):
            continue
        for shift_site in range(current + 4, min(end - 1, current + 0x50), 2):
            left, right = struct.unpack_from("<2H", image, shift_site)
            shift = left >> 6 & 0x1F
            if (left & 0xF800 == 0 and left & 7 == value and left >> 3 & 7 == value and shift in (27, 28) and right & 0xF800 == 0x0800 and right & 7 == value
                and right >> 3 & 7 == value and right >> 6 & 0x1F == shift):
                bits, no_key = 32 - shift, (1 << (32 - shift)) - 1
                if any(struct.unpack_from("<H", image, probe)[0] == 0x2800 | value << 8 | no_key for probe in range(shift_site + 4, min(end - 1, shift_site +
                    0x14), 2)):
                    if descriptor is None or _last_literal(image, start, current, word >> 3 & 7) == descriptor:
                        found.append((current, bits, no_key))
                    break
    return found

def _row_bounds(image: bytes, start: int, end: int) -> list[int]:
    from . import struct
    return sorted({word & 0xFF for current in range(start, end - 1, 2) if (word := struct.unpack_from("<H", image, current)[0]) & 0xF800 == 0x2800 and 5 <= (word
        & 0xFF) <= 8})

def _descending_row_register(image: bytes, start: int, end: int, sense_site: int | None = None,) -> int | None:
    """Recover an exact 5..0 row loop whose register indexes decoded events."""
    from . import _thumb_reachable, _thumb_successors, struct
    found: list[int] = []
    for register in range(8):
        normalize = (0x0600 | register << 3 | register, 0x0E00 | register << 3 | register,)
        for decrement in range(start, end - 7, 2):
            words = struct.unpack_from("<4H", image, decrement)
            if (words[:3] != (0x3801 | register << 8, *normalize) or words[3] & 0xFF00 != 0xD500):
                continue
            branch = decrement + 6
            targets = [target for target in _thumb_successors(image, branch, end) if target != branch + 2]
            if len(targets) != 1:
                continue
            loop_start = targets[0]
            if (loop_start < start + 2 or struct.unpack_from("<H", image, loop_start - 2)[0] != 0x2005 | register << 8):
                continue
            reachable = _thumb_reachable(image, loop_start, branch + 2)
            senses = ([sense_site] if sense_site is not None else[current for current in reachable if current + 3 < len(image) and (load := struct.unpack_from("<H",
                image, current)[0]) & 0xF800 == 0x6800 and (load >> 6 & 0x1F) * 4 == 0x34 and struct.unpack_from("<H", image, current + 2)[0] & 0xF800 == 0x8800])
            if not senses or not all(site in reachable for site in senses):
                continue
            if not any(struct.unpack_from("<H", image, current)[0] & 0xFE00 == 0x5C00 and struct.unpack_from("<H", image, current)[0] >> 6 & 7 == register for
                current in reachable):
                continue
            found.append(register)
            break
    return found[0] if len(found) == 1 else None

def find_descriptor_ram_scan_shapes(image: bytes, load_address: int = 0, _anchors: tuple[dict[str, object], ...] | None = None,) -> list[dict[str, object]]:
    """Report bounded RAM-descriptor scan shapes without publishing transport."""
    from . import DESCRIPTOR_MMIO_ROLES, _descending_row_register, _descriptor_mmio_provenance, _descriptor_pointer, _descriptor_senses, _low5_senses, _row_bounds, find_descriptor_scan_anchors, struct
    found: list[dict[str, object]] = []
    for anchor in (_anchors if _anchors is not None else find_descriptor_scan_anchors(image, load_address)):
        start, site = int(anchor["function"]) - load_address, int(anchor["anchor"]) - load_address
        end = min(start + int(anchor["fingerprint_size"]), len(image))
        senses = _descriptor_senses(image, start, end)
        senses.extend((site, 5, 0x1F) for site, _ in _low5_senses(image, start, end) if site not in {known for known, _, _ in senses})
        descriptor = _descriptor_pointer(image, start,[sense_site for sense_site, _, _ in senses],)
        bounds = _row_bounds(image, start, end)
        if (descriptor is None or not 0x01000000 <= descriptor < 0x02000000 or not senses):
            continue
        provenance = _descriptor_mmio_provenance(image, descriptor)
        for sense_site, sense_bits, no_key in senses:
            descending = _descending_row_register(image, start, end, sense_site,)
            bounded = 5 in bounds and any(value > 5 for value in bounds)
            if not bounded and descending is None:
                continue
            if not any(struct.unpack_from("<H", image, current)[0] & 0xFE00 == 0x5C00 for current in range(sense_site + 4, end - 1, 2)):
                continue
            shape = { "grammar": "descriptor-ram-bounded-scan-v1", "evidence": "static-structural", "function": load_address + start, "anchor": load_address +
                site, "descriptor_pointer": descriptor, "descriptor_pointer_provenance": "ROM literal to RAM descriptor", "sense_site": load_address +
                sense_site, "sense_pointer_offset": 0x34, "sense_bits": sense_bits, "no_key": no_key, "row_bounds": bounds, "table_decode": "byte-indexed",
                "absolute_register": DESCRIPTOR_MMIO_ROLES[0x34] if provenance else None, "absolute_roles": ({"control": DESCRIPTOR_MMIO_ROLES[0], "row_drive":
                DESCRIPTOR_MMIO_ROLES[0x20], "sense": DESCRIPTOR_MMIO_ROLES[0x34]} if provenance else None), "descriptor_mmio_provenance": provenance["kind"] if
                provenance else None, "semantic_limit": "event transport and runtime press/consumer/release remain unresolved" if provenance else
                "RAM descriptor initializer to physical MMIO, event transport, and runtime press/consumer/release remain unresolved", "fingerprint": anchor["fingerprint"],
                "fingerprint_size": anchor["fingerprint_size"], "fingerprint_scope": "linear-prefix", "fingerprint_boundary": anchor["fingerprint_boundary"], }
            if descending is not None:
                shape.update({"row_order": list(range(6)), "row_order_evidence": "direct-descending-loop"})
            found.append(shape)
    return found

def _table_base(image: bytes, start: int, end: int, sense_register: int) -> tuple[int, list[int]] | None:
    """Require literal(+immediate) table base and its actual LDRB[sense] use."""
    from . import facts_for, struct
    saved: dict[tuple[int, int], tuple[int, int]] = {}
    saved_pairs: set[tuple[int, int]] = set()
    for current in range(start, end - 1, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 == 0x7000:
            saved[(word >> 3 & 7, word >> 6 & 0x1F)] = (word & 7, current)
        elif word & 0xF800 == 0x7800:
            prior = saved.get((word >> 3 & 7, word >> 6 & 0x1F))
            if prior is not None and prior[1] < current:
                saved_pairs.add((prior[0], word & 7))
    for current in range(start, end - 1, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x4800:
            continue
        register, base = word >> 8 & 7, facts_for(image).thumb_literal_value(current, word >> 8 & 7)
        if base is None:
            continue
        # Compiler copy helper: literal source -> r0(sp), then later LDRB [sp,index].
        if (0 <= base <= len(image) - 32 and any(struct.unpack_from("<H", image, probe)[0] == 0x4668 and facts_for(image).thumb_call_target(probe + 2) is not
            None for probe in range(current + 2, min(current + 0x20, end - 5), 2))):
            table = list(image[base:base + 32])
            active = [0x1F ^ (1 << column) for column in range(5)]
            if len({table[value] for value in active}) == 5 and set(table[value] for value in active) == set(range(5)):
                if any(struct.unpack_from("<H", image, probe)[0] & 0xFE00 == 0x5C00 and struct.unpack_from("<H", image, probe)[0] >> 3 & 7 == 0 and struct.unpack_from("<H",
                    image, probe)[0] >> 6 & 7 == sense_register for probe in range(current + 4, min(end - 1, current + 0x300), 2)):
                    return base, table
        options = [(current + 2, base)]
        for adjust_site in range(current + 2, min(current + 0x120, end), 2):
            adjust = struct.unpack_from("<H", image, adjust_site)[0]
            if adjust & 0xF800 in (0x3000, 0x3800) and adjust >> 8 & 7 == register:
                options.append((adjust_site + 2, base + (adjust & 0xFF) * (1 if adjust & 0xF800 == 0x3000 else -1)))
        for scan_start, address in options:
            if not 0 <= address <= len(image) - 32:
                continue
            for probe in range(scan_start, min(end - 1, current + 0x120), 2):
                load = struct.unpack_from("<H", image, probe)[0]
                index = load >> 6 & 7
                direct = index == sense_register
                saved_sense = (sense_register, index) in saved_pairs
                if load & 0xFE00 == 0x5C00 and load >> 3 & 7 == register and (direct or saved_sense):
                    table = list(image[address:address + 32])
                    active = [0x1F ^ (1 << column) for column in range(5)]
                    if len({table[value] for value in active}) == 5 and set(table[value] for value in active) == set(range(5)):
                        return address, table
    return None

def _event_table(image: bytes, start: int, end: int) -> tuple[int, list[int]] | None:
    """Keep the legacy literal(+immediate) event-table provenance."""
    from . import ASCII_KEY_EVENTS, facts_for, struct
    for current in range(start, end - 1, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x4800:
            continue
        register, base = word >> 8 & 7, facts_for(image).thumb_literal_value(current, word >> 8 & 7)
        if base is None:
            continue
        for probe in range(current + 2, min(current + 0x120, end), 2):
            adjust = struct.unpack_from("<H", image, probe)[0]
            if adjust & 0xF800 not in (0x3000, 0x3800) or adjust >> 8 & 7 != register:
                continue
            address = base + (adjust & 0xFF) * (1 if adjust & 0xF800 == 0x3000 else -1)
            events = list(image[address:address + 30])
            if len(events) == 30 and all(events.count(event) == 1 for event in ASCII_KEY_EVENTS):
                return address, events
    return None

def _row_order(image: bytes, start: int, end: int, sense_site: int | None = None) -> tuple[list[int], str] | None:
    # Compiler stack-copy: literal six-byte order, then MOV r0, sp and BL copy.
    from . import _descending_row_register, facts_for, struct
    for current in range(start, end - 7, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x4800:
            continue
        address = facts_for(image).thumb_literal_value(current, word >> 8 & 7)
        if address is None or not 0 <= address <= len(image) - 6:
            continue
        order = list(image[address:address + 6])
        if (sorted(order) == list(range(6)) and any(struct.unpack_from("<H", image, probe)[0] == 0x4668 and facts_for(image).thumb_call_target(probe + 2) is not
            None for probe in range(current + 2, min(current + 0x20, end - 5), 2))):
            return order, "literal-stack-copy-row-order"
    # Direct counter: explicit zero, increment, and six bound in the scanner.
    for register in range(8):
        zero = any(struct.unpack_from("<H", image, current)[0] == 0x2000 | register << 8 for current in range(start, end - 1, 2))
        increment = any(struct.unpack_from("<H", image, current)[0] == 0x3001 | register << 8 for current in range(start, end - 1, 2))
        bound = any(struct.unpack_from("<H", image, current)[0] == 0x2806 | register << 8 for current in range(start, end - 1, 2))
        if zero and increment and bound:
            return list(range(6)), "direct-identity-loop"
    if _descending_row_register(image, start, end, sense_site) is not None:
        return list(range(6)), "direct-descending-loop"
    # A literal six-byte permutation is useful only when this scanner loads it by byte.
    for current in range(start, end - 1, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x4800:
            continue
        register, address = word >> 8 & 7, facts_for(image).thumb_literal_value(current, word >> 8 & 7)
        if address is None or not 0 <= address <= len(image) - 6:
            continue
        order = list(image[address:address + 6])
        if sorted(order) != list(range(6)):
            continue
        if any(struct.unpack_from("<H", image, probe)[0] & 0xFE00 == 0x5C00 and struct.unpack_from("<H", image, probe)[0] >> 3 & 7 == register for probe in
            range(current + 2, min(end - 1, current + 0x120), 2)):
            return order, "literal-byte-row-order"
    return None
