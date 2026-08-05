"""Static descriptor-keypad evidence; deliberately no runtime transport."""
from __future__ import annotations

import re
import struct
from collections import defaultdict

from .arm import (
    _thumb_callable_entry, _thumb_fingerprint, _thumb_function_start,
    _thumb_path_preserves_register, _thumb_reachable, _thumb_successors,
    thumb_bl_target, thumb_literal_value,
)
from .input_matrix import ASCII_KEY_EVENTS, _thumb_inbound_entries

LG_DESCRIPTOR_RAW = "lg-descriptor-raw-keypad-v1"
LG_DESCRIPTOR_RAW_FINGERPRINT = "lg-descriptor-low5-6x5-raw-v1"
RAW_CONSUMER_EVIDENCE = "shared-byte-ring32-r0-task-dispatch-v1"
LG_OBSERVED_SEMANTIC_FINGERPRINT = "lg-6x5-unique-event-semantics-v1"
LG_OBSERVED_KEY_EVENTS = {
    0: 0x09, 1: 0x85, 2: 0x52, 3: 0x50, 4: 0x87,
    5: 0x8D, 6: 0x88, 8: 0x8C, 9: 0x86, 10: 0x8B,
    11: 0x31, 12: 0x32, 13: 0x33, 14: 0x34, 15: 0x35,
    16: 0x36, 17: 0x37, 18: 0x38, 19: 0x39, 20: 0x2A,
    21: 0x30, 22: 0x23,
}
RAW_RING_STORE = re.compile(
    rb".\x4a\x04\x04\x50\x78\x24\x0c\x13\x78\x41\x1c"
    rb"\xc9\x06\xc9\x0e\x99\x42.{0,12}\x80\x18(?P<store>\x87\x70)"
    rb"\x50\x78\x01\x30\xc0\x06\xc0\x0e\x50\x70", re.S,
)
RAW_DEQUEUE_HEAD = re.compile(rb"\xf0\xb5.\x4c\x86\xb0\x60\x78\x21\x78\x88\x42", re.S)
RAW_THUMB_BL = re.compile(rb".[\xf0-\xf7].[\xf8-\xff]", re.S)

DESCRIPTOR_SCAN_ANCHORS = (
    ("row-drive-register-mask", re.compile(
        rb".\x8d\x49\x09\x49\x01\x01\x22.\x40\x12\x06\x12\x0e"
        rb".{0,8}\xd2\x43.{0,8}\x11\x43.\x85.\x8d.\x6a\x11\x80", re.S)),
    ("row-drive-immediate-mask5", re.compile(
        rb".\x8d\x49\x09\x49\x01.{0,12}\x1f\x23.{0,16}"
        rb".\x85.\x8d.\x6a\x11\x80", re.S)),
)
DESCRIPTOR_MMIO_ROLES = {
    0x00: 0x03000720, 0x08: 0x0300072C, 0x10: 0x03000724,
    0x18: 0x03000730, 0x20: 0x03000728, 0x28: 0x03000734,
    0x34: 0x0300072C,
}


def find_descriptor_scan_anchors(image: bytes, load_address: int = 0) -> list[dict[str, object]]:
    """Find descriptor row-drive anchors; not a sense/no-key transport."""
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
            found[start] = {
                "grammar": "descriptor-row-drive-anchor-v1", "variants": [variant],
                "function": load_address + start, "anchor": load_address + site,
                "sense_bits": None, "no_key": None, "absolute_register": None,
                "evidence": "structural-only",
                "semantic_limit": "drive-side only; sense/no-key unresolved",
                "fingerprint": fingerprint, "fingerprint_size": size,
                "fingerprint_scope": "linear-prefix", "fingerprint_boundary": boundary,
            }
    return [found[start] for start in sorted(found)]


def find_lg_descriptor_scan_anchors(image: bytes, load_address: int = 0) -> list[dict[str, object]]:
    """Compatibility alias for the cross-vendor descriptor grammar."""
    return find_descriptor_scan_anchors(image, load_address)


def _last_literal(image: bytes, start: int, position: int, register: int) -> int | None:
    for current in range(position - 2, start - 1, -2):
        if current + 2 <= len(image):
            value = thumb_literal_value(image, current, register)
            if value is not None:
                return value
    return None


def _descriptor_pointer(image: bytes, start: int,
                        sense_sites: list[int]) -> int | None:
    """Recover one RAM descriptor even when later senses use a register alias."""
    pointers = {
        value
        for site in sense_sites
        if (value := _last_literal(
            image, start, site,
            struct.unpack_from("<H", image, site)[0] >> 3 & 7,
        )) is not None and 0x01000000 <= value < 0x02000000
    }
    return next(iter(pointers)) if len(pointers) == 1 else None


def _observed_lg_mappings(events: list[int]) -> dict[int, dict[str, object]]:
    """Publish semantics only when complete observed event set is unique."""
    if any(events.count(event) != 1
           for event in LG_OBSERVED_KEY_EVENTS.values()):
        return {}
    return {
        bit: {
            "event": event,
            "rule": "temporary-evidence-gated-unique-event-set",
            "evidence": "firmware-table-unique-events+observed-key-semantics",
            "semantic_grammar_fingerprint":
                LG_OBSERVED_SEMANTIC_FINGERPRINT,
        }
        for bit, event in LG_OBSERVED_KEY_EVENTS.items()
    }


def _raw_consumer_metadata(image: bytes, enqueue: int,
                           event_codes: list[int], load_address: int) -> dict[str, object] | None:
    """Recover optional repeated raw-ring/task shape; never gates transport."""
    start = enqueue - load_address
    matches = [match for match in RAW_RING_STORE.finditer(
        image, start, min(len(image), start + 0x300)) if not match.start() & 1]
    if len(matches) != 1:
        return None
    match = matches[0]
    if match.start("store") not in _thumb_reachable(
            image, start, min(len(image), start + 0x300)):
        return None
    ring = thumb_literal_value(image, match.start(), 2)
    if ring is None or not 0x01000000 <= ring < 0x04000000:
        return None
    dequeues = []
    for head in RAW_DEQUEUE_HEAD.finditer(image):
        candidate = head.start()
        if (candidate & 1 or thumb_literal_value(image, candidate + 2, 4) != ring):
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
        if site & 1 or thumb_bl_target(image, site) != dequeue:
            continue
        move = struct.unpack_from("<H", image, site + 4)[0]
        if move & 0xFFF8 != 0x1C00 or move >> 3 & 7:
            continue
        guard = struct.unpack_from("<H", image, site + 6)[0]
        if guard & 0xFF00 != 0xD000:
            continue
        register = move & 7
        dispatch = thumb_bl_target(image, site + 8)
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
        compares = {struct.unpack_from("<H", image, current)[0] & 0xFF
                    for current in range(dispatch, min(len(image) - 1, dispatch + 0x180), 2)
                    if struct.unpack_from("<H", image, current)[0] & 0xFF00 == 0x2800 | register << 8}
        if len(wanted) == 4 and wanted <= compares:
            tasks.append((site, dispatch, register))
    if len(tasks) != 1:
        return None
    call, dispatch, register = tasks[0]
    return {"raw_ring": ring, "raw_ring_capacity": 32,
            "raw_enqueue_store": load_address + match.start("store"),
            "raw_enqueue_register": 7, "raw_dequeue": load_address + dequeue,
            "raw_dequeue_return": load_address + call + 4,
            "raw_task_entry": load_address + dispatch,
            "raw_task_register": register,
            "raw_consumer_evidence": RAW_CONSUMER_EVIDENCE}


def _descriptor_mmio_provenance(image: bytes, descriptor: int) -> dict[str, object] | None:
    def roles(offset: int) -> bool:
        return all(offset + field + 4 <= len(image) and struct.unpack_from("<I", image, offset + field)[0] == value
                   for field, value in DESCRIPTOR_MMIO_ROLES.items())
    def scatter(offset: int) -> dict[str, object] | None:
        source, target, size, bss, bss_size = struct.unpack_from("<5I", image, offset)
        if not (0 <= source < len(image) and 0 < size <= 0x800000 and source + size <= len(image)
                and 0x01000000 <= target < 0x02000000 and target + size == bss
                and 0 < bss_size <= 0x2000000 and bss + bss_size <= 0x04000000
                and target <= descriptor < target + size):
            return None
        descriptor_source = source + descriptor - target
        return ({"kind": "validated-scatter", "source": descriptor_source,
                 "scatter": offset} if roles(descriptor_source) else None)

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
        if (not offset & 3
                and (provenance := scatter(offset)) is not None):
            return provenance
        position = image.find(tail, position + 1)
    return None


def _low5_senses(image: bytes, start: int, end: int, descriptor: int | None = None) -> list[tuple[int, int]]:
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
            right = next((struct.unpack_from("<H", image, probe)[0]
                          for probe in range(shift_site + 2, min(end - 1, shift_site + 0x10), 2)
                          if struct.unpack_from("<H", image, probe)[0] & 0xF800 == 0x0800), 0)
            if (left & 0xF800 == 0 and left >> 6 & 0x1F == 27 and left & 0x3F == value << 3 | value
                    and right & 0xF800 == 0x0800 and right >> 6 & 0x1F == 27
                    and right & 0x3F == value << 3 | value
                    and any(struct.unpack_from("<H", image, probe)[0] == 0x2800 | value << 8 | 0x1F
                            for probe in range(shift_site + 4, min(end - 1, shift_site + 0x20), 2))):
                found.append((current, value))
                break
    return found


def _descriptor_senses(image: bytes, start: int, end: int, descriptor: int | None = None) -> list[tuple[int, int, int]]:
    """The reporter's generic low4/low5 descriptor sense grammar."""
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
            if (left & 0xF800 == 0 and left & 7 == value and left >> 3 & 7 == value
                    and shift in (27, 28) and right & 0xF800 == 0x0800
                    and right & 7 == value and right >> 3 & 7 == value and right >> 6 & 0x1F == shift):
                bits, no_key = 32 - shift, (1 << (32 - shift)) - 1
                if any(struct.unpack_from("<H", image, probe)[0] == 0x2800 | value << 8 | no_key
                       for probe in range(shift_site + 4, min(end - 1, shift_site + 0x14), 2)):
                    if descriptor is None or _last_literal(image, start, current, word >> 3 & 7) == descriptor:
                        found.append((current, bits, no_key))
                    break
    return found


def _row_bounds(image: bytes, start: int, end: int) -> list[int]:
    return sorted({word & 0xFF for current in range(start, end - 1, 2)
                   if (word := struct.unpack_from("<H", image, current)[0]) & 0xF800 == 0x2800
                   and 5 <= (word & 0xFF) <= 8})


def _descending_row_register(
        image: bytes, start: int, end: int, sense_site: int | None = None,
) -> int | None:
    """Recover an exact 5..0 row loop whose register indexes decoded events."""
    found: list[int] = []
    for register in range(8):
        normalize = (
            0x0600 | register << 3 | register,
            0x0E00 | register << 3 | register,
        )
        for decrement in range(start, end - 7, 2):
            words = struct.unpack_from("<4H", image, decrement)
            if (words[:3] != (0x3801 | register << 8, *normalize)
                    or words[3] & 0xFF00 != 0xD500):
                continue
            branch = decrement + 6
            targets = [target for target in _thumb_successors(
                image, branch, end) if target != branch + 2]
            if len(targets) != 1:
                continue
            loop_start = targets[0]
            if (loop_start < start + 2
                    or struct.unpack_from("<H", image, loop_start - 2)[0]
                    != 0x2005 | register << 8):
                continue
            reachable = _thumb_reachable(image, loop_start, branch + 2)
            senses = ([sense_site] if sense_site is not None else [
                current for current in reachable
                if current + 3 < len(image)
                and (load := struct.unpack_from("<H", image, current)[0])
                & 0xF800 == 0x6800
                and (load >> 6 & 0x1F) * 4 == 0x34
                and struct.unpack_from("<H", image, current + 2)[0]
                & 0xF800 == 0x8800
            ])
            if not senses or not all(site in reachable for site in senses):
                continue
            if not any(
                    struct.unpack_from("<H", image, current)[0] & 0xFE00
                    == 0x5C00
                    and struct.unpack_from("<H", image, current)[0] >> 6 & 7
                    == register for current in reachable):
                continue
            found.append(register)
            break
    return found[0] if len(found) == 1 else None


def find_descriptor_ram_scan_shapes(
        image: bytes, load_address: int = 0,
        _anchors: tuple[dict[str, object], ...] | None = None,
) -> list[dict[str, object]]:
    """Report bounded RAM-descriptor scan shapes without publishing transport."""
    found: list[dict[str, object]] = []
    for anchor in (_anchors if _anchors is not None
                   else find_descriptor_scan_anchors(image, load_address)):
        start, site = int(anchor["function"]) - load_address, int(anchor["anchor"]) - load_address
        end = min(start + int(anchor["fingerprint_size"]), len(image))
        senses = _descriptor_senses(image, start, end)
        senses.extend((site, 5, 0x1F) for site, _ in _low5_senses(image, start, end)
                      if site not in {known for known, _, _ in senses})
        descriptor = _descriptor_pointer(
            image, start, [sense_site for sense_site, _, _ in senses],
        )
        bounds = _row_bounds(image, start, end)
        if (descriptor is None
                or not 0x01000000 <= descriptor < 0x02000000
                or not senses):
            continue
        provenance = _descriptor_mmio_provenance(image, descriptor)
        for sense_site, sense_bits, no_key in senses:
            descending = _descending_row_register(
                image, start, end, sense_site,
            )
            bounded = 5 in bounds and any(value > 5 for value in bounds)
            if not bounded and descending is None:
                continue
            if not any(struct.unpack_from("<H", image, current)[0] & 0xFE00 == 0x5C00 for current in range(sense_site + 4, end - 1, 2)):
                continue
            shape = {
            "grammar": "descriptor-ram-bounded-scan-v1", "evidence": "static-structural",
            "function": load_address + start, "anchor": load_address + site,
            "descriptor_pointer": descriptor, "descriptor_pointer_provenance": "ROM literal to RAM descriptor",
            "sense_site": load_address + sense_site, "sense_pointer_offset": 0x34,
            "sense_bits": sense_bits, "no_key": no_key, "row_bounds": bounds, "table_decode": "byte-indexed",
            "absolute_register": DESCRIPTOR_MMIO_ROLES[0x34] if provenance else None,
            "absolute_roles": ({"control": DESCRIPTOR_MMIO_ROLES[0], "row_drive": DESCRIPTOR_MMIO_ROLES[0x20], "sense": DESCRIPTOR_MMIO_ROLES[0x34]} if provenance else None),
            "descriptor_mmio_provenance": provenance["kind"] if provenance else None,
            "semantic_limit": "event transport and runtime press/consumer/release remain unresolved" if provenance else "RAM descriptor initializer to physical MMIO, event transport, and runtime press/consumer/release remain unresolved",
            "fingerprint": anchor["fingerprint"], "fingerprint_size": anchor["fingerprint_size"],
            "fingerprint_scope": "linear-prefix", "fingerprint_boundary": anchor["fingerprint_boundary"],
            }
            if descending is not None:
                shape.update({"row_order": list(range(6)),
                              "row_order_evidence": "direct-descending-loop"})
            found.append(shape)
    return found


def _table_base(image: bytes, start: int, end: int, sense_register: int) -> tuple[int, list[int]] | None:
    """Require literal(+immediate) table base and its actual LDRB[sense] use."""
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
        register, base = word >> 8 & 7, thumb_literal_value(image, current, word >> 8 & 7)
        if base is None:
            continue
        # Compiler copy helper: literal source -> r0(sp), then later LDRB [sp,index].
        if (0 <= base <= len(image) - 32 and any(
                struct.unpack_from("<H", image, probe)[0] == 0x4668
                and thumb_bl_target(image, probe + 2) is not None
                for probe in range(current + 2, min(current + 0x20, end - 5), 2))):
            table = list(image[base:base + 32])
            active = [0x1F ^ (1 << column) for column in range(5)]
            if len({table[value] for value in active}) == 5 and set(table[value] for value in active) == set(range(5)):
                if any(struct.unpack_from("<H", image, probe)[0] & 0xFE00 == 0x5C00
                       and struct.unpack_from("<H", image, probe)[0] >> 3 & 7 == 0
                       and struct.unpack_from("<H", image, probe)[0] >> 6 & 7 == sense_register
                       for probe in range(current + 4, min(end - 1, current + 0x300), 2)):
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
    for current in range(start, end - 1, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x4800:
            continue
        register, base = word >> 8 & 7, thumb_literal_value(image, current, word >> 8 & 7)
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


def _row_order(image: bytes, start: int, end: int,
               sense_site: int | None = None) -> tuple[list[int], str] | None:
    # Compiler stack-copy: literal six-byte order, then MOV r0, sp and BL copy.
    for current in range(start, end - 7, 2):
        word = struct.unpack_from("<H", image, current)[0]
        if word & 0xF800 != 0x4800:
            continue
        address = thumb_literal_value(image, current, word >> 8 & 7)
        if address is None or not 0 <= address <= len(image) - 6:
            continue
        order = list(image[address:address + 6])
        if (sorted(order) == list(range(6)) and any(
                struct.unpack_from("<H", image, probe)[0] == 0x4668
                and thumb_bl_target(image, probe + 2) is not None
                for probe in range(current + 2, min(current + 0x20, end - 5), 2))):
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
        register, address = word >> 8 & 7, thumb_literal_value(image, current, word >> 8 & 7)
        if address is None or not 0 <= address <= len(image) - 6:
            continue
        order = list(image[address:address + 6])
        if sorted(order) != list(range(6)):
            continue
        if any(struct.unpack_from("<H", image, probe)[0] & 0xFE00 == 0x5C00 and struct.unpack_from("<H", image, probe)[0] >> 3 & 7 == register
               for probe in range(current + 2, min(end - 1, current + 0x120), 2)):
            return order, "literal-byte-row-order"
    return None


def _row_state(image: bytes, start: int, end: int) -> tuple[int, int, int, str] | None:
    """Recover only one exact byte read/increment/write scan-index state."""
    found: list[tuple[int, int, int]] = []
    for current in range(start, end - 1, 2):
        load = struct.unpack_from("<H", image, current)[0]
        if load & 0xF800 != 0x7800:
            continue
        base, value = load >> 3 & 7, load & 7
        offset = load >> 6 & 0x1F
        if not any(struct.unpack_from("<H", image, probe)[0] == 0x3001 | value << 8
                   for probe in range(current + 2, min(current + 0x12, end), 2)):
            continue
        if not any(struct.unpack_from("<H", image, probe)[0] == 0x7000 | offset << 6 | base << 3 | value
                   for probe in range(current + 2, min(current + 0x18, end), 2)):
            continue
        address = _last_literal(image, start, current, base)
        if address is not None:
            found.append((address, offset, current))
    return (*found[0], "ldrb-state-increment-store") if len(found) == 1 else None


def _sense_roles(image: bytes, start: int, end: int, descriptor: int, row_site: int) -> tuple[list[int], list[int]]:
    """Separate a pre-loop no-key guard from D+34 reads inside the six-row loop."""
    global_sites: list[int] = []
    row_sites: list[int] = []
    senses = [
        current for current in range(start, end - 3, 2)
        if ((load := struct.unpack_from("<H", image, current)[0]) & 0xF800
            == 0x6800
            and (load >> 6 & 0x1F) * 4 == 0x34
            and (halfword := struct.unpack_from(
                "<H", image, current + 2,
            )[0]) & 0xF800 == 0x8800
            and halfword >> 3 & 7 == load & 7)
    ]
    if _descriptor_pointer(image, start, senses) != descriptor:
        return global_sites, row_sites

    def closes_six_row_loop(sense: int) -> bool:
        if _descending_row_register(image, start, end, sense) is not None:
            return True
        for compare in range(sense + 4, min(sense + 0x80, end), 2):
            word = struct.unpack_from("<H", image, compare)[0]
            if word & 0xF800 != 0x2800 or word & 0xFF != 6:
                continue
            for branch in (compare + 2, compare + 4):
                for target in _thumb_successors(image, branch, end):
                    if (target == branch + 2
                            or not start <= target <= row_site):
                        continue
                    reachable = _thumb_reachable(
                        image, target, compare + 2
                    )
                    if sense in reachable and compare in reachable:
                        return True
        return False

    for current in senses:
        load = struct.unpack_from("<H", image, current)[0]
        value = load & 7
        no_key_guard = any(struct.unpack_from("<H", image, probe)[0] == 0x2800 | value << 8 | 0x1F
                           for probe in range(current + 4, min(current + 0x30, end), 2))
        if no_key_guard and current < row_site:
            global_sites.append(current)
        if current >= row_site and closes_six_row_loop(current):
            row_sites.append(current)
    return global_sites, row_sites


def _row_register(image: bytes, start: int, end: int, row_sites: list[int]) -> int | None:
    """Require one local counter to index and close the exact six-row loop."""
    if not row_sites:
        return None
    if (register := _descending_row_register(
            image, start, end, min(row_sites))) is not None:
        return register
    candidates: list[int] = []
    first = min(row_sites)
    for register in range(8):
        normalize = (
            0x0600 | register << 3 | register,
            0x0E00 | register << 3 | register,
        )
        for increment in range(first, end - 9, 2):
            if struct.unpack_from("<5H", image, increment)[:4] != (
                    0x3001 | register << 8, *normalize,
                    0x2806 | register << 8):
                continue
            branch = increment + 8
            branch_word = struct.unpack_from("<H", image, branch)[0]
            targets = [
                target for target in _thumb_successors(image, branch, end)
                if target != branch + 2
            ]
            loop_start = (
                targets[0] if len(targets) == 1 and targets[0] <= first
                else None
            )
            if (loop_start is None and branch_word & 0xF000 == 0xD000
                    and (branch_word & 0x0F00) < 0x0E00
                    and branch + 4 <= end):
                back = branch + 2
                back_word = struct.unpack_from("<H", image, back)[0]
                back_targets = [
                    target for target in _thumb_successors(image, back, end)
                    if target != back + 2
                ]
                if (back_word & 0xF800 == 0xE000
                        and len(back_targets) == 1
                        and back_targets[0] <= first):
                    loop_start = back_targets[0]
            if loop_start is None or not start <= loop_start <= first:
                continue
            reachable = _thumb_reachable(image, loop_start, increment)
            if (not all(site in reachable for site in row_sites)
                    or not any(
                        struct.unpack_from("<H", image, site)[0] & 0xFE00
                        == 0x5C00
                        and struct.unpack_from("<H", image, site)[0] >> 6 & 7
                        == register
                        for site in reachable
                    )):
                continue
            zeroes = [
                site for site in range(start, loop_start, 2)
                if struct.unpack_from("<H", image, site)[0]
                == 0x2000 | register << 8
                and _thumb_path_preserves_register(
                    image, site + 2, loop_start, end, register
                )
            ]
            if zeroes:
                candidates.append(register)
                break
    return candidates[0] if len(candidates) == 1 else None


def find_lg_descriptor_keypad_candidates(
        image: bytes, load_address: int = 0,
        _anchors: tuple[dict[str, object], ...] | None = None,
) -> list[dict[str, object]]:
    """Recover static LG low5 descriptor-to-raw candidates; never transport."""
    found: list[dict[str, object]] = []
    for anchor in (_anchors if _anchors is not None
                   else find_descriptor_scan_anchors(image, load_address)):
        prologue = int(anchor["function"]) - load_address
        end = min(prologue + 0x900, len(image) - 3)
        senses = _low5_senses(image, prologue, end)
        descriptor = _descriptor_pointer(
            image, prologue, [sense_site for sense_site, _ in senses],
        )
        if descriptor is None or not senses or not {5, 6}.issubset(_row_bounds(image, prologue, end)):
            continue
        columns = [(site, register, _table_base(image, prologue, end, register)) for site, register in senses]
        columns = [(site, table) for site, _, table in columns if table is not None]
        # The scanner can reread D+34; the final table-indexed read is its decode.
        if not columns:
            continue
        sense_site, column = columns[-1]
        event_table = _event_table(image, prologue, end)
        if event_table is None:
            continue
        calls: dict[int, list[int]] = defaultdict(list)
        for callsite in range(prologue, end, 2):
            target = thumb_bl_target(image, callsite)
            if target is not None and prologue - 0x400 <= target < prologue:
                calls[target].append(callsite)
        raw_sinks = [(target, sites) for target, sites in calls.items() if len(sites) >= 8]
        if len(raw_sinks) != 1:
            continue
        raw_sink, callsites = raw_sinks[0]
        entry = _thumb_callable_entry(image, prologue, _thumb_inbound_entries(image, {prologue - 2}))
        table_address, table = column
        active_senses = [0x1F ^ (1 << bit) for bit in range(5)]
        inverted = [next(value for value in active_senses if table[value] == column) for column in range(5)]
        events_address, events = event_table
        provenance = _descriptor_mmio_provenance(image, descriptor)
        candidate = {
            "grammar": LG_DESCRIPTOR_RAW_FINGERPRINT, "grammar_fingerprint": LG_DESCRIPTOR_RAW_FINGERPRINT,
            "evidence": "static-scan-to-raw-enqueue",
            "function": load_address + entry, "prologue": load_address + prologue,
            "callable_entry_evidence": "inbound-pre-push" if entry != prologue else "push",
            "descriptor_pointer": descriptor, "sense_site": load_address + sense_site,
            "sense_sites": [load_address + site for site, _ in senses],
            "sense_pointer_offset": 0x34, "sense_bits": 5, "no_key": 0x1F,
            "rows": 6, "columns": 5,
            "column_table": load_address + table_address, "column_map": table,
            "single_key_column_sense": inverted, "column_sense_map": "firmware-table-derived",
            "event_table": load_address + events_address, "event_codes": events,
            "event_table_formula": "event_codes[column * 6 + row]",
            "raw_enqueue": load_address + raw_sink, "raw_enqueue_callsite": load_address + callsites[0],
            "raw_enqueue_callsites": [load_address + site for site in callsites],
            "absolute_roles": ({"control": DESCRIPTOR_MMIO_ROLES[0], "row_drive": DESCRIPTOR_MMIO_ROLES[0x20], "sense": DESCRIPTOR_MMIO_ROLES[0x34]} if provenance else None),
            "descriptor_mmio_provenance": provenance["kind"] if provenance else None,
            "semantic_limit": "static candidate only; physical transport remains unproven",
        }
        mappings = _observed_lg_mappings(events)
        if mappings:
            candidate["provisional_mappings"] = mappings
        found.append(candidate)
    return found


def resolve_lg_descriptor_input(image: bytes, load_address: int = 0) -> tuple[dict[str, object] | None, str, list[dict[str, object]]]:
    """Accept exactly one fully cross-checked static candidate, no timer/runtime."""
    anchors = tuple(find_descriptor_scan_anchors(image, load_address))
    shapes = find_descriptor_ram_scan_shapes(image, load_address, anchors)
    accepted, rejected = [], []
    for candidate in find_lg_descriptor_keypad_candidates(
            image, load_address, anchors):
        reasons: list[str] = []
        matching = [shape for shape in shapes if (shape["row_bounds"] == [5, 6]
                    or shape.get("row_order_evidence") == "direct-descending-loop")
                    and shape["descriptor_pointer"] == candidate["descriptor_pointer"]
                    and shape["sense_site"] == candidate["sense_site"]
                    and abs(int(shape["function"]) - int(candidate["prologue"])) <= 2]
        if candidate["descriptor_mmio_provenance"] is None:
            reasons.append("descriptor-mmio-provenance-missing")
        if len(matching) != 1:
            reasons.append("matching-ram-shape-not-unique")
            row_order = None
        else:
            start = int(matching[0]["function"]) - load_address
            row_order = _row_order(
                image, start, start + int(matching[0]["fingerprint_size"]),
                int(candidate["sense_site"]) - load_address,
            )
            if row_order is None:
                reasons.append("row-order-not-proven")
        events = candidate["event_codes"]
        if any(events.count(event) != 1 for event in ASCII_KEY_EVENTS):
            reasons.append("numeric-events-not-unique")
        sites = candidate["raw_enqueue_callsites"]
        if not sites or any(thumb_bl_target(image, site - load_address) != candidate["raw_enqueue"] - load_address for site in sites):
            reasons.append("raw-enqueue-callsites-not-exact")
        if reasons:
            rejected.append({"function": candidate["function"], "grammar": candidate["grammar"], "reasons": reasons})
        else:
            candidate = {**candidate, "family": LG_DESCRIPTOR_RAW,
                         "row_order": row_order[0], "row_order_evidence": row_order[1]}
            consumer = _raw_consumer_metadata(
                image, int(candidate["raw_enqueue"]),
                list(candidate["event_codes"]), load_address,
            )
            if consumer is not None:
                candidate.update(consumer)
            global_sites, row_sites = _sense_roles(image, start, start + int(matching[0]["fingerprint_size"]),
                                                   int(candidate["descriptor_pointer"]),
                                                   int(candidate["sense_site"]) - load_address)
            candidate.update({"global_sense_sites": [site + load_address for site in global_sites],
                              "row_sense_sites": [site + load_address for site in row_sites]})
            row_register = _row_register(image, start, start + int(matching[0]["fingerprint_size"]), row_sites)
            if row_register is not None:
                candidate["row_register"] = row_register
                candidate["row_register_evidence"] = (
                    "five-indexed-descending-ldrb-six-row-backedge"
                    if row_order[1] == "direct-descending-loop" else
                    "zero-indexed-ldrb-six-row-backedge"
                )
            state = _row_state(image, start, start + int(matching[0]["fingerprint_size"]))
            if state is not None:
                candidate.update({"row_state_address": state[0], "row_state_offset": state[1],
                                  "row_state_site": state[2] + load_address,
                                  "row_state_evidence": state[3]})
            accepted.append(candidate)
    if len(accepted) == 1:
        return accepted[0], "accepted", rejected
    if len(accepted) > 1:
        rejected.extend({"function": candidate["function"], "grammar": candidate["grammar"], "reasons": ["multiple-accepted-scanners"]} for candidate in accepted)
        return None, "ambiguous", rejected
    return None, "rejected" if rejected else "not-found", rejected


__all__ = (
    "find_descriptor_scan_anchors", "find_lg_descriptor_scan_anchors",
    "find_descriptor_ram_scan_shapes", "find_lg_descriptor_keypad_candidates",
    "resolve_lg_descriptor_input", "LG_DESCRIPTOR_RAW", "LG_DESCRIPTOR_RAW_FINGERPRINT",
)
