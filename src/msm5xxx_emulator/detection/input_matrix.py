"""Exact direct-MMIO keypad matrix detection."""
from __future__ import annotations

import hashlib
import json
import re
import struct

from .arm import (
    _thumb_callable_entry,
    _thumb_fingerprint,
    _thumb_function_start,
    _thumb_path_preserves_register,
    _thumb_reachable,
    _thumb_successors,
    thumb_bl_target,
    thumb_literal_value,
)


DIRECT_MATRIX_TAIL = re.compile(
    rb".\x48\x00\x79\x00\x07\x00\x0f\x0f\x28.\xd0.\x49"
    rb"\x06\x23\x08\x5c\x18\x39\x58\x43\x40\x18..",
    re.S,
)
THUMB_BL = re.compile(
    rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", re.S
)
MAX_DIRECT_MATRIX_TAILS = 64
DIRECT_MATRIX_SEMANTICS = {
    "mmio_base": "0x03000690",
    "sense_offset": "0x04",
    "sense_width": "byte",
    "sense_mask": "low-nibble",
    "no_key": "0x0F",
    "column_map_bytes": 16,
    "event_table_relation": "column_map_address - 0x18",
    "event_table_bytes": 24,
    "row_stride": 6,
    "row_count": 6,
    "sink_edge": "table result register copied to r0 then exact direct BL",
    "sink_semantics": "not-classified",
}
DIRECT_MATRIX_FINGERPRINT = hashlib.sha256(
    json.dumps(
        DIRECT_MATRIX_SEMANTICS, sort_keys=True, separators=(",", ":")
    ).encode()
).hexdigest()
SAMSUNG_RING32 = "samsung-filtered-ring32-event-queue-v1"
LG_RING256 = "lg-ring256-event-queue-v1"
UNCLASSIFIED = "unclassified"
ASCII_KEY_EVENTS = tuple(b"123456789*0#")
SINGLE_KEY_COLUMN_SENSE = (0xE, 0xD, 0xB, 0x7)
PRODUCER_FEATURES = {
    SAMSUNG_RING32: (
        "event_arg_r0_to_r7",
        "compare_0xff",
        "compare_0x60",
        "ring32_lsl27",
        "ring32_lsr27",
        "event_store_offset_2",
        "byte_write_index_store",
    ),
    LG_RING256: (
        "event_arg_r0_to_r7",
        "ring256_lsl24",
        "ring256_lsr24",
        "event_store_offset_4",
        "halfword_read_index",
        "halfword_write_index",
        "halfword_write_index_store",
    ),
}


def _producer_feature_names(word: int) -> tuple[str, ...]:
    names: list[str] = []
    opcode = word & 0xF800
    shift = word >> 6 & 0x1F
    if opcode == 0x2800 and word & 0xFF == 0xFF:
        names.append("compare_0xff")
    if word == 0x2F60:
        names.append("compare_0x60")
    if opcode == 0 and shift == 27:
        names.append("ring32_lsl27")
    if opcode == 0x0800 and shift == 27:
        names.append("ring32_lsr27")
    if opcode == 0 and shift == 24:
        names.append("ring256_lsl24")
    if opcode == 0x0800 and shift == 24:
        names.append("ring256_lsr24")
    if opcode == 0x7000:
        displacement = shift
        if word & 7 == 7 and displacement == 2:
            names.append("event_store_offset_2")
        if word & 7 == 7 and displacement == 4:
            names.append("event_store_offset_4")
        if displacement == 1:
            names.append("byte_write_index_store")
    if opcode == 0x8800:
        displacement = shift * 2
        if displacement == 0:
            names.append("halfword_read_index")
        if displacement == 2:
            names.append("halfword_write_index")
    if opcode == 0x8000 and shift * 2 == 2:
        names.append("halfword_write_index_store")
    return tuple(names)


def _thumb_linear_return(image: bytes, current: int, start: int) -> bool:
    word = struct.unpack_from("<H", image, current)[0]
    if word == 0x4770 or word & 0xFF00 == 0xBD00:
        return True
    if word & 0xFF87 != 0x4700 or current < start + 2:
        return False
    register = word >> 3 & 0xF
    previous = struct.unpack_from("<H", image, current - 2)[0]
    return (
        register < 8
        and previous & 0xFF00 == 0xBC00
        and bool(previous & 1 << register)
    )


def classify_matrix_event_sink(
        image: bytes, event_sink: int, limit: int = 0x300
) -> dict[str, object]:
    """Classify queue features present on one reachable path to a return."""
    if (event_sink < 0 or event_sink & 1 or event_sink + 4 > len(image)
            or limit <= 0):
        return {"family": UNCLASSIFIED, "features": {}}
    end = min(len(image), event_sink + limit) & ~1
    names = tuple(dict.fromkeys(
        name for required in PRODUCER_FEATURES.values() for name in required
    ))
    feature_bits = {name: 1 << index for index, name in enumerate(names)}
    required_masks = {
        family: sum(feature_bits[name] for name in required)
        for family, required in PRODUCER_FEATURES.items()
    }
    features: dict[str, set[int]] = {}
    pending = [(event_sink, 0)]
    reached: set[tuple[int, int]] = set()
    return_masks: list[int] = []
    furthest = event_sink
    state_limit = max(256, (end - event_sink) * 16)
    while pending and len(reached) < state_limit:
        current, mask = pending.pop()
        state = (current, mask)
        if (state in reached or current < event_sink or current >= end
                or current & 1):
            continue
        reached.add(state)
        furthest = max(furthest, current + 2)
        word = struct.unpack_from("<H", image, current)[0]
        current_names: list[str] = []
        if current == event_sink + 2 and word == 0x1C07:
            current_names.append("event_arg_r0_to_r7")
        current_names.extend(_producer_feature_names(word))
        for name in current_names:
            features.setdefault(name, set()).add(current)
            mask |= feature_bits[name]
        if _thumb_linear_return(image, current, event_sink):
            return_masks.append(mask)
            continue
        pending.extend(
            (successor, mask)
            for successor in _thumb_successors(image, current, end)
        )
    boundary = (
        "state-limit" if pending else
        "linear-return" if return_masks else
        "cap" if event_sink + limit <= len(image) else
        "image-end"
    )
    family = UNCLASSIFIED
    if boundary == "linear-return":
        family = next((
            candidate for candidate, required in required_masks.items()
            if any(mask & required == required for mask in return_masks)
        ), UNCLASSIFIED)
    return {
        "family": family,
        "boundary": boundary,
        "bytes": furthest - event_sink,
        "features": {
            name: sorted(offsets) for name, offsets in features.items()
        },
    }


def validate_matrix_event_sink(
        image: bytes, callsite: int, event_sink: int
) -> dict[str, object]:
    """Require the recovered direct argument edge before queue classification."""
    if thumb_bl_target(image, callsite) != event_sink:
        return {"family": UNCLASSIFIED, "features": {}}
    return classify_matrix_event_sink(image, event_sink)


def _thumb_inbound_entries(
        image: bytes, entries: set[int]) -> set[int]:
    """Find pointers and direct BL edges with a bounded candidate count."""
    inbound: set[int] = set()
    remaining = set(entries)
    for entry in tuple(remaining):
        if (entry | 1).to_bytes(4, "little") in image:
            inbound.add(entry)
            remaining.remove(entry)
    if not remaining:
        return inbound
    for match in THUMB_BL.finditer(image):
        callsite = match.start()
        if callsite & 1:
            continue
        target = thumb_bl_target(image, callsite)
        if target in remaining:
            inbound.add(target)
            remaining.remove(target)
            if not remaining:
                break
    return inbound


def find_direct_matrix_scanners(
        image: bytes, load_address: int = 0) -> list[dict[str, object]]:
    """Find a direct-MMIO six-row keypad decode-to-call grammar."""
    found: dict[int, dict[str, object]] = {}
    sites: list[int] = []
    for match in DIRECT_MATRIX_TAIL.finditer(image):
        if not match.start() & 1:
            sites.append(match.start())
            if len(sites) > MAX_DIRECT_MATRIX_TAILS:
                return []
    prologues = {
        site: _thumb_function_start(image, site) for site in sites
    }
    possible_entries = {
        prologue - 2 for prologue in prologues.values()
        if (prologue >= 2
            and struct.unpack_from("<H", image, prologue - 2)[0]
            & 0xF800 == 0x4800)
    }
    inbound_entries = _thumb_inbound_entries(image, possible_entries)
    for site in sites:
        table_load = struct.unpack_from("<H", image, site + 24)[0]
        if table_load & 0xFE00 != 0x5C00 or table_load >> 3 & 7:
            continue
        row_register = table_load >> 6 & 7
        key_register = table_load & 7
        if row_register in (0, 1, 3):
            continue
        prologue = prologues[site]
        start = _thumb_callable_entry(image, prologue, inbound_entries)
        no_key_branch = struct.unpack_from("<H", image, site + 10)[0]
        branch_delta = (no_key_branch & 0xFF) << 1
        if branch_delta & 0x100:
            branch_delta -= 0x200
        row_increment = site + 14 + branch_delta
        if not site + 26 <= row_increment <= len(image) - 12:
            continue
        increment_words = struct.unpack_from("<3H", image, row_increment)
        normalize_row = (
            0x0600 | row_register << 3 | row_register,
            0x0E00 | row_register << 3 | row_register,
        )
        same_register_increment = (
            0x3001 | row_register << 8,
            *normalize_row,
        )
        temporary_r0_increment = (
            0x1C40 | row_register << 3,
            0x0600 | row_register,
            normalize_row[1],
        )
        if increment_words not in (
                same_register_increment, temporary_r0_increment):
            continue
        if (struct.unpack_from("<H", image, row_increment + 6)[0]
                != 0x2806 | row_register << 8):
            continue

        def valid_loop_target(target: int) -> bool:
            return (
                start + 2 <= target < site
                and struct.unpack_from("<H", image, target - 2)[0]
                == (0x2000 | row_register << 8)
            )

        branch = row_increment + 8
        branch_word = struct.unpack_from("<H", image, branch)[0]
        branch_targets = [
            target for target in _thumb_successors(image, branch, len(image))
            if target != branch + 2
        ]
        row_loop_start = None
        row_loop_shape = None
        if (branch_word & 0xFF00 == 0xDB00 and len(branch_targets) == 1
                and valid_loop_target(branch_targets[0])):
            row_loop_start = branch_targets[0]
            row_loop_shape = "conditional-back"
        elif (branch_word & 0xFF00 == 0xDA00 and len(branch_targets) == 1
              and branch + 2 < branch_targets[0]
              < min(site + 0x120, len(image))):
            back_branch = branch + 2
            back_word = struct.unpack_from("<H", image, back_branch)[0]
            back_targets = [
                target for target in _thumb_successors(
                    image, back_branch, len(image)
                )
                if target != back_branch + 2
            ]
            if (back_word & 0xF800 == 0xE000 and len(back_targets) == 1
                    and valid_loop_target(back_targets[0])):
                row_loop_start = back_targets[0]
                row_loop_shape = "guard-then-back"
        if row_loop_start is None:
            continue
        if site not in _thumb_reachable(
                image, row_loop_start, row_increment):
            continue
        move_to_r0 = 0x1C00 | key_register << 3
        sink_calls: list[tuple[int, int]] = []
        sink_search_end = min(site + 0x120, len(image) - 3)
        reachable = _thumb_reachable(image, site + 26, sink_search_end)
        for current in reachable:
            word = struct.unpack_from("<H", image, current)[0]
            if word != move_to_r0 or current + 6 > sink_search_end:
                continue
            target = thumb_bl_target(image, current + 2)
            if (target is not None and 0 <= target < len(image)
                    and _thumb_path_preserves_register(
                        image, site + 26, current,
                        sink_search_end, key_register
                    )):
                sink_calls.append((current + 2, target))
        if len(sink_calls) != 1:
            continue
        sink_callsite, sink = sink_calls[0]
        register_base = thumb_literal_value(image, site, 0)
        column_table_address = thumb_literal_value(image, site + 12, 1)
        column_table = (
            column_table_address - load_address
            if column_table_address is not None else -1
        )
        if (register_base is None
                or register_base != 0x03000690
                or not 0x18 <= column_table <= len(image) - 0x10):
            continue
        fingerprint, function_size, boundary = _thumb_fingerprint(image, start)
        event_table = column_table - 0x18
        column_map = list(image[column_table:column_table + 0x10])
        if [column_map[value] for value in SINGLE_KEY_COLUMN_SENSE] != list(range(4)):
            continue
        producer = validate_matrix_event_sink(image, sink_callsite, sink)
        family = str(producer["family"])
        found[start] = {
            "grammar": "direct-low-nibble-6-row-v1",
            "grammar_fingerprint": DIRECT_MATRIX_FINGERPRINT,
            "evidence": "static-scan-to-call",
            "function": load_address + start,
            "prologue": load_address + prologue,
            "callable_entry_evidence": (
                "pc-literal+inbound-reference+post-push-consumer"
                if start != prologue else "push"
            ),
            "sense_site": load_address + site,
            "register": register_base + 4,
            "row_register": row_register,
            "key_register": key_register,
            "event_sink_callsite": load_address + sink_callsite,
            "event_sink": load_address + sink,
            "event_sink_family": None if family == UNCLASSIFIED else family,
            "event_sink_validation": (
                "required-queue-features"
                if family != UNCLASSIFIED else "argument-edge-only"
            ),
            "row_init": load_address + row_loop_start - 2,
            "row_loop_start": load_address + row_loop_start,
            "row_loop_shape": row_loop_shape,
            "rows": 6,
            "columns": 4,
            "sense_bits": 4,
            "no_key": 0xF,
            "column_table": column_table_address,
            "column_map": column_map,
            "single_key_column_sense": list(SINGLE_KEY_COLUMN_SENSE),
            "event_table": load_address + event_table,
            "event_codes": list(image[event_table:event_table + 0x18]),
            "event_table_formula": "event_codes[column * 6 + row]",
            "fingerprint": fingerprint,
            "fingerprint_size": function_size,
            "fingerprint_scope": "linear-prefix",
            "fingerprint_boundary": boundary,
        }
    return [found[start] for start in sorted(found)]


def resolve_direct_matrix_input(
        image: bytes, load_address: int = 0
) -> tuple[dict[str, object] | None, str, list[dict[str, object]]]:
    """Resolve one safe profile and retain exact candidate reject reasons."""
    scanners = find_direct_matrix_scanners(image, load_address)
    accepted: list[dict[str, object]] = []
    rejected: list[dict[str, object]] = []
    for scanner in scanners:
        events = scanner["event_codes"]
        reasons: list[str] = []
        if scanner["event_sink_family"] is None:
            reasons.append("event-sink-family-unclassified")
        if any(events.count(event) == 0 for event in ASCII_KEY_EVENTS):
            reasons.append("numeric-event-missing")
        if any(events.count(event) > 1 for event in ASCII_KEY_EVENTS):
            reasons.append("numeric-event-duplicated")
        if reasons:
            rejected.append({
                "function": scanner["function"],
                "grammar_fingerprint": scanner["grammar_fingerprint"],
                "reasons": reasons,
            })
        else:
            accepted.append(scanner)
    if len(accepted) == 1:
        return accepted[0], "accepted", rejected
    if len(accepted) > 1:
        rejected.extend({
            "function": scanner["function"],
            "grammar_fingerprint": scanner["grammar_fingerprint"],
            "reasons": ["multiple-accepted-scanners"],
        } for scanner in accepted)
        return None, "ambiguous", rejected
    return None, "rejected" if rejected else "not-found", rejected


def detect_direct_matrix_input(
        image: bytes, load_address: int = 0
) -> dict[str, object] | None:
    """Return one queue-closed scanner with an unambiguous numeric layout."""
    return resolve_direct_matrix_input(image, load_address)[0]


__all__ = (
    "ASCII_KEY_EVENTS",
    "DIRECT_MATRIX_FINGERPRINT",
    "LG_RING256",
    "SAMSUNG_RING32",
    "classify_matrix_event_sink",
    "detect_direct_matrix_input",
    "find_direct_matrix_scanners",
    "resolve_direct_matrix_input",
    "validate_matrix_event_sink",
)
