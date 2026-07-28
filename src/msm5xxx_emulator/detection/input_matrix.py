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
    _thumb_reachable_preserving_register,
    _thumb_successors,
    thumb_bl_target,
    thumb_literal_value,
)
from .signatures import find_all


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
SAMSUNG_DUAL_PLANE_RING32 = "samsung-dual-plane-ring32-event-queue-v1"
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
    SAMSUNG_DUAL_PLANE_RING32: (
        "event_arg_r0_to_r4",
        "event_aux_r1_to_r5",
        "ring32_lsl27",
        "ring32_lsr27",
        "dual_plane_event_store",
        "dual_plane_aux_store",
        "byte_write_index_store",
        "halfword_read_index",
    ),
}
SAMSUNG_RAW_ENQUEUE_TAIL = bytes.fromhex(
    "0e48120c417805784b1cdb06db0eab4206d009188f7041780131c906c90e4170"
)
SAMSUNG_RAW_DEQUEUE = bytes.fromhex(
    "064a50781178884201d10020f74650180131c906c90e80781170f746"
)
SAMSUNG_RAW_RECEIVER_TAIL = bytes.fromhex("071c00d0")
SAMSUNG_RAW_R7_MOVE = bytes.fromhex("071c")
SAMSUNG_RAW_CONSUMER_EVIDENCE = "samsung-byte-ring32-r0-receiver-v1"
SAMSUNG_RAW_R7_CONSUMER_EVIDENCE = "samsung-byte-ring32-r7-task-dispatch-v1"
_SAMSUNG_CONSUMER_ROUTE_EVENTS = (0x54, 0x55, 0x63, 0x64)
_SAMSUNG_CONSUMER_ROUTE_EVIDENCE = "samsung-ring32-r7-route-v1"
_SAMSUNG_CONSUMER_ROUTE_LIMIT = 0x1000
N330_5X6_ENTRY = bytes.fromhex(
    "f0b501260024f1058bb0b04823f046fa002106224a43002000236a4400231354"
    "01300006000e0628f8d301310906090e0529eed3"
)
N330_PRESS_PREFIX = bytes.fromhex(
    "285d2a2801d052280dd1ac490978002909d0ff212d310122480067f066f9"
    "285da74908800be00021"
)
N330_RELEASE_PREFIX = bytes.fromhex(
    "295d081c0938f12803d889300006000e00e08020"
)
N330_GLOBAL_SENSE = bytes.fromhex("9b4f786b0068c006c00e1f2871d0")
N330_ROW_SENSE = bytes.fromhex("774f786b0068c206d20e1f2a15d0")
N330_5X6_SEMANTICS = {
    "rows": 6,
    "columns": 5,
    "register": "0x09000070",
    "register_size": 4,
    "sense_mask": "0x1f",
    "senses": (0x1E, 0x1D, 0x1B, 0x17, 0x0F),
    "release": "event-plus-0x80; invalid fallback=0x80",
}
N330_5X6_FINGERPRINT = hashlib.sha256(
    json.dumps(N330_5X6_SEMANTICS, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


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
        if current == event_sink + 2 and word == 0x1C04:
            current_names.append("event_arg_r0_to_r4")
        if current == event_sink + 6 and word == 0x1C0D:
            current_names.append("event_aux_r1_to_r5")
        if word == 0x7084:
            current_names.append("dual_plane_event_store")
        if word == 0x7085:
            current_names.append("dual_plane_aux_store")
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
        dual_plane_required = required_masks[SAMSUNG_DUAL_PLANE_RING32]
        if any(mask & dual_plane_required == dual_plane_required
               for mask in return_masks):
            family = SAMSUNG_DUAL_PLANE_RING32
        else:
            family = next((
                candidate for candidate, required in required_masks.items()
                if candidate != SAMSUNG_DUAL_PLANE_RING32
                and any(mask & required == required for mask in return_masks)
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


def _samsung_raw_consumer_metadata(
        image: bytes, event_sink: int, load_address: int
) -> dict[str, object] | None:
    """Recover one complete Samsung byte-ring observer chain."""
    tail = event_sink + 0x4A
    if (event_sink < 0 or event_sink & 1
            or image[tail:tail + len(SAMSUNG_RAW_ENQUEUE_TAIL)]
            != SAMSUNG_RAW_ENQUEUE_TAIL):
        return None
    ring = thumb_literal_value(image, tail, 0)
    if ring is None or not 0x01000000 <= ring < 0x04000000:
        return None
    dequeues = [position for position in find_all(image, SAMSUNG_RAW_DEQUEUE)
                if not position & 1
                and thumb_literal_value(image, position, 2) == ring]
    if len(dequeues) != 1:
        return None
    dequeue = dequeues[0]
    receivers = [
        tail - 4 for tail in find_all(image, SAMSUNG_RAW_RECEIVER_TAIL)
        if tail >= 4 and not (tail - 4) & 1
        and thumb_bl_target(image, tail - 4) == dequeue
    ]
    if len(receivers) != 1:
        return None
    receiver = receivers[0]
    return {
        "raw_ring": ring,
        "raw_ring_capacity": 32,
        "raw_enqueue_store": load_address + event_sink + 0x5E,
        "raw_enqueue_register": 7,
        "raw_dequeue": load_address + dequeue,
        "raw_dequeue_return": load_address + dequeue + 0x1A,
        "raw_task_entry": load_address + receiver + 4,
        "raw_task_register": 0,
        "raw_consumer_evidence": SAMSUNG_RAW_CONSUMER_EVIDENCE,
    }


def _samsung_raw_r7_consumer_metadata(
        image: bytes, event_sink: int, event_codes: list[int],
        load_address: int,
) -> dict[str, object] | None:
    """Recover an exact r7 dequeue-task observer without assigning key meaning."""
    if event_sink < 0 or event_sink & 1:
        return None
    enqueue_end = min(len(image), event_sink + 0x70)
    rings = [thumb_literal_value(image, current, 0)
             for current in range(event_sink + 0x40, enqueue_end - 1, 2)
             if struct.unpack_from("<H", image, current)[0] & 0xF800 == 0x4800
             and struct.unpack_from("<H", image, current)[0] >> 8 & 7 == 0]
    rings = [ring for ring in rings
             if ring is not None and 0x01000000 <= ring < 0x04000000]
    if len(rings) != 1:
        return None
    ring = rings[0]
    stores = [current for current in range(event_sink + 0x40, enqueue_end - 1, 2)
              if (struct.unpack_from("<H", image, current)[0] & 0xF800 == 0x7000
                  and struct.unpack_from("<H", image, current)[0] & 7 == 7
                  and struct.unpack_from("<H", image, current)[0] >> 6 & 0x1F == 2)]
    if (len(stores) != 1
            or stores[0] not in _thumb_reachable(
                image, event_sink, enqueue_end
            )):
        return None
    dequeues = [position for position in find_all(image, SAMSUNG_RAW_DEQUEUE)
                if not position & 1
                and thumb_literal_value(image, position, 2) == ring]
    if len(dequeues) != 1:
        return None
    dequeue = dequeues[0]
    tasks: list[tuple[int, int]] = []
    for move in find_all(image, SAMSUNG_RAW_R7_MOVE):
        call = move - 4
        if (call < 0 or call & 1 or thumb_bl_target(image, call) != dequeue
                or call + 10 > len(image)
                or struct.unpack_from("<H", image, call + 4)[0] != 0x1C07
                or struct.unpack_from("<H", image, call + 6)[0] & 0xFF00
                != 0xD000
                or struct.unpack_from("<H", image, call + 8)[0] & 0xF800
                != 0xE000):
            continue
        branches = _thumb_successors(image, call + 8, len(image))
        if len(branches) != 1:
            continue
        task = branches[0]
        end = min(len(image), task + 0x1000)
        consumers: dict[int, set[int]] = {}
        for current in _thumb_reachable_preserving_register(
                image, task, end, 7):
            word = struct.unpack_from("<H", image, current)[0]
            if (word & 0xFF00 != 0x2F00 or word & 0xFF not in event_codes
                    or current + 4 > len(image)):
                continue
            successors = _thumb_successors(image, current + 2, len(image))
            target = next((item for item in successors if item != current + 4), None)
            if (target is None or target + 6 > len(image)
                    or struct.unpack_from("<H", image, target)[0] != 0x1C38):
                continue
            consumer = thumb_bl_target(image, target + 2)
            if consumer is not None:
                consumers.setdefault(consumer, set()).add(word & 0xFF)
        closed = [consumer for consumer, events in consumers.items()
                  if len(events) >= 3]
        if len(closed) == 1:
            tasks.append((call, task))
    if len(tasks) != 1:
        return None
    call, task = tasks[0]
    return {
        "raw_ring": ring,
        "raw_ring_capacity": 32,
        "raw_enqueue_store": load_address + stores[0],
        "raw_enqueue_register": 7,
        "raw_dequeue": load_address + dequeue,
        "raw_dequeue_return": load_address + call + 4,
        "raw_task_entry": load_address + task,
        "raw_task_register": 7,
        "raw_consumer_evidence": SAMSUNG_RAW_R7_CONSUMER_EVIDENCE,
    }


def _samsung_consumer_route_handler(
        image: bytes, metadata: dict[str, object], load_address: int
) -> tuple[int, str] | None:
    """Recover the r7 handler already closed by Samsung raw-consumer evidence."""
    entry = metadata.get("raw_task_entry")
    register = metadata.get("raw_task_register")
    evidence = metadata.get("raw_consumer_evidence")
    if type(entry) is not int or type(register) is not int:
        return None
    entry -= load_address
    if not 0 <= entry <= len(image) - 2 or entry & 1:
        return None
    if register == 7:
        if evidence != SAMSUNG_RAW_R7_CONSUMER_EVIDENCE:
            return None
        return entry, evidence
    if register != 0 or evidence != SAMSUNG_RAW_CONSUMER_EVIDENCE:
        return None
    if (entry + 6 > len(image)
            or struct.unpack_from("<2H", image, entry) != (0x1C07, 0xD000)
            or struct.unpack_from("<H", image, entry + 4)[0] & 0xF800
            != 0xE000):
        return None
    targets = _thumb_successors(image, entry + 4, len(image))
    if len(targets) != 1:
        return None
    handler = targets[0]
    if not 0 <= handler <= len(image) - 2 or handler & 1:
        return None
    return handler, evidence


def _samsung_route_match(
        image: bytes, compare: int, end: int
) -> tuple[str, int] | None:
    """Follow r7 equality through an immediate conditional or one plain B."""
    current = compare + 2
    for hop in range(2):
        if not 0 <= current <= end - 2:
            return None
        word = struct.unpack_from("<H", image, current)[0]
        condition = word & 0xFF00
        if condition in (0xD000, 0xD100):
            successors = _thumb_successors(image, current, end)
            fallthrough = current + 2
            targets = [target for target in successors if target != fallthrough]
            if len(successors) != 2 or len(targets) != 1:
                return None
            matched = targets[0] if condition == 0xD000 else fallthrough
            if not 0 <= matched <= end - 2:
                return None
            return ("eq" if condition == 0xD000 else "ne"), matched
        if hop or word & 0xF800 != 0xE000:
            return None
        targets = _thumb_successors(image, current, end)
        if len(targets) != 1:
            return None
        current = targets[0]
    return None


def _samsung_consumer_route_metadata(
        image: bytes, metadata: dict[str, object], load_address: int
) -> dict[str, object]:
    """Fingerprint closed r7 event routes without assigning key semantics."""
    recovered = _samsung_consumer_route_handler(image, metadata, load_address)
    if recovered is None:
        return {
            "consumer_route_status": "not-closed",
            "consumer_route_reject_reason": "handler-unclosed",
        }
    handler, handoff = recovered
    end = min(len(image), handler + _SAMSUNG_CONSUMER_ROUTE_LIMIT)
    reachable = _thumb_reachable_preserving_register(image, handler, end, 7)
    event_fingerprints: dict[str, str] = {}
    for event in _SAMSUNG_CONSUMER_ROUTE_EVENTS:
        occurrences: list[tuple[str, str, int, str]] = []
        for compare in sorted(reachable):
            if struct.unpack_from("<H", image, compare)[0] != (0x2F00 | event):
                continue
            match = _samsung_route_match(image, compare, end)
            if match is None:
                return {
                    "consumer_route_status": "not-closed",
                    "consumer_route_reject_reason": (
                        f"event-{event:02x}-condition-unclosed"
                    ),
                }
            condition, route = match
            fingerprint, size, boundary = _thumb_fingerprint(image, route)
            occurrences.append((condition, fingerprint, size, boundary))
        if not occurrences:
            return {
                "consumer_route_status": "not-closed",
                "consumer_route_reject_reason": f"event-{event:02x}-missing",
            }
        encoded = json.dumps(
            sorted(occurrences), separators=(",", ":")
        ).encode()
        event_fingerprints[f"0x{event:02X}"] = hashlib.sha256(encoded).hexdigest()
    encoded = json.dumps(
        {"handoff": handoff, "events": event_fingerprints},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return {
        "consumer_route_status": "closed",
        "consumer_route_evidence": _SAMSUNG_CONSUMER_ROUTE_EVIDENCE,
        "consumer_route_fingerprint": hashlib.sha256(encoded).hexdigest(),
        "consumer_route_event_fingerprints": event_fingerprints,
    }


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


def _find_n330_5x6_scanners(
        image: bytes, load_address: int
) -> list[dict[str, object]]:
    """Recover the closed temporary N330 producer grammar."""
    found: list[dict[str, object]] = []
    start = 0
    while True:
        scanner = image.find(N330_5X6_ENTRY, start)
        if scanner < 0:
            return found
        start = scanner + 1
        press = scanner + 0x3EC
        release = scanner + 0x472
        press_call = press + len(N330_PRESS_PREFIX)
        release_call = release + len(N330_RELEASE_PREFIX)
        if (image[scanner + 0x6A:scanner + 0x6A + len(N330_GLOBAL_SENSE)]
                != N330_GLOBAL_SENSE
                or image[scanner + 0xF8:scanner + 0xF8 + len(N330_ROW_SENSE)]
                != N330_ROW_SENSE
                or image[press:press_call] != N330_PRESS_PREFIX
                or image[release:release_call] != N330_RELEASE_PREFIX):
            continue
        queue = thumb_bl_target(image, press_call)
        if queue is None or thumb_bl_target(image, release_call) != queue:
            continue
        producer = classify_matrix_event_sink(image, queue)
        if producer["family"] != SAMSUNG_DUAL_PLANE_RING32:
            continue
        literals = (scanner + 0x6A0, scanner + 0x90C)
        if any(literal + 4 > len(image) for literal in literals):
            continue
        pointers = tuple(struct.unpack_from("<I", image, literal)[0]
                         for literal in literals)
        table = pointers[0] - load_address
        if (len(set(pointers)) != 1 or table < 0 or table + 30 > len(image)):
            continue
        events = list(image[table:table + 30])
        if events.count(0) != 5 or events[-5:] != [0] * 5:
            continue
        found.append({
            "grammar": "n330-5x6-dual-plane-ring32-v1",
            "grammar_fingerprint": N330_5X6_FINGERPRINT,
            "evidence": "exact-entry+press-release+table-xrefs",
            "function": load_address + scanner,
            "sense_site": load_address + scanner + 0xFC,
            "global_sense_sites": [load_address + scanner + 0x6E],
            "row_sense_sites": [load_address + scanner + 0xFC],
            "register": 0x09000070,
            "register_size": 4,
            "register_reset": 0x1F,
            "row_register": 5,
            "rows": 6,
            "columns": 5,
            "sense_mask": 0x1F,
            "no_key": 0x1F,
            "single_key_column_sense": [0x1E, 0x1D, 0x1B, 0x17, 0x0F],
            "dynamic_mapped_sense": True,
            "mmio_map_start": 0x09000000,
            "mmio_map_size": 0x1000,
            "event_table": pointers[0],
            "event_table_bytes": events,
            "event_codes": events,
            "event_table_formula": "event_codes[column * 6 + row]",
            "event_table_literal_xrefs": [load_address + literal for literal in literals],
            "event_sink_callsite": load_address + press_call,
            "event_sink": load_address + queue,
            "event_sink_family": SAMSUNG_DUAL_PLANE_RING32,
            "event_sink_validation": "required-dual-plane-queue-features",
            "press_event_load": load_address + press,
            "release_event_load": load_address + release,
            "release_callsite": load_address + release_call,
            "release_grammar": "event-plus-0x80; invalid fallback=0x80",
        })


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
    return ([_ for _ in _find_n330_5x6_scanners(image, load_address)]
            + [found[start] for start in sorted(found)])


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
        if scanner["event_sink_family"] != SAMSUNG_DUAL_PLANE_RING32:
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
            if scanner["event_sink_family"] == SAMSUNG_RING32:
                metadata = _samsung_raw_consumer_metadata(
                    image, int(scanner["event_sink"]) - load_address,
                    load_address,
                )
                if metadata is None:
                    metadata = _samsung_raw_r7_consumer_metadata(
                        image, int(scanner["event_sink"]) - load_address,
                        list(events), load_address,
                    )
                if metadata is not None:
                    scanner.update(metadata)
                    scanner.update(_samsung_consumer_route_metadata(
                        image, metadata, load_address,
                    ))
                else:
                    scanner["consumer_route_status"] = "raw-consumer-not-closed"
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
    "N330_5X6_FINGERPRINT",
    "SAMSUNG_RING32",
    "SAMSUNG_DUAL_PLANE_RING32",
    "classify_matrix_event_sink",
    "detect_direct_matrix_input",
    "find_direct_matrix_scanners",
    "resolve_direct_matrix_input",
    "validate_matrix_event_sink",
)
