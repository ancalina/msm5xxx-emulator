from __future__ import annotations
from msm5xxx_emulator.detection.fact_bodies import thumb_body
import hashlib
import json
import re

DIRECT_MATRIX_TAIL = re.compile(rb".\x48\x00\x79\x00\x07\x00\x0f\x0f\x28.\xd0.\x49" rb"\x06\x23\x08\x5c\x18\x39\x58\x43\x40\x18..", re.S,)
THUMB_BL = re.compile(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", re.S)
MAX_DIRECT_MATRIX_TAILS = 64
DIRECT_MATRIX_SEMANTICS = {'mmio_base': '0x03000690', 'sense_offset': '0x04', 'sense_width': 'byte', 'sense_mask': 'low-nibble', 'no_key': '0x0F',
    'column_map_bytes': 16, 'event_table_relation': 'column_map_address - 0x18', 'event_table_bytes': 24, 'row_stride': 6, 'row_count': 6, 'sink_edge':
    'table result register copied to r0 then exact direct BL', 'sink_semantics': 'not-classified'}
DIRECT_MATRIX_FINGERPRINT = hashlib.sha256(json.dumps(DIRECT_MATRIX_SEMANTICS, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
SAMSUNG_RING32 = "samsung-filtered-ring32-event-queue-v1"
SAMSUNG_DUAL_PLANE_RING32 = "samsung-dual-plane-ring32-event-queue-v1"
LG_RING256 = "lg-ring256-event-queue-v1"
UNCLASSIFIED = "unclassified"
ASCII_KEY_EVENTS = tuple(b"123456789*0#")
SINGLE_KEY_COLUMN_SENSE = (0xE, 0xD, 0xB, 0x7)
PRODUCER_FEATURES = { SAMSUNG_RING32: ("event_arg_r0_to_r7", "compare_0xff", "compare_0x60", "ring32_lsl27", "ring32_lsr27", "event_store_offset_2",
    "byte_write_index_store",), LG_RING256: ("event_arg_r0_to_r7", "ring256_lsl24", "ring256_lsr24", "event_store_offset_4", "halfword_read_index",
    "halfword_write_index", "halfword_write_index_store",), SAMSUNG_DUAL_PLANE_RING32: ("event_arg_r0_to_r4", "event_aux_r1_to_r5", "ring32_lsl27",
    "ring32_lsr27", "dual_plane_event_store", "dual_plane_aux_store", "byte_write_index_store", "halfword_read_index",), }
SAMSUNG_RAW_ENQUEUE_TAIL = bytes.fromhex("0e48120c417805784b1cdb06db0eab4206d009188f7041780131c906c90e4170")
SAMSUNG_RAW_DEQUEUE = bytes.fromhex("064a50781178884201d10020f74650180131c906c90e80781170f746")
SAMSUNG_RAW_RECEIVER_TAIL = bytes.fromhex("071c00d0")
SAMSUNG_RAW_R7_MOVE = bytes.fromhex("071c")
SAMSUNG_RAW_CONSUMER_EVIDENCE = "samsung-byte-ring32-r0-receiver-v1"
SAMSUNG_RAW_R7_CONSUMER_EVIDENCE = "samsung-byte-ring32-r7-task-dispatch-v1"
SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE = ("samsung-byte-ring32-saved-task-dispatch-v1")
_SAMSUNG_CONSUMER_ROUTE_EVENTS = (0x54, 0x55, 0x63, 0x64)
_SAMSUNG_CONSUMER_ROUTE_EVIDENCE = "samsung-ring32-r7-route-v1"
_SAMSUNG_CONSUMER_ROUTE_LIMIT = 0x1000
N330_5X6_ENTRY = bytes.fromhex("f0b501260024f1058bb0b04823f046fa002106224a43002000236a4400231354" "01300006000e0628f8d301310906090e0529eed3")
N330_PRESS_PREFIX = bytes.fromhex("285d2a2801d052280dd1ac490978002909d0ff212d310122480067f066f9" "285da74908800be00021")
N330_RELEASE_PREFIX = bytes.fromhex("295d081c0938f12803d889300006000e00e08020")
N330_GLOBAL_SENSE = bytes.fromhex("9b4f786b0068c006c00e1f2871d0")
N330_ROW_SENSE = bytes.fromhex("774f786b0068c206d20e1f2a15d0")
N330_5X6_SEMANTICS = {'rows': 6, 'columns': 5, 'register': '0x09000070', 'register_size': 4, 'sense_mask': '0x1f', 'senses': (30, 29, 27, 23, 15), 'release':
    'event-plus-0x80; invalid fallback=0x80'}
N330_5X6_FINGERPRINT = hashlib.sha256(json.dumps(N330_5X6_SEMANTICS, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _matches_relocated_thumb_bl(image: bytes, position: int, template: bytes, bl_offset: int) -> bool:
    """Match fixed code around one relocation-sensitive Thumb BL."""
    from . import facts_for
    end = position + len(template)
    return (0 <= position <= len(image) - len(template) and image[position:position + bl_offset] == template[: bl_offset] and facts_for(image).thumb_call_target(position
        + bl_offset) is not None and image[position + bl_offset + 4:end] == template[bl_offset + 4:])

SAMSUNG_SIDEBAND_51_WORDS = { 0x26: 0x7900, 0x28: 0x2210, 0x2A: 0x4002, 0x36: 0x2A00, 0x42: 0x2A05, 0x50: 0x2A05, 0x56: 0x2A0A, 0x7E: 0x2A0A, 0xC6: 0x2751,
    0x294: 0x7BD8, 0x29E: 0x2803, 0x2A2: 0x2F00, 0x2AE: 0x20FF, 0x2C0: 0x722F, 0x2C6: 0x2002, 0x2C8: 0x73D8, 0x2D4: 0x7A28, 0x2D6: 0x4287, 0x2DA: 0x2003, 0x2DC:
    0x73D8, 0x2F8: 0x1C38, }

def _accepted_samsung_sideband_51(press_callsite: int, release_callsite: int, event_sink: int, load_address: int) -> dict[str, object]:
    return { "sideband_detection_status": "accepted", "sideband_detection_reject_reasons":[], "sideband_producers":[{ "grammar":
        "active-low-mmio-bit-debounced-event-v1", "evidence": "literal+mask+local-state+shared-queue", "semantic_status": "temporary-evidence-gated",
        "semantic_key": 7, "semantic_name": "END", "semantic_evidence": "event-0x51-independent-keyemu-maps", "event": 0x51, "event_register": 7, "register":
        0x03000694, "register_width": 1, "mask": 0x10, "polarity": "active-low", "press_callsite": load_address + press_callsite, "release_event": 0xFF,
        "release_callsite": load_address + release_callsite, "event_sink": load_address + event_sink, }], }

def _samsung_sideband_51_metadata(image: bytes, scanner: int, event_sink: int, load_address: int) -> dict[str, object]:
    """Describe one closed sideband event producer without owning its MMIO."""
    from . import SAMSUNG_SIDEBAND_51_WORDS, _accepted_samsung_sideband_51, _thumb_successors, facts_for, struct
    if scanner < 0 or scanner + 0x330 > len(image):
        return {}
    if (facts_for(image).thumb_literal_value(scanner + 0x24, 0) != 0x03000690 or struct.unpack_from("<H", image, scanner + 0xC6)[0] != 0x2751):
        return {}
    reasons = [f"shape-word-0x{offset:03x}-mismatch"
               for offset, word in SAMSUNG_SIDEBAND_51_WORDS.items()
               if struct.unpack_from("<H", image, scanner + offset)[0]
               != word]
    if set(_thumb_successors(image, scanner + 0x3A, scanner + 0x330)) != {scanner + 0x3C, scanner + 0x60}:
        reasons.append("active-low-branch-not-closed")
    if tuple(_thumb_successors(image, scanner + 0xC8, scanner + 0x330)) != (scanner + 0x27C,):
        reasons.append("event-state-branch-not-closed")
    if facts_for(image).thumb_call_target(scanner + 0x2B0) != event_sink:
        reasons.append("release-sink-mismatch")
    if facts_for(image).thumb_call_target(scanner + 0x2FA) != event_sink:
        reasons.append("press-sink-mismatch")
    if reasons:
        return { "sideband_detection_status": "rejected", "sideband_detection_reject_reasons": reasons, }
    return _accepted_samsung_sideband_51(scanner + 0x2FA, scanner + 0x2B0, event_sink, load_address)

_SAMSUNG_FLAG_SIDEBAND_CONTRACTS = ((0x0, 0x24, "d5ae96781ff473beefc005db98a2b3b8457c53b083c844b9a8b82f98595a981d", ((6, 1587208), (10, -652), (20, -300), (30,
    1587008))), (0x24, 0xa6, "3a39ae77e743c6c359591246c5226d2a956fd0da627c93796f4142aba0961bcd", ()), (0xe4, 0xe,
    "76f10e3c8c1c70f1871a60a026777e6908eb4747f9a1f55bd9a5c9e23afaab5d", ((10, -1112),)), (0x27e, 0xa6,
    "022984a41c17de11a4f99a945b710899908a83d4c7a47510e22b7075e4401551", ((4, 1586394), (52, -1522), (134, 399606), (146, -1522))),)
_SAMSUNG_FLAG_SIDEBAND_SINK = (0xc6, "8c94142d0256a9ff66c4ef0dce00f7d728ac7fa6f96f4232ce07226cbc16e68f", ((26, 219948), (154, -45292), (188, 1588080)))

def _samsung_flags_sideband_51_metadata(image: bytes, profile: dict[str, object], load_address: int,) -> dict[str, object]:
    """Separate exact producer; preserve rejection outside this opcode class."""
    from . import SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE, SAMSUNG_RING32, _SAMSUNG_FLAG_SIDEBAND_CONTRACTS, _SAMSUNG_FLAG_SIDEBAND_SINK, _accepted_samsung_sideband_51, _thumb_reachable, facts_for, hashlib, struct
    fields = [profile.get(key) for key in ("function", "sense_site", "event_sink", "raw_dequeue", "raw_ring")]
    if (profile.get("grammar") != "direct-low-nibble-6-row-v1" or profile.get("event_sink_family") != SAMSUNG_RING32 or profile.get("raw_consumer_evidence") !=
        SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE or type(profile.get("raw_task_register")) is not int or profile.get("raw_task_register") != 7 or not isinstance(profile.get("event_codes"),
        (list, tuple)) or any(type(value) is not int for value in fields)):
        return {}
    scanner, sense, sink, dequeue, ring = fields
    scanner, sense, sink, dequeue = (value - load_address for value in (scanner, sense, sink, dequeue))
    if (not 0 <= scanner <= len(image) - 0x324 or scanner & 1 or sense != scanner + 0x252):
        return {}
    # ANDS flags survive only these three literal LDRs, then original BNE.
    if image[scanner + 0x26:scanner + 0x2C] != bytes.fromhex("007910220240"):
        return {}
    def reject(reason):
        return {"sideband_detection_status": "rejected", "sideband_detection_reject_reasons":["flags-sideband-" + reason]}
    def shape(at, size, digest, calls) -> bool:
        links = calls
        if at is None or at & 1:
            return False
        body = thumb_body(facts_for(image), at, size, literal_offsets=(), call_fill=bytes.fromhex('00f000f8'))
        if body is None or body.sha256 != digest:
            return False
        targets = dict(body.calls)
        return all(0 <= at + delta <= len(image)-2 and targets.get(offset) == at + delta for offset, delta in links)
    if (any(not shape(scanner + offset, size, digest, calls) for offset, size, digest, calls in _SAMSUNG_FLAG_SIDEBAND_CONTRACTS) or not shape(sink, *_SAMSUNG_FLAG_SIDEBAND_SINK)):
        return reject("opcode-call-contract")
    def literal(offset, register):
        return facts_for(image).thumb_literal_value(scanner + offset, register)
    owner, flag = literal(0x30, 5), literal(0x2C, 0)
    if (any(type(value) is not int or value & 3 or not 0x01000020 <= value <= 0x04000000 - 0xC for value in (owner, flag, ring)) or len({owner, flag, ring}) !=
        3 or ring > 0x04000000 - 0x24):
        return reject("ram-owner-bounds")
    touched = ((owner - 0x20, owner + 0xC), (flag - 0x20, flag + 4), (ring, ring + 0x24))
    if any(max(left[0], right[0]) < min(left[1], right[1]) for index, left in enumerate(touched) for right in touched[:index]):
        return reject("ram-owner-overlap")
    if (literal(0x24, 0) != 0x03000690 or any(literal(offset, register) != owner for offset, register in ((0x5C, 4), (0x74, 4), (0x9C, 4), (0x292, 0))) or any(literal(offset,
        register) != flag for offset, register in ((0x5E, 3), (0xA8, 2))) or facts_for(image).thumb_literal_value(sink + 0x58, 2) != ring or facts_for(image).thumb_literal_value(dequeue,
        2) != ring):
        return reject("flag-state-ring-identity")
    # These contextual byte loads may suppress an event; never invent their state.
    if any(type(value) is not int or not 0x01000000 <= value < 0x04000000 - 5 for value in (literal(0x2E, 1), literal(0xBA, 1), literal(0x286, 0))):
        return reject("context-pointer-bounds")
    if any(facts_for(image).thumb_call_target(scanner + offset) != sink for offset in (0xEE, 0x2B2, 0x310)):
        return reject("shared-sinks")
    before = _thumb_reachable(image, scanner, sense)
    direct_releases = [site + 2 for site in before if site + 6 <= sense and image[site:site + 2] == b"\xff\x20" and facts_for(image).thumb_call_target(site + 2)
        == sink]
    events = [site for site in before if image[site:site + 2] == b"\x51\x27"]
    if direct_releases !=[scanner + 0xEE] or events !=[scanner + 0xC6]:
        return reject("producer-release-ambiguity")
    if 0x51 in profile.get("event_codes", ()):
        return reject("matrix-event-collision")
    return _accepted_samsung_sideband_51(scanner + 0x310, scanner + 0x2B2, sink, load_address)

def _thumb_immediate_byte_stores(image: bytes, path: set[int], end: int, value: int) -> set[tuple[int, int, int]]:
    """Return STRB sites fed by one preserved MOVS immediate."""
    from . import _thumb_reachable_preserving_register, struct
    stores: set[tuple[int, int, int]] = set()
    for move in path:
        word = struct.unpack_from("<H", image, move)[0]
        if word & 0xF800 != 0x2000 or word & 0xFF != value:
            continue
        register = word >> 8 & 7
        for site in _thumb_reachable_preserving_register(image, move + 2, end, register):
            if site not in path:
                continue
            store = struct.unpack_from("<H", image, site)[0]
            if store & 0xF800 == 0x7000 and store & 7 == register:
                stores.add((site, store >> 3 & 7, store >> 6 & 0x1F))
    return stores

def _samsung_sideband_51_family_metadata(image: bytes, scanner: int, sense_site: int, event_sink: int, load_address: int) -> dict[str, object]:
    """Close compiler variants of one bit4-to-event-0x51 producer."""
    from . import _accepted_samsung_sideband_51, _thumb_immediate_byte_stores, _thumb_path_preserves_register, _thumb_reachable, _thumb_reachable_preserving_register, _thumb_successors, facts_for, struct
    end = min(len(image), scanner + 0x600) & ~1
    if not 0 <= scanner < sense_site < end:
        return {}
    reachable = _thumb_reachable(image, scanner, end)
    search_end = min(sense_site, scanner + 0x100)
    base_reads: list[tuple[int, int, int]] = []
    for read in sorted(site for site in reachable if scanner <= site < search_end):
        word = struct.unpack_from("<H", image, read)[0]
        if word & 0xF800 != 0x7800 or word >> 6 & 0x1F != 4:
            continue
        value_register = word & 7
        base_register = word >> 3 & 7
        loads = [site for site in range(max(scanner, read - 0x30), read, 2) if (site in reachable and struct.unpack_from("<H", image, site)[0] & 0xF800 ==
            0x4800 and struct.unpack_from("<H", image, site)[0] >> 8 & 7 == base_register and facts_for(image).thumb_literal_value(site, base_register) ==
            0x03000690 and _thumb_path_preserves_register(image, site + 2, read, search_end, base_register))]
        if len(loads) == 1:
            base_reads.append((read, value_register, loads[0]))
    event_sites = [site for site in reachable if scanner <= site < sense_site and struct.unpack_from("<H", image, site)[0] == 0x2751]
    if not base_reads and not event_sites:
        return {}
    if not base_reads or not event_sites:
        return { "sideband_detection_status": "rejected", "sideband_detection_reject_reasons":[("bit4-mmio-read-not-found" if not base_reads else
            "event-0x51-materialization-not-found")], }
    chains: list[tuple[int, int, int, int, int | None, int]] = []
    for read, value_register, load in base_reads:
        for mask_site in range(read + 2, min(read + 0x10, sense_site), 2):
            mask_word = struct.unpack_from("<H", image, mask_site)[0]
            if (mask_site not in reachable or mask_word & 0xF800 != 0x2000 or mask_word & 0xFF != 0x10):
                continue
            mask_register = mask_word >> 8 & 7
            if mask_register == value_register:
                continue
            for and_site in range(mask_site + 2, min(mask_site + 0x10, sense_site), 2):
                and_word = struct.unpack_from("<H", image, and_site)[0]
                if (and_site not in reachable or and_word & 0xFFC0 != 0x4000 or {and_word & 7, and_word >> 3 & 7 } != {value_register, mask_register} or not
                    _thumb_path_preserves_register(image, read + 2, and_site, sense_site, value_register) or not _thumb_path_preserves_register(image, mask_site
                    + 2, and_site, sense_site, mask_register)):
                    continue
                result_register = and_word & 7
                # Literal LDRs preserve the ANDS flags used by this compiler variant.
                for flag_branch in range(and_site + 2, min(and_site + 0x10, sense_site), 2):
                    flag_word = struct.unpack_from("<H", image, flag_branch)[0]
                    if flag_branch not in reachable:
                        break
                    if flag_word & 0xFF00 == 0xD100:
                        chains.append((load, read, mask_site, and_site, None, flag_branch))
                        break
                    if (flag_word & 0xF800 != 0x4800 or facts_for(image).thumb_literal_value(flag_branch, flag_word >> 8 & 7) is None):
                        break
                for compare in range(and_site + 2, min(and_site + 0x20, sense_site), 2):
                    if (compare in reachable and struct.unpack_from("<H", image, compare)[0] == 0x2800 | result_register << 8 and struct.unpack_from("<H", image,
                        compare + 2)[0] & 0xFF00 == 0xD100 and _thumb_path_preserves_register(image, and_site + 2, compare, sense_site, result_register)):
                        chains.append((load, read, mask_site, and_site, compare, compare + 2,))
                        break
    reasons: list[str] = []
    if len(chains) != 1:
        reasons.append("bit4-active-low-chain-not-unique")
    if len(event_sites) != 1:
        reasons.append("event-0x51-materialization-not-unique")
    if reasons:
        return { "sideband_detection_status": "rejected", "sideband_detection_reject_reasons": reasons, }
    branch = chains[0][-1]
    event_site = event_sites[0]
    branch_successors = _thumb_successors(image, branch, sense_site)
    if (len(branch_successors) != 2 or branch + 2 not in branch_successors):
        return { "sideband_detection_status": "rejected", "sideband_detection_reject_reasons":["active-low-branch-not-closed"], }
    inactive_start = next(site for site in branch_successors if site != branch + 2)
    active_path = _thumb_reachable(image, branch + 2, sense_site)
    inactive_path = _thumb_reachable(image, inactive_start, sense_site)
    event_branch = event_site + 2
    successors = _thumb_successors(image, event_branch, end)
    if event_site not in active_path:
        reasons.append("event-0x51-not-on-active-low-path")
    if (struct.unpack_from("<H", image, event_branch)[0] & 0xF800 != 0xE000 or len(successors) != 1 or successors[0] <= sense_site):
        reasons.append("event-0x51-common-state-branch-not-closed")
    if reasons:
        return { "sideband_detection_status": "rejected", "sideband_detection_reject_reasons": reasons, }
    active_stores = _thumb_immediate_byte_stores(image, {site for site in active_path if site < event_site}, event_site, 1,)
    inactive_stores = _thumb_immediate_byte_stores(image, {site for site in inactive_path if site < event_site}, event_site, 0,)
    flag_gates: set[tuple[int, int, int]] = set()
    for gate in reachable:
        if not branch < gate < event_site or gate + 6 > sense_site:
            continue
        load = struct.unpack_from("<H", image, gate)[0]
        if load & 0xF800 != 0x7800:
            continue
        register = load & 7
        address = (load >> 3 & 7, load >> 6 & 0x1F)
        if (struct.unpack_from("<H", image, gate + 2)[0] != 0x2800 | register << 8 or struct.unpack_from("<H", image, gate + 4)[0] & 0xFF00 != 0xD000):
            continue
        gate_successors = _thumb_successors(image, gate + 4, sense_site)
        if len(gate_successors) != 2 or gate + 6 not in gate_successors:
            continue
        skip = next(site for site in gate_successors if site != gate + 6)
        if (event_site not in _thumb_reachable(image, gate + 6, sense_site) or event_site in _thumb_reachable(image, skip, sense_site)):
            continue
        if (any(site < gate and (base, offset) == address for site, base, offset in active_stores) and any(site < gate and (base, offset) == address for site,
            base, offset in inactive_stores)):
            flag_gates.add((gate, *address))
    if len(flag_gates) != 1:
        return { "sideband_detection_status": "rejected", "sideband_detection_reject_reasons":["sideband-active-flag-dataflow-not-closed"], }
    common = _thumb_reachable(image, successors[0], end)
    press_calls = [site + 2 for site in common if struct.unpack_from("<H", image, site)[0] == 0x1C38 and facts_for(image).thumb_call_target(site + 2) ==
        event_sink]
    release_calls = [site + 2 for site in common if struct.unpack_from("<H", image, site)[0] == 0x20FF and facts_for(image).thumb_call_target(site + 2) ==
        event_sink]
    direct_release_calls = [site + 2 for site in reachable if site + 6 <= sense_site and struct.unpack_from("<H", image, site)[0] == 0x20FF and facts_for(image).thumb_call_target(site
        + 2) == event_sink]
    candidate_stores = { (site, word >> 3 & 7, word >> 6 & 0x1F) for site in common for word in (struct.unpack_from("<H", image, site)[0],) if word & 0xF800 ==
        0x7000 and word & 7 == 7 }
    candidate_compares: list[tuple[int, tuple[int, int]]] = []
    for site in common:
        if site < 2 or site + 4 > end:
            continue
        compare = struct.unpack_from("<H", image, site)[0]
        load = struct.unpack_from("<H", image, site - 2)[0]
        loaded_register = compare >> 3 & 7
        address = (load >> 3 & 7, load >> 6 & 0x1F)
        if (compare & 0xFFC7 == 0x4287 and load & 0xF800 == 0x7800 and load & 7 == loaded_register and struct.unpack_from("<H", image, site + 2)[0] & 0xFF00 ==
            0xD100 and any(store < site and (base, offset) == address for store, base, offset in candidate_stores) and any(store > site and (base, offset) ==
            address for store, base, offset in candidate_stores)):
            candidate_compares.append((site, address))
    state_stores = { value: _thumb_immediate_byte_stores(image, common, end, value) for value in (1, 2, 3) }
    state_sources: list[tuple[int, tuple[int, int]]] = []
    for site in common:
        load = struct.unpack_from("<H", image, site)[0]
        if load & 0xF800 != 0x7800:
            continue
        register = load & 7
        address = (load >> 3 & 7, load >> 6 & 0x1F)
        preserved = _thumb_reachable_preserving_register(image, site + 2, end, register) & common
        compare_sites = { value:[compare for compare in preserved if struct.unpack_from("<H", image, compare)[0] == 0x2800 | register << 8 | value] for value in
            (1, 2, 3) }
        if (all(len(compare_sites[value]) == 1 for value in (1, 2, 3)) and all(any((base, offset) == address for _, base, offset in state_stores[value]) for
            value in (1, 2, 3))):
            state_sources.append((site, address))
    if len(press_calls) != 1:
        reasons.append("press-sink-not-unique")
    if len(release_calls) not in (1, 2):
        reasons.append("release-sink-not-unique")
    all_common_sink_calls = {site for site in common if facts_for(image).thumb_call_target(site) == event_sink}
    if all_common_sink_calls != set(press_calls + release_calls):
        reasons.append("unclassified-common-sink-call")
    if len(direct_release_calls) != 1:
        reasons.append("direct-release-sink-not-unique")
    if (len(candidate_compares) != 1 or len(state_sources) != 1 or candidate_compares[0][1] == state_sources[0][1]):
        reasons.append("candidate-debounce-state-not-closed")
    if reasons:
        return { "sideband_detection_status": "rejected", "sideband_detection_reject_reasons": reasons, }
    metadata = _accepted_samsung_sideband_51(press_calls[0], min(release_calls), event_sink, load_address)
    if len(release_calls) == 2:
        metadata["sideband_producers"][0]["release_callsites"] = [load_address + site for site in sorted(release_calls)]
    return metadata
