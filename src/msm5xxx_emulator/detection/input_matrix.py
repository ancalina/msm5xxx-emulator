"""Exact direct-MMIO keypad matrix detection."""
from __future__ import annotations

import hashlib
import json
import re
import struct

from .arm import (
    arm_b_target,
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
from .input_semantics import (
    KEYEMU_GRAMMAR_FINGERPRINT,
    KEYEMU_PASSTHROUGH,
    KeyemuSemantics,
    detect_keyemu_semantics,
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
SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE = (
    "samsung-byte-ring32-saved-task-dispatch-v1"
)
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


def _matches_relocated_thumb_bl(
        image: bytes, position: int, template: bytes, bl_offset: int) -> bool:
    """Match fixed code around one relocation-sensitive Thumb BL."""
    end = position + len(template)
    return (
        0 <= position <= len(image) - len(template)
        and image[position:position + bl_offset] == template[:bl_offset]
        and thumb_bl_target(image, position + bl_offset) is not None
        and image[position + bl_offset + 4:end] == template[bl_offset + 4:]
    )


SAMSUNG_SIDEBAND_51_WORDS = {
    0x26: 0x7900, 0x28: 0x2210, 0x2A: 0x4002, 0x36: 0x2A00,
    0x42: 0x2A05, 0x50: 0x2A05, 0x56: 0x2A0A, 0x7E: 0x2A0A,
    0xC6: 0x2751, 0x294: 0x7BD8, 0x29E: 0x2803, 0x2A2: 0x2F00,
    0x2AE: 0x20FF, 0x2C0: 0x722F, 0x2C6: 0x2002, 0x2C8: 0x73D8,
    0x2D4: 0x7A28, 0x2D6: 0x4287, 0x2DA: 0x2003, 0x2DC: 0x73D8,
    0x2F8: 0x1C38,
}


def _accepted_samsung_sideband_51(
        press_callsite: int, release_callsite: int, event_sink: int,
        load_address: int) -> dict[str, object]:
    return {
        "sideband_detection_status": "accepted",
        "sideband_detection_reject_reasons": [],
        "sideband_producers": [{
            "grammar": "active-low-mmio-bit-debounced-event-v1",
            "evidence": "literal+mask+local-state+shared-queue",
            "semantic_status": "temporary-evidence-gated",
            "semantic_key": 7,
            "semantic_name": "END",
            "semantic_evidence": "event-0x51-independent-keyemu-maps",
            "event": 0x51,
            "event_register": 7,
            "register": 0x03000694,
            "register_width": 1,
            "mask": 0x10,
            "polarity": "active-low",
            "press_callsite": load_address + press_callsite,
            "release_event": 0xFF,
            "release_callsite": load_address + release_callsite,
            "event_sink": load_address + event_sink,
        }],
    }


def _samsung_sideband_51_metadata(
        image: bytes, scanner: int, event_sink: int, load_address: int
) -> dict[str, object]:
    """Describe one closed sideband event producer without owning its MMIO."""
    if scanner < 0 or scanner + 0x330 > len(image):
        return {}
    if (thumb_literal_value(image, scanner + 0x24, 0) != 0x03000690
            or struct.unpack_from("<H", image, scanner + 0xC6)[0] != 0x2751):
        return {}
    reasons = [f"shape-word-0x{offset:03x}-mismatch"
               for offset, word in SAMSUNG_SIDEBAND_51_WORDS.items()
               if struct.unpack_from("<H", image, scanner + offset)[0]
               != word]
    if set(_thumb_successors(
            image, scanner + 0x3A, scanner + 0x330
    )) != {scanner + 0x3C, scanner + 0x60}:
        reasons.append("active-low-branch-not-closed")
    if tuple(_thumb_successors(
            image, scanner + 0xC8, scanner + 0x330
    )) != (scanner + 0x27C,):
        reasons.append("event-state-branch-not-closed")
    if thumb_bl_target(image, scanner + 0x2B0) != event_sink:
        reasons.append("release-sink-mismatch")
    if thumb_bl_target(image, scanner + 0x2FA) != event_sink:
        reasons.append("press-sink-mismatch")
    if reasons:
        return {
            "sideband_detection_status": "rejected",
            "sideband_detection_reject_reasons": reasons,
        }
    return _accepted_samsung_sideband_51(
        scanner + 0x2FA, scanner + 0x2B0, event_sink, load_address
    )


def _thumb_immediate_byte_stores(
        image: bytes, path: set[int], end: int, value: int
) -> set[tuple[int, int, int]]:
    """Return STRB sites fed by one preserved MOVS immediate."""
    stores: set[tuple[int, int, int]] = set()
    for move in path:
        word = struct.unpack_from("<H", image, move)[0]
        if word & 0xF800 != 0x2000 or word & 0xFF != value:
            continue
        register = word >> 8 & 7
        for site in _thumb_reachable_preserving_register(
                image, move + 2, end, register):
            if site not in path:
                continue
            store = struct.unpack_from("<H", image, site)[0]
            if store & 0xF800 == 0x7000 and store & 7 == register:
                stores.add((site, store >> 3 & 7, store >> 6 & 0x1F))
    return stores


def _samsung_sideband_51_family_metadata(
        image: bytes, scanner: int, sense_site: int, event_sink: int,
        load_address: int) -> dict[str, object]:
    """Close compiler variants of one bit4-to-event-0x51 producer."""
    end = min(len(image), scanner + 0x600) & ~1
    if not 0 <= scanner < sense_site < end:
        return {}
    reachable = _thumb_reachable(image, scanner, end)
    search_end = min(sense_site, scanner + 0x100)
    base_reads: list[tuple[int, int, int]] = []
    for read in sorted(site for site in reachable
                       if scanner <= site < search_end):
        word = struct.unpack_from("<H", image, read)[0]
        if word & 0xF800 != 0x7800 or word >> 6 & 0x1F != 4:
            continue
        value_register = word & 7
        base_register = word >> 3 & 7
        loads = [
            site for site in range(max(scanner, read - 0x30), read, 2)
            if (site in reachable
                and struct.unpack_from("<H", image, site)[0] & 0xF800
                == 0x4800
                and struct.unpack_from("<H", image, site)[0] >> 8 & 7
                == base_register
                and thumb_literal_value(image, site, base_register)
                == 0x03000690
                and _thumb_path_preserves_register(
                    image, site + 2, read, search_end, base_register
                ))
        ]
        if len(loads) == 1:
            base_reads.append((read, value_register, loads[0]))
    event_sites = [
        site for site in reachable
        if scanner <= site < sense_site
        and struct.unpack_from("<H", image, site)[0] == 0x2751
    ]
    if not base_reads and not event_sites:
        return {}
    if not base_reads or not event_sites:
        return {
            "sideband_detection_status": "rejected",
            "sideband_detection_reject_reasons": [
                ("bit4-mmio-read-not-found" if not base_reads
                 else "event-0x51-materialization-not-found")
            ],
        }

    chains: list[tuple[int, int, int, int, int, int]] = []
    for read, value_register, load in base_reads:
        for mask_site in range(read + 2, min(read + 0x10, sense_site), 2):
            mask_word = struct.unpack_from("<H", image, mask_site)[0]
            if (mask_site not in reachable
                    or mask_word & 0xF800 != 0x2000
                    or mask_word & 0xFF != 0x10):
                continue
            mask_register = mask_word >> 8 & 7
            if mask_register == value_register:
                continue
            for and_site in range(
                    mask_site + 2, min(mask_site + 0x10, sense_site), 2):
                and_word = struct.unpack_from("<H", image, and_site)[0]
                if (and_site not in reachable
                        or and_word & 0xFFC0 != 0x4000
                        or {and_word & 7, and_word >> 3 & 7}
                        != {value_register, mask_register}
                        or not _thumb_path_preserves_register(
                            image, read + 2, and_site, sense_site,
                            value_register
                        )
                        or not _thumb_path_preserves_register(
                            image, mask_site + 2, and_site, sense_site,
                            mask_register
                        )):
                    continue
                result_register = and_word & 7
                for compare in range(
                        and_site + 2, min(and_site + 0x20, sense_site), 2):
                    if (compare in reachable
                            and struct.unpack_from("<H", image, compare)[0]
                            == 0x2800 | result_register << 8
                            and struct.unpack_from(
                                "<H", image, compare + 2
                            )[0] & 0xFF00 == 0xD100
                            and _thumb_path_preserves_register(
                                image, and_site + 2, compare, sense_site,
                                result_register
                            )):
                        chains.append((
                            load, read, mask_site, and_site,
                            compare, compare + 2,
                        ))
                        break
    reasons: list[str] = []
    if len(chains) != 1:
        reasons.append("bit4-active-low-chain-not-unique")
    if len(event_sites) != 1:
        reasons.append("event-0x51-materialization-not-unique")
    if reasons:
        return {
            "sideband_detection_status": "rejected",
            "sideband_detection_reject_reasons": reasons,
        }

    branch = chains[0][-1]
    event_site = event_sites[0]
    branch_successors = _thumb_successors(image, branch, sense_site)
    if (len(branch_successors) != 2
            or branch + 2 not in branch_successors):
        return {
            "sideband_detection_status": "rejected",
            "sideband_detection_reject_reasons": [
                "active-low-branch-not-closed"
            ],
        }
    inactive_start = next(
        site for site in branch_successors if site != branch + 2
    )
    active_path = _thumb_reachable(image, branch + 2, sense_site)
    inactive_path = _thumb_reachable(image, inactive_start, sense_site)
    event_branch = event_site + 2
    successors = _thumb_successors(image, event_branch, end)
    if event_site not in active_path:
        reasons.append("event-0x51-not-on-active-low-path")
    if (struct.unpack_from("<H", image, event_branch)[0] & 0xF800
            != 0xE000 or len(successors) != 1
            or successors[0] <= sense_site):
        reasons.append("event-0x51-common-state-branch-not-closed")
    if reasons:
        return {
            "sideband_detection_status": "rejected",
            "sideband_detection_reject_reasons": reasons,
        }

    active_stores = _thumb_immediate_byte_stores(
        image, {site for site in active_path if site < event_site},
        event_site, 1,
    )
    inactive_stores = _thumb_immediate_byte_stores(
        image, {site for site in inactive_path if site < event_site},
        event_site, 0,
    )
    flag_gates: set[tuple[int, int, int]] = set()
    for gate in reachable:
        if not branch < gate < event_site or gate + 6 > sense_site:
            continue
        load = struct.unpack_from("<H", image, gate)[0]
        if load & 0xF800 != 0x7800:
            continue
        register = load & 7
        address = (load >> 3 & 7, load >> 6 & 0x1F)
        if (struct.unpack_from("<H", image, gate + 2)[0]
                != 0x2800 | register << 8
                or struct.unpack_from("<H", image, gate + 4)[0]
                & 0xFF00 != 0xD000):
            continue
        gate_successors = _thumb_successors(image, gate + 4, sense_site)
        if len(gate_successors) != 2 or gate + 6 not in gate_successors:
            continue
        skip = next(site for site in gate_successors if site != gate + 6)
        if (event_site not in _thumb_reachable(
                image, gate + 6, sense_site)
                or event_site in _thumb_reachable(image, skip, sense_site)):
            continue
        if (any(site < gate and (base, offset) == address
                for site, base, offset in active_stores)
                and any(site < gate and (base, offset) == address
                        for site, base, offset in inactive_stores)):
            flag_gates.add((gate, *address))
    if len(flag_gates) != 1:
        return {
            "sideband_detection_status": "rejected",
            "sideband_detection_reject_reasons": [
                "sideband-active-flag-dataflow-not-closed"
            ],
        }

    common = _thumb_reachable(image, successors[0], end)
    press_calls = [
        site + 2 for site in common
        if struct.unpack_from("<H", image, site)[0] == 0x1C38
        and thumb_bl_target(image, site + 2) == event_sink
    ]
    release_calls = [
        site + 2 for site in common
        if struct.unpack_from("<H", image, site)[0] == 0x20FF
        and thumb_bl_target(image, site + 2) == event_sink
    ]
    direct_release_calls = [
        site + 2 for site in reachable
        if site + 6 <= sense_site
        and struct.unpack_from("<H", image, site)[0] == 0x20FF
        and thumb_bl_target(image, site + 2) == event_sink
    ]
    candidate_stores = {
        (site, word >> 3 & 7, word >> 6 & 0x1F)
        for site in common
        for word in (struct.unpack_from("<H", image, site)[0],)
        if word & 0xF800 == 0x7000 and word & 7 == 7
    }
    candidate_compares: list[tuple[int, tuple[int, int]]] = []
    for site in common:
        if site < 2 or site + 4 > end:
            continue
        compare = struct.unpack_from("<H", image, site)[0]
        load = struct.unpack_from("<H", image, site - 2)[0]
        loaded_register = compare >> 3 & 7
        address = (load >> 3 & 7, load >> 6 & 0x1F)
        if (compare & 0xFFC7 == 0x4287
                and load & 0xF800 == 0x7800
                and load & 7 == loaded_register
                and struct.unpack_from("<H", image, site + 2)[0]
                & 0xFF00 == 0xD100
                and any(store < site and (base, offset) == address
                        for store, base, offset in candidate_stores)
                and any(store > site and (base, offset) == address
                        for store, base, offset in candidate_stores)):
            candidate_compares.append((site, address))

    state_stores = {
        value: _thumb_immediate_byte_stores(image, common, end, value)
        for value in (1, 2, 3)
    }
    state_sources: list[tuple[int, tuple[int, int]]] = []
    for site in common:
        load = struct.unpack_from("<H", image, site)[0]
        if load & 0xF800 != 0x7800:
            continue
        register = load & 7
        address = (load >> 3 & 7, load >> 6 & 0x1F)
        preserved = _thumb_reachable_preserving_register(
            image, site + 2, end, register
        ) & common
        compare_sites = {
            value: [
                compare for compare in preserved
                if struct.unpack_from("<H", image, compare)[0]
                == 0x2800 | register << 8 | value
            ]
            for value in (1, 2, 3)
        }
        if (all(len(compare_sites[value]) == 1 for value in (1, 2, 3))
                and all(any((base, offset) == address
                            for _, base, offset in state_stores[value])
                        for value in (1, 2, 3))):
            state_sources.append((site, address))
    if len(press_calls) != 1:
        reasons.append("press-sink-not-unique")
    if len(release_calls) != 1:
        reasons.append("release-sink-not-unique")
    if len(direct_release_calls) != 1:
        reasons.append("direct-release-sink-not-unique")
    if (len(candidate_compares) != 1 or len(state_sources) != 1
            or candidate_compares[0][1] == state_sources[0][1]):
        reasons.append("candidate-debounce-state-not-closed")
    if reasons:
        return {
            "sideband_detection_status": "rejected",
            "sideband_detection_reject_reasons": reasons,
        }
    return _accepted_samsung_sideband_51(
        press_calls[0], release_calls[0], event_sink, load_address
    )


def _same_image_keyemu_ok_mapping(
        profile: dict[str, object], semantics: KeyemuSemantics,
) -> dict[int, dict[str, object]]:
    """Bind OK only when matrix and exact native KEYEMUL share event ABI."""
    if (semantics.confidence != "exact-native"
            or semantics.grammar_fingerprint != KEYEMU_GRAMMAR_FINGERPRINT):
        return {}
    semantic_events = dict(semantics.event_map)
    if (semantic_events.get("O") != (0x53,)
            or semantic_events.get("release") != (0xFF,)):
        return {}
    events = list(profile.get("event_codes", ()))
    shared = (*map(ord, KEYEMU_PASSTHROUGH), 0x53)
    if any(events.count(event) != 1 for event in shared):
        return {}
    return {5: {
        "event": 0x53,
        "rule": "same-image-exact-keyemul-O-unique-cell",
        "evidence": (
            "exact-keyemul-semantics+unique-matrix-event-namespace"
        ),
        "semantic_grammar_fingerprint": KEYEMU_GRAMMAR_FINGERPRINT,
    }}


_SAMSUNG_CONFIRM_CONVERTER = bytes.fromhex(
    "512834d021dc342848d00edc312841d006dc23284ed02a284ad030285ed1f7463228"
    "39d0332859d1f74638283cd006dc352835d0362835d037284fd1f746392834d05028"
    "4ad1be20f7465f2840d010dc552841d007dc52282ed0532830d054283cd1c220f746"
    "5b2828d05e2836d1bf20f746652828d007dc60282bd0632821d064282bd19220f746"
    "66281fd0872825d19420f7463120f7463220f7463420f7463520f7463620f7463820"
    "f7463920f7462a20f7462320f7460820f7468120f7468320f7468d20f7468e20f746"
    "9120f746c020f746c120f746c320f7460123db031843f746"
)
_SAMSUNG_CONFIRM_PRESS = bytes.fromhex(
    "00b582b0012100ab197059705880684600f000f802b000bd"
)
_SAMSUNG_CONFIRM_MESSAGE_SINK = bytes.fromhex(
    "80b410490cc908399a1a402a17da0e4a402b06da5f1cdb004f609f180cc80cc708e0"
    "5f1cdb009a184f60d71fff3f0cc8fa3f0cc748680968401a80bcf7460020c043fae7"
)
_SAMSUNG_CONFIRM_NAMESPACE = (
    *ASCII_KEY_EVENTS, 0x53, 0x54, 0x55, 0x5B, 0x63, 0x64, 0x65, 0x66,
)
_SAMSUNG_CONFIRM_RULE = "same-image-ring32-confirm-consumer-v1"
_SAMSUNG_CONFIRM_FINGERPRINT = hashlib.sha256(
    _SAMSUNG_CONFIRM_CONVERTER + _SAMSUNG_CONFIRM_PRESS
    + _SAMSUNG_CONFIRM_MESSAGE_SINK + bytes(_SAMSUNG_CONFIRM_NAMESPACE)
    + b"raw-dequeue-delta:0x60;paired-raw-guards+saved-r7-press-v1"
).hexdigest()

_SAMSUNG_CONFIRM_STATE_CONVERTER = bytes.fromhex(
    "522852d022dc352850d010dc312846d006dc232854d02a2850d030285ed1f7463228"
    "3ed033283ed0342857d1f746392842d006dc36283bd037283bd038284dd1f7465028"
    "4bd0512848d14ae063283fd012dc5b2838d007dc532837d0542844d055283bd1c320"
    "f7465e283ad05f283ad0602833d1c120f7460021c943792836d007dc642828d06528"
    "24d0662826d19120f7467a282bd0872820d19420f7463120f7463220f7463320f746"
    "0be03520f7463620f7463720f7463920f7462a20f7462320f7460820f7468120f746"
    "8320f7468d20f7468e20f7469220f74609e0be20f746bf20f746c020f746c220f746"
    "081cf7460123db031843f746"
)
_SAMSUNG_CONFIRM_STATE_RULE = "same-image-ring32-confirm-saved-state-v1"

# Reached aligned-path contracts. Preserve branches, stores and constants;
# relocation-sensitive BL and PC-load displacements are checked separately.
_SAMSUNG_CONFIRM_CLOCK_CONTRACTS = {
    "clock": (130, "fa8ec97207aa8b5c1f7825c4b80878c6f96a6b0e037c5e33774b4a4cd63f7aa0"),
    "hardware": (64, "91a7e5a29998704101222fab0e80895d9f83e7678423c38fd25c005c6b82c7d8"),
    "copy": (14, "382df184ea60a0c8346efe76cf05e08520406e57bdd881dd782c65a8ae140571"),
    "assign": (12, "c4be156fe24ce917ee6573eb030476ef39f44a9966ac68d9bf055ffa82899089"),
    "add": (34, "84e1145cff7f91a33235d0e682fabe9fbdb609262463ece765910670f762f0ba"),
    "sum": (92, "812185ab79eb3b4c33af50ea4da425d621e07e9cb8d6e9505285b36009eb244e"),
    "multiply": (64, "4d2b12f5d49fbd1520a1537fb0fcc5090f193023a79fb297ef3234c39aad89c3"),
    "divide": (72, "8ad910c95849e7e5858cef1d53832b0e6f474c6f191398c9c049f089ff5d69a8"),
}
_SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS = {
    "lock": (28, "05bb1a2e651a889ae08f19e98607f956161b40424ed99b20b412b687a6667f10"),
    "unlock": (28, "d961305ca13c6c8a3d2a5bd54d508f2977a58483bff33d6de0ae24fa06c4fe82"),
    "scalar": (72, "ca730b18f8ed52cbcee991280aafffbb0d5520734787dba42d7fa265689aa3d9"),
}
_SAMSUNG_CONFIRM_STATE_FINGERPRINT = hashlib.sha256(
    _SAMSUNG_CONFIRM_STATE_CONVERTER + _SAMSUNG_CONFIRM_PRESS
    + _SAMSUNG_CONFIRM_MESSAGE_SINK + bytes(_SAMSUNG_CONFIRM_NAMESPACE)
    + json.dumps(_SAMSUNG_CONFIRM_CLOCK_CONTRACTS, sort_keys=True).encode()
    + json.dumps(_SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS, sort_keys=True).encode()
    + b"raw-dequeue-delta:0x66;saved-state+0x20;aligned-clock-output+0x18"
).hexdigest()


def _confirm_clock_code_matches(image: bytes, at: int, size: int,
                                digest: str, *, raw: bool = False) -> bool:
    if at < 0 or at & 1 or at + size > len(image):
        return False
    block = bytearray(image[at:at + size])
    if not raw:
        offset = 0
        while offset + 2 <= size:
            word = struct.unpack_from("<H", block, offset)[0]
            if (word & 0xF800 == 0xF000 and offset + 4 <= size
                    and struct.unpack_from("<H", block, offset + 2)[0] & 0xF800 == 0xF800):
                block[offset:offset + 4] = bytes.fromhex("00f000f8")
                offset += 4
                continue
            if word & 0xF800 == 0x4800:
                block[offset] = 0
            offset += 2
    return hashlib.sha256(block).hexdigest() == digest


def _confirm_saved_state_clock_closed(image: bytes, call: int,
                                     raw_call: int) -> bool:
    """Preserve saved payload under aligned task-stack/callee-saved ABI."""
    if not _thumb_path_preserves_register(
            image, raw_call - 0xA, raw_call + 0xA, raw_call + 0xC, 4):
        return False
    clock = thumb_bl_target(image, call + 0x10)
    if clock is None or not _confirm_clock_code_matches(
            image, clock, *_SAMSUNG_CONFIRM_CLOCK_CONTRACTS["clock"]):
        return False
    nodes = {"clock": clock}
    for name, offset in (("lock", 0xA), ("copy", 0x20), ("hardware", 0x26),
                         ("unlock", 0x2E), ("assign", 0x4A), ("multiply", 0x56),
                         ("add", 0x60), ("sum", 0x6A)):
        target = thumb_bl_target(image, clock + offset)
        if target is None:
            return False
        nodes[name] = target
    if thumb_bl_target(image, clock + 0x7A) != nodes["add"]:
        return False
    if nodes["lock"] & 3 or nodes["unlock"] & 3:
        return False
    divide = thumb_bl_target(image, nodes["hardware"] + 0x2E)
    stub = thumb_bl_target(image, nodes["multiply"] + 0x20)
    if (divide is None or stub is None or stub < 0 or stub & 3
            or image[stub:stub + 8] != bytes.fromhex("784700000030a0e3")):
        return False
    scalar = arm_b_target(image, stub + 8)
    if scalar is None or scalar & 3:
        return False
    nodes.update(divide=divide, scalar=scalar)
    if any(not _confirm_clock_code_matches(image, nodes[name], *contract)
           for name, contract in _SAMSUNG_CONFIRM_CLOCK_CONTRACTS.items()):
        return False
    if any(not _confirm_clock_code_matches(image, nodes[name], *contract, raw=True)
           for name, contract in _SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS.items()):
        return False
    state = thumb_literal_value(image, raw_call + 8, 5)
    destination = thumb_literal_value(image, raw_call - 0xC, 4)
    hardware = nodes["hardware"]
    flag = thumb_literal_value(image, hardware + 8, 2)
    inputs = (thumb_literal_value(image, clock + 6, 6),
              thumb_literal_value(image, clock + 0x10, 0),
              thumb_literal_value(image, clock + 0x6E, 0))
    return (
        state is not None and destination is not None and flag is not None
        and 0x01000000 <= state <= 0x04000000 - 0x24 and not state & 3
        and destination == state + 0x18
        and 0x01000000 <= flag < 0x04000000
        and not destination <= flag < state + 0x24
        and all(value is not None and not value & 3
                and 0x01000000 <= value <= 0x04000000 - 0x5C for value in inputs)
        and thumb_literal_value(image, hardware + 2, 1) == 0x030006E0
        and thumb_literal_value(image, hardware + 0x28, 3) == 0x3C1
    )


def _same_image_ring32_confirm_mapping(
        image: bytes, profile: dict[str, object], load_address: int,
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    """Bind one provisional confirm class to its physical scanner's raw ring."""
    def reject(reason: str):
        return {}, {
            "ok_mapping_status": "rejected",
            "ok_mapping_reject_reasons": [reason],
        }

    dequeue = profile.get("raw_dequeue")
    ring = profile.get("raw_ring")
    if (profile.get("event_sink_family") != SAMSUNG_RING32
            or type(dequeue) is not int or type(ring) is not int
            or not 0x01000000 <= ring < 0x04000000
            or profile.get("raw_consumer_evidence") not in (
                SAMSUNG_RAW_CONSUMER_EVIDENCE,
                SAMSUNG_RAW_R7_CONSUMER_EVIDENCE,
                SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE,
            )):
        return reject("raw-consumer-not-closed")
    dequeue -= load_address
    if dequeue & 1 or not 0 <= dequeue <= len(image) - 2:
        return reject("raw-consumer-not-closed")
    events = list(profile.get("event_codes", ()))
    if any(events.count(event) != 1 for event in _SAMSUNG_CONFIRM_NAMESPACE):
        return reject("namespace-not-unique")
    converters = [position for position in find_all(
        image, _SAMSUNG_CONFIRM_CONVERTER
    ) if not position & 1]
    saved_state = not converters
    if saved_state:
        converters = [position for position in find_all(
            image, _SAMSUNG_CONFIRM_STATE_CONVERTER
        ) if not position & 1]
    if len(converters) != 1:
        return reject("exact-converter-missing-or-ambiguous")
    converter = converters[0]
    calls = []
    for match in THUMB_BL.finditer(image):
        call = match.start()
        if not call & 1 and thumb_bl_target(image, call) == converter:
            calls.append(call)
            if len(calls) > 1:
                break
    if len(calls) != 1:
        return reject("converter-caller-not-unique")
    call = calls[0]
    raw_call = call - (0x66 if saved_state else 0x60)
    end = min(len(image), call + 0x100)
    if (raw_call < (0xC if saved_state else 0)
            or call + (0x1A if saved_state else 0x18) > len(image)
            or thumb_bl_target(image, raw_call) != dequeue):
        return reject("dequeue-call-mismatch")

    def word(at: int) -> int:
        return struct.unpack_from("<H", image, at)[0]

    if word(raw_call + 4) != 0x2800 or word(raw_call + 6) & 0xFF00 != 0xD000:
        return reject("raw-release-guard-unclosed")
    empty = set(_thumb_successors(image, raw_call + 6, end)) - {raw_call + 8}
    raw_guard = None
    if (saved_state and word(raw_call + 8) & 0xFF00 == 0x4D00
            and word(raw_call + 0xA) == 0x1C26
            and word(raw_call + 0xC) == 0x28FF):
        raw_guard = raw_call + 0xE
        shape = "saved-state-timestamp"
    elif not saved_state and word(raw_call + 8) == 0x28FF:
        raw_guard = raw_call + 0xA
        shape = "valid-event-timestamp"
    elif (not saved_state and word(raw_call + 8) & 0xFF00 == 0x4D00
          and word(raw_call + 0xA) == 0x28FF):
        raw_guard = raw_call + 0xC
        shape = "conditional-timestamp"
    if (raw_guard is None or word(raw_guard) & 0xFF00 != 0xD100
            or set(_thumb_successors(image, raw_guard, end))
            != {raw_guard + 2, call}):
        return reject("raw-release-guard-unclosed")

    if shape == "saved-state-timestamp":
        press_call = call + 0x16
        skip = set(_thumb_successors(image, call + 0xC, end)) - {call + 0xE}
        valid = (
            image[call + 4:call + 0xC] == bytes.fromhex("01232c1cd8422862")
            and word(call + 0xC) & 0xFF00 == 0xD000
            and len(skip) == 1 and press_call + 4 <= next(iter(skip)) < end
            and word(call + 0xE) == 0x1C30 and word(call + 0x14) == 0x6A20
        )
        if valid and not _confirm_saved_state_clock_closed(image, call, raw_call):
            return reject("saved-state-clock-unclosed")
    elif shape == "valid-event-timestamp":
        press_call = call + 0x14
        skip = set(_thumb_successors(image, call + 0xA, end)) - {call + 0xC}
        valid = (
            image[call + 4:call + 0xA] == bytes.fromhex("0123071cd842")
            and word(call + 0xA) & 0xFF00 == 0xD000
            and len(skip) == 1
            and press_call + 4 <= next(iter(skip)) < end
            and word(call + 0xC) & 0xFF00 == 0x4800
            and thumb_bl_target(image, call + 0xE) is not None
            and word(call + 0x12) == 0x1C38
        )
    else:
        press_call = call + 0x12
        valid = (
            image[call + 4:call + 8] == bytes.fromhex("071cbf28")
            and word(call + 8) & 0xFF00 == 0xD100
            and set(_thumb_successors(image, call + 8, end))
            == {call + 0xA, call + 0x10}
            and word(call + 0xA) & 0xFF00 == 0x4800
            and thumb_bl_target(image, call + 0xC) is not None
            and word(call + 0x10) == 0x1C38
        )
    if (not valid or (not saved_state and not _thumb_path_preserves_register(
            image, call + 8, press_call, press_call + 4, 7))):
        return reject("translated-press-shape-unclosed")
    if len(empty) != 1 or not press_call + 4 <= next(iter(empty)) < end:
        return reject("raw-release-guard-unclosed")
    press = thumb_bl_target(image, press_call)
    if (press is None or not _matches_relocated_thumb_bl(
            image, press, _SAMSUNG_CONFIRM_PRESS, 0x10)):
        return reject("press-message-abi-mismatch")
    sink = thumb_bl_target(image, press + 0x10)
    if (sink is None or sink < 0
            or image[sink:sink + len(_SAMSUNG_CONFIRM_MESSAGE_SINK)]
            != _SAMSUNG_CONFIRM_MESSAGE_SINK
            or any(value is None or not 0x01000000 <= value < 0x04000000
                   for value in (thumb_literal_value(image, sink + 2, 1),
                                 thumb_literal_value(image, sink + 0xE, 2)))):
        return reject("message-sink-unclosed")
    mapping = {5: {
        "event": 0x53,
        "semantic_status": "provisional-cross-firmware-class",
        "rule": _SAMSUNG_CONFIRM_RULE,
        "evidence": (
            "scanner-linked-dequeue+exact-converter+press-message"
            "+cross-firmware-selection"
        ),
        "semantic_grammar_fingerprint": _SAMSUNG_CONFIRM_FINGERPRINT,
        "raw_dequeue": load_address + dequeue,
        "converter_callsite": load_address + call,
        "converter": load_address + converter,
        "press_callsite": load_address + press_call,
        "press_message_sink": load_address + sink,
    }}
    if saved_state:
        mapping[5].update(
            semantic_status="temporary-evidence-gated-provisional",
            rule=_SAMSUNG_CONFIRM_STATE_RULE,
            evidence="scanner-linked-dequeue+exact-converter+saved-state-aligned-clock+selection",
            semantic_grammar_fingerprint=_SAMSUNG_CONFIRM_STATE_FINGERPRINT,
        )
    return mapping, {
        "ok_mapping_status": "accepted-provisional",
        "ok_mapping_reject_reasons": [],
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


def _samsung_raw_saved_consumer_metadata(
        image: bytes, event_sink: int, event_codes: list[int],
        load_address: int,
) -> dict[str, object] | None:
    """Recover semantic ring32 variants using r4/r7 across the task call."""
    end = min(len(image), event_sink + 0x100)
    reachable = _thumb_reachable(image, event_sink, end)
    stores = [
        current for current in reachable
        if current >= event_sink + 2
        and struct.unpack_from("<2H", image, current - 2)
        == (0x1880, 0x7087)
    ]
    pairs: list[tuple[int, int]] = []
    for store in stores:
        rings = [
            value for current in range(max(event_sink, store - 0x80), store, 2)
            if struct.unpack_from("<H", image, current)[0] & 0xFF00 == 0x4A00
            and (value := thumb_literal_value(image, current, 2)) is not None
            and 0x01000000 <= value < 0x04000000
        ]
        if len(rings) == 1:
            pairs.append((store, rings[0]))
    if len(pairs) != 1:
        return None
    store, ring = pairs[0]

    dequeues = []
    for body in find_all(image, bytes.fromhex("50781178884201d10020")):
        dequeue = body - 2
        if dequeue < 0 or dequeue & 1 or dequeue + 28 > len(image):
            continue
        words = struct.unpack_from("<14H", image, dequeue)
        if (thumb_literal_value(image, dequeue, 2) == ring
                and words[1:6] == (0x7850, 0x7811, 0x4288, 0xD101, 0x2000)
                and words[6] in (0x46F7, 0x4770)
                and words[7:13]
                == (0x1888, 0x3101, 0x06C9, 0x0EC9, 0x7880, 0x7011)
                and words[13] in (0x46F7, 0x4770)):
            dequeues.append(dequeue)
    if len(dequeues) != 1:
        return None
    dequeue = dequeues[0]

    tasks: list[tuple[int, int, int]] = []
    for register, move in ((4, 0x1C04), (7, 0x1C07)):
        for position in find_all(image, struct.pack("<H", move)):
            call = position - 4
            if (call < 0 or call & 1 or call + 12 > len(image)
                    or thumb_bl_target(image, call) != dequeue
                    or struct.unpack_from("<H", image, call + 6)[0] & 0xFF00
                    != 0xD000):
                continue
            task = thumb_bl_target(image, call + 8)
            if task is None or not 0 <= task <= len(image) - 2 or task & 1:
                continue
            branches = _thumb_successors(image, call + 6, len(image))
            if set(branches) != {call + 8, call + 12}:
                continue
            compare_base = 0x2800 | register << 8
            compared = {
                struct.unpack_from("<H", image, current)[0] & 0xFF
                for current in _thumb_reachable_preserving_register(
                    image, task, min(len(image), task + 0x1000), register
                )
                if struct.unpack_from("<H", image, current)[0] & 0xFF00
                == compare_base
                and struct.unpack_from("<H", image, current)[0] & 0xFF
                in event_codes
            }
            if len(compared) >= 3:
                tasks.append((call, task, register))
    if len(tasks) != 1:
        return None
    call, task, register = tasks[0]
    return {
        "raw_ring": ring,
        "raw_ring_capacity": 32,
        "raw_enqueue_store": load_address + store,
        "raw_enqueue_register": 7,
        "raw_dequeue": load_address + dequeue,
        "raw_dequeue_return": load_address + call + 4,
        "raw_task_entry": load_address + task,
        "raw_task_register": register,
        "raw_consumer_evidence": SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE,
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
        scanner = image.find(N330_5X6_ENTRY[:12], start)
        if scanner < 0:
            return found
        start = scanner + 1
        press = scanner + 0x3EC
        release = scanner + 0x472
        press_call = press + len(N330_PRESS_PREFIX)
        release_call = release + len(N330_RELEASE_PREFIX)
        if (not _matches_relocated_thumb_bl(
                    image, scanner, N330_5X6_ENTRY, 0x0C)
                or image[scanner + 0x6A:scanner + 0x6A + len(N330_GLOBAL_SENSE)]
                != N330_GLOBAL_SENSE
                or image[scanner + 0xF8:scanner + 0xF8 + len(N330_ROW_SENSE)]
                != N330_ROW_SENSE
                or not _matches_relocated_thumb_bl(
                    image, press, N330_PRESS_PREFIX, 0x1A)
                or image[release:release_call] != N330_RELEASE_PREFIX):
            continue
        queue = thumb_bl_target(image, press_call)
        if queue is None or thumb_bl_target(image, release_call) != queue:
            continue
        producer = classify_matrix_event_sink(image, queue)
        if (producer["family"] != SAMSUNG_DUAL_PLANE_RING32
                and not all(producer.get("features", {}).get(feature)
                            for feature in PRODUCER_FEATURES[
                                SAMSUNG_DUAL_PLANE_RING32])):
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
            "evidence": "relocation-normalized-entry+press-release+table-xrefs",
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
        sideband = _samsung_sideband_51_metadata(
            image, start, sink, load_address
        )
        if not sideband:
            sideband = _samsung_sideband_51_family_metadata(
                image, start, site, sink, load_address
            )
        found[start].update(sideband)
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
        if any(
                producer.get("event") in events
                for producer in scanner.get("sideband_producers", ())
                if isinstance(producer, dict)
        ):
            reasons.append("sideband-event-conflicts-with-matrix")
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
                if metadata is None:
                    metadata = _samsung_raw_saved_consumer_metadata(
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
        profile = accepted[0]
        mappings = _same_image_keyemu_ok_mapping(
            profile, detect_keyemu_semantics(image, load_address)
        )
        if not mappings and profile["event_sink_family"] == SAMSUNG_RING32:
            mappings, ok_metadata = _same_image_ring32_confirm_mapping(
                image, profile, load_address,
            )
            profile.update(ok_metadata)
        if mappings:
            profile["provisional_mappings"] = mappings
        return profile, "accepted", rejected
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


def _distributed_word(image: bytes, pc: int) -> int:
    return struct.unpack_from('<H', image, pc)[0] if 0 <= pc <= len(image) - 2 else -1


def _distributed_ram(pointer: int | None, size: int) -> bool:
    return isinstance(pointer, int) and 0x01000000 <= pointer <= 0x03000000 - size


def _distributed_irq(image: bytes, pc: int | None, enable: bool) -> bool:
    """Direct Thumb-to-ARM wrapper; previous IRQ mask returned in r0."""
    body = bytes.fromhex('7847000001e08ee300000fe1c010' +
                         ('c0' if enable else '80') +
                         'e301f021e1c00000e21eff2fe1')
    return pc is not None and 0 <= pc <= len(image) - len(body) and image[pc:pc + len(body)] == body


def _distributed_branch(image: bytes, pc: int, end: int, condition: int | None = None):
    word = _distributed_word(image, pc)
    if condition is None:
        if word & 0xf800 != 0xe000:
            return None
    elif word & 0xff00 != 0xd000 | condition << 8:
        return None
    edges = _thumb_successors(image, pc, end)
    target = edges[-1] if edges else None
    return target if target is not None and 0 <= target < end else None


def _distributed_hop(image: bytes, pc: int | None, goal: int, lower: int, end: int):
    """At most two unconditional trampolines, never arbitrary instructions."""
    for _ in range(3):
        if pc == goal:
            return True
        if pc is None or not lower <= pc < end:
            return False
        pc = _distributed_branch(image, pc, end)
    return False


def _distributed_gpio_arm(image: bytes, start: int, sense: int, unlock_site: int,
                          lock: int, unlock: int):
    """Three protected byte shadow updates and their GPIO store consumers."""
    pc = start
    if _distributed_word(image, pc) & 0xf800 == 0xe000:
        pc = _distributed_branch(image, pc, sense)
    blocks = []
    for offset in (12, 8, 4):
        if pc is None or not start <= pc < sense - 24 or thumb_bl_target(image, pc) != lock:
            return None
        shadow = thumb_literal_value(image, pc + 4, 1)
        mask_word = _distributed_word(image, pc + 6)
        if (not _distributed_ram(shadow, 1)
                or mask_word & 0xff00 != 0x2300 or not mask_word & 255
                or image[pc + 8:pc + 10] != bytes.fromhex('0a78')):
            return None
        mask, value, cursor = mask_word & 255, 0, pc + 10
        if _distributed_word(image, cursor) == 0x439a:
            cursor += 2
            if _distributed_word(image, cursor) & 0xff00 == 0x2300:
                value = _distributed_word(image, cursor) & 255
                cursor += 2
                if _distributed_word(image, cursor) != 0x431a:
                    return None
                cursor += 2
        elif _distributed_word(image, cursor) == 0x431a:
            value, cursor = mask, cursor + 2
        else:
            return None
        if value & ~mask or image[cursor:cursor + 4] != bytes.fromhex('0a700978'):
            return None
        base = thumb_literal_value(image, cursor + 4, 2)
        if base is None:
            return None
        cursor += 6
        if _distributed_word(image, cursor) & 0xf800 == 0xe000:
            cursor = _distributed_branch(image, cursor, sense)
        if (cursor is None or not start <= cursor <= sense - 6
                or _distributed_word(image, cursor) != 0x7011 | offset << 6):
            return None
        compare = cursor + 2
        if _distributed_word(image, compare) & 0xf800 == 0xe000:
            compare = _distributed_branch(image, compare, sense)
        if compare is None or not start <= compare <= sense - 6 or _distributed_word(image, compare) != 0x2800:
            return None
        next_pc = compare + 8
        taken = _distributed_branch(image, compare + 2, sense + 2, 1)
        if offset != 4:
            if taken != next_pc or thumb_bl_target(image, compare + 4) != unlock:
                return None
        else:
            if (not _distributed_hop(image, taken, sense, sense - 0x300, sense + 2)
                    or not _distributed_hop(image, compare + 4, unlock_site, start, sense + 2)):
                return None
        blocks.append({'shadow': shadow, 'address': base + offset,
                       'mask': mask, 'value': value, 'store': cursor})
        pc = next_pc
    return blocks


def _distributed_clear(image: bytes, helper: int, lock: int, unlock: int, ports):
    if not 0 <= helper <= len(image) - 84 or image[helper:helper + 2] != bytes.fromhex('80b5'):
        return False
    base = thumb_literal_value(image, helper + 12, 7)
    for block, call, offset, port in zip((6, 34, 60), (2, 30, 56), (12, 8, 4), ports):
        pc = helper + block
        shift = 2 if block == 6 else 0  # First block loads the shared GPIO pointer.
        if (thumb_bl_target(image, helper + call) != lock
                or thumb_literal_value(image, pc, 1) != port['shadow']
                or _distributed_word(image, pc + 2) != 0x2300 | port['mask']
                or _distributed_word(image, pc + 4) != 0x780a
                or image[pc + 6 + shift:pc + 12 + shift] != bytes.fromhex('9a430a700978')
                or _distributed_word(image, pc + 12 + shift) != 0x7039 | offset << 6
                or _distributed_word(image, pc + 14 + shift) != 0x2800
                or _distributed_branch(image, pc + 16 + shift, helper + 84, 1) != pc + 22 + shift
                or thumb_bl_target(image, pc + 18 + shift) != unlock
                or base is None or port['address'] != base + offset):
            return False
    return image[helper + 82:helper + 84] == bytes.fromhex('80bd')


def _distributed_ring32(image: bytes, sink: int, lock: int, unlock: int):
    if not 0 <= sink <= len(image) - 126 or image[sink:sink + 2] != bytes.fromhex('b0b5') or image[sink + 4:sink + 6] != bytes.fromhex('071c'):
        return None
    state = thumb_literal_value(image, sink + 2, 4)
    queue = thumb_literal_value(image, sink + 62, 0)
    tail = bytes.fromhex('2d0c417803784a1cd206d20e9a4207d009188f7041780131c906c90e417003e0')
    if (not _distributed_ram(state, 0x34) or not _distributed_ram(queue, 34)
            or thumb_bl_target(image, sink + 56) != lock
            or image[sink + 60:sink + 62] != bytes.fromhex('0504')
            or image[sink + 64:sink + 96] != tail
            or thumb_bl_target(image, sink + 108) != unlock
            or image[sink + 124:sink + 126] != bytes.fromhex('b0bd')
            or not _thumb_path_preserves_register(image, sink + 6, sink + 82, sink + 126, 7)):
        return None
    dequeues = [pc for pc in find_all(image, SAMSUNG_RAW_DEQUEUE)
                if not pc & 1 and thumb_literal_value(image, pc, 2) == queue]
    if len(dequeues) != 1:
        return None
    return {'family': 'distributed-filtered-byte-ring32-v1', 'ring': queue,
            'state': state, 'state_size': 0x34, 'slots': 32, 'event_offset': 2, 'wrap_mask': 31,
            'enqueue': sink, 'dequeue': dequeues[0], 'event_store': sink + 82,
            'write_index_store': sink + 92, 'read_index_store': dequeues[0] + 24}


def resolve_distributed_matrix_input(image: bytes, load_address: int = 0):
    """Opt-in temporary distributed GPIO byte scanner; numeric tokens only."""
    if load_address != 0:
        return None, 'unsupported-load-address', []
    candidates, rejected = [], []
    anchors = find_all(image, bytes.fromhex('f0b587b000276846'))
    if len(anchors) > MAX_DIRECT_MATRIX_TAILS:
        return None, 'candidate-cap', []
    for start in anchors:
        end = min(start + 0x700, len(image))
        if start & 1 or end < start + 0x560:
            continue
        # A class-local compiled layout: no absolute code/data addresses.
        global_load, sense_load, switch = start + 0xca, start + 0x310, start + 0xe8
        helper = thumb_bl_target(image, global_load - 4)
        arms = [switch + 16 + 2 * v for v in image[switch + 16:switch + 22]]
        lock = thumb_bl_target(image, arms[0]) if len(arms) == 6 else None
        unlock = thumb_bl_target(image, sense_load - 4)
        scanner_state = thumb_literal_value(image, start + 0x40, 4)
        reason = None
        if (image[start + 16:start + 18] != bytes.fromhex('0026')
                or image[global_load + 2:global_load + 10] != bytes.fromhex('01790907090f0f29')
                or image[sense_load + 2:sense_load + 10] != bytes.fromhex('00790007000f0f28')
                or thumb_literal_value(image, global_load, 0) != thumb_literal_value(image, sense_load, 0)
                or not _distributed_irq(image, lock, False) or not _distributed_irq(image, unlock, True)
                or not _thumb_path_preserves_register(image, start + 18, switch, end, 6)
                or not _thumb_path_preserves_register(image, start + 0x42, switch, end, 4)
                or not _distributed_ram(scanner_state, 0xA)
                or _distributed_branch(image, sense_load + 10, end, 0) != sense_load + 76
                or not _distributed_hop(image, _distributed_branch(image, global_load + 10, end, 0), sense_load + 0x190, start, end)
                or not _distributed_hop(image, _distributed_branch(image, switch + 4, end, 2), sense_load, switch, end)
                or image[switch:switch + 4] != bytes.fromhex('039a062a')
                or image[switch + 6:switch + 14] != bytes.fromhex('02a39b5c5b009f44')
                or len(set(arms)) != 6 or any(not switch + 22 <= a < sense_load for a in arms)):
            reason = 'scanner-switch-or-read-link'
        rows = [] if reason else [_distributed_gpio_arm(image, a, sense_load, sense_load - 4, lock, unlock) for a in arms]
        if not reason and (any(row is None for row in rows) or helper is None):
            reason = 'gpio-arm-not-closed'
        if not reason:
            ports = [{k: v for k, v in port.items() if k not in ('value', 'store')} for port in rows[0]]
            base = ports[0]['address'] - 12
            masks = [port['mask'] for port in ports]
            flat_mask = sum(mask << (8 * i) for i, mask in enumerate(masks))
            selections = [sum(port['value'] << (8 * i) for i, port in enumerate(row)) for row in rows]
            ordered_bits = [1 << bit for bit in range(24) if flat_mask & (1 << bit)]
            if (not 0x03000000 <= base <= 0x03001000 - 53 or base & 31
                    or thumb_literal_value(image, sense_load, 0) != base + 48
                    or any([{k: v for k, v in port.items() if k not in ('value', 'store')} for port in row] != ports for row in rows)
                    or len({port['shadow'] for port in ports}) != 3
                    or flat_mask.bit_count() != 6
                    or [flat_mask ^ value for value in selections] != ordered_bits
                    or not _distributed_clear(image, helper, lock, unlock, ports)):
                reason = 'gpio-mask-owner-or-clear-link'
        # Exact bounded column enumeration, stack batch store and row loop.
        batch = bytes.fromhex('0107090f0020ca43069201218140069a11400cd006214143')
        batch_tail = bytes.fromhex('8918039a8b5c711c0a06120e311c161c6a4653540a2e0eda01300006000e0428e6db0a2e07da039a501c0206120e0392062a00da')
        table = thumb_literal_value(image, sense_load + 36, 2)
        if not reason and (image[sense_load + 12:sense_load + 36] != batch
                or image[sense_load + 38:sense_load + 90] != batch_tail
                or _distributed_branch(image, sense_load + 90, end) != switch - 4
                or thumb_bl_target(image, sense_load + 92) != helper
                or thumb_bl_target(image, switch - 4) != helper
                or image[switch - 8:switch - 4] != bytes.fromhex('00220392')
                or table is None or not 0 <= table <= len(image) - 24):
            reason = 'column-batch-row-loop-link'
        # Single-element batch branch and R7 path through the existing state gate.
        pick, move = sense_load + 0x18a, sense_load + 0x222
        state_load = sense_load + 0x156
        batch_state = thumb_literal_value(image, state_load, 2)
        sink = thumb_bl_target(image, move + 2)
        if not reason and (image[sense_load + 96:sense_load + 100] != bytes.fromhex('012e5edd')
                or _distributed_branch(image, sense_load + 98, end, 13) != sense_load + 0x122
                or _distributed_branch(image, sense_load + 0x122, end) != sense_load + 0x152
                or image[sense_load + 0x152:sense_load + 0x154] != bytes.fromhex('012e')
                or image[state_load + 2:state_load + 6] != bytes.fromhex('517b0029')
                or not _distributed_ram(batch_state, 0xE)
                or _distributed_branch(image, state_load + 6, end, 13) != pick
                or image[pick:pick + 4] != bytes.fromhex('00af3f78')
                or not _thumb_path_preserves_register(image, pick + 4, move, end, 7)
                or image[move:move + 2] != bytes.fromhex('381c') or sink is None):
            reason = 'single-batch-stateful-transfer-link'
        producer = None if reason else _distributed_ring32(image, sink, lock, unlock)
        if not reason and (producer is None
                or thumb_literal_value(image, sense_load + 0x1fc, 0) != batch_state
                or thumb_literal_value(image, sense_load + 0x1ac, 1) != producer['state']):
            reason = 'ring32-provenance-or-state-link'
        events = [] if table is None or not 0 <= table <= len(image) - 24 else list(image[table:table + 24])
        if not reason and any(events.count(v) != 1 for v in ASCII_KEY_EVENTS):
            reason = 'numeric-event-missing-or-duplicated'
        if reason:
            rejected.append({'function': start, 'reasons': [reason]})
            continue
        candidates.append({'grammar': 'distributed-six-byte-numeric-v1',
            'function': start, 'scanner_state': scanner_state, 'scanner_state_size': 0xA,
            'batch_state': batch_state, 'batch_state_size': 0xE,
            'presence_site': global_load + 2, 'sense_site': sense_load + 2,
            'register': base + 52, 'register_width': 1, 'no_key': 15,
            'rows': 6, 'columns': 4, 'sense_bits': 4, 'single_key_column_sense': list(SINGLE_KEY_COLUMN_SENSE),
            'gpio_ports': ports, 'row_values': [[p['value'] for p in row] for row in rows],
            'global_values': [0, 0, 0], 'event_table': table, 'event_codes': events,
            'token_cells': [{'token': chr(v), 'event': v, 'row': events.index(v) % 6,
                             'column': events.index(v) // 6} for v in ASCII_KEY_EVENTS],
            'event_transfer': {'batch_store': sense_load + 56, 'single_pick': pick,
                               'move': move, 'call': move + 2},
            'producer': producer, 'runtime_admitted': False,
            'limits': 'Temporary opt-in numeric-only static class; GPIO owner/readback and natural input consumption require runtime validation.'})
    if len(candidates) > 1:
        return None, 'ambiguous-scanners', candidates
    return (candidates[0], 'static-candidate', rejected) if candidates else (None, 'rejected' if rejected else 'not-found', rejected)
