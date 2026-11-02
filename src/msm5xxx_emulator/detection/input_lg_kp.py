"""Source-qualified LG KP2000/KP2006 keypad scanner evidence."""
from __future__ import annotations

import struct
from collections import Counter

from .arm import thumb_bl_target, thumb_literal_value
from .input_descriptor import (
    _descriptor_mmio_provenance, _event_table, _low5_senses, _table_base,
)
from .input_matrix import ASCII_KEY_EVENTS


def find_kp_legacy_scanner(image: bytes, model: str) -> dict[str, object] | None:
    """Recover one KP scanner; callers must separately close timer and IRQ paths."""
    if model not in {"LG-KP2000", "LG-KP2006"}:
        return None
    marker = struct.pack("<3H", 0xb5f0, 0x7910, 0x2800)
    candidates = []
    cursor = 0
    while (site := image.find(marker, cursor)) >= 0:
        cursor = site + 1
        start = site - 2
        end = min(start + 0x2ac, len(image) - 3)
        if start < 0 or start & 1 or end < start + 0x200:
            continue
        descriptor = thumb_literal_value(image, start + 0x1a, 4)
        if descriptor is None or not 0x01000000 <= descriptor < 0x02000000:
            continue
        provenance = _descriptor_mmio_provenance(image, descriptor)
        if provenance is None:
            continue
        # These are Thumb operations on descriptor fields and the row loop:
        # row 0..3 use GPIO728[4:1], rows 4/5 use GPIO720[10:9].
        operations = {
            0x1c: 0x2202, 0x1e: 0x8da1, 0x22: 0x85a1,
            0x26: 0x6a22, 0x28: 0x8011, 0x36: 0x89a1,
            0x3e: 0x81a1, 0x42: 0x6822,
            0x4e: 0x6b60, 0x50: 0x8800, 0x52: 0x0940,
            0x60: 0x1c20, 0x82: 0x2400, 0x86: 0x2c04,
            0x8e: 0x8db1, 0x90: 0x231e, 0x94: 0x1c62,
            0xee: 0x2c05, 0xf6: 0x8db1, 0x100: 0x6a32,
            0x110: 0x89b1, 0x116: 0x4399,
            0x146: 0x8db1, 0x150: 0x6a32, 0x182: 0x4399,
            0x194: 0x6b70, 0x196: 0x8800,
            0x198: 0x06c0, 0x19a: 0x0ec0, 0x19c: 0x281f,
            0x1a4: 0x6b71, 0x1a6: 0x8809, 0x1a8: 0x0949,
            0x1b8: 0x2306, 0x1bc: 0x4358, 0x1be: 0x391e,
            0x1c2: 0x5d07, 0x1c6: 0x3401, 0x1cc: 0x2c06,
            0x1d0: 0xe759,
        }
        if any(struct.unpack_from("<H", image, start + off)[0] != word
               for off, word in operations.items()):
            continue
        helper = thumb_bl_target(image, start + 0x5a)
        if (helper is None or helper < 0 or helper + 0x4c > len(image)
                or thumb_bl_target(image, start + 0x1d2) != helper
                or thumb_literal_value(image, helper + 6, 7) != descriptor):
            continue
        helper_operations = {
            0: 0xb580, 8: 0x231e, 10: 0x8db9, 12: 0x4399,
            14: 0x85b9, 18: 0x6a3a, 0x22: 0x89b9,
            0x24: 0x2301, 0x26: 0x029b, 0x28: 0x4399, 0x2a: 0x81b9,
            0x2e: 0x683a, 0x3e: 0x89b9, 0x40: 0x2301,
            0x42: 0x025b, 0x44: 0x4399, 0x46: 0x81b9, 0x4a: 0x683a,
        }
        if any(struct.unpack_from("<H", image, helper + off)[0] != word
               for off, word in helper_operations.items()):
            continue
        senses = _low5_senses(image, start, end)
        if not any(pos == start + 0x194 for pos, _ in senses):
            continue
        columns = _table_base(image, start, end, 0)
        events = _event_table(image, start, end)
        if columns is None or events is None:
            continue
        event_address, event_codes = events
        if any(event_codes.count(value) != 1 for value in ASCII_KEY_EVENTS):
            continue
        calls = Counter(target for pos in range(start, end - 3, 2)
                        if (target := thumb_bl_target(image, pos)) is not None
                        and start - 0x400 <= target < start)
        sinks = [target for target, count in calls.items() if count >= 4]
        if len(sinks) != 1:
            continue
        callsites = [pos for pos in range(start, end - 3, 2)
                     if thumb_bl_target(image, pos) == sinks[0]]
        candidates.append({
            "grammar": "lg-kp-legacy-low5-6x5-v1", "function": start,
            "grammar_fingerprint": "lg-kp-legacy-low5-6x5-v1",
            "family": "lg-kp-legacy-raw-keypad-v1", "prologue": start,
            "descriptor_pointer": descriptor,
            "descriptor_mmio_provenance": provenance["kind"],
            "presence_site": start + 0x62, "sense_site": start + 0x194,
            "contact_site": start + 0x50, "contact2_site": start + 0x1a6,
            "sense_sites": [start + 0x5e, start + 0x194],
            "global_sense_sites": [start + 0x5e],
            "row_sense_sites": [start + 0x194],
            "row_register": 4, "row_register_evidence": "identity-six-row-loop",
            "event_table": event_address, "event_codes": event_codes,
            "column_map": columns[1], "column_table": columns[0],
            "raw_enqueue": sinks[0], "raw_enqueue_callsites": callsites,
            "raw_enqueue_callsite": callsites[0], "rows": 6, "columns": 5,
            "sense_bits": 5, "no_key": 31,
            "absolute_roles": {"control": 0x03000720,
                               "row_drive": 0x03000728,
                               "sense": 0x0300072c},
            "provisional_mappings": {
                bit: {"event": event, "rule": "ascii-table-entry"}
                for bit, event in zip(range(11, 23), b"123456789*0#")
            },
            "single_key_column_sense": [
                next(value for value in (30, 29, 27, 23, 15)
                     if columns[1][value] == column)
                for column in range(5)
            ],
        })
    return candidates[0] if len(candidates) == 1 else None
