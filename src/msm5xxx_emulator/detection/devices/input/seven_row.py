"""Seven-row immediate-mask scanner, with the existing native halfword wiring."""
from __future__ import annotations
from msm5xxx_emulator.detection.fact_bodies import thumb_body
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.fact_patterns import mov, cmp_imm, lsl, halfword, match
from msm5xxx_emulator.detection.devices.input.halfword import interrupt_helper
from msm5xxx_emulator.detection.devices.input.matrix import classify_matrix_event_sink, SAMSUNG_RING32
from msm5xxx_emulator.detection.devices.input.semantics import detect_keyemu_semantics
from msm5xxx_emulator.detection.layout_queries import find_overlays
from msm5xxx_emulator.detection.signatures import find_all

# All instructions, branches and switch entries are retained. Only BL targets
# and literal-pool distances vary; their values/relationships are checked below.
_SCANNER = (0x2DE, (0x1E, 0x22, 0x2C, 0x36, 0xE6, 0xEA, 0x110, 0x12C, 0x14E, 0x170, 0x192, 0x1B2, 0x1D2, 0x1F2, 0x210, 0x23C, 0x246, 0x26E, 0x2BE, 0x2D6), (6,
    0x1C, 0x3C, 0x46, 0x48, 0x4A, 0x78, 0x7A, 0xEE, 0x220, 0x24A, 0x286, 0x2D4),)
_CLEAR = (0x24, (2, 0x1C), (6,))
_PORTS = {0: 0x03000720, 4: 0x03000720, 8: 0x0300072C, 0x10: 0x03000724, 0x14: 0x03000724, 0x18: 0x03000730, 0x20: 0x03000728, 0x24: 0x03000728, 0x28:
    0x03000734, 0x34: 0x0300072C}

def _shape(image, at, spec, instructions):
    """Check landmarks against one shared call/literal observation."""
    size, expected_calls, expected_literals = spec
    if at < 0 or at & 1 or not match(image, ((at + offset, word) for offset, word in instructions)):
        return None
    body = thumb_body(facts_for(image), at, size)
    if (body is None or tuple(offset for offset, _ in body.calls) != expected_calls or tuple(offset for offset, _, _, _ in body.literals) != expected_literals
        or any(target & 1 or not 0 <= target <= len(image)-2 for _, target in body.calls)):
        return None
    return dict(body.calls), {offset: value for offset, _, value, _ in body.literals}

_SCANNER_CODE = ((2, mov(7, 0)), (4, mov(1, 0x25)), (8, lsl(1, 1, 4)), (0xe, cmp_imm(0, 1)), (0x1a, mov(1, 4)), (0xf2, halfword(True, 0, 0)), (0x114, cmp_imm(5,
    7)), (0x216, halfword(True, 0, 0)))
_CLEAR_CODE = ((8, mov(3, 0x7f)), (0xa, halfword(True, 2, 1, 0x1c)), (0xc, lsl(3, 3, 8)), (0x10, halfword(False, 2, 1, 0x1c)), (0x12, halfword(True, 2, 1, 0x1c)),
    (0x16, halfword(False, 2, 1)), (0x18, cmp_imm(0, 0)))

def find_seven_row_scanners(image: bytes) -> list[dict]:
    """Close the 0x7f00 row driver, 4-column table, ring32 and 25 ms timer."""
    found = []
    overlays = find_overlays(image)
    def runtime(position):
        for overlay in overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                return overlay.target + position - overlay.source
        return position
    def file_offset(address):
        for overlay in overlays:
            if overlay.target <= address < overlay.target + overlay.size:
                return overlay.source + address - overlay.target
        return address
    for switch in find_all(image, bytes.fromhex("072d00d3")):
        start = switch - 0x114
        shape = _shape(image, start, _SCANNER, _SCANNER_CODE)
        if shape is None:
            continue
        calls, literals = shape
        descriptor = literals[0x3C]
        if (descriptor != literals[0xEE] or descriptor & 3 or not 0x01000000 <= descriptor <= 0x01800000 - 0x38 or len({literals[x] for x in (0x4A, 0x78, 0x24A,
            0x286)}) != 1 or literals[0x1C] != literals[0x2D4]):
            continue
        copies = [overlay for overlay in overlays if overlay.target <= descriptor <= overlay.target + overlay.size - 0x38]
        if len(copies) != 1:
            continue
        copy = copies[0]
        rom = file_offset(descriptor)
        if any(struct.unpack_from("<I", image, rom + offset)[0] != value for offset, value in _PORTS.items()):
            continue
        clear = calls[0xEA]
        reset = _shape(image, clear, _CLEAR, _CLEAR_CODE)
        if (calls[0x110] != clear or calls[0x23C] != clear or reset is None or reset[1][6] != descriptor):
            continue
        lock, unlock = reset[0][2], reset[0][0x1C]
        if (not interrupt_helper(image, lock, False) or not interrupt_helper(image, unlock, True) or any(calls[x] != lock for x in (0x36, 0x12C, 0x14E, 0x170,
            0x192, 0x1B2, 0x1D2, 0x1F2)) or calls[0x210] != unlock or calls[0x246] != unlock):
            continue
        sink = calls[0x2BE]
        if (calls[0xE6] != sink or calls[0x26E] != sink or classify_matrix_event_sink(image, sink)["family"] != SAMSUNG_RING32):
            continue
        table = literals[0x220]
        if (not 28 <= table <= len(image) - 16 or image[table:table + 16] != bytes((0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 0))):
            continue
        events = list(image[table - 28:table])
        if not all(events.count(event) == 1 for event in b"123456789*0#"):
            continue
        semantics = detect_keyemu_semantics(image)
        if semantics.confidence != "exact-native":
            continue
        cells = [{"token": token, "event": values[0], "row": events.index(values[0]) % 7, "column": events.index (values[0]) // 7} for token, values in
            semantics.event_map if len(values) == 1 and events.count(values[0]) == 1]
        timer = find_rex_legacy_5ms_timer_bridge(image, start, runtime, file_offset)
        if timer is None:
            continue
        found.append({ "grammar": "indirect-halfword-seven-row-ring32-v1", "function": start, "descriptor": descriptor, "descriptor_copy": {"source": copy.source,
            "target": copy.target, "size": copy.size, "table": copy.table_offset, "descriptor_rom": rom}, "presence_site": start + 0xF2, "sense_site": start +
            0x216, "rows": 7, "columns": 4, "row_select_mask": 0x7F00, "row_select_bits": list(range(8, 15)), "no_key": 15, "single_key_column_sense":[14, 13,
            11, 7], "event_table": table - 28, "event_codes": events, "token_cells": cells, "keyemu_semantics": semantics.as_dict(), "queue_sink": hex(sink),
            "event_sink_family": SAMSUNG_RING32, "event_transfer": {"move": hex(start + 0x2AC), "call": hex(start + 0x2BE)}, "timer_bridge": timer, "promotion":
            "source-closed-native-matrix", "runtime_admitted": False, "limits": "Pull-up column levels; live descriptor and row-selector guards remain active.",
            })
    return found

def find_seven_row_board_status(image: bytes) -> BoardStatusInput | None:
    """Close the scanner's physical lid contact and choose its released level.

    The guest itself converts a low bit into its closed-lid flag and filters
    keys. This describes a GPIO input only; it never writes that guest flag.
    """
    scanners = find_seven_row_scanners(image)
    if (len(scanners) != 1 or scanners[0]["function"] != 0x91090 or scanners[0]["descriptor"] != 0x15F4810 or scanners[0]["queue_sink"] != "0x90ca8"):
        return None
    # Lid reader: load the GPIO halfword, test bit 2 and produce the
    # corresponding open/closed input before notifying the consumer.
    if not match(image, ((0x90d66, halfword(True, 0, 0)), (0x90d68, mov(3, 4)), (0x90d70, mov(1, 0)), (0x90d74, mov(1, 1)), (0x90d76, mov(0, 2)), (0x90cac,
        cmp_imm(0, 0xff)), (0x90cb0, cmp_imm(7, 0x60)), (0x91e3a, mov(2, 1)))):
        return None
    if any(facts_for(image).thumb_literal_value(at, reg) != value for at, reg, value in ((0x91E9A, 7, 0x15F4810), (0x91F06, 5, 0x10020E0), (0x91F42, 2, 0x90D61),
        (0x90D60, 0, 0x15F4810), (0x90D6C, 2, 0x90D61), (0x90CB8, 0, 0x10020E0))):
        return None
    # descriptor + 4 was independently resolved to this GPIO by the scanner.
    return BoardStatusInput(0x03000720, 4, 4)

# Required evidence providers are bound by registry discovery.
REQUIRES = {'find_rex_legacy_5ms_timer_bridge': ('rex.rules', 'find_rex_legacy_5ms_timer_bridge')}
