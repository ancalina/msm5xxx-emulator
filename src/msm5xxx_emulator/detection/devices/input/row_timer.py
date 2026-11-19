"""Link numeric row scanners to an independently closed timer controller."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
import struct

_GRAMMARS = {"table-row-halfword-seven-v1", "sparse-halfword-six-row-v1",
             "sparse-halfword-seven-row-v1", "pair-row-halfword-seven-v1",
             "halfword-five-column-rows-v1"}


def _slot_route_property(config, bridge, route):
    """Encode a two-bank controller for the same closed software-timer chain."""
    if not isinstance(route, dict) or not isinstance(bridge, dict):
        return None
    required = {"status": 0x03000c80, "enable": 0x03000c94, "mask": 0x200,
                "period": 5, "bank_count": 2, "group_row_size": 10,
                "group_count": 3}
    if any(type(route.get(key)) is not int or route[key] != value
           for key, value in required.items()):
        return None
    if (route.get("outer_callback") != bridge.get("outer_callback")
            or bridge.get("tick_ms") != 5):
        return None
    fields = ("vector_target", "wrapper", "handler_slot", "handler",
              "handler_validation_size", "callback_slot", "outer_callback")
    if any(type(route.get(key)) is not int for key in fields):
        return None
    ram, size, flash = (getattr(config, key, None)
                       for key in ("ram_base", "ram_size", "flash_size"))
    if any(type(value) is not int or value <= 0 for value in (ram, size, flash)):
        return None
    if (any(address & 3 or not ram <= address <= ram + size - 4 for address in
            (route["vector_target"], route["handler_slot"], route["callback_slot"]))
            or route["wrapper"] & 3 or route["handler"] & 1
            or route["outer_callback"] & 1
            or not 0 <= route["wrapper"] <= flash - 4
            or not 0 <= route["outer_callback"] <= flash - 68
            or route["handler_validation_size"] <= 0
            or not 0 <= route["handler"] <= flash - route["handler_validation_size"]):
        return None
    values = [route[key] for key in ("status", "enable", "mask")]
    values.append(5_000_000)
    values.extend(route[key] for key in fields)
    return ":".join(f"{value:x}" for value in values)


def _leading_literal_entry(image, push_start, presence):
    """Recover a function entry only from its linked LDR/PUSH/field prologue."""
    entry = push_start - 2
    if entry < 0 or push_start + 4 > len(image):
        return None
    word = struct.unpack_from("<H", image, entry)[0]
    # LDR r0, [PC, #imm]; the instruction immediately following it must be
    # the push that the generic function-start finder selected.
    if word & 0xF800 != 0x4800 or (word >> 8) & 7:
        return None
    facts = facts_for(image)
    push = facts.decode(CodeAddress(push_start))
    field = facts.decode(CodeAddress(push_start + 2))
    if push is None or field is None or push.mnemonic != "push":
        return None
    # Accept this narrowly evidenced prologue only when the first body
    # instruction reads a byte through r0, and the local CFG reaches presence.
    field_word = struct.unpack_from("<H", image, push_start + 2)[0]
    if field_word & 0xF800 != 0x7800 or ((field_word >> 3) & 7) != 0:
        return None
    literal = facts.literal(CodeAddress(entry))
    if literal is None or literal.register != a.ARM_REG_R0:
        return None
    result = facts.function(CodeAddress(entry), budget=1024)
    expected = (CodeAddress(entry), CodeAddress(push_start), CodeAddress(push_start + 2))
    if (not result.complete or result.truncated or result.unresolved
            or result.instructions[:3] != expected or CodeAddress(presence) not in result.instructions
            or field.mnemonic != "ldrb"):
        return None
    linked_read = next((access for access in result.accesses
                        if access.instruction == CodeAddress(push_start + 2)
                        and access.operation == "read" and access.width == 1), None)
    field_offset = (field_word >> 6) & 0x1F
    if linked_read is None or linked_read.address != literal.value + field_offset:
        return None
    return entry


def row_timer_profile(image, config, matrix):
    """Select the existing C80 model only through the scanner's timer chain."""
    if (not isinstance(matrix, dict) or matrix.get("grammar") not in _GRAMMARS
            or getattr(config, "load_address", None) != 0
            or type(getattr(config, "flash_size", None)) is not int):
        return None, None
    source = image[:min(len(image), config.flash_size)]
    presence = matrix.get("presence_site")
    if type(presence) is not int or presence & 1 or not 0 <= presence < len(source) - 2:
        return None, None
    scanner = _thumb_function_start(source, presence)

    def forward(position):
        for overlay in config.overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                return overlay.target + position - overlay.source
        layout = config.linker
        if layout and layout.data_source <= position < layout.data_source + layout.data_size:
            return layout.data_target + position - layout.data_source
        return position

    def reverse(address):
        for overlay in config.overlays:
            if overlay.target <= address < overlay.target + overlay.size:
                return overlay.source + address - overlay.target
        layout = config.linker
        if layout and layout.data_target <= address < layout.data_target + layout.data_size:
            return layout.data_source + address - layout.data_target
        return address if 0 <= address < len(source) else None

    leading_entry = _leading_literal_entry(source, scanner, presence)
    candidates = ([leading_entry, scanner] if leading_entry is not None
                  else [scanner])
    closed = []
    for candidate in candidates:
        bridge_candidate = find_rex_legacy_5ms_timer_bridge(
            source, candidate, forward, reverse)
        if (bridge_candidate is not None
                and bridge_candidate.get("scanner") == forward(candidate)
                and bridge_candidate.get("scanner_file_offset") == candidate
                and bridge_candidate.get("tick_ms") == 5):
            closed.append((candidate, bridge_candidate))
    if len(closed) != 1:
        return None, None
    scanner, bridge = closed[0]
    if matrix.get("grammar") == "pair-row-halfword-seven-v1":
        # This remains an input prerequisite. The global static-controller
        # telemetry and virtual-cell admission policy are left with their
        # own independent source contracts.
        route = source_slot_controller_candidate(source, config)
        encoded = _slot_route_property(config, bridge, route)
        return ((encoded, {"timer_bridge": bridge, "irq_route": route,
                           "route_source": "indexed-slot-controller-v1"})
                if encoded is not None else (None, None))
    route = find_rex_legacy_5ms_irq_route(source, bridge, forward, reverse,
                                       allow_b590_registrar=True)
    if matrix.get("grammar") == "halfword-five-column-rows-v1":
        route = reset_owned_two_bank_route(source, config, bridge, route)
        encoded = _slot_route_property(config, bridge, route)
        return ((encoded, {"timer_bridge": bridge, "irq_route": route,
                           "route_source": "reset-owned-two-bank-group-v1"})
                if encoded is not None else (None, None))
    if (route is None or not legacy_irq_route_metadata_valid(route)
            or route.get("controller_class") != "legacy-c80-three-bank-group14-v1"
            or route.get("outer_callback") != bridge.get("outer_callback")
            or route.get("drain") != bridge.get("drain")
            or route.get("drain_loop") != bridge.get("drain_loop_caller")):
        return None, None
    fields = ("status", "enable", "mask", "vector_target", "wrapper", "handler_slot",
              "handler", "handler_validation_size", "callback_slot", "outer_callback")
    if any(type(route.get(field)) is not int for field in fields):
        return None, None
    values = [route[field] for field in fields]
    values.insert(3, 5_000_000)
    values.append(3)
    encoded = ":".join(f"{value:x}" for value in values)
    # This also validates the candidate's NOR/RAM bounds and copied handler.
    if c80_rex_irq_profile(config, True) != encoded:
        return None, None
    return encoded, {"timer_bridge": bridge, "irq_route": route}


def loaded_row_timer_matches(self, loaded, limit):
    """Re-prove the input-only clock route from the actual loaded NOR bytes."""
    matrix = getattr(self, "matrix_input_profile", None)
    timer = matrix.get("scanner_timer") if isinstance(matrix, dict) else None
    if (not isinstance(timer, dict) or timer.get("route_source") not in
            ("indexed-slot-controller-v1", "reset-owned-two-bank-group-v1")):
        return True
    if type(limit) is not int or limit <= 0 or limit > len(loaded):
        return False
    encoded, current = row_timer_profile(loaded[:limit], self.config, matrix)
    return encoded == self.rex_c80_profile and current == timer


REQUIRES = {
    "reset_owned_two_bank_route": ("input.two_bank_row_timer", "reset_owned_two_bank_route"),
    "source_slot_controller_candidate": ("rex.slot_controller", "source_slot_controller_candidate"),
    "find_rex_legacy_5ms_timer_bridge": ("rex.rules", "find_rex_legacy_5ms_timer_bridge"),
    "find_rex_legacy_5ms_irq_route": ("rex.rules", "find_rex_legacy_5ms_irq_route"),
    "legacy_irq_route_metadata_valid": ("rex.route_metadata", "legacy_irq_route_metadata_valid"),
    "c80_rex_irq_profile": ("rex.transport_projection", "c80_rex_irq_profile"),
}
