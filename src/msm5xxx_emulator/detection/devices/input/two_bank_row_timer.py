"""Reset-owned source closure for the legacy two-bank keypad timer route."""
from __future__ import annotations

import struct
from capstone import arm as a

from msm5xxx_emulator.detection.arm import arm_b_word_target
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.devices.input.startup_copy import reset_linked_input_copy


_STATUS = 0x03000C80
_ENABLE = 0x03000C94
_MASK = 0x0200
_GROUP_ROW_SIZE = 10
_GROUP_COUNT = 3
_TIMER_SLOT = 30
_VECTOR_COPY_SIZE = 0x140
_MASK_TABLE_SIZE = 10


def _source_mappers(config, flash_end):
    overlays = tuple(getattr(config, "overlays", ()))
    linker = getattr(config, "linker", None)

    def forward(position):
        if type(position) is not int or not 0 <= position < flash_end:
            return None
        for overlay in overlays:
            if (type(getattr(overlay, "source", None)) is int
                    and type(getattr(overlay, "target", None)) is int
                    and type(getattr(overlay, "size", None)) is int
                    and overlay.source <= position < overlay.source + overlay.size):
                return overlay.target + position - overlay.source
        if (linker is not None and type(getattr(linker, "data_source", None)) is int
                and type(getattr(linker, "data_target", None)) is int
                and type(getattr(linker, "data_size", None)) is int
                and linker.data_source <= position < linker.data_source + linker.data_size):
            return linker.data_target + position - linker.data_source
        return position

    def reverse(address):
        if type(address) is not int:
            return None
        for overlay in overlays:
            if (type(getattr(overlay, "source", None)) is int
                    and type(getattr(overlay, "target", None)) is int
                    and type(getattr(overlay, "size", None)) is int
                    and overlay.target <= address < overlay.target + overlay.size):
                return overlay.source + address - overlay.target
        if (linker is not None and type(getattr(linker, "data_source", None)) is int
                and type(getattr(linker, "data_target", None)) is int
                and type(getattr(linker, "data_size", None)) is int
                and linker.data_target <= address < linker.data_target + linker.data_size):
            return linker.data_source + address - linker.data_target
        return address if 0 <= address < flash_end else None

    return forward, reverse


def _function_spans(facts, function, flash_end):
    spans = set()
    for site in function.instructions:
        ins = facts.decode(site)
        if ins is None or site.address + ins.size > flash_end:
            return None
        spans.add((site.address, ins.size))
    for literal in function.literals:
        if literal.pool + 4 > flash_end:
            return None
        spans.add((literal.pool, 4))
    return spans


def reset_owned_two_bank_route(image, config, bridge,
                               legacy_route) -> dict | None:
    """Return a timer route only when its controller tables have reset sources.

    The scanner bridge and legacy IRQ route are rederived with the same
    overlay/linker maps used by the input timer selector. The copied vector
    block, mask table, and all three ten-byte group rows must also map through
    reset-proven initialized-data copies.
    """
    if (not isinstance(image, (bytes, bytearray)) or not isinstance(bridge, dict)
            or not isinstance(legacy_route, dict)):
        return None
    image = bytes(image)
    flash_size = getattr(config, "flash_size", None)
    ram_base = getattr(config, "ram_base", None)
    ram_size = getattr(config, "ram_size", None)
    if (type(flash_size) is not int or type(ram_base) is not int
            or type(ram_size) is not int or flash_size <= 0
            or ram_base < 0 or ram_size <= 0):
        return None
    flash_end = min(len(image), flash_size)
    ram_end = ram_base + ram_size
    if flash_end <= 0 or ram_end > 0x100000000:
        return None
    source = image[:flash_end]
    scanner_file = bridge.get("scanner_file_offset")
    if type(scanner_file) is not int or not 0 <= scanner_file < flash_end:
        return None
    forward, reverse = _source_mappers(config, flash_end)
    if forward(scanner_file) != bridge.get("scanner"):
        return None
    verified_bridge = find_rex_legacy_5ms_timer_bridge(
        source, scanner_file, forward, reverse)
    if verified_bridge is None or verified_bridge != bridge:
        return None
    route = find_rex_legacy_5ms_irq_route(
        source, verified_bridge, forward, reverse,
        allow_b590_registrar=True)
    if route is None or route != legacy_route:
        return None
    if (not legacy_irq_route_metadata_valid(route)
            or route.get("controller_class") != "legacy-c80-two-bank-group10-v1"
            or route.get("status") != _STATUS or route.get("enable") != _ENABLE
            or route.get("mask") != _MASK or route.get("index") != _TIMER_SLOT
            or route.get("status_bank_count") != 2
            or route.get("group_row_size") != _GROUP_ROW_SIZE
            or route.get("outer_callback") != verified_bridge.get("outer_callback")
            or route.get("drain") != verified_bridge.get("drain")
            or route.get("drain_loop") != verified_bridge.get("drain_loop_caller")
            or verified_bridge.get("tick_ms") != 5):
        return None

    vector_target = route.get("vector_target")
    handler_file = route.get("handler_file_offset")
    if (type(vector_target) is not int or vector_target & 3
            or not ram_base <= vector_target <= ram_end - _VECTOR_COPY_SIZE
            or type(handler_file) is not int or handler_file & 1
            or not 0 <= handler_file < flash_end):
        return None
    vector_copy = reset_linked_input_copy(
        source, ((vector_target, _VECTOR_COPY_SIZE),), ram_base=ram_base,
        ram_size=ram_size, flash_size=flash_end)
    if (vector_copy is None or vector_copy.target != vector_target
            or vector_copy.source_address(vector_target, _VECTOR_COPY_SIZE) is None):
        return None
    vector_word_source = vector_copy.source_address(vector_target, 4)
    if (vector_word_source is None or not 0 <= vector_word_source <= flash_end - 4
            or arm_b_word_target(struct.unpack_from("<I", source, vector_word_source)[0],
                                 vector_target) != route.get("wrapper")):
        return None

    facts = facts_for(source)
    handler = facts.function(CodeAddress(handler_file, "thumb"), budget=1024,
                            stop_at_initial_return=True)
    if (not handler.complete or handler.truncated or handler.unresolved
            or not handler.instructions):
        return None
    handler_spans = _function_spans(facts, handler, flash_end)
    if handler_spans is None or any(
            (ins := facts.decode(site)) is not None and ins.id == a.ARM_INS_IT
            for site in handler.instructions):
        return None

    mask_load = facts.decode(CodeAddress(handler_file + 8, "thumb"))
    mask_literal = facts.literal(CodeAddress(handler_file + 8, "thumb"))
    if (mask_load is None or mask_load.id != a.ARM_INS_LDR
            or mask_load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or len(mask_load.operands) != 2
            or mask_load.operands[0].type != a.ARM_OP_REG
            or mask_load.operands[0].reg != a.ARM_REG_R7
            or mask_load.operands[1].type != a.ARM_OP_MEM
            or mask_load.operands[1].mem.base != a.ARM_REG_PC
            or mask_literal is None):
        return None
    mask_table = mask_literal.value
    if (type(mask_table) is not int or mask_table & 1
            or not ram_base <= mask_table <= ram_end - _MASK_TABLE_SIZE
            or not two_bank_handler_source(
                source, handler_file, mask_table, _STATUS)):
        return None

    data_copy = reset_linked_input_copy(
        source, ((mask_table, _MASK_TABLE_SIZE),), ram_base=ram_base,
        ram_size=ram_size, flash_size=flash_end)
    if (data_copy is None or data_copy.source_address(
            mask_table, _MASK_TABLE_SIZE) is None):
        return None
    callback_slot = route.get("callback_slot")
    if (type(callback_slot) is not int or callback_slot & 3
            or data_copy.source_address(callback_slot - 0x14, 28)
                != route.get("rom_seed")):
        return None

    group_proofs = []
    for site in handler.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.base != a.ARM_REG_PC):
            continue
        literal = facts.literal(site)
        if literal is None or type(literal.value) is not int:
            continue
        table = literal.value
        if data_copy.source_address(table + _GROUP_ROW_SIZE,
                                    _GROUP_COUNT * _GROUP_ROW_SIZE) is None:
            continue
        proof = group_stride_proof(
            source, handler_file, table,
            (data_copy.source, data_copy.target, data_copy.size, 0),
            _GROUP_COUNT, _GROUP_ROW_SIZE, _TIMER_SLOT, _MASK)
        if (proof is not None and proof.get("group_table") == table
                and proof.get("group_row_size") == _GROUP_ROW_SIZE
                and proof.get("group_count") == _GROUP_COUNT
                and proof.get("timer_group") == 3
                and proof.get("group_table_source") == data_copy.source_address(
                    table + _GROUP_ROW_SIZE, _GROUP_COUNT * _GROUP_ROW_SIZE)):
            group_proofs.append((table, proof))
    if len(group_proofs) != 1:
        return None
    group_table, group_proof = group_proofs[0]

    route_spans = set(handler_spans)
    route_spans.update(vector_copy.evidence)
    route_spans.add((vector_word_source, 4))
    route_spans.update(data_copy.evidence)
    route_spans.add((0x18, 4))
    route_spans.add((route["wrapper_file_offset"],
                     route["wrapper_validation_size"]))
    route_spans.add((route["rom_seed"], 28))
    route_spans.add((route["handler_setter_file_offset"], 14))
    route_spans.add((route["registrar_file_offset"], 0x70))
    route_spans.update(group_proof["source_sites"])
    if any(start < 0 or size <= 0 or start + size > flash_end
           for start, size in route_spans):
        return None

    result = dict(route)
    result.update({
        "period": 5,
        "bank_count": 2,
        "group_count": _GROUP_COUNT,
        "mask_table": mask_table,
        "group_table": group_table,
        "group_records": group_proof["group_records"],
        "vector_copy_source": vector_copy.source,
        "vector_copy_target": vector_copy.target,
        "vector_copy_size": vector_copy.size,
        "data_copy_source": data_copy.source,
        "data_copy_target": data_copy.target,
        "data_copy_size": data_copy.size,
        "mask_table_source": data_copy.source_address(mask_table,
                                                      _MASK_TABLE_SIZE),
        "group_table_source": group_proof["group_table_source"],
        "source_evidence": tuple(sorted(route_spans)),
        "route_source": "reset-owned-two-bank-group10-v1",
    })
    return result


REQUIRES = {
    "legacy_irq_route_metadata_valid": ("rex.route_metadata", "legacy_irq_route_metadata_valid"),
    "find_rex_legacy_5ms_irq_route": ("rex.rules", "find_rex_legacy_5ms_irq_route"),
    "find_rex_legacy_5ms_timer_bridge": ("rex.rules", "find_rex_legacy_5ms_timer_bridge"),
    "two_bank_handler_source": ("rex.slot_controller_flow", "two_bank_handler_source"),
    "group_stride_proof": ("rex.slot_controller_flow", "group_stride_proof"),
}
