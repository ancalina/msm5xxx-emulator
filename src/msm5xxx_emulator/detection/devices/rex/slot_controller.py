"""Source proof for a reset-linked, two-stage C80 timer controller route."""
from __future__ import annotations
import struct
from capstone import arm as a
from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .slot_controller_flow import descriptor_seeds as _descriptor_seeds
_STATUS = 0x03000C80
_ENABLE = 0x03000C94
_MASK = 0x0200
_IRQ_VECTOR = 0x18
_GROUP_COUNT = 3
_GROUP_ROW_SIZE = 10
_TIMER_SLOT = 30
_CALLBACK_SLOT_SIZE = 0x1C
_CALLBACK_FIELD = 0x14
def _is_reg(operand, register):
    return operand.type == a.ARM_OP_REG and operand.reg == register
def _is_imm(operand, value):
    return operand.type == a.ARM_OP_IMM and operand.imm == value
def _literal_value(facts, pc):
    literal = facts.literal(CodeAddress(pc, "thumb"))
    return None if literal is None else literal.value


def _common_handler_mask_load(image, handler, masks):
    """Require the shared two-bank source form before legacy shape checks."""
    facts = facts_for(image)
    site = CodeAddress(handler + 8, "thumb")
    instruction = facts.decode(site)
    literal = facts.literal(site)
    return (instruction is not None and instruction.id == a.ARM_INS_LDR
            and len(instruction.operands) == 2
            and _is_reg(instruction.operands[0], a.ARM_REG_R2)
            and instruction.operands[1].type == a.ARM_OP_MEM
            and instruction.operands[1].mem.base == a.ARM_REG_PC
            and literal is not None and literal.value == masks)
def _thumb_calls_to(image, target, call_index=None):
    """Find decoded Thumb BL instructions with one resolved source target."""
    from msm5xxx_emulator.detection.devices.rex.rules import THUMB_BL_PATTERN
    if call_index is not None:
        return tuple(call_index.get(target, ()))
    facts = facts_for(image)
    calls = []
    for match in THUMB_BL_PATTERN.finditer(image):
        pc = match.start()
        if pc & 1:
            continue
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if (ins is not None and ins.id == a.ARM_INS_BL
                and facts.thumb_call_target(pc) == target):
            calls.append(pc)
    return tuple(sorted(set(calls)))
def _literal_call_arguments(image, callsite):
    """Close a direct ``LDR R1, literal; MOVS R0, #n; BL`` argument edge."""
    facts = facts_for(image)
    move = facts.decode(CodeAddress(callsite - 2, "thumb"))
    load = facts.decode(CodeAddress(callsite - 4, "thumb"))
    call = facts.decode(CodeAddress(callsite, "thumb"))
    if (move is None or move.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            or len(move.operands) != 2 or not _is_reg(move.operands[0], a.ARM_REG_R0)
            or move.operands[1].type != a.ARM_OP_IMM
            or load is None or load.id != a.ARM_INS_LDR or len(load.operands) != 2
            or not _is_reg(load.operands[0], a.ARM_REG_R1)
            or load.operands[1].type != a.ARM_OP_MEM
            or load.operands[1].mem.base != a.ARM_REG_PC
            or call is None or call.id != a.ARM_INS_BL):
        return None
    literal = facts.literal(CodeAddress(callsite - 4, "thumb"))
    if literal is None:
        return None
    caller = _thumb_function_start(image, callsite)
    if caller >= callsite or caller & 1:
        return None
    flow = facts.function(CodeAddress(caller, "thumb"), budget=512,
                          stop_at_initial_return=True)
    source_sites = tuple(CodeAddress(pc, "thumb")
                         for pc in (callsite - 4, callsite - 2, callsite))
    from .slot_controller_flow import unconditional_sites
    if (not flow.complete or flow.truncated or flow.unresolved
            or any(site not in flow.instructions for site in source_sites)
            or not (flow.dominates(source_sites[0], source_sites[1])
                    and flow.dominates(source_sites[1], source_sites[2]))
            or any((source_sites[i], source_sites[i + 1]) not in flow.control_edges
                   for i in range(2))
            or not unconditional_sites(facts, flow,
                tuple(site.address for site in source_sites))
            or not any(site == source_sites[2]
                       for site, _target in flow.calls)):
        return None
    return {
        "slot": move.operands[1].imm,
        "callback_pointer": literal.value,
        "callback": literal.value & ~1,
        "caller": caller,
        "callsite": callsite,
        "literal_site": callsite - 4,
        "literal_pool": literal.pool,
    }
def _registration_calls(image, registrar, call_index=None, args_cache=None):
    calls = []
    for callsite in _thumb_calls_to(image, registrar, call_index):
        args = (args_cache.get(callsite) if args_cache is not None
                else _literal_call_arguments(image, callsite))
        if args is not None and args["callback_pointer"] & 1:
            calls.append(args)
    return calls
def _unique_call_for_slot(calls, slot):
    selected = [item for item in calls if item["slot"] == slot]
    callbacks = {item["callback_pointer"] for item in selected}
    return selected[0] if len(callbacks) == 1 and selected else None


def _candidate_route_key(candidate):
    (descriptor_file, descriptor, callback_table, words, layout, registrar,
     timer_call, shape, advance, handler, setter, groups, slot_index,
     timer_sites, _outer_callsite) = candidate
    return (
        descriptor_file, descriptor, callback_table, registrar, words,
        timer_call["callback_pointer"], timer_call["callback"], repr(shape),
        repr(advance), handler, setter["handler_slot"],
        tuple(setter["selector_calls"]), groups["group_table"],
        tuple(tuple(row) for row in groups["group_records"]), slot_index,
        tuple(timer_sites), layout["row_size"], layout["callback_offset"],
    )


def _collapse_route_candidates(candidates):
    """Collapse repeated source callsites only when the physical route matches."""
    by_route = {}
    callsites = {}
    for candidate in candidates:
        key = _candidate_route_key(candidate)
        by_route.setdefault(key, candidate)
        callsites.setdefault(key, set()).add(candidate[-1])
    if len(by_route) != 1:
        return None
    key, candidate = next(iter(by_route.items()))
    return candidate, tuple(sorted(callsites[key]))
def _row_layout(image, registrar, callback_table=None, callback_pointer=None):
    """Prove slot*0x1c + callback-field addressing in registrar code."""
    facts = facts_for(image)
    flow = facts.function(CodeAddress(registrar, "thumb"), budget=512,
                          stop_at_initial_return=True)
    if (not flow.complete or flow.truncated or flow.unresolved
            or not flow.instructions):
        return None
    instructions = []
    for site in sorted(flow.instructions, key=lambda item: item.address):
        ins = facts.decode(site)
        if ins is None:
            return None
        instructions.append((site.address, ins))
    slot_copies = set()
    callback_copies = set()
    strides = {}
    table_bases = []
    for pc, ins in instructions:
        if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_REG):
            if ins.operands[1].reg == a.ARM_REG_R0:
                slot_copies.add(ins.operands[0].reg)
            if ins.operands[1].reg == a.ARM_REG_R1:
                callback_copies.add(ins.operands[0].reg)
        if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_REG
                and ins.operands[2].type == a.ARM_OP_IMM
                and ins.operands[2].imm == 0):
            if ins.operands[1].reg == a.ARM_REG_R0:
                slot_copies.add(ins.operands[0].reg)
            if ins.operands[1].reg == a.ARM_REG_R1:
                callback_copies.add(ins.operands[0].reg)
        if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_IMM):
            strides[ins.operands[0].reg] = ins.operands[1].imm
        if (ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == a.ARM_REG_PC):
            value = _literal_value(facts, pc)
            if value is not None:
                table_bases.append((pc, ins.operands[0].reg, value))
    candidates = []
    for mul_index, (mul_pc, mul) in enumerate(instructions):
        if mul.mnemonic.lower().rstrip("s") != "mul" or len(mul.operands) != 3:
            continue
        if any(op.type != a.ARM_OP_REG for op in mul.operands):
            continue
        destination, left, right = (op.reg for op in mul.operands)
        for add_pc, add in instructions[mul_index + 1:mul_index + 4]:
            if (add.id != a.ARM_INS_ADD
                    or len(add.operands) != 3
                    or not _is_reg(add.operands[0], destination)):
                continue
            if add.operands[1].type != a.ARM_OP_REG or add.operands[2].type != a.ARM_OP_REG:
                continue
            add_regs = {add.operands[1].reg, add.operands[2].reg}
            bases = [(base_reg, value) for load_pc, base_reg, value in table_bases
                     if load_pc < add_pc and base_reg in add_regs
                     and (callback_table is None or value == callback_table)]
            if destination not in add_regs or len(add_regs) != 2:
                continue
            for base_reg, base_value in bases:
                if add_regs != {destination, base_reg}:
                    continue
                stride_regs = {reg for reg in (left, right) if strides.get(reg) == _CALLBACK_SLOT_SIZE}
                slot_regs = {reg for reg in (left, right) if reg in slot_copies}
                if not stride_regs or not slot_regs or stride_regs == slot_regs:
                    continue
                row_reg = destination
                stores = []
                fields = set()
                for pc, ins in instructions:
                    if pc <= add_pc or pc > add_pc + 0x70:
                        continue
                    if (ins.id == a.ARM_INS_STR and len(ins.operands) == 2
                            and ins.operands[0].type == a.ARM_OP_REG
                            and ins.operands[0].reg in callback_copies
                            and ins.operands[1].type == a.ARM_OP_MEM
                            and ins.operands[1].mem.base == row_reg
                            and ins.operands[1].mem.disp == _CALLBACK_FIELD):
                        stores.append(pc)
                    if (ins.id in (a.ARM_INS_LDR, a.ARM_INS_LDRH, a.ARM_INS_LDRB)
                            and len(ins.operands) == 2
                            and ins.operands[1].type == a.ARM_OP_MEM
                            and ins.operands[1].mem.base == row_reg):
                        fields.add((ins.id, ins.operands[1].mem.disp))
                if len(stride_regs) != 1 or len(callback_copies) != 1:
                    continue
                from .slot_controller_flow import prove_row_path
                if len(stores) == 1 and {4, 8, 0x0c, 0x10} <= {disp for _, disp in fields}:
                    for slot_reg in slot_regs:
                        if prove_row_path(image, registrar, mul_pc, add_pc, stores[0],
                                slot_reg, next(iter(stride_regs)), base_reg,
                                next(iter(callback_copies)), _CALLBACK_SLOT_SIZE,
                                _CALLBACK_FIELD, base_value, callback_pointer):
                            candidates.append((mul_pc, add_pc, row_reg, {slot_reg},
                                stride_regs, base_reg, stores[0], base_value))
    if len(candidates) != 1:
        return None
    mul_pc, add_pc, row_reg, slot_regs, stride_regs, base_reg, store_pc, table_value = candidates[0]
    return {
        "table": table_value,
        "row_size": _CALLBACK_SLOT_SIZE,
        "callback_offset": _CALLBACK_FIELD,
        "slot_registers": tuple(sorted(slot_regs)),
        "callback_registers": tuple(sorted(callback_copies)),
        "row_register": row_reg,
        "row_multiply_site": mul_pc,
        "row_add_site": add_pc,
        "callback_store_site": store_pc,
        "field_offsets": (4, 8, 0x0c, 0x10, _CALLBACK_FIELD),
        "source_sites": tuple((pc, ins.size) for pc, ins in instructions
                               if pc in (mul_pc, add_pc, store_pc)),
    }
def _arm_vector_slot(image, wrapper, ram_base, ram_size):
    """Close ARM vector wrapper's literal-loaded handler slot and BX route."""
    from msm5xxx_emulator.detection.facts import facts_for as _facts_for
    facts = _facts_for(image)
    end = min(len(image) - 4, wrapper + 0x100)
    literals = {}
    found = []
    for pc in range(wrapper, end, 4):
        ins = facts.decode(CodeAddress(pc, "arm"))
        if ins is None:
            break
        if (ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == a.ARM_REG_PC):
            literal = facts.literal(CodeAddress(pc, "arm"))
            if literal is not None and ram_base <= literal.value <= ram_base + ram_size - 4:
                literals[ins.operands[0].reg] = (literal.value, pc)
                continue
        if (ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base in literals
                and ins.operands[1].mem.disp == 0):
            target_reg = ins.operands[0].reg
            for later in range(pc + ins.size, min(end, pc + 0x20), 4):
                branch = facts.decode(CodeAddress(later, "arm"))
                if (branch is not None and branch.id == a.ARM_INS_BX
                        and branch.operands and _is_reg(branch.operands[0], target_reg)):
                    slot, literal_site = literals[ins.operands[1].mem.base]
                    from .slot_controller_flow import prove_vector_path
                    if prove_vector_path(image, wrapper, literal_site, pc, later):
                        found.append((slot, pc, later))
    unique = set(found)
    return next(iter(unique)) if len(unique) == 1 else None
def _registrar_setter_proof(image, setter, slot_table, expected_handler,
                            call_index=None, args_cache=None):
    """Prove indexed callback storage and the two selector vector stores."""
    facts = facts_for(image)
    setter_calls = _thumb_calls_to(image, setter, call_index)
    writer_calls = []
    for callsite in setter_calls:
        args = (args_cache.get(callsite) if args_cache is not None
                else _literal_call_arguments(image, callsite))
        if args is not None and args["slot"] in (0, 1):
            writer_calls.append(args)
    by_selector = {}
    for call in writer_calls:
        prior = by_selector.setdefault(call["slot"], set())
        prior.add(call["callback_pointer"])
    if (set(by_selector) != {0, 1}
            or (expected_handler is not None and by_selector[0] != {expected_handler | 1})
            or len(by_selector[1]) != 1 or by_selector[1] == by_selector[0]):
        return None
    flow = facts.function(CodeAddress(setter, "thumb"), budget=128,
                          stop_at_initial_return=True)
    if not flow.complete or flow.truncated or flow.unresolved:
        return None
    instructions = [(site.address, facts.decode(site)) for site in flow.instructions]
    instructions = [(pc, ins) for pc, ins in instructions if ins is not None]
    literal_reg = None
    slot = None
    stores = set()
    store_pcs = []
    for pc, ins in instructions:
        if (ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == a.ARM_REG_PC):
            value = _literal_value(facts, pc)
            if value is not None and value & 3 == 0:
                literal_reg, slot = ins.operands[0].reg, value
        if (ins.id == a.ARM_INS_STR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == a.ARM_REG_R1
                and ins.operands[1].type == a.ARM_OP_MEM
                and literal_reg is not None and ins.operands[1].mem.base == literal_reg):
            stores.add(ins.operands[1].mem.disp)
            store_pcs.append(pc)
    if slot is None or stores != {4, 8}:
        return None
    branches = [(pc, ins) for pc, ins in instructions
                if ins.id == a.ARM_INS_CMP and len(ins.operands) == 2
                and _is_reg(ins.operands[0], a.ARM_REG_R0)
                and _is_imm(ins.operands[1], 0)]
    if len(branches) != 1 or not any(ins.id == a.ARM_INS_B and ins.cc != a.ARM_CC_AL
                                      for _, ins in instructions):
        return None
    from .slot_controller_flow import prove_setter_path
    if not prove_setter_path(image, setter, branches[0][0], store_pcs,
                             literal_reg, slot):
        return None
    return {"setter": setter, "handler_slot": slot + 4,
            "selector_table_base": slot,
            "selector_calls": tuple((item["callsite"], item["slot"], item["callback_pointer"])
                                     for item in writer_calls),
            "stores": tuple(sorted(stores)),
            "source_sites": tuple((pc, ins.size) for pc, ins in instructions)}
def _copy_source(copy, address, size, image_size):
    source, target, length, _wrapper = copy
    if size <= 0 or address < target or address + size > target + length:
        return None
    offset = source + address - target
    return offset if offset >= 0 and offset + size <= image_size else None
def _vector_target(image):
    from msm5xxx_emulator.detection.devices.rex.rules import arm_b_word_target
    return arm_b_word_target(struct.unpack_from("<I", image, _IRQ_VECTOR)[0], _IRQ_VECTOR)
def source_slot_controller_candidate(image: bytes, config) -> dict[str, object] | None:
    """Return a source-closed C80 timer controller candidate, without admission.
    The result is telemetry for the input-only timer integration. It does not
    change global controller or virtual-cell selection.
    """
    if len(image) < 0x20:
        return None
    from msm5xxx_emulator.detection.devices.rex.rules import (
        _controller_callback_advance, _controller_two_bank_handler_at,
        _legacy_620_vector_copy, _ram_contains, rex_legacy_5ms_callback_shape_at,
    )
    from .slot_controller_flow import thumb_call_targets, thumb_span
    ram_base = int(getattr(config, "ram_base", 0))
    ram_size = int(getattr(config, "ram_size", 0))
    copy = _legacy_620_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
    if copy is None:
        return None
    source, target, copy_size, wrapper = copy
    if (not _ram_contains(target, copy_size, ram_base, ram_size)
            or _vector_target(image) != target):
        return None
    call_index = {}
    for callsite, callee in thumb_call_targets(image):
        call_index.setdefault(callee, []).append(callsite)
    args_cache = {}
    def call_args(callsite):
        if callsite not in args_cache:
            args_cache[callsite] = _literal_call_arguments(image, callsite)
        return args_cache[callsite]
    caller_targets = set()
    for callee, callsites in call_index.items():
        for callsite in callsites:
            if call_args(callsite) is not None:
                caller_targets.add(callee)
    registration_cache = {}
    setter_cache = {}
    candidates = []
    for descriptor_file, descriptor, words, callback_pointer in _descriptor_seeds(
            image, copy, _STATUS, _ENABLE, _MASK):
        status, enable, mask, masks, _limit, _unused_callback, _reserved = words
        registrar_candidates = {}
        for registrar, callsites in call_index.items():
            for callsite in callsites:
                args = call_args(callsite)
                if args is None:
                    continue
                registrar_key = (registrar, args["callback_pointer"])
                if registrar_key not in registrar_candidates:
                    registrar_candidates[registrar_key] = _row_layout(
                        image, registrar, callback_pointer=args["callback_pointer"])
                layout = registrar_candidates[registrar_key]
                if layout is None or not 0 <= descriptor - layout["table"]:
                    continue
                slot_index, remainder = divmod(descriptor - layout["table"], _CALLBACK_SLOT_SIZE)
                callback_table = layout["table"]
                if remainder or slot_index > 255 or callback_table < ram_base:
                    continue
                if not _ram_contains(callback_table, (slot_index + 1) * _CALLBACK_SLOT_SIZE, ram_base, ram_size):
                    continue
                if registrar not in registration_cache:
                    registration_cache[registrar] = _registration_calls(
                        image, registrar, call_index, args_cache)
                slot_calls = registration_cache[registrar]
                timer_call = _unique_call_for_slot(slot_calls, slot_index)
                if (timer_call is None or args["slot"] != slot_index
                        or args["callback_pointer"] != timer_call["callback_pointer"]):
                    continue
                callback = timer_call["callback"]
                shape = rex_legacy_5ms_callback_shape_at(image, callback)
                advance = _controller_callback_advance(image, callback)
                if shape is None or advance is None:
                    continue
                for setter_target in caller_targets:
                    if setter_target not in setter_cache:
                        setter_cache[setter_target] = _registrar_setter_proof(
                            image, setter_target, callback_table, None,
                            call_index, args_cache)
                    setter = setter_cache[setter_target]
                    if setter is None:
                        continue
                    irq_pointers = {ptr for _pc, sel, ptr in setter["selector_calls"] if sel == 0}
                    if len(irq_pointers) != 1:
                        continue
                    handler = next(iter(irq_pointers)) & ~1
                    if (not _common_handler_mask_load(image, handler, masks)
                            or not _controller_two_bank_handler_at(
                                image, handler, masks, status)):
                        continue
                    group_tables = set()
                    facts = facts_for(image)
                    for pc, ins in thumb_span(image, handler, min(len(image)-2, handler + 0x500)):
                        value = None
                        if (ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                                and ins.operands[0].type == a.ARM_OP_REG
                                and ins.operands[1].type == a.ARM_OP_MEM
                                and ins.operands[1].mem.base == a.ARM_REG_PC):
                            value = _literal_value(facts, pc)
                        if value is not None and _copy_source(copy, value,
                                (_GROUP_COUNT + 1) * _GROUP_ROW_SIZE, len(image)) is not None:
                                group_tables.add(value)
                    for group_table in group_tables:
                        from .slot_controller_flow import group_stride_proof
                        groups = group_stride_proof(image, handler, group_table, copy,
                            _GROUP_COUNT, _GROUP_ROW_SIZE, slot_index, _MASK)
                        if groups is None or groups["group_records"][2][4] != slot_index:
                            continue
                        candidates.append((descriptor_file, descriptor, callback_table,
                            words, layout, registrar, timer_call, shape, advance,
                            handler, setter, groups, slot_index,
                            tuple(item["callsite"] for item in slot_calls
                                  if item["slot"] == slot_index),
                            args["callsite"]))
    collapsed = _collapse_route_candidates(candidates)
    if collapsed is None:
        return None
    selected_candidate, registrar_call_sites = collapsed
    (descriptor_file, descriptor, callback_table, words, layout, registrar,
     timer_call, callback_shape, advance, handler, setter, groups, timer_slot,
     timer_registration_sites, _outer_callsite) = selected_candidate
    status, enable, mask, masks, _limit, callback_pointer, _reserved = words
    callback_slot = callback_table + timer_slot * _CALLBACK_SLOT_SIZE + _CALLBACK_FIELD
    handler_flow = facts_for(image).function(CodeAddress(handler, "thumb"),
        budget=1024, stop_at_initial_return=True)
    if (not handler_flow.complete or handler_flow.truncated or handler_flow.unresolved
            or not handler_flow.instructions):
        return None
    handler_end = max(site.address + (facts_for(image).decode(site).size)
                      for site in handler_flow.instructions
                      if facts_for(image).decode(site) is not None)
    if setter is None or not _ram_contains(setter["handler_slot"], 4, ram_base, ram_size):
        return None
    vector_route = _arm_vector_slot(image, wrapper, ram_base, ram_size)
    if vector_route is None or vector_route[0] != setter["handler_slot"]:
        return None
    copy_descriptor = _copy_source(copy, descriptor, 31 * _CALLBACK_SLOT_SIZE,
                                   len(image))
    if copy_descriptor is None:
        return None
    return {
        "status": status, "enable": enable, "mask": mask,
        "period": 5, "vector_target": target, "wrapper": wrapper,
        "handler_slot": setter["handler_slot"], "handler": handler,
        "handler_validation_size": handler_end - handler,
        "callback_slot": callback_slot, "outer_callback": timer_call["callback"],
        "timer_registration_sites": timer_registration_sites,
        "registrar_call_sites": registrar_call_sites,
        "bank_count": 2, "group_row_size": groups["group_row_size"],
        "group_count": groups["group_count"], "timer_group": groups["timer_group"],
        "copy": copy, "descriptor": descriptor,
        "descriptor_file_offset": descriptor_file,
        "descriptor_source": _copy_source(copy, descriptor, 28, len(image)),
        "callback_table": callback_table, "callback_table_source": copy_descriptor,
        "callback_row_size": layout["row_size"],
        "callback_field_offset": layout["callback_offset"],
        "registrar": registrar, "registrar_layout": layout,
        "callback_shape": callback_shape, "advance": advance,
        "handler_source_sites": groups["source_sites"],
        "setter": setter, "vector_route": vector_route,
        "group_records": groups["group_records"],
    }
