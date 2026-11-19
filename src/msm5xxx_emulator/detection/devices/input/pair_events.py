"""Event lookup and stack-pair consumer proofs for keypad scans."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for
from .pair_flow import (
    _branch_to, _is_cmp_imm, _is_mov_imm, _preserved_register, _thumb_insn,
)


def _arg_byte_offset(address, argument_index=0):
    argument = SymbolicValue.arg(argument_index)
    if address == argument:
        return 0
    if (address.kind == "op" and address.value == "add"
            and address.operands[0] == argument
            and address.operands[1].kind == "const"):
        return address.operands[1].value
    return None


def _register_index(register):
    if a.ARM_REG_R0 <= register <= a.ARM_REG_R7:
        return register - a.ARM_REG_R0
    return None


def _contains_input_byte(value, argument_index=0):
    if value is None:
        return False
    if value.kind == "load" and value.operands:
        if _arg_byte_offset(value.operands[0], argument_index) == 0:
            return True
    return any(_contains_input_byte(child, argument_index)
               for child in value.operands)


def _event_classifier_table(image, facts, function, event_codes):
    """Prove the mutable RAM lookup is indexed by the input event byte."""
    indexed_reads = [access for access in function.symbolic_accesses
                     if access.operation == "read" and access.width == 1
                     and _contains_input_byte(access.address, 0)]
    if not indexed_reads or not event_codes:
        return None
    tables = {}
    for access in indexed_reads:
        address = access.address
        if (address.kind != "op" or address.value != "add"
                or len(address.operands) != 2):
            continue
        constants = [value.value for value in address.operands
                     if value.kind == "const"]
        input_loads = [value for value in address.operands
                       if value.kind == "load" and value.operands
                       and value.width == 1 and not value.signed
                       and _arg_byte_offset(value.operands[0], 0) == 0]
        if len(constants) != 1 or len(input_loads) != 1:
            continue
        base = constants[0]
        load = _thumb_insn(facts, access.instruction.address)
        if (load is None or load.id != a.ARM_INS_LDRB or len(load.operands) != 2
                or load.operands[0].type != a.ARM_OP_REG
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.index in (0, a.ARM_REG_INVALID)):
            continue
        base_register = load.operands[1].mem.base
        index_register = load.operands[1].mem.index
        index_value = facts.register_value(function, access.instruction,
                                           index_register)
        if (facts.register_value(function, access.instruction, base_register)
                != SymbolicValue.const(base)
                or index_value is None or index_value.kind != "load"
                or index_value.width != 1 or index_value.signed
                or index_value.site not in function.instructions
                or not index_value.operands
                or _arg_byte_offset(index_value.operands[0], 0) != 0):
            continue
        input_instruction = facts.decode(index_value.site)
        if input_instruction is None or input_instruction.id != a.ARM_INS_LDRB:
            continue
        literals = [literal for literal in function.literals
                    if literal.value == base and literal.register == base_register
                    and function.dominates(literal.instruction,
                                           access.instruction)]
        if len(literals) != 1:
            continue
        writes = [item for item in function.symbolic_accesses
                  if item.operation == "write" and item.width == 1
                  and item.address == address
                  and function.dominates(access.instruction, item.instruction)]
        if not writes:
            continue
        class_branches = []
        for pc in function.instructions:
            compare = _thumb_insn(facts, pc.address)
            if (compare is None or compare.id != a.ARM_INS_CMP
                    or len(compare.operands) != 2
                    or compare.operands[0].type != a.ARM_OP_REG
                    or compare.operands[0].reg != load.operands[0].reg
                    or compare.operands[1].type != a.ARM_OP_IMM
                    or compare.operands[1].imm not in (0, 1, 2, 3)):
                continue
            branch_pc = pc.address + compare.size
            branch = _thumb_insn(facts, branch_pc)
            if (branch is not None and branch.id == a.ARM_INS_B
                    and branch.cc == a.ARM_CC_EQ
                    and function.dominates(access.instruction,
                                           CodeAddress(pc.address))
                    and _preserved_register(
                        image, access.instruction.address + load.size,
                        pc.address, load.operands[0].reg, facts)):
                class_branches.append(branch_pc)
        if not class_branches:
            continue
        item = tables.setdefault(base, {"base": base, "read_sites": set(),
            "write_sites": set(), "literal_sites": set(),
            "class_branch_sites": set(), "base_register": base_register,
            "index_register": index_register, "index_values": sorted(set(event_codes))})
        if (item["base_register"] != base_register
                or item["index_register"] != index_register
                or item["index_values"] != sorted(set(event_codes))):
            return None
        item["read_sites"].add(access.instruction.address)
        item["write_sites"].update(write.instruction.address for write in writes)
        item["literal_sites"].update((literal.instruction.address, literal.pool)
                                      for literal in literals)
        item["class_branch_sites"].update(class_branches)
    if not tables:
        return None
    result = []
    for item in tables.values():
        values = item["index_values"]
        start, end = item["base"] + min(values), item["base"] + max(values) + 1
        dependencies = {(site, facts.decode(CodeAddress(site)).size)
                        for site in (*item["read_sites"], *item["write_sites"],
                                     *item["class_branch_sites"])}
        dependencies.update((site, facts.decode(CodeAddress(site)).size)
                            for site, _pool in item["literal_sites"])
        dependencies.update((pool, 4) for _site, pool in item["literal_sites"])
        result.append({"base": item["base"], "address_start": start,
            "address_end": end, "index_register": _register_index(item["index_register"]),
            "base_register": _register_index(item["base_register"]),
            "index_source": "input-event-byte", "index_values": values,
            "read_sites": sorted(item["read_sites"]),
            "write_sites": sorted(item["write_sites"]),
            "literal_sites": sorted(site for site, _pool in item["literal_sites"]),
            "literal_pools": sorted(pool for _site, pool in item["literal_sites"]),
            "class_branch_sites": sorted(item["class_branch_sites"]),
            "contents": "mutable-runtime-state",
            "dependencies": sorted(dependencies)})
    return result


def _pair_callee_proof(image, target, *, consumer, event_codes=()):
    facts = facts_for(image)
    function = facts.function(CodeAddress(target), budget=512,
        symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                            a.ARM_REG_R1: SymbolicValue.arg(1)})
    if not function.complete or function.truncated or function.unresolved:
        return False
    read_offsets = {_arg_byte_offset(access.address)
                    for access in function.symbolic_accesses
                    if access.operation == "read" and access.width == 1}
    branch_offsets = set()
    for site in function.instructions:
        ins = facts.decode(site)
        if ins is None or ins.id != a.ARM_INS_B or ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID):
            continue
        branch = facts.branch_predicate(function, site)
        if branch is not None:
            branch_offsets.update(_arg_byte_offset(source.address)
                                  for source in branch.read_sources if source.width == 1)
    required_branches = {1} if consumer else {0, 1}
    if not {0, 1} <= read_offsets or not required_branches <= branch_offsets:
        return False
    if not consumer:
        event_stores, mode_stores = [], []
        for access in function.symbolic_accesses:
            if access.operation != "write" or access.width != 1:
                continue
            out_offset = _arg_byte_offset(access.address, 1)
            value = access.value
            source_offset = (_arg_byte_offset(value.operands[0])
                             if value is not None and value.kind == "load"
                             and value.operands else None)
            if out_offset == 0 and source_offset == 0:
                event_stores.append(access.instruction)
            if (out_offset == 1 and source_offset == 1
                    or out_offset == 1 and value is not None
                    and value.kind == "const" and value.value in (0, 1, 2)):
                mode_stores.append(access.instruction)
        if not event_stores or not mode_stores:
            return False
        classifier_tables = _event_classifier_table(image, facts, function,
                                                    event_codes)
        classifier_branches = {site for table in classifier_tables or ()
                               for site in table["class_branch_sites"]}
        event_branches = set()
        mode_branches = set()
        for site in function.instructions:
            ins = facts.decode(site)
            if ins is None or ins.id != a.ARM_INS_B or ins.cc in (a.ARM_CC_AL,
                                                                  a.ARM_CC_INVALID):
                continue
            branch = facts.branch_predicate(function, site)
            if branch is None:
                continue
            offsets = {_arg_byte_offset(source.address)
                       for source in branch.read_sources if source.width == 1}
            if 0 in offsets:
                event_branches.add(site.address)
            if 1 in offsets:
                mode_branches.add(site.address)
        event_branches.update(classifier_branches)
        output_pairs = []
        for event_store in event_stores:
            for mode_store in mode_stores:
                if function.linear_path(event_store, mode_store) is None:
                    continue
                mode_controls = [site for site in mode_branches
                    if function.dominates(CodeAddress(site), event_store)
                    and function.dominates(CodeAddress(site), mode_store)]
                class_controls = [site for site in event_branches
                    if function.dominates(CodeAddress(site), event_store)
                    and function.dominates(CodeAddress(site), mode_store)]
                if not mode_controls or not class_controls:
                    continue
                output_pairs.append({
                    "output_event_store": event_store.address,
                    "output_mode_store": mode_store.address,
                    "output_mode_source": ("input-mode" if
                        any(access.instruction == mode_store and
                            access.value is not None and
                            access.value.kind == "load" and
                            access.value.operands and
                            _arg_byte_offset(access.value.operands[0]) == 1
                            for access in function.symbolic_accesses
                            if access.operation == "write")
                        else "source-constant"),
                    "mode_control_sites": sorted(set(mode_controls)),
                    "event_control_sites": sorted(set(class_controls))})
        if not output_pairs:
            return False
        return {"hardware_only": True,
            "event_input_read_sites": sorted(access.instruction.address
                for access in function.symbolic_accesses
                if access.operation == "read" and access.width == 1
                and _arg_byte_offset(access.address) == 0),
            "mode_input_read_sites": sorted(access.instruction.address
                for access in function.symbolic_accesses
                if access.operation == "read" and access.width == 1
                and _arg_byte_offset(access.address) == 1),
            "output_pairs": output_pairs,
            "classifier_tables": classifier_tables or [],
            "dependencies": sorted(set(span for table in classifier_tables or []
                                       for span in table["dependencies"]))}
    # At least one event-handler call must receive the event byte itself;
    # unrelated calls after loading both bytes do not qualify.
    for site, _target in function.calls:
        value = facts.register_value(function, site, a.ARM_REG_R0)
        if (value is not None and value.kind == "load" and value.operands
                and _arg_byte_offset(value.operands[0]) == 0):
            return True
    return False


def _function_dependencies(facts, entry, *, budget=512, symbolic_registers=None):
    function = facts.function(CodeAddress(entry), budget=budget,
                              symbolic_registers=symbolic_registers or {})
    if not function.complete or function.truncated or function.unresolved:
        return None
    spans = {(site.address, facts.decode(site).size)
             for site in function.instructions if facts.decode(site) is not None}
    spans.update((literal.pool, 4) for literal in function.literals)
    return sorted(spans)


def _sp_add(image, pc, register, offset, facts):
    ins = _thumb_insn(facts, pc)
    return (ins is not None and ins.id == a.ARM_INS_ADD
            and len(ins.operands) == 3
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == register
            and ins.operands[1].type == a.ARM_OP_REG
            and ins.operands[1].reg == a.ARM_REG_SP
            and ins.operands[2].type == a.ARM_OP_IMM
            and ins.operands[2].imm == offset)


def _strb_at(image, pc, source, base, offset, facts):
    ins = _thumb_insn(facts, pc)
    return (ins is not None and ins.id == a.ARM_INS_STRB
            and len(ins.operands) == 2
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == source
            and ins.operands[1].type == a.ARM_OP_MEM
            and ins.operands[1].mem.base == base
            and ins.operands[1].mem.index in (0, a.ARM_REG_INVALID)
            and ins.operands[1].mem.disp == offset)


def _stack_pair_linkage(image, load_pc, predicate=None, consumer=None,
                        function=None, event_codes=()):
    """Prove a contiguous event/mode pair handoff and both consuming callees."""
    facts = facts_for(image)
    entry = _thumb_function_start(image, load_pc)
    function = function or facts.function(CodeAddress(entry), budget=1024)
    if not function.complete or function.truncated or function.unresolved:
        return None
    load = _thumb_insn(facts, load_pc)
    if (load is None or load.id != a.ARM_INS_LDRB or len(load.operands) != 2
            or load.operands[0].type != a.ARM_OP_REG
            or load.operands[1].type != a.ARM_OP_MEM
            or load.operands[1].mem.index in (0, a.ARM_REG_INVALID)):
        return None
    event_reg = load.operands[0].reg
    add_sp = _thumb_insn(facts, load_pc + 2)
    add_r1 = _thumb_insn(facts, load_pc + 4)
    if (add_sp is None or add_sp.id != a.ARM_INS_ADD or len(add_sp.operands) != 3
            or add_sp.operands[0].type != a.ARM_OP_REG
            or add_sp.operands[1].type != a.ARM_OP_REG
            or add_sp.operands[1].reg != a.ARM_REG_SP
            or add_sp.operands[2].type != a.ARM_OP_IMM
            or add_r1 is None or add_r1.id != a.ARM_INS_ADD
            or len(add_r1.operands) != 3 or add_r1.operands[0].reg != a.ARM_REG_R1
            or add_r1.operands[1].reg != a.ARM_REG_SP
            or add_r1.operands[2].type != a.ARM_OP_IMM):
        return None
    pair_reg = add_sp.operands[0].reg
    event_store = _thumb_insn(facts, load_pc + 6)
    if (event_store is None or event_store.id != a.ARM_INS_STRB
            or event_store.operands[1].type != a.ARM_OP_MEM):
        return None
    pair_base = add_sp.operands[2].imm + event_store.operands[1].mem.disp
    if (not _strb_at(image, load_pc + 6, event_reg, pair_reg,
                     event_store.operands[1].mem.disp, facts)
            or _thumb_insn(facts, load_pc + 8) is None):
        return None
    mode_store = _thumb_insn(facts, load_pc + 8)
    if (mode_store.id != a.ARM_INS_STRB or len(mode_store.operands) != 2
            or mode_store.operands[1].type != a.ARM_OP_MEM
            or mode_store.operands[1].mem.base != pair_reg
            or mode_store.operands[1].mem.index not in (0, a.ARM_REG_INVALID)
            or mode_store.operands[1].mem.disp != event_store.operands[1].mem.disp + 1
            or add_r1.operands[2].imm != pair_base - 4
            or not _sp_add(image, load_pc + 10, a.ARM_REG_R0, pair_base, facts)):
        return None
    mode_reg = mode_store.operands[0].reg
    mode = facts.register_value(function, CodeAddress(load_pc + 8), mode_reg)
    if mode != SymbolicValue.const(1):
        return None
    pred_call = load_pc + 12
    predicate_target = facts.thumb_call_target(pred_call)
    if predicate_target is None or predicate is not None and predicate_target != predicate:
        return None
    compare = _thumb_insn(facts, load_pc + 16)
    branch = _thumb_insn(facts, load_pc + 18)
    if (compare is None or compare.id != a.ARM_INS_CMP or len(compare.operands) != 2
            or compare.operands[0].reg != a.ARM_REG_R0
            or compare.operands[1].type != a.ARM_OP_IMM or compare.operands[1].imm != 1
            or branch is None or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_NE):
        return None
    if not _sp_add(image, load_pc + 20, a.ARM_REG_R0, pair_base - 4, facts):
        return None
    consumer_call = load_pc + 22
    consumer_target = facts.thumb_call_target(consumer_call)
    if (consumer_target is None or consumer is not None and consumer_target != consumer
            or not branch.operands or branch.operands[0].imm != consumer_call + 4):
        return None
    for source, destination in ((load_pc, load_pc + 6),
                                (load_pc + 6, load_pc + 8),
                                (load_pc + 8, pred_call),
                                (pred_call, consumer_call)):
        if not function.dominates(CodeAddress(source), CodeAddress(destination)):
            return None
    predicate_proof = _pair_callee_proof(image, predicate_target,
        consumer=False, event_codes=event_codes)
    if (not predicate_proof
            or not _pair_callee_proof(image, consumer_target, consumer=True)):
        return None
    return {"event_load_site": load_pc, "event_register": _register_index(event_reg),
            "event_stack_offset": pair_base, "mode_stack_offset": pair_base + 1,
            "consumer_arg_stack_offset": pair_base - 4,
            "predicate_output_stack_offset": pair_base - 4,
            "consumer_event_offset": 0, "consumer_mode_offset": 1,
            "mode": 1, "predicate_site": pred_call,
            "consumer_site": consumer_call,
            "predicate_target": predicate_target,
            "consumer_target": consumer_target,
            "predicate_hardware": predicate_proof}


def _second_pair_linkage(image, event_load, function, predicate_target,
                         consumer_target, facts, event_codes=()):
    """Prove the release/column scan stores its table byte and mode pair."""
    load = _thumb_insn(facts, event_load)
    if (load is None or load.id != a.ARM_INS_LDRB or len(load.operands) != 2
            or load.operands[0].type != a.ARM_OP_REG
            or load.operands[0].reg != a.ARM_REG_R7):
        return None
    stores = []
    for pc in range(event_load + 2, min(event_load + 0x60, len(image) - 2), 2):
        if not _strb_at(image, pc, a.ARM_REG_R7, a.ARM_REG_R3, 0x10, facts):
            continue
        if not _sp_add(image, pc - 2, a.ARM_REG_R3, 0, facts):
            continue
        if not function.dominates(CodeAddress(event_load), CodeAddress(pc)):
            continue
        try:
            preserved = _preserved_register(image, event_load + 2, pc,
                                             a.ARM_REG_R7, facts)
        except Exception:
            preserved = False
        if not preserved:
            continue
        stores.append(pc)
    if len(stores) != 1:
        return None
    event_store = stores[0]
    column_result_copy = event_load - 12
    if (not function.dominates(CodeAddress(column_result_copy),
                               CodeAddress(event_store))
            or not _preserved_register(image, column_result_copy + 2,
                                       event_store + 2, a.ARM_REG_R6, facts)):
        return None
    # The two predecessor branches select mode one or mode two, then join at
    # the adjacent mode-byte store. No branch may bypass either pair store.
    if (not _is_cmp_imm(_thumb_insn(facts, event_store + 2), a.ARM_REG_R6, 1)
            or not _branch_to(facts, event_store + 4, a.ARM_CC_NE, event_store + 10)
            or not _is_mov_imm(_thumb_insn(facts, event_store + 6), a.ARM_REG_R0, 1)
            or not _branch_to(facts, event_store + 8, a.ARM_CC_AL, event_store + 16)
            or not _is_mov_imm(_thumb_insn(facts, event_store + 10), a.ARM_REG_R0, 0)
            or not _is_mov_imm(_thumb_insn(facts, event_store + 14), a.ARM_REG_R0, 2)
            or not _sp_add(image, event_store + 16, a.ARM_REG_R3, 0, facts)
            or not _strb_at(image, event_store + 18, a.ARM_REG_R0,
                            a.ARM_REG_R3, 0x11, facts)):
        return None
    mode_store = event_store + 18
    predicate_call = event_store + 24
    if (facts.thumb_call_target(predicate_call) != predicate_target
            or not _sp_add(image, event_store + 20, a.ARM_REG_R0, 0x10, facts)
            or not _sp_add(image, event_store + 22, a.ARM_REG_R1, 0x0c, facts)):
        return None
    compare = _thumb_insn(facts, event_store + 28)
    reject_branch = _thumb_insn(facts, event_store + 30)
    if (not _is_cmp_imm(compare, a.ARM_REG_R0, 1)
            or reject_branch is None or reject_branch.id != a.ARM_INS_B
            or reject_branch.cc != a.ARM_CC_NE):
        return None
    consumers = [pc for pc in range(predicate_call + 4,
        min(predicate_call + 0x60, len(image) - 4), 2)
        if facts.thumb_call_target(pc) == consumer_target]
    if len(consumers) != 1:
        return None
    consumer_call = consumers[0]
    if (not _sp_add(image, consumer_call - 2, a.ARM_REG_R0, 0x0c, facts)
            or not reject_branch.operands
            or reject_branch.operands[0].imm != consumer_call + 4
            or not function.dominates(CodeAddress(event_store), CodeAddress(mode_store))
            or not function.dominates(CodeAddress(mode_store), CodeAddress(predicate_call))
            or not function.dominates(CodeAddress(predicate_call), CodeAddress(consumer_call))):
        return None
    predicate_proof = _pair_callee_proof(image, predicate_target,
        consumer=False, event_codes=event_codes)
    if not predicate_proof:
        return None
    return {"event_load_site": event_load,
            "event_register": _register_index(a.ARM_REG_R7),
            "event_stack_offset": 0x10, "mode_stack_offset": 0x11,
            "consumer_arg_stack_offset": 0x0c,
            "predicate_output_stack_offset": 0x0c,
            "consumer_event_offset": 0, "consumer_mode_offset": 1,
            "mode": "1-or-2", "predicate_site": predicate_call,
            "consumer_site": consumer_call,
            "predicate_target": predicate_target,
            "consumer_target": consumer_target,
            "predicate_hardware": predicate_proof}


def _event_index_shape(image, sense_site, facts):
    """Confirm (sense * 7) + drive indexes the LDRB event table."""
    ins = [_thumb_insn(facts, sense_site + offset)
           for offset in (16, 18, 20, 22, 24, 26)]
    if any(item is None for item in ins):
        return False
    shift, literal, sub_row, sub_end, add_base, load = ins
    return (shift.id == a.ARM_INS_LSL
            and len(shift.operands) == 3
            and shift.operands[0].type == a.ARM_OP_REG
            and shift.operands[0].reg == a.ARM_REG_R0
            and shift.operands[1].type == a.ARM_OP_REG
            and shift.operands[1].reg == a.ARM_REG_R7
            and shift.operands[2].type == a.ARM_OP_IMM
            and shift.operands[2].imm == 3
            and literal.id == a.ARM_INS_LDR
            and literal.operands[0].type == a.ARM_OP_REG
            and literal.operands[0].reg == a.ARM_REG_R1
            and sub_row.id == a.ARM_INS_SUB
            and len(sub_row.operands) == 3
            and sub_row.operands[0].type == a.ARM_OP_REG
            and sub_row.operands[0].reg == a.ARM_REG_R0
            and sub_row.operands[1].type == a.ARM_OP_REG
            and sub_row.operands[1].reg == a.ARM_REG_R0
            and sub_row.operands[2].type == a.ARM_OP_REG
            and sub_row.operands[2].reg == a.ARM_REG_R7
            and sub_end.id == a.ARM_INS_SUB
            and sub_end.operands[0].type == a.ARM_OP_REG
            and sub_end.operands[0].reg == a.ARM_REG_R1
            and sub_end.operands[0].type == a.ARM_OP_REG
            and sub_end.operands[0].reg == a.ARM_REG_R1
            and sub_end.operands[-1].type == a.ARM_OP_IMM
            and sub_end.operands[-1].imm == 0x3c
            and add_base.id == a.ARM_INS_ADD
            and len(add_base.operands) == 3
            and add_base.operands[0].type == a.ARM_OP_REG
            and add_base.operands[0].reg == a.ARM_REG_R5
            and add_base.operands[1].type == a.ARM_OP_REG
            and add_base.operands[1].reg == a.ARM_REG_R1
            and add_base.operands[2].type == a.ARM_OP_REG
            and add_base.operands[2].reg == a.ARM_REG_R0
            and load.id == a.ARM_INS_LDRB
            and load.operands[0].type == a.ARM_OP_REG
            and load.operands[0].reg == a.ARM_REG_R0
            and load.operands[1].type == a.ARM_OP_MEM
            and load.operands[1].mem.base == a.ARM_REG_R5
            and load.operands[1].mem.index == a.ARM_REG_R4)


def _event_index_shape_second(image, sense_site, expected_table, facts):
    shift = _thumb_insn(facts, sense_site + 20)
    ins = [_thumb_insn(facts, sense_site + offset)
           for offset in (22, 24, 26, 28, 30)]
    if shift is None or any(item is None for item in ins):
        return None
    literal, sub_row, sub_end, add_base, load = ins
    if (shift.id != a.ARM_INS_LSL or len(shift.operands) != 3
            or shift.operands[0].type != a.ARM_OP_REG
            or shift.operands[0].reg != a.ARM_REG_R0
            or shift.operands[1].type != a.ARM_OP_REG
            or shift.operands[1].reg != a.ARM_REG_R4
            or shift.operands[2].type != a.ARM_OP_IMM
            or shift.operands[2].imm != 3
            or literal.id != a.ARM_INS_LDR or literal.operands[0].type != a.ARM_OP_REG
            or literal.operands[0].reg != a.ARM_REG_R1
            or sub_row.id != a.ARM_INS_SUB or len(sub_row.operands) != 3
            or sub_row.operands[0].type != a.ARM_OP_REG
            or sub_row.operands[0].reg != a.ARM_REG_R0
            or sub_row.operands[1].type != a.ARM_OP_REG
            or sub_row.operands[1].reg != a.ARM_REG_R0
            or sub_row.operands[2].type != a.ARM_OP_REG
            or sub_row.operands[2].reg != a.ARM_REG_R4
            or sub_end.id != a.ARM_INS_SUB or len(sub_end.operands) != 2
            or sub_end.operands[0].type != a.ARM_OP_REG
            or sub_end.operands[0].reg != a.ARM_REG_R1
            or sub_end.operands[1].type != a.ARM_OP_IMM
            or sub_end.operands[1].imm != 0x3c
            or add_base.id != a.ARM_INS_ADD or len(add_base.operands) != 3
            or add_base.operands[0].type != a.ARM_OP_REG
            or add_base.operands[0].reg != a.ARM_REG_R0
            or add_base.operands[1].type != a.ARM_OP_REG
            or add_base.operands[1].reg != a.ARM_REG_R0
            or add_base.operands[2].type != a.ARM_OP_REG
            or add_base.operands[2].reg != a.ARM_REG_R1
            or load.id != a.ARM_INS_LDRB
            or load.operands[0].type != a.ARM_OP_REG
            or load.operands[0].reg != a.ARM_REG_R7
            or load.operands[1].type != a.ARM_OP_MEM
            or load.operands[1].mem.base != a.ARM_REG_R0
            or load.operands[1].mem.index != a.ARM_REG_R5):
        return None
    end = facts.literal(CodeAddress(sense_site + 22))
    return sense_site + 30 if end is not None and end.value - 0x3c == expected_table else None
