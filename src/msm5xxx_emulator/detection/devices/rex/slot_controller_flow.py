"""CFG and reaching-definition proof for indexed callback stores."""
import struct
from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


def two_bank_handler_source(image, handler, masks, status):
    """Expose the shared two-bank instruction contract to other domains."""
    from .rules.timer_shapes import _controller_two_bank_handler_at
    return _controller_two_bank_handler_at(image, handler, masks, status)


def descriptor_seeds(image, copy, status, enable, mask):
    source, _target, size, _wrapper = copy
    end = min(len(image), source + size)
    candidates = []
    for offset in range(source, end - 28 + 1, 4):
        words = struct.unpack_from("<7I", image, offset)
        if (words[0:3] != (status, enable, mask) or words[4] != words[3] + 6
                or words[6] != 0 or not words[5] & 1
                or words[5] & ~1 >= len(image)):
            continue
        runtime = copy[1] + offset - source
        candidates.append((offset, runtime, words, words[5] & ~1))
    return candidates


def thumb_call_targets(image):
    import re
    from msm5xxx_emulator.detection.devices.rex.rules import THUMB_BL_PATTERN
    facts = facts_for(image)
    for match in THUMB_BL_PATTERN.finditer(image):
        pc = match.start()
        if pc & 1:
            continue
        instruction = facts.decode(CodeAddress(pc, "thumb"))
        if instruction is not None and instruction.id == a.ARM_INS_BL:
            target = facts.thumb_call_target(pc)
            if target is not None:
                yield pc, target


def thumb_span(image, start, end):
    facts = facts_for(image)
    pc, result = start, []
    while pc < end:
        ins = facts.decode(CodeAddress(pc, "thumb"))
        if ins is None or ins.size not in (2, 4):
            break
        result.append((pc, ins))
        pc += ins.size
    return result


def one_definition(definitions):
    if definitions is None or len(definitions) != 1 or definitions[0] is None:
        return None
    return definitions[0]


def unconditional_sites(facts, flow, addresses):
    """Require plain ARM/Thumb instructions outside predicated IT blocks."""
    from capstone import arm as a
    if not flow.complete or flow.truncated or flow.unresolved:
        return False
    if any((ins := facts.decode(site)) is not None
           and ins.id == getattr(a, "ARM_INS_IT", -1)
           for site in flow.instructions):
        return False
    unconditional = (a.ARM_CC_AL, a.ARM_CC_INVALID)
    return all((ins := facts.decode(CodeAddress(pc, flow.entry.isa))) is not None
               and ins.cc in unconditional for pc in addresses)


def prove_row_path(image, registrar, multiply, addition, store, slot_reg,
                   stride_reg, base_reg, callback_reg, slot_size, callback_field,
                   callback_table, callback_pointer):
    from msm5xxx_emulator.detection.values import SymbolicValue
    if callback_pointer is None:
        return False
    facts = facts_for(image)
    entry = CodeAddress(registrar, "thumb")
    flow = facts.function(entry, budget=512,
        initial_registers={a.ARM_REG_R1: callback_pointer},
        symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)},
        stop_at_initial_return=True)
    sites = [CodeAddress(pc, "thumb") for pc in (multiply, addition, store)]
    if (not flow.complete or flow.truncated or flow.unresolved
            or any(site not in flow.instructions for site in sites)
            or not (flow.dominates(entry, sites[0])
                    and flow.dominates(sites[0], sites[1])
                    and flow.dominates(sites[1], sites[2]))):
        return False
    from .slot_controller_flow import unconditional_sites
    if not unconditional_sites(facts, flow, (multiply, addition, store)):
        return False
    defs = lambda use, reg: one_definition(facts.reaching_definitions(
        flow, CodeAddress(use, "thumb"), reg, include_entry=True))
    mul, add, saved = (facts.decode(site) for site in sites)
    if (any(ins is None for ins in (mul, add, saved)) or len(saved.operands) != 2
            or saved.operands[1].type != a.ARM_OP_MEM):
        return False
    slot_def = defs(multiply, slot_reg)
    stride_def = defs(multiply, stride_reg)
    table_def = defs(addition, base_reg)
    row_def = defs(store, saved.operands[1].mem.base)
    callback_def = defs(store, callback_reg)
    if None in (slot_def, stride_def, table_def, row_def, callback_def):
        return False
    slot_ins, stride_ins = facts.decode(slot_def), facts.decode(stride_def)
    table_ins, row_ins, callback_ins = (facts.decode(pc) for pc in
        (table_def, row_def, callback_def))
    if any(ins is None for ins in (slot_ins, stride_ins, table_ins, row_ins, callback_ins)):
        return False
    def reaches(source, destination):
        successors = {}
        for left, right in flow.control_edges:
            successors.setdefault(left, set()).add(right)
        pending, seen = [source], set()
        while pending:
            current = pending.pop()
            if current == destination:
                return True
            if current in seen:
                continue
            seen.add(current)
            pending.extend(successors.get(current, ()))
        return False
    def incoming_argument_survives(source_reg, copy_pc):
        definitions = facts.reaching_definitions(flow, copy_pc, source_reg,
                                                  include_entry=True)
        if definitions == (None,):
            return True
        if definitions is not None:
            return False
        reached_call = False
        copy_site = CodeAddress(copy_pc.address, "thumb")
        for callsite, target in flow.calls:
            if not reaches(callsite, copy_site):
                continue
            if flow.dominates(copy_site, callsite):
                continue
            reached_call = True
            if not callee_preserves(image, target, (source_reg,)):
                return False
        return reached_call
    slot_copy = (slot_ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
        and len(slot_ins.operands) == 2
        and slot_ins.operands[1].type == a.ARM_OP_REG
        and slot_ins.operands[1].reg == a.ARM_REG_R0)
    slot_copy |= (slot_ins.id == a.ARM_INS_ADD and len(slot_ins.operands) == 3
        and slot_ins.operands[1].type == a.ARM_OP_REG
        and slot_ins.operands[1].reg == a.ARM_REG_R0
        and slot_ins.operands[2].type == a.ARM_OP_IMM
        and slot_ins.operands[2].imm == 0)
    callback_copy = (callback_ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
        and len(callback_ins.operands) == 2
        and callback_ins.operands[1].type == a.ARM_OP_REG
        and callback_ins.operands[1].reg == a.ARM_REG_R1)
    callback_copy |= (callback_ins.id == a.ARM_INS_ADD and len(callback_ins.operands) == 3
        and callback_ins.operands[1].type == a.ARM_OP_REG
        and callback_ins.operands[1].reg == a.ARM_REG_R1
        and callback_ins.operands[2].type == a.ARM_OP_IMM
        and callback_ins.operands[2].imm == 0)
    if not (slot_copy and incoming_argument_survives(a.ARM_REG_R0, slot_def)):
        return False
    if not (stride_ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            and len(stride_ins.operands) == 2
            and stride_ins.operands[1].type == a.ARM_OP_IMM
            and stride_ins.operands[1].imm == slot_size):
        return False
    if (table_ins.id != a.ARM_INS_LDR
            or not any(item.instruction.address == table_def.address
                       and item.value == callback_table for item in flow.literals)
            or row_ins.id != a.ARM_INS_ADD
            or not callback_copy):
        return False
    if not unconditional_sites(facts, flow,
            (slot_def.address, callback_def.address)):
        return False
    if not incoming_argument_survives(a.ARM_REG_R1, callback_def):
        return False
    mul_operands = {operand.reg for operand in mul.operands
                    if operand.type == a.ARM_OP_REG}
    add_operands = {operand.reg for operand in add.operands
                    if operand.type == a.ARM_OP_REG}
    call_by_site = {site: target for site, target in flow.calls}
    for callsite in call_by_site:
        if (slot_def.address < callsite.address < store
                and flow.dominates(callsite, CodeAddress(store, "thumb"))):
            known_zero = (callback_ins.update_flags
                          and callsite.address == callback_def.address + callback_ins.size
                          and type(callback_pointer) is int and callback_pointer != 0)
            if not callee_preserves(image, call_by_site[callsite],
                                    (slot_reg, callback_reg), known_zero):
                return False
    return (mul.id == a.ARM_INS_MUL
            and {slot_reg, stride_reg} <= mul_operands
            and row_def.address == addition
            and len(add.operands) == 3
            and add.operands[0].type == a.ARM_OP_REG
            and add.operands[0].reg == saved.operands[1].mem.base
            and add_operands == {add.operands[0].reg, mul.operands[0].reg, base_reg}
            and saved.id == a.ARM_INS_STR and len(saved.operands) == 2
            and saved.operands[0].type == a.ARM_OP_REG
            and saved.operands[0].reg == callback_reg
            and saved.operands[1].mem.disp == callback_field)


def callee_preserves(image, target, registers, zero_flag_known=False):
    from msm5xxx_emulator.detection.values import _FLAG_Z
    facts = facts_for(image)
    initial = {_FLAG_Z: 0} if zero_flag_known else {}
    flow = facts.function(target, budget=512, initial_registers=initial,
                          stop_at_initial_return=True)
    if not flow.complete or flow.truncated or flow.unresolved or flow.calls:
        return False
    outgoing = {source for source, _target in flow.control_edges}
    terminals = [site for site in flow.instructions
        if site not in outgoing and (ins := facts.decode(site)) is not None
        and (ins.id == a.ARM_INS_BX and ins.operands
             and ins.operands[0].reg == a.ARM_REG_LR
             or ins.id == a.ARM_INS_POP and any(op.type == a.ARM_OP_REG
                                                and op.reg == a.ARM_REG_PC
                                                for op in ins.operands))]
    if not terminals or len(terminals) != len(set(flow.instructions) - outgoing):
        return False
    for register in registers:
        if any(facts.reaching_definitions(flow, terminal, register,
                                         include_entry=True) != (None,)
               for terminal in terminals):
            return False
    return True


def prove_setter_path(image, entry_address, compare, stores, slot_register, slot_address):
    from msm5xxx_emulator.detection.values import SymbolicValue
    facts = facts_for(image)
    entry = CodeAddress(entry_address, "thumb")
    flow = facts.function(entry, budget=128,
        symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                            a.ARM_REG_R1: SymbolicValue.arg(1)},
        stop_at_initial_return=True)
    compare_site = CodeAddress(compare, "thumb")
    store_sites = tuple(CodeAddress(pc, "thumb") for pc in stores)
    if (not flow.complete or flow.truncated or flow.unresolved
            or compare_site not in flow.instructions
            or any(site not in flow.instructions
                   or not flow.dominates(compare_site, site)
                   or not flow.dominates(entry, site) for site in store_sites)):
        return False
    if not unconditional_sites(facts, flow, (compare,)):
        return False
    if facts.reaching_definitions(flow, compare_site, a.ARM_REG_R0,
                                  include_entry=True) != (None,):
        return False
    compare = facts.decode(compare_site)
    branch_site = (CodeAddress(compare_site.address + compare.size, "thumb")
                   if compare is not None else None)
    branch = facts.decode(branch_site) if branch_site in flow.instructions else None
    if (branch is None or branch.id != a.ARM_INS_B
            or branch.cc != a.ARM_CC_NE or len(branch.operands) != 1
            or branch.operands[0].type != a.ARM_OP_IMM):
        return False
    if facts.reaching_definitions(flow, branch_site, a.ARM_REG_CPSR,
                                  include_entry=True) != (compare_site,):
        return False
    by_offset = {facts.decode(site).operands[1].mem.disp: site for site in store_sites}
    if (set(by_offset) != {4, 8}
            or branch.operands[0].imm != by_offset[8].address
            or branch_site.address + branch.size != by_offset[4].address):
        return False
    for site in store_sites:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_STR or len(ins.operands) != 2
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.base != slot_register
                or ins.operands[0].reg != a.ARM_REG_R1
                or ins.operands[1].mem.disp not in (4, 8)):
            return False
        source_defs = facts.reaching_definitions(flow, site, a.ARM_REG_R1,
                                                 include_entry=True)
        base_defs = facts.reaching_definitions(flow, site, slot_register,
                                               include_entry=True)
        if source_defs != (None,) or one_definition(base_defs) is None:
            return False
        base_def = one_definition(base_defs)
        if (not any(lit.instruction == base_def and lit.value == slot_address
                    for lit in flow.literals)):
            return False
    return True


def prove_vector_path(image, wrapper, literal_site, indirect_load, branch):
    facts = facts_for(image)
    entry = CodeAddress(wrapper, "arm")
    flow = facts.function(entry, budget=512, stop_at_initial_return=True,
                          _stop_before=frozenset({CodeAddress(branch, "arm")}))
    sites = tuple(CodeAddress(pc, "arm") for pc in
                  (literal_site, indirect_load, branch))
    if (not flow.complete or flow.truncated or flow.unresolved
            or any(site not in flow.instructions for site in sites)
            or not (flow.dominates(sites[0], sites[1])
                    and flow.dominates(sites[1], sites[2]))):
        return False
    if not unconditional_sites(facts, flow, (literal_site, indirect_load, branch)):
        return False
    literal, load, bx = (facts.decode(site) for site in sites)
    if (literal is None or load is None or bx is None
            or literal.id != a.ARM_INS_LDR or load.id != a.ARM_INS_LDR
            or bx.id != a.ARM_INS_BX or len(literal.operands) != 2
            or len(load.operands) != 2 or len(bx.operands) != 1):
        return False
    slot_reg = literal.operands[0].reg
    target_reg = load.operands[0].reg
    return (facts.reaching_definitions(flow, sites[1], load.operands[1].mem.base,
                                      include_entry=True) == (sites[0],)
            and facts.reaching_definitions(flow, sites[2], target_reg,
                                           include_entry=True) == (sites[1],)
            and bx.operands[0].reg == target_reg
            and slot_reg == load.operands[1].mem.base)


def _is_reg(operand, register):
    return operand.type == a.ARM_OP_REG and operand.reg == register

def _is_imm(operand, value):
    return operand.type == a.ARM_OP_IMM and operand.imm == value

def _literal_value(facts, pc):
    literal = facts.literal(CodeAddress(pc, "thumb"))
    return None if literal is None else literal.value

def _copy_source(copy, address, size, image_size):
    source, target, length, _wrapper = copy
    if size <= 0 or address < target or address + size > target + length:
        return None
    offset = source + address - target
    return offset if offset >= 0 and offset + size <= image_size else None

def group_stride_proof(image, handler, group_table, copy, group_count, group_row_size, timer_slot, mask):
    """Prove the three group rows, ten-byte scale, and timer slot-30 row."""
    facts = facts_for(image)
    end = min(len(image) - 2, handler + 0x280)
    code = []
    for pc, ins in thumb_span(image, handler, end):
        code.append((pc, ins))
        if (ins.id == a.ARM_INS_POP and any(op.type == a.ARM_OP_REG
                and op.reg == a.ARM_REG_PC for op in ins.operands)):
            break
        if (ins.id == a.ARM_INS_BX and ins.operands
                and ins.operands[0].type == a.ARM_OP_REG):
            break
    candidates = []
    for idx, (pc, mul) in enumerate(code):
        if mul.mnemonic.lower().rstrip("s") != "mul" or len(mul.operands) != 3:
            continue
        if any(op.type != a.ARM_OP_REG for op in mul.operands):
            continue
        dest, left, right = (op.reg for op in mul.operands)
        const_regs = {}
        base_regs = {}
        for earlier_pc, earlier in code[max(0, idx - 10):idx]:
            if (earlier.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    and len(earlier.operands) == 2
                    and earlier.operands[0].type == a.ARM_OP_REG
                    and earlier.operands[1].type == a.ARM_OP_IMM):
                const_regs[earlier.operands[0].reg] = earlier.operands[1].imm
            if (earlier.id == a.ARM_INS_LDR and len(earlier.operands) == 2
                    and earlier.operands[0].type == a.ARM_OP_REG
                    and earlier.operands[1].type == a.ARM_OP_MEM
                    and earlier.operands[1].mem.base == a.ARM_REG_PC):
                value = _literal_value(facts, earlier_pc)
                if value is not None:
                    base_regs[earlier.operands[0].reg] = value
        stride_regs = {reg for reg in (left, right)
                       if const_regs.get(reg) == group_row_size}
        if not stride_regs or len(stride_regs) != 1:
            continue
        for add_pc, add in code[idx + 1:idx + 4]:
            if (add.id not in (a.ARM_INS_ADD, a.ARM_INS_ADD)
                    or len(add.operands) != 3
                    or not _is_reg(add.operands[0], dest)
                    or any(op.type != a.ARM_OP_REG for op in add.operands[1:])):
                continue
            base_reg = next((reg for reg, value in base_regs.items()
                             if value == group_table and reg in
                             {add.operands[1].reg, add.operands[2].reg}), None)
            if base_reg is not None and dest in (add.operands[1].reg, add.operands[2].reg):
                candidates.append((idx, pc, add_pc, dest, next(iter(stride_regs)), base_reg))
    if len(candidates) != 1:
        return None
    idx, mul_pc, add_pc, row_reg, stride_reg, base_reg = candidates[0]
    counter_slot = None
    init_pc = None
    for j, (pc, ins) in enumerate(code[:idx]):
        if (ins.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                or len(ins.operands) != 2 or ins.operands[0].type != a.ARM_OP_REG
                or not _is_imm(ins.operands[1], 1)):
            continue
        reg = ins.operands[0].reg
        for store_pc, store in code[j + 1:min(idx, j + 4)]:
            if (store.id == a.ARM_INS_STR and len(store.operands) == 2
                    and _is_reg(store.operands[0], reg)
                    and store.operands[1].type == a.ARM_OP_MEM
                    and store.operands[1].mem.base == a.ARM_REG_SP):
                counter_slot = store.operands[1].mem.disp
                init_pc = pc
                break
        if counter_slot is not None:
            break
    if counter_slot is None:
        return None
    index_load = next((pc for pc, ins in code[idx - 4:idx]
        if ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
        and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.base == a.ARM_REG_SP
        and ins.operands[1].mem.disp == counter_slot), None)
    if index_load is None:
        return None
    footer = None
    for i, (pc, ins) in enumerate(code):
        if pc <= add_pc:
            continue
        if (ins.id not in (a.ARM_INS_ADD, a.ARM_INS_ADD)
                or len(ins.operands) not in (2, 3)
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[-1].type != a.ARM_OP_IMM
                or ins.operands[-1].imm != 1):
            continue
        register = ins.operands[0].reg
        for cmp_pc, compare in code[i + 1:i + 8]:
            if (compare.id != a.ARM_INS_CMP or len(compare.operands) != 2
                    or not _is_reg(compare.operands[0], register)
                    or not _is_imm(compare.operands[1], group_count + 1)):
                continue
            branch = next(((bp, bi) for bp, bi in code if bp == cmp_pc + compare.size), None)
            if branch is None or branch[1].id != a.ARM_INS_B or branch[1].cc not in (a.ARM_CC_GE, a.ARM_CC_HS):
                continue
            fallthrough = branch[0] + branch[1].size
            backedge = next(((bp, bi) for bp, bi in code
                             if bp >= fallthrough and bp < fallthrough + 8
                             and bi.id == a.ARM_INS_B and bi.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                             and bi.operands and bi.operands[0].type == a.ARM_OP_IMM
                             and bi.operands[0].imm <= index_load), None)
            counter_store = any(si.id == a.ARM_INS_STR and len(si.operands) == 2
                and _is_reg(si.operands[0], register)
                and si.operands[1].type == a.ARM_OP_MEM
                and si.operands[1].mem.base == a.ARM_REG_SP
                and si.operands[1].mem.disp == counter_slot
                for _, si in code[i + 1:code.index(branch) if branch in code else i + 8])
            if backedge is not None and counter_store:
                footer = (pc, cmp_pc, branch[0], backedge[0])
                break
        if footer:
            break
    if footer is None:
        return None
    pointer_regs = {row_reg}
    pointer_slots = set()
    fields = set()
    for pc, ins in code:
        if pc < add_pc or pc > footer[3]:
            continue
        if (ins.id == a.ARM_INS_STR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg in pointer_regs
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == a.ARM_REG_SP):
            pointer_slots.add(ins.operands[1].mem.disp)
        if (ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == a.ARM_REG_SP
                and ins.operands[1].mem.disp in pointer_slots):
            pointer_regs.add(ins.operands[0].reg)
        if (ins.id in (a.ARM_INS_LDRH, a.ARM_INS_LDRB) and len(ins.operands) == 2
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base in pointer_regs):
            fields.add((ins.id, ins.operands[1].mem.disp))
    halfwords = {disp for ins_id, disp in fields if ins_id == a.ARM_INS_LDRH}
    bytes_read = {disp for ins_id, disp in fields if ins_id == a.ARM_INS_LDRB}
    if not {0, 2, 4, 6} <= halfwords or not {8, 9} <= bytes_read:
        return None
    group_source = _copy_source(copy, group_table + group_row_size,
                                group_count * group_row_size,
                                len(image))
    if group_source is None or group_source + group_count * group_row_size > len(image):
        return None
    records = [struct.unpack_from("<4H2B", image,
        group_source + index * group_row_size) for index in range(group_count)]
    if (records[0][4:] != (1, 28) or records[1][4:] != (29, 29)
            or records[2][4:] != (timer_slot, timer_slot)
            or records[2][0] != mask or records[2][2] != mask):
        return None
    cfg = facts.function(CodeAddress(handler, "thumb"), budget=1024,
                         stop_at_initial_return=True)
    from .slot_controller_group_flow import _group_cfg_proof
    if not _group_cfg_proof(facts, cfg, code, init_pc, counter_slot,
            index_load, mul_pc, add_pc, row_reg, stride_reg, base_reg,
            group_table, group_row_size, group_count, footer):
        return None
    return {
        "group_row_size": group_row_size,
        "group_count": group_count,
        "timer_group": 3,
        "group_table": group_table,
        "group_table_source": group_source,
        "group_records": records,
        "source_sites": ((init_pc, 2), (mul_pc, 2), (add_pc, 2),
                         (footer[0], 2), (footer[1], 2),
                         (footer[2], 2), (footer[3], 2)),
    }


