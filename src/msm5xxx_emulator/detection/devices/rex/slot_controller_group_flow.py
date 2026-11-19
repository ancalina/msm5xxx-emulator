"""Reaching-definition checks for grouped timer table traversal."""
from .slot_controller_flow import one_definition, unconditional_sites
from msm5xxx_emulator.detection.facts import CodeAddress

def _group_cfg_proof(facts, flow, code, init_pc, counter_slot, index_load,
                     multiply, addition, row_reg, stride_reg, base_reg,
                     group_table, row_size, group_count, footer):
    from capstone import arm as a
    if not flow.complete or flow.truncated or flow.unresolved:
        return False
    site = lambda pc: CodeAddress(pc, "thumb")
    required = (init_pc, index_load, multiply, addition, *footer)
    if any(site(pc) not in flow.instructions for pc in required):
        return False
    def definition(pc, register):
        return one_definition(facts.reaching_definitions(
            flow, site(pc), register, include_entry=True))
    move = facts.decode(site(init_pc))
    if (move is None or len(move.operands) != 2
            or move.operands[0].type != a.ARM_OP_REG
            or move.operands[1].type != a.ARM_OP_IMM
            or move.operands[1].imm != 1):
        return False
    index_reg = next((operand.reg for operand in facts.decode(site(multiply)).operands[1:]
                      if operand.type == a.ARM_OP_REG and operand.reg != stride_reg), None)
    if index_reg is None:
        return False
    initial_stores = [(pc, ins) for pc, ins in code if init_pc < pc < index_load
        and ins.id == a.ARM_INS_STR and len(ins.operands) == 2
        and ins.operands[0].type == a.ARM_OP_REG
        and ins.operands[0].reg == move.operands[0].reg
        and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.base == a.ARM_REG_SP
        and ins.operands[1].mem.disp == counter_slot]
    if len(initial_stores) != 1:
        return False
    init_store, init_store_ins = initial_stores[0]
    mul_ins, add_ins = facts.decode(site(multiply)), facts.decode(site(addition))
    index_ins = facts.decode(site(index_load))
    stride_def = definition(multiply, stride_reg)
    index_def = definition(multiply, index_reg)
    base_def = definition(addition, base_reg)
    if (index_ins is None or index_ins.id != a.ARM_INS_LDR
            or len(index_ins.operands) != 2
            or index_ins.operands[1].type != a.ARM_OP_MEM
            or index_ins.operands[1].mem.base != a.ARM_REG_SP
            or index_ins.operands[1].mem.disp != counter_slot
            or index_def != site(index_load)
            or definition(init_store, move.operands[0].reg) != site(init_pc)
            or not flow.dominates(site(init_store), site(index_load))
            or not flow.dominates(site(index_load), site(multiply))):
        return False
    stride_ins = facts.decode(stride_def) if stride_def is not None else None
    base_ins = facts.decode(base_def) if base_def is not None else None
    if (stride_ins is None or stride_ins.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            or len(stride_ins.operands) != 2
            or stride_ins.operands[1].type != a.ARM_OP_IMM
            or stride_ins.operands[1].imm != row_size
            or base_ins is None or base_ins.id != a.ARM_INS_LDR
            or not any(lit.instruction == base_def and lit.value == group_table
                       for lit in flow.literals)
            or mul_ins is None or mul_ins.id != a.ARM_INS_MUL
            or len(mul_ins.operands) != 3
            or {index_reg, stride_reg} - {op.reg for op in mul_ins.operands
                                           if op.type == a.ARM_OP_REG}
            or add_ins is None or add_ins.id != a.ARM_INS_ADD
            or len(add_ins.operands) != 3
            or add_ins.operands[0].reg != row_reg
            or {mul_ins.operands[0].reg, base_reg} != {op.reg for op in add_ins.operands[1:]
                                                        if op.type == a.ARM_OP_REG}
            or not flow.dominates(site(multiply), site(addition))):
        return False
    row_stores = [(pc, ins) for pc, ins in code if addition < pc < footer[3]
        and site(pc) in flow.instructions
        and ins.id == a.ARM_INS_STR and len(ins.operands) == 2
        and ins.operands[0].type == a.ARM_OP_REG and ins.operands[0].reg == row_reg
        and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.base == a.ARM_REG_SP
        and ins.operands[1].mem.disp == 0]
    if len(row_stores) != 1 or definition(row_stores[0][0], row_reg) != site(addition):
        return False
    pointer_store = row_stores[0][0]
    fields = [(pc, ins) for pc, ins in code if addition < pc < footer[3]
        and site(pc) in flow.instructions
        and ins.id in (a.ARM_INS_LDRH, a.ARM_INS_LDRB)
        and len(ins.operands) == 2 and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.disp in (0, 2, 4, 6, 8, 9)]
    needed = {0: a.ARM_INS_LDRH, 2: a.ARM_INS_LDRH, 4: a.ARM_INS_LDRH,
              6: a.ARM_INS_LDRH, 8: a.ARM_INS_LDRB, 9: a.ARM_INS_LDRB}
    owned_fields = set()
    owned_sites = set()
    for pc, ins in fields:
        disp = ins.operands[1].mem.disp
        if ins.id != needed[disp]:
            continue
        base_reg = ins.operands[1].mem.base
        pointer_def = definition(pc, base_reg)
        if pointer_def is None:
            continue
        if pointer_def == site(addition):
            owned_fields.add((ins.id, disp))
            owned_sites.add(pc)
            continue
        source = facts.decode(pointer_def)
        if (source is None or source.id != a.ARM_INS_LDR
                or len(source.operands) != 2
                or source.operands[1].type != a.ARM_OP_MEM
                or source.operands[1].mem.base != a.ARM_REG_SP
                or source.operands[1].mem.disp != 0
                or not flow.dominates(site(pointer_store), pointer_def)):
            continue
        if any(other.id == a.ARM_INS_STR and len(other.operands) == 2
               and other.operands[1].type == a.ARM_OP_MEM
               and other.operands[1].mem.base == a.ARM_REG_SP
               and other.operands[1].mem.disp == 0
               and pointer_store < other_pc < pc
               for other_pc, other in code):
            continue
        owned_fields.add((ins.id, disp))
        owned_sites.add(pc)
    if any((kind, offset) not in owned_fields
           for offset, kind in needed.items()):
        return False
    pointer_stores = [pc for pc, ins in code
        if site(pc) in flow.instructions and ins.id == a.ARM_INS_STR
        and len(ins.operands) == 2
        and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.base == a.ARM_REG_SP
        and ins.operands[1].mem.disp == 0]
    if pointer_stores != [pointer_store]:
        return False
    update_pc, compare_pc, branch_pc, backedge_pc = footer
    update = facts.decode(site(update_pc))
    compare = facts.decode(site(compare_pc))
    branch = facts.decode(site(branch_pc))
    backedge = facts.decode(site(backedge_pc))
    if any(ins is None for ins in (update, compare, branch, backedge)):
        return False
    counter_reg = update.operands[0].reg
    footer_load = definition(update_pc, counter_reg)
    footer_store = next(((pc, ins) for pc, ins in code
        if update_pc < pc < compare_pc and ins.id == a.ARM_INS_STR
        and len(ins.operands) == 2 and ins.operands[0].reg == counter_reg
        and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.base == a.ARM_REG_SP
        and ins.operands[1].mem.disp == counter_slot), None)
    counter_stores = [pc for pc, ins in code
        if ins.id == a.ARM_INS_STR and len(ins.operands) == 2
        and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.base == a.ARM_REG_SP
        and ins.operands[1].mem.disp == counter_slot]
    store_source = (definition(footer_store[0], counter_reg)
                    if footer_store is not None else None)
    normalized_update = False
    if store_source is not None and store_source != site(update_pc):
        shift_right = facts.decode(store_source)
        shift_left_site = definition(store_source.address, counter_reg)
        shift_left = facts.decode(shift_left_site) if shift_left_site else None
        add_site = definition(shift_left_site.address, counter_reg) if shift_left_site else None
        if add_site is not None:
            add_source = facts.decode(add_site)
            normalized_update = (
                shift_right is not None and shift_right.id == a.ARM_INS_LSR
                and len(shift_right.operands) == 3
                and shift_right.operands[2].type == a.ARM_OP_IMM
                and shift_right.operands[2].imm == 16
                and shift_left is not None and shift_left.id == a.ARM_INS_LSL
                and len(shift_left.operands) == 3
                and shift_left.operands[2].type == a.ARM_OP_IMM
                and shift_left.operands[2].imm == 16
                and add_site == site(update_pc)
                and add_source is not None and add_source.id == a.ARM_INS_ADD)
    if update.id == a.ARM_INS_ADD and len(update.operands) == 3:
        update_source = (update.operands[1].reg
                         if update.operands[1].type == a.ARM_OP_REG else None)
        update_amount = update.operands[2]
    elif update.id == a.ARM_INS_ADD and len(update.operands) == 2:
        update_source = update.operands[0].reg
        update_amount = update.operands[1]
    else:
        update_source, update_amount = None, None
    if (update.id != a.ARM_INS_ADD or update_source != counter_reg
            or update_amount is None or update_amount.type != a.ARM_OP_IMM
            or update_amount.imm != 1 or footer_load is None
            or facts.decode(footer_load).id != a.ARM_INS_LDR
            or facts.decode(footer_load).operands[0].reg != counter_reg
            or facts.decode(footer_load).operands[1].mem.base != a.ARM_REG_SP
            or facts.decode(footer_load).operands[1].mem.disp != counter_slot
            or footer_store is None
            or set(counter_stores) != {init_store, footer_store[0]}
            or not (store_source == site(update_pc) or normalized_update)
            or compare.id != a.ARM_INS_CMP or compare.operands[0].reg != counter_reg
            or compare.operands[1].type != a.ARM_OP_IMM
            or compare.operands[1].imm != group_count + 1
            or branch.id != a.ARM_INS_B or branch.cc not in (a.ARM_CC_GE, a.ARM_CC_HS)
            or not flow.dominates(site(pointer_store), site(backedge_pc))
            or not flow.dominates(site(init_store), site(index_load))
            or not flow.dominates(site(index_load), site(multiply))
            or not flow.dominates(site(multiply), site(addition))
            or not flow.dominates(site(addition), site(pointer_store))
            or not flow.dominates(site(update_pc), site(compare_pc))
            or not flow.dominates(site(compare_pc), site(branch_pc))
            or not flow.dominates(site(footer_store[0]), site(backedge_pc))
            or backedge.id != a.ARM_INS_B or not backedge.operands
            or backedge.operands[0].imm != index_load
            or not branch.operands
            or branch_pc + branch.size != backedge_pc
            or branch.operands[0].imm != backedge_pc + backedge.size
            or (site(branch_pc), site(backedge_pc)) not in flow.control_edges
            or (site(branch_pc), site(branch.operands[0].imm)) not in flow.control_edges):
        return False
    unconditional = (init_pc, init_store, index_load, multiply, addition,
        stride_def.address, base_def.address, pointer_store,
        *owned_sites, footer_load.address, update_pc, footer_store[0],
        compare_pc, backedge_pc)
    if not unconditional_sites(facts, flow, unconditional):
        return False
    if facts.reaching_definitions(flow, site(branch_pc), a.ARM_REG_CPSR,
                                  include_entry=True) != (site(compare_pc),):
        return False
    frame = facts.stack_frame(flow)
    if frame is None or not frame.complete or not frame.balanced:
        return False
    return True
