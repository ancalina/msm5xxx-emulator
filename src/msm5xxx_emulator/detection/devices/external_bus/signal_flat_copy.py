"""Source proof for the halfword copy wrapper used by flat upload parsers."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.values import SymbolicValue


def _zero_move(ins, destination, source):
    return (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == destination
            and ins.operands[1].type == a.ARM_OP_REG
            and ins.operands[1].reg == source
            and ins.operands[2].type == a.ARM_OP_IMM
            and ins.operands[2].imm == 0)


def _reversed_halfword_copy(facts, wrapper_body):
    """Prove a source/destination-swapping wrapper and its counted loop."""
    if len(wrapper_body.call_sites) != 1:
        return None
    call = wrapper_body.call_sites[0]
    registers = dict(call.registers)
    if (registers.get(a.ARM_REG_R0) != SymbolicValue.arg(1)
            or registers.get(a.ARM_REG_R1) != SymbolicValue.arg(0)
            or registers.get(a.ARM_REG_R2) != SymbolicValue.arg(2)
            or registers.get(a.ARM_REG_R3) != 0):
        return None
    leaf = facts.function(call.target, budget=512)
    if not leaf.complete or leaf.unresolved or leaf.truncated:
        return None
    instructions = {pc.address: facts.decode(pc) for pc in leaf.instructions}
    source_regs = {ins.operands[0].reg for ins in instructions.values()
                   if ins is not None and _zero_move(ins, ins.operands[0].reg,
                                                     a.ARM_REG_R1)}
    destination_regs = {ins.operands[0].reg for ins in instructions.values()
                        if ins is not None and _zero_move(ins, ins.operands[0].reg,
                                                          a.ARM_REG_R0)}
    count_regs = {ins.operands[0].reg for ins in instructions.values()
                  if ins is not None and _zero_move(ins, ins.operands[0].reg,
                                                    a.ARM_REG_R2)}
    mode_regs = {ins.operands[0].reg for ins in instructions.values()
                 if ins is not None and _zero_move(ins, ins.operands[0].reg,
                                                   a.ARM_REG_R3)}
    if any(len(group) != 1 for group in
           (source_regs, destination_regs, count_regs, mode_regs)):
        return None
    source_reg = next(iter(source_regs))
    destination_reg = next(iter(destination_regs))
    count_reg = next(iter(count_regs))
    mode_reg = next(iter(mode_regs))
    for branch_at, target_at in leaf.back_edges:
        branch = instructions.get(branch_at)
        if (branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_NE):
            continue
        loop = [ins for address, ins in instructions.items()
                if target_at <= address <= branch_at and ins is not None]
        loads = [ins for ins in loop if ins.id == a.ARM_INS_LDRH
                 and len(ins.operands) == 2
                 and ins.operands[1].type == a.ARM_OP_MEM
                 and ins.operands[1].mem.base == source_reg
                 and not ins.operands[1].mem.index
                 and ins.operands[1].mem.disp == 0]
        stores = [ins for ins in loop if ins.id == a.ARM_INS_STRH
                  and len(ins.operands) == 2
                  and ins.operands[1].type == a.ARM_OP_MEM
                  and ins.operands[1].mem.base == destination_reg
                  and not ins.operands[1].mem.index
                  and ins.operands[1].mem.disp == 0]
        if (len(loads) != 1 or len(stores) != 1
                or loads[0].operands[0].reg != stores[0].operands[0].reg):
            continue
        load_pc = CodeAddress(loads[0].address, leaf.entry.isa,
                              leaf.entry.phase, leaf.entry.bank)
        store_pc = CodeAddress(stores[0].address, leaf.entry.isa,
                               leaf.entry.phase, leaf.entry.bank)
        if (not leaf.dominates(load_pc, store_pc)
                or leaf.linear_path(load_pc, store_pc) is None
                or facts.register_origins(leaf, store_pc,
                    stores[0].operands[0].reg) != ((load_pc,
                    loads[0].operands[0].reg),)):
            continue
        decrements = [ins for ins in loop if ins.id == a.ARM_INS_SUB
                      and len(ins.operands) == 2
                      and ins.operands[0].type == a.ARM_OP_REG
                      and ins.operands[0].reg == a.ARM_REG_R0
                      and ins.operands[1].type == a.ARM_OP_IMM
                      and ins.operands[1].imm == 1
                      and ins.update_flags
                      and ins.address + ins.size == branch_at]
        steps = {}
        for ins in loop:
            if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 2
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[1].type == a.ARM_OP_IMM
                    and ins.operands[1].imm == 2):
                steps[ins.operands[0].reg] = steps.get(
                    ins.operands[0].reg, 0) + 1
            elif (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                  and ins.operands[0].type == a.ARM_OP_REG
                  and ins.operands[1].type == a.ARM_OP_REG
                  and ins.operands[0].reg == ins.operands[1].reg
                  and ins.operands[2].type == a.ARM_OP_IMM
                  and ins.operands[2].imm == 2):
                steps[ins.operands[0].reg] = steps.get(
                    ins.operands[0].reg, 0) + 1
        if (not decrements or any(steps.get(reg) != 1 for reg in
                                  (source_reg, destination_reg))):
            continue
        counter_reg = decrements[0].operands[0].reg
        seeded = [ins for ins in instructions.values() if ins is not None
                  and ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                  and ins.operands[0].type == a.ARM_OP_REG
                  and ins.operands[0].reg == counter_reg
                  and ins.operands[1].type == a.ARM_OP_REG
                  and ins.operands[1].reg == count_reg
                  and ins.operands[2].type == a.ARM_OP_IMM
                  and ins.operands[2].imm == 1
                  and ins.address < target_at]
        if len(seeded) != 1:
            continue
        zero_entry = [ins for ins in instructions.values()
                      if ins is not None and ins.id == a.ARM_INS_B
                      and ins.cc == a.ARM_CC_EQ
                      and ins.operands and ins.operands[0].type == a.ARM_OP_IMM
                      and ins.operands[0].imm == decrements[0].address]
        if len(zero_entry) != 1 or not any(any(cmp.id == a.ARM_INS_CMP
                       and len(cmp.operands) == 2
                       and cmp.operands[0].type == a.ARM_OP_REG
                       and cmp.operands[0].reg == mode_reg
                       and cmp.operands[1].type == a.ARM_OP_IMM
                       and cmp.operands[1].imm == 0
                       and cmp.address + cmp.size == _ins.address
                       for cmp in instructions.values() if cmp is not None)
                   for _ins in zero_entry):
            continue
        return {'unit': 2, 'leaf': leaf}
    return None


