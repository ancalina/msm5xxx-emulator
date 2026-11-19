"""Instruction and register-flow predicates for paired keypad scans."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress


def _thumb_insn(facts, pc):
    return facts.decode(CodeAddress(pc))


def _preserved_register(image, start, end, register, facts):
    pc = start
    while pc < end:
        ins = _thumb_insn(facts, pc)
        if ins is None or ins.size not in (2, 4) or pc + ins.size > end:
            return False
        try:
            _, written = ins.regs_access()
        except Exception:
            return False
        if register in written and ins.id != a.ARM_INS_POP:
            return False
        pc += ins.size
    return True


def _is_mov_imm(ins, register, value):
    return (ins is not None and ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            and len(ins.operands) == 2
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == register
            and ins.operands[1].type == a.ARM_OP_IMM
            and ins.operands[1].imm == value)


def _is_add_imm(ins, register, value):
    if ins is None or ins.id != a.ARM_INS_ADD:
        return False
    return ((len(ins.operands) == 2
             and ins.operands[0].type == a.ARM_OP_REG
             and ins.operands[0].reg == register
             and ins.operands[1].type == a.ARM_OP_IMM
             and ins.operands[1].imm == value)
            or (len(ins.operands) == 3
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == register
                and ins.operands[1].type == a.ARM_OP_REG
                and ins.operands[1].reg == register
                and ins.operands[2].type == a.ARM_OP_IMM
                and ins.operands[2].imm == value))


def _is_cmp_imm(ins, register, value):
    return (ins is not None and ins.id == a.ARM_INS_CMP
            and len(ins.operands) == 2
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == register
            and ins.operands[1].type == a.ARM_OP_IMM
            and ins.operands[1].imm == value)


def _is_shift_imm(ins, instruction, register, amount):
    return (ins is not None and ins.id == instruction
            and len(ins.operands) == 3
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == register
            and ins.operands[1].type == a.ARM_OP_REG
            and ins.operands[1].reg == register
            and ins.operands[2].type == a.ARM_OP_IMM
            and ins.operands[2].imm == amount)


def _branch_to(facts, pc, condition, target):
    ins = _thumb_insn(facts, pc)
    return (ins is not None and ins.id == a.ARM_INS_B and ins.cc == condition
            and ins.operands and ins.operands[0].type == a.ARM_OP_IMM
            and ins.operands[0].imm == target)
