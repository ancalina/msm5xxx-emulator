"""Closed ARM transfer-helper instruction grammars for startup copies."""
from __future__ import annotations

from capstone import arm as a

from .facts import CodeAddress


def _closed_arm_body(facts, entry, copied, count):
    function = facts.function(entry, budget=512)
    if (not function.complete or function.truncated or function.unresolved
            or function.calls or function.scope_escapes or not function.instructions
            or entry.isa != 'arm' or entry.address & 3):
        return None
    decoded = [(site, facts.decode(site)) for site in
               sorted(function.instructions, key=lambda item: item.address)]
    decoded = [(site, ins) for site, ins in decoded if ins is not None]
    if (len(decoded) != count or any(
            right.address != left.address + 4
            for (left, _), (right, _) in zip(decoded, decoded[1:]))
            or any(not copied.source <= site.address < copied.source + copied.mapped_size
                   for site, _ in decoded)):
        return None
    if any(instruction.id != a.ARM_INS_B
           and instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
           for _site, instruction in decoded):
        return None
    return function, decoded


def _registers(instruction):
    return tuple(op.reg for op in instruction.operands
                 if op.type == a.ARM_OP_REG)


def _multiple(instruction, operation, base, registers):
    names = ('ldm', 'ldmia') if operation == a.ARM_INS_LDM else ('stm', 'stmia')
    return (instruction.id == operation and instruction.writeback
            and instruction.mnemonic in names
            and len(instruction.operands) == len(registers) + 1
            and instruction.operands[0].type == a.ARM_OP_REG
            and instruction.operands[0].reg == base
            and _registers(instruction)[1:] == registers)


def _arithmetic(instruction, operation, register, immediate):
    return (instruction.id == operation and instruction.update_flags
            and len(instruction.operands) == 3
            and all(op.type == a.ARM_OP_REG for op in instruction.operands[:2])
            and instruction.operands[0].reg == register
            and instruction.operands[1].reg == register
            and instruction.operands[2].type == a.ARM_OP_IMM
            and instruction.operands[2].imm == immediate)


def _branch(function, decoded, index, condition, target_index):
    site, instruction = decoded[index]
    target = decoded[target_index][0]
    fallthrough = CodeAddress(site.address + instruction.size, 'arm',
                              site.phase, site.bank)
    successors = {right for left, right in function.control_edges if left == site}
    return (instruction.id == a.ARM_INS_B and instruction.cc == condition
            and len(instruction.operands) == 1
            and instruction.operands[0].type == a.ARM_OP_IMM
            and instruction.operands[0].imm == target.address
            and successors == {target, fallthrough})


def _expected_edges(decoded, sequential, branches):
    expected = {(decoded[i][0], decoded[i + 1][0]) for i in sequential}
    expected.update((decoded[index][0], decoded[target][0])
                    for index, target in branches)
    expected.update((decoded[index][0], decoded[index + 1][0])
                    for index, _target in branches)
    return expected


def arm_memcpy_body(facts, entry, copied):
    """Prove R0/R1/R2 memcpy semantics and every header/tail CFG edge."""
    closed = _closed_arm_body(facts, entry, copied, 21)
    if closed is None:
        return None
    function, decoded = closed
    ins = [instruction for _site, instruction in decoded]
    required = tuple(getattr(a, f'ARM_REG_R{i}') for i in range(12))
    nine = tuple(getattr(a, f'ARM_REG_R{i}') for i in range(3, 12))
    three = tuple(getattr(a, f'ARM_REG_R{i}') for i in range(3, 6))
    one = (a.ARM_REG_R4,)
    if (ins[0].id != a.ARM_INS_PUSH or _registers(ins[0]) != required
            or not _arithmetic(ins[1], a.ARM_INS_SUB, a.ARM_REG_R2, 36)
            or not _branch(function, decoded, 2, a.ARM_CC_MI, 7)
            or not _multiple(ins[3], a.ARM_INS_LDM, a.ARM_REG_R1, nine)
            or not _multiple(ins[4], a.ARM_INS_STM, a.ARM_REG_R0, nine)
            or not _arithmetic(ins[5], a.ARM_INS_SUB, a.ARM_REG_R2, 36)
            or not _branch(function, decoded, 6, a.ARM_CC_PL, 3)
            or not _arithmetic(ins[7], a.ARM_INS_ADD, a.ARM_REG_R2, 24)
            or not _branch(function, decoded, 8, a.ARM_CC_MI, 13)
            or not _multiple(ins[9], a.ARM_INS_LDM, a.ARM_REG_R1, three)
            or not _multiple(ins[10], a.ARM_INS_STM, a.ARM_REG_R0, three)
            or not _arithmetic(ins[11], a.ARM_INS_SUB, a.ARM_REG_R2, 12)
            or not _branch(function, decoded, 12, a.ARM_CC_PL, 9)
            or not _arithmetic(ins[13], a.ARM_INS_ADD, a.ARM_REG_R2, 12)
            or not _branch(function, decoded, 14, a.ARM_CC_EQ, 19)
            or not _multiple(ins[15], a.ARM_INS_LDM, a.ARM_REG_R1, one)
            or not _multiple(ins[16], a.ARM_INS_STM, a.ARM_REG_R0, one)
            or not _arithmetic(ins[17], a.ARM_INS_SUB, a.ARM_REG_R2, 4)
            or not _branch(function, decoded, 18, a.ARM_CC_NE, 15)
            or ins[19].id != a.ARM_INS_POP or _registers(ins[19]) != required
            or ins[20].id != a.ARM_INS_BX or _registers(ins[20]) != (a.ARM_REG_LR,)):
        return None
    edges = _expected_edges(
        decoded, (0, 1, 3, 4, 5, 7, 9, 10, 11, 13, 15, 16, 17, 19),
        ((2, 7), (6, 3), (8, 13), (12, 9), (14, 19), (18, 15)))
    if set(function.control_edges) != edges:
        return None
    evidence = tuple(sorted((site.address, instruction.size)
                            for site, instruction in decoded))
    return function, evidence


def arm_memset_body(facts, entry, copied):
    """Prove the reset path's R0/R1 zero-fill helper and all of its CFG."""
    closed = _closed_arm_body(facts, entry, copied, 28)
    if closed is None:
        return None
    function, decoded = closed
    ins = [instruction for _site, instruction in decoded]
    required = tuple(getattr(a, f'ARM_REG_R{i}') for i in range(12))
    zero_registers = tuple(getattr(a, f'ARM_REG_R{i}') for i in range(2, 12))
    middle = tuple(getattr(a, f'ARM_REG_R{i}') for i in range(2, 6))
    last = (a.ARM_REG_R2,)
    if ins[0].id != a.ARM_INS_PUSH or _registers(ins[0]) != required:
        return None
    for index, register in enumerate(zero_registers, 1):
        move = ins[index]
        if (move.id != a.ARM_INS_MOV or len(move.operands) != 2
                or move.operands[0].type != a.ARM_OP_REG
                or move.operands[0].reg != register
                or move.operands[1].type != a.ARM_OP_IMM
                or move.operands[1].imm != 0):
            return None
    if (not _arithmetic(ins[11], a.ARM_INS_SUB, a.ARM_REG_R1, 40)
            or not _branch(function, decoded, 12, a.ARM_CC_MI, 16)
            or not _multiple(ins[13], a.ARM_INS_STM, a.ARM_REG_R0, zero_registers)
            or not _arithmetic(ins[14], a.ARM_INS_SUB, a.ARM_REG_R1, 40)
            or not _branch(function, decoded, 15, a.ARM_CC_PL, 13)
            or not _arithmetic(ins[16], a.ARM_INS_ADD, a.ARM_REG_R1, 24)
            or not _branch(function, decoded, 17, a.ARM_CC_MI, 21)
            or not _multiple(ins[18], a.ARM_INS_STM, a.ARM_REG_R0, middle)
            or not _arithmetic(ins[19], a.ARM_INS_SUB, a.ARM_REG_R1, 16)
            or not _branch(function, decoded, 20, a.ARM_CC_PL, 18)
            or not _arithmetic(ins[21], a.ARM_INS_ADD, a.ARM_REG_R1, 16)
            or not _branch(function, decoded, 22, a.ARM_CC_EQ, 26)
            or not _multiple(ins[23], a.ARM_INS_STM, a.ARM_REG_R0, last)
            or not _arithmetic(ins[24], a.ARM_INS_SUB, a.ARM_REG_R1, 4)
            or not _branch(function, decoded, 25, a.ARM_CC_NE, 23)
            or ins[26].id != a.ARM_INS_POP or _registers(ins[26]) != required
            or ins[27].id != a.ARM_INS_BX or _registers(ins[27]) != (a.ARM_REG_LR,)):
        return None
    edges = _expected_edges(
        decoded, (0, *range(1, 12), 13, 14, 16, 18, 19, 21, 23, 24, 26),
        ((12, 16), (15, 13), (17, 21), (20, 18), (22, 26), (25, 23)))
    if set(function.control_edges) != edges:
        return None
    evidence = tuple(sorted((site.address, instruction.size)
                            for site, instruction in decoded))
    return function, evidence
