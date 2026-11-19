"""Source argument and stack proof for a bounded Thumb copy wrapper."""
from __future__ import annotations

from dataclasses import dataclass

from capstone import arm as a

from .facts import CodeAddress, facts_for


@dataclass(frozen=True)
class WrappedCopyCall:
    target: CodeAddress
    callsite: CodeAddress
    stack_pointer: int
    frame_bytes: int
    effects: tuple[tuple[int, int], ...]
    evidence: tuple[tuple[int, int], ...]
    required_preserved_registers: tuple[int, ...]


def _condition(cc, flags):
    if cc in (a.ARM_CC_AL, a.ARM_CC_INVALID):
        return True
    if flags is None:
        return None
    needed = {a.ARM_CC_EQ: (1,), a.ARM_CC_NE: (1,),
              a.ARM_CC_HS: (2,), a.ARM_CC_LO: (2,),
              a.ARM_CC_HI: (1, 2), a.ARM_CC_LS: (1, 2),
              a.ARM_CC_MI: (0,), a.ARM_CC_PL: (0,),
              a.ARM_CC_GE: (0, 3), a.ARM_CC_LT: (0, 3),
              a.ARM_CC_GT: (0, 1, 3), a.ARM_CC_LE: (0, 1, 3)}.get(cc)
    if needed is None or any(flags[index] is None for index in needed):
        return None
    n, z, c, v = flags
    return {a.ARM_CC_EQ: z, a.ARM_CC_NE: not z,
            a.ARM_CC_HS: c, a.ARM_CC_LO: not c,
            a.ARM_CC_HI: c and not z, a.ARM_CC_LS: not c or z,
            a.ARM_CC_MI: n, a.ARM_CC_PL: not n,
            a.ARM_CC_GE: n == v, a.ARM_CC_LT: n != v,
            a.ARM_CC_GT: not z and n == v,
            a.ARM_CC_LE: z or n != v}.get(cc)


def _arithmetic(left, right, subtract):
    raw = left - right if subtract else left + right
    result = raw & 0xffffffff
    carry = left >= right if subtract else raw > 0xffffffff
    overflow = bool(((left ^ right) if subtract else ~(left ^ right))
                    & (left ^ result) & 0x80000000)
    return result, (bool(result & 0x80000000), result == 0, carry, overflow)


def _register_order(register):
    if a.ARM_REG_R0 <= register <= a.ARM_REG_R12:
        return register - a.ARM_REG_R0
    return {a.ARM_REG_SP: 13, a.ARM_REG_LR: 14, a.ARM_REG_PC: 15}.get(register, 99)


def copy_wrapper_call(image: bytes, entry: int, destination: int, source: int,
                      size: int, *, stack_pointer: int) -> WrappedCopyCall | None:
    """Prove forwarding on the actual, word-aligned, at-most-1MiB path.

    The leaf call is an explicit obligation: its source proof must establish
    copying, SP preservation, and preservation of the returned register set.
    This function alone never admits or installs a device or memory mapping.
    """
    if (type(image) is not bytes or any(type(value) is not int for value in
            (entry, destination, source, size, stack_pointer)) or entry & 1
            or not 0 <= entry <= len(image) - 2 or not 0 < size <= 0x100000
            or any(value & 3 for value in (source, destination, size, stack_pointer))
            or not 0 < stack_pointer <= 0xffffffff
            or not 0 <= source <= len(image) - size
            or not 0 <= destination <= 0x100000000 - size):
        return None
    facts = facts_for(image)
    preserved = tuple(range(a.ARM_REG_R4, a.ARM_REG_R11 + 1))
    original = {reg: ("entry-register", reg)
                for reg in range(a.ARM_REG_R0, a.ARM_REG_R12 + 1)}
    original[a.ARM_REG_LR] = ("entry-link",)
    registers = dict(original)
    registers.update({a.ARM_REG_R0: destination, a.ARM_REG_R1: source,
                      a.ARM_REG_R2: size, a.ARM_REG_SP: stack_pointer})
    memory, evidence, effects = {}, set(), set()
    flags, call = None, None
    pc, lowest = entry, stack_pointer

    def value(operand):
        if operand.shift.type or operand.subtracted:
            return None
        if operand.type == a.ARM_OP_IMM:
            return operand.imm
        if operand.type == a.ARM_OP_REG:
            return registers.get(operand.reg)
        return None

    def address(operand):
        if (operand.type != a.ARM_OP_MEM or operand.mem.index
                or operand.subtracted or operand.shift.type):
            return None
        base = (((pc + 4) & ~3) if operand.mem.base == a.ARM_REG_PC
                else registers.get(operand.mem.base))
        return base + operand.mem.disp if type(base) is int else None

    for _step in range(1024):
        if not entry <= pc < min(entry + 512, len(image) - 1):
            return None
        site = CodeAddress(pc, "thumb")
        ins = facts.decode(site)
        if (ins is None or ins.size not in (2, 4)
                or ins.size == 4 and ins.id != a.ARM_INS_BL
                or ins.id == a.ARM_INS_IT):
            return None
        evidence.add((pc, ins.size))
        operands = ins.operands
        next_pc = pc + ins.size
        try:
            _, written = ins.regs_access()
        except Exception:
            return None
        if (a.ARM_REG_PC in written
                and ins.id not in (a.ARM_INS_B, a.ARM_INS_BL, a.ARM_INS_BX)):
            return None
        if ins.id == a.ARM_INS_B:
            take = _condition(ins.cc, flags)
            if take is None or len(operands) != 1 or operands[0].type != a.ARM_OP_IMM:
                return None
            pc = operands[0].imm if take else next_pc
            continue
        if ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
            return None
        if ins.id in (a.ARM_INS_PUSH, a.ARM_INS_POP):
            regs = [op.reg for op in operands if op.type == a.ARM_OP_REG]
            if len(regs) != len(operands) or len(set(regs)) != len(regs):
                return None
            regs.sort(key=_register_order)
            sp = registers.get(a.ARM_REG_SP)
            if type(sp) is not int or sp & 3 or a.ARM_REG_SP in regs or a.ARM_REG_PC in regs:
                return None
            if ins.id == a.ARM_INS_PUSH:
                sp -= len(regs) * 4
                if sp < stack_pointer - 256 or sp < 0 or sp >= stack_pointer:
                    return None
                if any(start < stack_pointer and sp < start + size
                       for start in (destination, source)):
                    return None
                for index, reg in enumerate(regs):
                    memory[sp + index * 4] = registers.get(reg)
                lowest = min(lowest, sp)
            else:
                if any(sp + index * 4 not in memory for index in range(len(regs))):
                    return None
                for index, reg in enumerate(regs):
                    registers[reg] = memory[sp + index * 4]
                sp += len(regs) * 4
                if sp > stack_pointer:
                    return None
            registers[a.ARM_REG_SP] = sp
        elif ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS):
            if len(operands) != 2 or operands[0].type != a.ARM_OP_REG:
                return None
            result = value(operands[1])
            if result is None:
                return None
            registers[operands[0].reg] = result
            if ins.update_flags:
                if type(result) is not int:
                    return None
                flags = (bool(result & 0x80000000), result == 0,
                         flags[2] if flags else None, flags[3] if flags else None)
        elif ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB, a.ARM_INS_CMP):
            compare = ins.id == a.ARM_INS_CMP
            if compare and len(operands) == 2:
                left, right = value(operands[0]), value(operands[1])
            elif not compare and len(operands) in (2, 3) and operands[0].type == a.ARM_OP_REG:
                left, right = (value(operands[0]), value(operands[1])) if len(operands) == 2 else (value(operands[1]), value(operands[2]))
            else:
                return None
            if type(left) is not int or type(right) is not int:
                return None
            result, updated = _arithmetic(left, right, compare or ins.id == a.ARM_INS_SUB)
            if not compare:
                registers[operands[0].reg] = result
            if compare or ins.update_flags:
                flags = updated
        elif ins.id == a.ARM_INS_LSL:
            if (len(operands) != 3 or operands[0].type != a.ARM_OP_REG
                    or type(value(operands[1])) is not int
                    or operands[2].type != a.ARM_OP_IMM or not 0 < operands[2].imm < 32):
                return None
            before, shift = value(operands[1]), operands[2].imm
            result = before << shift & 0xffffffff
            registers[operands[0].reg] = result
            if ins.update_flags:
                flags = (bool(result & 0x80000000), result == 0,
                         bool(before & 1 << (32 - shift)), flags[3] if flags else None)
        elif ins.id == a.ARM_INS_LDR:
            if len(operands) != 2 or operands[0].type != a.ARM_OP_REG or ins.writeback:
                return None
            location = address(operands[1])
            if location is None or location & 3:
                return None
            if operands[1].mem.base == a.ARM_REG_PC:
                literal = facts.literal(site)
                if literal is None or literal.pool != location or not 0 <= location <= len(image) - 4:
                    return None
                loaded = literal.value
                evidence.add((location, 4))
            else:
                loaded = memory.get(location)
            if loaded is None:
                return None
            registers[operands[0].reg] = loaded
        elif ins.id in (a.ARM_INS_STR, a.ARM_INS_STRB):
            if len(operands) != 2 or ins.writeback:
                return None
            location, stored = address(operands[1]), value(operands[0])
            if location is None or stored is None:
                return None
            if ins.id == a.ARM_INS_STR and location in memory and not location & 3:
                memory[location] = stored
            elif (ins.id == a.ARM_INS_STRB and type(stored) is int
                    and 0x03000000 <= location < 0x03001000):
                effects.add((location, 1))
            else:
                return None
        elif ins.id == a.ARM_INS_LDM:
            if (len(operands) < 2 or any(op.type != a.ARM_OP_REG for op in operands)
                    or ins.writeback or ins.mnemonic not in ("ldm", "ldmia")):
                return None
            base = registers.get(operands[0].reg)
            regs = [op.reg for op in operands[1:]]
            if type(base) is not int or base & 3 or regs != sorted(regs, key=_register_order):
                return None
            loaded = [memory.get(base + index * 4) for index in range(len(regs))]
            if any(item is None for item in loaded):
                return None
            registers.update(zip(regs, loaded))
        elif ins.id == a.ARM_INS_BL:
            target = facts.thumb_call_target(pc)
            actual = tuple(registers.get(reg) for reg in (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2))
            if (call is not None or target is None or target & 1 or not 0 <= target < len(image) - 1
                    or actual != (destination, source, size)
                    or type(registers[a.ARM_REG_SP]) is not int
                    or not lowest <= registers[a.ARM_REG_SP] <= stack_pointer):
                return None
            call = (CodeAddress(target, "thumb"), site, registers[a.ARM_REG_SP])
            for reg in (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3, a.ARM_REG_R12):
                registers[reg] = ("leaf-output", reg)
            registers[a.ARM_REG_LR] = next_pc | 1
            flags = None
        elif ins.id == a.ARM_INS_BX:
            if (len(operands) != 1 or value(operands[0]) != original[a.ARM_REG_LR]
                    or registers[a.ARM_REG_SP] != stack_pointer or call is None
                    or any(registers.get(reg) != original[reg] for reg in preserved)):
                return None
            return WrappedCopyCall(call[0], call[1], call[2], stack_pointer - lowest,
                                   tuple(sorted(effects)), tuple(sorted(evidence)), preserved)
        else:
            return None
        pc = next_pc
    return None
