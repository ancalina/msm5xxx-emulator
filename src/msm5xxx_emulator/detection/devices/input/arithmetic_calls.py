"""Small, source-backed proofs for integer arithmetic helper calls."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for

_MASK = 0xFFFFFFFF
_SCRATCH = frozenset((a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2,
                      a.ARM_REG_R3, a.ARM_REG_R12))


def _condition(cc, flags):
    if cc in (a.ARM_CC_AL, a.ARM_CC_INVALID):
        return True
    n, z, c, v = flags
    checks = {
        a.ARM_CC_EQ: ((z,), lambda: z == 1), a.ARM_CC_NE: ((z,), lambda: z == 0),
        a.ARM_CC_HS: ((c,), lambda: c == 1), a.ARM_CC_LO: ((c,), lambda: c == 0),
        a.ARM_CC_MI: ((n,), lambda: n == 1), a.ARM_CC_PL: ((n,), lambda: n == 0),
        a.ARM_CC_VS: ((v,), lambda: v == 1), a.ARM_CC_VC: ((v,), lambda: v == 0),
        a.ARM_CC_HI: ((c, z), lambda: c == 1 and z == 0),
        a.ARM_CC_LS: ((c, z), lambda: c == 0 or z == 1),
        a.ARM_CC_GE: ((n, v), lambda: n == v), a.ARM_CC_LT: ((n, v), lambda: n != v),
        a.ARM_CC_GT: ((n, z, v), lambda: z == 0 and n == v),
        a.ARM_CC_LE: ((n, z, v), lambda: z == 1 or n != v),
    }
    entry = checks.get(cc)
    if entry is None:
        return None
    required, check = entry
    return check() if all(type(flag) is int for flag in required) else None


def _nz(value):
    value &= _MASK
    return (value >> 31, int(value == 0))


def _add_flags(left, right, carry, result):
    result &= _MASK
    n, z = _nz(result)
    c = int(left + right + carry > _MASK)
    v = int((~(left ^ right) & (left ^ result) & 0x80000000) != 0)
    return n, z, c, v


def _sub_flags(left, right, result):
    result &= _MASK
    n, z = _nz(result)
    c = int(left >= right)
    v = int(((left ^ right) & (left ^ result) & 0x80000000) != 0)
    return n, z, c, v


def _sets_flags(ins):
    # Capstone 5 reports update_flags for ARM ADC even when its encoding has
    # S=0. The explicit S mnemonic captures flag-setting variants instead.
    return ins.mnemonic.startswith(("movs", "subs", "rsbs", "adcs",
                                    "lsls", "lsrs", "asrs", "rors"))


def _shift(value, kind, amount, carry):
    value &= _MASK
    if amount < 0 or amount > 32:
        return None
    if kind == a.ARM_SFT_INVALID:
        return value, carry
    if kind == a.ARM_SFT_RRX or (kind == a.ARM_SFT_ROR and amount == 0):
        # ARM's immediate ROR #0 encoding means RRX: C enters bit 31 and
        # bit 0 becomes the shifter carry. An unknown input C cannot be guessed.
        if type(carry) is not int:
            return None
        return ((carry << 31) | (value >> 1)), value & 1
    if amount == 0:
        return value, carry
    if kind == a.ARM_SFT_LSL:
        if amount == 32:
            return 0, value & 1
        if amount > 32:
            return 0, 0
        return (value << amount) & _MASK, (value >> (32 - amount)) & 1
    if kind == a.ARM_SFT_LSR:
        if amount == 32:
            return 0, value >> 31
        return value >> amount, (value >> (amount - 1)) & 1
    if kind == a.ARM_SFT_ASR:
        signed = value - (1 << 32) if value & 0x80000000 else value
        if amount == 32:
            return (_MASK if signed < 0 else 0), value >> 31
        return (signed >> amount) & _MASK, (value >> (amount - 1)) & 1
    if kind == a.ARM_SFT_ROR:
        rotation = amount % 32
        result = value if rotation == 0 else ((value >> rotation) | (value << (32 - rotation))) & _MASK
        return result, (result >> 31)
    return None


def _read_operand(op, regs, pc, flags):
    if op.type == a.ARM_OP_IMM:
        value = op.imm & _MASK
    elif op.type == a.ARM_OP_REG and op.reg in regs:
        value = regs[op.reg]
    else:
        return None
    shift = op.shift
    if shift.type == a.ARM_SFT_INVALID:
        return value, flags[2]
    if shift.value < 0:
        return None
    shifted = _shift(value, shift.type, shift.value, flags[2])
    return shifted


def prove_small_divmod(image: bytes, target: int, divisor: int,
                       dividend: int) -> tuple[dict[int, int], set[tuple[int, int]]] | None:
    """Execute a bounded arithmetic routine and prove its r0/r1 quotient/remainder.

    The proof follows only the concrete path for the supplied arguments. Returned
    dependency spans identify every decoded instruction on that path.
    """
    if (type(image) is not bytes or type(target) is not int or target < 0
            or target & 1 or target >= len(image) or type(divisor) is not int
            or type(dividend) is not int or not 0 <= divisor <= _MASK
            or not 0 <= dividend <= _MASK or divisor == 0):
        return None
    facts = facts_for(image)
    regs = {a.ARM_REG_R0: divisor, a.ARM_REG_R1: dividend}
    # LR is symbolic: it may be read only by the terminal BX LR and never written.
    lr_unchanged = True
    flags = (None, None, None, None)
    pc, isa = target, "thumb"
    dependencies: set[tuple[int, int]] = set()
    for _ in range(128):
        if not 0 <= pc < len(image) or pc % (4 if isa == "arm" else 2):
            return None
        ins = facts.decode(CodeAddress(pc, isa))
        if ins is None or ins.size not in (2, 4) or pc + ins.size > len(image):
            return None
        dependencies.add((pc, ins.size))
        ops = ins.operands
        next_pc = pc + ins.size
        execute = _condition(ins.cc, flags)
        if execute is None:
            return None
        if not execute:
            pc = next_pc
            continue

        if ins.id == a.ARM_INS_BX:
            if len(ops) != 1 or ops[0].type != a.ARM_OP_REG:
                return None
            if ops[0].reg == a.ARM_REG_LR and lr_unchanged:
                if regs.get(a.ARM_REG_R0) != dividend // divisor or regs.get(a.ARM_REG_R1) != dividend % divisor:
                    return None
                return dict(regs), dependencies
            if ops[0].reg == a.ARM_REG_PC and isa == "thumb":
                isa, pc = "arm", (pc + 4) & ~3
                continue
            return None
        if ins.id == a.ARM_INS_B:
            if len(ops) != 1 or ops[0].type != a.ARM_OP_IMM:
                return None
            pc = ops[0].imm
            if pc % (4 if isa == "arm" else 2):
                return None
            continue

        if ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS):
            if len(ops) != 2 or ops[0].type != a.ARM_OP_REG or ops[0].reg not in _SCRATCH:
                return None
            # Rotated ARM immediates set C from the shifter result. Reject this
            # encoding rather than infer carry from Capstone's normalized value.
            if (isa == "arm" and _sets_flags(ins)
                    and ops[1].type == a.ARM_OP_IMM
                    and len(ins.bytes) == 4
                    and ((int.from_bytes(ins.bytes, "little") >> 8) & 0xF)):
                return None
            operand = _read_operand(ops[1], regs, pc, flags)
            if operand is None:
                return None
            value, shifter_carry = operand
            regs[ops[0].reg] = value
            if _sets_flags(ins):
                n, z = _nz(value)
                flags = (n, z, shifter_carry, flags[3])
        elif ins.id in (a.ARM_INS_SUB, a.ARM_INS_RSB, a.ARM_INS_ADC):
            if len(ops) != 3 or ops[0].type != a.ARM_OP_REG or ops[0].reg not in _SCRATCH:
                return None
            left = regs.get(ops[1].reg) if ops[1].type == a.ARM_OP_REG else None
            operand = _read_operand(ops[2], regs, pc, flags)
            if left is None or operand is None:
                return None
            right = operand[0]
            if ins.id == a.ARM_INS_SUB:
                value = (left - right) & _MASK
                updated = _sub_flags(left, right, value)
            elif ins.id == a.ARM_INS_RSB:
                value = (right - left) & _MASK
                updated = _sub_flags(right, left, value)
            else:
                if type(flags[2]) is not int:
                    return None
                value = (left + right + flags[2]) & _MASK
                updated = _add_flags(left, right, flags[2], value)
            regs[ops[0].reg] = value
            if _sets_flags(ins):
                flags = updated
        elif ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR, a.ARM_INS_ASR, a.ARM_INS_ROR):
            if len(ops) != 3 or ops[0].type != a.ARM_OP_REG or ops[0].reg not in _SCRATCH:
                return None
            source = regs.get(ops[1].reg) if ops[1].type == a.ARM_OP_REG else None
            amount = ops[2].imm if ops[2].type == a.ARM_OP_IMM else None
            if source is None or amount is None:
                return None
            kind = {a.ARM_INS_LSL: a.ARM_SFT_LSL, a.ARM_INS_LSR: a.ARM_SFT_LSR,
                    a.ARM_INS_ASR: a.ARM_SFT_ASR, a.ARM_INS_ROR: a.ARM_SFT_ROR}[ins.id]
            result = _shift(source, kind, amount, flags[2])
            if result is None:
                return None
            value, carry = result
            regs[ops[0].reg] = value
            if _sets_flags(ins):
                n, z = _nz(value)
                flags = (n, z, carry, flags[3])
        else:
            # This includes memory, calls, LR/saved-register writes and all
            # unsupported control or arithmetic instructions.
            return None

        if any(reg not in _SCRATCH for reg in regs if reg not in (a.ARM_REG_R0, a.ARM_REG_R1)):
            return None
        pc = next_pc
    return None
