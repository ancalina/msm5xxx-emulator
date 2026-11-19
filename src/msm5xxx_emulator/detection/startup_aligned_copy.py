"""Source-step an aligned, register-argument ARM memcpy implementation."""
from __future__ import annotations

from dataclasses import dataclass
import struct

import capstone as cs
from capstone import arm as a


_RETURN = object()
_PRESERVED = tuple(range(a.ARM_REG_R4, a.ARM_REG_R11 + 1))


@dataclass(frozen=True)
class _Byte:
    offset: int


@dataclass(frozen=True)
class _EntryRegister:
    register: int


def _register_rank(register):
    if a.ARM_REG_R0 <= register <= a.ARM_REG_R12:
        return register - a.ARM_REG_R0
    return {a.ARM_REG_SP: 13, a.ARM_REG_LR: 14, a.ARM_REG_PC: 15}.get(register, 99)


def _condition(cc, flags):
    if cc in (a.ARM_CC_AL, a.ARM_CC_INVALID):
        return True
    if flags is None:
        flags = (None, None, None, None)

    def known(index):
        value = flags[index]
        if value is None:
            raise ValueError("condition depends on unknown entry flags")
        return value

    predicate = {
        a.ARM_CC_EQ: lambda: known(1), a.ARM_CC_NE: lambda: not known(1),
        a.ARM_CC_HS: lambda: known(2), a.ARM_CC_LO: lambda: not known(2),
        a.ARM_CC_MI: lambda: known(0), a.ARM_CC_PL: lambda: not known(0),
        a.ARM_CC_VS: lambda: known(3), a.ARM_CC_VC: lambda: not known(3),
        a.ARM_CC_HI: lambda: known(2) and not known(1),
        a.ARM_CC_LS: lambda: not known(2) or known(1),
        a.ARM_CC_GE: lambda: known(0) == known(3),
        a.ARM_CC_LT: lambda: known(0) != known(3),
        a.ARM_CC_GT: lambda: not known(1) and known(0) == known(3),
        a.ARM_CC_LE: lambda: known(1) or known(0) != known(3),
    }.get(cc)
    if predicate is None:
        raise ValueError("unsupported condition code")
    return predicate()


def _read_word(image, address):
    return struct.unpack_from("<I", image, address)[0]


def aligned_copy_evidence(image, entry, source, destination, size, *,
                          code_start, code_size,
                          stack_pointer=0x70000000):
    """Prove an aligned call of at most one MiB copies each source byte once.

    Larger transfers must be split by a separately proved wrapper and checked
    as bounded chunks.

    `entry` is an address into `image`; bit zero selects Thumb interworking,
    and an even address starts in ARM state. `code_start:code_start+code_size`
    bounds all executed instructions. `stack_pointer` is the concrete entry
    SP used for stack-sensitive branches and spill checks. The supplied
    arguments are concrete, but source data is represented only by opaque
    byte tags.

    Returns executed source spans, compressed transfer spans, stack-frame
    size, and preserved registers, or ``None`` on unsupported instructions,
    paths, memory accesses, or incomplete/nonlinear copies.
    """
    if (not isinstance(image, (bytes, bytearray)) or type(entry) is not int
            or type(source) is not int or type(destination) is not int
            or type(size) is not int or type(code_start) is not int
            or type(code_size) is not int or type(stack_pointer) is not int):
        return None
    image = bytes(image)
    code_end = code_start + code_size
    pc = entry & ~1
    thumb = bool(entry & 1)
    if (code_size <= 0 or code_start < 0 or code_end > len(image)
            or code_end > 0x100000000 or not code_start <= pc < code_end
            or stack_pointer < 0x10000 or stack_pointer > 0xffffffff
            or stack_pointer & 3
            or source < 0 or size <= 0 or size > (1 << 20)
            or source + size > len(image)
            or source & 3 or destination < 0 or destination + size > 0x100000000
            or destination & 3 or size & 3
            or (source < destination + size and destination < source + size)
            or (destination < code_end and code_start < destination + size)):
        return None

    engine = {}
    for isa, mode in ((False, cs.CS_MODE_ARM), (True, cs.CS_MODE_THUMB)):
        disassembler = cs.Cs(cs.CS_ARCH_ARM, mode)
        disassembler.detail = True
        engine[isa] = disassembler

    # Capstone's register IDs are sparse (R0..R12 follow the ARM aliases).
    regs = [_EntryRegister(register) for register in range(128)]
    regs[a.ARM_REG_R0] = destination
    regs[a.ARM_REG_R1] = source
    regs[a.ARM_REG_R2] = size
    regs[a.ARM_REG_SP] = stack_pointer
    regs[a.ARM_REG_LR] = _RETURN
    saved = tuple(regs[index] for index in _PRESERVED)
    stack_base = stack_pointer
    stack = {}
    writes = []
    executed = set()
    steps = 0
    flags = (None, None, None, None)
    transfer_seen = False

    def integer(value):
        if type(value) is not int:
            raise ValueError("payload-dependent arithmetic")
        return value

    def operand_value(ins, operand, *, allow_shift=False):
        if operand.type == a.ARM_OP_REG:
            if operand.reg == a.ARM_REG_PC:
                raise ValueError("unmodeled PC read")
            if operand.subtracted or (operand.shift.type and not allow_shift):
                raise ValueError("transformed register operands are unsupported")
            return regs[operand.reg]
        if operand.type == a.ARM_OP_IMM:
            if operand.subtracted or operand.shift.type:
                raise ValueError("transformed immediate operands are unsupported")
            return operand.imm & 0xffffffff
        raise ValueError("unsupported operand")

    def set_nz(result, carry=None, overflow=None):
        nonlocal flags
        value = integer(result) & 0xffffffff
        old = flags if flags is not None else (None, None, None, None)
        flags = (bool(value & 0x80000000), value == 0,
                 old[2] if carry is None else bool(carry),
                 old[3] if overflow is None else bool(overflow))

    def sub_flags(left, right, result):
        left, right = integer(left), integer(right)
        raw = left - right
        set_nz(result, left >= right,
               bool(((left ^ right) & (left ^ raw) & 0x80000000)))

    def read_memory(address, width, *, stack_access=False):
        nonlocal transfer_seen
        if width != 4 or address & 3:
            raise ValueError("only aligned word reads are supported")
        if stack_access:
            if (address < stack_base - 0x10000 or address + width > stack_base
                    or (source < address + width and address < source + size)
                    or (destination < address + width
                        and address < destination + size)):
                raise ValueError("stack read is out of bounds or aliases copy memory")
            if address not in stack:
                raise ValueError("read from uninitialized stack")
            return stack[address]
        if source <= address and address + width <= source + size:
            transfer_seen = True
            return _Byte(address - source)
        raise ValueError("read outside payload or modeled stack")

    def write_memory(address, width, value, *, stack_access=False):
        if width != 4 or address & 3:
            raise ValueError("only aligned word writes are supported")
        if stack_access:
            if (address < stack_base - 0x10000 or address + width > stack_base
                    or (source < address + width and address < source + size)
                    or (destination < address + width
                        and address < destination + size)):
                raise ValueError("stack write is out of bounds or aliases copy memory")
            stack[address] = value
            return
        if destination <= address and address + width <= destination + size:
            if not isinstance(value, _Byte):
                raise ValueError("destination write lacks source-byte provenance")
            writes.append((value.offset, width, address - destination))
            return
        raise ValueError("write outside destination or modeled stack")

    def effective_address(mem):
        if mem.index:
            raise ValueError("indexed memory operands are unsupported")
        return (integer(regs[mem.base]) + mem.disp) & 0xffffffff

    try:
        while steps < 2_000_000:
            steps += 1
            if not code_start <= pc < code_end:
                raise ValueError("control leaves source bounds")
            raw = image[pc:min(pc + 4, code_end)]
            ins = next(engine[thumb].disasm(raw, pc, count=1), None)
            if ins is None or ins.size not in (2, 4) or pc + ins.size > code_end:
                raise ValueError("undecodable or truncated instruction")
            executed.add((pc, ins.size))
            next_pc = pc + ins.size
            if not _condition(ins.cc, flags):
                pc = next_pc
                continue

            if ins.id in (a.ARM_INS_B, a.ARM_INS_BX):
                if ins.id == a.ARM_INS_B:
                    if not ins.operands or ins.operands[0].type != a.ARM_OP_IMM:
                        raise ValueError("indirect branch")
                    pc = ins.operands[0].imm
                    continue
                if (len(ins.operands) != 1 or ins.operands[0].type != a.ARM_OP_REG):
                    raise ValueError("invalid BX")
                target_reg = ins.operands[0].reg
                if thumb and target_reg == a.ARM_REG_PC and steps == 1:
                    pc = (pc + 4) & ~3
                    thumb = False
                    continue
                if target_reg == a.ARM_REG_LR and regs[a.ARM_REG_LR] == _RETURN:
                    break
                raise ValueError("unproven indirect transfer")

            if ins.id in (a.ARM_INS_BL, a.ARM_INS_BLX):
                raise ValueError("calls are outside this leaf proof")

            if ins.id in (a.ARM_INS_PUSH, a.ARM_INS_POP):
                if _read_word(image, pc) & (1 << 22):
                    raise ValueError("user-bank stack transfers are unsupported")
                listed = [operand.reg for operand in ins.operands
                          if operand.type == a.ARM_OP_REG]
                if not listed or len(set(listed)) != len(listed):
                    raise ValueError("invalid stack register list")
                listed.sort(key=_register_rank)
                sp = integer(regs[a.ARM_REG_SP])
                if ins.id == a.ARM_INS_PUSH:
                    sp -= 4 * len(listed)
                    for offset, register in enumerate(listed):
                        write_memory(sp + 4 * offset, 4, regs[register],
                                     stack_access=True)
                    regs[a.ARM_REG_SP] = sp
                else:
                    for offset, register in enumerate(listed):
                        value = read_memory(sp + 4 * offset, 4,
                                            stack_access=True)
                        if register == a.ARM_REG_PC:
                            if value != _RETURN:
                                raise ValueError("stack return target is not the caller")
                            regs[a.ARM_REG_SP] = sp + 4 * len(listed)
                            pc = _RETURN
                            break
                        regs[register] = value
                    else:
                        regs[a.ARM_REG_SP] = sp + 4 * len(listed)
                    if pc == _RETURN:
                        break
                pc = next_pc
                continue

            if ins.id in (a.ARM_INS_LDM, a.ARM_INS_STM):
                if len(ins.operands) < 2 or ins.operands[0].type != a.ARM_OP_REG:
                    raise ValueError("invalid multiple transfer")
                base_reg = ins.operands[0].reg
                registers = [op.reg for op in ins.operands[1:]
                             if op.type == a.ARM_OP_REG]
                if not registers or len(registers) != len(ins.operands) - 1:
                    raise ValueError("invalid multiple register list")
                word = _read_word(image, pc)
                if ((word >> 24) & 1 or not (word >> 23) & 1
                        or (word >> 22) & 1
                        or base_reg in registers or a.ARM_REG_PC in registers):
                    raise ValueError("only increasing-address non-PC block transfers are supported")
                if (registers != sorted(registers, key=_register_rank)
                        or len(set(registers)) != len(registers)):
                    raise ValueError("unordered multiple register list")
                base = integer(regs[base_reg])
                for offset, register in enumerate(registers):
                    address = base + offset * 4
                    if ins.id == a.ARM_INS_LDM:
                        regs[register] = read_memory(address, 4)
                    else:
                        write_memory(address, 4, regs[register])
                if ins.writeback:
                    regs[base_reg] = base + 4 * len(registers)
                pc = next_pc
                continue

            if ins.id in (a.ARM_INS_LDR, a.ARM_INS_LDRB, a.ARM_INS_STR,
                          a.ARM_INS_STRB, a.ARM_INS_LDRH, a.ARM_INS_STRH):
                if len(ins.operands) < 2 or ins.operands[0].type != a.ARM_OP_REG \
                        or ins.operands[1].type != a.ARM_OP_MEM:
                    raise ValueError("unsupported scalar memory operation")
                reg, mem = ins.operands[0].reg, ins.operands[1].mem
                if reg == a.ARM_REG_PC:
                    raise ValueError("unmodeled PC write")
                if ins.operands[1].subtracted or ins.operands[1].shift.type:
                    raise ValueError("transformed memory operands are unsupported")
                address = effective_address(mem)
                width = (1 if ins.id in (a.ARM_INS_LDRB, a.ARM_INS_STRB)
                         else 2 if ins.id in (a.ARM_INS_LDRH, a.ARM_INS_STRH) else 4)
                if ins.id in (a.ARM_INS_LDR, a.ARM_INS_LDRB, a.ARM_INS_LDRH):
                    regs[reg] = read_memory(address, width)
                else:
                    write_memory(address, width, regs[reg])
                if ins.writeback:
                    if (len(ins.operands) < 3 or ins.operands[2].type != a.ARM_OP_IMM
                            or mem.disp != 0):
                        raise ValueError("unsupported writeback form")
                    regs[mem.base] = (integer(regs[mem.base]) + ins.operands[2].imm) & 0xffffffff
                pc = next_pc
                continue

            if ins.id in (a.ARM_INS_CMP, a.ARM_INS_CMN):
                if len(ins.operands) != 2:
                    raise ValueError("invalid compare")
                if ins.operands[1].shift.value:
                    raise ValueError("shifted compare operands are unsupported")
                left, right = map(lambda op: integer(operand_value(ins, op)), ins.operands)
                if ins.id == a.ARM_INS_CMP:
                    sub_flags(left, right, left - right)
                else:
                    raw = left + right
                    result = raw & 0xffffffff
                    set_nz(result, raw > 0xffffffff,
                           bool((~(left ^ right) & (left ^ result) & 0x80000000)))
                pc = next_pc
                continue

            if ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB, a.ARM_INS_AND,
                          a.ARM_INS_ORR, a.ARM_INS_EOR, a.ARM_INS_MOV,
                          a.ARM_INS_LSL, a.ARM_INS_LSR):
                if len(ins.operands) < 2 or ins.operands[0].type != a.ARM_OP_REG:
                    raise ValueError("unsupported data operation")
                dst = ins.operands[0].reg
                if dst == a.ARM_REG_PC:
                    raise ValueError("unmodeled PC write")
                old_value = operand_value(
                    ins, ins.operands[1],
                    allow_shift=(ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR)
                                 and len(ins.operands) == 2))
                right = operand_value(ins, ins.operands[2]) if len(ins.operands) == 3 else None
                if (ins.id not in (a.ARM_INS_LSL, a.ARM_INS_LSR)
                        and len(ins.operands) == 3
                        and ins.operands[2].shift.value):
                    raise ValueError("shifted data operands are unsupported")
                if ins.id == a.ARM_INS_MOV:
                    result = old_value
                elif (ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR)
                      and len(ins.operands) == 2):
                    left = integer(old_value)
                    shift = ins.operands[1].shift.value
                    result = (left << shift) if ins.id == a.ARM_INS_LSL else (left >> shift)
                elif len(ins.operands) == 3:
                    left = old_value
                    if ins.id == a.ARM_INS_ADD:
                        result = integer(left) + integer(right)
                    elif ins.id == a.ARM_INS_SUB:
                        result = integer(left) - integer(right)
                    elif ins.id == a.ARM_INS_AND:
                        result = integer(left) & integer(right)
                    elif ins.id == a.ARM_INS_ORR:
                        result = integer(left) | integer(right)
                    elif ins.id == a.ARM_INS_EOR:
                        result = integer(left) ^ integer(right)
                    elif ins.id == a.ARM_INS_LSL:
                        result = integer(left) << integer(right)
                    else:
                        result = integer(left) >> integer(right)
                else:
                    raise ValueError(f"unsupported data operation arity: {ins.mnemonic} {ins.op_str} at {pc:#x}")
                regs[dst] = result & 0xffffffff if type(result) is int else result
                if ins.update_flags or ins.mnemonic.endswith("s"):
                    if ins.id == a.ARM_INS_SUB:
                        sub_flags(old_value, right, result)
                    elif ins.id == a.ARM_INS_ADD:
                        left, right_value = integer(old_value), integer(right)
                        raw = left + right_value
                        wrapped = raw & 0xffffffff
                        set_nz(wrapped, raw > 0xffffffff,
                               bool((~(left ^ right_value)
                                     & (left ^ wrapped) & 0x80000000)))
                    elif ins.id == a.ARM_INS_LSL and len(ins.operands) == 3:
                        shift = integer(right)
                        value = integer(old_value)
                        carry = ((value >> (32 - shift)) & 1) if 0 < shift <= 32 else flags[2]
                        set_nz(result, carry)
                    elif ins.id == a.ARM_INS_LSR and len(ins.operands) == 3:
                        shift = integer(right)
                        value = integer(old_value)
                        carry = ((value >> (shift - 1)) & 1) if 0 < shift <= 32 else flags[2]
                        set_nz(result, carry)
                    elif ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR):
                        shift = ins.operands[1].shift.value
                        value = integer(old_value)
                        carry = (((value >> (32 - shift)) & 1)
                                 if ins.id == a.ARM_INS_LSL and 0 < shift <= 32
                                 else ((value >> (shift - 1)) & 1)
                                 if ins.id == a.ARM_INS_LSR and 0 < shift <= 32
                                 else flags[2])
                        set_nz(result, carry)
                    else:
                        set_nz(result)
                pc = next_pc
                continue

            raise ValueError(f"unsupported instruction {ins.mnemonic}")

        else:
            raise ValueError("instruction budget exceeded")

        if (not transfer_seen or regs[a.ARM_REG_SP] != stack_base
                or tuple(regs[index] for index in _PRESERVED) != saved):
            raise ValueError("copy does not return with preserved frame/registers")
        cursor = 0
        for source_offset, width, destination_offset in writes:
            if source_offset != cursor or destination_offset != cursor:
                raise ValueError("copy is incomplete, duplicated, reordered, or out of range")
            cursor += width
        if cursor != size:
            raise ValueError("copy is incomplete, duplicated, reordered, or out of range")
        if regs[a.ARM_REG_LR] != _RETURN:
            raise ValueError("link register was not preserved")
        return {
            "entry": entry,
            "code_spans": tuple(sorted(executed)),
            "transfer_spans": tuple(writes),
            "copied_bytes": cursor,
            "stack_frame_bytes": stack_base - min(
                [stack_base, *(address for address in stack)]),
            "preserved_registers": tuple(_PRESERVED) + (a.ARM_REG_SP, a.ARM_REG_LR),
            "steps": steps,
        }
    except (ValueError, IndexError, struct.error, OverflowError, TypeError):
        return None
