"""Conservative extraction of reset-linked ARM linker memory regions."""
from __future__ import annotations

import collections
import struct

try:
    from capstone import CS_ARCH_ARM, CS_GRP_JUMP, CS_MODE_ARM, CS_MODE_THUMB, Cs
    from capstone.arm import (
        ARM_INS_LDR,
        ARM_OP_IMM,
        ARM_OP_MEM,
        ARM_OP_REG,
        ARM_REG_LR,
        ARM_REG_PC,
        ARM_REG_SP,
    )
except ImportError:
    # Minimal runtimes retain the closed-consumer RAM fallback.
    Cs = None

_U32 = struct.Struct("<I")
_MAX_TRACE_BLOCKS = 96
_MAX_TRACE_ADDRESS = 0x400000
_MAX_ROUTINE_SIZE = 0x100


def _word(image: bytes, address: int) -> int | None:
    return _U32.unpack_from(image, address)[0] if 0 <= address <= len(image) - 4 else None


def _reset(image: bytes) -> tuple[int, bool] | None:
    word = _word(image, 0)
    if word is None:
        return None
    if word & 0xFF000000 == 0xEA000000:
        delta = (word & 0xFFFFFF) << 2
        if delta & 0x2000000:
            delta -= 0x4000000
        target = 8 + delta
        return (target, False) if 0 <= target < len(image) else None
    # LDR pc, [pc, +/-imm]
    if word & 0x0F7FF000 == 0x051FF000:
        address = 8 + ((word & 0xFFF) if word & 0x800000 else -(word & 0xFFF))
        value = _word(image, address)
        if value is not None and (value & ~1) < len(image):
            return value & ~1, bool(value & 1)
    return None


def _instructions(image: bytes, address: int, thumb: bool, count: int = 512):
    if not 0 <= address < len(image):
        return ()
    mode = CS_MODE_THUMB if thumb else CS_MODE_ARM
    decoder = Cs(CS_ARCH_ARM, mode)
    decoder.detail = True
    span = min(len(image), address + count * (2 if thumb else 4))
    return tuple(decoder.disasm(image[address:span], address, count=count))


def _trace(image: bytes, reset: tuple[int, bool]):
    """Follow bounded reset code and retain references reached through registers."""
    pending = [reset]
    visited: set[tuple[int, bool]] = set()
    references: dict[int, list[dict]] = collections.defaultdict(list)
    called: set[int] = set()
    while pending and len(visited) < _MAX_TRACE_BLOCKS:
        start, thumb = pending.pop()
        start &= ~1
        if ((start, thumb) in visited or start < 0
                or start >= min(len(image), _MAX_TRACE_ADDRESS)):
            continue
        visited.add((start, thumb))
        registers: dict[int, int] = {}
        for instruction in _instructions(image, start, thumb, 256):
            mnemonic = instruction.mnemonic
            operands = instruction.operands
            address = instruction.address
            is_branch = instruction.group(CS_GRP_JUMP)
            if instruction.id == ARM_INS_LDR and len(operands) >= 2:
                destination = operands[0].reg if operands[0].type == ARM_OP_REG else None
                source = operands[1]
                value = None
                if destination is not None and source.type == ARM_OP_MEM:
                    mem = source.mem
                    if mem.base == ARM_REG_PC and mem.index == 0:
                        literal = ((address + 4) & ~3 if thumb else address + 8) + mem.disp
                        value = _word(image, literal)
                        if value is not None:
                            entry = {"instruction": address, "literal": literal, "thumb": thumb}
                            if entry not in references[value]:
                                references[value].append(entry)
                    elif mem.base in registers and mem.index == 0:
                        pointed = registers[mem.base] + mem.disp
                        value = _word(image, pointed)
                        entry = {"instruction": address, "dereference": pointed, "thumb": thumb}
                        if entry not in references[pointed]:
                            references[pointed].append(entry)
                        if value is not None:
                            indirect = {"instruction": address, "literal": pointed, "thumb": thumb}
                            if indirect not in references[value]:
                                references[value].append(indirect)
                if destination is not None:
                    if value is None:
                        registers.pop(destination, None)
                    else:
                        registers[destination] = value
            elif mnemonic in ("mov", "movs", "movw") and len(operands) >= 2 and operands[0].type == ARM_OP_REG:
                destination = operands[0].reg
                source = operands[1]
                shift = getattr(source, "shift", None)
                unshifted = shift is None or shift.type == 0
                value = (source.imm if source.type == ARM_OP_IMM else
                         registers.get(source.reg) if source.type == ARM_OP_REG and unshifted else None)
                if value is None:
                    registers.pop(destination, None)
                else:
                    registers[destination] = value & 0xFFFFFFFF
            elif mnemonic in ("add", "adds", "sub", "subs") and len(operands) >= 3 and operands[0].type == ARM_OP_REG:
                destination = operands[0].reg
                left_op, right_op = operands[1], operands[2]
                left = registers.get(left_op.reg) if left_op.type == ARM_OP_REG else left_op.imm if left_op.type == ARM_OP_IMM else None
                shift = getattr(right_op, "shift", None)
                unshifted = shift is None or shift.type == 0
                right = (registers.get(right_op.reg) if right_op.type == ARM_OP_REG and unshifted else
                         right_op.imm if right_op.type == ARM_OP_IMM else None)
                if left is not None and right is not None:
                    registers[destination] = (left + right * (-1 if mnemonic.startswith("sub") else 1)) & 0xFFFFFFFF
                else:
                    registers.pop(destination, None)
            elif mnemonic in ("cmp", "cmn", "tst", "teq"):
                pass
            else:
                # Unknown writes invalidate the affected register rather than
                # allowing an old pointer value to create a false table link.
                try:
                    _, written = instruction.regs_access()
                except Exception:
                    written = ()
                if not is_branch and not mnemonic.startswith(("str", "stm", "cmp", "cmn", "tst", "teq")):
                    for destination in written:
                        registers.pop(destination, None)

            if is_branch and operands:
                target = None
                operand = operands[0]
                if operand.type == ARM_OP_IMM:
                    target = operand.imm
                elif operand.type == ARM_OP_REG:
                    target = registers.get(operand.reg)
                if mnemonic in ("bx", "blx") and operand.type == ARM_OP_REG and operand.reg != ARM_REG_LR:
                    continuation = registers.get(ARM_REG_LR)
                    if continuation is not None:
                        pending.append((continuation & ~1, bool(continuation & 1)))
                if target is not None:
                    mode = bool(target & 1) if mnemonic in ("bx", "blx") else thumb
                    target &= ~1
                    if 0 <= target < len(image):
                        pending.append((target, mode))
                        if mnemonic in ("bl", "blx"):
                            called.add(target | int(mode))
                if mnemonic in ("b", "bx") and not (mnemonic == "bx" and operand.type == ARM_OP_REG and operand.reg == ARM_REG_LR):
                    break
                if mnemonic == "bx" and operand.type == ARM_OP_REG and operand.reg == ARM_REG_LR:
                    break
    return references, called


def _routine_kind(image: bytes, address: int) -> str | None:
    stores = loads = zero = False
    for ins in _instructions(image, address & ~1, bool(address & 1), 32):
        mnemonic = ins.mnemonic
        names = {ins.reg_name(operand.reg) for operand in ins.operands if operand.type == ARM_OP_REG}
        stores |= mnemonic.startswith(("str", "stm"))
        loads |= mnemonic.startswith(("ldr", "ldm"))
        zero |= mnemonic.startswith(("mov", "eor"))
        returns = (
            (mnemonic == "bx" and ins.operands and ins.operands[0].type == ARM_OP_REG
             and ins.reg_name(ins.operands[0].reg) == "lr")
            or (mnemonic == "mov" and len(ins.operands) >= 2
                and ins.operands[0].type == ARM_OP_REG and ins.reg_name(ins.operands[0].reg) == "pc"
                and ins.operands[1].type == ARM_OP_REG and ins.reg_name(ins.operands[1].reg) == "lr")
            or (mnemonic == "bx")
            or (mnemonic.startswith(("pop", "ldm")) and "pc" in names)
            or mnemonic == "b"
        )
        if returns:
            break
    if not stores:
        return None
    if loads:
        return "rw-copy"
    if zero:
        return "zero-init"
    return None


def _regions(image: bytes, references: dict[int, list[dict]], called: set[int]) -> list[dict]:
    candidates: set[int] = set()
    for pointer in references:
        if 0 <= pointer < min(len(image), _MAX_TRACE_ADDRESS) and pointer % 4 == 0:
            for delta in (0, 4, 8, 12, 16):
                if pointer >= delta:
                    candidates.add(pointer - delta)
    result: dict[tuple, dict] = {}
    five_word_tables: set[int] = set()
    for address in sorted(candidates):
        if address + 20 > len(image):
            continue
        source, destination, size, zero, zero_size = struct.unpack_from("<5I", image, address)
        linked = [entry for offset in range(address, address + 20, 4) for entry in references.get(offset, ())]
        if (size >= 4 and zero_size >= 4 and not (source | destination | size | zero | zero_size) & 3
                and source + size <= len(image) and destination >= 0x100000
                and destination + size == zero and zero + zero_size <= 0x100000000
                and size <= 0x1000000 and zero_size <= 0x2000000
                and not source <= destination < source + size):
            evidence = {"table_offset": address, "references": linked}
            five_word_tables.add(address)
            for load, execute, length, kind in (
                (source, destination, size, "rw-copy"),
                (None, zero, zero_size, "zero-init"),
            ):
                result[(load, execute, length, kind)] = {
                    "load": load, "exec": execute, "size": length,
                    "kind": kind, "evidence": evidence,
                }
    for address in sorted(candidates):
        if address + 16 > len(image) or any(abs(address - table) < 20 for table in five_word_tables):
            continue
        linked_fields = [field for field in range(address, address + 16, 4) if field in references]
        if not linked_fields:
            continue
        source, destination, size, function = struct.unpack_from("<4I", image, address)
        linked_function = function in references or (function & ~1) in references
        if (source | destination | size) & 3 or not 4 <= size <= 0x1000000:
            continue
        if not 0x100000 <= destination or destination + size > 0x100000000 or not linked_function:
            continue
        if (function & ~1) < 0x40 or (source != 0 and source + size > len(image)):
            continue
        kind = _routine_kind(image, function)
        if kind is None or (kind != "zero-init" and source + size > len(image)):
            continue
        result[(None if kind == "zero-init" else source, destination, size, kind)] = {
            "load": None if kind == "zero-init" else source,
            "exec": destination, "size": size, "kind": kind,
            "evidence": {"table_offset": address, "referenced_fields": linked_fields,
                         "init_routine": function},
        }
    return sorted(result.values(), key=lambda region: region["exec"])


def detect_linker_memory_map(image: bytes) -> tuple[dict | None, str]:
    """Return reset-linked initialized regions as ``(profile, reason)``."""
    if not isinstance(image, (bytes, bytearray)):
        return None, "memory-map-image-not-bytes"
    if len(image) < 8:
        return None, "memory-map-image-too-small"
    reset = _reset(image)
    if reset is None:
        return None, "memory-map-reset-vector-unsupported"
    if Cs is None:
        return None, "memory-map-decoder-unavailable"
    references, called = _trace(image, reset)
    regions = _regions(image, references, called)
    if not regions:
        return None, "memory-map-no-reset-linked-descriptor"
    windows: list[dict] = []
    for region in regions:
        start, end = region["exec"], region["exec"] + region["size"]
        if windows and start <= windows[-1]["base"] + windows[-1]["size"]:
            previous = windows[-1]
            previous["size"] = max(end, previous["base"] + previous["size"]) - previous["base"]
        else:
            windows.append({"base": start, "size": end - start})
    return {
        "source": "linker-descriptor",
        "confidence": "medium",
        "reset": {"offset": reset[0], "thumb": reset[1]},
        "regions": regions,
        "ram_windows": windows,
    }, "accepted"
