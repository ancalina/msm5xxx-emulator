"""Abstract execution for descriptor-owned keypad row scans."""
from __future__ import annotations

from dataclasses import dataclass
import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .halfword.scanners import _mapped_irq, interrupt_helper
from .matrix.scanners import _distributed_irq

_ALL = 0xffffffff

@dataclass(frozen=True)
class _Bits:
    zero: int = 0
    one: int = 0

    @classmethod
    def constant(cls, value):
        return cls((~value) & _ALL, value & _ALL)

    def value(self):
        return self.one if self.zero | self.one == _ALL else None

    def logical(self, operation, other):
        if operation == "and":
            return _Bits(self.zero | other.zero, self.one & other.one)
        if operation == "or":
            return _Bits(self.zero & other.zero, self.one | other.one)
        return _Bits(self.one, self.zero).logical("and", other)


def _word(image, pc):
    return struct.unpack_from("<H", image, pc)[0] if 0 <= pc <= len(image) - 2 else -1


def _region_values(image, entry, use):
    """Observe every local path reaching the use, with explicit outer exits."""
    facts = facts_for(image)
    exits = {CodeAddress(use)}
    for pc in range(entry, use, 2):
        word = _word(image, pc)
        if word & 0xf800 == 0xe000 or word & 0xf000 == 0xd000:
            exits.update(CodeAddress(target) for target in
                _thumb_successors(image, pc, len(image)) if not entry <= target < use)
    region = facts.function_region(CodeAddress(entry), stop_before=tuple(
        sorted(exits, key=lambda pc: pc.address)), budget=2048)
    if not region.complete:
        return None
    values = {}
    for number in range(8):
        register = a.ARM_REG_R0 + number
        value = facts.register_value(region, CodeAddress(use), register)
        if value is not None and value.kind == "const":
            values[register] = _Bits.constant(value.value)
    return values


def _irq(image, target):
    if target is None or target & 1:
        return None
    for enabled in (False, True):
        if _mapped_irq(image, target, enabled):
            return ((target, 24),)
        profile = interrupt_helper(image, target, enabled)
        if profile:
            return ((target, 16), (int(profile["body"], 16), 20))
        if _distributed_irq(image, target, enabled):
            return ((target, 28),)
    return None


def _row_clear_helper(image, entry, descriptor):
    """Close the linked clear-and-commit helper used before a row switch."""
    facts = facts_for(image)
    if entry is None or entry & 1 or not 0 <= entry <= len(image) - 36:
        return None
    expected = {
        0: ("push", "{lr}"),
        8: ("movs", "r3, #0x3f"),
        12: ("lsls", "r3, r3, #8"),
        14: ("bics", "r2, r3"),
        18: ("ldrh", "r2, [r1, #0x1c]"),
        20: ("ldr", "r1, [r1, #0x10]"),
        22: ("strh", "r2, [r1]"),
        24: ("cmp", "r0, #0"),
        32: ("pop", "{r3}"),
        34: ("bx", "r3"),
    }
    for offset, (mnemonic, operands) in expected.items():
        ins = facts.decode(CodeAddress(entry + offset))
        if ins is None or (ins.mnemonic, ins.op_str) != (mnemonic, operands):
            return None
    first = facts.decode(CodeAddress(entry + 2))
    literal_load = facts.decode(CodeAddress(entry + 6))
    load_shadow = facts.decode(CodeAddress(entry + 10))
    store_shadow = facts.decode(CodeAddress(entry + 16))
    branch = facts.decode(CodeAddress(entry + 26))
    unlock = facts.decode(CodeAddress(entry + 28))
    literal = facts.literal(CodeAddress(entry + 6))
    if (first is None or first.id != a.ARM_INS_BL or literal_load is None
            or literal_load.id != a.ARM_INS_LDR or literal is None
            or literal.value != descriptor or literal.pool + 4 > len(image)
            or load_shadow is None or (load_shadow.mnemonic, load_shadow.op_str)
            != ("ldrh", "r2, [r1, #0x1c]")
            or store_shadow is None or (store_shadow.mnemonic, store_shadow.op_str)
            != ("strh", "r2, [r1, #0x1c]")
            or branch is None or branch.id != a.ARM_INS_B
            or branch.cc != a.ARM_CC_NE or not branch.operands
            or branch.operands[0].imm != entry + 32
            or unlock is None or unlock.id != a.ARM_INS_BL):
        return None
    lock_spans = _irq(image, facts.thumb_call_target(entry + 2))
    unlock_spans = _irq(image, facts.thumb_call_target(entry + 28))
    if lock_spans is None or unlock_spans is None:
        return None
    if facts.thumb_call_target(entry + 2) == facts.thumb_call_target(entry + 28):
        return None
    return (literal.pool, ((entry, 36), (literal.pool, 4),
                           *lock_spans, *unlock_spans))


def _clear_outputs(image, helper, masks, *, descriptor=-0x10000,
                   descriptor_rom=0, byte_memory=(), byte_ports=()):
    """Prove a balanced clear/commit function before an all-rows sample."""
    if helper is None or _word(image, helper) != 0xb580:
        return None
    facts = facts_for(image)
    function = facts.function(CodeAddress(helper), budget=256)
    if not function.complete or function.unresolved or function.truncated:
        return None
    finish = max(site.address for site in function.instructions) - 4
    if tuple(_word(image, finish + offset) for offset in (0, 2, 4)) != (0xbc80, 0xbc08, 0x4718):
        return None
    for site in function.instructions:
        if not helper + 2 <= site.address < finish:
            continue
        instruction = facts.decode(site)
        try:
            _, written = instruction.regs_access()
        except Exception:
            return None
        if any(register in written for register in (a.ARM_REG_R4, a.ARM_REG_R5, a.ARM_REG_R6)):
            return None
    result = _row_outputs(image, helper + 2, finish, {}, descriptor, descriptor_rom,
        byte_memory=byte_memory, byte_ports=byte_ports)
    if result is None or any(port not in result[0] or result[0][port].zero & mask != mask
                              for port, mask in masks):
        return None
    return result[1] | {(helper, 2), (finish, 6)}


def _row_outputs(image, entry, sense, initial, descriptor, descriptor_rom, *,
                 capture_load=False, capture_end=None,
                 capture_registers=False,
                 preserved_registers: dict[int, int] | None = None,
                 initial_stack: dict[int, int] | None = None,
                 copied_row=None, ram_dependencies=None,
                 byte_memory=(), initial_memory=None, byte_ports=(),
                 unknown_halfword_inputs=()):
    """Abstractly execute a bounded row switch; unknown instructions reject it.

    Shadow halfwords retain unknown unrelated pins. Only bits established by
    the actual read/mask/write sequence become row-wire evidence.
    Byte-memory spans are source-owned shadow/state bytes; copied rows may use
    aligned byte or halfword reads. Initial memory describes abstract loop
    inputs, never guest initialization.
    """
    facts = facts_for(image)
    input_sites = tuple(unknown_halfword_inputs)
    if input_sites and not capture_load:
        return None
    if any(not isinstance(item, tuple) or len(item) != 2
           or any(type(value) is not int for value in item)
           or item[0] & 1 or not 0 <= item[0] <= len(image) - 2
           or item[1] & 1 or not 0x03000000 <= item[1] < 0x03001000
           for item in input_sites):
        return None
    if len(set(input_sites)) != len(input_sites):
        return None
    input_sites = frozenset(input_sites)
    initial = dict(initial)
    frame_model = capture_load or initial_stack is not None
    if frame_model:
        initial[a.ARM_REG_SP] = _Bits.constant(0xffff0000)
    if any(not any(start <= address < start + size for start, size in byte_memory)
           for address in (initial_memory or {})):
        return None
    stack = dict(initial_memory or {})
    stack.update({0xffff0000 + slot: _Bits.constant(value)
                  for slot, value in (initial_stack or {}).items()})
    limit = capture_end if capture_load and capture_end is not None else sense
    pending = [(entry, initial, stack, {}, None)]
    seen, results, dependencies = set(), [], set()
    captured_registers = []
    capture_set = (None if capture_registers is True else
                   set(capture_registers) if capture_registers else set())
    graph = {}
    steps = 0

    def key_of(state):
        pc, registers, shadow, outputs, flags = state
        return (pc, tuple(sorted(registers.items())), tuple(sorted(shadow.items())),
                tuple(sorted(outputs.items())), flags)

    def enqueue(source, state):
        graph[source].add(key_of(state))
        pending.append(state)

    while pending:
        pc, registers, shadow, outputs, flags = pending.pop()
        state = (pc, registers, shadow, outputs, flags)
        key = key_of(state)
        if key in seen:
            continue
        seen.add(key)
        graph[key] = set()
        steps += 1
        if steps > 2048 or not entry <= pc <= limit:
            return None
        if capture_load and capture_end is not None and pc == capture_end:
            # A full firmware event buffer can end this scan without a load.
            continue
        if pc == sense and not capture_load:
            if any(registers.get(register, _Bits()).value() != value
                   for register, value in (preserved_registers or {}).items()):
                return None
            if initial_stack is not None and (registers.get(a.ARM_REG_SP, _Bits()).value() != 0xffff0000
                    or any(shadow.get(0xffff0000 + slot, _Bits()).value() != value
                           for slot, value in initial_stack.items())):
                return None
            results.append(outputs)
            if capture_registers:
                captured_registers.append(dict(registers) if capture_set is None else
                    {register: registers.get(register, _Bits()) for register in capture_set})
            continue
        ins = facts.decode(CodeAddress(pc))
        if ins is None or (ins.size != 2 and ins.id != a.ARM_INS_BL):
            return None
        if any(site == pc for site, _address in input_sites) and ins.id != a.ARM_INS_LDRH:
            return None
        dependencies.add((pc, ins.size))
        operands = ins.operands
        next_pc = pc + ins.size
        registers, shadow, outputs = dict(registers), dict(shadow), dict(outputs)

        def operand(op):
            if op.type == a.ARM_OP_IMM:
                return _Bits.constant(op.imm)
            if op.type == a.ARM_OP_REG:
                if op.reg == a.ARM_REG_PC:
                    return _Bits.constant(pc + 4)
                return registers.get(op.reg, _Bits())
            return _Bits()

        def memory(op):
            base = ((pc + 4) & ~3) if op.mem.base == a.ARM_REG_PC else registers.get(op.mem.base, _Bits()).value()
            index = registers.get(op.mem.index, _Bits()).value() if op.mem.index else 0
            if base is None or index is None or op.shift.type or op.subtracted:
                return None
            return (base + index + op.mem.disp) & _ALL

        if ins.id == a.ARM_INS_BL:
            if capture_load:
                # A bounded event-address trace ends an unsupported call path;
                # it does not model the callee or claim that the key is accepted.
                continue
            target = facts.thumb_call_target(pc)
            spans = _irq(image, target)
            if spans is None:
                summary = _row_clear_helper(image, target, descriptor)
                if summary is not None:
                    _, spans = summary
                    address = descriptor + 0x1c
                    prior = shadow.get(address, _Bits(0xffff0000, 0))
                    shadow[address] = prior.logical("and", _Bits.constant(~0x3f00))
            if spans is None:
                from .arithmetic_calls import prove_small_divmod
                divisor = registers.get(a.ARM_REG_R0, _Bits()).value()
                dividend = registers.get(a.ARM_REG_R1, _Bits()).value()
                arithmetic = prove_small_divmod(image, target, divisor, dividend)
                if arithmetic is None:
                    return None
                values, arithmetic_spans = arithmetic
                dependencies.update(arithmetic_spans)
                for reg in (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2,
                            a.ARM_REG_R3, a.ARM_REG_R12):
                    registers.pop(reg, None)
                registers.update({reg: _Bits.constant(value)
                                  for reg, value in values.items()})
                flags = None
                enqueue(key, (next_pc, registers, shadow, outputs, flags))
                continue
            dependencies.update(spans)
            for reg in (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3):
                registers.pop(reg, None)
            flags = None
        elif ins.id == a.ARM_INS_B:
            if not operands or operands[0].type != a.ARM_OP_IMM:
                return None
            target = operands[0].imm
            if ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                next_pc = target
            else:
                condition = None
                if flags is not None and flags[0] == "zero":
                    condition = {a.ARM_CC_EQ: flags[1], a.ARM_CC_NE: not flags[1]}.get(ins.cc)
                elif (flags is not None and len(flags) == 2
                        and all(type(value) is int for value in flags)):
                    left, right = flags
                    signed = lambda value: value - (1 << 32) if value & 0x80000000 else value
                    choices = {a.ARM_CC_EQ: left == right, a.ARM_CC_NE: left != right,
                        a.ARM_CC_HS: left >= right, a.ARM_CC_LO: left < right,
                        a.ARM_CC_HI: left > right, a.ARM_CC_LS: left <= right,
                        a.ARM_CC_GE: signed(left) >= signed(right), a.ARM_CC_LT: signed(left) < signed(right),
                        a.ARM_CC_GT: signed(left) > signed(right), a.ARM_CC_LE: signed(left) <= signed(right)}
                    condition = choices.get(ins.cc)
                if condition is not False:
                    enqueue(key, (target, registers, shadow, outputs, flags))
                if condition is True:
                    continue
        elif ins.id == a.ARM_INS_CMP:
            left, right = (operand(op).value() for op in operands)
            flags = (left, right) if left is not None and right is not None else None
        elif ins.id in (a.ARM_INS_LDR, a.ARM_INS_LDRH, a.ARM_INS_LDRB):
            if ins.writeback or len(operands) != 2 or operands[1].type != a.ARM_OP_MEM:
                return None
            address = memory(operands[1])
            width = {a.ARM_INS_LDR: 4, a.ARM_INS_LDRH: 2, a.ARM_INS_LDRB: 1}[ins.id]
            if address is None:
                return None
            if (any(site == pc for site, _address in input_sites)
                    and (width != 2 or (pc, address) not in input_sites)):
                return None
            if capture_load and pc == sense:
                if width != 1 or not 0 <= address < len(image):
                    return None
                dependencies.add((address, 1))
                results.append(address)
                continue
            if frame_model and 0xffff0000 <= address < 0xffff0100:
                if width != 4 or address not in shadow:
                    return None
                value = shadow[address]
            elif descriptor <= address <= descriptor + 0x38 - width:
                offset = address - descriptor
                if width == 4 and offset in (0, 4, 8, 0x10, 0x14, 0x18, 0x20, 0x24, 0x28, 0x34):
                    at = descriptor_rom + offset
                    dependencies.add((at, 4))
                    value = _Bits.constant(struct.unpack_from("<I", image, at)[0])
                elif width == 2 and offset in (0xc, 0x1c, 0x2c):
                    value = shadow.get(address, _Bits(0xffff0000, 0))
                else:
                    return None
            elif width == 2 and (pc, address) in input_sites:
                # A separately proved input reread remains unknown; this
                # permission cannot supply a byte/word read or any store.
                value = _Bits(0xffff0000, 0)
            elif width == 1 and any(start <= address < start + size
                                    for start, size in byte_memory):
                value = shadow.get(address, _Bits(0xffffff00, 0))
            elif (width in (1, 2) and copied_row is not None
                    and copied_row[2] <= address
                    and address + width <= copied_row[2] + copied_row[3]
                    and (width == 1 or address & 1 == 0)):
                copy_at, source, target, _ = copied_row
                at = source + address - target
                if not 0 <= at <= len(image) - width or (width == 2 and at & 1):
                    return None
                if copy_at is not None:
                    dependencies.add((copy_at, 20))
                dependencies.add((at, width))
                if ram_dependencies is not None:
                    ram_dependencies.add((address, width))
                value = _Bits.constant(int.from_bytes(image[at:at + width], "little"))
            elif 0 <= address <= len(image) - width:
                dependencies.add((address, width))
                value = _Bits.constant(int.from_bytes(image[address:address + width], "little"))
            else:
                return None
            registers[operands[0].reg] = value
        elif ins.id == a.ARM_INS_STR:
            if not frame_model or ins.writeback:
                return None
            address = memory(operands[1])
            if address is None or not 0xffff0000 <= address <= 0xffff00fc or address & 3:
                return None
            shadow[address] = operand(operands[0])
        elif ins.id == a.ARM_INS_STRH:
            if capture_load or ins.writeback:
                return None
            address = memory(operands[1])
            value = operand(operands[0])
            if address is None:
                return None
            if address - descriptor in (0xc, 0x1c, 0x2c):
                shadow[address] = _Bits(value.zero | 0xffff0000, value.one & 0xffff)
            elif address in (0x03000660, 0x03000664, 0x03000668, 0x03000720, 0x03000724, 0x03000728):
                outputs[address] = value
            else:
                return None
        elif ins.id == a.ARM_INS_STRB:
            if ins.writeback or len(operands) != 2:
                return None
            address = memory(operands[1])
            value = operand(operands[0])
            value = _Bits(value.zero | 0xffffff00, value.one & 255)
            if address is None:
                return None
            if any(start <= address < start + size for start, size in byte_memory):
                shadow[address] = value
            elif not capture_load and address in byte_ports:
                outputs[address] = value
            else:
                return None
        elif ins.id in (a.ARM_INS_MOV, a.ARM_INS_ADR):
            if len(operands) != 2:
                return None
            if operands[0].reg in (a.ARM_REG_PC, a.ARM_REG_SP):
                return None
            value = operand(operands[1])
            if ins.id == a.ARM_INS_ADR:
                value = _Bits.constant(((pc + 4) & ~3) + operands[1].imm)
            registers[operands[0].reg] = value
            if ins.update_flags:
                flags = None
        elif ins.id in (a.ARM_INS_AND, a.ARM_INS_ORR, a.ARM_INS_BIC, a.ARM_INS_MVN):
            destination = operands[0].reg
            left = operand(operands[0] if len(operands) == 2 else operands[1])
            right = operand(operands[-1])
            if ins.id == a.ARM_INS_MVN:
                value = _Bits(right.one, right.zero)
            elif ins.id == a.ARM_INS_BIC:
                value = left.logical("and", _Bits(right.one, right.zero))
            else:
                value = left.logical("and" if ins.id == a.ARM_INS_AND else "or", right)
            registers[destination] = value
            if ins.update_flags:
                flags = ("zero", value.value() == 0) if value.value() is not None else None
        elif ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR, a.ARM_INS_ADD, a.ARM_INS_SUB, a.ARM_INS_MUL):
            destination = operands[0].reg
            left = operand(operands[0] if len(operands) == 2 else operands[1])
            right = operand(operands[-1]).value()
            value = _Bits()
            if right is not None:
                if ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR):
                    if not 0 <= right <= 31:
                        return None
                    if ins.id == a.ARM_INS_LSL:
                        value = _Bits(((left.zero << right) | ((1 << right) - 1)) & _ALL, left.one << right & _ALL)
                    else:
                        value = _Bits((left.zero >> right) | ((_ALL << (32 - right)) & _ALL) if right else left.zero, left.one >> right)
                elif left.value() is not None:
                    operation = {a.ARM_INS_ADD: lambda: left.value() + right,
                        a.ARM_INS_SUB: lambda: left.value() - right,
                        a.ARM_INS_MUL: lambda: left.value() * right}
                    value = _Bits.constant(operation[ins.id]())
            if destination == a.ARM_REG_SP:
                return None
            if destination == a.ARM_REG_PC:
                if value.value() is None:
                    return None
                next_pc = value.value() & ~1
            else:
                registers[destination] = value
            if ins.update_flags:
                flags = None
        elif ins.id != a.ARM_INS_NOP:
            return None
        enqueue(key, (next_pc, registers, shadow, outputs, flags))
    # A merge is safe because it is one state with multiple incoming edges;
    # a reachable cycle is not, since some feasible execution can avoid sense.
    indegree = {key: 0 for key in graph}
    for successors in graph.values():
        for successor in successors:
            if successor not in indegree:
                return None
            indegree[successor] += 1
    acyclic = [key for key, degree in indegree.items() if degree == 0]
    removed = 0
    while acyclic:
        key = acyclic.pop()
        removed += 1
        for successor in graph[key]:
            indegree[successor] -= 1
            if indegree[successor] == 0:
                acyclic.append(successor)
    if removed != len(graph):
        return None
    if not results or any(result != results[0] for result in results):
        return None
    if capture_registers and (not captured_registers or any(
            state != captured_registers[0] for state in captured_registers)):
        return None
    if capture_registers:
        return results[0], dependencies, captured_registers[0]
    return results[0], dependencies

