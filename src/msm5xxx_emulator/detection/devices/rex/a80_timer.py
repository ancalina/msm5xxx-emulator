"""Source proof for the A80 timer and its REX interrupt route."""
from __future__ import annotations

import struct
from capstone import arm as a

from msm5xxx_emulator.detection.arm import arm_b_word_target
from msm5xxx_emulator.detection.fact_memory_map import detect_linker_memory_map
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


_STATUS = 0x03000A80
_ENABLE = 0x03000A94
_UPPER_STATUS = 0x03000A84
_UPPER_ENABLE = 0x03000A98
_ARM = 0x030007A0
_MASK = 0x200
_ROW_SIZE = 0x1C
_TIMER_INDEX = 0x25


def _u16(image: bytes, at: int) -> int | None:
    return struct.unpack_from('<H', image, at)[0] if 0 <= at <= len(image) - 2 else None


def _u32(image: bytes, at: int) -> int | None:
    return struct.unpack_from('<I', image, at)[0] if 0 <= at <= len(image) - 4 else None


def _thumb_branch_target(image: bytes, at: int) -> int | None:
    return facts_for(image).thumb_call_target(at)


def _timer_init(image: bytes) -> tuple[int, int, int, list[list[int]]] | None:
    """Find arm=2, then the matching row-37 callback registration."""
    facts = facts_for(image)
    pattern = b'\x02\x20\x08\x70'
    found = []
    at = 0
    while (at := image.find(pattern, at)) >= 0:
        store = at + 2
        arm_load, callback_load = store - 4, store + 2
        register_call = store + 6
        if (_u16(image, arm_load) is None or _u16(image, arm_load) & 0xF800 != 0x4800
                or _u16(image, callback_load) is None or _u16(image, callback_load) & 0xF800 != 0x4800
                or _u16(image, store + 4) != 0x2025):
            at += 2
            continue
        if (facts.thumb_literal_value(arm_load, 1) != _ARM
                or facts.thumb_literal_value(callback_load, 1) is None):
            at += 2
            continue
        callback = facts.thumb_literal_value(callback_load, 1)
        registrar = _thumb_branch_target(image, register_call)
        if callback is None or not callback & 1 or registrar is None:
            at += 2
            continue
        arm_literal = facts.literal(CodeAddress(arm_load, 'thumb'))
        callback_literal = facts.literal(CodeAddress(callback_load, 'thumb'))
        if (arm_literal is None or callback_literal is None
                or arm_literal.value != _ARM or callback_literal.value != callback):
            at += 2
            continue
        # Find the enclosing Thumb function prologue. The caller/linkage is
        # verified later from reset-owned source references.
        init = None
        for candidate in range(store - 2, max(-1, store - 0x100), -2):
            op = _u16(image, candidate)
            if op is not None and op & 0xFE00 == 0xB400 and op & 0x0100:
                init = candidate
                break
        if init is None:
            at += 2
            continue
        found.append((init, callback & ~1, registrar, [[init, store + 10 - init],
            [arm_load, 2], [store, 4], [callback_load, 2],
            [store + 4, 2], [register_call, 4],
            [arm_literal.pool, 4], [callback_literal.pool, 4]]))
        at += 2
    return found[0] if len(found) == 1 else None


def _registration(image: bytes, entry: int) -> tuple[int, list[list[int]]] | None:
    """Require a 28-byte registration row with callback at +0x14."""
    facts = facts_for(image)
    end = min(len(image), entry + 0xA0)
    words = [_u16(image, p) for p in range(entry, end - 1, 2)]
    table_values = []
    stride_at = []
    callback_store = False
    for i, word in enumerate(words):
        pc = entry + 2 * i
        if word == 0x201C and i + 3 < len(words):
            load = words[i + 1]
            # MULS r0,r5,r0; ADDS r0,r0,r1 follows the table-base literal.
            if (load is not None and load & 0xF800 == 0x4800 and load >> 8 & 7 == 1
                    and words[i + 2] & 0xFFC0 == 0x4340
                    and words[i + 3] & 0xFE00 == 0x1800):
                base = facts.thumb_literal_value(pc + 2, 1)
                if base is not None:
                    table_values.append((base, pc, pc + 2))
        if word is not None and word & 0xF800 == 0x6000 and (word >> 6 & 0x1F) * 4 == 0x14:
            callback_store = True
    for base, pc, load_pc in table_values:
        if callback_store and base & 3 == 0:
            literal = facts.literal(CodeAddress(load_pc, 'thumb'))
            if literal is not None and literal.value == base:
                stride_at.append((base, pc, load_pc, literal.pool))
    return ((stride_at[0][0], [[entry, end - entry], [stride_at[0][1], 8],
                [stride_at[0][3], 4]]) if len(stride_at) == 1 else None)


def _callback(image: bytes, entry: int) -> list[list[int]] | None:
    """Require both 5- and 10-unit scheduling paths in the callback."""
    facts = facts_for(image)
    if entry < 0 or entry + 0x50 > len(image):
        return None
    function = facts.function(CodeAddress(entry, 'thumb'), budget=256)
    if not function.instructions or not function.complete:
        return None
    body = image[entry:entry + 0x50]
    # The callback increments a halfword counter, wraps at 40, and chooses
    # 5 units normally or 10 units on wrap before calling the timer service.
    words = struct.unpack_from('<40H', body)
    if (words[0] & 0xF800 != 0x4800 or words[0] >> 8 & 7 != 1
            or words[1] & 0xFE00 != 0xB400):
        return None
    five = [i for i, op in enumerate(words) if op == 0x2405]
    ten = [i for i, op in enumerate(words) if op == 0x240A]
    if not five or not ten or not any(op == 0x2828 for op in words):
        return None
    calls = []
    for i in range(0, len(words) - 1):
        pc = entry + i * 2
        if words[i] & 0xF800 == 0xF000 and words[i + 1] & 0xF800 == 0xF800:
            target = facts.thumb_call_target(pc)
            if target is not None:
                calls.append((i, target))
    if len(calls) < 4:
        return None
    # The compare at 40 separates the 5-unit path from the 10-unit wrap path.
    # Its conditional branch must skip the 10 assignment and rejoin a shared
    # timer-call sequence, so both values are actually schedulable.
    compare = next((i for i, op in enumerate(words) if op == 0x2828), None)
    branch = (facts.decode(CodeAddress(entry + 2 * (compare + 1), 'thumb'))
              if compare is not None and compare + 1 < len(words) else None)
    target = (branch.operands[0].imm if branch is not None
              and branch.id == a.ARM_INS_B and branch.cc != a.ARM_CC_AL
              and branch.operands else None)
    if (target is None or not any(entry + 2 * i < target for i in ten)
            or not any(entry + 2 * index >= target for index, _ in calls)):
        return None
    return [[entry, 0x50], *[[entry + 2 * i, 4] for i, _ in calls],
            *[[literal.pool, 4] for literal in function.literals]]


def _source_copy(image: bytes, config, target: int, length: int, expected: int):
    """Use reset-linked source mapping and require the copied image word."""
    ram_base = getattr(config, 'ram_base', None)
    ram_size = getattr(config, 'ram_size', None)
    if (type(ram_base) is not int or type(ram_size) is not int
            or not ram_base <= target < target + length <= ram_base + ram_size):
        return None
    memory_map, status = detect_linker_memory_map(image)
    if memory_map is None or status != 'accepted':
        return None
    region = next((item for item in memory_map.get('regions', ())
        if item.get('kind') == 'rw-copy' and item.get('exec') <= target
        and target + length <= item.get('exec') + item.get('size')), None)
    if region is None:
        return None
    source = region.get('load')
    if type(source) is not int or _u32(image, source + target - region['exec']) != expected:
        return None
    guards = [[region['evidence']['table_offset'], 20], [source + target - region['exec'], length]]
    for item in region['evidence'].get('references', ()):
        for key in ('instruction', 'literal', 'dereference'):
            site = item.get(key)
            if type(site) is int:
                guards.append([site, 4])
    return source + target - region['exec'], guards


def _typed_irq_access_contract(accesses):
    required = {
        ('read', _STATUS, 4), ('read', _UPPER_STATUS, 1),
        ('write', _STATUS, 4), ('write', _UPPER_STATUS, 1),
        ('write', _ENABLE, 4), ('write', _UPPER_ENABLE, 1),
    }
    return required <= set(accesses)


def _dispatcher_body(image: bytes, entry: int, table: int, callback: int) -> list[list[int]] | None:
    """Check typed status sampling, the row layout and same-mask ACK."""
    facts = facts_for(image)
    if entry < 0 or entry + 0x200 > len(image):
        return None
    function = facts.function(CodeAddress(entry, 'thumb'), budget=1024)
    if not function.instructions or not function.complete or len(function.instructions) < 40:
        return None
    decoded = [facts.decode(pc) for pc in function.instructions]
    ops = [(ins.address, ins.mnemonic, ins.op_str) for ins in decoded if ins is not None]
    text = '\n'.join(f'{mnemonic} {operands}' for _, mnemonic, operands in ops)
    accesses = {(access.operation, access.address, access.width)
                for access in function.accesses}
    typed = _typed_irq_access_contract(accesses)
    if not (typed and any(ins.mnemonic in ('mul', 'muls') for ins in decoded if ins)
            and '#0x1c' in text and '#0x14' in text):
        return None
    # The row's mask at +8 must reach a hardware status write through shared
    # use-def facts. Its pointer at +0 and mask are checked in the copied row.
    ack = False
    for access in function.accesses:
        if (access.operation != 'write' or access.address != _STATUS
                or access.width != 4):
            continue
        write = facts.decode(access.instruction)
        if write is None or not write.operands or write.operands[0].type != a.ARM_OP_REG:
            continue
        value_reg = write.operands[0].reg
        for origin, origin_reg in facts.register_origins(
                function, access.instruction, value_reg):
            load = facts.decode(origin)
            if (origin_reg == value_reg and load is not None and load.mnemonic == 'ldr'
                    and len(load.operands) >= 2
                    and load.operands[1].type == a.ARM_OP_MEM
                    and load.operands[1].mem.disp == 8):
                ack = True
                break
        if ack:
            break
    if not ack:
        return None
    # Require the copied table row's exact hardware tuple and the callback code
    # address used by the installer, not merely a nearby table-shaped object.
    memory_map, status = detect_linker_memory_map(image)
    if memory_map is None or status != 'accepted':
        return None
    row_address = table + _TIMER_INDEX * _ROW_SIZE
    row = None
    region = next((item for item in memory_map.get('regions', ())
        if item.get('kind') == 'rw-copy' and item.get('exec') <= row_address
        and row_address + _ROW_SIZE <= item.get('exec') + item.get('size')), None)
    if region is not None:
        source = region['load'] + row_address - region['exec']
        raw = image[source:source + _ROW_SIZE]
        if len(raw) == _ROW_SIZE:
            row = struct.unpack('<7I', raw)
            # The pointer cells are initialized from the source image too.
            if row[0:3] != (_STATUS, _ENABLE, _MASK):
                row = None
    if row is None or callback & ~1 == 0:
        return None
    return [[entry, max(pc.address for pc in function.instructions) + 2 - entry],
            *[[literal.pool, 4] for literal in function.literals]]


def _setter_slot(image: bytes, setter: int, selector: int) -> tuple[int, list[list[int]]] | None:
    """Resolve the setter's selector branch to its corresponding pointer cell."""
    facts = facts_for(image)
    function = facts.function(CodeAddress(setter, 'thumb'), budget=64)
    if (not function.instructions or not function.complete or function.truncated
            or function.unresolved or function.calls or selector not in (0, 1)):
        return None
    instructions = [(pc, facts.decode(pc)) for pc in function.instructions]
    instructions = [(pc, ins) for pc, ins in instructions if ins is not None]
    comparisons = [(index, pc, ins) for index, (pc, ins) in enumerate(instructions)
                   if ins.id == a.ARM_INS_CMP and len(ins.operands) == 2
                   and ins.operands[0].type == a.ARM_OP_REG
                   and ins.operands[0].reg == a.ARM_REG_R0
                   and ins.operands[1].type == a.ARM_OP_IMM
                   and ins.operands[1].imm == 0]
    if len(comparisons) != 1:
        return None
    compare_index, compare_pc, _ = comparisons[0]
    for _, ins in instructions[:compare_index]:
        _, writes = ins.regs_access()
        if a.ARM_REG_R0 in writes:
            return None
    if compare_index + 1 >= len(instructions):
        return None
    branch_pc, branch = instructions[compare_index + 1]
    if (branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_NE
            or branch_pc.address != compare_pc.address + 2
            or not branch.operands or branch.operands[0].type != a.ARM_OP_IMM):
        return None
    taken_target = branch.operands[0].imm
    edges = set(function.control_edges)
    if ((compare_pc, branch_pc) not in edges
            or (branch_pc, CodeAddress(branch_pc.address + 2, 'thumb')) not in edges
            or (branch_pc, CodeAddress(taken_target, 'thumb')) not in edges):
        return None
    stores = []
    for index, (pc, ins) in enumerate(instructions):
        if (ins.id != a.ARM_INS_STR or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[0].reg != a.ARM_REG_R1
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.base != a.ARM_REG_R2
                or ins.operands[1].mem.index != 0 or ins.writeback):
            continue
        if index + 1 >= len(instructions) or instructions[index + 1][1].id != a.ARM_INS_BX:
            continue
        following = instructions[index + 1][1]
        if (not following.operands or following.operands[0].type != a.ARM_OP_REG
                or following.operands[0].reg != a.ARM_REG_LR):
            continue
        stores.append((index, pc, ins))
    if len(stores) != 2:
        return None
    fallthrough = [item for item in stores
                   if branch_pc.address < item[1].address < taken_target]
    taken = [item for item in stores if item[1].address == taken_target]
    if len(fallthrough) != 1 or len(taken) != 1:
        return None
    if fallthrough[0][1].address != branch_pc.address + 2:
        return None
    for _, ins in instructions:
        _, writes = ins.regs_access()
        if a.ARM_REG_R1 in writes:
            return None
    if any((store_pc, instructions[index + 1][0]) not in edges
           or instructions[index + 1][0].address != store_pc.address + 2
           for index, store_pc, _ in stores):
        return None
    _, selected_pc, selected_store = (
        fallthrough[0] if selector == 0 else taken[0])
    base_value = facts.register_value(function, selected_pc, a.ARM_REG_R2)
    if getattr(base_value, 'kind', None) != 'const':
        return None
    base = base_value.value
    base_literals = [facts.literal(pc) for pc, ins in instructions
                     if ins.id == a.ARM_INS_LDR and len(ins.operands) >= 2
                     and ins.operands[0].type == a.ARM_OP_REG
                     and ins.operands[0].reg == a.ARM_REG_R2
                     and ins.operands[1].type == a.ARM_OP_MEM
                     and ins.operands[1].mem.base == a.ARM_REG_PC]
    if (len(base_literals) != 1 or base_literals[0] is None
            or base_literals[0].value != base):
        return None
    literal = base_literals[0]
    displacement = selected_store.operands[1].mem.disp
    if displacement < 0 or displacement & 3:
        return None
    extent = max(pc.address for pc, _ in instructions) + 2 - setter
    return base + displacement, [[setter, extent], [literal.pool, 4]]


def _wrapper_loads_slot(image: bytes, wrapper: int, slot: int) -> list[list[int]] | None:
    """Require the vector's ARM wrapper to load and branch through the slot."""
    facts = facts_for(image)
    refs = [item for item in facts.literal_references(slot)
        if item.instruction.isa == 'arm'
        and wrapper <= item.instruction.address < wrapper + 0x400]
    function = facts.function(CodeAddress(wrapper, 'arm'), budget=512)
    if not function.instructions:
        return None
    owned = {pc.address for pc in function.instructions}
    edges = set(function.control_edges)
    for item in refs:
        if item.instruction.address not in owned:
            continue
        literal_ins = facts.decode(item.instruction)
        if (literal_ins is None or literal_ins.id != a.ARM_INS_LDR
                or len(literal_ins.operands) < 2
                or literal_ins.operands[0].type != a.ARM_OP_REG):
            continue
        reg = literal_ins.operands[0].reg
        insns = [(pc, facts.decode(pc)) for pc in function.instructions]
        for index, (pc, ins) in enumerate(insns):
            if pc.address != item.instruction.address or ins is None:
                continue
            for load_index in range(index + 1, min(index + 3, len(insns))):
                _, load = insns[load_index]
                if (load is None or load.id != a.ARM_INS_LDR or len(load.operands) < 2
                        or load.operands[0].type != a.ARM_OP_REG
                        or load.operands[0].reg != reg
                        or load.operands[1].type != a.ARM_OP_MEM
                        or load.operands[1].mem.base != reg
                        or load.operands[1].mem.index != 0
                        or load.operands[1].mem.disp != 0):
                    continue
                bx = None
                for bx_index in range(load_index + 1, min(load_index + 6, len(insns))):
                    bx_pc, candidate = insns[bx_index]
                    if candidate is None:
                        continue
                    if (candidate.id == a.ARM_INS_BX and candidate.operands
                            and candidate.operands[0].type == a.ARM_OP_REG
                            and candidate.operands[0].reg == reg):
                        bx = (bx_index, bx_pc)
                        break
                    _, writes = candidate.regs_access()
                    if reg in writes:
                        break
                if bx is not None:
                    start = item.instruction.address
                    end = bx[1].address + 4
                    path = [insns[path_index][0] for path_index in
                            range(index, bx[0] + 1)]
                    if any((left, right) not in edges
                           for left, right in zip(path, path[1:])):
                        continue
                    return [[start, 4], [item.pool, 4], [start, end - start]]
    return None


from .a80_timer_setup import (
    _channel_setup,
    _counter_reader,
    _startup_channel_order,
)


def find_a80_timer(image: bytes, config) -> dict[str, object] | None:
    """Return a source-closed timer controller profile, or decline safely."""
    if not isinstance(image, bytes) or not image:
        return None
    facts = facts_for(image)
    init = _timer_init(image)
    if init is None:
        return None
    init_entry, callback, registrar, init_spans = init
    callback_spans = _callback(image, callback)
    registration = _registration(image, registrar)
    if callback_spans is None or registration is None:
        return None
    table, registration_spans = registration
    # The dispatch table belongs to a reset-linked initialized RAM extent.
    # Read its matching ROM row through that source/target relation.
    memory_map, map_status = detect_linker_memory_map(image)
    if memory_map is None or map_status != 'accepted':
        return None
    row_address = table + _TIMER_INDEX * _ROW_SIZE
    row_region = next((item for item in memory_map.get('regions', ())
        if item.get('kind') == 'rw-copy' and item.get('exec') <= row_address
        and row_address + _ROW_SIZE <= item.get('exec') + item.get('size')), None)
    if row_region is None or type(row_region.get('load')) is not int:
        return None
    row_source_at = row_region['load'] + row_address - row_region['exec']
    raw_row = image[row_source_at:row_source_at + _ROW_SIZE]
    if len(raw_row) != _ROW_SIZE:
        return None
    source_row = struct.unpack('<7I', raw_row)
    if source_row[0:3] != (_STATUS, _ENABLE, _MASK):
        return None
    row_source_spans = [[row_source_at, _ROW_SIZE],
        [row_region['evidence']['table_offset'], 20]]
    for reference in row_region['evidence'].get('references', ()):
        for key in ('instruction', 'literal', 'dereference'):
            site = reference.get(key)
            if type(site) is int:
                row_source_spans.append([site, 4])
    # The installed dispatcher is supplied as a source literal to the reset
    # linked controller setup, then selected by its typed A80/A84 register use.
    dispatchers = []
    at = 0
    while (at := image.find(b'\x00\x20', at)) >= 0:
        selector = at
        load = selector - 2
        call = selector + 2
        op = _u16(image, load)
        if op is not None and op & 0xF800 == 0x4800 and op >> 8 & 7 == 1:
            value = facts.thumb_literal_value(load, 1)
            target = _thumb_branch_target(image, call)
            literal = facts.literal(CodeAddress(load, 'thumb'))
            if (value is not None and value & 1 and target is not None
                    and literal is not None and literal.value == value):
                dispatchers.append((value & ~1, target, selector, load,
                                    literal.pool, call))
        at += 2
    proof = None
    for dispatcher, setter, selector, load, dispatcher_pool, register_call in dispatchers:
        selector_ins = facts.decode(CodeAddress(selector, 'thumb'))
        selector_value = (selector_ins.operands[1].imm
            if selector_ins is not None and selector_ins.id == a.ARM_INS_MOV
            and len(selector_ins.operands) == 2
            and selector_ins.operands[0].type == a.ARM_OP_REG
            and selector_ins.operands[0].reg == a.ARM_REG_R0
            and selector_ins.operands[1].type == a.ARM_OP_IMM else None)
        slot = (_setter_slot(image, setter, selector_value)
                if selector_value in (0, 1) else None)
        if slot is None:
            continue
        body = _dispatcher_body(image, dispatcher, table, callback)
        if body is not None:
            proof = (dispatcher, setter, selector, load, dispatcher_pool,
                     register_call, body, slot)
            break
    if proof is None:
        return None
    (dispatcher, setter, selector, load, dispatcher_pool, register_call,
     dispatcher_spans, setter_proof) = proof
    channel = _channel_setup(image, config)
    counter = _counter_reader(image)
    startup_spans = (_startup_channel_order(image, channel[0], init_entry, setter)
                     if channel is not None else None)
    if channel is None or counter is None or startup_spans is None:
        return None
    # Reset vectors must reach the RAM vector trampoline, and the ROM copy row
    # must supply the first instruction executed from that RAM vector.
    vectors = facts.vectors()
    irq = next(((site, target) for site, target in vectors
        if site.address == 0x18 and site.isa == 'arm'), None)
    if irq is None:
        return None
    vector_target = irq[1].address
    ins = facts.decode(CodeAddress(vector_target, 'arm'))
    if ins is None or ins.mnemonic != 'ldr' or 'pc' not in ins.op_str:
        return None
    # The vector's ldr pc literal is an active RAM copy target. The copy source
    # proof is tied to the source instruction word at that target.
    if len(ins.operands) < 2 or ins.operands[1].mem.base != 11:
        return None
    pool = vector_target + 8 + ins.operands[1].mem.disp
    copied_target = _u32(image, pool)
    if copied_target is None:
        return None
    wrapper_copy = _source_copy(image, config, copied_target, 12, 0xEA000000)
    if wrapper_copy is None:
        return None
    source, copy_spans = wrapper_copy
    first_branch = _u32(image, source)
    second_branch = _u32(image, source + 4)
    wrapper_word = _u32(image, source + 8)
    if (arm_b_word_target(first_branch, copied_target) != copied_target + 8
            or arm_b_word_target(second_branch, copied_target + 4) != copied_target + 16
            or wrapper_word != 0xE51FF004 or _u32(image, source + 12) is None):
        return None
    wrapper = _u32(image, source + 12)
    wrapper_ins = facts.decode(CodeAddress(wrapper, 'arm'))
    if wrapper_ins is None:
        return None
    slot_address, setter_spans = setter_proof
    wrapper_spans = _wrapper_loads_slot(image, wrapper, slot_address)
    if wrapper_spans is None:
        return None
    spans = [*init_spans, *callback_spans, *registration_spans,
        *dispatcher_spans, *row_source_spans, *copy_spans,
        *setter_spans, *wrapper_spans,
        *channel[1], *counter[0], *startup_spans,
        [init_entry, 16], [setter, 2], [load, 2], [dispatcher_pool, 4],
        [selector, 2], [register_call, 4], [irq[0].address, 4],
        [vector_target, 4], [wrapper, 4], [pool, 4], [source + 12, 4]]
    merged = []
    for start, size in sorted({(int(start), int(size)) for start, size in spans}):
        end = start + size
        if merged and start <= merged[-1][0] + merged[-1][1]:
            merged[-1][1] = max(merged[-1][0] + merged[-1][1], end) - merged[-1][0]
        else:
            merged.append([start, size])
    return {
        'parameters': {
            'status': _STATUS, 'enable': _ENABLE,
            'upper_status': _UPPER_STATUS, 'upper_enable': _UPPER_ENABLE,
            'arm': _ARM, 'arm_value': 2, 'mask': _MASK,
            'clock_control': _ARM + 0xC, 'clock_mask': 0x33,
            'clock_value': 3, 'reload0': _ARM + 0x10,
            'reload1': _ARM + 0x14, 'reload_value': 0x80,
            'period_ns': 5_000_000,
        },
        'counter_contract': {
            'address': 0x03000740, 'read_width': 1, 'samples': 3,
            'scale': 100, 'bias': 0x3C1, 'divisor': 0x782,
            'result_width': 2, 'zero_sentinel': 4,
            'conversion': 'floor((100 * sample + 961) / 1922)',
            'clock_frequency_hz': None,
        },
        'table': table, 'timer_index': _TIMER_INDEX, 'callback': callback,
        'dispatcher': dispatcher, 'irq_wrapper': wrapper,
        'evidence_spans': merged,
    }
