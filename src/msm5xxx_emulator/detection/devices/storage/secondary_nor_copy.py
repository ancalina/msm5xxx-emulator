"""Prove an ARM/Thumb startup table copies an immutable NOR span to RAM."""
from __future__ import annotations

import struct
from dataclasses import dataclass

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.startup_entry import (
    _manual_wrapper,
    manual_interworking_entries,
    reset_vector_entry,
)


_MAX_STEPS = 8_000_000
_WATCHDOG = 0x030006D0


def _u32(image: bytes, address: int) -> int:
    return struct.unpack_from('<I', image, address)[0]


def _add_interval(intervals, start: int, length: int, source: int | None = None):
    if intervals and intervals[-1][0] + intervals[-1][1] == start:
        previous = intervals[-1]
        if source is None and len(previous) == 2:
            intervals[-1] = (previous[0], previous[1] + length)
            return
        if (source is not None and len(previous) == 3
                and previous[2] + previous[1] == source):
            intervals[-1] = (previous[0], previous[1] + length, previous[2])
            return
    intervals.append((start, length) if source is None else (start, length, source))


def _parse_rows(image: bytes, table: int, ram_base: int, ram_end: int):
    """Yield bounded 3- or 5-word row-table prefixes rooted at a code literal."""
    if table < 0 or table & 3 or table + 12 > len(image):
        return
    for fields in (3, 5):
        rows = []
        for index in range(8):
            at = table + index * fields * 4
            if at + fields * 4 > len(image):
                break
            values = struct.unpack_from('<' + 'I' * fields, image, at)
            source, target, length = values[:3]
            if (not length or (source | target | length) & 3
                    or source + length > len(image)
                    or target < ram_base or target + length > ram_end):
                break
            zero = None
            if fields == 5:
                zero_start, zero_length = values[3:]
                if ((zero_start | zero_length) & 3 or zero_start < ram_base
                        or zero_start + zero_length > ram_end):
                    break
                zero = (zero_start, zero_length)
            rows.append({'table_entry': at, 'source': source, 'target': target,
                         'length': length, 'zero': zero})
            yield tuple(rows)


@dataclass(frozen=True)
class _Value:
    value: int
    source: int | None = None


def _execute_copy_leaf(image: bytes, facts, function, rows, ram_base: int,
                       ram_end: int, required_span: tuple[int, int], *,
                       initial_sp: int | None = None):
    """Boundedly execute the scalar Thumb subset used by linked startup copies."""
    valid_pcs = {pc.address for pc in function.instructions}
    if not valid_pcs or not function.complete or function.unresolved or function.truncated or function.calls:
        return None
    source_ranges = tuple((row['source'], row['source'] + row['length']) for row in rows)
    start_sp = initial_sp if initial_sp is not None else ram_end - 4
    registers = {a.ARM_REG_SP: _Value(start_sp),
                 a.ARM_REG_LR: _Value(0xFFFFFFFE)}
    flags = {'z': False, 'n': False}
    overlay: dict[int, int] = {}
    copy_writes, zero_writes, auxiliary_zero_writes, watchdog_writes = [], [], [], []

    def get(reg):
        if reg not in registers:
            raise ValueError('uninitialized register')
        return registers[reg]

    def check_ram(address, size):
        return size > 0 and ram_base <= address and address + size <= ram_end

    def read(address, size):
        if address < 0 or size not in (1, 2, 4) or address + size > 0x100000000:
            raise ValueError('invalid read')
        raw = bytearray()
        for offset in range(size):
            current = address + offset
            if current in overlay:
                raw.append(overlay[current])
            elif current < len(image):
                raw.append(image[current])
            else:
                raise ValueError('read outside immutable image or initialized RAM')
        value = int.from_bytes(raw, 'little')
        source = address if size == 4 and any(lo <= address and address + 4 <= hi
                                               for lo, hi in source_ranges) else None
        return _Value(value, source)

    def write(address, size, value: _Value):
        if check_ram(address, size):
            transfer_overlap = False
            for row in rows:
                target_ranges = [(row['target'], row['target'] + row['length'])]
                if row['zero'] is not None and row['zero'][1]:
                    target_ranges.append((row['zero'][0], row['zero'][0] + row['zero'][1]))
                if any(address < hi and lo < address + size for lo, hi in target_ranges):
                    transfer_overlap = True
                    copied = (size == 4 and value.source is not None
                        and row['target'] <= address
                        and address + 4 <= row['target'] + row['length']
                        and value.source == row['source'] + address - row['target'])
                    cleared = (size == 4 and value.source is None and value.value == 0
                        and row['zero'] is not None and row['zero'][0] <= address
                        and address + 4 <= row['zero'][0] + row['zero'][1])
                    if not (copied or cleared):
                        raise ValueError('unexpected write inside a table transfer span')
            if (not transfer_overlap and address < required_span[1]
                    and required_span[0] < address + size):
                raise ValueError('unmapped write overlaps the required copied span')
            encoded = (value.value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')
            for offset, byte in enumerate(encoded):
                overlay[address + offset] = byte
            if size == 4 and value.source is not None:
                match = next((row for row in rows
                    if row['target'] <= address and address + 4 <= row['target'] + row['length']
                    and value.source == row['source'] + address - row['target']), None)
                if match is None:
                    raise ValueError('copy provenance does not match row mapping')
                _add_interval(copy_writes, address, 4, value.source)
            elif size == 4 and value.value == 0:
                match = next((row for row in rows if row['zero'] is not None
                    and row['zero'][0] <= address and address + 4 <= sum(row['zero'])), None)
                if match is not None:
                    _add_interval(zero_writes, address, 4)
                else:
                    _add_interval(auxiliary_zero_writes, address, 4)
            return
        if address == _WATCHDOG and size == 1 and value.value in (0, 1):
            watchdog_writes.append(value.value)
            return
        raise ValueError('write outside permitted RAM/watchdog routes')

    def literal_load(pc):
        literal = facts.literal(CodeAddress(pc, 'thumb'))
        if literal is None:
            raise ValueError('unresolved literal')
        return _Value(literal.value)

    def condition(cc):
        if cc in (a.ARM_CC_AL, a.ARM_CC_INVALID):
            return True
        if cc == a.ARM_CC_EQ:
            return flags['z']
        if cc == a.ARM_CC_NE:
            return not flags['z']
        raise ValueError('unsupported branch condition')

    def set_nz(value):
        value &= 0xFFFFFFFF
        flags['z'] = value == 0
        flags['n'] = bool(value & 0x80000000)

    pc = min(valid_pcs)
    steps = 0
    returned = False
    try:
        while steps < _MAX_STEPS:
            if pc not in valid_pcs:
                raise ValueError('control flow leaves the proven leaf')
            ins = facts.decode(CodeAddress(pc, 'thumb'))
            if ins is None:
                raise ValueError('undecodable instruction')
            steps += 1
            next_pc = pc + ins.size
            operands = ins.operands
            if ins.id == a.ARM_INS_LDR and len(operands) == 2:
                dest, mem = operands
                if mem.type != a.ARM_OP_MEM:
                    raise ValueError('unsupported LDR')
                if mem.mem.base == a.ARM_REG_PC:
                    value = literal_load(pc)
                else:
                    address = (get(mem.mem.base).value + mem.mem.disp) & 0xFFFFFFFF
                    value = read(address, 4)
                registers[dest.reg] = value
            elif ins.id in (a.ARM_INS_LDRB, a.ARM_INS_LDRH) and len(operands) == 2:
                dest, mem = operands
                address = get(mem.mem.base).value + mem.mem.disp
                if mem.mem.index:
                    address += get(mem.mem.index).value
                registers[dest.reg] = read(address, 1 if ins.id == a.ARM_INS_LDRB else 2)
            elif ins.id in (a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH) and len(operands) == 2:
                src, mem = operands
                address = get(mem.mem.base).value + mem.mem.disp
                if mem.mem.index:
                    address += get(mem.mem.index).value
                write(address & 0xFFFFFFFF,
                      {a.ARM_INS_STR: 4, a.ARM_INS_STRB: 1, a.ARM_INS_STRH: 2}[ins.id],
                      get(src.reg))
            elif ins.id in (a.ARM_INS_LDM, a.ARM_INS_STM):
                mem = operands[0]
                base = mem.mem.base
                regs = [op.reg for op in operands[1:] if op.type == a.ARM_OP_REG]
                address = get(base).value + mem.mem.disp
                for reg in sorted(regs):
                    if ins.id == a.ARM_INS_LDM:
                        registers[reg] = read(address, 4)
                    else:
                        write(address, 4, get(reg))
                    address += 4
                if mem.mem.base and mem.mem.disp:
                    registers[base] = _Value(address)
                elif getattr(mem.mem, 'index', 0):
                    registers[base] = _Value(address)
                elif ins.writeback:
                    registers[base] = _Value(address)
            elif ins.id in (a.ARM_INS_PUSH, a.ARM_INS_POP):
                regs = sorted(op.reg for op in operands
                              if op.type == a.ARM_OP_REG)
                sp = get(a.ARM_REG_SP).value
                if ins.id == a.ARM_INS_PUSH:
                    sp -= 4 * len(regs)
                    for index, reg in enumerate(regs):
                        # Preserve an incoming callee-saved value without
                        # treating it as a useful scalar input to the routine.
                        value = registers.get(reg, _Value(0xA5A5A5A5))
                        write(sp + index * 4, 4, value)
                    registers[a.ARM_REG_SP] = _Value(sp)
                else:
                    for index, reg in enumerate(regs):
                        value = read(sp + index * 4, 4)
                        if reg == a.ARM_REG_PC:
                            if value.value == 0xFFFFFFFE:
                                returned = True
                                break
                            next_pc = value.value & ~1
                        else:
                            registers[reg] = value
                    registers[a.ARM_REG_SP] = _Value(sp + 4 * len(regs))
            elif ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS):
                dest, src = operands[:2]
                value = _Value(src.imm) if src.type == a.ARM_OP_IMM else get(src.reg)
                registers[dest.reg] = value
                if ins.id == a.ARM_INS_MOVS:
                    set_nz(value.value)
            elif ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB):
                if len(operands) == 2:
                    dest, rhs = operands
                    lhs_value = get(dest.reg)
                else:
                    dest, lhs, rhs = operands[:3]
                    lhs_value = get(lhs.reg) if lhs.type == a.ARM_OP_REG else _Value(lhs.imm)
                rhs_value = get(rhs.reg).value if rhs.type == a.ARM_OP_REG else rhs.imm
                result = ((lhs_value.value + rhs_value) if ins.id == a.ARM_INS_ADD
                          else (lhs_value.value - rhs_value)) & 0xFFFFFFFF
                registers[dest.reg] = _Value(result)
                if ins.update_flags:
                    set_nz(result)
            elif ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR):
                dest, src, amount = operands[:3]
                shift = amount.imm
                value = get(src.reg).value
                result = (value << shift if ins.id == a.ARM_INS_LSL else value >> shift) & 0xFFFFFFFF
                registers[dest.reg] = _Value(result)
                if ins.update_flags:
                    set_nz(result)
            elif ins.id == a.ARM_INS_CMP:
                lhs, rhs = operands[:2]
                right = get(rhs.reg).value if rhs.type == a.ARM_OP_REG else rhs.imm
                set_nz((get(lhs.reg).value - right) & 0xFFFFFFFF)
            elif ins.id == a.ARM_INS_B:
                if condition(ins.cc):
                    next_pc = operands[0].imm
            elif ins.id == a.ARM_INS_BX:
                if operands[0].reg == a.ARM_REG_LR and get(a.ARM_REG_LR).value == 0xFFFFFFFE:
                    returned = True
                else:
                    raise ValueError('unresolved indirect transfer')
            else:
                raise ValueError('unsupported instruction in copy leaf')
            if returned:
                break
            pc = next_pc
        if not returned:
            raise ValueError('copy leaf did not return within budget')
        if get(a.ARM_REG_SP).value != start_sp:
            raise ValueError('copy leaf did not restore its stack')
    except (ValueError, IndexError, KeyError, TypeError, OverflowError):
        return None
    return {'copy_writes': tuple(copy_writes), 'zero_writes': tuple(zero_writes),
            'auxiliary_zero_writes': tuple(auxiliary_zero_writes),
            'watchdog_writes': tuple(watchdog_writes), 'steps': steps}


def _table_candidates(image: bytes, function):
    # A table can reside in ROM while its rows target RAM. Anchor candidates
    # only at literal values loaded by the proven copy leaf.
    values = {literal.value for literal in function.literals
              if type(literal.value) is int and literal.value & 3 == 0
              and 0 <= literal.value < len(image)}
    bases = set()
    for value in values:
        for words_back in range(5):
            base = value - words_back * 4
            if base >= 0 and base + 12 <= len(image):
                bases.add(base)
    return tuple(sorted(bases))


def _ranges_match(actual, expected):
    return tuple(actual) == tuple(expected)


def _spans(ranges):
    merged = []
    for start, end in sorted(set(ranges)):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [list(item) for item in merged]


def _reset_normal_routes(facts, leaf_entry: int | None = None):
    """Link the low-reset return bridge to a normal ARM helper call."""
    reset = reset_vector_entry(facts)
    if reset is None:
        return ()
    root = facts.function(reset, budget=8192, stop_at_initial_return=True)
    if not root.complete or root.truncated or root.unresolved:
        return ()
    initial_entries = tuple(proof for proof in manual_interworking_entries(facts)
                            if proof.reset_entry == reset)
    if not initial_entries:
        return ()
    routes = []
    for transfer, target in root.control_edges:
        if (transfer.isa != 'arm' or target.isa != 'thumb'
                or not root.dominates(reset, transfer)):
            continue
        wrapper = _manual_wrapper(facts, root, transfer, target)
        if wrapper is None:
            continue
        _, literal, return_words, return_targets = wrapper
        svc_entries = tuple(proof for proof in initial_entries
                            if proof.processor_mode == 0x13)
        svc_pointers = {proof.stack_pointer for proof in svc_entries}
        active_svc = svc_entries[0] if len(svc_pointers) == 1 and svc_entries else None
        if active_svc is None or active_svc.stack_site.address >= transfer.address:
            continue
        stack_stable = True
        for pc in root.instructions:
            if not active_svc.stack_site.address < pc.address < transfer.address:
                continue
            instruction = facts.decode(pc)
            if instruction is None or instruction.id in (a.ARM_INS_MSR,
                                                          getattr(a, 'ARM_INS_CPS', -1)):
                stack_stable = False
                break
            try:
                _, written = instruction.regs_access()
            except Exception:
                stack_stable = False
                break
            if a.ARM_REG_SP in written:
                stack_stable = False
                break
        if not stack_stable:
            continue
        thumb_returns = [item for item in return_targets if item.isa == 'thumb']
        for thumb_return in thumb_returns:
            bridge = facts.decode(thumb_return)
            if (bridge is None or bridge.id != a.ARM_INS_BX or len(bridge.operands) != 1
                    or bridge.operands[0].type != a.ARM_OP_REG
                    or bridge.operands[0].reg != a.ARM_REG_PC):
                continue
            arm_entry = (thumb_return.address + 4) & ~3
            compare = facts.decode(CodeAddress(arm_entry, 'arm', reset.phase, reset.bank))
            conditional = facts.decode(CodeAddress(arm_entry + 4, 'arm', reset.phase, reset.bank))
            branch = facts.decode(CodeAddress(arm_entry + 8, 'arm', reset.phase, reset.bank))
            if (compare is None or compare.id != a.ARM_INS_CMP or len(compare.operands) != 2
                    or compare.operands[0].type != a.ARM_OP_REG
                    or compare.operands[0].reg != a.ARM_REG_R0
                    or compare.operands[1].type != a.ARM_OP_IMM
                    or compare.operands[1].imm != 0
                    or conditional is None or conditional.id != a.ARM_INS_B
                    or conditional.cc != a.ARM_CC_NE
                    or branch is None or branch.id != a.ARM_INS_B
                    or branch.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                    or not branch.operands or branch.operands[0].type != a.ARM_OP_IMM):
                continue
            normal_entry = branch.operands[0].imm
            normal_function = facts.function(
                CodeAddress(normal_entry, 'arm', reset.phase, reset.bank), budget=4096)
            for normal_transfer, normal_target in normal_function.control_edges:
                if (normal_transfer.isa != 'arm' or normal_target.isa != 'thumb'
                        or (leaf_entry is not None
                            and normal_target.address != leaf_entry)):
                    continue
                normal_wrapper = _manual_wrapper(
                    facts, normal_function, normal_transfer, normal_target)
                if (normal_wrapper is None
                        or normal_wrapper[1].value != (normal_target.address | 1)):
                    continue
                reset_sp = active_svc.stack_pointer
                evidence = set(root.instructions)
                evidence.update(normal_function.instructions)
                evidence_code = {(pc.address, pc.address + facts.decode(pc).size)
                                 for pc in evidence if facts.decode(pc) is not None}
                evidence_literals = { (item.pool, item.pool + 4)
                    for item in (*root.literals, *normal_function.literals) }
                evidence_literals.update((pool, pool + 4) for pool, _ in return_words)
                evidence_literals.add((literal.pool, literal.pool + 4))
                routes.append({
                    'leaf_entry': normal_target.address,
                    'reset_entry': reset.address,
                    'reset_transfer': transfer.address,
                    'reset_target': target.address,
                    'return_thumb': thumb_return.address,
                    'return_arm': arm_entry,
                    'normal_entry': normal_entry,
                    'normal_transfer': normal_transfer.address,
                    'stack_pointer': reset_sp,
                    'processor_mode': 0x13,
                    'evidence_spans': _spans(evidence_code | evidence_literals),
                })
    return tuple(routes)


def find_copy_source(image: bytes, ram_base: int, ram_size: int,
                     required_span: tuple[int, int], expected_object: int) -> dict | None:
    """Prove ``[start,end)`` is copied from ROM to RAM, not subsequently zeroed.

    Three-word rows describe source, target, and copy length; five-word rows
    add a zero-fill range. Admission requires a reset-linked interworking route,
    exact execution of the selected row, no other write over the required span,
    and the mapped source word equal to ``expected_object``.
    """
    if (not isinstance(image, (bytes, bytearray)) or type(ram_base) is not int
            or type(ram_size) is not int or ram_base < 0 or ram_size <= 0
            or ram_base + ram_size > 0x100000000
            or not isinstance(required_span, tuple) or len(required_span) != 2
            or any(type(value) is not int for value in required_span)
            or required_span[0] < ram_base or required_span[0] >= required_span[1]
            or required_span[1] > ram_base + ram_size
            or type(expected_object) is not int or not 0 <= expected_object <= 0xFFFFFFFF):
        return None
    image = bytes(image)
    facts = facts_for(image)
    reset_entries = manual_interworking_entries(facts)
    linked = {}
    for proof in reset_entries:
        if proof.target.isa == 'thumb':
            linked.setdefault(proof.target.address, []).append({
                'kind': 'reset-interwork',
                'reset_entry': proof.reset_entry.address,
                'transfer': proof.transfer.address,
                'stack_site': proof.stack_site.address,
                'stack_pointer': proof.stack_pointer,
                'processor_mode': proof.processor_mode,
                'return_targets': [[item.address, item.isa]
                                   for item in proof.return_targets],
                'evidence_spans': _spans(set(proof.source_spans)
                    | set(proof.code_spans) | set(proof.literal_spans)),
                'interwork': [[proof.transfer.address - 16,
                               proof.transfer.address]],
            })
    for route in _reset_normal_routes(facts):
        linked.setdefault(route['leaf_entry'], []).append({
            'kind': 'reset-return-bridge', **route,
            'interwork': [[route['normal_transfer'] - 16,
                           route['normal_transfer']]],
        })
    if not linked:
        return None
    ram_end = ram_base + ram_size
    profiles = []
    for entry, guards_for_entry in linked.items():
        interwork_sites = [tuple(item) for guard in guards_for_entry
                           for item in guard['interwork']]
        function = facts.function(CodeAddress(entry, 'thumb'), budget=4096)
        if (not function.complete or function.unresolved or function.truncated
                or function.calls or len(function.instructions) < 8
                or not function.back_edges):
            continue
        tables = _table_candidates(image, function)
        insns = tuple(facts.decode(pc) for pc in function.instructions)
        if (not any(ins is not None and ins.id == a.ARM_INS_LDM for ins in insns)
                or not any(ins is not None and ins.id == a.ARM_INS_STM for ins in insns)):
            continue
        for table in tables:
            for rows in _parse_rows(image, table, ram_base, ram_end):
                covering = [row for row in rows
                    if row['target'] <= required_span[0]
                    and required_span[1] <= row['target'] + row['length']]
                if len(covering) != 1:
                    continue
                row = covering[0]
                source_at = row['source'] + required_span[0] - row['target']
                if (source_at + 4 > len(image)
                        or _u32(image, source_at) != expected_object):
                    continue
                for guard in guards_for_entry:
                    result = _execute_copy_leaf(
                        image, facts, function, rows, ram_base, ram_end,
                        required_span, initial_sp=guard['stack_pointer'])
                    if result is None:
                        continue
                    expected_copies = tuple((item['target'], item['length'], item['source'])
                                            for item in rows)
                    actual_copies = tuple(sorted(result['copy_writes']))
                    if not _ranges_match(actual_copies, tuple(sorted(expected_copies))):
                        continue
                    expected_zeros = tuple((item['zero'][0], item['zero'][1])
                                           for item in rows if item['zero'] is not None
                                           and item['zero'][1])
                    if not _ranges_match(tuple(sorted(result['zero_writes'])),
                                         tuple(sorted(expected_zeros))):
                        continue
                    if (any(item['zero'] is None for item in rows)
                            and result['auxiliary_zero_writes']):
                        continue
                    all_zero_writes = result['zero_writes'] + result['auxiliary_zero_writes']
                    if any(start < required_span[1] and required_span[0] < start + length
                           for start, length in all_zero_writes):
                        continue
                    evidence = {(pc.address, pc.address + facts.decode(pc).size)
                                for pc in function.instructions}
                    evidence.update((literal.pool, literal.pool + 4)
                                    for literal in function.literals)
                    evidence.update(tuple(item) for item in guard['evidence_spans'])
                    evidence.add((table, table + (20 if rows[0]['zero'] is not None else 12)))
                    evidence.add((source_at, source_at + 4))
                    profiles.append({
                        'signature': 'linked-ram-copy-table-v1',
                        'entry': entry | 1,
                        'interwork': [list(item) for item in interwork_sites],
                        'reset_link': guard,
                        'stack_pointer': guard['stack_pointer'],
                        'table': table,
                        'rows': rows,
                        'required_span': list(required_span),
                        'copy_source': source_at,
                        'expected_object': expected_object,
                        'copy_writes': [list(item) for item in result['copy_writes']],
                        'zero_writes': [list(item) for item in result['zero_writes']],
                        'watchdog_writes': len(result['watchdog_writes']),
                        'instruction_steps': result['steps'],
                        'evidence_spans': _spans(evidence),
                    })
    unique = {(item['entry'], item['table'], tuple(item['required_span'])) for item in profiles}
    return profiles[0] if len(unique) == 1 else None
