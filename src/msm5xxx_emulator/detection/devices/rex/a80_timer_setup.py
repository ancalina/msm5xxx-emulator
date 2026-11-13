"""Shared source queries for timer channel setup and counter conversion."""
from __future__ import annotations

import struct
from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, UNKNOWN_VALUE, facts_for

_STATUS = 0x03000A80
_ENABLE = 0x03000A94
_UPPER_STATUS = 0x03000A84
_UPPER_ENABLE = 0x03000A98
_ARM = 0x030007A0

def _u16(image: bytes, at: int) -> int | None:
    return struct.unpack_from('<H', image, at)[0] if 0 <= at <= len(image) - 2 else None

def _enclosing_thumb_function(image: bytes, site: int):
    """Find a complete Thumb function containing a literal-use site."""
    facts = facts_for(image)
    lower = max(0, site - 0x1000)
    for candidate in range(site & ~1, lower - 1, -2):
        op = _u16(image, candidate)
        if op is None or op & 0xFE00 != 0xB400 or not op & 0x0100:
            continue
        function = facts.function(CodeAddress(candidate, 'thumb'), budget=1024)
        if function.complete and CodeAddress(site, 'thumb') in function.instructions:
            return function
    return None


def _ordered_channel_updates(transforms):
    required = (('ands', 0xDF), ('ands', 0xEF), ('orrs', 2), ('orrs', 1))
    ordered = []
    cursor = -1
    for operation, value in required:
        match = next((item for item in transforms
                      if item[0] == operation and item[1] == value
                      and item[2] > cursor), None)
        if match is None:
            return None
        ordered.append(match)
        cursor = match[2]
    return tuple(ordered)


def _symbolic_step_matches(value, operation, immediate, prior):
    if (getattr(value, 'kind', None) != 'op'
            or getattr(value, 'value', None) != operation
            or len(getattr(value, 'operands', ())) != 2):
        return False
    left, right = value.operands
    is_constant = lambda item: (getattr(item, 'kind', None) == 'const'
                                and getattr(item, 'value', None) == immediate)
    return ((is_constant(left) and right == prior)
            or (is_constant(right) and left == prior))


def _state_load_matches_ram(value, ram_base, ram_size):
    if (getattr(value, 'kind', None) != 'load'
            or not getattr(value, 'operands', ())
            or type(ram_base) is not int or type(ram_size) is not int
            or ram_size <= 0):
        return False
    address = value.operands[0]
    if getattr(address, 'kind', None) != 'const':
        return False
    return ram_base <= address.value < ram_base + ram_size


def _channel_reload_values(reloads):
    pairs = {(address, value) for address, value, _ in reloads}
    return ((0x030007B4, 0x80) in pairs
            and (0x030007B0, 0x80) in pairs)


def _channel_linear_path(edges, instruction_addresses, start, end):
    """Require every instruction in a source sequence to be fallthrough-linked."""
    return all(address in instruction_addresses
               and (CodeAddress(address, 'thumb'),
                    CodeAddress(address + 2, 'thumb')) in edges
               for address in range(start, end, 2))


def _channel_setup(image: bytes, config=None):
    """Prove the reset channel clear/set and the paired reload writes."""
    facts = facts_for(image)
    refs = facts.literal_references(_ARM)
    candidates = {}
    for ref in refs:
        function = _enclosing_thumb_function(image, ref.instruction.address)
        if function is not None:
            candidates[function.entry.address] = function
    valid = []
    for entry, function in candidates.items():
        decoded = [(pc, facts.decode(pc)) for pc in function.instructions]
        decoded = [(pc, ins) for pc, ins in decoded if ins is not None]
        literal_pools = set()
        ops = []
        for pc, ins in decoded:
            literal = facts.literal(pc)
            if literal is not None:
                literal_pools.add(literal.pool)
            ops.append((pc, ins))
        accesses = {access.instruction: access for access in function.accesses
                    if access.operation == 'write' and access.width == 1}
        edges = set(function.control_edges)

        def known_at(use, register):
            value = facts.register_value(function, use, register)
            return value is not UNKNOWN_VALUE and getattr(value, 'kind', None) != 'unknown'

        # Require four ordered transforms of the same loaded state word,
        # each committed as a byte to control+0x0c. This expresses
        # (state & ~0x20 & ~0x10) | 2 | 1, preserving unrelated bits.
        transforms = []
        for index, (pc, ins) in enumerate(ops):
            if ins.mnemonic not in ('ands', 'orrs') or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if dst.type != a.ARM_OP_REG or src.type != a.ARM_OP_REG:
                continue
            source_value = facts.register_value(function, pc, src.reg)
            immediate = (source_value.value if getattr(source_value, 'kind', None) == 'const'
                         else None)
            expected_operation = 'ands' if immediate in (0xDF, 0xEF) else 'orrs'
            if immediate not in (0xDF, 0xEF, 2, 1) or ins.mnemonic != expected_operation:
                continue
            if not known_at(pc, dst.reg):
                continue
            store = next((candidate for candidate in ops[index + 1:index + 3]
                          if candidate[1].mnemonic == 'strb'
                          and candidate[1].operands
                          and candidate[1].operands[0].type == a.ARM_OP_REG
                          and candidate[1].operands[0].reg == dst.reg
                          and candidate[0] in accesses
                          and accesses[candidate[0]].address == _ARM + 0xC), None)
            if (store is not None and _channel_linear_path(edges,
                        {instruction.address for instruction, _ in ops},
                        pc.address, store[0].address)
                    and known_at(store[0], dst.reg)):
                transforms.append((ins.mnemonic, immediate, pc.address,
                                   store[0].address))
        ordered = _ordered_channel_updates(transforms)
        if ordered is None:
            continue
        if len([access for access in accesses.values()
                if access.address == _ARM + 0xC]) != 4:
            continue
        ordered_sites = [site for _, _, site, _ in ordered]
        if any(not (left < right) for left, right in zip(ordered_sites,
                                                         ordered_sites[1:])):
            continue
        first_site, last_site = ordered[0][2], ordered[-1][3]
        instruction_addresses = {pc.address for pc, _ in ops}
        if not _channel_linear_path(edges, instruction_addresses, first_site, last_site):
            continue
        first_pc = CodeAddress(ordered[0][2], 'thumb')
        first_ins = facts.decode(first_pc)
        state = (facts.register_value(function, first_pc, first_ins.operands[0].reg)
                 if first_ins is not None and first_ins.operands else UNKNOWN_VALUE)
        ram_base = getattr(config, 'ram_base', None)
        ram_size = getattr(config, 'ram_size', None)
        if not _state_load_matches_ram(state, ram_base, ram_size):
            continue
        source_address = state.operands[0].value
        if not any(access.operation == 'read' and access.width == 4
                   and access.instruction == state.site
                   and access.address == source_address for access in function.accesses):
            continue
        prior = state
        chain_valid = True
        for operation, immediate, _, store_site in ordered:
            store_pc = CodeAddress(store_site, 'thumb')
            store_ins = facts.decode(store_pc)
            if store_ins is None or not store_ins.operands:
                chain_valid = False
                break
            current = facts.register_value(function, store_pc,
                                           store_ins.operands[0].reg)
            symbolic_operation = 'and' if operation == 'ands' else 'or'
            if not _symbolic_step_matches(current, symbolic_operation, immediate, prior):
                chain_valid = False
                break
            prior = current
        if not chain_valid:
            continue

        # The same source function must program both byte reload registers:
        # A0+0x10+4 (7B4) then A0+0x10 (7B0), both with 0x80.
        reloads = []
        for index, (pc, ins) in enumerate(ops):
            if ins.mnemonic != 'strb' or len(ins.operands) < 2:
                continue
            source, memory = ins.operands[:2]
            if source.type != a.ARM_OP_REG or pc not in accesses or memory.type != a.ARM_OP_MEM:
                continue
            access = accesses[pc]
            if access.address not in (0x030007B0, 0x030007B4):
                continue
            value = facts.register_value(function, pc, source.reg)
            reloads.append((access.address,
                value.value if getattr(value, 'kind', None) == 'const' else None,
                pc.address))
        if not _channel_reload_values(reloads):
            continue
        start = function.entry.address
        end = max(pc.address for pc in function.instructions) + 2
        spans = [[start, end - start], *[[pool, 4] for pool in sorted(literal_pools)]]
        valid.append((start, spans, ordered, reloads))
    return valid[0] if len(valid) == 1 else None


def _counter_contract(reads, scale, bias, divisor, quotient_helper,
                      result_width=2, zero_sentinel=4):
    """Accept the firmware's byte sample and integer quotient contract."""
    return (tuple(reads) == ((0x03000740, 1), (0x03000740, 1), (0x03000740, 1))
            and scale == 100 and bias == 0x3C1 and divisor == 0x782
            and quotient_helper and result_width == 2 and zero_sentinel == 4)


def _counter_reader(image: bytes):
    """Prove the repeated 8-bit counter sample and software conversion."""
    facts = facts_for(image)
    valid = []
    for ref in facts.literal_references(_ARM):
        function = _enclosing_thumb_function(image, ref.instruction.address)
        if function is None:
            continue
        reads = tuple((access.address, access.width) for access in function.accesses
                      if access.operation == 'read' and access.address == 0x03000740)
        if len(reads) != 3 or any(width != 1 for _, width in reads):
            continue
        calls = list(function.calls)
        literals = {literal.value: literal for literal in function.literals}
        if 0x3C1 not in literals or 0x782 not in literals:
            continue
        decoded = [(pc, facts.decode(pc)) for pc in function.instructions]
        decoded = [(pc, ins) for pc, ins in decoded if ins is not None]
        arithmetic = False
        conversion_calls = []
        result_stores = []
        for pc, ins in decoded:
            if ins.mnemonic != 'strh' or len(ins.operands) < 2:
                continue
            source, memory = ins.operands[:2]
            if (source.type == a.ARM_OP_REG and memory.type == a.ARM_OP_MEM
                    and memory.mem.disp in (0, 2)):
                result_stores.append((pc, ins, source.reg, memory.mem.disp))
        if not any(offset == 0 for _, _, _, offset in result_stores) or not any(
                offset == 2 for _, _, _, offset in result_stores):
            continue
        sentinel = any(ins.mnemonic == 'movs' and len(ins.operands) == 2
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[1].type == a.ARM_OP_IMM and ins.operands[1].imm == 4
            and any(candidate.mnemonic == 'strh'
                and candidate.operands[0].type == a.ARM_OP_REG
                and candidate.operands[0].reg == ins.operands[0].reg
                and candidate.operands[1].type == a.ARM_OP_MEM
                and candidate.operands[1].mem.disp == 0
                for _, candidate in decoded[index + 1:index + 3])
            for index, (_, ins) in enumerate(decoded))
        if not sentinel:
            continue
        for index, (pc, ins) in enumerate(decoded):
            if ins.mnemonic != 'muls' or index < 1:
                continue
            if (ins.operands[0].type != a.ARM_OP_REG
                    or ins.operands[1].type != a.ARM_OP_REG
                    or ins.operands[2].type != a.ARM_OP_REG):
                continue
            scale_reg = ins.operands[1].reg
            if not any(prev.mnemonic == 'movs' and len(prev.operands) == 2
                    and prev.operands[0].type == a.ARM_OP_REG
                    and prev.operands[0].reg == scale_reg
                    and prev.operands[1].type == a.ARM_OP_IMM
                    and prev.operands[1].imm == 100
                    for _, prev in decoded[max(0, index - 3):index]):
                continue
            scale_value = facts.register_value(function, pc, scale_reg)
            if getattr(scale_value, 'kind', None) != 'const' or scale_value.value != 100:
                continue
            sample_sites = {access.instruction for access in function.accesses
                if access.operation == 'read' and access.address == 0x03000740
                and access.width == 1}
            sample_origins = facts.register_origins(function, pc, ins.operands[2].reg)
            if not any(site in sample_sites for site, _ in sample_origins):
                continue
            numerator = next((candidate for _, candidate in decoded[index + 1:index + 4]
                if candidate.mnemonic == 'adds' and len(candidate.operands) == 3
                and candidate.operands[0].type == a.ARM_OP_REG
                and candidate.operands[0].reg == a.ARM_REG_R1
                and candidate.operands[1].type == a.ARM_OP_REG
                and candidate.operands[1].reg == a.ARM_REG_R0
                and candidate.operands[2].type == a.ARM_OP_REG
                and candidate.operands[2].reg == a.ARM_REG_R1), None)
            if numerator is None:
                continue
            numerator_pc = next(source_pc for source_pc, candidate in decoded
                                if candidate is numerator)
            bias_value = facts.register_value(function, numerator_pc, a.ARM_REG_R1)
            if getattr(bias_value, 'kind', None) != 'const' or bias_value.value != 0x3C1:
                continue
            add_index = next(i for i, (_, candidate) in enumerate(decoded)
                             if candidate is numerator)
            bias_load = next(((load_pc, candidate) for load_pc, candidate
                in decoded[max(0, index - 3):index]
                if candidate.mnemonic == 'ldr' and candidate.operands
                and candidate.operands[0].type == a.ARM_OP_REG
                and candidate.operands[0].reg == a.ARM_REG_R1
                and facts.literal(load_pc) is not None
                and facts.literal(load_pc).value == 0x3C1), None)
            divisor_load = next(((load_pc, candidate) for load_pc, candidate
                in decoded[add_index + 1:add_index + 3]
                if candidate.mnemonic == 'ldr' and candidate.operands
                and candidate.operands[0].type == a.ARM_OP_REG
                and candidate.operands[0].reg == a.ARM_REG_R0
                and facts.literal(load_pc) is not None
                and facts.literal(load_pc).value == 0x782), None)
            if bias_load is None or divisor_load is None:
                continue
            conversion_calls.extend((site, target) for site, target in calls
                if site.address > divisor_load[0].address
                and getattr(facts.register_value(function, site, a.ARM_REG_R0), 'value', None) == 0x782
                and any(origin.address == numerator.address and register == a.ARM_REG_R1
                        for origin, register in facts.register_origins(function, site,
                                                                      a.ARM_REG_R1)))
            if conversion_calls:
                arithmetic = True
                break
        if not arithmetic:
            continue
        helper = None
        helper_spans = []
        for site, target in calls:
            if not any(candidate.address == target.address
                       and candidate.isa == target.isa
                       and candidate_site.address == site.address
                       for candidate_site, candidate in conversion_calls):
                continue
            if target.isa != 'thumb':
                continue
            bridge = facts.function(target, budget=128)
            bridge_ins = [(pc, facts.decode(pc)) for pc in bridge.instructions]
            if not bridge_ins or not any(ins is not None and ins.mnemonic == 'bx'
                    and ins.op_str.strip() == 'pc' for _, ins in bridge_ins):
                continue
            arm_start = CodeAddress((target.address + 4) & ~3, 'arm', target.phase, target.bank)
            quotient = facts.function(arm_start, budget=256)
            quotient_ops = [(pc, facts.decode(pc)) for pc in quotient.instructions]
            quotient_ops = [(pc, ins) for pc, ins in quotient_ops if ins is not None]
            mnemonics = [ins.mnemonic for _, ins in quotient_ops]
            returns_quotient = any(ins.mnemonic == 'mov'
                and ins.op_str.replace(' ', '') == 'r0,r2'
                and index + 1 < len(quotient_ops)
                and quotient_ops[index + 1][1].mnemonic == 'bx'
                and quotient_ops[index + 1][1].op_str.strip() == 'lr'
                for index, (_, ins) in enumerate(quotient_ops))
            has_divide_loop = (quotient.complete and 'rsbs' in mnemonics
                and 'subhs' in mnemonics and 'adc' in mnemonics and 'adcs' in mnemonics
                and returns_quotient)
            if has_divide_loop:
                helper = quotient
                helper_spans = [[target.address, 4],
                    *[[pc.address, ins.size] for pc, ins in quotient_ops]]
                break
        if not _counter_contract(reads, 100, 0x3C1, 0x782, helper is not None,
                                 result_width=2, zero_sentinel=4):
            continue
        start = function.entry.address
        end = max(pc.address for pc in function.instructions) + 2
        spans = [[start, end - start], *helper_spans]
        spans.extend([[literal.pool, 4] for literal in literals.values()
                      if literal.value in (0x030007A0, 0x14013648, 0x3C1, 0x782)])
        valid.append((spans, reads))
    return valid[0] if len(valid) == 1 else None


def _startup_channel_order(image: bytes, setup_entry: int, timer_entry: int,
                           irq_setter: int):
    """Link channel setup, IRQ enable setup, and timer arm in source order."""
    facts = facts_for(image)
    calls = facts.call_candidates('thumb')
    target_sites = {}
    for site, target in calls:
        target_sites.setdefault(target & ~1, []).append(site)

    managers = {}
    for site in target_sites.get(setup_entry & ~1, ()):
        function = _enclosing_thumb_function(image, site)
        if function is not None and any(target.address == (setup_entry & ~1)
                and target.isa == 'thumb' for _, target in function.calls):
            managers[function.entry.address] = function

    irq_initializers = []
    for site in target_sites.get(irq_setter & ~1, ()):
        body = _enclosing_thumb_function(image, site)
        if body is None:
            continue
        call_to_setter = any(target.address == (irq_setter & ~1)
                             and target.isa == 'thumb' for _, target in body.calls)
        values = {literal.value for literal in body.literals}
        writes = {(access.address, access.width) for access in body.accesses
                  if access.operation == 'write'}
        irq_writes = {(address, width) for address, width in writes
            if (address, width) in ((_STATUS, 4), (_UPPER_STATUS, 1),
                                    (_ENABLE, 4), (_UPPER_ENABLE, 1))}
        if (call_to_setter and _STATUS in values
                and irq_writes == {(_STATUS, 4), (_UPPER_STATUS, 1),
                                   (_ENABLE, 4), (_UPPER_ENABLE, 1)}):
            irq_initializers.append(body)

    for manager in managers.values():
        manager_calls = [site for site in target_sites.get(manager.entry.address, ())]
        for manager_callsite in manager_calls:
            owner = _enclosing_thumb_function(image, manager_callsite)
            if owner is None:
                continue
            owner_calls = [(site.address, target.address, target.isa)
                           for site, target in owner.calls]
            manager_sites = [site for site, target, isa in owner_calls
                             if target == manager.entry.address and isa == 'thumb']
            for irq in irq_initializers:
                irq_sites = [site for site, target, isa in owner_calls
                             if target == irq.entry.address and isa == 'thumb']
                timer_calls = [site for site, target, isa in owner_calls
                               if target == (timer_entry & ~1) and isa == 'thumb']
                for manager_site in manager_sites:
                    for irq_site in irq_sites:
                        for timer_site in timer_calls:
                            if manager_site < irq_site < timer_site:
                                spans = []
                                for body in (manager, irq, owner):
                                    end = max(pc.address for pc in body.instructions) + 2
                                    spans.append([body.entry.address,
                                                  end - body.entry.address])
                                    spans.extend([[literal.pool, 4]
                                                  for literal in body.literals])
                                spans.extend([[site, 4] for site in
                                              (manager_site, irq_site, timer_site)])
                                spans.extend([[site.address, 4] for site, target
                                    in manager.calls if target.address == (setup_entry & ~1)])
                                spans.extend([[site.address, 4] for site, target
                                    in irq.calls if target.address == (irq_setter & ~1)])
                                return spans
    return None


