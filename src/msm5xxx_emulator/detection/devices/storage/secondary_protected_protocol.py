"""Closed source proofs for the secondary protected-NOR command path."""
from __future__ import annotations

from capstone import CS_GRP_JUMP
from capstone import arm as a

from msm5xxx_emulator.detection.contracts import BodySpec
from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.values import SymbolicValue

from .secondary_query_address import selector_query_address


_ID_OFFSET = 0xA4
_SUPPORTED_MASK = 0x3F
_ADDRESS_FLOOR = 0x10000000

_IDENTIFY_BASE_PROBE = BodySpec(
    size=14,
    words=((0, 0x2100, 0xFFFF), (2, 0x20F3, 0xFFFF),
           (4, 0x8008, 0xFFFF), (6, 0x2109, 0xFFFF),
           (8, 0x0649, 0xFFFF), (10, 0x8008, 0xFFFF),
           (12, 0x4770, 0xFFFF)),
)


def _const_int(value):
    if type(value) is int:
        return value
    if isinstance(value, SymbolicValue) and value.kind == 'const':
        return value.value
    return None


def _register_constant(facts, body, site, operand):
    if operand.type == a.ARM_OP_IMM:
        return operand.imm & 0xFFFFFFFF
    if operand.type != a.ARM_OP_REG:
        return None
    value = facts.register_value(body, site, operand.reg)
    if isinstance(value, SymbolicValue) and value.kind == 'const':
        return value.value
    return None


def identify_base_probe(facts):
    """Find a complete F3 identify sequence that writes its derived base."""
    matches = []
    for match in _IDENTIFY_BASE_PROBE.find(facts):
        entry = CodeAddress(match.entry, 'thumb')
        body = facts.function(entry, budget=32, symbolic_registers={})
        if (not body.complete or body.unresolved or body.truncated or body.calls
                or len(body.instructions) != 7
                or body.instructions[-1].address != match.entry + 12):
            continue
        stores = [access for access in body.symbolic_accesses
                  if access.operation == 'write' and access.width == 2
                  and isinstance(access.address, SymbolicValue)
                  and access.address.kind == 'const'
                  and isinstance(access.value, SymbolicValue)
                  and access.value.kind == 'const' and access.value.value == 0xF3]
        if (len(stores) != 2 or stores[0].address.value != 0
                or stores[1].address.value < _ADDRESS_FLOOR
                or stores[1].address.value & 0xFFFF):
            continue
        if (stores[0].instruction.address >= stores[1].instruction.address
                or body.linear_path(stores[0].instruction, stores[1].instruction) is None):
            continue
        matches.append((match.entry, match.entry + _IDENTIFY_BASE_PROBE.size,
                        stores[1].address.value))
    return matches[0] if len(matches) == 1 else None


def identify_base_path(facts):
    """Require the identify command to have one complete direct-call owner."""
    probe = identify_base_probe(facts)
    if probe is None:
        return None
    owners = {}
    for site, target in facts.call_candidates(isa='thumb'):
        if target != probe[0]:
            continue
        site_address = site.address if isinstance(site, CodeAddress) else site
        for delta in range(0, 0x82, 2):
            entry = site_address - delta
            instruction = facts.decode(CodeAddress(entry, 'thumb'))
            if instruction is None or instruction.mnemonic != 'push' or 'lr' not in instruction.op_str:
                continue
            body = facts.function(CodeAddress(entry, 'thumb'), budget=1024,
                                  symbolic_registers={})
            if (not body.complete or body.unresolved or body.truncated
                    or CodeAddress(site_address, 'thumb') not in body.instructions
                    or not any(call_site.address == site_address
                               and call_target.isa == 'thumb'
                               and call_target.address == probe[0]
                               for call_site, call_target in body.calls)):
                continue
            end = body.instructions[-1].address + facts.decode(body.instructions[-1]).size
            previous = owners.get(entry)
            sites = set() if previous is None else previous[1]
            sites.add(site_address)
            owners[entry] = (end, sites)
            break
    if len(owners) != 1 or any(len(sites) != 1 for _, sites in owners.values()):
        return None
    caller, (end, _) = next(iter(owners.items()))
    return (*probe, caller, end)


def _source_sector_masks(facts, helper):
    """Find AND uses fed by a source-derived address shifted right 16."""
    def latest_definition(register, before):
        definitions = []
        for pc in helper.instructions:
            if pc.address >= before.address:
                continue
            instruction = facts.decode(pc)
            if instruction is None:
                continue
            try:
                _, written = instruction.regs_access()
            except Exception:
                written = ()
            if register in written:
                definitions.append((pc, instruction))
        return max(definitions, key=lambda item: item[0].address) if definitions else None

    masks = set()
    for and_pc in helper.instructions:
        instruction = facts.decode(and_pc)
        if (instruction is None or instruction.id != a.ARM_INS_AND
                or len(instruction.operands) not in (2, 3)):
            continue
        and_operands = instruction.operands
        source = and_operands[1] if len(and_operands) == 3 else and_operands[0]
        if source.type != a.ARM_OP_REG:
            continue
        and_source_reg = source.reg
        source_reg = and_source_reg
        shift_pc = None
        for _ in range(4):
            definition = latest_definition(source_reg, and_pc)
            if definition is None:
                break
            definition_pc, producer = definition
            operands = producer.operands
            if (producer.id == a.ARM_INS_LSR and len(operands) == 3
                    and operands[0].type == a.ARM_OP_REG
                    and operands[0].reg == source_reg
                    and operands[1].type == a.ARM_OP_REG
                    and operands[2].type == a.ARM_OP_IMM
                    and operands[2].imm == 16):
                input_value = facts.register_value(helper, definition_pc,
                                                   operands[1].reg)
                if (isinstance(input_value, SymbolicValue)
                        and input_value.kind == 'arg' and input_value.value == 0):
                    shift_pc = definition_pc
                break
            if (producer.id == a.ARM_INS_ADD and len(operands) == 3
                    and operands[0].type == a.ARM_OP_REG
                    and operands[0].reg == source_reg
                    and operands[1].type == a.ARM_OP_REG
                    and operands[2].type == a.ARM_OP_IMM
                    and operands[2].imm == 0):
                source_reg = operands[1].reg
                continue
            if (producer.id == a.ARM_INS_MOV and len(operands) == 2
                    and operands[0].type == a.ARM_OP_REG
                    and operands[0].reg == source_reg
                    and operands[1].type == a.ARM_OP_REG):
                source_reg = operands[1].reg
                continue
            break
        if shift_pc is None:
            continue
        if helper.linear_path(shift_pc, and_pc) is None:
            continue
        mask_index = 2 if len(and_operands) == 3 else 1
        masks.add((and_pc.address, and_source_reg, mask_index))
    return masks


def bank_window(candidate, facts, sectors, *, query_pointer=None):
    """Derive base and the addressable sector aperture from the command leaf."""
    interval = candidate['protocol_intervals']['command_helper']
    helper = facts.function(CodeAddress(interval[0], 'thumb'), budget=1024,
                            symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
    if (not helper.complete or helper.unresolved or helper.truncated
            or helper.calls):
        return None
    bases = set()
    for pc in helper.instructions:
        instruction = facts.decode(pc)
        if (instruction is None or instruction.id != a.ARM_INS_CMP
                or len(instruction.operands) != 2):
            continue
        operands = instruction.operands
        values = [_register_constant(facts, helper, pc, operand)
                  for operand in operands]
        if any(type(value) is int and _ADDRESS_FLOOR <= value <= 0xFFFF0000
               and value & 0xFFFF == 0 for value in values):
            if any(operand.type == a.ARM_OP_REG
                   and isinstance(facts.register_value(helper, pc, operand.reg),
                                  SymbolicValue)
                   and facts.register_value(helper, pc, operand.reg).kind == 'arg'
                   and facts.register_value(helper, pc, operand.reg).value == 0
                   for operand in operands):
                bases.update(value for value in values if type(value) is int
                             and _ADDRESS_FLOOR <= value <= 0xFFFF0000
                             and value & 0xFFFF == 0)
    mask_sites = _source_sector_masks(facts, helper)
    if len(bases) > 1 or not mask_sites:
        return None
    bank_base = next(iter(bases)) if bases else None
    query_derived = False
    identify = None
    sector_size = sectors[0] if sectors and len(set(sectors)) == 1 else None
    if sector_size is None or sector_size != 0x10000:
        return None
    if bank_base is None:
        probe_interval = candidate.get('protocol_intervals', {}).get('identify_base')
        caller_interval = candidate.get('protocol_intervals', {}).get('identify_caller')
        if (isinstance(probe_interval, (tuple, list)) and len(probe_interval) == 2
                and all(type(value) is int for value in probe_interval)
                and probe_interval[1] - probe_interval[0] == 14
                and isinstance(caller_interval, (tuple, list))
                and len(caller_interval) == 2
                and all(type(value) is int for value in caller_interval)):
            identify = identify_base_path(facts)
            if (identify is not None and tuple(identify[:2]) == tuple(probe_interval)
                    and tuple(identify[3:5]) == tuple(caller_interval)):
                bank_base = identify[2]
        if bank_base is None:
            query_address = selector_query_address(candidate, facts, query_pointer)
            if query_address is None:
                return None
            concrete_masks = set()
            for and_pc, _, mask_index in mask_sites:
                instruction = facts.decode(CodeAddress(and_pc, 'thumb'))
                if instruction is None or instruction.id != a.ARM_INS_AND:
                    continue
                mask = _register_constant(facts, helper, CodeAddress(and_pc, 'thumb'),
                                          instruction.operands[mask_index])
                if type(mask) is int:
                    concrete_masks.add(mask)
            if len(concrete_masks) != 1:
                return None
            possible_mask = next(iter(concrete_masks))
            if possible_mask not in (_SUPPORTED_MASK, 0x7F):
                return None
            bank_base = query_address & ~(((possible_mask + 1) * sector_size) - 1)
            query_derived = True
    # Resolve the selected branch with the source-derived aperture base. This
    # keeps branch-merged unknown register values from hiding the exact mask.
    selected = facts.function(
        CodeAddress(interval[0], 'thumb'), budget=1024,
        initial_registers={a.ARM_REG_R0: bank_base}, symbolic_registers={})
    if not selected.complete or selected.unresolved or selected.truncated or selected.calls:
        return None
    masks = set()
    for pc, source_reg, mask_index in mask_sites:
        instruction = facts.decode(CodeAddress(pc, 'thumb'))
        if instruction is None or instruction.id != a.ARM_INS_AND:
            continue
        mask_operand = instruction.operands[mask_index]
        site = CodeAddress(pc, 'thumb')
        source_value = facts.register_value(selected, site, source_reg)
        concrete = _const_int(source_value)
        mask = _register_constant(facts, selected, site, mask_operand)
        if (concrete == (bank_base >> 16) and type(mask) is int
                and mask > 0 and mask & (mask + 1) == 0):
            masks.add(mask)
    if len(masks) != 1:
        return None
    mask = next(iter(masks))
    bank_length = (mask + 1) * sector_size
    if (mask not in (_SUPPORTED_MASK, 0x7F) or sector_size != 0x10000
            or bank_base & (bank_length - 1)
            or bank_base + bank_length > 0x100000000):
        return None
    if mask == 0x7F and identify is None:
        probe_interval = candidate.get('protocol_intervals', {}).get('identify_base')
        caller_interval = candidate.get('protocol_intervals', {}).get('identify_caller')
        if isinstance(probe_interval, (tuple, list)):
            if identify is None:
                identify = identify_base_path(facts)
            if (identify is not None and tuple(identify[:2]) == tuple(probe_interval)
                    and tuple(identify[3:5]) == tuple(caller_interval or ())):
                if identify[2] != bank_base:
                    return None
            elif query_pointer is None:
                return None
        elif not query_derived:
            return None
    address, extent = candidate.get('address'), candidate.get('size')
    if (type(address) is not int or type(extent) is not int or extent <= 0
            or address < bank_base or address + extent > bank_base + bank_length):
        return None
    return bank_base, bank_length, sector_size


def _getter_field_adjustment(candidate, facts):
    """Prove the linked active-object getter returns its pointer field + 4."""
    lifecycle = candidate['lifecycle']
    entry = lifecycle['active_object_getter']
    consumer = candidate.get('sector_prefix_consumer')
    global_address = consumer.get('global_address') if isinstance(consumer, dict) else None
    if type(global_address) is not int:
        return None
    body = facts.function(CodeAddress(entry, 'thumb'), budget=256,
                          symbolic_registers={})
    if not body.complete or body.unresolved or body.truncated or body.calls:
        return None
    pointer_loads = set()
    for access in body.symbolic_accesses:
        if (access.operation == 'read' and access.width == 4
                and isinstance(access.address, SymbolicValue)
                and access.address.kind == 'const'
                and access.address.value == global_address + 4):
            instruction = facts.decode(access.instruction)
            if (instruction is not None and instruction.id == a.ARM_INS_LDR
                    and len(instruction.operands) == 2
                    and instruction.operands[0].type == a.ARM_OP_REG
                    and instruction.operands[0].reg == a.ARM_REG_R0
                    and instruction.operands[1].type == a.ARM_OP_MEM
                    and instruction.operands[1].mem.base == a.ARM_REG_R0
                    and instruction.operands[1].mem.disp == 4):
                pointer_loads.add(access.instruction)
    if len(pointer_loads) != 1:
        return None
    pointer_load = next(iter(pointer_loads))
    adjustments = []
    for index, pc in enumerate(body.instructions):
        instruction = facts.decode(pc)
        if instruction is None:
            return None
        operands = instruction.operands
        if (instruction.id == a.ARM_INS_ADD
                and len(operands) == 2
                and operands[0].type == a.ARM_OP_REG
                and operands[0].reg == a.ARM_REG_R0
                and operands[1].type == a.ARM_OP_IMM):
            following = (facts.decode(body.instructions[index + 1])
                         if index + 1 < len(body.instructions) else None)
            if (operands[1].imm & 0xFFFFFFFF == 4 and following is not None
                    and following.id == a.ARM_INS_BX
                    and len(following.operands) == 1
                    and following.operands[0].type == a.ARM_OP_REG
                    and following.operands[0].reg == a.ARM_REG_LR):
                adjustments.append((pc, body.instructions[index + 1]))
    load_value = SymbolicValue('load', operands=(SymbolicValue.const(global_address + 4),),
                               width=4, site=pointer_load)
    for add_pc, return_pc in adjustments:
        if (not body.dominates(pointer_load, add_pc)
                or facts.register_value(body, add_pc, a.ARM_REG_R0) != load_value
                or body.linear_path(add_pc, return_pc) is None):
            continue
        returned = facts.register_value(body, return_pc, a.ARM_REG_R0)
        if (isinstance(returned, SymbolicValue) and returned.kind == 'op'
                and returned.value == 'add' and len(returned.operands) == 2
                and SymbolicValue.const(4) in returned.operands
                and load_value in returned.operands):
            return 4
    return None


def _halfword_pair_after_call(candidate, facts, getter, offsets):
    """Track the returned pointer through one branch-free halfword read path."""
    initializer = candidate['lifecycle']['count_initializer']
    body = facts.function(CodeAddress(initializer, 'thumb'), budget=2048,
                          symbolic_registers={})
    if not body.complete or body.unresolved or body.truncated:
        return False
    sites = [site for site, target in body.calls if target.address == getter
             and target.isa == 'thumb']
    if len(sites) != 1:
        return False
    call = sites[0]
    ins = facts.decode(call)
    if ins is None:
        return False
    start = CodeAddress(call.address + ins.size, 'thumb', call.phase, call.bank)
    pcs = [pc for pc in body.instructions if pc.address >= start.address]
    tracked = {a.ARM_REG_R0: ('base', 0)}
    reads = set()
    found_end = None
    for pc in pcs:
        instruction = facts.decode(pc)
        if instruction is None:
            return False
        operands = instruction.operands
        if instruction.group(CS_GRP_JUMP):
            # Calls are allowed only after the source reads have been found.
            if reads >= set(offsets):
                found_end = pc
                break
            return False
        if (instruction.id == a.ARM_INS_LDRH and len(operands) == 2
                and operands[1].type == a.ARM_OP_MEM):
            dest, memory = operands
            base_value = tracked.get(memory.mem.base)
            index_value = tracked.get(memory.mem.index) if memory.mem.index else 0
            if (isinstance(base_value, tuple) and base_value[0] == 'base'
                    and type(index_value) is int):
                displacement = base_value[1] + index_value + memory.mem.disp
                if displacement in offsets:
                    reads.add(displacement)
            if dest.type == a.ARM_OP_REG:
                tracked.pop(dest.reg, None)
        elif (instruction.id == a.ARM_INS_ADD
              and len(operands) == 3
              and operands[0].type == a.ARM_OP_REG
              and operands[1].type == a.ARM_OP_REG
              and operands[2].type in (a.ARM_OP_IMM, a.ARM_OP_REG)):
            src = tracked.get(operands[1].reg)
            addend = (tracked.get(operands[2].reg)
                      if operands[2].type == a.ARM_OP_REG
                      else operands[2].imm if operands[2].type == a.ARM_OP_IMM
                      else None)
            if (isinstance(src, tuple) and src[0] == 'base'
                    and type(addend) is int):
                tracked[operands[0].reg] = ('base', src[1] + addend)
            elif type(src) is int and type(addend) is int:
                tracked[operands[0].reg] = src + addend
            else:
                tracked.pop(operands[0].reg, None)
        elif (instruction.id == a.ARM_INS_ADD
              and len(operands) == 2
              and operands[0].type == a.ARM_OP_REG
              and operands[1].type == a.ARM_OP_IMM):
            prior = tracked.get(operands[0].reg)
            if isinstance(prior, tuple) and prior[0] == 'base':
                tracked[operands[0].reg] = ('base', prior[1] + operands[1].imm)
            elif type(prior) is int:
                tracked[operands[0].reg] = prior + operands[1].imm
            else:
                tracked.pop(operands[0].reg, None)
        elif (instruction.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
              and len(operands) == 2
              and operands[0].type == a.ARM_OP_REG
              and operands[1].type == a.ARM_OP_REG):
            src = tracked.get(operands[1].reg)
            if src is not None:
                tracked[operands[0].reg] = src
            else:
                tracked.pop(operands[0].reg, None)
        elif (instruction.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
              and len(operands) == 2
              and operands[0].type == a.ARM_OP_REG
              and operands[1].type == a.ARM_OP_IMM):
            tracked[operands[0].reg] = operands[1].imm
        else:
            try:
                _, written = instruction.regs_access()
            except Exception:
                written = ()
            for register in written:
                tracked.pop(register, None)
        if reads >= set(offsets):
            found_end = pc
            break
    if reads < set(offsets) or found_end is None:
        return False
    return body.linear_path(start, found_end) is not None


def packed_identity_is_read(candidate, facts, object_address):
    lifecycle = candidate['lifecycle']
    getter = lifecycle['active_object_getter']
    adjustment = _getter_field_adjustment(candidate, facts)
    if adjustment is None:
        return False
    # The copied descriptor stores the packed identity as adjacent halfwords.
    offsets = (_ID_OFFSET - adjustment, _ID_OFFSET + 2 - adjustment)
    return _halfword_pair_after_call(candidate, facts, getter, offsets)


