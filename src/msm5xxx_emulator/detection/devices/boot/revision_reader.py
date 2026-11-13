"""Code evidence for a cached halfword revision reader and acceptance gate."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


_REVISION_REGISTER = 0x0300075c
_REVISION_BLOCK = 0x03000740
_RAW_REVISION = 0x20f5
_COMPATIBLE_REVISION = 0xf025
_ACCEPTED_THRESHOLD = 0xf051
_WORD_MASK = 0xffffffff


def _span(facts, function):
    if not function.instructions:
        return None
    start = min(pc.address for pc in function.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {'span': [start - facts.base, end - start],
            'extra_spans': [[literal.pool - facts.base, 4]
                            for literal in function.literals]}


def _return_values(facts, function, start):
    instructions = {pc.address: pc for pc in function.instructions}
    registers = {}
    popped = set()
    pc = start
    visited = set()
    for _ in range(24):
        if pc in visited:
            return None
        visited.add(pc)
        site = instructions.get(pc)
        if site is None:
            return None
        ins = facts.decode(site)
        if ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(ins.operands) == 2:
            dst, src = ins.operands
            if dst.type != a.ARM_OP_REG or src.type != a.ARM_OP_IMM:
                return None
            registers[dst.reg] = src.imm & _WORD_MASK
        elif ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR) and len(ins.operands) == 3:
            dst, src, amount = ins.operands
            if (dst.type != a.ARM_OP_REG or src.type != a.ARM_OP_REG
                    or amount.type != a.ARM_OP_IMM or src.reg not in registers):
                return None
            value = registers[src.reg]
            registers[dst.reg] = ((value << amount.imm) if ins.id == a.ARM_INS_LSL
                                  else value >> amount.imm) & _WORD_MASK
        elif ins.id == a.ARM_INS_B and ins.cc == a.ARM_CC_AL:
            pc = ins.operands[0].imm & _WORD_MASK
            continue
        elif ins.id == a.ARM_INS_POP:
            popped = {op.reg for op in ins.operands
                      if op.type == a.ARM_OP_REG}
        elif ins.id == a.ARM_INS_BX:
            target = ins.operands[0].reg
            if target not in popped:
                return None
            return registers.get(a.ARM_REG_R0)
        else:
            return None
        pc += ins.size
    return None


def _consumer(facts, function, reader):
    if (not function.complete or function.unresolved or function.truncated
            or len(function.calls) != 1 or function.calls[0][1] != reader.entry):
        return False
    instructions = {pc.address: facts.decode(pc) for pc in function.instructions}
    threshold_registers = {literal.register for literal in function.literals
                           if literal.value == _ACCEPTED_THRESHOLD}
    if a.ARM_REG_R1 not in threshold_registers:
        return False
    for address, ins in instructions.items():
        if (ins.id != a.ARM_INS_CMP or len(ins.operands) != 2
                or ins.operands[0].reg != a.ARM_REG_R0
                or ins.operands[1].reg != a.ARM_REG_R1):
            continue
        branch = instructions.get(address + ins.size)
        if (branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_LO or not branch.operands
                or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        accepted = _return_values(facts, function, branch.address + branch.size)
        rejected = _return_values(facts, function, branch.operands[0].imm & _WORD_MASK)
        if accepted == 0x8000 and rejected == 0:
            return True
    return False


def _reader_transform(facts, function):
    if (not function.complete or function.unresolved or function.truncated
            or function.calls):
        return None
    raw_reads = []
    for access in function.accesses:
        if (access.operation, access.address, access.width) != ('read', _REVISION_REGISTER, 2):
            continue
        ins = facts.decode(access.instruction)
        if (ins.id != a.ARM_INS_LDRH or len(ins.operands) != 2
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.disp != 0x1c):
            continue
        if not any(literal.value == _REVISION_BLOCK
                   and literal.register == ins.operands[1].mem.base
                   for literal in function.literals):
            continue
        raw_reads.append((access, ins))
    if len(raw_reads) != 1:
        return None
    raw_access, raw_instruction = raw_reads[0]
    ordered = sorted(function.instructions, key=lambda pc: pc.address)
    if raw_access.instruction not in ordered:
        return None

    stores = [access for access in function.accesses
              if access.operation == 'write' and access.width == 2
              and access.address != _REVISION_REGISTER
              and access.instruction.address > raw_access.instruction.address
              and facts.decode(access.instruction).id == a.ARM_INS_STRH]
    if len(stores) != 1:
        return None
    cache_store = stores[0]
    identity = tuple([0] + [1 << bit for bit in range(16)])
    values = {raw_instruction.operands[0].reg: identity}
    current = raw_access.instruction.address + facts.decode(raw_access.instruction).size
    store_instruction = cache_store.instruction
    verified_store = False
    while current <= store_instruction.address:
        site = next((pc for pc in ordered if pc.address == current), None)
        if site is None:
            return None
        ins = facts.decode(site)
        if site == store_instruction:
            if ins.id != a.ARM_INS_STRH or ins.operands[0].reg not in values:
                return None
            expected = tuple([0] + [
                (((basis >> 8) & 0xf0) | ((basis & 0xf0) << 8)
                 | (basis & 0x0f)) & 0xffff
                for basis in (1 << bit for bit in range(16))])
            if tuple(values[ins.operands[0].reg]) != expected:
                return None
            verified_store = True
            break
        if ins.id in (a.ARM_INS_LSL, a.ARM_INS_LSR):
            if len(ins.operands) != 3:
                return None
            dst, src, amount = ins.operands
            if (src.reg not in values or amount.type != a.ARM_OP_IMM):
                return None
            source_values = values[src.reg]
            op = ((lambda value: value << amount.imm) if ins.id == a.ARM_INS_LSL
                  else (lambda value: value >> amount.imm))
            values[dst.reg] = tuple(op(value) & _WORD_MASK for value in source_values)
        elif ins.id in (a.ARM_INS_AND, a.ARM_INS_ORR):
            if len(ins.operands) == 2:
                dst, source = ins.operands
                left, right = values.get(dst.reg), values.get(source.reg)
            elif len(ins.operands) == 3:
                dst, left_op, right_op = ins.operands
                left, right = values.get(left_op.reg), values.get(right_op.reg)
            else:
                return None
            if left is None or right is None:
                return None
            combine = (lambda x, y: x & y) if ins.id == a.ARM_INS_AND else (lambda x, y: x | y)
            values[dst.reg] = tuple(combine(x, y) & _WORD_MASK
                                    for x, y in zip(left, right))
        elif ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS):
            if len(ins.operands) != 2:
                return None
            dst, source = ins.operands
            if source.type == a.ARM_OP_IMM:
                values[dst.reg] = tuple([source.imm & _WORD_MASK] * 17)
            elif source.type == a.ARM_OP_REG and source.reg in values:
                values[dst.reg] = values[source.reg]
            else:
                return None
        else:
            return None
        current += ins.size
    else:
        return None

    if not verified_store:
        return None

    cache_reads = [access for access in function.accesses
                   if access.operation == 'read' and access.width == 2
                   and access.address == cache_store.address
                   and access.instruction.address > cache_store.instruction.address
                   and facts.decode(access.instruction).id == a.ARM_INS_LDRH
                   and facts.decode(access.instruction).operands[0].reg == a.ARM_REG_R0]
    if len(cache_reads) != 1:
        return None
    if not any((ins := facts.decode(pc)).id == a.ARM_INS_BX
               and ins.operands[0].reg == a.ARM_REG_LR
               and pc.address > cache_reads[0].instruction.address
               for pc in function.instructions):
        return None
    return cache_store.address


def _owners(facts, site, *, limit=0x200):
    for address in range(max(0, site - limit) & ~1, site, 2):
        ins = facts.decode(CodeAddress(address, 'thumb'))
        if (ins is None or ins.id != a.ARM_INS_PUSH
                or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR
                           for op in ins.operands)):
            continue
        function = facts.function(CodeAddress(address, 'thumb'), budget=128)
        if (function.complete and not function.unresolved and not function.truncated
                and CodeAddress(site, 'thumb') in function.instructions):
            yield function


def find_cached_revision(image: bytes):
    """Recognize the linked cached 16-bit revision transform and feature gate."""
    if not isinstance(image, bytes) or len(image) < 0x100:
        return None
    facts = facts_for(image)
    references = facts.literal_references(_REVISION_BLOCK)
    if not references:
        return None
    calls = facts.call_candidates('thumb')
    targets = {target for _, target in calls}
    reader_candidates = set()
    for reference in references:
        address = reference.instruction.address
        for target in targets:
            if 0 <= address - target <= 0x1000:
                reader_candidates.add(target)
    readers = []
    for target in reader_candidates:
        reader = facts.function(CodeAddress(target, 'thumb'), budget=256)
        cache_address = _reader_transform(facts, reader)
        if cache_address is not None:
            readers.append((reader, cache_address))
    if len(readers) != 1:
        return None
    reader, cache_address = readers[0]

    consumers = []
    for site, target in calls:
        if target != reader.entry.address:
            continue
        for owner in _owners(facts, site):
            if _consumer(facts, owner, reader):
                consumers.append((owner, site))
    unique = {(owner.entry, site) for owner, site in consumers}
    if len(unique) != 1:
        return None
    consumer_entry, consumer_site = next(iter(unique))
    consumer = facts.function(consumer_entry, budget=128)

    raw_value = _RAW_REVISION
    normalized = (((raw_value >> 8) & 0xf0) | ((raw_value & 0xf0) << 8)
                  | (raw_value & 0x0f)) & 0xffff
    if normalized != _COMPATIBLE_REVISION or not normalized < _ACCEPTED_THRESHOLD:
        return None
    evidence = [_span(facts, reader), _span(facts, consumer)]
    evidence = [item for item in evidence if item is not None]
    return {
        'register': _REVISION_REGISTER,
        'raw_value': raw_value,
        'revision': normalized,
        'cache_address': cache_address,
        'threshold': _ACCEPTED_THRESHOLD,
        'evidence': evidence,
    }
