"""Source-proven event indexing and saved-frame call flow for five-column scans."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .row_execution import _Bits, _irq, _row_outputs


def unconditional(ins):
    return ins is not None and ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)


def no_thumb_it(facts, function):
    """Reject reachable IT blocks until their predicates are modeled."""
    return all((ins := facts.decode(site)) is not None and ins.id != a.ARM_INS_IT
               for site in function.instructions)


def event_map(image, sample_pc, event_load, row_register, row_count,
              sample_register, capture_end, descriptor, descriptor_rom,
              column_sense, keys, *, descriptor_registers=(),
              extra_sense_reads=()):
    """Resolve every low-five one-hot input through the real byte table.

    ``descriptor_registers`` contains only aliases already proved to hold D
    at the start of this bounded trace. ``extra_sense_reads`` names exact,
    source-proven halfword rereads as ``(PC, address)`` pairs; their values
    stay unknown so filter branches remain abstract.
    """
    facts = facts_for(image)
    try:
        descriptor_registers = tuple(descriptor_registers)
        extra_sense_reads = tuple(extra_sense_reads)
    except TypeError:
        return None
    if (any(type(register) is not int
                   or not a.ARM_REG_R0 <= register <= a.ARM_REG_R12
                   or register in (row_register, sample_register)
                   for register in descriptor_registers)
            or len(set(descriptor_registers)) != len(descriptor_registers)
            or any(not isinstance(item, tuple) or len(item) != 2
                   or any(type(value) is not int for value in item)
                   or item[0] & 1 or not sample_pc + 2 <= item[0] < event_load
                   or item[1] & 1 or not 0x03000000 <= item[1] < 0x03001000
                   for item in extra_sense_reads)
            or len(set(extra_sense_reads)) != len(extra_sense_reads)):
        return None
    load_ins = facts.decode(CodeAddress(event_load))
    if (load_ins is None or load_ins.id != a.ARM_INS_LDRB or len(load_ins.operands) != 2
            or load_ins.operands[0].type != a.ARM_OP_REG
            or load_ins.operands[1].type != a.ARM_OP_MEM
            or not load_ins.operands[1].mem.index):
        return None
    addresses, dependencies = [], set()
    for raw in column_sense:
        for row in range(row_count):
            initial = {sample_register: _Bits.constant(raw),
                       row_register: _Bits.constant(row)}
            initial.update({register: _Bits.constant(descriptor)
                            for register in descriptor_registers})
            result = _row_outputs(image, sample_pc + 2, event_load, initial,
                descriptor, descriptor_rom, capture_load=True,
                capture_end=capture_end,
                unknown_halfword_inputs=extra_sense_reads)
            if result is None:
                return None
            addresses.append(result[0])
            dependencies.update(result[1])
    if len(addresses) != len(column_sense) * row_count:
        return None
    table = addresses[0]
    if addresses != list(range(table, table + len(column_sense) * row_count)):
        return None
    if not 0 <= table <= len(image) - len(column_sense) * row_count:
        return None
    events = list(image[table:table + len(column_sense) * row_count])
    if any(events.count(key) != 1 for key in keys):
        return None
    return table, events, dependencies


def _saved_frame_call(image, target, register, values, descriptor,
                      descriptor_rom):
    """Prove a direct helper restores a saved event register on every return."""
    if target is None or target & 1 or not 0 <= target < len(image) - 2:
        return None
    facts = facts_for(image)
    function = facts.function(CodeAddress(target), budget=512)
    if (not function.complete or function.unresolved or function.truncated
            or not no_thumb_it(facts, function)):
        return None
    sites = {site.address: site for site in function.instructions}
    prologue_site = sites.get(target)
    prologue = facts.decode(prologue_site) if prologue_site is not None else None
    pushed = (frozenset(op.reg for op in prologue.operands if op.type == a.ARM_OP_REG)
              if prologue is not None and prologue.id == a.ARM_INS_PUSH else frozenset())
    if pushed != frozenset((register, a.ARM_REG_LR)) or not unconditional(prologue):
        return None
    pop_event = pop_link = return_site = None
    for pc, site in sites.items():
        ins = facts.decode(site)
        next_ins = facts.decode(CodeAddress(pc + 2))
        ret = facts.decode(CodeAddress(pc + 4))
        regs = frozenset(op.reg for op in ins.operands if op.type == a.ARM_OP_REG) if ins else frozenset()
        next_regs = (frozenset(op.reg for op in next_ins.operands if op.type == a.ARM_OP_REG)
                     if next_ins is not None else frozenset())
        if (ins is not None and ins.id == a.ARM_INS_POP and unconditional(ins)
                and regs == frozenset((register,))
                and next_ins is not None and next_ins.id == a.ARM_INS_POP
                and unconditional(next_ins)
                and len(next_regs) == 1 and a.ARM_REG_PC not in next_regs
                and next_regs != frozenset((register,))
                and ret is not None and ret.id == a.ARM_INS_BX
                and unconditional(ret)
                and ret.operands and ret.operands[0].type == a.ARM_OP_REG
                and ret.operands[0].reg in next_regs):
            pop_event, pop_link, return_site = pc, pc + 2, pc + 4
            break
    if pop_event is None:
        return None
    returns = []
    for pc, site in sites.items():
        ins = facts.decode(site)
        if (ins is not None and (ins.id == a.ARM_INS_BX
                or ins.id == a.ARM_INS_POP and any(
                    op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC
                    for op in ins.operands))):
            returns.append(pc)
    if (returns != [return_site]
            or not function.dominates(CodeAddress(pop_event), CodeAddress(return_site))
            or not function.dominates(CodeAddress(pop_link), CodeAddress(return_site))):
        return None
    dependencies = {(target, pop_link + 4 - target)}
    for value in sorted(set(values)):
        slots = {}
        offset = 0
        # Thumb PUSH places the low register before LR. Capstone's enum
        # values place LR before R0 and do not encode that memory order.
        for saved in (register, a.ARM_REG_LR):
            slots[offset] = value if saved == register else 0x5a5a0000 | saved
            offset += 4
        result = _row_outputs(image, target + prologue.size, pop_event,
            {register: _Bits.constant(value)}, descriptor, descriptor_rom,
            initial_stack=slots)
        if result is None:
            return None
        dependencies.update(result[1])
    return dependencies


def saved_frame_calls(image, function, start, limit, register, values,
                      descriptor, descriptor_rom):
    """Map proven frame-preserving direct callees in a bounded call interval."""
    facts = facts_for(image)
    calls = {}
    for site in function.instructions:
        if not start <= site.address < limit:
            continue
        ins = facts.decode(site)
        if ins is None or ins.id != a.ARM_INS_BL:
            continue
        target = facts.thumb_call_target(site.address)
        proof = _saved_frame_call(image, target, register, values,
                                  descriptor, descriptor_rom)
        if proof is not None:
            calls[target] = proof
    return calls


def preserves_register(image, target, register):
    """Prove a direct helper never writes a register except via closed IRQs."""
    if target is None or target & 1 or not 0 <= target < len(image) - 2:
        return False
    facts = facts_for(image)
    function = facts.function(CodeAddress(target), budget=512)
    if (not function.complete or function.unresolved or function.truncated
            or not no_thumb_it(facts, function)):
        return False
    for site in function.instructions:
        ins = facts.decode(site)
        if ins is None:
            return False
        try:
            _, written = ins.regs_access()
        except Exception:
            return False
        if register in written:
            return False
        if ins.id == a.ARM_INS_BLX:
            return False
        if ins.id == a.ARM_INS_BL:
            if (not unconditional(ins)
                    or _irq(image, facts.thumb_call_target(site.address)) is None):
                return False
    return True
