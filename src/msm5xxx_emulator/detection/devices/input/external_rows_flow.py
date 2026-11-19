"""Local CFG and argument-flow proofs for external-latch key scanners."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress

_SENSE_MASK = 0x1f
_OUTPUT_MASK = 0x8850
_SELECTOR_MASK = 0x3


def _has_low_five_sample(function, facts) -> bool:
    """Require a linked word read, low-five extraction, and idle comparison."""
    reads = {access.instruction for access in function.accesses
             if access.operation == "read" and access.width == 4
             and access.address == 0x09000070}
    reads.update(access.instruction for access in function.symbolic_accesses
                 if access.operation == "read" and access.width == 4
                 and access.address.kind == "const"
                 and access.address.value == 0x09000070)
    if not reads:
        return False
    for read in reads:
        seq = [facts.decode(CodeAddress(read.address + off, read.isa,
                                        read.phase, read.bank))
               for off in (2, 4, 6, 8)]
        if any(ins is None for ins in seq):
            continue
        if not all(CodeAddress(read.address + off, read.isa, read.phase,
                               read.bank) in function.instructions
                   for off in (0, 2, 4, 6, 8)):
            continue
        # LSL/LSR by 27 leaves the low five source bits; the adjacent compare
        # against 31 is the scanner's all-released condition.
        loaded = facts.decode(read)
        if (loaded is None or loaded.id not in (a.ARM_INS_LDR, a.ARM_INS_LDRB,
                                                a.ARM_INS_LDRH)
                or not loaded.operands or loaded.operands[0].type != a.ARM_OP_REG):
            continue
        register = loaded.operands[0].reg
        if (seq[0].id == a.ARM_INS_LSL and seq[0].operands[0].reg == register
                and seq[0].operands[1].reg == register
                and seq[0].operands[-1].imm == 27
                and seq[1].id == a.ARM_INS_LSR
                and seq[1].operands[0].reg == register
                and seq[1].operands[1].reg == register
                and seq[1].operands[-1].imm == 27
                and seq[2].id == a.ARM_INS_CMP
                and seq[2].operands[0].reg == register
                and seq[2].operands[-1].imm == _SENSE_MASK
                and seq[3].id == a.ARM_INS_B
                and seq[3].cc in (a.ARM_CC_EQ, a.ARM_CC_NE)
                and function.dominates(read, CodeAddress(read.address + 6,
                    read.isa, read.phase, read.bank))):
            return True
    return False


def _byte_load_source(value):
    """Return a source load site only when the call value retains byte-load lineage."""
    if value is None:
        return None
    if getattr(value, "kind", None) == "load":
        return value.site
    for operand in getattr(value, "operands", ()):
        source = _byte_load_source(operand)
        if source is not None:
            return source
    return None


def _constant(value):
    if type(value) is int:
        return value & 0xffffffff
    if getattr(value, "kind", None) == "const":
        return value.value & 0xffffffff
    return None


def _register_lineage(function, facts, use, register):
    """Follow register copies to a loop input, preserving simple shift form."""
    lineage = []
    current, end = register, use.address
    sites = sorted((site for site in function.instructions
                    if site.address < end), key=lambda site: site.address)
    while len(lineage) < 5:
        definition = None
        for site in reversed(sites):
            ins = facts.decode(site)
            if ins is None:
                continue
            if ins.id in (a.ARM_INS_BL, a.ARM_INS_BLX) and current in (
                    a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2,
                    a.ARM_REG_R3, a.ARM_REG_R12):
                return None
            try:
                _, writes = ins.regs_access()
            except Exception:
                return None
            if current in writes:
                definition = site, ins
                break
        if definition is None:
            return None
        site, ins = definition
        if (ins.operands and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == current
                and ins.id == a.ARM_INS_LSL and len(ins.operands) == 3
                and ins.operands[-1].type == a.ARM_OP_IMM
                and ins.operands[-1].imm == 2
                and ins.operands[1].type == a.ARM_OP_REG):
            lineage.append(("lsl2", ins.operands[1].reg))
            return ins.operands[1].reg, tuple(lineage)
        if (ins.operands and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == current
                and ins.id in (a.ARM_INS_MOV, a.ARM_INS_ADD)
                and any(op.type == a.ARM_OP_REG for op in ins.operands[1:])
                and all(op.type == a.ARM_OP_REG or
                        op.type == a.ARM_OP_IMM and op.imm == 0
                        for op in ins.operands[1:])):
            sources = [op.reg for op in ins.operands[1:]
                       if op.type == a.ARM_OP_REG]
            if len(sources) != 1:
                return None
            lineage.append(("copy", sources[0]))
            current, end = sources[0], site.address
            sites = [item for item in sites if item.address < end]
            continue
        return None
    return None


def _event_handlers(function, facts=None):
    """Recover press/release argument roles from dataflow at each real call."""
    handlers = []
    for site in function.call_sites:
        registers = dict(site.registers)
        r0, r1 = registers.get(a.ARM_REG_R0), registers.get(a.ARM_REG_R1)
        if _constant(r1) == 0:
            event_register, auxiliary_register, auxiliary_value = a.ARM_REG_R0, a.ARM_REG_R1, 0
            event_value = r0
        elif _constant(r0) == 0xff:
            event_register, auxiliary_register, auxiliary_value = a.ARM_REG_R1, a.ARM_REG_R0, 0xff
            event_value = r1
        else:
            continue
        load_site = _byte_load_source(event_value)
        if load_site is None and facts is not None:
            load_site = _local_event_source(function, facts, site.site,
                                            event_register, auxiliary_register,
                                            auxiliary_value)
        if load_site is None:
            continue
        handlers.append({"call_site": site.site.address,
                         "handler": site.target.address,
                         "event_register": event_register - a.ARM_REG_R0,
                         "event_load": load_site.address,
                         "auxiliary_register": auxiliary_register - a.ARM_REG_R0,
                         "auxiliary_value": auxiliary_value})
    presses = [item for item in handlers if item["auxiliary_value"] == 0]
    releases = [item for item in handlers if item["auxiliary_value"] == 0xff]
    if len(presses) != 1 or len(releases) != 1 or presses[0]["handler"] != releases[0]["handler"]:
        return None
    return handlers


def _local_event_source(function, facts, call_site, event_register,
                        auxiliary_register, auxiliary_value):
    """Close nearby byte-load and immediate argument writes at a sink call."""
    event_reg, auxiliary_reg = event_register, auxiliary_register
    by_address = {site.address: site for site in function.instructions}
    candidates = []
    for address in range(max(function.entry.address, call_site.address - 16),
                         call_site.address, 2):
        site = by_address.get(address)
        ins = facts.decode(site) if site is not None else None
        if (ins is not None and ins.id == a.ARM_INS_LDRB
                and ins.operands and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == event_reg):
            candidates.append(site)
    if not candidates:
        return None
    load = max(candidates, key=lambda site: site.address)
    # Confirm that no later instruction replaces the loaded event byte.
    for address in range(load.address + 2, call_site.address, 2):
        site = by_address.get(address)
        ins = facts.decode(site) if site is not None else None
        if ins is None:
            return None
        try:
            _, writes = ins.regs_access()
        except Exception:
            return None
        if event_reg in writes:
            return None
    aux_writes = []
    for address in range(max(function.entry.address, call_site.address - 12),
                         call_site.address, 2):
        site = by_address.get(address)
        ins = facts.decode(site) if site is not None else None
        if ins is None:
            continue
        try:
            _, writes = ins.regs_access()
        except Exception:
            return None
        if auxiliary_reg in writes:
            aux_writes.append((site, ins))
    if not aux_writes:
        return None
    last_site, last_ins = aux_writes[-1]
    if (last_ins.id != a.ARM_INS_MOV or len(last_ins.operands) != 2
            or last_ins.operands[0].type != a.ARM_OP_REG
            or last_ins.operands[0].reg != auxiliary_reg
            or last_ins.operands[1].type != a.ARM_OP_IMM
            or (last_ins.operands[1].imm & 0xffffffff) != auxiliary_value):
        return None
    if last_site.address < load.address and auxiliary_value == 0xff:
        return None
    return load


def _written_address(function, address: int, operation: str) -> bool:
    if any(access.operation == operation and access.address == address
           for access in function.accesses):
        return True
    return any(access.operation == operation
               and access.address.kind == "const"
               and access.address.value == address
               for access in function.symbolic_accesses)


def _handlers_share_row_index(handlers, facts, row_register):
    for handler in handlers:
        load = facts.decode(CodeAddress(handler["event_load"]))
        if (load is None or load.id != a.ARM_INS_LDRB or len(load.operands) != 2
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.index != row_register):
            return False
    return True


def _loop_records(function, facts, *, bound=None, counter=None):
    """Return closed counter loops with zero init, unit step, and LO backedge."""
    records = []
    back_edges = set(function.back_edges)
    for branch_site in function.instructions:
        branch = facts.decode(branch_site)
        if (branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_LO or not branch.operands
                or branch.operands[0].type != a.ARM_OP_IMM):
            continue
        target = branch.operands[0].imm
        if (branch_site.address, target) not in back_edges:
            continue
        compare_site = next((site for site in function.instructions
                             if site.address < branch_site.address
                             and branch_site.address - site.address <= 4
                             and (ins := facts.decode(site)) is not None
                             and ins.id == a.ARM_INS_CMP
                             and len(ins.operands) == 2
                             and ins.operands[0].type == a.ARM_OP_REG
                             and ins.operands[1].type == a.ARM_OP_IMM), None)
        if compare_site is None:
            continue
        compare = facts.decode(compare_site)
        register = compare.operands[0].reg
        count = compare.operands[1].imm
        if (bound is not None and count != bound) or (counter is not None
                                                       and register != counter):
            continue
        increments = []
        for site in function.instructions:
            if not target <= site.address < compare_site.address:
                continue
            ins = facts.decode(site)
            if (ins is not None and ins.id == a.ARM_INS_ADD
                    and ins.operands and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[0].reg == register
                    and ins.operands[-1].type == a.ARM_OP_IMM
                    and ins.operands[-1].imm == 1):
                increments.append(site)
        if len(increments) != 1:
            continue
        initializers = []
        for site in function.instructions:
            if site.address >= target:
                continue
            ins = facts.decode(site)
            if (ins is not None and ins.id == a.ARM_INS_MOV
                    and len(ins.operands) == 2
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[0].reg == register
                    and ins.operands[1].type == a.ARM_OP_IMM
                    and ins.operands[1].imm == 0
                    and function.dominates(site, CodeAddress(target,
                        branch_site.isa, branch_site.phase, branch_site.bank))):
                initializers.append(site)
        if not initializers:
            continue
        initialize = max(initializers, key=lambda site: site.address)
        if any(_writes_register(facts, site, register)
               for site in function.instructions
               if initialize.address < site.address < target):
            continue
        increment = increments[0]
        if not (function.dominates(increment, compare_site)
                and function.dominates(compare_site, branch_site)):
            continue
        records.append({"target": target, "counter": register, "bound": count,
                        "initialize": initialize, "increment": increment,
                        "compare": compare_site, "branch": branch_site})
    return records


def _writes_register(facts, site, register):
    ins = facts.decode(site)
    if ins is None:
        return True
    try:
        _, writes = ins.regs_access()
    except Exception:
        return True
    return register in writes


def _reg_sources(ins):
    return {operand.reg for operand in ins.operands[1:]
            if operand.type == a.ARM_OP_REG}


def _value_constants(value):
    if getattr(value, "kind", None) == "const":
        return {value.value}
    return set().union(*(_value_constants(item)
                         for item in getattr(value, "operands", ())))


def _global_presence(function, facts):
    """Prove both all-row masks are committed before the global sense read."""
    sense_sites = {access.instruction for access in function.accesses
                   if access.operation == "read" and access.address == 0x09000070}
    if not sense_sites:
        return False
    stores = {port: [access.instruction for access in function.accesses
                     if access.operation == "write" and access.address == port]
              for port in (0x09000000, 0x09000004)}
    masks = {0x09000000: _OUTPUT_MASK, 0x09000004: _SELECTOR_MASK}
    for read in sense_sites:
        if any(not any(site.address < read.address
                       and function.dominates(site, read)
                       and (ins := facts.decode(site)) is not None
                       and ins.operands
                       and masks[port] in _value_constants(
                           facts.register_value(function, site, ins.operands[0].reg))
                       for site in stores[port])
               for port in stores):
            continue
        return True
    return False


