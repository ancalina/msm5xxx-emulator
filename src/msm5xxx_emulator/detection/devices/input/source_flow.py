"""Closed Thumb source regions with a restored entry link register."""
from __future__ import annotations

from collections import deque

from capstone import CS_GRP_CALL
from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, FunctionFacts, facts_for
from msm5xxx_emulator.detection.stack_facts import stack_frame

_UNKNOWN = None
_LR_TOKEN = ("entry-lr",)
_SP = a.ARM_REG_SP
_LR = a.ARM_REG_LR
_PC = a.ARM_REG_PC
_REG_IDS = tuple(getattr(a, f"ARM_REG_R{i}") for i in range(13)) + (_LR,)
_MAX_STATES = 4096


def _freeze(regs, slots):
    return (tuple(sorted(regs.items())), tuple(sorted(slots.items())))


def _write_slot(slots, address, width, value):
    """Write a byte range and invalidate every overlapping saved word."""
    for start in tuple(slots):
        if address < start + 4 and start < address + width:
            del slots[start]
    if width == 4 and address % 4 == 0:
        slots[address] = value


def _imm_operand(op):
    return op.imm if op.type == a.ARM_OP_IMM else None


def _reg_operand(op):
    return op.reg if op.type == a.ARM_OP_REG else None


def _offset(pointer, displacement=0):
    if isinstance(pointer, tuple) and len(pointer) == 2 and pointer[0] == "sp":
        return pointer[1] + displacement
    return None


def _transfer(facts, function, frame, site, state):
    ins = facts.decode(site)
    if (ins is None or site.isa != "thumb"
            or ins.size != 2 and ins.id != a.ARM_INS_BL):
        return None
    regs, slots = dict(state[0]), dict(state[1])
    regs.setdefault(_SP, ("sp", frame.offset_at(site)))
    operands = ins.operands
    if ins.id in (a.ARM_INS_BX,):
        return (regs, slots)
    if ins.id in (a.ARM_INS_B, a.ARM_INS_BX):
        return (regs, slots)
    if ins.id in (a.ARM_INS_PUSH, a.ARM_INS_POP):
        access = {(x.register, x.operation): x.offset for x in frame.accesses if x.site == site}
        for register in _REG_IDS:
            key = (register, "write" if ins.id == a.ARM_INS_PUSH else "read")
            if key not in access:
                continue
            at = access[key]
            if ins.id == a.ARM_INS_PUSH:
                _write_slot(slots, at, 4, regs.get(register))
            else:
                regs[register] = slots.get(at)
        sp = _offset(regs.get(_SP))
        if sp is None:
            return None
        regs[_SP] = ("sp", sp + (-4 * len(access) if ins.id == a.ARM_INS_PUSH else 4 * len(access)))
        return (regs, slots)

    # Exact register copies, immediate arithmetic, and MOV-from-SP aliases.
    if ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(operands) == 2:
        if any(operand.shift.type for operand in operands):
            return None
        dst, src = map(_reg_operand, operands)
        if dst is not None:
            value = regs.get(src) if src is not None else _imm_operand(operands[1])
            regs[dst] = value
            if dst == _SP and _offset(value) is None:
                return None
            return (regs, slots)
    if ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB) and len(operands) in (2, 3):
        dst = _reg_operand(operands[0])
        src = _reg_operand(operands[1]) if len(operands) == 3 else dst
        amount = _imm_operand(operands[-1])
        if dst is not None and src is not None and amount is not None:
            base = regs.get(src)
            delta = amount if ins.id == a.ARM_INS_ADD else -amount
            if _offset(base) is not None:
                value = ("sp", _offset(base) + delta)
            elif type(base) is int:
                value = (base + delta) & 0xffffffff
            else:
                value = None
            regs[dst] = value
            if dst == _SP and _offset(value) is None:
                return None
            return (regs, slots)

    # Multi-register transfers. Register order is architectural ascending;
    # this bounded proof handles IA aliases, the common Thumb encoding.
    if ins.id in (a.ARM_INS_LDM, a.ARM_INS_STM):
        if len(operands) < 2 or operands[0].type != a.ARM_OP_REG:
            return None
        base_reg = operands[0].reg
        base = regs.get(base_reg)
        address = _offset(base)
        reglist = [op.reg for op in operands[1:] if op.type == a.ARM_OP_REG]
        if not reglist or len(reglist) != len(operands) - 1:
            return None
        is_load = ins.id == a.ARM_INS_LDM
        mode = ins.mnemonic.lower()[3:]
        if mode not in ("", "ia", "ib", "da", "db"):
            return None
        if address is None:
            if type(base) is not int:
                return None
        count = len(reglist)
        start = (None if address is None else address + 4 if mode == "ib" else address - 4 * count if mode == "db"
                 else address - 4 * (count - 1) if mode == "da" else address)
        for index, register in enumerate(reglist):
            at = start + index * 4 if address is not None else None
            if is_load:
                regs[register] = slots.get(at) if at is not None else None
            elif at is not None:
                _write_slot(slots, at, 4, regs.get(register))
        if ins.writeback:
            if address is None:
                regs[base_reg] = None
            else:
                step = -4 * count if mode in ("da", "db") else 4 * count
                regs[base_reg] = ("sp", address + step)
        return (regs, slots)

    # Literal loads retain constants for pointers and values used later.
    literal = facts.literal(site)
    if literal is not None:
        regs[literal.register] = literal.value
        return (regs, slots)

    # Scalar loads and stores through a known stack alias or known global.
    memops = [(i, op) for i, op in enumerate(operands) if op.type == a.ARM_OP_MEM]
    if memops:
        if len(memops) != 1 or len(operands) != 2 or ins.writeback:
            return None
        index, mem = memops[0]
        if (mem.mem.index not in (0, a.ARM_REG_INVALID) or mem.shift.type
                or getattr(mem.mem, "subtracted", False)):
            return None
        base = regs.get(mem.mem.base)
        displacement = mem.mem.disp
        address = _offset(base, displacement)
        if address is None and type(base) is not int:
            # Unknown stores may alias a live stack word.
            return None
        regop = operands[1 - index]
        if regop.type != a.ARM_OP_REG:
            return None
        register = regop.reg
        widths = {a.ARM_INS_LDR: (True, 4), a.ARM_INS_LDRB: (True, 1), a.ARM_INS_LDRH: (True, 2),
                  a.ARM_INS_STR: (False, 4), a.ARM_INS_STRB: (False, 1), a.ARM_INS_STRH: (False, 2)}
        if ins.id not in widths:
            return None
        is_load, width = widths[ins.id]
        if is_load:
            if register == _SP:
                return None
            regs[register] = slots.get(address) if address is not None and width == 4 and address % 4 == 0 else None
        elif address is not None:
            _write_slot(slots, address, width, regs.get(register))
        return (regs, slots)

    # Opaque calls follow the source ABI. Passing an SP-derived pointer is not
    # modeled because the callee could retain or write through it.
    if ins.group(CS_GRP_CALL):
        if any(_offset(regs.get(getattr(a, f"ARM_REG_R{i}"))) is not None for i in range(4)):
            return None
        for register in (getattr(a, f"ARM_REG_R{i}") for i in range(4)):
            regs[register] = None
        regs[getattr(a, "ARM_REG_R12")] = None
        regs[_LR] = None
        return (regs, slots)

    try:
        _, written = ins.regs_access()
    except Exception:
        return None
    if _SP in written or _PC in written:
        return None
    for register in written:
        regs[register] = None
    return (regs, slots)


def _prove_returns(facts, function, frame, sites):
    """Propagate symbolic LR and stack state along paths reaching each BX."""
    successors = {}
    predecessors = {}
    for source, target in function.control_edges:
        successors.setdefault(source, set()).add(target)
        predecessors.setdefault(target, set()).add(source)
    # Stop-before boundaries can also represent paths that continue into an
    # outer loop. They are irrelevant to LR restoration at a separate return.
    ancestors = set(sites)
    pending_ancestors = list(sites)
    while pending_ancestors:
        target = pending_ancestors.pop()
        for source in predecessors.get(target, ()):
            if source not in ancestors:
                ancestors.add(source)
                pending_ancestors.append(source)
    initial_regs = {_SP: ("sp", 0), _LR: _LR_TOKEN}
    incoming = {function.entry: {_freeze(initial_regs, {})}}
    pending = deque([function.entry])
    seen_states = 0
    reached = {site: set() for site in sites}
    while pending:
        site = pending.popleft()
        states = tuple(incoming.get(site, ()))
        if site in sites:
            reached[site].update(states)
            continue
        if site not in ancestors:
            continue
        if site in function.scope_before or site in function.scope_exits:
            continue
        ins = facts.decode(site)
        if ins is None:
            return False
        for state in states:
            # Conditional instructions may or may not execute. The source CFG
            # records the control alternatives; retaining both effects is safe.
            after = _transfer(facts, function, frame, site, state)
            if after is None:
                return False
            outputs = {_freeze(*after)}
            if ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                outputs.add(state)
            for output in outputs:
                for target in successors.get(site, ()):
                    if target not in ancestors:
                        continue
                    bucket = incoming.setdefault(target, set())
                    if output not in bucket:
                        bucket.add(output)
                        pending.append(target)
                        seen_states += 1
                        if seen_states > _MAX_STATES:
                            return False
    if any(not states for states in reached.values()):
        return False
    for site, states in reached.items():
        if frame.offset_at(site) != 0:
            return False
        ins = facts.decode(site)
        if ins is None or not ins.operands or ins.operands[0].type != a.ARM_OP_REG:
            return False
        target_reg = ins.operands[0].reg
        for frozen_regs, _ in states:
            regs = dict(frozen_regs)
            if regs.get(target_reg) != _LR_TOKEN:
                return False
            if _offset(regs.get(_SP)) != 0:
                return False
    return True


def closed_input_region(image: bytes, entry: int, stop_before: tuple[int, ...], budget: int = 2048) -> FunctionFacts | None:
    """Return a complete local Thumb prefix whose early BX sites restore LR.

    Only unconditional BX-register escapes can be added as normal-return
    boundaries, and each such site must pass a stack-aware restoration proof.
    """
    if (not isinstance(image, bytes) or type(entry) is not int or entry < 0 or entry & 1
            or type(budget) is not int or budget <= 0):
        return None
    try:
        requested = tuple(CodeAddress(value) for value in stop_before)
        if any(type(value) is not int or value < 0 or value & 1 for value in stop_before):
            return None
        facts = facts_for(image)
        start = CodeAddress(entry)
        first = (facts.function_region(start, stop_before=requested, budget=min(budget, 8192))
                 if requested else facts.function(start, budget=min(budget, 8192)))
        if any(site.isa != "thumb" or (ins := facts.decode(site)) is None
               or ins.size != 2 and ins.id != a.ARM_INS_BL
               for site in first.instructions if site not in first.scope_before):
            return None
        reachable = set(first.instructions)
        requested_bx = []
        for endpoint in requested:
            if endpoint not in reachable:
                continue
            ins = facts.decode(endpoint)
            if ins is not None and ins.id == a.ARM_INS_BX:
                if ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                    return None
                requested_bx.append(endpoint)
        added = []
        successors = {source for source, _ in first.control_edges}
        bx_returns = [site for site in first.instructions if site not in successors and site not in first.scope_exits
                      and (ins := facts.decode(site)) is not None and ins.id == a.ARM_INS_BX]
        for site in set(first.scope_escapes) | set(bx_returns):
            ins = facts.decode(site)
            if ins is None or ins.id != a.ARM_INS_BX or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                return None
            added.append(site)
        endpoints = tuple(sorted(set(requested) | set(added), key=lambda pc: pc.address))
        proof_sites = tuple(sorted(set(added) | set(requested_bx), key=lambda pc: pc.address))
        if not added and not proof_sites:
            return first if first.complete and not first.unresolved and not first.truncated else None
        region = (facts.function_region(start, stop_before=endpoints, budget=min(budget, 8192))
                  if added else first)
        if (not region.complete or region.unresolved or region.truncated or region.scope_escapes
                or not region.instructions or any(target not in set(region.instructions) for _, target in region.control_edges)):
            return None
        frame = stack_frame(facts, region)
        if frame is None or not frame.complete or not _prove_returns(facts, region, frame, proof_sites):
            return None
        return region
    except (ValueError, TypeError, KeyError):
        return None
