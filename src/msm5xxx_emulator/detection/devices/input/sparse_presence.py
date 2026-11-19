"""Closed source proofs for sparse scanner presence and released-contact reads."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress


def _reg(ins, index):
    return (ins.operands[index].reg
            if ins is not None and index < len(ins.operands)
            and ins.operands[index].type == a.ARM_OP_REG else None)


def _imm(ins, index):
    return (ins.operands[index].imm
            if ins is not None and index < len(ins.operands)
            and ins.operands[index].type == a.ARM_OP_IMM else None)


def _is_shift(ins, kind, output, source, amount):
    return (ins is not None and ins.id == kind and len(ins.operands) == 3
            and _reg(ins, 0) == output and _reg(ins, 1) == source
            and _imm(ins, 2) == amount)


def _read_pointer(facts, function, site, descriptor):
    ins = facts.decode(site)
    if (ins is None or ins.id != a.ARM_INS_LDRH or len(ins.operands) != 2
            or ins.operands[1].type != a.ARM_OP_MEM
            or ins.operands[1].mem.index or ins.operands[1].mem.disp != 0):
        return None
    base = ins.operands[1].mem.base
    value = facts.register_value(function, site, base)
    if (value.kind != "load" or len(value.operands) != 1
            or value.operands[0].kind != "const"
            or value.operands[0].value != descriptor + 0x34):
        return None
    return _reg(ins, 0)


def nibble_read_sites(facts, function, descriptor):
    """Find D+34 halfword reads whose bit 0..3 reaches a CMP #15 branch."""
    sites = []
    instructions = sorted(function.instructions, key=lambda site: site.address)
    reads = {site: _read_pointer(facts, function, site, descriptor)
             for site in instructions}
    for read_site, read_reg in reads.items():
        if read_reg is None:
            continue
        for compare_site in instructions:
            if not read_site.address < compare_site.address <= read_site.address + 0x30:
                continue
            compare = facts.decode(compare_site)
            output = _reg(compare, 0)
            if (compare is None or compare.id != a.ARM_INS_CMP
                    or output is None or _imm(compare, 1) != 0xf):
                continue
            definitions = facts.reaching_definitions(function, compare_site, output)
            if definitions is None or len(definitions) != 1:
                continue
            lsr_site = definitions[0]
            lsr = facts.decode(lsr_site)
            source = _reg(lsr, 1)
            if (not _is_shift(lsr, a.ARM_INS_LSR, output, source, 28)
                    or facts.reaching_definitions(function, lsr_site, source) is None
                    or len(facts.reaching_definitions(function, lsr_site, source)) != 1):
                continue
            lsl_site = facts.reaching_definitions(function, lsr_site, source)[0]
            lsl = facts.decode(lsl_site)
            lsl_source = _reg(lsl, 1)
            if (not _is_shift(lsl, a.ARM_INS_LSL, source, lsl_source, 28)
                    or facts.reaching_definitions(function, lsl_site, lsl_source)
                        != (read_site,)):
                continue
            for branch_site in instructions:
                if not compare_site.address < branch_site.address <= compare_site.address + 8:
                    continue
                branch = facts.decode(branch_site)
                if (branch is not None and branch.id == a.ARM_INS_B
                        and branch.cc in (a.ARM_CC_EQ, a.ARM_CC_NE)
                        and facts.reaching_definitions(
                            function, branch_site, a.ARM_REG_CPSR) == (compare_site,)):
                    sites.append({"read_site": read_site.address,
                                  "compare_site": compare_site.address,
                                  "branch_site": branch_site.address,
                                  "branch_cc": branch.cc})
                    break
            break
    return tuple(sites)


def presence_for_loop(facts, function, samples, loop_site):
    """Choose the closest preceding sampled nibble that has a path to a loop."""
    edges = {}
    for source, target in function.control_edges:
        edges.setdefault(source, set()).add(target)

    def reaches(start):
        pending, seen = [start], set()
        goal = CodeAddress(loop_site, "thumb")
        while pending and len(seen) <= len(function.instructions):
            current = pending.pop()
            if current == goal:
                return True
            if current in seen:
                continue
            seen.add(current)
            pending.extend(edges.get(current, ()))
        return False

    candidates = [sample for sample in samples
                 if sample["read_site"] < loop_site
                 and reaches(CodeAddress(sample["branch_site"], "thumb"))]
    if not candidates:
        return None
    return max(candidates, key=lambda sample: sample["read_site"])["read_site"]


def _callee_register_dependencies(image, facts, call_site, register,
                                  descriptor, descriptor_source, cache):
    target = facts.thumb_call_target(call_site.address)
    if target is None:
        return None
    key = (target, register, descriptor, descriptor_source)
    if key in cache:
        return cache[key]
    callee = facts.function(CodeAddress(target, "thumb"), budget=512)
    if (not callee.complete or callee.truncated or callee.unresolved):
        cache[key] = None
        return None
    for site in callee.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id == a.ARM_INS_IT
                or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                and ins.id != a.ARM_INS_B):
            cache[key] = None
            return None
    from .mapped_seven_rows_flow import _callee_preserves_register
    if _callee_preserves_register(image, target, register):
        dependencies = set()
        for site in callee.instructions:
            ins = facts.decode(site)
            if ins is None:
                cache[key] = None
                return None
            dependencies.add((site.address, ins.size))
        dependencies.update((literal.pool, 4) for literal in callee.literals)
        cache[key] = frozenset(dependencies)
        return cache[key]
    from .five_column_flow import _saved_frame_call
    cache[key] = _saved_frame_call(
        image, target, register, tuple(range(256)), descriptor,
        descriptor_source)
    if cache[key] is not None:
        cache[key] = frozenset(cache[key])
    return cache[key]


def _event_reaches_store(image, facts, function, jump_site, store_site,
                         register, descriptor, descriptor_source,
                         callee_cache):
    edges = {}
    for source, target in function.control_edges:
        edges.setdefault(source, set()).add(target)
    instructions = set(function.instructions)
    calls = {site for site, _ in function.calls}
    calls.update(site for site in instructions
                 if (ins := facts.decode(site)) is not None
                 and ins.id in (a.ARM_INS_BL, a.ARM_INS_BLX))
    # IT state makes the local CFG insufficient to establish unconditional
    # preservation. Sparse event paths currently have no IT-based grammar.
    if any((ins := facts.decode(site)) is None or ins.id == a.ARM_INS_IT
           for site in function.instructions):
        return False
    pending = list(edges.get(jump_site, ()))
    seen = set()
    call_dependencies = set()
    while pending and len(seen) <= len(function.instructions):
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        # A call route counts only when its bounded callee proof establishes
        # preservation of the event register and returns its source spans.
        if current == store_site:
            return call_dependencies
        if current in calls:
            proof = _callee_register_dependencies(
                image, facts, current, register, descriptor, descriptor_source,
                callee_cache)
            if proof is None:
                continue
            call_dependencies.update(proof)
            pending.extend(edges.get(current, ()))
            continue
        ins = facts.decode(current)
        if ins is None:
            continue
        try:
            _, writes = ins.regs_access()
        except Exception:
            return False
        if register in writes:
            continue
        pending.extend(edges.get(current, ()))
    return False


def _function_reaches(function, source, target):
    edges = {}
    for start, end in function.control_edges:
        edges.setdefault(start, set()).add(end)
    pending, seen = [CodeAddress(source, "thumb")], set()
    goal = CodeAddress(target, "thumb")
    while pending and len(seen) <= len(function.instructions):
        current = pending.pop()
        if current == goal:
            return True
        if current not in seen:
            seen.add(current)
            pending.extend(edges.get(current, ()))
    return False


def released_contact(image, facts, function, descriptor, descriptor_source,
                     sense_address, samples, ram_base, ram_end, nor_end, *,
                     event_register, event_load_site):
    """Prove a separate D+34 bit-4 gate, released high path and state event."""
    if (type(event_register) is not int or not 0 <= event_register < 8
            or type(event_load_site) is not int or event_load_site < 0):
        return None
    event_reg = a.ARM_REG_R0 + event_register
    numeric_site = CodeAddress(event_load_site, "thumb")
    numeric_load = facts.decode(numeric_site)
    if (numeric_site not in function.instructions or numeric_load is None
            or numeric_load.id != a.ARM_INS_LDRB
            or _reg(numeric_load, 0) != event_reg):
        return None
    if (descriptor_source + 0x38 > nor_end
            or int.from_bytes(image[descriptor_source + 8:descriptor_source + 12], "little")
                != sense_address
            or int.from_bytes(image[descriptor_source + 0x34:descriptor_source + 0x38], "little")
                != sense_address):
        return None
    instructions = sorted(function.instructions, key=lambda site: site.address)
    contacts = []
    callee_cache = {}
    for read_site in instructions:
        read_reg = _read_pointer(facts, function, read_site, descriptor)
        if read_reg is None:
            continue
        shift_site = None
        for candidate in instructions:
            if not read_site.address < candidate.address <= read_site.address + 10:
                continue
            shift = facts.decode(candidate)
            if (_is_shift(shift, a.ARM_INS_LSR, read_reg, read_reg, 5)
                    and facts.reaching_definitions(
                        function, candidate, read_reg) == (read_site,)):
                shift_site = candidate
                break
        if shift_site is None:
            continue
        branch_site = CodeAddress(shift_site.address + 2, "thumb")
        branch = facts.decode(branch_site)
        if (branch is None or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_HS
                or facts.reaching_definitions(function, branch_site, a.ARM_REG_CPSR)
                    != (shift_site,)):
            continue
        event_site = CodeAddress(branch_site.address + 2, "thumb")
        event = facts.decode(event_site)
        jump_site = CodeAddress(event_site.address + 2, "thumb")
        jump = facts.decode(jump_site)
        if (event is None or event.id != a.ARM_INS_MOV or _reg(event, 0) != event_reg
                or _imm(event, 1) != 0x51 or jump is None or jump.id != a.ARM_INS_B
                or jump.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
            continue
        handler = CodeAddress(_imm(jump, 0), "thumb")
        stores = []
        for store_site in instructions:
            store = facts.decode(store_site)
            if (store_site.address < handler.address or store is None
                    or store.id != a.ARM_INS_STRB or len(store.operands) != 2
                    or _reg(store, 0) != event_reg
                    or store.operands[1].type != a.ARM_OP_MEM
                    or store.operands[1].mem.disp != 4):
                continue
            aux_dependencies = _event_reaches_store(
                image, facts, function, jump_site, store_site, event_reg,
                descriptor, descriptor_source, callee_cache)
            numeric_dependencies = _event_reaches_store(
                image, facts, function, numeric_site, store_site, event_reg,
                descriptor, descriptor_source, callee_cache)
            if aux_dependencies is False or numeric_dependencies is False:
                continue
            if aux_dependencies is None or numeric_dependencies is None:
                continue
            base = store.operands[1].mem.base
            state = facts.register_value(function, store_site, base)
            if (state.kind == "const" and type(state.value) is int
                    and ram_base <= state.value and state.value + 5 <= ram_end):
                stores.append((store_site, state.value,
                               set(aux_dependencies) | set(numeric_dependencies)))
        if not stores or len({state for _, state, _ in stores}) != 1:
            continue
        high_target = _imm(branch, 0)
        if not any(sample["read_site"] >= high_target and _function_reaches(
                function, high_target, sample["read_site"]) for sample in samples):
            continue
        store_site, state, event_dependencies = stores[0]
        dependencies = {(read_site.address, 2), (shift_site.address, 2),
                         (branch_site.address, 2), (event_site.address, 2),
                         (jump_site.address, 2), (handler.address, 2),
                         (store_site.address, 2), (descriptor_source, 0x38)}
        for site in function.instructions:
            instruction = facts.decode(site)
            if instruction is not None:
                dependencies.add((site.address, instruction.size))
        dependencies.update((literal.pool, 4) for literal in function.literals)
        dependencies.update(event_dependencies)
        literal = facts.literal(handler)
        if literal is not None:
            dependencies.add((literal.pool, 4))
        if any(sample["read_site"] == read_site.address for sample in samples):
            continue
        contacts.append({"status_site": read_site.address,
                         "released_level": 0x10,
                         "event_store_site": store_site.address,
                         "event_register": event_register,
                         "event_state_address": state + 4,
                         "dependencies": sorted(dependencies),
                         "state_ranges": [(state, 5)]})
    return contacts[0] if len(contacts) == 1 else None
