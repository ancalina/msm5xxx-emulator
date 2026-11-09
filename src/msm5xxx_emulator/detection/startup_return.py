"""Entry-return preservation checks for closed startup procedures."""
from __future__ import annotations

from capstone import arm as a


def caller_preserves_entry_lr(facts, function, frame, calls, terminals,
                              initial_sp, allowed_calls, loop_store_ranges):
    """Prove the entry LR reaches each terminal return without memory clobber."""
    if not calls and all(
            (instruction := facts.decode(terminal)) is not None
            and instruction.id == a.ARM_INS_BX
            and instruction.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            and len(instruction.operands) == 1
            and instruction.operands[0].type == a.ARM_OP_REG
            and instruction.operands[0].reg == a.ARM_REG_LR
            and facts.reaching_definitions(
                function, terminal, a.ARM_REG_LR,
                include_entry=True) == (None,)
            for terminal in terminals):
        return True
    if type(initial_sp) is not int:
        return False
    saves = tuple(access for access in frame.accesses
                  if access.operation == 'write'
                  and access.register == a.ARM_REG_LR and access.width == 4
                  and facts.reaching_definitions(
                      function, access.site, a.ARM_REG_LR,
                      include_entry=True) == (None,)
                  and all(function.dominates(access.site, site)
                          for site, _ in calls))
    call_sites = {site for site, _ in calls}
    allowed_calls = frozenset(allowed_calls)
    unmodelled = facts.unmodelled_memory(function)
    if unmodelled is None:
        return False
    unmodelled = frozenset(unmodelled)
    frame_sites = frozenset(access.site for access in frame.accesses)
    accesses = {access.instruction: access
                for access in function.symbolic_accesses
                if access.operation == 'write'}
    loop_stores = {site for site, _lo, _hi in loop_store_ranges}

    for saved in saves:
        if any(access.operation == 'write'
               and access.offset < saved.offset + saved.width
               and saved.offset < access.offset + access.width
               for access in frame.accesses if access != saved):
            continue
        address = initial_sp + saved.offset
        if address < 0 or address + saved.width > 0x100000000:
            continue
        width = saved.width
        valid = True
        for terminal in terminals:
            ins = facts.decode(terminal)
            reads = tuple(access for access in frame.accesses
                          if access.operation == 'read' and access.width == 4
                          and access.offset == saved.offset
                          and function.dominates(access.site, terminal))
            if (ins is not None and ins.id == a.ARM_INS_BX
                    and len(ins.operands) == 1
                    and ins.operands[0].type == a.ARM_OP_REG):
                register = ins.operands[0].reg
                reads = tuple(access for access in reads
                              if access.register == register
                              and facts.reaching_definitions(
                                  function, terminal, register)
                              == (access.site,))
            elif ins is not None and ins.id == a.ARM_INS_POP:
                reads = tuple(access for access in reads
                              if access.site == terminal
                              and access.register == a.ARM_REG_PC)
            else:
                reads = ()
            if len(reads) != 1:
                valid = False
                break

            read = reads[0]
            overlapping = set()
            unknown_writes = set()
            overlapping.update(
                site for site, lo, hi in loop_store_ranges
                if address < hi and lo < address + width)
            for site, access in accesses.items():
                if site in loop_stores:
                    continue
                target = access.address
                if getattr(target, 'kind', None) == 'const':
                    target = target.value
                if (type(target) is not int or type(access.width) is not int
                        or access.predicate not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                    unknown_writes.add(site)
                    continue
                if target < address + width and address < target + access.width:
                    overlapping.add(site)

            def defines(site):
                if site == saved.site or site in overlapping:
                    access = accesses.get(site)
                    if site != saved.site and (
                            access is None
                            or access.predicate not in (a.ARM_CC_AL,
                                                        a.ARM_CC_INVALID)):
                        return None
                    return True
                if site in allowed_calls or site in frame_sites:
                    return False
                if site in call_sites or site in unknown_writes or site in unmodelled:
                    return None
                return False

            definitions = facts._reaching_sites(
                function, read.site, frozenset(), False, defines)
            if definitions != (saved.site,):
                valid = False
                break
        if valid:
            return True
    return False
