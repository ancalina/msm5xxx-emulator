"""CFG proof for aligned prefix, unrolled word chunks, and word tails."""
from __future__ import annotations

from capstone import arm as a

from .facts import CodeAddress
from .startup_reset_ldm_copy import _const, _field_origin
from .startup_reset_pulsed_copy import _closed_returns


def _reg(ins, index):
    if ins is None or index >= len(ins.operands):
        return None
    operand = ins.operands[index]
    return operand.reg if operand.type == a.ARM_OP_REG else None


def _imm(ins, index):
    if ins is None or index >= len(ins.operands):
        return None
    operand = ins.operands[index]
    return operand.imm if operand.type == a.ARM_OP_IMM else None


def _one_word_pair(load, store, source_reg, destination_reg, value_reg):
    return bool(
        load is not None and store is not None
        and load.id == a.ARM_INS_LDM and store.id == a.ARM_INS_STM
        and load.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
        and store.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)
        and load.size == store.size == 2
        and load.writeback and store.writeback
        and len(load.operands) == len(store.operands) == 2
        and _reg(load, 0) == source_reg and _reg(store, 0) == destination_reg
        and _reg(load, 1) == _reg(store, 1) == value_reg)


def _edges(function):
    edges, predecessors = {}, {}
    for left, right in function.control_edges:
        edges.setdefault(left, set()).add(right)
        predecessors.setdefault(right, set()).add(left)
    return edges, predecessors


def chunked_word_loop_proof(facts, function, fields, source_cell,
                            destination_cell, size_cell, source, destination,
                            size, nor_end, target_ranges):
    """Prove a CFG-closed prefix/bulk/tail LDMIA/STMIA copy.

    The prefix advances one word until the destination is 32-byte aligned.
    The middle loop copies a fixed contiguous burst of single-word pairs and
    runs only when ``destination + burst < end``. The tail copies one word
    until destination reaches end. The burst length is derived from the
    number of decoded pairs and the reaching immediate additions.
    """
    if (not function.complete or function.truncated or function.unresolved
            or type(source_cell) is not int
            or (destination_cell, size_cell) != (source_cell + 4, source_cell + 8)
            or any(type(value) is not int for value in
                   (source, destination, size, nor_end))
            or source_cell < 0 or source_cell + 12 > nor_end or nor_end <= 0
            or any(type(lo) is not int or type(hi) is not int or lo < 0
                   or hi <= lo or hi > 0x100000000 for lo, hi in target_ranges)
            or size <= 0 or size & 3 or source < 0 or source & 3
            or destination < 0 or destination & 3
            or source + size > nor_end
            or not (source + size <= destination
                    or destination + size <= source)
            or not any(lo <= destination and destination + size <= hi
                       for lo, hi in target_ranges)):
        return None

    instructions = {site: facts.decode(site) for site in function.instructions}
    if any(ins is None or site.address < 0 or site.address + ins.size > nor_end
           for site, ins in instructions.items()):
        return None
    if any(type(item.pool) is not int or item.pool < 0 or item.pool + 4 > nor_end
           for item in function.literals):
        return None
    edges, predecessors = _edges(function)

    def following(site):
        ins = instructions.get(site)
        return (CodeAddress(site.address + ins.size, site.isa, site.phase, site.bank)
                if ins is not None else None)

    def direct_branch(site, condition=None):
        ins = instructions.get(site)
        if (ins is None or ins.id != a.ARM_INS_B or ins.size != 2
                or len(ins.operands) != 1 or _imm(ins, 0) is None
                or (condition is not None and ins.cc != condition)
                or (condition is None
                    and ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID))):
            return None
        return CodeAddress(_imm(ins, 0), site.isa, site.phase, site.bank)

    gprs = {a.ARM_REG_R0 + index for index in range(13)}
    for prefix_cmp_site, prefix_cmp in instructions.items():
        if (prefix_cmp is None or prefix_cmp_site.isa != "thumb"
                or prefix_cmp.id != a.ARM_INS_CMP or prefix_cmp.size != 2
                or prefix_cmp.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(prefix_cmp.operands) != 2):
            continue
        destination_reg, end_reg = _reg(prefix_cmp, 0), _reg(prefix_cmp, 1)
        prefix_branch_site = following(prefix_cmp_site)
        prefix_body = direct_branch(prefix_branch_site, a.ARM_CC_LO)
        prefix_false = following(prefix_branch_site)
        bulk_guard = direct_branch(prefix_false)
        if (destination_reg not in gprs or end_reg not in gprs
                or destination_reg == end_reg or prefix_body is None
                or bulk_guard is None):
            continue

        load_site = prefix_body
        prefix_load = instructions.get(load_site)
        prefix_store_site = following(load_site)
        prefix_store = instructions.get(prefix_store_site)
        alignment_site = following(prefix_store_site)
        alignment = instructions.get(alignment_site)
        alignment_branch_site = following(alignment_site)
        alignment_branch = instructions.get(alignment_branch_site)
        to_bulk_site = following(alignment_branch_site)
        to_bulk = instructions.get(to_bulk_site)
        if (not _one_word_pair(prefix_load, prefix_store,
                               _reg(prefix_load, 0), destination_reg,
                               _reg(prefix_load, 1))
                or prefix_store_site is None or alignment is None
                or alignment.id != a.ARM_INS_LSL or alignment.size != 2
                or alignment.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(alignment.operands) != 3
                or _reg(alignment, 1) != destination_reg
                or _imm(alignment, 2) != 27
                or _reg(alignment, 0) in (destination_reg, end_reg,
                                          _reg(prefix_load, 0))
                or alignment_branch is None or alignment_branch.size != 2
                or alignment_branch.id != a.ARM_INS_B
                or alignment_branch.cc != a.ARM_CC_NE
                or direct_branch(to_bulk_site) != bulk_guard):
            continue
        source_reg = _reg(prefix_load, 0)
        value_reg = _reg(prefix_load, 1)
        if (source_reg not in gprs or value_reg not in gprs
                or len({source_reg, destination_reg, end_reg, value_reg}) != 4):
            continue
        if (direct_branch(alignment_branch_site, a.ARM_CC_NE) != prefix_cmp_site
                or edges.get(prefix_cmp_site) != {prefix_branch_site}
                or edges.get(prefix_branch_site) !=
                    {prefix_body, prefix_false}
                or edges.get(prefix_false) != {bulk_guard}
                or edges.get(load_site) != {prefix_store_site}
                or edges.get(prefix_store_site) != {alignment_site}
                or edges.get(alignment_site) != {alignment_branch_site}
                or edges.get(alignment_branch_site) !=
                    {prefix_cmp_site, to_bulk_site}
                or predecessors.get(prefix_body) != {prefix_branch_site}
                or predecessors.get(prefix_store_site) != {load_site}
                or predecessors.get(alignment_site) != {prefix_store_site}
                or predecessors.get(alignment_branch_site) != {alignment_site}
                or predecessors.get(to_bulk_site) != {alignment_branch_site}
                or (prefix_branch_site.address, prefix_body.address)
                    not in function.back_edges
                or facts.reaching_definitions(
                    function, prefix_branch_site, a.ARM_REG_CPSR)
                    != (prefix_cmp_site,)
                or facts.reaching_definitions(
                    function, alignment_branch_site, a.ARM_REG_CPSR)
                    != (alignment_site,)):
            continue

        # The bulk body is a contiguous run of identical one-word pairs.
        bulk_test_site = following(bulk_guard)
        bulk_cmp_site = following(bulk_test_site)
        bulk_branch_site = following(bulk_cmp_site)
        bulk_start = direct_branch(bulk_branch_site, a.ARM_CC_LO)
        bulk_false_site = following(bulk_branch_site)
        bulk_false = direct_branch(bulk_false_site)
        if (bulk_start is None or instructions.get(bulk_guard) is None
                or instructions[bulk_guard].id != a.ARM_INS_ADD
                or instructions[bulk_guard].cc not in
                    (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or instructions[bulk_guard].size != 2
                or instructions.get(bulk_test_site) is None
                or instructions[bulk_test_site].id != a.ARM_INS_ADD
                or instructions[bulk_test_site].size != 2
                or instructions[bulk_test_site].cc not in
                    (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or instructions.get(bulk_cmp_site) is None
                or instructions[bulk_cmp_site].id != a.ARM_INS_CMP
                or instructions[bulk_cmp_site].size != 2
                or instructions.get(bulk_branch_site) is None
                or instructions[bulk_branch_site].cc != a.ARM_CC_LO
                or bulk_false is None):
            continue
        chunk_scratch = _reg(instructions[bulk_guard], 0)
        if (chunk_scratch not in gprs or chunk_scratch in
                (source_reg, destination_reg, end_reg)
                or _reg(instructions[bulk_guard], 1) != destination_reg
                or _reg(instructions[bulk_test_site], 0) != chunk_scratch
                or _reg(instructions[bulk_cmp_site], 0) != chunk_scratch
                or _reg(instructions[bulk_cmp_site], 1) != end_reg):
            continue
        first_addend = _imm(instructions[bulk_guard], 2)
        second_addend = _imm(instructions[bulk_test_site], 1)
        if (len(instructions[bulk_guard].operands) != 3
                or len(instructions[bulk_test_site].operands) != 2
                or _reg(instructions[bulk_test_site], 0) != chunk_scratch
                or first_addend is None or second_addend is None):
            continue
        chunk_size = first_addend + second_addend
        if (chunk_size <= 0 or chunk_size & 3
                or destination + size + chunk_size >= 0x100000000):
            continue

        bulk_pairs = []
        cursor = bulk_start
        while cursor.address < bulk_guard.address:
            load = instructions.get(cursor)
            store_site = following(cursor)
            store = instructions.get(store_site)
            if (not _one_word_pair(load, store, source_reg, destination_reg,
                                   value_reg)
                    or store_site is None
                    or edges.get(cursor) != {store_site}
                    or edges.get(store_site) != {following(store_site)}):
                bulk_pairs = []
                break
            bulk_pairs.append((cursor, store_site))
            cursor = following(store_site)
        if (not bulk_pairs or cursor != bulk_guard
                or len(bulk_pairs) * 4 != chunk_size
                or edges.get(bulk_guard) != {bulk_test_site}
                or edges.get(bulk_test_site) != {bulk_cmp_site}
                or edges.get(bulk_cmp_site) != {bulk_branch_site}
                or edges.get(bulk_branch_site) != {bulk_start, bulk_false_site}
                or edges.get(bulk_false_site) != {bulk_false}
                or predecessors.get(bulk_test_site) != {bulk_guard}
                or predecessors.get(bulk_cmp_site) != {bulk_test_site}
                or predecessors.get(bulk_branch_site) != {bulk_cmp_site}
                or predecessors.get(bulk_false_site) != {bulk_branch_site}
                or predecessors.get(bulk_guard) !=
                    {prefix_false, to_bulk_site, bulk_pairs[-1][1]}
                or predecessors.get(bulk_start) != {bulk_branch_site}
                or (bulk_branch_site.address, bulk_start.address)
                    not in function.back_edges
                or facts.reaching_definitions(
                    function, bulk_branch_site, a.ARM_REG_CPSR)
                    != (bulk_cmp_site,)
                or facts.reaching_definitions(
                    function, bulk_cmp_site, chunk_scratch)
                    != (bulk_test_site,)):
            continue
        if any(predecessors.get(load_site) !=
               ({bulk_branch_site} if index == 0 else
                {bulk_pairs[index - 1][1]})
               or predecessors.get(store_site) != {load_site}
               for index, (load_site, store_site) in enumerate(bulk_pairs)):
            continue

        tail_cmp_site = bulk_false
        tail_cmp = instructions.get(tail_cmp_site)
        tail_branch_site = following(tail_cmp_site)
        tail_branch = instructions.get(tail_branch_site)
        tail_body = (CodeAddress(_imm(tail_branch, 0), tail_cmp_site.isa,
                                 tail_cmp_site.phase, tail_cmp_site.bank)
                     if tail_branch is not None
                     and tail_branch.id == a.ARM_INS_B
                     and tail_branch.cc == a.ARM_CC_LO
                     and len(tail_branch.operands) == 1
                     and _imm(tail_branch, 0) is not None else None)
        tail_store_site = following(tail_body) if tail_body is not None else None
        tail_store = instructions.get(tail_store_site)
        if (tail_cmp is None or tail_cmp.id != a.ARM_INS_CMP
                or tail_cmp.size != 2 or tail_cmp.cc not in
                    (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(tail_cmp.operands) != 2
                or _reg(tail_cmp, 0) != destination_reg
                or _reg(tail_cmp, 1) != end_reg
                or tail_branch is None or tail_branch.size != 2
                or tail_body is None
                or not _one_word_pair(instructions.get(tail_body), tail_store,
                                      source_reg, destination_reg, value_reg)
                or following(tail_store_site) != tail_cmp_site
                or edges.get(tail_body) != {tail_store_site}
                or edges.get(tail_store_site) != {tail_cmp_site}
                or edges.get(tail_cmp_site) != {tail_branch_site}
                or edges.get(tail_branch_site) !=
                    {tail_body, following(tail_branch_site)}
                or predecessors.get(tail_body) != {tail_branch_site}
                or predecessors.get(tail_store_site) != {tail_body}
                or predecessors.get(tail_cmp_site) !=
                    {tail_store_site, bulk_false_site}
                or (tail_branch_site.address, tail_body.address)
                    not in function.back_edges
                or facts.reaching_definitions(
                    function, tail_branch_site, a.ARM_REG_CPSR)
                    != (tail_cmp_site,)):
            continue

        # All three loops are closed, and no other entry can bypass setup.
        prefix_preheaders = [
            site for site in predecessors.get(prefix_cmp_site, ())
            if site != alignment_branch_site
            and direct_branch(site) == prefix_cmp_site]
        if (len(prefix_preheaders) != 1
                or predecessors.get(prefix_cmp_site) !=
                    {prefix_preheaders[0], alignment_branch_site}
                or not edges.get(prefix_preheaders[0]) == {prefix_cmp_site}
                or not _closed_returns(facts, function, instructions, edges,
                                       prefix_preheaders[0])):
            continue

        cut_edges = ((alignment_branch_site, prefix_cmp_site),
                     (bulk_branch_site, bulk_start),
                     (tail_branch_site, tail_body))
        if (_field_origin(facts, function, fields, prefix_body, source_reg,
                          cut_edges) != source_cell
                or _field_origin(facts, function, fields, prefix_body,
                                 destination_reg, cut_edges)
                    != destination_cell
                or _const(facts, function, prefix_body, source_reg,
                          cut_edges) != source
                or _const(facts, function, prefix_body, destination_reg,
                          cut_edges) != destination):
            continue

        end_defs = facts.reaching_definitions(
            function, prefix_cmp_site, end_reg, cut_edges=cut_edges)
        if end_defs is None or len(end_defs) != 1:
            continue
        end_site = end_defs[0]
        end_add = instructions.get(end_site)
        if (end_add is None or end_add.id != a.ARM_INS_ADD
                or end_add.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or len(end_add.operands) != 3
                or _reg(end_add, 0) != end_reg
                or any(op.shift.type or op.subtracted
                       for op in end_add.operands)):
            continue
        origins = (_field_origin(facts, function, fields, end_site,
                                 _reg(end_add, 1), ()),
                   _field_origin(facts, function, fields, end_site,
                                 _reg(end_add, 2), ()))
        if (None in origins or set(origins) != {destination_cell, size_cell}
                or _const(facts, function, prefix_cmp_site, end_reg,
                          cut_edges) != destination + size):
            continue

        all_loop_sites = {prefix_cmp_site, prefix_branch_site, prefix_body,
                          prefix_store_site, alignment_site,
                          alignment_branch_site, to_bulk_site,
                          bulk_guard, bulk_test_site, bulk_cmp_site,
                          bulk_branch_site, bulk_false_site, bulk_start,
                          tail_cmp_site, tail_branch_site, tail_body,
                          tail_store_site, following(tail_branch_site)}
        for pair in bulk_pairs:
            all_loop_sites.update(pair)
        if any(site not in instructions for site in all_loop_sites):
            continue
        evidence = {(source_cell, 12), (source, size)}
        evidence.update((site.address, instructions[site].size)
                        for site in instructions)
        evidence.update((item.pool, 4) for item in function.literals)
        evidence.update((site.address, facts.decode(site).size)
                        for sites in fields.values() for site in sites)
        return size, tuple(sorted(evidence)), following(tail_branch_site)
    return None
