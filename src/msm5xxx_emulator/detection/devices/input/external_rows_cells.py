"""Loop and local-cell flow proofs for external-latch key scanners."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress
from .external_rows_flow import (_constant, _register_lineage, _writes_register)
from .row_execution import _Bits, _row_outputs


def _register_unchanged(function, facts, register, start, end):
    return not any(_writes_register(facts, site, register)
                   for site in function.instructions
                   if start.address < site.address < end.address)


def _reg_sources(ins):
    return {operand.reg for operand in ins.operands[1:]
            if operand.type == a.ARM_OP_REG}

def _linked_table_base(function, facts, site, table_pointer, table_address):
    """Return the subtraction source register only for this linked table base."""
    ins = facts.decode(site)
    if (ins is None or ins.id != a.ARM_INS_SUB
            or len(ins.operands) not in (2, 3)
            or ins.operands[0].type != a.ARM_OP_REG
            or ins.operands[-1].type != a.ARM_OP_IMM):
        return None
    register = ins.operands[0].reg
    source = _constant(facts.register_value(function, site, register))
    if source != table_pointer or source - ins.operands[-1].imm != table_address:
        return None
    return register


def _indexed_mul(function, facts, loop):
    """Find `counter * 6` inside a proven bounded loop."""
    for site in function.instructions:
        if not loop["target"] <= site.address < loop["compare"].address:
            continue
        ins = facts.decode(site)
        if (ins is None or ins.mnemonic not in ("mul", "muls")
                or len(ins.operands) != 3
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[0].reg != loop["counter"]
                or loop["counter"] not in _reg_sources(ins)):
            continue
        if any(_constant(facts.register_value(function, site, operand.reg)) == 6
               for operand in ins.operands[1:]
               if operand.type == a.ARM_OP_REG
               and operand.reg != loop["counter"]):
            return site
    return None


def _sense_capture_matches(raw, row, captured_address, table_address):
    """Require active-low sense bits to select the matching column-major cell."""
    active = [column for column in range(5) if not (raw & (1 << column))]
    return (len(active) == 1 and captured_address ==
            table_address + active[0] * 6 + row)


def _column_contacts_linked(image, function, facts, row_loop, column_loop,
                            row_register, raw_event_load, table_address):
    """Execute the real sense-to-cell path for all active-low row/column pairs."""
    sample_sites = sorted({access.instruction for access in function.accesses
                           if access.operation == "read" and access.width == 4
                           and access.address == 0x09000070
                           and row_loop["target"] <= access.instruction.address
                           < row_loop["increment"].address},
                          key=lambda site: site.address)
    if len(sample_sites) != 1:
        return None
    capture_end = column_loop["branch"].address + 2
    evidence = set()
    for sample_site in sample_sites:
        sample = facts.decode(sample_site)
        if (sample is None or sample.id != a.ARM_INS_LDR
                or len(sample.operands) != 2
                or sample.operands[0].type != a.ARM_OP_REG):
            continue
        raw_register = sample.operands[0].reg
        proof = set()
        valid = True
        for row in range(6):
            for column in range(5):
                raw = 0x1f ^ (1 << column)
                captured = _row_outputs(
                    image, sample_site.address + sample.size,
                    raw_event_load.address,
                    {raw_register: _Bits.constant(raw),
                     row_register: _Bits.constant(row)},
                    0, 0, capture_load=True, capture_end=capture_end,
                    byte_memory=((0xffff0004, 30),))
                if (captured is None or not _sense_capture_matches(
                        raw, row, captured[0], table_address)):
                    valid = False
                    break
                proof.update(captured[1])
            if not valid:
                break
        if valid:
            evidence.update(proof)
    return evidence or None


def _raw_cell_stage(image, function, facts, row_load, raw_event_load,
                    table_pointer, table_address, loops):
    """Bind scan rows and columns to row-vector and raw 30-cell indices."""
    first = facts.decode(row_load)
    event = facts.decode(raw_event_load)
    if (first is None or first.id != a.ARM_INS_LDRH
            or first.operands[1].type != a.ARM_OP_MEM
            or event is None or event.id != a.ARM_INS_LDRB
            or event.operands[1].type != a.ARM_OP_MEM):
        return None
    row_lineage = _register_lineage(function, facts, row_load,
                                    first.operands[1].mem.index)
    if row_lineage is None:
        return None
    row_reg = row_lineage[0]
    row_loops = [loop for loop in loops if loop["bound"] == 6
                  and loop["counter"] == row_reg
                  and loop["target"] <= row_load.address
                  < loop["increment"].address
                  and loop["target"] <= raw_event_load.address
                  < loop["increment"].address]
    if len(row_loops) != 1 or event.operands[1].mem.index != row_reg:
        return None
    column_loops = [loop for loop in loops if loop["bound"] == 5
                    and loop["target"] <= raw_event_load.address
                    < loop["increment"].address]
    for column_loop in column_loops:
        multiply = _indexed_mul(function, facts, column_loop)
        if multiply is None:
            continue
        column_reg = column_loop["counter"]
        load_base = event.operands[1].mem.base
        for sub_site in function.instructions:
            pointer_reg = _linked_table_base(function, facts, sub_site,
                                             table_pointer, table_address)
            if pointer_reg is None:
                continue
            for add_site in function.instructions:
                if not sub_site.address < add_site.address <= raw_event_load.address:
                    continue
                add = facts.decode(add_site)
                if (add is None or add.id != a.ARM_INS_ADD
                        or len(add.operands) != 3
                        or add.operands[0].type != a.ARM_OP_REG
                        or add.operands[0].reg != load_base
                        or not {pointer_reg, column_reg} <= _reg_sources(add)):
                    continue
                event_index = event.operands[1].mem.index
                if (not function.dominates(multiply, add_site)
                        or not function.dominates(add_site, raw_event_load)
                        or not function.linear_path(multiply, add_site)
                        or not function.linear_path(add_site, raw_event_load)
                        or not _register_unchanged(function, facts, column_reg,
                                                   multiply, add_site)
                        or not _register_unchanged(function, facts, row_reg,
                                                   row_load, raw_event_load)
                        or not _register_unchanged(function, facts,
                                                   add.operands[0].reg,
                                                   add_site, raw_event_load)
                        or not _register_unchanged(function, facts, event_index,
                                                   add_site, raw_event_load)):
                    continue
                # The same col*6+row coordinate writes a raw scan cell in
                # the frame-local 30-byte matrix at SP+4.
                for base_add in function.instructions:
                    if not multiply.address < base_add.address < raw_event_load.address:
                        continue
                    base_ins = facts.decode(base_add)
                    if (base_ins is None or base_ins.id != a.ARM_INS_ADD
                            or len(base_ins.operands) != 3
                            or base_ins.operands[0].type != a.ARM_OP_REG
                            or base_ins.operands[1].type != a.ARM_OP_REG
                            or base_ins.operands[1].reg != a.ARM_REG_SP
                            or base_ins.operands[2].type != a.ARM_OP_IMM
                            or base_ins.operands[2].imm != 4):
                        continue
                    cell_reg = base_ins.operands[0].reg
                    cell_add = next((site for site in function.instructions
                                     if base_add.address < site.address
                                     < raw_event_load.address
                                     and (ins := facts.decode(site)) is not None
                                     and ins.id == a.ARM_INS_ADD
                                     and len(ins.operands) == 3
                                     and ins.operands[0].type == a.ARM_OP_REG
                                     and column_reg in _reg_sources(ins)
                                     and cell_reg in _reg_sources(ins)), None)
                    if cell_add is None:
                        continue
                    cell_ins = facts.decode(cell_add)
                    cell_base = cell_ins.operands[0].reg
                    for store_site in function.instructions:
                        store = facts.decode(store_site)
                        if (store is None or store.id != a.ARM_INS_STRB
                                or len(store.operands) != 2
                                or store.operands[1].type != a.ARM_OP_MEM
                                or store.operands[1].mem.base != cell_base
                                or store.operands[1].mem.index != row_reg
                                or not cell_add.address < store_site.address
                                < column_loop["increment"].address):
                            continue
                        if (not function.dominates(multiply, base_add)
                                or not function.dominates(base_add, cell_add)
                                or not function.dominates(cell_add, store_site)
                                or not function.linear_path(multiply, base_add)
                                or not function.linear_path(base_add, cell_add)
                                or not function.linear_path(cell_add, store_site)
                                or not _register_unchanged(function, facts,
                                    column_reg, multiply, cell_add)
                                or not _register_unchanged(function, facts,
                                    cell_reg, base_add, cell_add)
                                or not _register_unchanged(function, facts,
                                    cell_base, cell_add, store_site)
                                or not _register_unchanged(function, facts,
                                    row_reg, cell_add, store_site)):
                            continue
                        sense_evidence = _column_contacts_linked(
                            image, function, facts, row_loops[0],
                            column_loop, row_reg, raw_event_load,
                            table_address)
                        if sense_evidence is None:
                            continue
                        return {"row_register": row_reg,
                                "column_register": column_reg,
                                "row_loop": row_loops[0],
                                "column_loop": column_loop,
                                "multiply": multiply,
                                "cell_store": store_site,
                                "sense_dependencies": sense_evidence,
                                "event_load": raw_event_load}
    return None


def _stack_slot(ins, operation):
    if (ins is None or ins.mnemonic != operation or len(ins.operands) != 2
            or ins.operands[1].type != a.ARM_OP_MEM
            or ins.operands[1].mem.base != a.ARM_REG_SP
            or ins.operands[1].mem.index):
        return None
    return ins.operands[1].mem.disp


def _stack_slot_survives(function, facts, initial_store, slot, sinks):
    """Reject any later stack store that can replace a saved source slot."""
    for sink in sinks:
        if any(initial_store.address < site.address < sink.address
               and site != initial_store
               and (store := facts.decode(site)) is not None
               and store.id in (a.ARM_INS_STR, a.ARM_INS_STRH, a.ARM_INS_STRB)
               and _stack_slot(store, store.mnemonic) == slot
               for site in function.instructions):
            return False
    return True


def _flat_event_stage(function, facts, table_pointer, event_address,
                      handlers, row_register, loops):
    """Prove flat cell/state pass and LUT pointer slot reach both event calls."""
    handler_loads = [CodeAddress(item["event_load"]) for item in handlers]
    if len(handler_loads) != 2:
        return None
    inner_loops = [loop for loop in loops if loop["bound"] == 6
                   and loop["counter"] == row_register
                   and all(loop["target"] < load.address
                           < loop["increment"].address for load in handler_loads)]
    outer_loops = [loop for loop in loops if loop["bound"] == 5
                   and loop["target"] < min(load.address for load in handler_loads)
                   and loop["increment"].address > max(load.address for load in handler_loads)]
    if len(inner_loops) != 1 or len(outer_loops) != 1:
        return None
    inner, outer = inner_loops[0], outer_loops[0]
    outer_target = CodeAddress(outer["target"])
    slot_reads = []
    for site in function.instructions:
        if not outer["target"] <= site.address <= outer["target"] + 8:
            continue
        ins = facts.decode(site)
        if (ins is not None and ins.id == a.ARM_INS_LDR
                and len(ins.operands) == 2
                and ins.operands[0].type == a.ARM_OP_REG
                and ins.operands[0].reg == outer["counter"]):
            slot = _stack_slot(ins, "ldr")
            if slot is not None:
                slot_reads.append((site, slot))
    if len(slot_reads) != 1:
        return None
    counter_load, column_slot = slot_reads[0]
    initial_slot_stores, increment_slot_stores = [], []
    for site in function.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_STR
                or not ins.operands or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[0].reg != outer["counter"]
                or _stack_slot(ins, "str") != column_slot):
            continue
        if outer["initialize"].address < site.address < outer["target"]:
            initial_slot_stores.append(site)
        if outer["increment"].address < site.address < outer["compare"].address:
            increment_slot_stores.append(site)
    if len(initial_slot_stores) != 1 or len(increment_slot_stores) != 1:
        return None
    if not (function.dominates(initial_slot_stores[0], outer_target)
            and function.dominates(increment_slot_stores[0], outer["compare"])):
        return None
    multiply = _indexed_mul(function, facts, outer)
    if multiply is None or multiply.address >= inner["target"]:
        return None
    product_register = outer["counter"]
    if not function.dominates(counter_load, multiply):
        return None
    if any(_writes_register(facts, site, product_register)
           for site in function.instructions
           if multiply.address < site.address < inner["target"]):
        return None

    # Raw scan cells and debounce state both use the same column product and
    # inner row counter for the current column.
    raw_base = None
    state_base = None
    for site in function.instructions:
        if not outer["target"] < site.address < inner["target"]:
            continue
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_ADD or len(ins.operands) != 3
                or ins.operands[0].type != a.ARM_OP_REG):
            continue
        if (ins.operands[1].type == a.ARM_OP_REG
                and ins.operands[1].reg == a.ARM_REG_SP
                and ins.operands[2].type == a.ARM_OP_IMM
                and ins.operands[2].imm == 4):
            frame_base = ins.operands[0].reg
            for sum_site in function.instructions:
                if not site.address < sum_site.address <= site.address + 4:
                    continue
                summed = facts.decode(sum_site)
                if (summed is not None and summed.id == a.ARM_INS_ADD
                        and len(summed.operands) == 3
                        and summed.operands[0].type == a.ARM_OP_REG
                        and {frame_base, product_register} <= _reg_sources(summed)):
                    raw_base = summed.operands[0].reg
        if product_register not in _reg_sources(ins):
            continue
        other = [op.reg for op in ins.operands[1:]
                 if op.type == a.ARM_OP_REG and op.reg != product_register]
        if len(other) != 1:
            continue
        suffix_ready = any((suffix := facts.decode(previous)) is not None
                           and suffix.id == a.ARM_INS_ADD
                           and len(suffix.operands) == 2
                           and suffix.operands[0].type == a.ARM_OP_REG
                           and suffix.operands[0].reg == other[0]
                           and suffix.operands[-1].type == a.ARM_OP_IMM
                           and suffix.operands[-1].imm == 0x52
                           for previous in function.instructions
                           if site.address - 8 <= previous.address < site.address)
        if suffix_ready:
            state_base = ins.operands[0].reg
    if raw_base is None or state_base is None:
        return None
    row_reads = {site.address: facts.decode(site) for site in function.instructions
                 if inner["target"] <= site.address < inner["increment"].address}
    raw_direct = any(ins is not None and ins.id == a.ARM_INS_LDRB
                     and ins.operands[1].type == a.ARM_OP_MEM
                     and ins.operands[1].mem.base == raw_base
                     and ins.operands[1].mem.index == row_register
                     for ins in row_reads.values())
    raw_slot_stores = []
    for site in function.instructions:
        store = facts.decode(site)
        if (outer["target"] <= site.address < inner["target"]
                and store is not None and store.id == a.ARM_INS_STR
                and store.operands[0].type == a.ARM_OP_REG
                and store.operands[0].reg == raw_base):
            slot = _stack_slot(store, "str")
            if slot is not None:
                raw_slot_stores.append((site, slot))
    raw_slot = any(
        ins is not None and ins.id == a.ARM_INS_LDRB
        and ins.operands[1].type == a.ARM_OP_MEM
        and ins.operands[1].mem.index == row_register
        and any(_stack_slot(facts.decode(load_site), "ldr") == slot
                and facts.decode(load_site).operands[0].reg == ins.operands[1].mem.base
                and 0 < site.address - load_site.address <= 4
                and function.dominates(store_site, load_site)
                for load_site in function.instructions
                if (facts.decode(load_site) is not None
                    and facts.decode(load_site).id == a.ARM_INS_LDR
                    and facts.decode(load_site).operands[0].type == a.ARM_OP_REG)
                for store_site, slot in raw_slot_stores)
        for site_address, ins in row_reads.items()
        for site in (CodeAddress(site_address),))
    if not (raw_direct or raw_slot):
        return None
    if not any(ins is not None and ins.id == a.ARM_INS_LDRB
               and ins.operands[1].type == a.ARM_OP_MEM
               and ins.operands[1].mem.base == state_base
               and ins.operands[1].mem.index == row_register
               for ins in row_reads.values()):
        return None
    if not any(ins is not None and ins.id == a.ARM_INS_STRB
               and ins.operands[1].type == a.ARM_OP_MEM
               and ins.operands[1].mem.base == state_base
               and ins.operands[1].mem.index == row_register
               for ins in row_reads.values()):
        return None

    # Each sink byte indexes the same row counter from a per-column table
    # pointer. Firmware may preserve that pointer in a frame slot or a live
    # callee-saved register; either path must derive from the linked table.
    sink_sources = []
    for event_load_site in handler_loads:
        load = facts.decode(event_load_site)
        if (load is None or load.id != a.ARM_INS_LDRB
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.index != row_register):
            return None
        base_register = load.operands[1].mem.base
        base_loads = []
        for site in function.instructions:
            if not event_load_site.address - 6 <= site.address < event_load_site.address:
                continue
            ins = facts.decode(site)
            if (ins is not None and ins.id == a.ARM_INS_LDR
                    and ins.operands and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[0].reg == base_register
                    and _stack_slot(ins, "ldr") is not None):
                base_loads.append((site, _stack_slot(ins, "ldr")))
        if len(base_loads) == 1:
            sink_sources.append(("stack", base_loads[0][1], base_loads[0][0]))
        elif not base_loads:
            sink_sources.append(("register", base_register, event_load_site))
        else:
            return None
    if len({(kind, value) for kind, value, _ in sink_sources}) != 1:
        return None
    source_kind, event_source, _ = sink_sources[0]
    pointer_defs = []
    for sub_site in function.instructions:
        pointer_register = _linked_table_base(function, facts, sub_site,
                                              table_pointer, event_address)
        if pointer_register is None:
            continue
        for add_site in function.instructions:
            if not sub_site.address < add_site.address < inner["target"]:
                continue
            add = facts.decode(add_site)
            if (add is None or add.id != a.ARM_INS_ADD
                    or len(add.operands) != 3
                    or add.operands[0].type != a.ARM_OP_REG
                    or not {pointer_register, product_register} <= _reg_sources(add)):
                continue
            result_register = add.operands[0].reg
            if source_kind == "stack":
                stores = [site for site in function.instructions
                          if add_site.address < site.address < inner["target"]
                          and (store := facts.decode(site)) is not None
                          and store.id == a.ARM_INS_STR
                          and store.operands[0].type == a.ARM_OP_REG
                          and store.operands[0].reg == result_register
                          and _stack_slot(store, "str") == event_source]
                if len(stores) != 1:
                    continue
                pointer_site = stores[0]
                reaches_sinks = all(function.dominates(pointer_site, sink_site)
                                    for _, _, sink_site in sink_sources)
                preserves_result = _register_unchanged(
                    function, facts, result_register, add_site, pointer_site)
            else:
                if result_register != event_source:
                    continue
                pointer_site = add_site
                reaches_sinks = all(function.dominates(add_site, sink_site)
                                    for _, _, sink_site in sink_sources)
                preserves_result = not any(
                    _writes_register(facts, site, result_register)
                    for site in function.instructions
                    if add_site.address < site.address < min(
                        item[2].address for item in sink_sources))
            slot_survives = (source_kind != "stack" or _stack_slot_survives(
                function, facts, pointer_site, event_source,
                [sink_site for _, _, sink_site in sink_sources]))
            if (not any(_writes_register(facts, intervening, pointer_register)
                        for intervening in function.instructions
                        if sub_site.address < intervening.address < add_site.address)
                    and function.dominates(multiply, add_site)
                    and function.linear_path(multiply, add_site)
                    and function.linear_path(sub_site, add_site)
                    and reaches_sinks and preserves_result and slot_survives):
                pointer_defs.append(pointer_site)
    if len(pointer_defs) != 1:
        return None
    return {"column_loop": outer, "row_loop": inner,
            "column_slot": column_slot,
            "event_pointer_storage": source_kind, "event_source": event_source,
            "multiply": multiply, "event_pointer_store": pointer_defs[0],
            "sink_event_loads": [site.address for site in handler_loads],
            "raw_base_register": raw_base, "state_base_register": state_base}


