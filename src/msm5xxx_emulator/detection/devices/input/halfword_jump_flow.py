"""Local source proofs for halfword-offset computed row switches."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_successors
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .row_execution import _Bits, _row_outputs, _word
from .halfword_jump_targets import _imm, _jump_switch, _reg


def _row_footer(image: bytes, header: int, sample: int, row_register: int,
                *, rows: int = 6):
    """Require the same initialized counter to advance and bound the loop."""
    facts = facts_for(image)
    matches = []
    for pc in range(sample + 2, min(sample + 0x100, len(image) - 12), 2):
        increment = facts.decode(CodeAddress(pc))
        if (increment is None or increment.id != a.ARM_INS_ADD
                or len(increment.operands) != 2
                or _reg(increment.operands[0]) != row_register
                or _imm(increment.operands[1]) != 1):
            continue
        # A preceding IT can predicate up to four Thumb instructions.
        # Decoding an increment alone omits that surrounding predicate state.
        preceding = (facts.decode(CodeAddress(at))
                     for at in range(max(sample + 2, pc - 16), pc, 2))
        if any(ins is not None and ins.id == a.ARM_INS_IT for ins in preceding):
            continue
        norm_lsl = facts.decode(CodeAddress(pc + 2))
        norm_lsr = facts.decode(CodeAddress(pc + 4))
        compare = facts.decode(CodeAddress(pc + 6))
        bound_branch = facts.decode(CodeAddress(pc + 8))
        backedge = facts.decode(CodeAddress(pc + 10))
        if (norm_lsl is None or norm_lsl.id != a.ARM_INS_LSL
                or len(norm_lsl.operands) != 3
                or _reg(norm_lsl.operands[0]) != row_register
                or _reg(norm_lsl.operands[1]) != row_register
                or _imm(norm_lsl.operands[2]) != 24
                or norm_lsr is None or norm_lsr.id != a.ARM_INS_LSR
                or len(norm_lsr.operands) != 3
                or _reg(norm_lsr.operands[0]) != row_register
                or _reg(norm_lsr.operands[1]) != row_register
                or _imm(norm_lsr.operands[2]) != 24
                or compare is None or compare.id != a.ARM_INS_CMP
                or len(compare.operands) != 2
                or _reg(compare.operands[0]) != row_register
                or _imm(compare.operands[1]) != rows
                or bound_branch is None or bound_branch.id != a.ARM_INS_B
                or bound_branch.cc not in (a.ARM_CC_GE, a.ARM_CC_HS)
                or backedge is None or backedge.id != a.ARM_INS_B
                or backedge.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or _imm(backedge.operands[0]) != header):
            continue
        exit_target = _imm(bound_branch.operands[0])
        if exit_target is None or header <= exit_target <= pc:
            continue
        matches.append({"increment": pc, "compare": pc + 6,
            "bound_branch": pc + 8, "exit": exit_target,
            "backedge": pc + 10})
    return matches[0] if len(matches) == 1 else None


def _reachable_without_write(image: bytes, start: int, stop: int,
                             register: int, *, allowed_writes=()):
    """Conservatively reject any decoded write to a live loop counter."""
    facts = facts_for(image)
    allowed = set(allowed_writes)
    for pc in range(start, stop, 2):
        ins = facts.decode(CodeAddress(pc))
        if ins is None:
            continue
        if ins.id == a.ARM_INS_IT:
            return False
        if pc in allowed:
            continue
        try:
            _, written = ins.regs_access()
        except Exception:
            return False
        if register in written:
            return False
    return True


def _cfg_preserves_register(image: bytes, start: int, stop: int,
                            register: int):
    """Require a complete source CFG to preserve a live register to a stop."""
    if (type(start) is not int or type(stop) is not int
            or start < 0 or stop <= start or start & 1 or stop & 1):
        return False
    facts = facts_for(image)
    try:
        region = facts.function_region(CodeAddress(start),
            stop_before=(CodeAddress(stop),), budget=512)
    except (ValueError, RuntimeError):
        return False
    if (not region.complete or region.unresolved or region.truncated
            or region.scope_escapes or region.calls
            or CodeAddress(stop) not in region.instructions):
        return False
    for site in region.instructions:
        if site == CodeAddress(stop) or site in region.scope_before:
            continue
        ins = facts.decode(site)
        if ins is None or ins.id == a.ARM_INS_IT:
            return False
        try:
            _, writes = ins.regs_access()
        except Exception:
            return False
        if register in writes:
            return False
    return True


def _event_buffer_store(image: bytes, load_pc: int, event_register: int):
    """Follow the loaded event into its concrete stack-buffer byte store."""
    facts = facts_for(image)
    load = facts.decode(CodeAddress(load_pc))
    if (load is None or load.id != a.ARM_INS_LDRB
            or len(load.operands) != 2
            or _reg(load.operands[0]) != event_register):
        return None
    frame_bases = set()
    stores = []
    for pc in range(load_pc + 2, min(load_pc + 0x20, len(image) - 2), 2):
        ins = facts.decode(CodeAddress(pc))
        if ins is None or ins.id in (a.ARM_INS_B, a.ARM_INS_BL, a.ARM_INS_BX):
            break
        try:
            _, written = ins.regs_access()
        except Exception:
            return None
        if event_register in written:
            return None
        if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                and _reg(ins.operands[1]) == a.ARM_REG_SP
                and _imm(ins.operands[2]) == 4):
            frame_bases.add(_reg(ins.operands[0]))
        if (ins.id == a.ARM_INS_STRB and len(ins.operands) == 2
                and _reg(ins.operands[0]) == event_register
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base in frame_bases
                and ins.operands[1].mem.index):
            stores.append(pc)
        try:
            _, written = ins.regs_access()
        except Exception:
            return None
        for register in written:
            if register != a.ARM_REG_SP and not (
                    ins.id == a.ARM_INS_ADD and len(ins.operands) == 3
                    and _reg(ins.operands[0]) == register
                    and _reg(ins.operands[1]) == a.ARM_REG_SP
                    and _imm(ins.operands[2]) == 4):
                frame_bases.discard(register)
    return stores[0] if len(stores) == 1 else None


def _contact_read(image: bytes, read_pc: int, descriptor: int,
                  descriptor_rom: int):
    """Prove the distinct active-low auxiliary bit-4 gate."""
    facts = facts_for(image)
    read = facts.decode(CodeAddress(read_pc))
    pointer = facts.decode(CodeAddress(read_pc - 2))
    if (read is None or read.id != a.ARM_INS_LDRH or len(read.operands) != 2
            or read.operands[1].type != a.ARM_OP_MEM
            or read.operands[1].mem.disp or read.operands[1].mem.index
            or pointer is None or pointer.id != a.ARM_INS_LDR
            or len(pointer.operands) != 2
            or pointer.operands[0].type != a.ARM_OP_REG
            or pointer.operands[1].type != a.ARM_OP_MEM
            or pointer.operands[1].mem.disp != 0x34
            or read.operands[1].mem.base != pointer.operands[0].reg):
        return None
    register = pointer.operands[1].mem.base
    literal = facts.literal(CodeAddress(read_pc - 6))
    if (literal is None or literal.register != register
            or literal.value != descriptor
            or not _reachable_without_write(image, read_pc - 4,
                                             read_pc - 2, register)):
        return None
    for pc in range(read_pc + 2, min(read_pc + 22, len(image) - 4), 2):
        mask = facts.decode(CodeAddress(pc))
        if (mask is None or mask.id != a.ARM_INS_AND
                or len(mask.operands) != 2
                or _reg(mask.operands[0]) != read.operands[0].reg
                or _reg(mask.operands[1]) is None):
            continue
        mask_reg = _reg(mask.operands[1])
        sources = []
        for source_pc in range(read_pc + 2, pc, 2):
            source = facts.decode(CodeAddress(source_pc))
            if (source is not None and source.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    and len(source.operands) == 2
                    and _reg(source.operands[0]) == mask_reg
                    and _imm(source.operands[1]) == 0x10):
                sources.append(source_pc)
        if len(sources) != 1 or not _reachable_without_write(
                image, sources[0] + 2, pc, mask_reg):
            continue
        if any((ins := facts.decode(CodeAddress(at))) is None
               or ins.id in (a.ARM_INS_B, a.ARM_INS_BL, a.ARM_INS_BX)
               for at in range(sources[0] + 2, pc, 2)):
            continue
        cmp_pc = pc + 2
        while cmp_pc < min(pc + 8, len(image) - 4):
            cmp = facts.decode(CodeAddress(cmp_pc))
            if cmp is not None and cmp.id == a.ARM_INS_CMP:
                break
            if cmp is None or read.operands[0].reg in cmp.regs_access()[1]:
                cmp = None
                break
            cmp_pc += cmp.size
        branch = facts.decode(CodeAddress(cmp_pc + 2)) if cmp is not None else None
        if (cmp is not None and len(cmp.operands) == 2
                and _reg(cmp.operands[0]) == read.operands[0].reg
                and _imm(cmp.operands[1]) == 0
                and branch is not None and branch.id == a.ARM_INS_B
                and branch.cc == a.ARM_CC_NE):
            return {"read_site": read_pc, "mask": 0x10,
                "branch_site": cmp_pc + 2,
                "released_target": _imm(branch.operands[0]),
                "descriptor_source": descriptor_rom,
                "dependencies": {(read_pc - 6, cmp_pc + 4 - (read_pc - 6)),
                                 (literal.pool, 4)}}
    return None


def _matrix_lookup(image: bytes, sample: int, event_load: int,
                   row_register: int, footer_increment: int, *, rows: int = 6):
    """Prove the bounded column loop and execute its actual table expression."""
    facts = facts_for(image)
    senses = (14, 13, 11, 7)
    load = facts.decode(CodeAddress(event_load))
    add = facts.decode(CodeAddress(event_load - 2))
    if (load is None or load.id != a.ARM_INS_LDRB or len(load.operands) != 2
            or load.operands[1].type != a.ARM_OP_MEM
            or load.operands[1].mem.index != row_register
            or add is None or add.id != a.ARM_INS_ADD
            or len(add.operands) != 3
            or load.operands[1].mem.base != _reg(add.operands[0])):
        return None
    address_reg = load.operands[1].mem.base
    muls = []
    for pc in range(max(sample + 2, event_load - 20), event_load - 2, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is not None and ins.id == a.ARM_INS_MUL
                and len(ins.operands) == 3
                and _reg(ins.operands[0]) == _reg(add.operands[1])):
            muls.append((pc, ins))
    if len(muls) != 1:
        return None
    mul_pc, mul = muls[0]
    col_reg = _reg(mul.operands[1])
    scale_reg = _reg(mul.operands[2])
    table_reg = _reg(add.operands[2])
    if col_reg is None or scale_reg is None or table_reg is None:
        return None
    scales, tables = [], []
    for pc in range(max(sample + 2, mul_pc - 12), mul_pc, 2):
        ins = facts.decode(CodeAddress(pc))
        if (ins is not None and ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                and len(ins.operands) == 2
                and _reg(ins.operands[0]) == scale_reg
                and _imm(ins.operands[1]) == rows):
            scales.append(pc)
        literal = facts.literal(CodeAddress(pc))
        if literal is not None and literal.register == table_reg:
            tables.append((pc, literal.value, literal.pool))
    if len(scales) != 1 or len(tables) != 1:
        return None
    table_pc, table, table_pool = tables[0]
    if (not 0 <= table <= len(image) - rows * len(senses)
            or not 0 <= table_pool <= len(image) - 4):
        return None
    # Check the single-low-bit selector loop: low nibble -> one-hot test ->
    # indexed lookup on the fallthrough, followed by a bounded four-column
    # counter recurrence. The inactive path must join at the same count test.
    raw = facts.decode(CodeAddress(sample + 2))
    sample_read = facts.decode(CodeAddress(sample))
    raw_shift = facts.decode(CodeAddress(sample + 4))
    col_init = facts.decode(CodeAddress(sample + 14))
    bit_init = facts.decode(CodeAddress(sample + 16))
    bit_shift = facts.decode(CodeAddress(sample + 18))
    bit_clear = facts.decode(CodeAddress(sample + 20))
    inactive = facts.decode(CodeAddress(sample + 22))
    if (sample_read is None or sample_read.id != a.ARM_INS_LDRH
            or len(sample_read.operands) != 2
            or raw is None or raw.id != a.ARM_INS_LSL or len(raw.operands) != 3
            or raw.operands[2].type != a.ARM_OP_IMM
            or raw.operands[2].imm != 28
            or _reg(raw.operands[1]) != _reg(sample_read.operands[0])
            or _reg(raw.operands[0]) != _reg(sample_read.operands[0])
            or raw_shift is None or raw_shift.id != a.ARM_INS_LSR
            or len(raw_shift.operands) != 3
            or _reg(raw_shift.operands[0]) != _reg(raw.operands[0])
            or raw_shift.operands[2].type != a.ARM_OP_IMM
            or raw_shift.operands[2].imm != 28
            or col_init is None or col_init.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            or len(col_init.operands) != 2 or _imm(col_init.operands[1]) != 0
            or bit_init is None or bit_init.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            or len(bit_init.operands) != 2 or _imm(bit_init.operands[1]) != 1
            or bit_shift is None or bit_shift.id != a.ARM_INS_LSL
            or len(bit_shift.operands) not in (2, 3)
            or bit_clear is None or bit_clear.id != a.ARM_INS_BIC
            or inactive is None or inactive.id != a.ARM_INS_B
            or inactive.cc != a.ARM_CC_EQ):
        return None
    raw_reg = _reg(raw.operands[0])
    # The selector loop uses a second normalized copy so the raw nibble stays
    # live while the first copy carries the no-key comparison flags.
    raw_copy_lsl = facts.decode(CodeAddress(sample + 10))
    raw_copy_lsr = facts.decode(CodeAddress(sample + 12))
    no_key_cmp = facts.decode(CodeAddress(sample + 6))
    no_key_branch = facts.decode(CodeAddress(sample + 8))
    if (raw_shift.operands[1].reg != raw_reg
            or no_key_cmp is None or no_key_cmp.id != a.ARM_INS_CMP
            or _reg(no_key_cmp.operands[0]) != raw_reg
            or _imm(no_key_cmp.operands[1]) != 15
            or no_key_branch is None or no_key_branch.id != a.ARM_INS_B
            or no_key_branch.cc != a.ARM_CC_EQ
            or raw_copy_lsl is None or raw_copy_lsl.id != a.ARM_INS_LSL
            or len(raw_copy_lsl.operands) != 3
            or _reg(raw_copy_lsl.operands[1]) != raw_reg
            or _imm(raw_copy_lsl.operands[2]) != 28
            or raw_copy_lsr is None or raw_copy_lsr.id != a.ARM_INS_LSR
            or len(raw_copy_lsr.operands) != 3
            or _reg(raw_copy_lsr.operands[0]) != _reg(raw_copy_lsl.operands[0])
            or _reg(raw_copy_lsr.operands[1]) != _reg(raw_copy_lsl.operands[0])
            or _imm(raw_copy_lsr.operands[2]) != 28
            or _reg(col_init.operands[0]) != col_reg
            or _reg(bit_shift.operands[0]) != _reg(bit_init.operands[0])
            or (len(bit_shift.operands) == 2
                and _reg(bit_shift.operands[1]) != col_reg)
            or (len(bit_shift.operands) == 3
                and (_reg(bit_shift.operands[1]) != _reg(bit_init.operands[0])
                     or _reg(bit_shift.operands[2]) != col_reg))
            or _reg(bit_clear.operands[0]) != _reg(bit_init.operands[0])
            or _reg(bit_clear.operands[-1]) != _reg(raw_copy_lsr.operands[0])):
        return None
    loop = sample + 16
    branch_target = _imm(inactive.operands[0])
    if (branch_target is None or branch_target <= event_load
            or _imm(no_key_branch.operands[0]) != footer_increment):
        return None
    count_cmp = facts.decode(CodeAddress(branch_target))
    count_exit = facts.decode(CodeAddress(branch_target + 2))
    col_inc = facts.decode(CodeAddress(branch_target + 4))
    col_lsl = facts.decode(CodeAddress(branch_target + 6))
    col_lsr = facts.decode(CodeAddress(branch_target + 8))
    col_cmp = facts.decode(CodeAddress(branch_target + 10))
    col_back = facts.decode(CodeAddress(branch_target + 12))
    if (count_cmp is None or count_cmp.id != a.ARM_INS_CMP
            or count_exit is None or count_exit.id != a.ARM_INS_B
            or count_exit.cc not in (a.ARM_CC_GE, a.ARM_CC_HS)
            or col_inc is None or col_inc.id != a.ARM_INS_ADD
            or _reg(col_inc.operands[0]) != col_reg
            or _imm(col_inc.operands[1]) != 1
            or col_lsl is None or col_lsl.id != a.ARM_INS_LSL
            or _reg(col_lsl.operands[0]) != col_reg
            or _imm(col_lsl.operands[2]) != 24
            or col_lsr is None or col_lsr.id != a.ARM_INS_LSR
            or _reg(col_lsr.operands[0]) != col_reg
            or _imm(col_lsr.operands[2]) != 24
            or col_cmp is None or col_cmp.id != a.ARM_INS_CMP
            or _reg(col_cmp.operands[0]) != col_reg
            or _imm(col_cmp.operands[1]) != len(senses)
            or col_back is None or col_back.id != a.ARM_INS_B
            or col_back.cc not in (a.ARM_CC_LO, a.ARM_CC_LT)
            or _imm(col_back.operands[0]) != loop
            or _imm(count_cmp.operands[1]) is None
            or _imm(count_cmp.operands[1]) < rows):
        return None
    # The lookup block is a straight-line, source-decoded multiply-by-six,
    # table addition and indexed byte load. Execute it for every column/row.
    calc_start = min(scales[0], table_pc)
    addresses, dependencies = [], {(table, rows * len(senses)),
                                   (table_pool, 4)}
    for col in range(len(senses)):
        for row in range(rows):
            initial = {col_reg: _Bits.constant(col),
                       row_register: _Bits.constant(row)}
            result = _row_outputs(image, calc_start, event_load, initial,
                -0x10000, 0, capture_load=True,
                capture_end=event_load + 2)
            if result is None:
                return None
            addresses.append(result[0])
            dependencies.update(result[1])
    expected = [table + col * rows + row
                for col in range(len(senses)) for row in range(rows)]
    if addresses != expected:
        return None
    cells = list(image[table:table + len(addresses)])
    if any(cells.count(cell) != 1 for cell in b"123456789*0#"):
        return None
    return (event_load, load.operands[0].reg, table, cells, dependencies)


def _prove_computed_rows(image: bytes, descriptor: int, descriptor_rom: int,
                         descriptor_register: int, presence: int,
                         sample: int, event_load: int,
                         contact_read: int | None, *, terminal_sites=()):
    """Close row drive, all-row clear, footer, lookup and event handoff."""
    facts = facts_for(image)
    switch = _jump_switch(image, sample, terminal_sites=terminal_sites)
    if switch is None:
        return None
    row = switch["row_register"]
    footer = _row_footer(image, switch["header"], sample, row)
    if footer is None:
        return None
    # Header initialization is the only fallthrough into the first row; the
    # exact footer backedge is the only source-owned recurrence.
    if not _reachable_without_write(image, switch["header"] + 2,
            switch["dispatch"], row):
        return None
    outputs, dependencies = [], set(switch["dependencies"])
    for index, arm in enumerate(switch["arms"]):
        result = _row_outputs(image, arm, sample,
            {row: _Bits.constant(index)}, descriptor, descriptor_rom,
            preserved_registers={row: index},
            capture_registers={descriptor_register})
        if (result is None
                or result[2][descriptor_register].value() != descriptor):
            return None
        outputs.append(result[0])
        dependencies.update(result[1])
    pins = sorted(set().union(*(set(output) for output in outputs)))
    if not 1 <= len(pins) <= 2 or any(port not in (0x03000720, 0x03000724,
            0x03000728) for port in pins):
        return None
    masks = []
    for port in pins:
        zero = one = 0
        for output in outputs:
            if port not in output:
                return None
            zero |= output[port].zero
            one |= output[port].one
        masks.append(zero & one & 0xffff)
    wires = [(port, 1 << bit) for port, mask in zip(pins, masks)
             for bit in range(16) if mask & (1 << bit)]
    if len(wires) != 6:
        return None
    order = []
    for output in outputs:
        if any(port not in output or
               (output[port].zero | output[port].one) & mask != mask
               for port, mask in zip(pins, masks)):
            return None
        selected = [i for i, (port, bit) in enumerate(wires)
                    if output[port].zero & bit]
        if len(selected) != 1:
            return None
        order.append(selected[0])
    if sorted(order) != list(range(6)):
        return None
    # The zero initialization and bound guard must dominate the decoded arms;
    # default path bypasses row writes and joins at the common sense read.
    default = _row_outputs(image, switch["guard_target"], sample,
        {descriptor_register: _Bits.constant(descriptor)}, descriptor,
        descriptor_rom, capture_registers={descriptor_register})
    if (default is None or default[0]
            or default[2][descriptor_register].value() != descriptor):
        return None
    clear = None
    clear_call = None
    for pc in range(max(0, presence - 0x40), presence - 2, 2):
        ins = facts.decode(CodeAddress(pc))
        if ins is None or ins.id != a.ARM_INS_BL:
            continue
        target = facts.thumb_call_target(pc)
        from .row_execution import _clear_outputs
        proof = _clear_outputs(image, target,
            tuple(zip(pins, masks)), descriptor=descriptor,
            descriptor_rom=descriptor_rom)
        if proof is not None:
            if clear is not None:
                return None
            clear, clear_call = proof, pc
    if clear is None or clear_call + 4 > presence:
        return None
    from msm5xxx_emulator.detection.arm import _thumb_function_start
    function_start = _thumb_function_start(image, presence)
    if function_start is None:
        return None
    pc = function_start
    while pc < clear_call:
        ins = facts.decode(CodeAddress(pc))
        if ins is None:
            return None
        if ins.id == a.ARM_INS_B and ins.operands:
            target = _imm(ins.operands[0])
            if target is None or clear_call < target <= presence:
                return None
        pc += ins.size
    # The released-level sideband branch must enter the all-row clear; then
    # the straight-line return path reaches the low-four-bit presence read.
    for pc in range(clear_call + 4, presence, 2):
        ins = facts.decode(CodeAddress(pc))
        if ins is None or ins.id in (a.ARM_INS_B, a.ARM_INS_BL, a.ARM_INS_BX):
            return None
    if contact_read is not None:
        contact_gate = _contact_read(image, contact_read, descriptor,
                                     descriptor_rom)
        if contact_gate is None or contact_gate["released_target"] != clear_call:
            return None
    lookup = _matrix_lookup(image, sample, event_load, row,
                            footer["increment"])
    if lookup is None:
        return None
    sink = _event_buffer_store(image, event_load, lookup[1])
    if sink is None:
        return None
    if (not _reachable_without_write(image, sample + 2,
            footer["increment"], row, allowed_writes=())
            or not _cfg_preserves_register(image, sample + 2,
                                           footer["increment"], row)):
        return None
    contact = (_contact_read(image, contact_read, descriptor, descriptor_rom)
               if contact_read is not None else None)
    # Contact is optional for the row scan, but if the source carries the
    # descriptor-backed low-active bit-4 sideband, retain its source evidence.
    dependencies.update(clear)
    dependencies.update(lookup[4])
    dependencies.update(((event_load, sink + 2 - event_load),
                         (clear_call, 4),
                         (presence, 10), (sample, 10),
                         (footer["increment"], 12)))
    if contact is not None:
        dependencies.update(contact["dependencies"])
    return {"rows": 6, "columns": 4, "presence_site": presence,
        "sense_site": sample, "row_counter_register": row - a.ARM_REG_R0,
        "row_ports": pins, "row_masks": masks,
        "row_wire_order": order, "no_key": 15,
        "single_key_column_sense": [14, 13, 11, 7],
        "event_load_site": lookup[0],
        "event_register": lookup[1] - a.ARM_REG_R0,
        "event_table": lookup[2], "event_codes": lookup[3],
        "event_sink_site": sink, "row_loop": switch["header"],
        "counter_footer": footer, "contact": contact,
        "dependencies": sorted(dependencies)}
