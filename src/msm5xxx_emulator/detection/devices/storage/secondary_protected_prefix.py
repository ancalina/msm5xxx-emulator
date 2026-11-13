"""Sector-prefix loop proofs for table-described secondary NOR."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.contracts import BodySpec
from msm5xxx_emulator.detection.facts import CodeAddress


def prefix_consumers(facts) -> tuple[dict, ...]:
    """Find complete sector-prefix loops, including callback-linked variants."""
    found = {item["entry"]: item for item in _fixed_prefix_consumers(facts)}
    for item in _linked_prefix_consumers(facts):
        found[item["entry"]] = item
    return tuple(found[key] for key in sorted(found))


def _fixed_prefix_consumers(facts) -> tuple[dict, ...]:
    """Retain the compact body variant with a complete shared-fact match."""
    spec = BodySpec(
        size=64,
        words=((0, 0xB5B0, 0xFFFF), (4, 0x1C04, 0xFFFF),
               (6, 0x6868, 0xFFFF), (8, 0x2800, 0xFFFF),
               (10, 0xD100, 0xFF00), (20, 0x3031, 0xFFFF),
               (26, 0x2000, 0xFFFF), (28, 0x2100, 0xFFFF),
               (30, 0x686A, 0xFFFF), (32, 0xE000, 0xF800),
               (34, 0x008B, 0xFFFF), (36, 0x189B, 0xFFFF),
               (38, 0x689B, 0xFFFF), (40, 0x1818, 0xFFFF),
               (42, 0x3101, 0xFFFF), (44, 0x42A1, 0xFFFF),
               (46, 0xDB00, 0xFF00), (48, 0x32C0, 0xFFFF),
               (50, 0x6811, 0xFFFF), (56, 0xBCB0, 0xFFFF),
               (58, 0xBC08, 0xFFFF), (60, 0x4718, 0xFFFF)),
        literals=((2, 5), (16, 0)),
    )
    found = []
    for match in spec.find(facts):
        fn = facts.function(CodeAddress(match.entry, "thumb"), budget=256,
                            symbolic_registers={})
        if not fn.complete or not fn.back_edges:
            continue
        ins = {item.address: facts.decode(CodeAddress(item.address, "thumb"))
               for item in fn.instructions}
        if any(value is None for value in ins.values()):
            continue
        # The structured body contract captures the descriptor global and
        # validates the loop's fixed table scale, +8 entry load, byte sum,
        # and +0xc0 indirect erase dispatch.
        found.append({"entry": match.entry, "global_address": match.values[2],
                      "global_load": match.pools[0],
                      "body": (match.entry, match.entry + match.size),
                      "index_loop": (match.entry + 34, match.entry + 52),
                      "function_interval": (fn.entry.address,
                                            fn.instructions[-1].address + 2)})
    return tuple(found)


def _reg(ins, operand):
    return operand.reg if operand.type == a.ARM_OP_REG else None


def _prefix_loop(instructions):
    """Recognize index*4/table+8/byte-sum prefix loops by register flow."""
    for pos in range(max(0, len(instructions) - 6)):
        seq = instructions[pos:pos + 7]
        if len(seq) != 7 or any(ins is None for ins in seq):
            continue
        shift, add_base, load, add_sum, increment, compare, branch = seq
        if (shift.mnemonic not in ("lsl", "lsls") or len(shift.operands) != 3 or
                shift.operands[2].type != a.ARM_OP_IMM or shift.operands[2].imm != 2):
            continue
        scaled, index = _reg(shift, shift.operands[0]), _reg(shift, shift.operands[1])
        if scaled is None or index is None:
            continue
        if (add_base.mnemonic not in ("add", "adds") or len(add_base.operands) != 3 or
                _reg(add_base, add_base.operands[0]) != scaled or
                _reg(add_base, add_base.operands[1]) != scaled):
            continue
        table = _reg(add_base, add_base.operands[2])
        if table is None or load.mnemonic != "ldr" or len(load.operands) != 2:
            continue
        if (load.operands[1].type != a.ARM_OP_MEM or
                load.operands[1].mem.base != scaled or
                load.operands[1].mem.disp != 8):
            continue
        value = _reg(load, load.operands[0])
        if (value is None or add_sum.mnemonic not in ("add", "adds") or
                len(add_sum.operands) != 3):
            continue
        accumulator = _reg(add_sum, add_sum.operands[0])
        if (value == accumulator or
                {_reg(add_sum, add_sum.operands[1]), _reg(add_sum, add_sum.operands[2])}
                != {value, accumulator}):
            continue
        if (increment.mnemonic not in ("add", "adds") or len(increment.operands) != 2 or
                _reg(increment, increment.operands[0]) != index or
                increment.operands[1].type != a.ARM_OP_IMM or increment.operands[1].imm != 1):
            continue
        if (compare.mnemonic != "cmp" or len(compare.operands) != 2 or
                _reg(compare, compare.operands[0]) != index or
                _reg(compare, compare.operands[1]) is None):
            continue
        limit = _reg(compare, compare.operands[1])
        if (branch.mnemonic != "blt" or not branch.operands or
                branch.operands[0].type != a.ARM_OP_IMM or
                not shift.address <= branch.operands[0].imm < branch.address):
            continue
        return {
            "start": shift.address, "end": branch.address + branch.size,
            "index": index, "limit": limit, "accumulator": accumulator,
            "table": table, "entry_branch": branch.address,
        }
    return None


def _linked_prefix_consumers(facts) -> tuple[dict, ...]:
    """Prove a prefix loop through its active-object erase callback dispatch.

    Some compiler layouts move the descriptor check and error path before the
    loop, so a fixed 64-byte body is too strict. This recognizer closes the
    loop's register roles, the active-object global+4 load, and its +0xc0
    callback load through a one-instruction BX trampoline.
    """
    image = facts.image
    candidates = []
    # Thumb LSL-immediate by two has a bounded encoding mask; only those
    # aligned halfwords need Capstone decoding or function ownership queries.
    for at in range(0, len(image) - 28, 2):
        halfword = image[at] | image[at + 1] << 8
        if halfword & 0xF800 or halfword & 0x07C0 != 0x0080:
            continue
        loop_start = facts.base + at
        instruction = facts.decode(CodeAddress(loop_start, "thumb"))
        if instruction is None:
            continue
        # A quick contiguous check discards ordinary shifts before attempting
        # bounded containing-function queries.
        if _prefix_loop(tuple(facts.decode(CodeAddress(loop_start + step * 2, "thumb"))
                              for step in range(7))) is None:
            continue
        for delta in range(2, 0x102, 2):
            entry = loop_start - delta
            if entry < facts.base:
                break
            prologue = facts.decode(CodeAddress(entry, "thumb"))
            if (prologue is None or prologue.id != a.ARM_INS_PUSH or
                    a.ARM_REG_LR not in prologue.regs_access()[0]):
                continue
            body = facts.function(CodeAddress(entry, "thumb"), budget=512,
                                  symbolic_registers={})
            body_sites = {item.address for item in body.instructions}
            if (not body.complete or not body.back_edges or
                    loop_start not in body_sites):
                continue
            instructions = [facts.decode(CodeAddress(item.address, "thumb"))
                            for item in body.instructions]
            loop = _prefix_loop(instructions)
            if loop is None or loop["start"] != loop_start:
                continue
            by_address = {ins.address: ins for ins in instructions}
            compare = next((ins for ins in instructions
                            if ins.address + ins.size == loop["entry_branch"]), None)
            if compare is None:
                continue
            # First-iteration initialization and the count argument must be
            # unique on every path reaching the loop test.
            cut = ((CodeAddress(loop["entry_branch"], "thumb"),
                    CodeAddress(loop_start, "thumb")),)
            def first_iteration_definition(register):
                # Post-tested loops enter the body directly; pre-tested loops
                # enter at the compare. Removing the back edge distinguishes
                # the first-iteration value in either layout.
                for use in (loop_start, compare.address):
                    definitions = facts.reaching_definitions(
                        body, CodeAddress(use, "thumb"), register, cut_edges=cut)
                    if definitions and len(definitions) == 1:
                        definition = by_address.get(definitions[0].address)
                        if (definition is not None and definition.mnemonic in ("mov", "movs") and
                                len(definition.operands) == 2 and
                                definition.operands[1].type == a.ARM_OP_IMM and
                                definition.operands[1].imm == 0):
                            return definitions
                return None
            index_defs = first_iteration_definition(loop["index"])
            sum_defs = first_iteration_definition(loop["accumulator"])
            limit_defs = facts.reaching_definitions(
                body, CodeAddress(compare.address, "thumb"), loop["limit"])
            if not (index_defs and len(index_defs) == 1 and sum_defs and len(sum_defs) == 1 and
                    limit_defs and len(limit_defs) == 1):
                continue
            init_index = by_address.get(index_defs[0].address)
            init_sum = by_address.get(sum_defs[0].address)
            init_limit = by_address.get(limit_defs[0].address)
            if not (init_index and init_sum and init_limit):
                continue
            if not (init_index.mnemonic in ("mov", "movs") and len(init_index.operands) == 2 and
                    _reg(init_index, init_index.operands[0]) == loop["index"] and
                    init_index.operands[1].type == a.ARM_OP_IMM and init_index.operands[1].imm == 0 and
                    init_sum.mnemonic in ("mov", "movs") and len(init_sum.operands) == 2 and
                    _reg(init_sum, init_sum.operands[0]) == loop["accumulator"] and
                    init_sum.operands[1].type == a.ARM_OP_IMM and init_sum.operands[1].imm == 0 and
                    init_limit.mnemonic in ("mov", "adds") and len(init_limit.operands) >= 2 and
                    _reg(init_limit, init_limit.operands[0]) == loop["limit"] and
                    _reg(init_limit, init_limit.operands[1]) == a.ARM_REG_R0):
                continue
            table_load = by_address.get(loop_start + 4)
            table_source = by_address.get(loop_start + 2)
            if not table_load or not table_source:
                continue
            object_reg = _reg(table_source, table_source.operands[2])
            if object_reg is None:
                continue
            object_defs = facts.reaching_definitions(
                body, CodeAddress(table_source.address, "thumb"), object_reg)
            if not object_defs or len(object_defs) != 1:
                continue
            object_load = by_address.get(object_defs[0].address)
            if (object_load is None or object_load.mnemonic != "ldr" or
                    len(object_load.operands) != 2 or
                    _reg(object_load, object_load.operands[0]) != object_reg or
                    object_load.operands[1].type != a.ARM_OP_MEM or
                    object_load.operands[1].mem.disp != 4):
                continue
            global_reg = object_load.operands[1].mem.base
            global_defs = facts.reaching_definitions(
                body, CodeAddress(object_load.address, "thumb"), global_reg)
            if not global_defs or len(global_defs) != 1:
                continue
            global_literal = facts.literal(global_defs[0])
            if global_literal is None or not 0x14000000 <= global_literal.value < 0x15000000:
                continue
            # The same object pointer supplies the geometry table and the
            # erase callback slot. Reaching definitions reject intervening
            # register reuse or a different object on a joined path.
            callback_adds = [ins for ins in instructions
                             if ins.mnemonic in ("add", "adds") and len(ins.operands) == 2 and
                             _reg(ins, ins.operands[0]) == object_reg and
                             ins.operands[1].type == a.ARM_OP_IMM and ins.operands[1].imm == 0xC0 and
                             ins.address > loop["entry_branch"]]
            linked_call = None
            for add in callback_adds:
                defs = facts.reaching_definitions(body, CodeAddress(add.address, "thumb"), object_reg)
                if defs != object_defs:
                    continue
                pos = next(i for i, ins in enumerate(instructions) if ins.address == add.address)
                if pos + 2 >= len(instructions):
                    continue
                load_callback = instructions[pos + 1]
                call = instructions[pos + 2]
                if (load_callback.mnemonic != "ldr" or len(load_callback.operands) != 2 or
                        load_callback.operands[1].type != a.ARM_OP_MEM or
                        load_callback.operands[1].mem.base != object_reg or
                        load_callback.operands[1].mem.disp != 0 or call.id not in (a.ARM_INS_BL, a.ARM_INS_BLX) or
                        not call.operands or call.operands[0].type != a.ARM_OP_IMM):
                    continue
                callback_reg = _reg(load_callback, load_callback.operands[0])
                target = call.operands[0].imm & ~1
                trampoline = facts.decode(CodeAddress(target, "thumb"))
                if (callback_reg is None or trampoline is None or trampoline.id != a.ARM_INS_BX or
                        not trampoline.operands or _reg(trampoline, trampoline.operands[0]) != callback_reg):
                    continue
                callback_defs = facts.reaching_definitions(
                    body, CodeAddress(call.address, "thumb"), callback_reg)
                if callback_defs == (CodeAddress(load_callback.address, "thumb"),):
                    linked_call = call
                    break
            if linked_call is None:
                continue
            interval = (body.entry.address, body.instructions[-1].address + 2)
            candidates.append({
                "entry": body.entry.address,
                "global_address": global_literal.value,
                "global_load": global_literal.pool,
                "body": interval,
                "index_loop": (loop["start"], loop["end"]),
                "function_interval": interval,
            })
            break
    unique = {item["entry"]: item for item in candidates}
    return tuple(unique[key] for key in sorted(unique))


