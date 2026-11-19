"""Reset-owned seven-drive, four-sense keypad scan using stack event pairs."""
from __future__ import annotations

import re
import struct

from capstone import arm as a

from msm5xxx_emulator.detection.arm import _thumb_function_start
from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for
from .row_execution import _Bits, _row_outputs, _word
from .startup_copy import reset_linked_input_copy

from .pair_flow import (
    _thumb_insn, _preserved_register, _is_mov_imm, _is_add_imm, _is_cmp_imm, _is_shift_imm, _branch_to,
)
from .pair_events import (
    _function_dependencies, _sp_add, _strb_at, _stack_pair_linkage,
    _second_pair_linkage, _event_index_shape, _event_index_shape_second,
)

GRAMMAR = "pair-row-halfword-seven-v1"
_SENSE = (0x8800, 0x0700, 0x0f00, 0x280f)


def _low_sample(image, pc):
    """Recognize a halfword read followed by low-nibble extraction."""
    if tuple(_word(image, pc + offset) for offset in (0, 2, 4)) != _SENSE[:3]:
        return False
    tail = _word(image, pc + 6)
    if tail not in (0x280f, 0x9005):
        return False
    pointer = _word(image, pc - 2)
    load = _word(image, pc)
    return (load & 0xffc0 == 0x8800
            and pointer & 0xffc0 == 0x6b40
            and (pointer & 7) == (load >> 3 & 7))


def _first_scan_loops(image, sense_site, facts, function):
    event_load = sense_site + 26
    if not (_is_mov_imm(_thumb_insn(facts, sense_site + 10), a.ARM_REG_R7, 0)
            and _is_mov_imm(_thumb_insn(facts, sense_site + 12), a.ARM_REG_R6, 1)
            and _is_mov_imm(_thumb_insn(facts, sense_site + 14), a.ARM_REG_R4, 0)):
        return False
    drive = []
    sense = []
    for pc in range(event_load + 2, min(event_load + 0x50, len(image) - 2), 2):
        if (_is_add_imm(_thumb_insn(facts, pc), a.ARM_REG_R4, 1)
                and _is_shift_imm(_thumb_insn(facts, pc + 2), a.ARM_INS_LSL,
                                  a.ARM_REG_R4, 24)
                and _is_shift_imm(_thumb_insn(facts, pc + 4), a.ARM_INS_LSR,
                                  a.ARM_REG_R4, 24)
                and _is_cmp_imm(_thumb_insn(facts, pc + 6), a.ARM_REG_R4, 7)
                and _branch_to(facts, pc + 8, a.ARM_CC_LT, event_load)
                and function.dominates(CodeAddress(sense_site + 14), CodeAddress(event_load))
                and function.dominates(CodeAddress(event_load), CodeAddress(pc))
                and function.dominates(CodeAddress(pc), CodeAddress(pc + 6))
                and function.dominates(CodeAddress(pc + 6), CodeAddress(pc + 8))
                and _preserved_register(image, event_load + 2, pc,
                                        a.ARM_REG_R4, facts)):
            drive.append(pc)
        if (_is_add_imm(_thumb_insn(facts, pc), a.ARM_REG_R7, 1)
                and _is_shift_imm(_thumb_insn(facts, pc + 2), a.ARM_INS_LSL,
                                  a.ARM_REG_R7, 24)
                and _is_shift_imm(_thumb_insn(facts, pc + 4), a.ARM_INS_LSR,
                                  a.ARM_REG_R7, 24)
                and _is_cmp_imm(_thumb_insn(facts, pc + 6), a.ARM_REG_R7, 4)
                and _branch_to(facts, pc + 8, a.ARM_CC_LT, sense_site + 14)
                and function.dominates(CodeAddress(sense_site + 10), CodeAddress(event_load))
                and function.dominates(CodeAddress(event_load), CodeAddress(pc))
                and function.dominates(CodeAddress(pc), CodeAddress(pc + 6))
                and function.dominates(CodeAddress(pc + 6), CodeAddress(pc + 8))
                and _preserved_register(image, event_load + 2, pc,
                                        a.ARM_REG_R7, facts)):
            sense.append(pc)
    return len(drive) == 1 and len(sense) == 1


def _second_scan_loops(image, sense_site, row_entry, facts, function):
    """Bind the sensed 0..3 loop to the actual seven-drive outer loop."""
    if (not _is_mov_imm(_thumb_insn(facts, sense_site + 8), a.ARM_REG_R4, 0)
            or not _is_mov_imm(_thumb_insn(facts, row_entry - 2), a.ARM_REG_R5, 0)
            or not function.dominates(CodeAddress(row_entry - 2),
                                      CodeAddress(row_entry))):
        return False
    inner = []
    for pc in range(sense_site + 28, min(sense_site + 0x100, len(image) - 2), 2):
        if (_is_add_imm(_thumb_insn(facts, pc), a.ARM_REG_R4, 1)
                and _is_shift_imm(_thumb_insn(facts, pc + 2), a.ARM_INS_LSL,
                                  a.ARM_REG_R4, 24)
                and _is_shift_imm(_thumb_insn(facts, pc + 4), a.ARM_INS_LSR,
                                  a.ARM_REG_R4, 24)
                and _is_cmp_imm(_thumb_insn(facts, pc + 6), a.ARM_REG_R4, 4)
                and _branch_to(facts, pc + 8, a.ARM_CC_LT, sense_site + 10)
                and function.dominates(CodeAddress(sense_site + 8), CodeAddress(sense_site + 30))
                and function.dominates(CodeAddress(sense_site + 30), CodeAddress(pc))
                and function.dominates(CodeAddress(pc), CodeAddress(pc + 6))
                and function.dominates(CodeAddress(pc + 6), CodeAddress(pc + 8))
                and _preserved_register(image, sense_site + 10, pc,
                                        a.ARM_REG_R4, facts)):
            inner.append(pc)
    if len(inner) != 1:
        return False
    if (not function.dominates(CodeAddress(row_entry), CodeAddress(sense_site + 30))
            or not _preserved_register(image, row_entry, sense_site + 30,
                                       a.ARM_REG_R5, facts)):
        return False
    outer = []
    for pc in range(inner[0] + 10, min(sense_site + 0x120, len(image) - 4), 2):
        if not _is_add_imm(_thumb_insn(facts, pc), a.ARM_REG_R5, 1):
            continue
        # Firmware uses BGE exit followed by an unconditional branch to the
        # row drive. Both the increment and the selected row transition are
        # part of the loop proof.
        compare = next((at for at in range(pc + 2, min(pc + 10, len(image) - 2), 2)
                        if _is_cmp_imm(_thumb_insn(facts, at), a.ARM_REG_R5, 7)), None)
        if compare is None:
            continue
        branch = _thumb_insn(facts, compare + 2)
        back = _thumb_insn(facts, compare + 4)
        if (branch is not None and branch.id == a.ARM_INS_B
                and branch.cc == a.ARM_CC_GE and branch.operands
                and branch.operands[0].type == a.ARM_OP_IMM
                and branch.operands[0].imm == compare + 6
                and back is not None and back.id == a.ARM_INS_B
                and back.cc == a.ARM_CC_AL and back.operands
                and back.operands[0].type == a.ARM_OP_IMM
                and back.operands[0].imm == row_entry
                and function.dominates(CodeAddress(inner[0]), CodeAddress(pc))
                and function.dominates(CodeAddress(pc), CodeAddress(compare))
                and function.dominates(CodeAddress(compare), CodeAddress(compare + 2))
                and function.dominates(CodeAddress(compare + 2), CodeAddress(compare + 4))):
            outer.append(pc)
    return len(outer) == 1


def _sense_column_map(image, sense_site, facts):
    """Derive column order from the raw low-nibble sample and bit-test call."""
    if (not _low_sample(image, sense_site)
            or _word(image, sense_site + 6) != 0x9005):
        return None
    copy_index = _thumb_insn(facts, sense_site + 10)
    read_sample = _thumb_insn(facts, sense_site + 12)
    if (copy_index is None or copy_index.id != a.ARM_INS_ADD
            or len(copy_index.operands) != 3
            or copy_index.operands[0].type != a.ARM_OP_REG
            or copy_index.operands[0].reg != a.ARM_REG_R1
            or copy_index.operands[1].type != a.ARM_OP_REG
            or copy_index.operands[1].reg != a.ARM_REG_R4
            or copy_index.operands[2].type != a.ARM_OP_IMM
            or copy_index.operands[2].imm != 0
            or read_sample is None or read_sample.id != a.ARM_INS_LDR
            or len(read_sample.operands) != 2
            or read_sample.operands[0].type != a.ARM_OP_REG
            or read_sample.operands[0].reg != a.ARM_REG_R0
            or read_sample.operands[1].type != a.ARM_OP_MEM
            or read_sample.operands[1].mem.base != a.ARM_REG_SP
            or read_sample.operands[1].mem.disp != 0x14):
        return None
    target = facts.thumb_call_target(sense_site + 14)
    if target is None:
        return None
    result_copy = _thumb_insn(facts, sense_site + 18)
    if (result_copy is None or result_copy.id != a.ARM_INS_ADD
            or len(result_copy.operands) != 3
            or result_copy.operands[0].type != a.ARM_OP_REG
            or result_copy.operands[0].reg != a.ARM_REG_R6
            or result_copy.operands[1].type != a.ARM_OP_REG
            or result_copy.operands[1].reg != a.ARM_REG_R0
            or result_copy.operands[2].type != a.ARM_OP_IMM
            or result_copy.operands[2].imm != 0):
        return None
    helper = facts.function(CodeAddress(target), budget=96,
        symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0),
                            a.ARM_REG_R1: SymbolicValue.arg(1)})
    if not helper.complete or helper.truncated or helper.unresolved:
        return None
    bit_shifts = []
    for site in helper.instructions:
        shift = facts.decode(site)
        if (shift is None or shift.id != a.ARM_INS_ASR
                or len(shift.operands) != 2
                or shift.operands[0].type != a.ARM_OP_REG
                or shift.operands[0].reg != a.ARM_REG_R0
                or shift.operands[1].type != a.ARM_OP_REG
                or shift.operands[1].reg != a.ARM_REG_R1):
            continue
        lsl = _thumb_insn(facts, site.address + shift.size)
        lsr = _thumb_insn(facts, site.address + shift.size + 2)
        ret = _thumb_insn(facts, site.address + shift.size + 4)
        if (_is_shift_imm(lsl, a.ARM_INS_LSL, a.ARM_REG_R0, 31)
                and _is_shift_imm(lsr, a.ARM_INS_LSR, a.ARM_REG_R0, 31)
                and ret is not None and ret.id == a.ARM_INS_BX
                and ret.operands and ret.operands[0].reg == a.ARM_REG_LR):
            bit_shifts.append(site.address)
    if len(bit_shifts) != 1:
        return None
    # Indexes outside the supported range return -1. The scanner loop proves
    # its index is 0..3, within the helper's 0..31 transform branch.
    shift_pc = bit_shifts[0]
    valid_return = shift_pc + 6
    returns = [site for site in helper.instructions
               if (ins := facts.decode(site)) is not None
               and ins.id == a.ARM_INS_BX and ins.operands
               and ins.operands[0].type == a.ARM_OP_REG
               and ins.operands[0].reg == a.ARM_REG_LR]
    checks = []
    for site in helper.instructions:
        compare = facts.decode(site)
        if not _is_cmp_imm(compare, a.ARM_REG_R1, 0) and not _is_cmp_imm(
                compare, a.ARM_REG_R1, 32):
            continue
        branch_pc = site.address + compare.size
        branch = _thumb_insn(facts, branch_pc)
        if (branch is not None and branch.id == a.ARM_INS_B
                and branch.cc == a.ARM_CC_LT and branch.operands
                and branch.operands[0].type == a.ARM_OP_IMM):
            checks.append((site.address, compare.operands[1].imm, branch_pc,
                           branch.operands[0].imm))
    lower = [item for item in checks if item[1] == 0]
    upper = [item for item in checks if item[1] == 32]
    if len(lower) != 1 or len(upper) != 1:
        return None
    lower_pc, _, lower_branch, lower_fail = lower[0]
    upper_pc, _, upper_branch, upper_target = upper[0]

    def invalid_sentinel(start):
        zero = _thumb_insn(facts, start)
        invert = _thumb_insn(facts, start + 2)
        ret = _thumb_insn(facts, start + 4)
        return (_is_mov_imm(zero, a.ARM_REG_R0, 0)
                and invert is not None and invert.id == a.ARM_INS_MVN
                and len(invert.operands) == 2
                and invert.operands[0].reg == a.ARM_REG_R0
                and invert.operands[1].reg == a.ARM_REG_R0
                and ret is not None and ret.id == a.ARM_INS_BX
                and ret.operands and ret.operands[0].reg == a.ARM_REG_LR)

    expected_returns = sorted({lower_fail + 4, upper_branch + 6,
                               valid_return})
    if (upper_pc != lower_branch + 2 or upper_branch != upper_pc + 2
            or upper_target != shift_pc
            or not helper.dominates(CodeAddress(target), CodeAddress(lower_pc))
            or not helper.dominates(CodeAddress(lower_pc), CodeAddress(upper_pc))
            or not helper.dominates(CodeAddress(upper_branch), CodeAddress(shift_pc))
            or not invalid_sentinel(lower_fail)
            or not invalid_sentinel(upper_branch + 2)
            or [site.address for site in returns] != expected_returns
            or not helper.dominates(CodeAddress(shift_pc), CodeAddress(valid_return))
            or facts.register_value(helper, CodeAddress(shift_pc), a.ARM_REG_R0)
                != SymbolicValue.arg(0)
            or facts.register_value(helper, CodeAddress(shift_pc), a.ARM_REG_R1)
                != SymbolicValue.arg(1)):
        return None
    # The helper reduces (sample >> senseIndex) to its low bit. The loop proof
    # establishes senseIndex 0..3; idle F then makes each active-low value
    # derivable directly from the selected pin.
    return ([0xf ^ (1 << index) for index in range(4)], target,
            bit_shifts[0])


def _row_layout(image, sense_site, descriptor, descriptor_rom, facts):
    """Find the bounded output loop that selects each of seven physical rows."""
    upper = sense_site - 2
    search_end = min(sense_site + 0x220, len(image) - 2)
    candidates = []
    for entry in range(max(0, sense_site - 0x180), search_end, 2):
        if entry >= upper:
            break
        outputs = []
        row_dependencies = set()
        for row in range(7):
            initial = {a.ARM_REG_R5: _Bits.constant(row)}
            # The descriptor is a proven live pointer used by row stores.
            initial[a.ARM_REG_R7] = _Bits.constant(descriptor)
            result = _row_outputs(image, entry, upper, initial, descriptor,
                                  descriptor_rom, preserved_registers={a.ARM_REG_R5: row})
            if result is None:
                break
            outputs.append(result[0])
            row_dependencies.update(result[1])
        if len(outputs) != 7:
            continue
        wiring = _row_wires_seven(outputs)
        if wiring is None:
            continue
        ports, order = wiring
        if (len(ports) != 2 or [port for port, _ in ports] != [0x03000720, 0x03000728]
                or sorted(order) != list(range(7))):
            continue
        # Each execution selects exactly one active-low drive line; all other
        # lines in both banks remain high.
        wires = [(port, 1 << bit) for port, mask in ports
                 for bit in range(16) if mask & (1 << bit)]
        if len(wires) != 7:
            continue
        good = True
        for output in outputs:
            selected = []
            for index, (port, bit) in enumerate(wires):
                state = output.get(port)
                if state is None or (state.zero & bit) == 0 and (state.one & bit) == 0:
                    good = False
                    break
                if state.zero & bit:
                    selected.append(index)
            if not good or len(selected) != 1:
                good = False
                break
        if good:
            candidates.append((entry, ports, order, sorted(row_dependencies)))
    return candidates[0] if len(candidates) == 1 else None


def _row_wires_seven(outputs):
    ports = sorted(set().union(*(output.keys() for output in outputs)))
    masks = []
    for port in ports:
        zeros = ones = 0
        for output in outputs:
            if port not in output:
                return None
            zeros |= output[port].zero
            ones |= output[port].one
        masks.append(zeros & ones & 0xffff)
    selected = [(port, mask) for port, mask in zip(ports, masks) if mask]
    wires = [(port, 1 << bit) for port, mask in selected
             for bit in range(16) if mask & (1 << bit)]
    if len(wires) != 7:
        return None
    order = []
    for output in outputs:
        if any((output[port].zero | output[port].one) & mask != mask
               for port, mask in selected):
            return None
        low = [index for index, (port, bit) in enumerate(wires)
               if output[port].zero & bit]
        if len(low) != 1:
            return None
        order.append(low[0])
    return (selected, order) if sorted(order) == list(range(7)) else None


def find_pair_row_scanners(image: bytes, config) -> list[dict]:
    facts = facts_for(image)
    found = []
    for match in re.finditer(rb"\x00\x88\x00\x07\x00\x0f\x0f\x28", image):
        sense = match.start()
        if sense & 1 or not _low_sample(image, sense):
            continue
        pointer_load = _word(image, sense - 2)
        base_register = pointer_load >> 3 & 7
        pointer_register = pointer_load & 7
        if pointer_register != 0 or pointer_load & 0xffc0 != 0x6b40:
            continue
        entry = _thumb_function_start(image, sense)
        main_function = facts.function(CodeAddress(entry), budget=1024)
        if (not main_function.complete or main_function.truncated
                or main_function.unresolved):
            continue
        literal = facts.literal(CodeAddress(entry + 2))
        ins = facts.decode(CodeAddress(entry + 2))
        if (literal is None or ins is None or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[0].reg != a.ARM_REG_R0 + base_register
                or not main_function.dominates(CodeAddress(entry + 2),
                                               CodeAddress(sense - 2))
                or not _preserved_register(image, entry + 4, sense - 2,
                                           a.ARM_REG_R0 + base_register, facts)):
            continue
        descriptor = literal.value
        if (type(descriptor) is not int or descriptor & 3
                or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38):
            continue
        copy = reset_linked_input_copy(image, ((descriptor, 0x38),),
            ram_base=config.ram_base, ram_size=config.ram_size, flash_size=config.flash_size)
        if copy is None:
            continue
        descriptor_rom = copy.source_address(descriptor, 0x38)
        if descriptor_rom is None or not 0 <= descriptor_rom <= len(image) - 0x38:
            continue
        sense_address = struct.unpack_from("<I", image, descriptor_rom + 0x34)[0]
        drive_port0 = struct.unpack_from("<I", image, descriptor_rom)[0]
        drive_port1 = struct.unpack_from("<I", image, descriptor_rom + 0x20)[0]
        if ((sense_address, drive_port0, drive_port1) !=
                (0x0300072c, 0x03000720, 0x03000728)):
            continue
        # The first table walk computes (sense index * 7) + drive index and
        # loads its event byte. Verify the arithmetic and indexed source.
        expected = ((sense + 10, a.ARM_INS_MOV), (sense + 12, a.ARM_INS_MOV),
                    (sense + 14, a.ARM_INS_MOV), (sense + 16, a.ARM_INS_LSL),
                    (sense + 18, a.ARM_INS_LDR), (sense + 20, a.ARM_INS_SUB),
                    (sense + 22, a.ARM_INS_SUB), (sense + 24, a.ARM_INS_ADD),
                    (sense + 26, a.ARM_INS_LDRB))
        if any((ins := _thumb_insn(facts, pc)) is None or ins.id != kind
               for pc, kind in expected):
            continue
        if (not _event_index_shape(image, sense, facts)
                or not _first_scan_loops(image, sense, facts, main_function)):
            continue
        literal = facts.literal(CodeAddress(sense + 18))
        if literal is None:
            continue
        table_end = literal.value
        if (type(table_end) is not int or table_end < 0x3c
                or not 0 <= table_end - 0x3c <= len(image) - 28):
            continue
        table = table_end - 0x3c
        events = list(image[table:table + 28])
        if any(events.count(event) != 1 for event in b"123456789*0#"):
            continue
        # Source stores the event/mode in a two-byte stack pair. Its numeric
        # table event is accepted by the same predicate and event consumer.
        event_load = sense + 26
        pair = _stack_pair_linkage(image, event_load, function=main_function,
                                   event_codes=events)
        if (pair is None or pair["mode"] != 1
                or pair["predicate_target"] == pair["consumer_target"]):
            continue
        second = None
        for pc in range(sense + 0x80, min(sense + 0x180, len(image) - 2), 2):
            if _low_sample(image, pc):
                second = pc
                break
        if second is None:
            continue
        layout = _row_layout(image, second, descriptor, descriptor_rom, facts)
        if layout is None:
            continue
        drive_entry, ports, order, row_dependencies = layout
        second_event_load = _event_index_shape_second(image, second, table, facts)
        if (second_event_load is None
                or not _second_scan_loops(image, second, drive_entry, facts,
                                          main_function)):
            continue
        second_pair = _second_pair_linkage(image, second_event_load, main_function,
            pair["predicate_target"], pair["consumer_target"], facts,
            event_codes=events)
        column_map = _sense_column_map(image, second, facts)
        if second_pair is None or column_map is None:
            continue
        classifier_tables = pair["predicate_hardware"]["classifier_tables"]
        if (not classifier_tables
                or classifier_tables != second_pair["predicate_hardware"]["classifier_tables"]
                or any(table["address_start"] < config.ram_base
                       or table["address_end"] > config.ram_base + config.ram_size
                       for table in classifier_tables)):
            continue
        column_senses, column_helper, column_bit_test = column_map
        read_sites = [sense, second]
        if any(not 0 <= site <= min(len(image), config.flash_size) - 8 for site in read_sites):
            continue
        dependencies = set(copy.evidence)
        dependencies.update(((descriptor_rom, 0x38), (table, 28), (literal.pool, 4)))
        dependencies.update(_function_dependencies(facts, entry, budget=1024) or ())
        dependencies.update(row_dependencies)
        dependencies.update(_function_dependencies(facts, pair["predicate_target"]) or ())
        dependencies.update(_function_dependencies(facts, pair["consumer_target"]) or ())
        dependencies.update(_function_dependencies(facts, column_helper) or ())
        dependencies.update(pair["predicate_hardware"]["dependencies"])
        dependencies.update(second_pair["predicate_hardware"]["dependencies"])
        dependencies.update(((second, second_pair["consumer_site"] + 4 - second),))
        found.append({"grammar": GRAMMAR, "rows": 7, "columns": 4,
            "descriptor": descriptor, "descriptor_source": descriptor_rom,
            "sense_address": sense_address, "presence_site": sense,
            "sense_site": second, "source_sites": [
                {"presence_site": sense, "sense_site": second,
                 "event_load_site": pair["event_load_site"],
                 "event_register": pair["event_register"]},
                {"presence_site": sense, "sense_site": second,
                 "event_load_site": second_pair["event_load_site"],
                 "event_register": second_pair["event_register"]}],
            "event_load_sites": [pair["event_load_site"], second_event_load],
            "event_registers": [pair["event_register"], second_pair["event_register"]],
            "event_pair_sources": [pair, second_pair],
            "row_ports": [port for port, _ in ports],
            "row_masks": [mask for _, mask in ports], "row_wire_order": order,
            "event_table": table, "event_codes": events,
            "predicate_hardware": [pair["predicate_hardware"],
                                    second_pair["predicate_hardware"]],
            "classifier_tables": classifier_tables,
            "event_load_site": event_load, "event_register": 0,
            "predicate_site": pair["predicate_site"], "consumer_site": pair["consumer_site"],
            "pair_mode": pair["mode"], "pair_stack_offset": pair["event_stack_offset"],
            "sense_column_helper": {"call_site": second + 14,
                "target": column_helper, "bit_test_site": column_bit_test},
            "row_loop": drive_entry, "no_key": 15,
            "single_key_column_sense": column_senses,
            "dependencies": sorted(dependencies)})
    return found


def pair_row_property(image, config, *, status_descriptor_claimed=False):
    if (status_descriptor_claimed or getattr(config, "load_address", None) != 0
            or type(getattr(config, "ram_base", None)) is not int
            or type(getattr(config, "ram_size", None)) is not int
            or type(getattr(config, "flash_size", None)) is not int):
        return None, None
    profiles = find_pair_row_scanners(image, config)
    if len(profiles) != 1:
        return None, None
    profile = profiles[0]
    limit = min(len(image), config.flash_size)
    if any(type(at) is not int or type(size) is not int or size <= 0
           or at < 0 or at > limit - size for at, size in profile["dependencies"]):
        return None, None
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address in [profile["sense_address"], *profile["row_ports"]]:
        return None, None
    fields = [profile["descriptor"], profile["presence_site"], profile["sense_site"]]
    fields.extend(value for pair in zip(profile["row_ports"], profile["row_masks"]) for value in pair)
    return "matrix-halfword-wires=" + ":".join(f"{value:x}" for value in fields), profile
