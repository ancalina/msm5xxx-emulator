"""Source evidence for memory windows used by a word-command NAND image."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, source_prefix
from msm5xxx_emulator.detection.values import SymbolicValue
from .boot_nand_word_helpers import _span, _uart_source


_PAGE = 0x1000
_CODE_LIMIT = 0x01000000
_UPLOAD_SPANS = ((0x50000000, 0x4000), (0x50200000, 0x3000),
                 (0x50400000, 0x1000), (0x58000000, 0x1000))
_WINDOWS = ((0x48000000, _PAGE), (0x50C00000, _PAGE),
            (0x58C00000, _PAGE), (0x30010000, _PAGE),
            (0x65800000, _PAGE), (0x65000000, _PAGE),
            (0x62800000, _PAGE), (0x50000000, 0x4000),
            (0x50200000, 0x4000), (0x50400000, _PAGE),
            (0x58000000, _PAGE))


def _valid_spans(spans, image_size):
    if not isinstance(spans, (list, tuple)) or not spans:
        return False
    for item in spans:
        if not isinstance(item, dict) or 'span' not in item:
            return False
        for key in ("span", "extra_spans"):
            values = [item[key]] if key == "span" and key in item else item.get(key, ())
            for span in values:
                if (not isinstance(span, (list, tuple)) or len(span) != 2
                        or any(type(value) is not int for value in span)
                        or span[0] < 0 or span[1] <= 0
                        or span[0] + span[1] > image_size):
                    return False
    return True


def _upload_windows(profile, image_size):
    if (not isinstance(profile, dict) or profile.get("version") != 1
            or not _valid_spans(profile.get("evidence"), image_size)):
        return None
    profile_ranges = profile.get("ranges")
    if not isinstance(profile_ranges, (list, tuple)) or not profile_ranges:
        return None
    ranges = []
    for item in profile_ranges:
        if not isinstance(item, dict):
            return None
        base, length = item.get("base"), item.get("length")
        if (type(base) is not int or type(length) is not int or base < 0
                or length <= 0 or base + length > 0x100000000
                or base & (_PAGE - 1) or length & (_PAGE - 1)):
            return None
        ranges.append((base, base + length))
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        return None
    selected = []
    for required_base, required_length in _UPLOAD_SPANS:
        target_end = required_base + required_length
        cursor = required_base
        for start, end in ranges:
            if end <= cursor or start >= target_end:
                continue
            if start > cursor:
                break
            cursor = min(target_end, end)
            if cursor == target_end:
                break
        if cursor != target_end:
            return None
        selected.append({"base": required_base, "length": required_length})
    return selected


def _span_for(facts, function, source=0):
    return _span(facts, function, source)


def _thumb_owners(facts, site, *, limit=0x800):
    """Yield complete Thumb functions whose decoded body owns a candidate."""
    start = max(facts.base, site - limit) & ~1
    for address in range(start, site + 1, 2):
        instruction = facts.decode(CodeAddress(address, "thumb"))
        if (instruction is None or instruction.id != a.ARM_INS_PUSH
                or not any(operand.type == a.ARM_OP_REG
                           and operand.reg == a.ARM_REG_LR
                           for operand in instruction.operands)):
            continue
        function = facts.function(CodeAddress(address, "thumb"), budget=1024)
        if (function.complete and not function.unresolved and not function.truncated
                and CodeAddress(site, "thumb") in function.instructions):
            yield function


def _caller_functions(facts, function, callers):
    result = {}
    for call_site, target in callers.get(function.entry.address, ()):
        if target & ~1 != function.entry.address:
            continue
        for owner in _thumb_owners(facts, call_site):
            if (owner.complete and not owner.unresolved and not owner.truncated
                    and any(item.address == call_site
                            and child.address == function.entry.address
                            for item, child in owner.calls)):
                result.setdefault(owner.entry.address, owner)
    for owner, _veneer, _pool, _end in _interworking_veneer_links(facts, function):
        result.setdefault(owner.entry.address, owner)
    return tuple(result.values())


def _interworking_veneer_links(facts, function):
    """Link a Thumb function through an ARM literal-load/BX veneer."""
    phase, bank = function.entry.phase, function.entry.bank
    pointer = function.entry.address | 1

    def extract():
        links = []
        references = facts.literal_references(pointer, phase=phase, bank=bank)
        candidates = None
        for reference in references:
            veneer = reference.instruction
            if veneer.isa != "arm":
                continue
            load = facts.decode(veneer)
            branch_pc = CodeAddress(veneer.address + 4, "arm", phase, bank)
            branch = facts.decode(branch_pc)
            literal = facts.literal(veneer)
            if (load is None or load.id != a.ARM_INS_LDR or len(load.operands) != 2
                    or load.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                    or load.operands[0].type != a.ARM_OP_REG
                    or load.operands[0].reg != a.ARM_REG_IP
                    or load.operands[1].type != a.ARM_OP_MEM
                    or load.operands[1].mem.base != a.ARM_REG_PC
                    or load.operands[1].mem.index
                    or branch is None or branch.id != a.ARM_INS_BX
                    or branch.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                    or len(branch.operands) != 1
                    or branch.operands[0].type != a.ARM_OP_REG
                    or branch.operands[0].reg != a.ARM_REG_IP
                    or literal is None or literal.register != a.ARM_REG_IP
                    or literal.value != pointer):
                continue
            if candidates is None:
                candidates = facts.interworking_call_candidates(
                    phase=phase, bank=bank,
                    limit=min(len(facts.image), _CODE_LIMIT))
            for source_call, target in candidates:
                if (source_call.isa != "thumb" or target.isa != "arm"
                        or target.address != veneer.address):
                    continue
                caller = facts.function(source_call, budget=512)
                caller_body = sorted(caller.instructions,
                                     key=lambda site: site.address)
                if (not caller.complete or caller.unresolved or caller.truncated
                        or source_call not in caller.instructions
                        or len(caller_body) != 2
                        or caller_body[0] != source_call
                        or caller_body[1].address != source_call.address + 4
                        or not any(site == source_call
                                   and child.address == veneer.address
                                   and child.isa == "arm"
                                   for site, child in caller.calls)):
                    continue
                return_instruction = facts.decode(caller_body[1])
                if (return_instruction is None or return_instruction.id != a.ARM_INS_POP
                        or not any(operand.type == a.ARM_OP_REG
                                   and operand.reg == a.ARM_REG_PC
                                   for operand in return_instruction.operands)):
                    continue
                links.append((caller, veneer, literal.pool,
                              branch_pc.address + branch.size))
        return tuple(links)

    return facts.memo("interworking-veneer-links",
                      (function.entry.address, phase, bank), extract)


def _interworking_evidence(facts, function, source=0):
    evidence = []
    for caller, veneer, pool, end in _interworking_veneer_links(facts, function):
        evidence.append(_span_for(facts, caller, source))
        evidence.append({
            "span": [source + veneer.address - facts.base, end - veneer.address],
            "extra_spans": [[source + pool - facts.base, 4]],
        })
    return evidence


def _linked_evidence(facts, function, callers, source=0):
    evidence = [_span_for(facts, function, source)]
    evidence.extend(_span_for(facts, owner, source)
                    for owner in _caller_functions(facts, function, callers))
    evidence.extend(_interworking_evidence(facts, function, source))
    return evidence


def _linked_owners(facts, site, callers):
    for function in _thumb_owners(facts, site):
        if _caller_functions(facts, function, callers):
            yield function
            continue
        # Some routines load a literal before saving LR. A call can target
        # that short prefix, so check complete bodies beginning up to 8 bytes
        # before the PUSH owner rather than treating it as unlinked.
        for target in range(max(facts.base, function.entry.address - 8),
                            function.entry.address, 2):
            if not callers.get(target):
                continue
            prefixed = facts.function(CodeAddress(target, "thumb"), budget=1024)
            if (not prefixed.complete or prefixed.unresolved or prefixed.truncated
                    or CodeAddress(site, "thumb") not in prefixed.instructions):
                continue
            if _caller_functions(facts, prefixed, callers):
                yield prefixed
                break


def _partial_callers(facts, function):
    """Yield linked callers whose known prefix reaches a direct call."""
    target = function.entry.address
    for site, called in facts.call_candidates(function.entry.isa):
        if called & ~1 != target:
            continue
        start = max(facts.base, site - 0x800) & ~1
        for address in range(start, site + 1, 2):
            entry = CodeAddress(address, "thumb", function.entry.phase,
                                function.entry.bank)
            instruction = facts.decode(entry)
            if (instruction is None or instruction.id != a.ARM_INS_PUSH
                    or not any(operand.type == a.ARM_OP_REG
                               and operand.reg == a.ARM_REG_LR
                               for operand in instruction.operands)):
                continue
            owner = facts.function(entry, budget=1024)
            call_site = CodeAddress(site, "thumb", entry.phase, entry.bank)
            if (owner.truncated or call_site not in owner.instructions
                    or not any(source == call_site and child.address == target
                               and child.isa == function.entry.isa
                               for source, child in owner.calls)
                    or any(unresolved.address <= site for unresolved in owner.unresolved)):
                continue
            yield owner


def _callers(facts):
    result = {}
    for site, target in facts.call_candidates("thumb"):
        result.setdefault(target & ~1, []).append((site, target))
    return result


def _constructors(facts, immediate, shift, callers):
    """Find complete called functions that build a peripheral base in code."""
    found = {}
    for register in range(8):
        mov = 0x2000 | (register << 8) | immediate
        lsl = (shift << 6) | (register << 3) | register
        candidate = struct.pack("<HH", mov, lsl)
        for site in facts.string_candidates(candidate):
            first = facts.decode(CodeAddress(site, "thumb"))
            second = facts.decode(CodeAddress(site + 2, "thumb"))
            if (first is None or second is None
                    or first.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    or second.id != a.ARM_INS_LSL
                    or first.operands[0].reg != second.operands[0].reg
                    or second.operands[1].reg != first.operands[0].reg
                    or second.operands[2].imm != shift):
                continue
            for function in _linked_owners(facts, site, callers):
                found.setdefault(function.entry.address, function)
    return tuple(found.values())


def _owners_with_accesses(facts, immediate, shift, base, required, callers):
    result = []
    for function in _constructors(facts, immediate, shift, callers):
        accesses = {(use.operation, use.address - base, use.width)
                    for use in function.accesses if base <= use.address < base + _PAGE}
        if required <= accesses:
            result.append(function)
    return result


def _pointer_field(facts, function, value):
    writes = [use for use in function.accesses
              if use.operation == "write" and use.width == 4]
    for first in writes:
        if first.value != value:
            continue
        first_ins = facts.decode(first.instruction)
        if (first_ins is None or first_ins.id != a.ARM_INS_STR
                or len(first_ins.operands) != 2
                or first_ins.operands[1].type != a.ARM_OP_MEM):
            continue
        for second in writes:
            if second.value != value + 0x40 or second.address != first.address + 4:
                continue
            second_ins = facts.decode(second.instruction)
            if (second_ins is not None and second_ins.id == a.ARM_INS_STR
                    and len(second_ins.operands) == 2
                    and second_ins.operands[1].type == a.ARM_OP_MEM
                    and second_ins.operands[1].mem.base == first_ins.operands[1].mem.base
                    and second_ins.operands[1].mem.disp
                    == first_ins.operands[1].mem.disp + 4):
                return True
    for pc in function.instructions:
        instruction = facts.decode(pc)
        if (instruction is None or instruction.id != a.ARM_INS_STR
                or len(instruction.operands) != 2
                or instruction.operands[0].type != a.ARM_OP_REG
                or instruction.operands[1].type != a.ARM_OP_MEM
                or instruction.operands[1].mem.disp != 0x40):
            continue
        resolved = facts.register_value(function, pc, instruction.operands[0].reg)
        if (isinstance(resolved, SymbolicValue) and resolved.kind == "const"
                and resolved.value == value):
            return True
    return False


def _computed_windows(facts):
    callers = _callers(facts)
    evidence = []
    timer_reads = _owners_with_accesses(facts, 0x65, 24, 0x65000000,
        {("read", 0x18, 4), ("read", 0x1C, 4)}, callers)
    timer_writes = _owners_with_accesses(facts, 0x65, 24, 0x65000000,
        {("write", 4, 4), ("write", 0x10, 4), ("write", 0x14, 4)}, callers)
    if not timer_reads or not timer_writes:
        return None
    for function in (*timer_reads, *timer_writes):
        evidence.extend(_linked_evidence(facts, function, callers))

    signal_owners = _owners_with_accesses(facts, 0xC5, 23, 0x62800000,
        {("write", 0, 4), ("write", 8, 4)}, callers)
    pointer_owners = _constructors(facts, 0xC5, 23, callers)
    if not signal_owners or not any(_pointer_field(facts, function, 0x62800000)
                                    for function in pointer_owners):
        return None
    for function in {*signal_owners, *pointer_owners}:
        evidence.extend(_linked_evidence(facts, function, callers))
    return evidence


def _copy_source(facts):
    callers = _callers(facts)
    found = []
    for reference in facts.literal_references(0x30010000):
        site = reference.instruction
        if site.isa != "thumb":
            continue
        for function in _linked_owners(facts, site.address, callers):
            if (any(access.operation == "read" and access.address == 0x30010000
                    and access.width == 4 for access in function.accesses)
                    and function.calls):
                found.append(function)
    unique = {function.entry.address: function for function in found}
    return tuple(unique.values())


def _typed_502_control(facts):
    page_start, page_end = 0x50203000, 0x50204000
    references = facts.literal_references_in(((page_start, page_end),))
    for reference in references:
        if reference.instruction.isa != "thumb":
            continue
        for function in _thumb_owners(facts, reference.instruction.address):
            if (not function.complete or function.unresolved or function.truncated
                    or not any(page_start <= use.address < page_end
                               and use.width in (1, 2, 4)
                               and use.operation in ("read", "write")
                               for use in function.accesses)):
                continue
            if next(_partial_callers(facts, function), None) is not None:
                return function
    return None


def _typed_502_evidence(facts, function):
    evidence = _linked_evidence(facts, function, _callers(facts))
    known = {tuple(item["span"]) for item in evidence if item is not None}
    for caller in _partial_callers(facts, function):
        span = _span_for(facts, caller)
        if span is not None and tuple(span["span"]) not in known:
            evidence.append(span)
            known.add(tuple(span["span"]))
    return evidence


def _callback_table(stage_facts, stage_reset, stage_source):
    instructions = {pc.address: stage_facts.decode(pc) for pc in stage_reset.instructions}
    for literal in stage_reset.literals:
        table = literal.value
        if table & 3 or not 0 <= table <= len(stage_facts.image) - 4:
            continue
        table_registers = set()
        for pc in stage_reset.instructions:
            instruction = instructions.get(pc.address)
            pool_literal = stage_facts.literal(pc)
            if (instruction is not None and instruction.id == a.ARM_INS_LDR
                    and instruction.operands[0].type == a.ARM_OP_REG
                    and instruction.operands[1].type == a.ARM_OP_MEM
                    and instruction.operands[1].mem.base == a.ARM_REG_PC
                    and pool_literal is not None and pool_literal.value == table):
                table_registers.add(instruction.operands[0].reg)
        if not table_registers:
            continue
        dispatch = False
        for address, instruction in instructions.items():
            if (instruction is None or instruction.id != a.ARM_INS_BLX
                    or len(instruction.operands) != 1
                    or instruction.operands[0].type != a.ARM_OP_REG
                    or instruction.operands[0].reg != a.ARM_REG_R0):
                continue
            cursor_address = next((site.address for site in reversed(
                sorted(stage_reset.instructions, key=lambda item: item.address))
                if site.address < address
                and (item := instructions.get(site.address)) is not None
                and item.id == a.ARM_INS_LDR
                and item.writeback and item.operands[0].reg == a.ARM_REG_R0
                and item.operands[1].type == a.ARM_OP_MEM
                and item.operands[1].mem.disp == 0
                and item.operands[1].mem.base in table_registers
                and item.operands[2].type == a.ARM_OP_IMM
                and item.operands[2].imm == 4), None)
            table_cursor = instructions.get(cursor_address) if cursor_address is not None else None
            between = [instructions.get(site.address) for site in stage_reset.instructions
                       if cursor_address is not None and cursor_address < site.address < address]
            guarded = any(item is not None and item.id == a.ARM_INS_CMP
                          and item.operands[0].reg == a.ARM_REG_R0
                          and item.operands[1].type == a.ARM_OP_IMM
                          and item.operands[1].imm == 0
                          for item in between)
            skipped_empty = any(item is not None and item.id == a.ARM_INS_B
                                and item.cc == a.ARM_CC_EQ for item in between)
            after = [instructions.get(address + offset) for offset in (4, 8)]
            if (table_cursor is not None and guarded and skipped_empty
                    and after[0] is not None
                    and after[0].id == a.ARM_INS_CMP
                    and after[0].operands[0].reg == a.ARM_REG_R0
                    and after[0].operands[1].type == a.ARM_OP_IMM
                    and after[0].operands[1].imm == 0
                    and after[1] is not None and after[1].id == a.ARM_INS_B
                    and after[1].cc == a.ARM_CC_NE):
                cursor_register = table_cursor.operands[1].mem.base
                if any(item is not None and item.id == a.ARM_INS_LDR
                       and item.operands[0].reg == cursor_register
                       and item.operands[1].type == a.ARM_OP_MEM
                       and item.operands[1].mem.base == a.ARM_REG_PC
                       and (source := stage_facts.literal(pc)) is not None
                       and source.value == table
                       for pc in stage_reset.instructions
                       if (item := instructions.get(pc.address)) is not None):
                    dispatch = True
                    break
        if not dispatch:
            continue
        pointers = []
        terminated = False
        for offset in range(table, min(table + 0x80, len(stage_facts.image) - 3), 4):
            pointer = struct.unpack_from("<I", stage_facts.image, offset)[0]
            if pointer == 0:
                terminated = True
                break
            if (pointer & ~1) >= len(stage_facts.image):
                pointers = []
                break
            pointers.append(pointer)
        if not terminated or not pointers:
            continue
        bodies = []
        for pointer in pointers:
            body = stage_facts.function(CodeAddress(pointer & ~1,
                "thumb" if pointer & 1 else "arm"), budget=1024)
            if (not body.instructions or not body.complete
                    or body.unresolved or body.truncated):
                bodies = []
                break
            bodies.append(body)
        if not bodies:
            continue
        writes = {(use.address, use.width) for body in bodies for use in body.accesses
                  if use.operation == "write"}
        if not {(0x50C0000C, 4), (0x58C0000C, 4),
                (0x48000020, 4), (0x48000024, 4),
                (0x48000028, 4), (0x4800002C, 4)} <= writes:
            continue
        linked_controller = False
        for body in bodies:
            for _call, target in body.calls:
                callee = stage_facts.function(target, budget=512)
                callee_writes = {(use.address, use.width) for use in callee.accesses
                                 if use.operation == "write"}
                if {(0x48000030, 4), (0x48000034, 4)} <= callee_writes:
                    bodies.append(callee)
                    linked_controller = True
                    break
            if linked_controller:
                break
        if not linked_controller:
            continue
        evidence = [_span_for(stage_facts, stage_reset, stage_source)]
        evidence.extend(_span_for(stage_facts, body, stage_source) for body in bodies)
        evidence.append({"span": [stage_source + table, offset + 4 - table]})
        evidence.append({"span": [stage_source + literal.pool, 4]})
        return [item for item in evidence if item is not None]
    return None


def find_word_windows(image: bytes, stage_source: int, stage_size: int,
                      stage_reset, upload_profile):
    """Return source spans and ranges for the linked word boot's fixed windows."""
    if (not isinstance(image, bytes) or type(stage_source) is not int
            or type(stage_size) is not int or stage_source < 0 or stage_size <= 0
            or stage_source + stage_size > len(image)
            or not getattr(stage_reset, "instructions", None)):
        return None
    upload_ranges = _upload_windows(upload_profile, len(image))
    if upload_ranges is None:
        return None

    stage = image[stage_source:stage_source + stage_size]
    stage_facts = facts_for(stage)
    if stage_reset.entry.address >= stage_size:
        return None
    callback_evidence = _callback_table(stage_facts, stage_reset, stage_source)
    if callback_evidence is None:
        return None

    references = stage_facts.reset_references(stage_reset.entry, limit_address=stage_size)
    uart = _uart_source(stage_facts, references)
    if uart is None:
        return None
    uart_evidence = _span_for(stage_facts, uart, stage_source)

    code_limit = min(len(image), _CODE_LIMIT)
    code_facts = facts_for(source_prefix(image, code_limit))
    control_502 = _typed_502_control(code_facts)
    if control_502 is None:
        return None
    control_evidence = _typed_502_evidence(code_facts, control_502)
    computed_evidence = _computed_windows(code_facts)
    if computed_evidence is None:
        return None
    copy_sources = _copy_source(code_facts)
    if not copy_sources:
        return None
    callers = _callers(code_facts)
    copy_evidence = []
    for function in copy_sources:
        copy_evidence.extend(_linked_evidence(code_facts, function, callers))

    windows = [{"base": base, "length": length} for base, length in _WINDOWS]
    windows.sort(key=lambda item: (item["base"], item["length"]))
    if any(left["base"] + left["length"] > right["base"]
           for left, right in zip(windows, windows[1:])):
        return None

    evidence = [*callback_evidence, uart_evidence,
                *control_evidence, *computed_evidence, *copy_evidence,
                *upload_profile["evidence"]]
    evidence = [item for item in evidence if item is not None]
    if not _valid_spans(evidence, len(image)):
        return None
    return {"version": 1, "windows": windows, "evidence": evidence}
