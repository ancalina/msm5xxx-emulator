"""Source-backed recovery of a secondary NOR bank embedded in a dump."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, source_prefix


def _register(instruction, index):
    if (instruction is None or len(instruction.operands) <= index
            or instruction.operands[index].type != a.ARM_OP_REG):
        return None
    return instruction.operands[index].reg


def _memory(instruction, index):
    if (instruction is None or len(instruction.operands) <= index
            or instruction.operands[index].type != a.ARM_OP_MEM):
        return None
    operand = instruction.operands[index].mem
    return operand.base, operand.disp, operand.index


def _merge_spans(spans):
    merged = []
    for start, end in sorted(set(spans)):
        if start < 0 or end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _code_records(facts, bank_base, bank_length, code_limit):
    """Find literal-backed descriptor records through a closed local path."""
    literals = facts.literal_references_in(((bank_base, bank_base + bank_length),))
    records = []
    for literal in literals:
        if literal.value & 3:
            continue
        body = facts.function(literal.instruction, budget=256)
        if (not body.complete or body.truncated or body.unresolved
                or literal.instruction not in body.instructions):
            continue
        decoded = {pc: facts.decode(pc) for pc in body.instructions}
        source_reg = literal.register
        first_load = second_load = None
        first_store = second_store = None
        for pc in body.instructions:
            instruction = decoded[pc]
            destination = _register(instruction, 0)
            memory = _memory(instruction, 1)
            if instruction is None or memory is None or memory[2] != 0:
                continue
            base, offset, _ = memory
            if instruction.id == a.ARM_INS_LDR and base == source_reg:
                if offset == 0:
                    first_load = (pc, destination)
                elif offset == 4:
                    second_load = (pc, destination)
            elif instruction.id == a.ARM_INS_STR and destination is not None:
                if (offset == 0x0C and first_load is not None
                        and destination == first_load[1]):
                    first_store = (pc, base, destination)
                elif (offset == 0x10 and second_load is not None
                      and destination == second_load[1]):
                    second_store = (pc, base, destination)
        if not (first_load and second_load and first_store and second_store
                and first_store[1] == second_store[1]):
            continue
        points = (literal.instruction, first_load[0], first_store[0],
                  second_load[0], second_store[0])
        paths = [body.linear_path(left, right)
                 for left, right in zip(points, points[1:])]
        if any(path is None for path in paths):
            continue
        # Shared data-flow queries close the descriptor base and both values.
        if any(facts.register_origins(body, site, source_reg)
               != ((literal.instruction, source_reg),)
               for site in (first_load[0], second_load[0])):
            continue
        if (facts.register_origins(body, first_store[0], first_store[2])
                != ((first_load[0], first_load[1]),)
                or facts.register_origins(body, second_store[0], second_store[2])
                != ((second_load[0], second_load[1]),)):
            continue
        first_value = facts.register_value(body, first_store[0], first_store[2])
        second_value = facts.register_value(body, second_store[0], second_store[2])
        if (getattr(first_value, "kind", None) != "load"
                or getattr(first_value, "site", None) != first_load[0]
                or getattr(second_value, "kind", None) != "load"
                or getattr(second_value, "site", None) != second_load[0]):
            continue
        first_base = facts.register_origins(body, first_store[0], first_store[1])
        second_base = facts.register_origins(body, second_store[0], second_store[1])
        if first_base is None or second_base is None:
            first_base = facts.reaching_definitions(body, first_store[0],
                first_store[1], include_entry=True)
            second_base = facts.reaching_definitions(body, second_store[0],
                second_store[1], include_entry=True)
        if first_base is None or first_base != second_base:
            continue
        spans = []
        for pc in body.instructions:
            instruction = facts.decode(pc)
            if instruction is not None:
                spans.append((pc.address, pc.address + instruction.size))
        for used in body.literals:
            spans.append((used.pool, used.pool + 4))
        records.append({
            "record_address": literal.value,
            "literal_site": literal.instruction.address,
            "descriptor_loads": (first_load[0].address, second_load[0].address),
            "output_stores": (first_store[0].address, second_store[0].address),
            "evidence_spans": _merge_spans(spans),
        })
    # A descriptor can have several lexical references. Keep one code proof
    # per distinct source record address and retain every supporting span.
    grouped = {}
    for item in records:
        grouped.setdefault(item["record_address"], []).append(item)
    result = []
    for address, items in sorted(grouped.items()):
        result.append({
            "record_address": address,
            "consumers": tuple(items),
            "evidence_spans": _merge_spans(span for item in items
                for span in item["evidence_spans"]),
        })
    return tuple(result)


def _media_format(data, length):
    if length <= 0 or length > len(data):
        return None
    view = data[:length]
    if (length >= 8 and view[:4] == b"RIFF"
            and int.from_bytes(view[4:8], "little") + 8 == length):
        return "riff"
    if (length >= 8 and view[:4] == b"cmid"
            and int.from_bytes(view[4:8], "big") + 8 == length):
        return "cmid"
    return None


def _bank_records(image, origin, bank_base, bank_length, code_records):
    end = origin + bank_length
    records = []
    for source in code_records:
        record_address = source["record_address"]
        offset_in_bank = record_address - bank_base
        record_offset = origin + offset_in_bank
        if not (0 <= offset_in_bank <= bank_length - 8
                and record_offset + 8 <= end):
            continue
        payload_address = int.from_bytes(image[record_offset:record_offset + 4],
                                         "little")
        length = int.from_bytes(image[record_offset + 4:record_offset + 8],
                                "little")
        payload_delta = payload_address - bank_base
        if (payload_address < bank_base or payload_delta >= bank_length
                or length <= 0 or length > bank_length - payload_delta):
            continue
        payload_offset = origin + payload_delta
        media = _media_format(image[payload_offset:payload_offset + length], length)
        if media is None:
            continue
        records.append({
            "record_address": record_address,
            "record_offset": record_offset,
            "payload_address": payload_address,
            "payload_offset": payload_offset,
            "length": length,
            "format": media,
            "code_evidence_spans": source["evidence_spans"],
        })
    return records


def find_secondary_seed(image, bank_base, bank_length, code_limit=None):
    """Return a source-proven bank seed offset, or ``None``.

    Code references are discovered from the supplied image prefix. Candidate
    source offsets are full bank-aligned windows in the same immutable image.
    Multiple windows are accepted only when their complete bank bytes match.
    """
    if (not isinstance(image, (bytes, bytearray, memoryview))
            or type(bank_base) is not int or type(bank_length) is not int
            or bank_base < 0 or bank_length <= 0
            or bank_base + bank_length > 1 << 32):
        return None
    if not isinstance(image, bytes):
        image = bytes(image)
    if code_limit is None:
        code_limit = len(image)
    if type(code_limit) is not int or not 0 < code_limit <= len(image):
        return None
    aligned_origins = tuple(range(0, len(image) - bank_length + 1,
                                  bank_length))
    if not aligned_origins:
        return None
    facts = facts_for(source_prefix(image, code_limit))
    code_records = _code_records(facts, bank_base, bank_length, code_limit)
    if len(code_records) < 2:
        return None
    candidates = {}
    for origin in aligned_origins:
        records = _bank_records(image, origin, bank_base, bank_length,
                                code_records)
        distinct = {record["record_address"] for record in records}
        if len(distinct) >= 2:
            candidates[origin] = records
    if not candidates:
        return None
    origins = sorted(candidates)
    selected = origins[0]
    selected_bytes = image[selected:selected + bank_length]
    if any(image[origin:origin + bank_length] != selected_bytes
           for origin in origins[1:]):
        return None
    records = candidates[selected]
    evidence = _merge_spans(span for record in records
                            for span in record["code_evidence_spans"])
    return {
        "source_offset": selected,
        "source_length": bank_length,
        "source_span": (selected, selected + bank_length),
        "identical_source_offsets": tuple(origins),
        "records": tuple(records),
        "evidence_spans": evidence,
    }
