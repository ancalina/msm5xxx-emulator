"""Select the linked word-command NAND bootstrap and supplied load stage."""
from __future__ import annotations
import struct
from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .boot_nand_word_helpers import (
    _HIGH, _HIGH_SIZE, _LOW_RAM_END,
    _span,
    _reference_spans,
    _function,
    _entry_function,
    _getter,
    _copy_provider,
    _selector,
    _fixed_row_installer,
    _word_poll,
    _operation,
    _input_profile,
    _uart_source,
    _stack_setup,
)

REQUIRES = {
    'find_dram_command_profile': ('memory.dram_commands', 'find_dram_command_profile'),
}


def find_boot_nand_word(image: bytes):
    """Require the linked word-command NAND table and both supported ID fields."""
    if not isinstance(image, bytes) or len(image) < 0x14000:
        return None
    prefix = image[:_HIGH_SIZE]
    if any(struct.pack('<I', value) not in prefix
           for value in (0x64000300, 0x80000940)):
        return None
    metadata_source, metadata_destination, metadata_length = struct.unpack_from('<3I', image, 16 * 512)
    if (metadata_source != 0x4000 or metadata_destination != 0
            or metadata_length < 0x4000 or metadata_length > 0x10000
            or metadata_source + metadata_length > len(image)):
        return None
    high = facts_for(prefix, base=_HIGH)
    high_reset = high.function(CodeAddress(_HIGH, 'arm'), budget=1024)
    if (high_reset.truncated
            or any(target != CodeAddress(0, 'arm') for target in high_reset.unresolved)
            or not high_reset.complete and not high_reset.unresolved):
        return None
    stage = image[metadata_source:metadata_source + metadata_length]
    stage_facts = facts_for(stage)
    vectors = stage_facts.vectors()
    if (not vectors or vectors[0][0].address != 0
            or not 0 <= vectors[0][1].address < len(stage)):
        return None
    stage_reset = stage_facts.function(vectors[0][1], budget=2048)
    if not stage_reset.instructions:
        return None

    high_references = high.reset_references(CodeAddress(_HIGH, 'arm'), limit_address=_HIGH + _HIGH_SIZE)
    reset_targets = {target for _, target in high_reset.calls}
    if not reset_targets:
        return None
    # The reset path must contain a NAND reader followed by the ROM initializer.
    boot_loader = None
    if not any(target.isa == 'thumb' for target in reset_targets):
        return None
    high_call_addresses = {target.address for target in high_references.calls}
    if not any(_HIGH <= address < _HIGH + 0x2000 for address in high_call_addresses):
        return None

    callback_reset = _stack_setup(stage_facts, stage_reset)
    if callback_reset is None:
        return None
    input_evidence = _input_profile(stage_facts, stage_reset, metadata_source)
    low_references = stage_facts.reset_references(vectors[0][1], limit_address=len(stage))
    uart = _uart_source(stage_facts, low_references)

    templates = []
    for offset in range(0, _HIGH_SIZE - 14 * 4 + 1, 4):
        slots = struct.unpack_from('<14I', prefix, offset)
        if slots[11] != 0:
            continue
        required = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13)
        if any(not (slots[index] & 1 and _HIGH <= (slots[index] & ~1) < _HIGH + 0x2000)
               for index in required):
            continue
        accessors = [_getter(high, slots[index], shape) for index, shape in (
            (3, 'capacity'), (4, 0x6c), (5, 0x70), (6, 0x74), (1, 0x78), (2, 0x7c))]
        if any(item is None for item in accessors):
            continue
        records_offset = offset + 0x5c
        if records_offset + 0x24 > _HIGH_SIZE:
            continue
        first = struct.unpack_from('<9I', prefix, records_offset)
        if (not 0x100 <= first[1] <= 0x2000 or first[2] != 32
                or first[3:5] != (512, 528) or first[7:9] != (1, 0)
                or not 0 <= first[5] <= 0xff or not 0 <= first[6] <= 0xff):
            continue
        templates.append((offset, slots, records_offset, first, accessors))
    if len(templates) != 1:
        return None
    table_offset, slots, records_offset, first_record, accessors = templates[0]
    record_address = _HIGH + records_offset

    selector_result = None
    for entry in high_references.calls:
        function = _entry_function(high, entry, budget=1024)
        if _HIGH + records_offset not in {literal.value for literal in function.literals}:
            continue
        if first_record[1:9] == (0x1000, 32, 512, 528, 0x98, 0x76, 1, 0):
            selector = _selector(high, function, record_address, high_references)
            selection_kind = 'id-match'
        else:
            selector = _fixed_row_installer(high, function, record_address)
            selection_kind = 'fixed-row'
        if selector is not None:
            selector_result = (function, selector[1], selection_kind)
            break
    if selector_result is None:
        return None
    selector_function, copy_functions, selection_kind = selector_result

    initializer_matches = []
    for entry in high_references.calls:
        candidate = _entry_function(high, entry, budget=1024)
        commands = tuple(use.value for use in candidate.accesses
            if use.operation == 'write' and use.address == 0x64000300 and use.width == 4)
        if commands[:4] != (0, 7, 5, 6):
            continue
        identity_reads = [use for use in candidate.accesses
                          if use.operation == 'read' and use.address == 0x64000308
                          and use.width == 4]
        candidate_instructions = {pc.address: high.decode(pc)
                                  for pc in candidate.instructions}
        decode_identity = False
        for access in identity_reads:
            at = access.instruction.address
            seq = [candidate_instructions.get(at + step) for step in (2, 4, 6, 8)]
            if (len(seq) == 4 and all(seq)
                    and seq[0].id == a.ARM_INS_LSL and seq[0].operands[2].imm == 1
                    and seq[1].id == a.ARM_INS_LSL and seq[1].operands[2].imm == 9
                    and seq[2].id == a.ARM_INS_LSR and seq[2].operands[2].imm == 24
                    and seq[3].id == a.ARM_INS_LSR and seq[3].operands[2].imm == 24):
                decode_identity = True
        if decode_identity:
            initializer_matches.append((entry, candidate))
    if len(initializer_matches) != 1:
        return None
    initializer_entry, initializer = initializer_matches[0]

    operations = []
    for index, command in ((12, 1), (9, 3), (10, 4)):
        operation = _operation(high, slots[index], command)
        if operation is None:
            return None
        operations.append(operation)
    wait_functions = {target.address: high.function(target, budget=128)
                      for function in operations for _, target in function.calls
                      if target.isa == 'thumb'}
    if len(wait_functions) < 2:
        return None

    main_size = first_record[1] * first_record[2] * first_record[3]
    raw_size = main_size + main_size // 32
    if not 0x01000000 <= main_size <= 0x08000000 or main_size % 16384:
        return None

    # Require a reset-linked high loader and an initializer call through the
    # selected operation table.
    for target in reset_targets:
        body = _entry_function(high, target, budget=1024)
        if any(child.address == initializer.entry.address for _, child in body.calls):
            boot_loader = body
    if boot_loader is None:
        return None
    if not any(target.address == initializer.entry.address for target in high_references.calls):
        return None

    stage_callback_sources = _stage_callback_functions(stage_facts, callback_reset)
    control_sources = [(stage_facts, stage_reset), (high, high_reset),
        (high, boot_loader), (high, initializer), (high, selector_function),
        *((high, function) for function in operations),
        *((high, function) for function in wait_functions.values()),
        *((stage_facts, function) for function in stage_callback_sources)]
    control_sources.extend((high, _entry_function(high, entry, budget=1024))
                           for entry in high_references.calls)
    control_sources = [(source_facts, function) for source_facts, function in control_sources if any(
        0x40000000 <= access.address < 0xffff0000 and access.width in (1, 2, 4)
        and not 0x64000000 <= access.address < 0x64001000
        and not 0x80000000 <= access.address < 0x80010000
        for access in function.accesses)]
    control_pages = sorted({access.address & ~0xfff for _, function in control_sources
        for access in function.accesses if 0x40000000 <= access.address < 0xffff0000
        and access.width in (1, 2, 4)
        and not 0x64000000 <= access.address < 0x64001000
        and not 0x80000000 <= access.address < 0x80010000})
    control_windows = []
    for page in control_pages:
        if control_windows and control_windows[-1]['base'] + control_windows[-1]['length'] == page:
            control_windows[-1]['length'] += 0x1000
        else:
            control_windows.append({'base': page, 'length': 0x1000})

    evidence = [
        *_reference_spans(high, high_references),
        *_reference_spans(stage_facts, low_references, metadata_source),
        _span(high, high_reset),
        _span(high, boot_loader),
        _span(high, initializer),
        _span(high, selector_function),
        *[_span(high, function) for function in copy_functions],
        *[_span(high, function) for function in accessors],
        *[_span(high, function) for function in operations],
        *[_span(high, function) for function in wait_functions.values()],
        _span(stage_facts, stage_reset, metadata_source),
        _span(stage_facts, uart, metadata_source) if uart is not None else None,
        _span(stage_facts, callback_reset['function'], metadata_source),
        input_evidence,
        {'span': [16 * 512, 512]},
        {'span': [table_offset, 14 * 4]},
        {'span': [records_offset, 0x24]},
        {'span': callback_reset['table']},
    ]
    evidence = [item for item in evidence if item is not None]
    profile = {
        'version': 1,
        'blocks': first_record[1],
        'pages_per_block': first_record[2],
        'page_size': first_record[3],
        'spare_size': first_record[4] - first_record[3],
        'main_size': main_size,
        'raw_size': raw_size,
        'identity_status': ((first_record[5] << 24) | (first_record[6] << 16)) >> 1,
        'word_interface': True,
        'stage_source': metadata_source,
        'stage_size': metadata_length,
        'ram_span': _LOW_RAM_END,
        'selection_kind': selection_kind,
        'uart_evidence': [_span(stage_facts, uart, metadata_source)] if uart is not None else [],
        **({'input_address': 0x48000050, 'input_value': 31,
            'input_evidence': input_evidence} if input_evidence is not None else {}),
        'evidence': evidence,
    }
    dram = find_dram_command_profile(image, code_size=_HIGH_SIZE)
    profile['control_windows'] = [*control_windows, *(dram['windows'] if dram else ())]
    profile['control_evidence'] = [_span(source_facts, function,
        metadata_source if source_facts is stage_facts else 0)
        for source_facts, function in control_sources]
    if dram:
        profile['control_evidence'].extend(dram['evidence'])
    return profile


def _stage_callback_functions(stage_facts, callback_reset):
    """Collect complete table callbacks and their two direct-callee levels."""
    table, length = callback_reset['table']
    data = stage_facts.image
    if (type(table) is not int or type(length) is not int or table & 3
            or length < 8 or length > 0x80 or length & 3
            or table < 0 or table + length > len(data)):
        return ()
    pointers = []
    terminated = False
    for offset in range(table, table + length, 4):
        pointer = struct.unpack_from('<I', data, offset)[0]
        if pointer == 0:
            terminated = True
            break
        if not 0 <= (pointer & ~1) < len(data):
            return ()
        pointers.append(pointer)
    if not terminated or not pointers:
        return ()

    pending = [(pointer, 0) for pointer in pointers]
    functions = {}
    while pending:
        pointer, depth = pending.pop(0)
        entry = (pointer & ~1, 'thumb' if pointer & 1 else 'arm')
        if entry in functions:
            continue
        function = _function(stage_facts, pointer, budget=1024)
        if (not function.complete or function.unresolved or function.truncated
                or not function.instructions
                or any(not 0 <= pc.address < len(data)
                       for pc in function.instructions)):
            continue
        functions[entry] = function
        if depth == 2:
            continue
        for _, target in function.calls:
            if not 0 <= target.address < len(data):
                continue
            child_pointer = target.address | (1 if target.isa == 'thumb' else 0)
            pending.append((child_pointer, depth + 1))
    return tuple(functions.values())
