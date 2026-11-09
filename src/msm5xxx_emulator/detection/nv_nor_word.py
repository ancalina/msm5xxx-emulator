"""Code-linked discovery of the word-wide AMD x16 NOR descriptor."""
from __future__ import annotations

import struct
from dataclasses import dataclass

from capstone import arm as a

from .facts import CodeAddress, FirmwareFacts, FunctionFacts, SymbolicValue, facts_for
from .image_view import LoadOperation
from .startup_facts import (
    OrderedCopyTransfer, ResetPrefixProof, VectorCopyRow, _callbacks_share_state,
    _initializer_has_direct_caller, _state_initializer,
    prove_ordered_copy_transfer, prove_reset_prefix_completion,
    vector_copy_rows,
)
from .storage_facts import (
    parse_u32_array, parse_x16_descriptor, u32_at as _word,
    uniform_sector_size,
)


_CODE_ID = 0x225F0004
_DESCRIPTOR_SIZE = 228
_SECTOR_COUNT = 32
_SECTOR_SIZE = 0x10000
_CALLBACK_FIELDS = (184, 188, 192, 196)
_WINDOW_BASE = 0x00400000
_WINDOW_SIZE = 0x00200000
_LOGICAL_CAPACITY = 0x00100000


@dataclass(frozen=True, slots=True)
class WordNORDescriptor:
    address: int
    window_base: int
    physical_size: int
    logical_capacity: int
    sector_size: int
    manufacturer_id: int
    device_id: int
    callbacks: tuple[tuple[str, CodeAddress], ...]


@dataclass(frozen=True, slots=True)
class WordNORProof:
    """Located static proof supporting one legacy word-NOR tuple."""

    profile: tuple[int, int, int, int, int, int]
    descriptor: WordNORDescriptor
    vector_copy: VectorCopyRow
    state_address: int
    initializer: CodeAddress
    wrapper: CodeAddress
    probe: CodeAddress
    pool: int
    probe_commands: tuple[CodeAddress, ...]
    erase_commands: tuple[CodeAddress, ...]
    transfer: OrderedCopyTransfer
    pool_source: int
    reset_prefix: ResetPrefixProof


@dataclass(frozen=True, slots=True)
class _ProbeProof:
    wrapper: CodeAddress
    entry: CodeAddress
    function: FunctionFacts
    pool: int
    pool_source: int
    commands: tuple[CodeAddress, ...]


def _descriptor_offsets(image: bytes):
    marker = struct.pack('<I', _CODE_ID)
    cursor = 0
    while (cursor := image.find(marker, cursor)) >= 0:
        if cursor >= 164:
            descriptor = cursor - 164
            if not descriptor & 3 and descriptor + _DESCRIPTOR_SIZE <= len(image):
                yield descriptor
        cursor += 1


def _descriptor_profile(image: bytes, descriptor: int, ram_base: int,
                        ram_size: int, facts: FirmwareFacts
                        ) -> WordNORDescriptor | None:
    if not facts.view.covers(descriptor, _DESCRIPTOR_SIZE,
                             phase='reset', bank='primary'):
        return None
    common = parse_x16_descriptor(image, descriptor + 164,
                                  callback_count=len(_CALLBACK_FIELDS),
                                  address=descriptor)
    if (common is None or common.device_id != _CODE_ID
            or common.reserved != 0 or common.mode != 1):
        return None
    count = _word(image, descriptor + 4)
    if count != _SECTOR_COUNT:
        return None
    sectors = parse_u32_array(image, descriptor + 8, count,
                              max_count=_SECTOR_COUNT)
    if (sectors is None or len(sectors) != _SECTOR_COUNT
            or uniform_sector_size(sectors, minimum=_SECTOR_SIZE,
                                   maximum=_SECTOR_SIZE) != _SECTOR_SIZE):
        return None

    physical_size = sum(sectors)
    window_base, capacity = common.base_words * 2, common.usable_words * 2
    if (window_base != _WINDOW_BASE or physical_size != _WINDOW_SIZE
            or capacity != _LOGICAL_CAPACITY
            or window_base + physical_size > ram_base):
        return None

    callbacks = []
    for name, pointer in zip(('read', 'program', 'erase', 'status'),
                             common.callbacks):
        if pointer is None or not pointer & 1 or (pointer & ~1) >= len(image):
            return None
        callbacks.append((name, CodeAddress(pointer & ~1, 'thumb')))
    if len({entry for _, entry in callbacks}) != len(callbacks):
        return None

    return WordNORDescriptor(
        descriptor, window_base, physical_size, capacity, _SECTOR_SIZE,
        4, 0x225F, tuple(callbacks),
    )


def _constant(value):
    if isinstance(value, SymbolicValue) and value.kind == 'const':
        return value.value if type(value.value) is int else None
    return None


def _contains_state_load(value, state: int) -> bool:
    if not isinstance(value, SymbolicValue):
        return False
    if (value.kind == 'load' and value.operands
            and _constant(value.operands[0]) == state):
        return True
    return any(_contains_state_load(item, state) for item in value.operands)


def _memory_access(function: FunctionFacts, address: int, operation: str):
    return tuple(access for access in function.symbolic_accesses
                 if access.operation == operation and access.width == 2
                 and access.predicate == a.ARM_CC_AL
                 and _constant(access.address) == address)


def _source_pool_matches(postcopy: FirmwareFacts, transfer: OrderedCopyTransfer,
                         pool: int, descriptor_address: int) -> int | None:
    """Verify the pool in materialized memory and return its original address."""
    copied_start, copied_end = transfer.copied_target
    if not copied_start <= pool or pool + 16 > copied_end:
        return None
    original = postcopy.view.original_address(
        pool, 16, phase='post-copy', source_phase='reset', bank='primary')
    if original is None:
        return None
    raw = postcopy.view.read(pool, 16, phase='post-copy', bank='primary')
    source = postcopy.view.read(original, 16, phase='reset', bank='primary')
    if (raw is None or source is None or raw != source
            or struct.unpack_from('<I', raw)[0] != descriptor_address
            or struct.unpack_from('<I', raw, 12)[0] != 0):
        return None
    return original


def _postcopy_view(facts: FirmwareFacts, transfer: OrderedCopyTransfer
                   ) -> FirmwareFacts | None:
    operations = []
    for item, (source, source_end, target, target_end) in zip(
            transfer.copy_loops, transfer.copy_spans):
        evidence = (item.compare.address, *item.back_edge)
        operations.append(LoadOperation(
            'copy', source, target, target_end - target, evidence))
    for item, (target, end) in zip(transfer.clear_loops,
                                   transfer.clear_spans):
        evidence = (item.compare.address, *item.back_edge)
        operations.append(LoadOperation(
            'zero', None, target, end - target, evidence))
    try:
        return facts.after_loads(operations)
    except ValueError:
        return None


def _ordered_transfer(facts: FirmwareFacts, row: VectorCopyRow
                      ) -> OrderedCopyTransfer | None:
    references = facts.literal_access_candidates(
        ((row.table, row.table + 20),), limit=len(facts.image))
    candidates = []
    for entry in sorted({item.load for item in references},
                        key=lambda pc: (pc.address, pc.isa, pc.phase, pc.bank)):
        candidates.extend(prove_ordered_copy_transfer(
            facts, row, references, entry=entry,
            extra_write_ranges=((0x03000600, 0x03000780),)))
    unique = {(item.entry, item.copy_spans, item.clear_spans): item
              for item in candidates}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _linked_probe(facts: FirmwareFacts, descriptor: WordNORDescriptor,
                  state: int, transfer: OrderedCopyTransfer,
                  postcopy: FirmwareFacts, initializer: FunctionFacts
                  ) -> tuple[FunctionFacts, int] | None:
    descriptor_address = descriptor.address
    matches = []
    for _, wrapper_entry in initializer.calls:
        if wrapper_entry.isa != 'thumb':
            continue
        wrapper = facts.function(wrapper_entry, budget=2048)
        if not wrapper.complete:
            continue
        calls_from_initializer = tuple(
            site for site, target in initializer.calls if target == wrapper_entry)
        if not any(initializer.linear_path(
                access.instruction, site) is not None
                   for access in initializer.symbolic_accesses
                   if access.operation == 'write' and access.width == 4
                   and _constant(access.address) == state
                   and _constant(access.value) == 0
                   for site in calls_from_initializer):
            continue
        for _, probe_entry in wrapper.calls:
            if probe_entry.isa != 'thumb':
                continue
            # Keep the first loop iteration's concrete base/pool address. The
            # back-edge join widens the cursor and loses that local evidence;
            # the loop itself is not being treated as a completed operation.
            postcopy_entry = CodeAddress(
                probe_entry.address, probe_entry.isa, 'post-copy',
                probe_entry.bank)
            probe = postcopy.function(postcopy_entry, budget=2048,
                                      symbolic_registers={},
                                      follow_back_edges=False)
            if probe.truncated or probe.unresolved:
                continue
            literals = {item.value for item in probe.literals
                        if type(item.value) is int}
            pool_candidates = tuple(sorted(
                value for value in literals
                if transfer.copied_target[0] <= value
                and value + 16 <= transfer.copied_target[1] and value % 4 == 0
            ))
            for pool in pool_candidates:
                pool_source = _source_pool_matches(
                    postcopy, transfer, pool, descriptor_address)
                if pool_source is None:
                    continue
                pool_reads = tuple(
                    access for access in probe.symbolic_accesses
                    if access.operation == 'read' and access.width == 4
                    and _constant(access.address) == pool)
                descriptor_reads = tuple(
                    access for access in probe.symbolic_accesses
                    if access.operation == 'read' and access.width == 4
                    and _constant(access.address) == descriptor_address + 176)
                if not pool_reads or not descriptor_reads:
                    continue
                if not {descriptor_address + 128, state,
                        descriptor.window_base + 0xAA0,
                        descriptor.window_base + 0x540, pool} <= literals:
                    continue

                writes = sorted(
                    (access for access in probe.symbolic_accesses
                     if access.operation == 'write' and access.width == 2
                     and access.predicate == a.ARM_CC_AL),
                    key=lambda item: item.instruction.address,
                )
                unlock_a = _memory_access(probe, descriptor.window_base + 0xAAA,
                                          'write')
                unlock_b = _memory_access(probe, descriptor.window_base + 0x554,
                                          'write')
                autoselect = tuple(access for access in writes
                                   if _constant(access.value) == 0x90
                                   and _contains_state_load(access.address, state))
                reset = tuple(access for access in writes
                              if _constant(access.value) == 0xF0
                              and _contains_state_load(access.address, state))
                if not unlock_a or not unlock_b or not autoselect or not reset:
                    continue
                a_writes = tuple(access for access in unlock_a
                                 if _constant(access.value) == 0xAA)
                b_writes = tuple(access for access in unlock_b
                                 if _constant(access.value) == 0x55)
                if not a_writes or not b_writes:
                    continue
                command_sequence = (a_writes[0], b_writes[0], autoselect[0], reset[0])
                if any(left.instruction.address >= right.instruction.address
                       or probe.linear_path(left.instruction,
                                            right.instruction) is None
                       for left, right in zip(command_sequence,
                                              command_sequence[1:])):
                    continue
                matches.append(_ProbeProof(
                    wrapper_entry, postcopy_entry, probe, pool, pool_source,
                    tuple(item.instruction for item in command_sequence)))
    unique = {(item.wrapper, item.entry, item.pool): item for item in matches}
    if len(unique) != 1:
        return None
    return next(iter(unique.values()))


def _erase_contract(facts: FirmwareFacts, entry: CodeAddress,
                    descriptor: WordNORDescriptor) -> tuple[CodeAddress, ...] | None:
    function = facts.function(entry, budget=4096, symbolic_registers={})
    if not function.complete:
        return None
    writes = sorted((access for access in function.symbolic_accesses
                     if access.operation == 'write' and access.width == 2
                     and access.predicate == a.ARM_CC_AL),
                    key=lambda item: item.instruction.address)
    expected = ((descriptor.window_base + 0xAAA, 0xAA),
                (descriptor.window_base + 0x554, 0x55),
                (descriptor.window_base + 0xAAA, 0x80),
                (descriptor.window_base + 0xAAA, 0xAA),
                (descriptor.window_base + 0x554, 0x55))
    for start in range(len(writes) - len(expected)):
        segment = writes[start:start + len(expected)]
        if tuple((_constant(item.address), _constant(item.value))
                 for item in segment) != expected:
            continue
        terminal = next((item for item in writes[start + len(expected):]
                         if _constant(item.value) == 0x30), None)
        if terminal is None:
            continue
        ordered = tuple(segment) + (terminal,)
        if all(function.linear_path(left.instruction, right.instruction) is not None
               for left, right in zip(ordered, ordered[1:])):
            return tuple(item.instruction for item in ordered)
    return None


def _word_profile(image: bytes, facts: FirmwareFacts, descriptor: int,
                  vector_copy, reset_entry: CodeAddress,
                  ram_base: int, ram_size: int
                  ) -> WordNORProof | None:
    profile = _descriptor_profile(image, descriptor, ram_base, ram_size, facts)
    if profile is None:
        return None
    callbacks = dict(profile.callbacks)
    functions = {name: facts.function(entry, budget=4096,
                                       symbolic_registers={})
                 for name, entry in callbacks.items()}
    if any(not function.complete for function in functions.values()):
        return None
    shared_states = None
    for function in functions.values():
        values = {item.value for item in function.literals
                  if type(item.value) is int
                  and ram_base <= item.value <= ram_base + ram_size - 32
                  and item.value % 4 == 0}
        shared_states = values if shared_states is None else shared_states & values
    if not shared_states or len(shared_states) != 1:
        return None
    state = next(iter(shared_states))
    if not _callbacks_share_state(facts, callbacks, state):
        return None
    initializer = _state_initializer(facts, state)
    if (initializer is None
            or not _initializer_has_direct_caller(facts, initializer, state)):
        return None
    transfer = _ordered_transfer(facts, vector_copy)
    if transfer is None:
        return None
    reset_prefix = prove_reset_prefix_completion(facts, reset_entry, transfer)
    if reset_prefix is None:
        return None
    postcopy = _postcopy_view(facts, transfer)
    if postcopy is None:
        return None
    probe = _linked_probe(facts, profile, state, transfer, postcopy, initializer)
    if probe is None:
        return None
    erase_commands = _erase_contract(facts, callbacks['erase'], profile)
    if erase_commands is None:
        return None
    return WordNORProof(
        (profile.window_base, profile.physical_size, profile.sector_size,
         profile.manufacturer_id, profile.device_id, 0),
        profile, vector_copy, state, initializer.entry,
        probe.wrapper, probe.entry, probe.pool, probe.commands, erase_commands,
        transfer, probe.pool_source, reset_prefix,
    )


def find_word_nv_nor_proof(image: bytes, ram_base: int,
                           ram_size: int) -> WordNORProof | None:
    """Return the code-linked descriptor and its located hardware proof."""
    if (type(ram_base) is not int or type(ram_size) is not int
            or ram_base < 0 or ram_size <= 0
            or ram_base + ram_size > 0x100000000):
        return None
    try:
        image = bytes(image)
    except (TypeError, ValueError):
        return None
    facts = facts_for(image)
    copies = vector_copy_rows(facts, ram_base, ram_size)
    if len(copies) != 1:
        return None
    vector_copy, = copies
    reset_vectors = tuple(target for site, target in facts.vectors()
                          if site.address == 0 and site.isa == 'arm'
                          and site.phase == 'reset' and site.bank == 'primary')
    if len(reset_vectors) != 1:
        return None
    reset_entry, = reset_vectors
    matches = []
    for descriptor in _descriptor_offsets(image):
        result = _word_profile(image, facts, descriptor, vector_copy, reset_entry,
                               ram_base, ram_size)
        if result is not None:
            matches.append(result)
    return matches[0] if len(matches) == 1 else None


def find_word_offset_nv_nor(image: bytes, ram_base: int,
                            ram_size: int) -> tuple[int, int, int, int, int, int] | None:
    """Project one code-linked word-NOR proof to its legacy public tuple."""
    proof = find_word_nv_nor_proof(image, ram_base, ram_size)
    return None if proof is None else proof.profile
