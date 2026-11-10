"""Compiled-compatible byte-wide AMD x16 NOR descriptor discovery."""
from __future__ import annotations
import struct
from dataclasses import dataclass
from msm5xxx_emulator.detection.facts import CodeAddress, ScatterCandidate, facts_for
from msm5xxx_emulator.detection.startup_facts import (CopyConsumerProof, _callbacks_share_state, _initializer_has_direct_caller, _state_initializer,
    prove_copy_consumer)
from msm5xxx_emulator.detection.devices.storage.nor_protocol import NORHardwareEvidence, known_amd_x16_profile, prove_amd_x16_hardware_contract
from msm5xxx_emulator.detection.storage_facts import parse_u32_array, parse_x16_descriptor, u32_at as _word, uniform_sector_size

_SCATTER_LIMIT = 0x40000
_DESCRIPTOR_SIZE = 228
_CODE_ID = 0x005F0004
_SECTOR_COUNT = 14
_SECTOR_SIZE = 0x10000
_DESCRIPTOR_FIELDS = (184, 188, 192)

@dataclass(frozen=True, slots=True)
class ByteNORProof:
    """Located static proof supporting one legacy byte-NOR tuple."""

    profile: tuple[int, int, int, int]
    row: ScatterCandidate
    consumer: CopyConsumerProof
    source_descriptor: int
    descriptor_address: int
    state_address: int
    initializer: CodeAddress
    callbacks: tuple[tuple[str, CodeAddress], ...]
    command_sites: tuple[CodeAddress, ...]
    sectors: tuple[int, ...]
    hardware: NORHardwareEvidence

def _descriptor_offsets(image: bytes, source: int, size: int):
    marker = struct.pack('<I', _CODE_ID)
    end = min(source + size, len(image))
    position = source
    while (position := image.find(marker, position, end)) >= 0:
        if not position & 3 and position >= source + 164:
            start = position - 164
            if (start >= source and start + _DESCRIPTOR_SIZE <= end and not start & 3):
                yield start
        position += 1

def _descriptor_profile(image, row, descriptor, ram_base, ram_size):
    common = parse_x16_descriptor(image, descriptor + 164, callback_count=len(_DESCRIPTOR_FIELDS), address= descriptor)
    if common is None:
        return None
    count = _word(image, descriptor + 4)
    if count != _SECTOR_COUNT:
        return None
    sectors = parse_u32_array(image, descriptor + 8, count, max_count=_SECTOR_COUNT)
    sector_size = (uniform_sector_size(sectors, minimum=_SECTOR_SIZE, maximum=_SECTOR_SIZE) if sectors is not None else None)
    if sector_size is None:
        return None
    profile = known_amd_x16_profile(common.device_id, sectors)
    if profile is None:
        return None
    descriptor_address = row.target + descriptor - row.source
    aperture_base = common.base_words
    aperture_size = common.usable_words
    if (aperture_base is None or aperture_size != sum(sectors) or aperture_base < profile.window_base or aperture_base + aperture_size > profile.window_base +
        profile.capacity or _word(image, descriptor + 208) != descriptor_address):
        return None
    if (descriptor_address < row.target or descriptor_address + _DESCRIPTOR_SIZE > row.target + row.size or not ram_base <= descriptor_address or
        descriptor_address + _DESCRIPTOR_SIZE > ram_base + ram_size):
        return None
    if (row.zero_target is not None and row.zero_size is not None and max(row.zero_target, descriptor_address) < min(row.zero_target + row.zero_size,
        descriptor_address + _DESCRIPTOR_SIZE)):
        return None
    callbacks = {}
    for name, pointer in zip(('read', 'program', 'erase'), common.callbacks):
        if pointer is None or not pointer & 1:
            return None
        address = pointer & ~1
        if address >= len(image):
            return None
        callbacks[name] = CodeAddress(address, 'thumb')
    if len(set(callbacks.values())) != len(callbacks):
        return None
    return profile, callbacks, sectors

def _descriptor_has_code_consumer(facts, descriptor_address, descriptor_size, references, consumer):
    """Require code xrefs into the relocated object beyond the copy loop."""
    reads = tuple(item for item in references if descriptor_address <= item.address < descriptor_address + descriptor_size and item.operation == 'read' and item.width
        in (2, 4) and item.use not in {site for _, site in consumer.fields})
    return bool(reads)

def find_byte_nv_nor_proof(image: bytes, ram_base: int, ram_size: int) -> ByteNORProof | None:
    """Return the code-declared byte-NOR contract and located evidence.

    The result describes a compiled-compatible device profile. Static
    evidence requires a code-consumed relocation row, an in-range descriptor
    with a supported code ID and geometry, and descriptor callbacks that
    directly call the closed x16 bypass and erase command helpers. It does
    not verify the RTOS data-transfer algorithm or claim a physical part
    identity independently of the firmware's descriptor.
    """
    if (type(ram_base) is not int or type(ram_size) is not int or ram_base < 0 or ram_size <= 0 or ram_base + ram_size > 0x100000000):
        return None
    try:
        image = bytes(image)
    except (TypeError, ValueError):
        return None
    facts = facts_for(image)
    scan_limit = min(_SCATTER_LIMIT, len(image))
    rows = tuple(row for row in facts.scatter_candidates(limit=scan_limit) if row.source % 4 == 0 and row.target % 4 == 0 and row.size >= _DESCRIPTOR_SIZE and
        row.source + row.size <= len(image) and ram_base <= row.target and row.target + row.size <= ram_base + ram_size and row.zero_target is not None and row.zero_size
        is not None and row.zero_target % 4 == 0 and row.zero_size % 4 == 0 and row.zero_size > 0 and ram_base <= row.zero_target and row.zero_target + row.zero_size
        <= ram_base + ram_size)
    if not rows:
        return None
    marker = struct.pack('<I', _CODE_ID)
    id_offsets = []
    cursor = 0
    while (cursor := image.find(marker, cursor)) >= 0:
        id_offsets.append(cursor)
        cursor += 1
    rows = tuple(row for row in rows if any(row.source <= address < row.source + row.size for address in id_offsets))
    if not rows:
        return None
    references = facts.literal_access_candidates(((0, min(scan_limit, 1 << 32)),), limit=scan_limit)
    matches = {}
    for row in rows:
        descriptor_sites = tuple(_descriptor_offsets(image, row.source, row.size))
        if not descriptor_sites:
            continue
        consumers = prove_copy_consumer(facts, row, references, extra_write_ranges=((0x03000600, 0x03000780),))
        if len(consumers) != 1:
            continue
        consumer = consumers[0]
        for descriptor in descriptor_sites:
            parsed = _descriptor_profile(image, row, descriptor, ram_base, ram_size)
            if parsed is None:
                continue
            profile, callbacks, sectors = parsed
            descriptor_address = row.target + descriptor - row.source
            state_address = descriptor_address - 16
            pointer_offsets = _DESCRIPTOR_FIELDS
            callback_pointers = tuple((_word(image, descriptor + offset), descriptor + offset) for offset in pointer_offsets)
            descriptor_references = facts.literal_access_candidates(((descriptor_address, descriptor_address + _DESCRIPTOR_SIZE),), limit=len(image))
            if (any(pointer is None for pointer, _ in callback_pointers) or any(facts.pointer_candidates(pointer) != (source,) for pointer, source in
                callback_pointers) or not _descriptor_has_code_consumer(facts, descriptor_address, _DESCRIPTOR_SIZE, descriptor_references, consumer) or (initializer
                := _state_initializer(facts, state_address)) is None or not _initializer_has_direct_caller(facts, initializer, state_address) or not
                _callbacks_share_state(facts, callbacks, state_address)):
                continue
            evidence = prove_amd_x16_hardware_contract(_word(image, descriptor + 164), sectors, callbacks, facts, consumer, window_base=profile.window_base,
                window_size=profile.capacity,)
            if evidence is not None:
                matches[(row.table, descriptor)] = ByteNORProof((evidence.profile.window_base, evidence.profile.capacity, evidence.profile.manufacturer_id,
                    evidence.profile.device_id), row, consumer, descriptor, descriptor_address, state_address, initializer.entry, tuple(sorted(callbacks.items())),
                    tuple(write.instruction for _, writes in evidence.command_writes for write in writes), sectors, evidence,)
    if len(matches) != 1:
        return None
    return next(iter(matches.values()))

def find_byte_offset_nv_nor(image: bytes, ram_base: int, ram_size: int) -> tuple[int, int, int, int] | None:
    """Project one code-linked byte-NOR proof to its legacy public tuple."""
    proof = find_byte_nv_nor_proof(image, ram_base, ram_size)
    return None if proof is None else proof.profile
