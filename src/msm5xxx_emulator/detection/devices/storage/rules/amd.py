from __future__ import annotations

def seeded_amd_x16_nor_profile(image: bytes, load_address: int, flash_size: int, ram_base: int, ram_size: int,) -> tuple[tuple[int, int, tuple[tuple[int, int],
    ...], int, int] | None, str | None]:
    """Temporary evidence-gated seeded descriptor class, with native fallback.

    Byte-sized sector entries omit two reserved bottom sectors. Do not derive
    capacity from the driver's overpermissive doubled-span bounds check.
    Independent firmware reproduction is required before widening this class.
    """
    from . import _record_amd_x16_shape_at, facts_for, find_all, struct
    primary = image[:flash_size]
    writer_prefix = bytes.fromhex("f8b5041c8818171c")
    writers = find_all(primary, writer_prefix)
    if not writers:
        return None, None
    if len(writers) != 1 or load_address != 0 or len(primary) != flash_size:
        return None, "seeded-writer-map"
    writer = writers[0]
    records = find_all(primary, struct.pack("<3I", 0x009C0098, 0, 1))
    if len(records) != 1:
        return None, "seeded-descriptor-ambiguity"
    matches = []
    for record in records:
        if record < 0x124 or record + 0x30 > len(primary):
            continue
        fields = struct.unpack_from("<12I", primary, record)
        _, _, _, usable, span, reader, program, erase, _, _, _, context = fields
        if (program != writer + 1 or not reader & 1 or not erase & 1 or context & 3 or not ram_base + 4 <= context <= ram_base + ram_size - 0x160 or (usable,
            span) != (0x804000, 0x3FC000) or usable + span > flash_size):
            continue
        table = record - 0x124
        if (struct.unpack_from("<I", primary, table + 4)[0] != 69 or struct.unpack_from("<69I", primary, table + 8) != (0x2000,) * 6 + (0x10000,) * 63):
            continue
        matches.append((reader - 1, erase - 1, context - 4))
    if len(matches) != 1:
        return None, "seeded-descriptor-geometry"
    reader, erase, context_global = matches[0]
    eraser = facts_for(primary).thumb_call_target(erase + 0x4A)
    if eraser is None:
        return None, "seeded-erase-link"
    shapes = ((reader, "f0b5061c88180f1c", 0x56, (0x2A, 0x46, 0x4E), "8f21ec8e07acbdb32e85d0c41aac7c96964e2ab78060c83421a8d00e0de42a25"), (writer, writer_prefix.hex(),
        0xF8, (0x4A, 0x64, 0x6C, 0xA2, 0xBE, 0xC6, 0xD4, 0xE8, 0xF0), "a4bb489e451032d1b09dd39967144c828a2e8ff3536054e82fd2f8ae0b91d0c8"), (erase,
        "b8b51b4c071c2079", 0x70, (0x22, 0x3A, 0x44, 0x4A, 0x60), "99a4336548fb90419928808bde5e5cb1bf01ddde958688a9ace084262a50222a"), (eraser, "b0b5071c", 0x48,
        (0x04, 0x24, 0x2C, 0x38), "d3a82d96162f4fb98af9a6d986bbf150a1ad68c190c0e2da7bc2eba0a92f1bcb"),)
    if not all(_record_amd_x16_shape_at(primary, pos, bytes.fromhex(prefix), size, calls, digest) for pos, prefix, size, calls, digest in shapes):
        return None, "seeded-driver-shape"
    if (any(facts_for(primary).thumb_literal_value(pos, reg) != context_global for pos, reg in ((reader + 8, 1), (reader + 0x30, 0), (writer + 8, 2), (erase +
        0x26, 0))) or any(facts_for(primary).thumb_literal_value(pos, reg) != value for pos, reg, value in ((writer + 0x4E, 2, 0x80AAA0), (writer + 0xA6, 2,
        0x80AAA0), (writer + 0x54, 3, 0x805540), (writer + 0xAC, 3, 0x805540), (eraser + 8, 2, 0x80AAA0), (eraser + 0xE, 5, 0x805540)))):
        return None, "seeded-driver-literals"
    status = facts_for(primary).thumb_literal_value(writer + 0x18, 3)
    if (status is None or status & 3 or not ram_base <= status <= ram_base + ram_size - 12 or facts_for(primary).thumb_literal_value(reader + 0x1A, 1) != status
        or facts_for(primary).thumb_literal_value(reader + 0x32, 1) != status or facts_for(primary).thumb_literal_value(erase + 2, 4) != status or facts_for(primary).thumb_call_target(writer
        + 0x6C) != facts_for(primary).thumb_call_target(eraser + 0x2C)):
        return None, "seeded-driver-state"
    consumers = [pos for pos in find_all(primary, bytes.fromhex("f8b500250026")) if _record_amd_x16_shape_at(primary, pos, bytes.fromhex("f8b500250026"), 0xAC,
        (0x06, 0x2C, 0x3C, 0x66), "9470bcfe234ab5dd26dbdff97e7f7c2229c9bd8405c64b1d90626e63ee709f0f")]
    if len(consumers) != 1:
        return None, "seeded-sector-consumer"
    getter = facts_for(primary).thumb_call_target(consumers[0] + 6)
    if (getter is None or getter < 0 or primary[getter:getter + 14] != bytes.fromhex("03480068002800d1704704307047") or facts_for(primary).thumb_literal_value(getter,
        0) != context_global):
        return None, "seeded-sector-context"
    builder = consumers[0]
    array_base = facts_for(primary).thumb_literal_value(builder + 0x80, 7)
    offset_getters = find_all(primary, bytes.fromhex("01b500ab1878044980000858597801b008bc090240181847"))
    if (array_base is None or (array_base + 0x96) & 3 or not ram_base <= array_base <= ram_base + ram_size - 0x96 - 69 * 4 or any(facts_for(primary).thumb_literal_value(builder
        + offset, register) != array_base for offset, register in ((0x0E, 7), (0x62, 0), (0x6A, 2), (0x78, 0))) or len(offset_getters) != 1 or facts_for(primary).thumb_literal_value(offset_getters[0]
        + 6, 1) != array_base + 0x96):
        return None, "seeded-sector-array"
    return (0x800000, 0x400000, ((8, 0x2000), (63, 0x10000)), 0x98, 0x9C), None

def find_record_amd_x16_nor(image: bytes, flash_size: int,) -> tuple[int, int, int] | None:
    """Return one temporary exact descriptor-mapped Record NOR profile."""
    from . import ADJACENT_AMD_X16_RECORD_LOG, ADJACENT_AMD_X16_RECORD_MARKER, RECORD_AMD_X16_COPY_WRAPPER_CALLS, RECORD_AMD_X16_COPY_WRAPPER_HASH, RECORD_AMD_X16_COPY_WRAPPER_PREFIX, RECORD_AMD_X16_COPY_WRAPPER_SIZE, RECORD_AMD_X16_ENUMERATOR_HASH, RECORD_AMD_X16_ENUMERATOR_PREFIX, RECORD_AMD_X16_ENUMERATOR_SIZE, RECORD_AMD_X16_ERASER_CALLS, RECORD_AMD_X16_ERASER_HASH, RECORD_AMD_X16_ERASER_PREFIX, RECORD_AMD_X16_ERASER_SIZE, RECORD_AMD_X16_ERASE_WRAPPER_CALLS, RECORD_AMD_X16_ERASE_WRAPPER_HASH, RECORD_AMD_X16_ERASE_WRAPPER_PREFIX, RECORD_AMD_X16_ERASE_WRAPPER_SIZE, RECORD_AMD_X16_INIT_CALLS, RECORD_AMD_X16_INIT_HASH, RECORD_AMD_X16_INIT_PREFIX, RECORD_AMD_X16_INIT_SIZE, RECORD_AMD_X16_MAPPER_CALLS, RECORD_AMD_X16_MAPPER_HASH, RECORD_AMD_X16_MAPPER_PREFIX, RECORD_AMD_X16_MAPPER_SIZE, RECORD_AMD_X16_PROFILE, RECORD_AMD_X16_WRITER_CALLS, RECORD_AMD_X16_WRITER_HASH, RECORD_AMD_X16_WRITER_PREFIX, RECORD_AMD_X16_WRITER_SIZE, _record_amd_x16_shape_at, facts_for, find_all
    if flash_size != 0x1200000:
        return None
    primary = image[:flash_size]
    shapes = ((RECORD_AMD_X16_WRITER_PREFIX, RECORD_AMD_X16_WRITER_SIZE, RECORD_AMD_X16_WRITER_CALLS, RECORD_AMD_X16_WRITER_HASH), (RECORD_AMD_X16_ERASER_PREFIX,
        RECORD_AMD_X16_ERASER_SIZE, RECORD_AMD_X16_ERASER_CALLS, RECORD_AMD_X16_ERASER_HASH), (RECORD_AMD_X16_MAPPER_PREFIX, RECORD_AMD_X16_MAPPER_SIZE,
        RECORD_AMD_X16_MAPPER_CALLS, RECORD_AMD_X16_MAPPER_HASH), (RECORD_AMD_X16_ERASE_WRAPPER_PREFIX, RECORD_AMD_X16_ERASE_WRAPPER_SIZE,
        RECORD_AMD_X16_ERASE_WRAPPER_CALLS, RECORD_AMD_X16_ERASE_WRAPPER_HASH), (RECORD_AMD_X16_COPY_WRAPPER_PREFIX, RECORD_AMD_X16_COPY_WRAPPER_SIZE,
        RECORD_AMD_X16_COPY_WRAPPER_CALLS, RECORD_AMD_X16_COPY_WRAPPER_HASH), (RECORD_AMD_X16_INIT_PREFIX, RECORD_AMD_X16_INIT_SIZE, RECORD_AMD_X16_INIT_CALLS,
        RECORD_AMD_X16_INIT_HASH), (RECORD_AMD_X16_ENUMERATOR_PREFIX, RECORD_AMD_X16_ENUMERATOR_SIZE, (), RECORD_AMD_X16_ENUMERATOR_HASH),)
    positions: list[int] = []
    for prefix, size, calls, body_hash in shapes:
        matches = [position for position in find_all(primary, prefix) if _record_amd_x16_shape_at(primary, position, prefix, size, calls, body_hash)]
        if len(matches) != 1:
            return None
        positions.append(matches[0])
    writer, eraser, mapper, erase_wrapper, copy_wrapper, record_init, enum = (positions)
    if (facts_for(primary).thumb_call_target(mapper + 0x52) != enum or facts_for(primary).thumb_call_target(erase_wrapper + 0x3C) != eraser or facts_for(primary).thumb_call_target(copy_wrapper
        + 0x92) != writer or facts_for(primary).thumb_call_target(record_init + 0xCC) != writer or primary[record_init + 0x10C: record_init + 0x10E] !=
        ADJACENT_AMD_X16_RECORD_MARKER or primary[record_init + 0x110:record_init + 0x120] != ADJACENT_AMD_X16_RECORD_LOG or primary[enum + 0xF8:enum + 0xFF] !=
        b"RECORD\0"):
        return None
    base, size, sector_size = RECORD_AMD_X16_PROFILE
    return ((base, size, sector_size) if base + size <= flash_size else None)

def find_catalog_amd_x16_nor(image: bytes, flash_size: int, ram_base: int,) -> tuple[int, int, int] | None:
    """Return one temporary exact descriptor-mapped catalog NOR profile."""
    from . import CATALOG_AMD_X16_PROFILE, find_record_amd_x16_nor
    base, size, sector_size = CATALOG_AMD_X16_PROFILE
    return ((base, size, sector_size) if find_record_amd_x16_nor(image, flash_size) is not None and base == flash_size and base + size == ram_base else None)

def direct_amd_x16_nor_profile(image: bytes, load_address: int, flash_size: int, image_offset: int, ram_base: int, ram_size: int,) -> tuple[tuple[int, int, int,
    int, int, int] | None, str | None]:
    """Decode one exact ordered-descriptor direct AMD x16 NOR probe."""
    from . import DIRECT_AMD_X16_CALLER_PREFIX, DIRECT_AMD_X16_PROBE_SIGNATURE, _direct_x16_descriptor_profile, facts_for, find_all, struct
    flash_end = load_address + flash_size
    ram_end = ram_base + ram_size
    primary_end = min(len(image), image_offset + flash_size)
    primary = image[image_offset:primary_end]
    def primary_offset(address: int, size: int) -> int | None:
        offset = address - load_address
        if (load_address <= address <= flash_end - size and 0 <= offset <= len(primary) - size):
            return offset
        return None
    def read_primary(address: int, size: int) -> bytes | None:
        offset = primary_offset(address, size)
        return primary[offset:offset + size] if offset is not None else None
    probes = find_all(primary, DIRECT_AMD_X16_PROBE_SIGNATURE)
    if not probes:
        return None, None
    if len(probes) != 1:
        return None, "probe-shape-mismatch"
    probe = probes[0]
    literal_offset = probe + len(DIRECT_AMD_X16_PROBE_SIGNATURE)
    if literal_offset + 12 > len(primary):
        return None, "probe-shape-mismatch"
    descriptor_view, flash_base_global, table_global = struct.unpack_from("<3I", primary, literal_offset)
    if (descriptor_view & 3 or flash_base_global & 3 or table_global & 3 or not ram_base <= flash_base_global <= ram_end - 4 or not ram_base <= table_global <=
        ram_end - 4):
        return None, "probe-global-range-mismatch"
    callers = [caller for caller in find_all(primary, DIRECT_AMD_X16_CALLER_PREFIX) if (caller + 0x50 <= len(primary) and all(facts_for(primary).thumb_call_target(caller
        + offset) is not None for offset in (0x10, 0x1E, 0x2E, 0x38)) and facts_for(primary).thumb_call_target(caller + 0x18) == probe and primary[caller + 0x14:caller
        + 0x18] == bytes.fromhex("002804d1") and primary[caller + 0x1C:caller + 0x1E] == bytes.fromhex("2860") and primary[caller + 0x22:caller + 0x2E] == bytes.fromhex("2868002800d13760002806d1")
        and primary[caller + 0x32:caller + 0x38] == bytes.fromhex("ff2089300549") and primary[caller + 0x3C: caller + 0x44] == bytes.fromhex("3471f0bc08bc1847")
        and facts_for(primary).thumb_literal_value(caller + 4, 6) == flash_base_global and (return_global := facts_for(primary).thumb_literal_value(caller + 8,
        5)) is not None and not return_global & 3 and ram_base <= return_global <= ram_end - 4 and (log_string := facts_for(primary).thumb_literal_value(caller
        + 0x36, 1)) is not None and primary_offset(log_string, 4) is not None)]
    if len(callers) != 1:
        return None, "probe-caller-mismatch"
    descriptor = descriptor_view + 8
    descriptor_offset = primary_offset(descriptor, 0x30)
    name_offset = primary_offset(descriptor + 0x30, 4)
    profile, rejection = _direct_x16_descriptor_profile(primary, descriptor, descriptor_offset, name_offset, read_primary, name_bound=len(primary), load_address=load_address,
        flash_end=flash_end, ram_base=ram_base, ram_end=ram_end, base_at_ram_end=False, facts=facts_for(image), cache_key=('amd-direct', load_address,
        image_offset, primary_end),)
    if profile is None:
        return None, rejection
    return profile, None

def _direct_x16_descriptor_profile(primary: bytes, descriptor: int, descriptor_offset: int | None, name_offset: int | None, read_primary, *, name_bound: int,
    load_address: int, flash_end: int, ram_base: int, ram_end: int, base_at_ram_end: bool, facts, cache_key: tuple,) -> tuple[tuple[int, int, int, int, int, int]
    | None, str | None]:
    """Decode shared ordered-table and x16 descriptor constraints."""
    from . import PAGE, parse_x16_descriptor, printable_name_end, sector_tables_before, uniform_sector_size
    if descriptor_offset is None or name_offset is None:
        return None, "descriptor-shape-mismatch"
    candidates = sector_tables_before(read_primary, descriptor, expected_name=descriptor + 0x30, facts=facts, cache_key=cache_key,)
    if len(candidates) != 1:
        return None, "descriptor-shape-mismatch"
    table = candidates[0]
    descriptor_facts = parse_x16_descriptor(primary, descriptor_offset, callback_count=7, address=descriptor)
    assert descriptor_facts is not None
    base_address = descriptor_facts.base_words * 2
    size = descriptor_facts.usable_words * 2
    name_end = printable_name_end(primary, descriptor_offset + 0x30, name_bound)
    if (descriptor_facts.reserved != 0 or descriptor_facts.mode != 1 or any(not (pointer & 1) or not load_address <= (pointer & ~1) < flash_end for pointer in
        descriptor_facts.callbacks) or name_end is None or descriptor_facts.manufacturer in (0, 0xFFFF) or descriptor_facts.device in (0, 0xFFFF) or (base_at_ram_end
        and base_address != ram_end) or (not base_at_ram_end and not ram_base <= base_address < ram_end) or size <= 0 or (not base_at_ram_end and base_address +
        size > ram_end) or base_address + size > 0x100000000 or sum(table.sectors) != size):
        return None, "descriptor-content-mismatch"
    sector_size = uniform_sector_size(table.sectors, minimum=PAGE)
    if (sector_size is None or base_address % sector_size or size % sector_size):
        return None, "geometry-sector-mismatch"
    return (base_address, size, sector_size, descriptor_facts.manufacturer, descriptor_facts.device, descriptor_facts.mode,), None

def direct_intel_x16_nor_profile(image: bytes, probe_address: int | None, load_address: int, flash_size: int, image_offset: int, ram_base: int, ram_size: int,) -> tuple[tuple[int,
    int, int, int, int] | None, str | None]:
    """Decode one ordered-descriptor direct Intel x16 NOR probe."""
    from . import DIRECT_INTEL_X16_CALLER_PREFIX, DIRECT_INTEL_X16_PROBE_SIGNATURE, _direct_x16_descriptor_profile, facts_for, find_all, struct
    if probe_address is None:
        return None, None
    flash_end = load_address + flash_size
    primary_end = min(len(image), image_offset + flash_size)
    ram_end = ram_base + ram_size
    def primary_offset(address: int, size: int) -> int | None:
        offset = image_offset + address - load_address
        if (load_address <= address <= flash_end - size and image_offset <= offset <= primary_end - size):
            return offset
        return None
    def read_primary(address: int, size: int) -> bytes | None:
        offset = primary_offset(address, size)
        return image[offset:offset + size] if offset is not None else None
    signature = DIRECT_INTEL_X16_PROBE_SIGNATURE
    probe = primary_offset(probe_address, len(signature) + 12)
    if (probe is None or image[probe:probe + len(signature)] != signature or image.find(signature, image_offset, primary_end) != probe or image.find(signature,
        probe + 1, primary_end) >= 0):
        return None, "probe-shape-mismatch"
    descriptor_view, flash_base_global, table_global = struct.unpack_from("<3I", image, probe + len(signature))
    if (descriptor_view & 3 or flash_base_global & 3 or table_global & 3 or not ram_base <= flash_base_global <= ram_end - 4 or not ram_base <= table_global <=
        ram_end - 4):
        return None, "probe-global-range-mismatch"
    primary = image[image_offset:primary_end]
    probe_position = probe - image_offset
    callers = [caller for caller in find_all(primary, DIRECT_INTEL_X16_CALLER_PREFIX) if (caller + 68 <= len(primary) and facts_for(primary).thumb_call_target(caller
        + 14) == probe_position and primary[caller + 18:caller + 24] == bytes.fromhex("3860002806d1") and primary[caller + 28:caller + 34] == bytes.fromhex("ff2089300849")
        and primary[caller + 38:caller + 46] == bytes.fromhex("3868ff300130c069") and primary[caller + 50:caller + 58] == bytes.fromhex("2c71b0bc08bc1847") and
        all(facts_for(primary).thumb_call_target(caller + offset) is not None for offset in (24, 34, 46)) and facts_for(primary).thumb_literal_value(caller + 2,
        5) == flash_base_global and (return_global := facts_for(primary).thumb_literal_value(caller + 6, 7)) is not None and not return_global & 3 and ram_base
        <= return_global <= ram_end - 4)]
    if len(callers) != 1:
        return None, "probe-caller-mismatch"
    descriptor = descriptor_view + 8
    descriptor_offset = primary_offset(descriptor, 0x30)
    name_offset = primary_offset(descriptor + 0x30, 4)
    profile, rejection = _direct_x16_descriptor_profile(image, descriptor, descriptor_offset, name_offset, read_primary, name_bound=primary_end, load_address=load_address,
        flash_end=flash_end, ram_base=ram_base, ram_end=ram_end, base_at_ram_end=True, facts=facts_for(image), cache_key=('intel-direct', load_address,
        image_offset, primary_end),)
    if profile is None:
        return None, rejection
    return profile[:5], None

def mapped_primary_intel_x16_nor_profile(image: bytes, flash_size: int, ram_base: int,) -> tuple[tuple[int, int, int, int] | None, str | None]:
    """Admit one temporary exact-signature mapped primary NOR profile."""
    from . import MAPPED_PRIMARY_INTEL_X16_SIGNATURES, find_all
    primary = image[:flash_size]
    anchor_signature = MAPPED_PRIMARY_INTEL_X16_SIGNATURES[0][1]
    anchors = find_all(primary, anchor_signature)
    if not anchors:
        return None, None
    if len(anchors) != 1:
        return None, "code-anchor-mismatch"
    anchor = anchors[0]
    for index, (delta, signature) in enumerate(MAPPED_PRIMARY_INTEL_X16_SIGNATURES):
        position = anchor + delta
        if (position < 0 or primary[position:position + len(signature)] != signature or find_all(primary, signature) !=[position]):
            return None, f"code-signature-{index}-mismatch"
    logical_base = 0x00000000
    physical_base = 0x00800000
    size = 0x00800000
    sector_size = 0x00010000
    if (len(primary) != flash_size or logical_base + size != flash_size or physical_base + size != ram_base or physical_base < flash_size or size % sector_size):
        return None, "mapped-geometry-mismatch"
    return (logical_base, physical_base, size, sector_size), None
