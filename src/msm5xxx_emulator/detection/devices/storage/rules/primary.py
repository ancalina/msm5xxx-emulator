from __future__ import annotations
from msm5xxx_emulator.detection.contracts import _normalized_thumb_sha256

def primary_probe_x16_nor_profile(image: bytes, probe_address: int | None, load_address: int, flash_size: int, image_offset: int, ram_base: int,
    ram_image_offset: int, ram_image_size: int, ram_size: int | None = None,) -> tuple[tuple[int, int, tuple[tuple[int, int], ...], int, int] | None, str | None,]:
    """Decode one descriptor-linked primary x16 NOR probe profile."""
    from . import PAGE, PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE, PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE, PRIMARY_FLASH_PROBE_SIGNATURE, PRIMARY_STATIC_TABLE_COPY_PATTERN, facts_for, find_all, parse_sector_table, parse_x16_descriptor, printable_name_end, sector_regions, sector_tables_before, struct
    if probe_address is None:
        return None, None
    flash_end = load_address + flash_size
    mapped_ram_size = ram_image_size if ram_size is None else ram_size
    ram_end = ram_base + mapped_ram_size
    primary_end = min(len(image), image_offset + flash_size)
    def primary_offset(address: int, size: int) -> int | None:
        offset = image_offset + address - load_address
        if (load_address <= address <= flash_end - size and image_offset <= offset <= len(image) - size):
            return offset
        return None
    def read_sector_data(address: int, size: int) -> bytes | None:
        # Legacy admission bounds the table header to the flash mapping, then
        # bounds the sector payload to supplied bytes.
        offset = primary_offset(address, 8)
        if offset is None or offset < 0 or offset + size > len(image):
            return None
        return image[offset:offset + size]
    def ram_offset(address: int, size: int) -> int | None:
        relative = address - ram_base
        offset = image_offset + ram_image_offset + relative
        return offset if (0 <= relative <= ram_image_size - size and 0 <= offset <= len(image) - size) else None
    signature_size = len(PRIMARY_FLASH_PROBE_SIGNATURE)
    probe = primary_offset(probe_address, signature_size + 12)
    if probe is None:
        return None, "probe-shape-mismatch"
    candidate = image[probe:probe + signature_size]
    if candidate == PRIMARY_FLASH_PROBE_SIGNATURE:
        signature = PRIMARY_FLASH_PROBE_SIGNATURE
        static_descriptor = False
        external_static_descriptor = False
    elif candidate == PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE:
        signature = PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE
        static_descriptor = True
        external_static_descriptor = False
    elif candidate == PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE:
        signature = PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE
        static_descriptor = True
        external_static_descriptor = True
    else:
        return None, "probe-shape-mismatch"
    if (flash_size <= 0 or mapped_ram_size <= 0 or image.find(signature, image_offset, primary_end) != probe or image.find(signature, probe + 1, primary_end) >=
        0 or any(image.find(other, image_offset, primary_end) >= 0 for other in (PRIMARY_FLASH_PROBE_SIGNATURE, PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE,
        PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE,) if other != signature)):
        return None, "probe-shape-mismatch"
    descriptor_base, flash_base_global, table_global = struct.unpack_from("<3I", image, probe + len(signature))
    if (flash_base_global & 3 or table_global & 3):
        return None, "probe-global-alignment-mismatch"
    if (not ram_base <= flash_base_global <= ram_end - 4 or not ram_base <= table_global <= ram_end - 8):
        return None, "probe-global-range-mismatch"
    static_runtime_table = False
    if static_descriptor:
        primary = image[image_offset:primary_end]
        probe_position = probe - image_offset
        if external_static_descriptor:
            wrappers = [wrapper for wrapper in find_all(primary, b"\x00\xb5") if (facts_for(primary).thumb_call_target(wrapper + 2) == probe_position and
                primary[wrapper + 6:wrapper + 10] == b"\x08\xbc\x18\x47")]
            if wrappers !=[probe_position - 0x44]:
                return None, "probe-external-wrapper-mismatch"
            descriptor_address = descriptor_base + 8
            static_offset = primary_offset(descriptor_address, 0x38)
            if static_offset is None:
                return None, "probe-external-descriptor-mismatch"
            usable_words = struct.unpack_from("<I", image, static_offset + 0x10)[0]
            tables = tuple(table for table in sector_tables_before(read_sector_data, descriptor_address, expected_name=descriptor_address + 0x38, facts=facts_for(image),
                cache_key=('primary-probe-external', load_address, image_offset, primary_end),) if sum(table.sectors) == usable_words * 2)
            if len(tables) != 1:
                return None, "probe-external-descriptor-mismatch"
            entry, terminator, flash_base = tables[0].address, 0, 0
        else:
            wrapper = probe_position - 0x4C
            if (wrapper < 0 or primary[wrapper:wrapper + 2] != b"\x00\xb5" or facts_for(primary).thumb_call_target(wrapper + 2) != probe_position or primary[wrapper
                + 6:wrapper + 10] != b"\x08\xbc\x18\x47"):
                return None, "probe-static-initializer-mismatch"
            callers: list[int] = []
            for caller in find_all(primary, b"\xb0\xb5\x01\x20\xc0\x05"):
                object_global = facts_for(primary).thumb_literal_value(caller + 8, 7)
                consumer = facts_for(primary).thumb_call_target(caller + 22)
                if (caller + 30 <= len(primary) and facts_for(primary).thumb_literal_value(caller + 6, 4) == flash_base_global and object_global is not None and
                    not (object_global & 3) and ram_base <= object_global <= ram_end - 4 and primary[caller + 10:caller + 16] == b"\x00\x25\x20\x60\x3d\x60" and
                    facts_for(primary).thumb_call_target(caller + 16) == wrapper and primary[caller + 20:caller + 22] == b"\x38\x60" and consumer is not None
                    and 0 <= consumer < flash_size and primary[caller + 26:caller + 30] == b"\x38\x68\x00\x28"):
                    callers.append(caller)
            if len(callers) != 1:
                return None, "probe-static-initializer-mismatch"
            flash_base = 1 << 23
            copy_links: list[tuple[int, int]] = []
            for match in PRIMARY_STATIC_TABLE_COPY_PATTERN.finditer(primary):
                copy = match.start()
                size_field = facts_for(primary).thumb_literal_value(copy, 0)
                source_field = facts_for(primary).thumb_literal_value(copy + 6, 0)
                target_field = facts_for(primary).thumb_literal_value(copy + 10, 1)
                if (copy & 1 or size_field is None or source_field is None or source_field & 3 or target_field != source_field + 4 or size_field != source_field
                    + 8):
                    continue
                tuple_offset = primary_offset(source_field, 20)
                if tuple_offset is None:
                    continue
                source, target, size, bss, bss_size = struct.unpack_from("<5I", image, tuple_offset)
                if (source & 3 or target & 3 or size < 8 or size & 3 or primary_offset(source, size) is None or not ram_base <= target <= table_global or size >
                    ram_end - target or table_global > target + size - 8 or target + size != bss or bss_size <= 0 or bss_size > ram_end - bss):
                    continue
                table_source = source + table_global - target
                table_offset = primary_offset(table_source, 8)
                if table_offset is None:
                    continue
                entry, terminator = struct.unpack_from("<2I", image, table_offset)
                if terminator == 0 and load_address <= entry < flash_end:
                    copy_links.append((copy, entry))
            if len(copy_links) != 1:
                return None, "probe-global-linkage-mismatch"
            _, entry = copy_links[0]
            terminator = 0
    else:
        if ram_image_size > 0:
            base_offset = ram_offset(flash_base_global, 4)
            table_offset = ram_offset(table_global, 8)
            if base_offset is None or table_offset is None:
                return None, "probe-runtime-snapshot-missing"
            flash_base = struct.unpack_from("<I", image, base_offset)[0]
            entry, terminator = struct.unpack_from("<2I", image, table_offset)
        else:
            primary = image[image_offset:primary_end]
            probe_position = probe - image_offset
            wrapper = probe_position - 0x4C
            if (wrapper < 0 or primary[wrapper:wrapper + 2] != b"\x00\xb5" or facts_for(primary).thumb_call_target(wrapper + 2) != probe_position or primary[wrapper
                + 6:wrapper + 10] != b"\x08\xbc\x18\x47"):
                return None, "probe-static-initializer-mismatch"
            callers: list[tuple[int, int]] = []
            for caller in find_all(primary, b"\xb0\xb5"):
                if caller + 30 > len(primary):
                    continue
                move, shift = struct.unpack_from("<2H", primary, caller + 2)
                object_global = facts_for(primary).thumb_literal_value(caller + 8, 7)
                consumer = facts_for(primary).thumb_call_target(caller + 22)
                if (move & 0xFF00 != 0x2000 or shift & 0xF83F or facts_for(primary).thumb_literal_value(caller + 6, 4) != flash_base_global or object_global is
                    None or object_global & 3 or table_global != object_global + 0x78 or not ram_base <= object_global <= ram_end - 4 or primary[caller + 10:
                    caller + 16] != b"\x00\x25\x20\x60\x3d\x60" or facts_for(primary).thumb_call_target(caller + 16) != wrapper or primary[caller + 20:caller +
                    22] != b"\x38\x60" or consumer is None or consumer + 20 > len(primary) or primary[caller + 26:caller + 30] != b"\x38\x68\x00\x28" or primary[consumer:consumer
                    + 12] != bytes.fromhex("044800b50068ff3041300069") or facts_for(primary).thumb_literal_value(consumer, 0) != object_global or facts_for(primary).thumb_call_target(consumer
                    + 12) is None or primary[consumer + 16:consumer + 20] != b"\x08\xbc\x18\x47"):
                    continue
                callers.append((caller, (move & 0xFF) << (shift >> 6 & 0x1F)))
            if len(callers) != 1:
                return None, "probe-static-initializer-mismatch"
            _, flash_base = callers[0]
            copy_links: list[int] = []
            for offset in range(0, min(len(primary) - 20, 0x20000) + 1, 4):
                source, target, size, bss, bss_size = struct.unpack_from("<5I", primary, offset)
                source_offset = primary_offset(source, size)
                if (source & 3 or target & 3 or size < 8 or size & 3 or source_offset is None or not ram_base <= target <= table_global or size > ram_end -
                    target or table_global > target + size - 8 or target + size != bss or bss_size <= 0 or bss_size > ram_end - bss):
                    continue
                table_source = source + table_global - target
                table_offset = primary_offset(table_source, 8)
                if table_offset is None:
                    continue
                candidate_entry, candidate_terminator = struct.unpack_from("<2I", image, table_offset)
                if (candidate_terminator == 0 and load_address <= candidate_entry < flash_end):
                    copy_links.append(candidate_entry)
            if len(copy_links) != 1:
                return None, "probe-global-linkage-mismatch"
            entry, terminator = copy_links[0], 0
            static_runtime_table = True
    entry_offset = primary_offset(entry, 8)
    if (terminator != 0 or entry_offset is None or not load_address <= entry < flash_end):
        return None, "descriptor-table-mismatch"
    table = parse_sector_table(read_sector_data, entry)
    if table is None:
        return None, "geometry-count-mismatch"
    name_address, sector_count = table.name_address, table.count
    descriptor = entry + 8 + sector_count * 4
    descriptor_offset = primary_offset(descriptor, 0x38)
    name_offset = primary_offset(name_address, 4)
    if ((not static_descriptor and descriptor != entry + 0x124) or descriptor_base != descriptor - (8 if static_descriptor else 0x24) or descriptor_offset is
        None or name_offset is None or name_address != descriptor + 0x38 or entry_offset + 8 + sector_count * 4 > len(image)):
        return None, "descriptor-shape-mismatch"
    descriptor_facts = parse_x16_descriptor(image, descriptor_offset, callback_count=9, address=descriptor)
    assert descriptor_facts is not None
    reserved, device_control_options = descriptor_facts.reserved, descriptor_facts.mode
    manufacturer, device = descriptor_facts.manufacturer, descriptor_facts.device
    base_address = flash_base + descriptor_facts.base_words * 2
    size = descriptor_facts.usable_words * 2
    printable_end = printable_name_end(image, name_offset, primary_end)
    physical_end = base_address + size
    external_range = (load_address == 0 and base_address < ram_base and size <= ram_base - base_address and physical_end > base_address and not physical_end & (physical_end
        - 1) and (flash_end <= base_address or physical_end == flash_end))
    dumped_end = load_address + primary_end - image_offset
    linked_tail_range = (static_runtime_table and dumped_end <= base_address < physical_end <= ram_base and flash_end < physical_end)
    contained_range = (load_address <= base_address < flash_end and size <= flash_end - base_address)
    range_valid = (external_range if external_static_descriptor else contained_range or linked_tail_range)
    if (reserved != 0 or device_control_options != 1 or any(not (pointer & 1) or not load_address <= (pointer & ~1) < flash_end for pointer in descriptor_facts.callbacks)
        or printable_end is None or manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF) or size <= 0 or not range_valid or sum(table.sectors) != size):
        return None, "descriptor-content-mismatch"
    regions, geometry_error = sector_regions(table.sectors, minimum=PAGE)
    if geometry_error is not None:
        return None, geometry_error
    assert regions is not None
    if (base_address - load_address) % regions[0][1]:
        return None, "geometry-base-alignment-mismatch"
    return (base_address - load_address, size, tuple(regions), manufacturer, device,), None

def qualcomm_efs_seed(size: int, chipset: str) -> bytes:
    """Return the captured MSM5500 GEFS seed, otherwise erased NOR."""
    if size < 0x200:
        raise ValueError("secondary flash is too small for GEFS")
    seed = bytearray(b"\xff" * size)
    if chipset != "MSM5500":
        return bytes(seed)
    seed[:0x14] = bytes.fromhex("ed000a0000000100000000000b00000000000000")
    seed[0x15:0x18] = b"\x00\x01\x03"
    seed[0x1C:0x28] = b"\x0b$USER_DIRS\x00"
    seed[0x1FC:0x200] = bytes.fromhex("0000d586")
    return bytes(seed)

def fujitsu_x16_bulk_write_mode_at(image: bytes, position: int, secondary_base: int,) -> str | None:
    from . import FUJITSU_X16_BULK_WRITE_HASHED_SHAPES, FUJITSU_X16_BULK_WRITE_LEGACY_CALLS, FUJITSU_X16_BULK_WRITE_LEGACY_HASH, FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX, FUJITSU_X16_BULK_WRITE_PATTERNS, facts_for, hashlib, struct
    for pattern, literal_offset, unlock_offset in FUJITSU_X16_BULK_WRITE_PATTERNS:
        if (pattern.match(image, position) is not None and position + literal_offset + 4 <= len(image) and struct.unpack_from("<I", image, position +
            literal_offset)[0] == secondary_base + unlock_offset):
            return "unlock-bypass"
    if (0 <= position <= len(image) - 0x94 and image[position:position + len(FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX)] == FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX and
        struct.unpack_from("<I", image, position + 0x90)[0] == secondary_base + 0xAA0):
        if _normalized_thumb_sha256(image, position, 0x7E) == (FUJITSU_X16_BULK_WRITE_LEGACY_HASH, FUJITSU_X16_BULK_WRITE_LEGACY_CALLS):
            return "unlock-bypass"
    for (prefix, body_size, literal_offset, literal_deltas, expected_calls, body_hash) in FUJITSU_X16_BULK_WRITE_HASHED_SHAPES:
        if (position < 0 or position + max(body_size, literal_offset + 8) > len(image) or image[position: position + len(prefix)] != prefix or struct.unpack_from("<2I",
            image, position + literal_offset) != tuple(secondary_base + delta for delta in literal_deltas)):
            continue
        if _normalized_thumb_sha256(image, position, body_size) == (body_hash, expected_calls):
            return "per-word-unlock"
    return None

def fujitsu_x16_bulk_write_at(image: bytes, position: int, secondary_base: int) -> bool:
    from . import fujitsu_x16_bulk_write_mode_at
    return fujitsu_x16_bulk_write_mode_at(image, position, secondary_base) is not None

def find_fujitsu_x16_bulk_write(image: bytes, secondary_base: int) -> int | None:
    from . import FUJITSU_X16_BULK_WRITE_HASHED_SHAPES, FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX, FUJITSU_X16_BULK_WRITE_PATTERNS, find_all, fujitsu_x16_bulk_write_at
    if b"fs_fujitsu.c\0" not in image:
        return None
    candidates = { match.start() for pattern, _literal_offset, _unlock_offset in FUJITSU_X16_BULK_WRITE_PATTERNS for match in pattern.finditer(image) }
    for prefix, *_rest in FUJITSU_X16_BULK_WRITE_HASHED_SHAPES:
        candidates.update(find_all(image, prefix))
    candidates.update(find_all(image, FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX))
    matches = [position for position in sorted(candidates) if fujitsu_x16_bulk_write_at(image, position, secondary_base)]
    return matches[0] if len(matches) == 1 else None

def find_adjacent_fujitsu_x16_nor(image: bytes, flash_size: int,) -> tuple[int, int, int, int] | None:
    """Return a uniquely linked adjacent Fujitsu command-bus region."""
    from . import FUJITSU_MB84VD2219X_IDS, find_all, find_fujitsu_x16_bulk_write, struct
    device_id = FUJITSU_MB84VD2219X_IDS[0] | (FUJITSU_MB84VD2219X_IDS[1] << 16)
    if b"fs_fujitsu.c\0" not in image or flash_size <= 0:
        return None
    complete_primary = flash_size <= len(image)
    profiles: list[tuple[int, int, int, int]] = []
    for descriptor in find_all(image, struct.pack("<I", device_id)):
        if (descriptor & 3 or descriptor + 0x2C > min(flash_size, len(image))):
            continue
        identity, reserved, banks, usable_base, usable_size = (struct.unpack_from("<5I", image, descriptor))
        functions = struct.unpack_from("<6I", image, descriptor + 0x14)
        # Some MB84VD2219X layouts expose only the usable range after one or
        # more 8 KiB boot sectors.  The descriptor, exact writer literals,
        # function table, and remaining-sector geometry jointly own the
        # adjacent physical device; a bare address or truncated dump does not.
        command_base = flash_size
        writer = find_fujitsu_x16_bulk_write(image, command_base)
        reserved_boot = usable_base - command_base
        physical_size = reserved_boot + usable_size
        if (identity == device_id and reserved == 0 and banks == 1 and writer is not None and (functions[1] & ~1) == writer and all(pointer & 1 and pointer & ~1
            < len(image) for pointer in functions) and 0 <= reserved_boot <= 0x10000 and reserved_boot % 0x2000 == 0 and physical_size in (0x200000, 0x400000,
            0x800000) and command_base % physical_size == 0 and physical_size >= 0x10000 and (physical_size - 0x10000) % 0x10000 == 0):
            small_sectors = (0x10000 - reserved_boot) // 0x2000
            large_sectors = (physical_size - 0x10000) // 0x10000
            sector_sizes = ((0x2000,) * small_sectors + (0x10000,) * large_sectors)
            geometry = struct.pack(
                f"<{len(sector_sizes) + 1}I",
                len(sector_sizes), *sector_sizes,
            )
            geometry_records = []
            for position in find_all(image, geometry):
                record = position - 4
                if record < 0:
                    continue
                name = struct.unpack_from("<I", image, record)[0]
                end = image.find(b"\0", name, min(len(image), name + 64))
                if (0 <= name < len(image) and end >= name + 4 and all(0x20 <= byte <= 0x7E for byte in image[name:end])):
                    geometry_records.append(record)
            if len(geometry_records) == 1:
                partition_end = command_base + physical_size
                for candidate_size in (0x400000, 0x800000):
                    if (candidate_size <= physical_size or command_base % candidate_size):
                        continue
                    boundaries = (list(range(command_base, command_base + 0x10000, 0x2000)) + list(range(command_base + 0x10000, command_base + candidate_size,
                        0x10000)))
                    table = struct.pack(
                        f"<{len(boundaries)}I", *boundaries
                    )
                    if len(find_all(image, table)) != 1:
                        continue
                    resource_runs = []
                    for position in find_all(image, struct.pack("<I", partition_end)):
                        if position & 3 or position + 0x40 > len(image):
                            continue
                        values = struct.unpack_from("<16I", image, position)
                        deltas = tuple(right - left for left, right in zip(values, values[1:]))
                        if (all(not value & 0xF and partition_end <= value < command_base + candidate_size for value in values) and all(delta >= 0 for delta in
                            deltas) and any(0 < delta < 0x10000 for delta in deltas)):
                            resource_runs.append(position)
                    if len(resource_runs) == 1:
                        physical_size = candidate_size
                profiles.append((command_base, physical_size, *FUJITSU_MB84VD2219X_IDS))
                continue
        if not complete_primary:
            continue
        command_base = usable_base - 0x10000
        writer = find_fujitsu_x16_bulk_write(image, command_base)
        if (identity != device_id or reserved != 0 or banks != 1
                or command_base != flash_size
                or usable_base != command_base + 0x10000
                or usable_size <= 0 or usable_size % 0x10000
                or writer is None
                or any(not pointer & 1 or pointer & ~1 >= flash_size
                       for pointer in functions)
                # The established +0x60 class keeps its existing transport
                # fallback and persistent-state extent.  This detector owns
                # only the newly closed adjacent +0x6C class.
                or writer - (functions[3] & ~1) != 0x6C):
            continue
        sectors = usable_size // 0x10000
        usable_geometry = (struct.pack("<I", sectors)
                           + struct.pack(f"<{sectors}I",
                                         *(0x10000,) * sectors))
        geometry_records = []
        for position in find_all(image, usable_geometry):
            record = position - 4
            if record < 0:
                continue
            name = struct.unpack_from("<I", image, record)[0]
            end = image.find(b"\0", name, min(flash_size, name + 64))
            if (0 <= name < flash_size and end >= name + 4 and all(0x20 <= byte <= 0x7E for byte in image[name: end])):
                geometry_records.append(record)
        if len(geometry_records) != 1:
            continue
        physical_sizes = []
        for size in (0x200000, 0x400000, 0x800000):
            boundaries = (list(range(command_base, command_base + 0x10000, 0x2000)) + list(range(command_base + 0x10000, command_base + size, 0x10000)) +[0])
            table = struct.pack(f"<{len(boundaries)}I", *boundaries)
            if len(find_all(image, table)) == 1:
                physical_sizes.append(size)
        if (len(physical_sizes) != 1 or 0x10000 + usable_size > physical_sizes[0] or command_base % physical_sizes[0]):
            continue
        profiles.append((command_base, physical_sizes[0], *FUJITSU_MB84VD2219X_IDS))
    return profiles[0] if len(profiles) == 1 else None
