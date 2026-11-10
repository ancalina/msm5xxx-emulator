from __future__ import annotations

def find_embedded_fujitsu_x16_nor(image: bytes, flash_size: int,) -> tuple[int, int, int, int] | None:
    """Return a uniquely linked Fujitsu command-bus region in the dump."""
    from . import FUJITSU_MB84VD2219X_IDS, find_all, find_fujitsu_x16_bulk_write, struct
    device_size = 0x200000
    device_id = FUJITSU_MB84VD2219X_IDS[0] | (FUJITSU_MB84VD2219X_IDS[1] << 16)
    if (b"fs_fujitsu.c\0" not in image or flash_size <= 0 or flash_size > len(image)):
        return None
    profiles: list[tuple[int, int, int, int]] = []
    for descriptor in find_all(image, struct.pack("<I", device_id)):
        if descriptor & 3 or descriptor + 0x2C > flash_size:
            continue
        identity, reserved, banks, usable_base, usable_size = (struct.unpack_from("<5I", image, descriptor))
        command_base = usable_base - 0x10000
        if (identity != device_id or reserved != 0 or banks != 1 or command_base <= 0 or command_base % device_size or command_base + device_size > flash_size
            or usable_base != command_base + 0x10000 or usable_size <= 0 or usable_size % 0x10000 or usable_base + usable_size > command_base + device_size):
            continue
        functions = struct.unpack_from("<6I", image, descriptor + 0x14)
        writer = find_fujitsu_x16_bulk_write(image, command_base)
        if (writer is None or any(not pointer & 1 or pointer & ~1 >= flash_size for pointer in functions) or (functions[3] & ~1) + 0x60 != writer):
            continue
        sectors = usable_size // 0x10000
        geometry = (struct.pack("<I", sectors)
                    + struct.pack(f"<{sectors}I", *(0x10000,) * sectors))
        geometry_records: list[int] = []
        for position in find_all(image, geometry):
            record = position - 4
            if record < 0:
                continue
            name = struct.unpack_from("<I", image, record)[0]
            end = image.find(b"\0", name, min(flash_size, name + 64))
            if (0 <= name < flash_size and end >= name + 4 and all(0x20 <= byte <= 0x7E for byte in image[name: end])):
                geometry_records.append(record)
        if len(geometry_records) != 1:
            continue
        profiles.append((command_base, device_size, *FUJITSU_MB84VD2219X_IDS))
    # Later inline layout places 112 sector entries before seven callbacks.
    name_positions = find_all(image, b"Fujitsu MB84VD2219X\0")
    if len(name_positions) == 1:
        for descriptor in find_all(image, struct.pack("<I", name_positions[0])):
            if descriptor & 3 or descriptor + 8 > flash_size:
                continue
            sector_count = struct.unpack_from("<I", image, descriptor + 4)[0]
            info_end = descriptor + 8 + sector_count * 4
            if (sector_count != 112 or info_end + 0x30 > flash_size or struct.unpack_from("<4H", image, info_end) != (0x98, 0x9C, 0, 0) or struct.unpack_from("<H",
                image, info_end + 8)[0] != 1):
                continue
            sectors = struct.unpack_from(
                f"<{sector_count}I", image, descriptor + 8
            )
            usable_base, usable_size = struct.unpack_from("<2I", image, info_end + 0xC)
            functions = struct.unpack_from("<7I", image, info_end + 0x14)
            command_base = usable_base - 0x10000
            physical_size = flash_size - command_base
            if (command_base <= 0 or physical_size != 0x800000 or command_base % physical_size):
                continue
            writer = find_fujitsu_x16_bulk_write(image, command_base)
            boundaries = (list(range(command_base, command_base + 0x10000, 0x2000)) + list(range(command_base + 0x10000, command_base + physical_size - 0x10000,
                0x10000)) + list(range(command_base + physical_size - 0x10000, command_base + physical_size, 0x2000)) +[command_base + physical_size])
            boundary_table = struct.pack(
                f"<{len(boundaries)}I", *boundaries
            )
            if (usable_base != command_base + 0x10000 or usable_size != sum(sectors) or any(size != 0x10000 for size in sectors) or usable_base + usable_size >
                flash_size or writer is None or (functions[2] & ~1) != writer or len(find_all(image, boundary_table)) != 1 or any(not pointer & 1 or pointer & ~
                1 >= flash_size for pointer in functions)):
                continue
            profiles.append((command_base, physical_size, *FUJITSU_MB84VD2219X_IDS))
    return profiles[0] if len(profiles) == 1 else None

def find_compound_fujitsu_layout(image: bytes, load_address: int = 0) -> tuple[int, int] | None:
    """Return primary/secondary sizes for a complete Fujitsu 4+2 MiB dump."""
    from . import arm_vector_score, find_fujitsu_x16_bulk_write
    secondary_size = 0x200000
    found: list[tuple[int, int]] = []
    for primary_size in (0x200000, 0x400000, 0x800000):
        if len(image) != primary_size + secondary_size:
            continue
        primary = image[:primary_size]
        secondary = image[primary_size:]
        marker = secondary.find(b"\x0b$USER_DIRS\0")
        storage = (not secondary.strip(b"\xff") or (marker >= 0 and marker & 0xFF == 0x1C and b"nvm/" in secondary))
        if (arm_vector_score(primary) >= 2 and b"fs_fujitsu.c\0" in primary and find_fujitsu_x16_bulk_write(primary, load_address + primary_size) is not None
            and arm_vector_score(secondary) < 2 and storage):
            found.append((primary_size, secondary_size))
    return found[0] if len(found) == 1 else None

def fujitsu_x16_flash_ids(image: bytes, writer_address: int | None, load_address: int, secondary_base: int) -> tuple[int, int] | None:
    from . import FUJITSU_MB84VD2219X_IDS, fujitsu_x16_bulk_write_at
    position = -1 if writer_address is None else writer_address - load_address
    if (position >= 0 and fujitsu_x16_bulk_write_at(image, position, secondary_base)):
        return FUJITSU_MB84VD2219X_IDS
    return None
