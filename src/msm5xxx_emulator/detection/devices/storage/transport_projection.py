"""Source-qualified machine properties owned by this device domain."""
from __future__ import annotations
from .sharp_board_status import find_sharp_board_status_profile
from msm5xxx_emulator.detection.contracts import fields_match
from msm5xxx_emulator.detection.startup_sdram import reset_copy_ram_profile
from msm5xxx_emulator.detection.devices.storage.spi_nv import find_spi_nv_profile
from msm5xxx_emulator.detection.devices.storage.small_page_nand import small_page_nand_profile
from msm5xxx_emulator.detection.devices.storage.middle_nand import find_middle_nand_profile
from msm5xxx_emulator.detection.devices.storage.static_middle_nand import find_static_middle_nand_profile
from msm5xxx_emulator.detection.devices.storage.low_port_nand import find_low_port_nand_driver
from msm5xxx_emulator.detection.devices.storage.guarded_middle_nand import find_guarded_middle_nand_profile
from msm5xxx_emulator.detection.devices.storage.nv_nor import legacy_nv_tuple, select_legacy_nv_nor
from msm5xxx_emulator.detection.devices.storage.rules import flash_id_for_size, find_adjacent_amd_x16_nor
from msm5xxx_emulator.detection.devices.storage.upper_nor import UPPER_FLASH_ADDRESS, UPPER_FLASH_SIZE
RAW_NAND_STATUS_SIGNATURE = bytes.fromhex("00200521c9051522520580b4702717700b78c02b08d0c12b03d0044b01309842" "f5d3022080bc70470120fbe7")
RAW_NAND_RESET_SIGNATURE = bytes.fromhex("ff201521490508707047")
RAW_NAND_PAGE_SIGNATURE = bytes.fromhex("510a2031d205d20d")
RAW_NAND_BLOCK_PREFIX = bytes.fromhex("80b501277801")
RAW_NAND_BLOCK_SUFFIX = bytes.fromhex("013701239b029f42f7db")
RAW_NAND_X16_PREFIX = bytes.fromhex("0526f605")
RAW_NAND_X16_TRANSFER = bytes.fromhex("20883080")
from msm5xxx_emulator.detection.contracts import boot_storage_profile as _boot_storage_profile
from msm5xxx_emulator.detection.contracts import loaded_source_matches as qemu_loaded_source_matches
from msm5xxx_emulator.detection.contracts import source_class_limit as _source_class_limit

def qemu_sharp_board_status_property(image: bytes, loaded: bytes, config: object, *, claimed: bool,) -> tuple[str | None, str | None]:
    """Admit one source-verified board input without replacing another owner."""
    if claimed:
        return None, "input-owner-conflict"
    args = (config.flash_size, config.ram_base, config.ram_size)
    profile, reason = find_sharp_board_status_profile(image, *args)
    if profile is None:
        return None, reason
    if find_sharp_board_status_profile(loaded[:len(image)], *args)[0] != profile:
        return None, "loaded-source-mismatch"
    inputs = [item for item in (profile['rf'], profile['lid']) if item is not None]
    if len(inputs) != 1:
        return None, "ambiguous-board-input"
    item = inputs[0]
    return (f"board-status-input={item['address']:x}:{item['mask']:x}:"
            f"{item['default']:x}"), None

def qemu_native_nand_profile(image: bytes, config: object) -> tuple[dict | None, str | None]:
    """Bind the temporary native protocol to this loaded image and RAM gap."""
    profile = getattr(config, "native_nand_profile", None)
    if profile is None or not getattr(config, "nand_enabled", False):
        return None, None
    if (type(profile) is not dict or type(getattr(config, "flash_size", None)) is not int or not 0 < config.flash_size <= len(image)):
        return None, "invalid-profile"
    image = image[:config.flash_size]
    expected = small_page_nand_profile(image)
    ram = reset_copy_ram_profile(image)
    if expected is None or expected != profile:
        return None, "producer-shape-mismatch"
    if (ram is None or ram != getattr(config, "ram_bootstrap_profile", None) or type(getattr(config, "load_address", None)) is not int or config.load_address !=
        0 or any(getattr(config, key, None) != ram[key] for key in ("ram_base", "ram_size"))):
        return None, "reset-copy-memory-mismatch"
    geometry = tuple(getattr(config, key, None) for key in ("nand_data_size", "nand_page_size", "nand_spare_size", "nand_pages_per_block", "nand_bus_width"))
    if (any(type(value) is not int for value in geometry) or geometry != (0x2000000, 512, 16, 32, 2)):
        return None, "unsupported-main-oob-geometry"
    return expected, None

def qemu_upper_nor_enabled(config: object) -> bool:
    """Accept only the detector's closed fixed upper-NOR range."""
    address = getattr(config, "upper_flash_address", None)
    size = int(getattr(config, "upper_flash_size", 0))
    if address is None and size == 0:
        return False
    if address != UPPER_FLASH_ADDRESS or size != UPPER_FLASH_SIZE:
        raise ValueError("QEMU cannot represent the detected upper NOR")
    return True

def qemu_raw_nand_main_profile(image: bytes, config: object,) -> tuple[tuple[int, int, int, int, int, int, int] | None, str | None]:
    """Admit the closed, main-area-only small-page x16 NAND class."""
    if not getattr(config, "nand_enabled", False):
        return None, None
    guarded = find_guarded_middle_nand_profile(image)
    if guarded is not None:
        if (getattr(config, "load_address", None) != 0 or getattr(config, "flash_size", 0) > 0x01000000 or getattr(config, "ram_base", None) != 0x01000000 or
            getattr(config, "ram_size", None) != 0x800000 or getattr(config, "upper_flash_address", None) is not None):
            return None, "guarded-middle-aperture-mapping-conflict"
        return (0x01800000, 0x01900000, 0x01a00000, 0x2000000, 512, 32, 2), None
    direct_middle = (find_static_middle_nand_profile(image) if find_table7_matrix(image) is not None else None)
    if direct_middle is not None:
        if (getattr(config, "load_address", None) != 0 or getattr(config, "flash_size", 0) > 0x01000000 or getattr(config, "ram_base", None) != 0x01000000 or
            getattr(config, "ram_size", None) != 0x800000 or getattr(config, "upper_flash_address", None) is not None):
            return None, "direct-middle-aperture-mapping-conflict"
        return (0x01800000, 0x01900000, 0x01A00000, 0x1000000, 512, 32, 2), None
    middle = find_middle_nand_profile(image)
    if middle is not None:
        if (getattr(config, "chipset", None) != "MSM5500" or getattr(config, "flash_size", None) != 0x800000 or getattr(config, "load_address", None) != 0 or
            getattr(config, "ram_base", None) != 0x01000000 or getattr(config, "ram_size", None) != 0x800000 or getattr(config, "upper_flash_address", None) is
            not None):
            return None, "middle-aperture-mapping-conflict"
        if tuple(getattr(config, name, None) for name in ("nand_data_size", "nand_page_size", "nand_pages_per_block", "nand_bus_width")) != (0x1000000, 512, 32,
            2):
            return None, "middle-main-geometry-conflict"
        return (0x01800000, 0x01900000, 0x01A00000, 0x1000000, 512, 32, 2), None
    if getattr(config, "upper_flash_address", None) is not None:
        return None, "upper-nor-conflict"
    geometry = tuple(getattr(config, name, None) for name in ("nand_data_size", "nand_page_size", "nand_pages_per_block", "nand_bus_width",))
    if geometry != (0x800000, 0x200, 0x20, 2):
        return None, "unsupported-main-geometry"
    sites: list[int] = []
    start = 0
    while True:
        site = image.find(RAW_NAND_STATUS_SIGNATURE, start)
        if site < 0:
            break
        reset = site + 0x30
        if (image[reset:reset + len(RAW_NAND_RESET_SIGNATURE)] == RAW_NAND_RESET_SIGNATURE and bytes.fromhex("29210905") in image[site:site + 0x100]):
            sites.append(site)
        start = site + 2
    status_reset_shape = (bool(sites) and image.count(RAW_NAND_RESET_SIGNATURE) >= 2)
    page_shape = image.count(RAW_NAND_PAGE_SIGNATURE) >= 2
    block_shape = False
    block_at = 0
    while (block_at := image.find(RAW_NAND_BLOCK_PREFIX, block_at)) >= 0:
        if (not block_at & 1 and image[block_at + 10:block_at + 10 + len(RAW_NAND_BLOCK_SUFFIX)] == RAW_NAND_BLOCK_SUFFIX):
            block_shape = True
            break
        block_at += 1
    x16 = image.find(RAW_NAND_X16_PREFIX)
    x16_shape = (x16 >= 0 and RAW_NAND_X16_TRANSFER in image[x16 + 4:x16 + 20])
    if status_reset_shape and page_shape and block_shape and x16_shape:
        return (0x02800000, 0x02900000, 0x02A00000, 0x800000, 0x200, 0x20, 2), None
    low_port_shape = (getattr(config, "flash_size", None) == 0x800000 and find_low_port_nand_driver(image))
    if low_port_shape:
        return (0x00800000, 0x00900000, 0x00A00000, 0x800000, 0x200, 0x20, 2), None
    if not status_reset_shape:
        return None, "incomplete-status-reset-shape"
    return None, "incomplete-main-geometry-shape"

def qemu_spi_nv_properties(config: object, image: bytes, *, input_claimed: bool = False, eeprom_claimed: bool = False):
    profile, reason = _boot_storage_profile(config, image, "spi_nv_profile", find_spi_nv_profile)
    if profile is None:
        return None, reason
    if (input_claimed or eeprom_claimed or getattr(config, "key_register", None) is not None):
        return None, "spi-nv-gpio-owner-unclosed"
    status = getattr(config, "board_status_input", None)
    if status is not None and 0x03000660 <= status.address < 0x03000680:
        return None, "spi-nv-status-owner-conflict"
    spans = ((profile["descriptor_address"], 6), (profile["shadow_address"] - 2, 8), (profile["cache_address"], profile["cache_size"]))
    if any(not config.ram_base <= start <= config.ram_base + config.ram_size - size for start, size in spans):
        return None, "spi-nv-source-state-outside-ram"
    reserved = getattr(config, "ram_bootstrap_profile", None)
    if isinstance(reserved, dict):
        begin = reserved.get("reserved_base")
        size = reserved.get("reserved_size")
        if (type(begin) is int and type(size) is int and any(start < begin + size and start + length > begin for start, length in spans)):
            return None, "spi-nv-source-state-in-reserved-span"
    # shortcut: virtual 5ms policy; replace only after physical timing is measured.
    return ("experimental-spi-nv-write-ns=5000000,"
            f"spi-nv-source-geometry={profile['descriptor_address']:x}"), None

def qemu_amd_bank_profile(original: bytes, loaded: bytes, config: object, *, nor_claimed: bool = False) -> tuple[dict | None, str | None]:
    """Bind a bounded bank to the actual loaded immutable producer graph."""
    from msm5xxx_emulator.detection.devices.storage.amd_bank import find_amd_bank_profile
    from msm5xxx_emulator.detection.devices.storage.fixed_ram_amd import find_fixed_ram_amd_profile
    limit = _source_class_limit(original, config)
    if (limit is not None and limit < config.flash_size and not nor_claimed and config.load_address == 0 and len (loaded) >= limit):
        args_fixed = (config.flash_size, config.ram_base, config.ram_size)
        fixed = find_fixed_ram_amd_profile(original[:limit], *args_fixed)
        if fixed is not None and fixed == find_fixed_ram_amd_profile(loaded[:limit], *args_fixed):
            return fixed, None
    if limit is None or limit != config.flash_size or len(loaded) != limit:
        return None, "amd-bank-source-layout-unverified"
    args = (config.load_address, config.flash_size, config.ram_base, config.ram_size)
    from msm5xxx_emulator.detection.devices.storage.efs_nor import find_inline_efs_nor_profile
    profile, reason = find_amd_bank_profile(original[:limit], *args)
    inline, inline_reason = find_inline_efs_nor_profile(original[:limit], *args)
    if profile is not None and inline is not None:
        return None, "amd-bank-inline-efs-owner-conflict"
    finder = find_amd_bank_profile
    if inline is not None or inline_reason is not None:
        if profile is not None:
            return None, "amd-bank-inline-efs-candidate-conflict"
        profile, reason, finder = inline, inline_reason, find_inline_efs_nor_profile
    if profile is None and not nor_claimed and config.load_address == 0:
        args_fixed = (config.flash_size, config.ram_base, config.ram_size)
        fixed = find_fixed_ram_amd_profile(original[:limit], *args_fixed)
        if fixed is not None and fixed == find_fixed_ram_amd_profile(loaded, *args_fixed):
            return fixed, None
    if profile is None:
        return None, reason
    if nor_claimed:
        return None, "amd-bank-owner-conflict"
    try:
        if (profile['signature'] not in ('thumb-copy-selected-amd-x16-bank-v1', 'inline-copy-selected-efs-amd-x16-v1') or profile['admission'] !=
            'temporary-evidence-gated'):
            return None, "amd-bank-contract-unclosed"
        base, size, sector = (profile[k] for k in ('base', 'size', 'sector_size'))
        if (any(type(profile[k]) is not int for k in ('base', 'size', 'sector_size', 'backing_size', 'id0', 'id1')) or not 0 < base < base + size <= limit or
            sector < 0x1000 or sector & (sector - 1) or base % sector or size % sector or profile['backing_size'] != 1 << (size - 1).bit_length() or not 0 <=
            profile['id0'] <= 0xffff or not 0 <= profile['id1'] <= 0xffff):
            return None, "amd-bank-geometry-unclosed"
        guards = profile['guard_intervals']
        if not qemu_loaded_source_matches({'code_intervals': guards}, original, loaded):
            return None, "amd-bank-loaded-source-mismatch"
        if any(max(start, base) < min(end, base + size) for start, end in guards):
            return None, "amd-bank-source-overlaps-array"
        current, _ = finder(loaded, *args)
        if current != profile:
            return None, "amd-bank-loaded-contract-mismatch"
    except (KeyError, TypeError, ValueError):
        return None, "amd-bank-contract-unclosed"
    return profile, None

def qemu_protected_nor_properties(image: bytes, config: object, profile: dict | None, *, nor_claimed: bool = False) -> tuple[str | None, str | None]:
    if profile is None:
        return None, None
    limit = _source_class_limit(image, config)
    if limit is None:
        return None, "protected-nor-source-layout-unverified"
    if nor_claimed:
        return None, "protected-nor-existing-owner-retained"
    if (not isinstance(profile, dict) or not fields_match(profile, (('signature', 'arm-thumb-copy-selected-protected-nor-x16-v1'), ('admission',
        'temporary-evidence-gated'), ('bus_width', 2), ('initial_base', 0)))):
        return None, "protected-nor-contract-unclosed"
    try:
        base, size, sectors = profile["address"], profile["size"], profile["sector_sizes"]
        if (any(type(v) is not int for v in (base, size)) or base & 255 or size <= 0 or not 0 <= base < base + size <= limit or not isinstance(sectors, (tuple,
            list)) or not 0 < len(sectors) <= 42 or any(type(v) is not int or v <= 0 or v & 255 for v in sectors) or len(set(sectors)) != 1 or sum(sectors) !=
            size):
            return None, "protected-nor-geometry-unclosed"
        rb, rs = config.ram_base, config.ram_size
        obj, global_, selected, state = (profile[k] for k in ("selected_object", "object_global", "selection_cell", "state_global"))
        probe = profile["discarded_probe"];pram, prom = probe["address"], probe["source"]
        fields = [global_, obj, selected, state, pram, prom]
        if (any(type(v) is not int or not 0 <= v <= 0xffffffff for v in fields) or any(v & 3 for v in (global_, obj, selected, state)) or (pram | prom) & 1 or
            probe.get("size") != 20 or type(rb) is not int or type(rs) is not int or rb < 0 or rs <= 0 or rb + rs > 0x100000000):
            return None, "protected-nor-source-pointers-unclosed"
        for at, length in ((global_, 4), (selected, 4), (state, 12), (pram, 20)):
            if not rb <= at <= rb + rs - length:
                return None, "protected-nor-source-state-outside-ram"
        for at, length in ((obj, 0xd0), (prom, 20)):
            if not 0 <= at <= limit - length or at < base + size and base < at + length:
                return None, "protected-nor-source-ro-owner-conflict"
        guards = profile.get("runtime_guards", {})
        if (not isinstance(guards, dict) or any(guards.get(k) != v for k, v in { "active_object": global_, "expected_object": obj, "selection_cell": selected,
            "expected_selection": obj, "base_address": state, "expected_base": 0, "mode_address": state + 4, "operation_address": state + 8}.items())):
            return None, "protected-nor-runtime-contract-unclosed"
    except (KeyError, TypeError, ValueError, AttributeError):
        return None, "protected-nor-malformed-profile"
    # Deterministic virtual erase policy; the physical part and latency are unverified.
    return (f"experimental-protected-nor={base:x}:{size:x}:{sectors[0]:x}:f4240,"
            "protected-nor-source=" + ":".join(f"{v:x}" for v in fields)), None

def adjacent_amd_x16_flash_ids(config: object, image: bytes) -> tuple[int, int] | None:
    """Admit a closed adjacent GEFS/AMD NOR class."""
    load = getattr(config, "load_address", None)
    primary_size = getattr(config, "flash_size", None)
    base = getattr(config, "secondary_flash_address", None)
    size = getattr(config, "secondary_flash_size", None)
    ram_base = getattr(config, "ram_base", None)
    identity = getattr(config, "flash_id_value", None)
    if (any(type(value) is not int for value in (load, primary_size, base, size, ram_base, identity,)) or size != 0x800000 or base != load + primary_size or
        base + size != ram_base or identity != flash_id_for_size(size)):
        return None
    native = (getattr(config, "chipset", None) == "MSM5500" and b"fsd_amd.c\0" in image and b"\x0b$USER_DIRS\0" in image)
    exact = (getattr(config, "chipset", None) == "MSM5100" and find_adjacent_amd_x16_nor(image[:primary_size], primary_size,) == (base, size, identity & 0xFFFF,
        identity >> 16))
    if not native and not exact:
        return None
    return identity & 0xFFFF, identity >> 16 & 0xFFFF

def select_primary_x16_nor_profile(legacy: tuple[int, int, int, int, int] | None, probe: tuple[int, int, tuple[tuple[int, int], ...], int, int,] | None,) -> tuple[tuple[int,
    int, int, int, int] | None, tuple[tuple[int, int], ...] | None, str | None,]:
    """Prefer exact probe geometry only when detectors agree."""
    if probe is None:
        return legacy, None, None
    base, size, regions, id0, id1 = probe
    profile = base, size, regions[0][1], id0, id1
    if legacy is not None:
        legacy_base, legacy_size, sector_size, legacy_id0, legacy_id1 = legacy
        if ((legacy_base, legacy_size, legacy_id0, legacy_id1) != (base, size, id0, id1) or regions != ((size // sector_size, sector_size),)):
            return None, None, "detector-conflict"
    return profile, regions, None

def qemu_legacy_nv_nor_profile(image: bytes, config: object, *, claimed: bool = False,) -> tuple[str, tuple[int, ...]] | None:
    """Select one source-closed missing NV bank without displacing an owner."""
    capability = select_legacy_nv_nor(image, config, claimed=claimed)
    return legacy_nv_tuple(capability)

# Required evidence providers are bound by registry discovery.
REQUIRES = {'find_table7_matrix': ('input.table7', 'find_table7_matrix')}
