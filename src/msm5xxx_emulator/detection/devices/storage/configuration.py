"""Storage-owned state identity and NOR configuration selection."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .rules import find_fujitsu_x16_bulk_write, flash_id_for_size
from msm5xxx_emulator.detection.layout_queries import plausible_ram_seed_size
from .upper_nor import UPPER_FLASH_ADDRESS, UPPER_FLASH_SIZE, find_upper_nor

DEFAULT_STATE_ROOT = Path(os.environ.get("MSM5XXX_STATE_DIR", Path.home() / ".msm5xxx-emulator")).expanduser()

def configuration_fields(layout, drivers, storage):
    return {'flash_size': storage.flash_size, 'secondary_flash_address': layout.requested_load_address + storage.flash_size if layout.compound_fujitsu else
        storage.adjacent[0] if storage.adjacent else None, 'secondary_flash_size': storage.compound_secondary_size or storage.adjacent_secondary_size or storage.flash_size,
        'secondary_flash_image': None, 'secondary_flash_image_offset': storage.compound_secondary_offset, 'secondary_flash_state': storage.default_secondary_state,
        'secondary_flash_read_address': storage.secondary_flash_read_address, 'secondary_flash_write_address': storage.secondary_flash_write_address,
        'legacy_efs_page_read_address': storage.legacy_efs_page_read_address, 'ram_image_offset': storage.compound_secondary_offset + storage.compound_secondary_size
        if storage.compound_secondary_offset is not None and storage.compound_secondary_size is not None else storage.flash_size, 'ram_image_size': 0 if layout.compound_fujitsu
        else plausible_ram_seed_size(len(layout.image), storage.flash_size), 'nand_bad_block_address': storage.nand_bad_block_address, 'nand_read_address':
        storage.nand_read_address, 'nand_write_address': storage.nand_write_address, 'nand_enabled': storage.nand_enabled, 'native_nand_profile': storage.native_nand_profile,
        'nand_image': None, 'nand_data_size': 33554432 if storage.native_nand_profile is not None or storage.guarded_nand is not None else 16777216 if storage.nand_bad_block_address
        is not None or storage.direct_middle_nand is not None else 8388608, 'nand_page_size': 512, 'nand_spare_size': 16, 'nand_pages_per_block': 32,
        'nand_bus_width': 2, 'flash_id_address': storage.flash_id_address, 'flash_id_value': storage.descriptor_flash_id if storage.descriptor_flash_id is not
        None else storage.adjacent_amd[2] | storage.adjacent_amd[3] << 16 if storage.adjacent_amd is not None else flash_id_for_size(storage.flash_size) if
        storage.flash_id_address is not None else None, 'primary_flash_probe_address': storage.primary_flash_probe_address, 'flash_state': storage.default_flash_state,
        'spi_nv_profile': drivers.spi_nv_profile}

def _file_identity(filename: str | None) -> str:
    if not filename:
        return ""
    digest = hashlib.sha256()
    try:
        with Path(filename).expanduser().open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        # Construction reports the useful missing/unreadable-file error.  A
        # stable path token still prevents it aliasing an unrelated seed.
        digest.update(str(Path(filename).expanduser()).encode("utf-8"))
    return digest.hexdigest()[:16]

def default_state_paths(path: Path, image: bytes, flash_size: int, secondary_size: int, secondary_image: str | None = None, nand_image: str | None = None,
    nand_geometry: tuple[int, int, int, int, int] | None = None, secondary_generated_efs: bool = False, secondary_seed: bytes | None = None,) -> tuple[str, str]:
    identity = hashlib.sha256(image[:flash_size]).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", path.stem)[:48] or "firmware"
    seed_identity = _file_identity(secondary_image)
    internal_seed_identity = (hashlib.sha256(secondary_seed).hexdigest()[:16] if secondary_seed is not None else "")
    nand_identity = _file_identity(nand_image)
    suffix = ((f"-s{seed_identity}" if seed_identity else "")
              + (f"-si{internal_seed_identity}"
                 if internal_seed_identity and not seed_identity else "")
              + ("-sefs" if secondary_generated_efs and not seed_identity else "")
              + (f"-n{nand_identity}" if nand_identity else "")
              + ("-g" + "-".join(f"{value:x}" for value in nand_geometry)
                 if nand_geometry else ""))
    base = (DEFAULT_STATE_ROOT / "firmware"
            / f"{stem}-{identity}-{flash_size:x}{suffix}")
    return f"{base}.flash.json", f"{base}.efs-{secondary_size:x}.json"

def infer_secondary_nor(config, image: bytes, overrides, descriptor_flash_id: int | None = None) -> None:
    # These MSM5500 boards use a second AMD NOR for EFS/NV between boot ROM
    # and SDRAM.  It is not a mirror of the firmware chip.
    secondary_nor_detected = (config.flash_id_address is not None and config.secondary_flash_read_address is not None and b"fsd_amd.c\0" in image and
        b"\x0b$USER_DIRS\0" in image and bytes.fromhex("0120c0052060") in image and config.flash_size == 0x800000)
    # The wrapper signatures above are useful when present, but several
    # otherwise identical MSM5500 builds inline their AMD routines.  The
    # physical layout and filesystem fingerprints are independent evidence:
    # an 8 MiB program NOR, another 8 MiB slot before SDRAM, the AMD driver,
    # and a GEFS root marker.  This covers the E110/V-series family without
    # treating an arbitrary partial image as a second flash chip.
    family_secondary_nor_detected = (config.chipset == "MSM5500" and config.flash_size == config.secondary_flash_size == 0x800000 and config.ram_base - (config.load_address
        + config.flash_size) == config.secondary_flash_size and b"fsd_amd.c\0" in image and b"\x0b$USER_DIRS\0" in image)
    legacy_secondary_nor_detected = (config.legacy_efs_page_read_address is not None and config.secondary_flash_read_address is not None and config.secondary_flash_write_address
        is not None and config.chipset == "MSM5500" and config.flash_size == 0x800000)
    fujitsu_secondary_nor_detected = (config.secondary_flash_write_address is not None and find_fujitsu_x16_bulk_write(image, config.load_address + config.flash_size)
        is not None)
    if (config.secondary_flash_address is None and (secondary_nor_detected or legacy_secondary_nor_detected or family_secondary_nor_detected or
        fujitsu_secondary_nor_detected) and config.ram_base - (config.load_address + config.flash_size) == config.secondary_flash_size):
        config.secondary_flash_address = config.load_address + config.flash_size
        if family_secondary_nor_detected and not (secondary_nor_detected or legacy_secondary_nor_detected):
            config.detection_notes.append("secondary AMD NOR inferred from MSM5500 8+8 MiB layout and GEFS driver")
    if (config.flash_id_address is not None and descriptor_flash_id is None and (overrides is None or getattr(overrides, "flash_id_value", None) is None)):
        detected_size = (config.secondary_flash_size if config.secondary_flash_address not in (None, 0) else config.flash_size)
        config.flash_id_value = flash_id_for_size(detected_size)

def configure_state_paths(config, path: Path, image: bytes, overrides) -> bytes | None:
    internal_secondary_seed = None
    if (config.secondary_flash_image_offset is not None and not config.secondary_flash_image):
        start = config.secondary_flash_image_offset
        end = start + config.secondary_flash_size
        if 0 <= start < end <= len(image):
            internal_secondary_seed = image[start:end]
    state_flash, state_secondary = default_state_paths(path, image, config.flash_size, config.secondary_flash_size, config.secondary_flash_image, config.nand_image,
        ((config.nand_data_size, config.nand_page_size, config.nand_spare_size, config.nand_pages_per_block, config.nand_bus_width) if config.nand_enabled else
        None), (config.secondary_flash_address not in (None, 0) and not config.secondary_flash_image and config.secondary_flash_image_offset is None and
        b"\x0b$USER_DIRS\0" in image), secondary_seed=internal_secondary_seed,)
    if overrides is None or getattr(overrides, "flash_state", None) is None:
        config.flash_state = state_flash
    if overrides is None or getattr(overrides, "secondary_flash_state", None) is None:
        config.secondary_flash_state = state_secondary
    return internal_secondary_seed

def infer_upper_nor(config, image: bytes) -> None:
    admitted, reason = find_upper_nor(image)
    if admitted:
        config.upper_flash_address = UPPER_FLASH_ADDRESS
        config.upper_flash_size = UPPER_FLASH_SIZE
        state = Path(config.flash_state)
        config.upper_flash_state = str(state.with_name(state.stem + ".upper-02800000-800000.json"))
        config.detection_notes.append("upper NOR admitted by relocatable catalog/materializer/AMD writer grammar")
    else:
        config.detection_notes.append(f"upper NOR detector rejected at {reason}")

def apply_image_overrides(config, overrides):
    if getattr(overrides, "nand_enabled", None) is None and config.nand_image:
        config.nand_enabled = True
    if (getattr(overrides, "secondary_flash_image", None) is not None and getattr(overrides, "secondary_flash_image_offset", None) is None):
        config.secondary_flash_image_offset = None

from .boot_rules import MAX_FLASH_SIZE
from msm5xxx_emulator.detection.image_view import ADDRESS_SPACE
from msm5xxx_emulator.detection.layout_queries import normalised_flash_size

def apply_geometry_overrides(config, overrides, image, compound_fujitsu, required_flash_extent, descriptor_flash_id):
    if getattr(overrides, "flash_size", None) is None:
        limit = (config.ram_base - config.load_address if config.ram_base > config.load_address else min(MAX_FLASH_SIZE, ADDRESS_SPACE - config.load_address))
        config.flash_size = (compound_fujitsu[0] if compound_fujitsu else normalised_flash_size(max(len(image), required_flash_extent), limit))
    if getattr(overrides, "secondary_flash_size", None) is None:
        config.secondary_flash_size = (compound_fujitsu[1] if compound_fujitsu else config.flash_size)
    if getattr(overrides, "ram_image_offset", None) is None:
        config.ram_image_offset = (config.secondary_flash_image_offset + config.secondary_flash_size if config.secondary_flash_image_offset is not None else
            config.flash_size)
    if getattr(overrides, "ram_image_size", None) is None:
        config.ram_image_size = plausible_ram_seed_size(len(image), config.ram_image_offset, config.ram_size)
    if config.secondary_flash_address in (None, 0):
        config.secondary_flash_image_offset = None
    if (getattr(overrides, "flash_id_value", None) is None and config.flash_id_address is not None):
        config.flash_id_value = (descriptor_flash_id if descriptor_flash_id is not None else flash_id_for_size(config.flash_size))
