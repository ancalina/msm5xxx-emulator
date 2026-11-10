"""Domain-owned final configuration and source admission."""
from __future__ import annotations
from msm5xxx_emulator.detection.layout_queries import find_missing_overlays, find_runtime_overlays

from .rules import primary_probe_x16_nor_profile
from .efs_nor import find_inline_efs_nor_profile
from msm5xxx_emulator.detection.layout_queries import plausible_ram_seed_size

def note_native_nand(config, storage):
    if storage.native_nand_profile is not None:
        config.detection_notes.append("temporary reset-linked x16 NAND: 512+16 transfer bytes, " "32 pages/block; virtual row envelope and timing, unknown ID; "
            "original NAND/OOB resources are not recovered")

def extend_primary_span(config, layout):
    if layout.requested_flash_size is None:
        probe_profile, _probe_reject = primary_probe_x16_nor_profile(layout.image, config.primary_flash_probe_address, config.load_address, config.flash_size, 0,
            config.ram_base, config.ram_image_offset, config.ram_image_size, config.ram_size,)
        if probe_profile is not None:
            tail_base, tail_size, _regions, _id0, _id1 = probe_profile
            physical_flash_size = tail_base + tail_size
            if physical_flash_size > config.flash_size:
                config.flash_size = physical_flash_size
                if (config.secondary_flash_address is None and (layout.overrides is None or getattr(layout.overrides, "secondary_flash_size", None) is None)):
                    config.secondary_flash_size = physical_flash_size
                if (layout.overrides is None or getattr(layout.overrides, "ram_image_offset", None) is None):
                    config.ram_image_offset = physical_flash_size
                if layout.overrides is None or getattr(layout.overrides, "ram_image_size", None) is None:
                    config.ram_image_size = plausible_ram_seed_size(len(layout.image), physical_flash_size, config.ram_size)
                config.detection_notes.append("descriptor-linked x16 NOR extends partial primary physical span")

def note_inline_source(config, layout):
    inline_efs, inline_efs_reason = find_inline_efs_nor_profile(layout.image[:config.flash_size], config.load_address, config.flash_size, config.ram_base,
        config.ram_size,)
    if inline_efs is not None:
        config.detection_notes.append(
            "inline EFS AMD x16 NOR admitted from reset-owned copy, RAM selection, "
            f"descriptor/callback/DQ6 linkage: {inline_efs['base']:x}:"
            f"{inline_efs['size']:x}:{inline_efs['sector_size']:x}:"
            f"{inline_efs['id0']:x}:{inline_efs['id1']:x}"
        )
    elif inline_efs_reason is not None:
        config.detection_notes.append(f"inline EFS NOR detector rejected: {inline_efs_reason}")

def finalize_dump_status(config: FirmwareConfig, image: bytes, internal_secondary_seed: bytes | None) -> None:
    missing = max(0, config.flash_size - len(image))
    trailer = max(0, len(image) - config.flash_size)
    config.missing_overlays = find_missing_overlays(image, config.flash_size, config.load_address)
    config.runtime_overlays = find_runtime_overlays(image, config.ram_base, config.ram_size)
    if config.runtime_overlays:
        config.detection_notes.append(
            f"{len(config.runtime_overlays)} internal-RAM overlay candidate(s) "
            "use SDRAM source; runtime provenance required before "
            "partition-load inference"
        )
    if internal_secondary_seed is not None:
        config.dump_status = (
            f"complete compound NOR image; primary 0x{config.flash_size:X} + "
            f"secondary 0x{config.secondary_flash_size:X}"
        )
        config.detection_notes.append("Fujitsu x16 command bus and GEFS records prove internal " "secondary NOR image")
    elif missing:
        config.dump_status = f"partial NOR; padded 0x{missing:X} erased bytes"
        config.detection_notes.append(
            f"dump is 0x{missing:X} bytes shorter than inferred NOR capacity"
        )
        for overlay in config.missing_overlays:
            config.detection_notes.append(
                "missing executable overlay source "
                f"0x{overlay.source:X}..0x{overlay.source + overlay.size:X}"
            )
    elif trailer:
        if config.ram_image_size:
            config.dump_status = f"full NOR + 0x{trailer:X} RAM snapshot"
        else:
            config.dump_status = f"full NOR + 0x{trailer:X} small trailer"
    else:
        config.dump_status = "complete NOR image"
