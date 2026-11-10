from __future__ import annotations
import os
from pathlib import Path
from msm5xxx_emulator.detection.registry import device_domain

from msm5xxx_emulator.detection.image_view import ADDRESS_SPACE
DISABLEABLE_ADDRESS_FIELDS = frozenset({ "delay_address", "busy_delay_address", "secondary_flash_read_address", "secondary_flash_write_address",
    "legacy_efs_page_read_address", "eeprom_read_address", "eeprom_write_address", "eeprom_geometry_address", "nand_bad_block_address", "nand_read_address",
    "nand_write_address", "rex_idle_address", "rex_tick_address", "rex_irq_wrapper_address", "board_adc_address", "flash_id_address", "crc16_address",
    "dmd_download_address", "primary_flash_probe_address", "board_revision_register", "framebuffer_address", "framebuffer_flush_address",
    "framebuffer_rect_flush_address", })

def _apply_overrides(config: FirmwareConfig, overrides: argparse.Namespace, *, image: bytes, primary_image: bytes, compound_fujitsu: tuple[int, int] | None,
    required_flash_extent: int, auto_relative: set[str], clear_layout: list[tuple[int | None, bool]], copy_layout: list[tuple[int | None, bool]], ramp_layout:
    list[tuple[int | None, bool]], descriptor_flash_id: int | None = None) -> None:
    from . import DISABLEABLE_ADDRESS_FIELDS
    for key in ("model", "chipset", "width", "height", "framebuffer_address", "framebuffer_stride", "framebuffer_format", "framebuffer_flush_address",
        "framebuffer_rect_flush_address", "board_revision", "board_revision_register", "board_revision_value", "image_offset", "load_address", "flash_size",
        "secondary_flash_address", "secondary_flash_size", "secondary_flash_image", "secondary_flash_image_offset", "secondary_flash_state",
        "secondary_flash_read_address", "secondary_flash_write_address", "legacy_efs_page_read_address", "eeprom_read_address", "eeprom_write_address",
        "eeprom_geometry_address", "ram_base", "ram_size", "ram_image_offset", "ram_image_size", "entry", "key_register", "key_active_low", "audio_play_address",
        "fast_boot_address", "delay_address", "busy_delay_address", "nand_bad_block_address", "nand_read_address", "nand_write_address", "nand_enabled",
        "nand_image", "nand_data_size", "nand_page_size", "nand_spare_size", "nand_pages_per_block", "nand_bus_width", "rex_idle_address", "rex_tick_address",
        "rex_irq_wrapper_address", "rex_irq_arm_address", "rex_tick_ms", "rex_static_controller_experimental", "board_adc_address", "board_adc_value",
        "flash_id_address", "flash_id_value", "crc16_address", "dmd_download_address", "primary_flash_probe_address", "flash_state"):
        value = getattr(overrides, key, None)
        if value is not None:
            setattr(config, key, value)
    device_domain('display.configuration').apply_overrides(config, overrides)
    for field in DISABLEABLE_ADDRESS_FIELDS:
        if getattr(overrides, field, None) == 0:
            setattr(config, field, None)
    device_domain('storage.configuration').apply_image_overrides(config, overrides)
    device_domain('boot.configuration').apply_revision_override(config)
    device_domain('memory.configuration').apply_overrides(config, overrides, primary_image)
    device_domain('storage.configuration').apply_geometry_overrides(config, overrides, image, compound_fujitsu, required_flash_extent, descriptor_flash_id)
    if config.load_address:
        for field in auto_relative:
            if getattr(overrides, field, None) is None:
                address = getattr(config, field)
                if address is not None:
                    setattr(config, field, config.load_address + address)
        device_domain('memory.configuration').relocate_operations(config, clear_layout, copy_layout, ramp_layout)

def _scan_layout(path, overrides):
    from . import ADDRESS_SPACE, LayoutCapture, _embedded_model_scores, _verified_embedded_model, bind_facts, chipset_confidence, detect_chipset, detect_model, find_arm_vector_offset, find_linker_layout, load_firmware_image, restore_sparse_nor_gap
    loaded = load_firmware_image(path)
    raw = loaded.image
    requested_image_offset = (getattr(overrides, "image_offset", None) if overrides else None)
    vector_offset, vector_score = find_arm_vector_offset(raw)
    image_offset = (vector_offset if requested_image_offset is None and vector_score >= 4 else requested_image_offset or 0)
    if not 0 <= image_offset < len(raw):
        raise ValueError(f"image offset outside firmware: 0x{image_offset:X}")
    # Keep the complete capture for metadata and resource discovery.
    # Code/layout discovery inspects only the primary supplied region:
    # full dumps commonly append a live RAM snapshot containing copied code.
    image, sparse_gap = restore_sparse_nor_gap(raw[image_offset:])
    supplied = getattr(loaded, 'image_view', None)
    if supplied is not None:
        bind_facts(image, supplied.normalized(image_offset, size=len(image), gap=sparse_gap))
    requested_load_address = (getattr(overrides, "load_address", None) if overrides else None)
    requested_load_address = 0 if requested_load_address is None else requested_load_address
    if not 0 <= requested_load_address < ADDRESS_SPACE:
        raise ValueError("load address outside 32-bit address space")
    model_scores = _embedded_model_scores(image)
    chipset = detect_chipset(image, "")
    detection_notes: list[str] = []
    model = detect_model(image, path, model_scores, chipset, notes=detection_notes)
    verified_model = _verified_embedded_model(image, model_scores)
    if verified_model != model:
        verified_model = None
    override_model = (getattr(overrides, "model", None) if overrides else None)
    if override_model is not None and (not isinstance(override_model, str) or not override_model.strip()):
        raise ValueError("model override must not be empty")
    confidence = chipset_confidence(image, chipset)
    image_kind = device_domain('boot.capture').classify_image(image, image_offset, requested_image_offset, detection_notes)
    if sparse_gap is not None:
        gap_offset, gap_size = sparse_gap
        detection_notes.append(
            f"restored 0x{gap_size:X}-byte erased sparse NOR gap at "
            f"0x{gap_offset:X} from boot-table and vector references"
        )
    device_domain('identity.configuration').note_support(chipset, confidence, detection_notes)
    scan_chipset = ((getattr(overrides, "chipset", None) if overrides else None) or chipset)
    requested_ram_base = (getattr(overrides, "ram_base", None) if overrides else None)
    scan_ram_base = device_domain('memory.configuration').scan_base(scan_chipset, requested_ram_base)
    requested_flash_size = (getattr(overrides, "flash_size", None) if overrides else None)
    compound_fujitsu, required_flash_extent, scan_flash_size = device_domain('storage.capture').capture_primary_extent(image, requested_load_address,
        requested_flash_size, scan_ram_base, detection_notes)
    primary_image = image[:min(len(image), scan_flash_size)]
    if supplied is not None:
        bind_facts(primary_image, supplied.normalized(image_offset, size=len(primary_image), gap=sparse_gap))
    linker = find_linker_layout(primary_image, requested_load_address)
    requested_ram_size = (getattr(overrides, 'ram_size', None) if overrides else None)
    ram_base, ram_size, ram_bootstrap_profile, primary_image = device_domain('memory.capture').capture_layout(primary_image, linker, chipset,
        requested_load_address, requested_ram_base, requested_ram_size, image_kind, detection_notes)
    return LayoutCapture(path=path, overrides=overrides, chipset=chipset, compound_fujitsu=compound_fujitsu, confidence=confidence, detection_notes=detection_notes,
        image=image, image_kind=image_kind, image_offset=image_offset, linker=linker, loaded=loaded, model=model, override_model=override_model, primary_image=primary_image,
        ram_base=ram_base, ram_bootstrap_profile=ram_bootstrap_profile, ram_size=ram_size, requested_flash_size=requested_flash_size, requested_load_address=requested_load_address,
        required_flash_extent=required_flash_extent, scan_chipset=scan_chipset, scan_flash_size=scan_flash_size, verified_model=verified_model)

REQUIRES = {'detect_model': ('identity.model', 'detect_model'), 'embedded_model_scores': ('identity.model', 'embedded_model_scores'), 'verified_embedded_model':
    ('identity.model', 'verified_embedded_model'), '_embedded_model_scores': ('identity.model', 'embedded_model_scores'), '_verified_embedded_model': ('identity.model',
    'verified_embedded_model')}
