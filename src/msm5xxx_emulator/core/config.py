"""Configuration and memory-layout data shared by detection and runtime."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class LinkerLayout:
    table_offset: int
    data_source: int
    data_target: int
    data_size: int
    bss_target: int
    bss_size: int


@dataclass(slots=True)
class CopyLayout:
    table_offset: int
    source: int
    target: int
    size: int


@dataclass(frozen=True, slots=True)
class BoardStatusInput:
    """One firmware-proven board-status byte with its default asserted bit."""
    address: int
    mask: int
    default: int


@dataclass(slots=True)
class FirmwareConfig:
    path: str
    file_size: int
    firmware_sha256: str
    model: str
    chipset: str
    chipset_confidence: str
    image_kind: str
    dump_status: str
    detection_notes: list[str]
    width: int
    height: int
    framebuffer_address: int | None
    framebuffer_stride: int
    framebuffer_format: str
    framebuffer_flush_address: int | None
    framebuffer_rect_flush_address: int | None
    board_revision: str
    board_revision_register: int | None
    board_revision_value: int | None
    board_status_input: BoardStatusInput | None
    image_offset: int
    load_address: int
    flash_size: int
    secondary_flash_address: int | None
    secondary_flash_size: int
    secondary_flash_image: str | None
    secondary_flash_image_offset: int | None
    secondary_flash_state: str
    secondary_flash_read_address: int | None
    secondary_flash_write_address: int | None
    legacy_efs_page_read_address: int | None
    eeprom_read_address: int | None
    eeprom_write_address: int | None
    eeprom_geometry_address: int | None
    ram_base: int
    ram_size: int
    ram_image_offset: int
    ram_image_size: int
    entry: int
    key_register: int | None
    key_active_low: bool
    audio_play_address: int | None
    ma2_silent_boot_address: int | None
    fast_boot_address: int | None
    nand_bad_block_address: int | None
    nand_read_address: int | None
    nand_write_address: int | None
    delay_address: int | None
    busy_delay_address: int | None
    nand_enabled: bool
    nand_image: str | None
    nand_data_size: int
    nand_page_size: int
    nand_spare_size: int
    nand_pages_per_block: int
    nand_bus_width: int
    rex_idle_address: int | None
    rex_tick_address: int | None
    rex_irq_wrapper_address: int | None
    rex_irq_handler_address: int | None
    rex_irq_handler_slot: int | None
    rex_irq_callback_slot: int | None
    rex_irq_status_address: int | None
    rex_irq_enable_address: int | None
    rex_irq_arm_address: int | None
    rex_irq_mask: int
    rex_tick_ms: int
    board_adc_address: int | None
    board_adc_reader_address: int | None
    board_adc_value: int
    flash_id_address: int | None
    flash_id_value: int | None
    crc16_address: int | None
    dmd_download_address: int | None
    primary_flash_probe_address: int | None
    memory_clear_addresses: list[int]
    memory_copy_addresses: list[int]
    register_ramp_addresses: list[int]
    arm_memory_copy_addresses: list[int]
    flash_state: str
    linker: LinkerLayout | None
    overlays: list[CopyLayout]
    missing_overlays: list[CopyLayout]
    runtime_overlays: list[CopyLayout]
    verified_model: str | None = None
    guest_owned_status_72c: bool = False

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["file_size_hex"] = f"0x{self.file_size:X}"
        return result

    def firmware_identity(self) -> dict[str, object]:
        basename = self.path.replace("\\", "/").rsplit("/", 1)[-1] or "firmware"
        return {"basename": basename, "bytes": self.file_size,
                "sha256": self.firmware_sha256}

    def diagnostic_config(self) -> dict[str, object]:
        result = self.to_dict()
        for field in ("path", "flash_state", "secondary_flash_image",
                      "secondary_flash_state", "nand_image"):
            result.pop(field, None)
        result["firmware"] = self.firmware_identity()
        return result
