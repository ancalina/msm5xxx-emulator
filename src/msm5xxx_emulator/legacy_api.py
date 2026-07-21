"""Explicit compatibility API for the legacy ``msm5xxx`` module."""
from __future__ import annotations

from .core.config import BoardStatusInput, CopyLayout, FirmwareConfig, LinkerLayout
from .core.constants import (
    BUILD_CODENAME, FRAMEBUFFER_FORMATS, LCD_MMIO_PRIMARY_COMMAND_SIZE,
    LCD_MMIO_PRIMARY_END, LCD_MMIO_PRIMARY_START, MAX_NAND_BACKING_SIZE,
    MAX_NAND_DATA_SIZE, MAX_RAM_SIZE, PAGE, REX_TICK_INTERVAL,
)
from .core.emulator import GenericMSMEmulator
from .core.errors import HostBackendFault
from .detection.arm import (
    arm_b_target, arm_b_word_target, arm_vector_score, thumb_bl_target,
    thumb_literal_value,
)
from .detection.boot import (
    ARM_MEMORY_CLEAR_CHUNK_SIGNATURE, BOARD_ADC_READER_READ_OFFSET,
    BUSY_DELAY_REGISTER_SIGNATURE, BUSY_DELAY_SIGNATURE,
    DMD_DOWNLOAD_510X_SIGNATURE, OPTIONAL_RAM_CALLER_PATTERN,
    OPTIONAL_RAM_PROBE_SIGNATURE, absent_optional_ram_probe_addresses,
    busy_delay_addresses, find_ma2_silent_boot_wait,
)
from .detection.chipset import chipset_confidence, detect_chipset
from .detection.display import detect_lcd_width_hint, find_framebuffer_layout
from .detection.firmware import (
    DEFAULT_STATE_ROOT, DISABLEABLE_ADDRESS_FIELDS, MAX_FLASH_SIZE,
    _embedded_model_scores, default_state_paths, detect,
)
from .detection.input import (
    BOARD_ADC_READER_DATA_ADDRESS, board_adc_reader_at, detect_input_profile,
    find_board_adc_reader, find_board_status_input,
)
from .detection.memory_layout import (
    aligned, find_arm_memory_copy_addresses, find_arm_vector_offset,
    find_linker_layout, find_missing_overlays,
    find_overlays, find_runtime_overlays, infer_ram_base, interval_gaps,
    normalised_flash_size, plausible_ram_seed_size,
    referenced_flash_extent, restore_sparse_nor_gap,
)
from .detection.model import detect_model
from .detection.rex import (
    REX_5MS_CALLBACK_SIZE, REX_TICK_SIGNATURE, find_rex_5ms_irq_arm,
    find_rex_5ms_irq_route, find_rex_5ms_sleep_timer, find_rex_idle_address,
    find_trampm5_consumer, rex_5ms_callback_at, rex_sleep_call_at,
    rex_timer_advance_at, trampm5_consumer_at,
)
from .detection.signatures import find_all
from .detection.storage import (
    EEPROM_24LC64_CLASS_A_READ_PREFIX, EEPROM_24LC64_CLASS_A_SENTINEL,
    EEPROM_24LC64_CLASS_A_WRITE_PREFIX, EEPROM_24LCXX_READ_SIGNATURE,
    EEPROM_24LCXX_WRITE_PREFIX, EEPROM_24LCXX_X270_INIT_SIGNATURE,
    EEPROM_24LCXX_X270_READ_PREFIX, EEPROM_24LCXX_X270_WRITE_PREFIX,
    EEPROM_24LCXX_X430_INIT_SIGNATURE, EEPROM_24LCXX_X430_READ_PREFIX,
    EEPROM_24LCXX_X430_WRITE_PREFIX, EEPROM_24LCXX_X7700_INIT_SIGNATURE,
    EEPROM_24LCXX_X7700_READ_PREFIX, EEPROM_24LCXX_X7700_WRITE_PREFIX,
    eeprom_24lc64_class_a_write_at, eeprom_24lcxx_write_at,
    find_24lc64_class_a_driver, find_24lcxx_driver,
    find_24lcxx_x270_driver, find_24lcxx_x430_driver,
    find_24lcxx_x7700_driver,
    find_compound_fujitsu_layout, find_fujitsu_x16_bulk_write,
    flash_id_for_size, fujitsu_x16_bulk_write_at, fujitsu_x16_flash_ids,
    qualcomm_efs_seed,
)
from .devices.storage.nor import NORFlash


__all__ = (
    "BoardStatusInput", "CopyLayout", "FirmwareConfig", "LinkerLayout",
    "BUILD_CODENAME", "FRAMEBUFFER_FORMATS", "LCD_MMIO_PRIMARY_COMMAND_SIZE",
    "LCD_MMIO_PRIMARY_END", "LCD_MMIO_PRIMARY_START", "MAX_NAND_BACKING_SIZE",
    "MAX_NAND_DATA_SIZE", "MAX_RAM_SIZE", "PAGE", "REX_TICK_INTERVAL",
    "GenericMSMEmulator", "HostBackendFault", "NORFlash", "aligned",
    "arm_b_target", "arm_b_word_target", "arm_vector_score",
    "thumb_bl_target", "thumb_literal_value", "ARM_MEMORY_CLEAR_CHUNK_SIGNATURE",
    "BOARD_ADC_READER_READ_OFFSET", "BUSY_DELAY_REGISTER_SIGNATURE",
    "BUSY_DELAY_SIGNATURE", "DMD_DOWNLOAD_510X_SIGNATURE",
    "OPTIONAL_RAM_CALLER_PATTERN", "OPTIONAL_RAM_PROBE_SIGNATURE",
    "absent_optional_ram_probe_addresses", "busy_delay_addresses",
    "find_ma2_silent_boot_wait", "chipset_confidence", "detect_chipset",
    "detect_lcd_width_hint", "DEFAULT_STATE_ROOT", "DISABLEABLE_ADDRESS_FIELDS",
    "MAX_FLASH_SIZE", "default_state_paths", "detect",
    "BOARD_ADC_READER_DATA_ADDRESS", "board_adc_reader_at",
    "detect_input_profile", "find_board_adc_reader", "find_board_status_input",
    "find_arm_memory_copy_addresses", "find_arm_vector_offset",
    "find_framebuffer_layout", "find_linker_layout", "find_missing_overlays",
    "find_overlays", "find_runtime_overlays", "infer_ram_base",
    "interval_gaps", "normalised_flash_size", "plausible_ram_seed_size",
    "referenced_flash_extent", "restore_sparse_nor_gap",
    "detect_model", "REX_5MS_CALLBACK_SIZE", "REX_TICK_SIGNATURE",
    "find_rex_5ms_irq_arm", "find_rex_5ms_irq_route",
    "find_rex_5ms_sleep_timer", "find_rex_idle_address",
    "find_trampm5_consumer", "rex_5ms_callback_at", "rex_sleep_call_at",
    "rex_timer_advance_at", "trampm5_consumer_at", "find_all",
    "EEPROM_24LC64_CLASS_A_READ_PREFIX",
    "EEPROM_24LC64_CLASS_A_SENTINEL", "EEPROM_24LC64_CLASS_A_WRITE_PREFIX",
    "EEPROM_24LCXX_READ_SIGNATURE", "EEPROM_24LCXX_WRITE_PREFIX",
    "EEPROM_24LCXX_X270_INIT_SIGNATURE", "EEPROM_24LCXX_X270_READ_PREFIX",
    "EEPROM_24LCXX_X270_WRITE_PREFIX", "EEPROM_24LCXX_X430_INIT_SIGNATURE",
    "EEPROM_24LCXX_X430_READ_PREFIX", "EEPROM_24LCXX_X430_WRITE_PREFIX",
    "EEPROM_24LCXX_X7700_INIT_SIGNATURE", "EEPROM_24LCXX_X7700_READ_PREFIX",
    "EEPROM_24LCXX_X7700_WRITE_PREFIX", "eeprom_24lc64_class_a_write_at",
    "eeprom_24lcxx_write_at", "find_24lc64_class_a_driver",
    "find_24lcxx_driver", "find_24lcxx_x270_driver", "find_24lcxx_x430_driver",
    "find_24lcxx_x7700_driver", "find_compound_fujitsu_layout",
    "find_fujitsu_x16_bulk_write", "flash_id_for_size",
    "fujitsu_x16_bulk_write_at", "fujitsu_x16_flash_ids",
    "qualcomm_efs_seed", "main",
)


def main() -> int:
    """Run CLI while keeping legacy dependency patch points stable."""
    from . import cli

    cli.BUILD_CODENAME = BUILD_CODENAME
    cli.FRAMEBUFFER_FORMATS = FRAMEBUFFER_FORMATS
    cli.GenericMSMEmulator = GenericMSMEmulator
    cli.HostBackendFault = HostBackendFault
    cli.detect = detect
    return cli.main()
