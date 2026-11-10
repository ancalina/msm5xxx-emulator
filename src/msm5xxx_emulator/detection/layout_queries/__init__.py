"""Firmware memory-layout detection."""
import hashlib
import struct
from ...core.config import CopyLayout, LinkerLayout
from ..arm import arm_vector_score, thumb_bl_target, thumb_literal_value
from ..layout_facts import layout_facts_for, _image_offset, _contiguous_address_length_array, find_linker_layout
from ..signatures import find_all
from .tables import (PAGE, _HIGH_RAM_TEST_PREFIX, _HIGH_RAM_TEST_SHA256, _high_ram_readback_layout, find_high_ram_readback_tests, _reset_copy_covers_upper_half,
    high_ram_bootstrap_profile, _BOOT_REGISTER_TABLE_LOOP, _BOOT_REGISTER_TABLE_WILDCARDS, _BOOT_REGISTER_DESTINATIONS, ARM_MEMORY_COPY_SIGNATURE,
    ARM_MEMORY_COPY_TAIL, ARM_MEMORY_COPY_TAIL_OFFSET, _BOOTSTRAP_PROGRESS_CLEAR, _DUAL_SDRAM_BOOTSTRAP, _DUAL_SDRAM_STATUS_LITERAL_OFFSET,
    _DUAL_SDRAM_FLAG_LITERAL_OFFSET, _DUAL_SDRAM_DISPATCH_LITERAL_OFFSET, _DUAL_SDRAM_LOW_BASE, _DUAL_SDRAM_HIGH_BASE, _DUAL_SDRAM_END,
    _HIGH_BANK_READER_BOOTSTRAP, _HIGH_BANK_READER_BOOTSTRAP_TAIL, _HIGH_BANK_READER_ENTRY, _HIGH_BANK_READER, _HIGH_BANK_READER_ASSIGN,
    _HIGH_BANK_READER_CONSUMER, _bootstrap_ram_base, _boot_register_table_pointer, _is_boot_register_table, restore_sparse_nor_gap, find_arm_vector_offset,
    infer_ram_base, has_dual_sdram_bootstrap, has_high_bank_reader_bootstrap, plausible_ram_seed_size, aligned, interval_gaps, normalised_flash_size,
    referenced_flash_extent)
from .bootstrap import (_referenced_flash_extent, find_overlays, find_missing_overlays, find_runtime_overlays, find_arm_memory_copy_addresses, _DUAL_STAGE_RESET,
    _DUAL_STAGE_PRIVATE, _DUAL_STAGE_NORMAL, _DUAL_STAGE_SCATTER, _DUAL_STAGE_ROUTE, dual_stage_ram_profile)
