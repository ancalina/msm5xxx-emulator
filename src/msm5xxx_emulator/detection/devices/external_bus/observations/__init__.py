"""Instruction and literal shapes for external device support.

Detectors use instruction words, loaded literals, and control-flow linkage.
They return a profile and an acceptance reason, or None and a rejection reason.
"""
import struct
from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, source_prefix
from .reset import (PAGE, _HIGH_RAM_TEST_PREFIX, _EXTENTS, _RAM_PATTERN, _UART_BASE, _DOG, _GPIO720, _STATUS_BASE, _u16, _u32, _find_all, _thumb_literal,
    _thumb_b_target, _thumb_bl_target, _movs_imm, _is_lsl_reg, _EXTERNAL_LCD_STORE_OFFSETS, _is_narrow_store, _narrow_store_offset, _reset_called,
    _BODY_FIELD_PTRS, _table_from_body, _arm_branch_delta, _arm_immediate, _ram_test_body_shape, _high_ram_layout, _reset_copy_covers_upper_half,
    _cs_store_sites, _cs_ctrl_sites, detect_external_ram)
from .windows import (detect_external_cs0a, _literal_window_accesses_many, _literal_window_accesses, detect_external_cs09, detect_external_windows,
    _thumb_shifted_08c_stores, detect_gpio_ready_bit21, detect_external_panel_writers, _bit3_polls, _uart_cr_inits, _push_lr, detect_boot_uart, _reset_push,
    detect_boot_strap, _thumb_cond_b_target, _thumb_literal_pool, _thumb_literal_loads_of, _thumb_writes_register, _reset_helper_source_spans,
    _thumb_reset_function_end)
from .contacts import (_thumb_nearest_push_lr, _thumb_calls_to, _status_zero_branch, _status_panel_branch, detect_boot_gpio_bit9, _boot_gpio_bit9_panel_sites,
    detect_external_status, _shift_stores, _bit21_spins, _external_lcd_writers)
from .lcd import detect_external_lcd
