"""Shared emulator core constants."""
from __future__ import annotations

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                               UC_ARM_REG_R6, UC_ARM_REG_R7)


PAGE = 0x1000
MAX_RAM_SIZE = 0x08000000
MAX_NAND_DATA_SIZE = 0x08000000
MAX_NAND_BACKING_SIZE = 0x10000000
MAX_DYNAMIC_PAGES = 2048
UNMAPPED_ACCESS_HISTORY_LIMIT = 16
LCD_MMIO_PRIMARY_START = 0x02000000
LCD_MMIO_PRIMARY_COMMAND_SIZE = PAGE
LCD_MMIO_PRIMARY_END = 0x02800000
BOOTSTRAP_HLE_SLACK = 0x400
# Hardware-poll release is guest-visible; keep the established observation cadence
# independent of GUI/public run() partitions.
POLL_OBSERVATION_STEPS = 100_000
BUILD_CODENAME = "ancal"
HANDSET_KEY_COUNT = 23
NAND_MMIO_RANGES = (
    (0x01800000, 0x01801000),
    (0x01900000, 0x01901000),
    (0x01A00000, 0x01A01000),
)
FRAMEBUFFER_FORMATS = ("rgb565le", "bgr565le", "rgb565be", "bgr565be")
LCD_MEMORY_WRITE_COMMANDS = frozenset((0x22, 0x2C, 0x3C, 0x5C))
PACKED_RGB332_WINDOW_COMMANDS = frozenset((0x45, 0x46, 0x47, 0x48))
BYTE_RGB565_BOOT_COMMANDS = bytes.fromhex(
    "AF EB 81 3F AF 27 D6 0F 15 40 50 6F 73 89 90 B0 C6 D0 "
    "F1 3F F4 08 F5 00 F6 67 F7 3F F9"
)
BYTE_RGB565_BOOT_WIDTH = 96
BYTE_RGB565_BOOT_HEIGHT = 64
REX_TICK_INTERVAL = 100_000
THUMB_LOW_REGISTERS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                       UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                       UC_ARM_REG_R6, UC_ARM_REG_R7)
STABLE_MSM_MMIO = (
    # Bit 4 selects normal handset boot on several board revisions; bit 2 is
    # retained for the later 5100/5500 startup code.
    (0x0300072C, b"\x14"),
    (0x03000694, b"\x10"),      # early MSM5000 board strap
    (0x030007AC, b"\x57"),      # MSM revision/status
    (0x03000C1C, b"\xff"),      # clock-ready status
    (0x03000720, b"\xff\xff"),
    (0x03000724, b"\xff\xff"),
)
