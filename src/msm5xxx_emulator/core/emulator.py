#!/usr/bin/env python3
"""Generic Qualcomm MSM5000/MSM5100/MSM5500 firmware bring-up runner."""
from __future__ import annotations

import argparse
import binascii
from collections import Counter, deque
from dataclasses import asdict, dataclass
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import struct
import threading

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn import UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE
from unicorn import (UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_UNMAPPED,
                     UC_MEM_WRITE_UNMAPPED, UC_MODE_ARM, UC_PROT_ALL, UC_PROT_READ)
from unicorn import UC_PROT_WRITE
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_SPSR
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R12)
from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7
from unicorn.arm_const import UC_ARM_REG_SP, UC_CPU_ARM_TI925T

from ..devices.storage.nor import FUJITSU_MB84VD2219X_IDS, NORFlash
from ..state_io import (atomic_write_bytes, atomic_write_text, durable_unlink,
                        exclusive_path_lock, lock_path)


LOGGER = logging.getLogger("msm5xxx")

try:
    from e170_gm_audio import ApproximateSmafPlayer
except ImportError:
    ApproximateSmafPlayer = None


PAGE = 0x1000
ADDRESS_SPACE = 1 << 32
MAX_FLASH_SIZE = 0x04000000
MAX_RAM_SIZE = 0x08000000
MAX_NAND_DATA_SIZE = 0x08000000
MAX_NAND_BACKING_SIZE = 0x10000000
MAX_DYNAMIC_PAGES = 2048
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
DEFAULT_STATE_ROOT = Path(os.environ.get(
    "MSM5XXX_STATE_DIR", Path.home() / ".msm5xxx-emulator"
)).expanduser()
MODEL_RE = re.compile(
    rb"(?:SCH-[A-Z]\d{3,4}|SPH-[A-Z]\d{3,4}|LG-[A-Z]{2}\d{3,4}|SCP-?\d{3,4})",
    re.I,
)
LCD_PIXEL_RE = re.compile(rb"m\.LCD_PIXEL\x00{1,4}(\d{3})(\d{3})\x00")
KNOWN_SCREENS = {
    "LG-SD810": (120, 160),
    "LG-SV130": (176, 220),
    "SCH-E100": (128, 160),
    "SCH-E170": (176, 220),
    "SCH-E370": (128, 160),
    "SCH-E135": (128, 160),
    "SCH-E470": (176, 220),
    "SCH-V540": (176, 220),
    "SCH-X430": (128, 160),
}
AUDIO_PLAY_SIGNATURE = bytes.fromhex(
    "ffb5071c0e1c27490868400838d38868002835db002f33db042f31da002e2fd0c"
    "c207843441824342078012828d1e51d1d35281cfff76afa039b0120002b00d1"
)
LG_INPUT_PATTERN = re.compile(
    rb"\x00\xb5.{4}.{4}\x08\xbc\x18\x47\x00\x00"
    rb"\x90\xb5\x07\x1c\x0c\x1c.{4}\x39\x88\x21\x43\x39\x80"
    rb"\x00\x28\x01\xd1.{4}\x90\xbc\x08\xbc\x18\x47"
    rb"\x90\xb5\x07\x1c\x0c\x1c.{4}\x39\x88\x21\x40\x39\x80"
    rb"\x00\x28\x01\xd1",
    re.S,
)
LG_DECODED_ENQUEUE_SIGNATURE = bytes.fromhex(
    "f7b50c1c151c17480121490240188078202803db0020febc08bc1847"
)
SAMSUNG_INPUT_PATTERN = re.compile(
    rb"\x54\x2f.{2}\x55\x2f.{2}.{0,120}"
    rb"\x50\x78\x13\x78\x41\x1c\xc9\x06\xc9\x0e\x99\x42\x07\xd0"
    rb"\x80\x18\x87\x70\x50\x78\x01\x30\xc0\x06\xc0\x0e\x50\x70",
    re.S,
)
SECONDARY_FLASH_WRAPPER_PATTERN = re.compile(
    rb"\xf0\xb5.\x4e\x07\x1c\x30\x68\x15\x1c\x0c\x1c\x00\x28.\xd1"
    rb".{4}\xff\x20.\x30.\x49.{4}.\x48\x00\x79\x01\x28\x02\xd1"
    rb"\xf0\xbc\x08\xbc\x18\x47\x30\x68\x2a\x1c\xff\x30.\x30"
    rb"(?P<dispatch>\xc3\x6b|\x03\x68)\x21\x1c\x38\x1c.{4}",
    re.S,
)
FUJITSU_X16_BULK_WRITE_PATTERNS = (
    (re.compile(
        rb"\xf0\xb5\x14\x1c\x05\x1c\x0f\x1c\x40\x08\x03\xd2"
        rb"\x78\x08\x01\xd2\x60\x08\x02\xd3.{20}\x2e\x88.{4}"
        rb"\x15\x4a\xa0\x21\x51\x81\x3e\x80\x00\x28\x01\xd1.{4}"
        rb"\x01\x22\x38\x1c\x31\x1c.{4}\x00\x28.{10}\x01\x20"
        rb"\xf0\xbd\x01\x20\xc0\x05\x02\x3c\x02\x35\x02\x37.{12}"
        rb"\x00\x2c\xda\xd1\x00\x20\xf0\xbd", re.S,
    ), 0x84, 0xAA0),
    (re.compile(
        rb"\xf0\xb5\x0f\x1c\x04\x1c\x15\x1c\x40\x08\x03\xd2"
        rb"\x78\x08\x01\xd2\x68\x08\x03\xd3.{24}\x26\x88.{4}"
        rb"\x16\x4a\xa0\x21\x51\x81\x3e\x80\x00\x28\x01\xd1.{4}"
        rb"\x01\x22\x31\x1c\x38\x1c.{4}\x00\x28.{10}\x01\x20"
        rb"\xf0\xbc\x08\xbc\x18\x47\x02\x34\x02\x37\x02\x3d.{16}"
        rb"\x00\x2d\xd8\xd1\x00\x20\xed\xe7", re.S,
    ), 0x8C, 0xAAA0),
)
LEGACY_SECONDARY_FLASH_READ_SIGNATURE = bytes.fromhex(
    "80b50a4f01233b7000233b70084f7b683f7a012f03d1012080bc08bc1847"
)
LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE = bytes.fromhex(
    "b0b50c1c071c151c0d49012008700020087000f007fd002804d10a494868097a"
    "012903d10120b0bc08bc1847"
)
LEGACY_EFS_PAGE_READ_SIGNATURE = bytes.fromhex(
    "f0b5071c1d1cffb0504c86b00120207000262670031c141c0440849400d100231e"
    "06360eeb07db0f839300d100200006000e5208ab1c5c08002e01d0002801d0"
)
EEPROM_24LCXX_WRITE_PREFIX = bytes.fromhex(
    "f7b593b001267603149c171cb442f94902db8878012802d10020149c06e0"
    "c878149c01235b03e21a1404240c0a880625b24202d089780229"
)
EEPROM_24LCXX_READ_SIGNATURE = bytes.fromhex(
    "f0b5151c01225203071cfa48914202db8378012b02d100240e1c05e001235b03"
    "c91ac4780e04360c0188914202d08078"
)
# Exact ADS variant observed at the X430/VE21 24LC256 transport entries.  The
# short prefixes alone are never enough to enable HLE; find_24lcxx_driver()
# also requires the unique marker, initializer, and three matching literals.
EEPROM_24LCXX_X430_WRITE_PREFIX = bytes.fromhex(
    "f7b593b0161c012314995b039942f64f02db"
)
EEPROM_24LCXX_X430_READ_PREFIX = bytes.fromhex(
    "f0b5041c151c01235b039942f64802db8278"
)
EEPROM_24LCXX_X430_INIT_SIGNATURE = bytes.fromhex(
    "01200449c0030880012088700020c8707047"
)
# Exact compiler class shared by the X270/X730/X820 24LC256 transports.  As
# with X430, discovery also requires the unique marker, initializer, and
# paired geometry literals below.
EEPROM_24LCXX_X270_WRITE_PREFIX = bytes.fromhex(
    "f7b5161c93b0149901235b039942f74a02db"
)
EEPROM_24LCXX_X270_READ_PREFIX = bytes.fromhex(
    "f0b5041c151c01235b039942f74802db8278"
)
EEPROM_24LCXX_X270_INIT_SIGNATURE = bytes.fromhex(
    "01200449c0030880012088700020c8707047"
)
# SPH-X7700 has a separately compiled 24LC256 transport.  Its duplicated
# source-name string is not a uniqueness signal, so discovery below requires
# both full entry prefixes, one initializer, and both geometry literals.
EEPROM_24LCXX_X7700_WRITE_PREFIX = bytes.fromhex(
    "f7b593b0161c012314995b039942f74f02dbb878012802d10020149c05e0f878"
    "1499f34a89180c04240c3a88f04bf149da4202d0bb78022b08d1620b520703d1"
)
EEPROM_24LCXX_X7700_READ_PREFIX = bytes.fromhex(
    "f0b5051c141c01235b039942f64802db8278012a02d100260f1c04e0f34ac678"
    "89180f043f0c011c0088f04bd84202d0897802290ad1780b400703d13819400b"
)
EEPROM_24LCXX_X7700_INIT_SIGNATURE = bytes.fromhex(
    "01200449c0030880012088700020c8707047"
)
MA2_COMMAND_BUS_SIGNATURE = bytes.fromhex("4121c90468700870")
MA2_REGISTER_READ_SIGNATURE = bytes.fromhex("80b504494127ff0448703870")
MA2_STATUS_WAIT_SIGNATURE = bytes.fromhex(
    "f8b500220f1c0092041c00237d22154d"
)
MA2_INIT_SIGNATURE = bytes.fromhex("90b5b2b06846c822")
MA2_RESET_AFTER_BL_SIGNATURE = bytes.fromhex(
    "1d4902230a781c4d1a430a7009782971"
)
FAST_BOOT_SIGNATURE = bytes.fromhex(
    "234a80b401201070002111702148224f03683f68de19214b1d68046801e001cd"
    "01c4b442fbd30120107011701c481d4f03683f68de191c1c012005e02160a303"
)
NAND_BAD_BLOCK_SIGNATURE = bytes.fromhex(
    "f0b5010a0406240e00270d062d0e0026fff7deff50200d214905087019210905"
    "0e70201c384308700d70fff7d6ff0320c0050088064b984203d00220f0bc08bc"
)
DELAY_SIGNATURE = bytes.fromhex(
    "f0b41d4a978c116a79437a013f239a1a0026322809dc4843222179438018401a"
    "801100d4061c154f22e032234b439d1822237b43341ceb1a9b1100d41c1c0f4f"
)
NAND_READ_SIGNATURE = bytes.fromhex(
    "f0b5071c01201d1c031c141cffb086b00440849400d100231e06360e01202b1c"
    "0340839300d100200006000e5208ab1c5c08002e01d0002801d0681c4408080a"
)
NAND_WRITE_SIGNATURE = bytes.fromhex(
    "feb5071c1c1cd807c00f5208581c4508080a0606360e0806000e01901006000e"
    "0290fff77bfe0d204005ff23013300219a4201d2017001e05022027080220d20"
)
BUSY_DELAY_SIGNATURE = bytes.fromhex("0943094309430138fadcf746")
REGISTER_RAMP_PREFIX = bytes.fromhex(
    "32234b439d1822237b43341ceb1a9b1100d41c1c0f4f3c80"
    "32234b4332389b189b1101d41c1c00e0341c2404240c01e0"
)
REX_TICK_SIGNATURE = bytes.fromhex("00b500f08ffb08bc1847")
REX_5MS_WRAPPER_ANCHOR = bytes.fromhex(
    "800801d30a4800e00a480168053901600520"
)
REX_5MS_CALLBACK_SIZE = 64
REX_TIMER_ADVANCE_SIZE = 70
BOARD_ADC_SIGNATURE = bytes.fromhex(
    "f1b584b00027049a002521492e1c009700200024895cd2000392ca1f033a0a31"
)
BOARD_ADC_READER_PREFIX = bytes.fromhex("90b5071c")
BOARD_ADC_READER_BODY = bytes.fromhex(
    "1e48802301781943017001789f2319400170022f03d10178402319430ae0"
    "032f03d101786023194304e0002f03d101782023194301700178071c0a20"
)
BOARD_ADC_READER_MID_BODY = bytes.fromhex("387880239843387039780a20")
BOARD_ADC_READER_TAIL = bytes.fromhex("0548808907063f0e002c01d1")
BOARD_ADC_READER_BL_OFFSETS = (0x04, 0x0C, 0x12, 0x52, 0x56, 0x5A,
                               0x6A, 0x6E, 0x74, 0x78, 0x88)
BOARD_ADC_READER_SIZE = 0x98
BOARD_ADC_READER_LITERAL = 0x03000780
BOARD_ADC_READER_DATA_ADDRESS = BOARD_ADC_READER_LITERAL + 0x0C
BOARD_ADC_READER_READ_OFFSET = 0x7E
FLASH_ID_SIGNATURE = bytes.fromhex(
    "30b50e4b011ccc18084d094b258023800b4bca18074b1380074b238008884b88"
    "00041b04000c"
)
CRC16_SIGNATURE = bytes.fromhex(
    "90b4c0430004000c0a4f0ce00c78031263405b00fb5a000258400004000c013a"
    "1204120c0131002af0dcc0430004000c90bc7047"
)
FLASH_IDS_BY_SIZE = {
    0x200000: 0x222D0001,  # AMD AM29DL162BT
    0x400000: 0x22500001,  # AMD AM29DL323DT
    0x800000: 0x227E0001,  # AMD AM29DL640G
}
MEMORY_CLEAR_LOOP_SIGNATURE = bytes.fromhex(
    "b4420dd202e0211d0c1cf9e700212160a103f8d1"
)
# ARM ADS emits this 128-byte unrolled BSS loop in several later Samsung BSPs.
# The complete tail is validated dynamically before HLE is applied.
MEMORY_CLEAR_128_SIGNATURE = bytes.fromhex(
    "20606060a060e06020616061a061e061"
    "20626062a062e06220636063a063e063"
)
MEMORY_COPY_LOOP_SIGNATURE = bytes.fromhex(
    "b44208d204e0291d0d1c211d0c1cf7e729682160f7e7"
)
ARM_MEMORY_COPY_SIGNATURE = bytes.fromhex(
    "030052e33e00009a03c010e20800000a0130d1e402005ce3"
    "0c2082e001c0d1940130c0e40130d134"
)
ARM_MEMORY_COPY_TAIL = bytes.fromhex(
    "043080241040bde81eff2f01822fb0e10120d1440130d124"
    "01c0d1240120c0440130c02401c0c0241eff2fe1"
)
ARM_MEMORY_COPY_TAIL_OFFSET = 0xF8
DMD_DOWNLOAD_SIGNATURE = bytes.fromhex("f0b5002701250024354901200870")
PRIMARY_FLASH_PROBE_SIGNATURE = bytes.fromhex(
    "16481749006b096840004018aa221101411881b04a81552215239b01c3189a82"
    "90224a81018800ab198041885980f02101800c480ce000abff3121311a888b88"
    "9a4204d100ab5a88c9888a4203d0043001680029efd1006801b07047"
)
FRAMEBUFFER_DESCRIPTOR_PATTERN = re.compile(
    rb"\x10\x22\x00\x28\x07\xd1(?P<width>.)\x20\x08\x60"
    rb"(?P<height>.)\x20\x48\x60\x8a\x60\xca\x60\x08\x48\x08\xe0"
    rb"\x01\x28\x09\xd1(?P<sub_width>.)\x20\x08\x60\x48\x60.\x20"
    rb"\x88\x60\x04\x48\xca\x60\x08\x61\x01\x20\x70\x47"
    rb"\x00\x20\x70\x47\x00\x00(?P<main>.{4})(?P<sub>.{4})"
    rb"\x00\x48\x70\x47(?P<end>.{4})",
    re.S,
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
DISABLEABLE_ADDRESS_FIELDS = frozenset({
    "delay_address", "busy_delay_address", "secondary_flash_read_address",
    "secondary_flash_write_address", "legacy_efs_page_read_address",
    "eeprom_read_address", "eeprom_write_address", "eeprom_geometry_address",
    "nand_bad_block_address", "nand_read_address", "nand_write_address",
    "rex_idle_address", "rex_tick_address", "rex_irq_wrapper_address",
    "board_adc_address",
    "flash_id_address", "crc16_address", "dmd_download_address",
    "primary_flash_probe_address", "board_revision_register",
    "framebuffer_address", "framebuffer_flush_address",
    "framebuffer_rect_flush_address",
})
REX_TICK_INTERVAL = 100_000
REX_IRQ_WRAPPER_SIGNATURE = bytes.fromhex(
    "04e04ee20f542de900004fe101002de92c029fe5b010d0e1011081e2b010c0e1"
    "9ff021e300402de918329fe5003093e5010013e310e29f1510e29f0513ff2fe1"
)
REX_IRQ_WRAPPER_RUNTIME_SIZE = 0x260
REX_IRQ_HANDLER_RUNTIME_SIZE = 0x1DC
TRAMPM5_CONSUMER_SIZE = 40
REX_INTLOCK_SIGNATURE = bytes.fromhex(
    "7847000001e08ee300000fe1c01080e301f021e1c00000e2"
)
REX_INTFREE_SIGNATURE = bytes.fromhex(
    "7847000001e08ee300000fe1c010c0e301f021e1c00000e2"
)
REX_IRQ_DRAIN_PATTERN = re.compile(
    rb"\x08\x43\x1f\xd1.{4}\x47\x48\x00\x88\x01\x28\x03\xd1"
    rb".{4}\x00\x28\xfb\xd1", re.S,
)
THUMB_LOW_REGISTERS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                       UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                       UC_ARM_REG_R6, UC_ARM_REG_R7)
MSM_REVISION_BLOCK = 0x03000740
MSM_REVISION_REGISTER = MSM_REVISION_BLOCK + 0x1C
MSM_REVISION_RAW_F022 = 0x20F2
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


def detect_model(image: bytes, path: Path) -> str:
    """Combine dump name and embedded compatibility/model strings.

    Prototype and upgrade images often retain an older model name in a shared
    module.  A handset-looking token in the supplied filename therefore wins
    when the image is clearly from the same manufacturer.
    """
    embedded = [item.decode("ascii").upper() for item in MODEL_RE.findall(image)]
    stem = path.stem.upper()
    normalised_stem = re.sub(r"[_ ]+", "-", stem)
    full_name = re.search(
        r"(?:(?:SCH|SPH|KTFT)-[A-Z]\d{3,4}|LG-[A-Z]{2}\d{3,4}|SCP-?\d{3,4})",
        normalised_stem,
    )
    if full_name:
        token = full_name.group(0)
        return re.sub(r"^SCP(?=\d)", "SCP-", token)
    explicit = re.search(
        r"(?<![A-Z0-9])(?:SCH[-_ ]?)?([A-Z]\d{3})(?:\b|_)", stem
    )
    if explicit and (embedded or stem.startswith(("SCH", "E", "V", "X"))):
        token = explicit.group(1)
        if any(item.startswith("SCH-") for item in embedded) or not embedded:
            return f"SCH-{token}"
    if embedded:
        counts = Counter(embedded)
        return max(counts, key=lambda item: (counts[item], embedded.index(item)))
    return path.stem


def detect_lcd_width_hint(image: bytes) -> int | None:
    """Return one plausible firmware-declared UI width, never its viewport height."""
    widths = {
        int(match.group(1))
        for match in LCD_PIXEL_RE.finditer(image)
        if 64 <= int(match.group(1)) <= 320
        and 32 <= int(match.group(2)) <= 320
    }
    return widths.pop() if len(widths) == 1 else None


def detect_chipset(image: bytes, model: str) -> str:
    """Identify the BSP generation, ignoring inherited MSM5000 modules."""
    lowered = image.lower()
    if b"msm6050" in lowered:
        return "MSM6050"
    # Clock/boot modules belong to the active board support package.  Radio,
    # display and data modules retain MSM5000 names in both later generations.
    if (b"clkrgm_5500.c" in lowered or b"boothw_5500.c" in lowered
            or b"dmddown_5500.c" in lowered):
        return "MSM5500"
    if (b"clkrgm_5100.c" in lowered or b"boothw_510x.c" in lowered
            or b"mclk_5105.c" in lowered):
        return "MSM5100"
    if b"mclk_5000.c" in lowered:
        return "MSM5000"
    if b"dec5000.c" in lowered or b"dec5000_.c" in lowered:
        return "MSM5000"
    has_5500 = b"MSM5500" in image.upper()
    has_5100 = b"MSM5100" in image.upper()
    if has_5500 and not has_5100:
        return "MSM5500"
    if has_5100 and not has_5500:
        return "MSM5100"
    if model == "SCH-X430" and b"MSM5000" in image.upper():
        return "MSM5000"
    if re.fullmatch(r"SPH-X9\d{3}", model):
        return "MSM5100"
    return "MSM5xxx"


def chipset_confidence(image: bytes, chipset: str) -> str:
    lowered = image.lower()
    markers = {
        "MSM5500": (b"clkrgm_5500.c", b"boothw_5500.c", b"dmddown_5500.c"),
        "MSM5100": (b"clkrgm_5100.c", b"boothw_510x.c", b"mclk_5105.c"),
        "MSM5000": (b"mclk_5000.c",),
        "MSM6050": (b"msm6050",),
    }
    if chipset in markers and any(marker in lowered for marker in markers[chipset]):
        return "high"
    if chipset != "MSM5xxx":
        return "medium"
    return "unknown"


def arm_vector_score(image: bytes, offset: int = 0) -> int:
    if offset < 0 or offset + 32 > len(image):
        return 0
    words = struct.unpack_from("<8I", image, offset)
    score = 0
    for index, word in enumerate(words):
        if word & 0x0E000000 != 0x0A000000 or word >> 28 == 0xF:
            continue
        displacement = (word & 0x00FFFFFF) << 2
        if displacement & 0x02000000:
            displacement -= 0x04000000
        target = (offset + index * 4 + 8 + displacement) & 0xFFFFFFFF
        if target < len(image) or 0x01000000 <= target < 0x04000000:
            score += 1
    return score


def find_arm_vector_offset(image: bytes) -> tuple[int, int]:
    """Return the best small dump-header offset and validated vector score."""
    best = (0, arm_vector_score(image, 0))
    for offset in range(4, min(0x100, len(image) - 32) + 1, 4):
        score = arm_vector_score(image, offset)
        if score > best[1]:
            best = (offset, score)
    return best


def infer_ram_base(layout: LinkerLayout | None, chipset: str,
                   image: bytes = b"") -> int:
    """Select the 8 MiB SDRAM bank that contains linker data and BSS."""
    if layout is not None:
        first = layout.data_target
        last = layout.bss_target + layout.bss_size
        for base in (0x01000000, 0x01800000):
            if base <= first and last <= base + 0x00800000:
                return base
    if image:
        # Linker tables are absent in several partial builds.  Literal pools
        # in the reset/driver region still reveal which external SDRAM bank
        # the image was linked against.  Requiring a 3:1 margin avoids random
        # resource words deciding the result.
        counts: list[int] = []
        sample = image[:min(len(image), 0x20000)]
        sample = sample[:len(sample) & ~3]
        words = tuple(value[0] for value in struct.iter_unpack("<I", sample))
        for base in (0x01000000, 0x01800000):
            counts.append(sum(base <= value < base + 0x00800000
                              for value in words))
        if max(counts, default=0) >= 32:
            if counts[0] >= counts[1] * 3:
                return 0x01000000
            if counts[1] >= counts[0] * 3:
                return 0x01800000
    return 0x01000000 if chipset in ("MSM5000", "MSM5500") else 0x01800000


def plausible_ram_seed_size(image_size: int, flash_size: int,
                            ram_size: int = 0x00800000) -> int:
    """Reject tiny capture trailers while preserving real RAM snapshots."""
    tail = max(0, image_size - flash_size)
    return min(tail, ram_size) if tail >= 0x10000 else 0


def aligned(value: int) -> int:
    return (value + PAGE - 1) & -PAGE


def interval_gaps(start: int, end: int,
                  excluded: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Subtract half-open intervals and return remaining half-open gaps."""
    if start >= end:
        return []
    gaps: list[tuple[int, int]] = []
    cursor = start
    for left, right in sorted(excluded):
        left, right = max(start, left), min(end, right)
        if left >= right or right <= cursor:
            continue
        if cursor < left:
            gaps.append((cursor, left))
        cursor = max(cursor, right)
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def integer(value: str) -> int:
    return int(value, 0)


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


def default_state_paths(path: Path, image: bytes, flash_size: int,
                        secondary_size: int, secondary_image: str | None = None,
                        nand_image: str | None = None,
                        nand_geometry: tuple[int, int, int, int, int] | None = None,
                        secondary_generated_efs: bool = False,
                        ) -> tuple[str, str]:
    identity = hashlib.sha256(image[:flash_size]).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", path.stem)[:48] or "firmware"
    seed_identity = _file_identity(secondary_image)
    nand_identity = _file_identity(nand_image)
    suffix = ((f"-s{seed_identity}" if seed_identity else "")
              + ("-sefs" if secondary_generated_efs and not seed_identity else "")
              + (f"-n{nand_identity}" if nand_identity else "")
              + ("-g" + "-".join(f"{value:x}" for value in nand_geometry)
                 if nand_geometry else ""))
    base = (DEFAULT_STATE_ROOT / "firmware"
            / f"{stem}-{identity}-{flash_size:x}{suffix}")
    return f"{base}.flash.json", f"{base}.efs-{secondary_size:x}.json"


def flash_id_for_size(size: int) -> int | None:
    """Return a firmware-supported AMD NOR ID for a complete dump."""
    for capacity, device_id in FLASH_IDS_BY_SIZE.items():
        if capacity - PAGE <= size <= capacity:
            return device_id
    return None


def normalised_flash_size(size: int, address_limit: int) -> int:
    """Recover physical NOR capacity from partial dumps and small trailers."""
    capacities = (0x200000, 0x400000, 0x800000, 0x1000000,
                  0x1800000, 0x2000000)
    for capacity in capacities:
        if capacity <= address_limit and size <= capacity:
            return capacity
        # A short trailer beyond an exact NOR capacity is normally a captured
        # RAM prefix, not a non-standard flash chip size.
        if capacity < address_limit and capacity < size <= capacity + 0x10000:
            return capacity
    return min(size, address_limit)


def referenced_flash_extent(image: bytes, load_address: int = 0) -> int:
    """Infer NOR capacity from boot copy tables even when their source is absent."""
    extent = 0
    for offset in range(0, min(len(image) - 12, 0x20000) + 1, 4):
        source_address, target, size = struct.unpack_from("<3I", image, offset)
        if not (0x03800000 <= target < 0x03A00000
                and target % PAGE == 0 and 0x100 <= size <= 0x200000):
            continue
        source = source_address - load_address
        if (0x1000 <= source < 0x02000000
                and source > offset + 0x20
                and source + size <= 0x02000000):
            extent = max(extent, source + size)
    return extent


def qualcomm_efs_seed(size: int, chipset: str) -> bytes:
    """Return the captured MSM5500 GEFS seed, otherwise erased NOR."""
    if size < 0x200:
        raise ValueError("secondary flash is too small for GEFS")
    seed = bytearray(b"\xff" * size)
    if chipset != "MSM5500":
        return bytes(seed)
    seed[:0x14] = bytes.fromhex("ed000a0000000100000000000b00000000000000")
    seed[0x15:0x18] = b"\x00\x01\x03"
    seed[0x1C:0x28] = b"\x0b$USER_DIRS\x00"
    seed[0x1FC:0x200] = bytes.fromhex("0000d586")
    return bytes(seed)


def find_all(image: bytes, signature: bytes) -> list[int]:
    found: list[int] = []
    offset = 0
    while (offset := image.find(signature, offset)) >= 0:
        found.append(offset)
        offset += 1
    return found


def find_ma2_silent_boot_wait(image: bytes) -> int | None:
    """Find the uniquely cross-checked MA2 status-wait entry."""
    if b"Ma2main.c\0" not in image or b"Ma2lib.c\0" not in image:
        return None
    commands = find_all(image, MA2_COMMAND_BUS_SIGNATURE)
    reads = find_all(image, MA2_REGISTER_READ_SIGNATURE)
    waits = find_all(image, MA2_STATUS_WAIT_SIGNATURE)
    inits = find_all(image, MA2_INIT_SIGNATURE)
    if not all(len(matches) == 1 for matches in (commands, reads, waits, inits)):
        return None
    command, read, wait, init = commands[0], reads[0], waits[0], inits[0]
    reset = command - 0xA4
    if (any(position & 1 for position in (command, read, wait, init))
            or read != command + 0x78
            or init != command + 0x9CC
            or reset < 0
            or reset + 0x90 > len(image)
            or image[command + 0xC:command + 0x12]
            != bytes.fromhex("4120c0048770")
            or image[read + 0x10:read + 0x14] != bytes.fromhex("b87880bd")
            or image[reset:reset + 2] != b"\xb0\xb5"
            or image[reset + 6:reset + 6 + len(MA2_RESET_AFTER_BL_SIGNATURE)]
            != MA2_RESET_AFTER_BL_SIGNATURE
            or struct.unpack_from("<I", image, reset + 0x80)[0] != 0x03000680
            or struct.unpack_from("<I", image, reset + 0x88)[0] != 0x03000670
            or thumb_bl_target(image, init + 0x10) != command + 0x824
            or thumb_bl_target(image, init + 0x16) != command + 0x838
            or thumb_bl_target(image, init + 0x48) != command + 0x90):
        return None
    fixed_wait_chunks = (
        (0x1A, bytes.fromhex("0026f64315e0")),
        (0x24, bytes.fromhex("384003d0281c")),
        (0x2E, bytes.fromhex("09e00d480078002807d0281c")),
        (0x3E, bytes.fromhex("0a4900200870301cf8bd")),
        (0x50, bytes.fromhex("2040e5d0281c")),
        (0x5A, bytes.fromhex("0020f3e70000")),
    )
    if (wait + 0x60 > len(image)
            or any(image[wait + offset:wait + offset + len(expected)] != expected
                   for offset, expected in fixed_wait_chunks)
            or thumb_bl_target(image, wait + 0x20) != command + 0xC2
            or thumb_bl_target(image, wait + 0x4C) != command + 0xF2):
        return None
    return wait


def eeprom_24lcxx_write_at(image: bytes, position: int) -> bool:
    """Match the common ADS 24LCxx writer while ignoring its literal reach."""
    prefix = EEPROM_24LCXX_WRITE_PREFIX
    return (position & 1 == 0
            and 0 <= position <= len(image) - len(prefix)
            and image[position:position + 14] == prefix[:14]
            and image[position + 15:position + len(prefix)] == prefix[15:])


def _eeprom_24lcxx_variant_geometry_at(image: bytes, position: int,
                                        ldr_offset: int, literal_offset: int,
                                        geometry: int) -> bool:
    """Check one exact 24LCxx variant literal against its paired geometry."""
    if position + ldr_offset + 2 > len(image):
        return False
    operation = struct.unpack_from("<H", image, position + ldr_offset)[0]
    if operation & 0xF800 != 0x4800:
        return False
    literal = ((position + ldr_offset + 4) & ~3) + (operation & 0xFF) * 4
    return (literal == position + literal_offset
            and literal + 4 <= len(image)
            and struct.unpack_from("<I", image, literal)[0] == geometry)


def find_24lcxx_x430_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the uniquely cross-checked X430/VE21 compiler variant."""
    marker = b"nv24lcxx.c\0"
    if len(find_all(image.lower(), marker)) != 1:
        return None
    writes = find_all(image, EEPROM_24LCXX_X430_WRITE_PREFIX)
    reads = find_all(image, EEPROM_24LCXX_X430_READ_PREFIX)
    initializers = find_all(image, EEPROM_24LCXX_X430_INIT_SIGNATURE)
    if not all(len(matches) == 1 for matches in (writes, reads, initializers)):
        return None
    write, read, initializer = writes[0], reads[0], initializers[0]
    literal = initializer + 0x14
    if literal + 4 > len(image):
        return None
    geometry = struct.unpack_from("<I", image, literal)[0]
    if geometry & 3 or not 0x00800000 <= geometry < 0x02000000:
        return None
    if not (_eeprom_24lcxx_variant_geometry_at(
            image, write, 0xE, 0x3E8, geometry
    ) and _eeprom_24lcxx_variant_geometry_at(
            image, read, 0xC, 0x3E8, geometry
    )):
        return None
    return read, write, geometry


def find_24lcxx_x270_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the uniquely cross-checked X270/X730/X820 compiler class."""
    marker = b"nv24lcxx.c\0"
    if len(find_all(image.lower(), marker)) != 1:
        return None
    writes = find_all(image, EEPROM_24LCXX_X270_WRITE_PREFIX)
    reads = find_all(image, EEPROM_24LCXX_X270_READ_PREFIX)
    initializers = find_all(image, EEPROM_24LCXX_X270_INIT_SIGNATURE)
    if not all(len(matches) == 1 for matches in (writes, reads, initializers)):
        return None
    write, read, initializer = writes[0], reads[0], initializers[0]
    literal = initializer + 0x14
    if literal + 4 > len(image):
        return None
    geometry = struct.unpack_from("<I", image, literal)[0]
    if geometry & 3 or not 0x00800000 <= geometry < 0x02000000:
        return None
    if not (_eeprom_24lcxx_variant_geometry_at(
            image, write, 0xE, 0x3EC, geometry
    ) and _eeprom_24lcxx_variant_geometry_at(
            image, read, 0xC, 0x3EC, geometry
    )):
        return None
    return read, write, geometry


def find_24lcxx_x7700_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the uniquely paired X7700 24LC256 compiler variant."""
    if b"nv24lcxx.c\0" not in image.lower():
        return None
    writes = find_all(image, EEPROM_24LCXX_X7700_WRITE_PREFIX)
    reads = find_all(image, EEPROM_24LCXX_X7700_READ_PREFIX)
    initializers = find_all(image, EEPROM_24LCXX_X7700_INIT_SIGNATURE)
    if not all(len(matches) == 1 for matches in (writes, reads, initializers)):
        return None
    write, read, initializer = writes[0], reads[0], initializers[0]
    literal = initializer + 0x14
    if literal + 4 > len(image):
        return None
    geometry = struct.unpack_from("<I", image, literal)[0]
    if geometry & 3 or not 0x00800000 <= geometry < 0x02000000:
        return None
    if not (_eeprom_24lcxx_variant_geometry_at(
            image, write, 0xE, 0x3EC, geometry
    ) and _eeprom_24lcxx_variant_geometry_at(
            image, read, 0xC, 0x3E8, geometry
    )):
        return None
    return read, write, geometry


def find_24lcxx_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return unique read/write offsets and the firmware geometry global."""
    if b"nv24lcxx.c\0" not in image.lower():
        return None
    writes = [position for position in find_all(image, EEPROM_24LCXX_WRITE_PREFIX[:14])
              if eeprom_24lcxx_write_at(image, position)]
    reads = find_all(image, EEPROM_24LCXX_READ_SIGNATURE)
    if len(writes) == 1 and len(reads) == 1:
        write = writes[0]
        operation = struct.unpack_from("<H", image, write + 14)[0]
        if operation & 0xF800 == 0x4800 and (operation >> 8) & 7 == 1:
            literal = ((write + 18) & ~3) + (operation & 0xFF) * 4
            if literal + 4 <= len(image):
                geometry = struct.unpack_from("<I", image, literal)[0]
                read_operation = struct.unpack_from("<H", image, reads[0] + 10)[0]
                read_literal = (((reads[0] + 14) & ~3)
                                + (read_operation & 0xFF) * 4)
                if (not geometry & 3
                        and 0x00800000 <= geometry < 0x02000000
                        and read_operation & 0xF800 == 0x4800
                        and (read_operation >> 8) & 7 == 0
                        and read_literal + 4 <= len(image)
                        and struct.unpack_from("<I", image, read_literal)[0]
                        == geometry):
                    return reads[0], write, geometry
    return (find_24lcxx_x430_driver(image)
            or find_24lcxx_x270_driver(image)
            or find_24lcxx_x7700_driver(image))


def fujitsu_x16_bulk_write_at(image: bytes, position: int,
                              secondary_base: int) -> bool:
    for pattern, literal_offset, unlock_offset in FUJITSU_X16_BULK_WRITE_PATTERNS:
        if (pattern.match(image, position) is not None
                and position + literal_offset + 4 <= len(image)
                and struct.unpack_from("<I", image, position + literal_offset)[0]
                == secondary_base + unlock_offset):
            return True
    return False


def find_fujitsu_x16_bulk_write(image: bytes, secondary_base: int) -> int | None:
    if b"fs_fujitsu.c\0" not in image:
        return None
    matches = [
        match.start()
        for pattern, _literal_offset, _unlock_offset in FUJITSU_X16_BULK_WRITE_PATTERNS
        for match in pattern.finditer(image)
        if fujitsu_x16_bulk_write_at(image, match.start(), secondary_base)
    ]
    return matches[0] if len(matches) == 1 else None


def fujitsu_x16_flash_ids(image: bytes, writer_address: int | None,
                          load_address: int,
                          secondary_base: int) -> tuple[int, int] | None:
    position = -1 if writer_address is None else writer_address - load_address
    if (position >= 0
            and fujitsu_x16_bulk_write_at(image, position, secondary_base)):
        return FUJITSU_MB84VD2219X_IDS
    return None


def find_framebuffer_layout(
        image: bytes) -> tuple[int, int, int, int, int, int] | None:
    """Find the validated Qualcomm/LG main-LCD RAM descriptor and flush calls."""
    found: list[tuple[int, int, int, int, int, int]] = []
    for match in FRAMEBUFFER_DESCRIPTOR_PATTERN.finditer(image):
        start = match.start()
        width = match.group("width")[0]
        height = match.group("height")[0]
        sub_width = match.group("sub_width")[0]
        main, sub, end = (struct.unpack("<I", match.group(name))[0]
                          for name in ("main", "sub", "end"))
        stride = ((width + 7) // 8) * 16
        sub_stride = ((sub_width + 7) // 8) * 16
        if (not 32 <= min(width, height, sub_width)
                or main & 1
                or not 0x00800000 <= main < 0x08000000
                or sub != main + stride * height
                or end != sub + sub_stride * sub_width):
            continue
        if image[start + 0x44:start + 0x4E] != bytes.fromhex(
                "0920c002704702207047"):
            continue
        if image[start + 0x4E:start + 0x5C] != bytes.fromhex(
                "021c081c002a00b505d1db220021"):
            continue
        if image[start + 0x6E:start + 0x7C] != bytes.fromhex(
                "80b5071c081c111c1a1c002f04d1"):
            continue
        if image[start + 0x8C:start + 0x9A] != bytes.fromhex(
                "ffb581b00aaf151c1e1cb32090cf"):
            continue
        if image[start + 0xD0:start + 0xDA] != bytes.fromhex(
                "231c321c291c00970298"):
            continue
        row = thumb_bl_target(image, start + 0x5C)
        second_row = thumb_bl_target(image, start + 0x7C)
        rect = thumb_bl_target(image, start + 0xDA)
        if (row is None or row != second_row or rect is None
                or not 0 <= row < len(image) or not 0 <= rect < len(image)):
            continue
        found.append((width, height, main, stride, row, rect))
    return found[0] if len(found) == 1 else None


def thumb_bl_target(image: bytes, address: int) -> int | None:
    """Decode one ARMv4T Thumb BL without needing a disassembler."""
    if not 0 <= address <= len(image) - 4:
        return None
    high, low = struct.unpack_from("<2H", image, address)
    if high & 0xF800 != 0xF000 or low & 0xF800 != 0xF800:
        return None
    displacement = ((high & 0x7FF) << 12) | ((low & 0x7FF) << 1)
    if displacement & (1 << 22):
        displacement -= 1 << 23
    return address + 4 + displacement


def board_adc_reader_at(image: bytes, position: int) -> bool:
    """Validate one shared ADC reader without matching unrelated MMIO users."""
    if position & 1 or position < 0 or position + BOARD_ADC_READER_SIZE > len(image):
        return False
    fixed = (
        (0, BOARD_ADC_READER_PREFIX),
        (8, bytes.fromhex("0404240c")),
        (0x10, bytes.fromhex("2a20")),
        (0x16, BOARD_ADC_READER_BODY),
        (0x5E, BOARD_ADC_READER_MID_BODY),
        (0x72, bytes.fromhex("0b20")),
        (0x7C, BOARD_ADC_READER_TAIL),
        (0x8C, bytes.fromhex("381c90bd")),
    )
    if any(image[position + offset:position + offset + len(expected)] != expected
           for offset, expected in fixed):
        return False
    if struct.unpack_from("<I", image, position + 0x94)[0] != BOARD_ADC_READER_LITERAL:
        return False
    return all((target := thumb_bl_target(image, position + offset)) is not None
               and 0 <= target < len(image)
               for offset in BOARD_ADC_READER_BL_OFFSETS)


def find_board_adc_reader(image: bytes) -> int | None:
    """Return unique shared Thumb ADC reader, never loose ADC MMIO literal hits."""
    matches = [position for position in find_all(image, BOARD_ADC_READER_PREFIX)
               if board_adc_reader_at(image, position)]
    return matches[0] if len(matches) == 1 else None


def arm_b_target(image: bytes, address: int) -> int | None:
    """Decode one ARM B immediate without accepting BL or invalid cond."""
    if not 0 <= address <= len(image) - 4:
        return None
    word = struct.unpack_from("<I", image, address)[0]
    return arm_b_word_target(word, address)


def arm_b_word_target(word: int, address: int) -> int | None:
    if word & 0xFF000000 != 0xEA000000:
        return None
    displacement = (word & 0xFFFFFF) << 2
    if displacement & (1 << 25):
        displacement -= 1 << 26
    return address + 8 + displacement


def rex_timer_advance_at(image: bytes, position: int) -> bool:
    """Validate the old REX delta-timer list walker used by MSM5000 BSPs."""
    if position < 0 or position + REX_TIMER_ADVANCE_SIZE > len(image):
        return False
    words = struct.unpack_from("<35H", image, position)

    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000
                and words[index + 1] & 0xF800 == 0xF800)

    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800
                and words[index] >> 8 & 7 == register)

    return (
        words[:2] == (0xB5F0, 0x1C04)
        and bl(2)
        and words[4] == 0x1C07
        and literal(5, 0)
        and words[6:11] == (0x2600, 0x6805, 0xE011, 0x68A8, 0x42A0)
        and words[11] & 0xFF00 == 0xD800
        and words[12:21] == (
            0x60AE, 0xCD03, 0x3D08, 0x6008, 0x6868,
            0x6829, 0x6048, 0x68E8, 0x6929,
        )
        and bl(21)
        and words[23:27] == (0xE001, 0x1B00, 0x60A8, 0x682D)
        and literal(27, 0)
        and words[28] == 0x4285
        and words[29] & 0xFF00 == 0xD100
        and words[30:32] == (0x2F00, 0xD101)
        and bl(32)
        and words[34] == 0xBDF0
    )


def rex_5ms_callback_at(image: bytes, position: int) -> int | None:
    """Validate the complete IRQ callback and return its timer-walker target."""
    if position < 0 or position + REX_5MS_CALLBACK_SIZE > len(image):
        return None
    words = struct.unpack_from("<32H", image, position)

    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000
                and words[index + 1] & 0xF800 == 0xF800)

    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800
                and words[index] >> 8 & 7 == register)

    if not (
        words[0] == 0xB580
        and bl(1)
        and words[3:6] == (0x0407, 0x0C3F, 0x2105)
        and literal(6, 0) and bl(7)
        and literal(9, 0) and bl(10)
        and words[12:14] == (0x0880, 0xD301)
        and literal(14, 0)
        and words[15] == 0xE000
        and literal(16, 0)
        and words[17:21] == (0x6801, 0x3905, 0x6001, 0x2005)
        and bl(21)
        and literal(23, 0)
        and words[24] == 0x2105
        and bl(25)
        and words[27:29] == (0x2F00, 0xD101)
        and bl(29)
        and words[31] == 0xBD80
    ):
        return None
    return thumb_bl_target(image, position + 42)


def rex_sleep_call_at(image: bytes, position: int) -> int | None:
    """Return the sleep-controller BL in one validated MSM5000 idle loop."""
    if position < 0 or position + 56 > len(image):
        return None
    words = struct.unpack_from("<28H", image, position)

    def bl(index: int) -> bool:
        return (words[index] & 0xF800 == 0xF000
                and words[index + 1] & 0xF800 == 0xF800)

    def literal(index: int, register: int) -> bool:
        return (words[index] & 0xF800 == 0x4800
                and words[index] >> 8 & 7 == register)

    if not (
        literal(0, 4)
        and words[1:4] == (0x7820, 0x2801, 0xD106)
        and literal(4, 0)
        and words[5:8] == (0x7800, 0x2801, 0xD102)
        and literal(8, 0)
        and words[9:12] == (0x7800, 0xE000, 0x2008)
        and bl(12) and bl(14)
        and words[16:21] == (0x2104, 0x1C07, 0x2009, 0x05C0, 0x7822)
        and bl(21)
        and words[23] == 0x2F00
        and words[24] & 0xFF00 == 0xD100
        and bl(25)
        and words[27] & 0xF800 == 0xE000
    ):
        return None
    return position + 42


def thumb_literal_value(image: bytes, position: int,
                        register: int) -> int | None:
    if not 0 <= position <= len(image) - 2:
        return None
    word = struct.unpack_from("<H", image, position)[0]
    if word & 0xF800 != 0x4800 or word >> 8 & 7 != register:
        return None
    literal = ((position + 4) & ~3) + (word & 0xFF) * 4
    if literal + 4 > len(image):
        return None
    return struct.unpack_from("<I", image, literal)[0]


def trampm5_consumer_at(
        image: bytes, position: int) -> tuple[int, int, int] | None:
    """Validate one old trampm5 consumer and return q_get, thunk, queue."""
    if position < 0 or position + TRAMPM5_CONSUMER_SIZE > len(image):
        return None
    words = struct.unpack_from("<17H", image, position)
    if not (
        words[0] == 0xB590
        and words[1] == 0x4808
        and words[4:10] == (0x2400, 0x1C07, 0x2800,
                            0xD006, 0x68F8, 0x68B9)
        and words[12:] == (0x713C, 0x2001, 0xBD90, 0x1C20, 0xBD90)
    ):
        return None
    targets = (thumb_bl_target(image, position + 4),
               thumb_bl_target(image, position + 20))
    if any(target is None or target & 1 or not 0 <= target < len(image)
           for target in targets):
        return None
    if image[int(targets[1]):int(targets[1]) + 2] != b"\x08\x47":
        return None
    queue = thumb_literal_value(image, position + 2, 0)
    if (queue is None or queue & 3
            or not 0x00800000 <= queue < 0x08000000):
        return None
    return int(targets[0]), int(targets[1]), queue


def find_trampm5_consumer(image: bytes) -> int | None:
    """Find one unique old trampm5 queue consumer."""
    matches: list[int] = []
    offset = 0
    while (offset := image.find(b"\x90\xb5", offset)) >= 0:
        if not offset & 1 and trampm5_consumer_at(image, offset) is not None:
            matches.append(offset)
        offset += 2
    return matches[0] if len(matches) == 1 else None


def find_rex_5ms_irq_arm(image: bytes, tick_position: int) -> int | None:
    """Find one MMIO byte arm bound to this 5 ms callback registrar."""
    registration_targets: list[int] = []
    for position in range(0, len(image) - 8, 2):
        if (thumb_literal_value(image, position, 1) == tick_position | 1
                and struct.unpack_from("<H", image, position + 2)[0]
                == 0x201C):
            target = thumb_bl_target(image, position + 4)
            if target is not None and 0 <= target < len(image):
                registration_targets.append(target)
    if (len(registration_targets) != 3
            or len(set(registration_targets)) != 1):
        return None
    registrar = registration_targets[0]
    arms: list[int] = []
    for position in range(10, len(image) - 4, 2):
        arm = thumb_literal_value(image, position - 10, 1)
        if (thumb_bl_target(image, position) == registrar
                and arm is not None and 0x03000000 <= arm < 0x04000000
                and struct.unpack_from("<2H", image, position - 8)
                == (0x2002, 0x7008)
                and thumb_literal_value(image, position - 4, 1)
                == tick_position | 1
                and struct.unpack_from("<H", image, position - 2)[0]
                == 0x201C):
            arms.append(arm)
    return arms[0] if len(arms) == 1 else None


def find_rex_5ms_irq_route(
        image: bytes, tick_position: int,
        map_position=None) -> tuple[int, int, int, int, int, int, int] | None:
    """Bind one 5 ms callback to its complete old Qualcomm IRQ route."""
    runtime = map_position or (lambda position: position)
    tick_address = runtime(tick_position)
    if tick_address is None:
        return None
    delta = tick_address - tick_position

    def runtime_code(position: int) -> int | None:
        address = runtime(position)
        return address if address == position + delta else None

    walker = rex_5ms_callback_at(image, tick_position)
    if (walker is None or runtime_code(walker) is None
            or not rex_timer_advance_at(image, walker)):
        return None
    callback_targets = tuple(
        thumb_bl_target(image, tick_position + item)
        for item in (2, 14, 20, 42, 50, 58)
    )
    if any(target is None or not 0 <= target < len(image)
           or runtime_code(target) is None
           for target in callback_targets):
        return None
    lock = thumb_bl_target(image, walker + 4)
    expiry = thumb_bl_target(image, walker + 42)
    unlock = thumb_bl_target(image, walker + 64)
    if (lock is None or expiry is None or unlock is None
            or any(runtime_code(target) is None
                   for target in (lock, expiry, unlock))
            or callback_targets[0] != lock
            or callback_targets[3] != walker
            or callback_targets[5] != unlock
            or image[lock:lock + len(REX_INTLOCK_SIGNATURE)]
            != REX_INTLOCK_SIGNATURE
            or image[unlock:unlock + len(REX_INTFREE_SIGNATURE)]
            != REX_INTFREE_SIGNATURE
            or not 0 <= expiry <= len(image) - 60):
        return None
    expiry_words = struct.unpack_from("<30H", image, expiry)
    if not (
        expiry_words[:3] == (0xB5F0, 0x1C0E, 0x1C07)
        and thumb_bl_target(image, expiry + 6) == lock
        and expiry_words[5:12] == (
            0x68FC, 0x1C05, 0x1C20, 0x4330, 0x60F8, 0x6938, 0x4030,
        )
        and expiry_words[12] & 0xFF00 == 0xD000
        and expiry_words[13:16] == (0x2000, 0x6138, 0x4807)
        and expiry_words[16:21] == (
            0x6979, 0x6882, 0x6952, 0x4291, 0xD902,
        )
        and expiry_words[21] == 0x6087
        and (target := thumb_bl_target(image, expiry + 44)) is not None
        and 0 <= target < len(image)
        and runtime_code(target) is not None
        and expiry_words[24:26] == (0x2D00, 0xD101)
        and thumb_bl_target(image, expiry + 52) == unlock
        and expiry_words[28:] == (0x1C20, 0xBDF0)
    ):
        return None
    consumers: list[tuple[int, int, int, int]] = []
    offset = 0
    while (offset := image.find(b"\x90\xb5\x08\x48", offset)) >= 0:
        result = trampm5_consumer_at(image, offset)
        if result is not None:
            consumers.append((offset, *result))
        offset += 2
    if len(consumers) != 1:
        return None
    consumer, q_get, thunk, queue = consumers[0]
    if any(runtime_code(target) is None
           for target in (consumer, q_get, thunk)):
        return None

    enqueue_matches: list[int] = []
    enqueue_layouts = (
        (bytes.fromhex("04043879240c002809d0"), 24, 32, 46, 54, 62, 0x48),
        (bytes.fromhex("04043879240c002808d0"), 22, 30, 44, 52, 60, 0x4C),
    )
    offset = 0
    while (offset := image.find(b"\x90\xb5\x07\x1c", offset)) >= 0:
        for (signature, get_at, unlock_a, unlock_b,
             put_stub_at, put_at, queue_at) in enqueue_layouts:
            q_put = thumb_bl_target(image, offset + put_at)
            enqueue_targets = tuple(
                thumb_bl_target(image, offset + item)
                for item in (get_at, put_stub_at, put_at)
            )
            if (offset + queue_at + 4 <= len(image)
                    and runtime_code(offset) is not None
                    and image[offset + 8:offset + 18] == signature
                    and thumb_bl_target(image, offset + 4) == lock
                    and thumb_bl_target(image, offset + unlock_a) == unlock
                    and thumb_bl_target(image, offset + unlock_b) == unlock
                    and all(target is not None and 0 <= target < len(image)
                            and runtime_code(target) is not None
                            for target in enqueue_targets)
                    and q_put is not None
                    and runtime_code(q_put) is not None
                    and image[q_put:q_put + 6] == b"\x90\xb5\x0c\x1c\x07\x1c"
                    and thumb_bl_target(image, q_put + 6) == lock
                    and struct.unpack_from("<I", image, offset + queue_at)[0]
                    == queue):
                enqueue_matches.append(offset)
        offset += 2
    if len(enqueue_matches) != 1:
        return None
    enqueue = enqueue_matches[0]
    producer = callback_targets[4]
    if (producer is None or not 0 <= producer <= len(image) - 0x54
            or runtime_code(producer) is None
            or image[producer:producer + 6] != b"\xf8\xb5\x0c\x1c\x07\x1c"
            or not all((target := thumb_bl_target(image, producer + item))
                       is not None and 0 <= target < len(image)
                       and runtime_code(target) is not None
                       for item in (6, 42, 68))
            or thumb_bl_target(image, producer + 6) != lock
            or image[producer + 10:producer + 42] != bytes.fromhex(
                "0004000c00907868002824d08168091b81601de07868041c0069a168451a201c"
            )
            or image[producer + 46:producer + 68] != bytes.fromhex(
                "6069e668002808d02061a060207e002800d16061201c"
            )
            or image[producer + 72:producer + 80]
            != bytes.fromhex("a562e01d15306662")
            or thumb_bl_target(image, producer + 80) != enqueue):
        return None

    candidates: list[tuple[int, int, int, int, int, int, int]] = []
    for match in REX_IRQ_DRAIN_PATTERN.finditer(image):
        tail = match.start()
        handler = tail - 0x34
        if (handler < 0
                or image[handler:handler + 4] != b"\xf0\xb5\x86\xb0"
                or thumb_bl_target(image, tail + 16) != consumer
                or handler + REX_IRQ_HANDLER_RUNTIME_SIZE > len(image)):
            continue
        (summary, status, nesting, summary_high, groups,
         descriptors, enable) = struct.unpack_from(
            "<7I", image, handler + 0x154
        )
        if (summary_high != summary + 8
                or descriptors != summary + 0xC
                or groups != descriptors + 0x1D * 0x1C
                or status & 3 or enable != status + 8
                or not 0x03000000 <= status < 0x04000000
                or struct.unpack_from("<I", image, handler + 0x170)[0]
                != enable + 4):
            continue
        handler_address = runtime_code(handler)
        if handler_address is None:
            continue
        default_position = handler - 0x38
        default_address = (runtime_code(default_position)
                           if 0 <= default_position < len(image) else None)
        if default_address is None:
            continue
        handler_literal = handler + 0x1D4
        if (struct.unpack_from("<I", image, handler_literal)[0]
                != handler_address | 1
                or struct.unpack_from("<I", image, handler_literal + 4)[0]
                != queue):
            continue
        registration = handler_literal - 0x22
        if (runtime_code(registration) is None
                or thumb_literal_value(image, registration, 1)
                != handler_address | 1
                or struct.unpack_from("<H", image, registration + 2)[0]
                != 0x2000):
            continue
        setter = thumb_bl_target(image, registration + 4)
        if (setter is None or not 0 <= setter <= len(image) - 20
                or runtime_code(setter) is None):
            continue
        if not (
            image[setter:setter + 2] == b"\x02\x1c"
            and image[setter + 4:setter + 8] == b"\x01\xd1\xc1\x60"
            and image[setter + 8:setter + 14]
            == b"\xf7\x46\x01\x61\xf7\x46"
        ):
            continue
        root = thumb_literal_value(image, setter + 2, 0)
        if root is None or nesting != root + 0x14:
            continue

        wrappers: list[int] = []
        wrapper_body = REX_IRQ_WRAPPER_SIGNATURE[4:]
        wrapper = 0
        while (wrapper := image.find(wrapper_body, wrapper)) >= 0:
            entry = wrapper - 4
            wrapper_address = runtime_code(wrapper)
            entry_address = runtime_code(entry)
            if (entry >= 0 and not entry & 3 and not wrapper & 3
                    and wrapper_address is not None
                    and entry_address is not None
                    and not wrapper_address & 3 and not entry_address & 3
                    and wrapper + 0x25C <= len(image)
                    and image[entry:wrapper] == REX_IRQ_WRAPPER_SIGNATURE[:4]
                    and tuple(struct.unpack_from("<I", image, wrapper + item)[0]
                              for item in (0x240, 0x244, 0x250, 0x254))
                    == (nesting, root + 0xC, root + 4, root + 8)
                    and tuple(struct.unpack_from(
                        "<I", image, wrapper + item
                    )[0] for item in (0x248, 0x24C, 0x258))
                    == (wrapper_address + 0x3C, wrapper_address + 0x40,
                        wrapper_address + 0x168)):
                wrappers.append(entry)
            wrapper += 4
        if len(wrappers) != 1:
            continue

        registration_targets: list[int] = []
        for position in range(0, len(image) - 8, 2):
            if (runtime_code(position) is not None
                    and thumb_literal_value(image, position, 1)
                    == tick_address | 1
                    and struct.unpack_from("<H", image, position + 2)[0]
                    == 0x201C):
                target = thumb_bl_target(image, position + 4)
                if (target is not None and 0 <= target < len(image)
                        and runtime_code(target) is not None):
                    registration_targets.append(target)
        if (len(registration_targets) != 3
                or len(set(registration_targets)) != 1):
            continue
        registrar = registration_targets[0]
        if (not 0 <= registrar <= len(image) - 0x70
                or runtime_code(registrar) is None):
            continue
        words = struct.unpack_from("<23H", image, registrar)
        registrar_lock = thumb_bl_target(image, registrar + 6)
        if not (
            words[:3] == (0xB5F0, 0x1C04, 0x1C0F)
            and registrar_lock == lock
            and runtime_code(registrar_lock) is not None
            and image[registrar_lock:registrar_lock + len(REX_INTLOCK_SIGNATURE)]
            == REX_INTLOCK_SIGNATURE
            and words[5:7] == (0x1C05, 0x2F00)
            and words[8:14] == (0xD100, 0x1C37, 0x2C00,
                                0xDB01, 0x2C1D, 0xDB03)
            and words[18:20] == (0x201C, 0x4360)
            and words[21:23] == (0x1840, 0x6147)
            and thumb_literal_value(image, registrar + 40, 1) == descriptors
        ):
            if not (
                words[8:13] == (0xD100, 0x1C37, 0x2C00,
                                 0xDB01, 0x2C1D)
                and words[13] == 0xDB04
                and thumb_literal_value(image, registrar + 42, 1)
                == descriptors
            ):
                continue
        if (thumb_literal_value(image, registrar + 14, 6)
                != default_address | 1):
            continue
        initializer = struct.pack(
            "<8I", status, enable, 0x0200, summary, summary + 4,
            default_address | 1, 0, 4,
        )
        if image.count(initializer) != 1:
            continue
        indirect_calls = tuple(
            thumb_bl_target(image, handler + item) for item in (0xEA, 0x112)
        )
        if (image[handler + 0xE8:handler + 0xEA] != b"\x78\x69"
                or image[handler + 0x110:handler + 0x112] != b"\x78\x69"
                or any(target is None or not 0 <= target < len(image)
                       or runtime_code(target) is None
                       or image[target:target + 2] != b"\x00\x47"
                       for target in indirect_calls)):
            continue
        wrapper_address = runtime_code(wrappers[0])
        if wrapper_address is None:
            continue
        candidates.append((
            wrapper_address, handler_address, root + 0xC,
            descriptors + 0x1C * 0x1C + 0x14,
            status, enable, 0x0200,
        ))
    return candidates[0] if len(candidates) == 1 else None


def find_rex_5ms_sleep_timer(image: bytes) -> tuple[int, int, int] | None:
    """Find a unique post-sleep hook and its proven 5 ms IRQ callback."""
    sleep_calls: list[int] = []
    offset = 0
    sleep_anchor = bytes.fromhex("2078012806d1")
    while (offset := image.find(sleep_anchor, offset)) >= 0:
        call = rex_sleep_call_at(image, offset - 2)
        if call is not None:
            sleep_calls.append(call)
        offset += 2

    tick_callbacks: list[int] = []
    offset = 0
    while (offset := image.find(REX_5MS_WRAPPER_ANCHOR, offset)) >= 0:
        callback = offset - 24
        target = rex_5ms_callback_at(image, callback)
        if target is not None and rex_timer_advance_at(image, target):
            tick_callbacks.append(callback)
        offset += 2
    sleep_calls = list(dict.fromkeys(sleep_calls))
    tick_callbacks = list(dict.fromkeys(tick_callbacks))
    if len(sleep_calls) == len(tick_callbacks) == 1:
        # The controller BL must execute.  Hook its return address, then invoke
        # the firmware-installed callback before the following CMP runs.
        return sleep_calls[0] + 4, tick_callbacks[0], 5
    return None


def find_rex_idle_address(image: bytes) -> int | None:
    """Find the final idle BL in the old Qualcomm REX signal loop."""
    candidates: list[int] = []
    fixed = {
        0: 0x0BC1, 1: 0xD306, 2: 0x2108, 6: 0x2101, 7: 0x0389,
        8: 0xE007, 9: 0x0B81, 10: 0xD309, 11: 0x2108,
        15: 0x2101, 16: 0x0349, 20: 0xE7D8, 21: 0x0A80,
        22: 0xD302, 25: 0xE7D3,
    }
    anchor = struct.pack("<3H", fixed[0], fixed[1], fixed[2])
    offset = 0
    while (offset := image.find(anchor, offset)) >= 0:
        if offset & 1 or offset + 52 > len(image):
            offset += 1
            continue
        words = struct.unpack_from("<26H", image, offset)
        if any(words[index] != value for index, value in fixed.items()):
            offset += 2
            continue
        if any(words[index] & 0xFFC7 != 0x1C00 for index in (3, 12, 17)):
            offset += 2
            continue
        if any(not (words[index] & 0xF800 == 0xF000
                    and words[index + 1] & 0xF800 == 0xF800)
               for index in (4, 13, 18, 23)):
            offset += 2
            continue
        idle = offset + 52
        last_bl: int | None = None
        for address in range(idle, min(len(image), idle + 0x80), 2):
            word = struct.unpack_from("<H", image, address)[0]
            following = (struct.unpack_from("<H", image, address + 2)[0]
                         if address + 4 <= len(image) else 0)
            if word & 0xF800 == 0xF000 and following & 0xF800 == 0xF800:
                last_bl = address
                continue
            if word & 0xF800 != 0xE000:
                continue
            displacement = (word & 0x7FF) * 2
            if displacement & 0x800:
                displacement -= 0x1000
            if address + 4 + displacement <= offset:
                if last_bl is not None and last_bl + 4 == address:
                    candidates.append(last_bl)
                break
        offset += 2
    return candidates[0] if len(candidates) == 1 else None


def detect_input_profile(image: bytes, load_address: int = 0
                         ) -> tuple[str, int, int | None] | None:
    """Locate LG/Samsung input signatures for diagnostics only."""
    lg_matches = list(LG_INPUT_PATTERN.finditer(image))
    if len(lg_matches) == 1:
        wrapper = lg_matches[0].start()
        decoder = thumb_bl_target(image, wrapper + 2)
        drain = thumb_bl_target(image, wrapper + 6)
        enqueue = decoder + 0x6C if decoder is not None else -1
        if (drain is not None
                and image[enqueue:enqueue + len(LG_DECODED_ENQUEUE_SIGNATURE)]
                == LG_DECODED_ENQUEUE_SIGNATURE):
            return "lg-decoded", load_address + enqueue, load_address + drain

    samsung_matches = list(SAMSUNG_INPUT_PATTERN.finditer(image))
    if len(samsung_matches) == 1:
        match = samsung_matches[0].start()
        for entry in range(match & ~1, max(-1, match - 0xC0), -2):
            if image[entry:entry + 4] in (b"\x80\xb5\x07\x1c",
                                           b"\xb0\xb5\x07\x1c"):
                return "samsung-queue", load_address + entry, None
    return None


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


BOARD_STATUS_INPUT_BODY = bytes.fromhex(
    "007808231840082801d1012100e00021002700260124002936484ad0"
)


def find_board_status_input(image: bytes) -> BoardStatusInput | None:
    """Accept one unique Thumb byte-status mask/branch/debounce control shape."""
    found: set[BoardStatusInput] = set()
    offset = 0
    while (offset := image.find(b"\xf0\xb5", offset)) >= 0:
        address = thumb_literal_value(image, offset + 2, 0)
        candidate = (BoardStatusInput(address, 0x08, 0x08)
                     if address is not None
                     and 0x03000000 <= address < 0x03800000 else None)
        if (image[offset + 4:offset + 4 + len(BOARD_STATUS_INPUT_BODY)]
                == BOARD_STATUS_INPUT_BODY):
            if candidate is not None:
                found.add(candidate)
        elif candidate is not None and image[offset + 4:offset + 6] == b"\x00\x78":
            body_end = min(offset + 0x400, len(image) - 1)
            pop = next((position for position in range(offset + 6, body_end, 2)
                        if struct.unpack_from("<H", image, position)[0] == 0xBDF0),
                       None)
            early_end = min(offset + 0x100, pop if pop is not None else offset)
            debounced = (pop is not None
                         and b"\x5f\x27" in image[offset + 6:pop]
                         and b"\x60\x27" in image[offset + 6:pop])
            for movs in range(offset + 6, early_end, 2):
                move = struct.unpack_from("<H", image, movs)[0]
                if move & 0xF8FF != 0x2008:
                    continue
                mask_register = (move >> 8) & 7
                if mask_register == 0:
                    continue
                for ands in range(movs + 2, min(movs + 10, early_end), 2):
                    word = struct.unpack_from("<H", image, ands)[0]
                    if word & 0xFFC0 != 0x4000:
                        continue
                    result = word & 7
                    source = (word >> 3) & 7
                    if {result, source} != {0, mask_register}:
                        continue
                    compare = 0x2808 | (result << 8)
                    for position in range(ands + 2, min(ands + 16, early_end), 2):
                        if struct.unpack_from("<H", image, position)[0] != compare:
                            continue
                        for branch in range(position + 2,
                                            min(position + 8, early_end), 2):
                            if struct.unpack_from("<H", image, branch)[0] & 0xFF00 != 0xD100:
                                continue
                            if (debounced and all(
                                    (word := struct.unpack_from("<H", image, delay)[0])
                                    == 0xBF00 or word & 0xF800 == 0x4800
                                    for delay in range(position + 2, branch, 2))):
                                found.add(candidate)
                        break
        offset += 2
    return next(iter(found)) if len(found) == 1 else None


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
    key_register: int
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

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["file_size_hex"] = f"0x{self.file_size:X}"
        return result

    def firmware_identity(self) -> dict[str, object]:
        """Return shareable firmware identity without its local path."""
        basename = self.path.replace("\\", "/").rsplit("/", 1)[-1] or "firmware"
        return {
            "basename": basename,
            "bytes": self.file_size,
            "sha256": self.firmware_sha256,
        }

    def diagnostic_config(self) -> dict[str, object]:
        """Return technical detection data safe to put in a user log."""
        result = self.to_dict()
        for field in (
                "path", "flash_state", "secondary_flash_image",
                "secondary_flash_state", "nand_image"):
            result.pop(field, None)
        result["firmware"] = self.firmware_identity()
        return result


def _image_offset(address: int, image_size: int, load_address: int) -> int | None:
    if load_address and load_address <= address < load_address + image_size:
        return address - load_address
    if 0 <= address < image_size:
        return address
    return None


def find_linker_layout(image: bytes, load_address: int = 0) -> LinkerLayout | None:
    """Find Qualcomm scatter-load data/BSS tuple without model addresses."""
    limit = min(len(image) - 20, 0x20000)
    preferred = (0x10028,)
    offsets = (*preferred, *(range(0, limit + 1, 4)))
    seen: set[int] = set()
    for offset in offsets:
        if offset in seen or offset + 20 > len(image):
            continue
        seen.add(offset)
        source_address, target, size, bss, bss_size = struct.unpack_from(
            "<5I", image, offset
        )
        source = _image_offset(source_address, len(image), load_address)
        valid = (
            source is not None
            and 0 < size <= 0x800000
            and source + size <= len(image)
            # The supported MSM5000/5100/5500 boards expose external SDRAM in
            # the 0x01000000 or 0x01800000 8 MiB bank.  Repeated 0x00800000 /
            # 0x00010000 tables in resources are not scatter-load metadata.
            and 0x01000000 <= target < 0x02000000
            and target + size == bss
            and 0 < bss_size <= 0x2000000
            and bss + bss_size <= 0x08000000
        )
        if valid:
            return LinkerLayout(offset, source, target, size, bss, bss_size)
    return None


def find_overlays(image: bytes, load_address: int = 0) -> list[CopyLayout]:
    """Find boot tables that relocate MSM internal-RAM executable overlays."""
    found: list[CopyLayout] = []
    for offset in range(0, min(len(image) - 12, 0x20000) + 1, 4):
        source_address, target, size = struct.unpack_from("<3I", image, offset)
        source = _image_offset(source_address, len(image), load_address)
        internal_ram = 0x03800000 <= target < 0x03A00000 and target % PAGE == 0
        runtime_rom = (0x01400000 <= target < 0x01800000
                       and target % PAGE == 0 and source is not None
                       and 0 < source - offset <= 0x40)
        if (source is not None and 0x100 <= size <= 0x200000
                and source + size <= len(image) and (internal_ram or runtime_rom)):
            candidate = CopyLayout(offset, source, target, size)
            if not any(item.target == target and item.size == size for item in found):
                found.append(candidate)
    return found


def find_missing_overlays(image: bytes, flash_size: int,
                          load_address: int = 0) -> list[CopyLayout]:
    """Find boot copy entries whose executable ROM source was not dumped."""
    found: list[CopyLayout] = []
    for offset in range(0, min(len(image) - 12, 0x20000) + 1, 4):
        source_address, target, size = struct.unpack_from("<3I", image, offset)
        source = source_address - load_address
        if (0x1000 <= source < flash_size
                and source > offset + 0x20
                and 0x03800000 <= target < 0x03A00000
                and target % PAGE == 0
                and 0x100 <= size <= 0x200000
                and source + size <= flash_size
                and source + size > len(image)):
            candidate = CopyLayout(offset, source, target, size)
            if candidate not in found:
                found.append(candidate)
    return found


def find_runtime_overlays(image: bytes, ram_base: int,
                          ram_size: int) -> list[CopyLayout]:
    """Find executable overlays whose source must first be loaded into SDRAM.

    Several later Samsung builds keep an application/DSP partition in NAND,
    load it into external RAM, then copy a small executable bank into MSM
    internal RAM.  Such a tuple must not be mistaken for a NOR file offset.
    """
    found: list[CopyLayout] = []
    ram_end = ram_base + ram_size
    for offset in range(0, min(len(image) - 12, 0x40000) + 1, 4):
        source, target, size = struct.unpack_from("<3I", image, offset)
        if (ram_base <= source < source + size <= ram_end
                and 0x03800000 <= target < target + size <= 0x03A00000
                and source & 1 == 0 and target & 1 == 0
                and 0x100 <= size <= 0x200000):
            candidate = CopyLayout(offset, source, target, size)
            if candidate not in found:
                found.append(candidate)
    return found


def find_arm_memory_copy_addresses(image: bytes, overlays: list[CopyLayout],
                                   linker: LinkerLayout | None = None,
                                   load_address: int = 0) -> list[int]:
    """Locate the validated ARM copier in ROM and every proven runtime copy.

    The instruction hook performs its own full prefix/tail, CPU-state, source,
    destination, and overlap validation.  Discovery can therefore include all
    aligned exact bodies in primary NOR instead of assuming the copier always
    lives in an internal-RAM overlay; several MSM5000/5100 BSPs call it from
    ROM or from the linker-relocated data bank.
    """
    found: set[int] = set()
    for position in find_all(image, ARM_MEMORY_COPY_SIGNATURE):
        if (position & 3
                or image[position + ARM_MEMORY_COPY_TAIL_OFFSET:
                         position + ARM_MEMORY_COPY_TAIL_OFFSET
                         + len(ARM_MEMORY_COPY_TAIL)] != ARM_MEMORY_COPY_TAIL):
            continue
        found.add(load_address + position)
        if (linker is not None
                and linker.data_source <= position
                < linker.data_source + linker.data_size):
            found.add(linker.data_target + position - linker.data_source)
        for overlay in overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                found.add(overlay.target + position - overlay.source)
    return sorted(found)


def detect(path: Path, overrides: argparse.Namespace | None = None) -> FirmwareConfig:
    raw = path.read_bytes()
    requested_image_offset = (getattr(overrides, "image_offset", None)
                              if overrides else None)
    vector_offset, vector_score = find_arm_vector_offset(raw)
    image_offset = (vector_offset if requested_image_offset is None
                    and vector_score >= 4 else requested_image_offset or 0)
    if not 0 <= image_offset < len(raw):
        raise ValueError(f"image offset outside firmware: 0x{image_offset:X}")
    # Keep the complete capture for model strings, EFS discovery, and an
    # optional RAM seed.  Code/layout discovery must only inspect primary NOR:
    # full dumps commonly append a live RAM snapshot containing copied code.
    image = raw[image_offset:]
    requested_load_address = (getattr(overrides, "load_address", None)
                              if overrides else None)
    requested_load_address = 0 if requested_load_address is None else requested_load_address
    if not 0 <= requested_load_address < ADDRESS_SPACE:
        raise ValueError("load address outside 32-bit address space")
    model = detect_model(image, path)
    chipset = detect_chipset(image, model)
    confidence = chipset_confidence(image, chipset)
    vector_score = arm_vector_score(image)
    image_kind = "firmware" if vector_score >= 2 else "data/non-bootable"
    detection_notes: list[str] = []
    if image_kind != "firmware":
        detection_notes.append("no valid ARM exception vector table")
    elif image_offset and requested_image_offset is None:
        detection_notes.append(
            f"skipped 0x{image_offset:X}-byte dump header before ARM vectors"
        )
    if confidence == "unknown":
        detection_notes.append("no generation-specific clock/boot BSP marker")
    if chipset == "MSM6050":
        detection_notes.append("MSM6050 is outside the supported 5000/5100/5500 scope")
    scan_chipset = ((getattr(overrides, "chipset", None) if overrides else None)
                    or chipset)
    scan_ram_base = (getattr(overrides, "ram_base", None)
                     if overrides else None)
    if scan_ram_base is None:
        scan_ram_base = (0x01000000
                         if scan_chipset in ("MSM5000", "MSM5500")
                         else 0x01800000)
    requested_flash_size = (getattr(overrides, "flash_size", None)
                            if overrides else None)
    required_flash_extent = referenced_flash_extent(
        image, requested_load_address
    )
    if requested_flash_size is None:
        scan_limit = (scan_ram_base - requested_load_address
                      if scan_ram_base > requested_load_address
                      else min(MAX_FLASH_SIZE,
                               ADDRESS_SPACE - requested_load_address))
        scan_flash_size = normalised_flash_size(
            max(len(image), required_flash_extent),
            min(MAX_FLASH_SIZE, scan_limit),
        )
    else:
        if requested_flash_size <= 0:
            raise ValueError("flash size must be positive")
        scan_flash_size = requested_flash_size
    primary_image = image[:min(len(image), scan_flash_size)]
    board_status_input = find_board_status_input(primary_image)
    if board_status_input is not None:
        detection_notes.append(
            "Thumb byte-status mask/branch/debounce shape detected board-status input"
        )
    width, height = KNOWN_SCREENS.get(model, (176, 220))
    revision_match = re.search(rb"(?:HW|BOARD)[ _-]?REV(?:ISION)?[^\x00\r\n]{0,24}", image, re.I)
    revision = revision_match.group().decode("ascii", "replace") if revision_match else "auto/unknown"
    auto_relative: set[str] = set()

    def direct_signature(field: str, signature: bytes) -> int | None:
        position = primary_image.find(signature)
        if (position < 0
                or primary_image.find(signature, position + 1) >= 0):
            return None
        auto_relative.add(field)
        return position

    linker = find_linker_layout(primary_image, requested_load_address)
    audio_address = direct_signature("audio_play_address", AUDIO_PLAY_SIGNATURE)
    fast_boot_address = direct_signature("fast_boot_address", FAST_BOOT_SIGNATURE)
    delay_address = direct_signature("delay_address", DELAY_SIGNATURE)
    busy_delay_address = direct_signature("busy_delay_address", BUSY_DELAY_SIGNATURE)
    rex_tick_address = direct_signature("rex_tick_address", REX_TICK_SIGNATURE)
    rex_idle_address = find_rex_idle_address(primary_image)
    rex_irq_route = None
    rex_irq_arm_address = None
    rex_tick_ms = 1000
    if rex_idle_address is not None:
        auto_relative.add("rex_idle_address")
    rex_5ms_pair = (find_rex_5ms_sleep_timer(primary_image)
                    if rex_idle_address is None and rex_tick_address is None
                    else None)
    if rex_5ms_pair is not None:
        rex_idle_address, rex_tick_address, rex_tick_ms = rex_5ms_pair
    board_adc_address = direct_signature("board_adc_address", BOARD_ADC_SIGNATURE)
    board_adc_reader_position = find_board_adc_reader(primary_image)
    overlays = find_overlays(primary_image, requested_load_address)

    def mapped_position(position: int) -> tuple[int | None, bool]:
        if position < 0:
            return None, False
        for overlay in overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                return overlay.target + position - overlay.source, False
        if (linker is not None
                and linker.data_source <= position < linker.data_source + linker.data_size):
            return linker.data_target + position - linker.data_source, False
        return position, True

    def runtime_position(field: str, position: int) -> int | None:
        address, relative = mapped_position(position)
        if address is not None and relative:
            auto_relative.add(field)
        return address

    def mapped_runtime(position: int) -> int | None:
        address, relative = mapped_position(position)
        if address is not None and relative:
            address += requested_load_address
        return address

    board_adc_reader_address = (
        runtime_position("board_adc_reader_address", board_adc_reader_position)
        if board_adc_reader_position is not None else None
    )
    if board_adc_reader_address is not None:
        detection_notes.append(
            "Thumb ADC reader shape and channel-gated MMIO data path detected"
        )

    if rex_5ms_pair is not None:
        idle_position, tick_position, rex_tick_ms = rex_5ms_pair
        rex_idle_address = mapped_runtime(idle_position)
        rex_tick_address = mapped_runtime(tick_position)
        rex_irq_route = find_rex_5ms_irq_route(
            primary_image, tick_position, mapped_runtime
        )
        detection_notes.append(
            "REX sleep loop and periodic wrapper prove 5 ms timer-list advance"
        )
        if rex_irq_route is not None:
            rex_irq_arm_address = find_rex_5ms_irq_arm(
                primary_image, tick_position
            )
            detection_notes.append(
                "REX IRQ wrapper/controller route proves firmware 5 ms delivery"
            )

    def runtime_signature(field: str, signature: bytes) -> int | None:
        position = primary_image.find(signature)
        if (position < 0
                or primary_image.find(signature, position + 1) >= 0):
            return None
        return runtime_position(field, position)

    ma2_wait = find_ma2_silent_boot_wait(primary_image)
    ma2_silent_boot_address = (
        runtime_position("ma2_silent_boot_address", ma2_wait)
        if ma2_wait is not None else None
    )
    if ma2_silent_boot_address is not None:
        detection_notes.append(
            "Yamaha MA2 silent boot stub detected; status-wait calls return "
            "success without device emulation"
        )

    framebuffer = find_framebuffer_layout(primary_image)
    framebuffer_address = None
    framebuffer_stride = 0
    framebuffer_format = "none"
    framebuffer_flush_address = None
    framebuffer_rect_flush_address = None
    if framebuffer is not None:
        width, height, framebuffer_address, framebuffer_stride, row, rect = framebuffer
        framebuffer_format = "rgb565le"
        framebuffer_flush_address = runtime_position("framebuffer_flush_address", row)
        framebuffer_rect_flush_address = runtime_position(
            "framebuffer_rect_flush_address", rect
        )

    nand_bad_block_address = runtime_signature("nand_bad_block_address",
                                               NAND_BAD_BLOCK_SIGNATURE)
    nand_read_address = runtime_signature("nand_read_address", NAND_READ_SIGNATURE)
    nand_write_address = runtime_signature("nand_write_address", NAND_WRITE_SIGNATURE)
    flash_id_address = runtime_signature("flash_id_address", FLASH_ID_SIGNATURE)
    crc16_address = runtime_signature("crc16_address", CRC16_SIGNATURE)
    dmd_download_address = runtime_signature("dmd_download_address",
                                             DMD_DOWNLOAD_SIGNATURE)
    primary_flash_probe_address = runtime_signature(
        "primary_flash_probe_address", PRIMARY_FLASH_PROBE_SIGNATURE
    )
    secondary_flash_read_address = None
    secondary_flash_write_address = None
    legacy_efs_page_read_address = runtime_signature(
        "legacy_efs_page_read_address", LEGACY_EFS_PAGE_READ_SIGNATURE
    )
    wrapper_offset = 0
    wrapper_reads: list[int] = []
    wrapper_writes: list[int] = []
    while match := SECONDARY_FLASH_WRAPPER_PATTERN.search(
            primary_image, wrapper_offset):
        if match.group("dispatch") == b"\xc3\x6b":
            wrapper_reads.append(match.start())
        else:
            wrapper_writes.append(match.start())
        wrapper_offset = match.start() + 2
    if len(wrapper_reads) == 1:
        secondary_flash_read_address = runtime_position(
            "secondary_flash_read_address", wrapper_reads[0])
    if len(wrapper_writes) == 1:
        secondary_flash_write_address = runtime_position(
            "secondary_flash_write_address", wrapper_writes[0])
    legacy_read = runtime_signature(
        "secondary_flash_read_address", LEGACY_SECONDARY_FLASH_READ_SIGNATURE
    )
    legacy_write = runtime_signature(
        "secondary_flash_write_address", LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE
    )
    if secondary_flash_read_address is None:
        secondary_flash_read_address = legacy_read
    if secondary_flash_write_address is None:
        secondary_flash_write_address = legacy_write
    if secondary_flash_write_address is None:
        bulk_write = find_fujitsu_x16_bulk_write(
            primary_image, requested_load_address + scan_flash_size
        )
        if bulk_write is not None:
            secondary_flash_write_address = runtime_position(
                "secondary_flash_write_address", bulk_write
            )
            detection_notes.append(
                "Fujitsu x16 bulk writer proves adjacent secondary NOR command bus"
            )
    eeprom_read_address = None
    eeprom_write_address = None
    eeprom_geometry_address = None
    eeprom_driver = find_24lcxx_driver(primary_image)
    if eeprom_driver is not None:
        eeprom_read, eeprom_write, eeprom_geometry_address = eeprom_driver
        eeprom_read_address = runtime_position(
            "eeprom_read_address", eeprom_read
        )
        eeprom_write_address = runtime_position(
            "eeprom_write_address", eeprom_write
        )
        detection_notes.append(
            "24LCxx EEPROM read/write driver and geometry descriptor detected"
        )
    clear_positions = [
        *find_all(primary_image, MEMORY_CLEAR_LOOP_SIGNATURE),
        *find_all(primary_image, MEMORY_CLEAR_128_SIGNATURE),
    ]
    clear_layout = [mapped_position(position)
                    for position in dict.fromkeys(clear_positions)]
    copy_layout = [mapped_position(position)
                   for position in find_all(primary_image,
                                            MEMORY_COPY_LOOP_SIGNATURE)]
    ramp_layout = [mapped_position(position + len(REGISTER_RAMP_PREFIX))
                   for position in find_all(primary_image, REGISTER_RAMP_PREFIX)]
    memory_clear_addresses = [address for address, _relative in clear_layout
                              if address is not None]
    memory_copy_addresses = [address for address, _relative in copy_layout
                             if address is not None]
    register_ramp_addresses = [address for address, _relative in ramp_layout
                               if address is not None]
    arm_memory_copy_addresses = find_arm_memory_copy_addresses(
        primary_image, overlays, linker, requested_load_address
    )
    # Some Samsung/LG builds inline the raw small-page NAND primitives, so no
    # standalone function signature survives.  The filesystem driver marker
    # plus all three physical command/address/data port literals is a stronger
    # board-level condition than any model-name guess.
    raw_nand_ports = (
        b"fs_ks_nand.c" in primary_image.lower()
        and all(struct.pack("<I", port) in primary_image
                for port in (0x01800000, 0x01900000, 0x01A00000))
    )
    nand_enabled = (raw_nand_ports or any(item is not None for item in (
        nand_bad_block_address, nand_read_address, nand_write_address
    )))
    if raw_nand_ports and all(item is None for item in (
            nand_bad_block_address, nand_read_address, nand_write_address)):
        detection_notes.append(
            "raw NAND enabled from fs_ks_nand driver and physical port literals"
        )
    needs_msm_revision = (b" Unsupported MSM REV " in primary_image
                          and struct.pack("<I", MSM_REVISION_BLOCK)
                          in primary_image)
    ram_base = infer_ram_base(linker, chipset, primary_image)
    requested_ram_base = (getattr(overrides, "ram_base", None)
                          if overrides else None)
    if requested_ram_base is not None:
        ram_base = requested_ram_base
    flash_size = normalised_flash_size(
        max(len(image), required_flash_extent), ram_base
    )
    default_flash_state, default_secondary_state = default_state_paths(
        path, image, flash_size, flash_size
    )
    config = FirmwareConfig(
        path=str(path), file_size=len(raw),
        firmware_sha256=hashlib.sha256(raw).hexdigest(), model=model, chipset=chipset,
        chipset_confidence=confidence, image_kind=image_kind,
        dump_status="pending", detection_notes=detection_notes,
        width=width, height=height, board_revision=revision,
        framebuffer_address=framebuffer_address,
        framebuffer_stride=framebuffer_stride,
        framebuffer_format=framebuffer_format,
        framebuffer_flush_address=framebuffer_flush_address,
        framebuffer_rect_flush_address=framebuffer_rect_flush_address,
        board_revision_register=(0x00DFFFDC if model == "SCH-E470"
                                 else MSM_REVISION_REGISTER
                                 if needs_msm_revision else None),
        board_revision_value=(0x1D if model == "SCH-E470"
                              else MSM_REVISION_RAW_F022
                              if needs_msm_revision else None),
        board_status_input=board_status_input,
        image_offset=image_offset, load_address=0,
        flash_size=flash_size,
        secondary_flash_address=None, secondary_flash_size=flash_size,
        secondary_flash_image=None,
        secondary_flash_state=default_secondary_state,
        secondary_flash_read_address=secondary_flash_read_address,
        secondary_flash_write_address=secondary_flash_write_address,
        legacy_efs_page_read_address=legacy_efs_page_read_address,
        eeprom_read_address=eeprom_read_address,
        eeprom_write_address=eeprom_write_address,
        eeprom_geometry_address=eeprom_geometry_address,
        ram_base=ram_base,
        ram_size=0x00800000, ram_image_offset=flash_size,
        ram_image_size=plausible_ram_seed_size(len(image), flash_size), entry=0,
        key_register=0x03000738, key_active_low=True,
        audio_play_address=audio_address,
        ma2_silent_boot_address=ma2_silent_boot_address,
        fast_boot_address=fast_boot_address,
        nand_bad_block_address=nand_bad_block_address,
        nand_read_address=nand_read_address,
        nand_write_address=nand_write_address,
        delay_address=delay_address,
        busy_delay_address=busy_delay_address,
        nand_enabled=nand_enabled,
        nand_image=None,
        nand_data_size=0x1000000 if nand_bad_block_address is not None else 0x800000,
        nand_page_size=512, nand_spare_size=16, nand_pages_per_block=32,
        nand_bus_width=2,
        rex_idle_address=rex_idle_address,
        rex_tick_address=rex_tick_address,
        rex_irq_wrapper_address=(rex_irq_route[0] if rex_irq_route else None),
        rex_irq_handler_address=(rex_irq_route[1] if rex_irq_route else None),
        rex_irq_handler_slot=(rex_irq_route[2] if rex_irq_route else None),
        rex_irq_callback_slot=(rex_irq_route[3] if rex_irq_route else None),
        rex_irq_status_address=(rex_irq_route[4] if rex_irq_route else None),
        rex_irq_enable_address=(rex_irq_route[5] if rex_irq_route else None),
        rex_irq_arm_address=rex_irq_arm_address,
        rex_irq_mask=(rex_irq_route[6] if rex_irq_route else 0),
        rex_tick_ms=rex_tick_ms,
        board_adc_address=board_adc_address,
        board_adc_reader_address=board_adc_reader_address,
        board_adc_value=0xC2,
        flash_id_address=flash_id_address,
        flash_id_value=(flash_id_for_size(flash_size)
                        if flash_id_address is not None else None),
        crc16_address=crc16_address,
        dmd_download_address=dmd_download_address,
        primary_flash_probe_address=primary_flash_probe_address,
        memory_clear_addresses=memory_clear_addresses,
        memory_copy_addresses=memory_copy_addresses,
        register_ramp_addresses=register_ramp_addresses,
        arm_memory_copy_addresses=arm_memory_copy_addresses,
        flash_state=default_flash_state,
        linker=linker, overlays=overlays, missing_overlays=[], runtime_overlays=[],
    )
    if overrides is not None:
        for key in ("model", "chipset", "width", "height",
                    "framebuffer_address", "framebuffer_stride", "framebuffer_format",
                    "framebuffer_flush_address", "framebuffer_rect_flush_address",
                    "board_revision",
                    "board_revision_register", "board_revision_value", "image_offset",
                    "load_address", "flash_size", "secondary_flash_address",
                    "secondary_flash_size", "secondary_flash_image",
                    "secondary_flash_state", "secondary_flash_read_address",
                    "secondary_flash_write_address", "legacy_efs_page_read_address",
                    "eeprom_read_address", "eeprom_write_address",
                    "eeprom_geometry_address",
                    "ram_base", "ram_size",
                    "ram_image_offset", "ram_image_size", "entry",
                    "key_register", "key_active_low",
                    "audio_play_address", "fast_boot_address", "delay_address",
                    "busy_delay_address", "nand_bad_block_address",
                    "nand_read_address", "nand_write_address", "nand_enabled",
                    "nand_image", "nand_data_size", "nand_page_size", "nand_spare_size",
                    "nand_pages_per_block", "nand_bus_width",
                    "rex_idle_address", "rex_tick_address",
                    "rex_irq_wrapper_address", "rex_irq_arm_address",
                    "rex_tick_ms",
                    "board_adc_address", "board_adc_value",
                    "flash_id_address", "flash_id_value", "crc16_address",
                    "dmd_download_address",
                    "primary_flash_probe_address",
                    "flash_state"):
            value = getattr(overrides, key, None)
            if value is not None:
                setattr(config, key, value)
        if (getattr(overrides, "framebuffer_stride", None) is None
                and config.framebuffer_address is not None
                and (getattr(overrides, "width", None) is not None
                     or config.framebuffer_stride <= 0)):
            config.framebuffer_stride = ((config.width + 7) // 8) * 16
        if (getattr(overrides, "framebuffer_address", None) is not None
                and getattr(overrides, "framebuffer_format", None) is None):
            config.framebuffer_format = "rgb565le"
        if (getattr(overrides, "framebuffer_address", None) == 0
                or getattr(overrides, "framebuffer_format", None) == "none"):
            config.framebuffer_address = None
            config.framebuffer_stride = 0
            config.framebuffer_format = "none"
            config.framebuffer_flush_address = None
            config.framebuffer_rect_flush_address = None
        for field in DISABLEABLE_ADDRESS_FIELDS:
            if getattr(overrides, field, None) == 0:
                setattr(config, field, None)
        if getattr(overrides, "nand_enabled", None) is None and config.nand_image:
            config.nand_enabled = True
        if config.board_revision_value is None:
            try:
                config.board_revision_value = int(config.board_revision, 0)
            except ValueError:
                pass
        if (getattr(overrides, "chipset", None) is not None
                and getattr(overrides, "ram_base", None) is None):
            config.ram_base = infer_ram_base(
                config.linker, config.chipset, primary_image
            )
        if (getattr(overrides, "model", None) is not None
                and getattr(overrides, "width", None) is None
                and getattr(overrides, "height", None) is None):
            config.width, config.height = KNOWN_SCREENS.get(
                config.model, (config.width, config.height)
            )
        if getattr(overrides, "flash_size", None) is None:
            limit = (config.ram_base - config.load_address
                     if config.ram_base > config.load_address
                     else min(MAX_FLASH_SIZE, ADDRESS_SPACE - config.load_address))
            config.flash_size = normalised_flash_size(
                max(len(image), required_flash_extent), limit
            )
        if getattr(overrides, "secondary_flash_size", None) is None:
            config.secondary_flash_size = config.flash_size
        if getattr(overrides, "ram_image_offset", None) is None:
            config.ram_image_offset = config.flash_size
        if getattr(overrides, "ram_image_size", None) is None:
            config.ram_image_size = plausible_ram_seed_size(
                len(image), config.ram_image_offset, config.ram_size
            )
        if (getattr(overrides, "flash_id_value", None) is None
                and config.flash_id_address is not None):
            config.flash_id_value = flash_id_for_size(config.flash_size)
        if config.load_address:
            for field in auto_relative:
                if getattr(overrides, field, None) is None:
                    address = getattr(config, field)
                    if address is not None:
                        setattr(config, field, config.load_address + address)
            config.memory_clear_addresses = [
                config.load_address + address if relative else address
                for address, relative in clear_layout if address is not None
            ]
            config.memory_copy_addresses = [
                config.load_address + address if relative else address
                for address, relative in copy_layout if address is not None
            ]
            config.register_ramp_addresses = [
                config.load_address + address if relative else address
                for address, relative in ramp_layout if address is not None
            ]
    # These MSM5500 boards use a second AMD NOR for EFS/NV between boot ROM
    # and SDRAM.  It is not a mirror of the firmware chip.
    secondary_nor_detected = (
        config.flash_id_address is not None
        and config.secondary_flash_read_address is not None
        and b"fsd_amd.c\0" in image
        and b"\x0b$USER_DIRS\0" in image
        and bytes.fromhex("0120c0052060") in image
        and config.flash_size == 0x800000
    )
    # The wrapper signatures above are useful when present, but several
    # otherwise identical MSM5500 builds inline their AMD routines.  The
    # physical layout and filesystem fingerprints are independent evidence:
    # an 8 MiB program NOR, another 8 MiB slot before SDRAM, the AMD driver,
    # and a GEFS root marker.  This covers the E110/V-series family without
    # treating an arbitrary partial image as a second flash chip.
    family_secondary_nor_detected = (
        config.chipset == "MSM5500"
        and config.flash_size == config.secondary_flash_size == 0x800000
        and config.ram_base - (config.load_address + config.flash_size)
        == config.secondary_flash_size
        and b"fsd_amd.c\0" in image
        and b"\x0b$USER_DIRS\0" in image
    )
    legacy_secondary_nor_detected = (
        config.legacy_efs_page_read_address is not None
        and config.secondary_flash_read_address is not None
        and config.secondary_flash_write_address is not None
        and config.chipset == "MSM5500"
        and config.flash_size == 0x800000
    )
    if (config.secondary_flash_address is None
            and (secondary_nor_detected or legacy_secondary_nor_detected
                 or family_secondary_nor_detected)
            and config.ram_base - (config.load_address + config.flash_size)
            == config.secondary_flash_size):
        config.secondary_flash_address = config.load_address + config.flash_size
        if family_secondary_nor_detected and not (
                secondary_nor_detected or legacy_secondary_nor_detected):
            config.detection_notes.append(
                "secondary AMD NOR inferred from MSM5500 8+8 MiB layout and GEFS driver"
            )
    if (config.flash_id_address is not None
            and (overrides is None or getattr(overrides, "flash_id_value", None) is None)):
        detected_size = (config.secondary_flash_size
                         if config.secondary_flash_address not in (None, 0)
                         else config.flash_size)
        config.flash_id_value = flash_id_for_size(detected_size)
    state_flash, state_secondary = default_state_paths(
        path, image, config.flash_size, config.secondary_flash_size,
        config.secondary_flash_image, config.nand_image,
        ((config.nand_data_size, config.nand_page_size, config.nand_spare_size,
         config.nand_pages_per_block, config.nand_bus_width)
         if config.nand_enabled else None),
        (config.secondary_flash_address not in (None, 0)
         and not config.secondary_flash_image
         and b"\x0b$USER_DIRS\0" in image),
    )
    if overrides is None or getattr(overrides, "flash_state", None) is None:
        config.flash_state = state_flash
    if overrides is None or getattr(overrides, "secondary_flash_state", None) is None:
        config.secondary_flash_state = state_secondary
    missing = max(0, config.flash_size - len(image))
    trailer = max(0, len(image) - config.flash_size)
    config.missing_overlays = find_missing_overlays(
        image, config.flash_size, config.load_address
    )
    config.runtime_overlays = find_runtime_overlays(
        image, config.ram_base, config.ram_size
    )
    if config.runtime_overlays:
        config.detection_notes.append(
            f"{len(config.runtime_overlays)} internal-RAM overlay(s) require "
            "a prior SDRAM/NAND partition load"
        )
    if missing:
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
    return config


_QUOTED_ABSOLUTE_PATH_RE = re.compile(
    r"(?P<quote>['\"])(?P<path>(?:[A-Za-z]:[\\/]|/)[^'\"]*)(?P=quote)"
)
_PLAIN_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![\w])(?:[A-Za-z]:[\\/]|/)[^\s'\"<>()\[\]{},;:]+"
)


def _safe_host_error_text(value: object) -> str:
    """Keep backend error text useful without retaining local absolute paths."""
    def basename(path: str) -> str:
        return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or "."

    text = str(value)
    text = _QUOTED_ABSOLUTE_PATH_RE.sub(
        lambda match: f"{match['quote']}{basename(match['path'])}{match['quote']}",
        text,
    )
    return _PLAIN_ABSOLUTE_PATH_RE.sub(lambda match: basename(match[0]), text)


class HostBackendFault(RuntimeError):
    """Terminal Unicorn host-backend error with a pre-call Python checkpoint."""

    def __init__(self, error: OSError, diagnostic: dict[str, object]) -> None:
        message = _safe_host_error_text(
            getattr(error, "strerror", None) or str(error)
        )
        self.diagnostic = {
            **diagnostic,
            "host_error": f"{type(error).__name__}: {message}",
        }
        super().__init__(f"Unicorn host backend failure: {message}")


class GenericMSMEmulator:
    """Firmware-first ARMv4T runner; unknown data MMIO pages become zero-backed."""

    def __init__(self, config: FirmwareConfig) -> None:
        self.config = config
        LOGGER.info("emulator init config=%s",
                    json.dumps(config.diagnostic_config(), ensure_ascii=False,
                               sort_keys=True))
        if config.image_kind != "firmware":
            raise ValueError(
                "input has no ARM exception vector table; it appears to be "
                "EFS/data rather than executable firmware"
            )
        if not 32 <= config.width <= 1024 or not 32 <= config.height <= 1024:
            raise ValueError("screen dimensions must be in 32..1024")
        if config.chipset not in ("MSM5000", "MSM5100", "MSM5500", "MSM5xxx"):
            raise ValueError(f"unsupported chipset: {config.chipset}")
        if not 0 <= config.load_address < ADDRESS_SPACE:
            raise ValueError("flash load address outside 32-bit address space")
        if not 0 < config.flash_size <= MAX_FLASH_SIZE:
            raise ValueError("flash size must be in 1..64 MiB")
        flash_end = config.load_address + config.flash_size
        if flash_end > ADDRESS_SPACE:
            raise ValueError("flash range outside 32-bit address space")
        if not 0 < config.ram_base < ADDRESS_SPACE:
            raise ValueError("RAM base must be a positive 32-bit address")
        if not 0 < config.ram_size <= MAX_RAM_SIZE:
            raise ValueError("RAM size must be in 1..128 MiB")
        ram_end = config.ram_base + config.ram_size
        if ram_end > ADDRESS_SPACE:
            raise ValueError("RAM range outside 32-bit address space")
        if max(config.load_address, config.ram_base) < min(flash_end, ram_end):
            raise ValueError("primary flash overlaps configured RAM")
        if config.linker is not None:
            layout = config.linker
            if not (config.ram_base <= layout.data_target
                    <= layout.data_target + layout.data_size == layout.bss_target
                    < layout.bss_target + layout.bss_size <= ram_end):
                raise ValueError("linker data/BSS range outside configured RAM")
        configured = ((config.load_address, flash_end, "primary flash"),
                      (config.ram_base, ram_end, "RAM"))
        for start, end, label in configured:
            if max(start, 0x02000000) < min(end, 0x02801000):
                raise ValueError(f"{label} overlaps fixed LCD MMIO")
            if max(start, 0x02C00000) < min(end, 0x02C01000):
                raise ValueError(f"{label} overlaps fixed alternate LCD MMIO")
            if max(start, 0x03000000) < min(end, 0x04000000):
                raise ValueError(f"{label} overlaps fixed MSM MMIO/internal RAM")
        if config.nand_enabled:
            for start, end, label in configured:
                if any(max(start, port_start) < min(end, port_end)
                       for port_start, port_end in NAND_MMIO_RANGES):
                    raise ValueError(f"{label} overlaps fixed NAND MMIO")
        if not 0 <= config.entry < config.flash_size:
            raise ValueError("entry offset outside primary flash")
        if config.framebuffer_address is not None:
            if config.framebuffer_format not in FRAMEBUFFER_FORMATS:
                raise ValueError(f"unsupported framebuffer format: {config.framebuffer_format}")
            if config.framebuffer_stride < config.width * 2:
                raise ValueError("framebuffer stride is smaller than one RGB565 row")
            framebuffer_end = (config.framebuffer_address
                               + config.framebuffer_stride * config.height)
            if (config.framebuffer_address < config.ram_base
                    or framebuffer_end > ram_end):
                raise ValueError("framebuffer range outside configured RAM")
        elif (config.framebuffer_flush_address is not None
              or config.framebuffer_rect_flush_address is not None):
            raise ValueError("framebuffer trigger configured without framebuffer address")
        if not config.flash_state:
            raise ValueError("primary flash state path is empty")
        secondary_base = config.secondary_flash_address
        if secondary_base == 0:
            secondary_base = None
        if secondary_base is not None and not config.secondary_flash_state:
            raise ValueError("secondary flash state path is empty")

        def resolved_path(filename: str) -> Path:
            return Path(filename).expanduser().resolve()

        config.flash_state = str(resolved_path(config.flash_state))
        if secondary_base is not None:
            config.secondary_flash_state = str(resolved_path(
                config.secondary_flash_state
            ))
        eeprom_enabled = (
            config.eeprom_geometry_address is not None
            and (config.eeprom_read_address is not None
                 or config.eeprom_write_address is not None)
        )
        eeprom_state_path = resolved_path(config.flash_state + ".eeprom.bin")
        persistent_outputs = [
            ("primary flash state", resolved_path(config.flash_state)),
        ]
        if secondary_base is not None:
            persistent_outputs.append((
                "secondary flash state",
                resolved_path(config.secondary_flash_state),
            ))
        if eeprom_enabled:
            persistent_outputs.append(("EEPROM state", eeprom_state_path))
        if config.nand_enabled:
            persistent_outputs.extend((
                ("NAND state", resolved_path(config.flash_state + ".nand.bin")),
                ("NAND metadata", resolved_path(config.flash_state + ".nand.json")),
            ))
        write_targets: list[tuple[str, Path]] = []
        for label, state_path in persistent_outputs:
            write_targets.extend((
                (label, state_path),
                (f"{label} temporary",
                 state_path.with_suffix(state_path.suffix + ".tmp")),
            ))
        state_locks = [("primary state lock", lock_path(config.flash_state))]
        if secondary_base is not None:
            state_locks.append((
                "secondary state lock", lock_path(config.secondary_flash_state)
            ))
        if eeprom_enabled:
            state_locks.append(("EEPROM state lock", lock_path(eeprom_state_path)))
        write_targets.extend(state_locks)
        protected_inputs = [("firmware", resolved_path(config.path))]
        if secondary_base is not None and config.secondary_flash_image:
            protected_inputs.append((
                "secondary flash image",
                resolved_path(config.secondary_flash_image),
            ))
        if config.nand_enabled and config.nand_image:
            protected_inputs.append(("NAND image", resolved_path(config.nand_image)))
        for index, (label, path) in enumerate(write_targets):
            for other_label, other_path in [*write_targets[:index], *protected_inputs]:
                if path == other_path:
                    raise ValueError(f"{label} path collides with {other_label}")
        if config.nand_bus_width not in (1, 2):
            raise ValueError("NAND bus width must be 1 or 2 bytes")
        if not 0 < config.nand_data_size <= MAX_NAND_DATA_SIZE:
            raise ValueError("NAND data size must be in 1..128 MiB")
        if not 256 <= config.nand_page_size <= 0x4000:
            raise ValueError("NAND page size must be in 256..16384 bytes")
        if not 0 < config.nand_spare_size <= 0x1000:
            raise ValueError("NAND spare size must be in 1..4096 bytes")
        if not 0 < config.nand_pages_per_block <= 0x1000:
            raise ValueError("NAND pages per block must be in 1..4096")
        if config.nand_data_size % config.nand_page_size:
            raise ValueError("NAND data size must be a whole number of pages")
        raw = Path(config.path).read_bytes()
        if not 0 <= config.image_offset < len(raw):
            raise ValueError("image offset outside firmware")
        available = raw[config.image_offset:]
        # Partial dumps are padded as erased NOR.  The inferred capacity is
        # independently bounded above, so a large omitted tail is safe here.
        if (config.ram_image_size < 0 or config.ram_image_offset < 0
                or config.ram_image_size > config.ram_size
                or (config.ram_image_size
                    and config.ram_image_offset + config.ram_image_size > len(available))):
            raise ValueError("RAM seed range outside firmware")
        ram_seed = (available[config.ram_image_offset:
                              config.ram_image_offset + config.ram_image_size]
                    if config.ram_image_size else b"")
        self.image = (available[:config.flash_size]
                      + b"\xff" * max(0, config.flash_size - len(available)))
        # Bootstrap inference must distinguish actual supplied NOR bytes from
        # the erased padding that lets a partial dump model its physical chip.
        # A structural early copy may not promote a padded tail into firmware.
        self.primary_rom_end = (config.load_address
                                + min(len(available), config.flash_size))
        self.original_image = bytes(self.image)
        self.flash = NORFlash(self.image, Path(config.flash_state))
        self.image = bytes(self.flash.data)
        self.secondary_flash: NORFlash | None = None
        self.secondary_base: int | None = secondary_base
        self._lazy_secondary_attempted: set[int] = set()
        if secondary_base is not None:
            secondary_end = secondary_base + config.secondary_flash_size
            image_end = config.load_address + len(self.image)
            overlaps_image = (max(secondary_base, config.load_address)
                              < min(secondary_end, image_end))
            overlaps_ram = max(secondary_base, config.ram_base) < min(secondary_end, ram_end)
            overlaps_nand = (config.nand_enabled
                             and any(max(secondary_base, port_start)
                                     < min(secondary_end, port_end)
                                     for port_start, port_end in NAND_MMIO_RANGES))
            overlaps_fixed = (
                max(secondary_base, 0x02000000) < min(secondary_end, 0x02801000)
                or max(secondary_base, 0x02C00000) < min(secondary_end, 0x02C01000)
                or max(secondary_base, 0x03000000) < min(secondary_end, 0x04000000)
            )
            if (not 0 < config.secondary_flash_size <= MAX_FLASH_SIZE
                    or secondary_base < 0
                    or secondary_end > ADDRESS_SPACE or overlaps_image or overlaps_ram
                    or overlaps_nand or overlaps_fixed):
                raise ValueError(f"invalid secondary flash: 0x{secondary_base:X}")
            if config.secondary_flash_image:
                seed = Path(config.secondary_flash_image).read_bytes()
                if len(seed) > config.secondary_flash_size:
                    raise ValueError("secondary flash image is larger than configured size")
                seed += b"\xff" * (config.secondary_flash_size - len(seed))
            elif b"\x0b$USER_DIRS\0" in available:
                seed = qualcomm_efs_seed(
                    config.secondary_flash_size, config.chipset
                )
            else:
                seed = b"\xff" * config.secondary_flash_size
            self.secondary_flash = NORFlash(seed, Path(config.secondary_flash_state))
        self.eeprom_enabled = eeprom_enabled
        self.eeprom_state_path = eeprom_state_path
        self.eeprom_data = bytearray()
        self.eeprom_original = b""
        self.eeprom_loaded = b""
        self.eeprom_operations: list[tuple[int, bytes]] = []
        self.eeprom_capacity = 0
        self.eeprom_loaded_from_state = False
        self.eeprom_error: str | None = None
        storage_ranges = [
            (config.load_address, flash_end, "primary flash"),
            (config.ram_base, ram_end, "RAM"),
        ]
        if secondary_base is not None:
            storage_ranges.append((
                secondary_base, secondary_base + config.secondary_flash_size,
                "secondary flash",
            ))
        register_ranges = [(config.key_register, config.key_register + 4,
                            "key register")]
        if config.board_revision_register is not None:
            register_ranges.append((
                config.board_revision_register,
                config.board_revision_register + 4,
                "board revision register",
            ))
        if config.board_status_input is not None:
            register_ranges.append((
                config.board_status_input.address,
                config.board_status_input.address + 1,
                "board status input",
            ))
        register_reserved = [
            (0x02000000, 0x02801000, "LCD MMIO"),
            (0x02C00000, 0x02C01000, "alternate LCD MMIO"),
            (0x03800000, 0x03A00000, "internal RAM"),
            *((address, address + len(value), "stable MSM MMIO")
              for address, value in STABLE_MSM_MMIO),
            *((overlay.target, overlay.target + overlay.size, "executable overlay")
              for overlay in config.overlays),
        ]
        if config.nand_enabled:
            register_reserved.extend(
                (start, end, "NAND MMIO") for start, end in NAND_MMIO_RANGES
            )
        for index, (start, end, label) in enumerate(register_ranges):
            if not 0 <= start < end <= ADDRESS_SPACE:
                raise ValueError(f"{label} outside 32-bit address space")
            conflicts = [*storage_ranges, *register_reserved,
                         *register_ranges[:index]]
            for other_start, other_end, other_label in conflicts:
                if max(start, other_start) < min(end, other_end):
                    # SCH-E470 partial dumps reference code in the upper half
                    # of a 16 MiB NOR while also decoding the board-revision
                    # latch at 0x00DFFFDC.  The physical board uses that small
                    # MMIO aperture as a hole in the NOR window.  Accept the
                    # aperture only when it lies beyond the bytes actually
                    # supplied by the dump; never hide real firmware bytes.
                    supplied_end = (config.load_address
                                    + min(len(available), config.flash_size))
                    if (label == "board revision register"
                            and other_label == "primary flash"
                            and start >= supplied_end):
                        continue
                    raise ValueError(f"{label} overlaps {other_label}")
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_TI925T)
        # Map actual devices and storage, rather than one contiguous 80 MiB
        # arena.  Besides catching bad pointers, this avoids large-map issues
        # seen in the Windows Unicorn backend.
        ranges = [
            (config.load_address, len(self.image)),
            (config.ram_base, config.ram_size),
            (config.key_register, 4),
            (0x02000000, PAGE),       # LCD command/data bus
            (0x02800000, PAGE),       # alternate/indexed LCD bus
            (0x02C00000, PAGE),       # later parallel LCD command/data bus
            (0x03000000, 0x01000000), # MSM MMIO and internal RAM overlays
            # Some incomplete board dumps retain an all-ones optional-device
            # pointer.  On the physical 32-bit bus this lands on open bus,
            # rather than becoming a host pointer or crashing Unicorn.
            (0xFFFFF000, PAGE),
            *((address, len(value)) for address, value in STABLE_MSM_MMIO),
        ]
        if config.nand_enabled:
            ranges.extend((start, end - start) for start, end in NAND_MMIO_RANGES)
        if secondary_base is not None:
            ranges.append((secondary_base, config.secondary_flash_size))
        if config.board_revision_register is not None:
            ranges.append((config.board_revision_register, 4))
        mapped_ranges: list[tuple[int, int]] = []
        for start, length in ranges:
            if not 0 <= start < ADDRESS_SPACE or start + length > ADDRESS_SPACE:
                raise ValueError(f"mapping outside 32-bit address space: 0x{start:X}")
            left = start & -PAGE
            right = aligned(start + length)
            if left < right:
                mapped_ranges.append((left, right))
        merged: list[list[int]] = []
        for left, right in sorted(mapped_ranges):
            if merged and left <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], right)
            else:
                merged.append([left, right])
        for left, right in merged:
            self.uc.mem_map(left, right - left, UC_PROT_ALL)
        self.uc.mem_write(config.load_address, self.image)
        self.uc.mem_write(0xFFFFF000, b"\xff" * PAGE)
        if secondary_base is not None and self.secondary_flash is not None:
            self.uc.mem_write(secondary_base, bytes(self.secondary_flash.data))
        if ram_seed:
            self.uc.mem_write(config.ram_base, ram_seed)
        self.flash.ids = self._detect_primary_flash_ids()
        if self.secondary_flash is not None:
            secondary_ids = fujitsu_x16_flash_ids(
                self.original_image, config.secondary_flash_write_address,
                config.load_address, int(secondary_base)
            )
            if secondary_ids is not None:
                self.secondary_flash.ids = secondary_ids
            elif config.flash_id_value is not None:
                self.secondary_flash.ids = (config.flash_id_value & 0xFFFF,
                                            config.flash_id_value >> 16 & 0xFFFF)
        self.uc.mem_write(config.key_register,
                          struct.pack("<I", 0xFFFFFFFF if config.key_active_low else 0))
        for address, value in STABLE_MSM_MMIO:
            self.uc.mem_write(address, value)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._stable_mmio_read,
                             begin=address, end=address + len(value) - 1,
                             user_data=(address, value))
        if (config.board_revision_register is not None
                and config.board_revision_value is not None):
            self.uc.mem_write(config.board_revision_register,
                              struct.pack("<I", config.board_revision_value & 0xFFFFFFFF))
        self._refresh_board_status_input(self.uc)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0xD3)
        stack = ram_end - 4
        if config.linker:
            candidate = (aligned(config.linker.bss_target + config.linker.bss_size
                                 + 0x100000) - 4)
            if config.ram_base <= candidate < ram_end:
                stack = candidate
        self.uc.reg_write(UC_ARM_REG_SP, stack)
        self.instructions = 0
        self.reset_entries = 0
        self.fast_boot_used = False
        self.fault: str | None = None
        self._host_backend_fault: HostBackendFault | None = None
        self._logged_fault: str | None = None
        self.tail: deque[int] = deque(maxlen=64)
        self.hot: Counter[int] = Counter()
        self.mmio_reads: Counter[tuple[int, int, int]] = Counter()
        self.mmio_read_totals: Counter[tuple[int, int, int]] = Counter()
        self.poll_escapes: list[dict[str, int]] = []
        self._poll_escape_keys: set[tuple[int, int, int, int, int]] = set()
        self._poll_candidate_chunks: Counter[tuple[int, int, int]] = Counter()
        self._poll_window_remaining = POLL_OBSERVATION_STEPS
        self.ready_bits: dict[tuple[int, int], tuple[int, int]] = {}
        self.zero_fetches = 0
        self.rex_idle_entries = 0
        self.rex_ticks = 0
        self.rex_elapsed_ms = 0
        self.rex_next_instruction = 0
        self._rex_tick_return_address: int | None = None
        self._rex_tick_context: tuple[tuple[int, int], ...] | None = None
        self._rex_irq_pending = [0, 0]
        self.rex_irq_deliveries = 0
        self.board_adc_reads = 0
        self._board_adc_reader_channel: int | None = None
        self.flash_id_reads = 0
        self.fast_crc16_calls = 0
        self.fast_dmd_downloads = 0
        self.ram_seed_size = len(ram_seed)
        self.secondary_flash_reads = 0
        self.secondary_flash_writes = 0
        self.legacy_efs_page_reads = 0
        self.eeprom_reads = 0
        self.eeprom_read_bytes = 0
        self.eeprom_writes = 0
        self.eeprom_write_bytes = 0
        self.fast_memory_clears = 0
        self.fast_memory_copies = 0
        self.fast_register_ramps = 0
        self.fast_arm_memory_copies = 0
        # A few BSPs construct the initial runtime image with a literal
        # ROM->SDRAM copy, a contiguous BSS clear, then one IRAM overlay copy
        # instead of an ordinary linker table. These bounds are a one-shot
        # lease for that exact bootstrap chain; they never authorize later
        # runtime work buffers.
        self._bootstrap_data_end: int | None = None
        self._bootstrap_rom_end: int | None = None
        self._bootstrap_bss_end: int | None = None
        self._bootstrap_bss_complete = False
        self._bootstrap_iram_end: int | None = None
        # The structural Thumb clear/copy HLE and the older generic
        # scatter-load escape are individually safe, but they describe
        # mutually exclusive bootstrap phases.  Once real RAM-init work has
        # been completed by the former, do not later return through the
        # latter's guessed LR.
        self.hot_loop_hle_used = False
        # The emulation worker can identify a new LCD geometry while Tk is
        # rendering the previous immutable frame.  Publish width/height/frame
        # as one snapshot so the GUI never hands Pillow mismatched byte counts.
        self._display_lock = threading.Lock()
        self.framebuffer = bytearray(config.width * config.height * 3)
        self.display_frame = bytes(self.framebuffer)
        self.frame_sequence = 0
        self.firmware_frame_sequence = 0
        self.lcd_writes = 0
        self.lcd_port_writes: Counter[tuple[int, int]] = Counter()
        # Some boards expose a pixel FIFO at a board-specific LCD aperture
        # instead of the command/data pair used by the Samsung BSPs.  Keep a
        # bounded rolling capture for such ports and promote it only after a
        # complete RGB565-sized scanout has actually been observed.
        self._lcd_raw_streams: dict[tuple[int, int], deque[int]] = {}
        self._lcd_raw_counts: Counter[tuple[int, int]] = Counter()
        self._lcd_raw_frames: Counter[tuple[int, int]] = Counter()
        self._lcd_raw_port: tuple[int, int] | None = None
        self._lcd_raw_segment_streams: dict[tuple[int, int], deque[int]] = {}
        self._lcd_raw_segment_counts: Counter[tuple[int, int]] = Counter()
        self._lcd_recent_commands: deque[int] = deque(maxlen=8)
        # Hold only the exact byte-command/low-byte-word page candidate
        # until two adjacent rows prove it.  This sidecar never decodes pixels.
        self._lcd_lowbyte_page_stage = ""
        self._lcd_lowbyte_page_page = -1
        self._lcd_lowbyte_page_last = -1
        self._lcd_lowbyte_page_high = -1
        self._lcd_lowbyte_page_rows = 0
        self._lcd_lowbyte_page_words: list[int] = []
        # A byte-wide 0x028+2 transport occurs on one otherwise unknown board.
        # It is promoted only after its complete controller setup fingerprint
        # and one exact 96x64 RGB565 payload have both been observed.
        self._lcd_byte_rgb565_commands = bytearray()
        self._lcd_byte_rgb565_payload: bytearray | None = None
        # One selector/data board uses packed register/argument words.  Its
        # mode register selects either paired RGB666 or one-word RGB565.
        self._lcd_selector_registers: dict[int, int] = {}
        self._lcd_selector_words: list[int] = []
        self._lcd_selector_expected = 0
        self._lcd_selector_window: tuple[int, int, int, int] | None = None
        self._lcd_selector_format: str | None = None
        # An early 12-bit controller addresses one horizontal run with the
        # exact 0x03=x, 0x05=y, 0x0B=pixels command sequence.
        self._lcd_bgr444_command: int | None = None
        self._lcd_bgr444_axis_state = 0
        self._lcd_bgr444_cursor = [0, 0]
        self._lcd_bgr444_qualified = False
        self._lcd_bgr444_dirty = False
        self._lcd_bgr444_streamed_pixels = 0
        self._lcd_bgr444_run_origin: tuple[int, int] | None = None
        self._lcd_bgr444_run_words: list[int] = []
        self._lcd_bgr444_runs: list[tuple[int, int, tuple[int, ...]]] = []
        self._lcd_protocol = "unknown"
        self._lcd_frame_protocol = "none"
        if config.framebuffer_address is not None:
            self._render_framebuffer_region(
                0, 0, config.width - 1, config.height - 1,
                firmware_originated=False,
            )
        self.nand_commands: list[int] = []
        self.nand_image = bytearray()
        self.nand_raw_page_size = config.nand_page_size + config.nand_spare_size
        self.nand_page_count = config.nand_data_size // config.nand_page_size
        nand_backing_size = self.nand_page_count * self.nand_raw_page_size
        if nand_backing_size > MAX_NAND_BACKING_SIZE:
            raise ValueError("NAND raw backing exceeds 256 MiB safety limit")
        if config.nand_enabled:
            if config.nand_image:
                supplied = Path(config.nand_image).read_bytes()
                self.nand_image = self._normalise_nand(supplied, nand_backing_size,
                                                       "NAND image")
            else:
                self.nand_image = bytearray(b"\xff" * nand_backing_size)
        self.nand_original = bytes(self.nand_image)
        self.nand_state_path = Path(config.flash_state + ".nand.bin")
        self.nand_metadata_path = Path(config.flash_state + ".nand.json")
        self.nand_recovered_seed = False
        self.nand_needs_rewrite = False
        if config.nand_enabled:
            with exclusive_path_lock(config.flash_state):
                self.nand_recovered_seed = self.nand_state_path.is_file()
                if self.nand_recovered_seed:
                    self._validate_nand_metadata()
                    saved = self.nand_state_path.read_bytes()
                    saved_nand = self._normalise_nand(
                        saved, len(self.nand_image), "NAND state"
                    )
                    self.nand_image[:] = saved_nand
                    self.nand_needs_rewrite = (
                        len(saved) != len(self.nand_image)
                        or not self.nand_metadata_path.is_file()
                    )
        self.nand_loaded = bytes(self.nand_image)
        self.nand_operations: list[tuple[str, int, bytes | int]] = []
        self.nand_mode = "idle"
        self.nand_address: list[int] = []
        self.nand_cursor = 0
        self.nand_reads = 0
        self.nand_writes = 0
        self.nand_bad_block_probes = 0
        self.nand_program = bytearray()
        self.nand_spare_latched = False
        self._lg_pixels: list[int] = []
        self._lcd_mode = 0
        self._lcd_command = 0
        self._lcd_args: list[int] = []
        self._lcd_x = [0, config.width - 1]
        self._lcd_y = [0, config.height - 1]
        self._lcd_cursor = [0, 0]
        self._lcd_expected = 0
        self._lcd_streamed = 0
        self._lcd_direct_cursor = [0, 0]
        self._lcd_direct_window = [config.width, config.height]
        self._lcd_direct_origin = [0, 0]
        self._lcd_direct_calibrated = [False, False]
        self._lcd_gram_cursor = [0, 0]
        self._lcd_gram_addressed = False
        self._lcd_gram_dirty = False
        self._lcd_packed_21_state = 0
        self._lcd_data_byte_latch: dict[int, int] = {}
        # An older 0x028 board uses the direct 0x75/0x15/0x5C setup while
        # sharing the aperture with page-LCD traffic.  Hold only that exact
        # short grammar until it proves itself; all other traffic stays on
        # the existing parallel/page path.
        self._lcd_028_direct_probe: list[tuple[int, int, int]] = []
        # The E370-class +8/+C controller packs two RGB332 pixels into one
        # data word.  Keep it wholly separate from the ordinary 0x020/+4
        # command state: unrelated LCD traffic must not turn register 0x22
        # into a generic GRAM transfer halfway through a packed frame.
        self._lcd_packed_command = 0
        self._lcd_packed_window_order: list[int] = []
        self._lcd_packed_registers: dict[int, int] = {}
        self._lcd_packed_qualified = False
        self._lcd_packed_window = [0, 0, -1, -1]
        self._lcd_packed_cursor = [0, 0]
        self._lcd_packed_expected_words = 0
        self._lcd_packed_streamed_words = 0
        # Some earlier MSM5000 boards use a byte-wide, page-addressed
        # monochrome controller on the 0x02000000/+4 or 0x02800000/+4
        # aperture.  It is not RGB565: B0..BF select 8-pixel pages and the
        # 10..1F/00..0F pair selects a byte column.  Keep its state separate
        # from the direct RGB controllers until two complete adjacent page
        # rows prove the transport; that prevents an incidental B0 register
        # write on a colour panel from changing its renderer.
        self._lcd_page_current = -1
        self._lcd_page_port: int | None = None
        self._lcd_page_column_high: int | None = None
        self._lcd_page_column_ready = False
        self._lcd_page_column = 0
        self._lcd_page_start_column = 0
        self._lcd_page_data_count = 0
        self._lcd_page_row_bytes = 0
        self._lcd_page_width = 0
        self._lcd_page_height = 0
        self._lcd_page_bits_per_pixel = 1
        self._lcd_page_width_hint = detect_lcd_width_hint(self.image)
        self._lcd_page_geometry_rendered = False
        self._lcd_page_candidate_rows = 0
        self._lcd_page_last_finished = -1
        self._lcd_page_qualified = False
        self._lcd_page_seen: set[int] = set()
        self._lcd_page_ram = bytearray(16 * 256)
        self._lcd_index = 0
        self._lcd_indexed_dirty = False
        self.dynamic_pages: set[int] = set()
        self.last_unmapped: dict[str, int] | None = None
        self._chunk_unmapped: dict[str, int] | None = None
        self._lcd_mmio_extended_mapped = False
        self.held_keys: set[int] = set()
        self.key_baselines: dict[int, int] = {}
        self.input_profile = detect_input_profile(self.image, config.load_address)
        self.input_error = ""
        self.input_events = 0
        self.firmware_key_events = 0
        if self.input_profile is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._input_entry_observed,
                             begin=self.input_profile[1], end=self.input_profile[1])
        self._flash_restore: dict[int, bytes] = {}
        self.audio_player = ApproximateSmafPlayer() if ApproximateSmafPlayer is not None else None
        self.audio_play_requests = 0
        self.audio_last_size = 0
        self.ma2_silent_boot_calls = 0
        self.audio_discovered_address: int | None = None
        self._audio_probe_hook: int | None = None
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x03000000, end=0x03FFFFFF)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x02800000, end=0x02800FFF)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x02C00000, end=0x02C00FFF)
        flash_end = config.load_address + len(self.image)
        open_bus_exclusions = [
            *NAND_MMIO_RANGES,
            (0x02000000, 0x02801000),  # LCD buses and indexed registers
            (0x02C00000, 0x02C01000),
            (0x03000000, 0x04000000),  # MSM MMIO plus internal RAM
            (config.key_register, config.key_register + 4),
            *((address, address + len(value))
              for address, value in STABLE_MSM_MMIO),
        ]
        if config.board_revision_register is not None:
            open_bus_exclusions.append((config.board_revision_register,
                                        config.board_revision_register + 4))
        if secondary_base is not None:
            open_bus_exclusions.append((
                secondary_base, secondary_base + config.secondary_flash_size
            ))
        for left, right in interval_gaps(
                flash_end, config.ram_base, open_bus_exclusions):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._open_bus_read,
                             begin=left, end=right - 1)
        # The old MSMs commonly expose one 8 MiB SDRAM bank.  A permissive
        # backing arena must not make a physically absent second bank writable.
        absent_start = config.ram_base + config.ram_size
        if absent_start < 0x02000000:
            for left, right in interval_gaps(
                    absent_start, 0x02000000, open_bus_exclusions):
                self.uc.hook_add(UC_HOOK_MEM_READ, self._open_bus_read,
                                 begin=left, end=right - 1)
        if (config.board_revision_register is not None
                and config.board_revision_value is not None):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._board_revision_read,
                             begin=config.board_revision_register,
                             end=config.board_revision_register + 3)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._lcd_write,
                         begin=0x02000000, end=0x02800FFF)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._lcd_write,
                         begin=0x02C00000, end=0x02C00FFF)
        if config.framebuffer_flush_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._framebuffer_rows,
                             begin=config.framebuffer_flush_address,
                             end=config.framebuffer_flush_address)
        if config.framebuffer_rect_flush_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._framebuffer_rect,
                             begin=config.framebuffer_rect_flush_address,
                             end=config.framebuffer_rect_flush_address)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                         begin=config.load_address,
                         end=config.load_address + len(self.image) - 1,
                         user_data=(config.load_address, self.flash))
        self.uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                         begin=config.load_address,
                         end=config.load_address + len(self.image) - 1,
                         user_data=(config.load_address, self.flash))
        if secondary_base is not None and self.secondary_flash is not None:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                             begin=secondary_base,
                             end=secondary_base + config.secondary_flash_size - 1,
                             user_data=(secondary_base, self.secondary_flash))
            self.uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                             begin=secondary_base,
                             end=secondary_base + config.secondary_flash_size - 1,
                             user_data=(secondary_base, self.secondary_flash))
            if config.secondary_flash_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._secondary_flash_read_fast,
                                 begin=config.secondary_flash_read_address,
                                 end=config.secondary_flash_read_address)
            if config.secondary_flash_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._secondary_flash_write_fast,
                                 begin=config.secondary_flash_write_address,
                                 end=config.secondary_flash_write_address)
        if eeprom_enabled:
            if config.eeprom_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._eeprom_read_fast,
                                 begin=config.eeprom_read_address,
                                 end=config.eeprom_read_address)
            if config.eeprom_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._eeprom_write_fast,
                                 begin=config.eeprom_write_address,
                                 end=config.eeprom_write_address)
        if config.legacy_efs_page_read_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._legacy_efs_page_read,
                             begin=config.legacy_efs_page_read_address,
                             end=config.legacy_efs_page_read_address)
        if config.nand_enabled:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_command,
                             begin=0x01A00000, end=0x01A00000)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_address_write,
                             begin=0x01900000, end=0x01900000)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._nand_data_read,
                             begin=0x01800000, end=0x01800003)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_data_write,
                             begin=0x01800000, end=0x01800003)
        if config.audio_play_address:
            self.uc.hook_add(UC_HOOK_CODE, self._audio_play,
                             begin=config.audio_play_address,
                             end=config.audio_play_address)
        if config.ma2_silent_boot_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._ma2_silent_boot,
                             begin=config.ma2_silent_boot_address,
                             end=config.ma2_silent_boot_address)
        if config.fast_boot_address and config.linker is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_boot_hook,
                             begin=config.fast_boot_address,
                             end=config.fast_boot_address)
        if config.nand_enabled:
            if config.nand_bad_block_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_bad_block,
                                 begin=config.nand_bad_block_address,
                                 end=config.nand_bad_block_address)
            if config.nand_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_read_fast,
                                 begin=config.nand_read_address,
                                 end=config.nand_read_address)
            if config.nand_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_write_fast,
                                 begin=config.nand_write_address,
                                 end=config.nand_write_address)
        if config.delay_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._return_if_thumb_signature,
                             begin=config.delay_address, end=config.delay_address,
                             user_data=DELAY_SIGNATURE)
        if config.busy_delay_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._return_if_thumb_signature,
                             begin=config.busy_delay_address,
                             end=config.busy_delay_address,
                             user_data=BUSY_DELAY_SIGNATURE)
        if config.rex_idle_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._rex_tick,
                             begin=config.rex_idle_address, end=config.rex_idle_address)
        if (config.rex_irq_wrapper_address is not None
                and config.rex_irq_status_address is not None):
            self.uc.hook_add(
                UC_HOOK_MEM_WRITE, self._rex_irq_status_write,
                begin=config.rex_irq_status_address,
                end=config.rex_irq_status_address + 7,
            )
            self.uc.hook_add(
                UC_HOOK_MEM_READ, self._rex_irq_status_read,
                begin=config.rex_irq_status_address,
                end=config.rex_irq_status_address + 7,
            )
        if config.board_adc_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._board_adc,
                             begin=config.board_adc_address, end=config.board_adc_address)
        if config.board_adc_reader_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._board_adc_reader_entry,
                             begin=config.board_adc_reader_address,
                             end=config.board_adc_reader_address)
        if config.flash_id_address is not None and config.flash_id_value is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._flash_id,
                             begin=config.flash_id_address, end=config.flash_id_address)
        if config.crc16_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._crc16_fast,
                             begin=config.crc16_address, end=config.crc16_address)
        if config.dmd_download_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._dmd_download_fast,
                             begin=config.dmd_download_address,
                             end=config.dmd_download_address)
        for address in config.memory_clear_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_memory_clear,
                             begin=address, end=address)
        for address in config.memory_copy_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_memory_copy,
                             begin=address, end=address)
        for address in config.register_ramp_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_register_ramp,
                             begin=address, end=address)
        for address in config.arm_memory_copy_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_arm_memory_copy,
                             begin=address, end=address)
        # GUI execution uses small run() chunks.  Keep this observer for the
        # session instead of repeatedly creating and deleting a Unicorn block
        # hook; long Windows sessions otherwise churn the backend hook list.
        self._trace_hook = self.uc.hook_add(UC_HOOK_BLOCK, self._trace)

    def _normalise_nand(self, payload: bytes, expected: int, label: str) -> bytearray:
        """Accept current raw-page files plus legacy data-only/smaller saves."""
        if len(payload) == expected:
            return bytearray(payload)
        raw = self.nand_raw_page_size
        data = self.config.nand_page_size
        if len(payload) <= expected and len(payload) % raw == 0:
            return bytearray(payload + b"\xff" * (expected - len(payload)))
        if len(payload) <= self.config.nand_data_size and len(payload) % data == 0:
            converted = bytearray()
            spare = b"\xff" * self.config.nand_spare_size
            for offset in range(0, len(payload), data):
                converted.extend(payload[offset:offset + data])
                converted.extend(spare)
            converted.extend(b"\xff" * (expected - len(converted)))
            return converted
        raise ValueError(f"{label} size/geometry mismatch: got 0x{len(payload):X}, "
                         f"expected 0x{expected:X}")

    def _nand_metadata(self) -> dict[str, object]:
        return {
            "format": 1,
            "firmware_sha256": hashlib.sha256(self.flash.original).hexdigest(),
            "seed_sha256": hashlib.sha256(self.nand_original).hexdigest(),
            "geometry": {
                "data_size": self.config.nand_data_size,
                "page_size": self.config.nand_page_size,
                "spare_size": self.config.nand_spare_size,
                "pages_per_block": self.config.nand_pages_per_block,
                "bus_width": self.config.nand_bus_width,
            },
        }

    def _validate_nand_metadata(self) -> None:
        if not self.nand_metadata_path.is_file():
            return  # legacy save; it will be rewritten with metadata on close
        try:
            metadata = json.loads(self.nand_metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid NAND metadata: {self.nand_metadata_path}") from error
        expected = self._nand_metadata()
        for key in ("firmware_sha256", "seed_sha256", "geometry"):
            if metadata.get(key) != expected[key]:
                raise ValueError(f"NAND state {key} mismatch: {self.nand_metadata_path}")

    def _attach_lazy_secondary_nor(self, uc: Uc, access: int, address: int,
                                   size: int, value: int) -> bool:
        """Attach an erased second AMD NOR only when firmware proves its bus.

        A number of early MSM5000/5500 dumps contain only the program NOR;
        their EFS/NV chip is a separate, initially erased device immediately
        after it.  Mapping it as anonymous RAM turns AMD unlock traffic into
        all-ones callback pointers.  A data read in that exact adjacent bank,
        or the canonical first AMD unlock write (base + 0xAAA, 0xAA), is
        sufficient device evidence without relying on a handset name.
        """
        if self.secondary_flash is not None or access == UC_MEM_FETCH_UNMAPPED:
            return False
        base = self.config.load_address + self.config.flash_size
        gap = self.config.ram_base - base
        if not (0 < base < self.config.ram_base and gap >= 0x200000):
            return False
        capacity = min(self.config.flash_size, gap, MAX_FLASH_SIZE)
        capacity &= -PAGE
        if capacity < 0x200000 or address < base or address >= base + capacity:
            return False
        unlock = (access == UC_MEM_WRITE_UNMAPPED
                  and address == base + 0xAAA and (value & 0xFF) == 0xAA)
        adjacent_read = access == UC_MEM_READ_UNMAPPED
        if not (unlock or adjacent_read) or base in self._lazy_secondary_attempted:
            return False
        self._lazy_secondary_attempted.add(base)
        # Detection normally gives every image a default ``.efs`` state name,
        # even when it did not prove a secondary chip at construction time.
        # Do not reuse that potentially stale state after a runtime attach:
        # the capacity and erased/GEFS seed are part of the device identity.
        state_path = Path(self.config.flash_state).with_name(
            Path(self.config.flash_state).stem
            + f".lazy-secondary-{base:08x}-{capacity:x}.json"
        )
        try:
            seed = (qualcomm_efs_seed(capacity, self.config.chipset)
                    if b"\x0b$USER_DIRS\0" in self.original_image
                    else b"\xff" * capacity)
            secondary = NORFlash(seed, state_path)
            ids = fujitsu_x16_flash_ids(
                self.original_image, self.config.secondary_flash_write_address,
                self.config.load_address, base
            )
            identity = flash_id_for_size(capacity)
            if ids is not None:
                secondary.ids = ids
            elif identity is not None:
                secondary.ids = (identity & 0xFFFF, identity >> 16 & 0xFFFF)
            uc.mem_map(base, capacity, UC_PROT_ALL)
            uc.mem_write(base, bytes(secondary.data))
            uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                        begin=base, end=base + capacity - 1,
                        user_data=(base, secondary))
            uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                        begin=base, end=base + capacity - 1,
                        user_data=(base, secondary))
            if self.config.secondary_flash_read_address is not None:
                uc.hook_add(
                    UC_HOOK_CODE, self._secondary_flash_read_fast,
                    begin=self.config.secondary_flash_read_address,
                    end=self.config.secondary_flash_read_address,
                )
            if self.config.secondary_flash_write_address is not None:
                uc.hook_add(
                    UC_HOOK_CODE, self._secondary_flash_write_fast,
                    begin=self.config.secondary_flash_write_address,
                    end=self.config.secondary_flash_write_address,
                )
        except (OSError, UcError, ValueError) as error:
            LOGGER.debug("lazy secondary NOR rejected base=0x%08X: %s", base, error)
            return False
        self.secondary_flash = secondary
        self.secondary_base = base
        self.config.secondary_flash_address = base
        self.config.secondary_flash_size = capacity
        self.config.secondary_flash_state = str(state_path.resolve())
        evidence = "AMD unlock" if unlock else "adjacent-bank read"
        self.config.detection_notes.append(
            f"lazy secondary NOR 0x{base:08X}+0x{capacity:X} attached from {evidence}"
        )
        LOGGER.info("lazy secondary NOR attached base=0x%08X size=0x%X evidence=%s",
                    base, capacity, evidence)
        return True

    def _unmapped(self, uc: Uc, access: int, address: int, size: int,
                  value: int, user_data: object) -> bool:
        event = {
            "access": access, "address": address, "size": size, "value": value,
        }
        self.last_unmapped = event
        if access == UC_MEM_FETCH_UNMAPPED:
            self._chunk_unmapped = event
            return False
        if self._attach_lazy_secondary_nor(uc, access, address, size, value):
            return True
        # Later MSM5500 boards use addresses throughout the primary LCD
        # controller aperture, not just its command page. It is already a
        # reserved non-executable device range and is covered by the LCD
        # observation hook, so expand it lazily as one RW bank rather than
        # consuming the general partial-dump map budget one 4 KiB page at a
        # time. This preserves bad-code-pointer detection while allowing the
        # real controller register bank to initialize.
        if (LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE
                <= address < LCD_MMIO_PRIMARY_END):
            if not self._lcd_mmio_extended_mapped:
                try:
                    uc.mem_map(
                        LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE,
                        LCD_MMIO_PRIMARY_END
                        - (LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE),
                        UC_PROT_READ | UC_PROT_WRITE,
                    )
                except UcError:
                    self._chunk_unmapped = event
                    return False
                self._lcd_mmio_extended_mapped = True
                LOGGER.info("lazy-mapped LCD MMIO aperture 0x%08X..0x%08X",
                            LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE,
                            LCD_MMIO_PRIMARY_END)
            return True
        if address >= 0x80000000:
            self._chunk_unmapped = event
            return False
        page = address & -PAGE
        if page not in self.dynamic_pages and len(self.dynamic_pages) >= MAX_DYNAMIC_PAGES:
            self.fault = (f"dynamic data mapping limit ({MAX_DYNAMIC_PAGES * PAGE // 0x100000} MiB) "
                          f"at 0x{address:08X}")
            self._chunk_unmapped = event
            return False
        try:
            # Dynamically discovered data/MMIO must never silently become
            # executable code when a partial dump later jumps into the hole.
            uc.mem_map(page, PAGE, UC_PROT_READ | UC_PROT_WRITE)
            self.dynamic_pages.add(page)
        except UcError:
            self._chunk_unmapped = event
            return False
        return True

    def _unmapped_fault_detail(self) -> str:
        """Describe the failing bus access without confusing successful probes."""
        event = self._chunk_unmapped
        if event is None:
            return ""
        labels = {
            UC_MEM_FETCH_UNMAPPED: "fetch",
            UC_MEM_READ_UNMAPPED: "read",
            UC_MEM_WRITE_UNMAPPED: "write",
        }
        label = labels.get(event["access"], f"access-{event['access']}")
        return ("; unmapped %s address=0x%08X size=%d value=0x%X"
                % (label, event["address"], event["size"], event["value"]))

    def _fault_context(self) -> dict[str, object] | None:
        if self.fault is None:
            return None
        pc = self.uc.reg_read(UC_ARM_REG_PC) & 0xFFFFFFFF
        lr = self.uc.reg_read(UC_ARM_REG_LR) & 0xFFFFFFFF
        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR) & 0xFFFFFFFF
        thumb = bool(cpsr & 0x20)
        try:
            instruction = bytes(self.uc.mem_read(pc, 2 if thumb else 4)).hex()
        except UcError:
            instruction = None
        missing_overlay = next((
            item for item in self.config.missing_overlays
            if item.target <= pc < item.target + item.size
        ), None)
        if missing_overlay is not None:
            region = "missing-overlay-target"
        elif (self.primary_rom_end <= pc
              < self.config.load_address + len(self.image)):
            region = "erased-primary-padding"
        elif (self.config.load_address <= pc
              < self.config.load_address + len(self.image)):
            region = "primary-rom"
        elif self.config.ram_base <= pc < self.config.ram_base + self.config.ram_size:
            region = "ram"
        elif 0x03800000 <= pc < 0x03A00000:
            region = "internal-ram"
        else:
            region = "unconfigured"
        return {
            "pc": f"0x{pc:08X}",
            "lr": f"0x{lr:08X}",
            "cpsr": f"0x{cpsr:08X}",
            "cpu_state": "thumb" if thumb else "arm",
            "instruction_bytes": instruction,
            "region": region,
            "previous_block": (f"0x{self.tail[-2]:08X}"
                               if len(self.tail) >= 2 else None),
        }

    @staticmethod
    def _control_sink_from_tail(tail: deque[int] | list[int],
                                instruction: bytes = b"") -> int | None:
        """Identify only a proven one-instruction ARM/Thumb self-branch."""
        recent = list(tail)[-32:]
        if (len(recent) == 32 and len(set(recent)) == 1
                and (instruction.startswith(b"\xfe\xe7")
                     or instruction.startswith(b"\xfe\xff\xff\xea"))):
            return recent[0]
        return None

    @staticmethod
    def _missing_overlay_error(overlay: CopyLayout) -> str:
        return (
            "required executable overlay is absent from partial dump "
            f"(ROM 0x{overlay.source:X}..0x{overlay.source + overlay.size:X}; "
            f"target 0x{overlay.target:08X}.."
            f"0x{overlay.target + overlay.size:08X})"
        )

    def _trace(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        self._restore_flash_once(uc, address, size, user_data)
        if self._rex_irq_boundary(uc, address):
            return
        self.tail.append(address)
        self.hot[address] += 1
        if address == self.config.load_address + self.config.entry:
            self.reset_entries += 1
        if self.config.audio_play_address is None and self.audio_discovered_address is None:
            self._probe_audio_call(uc, address)
        in_primary = (self.config.load_address <= address
                      < self.config.load_address + len(self.image))
        try:
            stream = bytes(uc.mem_read(address, min(max(size, 4), 16)))
            zero_stream = not any(stream)
        except UcError:
            stream = b""
            zero_stream = False
        missing_overlay = next((
            item for item in self.config.missing_overlays
            if item.target <= address < item.target + item.size
        ), None)
        if (missing_overlay is not None and stream
                and stream[0] in (0, 0xFF)
                and all(byte == stream[0] for byte in stream)):
            self.fault = self._missing_overlay_error(missing_overlay)
            uc.emu_stop()
            return
        if (self.primary_rom_end <= address
                < self.config.load_address + len(self.image)
                and stream and all(byte == 0xFF for byte in stream)):
            self.fault = (
                "execution entered erased NOR padding beyond partial dump at "
                f"0x{address:08X} (supplied end 0x{self.primary_rom_end:08X}; "
                f"flash end 0x{self.config.load_address + len(self.image):08X})"
            )
            uc.emu_stop()
            return
        if not in_primary and zero_stream:
            self.zero_fetches += 1
            if self.zero_fetches >= 8:
                dependency = next((item for item in self.config.runtime_overlays
                                   if item.target <= address
                                   < item.target + item.size), None)
                source_empty = False
                if dependency is not None:
                    try:
                        source_empty = not any(uc.mem_read(
                            dependency.source,
                            min(dependency.size, 64),
                        ))
                    except UcError:
                        source_empty = True
                if dependency is not None and source_empty:
                    self.fault = (
                        "runtime executable overlay source is absent: "
                        f"SDRAM 0x{dependency.source:08X}.."
                        f"0x{dependency.source + dependency.size:08X} must be "
                        "loaded from NAND/another partition before "
                        f"0x{address:08X} can execute"
                    )
                else:
                    self.fault = f"zero-filled instruction stream at 0x{address:08X}"
                uc.emu_stop()
        else:
            self.zero_fetches = 0
        if self.fault is None and self._try_hot_thumb_memory_loop(uc, address):
            self.hot_loop_hle_used = True

    def _read(self, uc: Uc, access: int, address: int, size: int,
              value: int, user_data: object) -> None:
        pc = uc.reg_read(UC_ARM_REG_PC) & ~1
        try:
            if struct.unpack("<H", uc.mem_read(pc + 2, 2))[0] == 0x4770:
                pc = uc.reg_read(UC_ARM_REG_LR) & ~1
        except UcError:
            pass
        self._board_adc_reader_data_read(uc, address, size)
        self._refresh_board_status_input(uc, address, size)
        status = getattr(self.config, "rex_irq_status_address", None)
        controller = (status is not None
                      and max(address, status) < min(address + size, status + 0x10))
        masks = None if controller else self.ready_bits.get((address, size))
        if masks:
            current = int.from_bytes(uc.mem_read(address, size), "little")
            set_mask, clear_mask = masks
            uc.mem_write(address, ((current | set_mask) & ~clear_mask).to_bytes(size, "little"))
        self.mmio_reads[(pc, address, size)] += 1
        self.mmio_read_totals[(pc, address, size)] += 1

    def _open_bus_read(self, uc: Uc, access: int, address: int, size: int,
                       value: int, user_data: object) -> None:
        if (self.secondary_flash is not None and self.secondary_base is not None
                and self.secondary_base <= address
                and address + size <= self.secondary_base + self.config.secondary_flash_size):
            return
        uc.mem_write(address, b"\xff" * size)

    @staticmethod
    def _stable_mmio_read(uc: Uc, access: int, address: int, size: int,
                          value: int, user_data: object) -> None:
        register, reset_value = user_data
        uc.mem_write(register, reset_value)

    def _board_revision_read(self, uc: Uc, access: int, address: int, size: int,
                             value: int, user_data: object) -> None:
        register = self.config.board_revision_register
        revision = self.config.board_revision_value
        if register is not None and revision is not None:
            uc.mem_write(register, struct.pack("<I", revision & 0xFFFFFFFF))

    def _refresh_board_status_input(self, uc: Uc, address: int | None = None,
                                    size: int = 0) -> None:
        status = getattr(self.config, "board_status_input", None)
        if status is None:
            return
        if address is not None and not address <= status.address < address + size:
            return
        current = uc.mem_read(status.address, 1)[0]
        uc.mem_write(status.address, bytes((current | status.default & status.mask,)))

    def _release_hardware_poll(self) -> bool:
        """Supply ready bits only when firmware is provably stuck polling MMIO."""
        if not self.mmio_reads:
            return False
        protected = (
            (self.config.load_address,
             self.config.load_address + self.config.flash_size),
            (self.config.ram_base,
             self.config.ram_base + self.config.ram_size),
        )
        secondary = self.config.secondary_flash_address
        if secondary not in (None, 0):
            protected += ((secondary,
                           secondary + self.config.secondary_flash_size),)
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is not None:
            protected += ((status, status + 0x10),)
        key_start = self.config.key_register
        board = self.config.board_revision_register
        # A status-ready loop can be followed immediately by a device-ID/data
        # compare.  Once the first condition is already supplied, inspect the
        # next hottest exact poll instead of repeatedly selecting the same one.
        for (pc, address, size), count in self.mmio_reads.most_common(8):
            if count < 100 or not 0 < size <= 8:
                continue
            if max(address, key_start) < min(address + size, key_start + 4):
                continue
            if (board is not None
                    and max(address, board) < min(address + size, board + 4)):
                continue
            if any(max(address, start) < min(address + size, end)
                   for start, end in protected):
                continue  # ROM/NOR/SDRAM is never a hardware-ready bit
            if 0x03800000 <= address < 0x03A00000:
                continue  # internal RAM/software locks are not hardware polls
            inferred = self._infer_thumb_poll_value(pc, address, size)
            if inferred is None:
                continue
            value, bit, state = inferred
            set_mask, clear_mask = self.ready_bits.get((address, size), (0, 0))
            mask = 1 << bit
            if (state and set_mask & mask) or (not state and clear_mask & mask):
                continue
            candidate = (pc, address, size)
            self._poll_candidate_chunks[candidate] += 1
            if self._poll_candidate_chunks[candidate] < 2:
                continue
            del self._poll_candidate_chunks[candidate]
            if state:
                set_mask |= mask
                clear_mask &= ~mask
            else:
                clear_mask |= mask
                set_mask &= ~mask
            self.ready_bits[(address, size)] = (set_mask, clear_mask)
            self.uc.mem_write(address, value.to_bytes(size, "little"))
            event_key = (pc, address, size, bit, int(state))
            if (event_key not in self._poll_escape_keys
                    and len(self.poll_escapes) < 256):
                self._poll_escape_keys.add(event_key)
                self.poll_escapes.append({
                    "pc": pc, "address": address, "size": size,
                    "reads": count, "value": value, "bit": bit,
                    "state": int(state),
                })
            return True
        return False

    def _infer_thumb_poll_value(self, pc: int, address: int,
                                size: int) -> tuple[int, int, bool] | None:
        """Derive a polled bit from exact Thumb control-flow patterns."""
        try:
            words = struct.unpack("<6H", self.uc.mem_read(pc, 12))
        except UcError:
            return None
        read_register = words[0] & 7
        # Direct MMIO data/ID read followed by CMP #imm and a backward BEQ/BNE.
        # V540 uses this after its LCD serial-interface ready-bit handshake.
        compare = words[1]
        branch = words[2]
        condition = branch >> 8 & 0xF
        displacement = (branch & 0xFF) * 2
        if displacement & 0x100:
            displacement -= 0x200
        branch_address = pc + 4
        if (compare & 0xF800 == 0x2800
                and compare >> 8 & 7 == read_register
                and branch & 0xF000 == 0xD000 and condition in (0, 1)
                and branch_address + 4 + displacement <= pc):
            expected = compare & 0xFF
            wanted = expected if condition == 1 else (0 if expected else 1)
            if wanted < 1 << (size * 8):
                changed = wanted ^ int.from_bytes(
                    self.uc.mem_read(address, size), "little"
                )
                bit = ((changed & -changed).bit_length() - 1 if changed else 0)
                return wanted, bit, bool(wanted & (1 << bit))
        # LG MSM5100 boot code reads a byte, branches back to MOV/ANDS, and
        # exits through BNE once the live one-bit mask becomes ready.
        if words[0] & 0xF800 == 0x7800 and words[1] & 0xF800 == 0xE000:
            displacement = (words[1] & 0x7FF) * 2
            if displacement & 0x800:
                displacement -= 0x1000
            target = pc + 6 + displacement
            try:
                move, ands, branch = struct.unpack("<3H", self.uc.mem_read(target, 6))
            except UcError:
                pass
            else:
                scratch = move & 7
                mask_register = move >> 3 & 7
                branch_displacement = (branch & 0xFF) * 2
                if branch_displacement & 0x100:
                    branch_displacement -= 0x200
                exit_target = target + 8 + branch_displacement
                exact_loop = (
                    target < pc
                    and move & 0xFFC0 == 0x1C00  # ADDS Rd, Rm, #0 (MOV alias)
                    and ands & 0xFFC0 == 0x4000
                    and ands & 7 == scratch
                    and ands >> 3 & 7 == read_register
                    and branch & 0xFF00 == 0xD100  # BNE exit
                    and exit_target > pc + 2
                )
                if exact_loop:
                    registers = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                 UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                 UC_ARM_REG_R6, UC_ARM_REG_R7)
                    mask = self.uc.reg_read(registers[mask_register])
                    if 0 < mask < 1 << (size * 8) and mask & (mask - 1) == 0:
                        current = int.from_bytes(self.uc.mem_read(address, size), "little")
                        bit = mask.bit_length() - 1
                        return current | mask, bit, True
        for index in range(1, 4):
            literal_load = words[index]
            if literal_load & 0xF800 != 0x4800:
                continue
            literal_register = literal_load >> 8 & 7
            literal_address = ((pc + index * 2 + 4) & ~3) + (literal_load & 0xFF) * 4
            expected = int.from_bytes(self.uc.mem_read(literal_address, 4), "little")
            compare = words[index + 1]
            branch = words[index + 2]
            compared = {compare & 7, compare >> 3 & 7}
            condition = branch >> 8 & 0xF
            displacement = (branch & 0xFF) * 2
            if displacement & 0x100:
                displacement -= 0x200
            branch_address = pc + (index + 2) * 2
            backward = branch_address + 4 + displacement <= pc
            if (compare & 0xFFC0 == 0x4280
                    and compared == {read_register, literal_register}
                    and condition == 1 and backward and expected < 1 << (size * 8)):
                return expected, 0, bool(expected & 1)
        # Some BSPs poll a halfword bit with a direct conditional
        # back-edge instead of an explicit unconditional retry branch.
        if len(words) >= 5:
            left, right, compare, branch = words[1:5]
            branch_displacement = (branch & 0xFF) * 2
            if branch_displacement & 0x100:
                branch_displacement -= 0x200
            branch_target = pc + 4 * 2 + 4 + branch_displacement
            exact_split_loop = (
                size == 2
                and words[0] & 0xF800 == 0x8800  # LDRH Rd, [Rb, #imm]
                and left & 0xF800 == 0x0000 and left >> 6 & 0x1F == 31
                and left & 7 == read_register and left >> 3 & 7 == read_register
                and right & 0xF800 == 0x0800 and right >> 6 & 0x1F == 31
                and right & 7 == read_register and right >> 3 & 7 == read_register
                and compare == (0x2800 | read_register << 8 | 1)
                and branch & 0xFF00 == 0xD000  # BEQ retry
                and branch_target == pc
            )
            if exact_split_loop:
                current = int.from_bytes(self.uc.mem_read(address, size), "little")
                return current & ~1, 0, False
        # Early MSM5000 BSPs normalize one status bit with LSLS/LSRS, compare
        # it with 0/1, take the conditional edge as the exit, and use an
        # explicit backward B for the polling edge.  This is the common form
        # used by LG-SD1020 around the 0x03000780 clock-status register.
        if len(words) >= 6:
            left, right, compare, branch, loop = words[1:6]
            left_register = left & 7
            left_source = left >> 3 & 7
            left_shift = left >> 6 & 0x1F
            right_register = right & 7
            right_source = right >> 3 & 7
            right_shift = right >> 6 & 0x1F
            condition = branch >> 8 & 0xF
            branch_displacement = (branch & 0xFF) * 2
            if branch_displacement & 0x100:
                branch_displacement -= 0x200
            exit_target = pc + 4 * 2 + 4 + branch_displacement
            loop_displacement = (loop & 0x7FF) * 2
            if loop_displacement & 0x800:
                loop_displacement -= 0x1000
            loop_address = pc + 5 * 2
            loop_target = loop_address + 4 + loop_displacement
            extracted_bit = right_shift - left_shift
            exact_extract = (
                words[0] & 7 == left_source
                and left & 0xF800 == 0x0000 and left_shift
                and right & 0xF800 == 0x0800
                and right_source == left_register
                and right_register == left_register
                and right_shift == left_shift
                and compare & 0xF800 == 0x2800
                and compare >> 8 & 7 == left_register
                and compare & 0xFF in (0, 1)
                and branch & 0xF000 == 0xD000 and condition in (0, 1)
                and exit_target > loop_address
                and loop & 0xF800 == 0xE000 and loop_target <= pc
                and 0 <= extracted_bit < size * 8
            )
            if exact_extract:
                compared_value = compare & 0xFF
                wanted = compared_value if condition == 0 else 1 - compared_value
                current = int.from_bytes(self.uc.mem_read(address, size), "little")
                mask = 1 << extracted_bit
                value = current | mask if wanted else current & ~mask
                return value, extracted_bit, bool(wanted)
        # Exact adjacent LSRS + BHS/BLO.  Allow LSRS at word zero when `_read`
        # moved the PC from a leaf MMIO accessor to its R0 consumer.
        for index in (0, 1):
            word = words[index]
            if word & 0xF800 != 0x0800:
                continue
            shift = (word >> 6) & 0x1F
            source_register = word >> 3 & 7
            if not shift or source_register != (0 if index == 0 else read_register):
                continue
            branch_word = words[index + 1]
            condition = branch_word >> 8 & 0xF
            if branch_word & 0xF000 != 0xD000 or condition not in (2, 3):
                continue
            displacement = (branch_word & 0xFF) * 2
            if displacement & 0x100:
                displacement -= 0x200
            branch = pc + (index + 1) * 2
            target = branch + 4 + displacement
            want_taken = target > branch
            # If conditional fallthrough contains an unconditional branch back
            # to the read, conditional edge is exit regardless of direction.
            for later, later_word in enumerate(words[index + 2:], index + 2):
                if later_word & 0xF800 != 0xE000:
                    continue
                later_displacement = (later_word & 0x7FF) * 2
                if later_displacement & 0x800:
                    later_displacement -= 0x1000
                later_address = pc + later * 2
                if later_address + 4 + later_displacement <= pc:
                    want_taken = True
                break
            try:
                target_word = struct.unpack("<H", self.uc.mem_read(target, 2))[0]
                if target_word & 0xFE00 == 0xBC00 or target_word == 0x4770:
                    want_taken = True
            except UcError:
                pass
            # The complementary form has a forward conditional edge into a
            # retry body and either an immediate forward B or MOV/POP/BX LR
            # as its non-taken return.  In that CFG carry=1 enters the busy
            # body, while carry=0 reaches the caller.  Require the complete
            # local graph before reversing it: the taken body must branch
            # directly back to this MMIO read.
            fallthrough = pc + (index + 2) * 2
            retry_exit = self._thumb_unconditional_target(
                fallthrough, words[index + 2]
            )
            if retry_exit is None:
                try:
                    move, pop, return_instruction = struct.unpack(
                        "<3H", self.uc.mem_read(fallthrough, 6)
                    )
                except UcError:
                    pass
                else:
                    if (move & 0xFFC0 == 0x1C00 and move & 7 == 0
                            and move >> 3 & 7 == read_register
                            and pop & 0xFE00 == 0xBC00
                            and not (pop & 0x0100)
                            and return_instruction == 0x4770):
                        retry_exit = target + 0x20
            if (target > fallthrough and retry_exit is not None
                    and retry_exit > target and retry_exit - target <= 0x40):
                retry_back = None
                try:
                    for candidate_address in range(target, retry_exit, 2):
                        candidate_word = struct.unpack(
                            "<H", self.uc.mem_read(candidate_address, 2)
                        )[0]
                        retry_back = self._thumb_unconditional_target(
                            candidate_address, candidate_word
                        )
                        if retry_back is not None:
                            break
                        # A conditional branch, branch exchange, return, or
                        # Thumb long branch before the back-edge makes this a
                        # real control-flow path rather than the proven busy
                        # retry grammar.
                        if ((candidate_word & 0xF000) == 0xD000
                                or (candidate_word & 0xFF00) == 0x4700
                                or (candidate_word & 0xFF00) == 0xBD00
                                or (candidate_word & 0xF800) in (0xF000, 0xF800)
                                or ((candidate_word & 0xFC00) == 0x4400
                                    and (candidate_word & 0x300) in (0, 0x200)
                                    and (candidate_word & 0x80)
                                    and (candidate_word & 7) == 7)):
                            break
                except UcError:
                    retry_back = None
                if retry_back is not None and pc - 0x20 <= retry_back <= pc:
                    want_taken = False
            carry = want_taken if condition == 2 else not want_taken
            bit = shift - 1
            if bit >= size * 8:
                return None
            current = int.from_bytes(self.uc.mem_read(address, size), "little")
            value = current | (1 << bit) if carry else current & ~(1 << bit)
            return value, bit, bool(carry)
        return None

    def set_framebuffer_format(self, framebuffer_format: str) -> None:
        """Apply a verified framebuffer colour interpretation without rebooting."""
        if framebuffer_format not in FRAMEBUFFER_FORMATS:
            raise ValueError(f"unsupported framebuffer format: {framebuffer_format}")
        if self.config.framebuffer_address is None:
            raise ValueError("framebuffer format requires a framebuffer address")
        if framebuffer_format == "none":
            raise ValueError("framebuffer format cannot be none while it is mapped")
        if self.config.framebuffer_format == framebuffer_format:
            return
        self.config.framebuffer_format = framebuffer_format
        self._render_framebuffer_region(
            0, 0, self.config.width - 1, self.config.height - 1, force=True,
            firmware_originated=False,
        )

    def _render_framebuffer_region(self, x0: int, y0: int, x1: int, y1: int,
                                   force: bool = True, *,
                                   firmware_originated: bool = True) -> bool:
        address = self.config.framebuffer_address
        if address is None:
            return False
        x0, y0 = max(0, x0), max(0, y0)
        x1 = min(self.config.width - 1, x1)
        y1 = min(self.config.height - 1, y1)
        if x0 > x1 or y0 > y1:
            return False
        endian = "big" if self.config.framebuffer_format.endswith("be") else "little"
        bgr = self.config.framebuffer_format.startswith("bgr")
        changed = False
        for y in range(y0, y1 + 1):
            row = self.uc.mem_read(
                address + y * self.config.framebuffer_stride + x0 * 2,
                (x1 - x0 + 1) * 2,
            )
            for column, offset in enumerate(range(0, len(row), 2), x0):
                value = int.from_bytes(row[offset:offset + 2], endian)
                if bgr:
                    value = ((value & 0x07E0) | (value & 0x001F) << 11
                             | (value >> 11 & 0x001F))
                target = (y * self.config.width + column) * 3
                before = self.framebuffer[target:target + 3]
                self._pixel(y * self.config.width + column, value)
                changed |= before != self.framebuffer[target:target + 3]
        if force or changed:
            self._lcd_protocol = f"framebuffer-{self.config.framebuffer_format}"
            self._publish_frame(firmware_originated=firmware_originated)
        return changed

    def _framebuffer_rows(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        if uc.reg_read(UC_ARM_REG_R0) != self.config.framebuffer_address:
            return
        self.lcd_writes += 1
        self._render_framebuffer_region(
            0, uc.reg_read(UC_ARM_REG_R1), self.config.width - 1,
            uc.reg_read(UC_ARM_REG_R2),
        )

    def _framebuffer_rect(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        if uc.reg_read(UC_ARM_REG_R0) != self.config.framebuffer_address:
            return
        try:
            y1 = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
        except (UcError, struct.error):
            return
        self.lcd_writes += 1
        self._render_framebuffer_region(
            uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2),
            uc.reg_read(UC_ARM_REG_R3), y1,
        )

    def _pixel(self, index: int, value: int) -> None:
        if not 0 <= index < self.config.width * self.config.height:
            return
        offset = index * 3
        self.framebuffer[offset:offset + 3] = bytes((
            (value >> 8 & 0xF8) | (value >> 13),
            (value >> 3 & 0xFC) | (value >> 9 & 3),
            (value << 3 & 0xF8) | (value >> 2 & 7),
        ))

    def _publish_frame(self, *, firmware_originated: bool = True) -> None:
        """Atomically expose only a complete scanout to the GUI thread."""
        frame = bytes(self.framebuffer)
        with self._display_lock:
            self.display_frame = frame
            self.frame_sequence += 1
            if firmware_originated:
                self.firmware_frame_sequence = (
                    getattr(self, "firmware_frame_sequence", 0) + 1
                )
            self._lcd_frame_protocol = self._lcd_protocol

    def display_snapshot(self) -> tuple[int, int, bytes]:
        """Return a geometry/frame triple which is safe for a GUI consumer."""
        with self._display_lock:
            width, height = self.config.width, self.config.height
            frame = self.display_frame
        # The lock makes this invariant unconditional; retain the guard as a
        # useful failure boundary for future display producers.
        if len(frame) != width * height * 3:
            raise RuntimeError("inconsistent display snapshot")
        return width, height, frame

    @staticmethod
    def _lcd_full_window_geometry(x_axis: list[int],
                                  y_axis: list[int]) -> tuple[int, int] | None:
        """Return a controller-proven full-screen window, if one is present."""
        spans = tuple(
            end - start + 1 if end >= start else ((end - start) & 0xFF) + 1
            for start, end in (x_axis, y_axis)
        )
        if (x_axis[0] != 0 or y_axis[0] != 0
                or not (64 <= spans[0] <= 320 and 64 <= spans[1] <= 320)
                or spans[0] * spans[1] < 0x2000):
            return None
        return spans

    def _set_display_geometry(self, width: int, height: int, *, force: bool = False) -> None:
        """Adopt a controller-proven panel geometry before its first visible frame."""
        visible = any(self.framebuffer)
        if ((width, height) == (self.config.width, self.config.height)
                or (visible and not force)
                or not (64 <= width <= 320 and 64 <= height <= 320)):
            return
        with self._display_lock:
            self.config.width, self.config.height = width, height
            self.framebuffer = bytearray(width * height * 3)
            self.display_frame = bytes(self.framebuffer)
        self._lcd_direct_calibrated = [False, False]
        self._lcd_raw_streams.clear()
        self._lcd_raw_counts.clear()
        self._lcd_raw_frames.clear()
        self._lcd_raw_port = None
        self._lcd_raw_segment_streams.clear()
        self._lcd_raw_segment_counts.clear()

    def _lcd_promote_gram_geometry(self) -> None:
        """Use an addressed full GRAM window before cursor-wrapped pixels."""
        geometry = self._lcd_full_window_geometry(self._lcd_x, self._lcd_y)
        current = (self.config.width, self.config.height)
        known = KNOWN_SCREENS.get(getattr(self.config, "model", ""))
        # GRAM dimensions can be larger than the glass.  They may replace the
        # generic 176x220 fallback (as on SC-7080), but never overwrite a
        # known model panel or a previously detected/manual non-default size.
        if (geometry is not None and (geometry == current
                                      or (known is None
                                          and current == (176, 220)))):
            self._set_display_geometry(*geometry)

    def _flush_indexed_frame(self) -> None:
        if self._lcd_indexed_dirty:
            self._publish_frame()
            self._lcd_indexed_dirty = False
        if self._lcd_gram_dirty:
            self._publish_frame()
            self._lcd_gram_dirty = False

    def _lcd_page_set_geometry(self) -> None:
        """Adopt a geometry proved by a byte-wide page-controller scan."""
        if (not self._lcd_page_qualified or not self._lcd_page_width
                or not self._lcd_page_height):
            return
        target = (self._lcd_page_width, self._lcd_page_height)
        changed = target != (self.config.width, self.config.height)
        if changed:
            # A 128-pixel-high panel identifies itself by reaching page B8
            # during its blank first scan, before we have published pixels.
            # Preserve an already visible frame rather than guessing its
            # geometry during a later rectangle update.
            self._set_display_geometry(*target, force=self.frame_sequence == 0)
        if (target == (self.config.width, self.config.height)
                and (changed or not self._lcd_page_geometry_rendered)):
            self._lcd_page_geometry_rendered = True
            if self._lcd_page_render_all():
                self._lcd_protocol = f"page-{self._lcd_page_bits_per_pixel}bpp"
                self._publish_frame()

    @staticmethod
    def _lcd_page_layout(row_bytes: int,
                         width_hint: int | None) -> tuple[int, int]:
        """Separate physical columns from interleaved page bitplanes."""
        if (width_hint is not None and row_bytes % width_hint == 0
                and row_bytes // width_hint in (1, 2)):
            return width_hint, row_bytes // width_hint
        return row_bytes, 1

    def _lcd_page_render_column(self, page: int, column: int) -> bool:
        """Render one physical column from one or two interleaved bitplanes."""
        if not (0 <= page < self.config.height // 8
                and 0 <= column < self.config.width):
            return False
        bits_per_pixel = self._lcd_page_bits_per_pixel
        raw = page * 256 + column * bits_per_pixel
        planes = self._lcd_page_ram[raw:raw + bits_per_pixel]
        if len(planes) != bits_per_pixel:
            return False
        changed = False
        for bit in range(8):
            index = (page * 8 + bit) * self.config.width + column
            offset = index * 3
            before = self.framebuffer[offset:offset + 3]
            level = 0
            for plane_index, value in enumerate(planes):
                level |= ((value >> bit) & 1) << (
                    bits_per_pixel - plane_index - 1
                )
            shade = level * 255 // ((1 << bits_per_pixel) - 1)
            self.framebuffer[offset:offset + 3] = bytes((shade, shade, shade))
            changed |= before != self.framebuffer[offset:offset + 3]
        return changed

    def _lcd_page_render_current(self) -> bool:
        """Apply the current page transfer after its protocol is validated."""
        if (not self._lcd_page_qualified or self._lcd_page_current < 0
                or not self._lcd_page_data_count):
            return False
        self._lcd_page_set_geometry()
        if (self.config.width, self.config.height) != (
                self._lcd_page_width, self._lcd_page_height):
            return False
        changed = False
        for column in range(self._lcd_page_width):
            changed |= self._lcd_page_render_column(self._lcd_page_current, column)
        return changed

    def _lcd_page_render_all(self) -> bool:
        """Restore page RAM after the first controller-proven geometry change."""
        if (self.config.width, self.config.height) != (
                self._lcd_page_width, self._lcd_page_height):
            return False
        changed = False
        for page in range(self._lcd_page_height // 8):
            for column in range(self._lcd_page_width):
                changed |= self._lcd_page_render_column(page, column)
        return changed

    def _lcd_page_flush_current(self) -> None:
        """Publish a validated partial page without treating a chunk as a row end."""
        if self._lcd_page_render_current():
            self._lcd_protocol = f"page-{self._lcd_page_bits_per_pixel}bpp"
            self._publish_frame()

    def _lcd_page_finish_transfer(self) -> None:
        """Close a page transfer when firmware selects the next command."""
        page = self._lcd_page_current
        count = self._lcd_page_data_count
        whole_row = (self._lcd_page_start_column == 0 and count in (128, 256))
        if whole_row:
            if not self._lcd_page_row_bytes:
                self._lcd_page_row_bytes = count
                (self._lcd_page_width,
                 self._lcd_page_bits_per_pixel) = self._lcd_page_layout(
                    count, self._lcd_page_width_hint
                )
                self._lcd_page_candidate_rows = 1
            elif (count == self._lcd_page_row_bytes
                  and page == self._lcd_page_last_finished + 1):
                self._lcd_page_candidate_rows += 1
            elif count == self._lcd_page_row_bytes:
                self._lcd_page_candidate_rows = 1
            elif not self._lcd_page_qualified:
                self._lcd_page_row_bytes = count
                (self._lcd_page_width,
                 self._lcd_page_bits_per_pixel) = self._lcd_page_layout(
                    count, self._lcd_page_width_hint
                )
                self._lcd_page_candidate_rows = 1
            self._lcd_page_last_finished = page
            if self._lcd_page_candidate_rows >= 2:
                self._lcd_page_qualified = True
        elif count and not self._lcd_page_qualified:
            self._lcd_page_candidate_rows = 0
        self._lcd_page_flush_current()

    def _lcd_page_begin_command(self, address: int, size: int, value: int,
                                *, byte_wide: bool = False) -> bool:
        """Recognise a page-LCD command grammar on its command port."""
        if (size not in (1, 2) or (size == 2 and value > 0xFF)
                or (byte_wide and size != 1)):
            return False
        command = value & 0xFF
        if 0xB0 <= command <= 0xBF:
            self._lcd_page_finish_transfer()
            page = command & 0x0F
            self._lcd_page_current = page
            self._lcd_page_port = address
            self._lcd_page_column_high = None
            self._lcd_page_column_ready = False
            self._lcd_page_column = 0
            self._lcd_page_start_column = 0
            self._lcd_page_data_count = 0
            self._lcd_page_seen.add(page)
            if page >= 8:
                self._lcd_page_height = 128
            elif (page == 0 and not self._lcd_page_height
                  and all(index in self._lcd_page_seen for index in range(8))):
                # A B0 restart after B0..B7 is a complete 64-pixel page scan.
                self._lcd_page_height = 64
            self._lcd_page_set_geometry()
            return True
        if (self._lcd_page_current < 0 or self._lcd_page_port != address):
            return False
        if 0x10 <= command <= 0x1F:
            if byte_wide and command != 0x10:
                self._lcd_page_finish_transfer()
                self._lcd_page_current = -1
                self._lcd_page_port = None
                self._lcd_page_column_high = None
                self._lcd_page_column_ready = False
                return False
            self._lcd_page_finish_transfer()
            self._lcd_page_data_count = 0
            self._lcd_page_column_high = command & 0x0F
            self._lcd_page_column_ready = False
            return True
        if 0x00 <= command <= 0x0F and self._lcd_page_column_high is not None:
            if byte_wide and (command or self._lcd_page_column_high):
                self._lcd_page_finish_transfer()
                self._lcd_page_current = -1
                self._lcd_page_port = None
                self._lcd_page_column_high = None
                self._lcd_page_column_ready = False
                return False
            self._lcd_page_finish_transfer()
            self._lcd_page_start_column = (
                self._lcd_page_column_high << 4 | command & 0x0F
            )
            self._lcd_page_column = self._lcd_page_start_column * (
                self._lcd_page_bits_per_pixel if self._lcd_page_qualified else 1
            )
            self._lcd_page_data_count = 0
            self._lcd_page_column_ready = True
            return True
        # A different command ends a page span; do not let its future data
        # bytes be mistaken for a continuation of the previous column run.
        self._lcd_page_finish_transfer()
        self._lcd_page_data_count = 0
        self._lcd_page_column_high = None
        self._lcd_page_column_ready = False
        if byte_wide:
            self._lcd_page_current = -1
            self._lcd_page_port = None
        return False

    def _lcd_page_feed_data(self, address: int, size: int, value: int) -> bool:
        """Record page-RAM data and consume it once the grammar is proven."""
        if (self._lcd_page_port is None
                or address != self._lcd_page_port + 4
                or size not in (1, 2)
                or (size == 2 and value > 0xFF)
                or (self._lcd_page_port == 0x02000000 and size != 1)
                or self._lcd_page_current < 0
                or not self._lcd_page_column_ready):
            return False
        column = self._lcd_page_column
        if 0 <= column < 256:
            self._lcd_page_ram[self._lcd_page_current * 256 + column] = value & 0xFF
        self._lcd_page_column += 1
        self._lcd_page_data_count += 1
        return self._lcd_page_qualified

    def _lcd_byte_rgb565_reset(self) -> None:
        self._lcd_byte_rgb565_commands.clear()
        self._lcd_byte_rgb565_payload = None

    def _lcd_byte_rgb565_begin_command(self, size: int, value: int) -> None:
        """Recognise one complete byte-bus controller setup before pixels."""
        if size != 1:
            self._lcd_byte_rgb565_reset()
            return
        if self._lcd_byte_rgb565_payload is not None:
            self._lcd_byte_rgb565_reset()
        command = value & 0xFF
        position = len(self._lcd_byte_rgb565_commands)
        if (position < len(BYTE_RGB565_BOOT_COMMANDS)
                and command == BYTE_RGB565_BOOT_COMMANDS[position]):
            self._lcd_byte_rgb565_commands.append(command)
            if len(self._lcd_byte_rgb565_commands) == len(BYTE_RGB565_BOOT_COMMANDS):
                self._lcd_byte_rgb565_payload = bytearray()
            return
        self._lcd_byte_rgb565_commands[:] = (
            bytes((command,)) if command == BYTE_RGB565_BOOT_COMMANDS[0] else b""
        )

    def _lcd_byte_rgb565_feed_data(self, address: int, size: int, value: int) -> bool:
        """Render the exact byte-wide, big-endian 96x64 RGB565 boot stream."""
        payload = self._lcd_byte_rgb565_payload
        if payload is None:
            return False
        if address != 0x02800002 or size != 1:
            self._lcd_byte_rgb565_reset()
            return False
        payload.append(value & 0xFF)
        expected = BYTE_RGB565_BOOT_WIDTH * BYTE_RGB565_BOOT_HEIGHT * 2
        if len(payload) > expected:
            self._lcd_byte_rgb565_reset()
            return False
        if len(payload) < expected:
            return True
        if not any(payload):
            self._lcd_byte_rgb565_reset()
            return True
        # A full payload is stronger evidence than the unknown-model default
        # geometry.  Never replace a previously rendered, unrelated panel.
        self._set_display_geometry(
            BYTE_RGB565_BOOT_WIDTH, BYTE_RGB565_BOOT_HEIGHT,
            force=self.frame_sequence == 0,
        )
        if (self.config.width, self.config.height) == (
                BYTE_RGB565_BOOT_WIDTH, BYTE_RGB565_BOOT_HEIGHT):
            for index in range(BYTE_RGB565_BOOT_WIDTH * BYTE_RGB565_BOOT_HEIGHT):
                offset = index * 2
                self._pixel(index, payload[offset] << 8 | payload[offset + 1])
            self._publish_frame()
        self._lcd_byte_rgb565_reset()
        return True

    def _lcd_byte_rgb565_interrupt(self, address: int, size: int) -> None:
        """Reject a partial fingerprint when another LCD transport intervenes."""
        if (not self._lcd_byte_rgb565_commands
                and self._lcd_byte_rgb565_payload is None):
            return
        if address == 0x02800000 and size == 1:
            return
        if (address == 0x02800002 and size == 1
                and self._lcd_byte_rgb565_payload is not None):
            return
        self._lcd_byte_rgb565_reset()

    def _lcd_selector_reset(self) -> None:
        self._lcd_selector_words.clear()
        self._lcd_selector_expected = 0
        self._lcd_selector_window = None
        self._lcd_selector_format = None

    def _lcd_selector_begin_command(self, size: int, value: int) -> bool:
        """Recognise the packed-register selector's exact pixel window."""
        if size != 2:
            self._lcd_selector_reset()
            return False
        if self._lcd_selector_expected:
            self._lcd_selector_reset()
        register, argument = value >> 8 & 0xFF, value & 0xFF
        self._lcd_selector_registers[register] = argument
        mode = self._lcd_selector_registers.get(0x0D)
        if register != 0x0E or argument or mode not in (0, 1):
            return False
        window = tuple(self._lcd_selector_registers.get(register, -1)
                       for register in (0x02, 0x03, 0x04, 0x05))
        x0, y0, x1, y1 = window
        if not (0 <= x0 <= x1 < 320 and 0 <= y0 <= y1 < 320):
            return False
        pixels = (x1 - x0 + 1) * (y1 - y0 + 1)
        self._lcd_selector_window = window
        self._lcd_selector_format = "rgb666" if mode == 0 else "rgb565"
        self._lcd_selector_expected = pixels * (2 if mode == 0 else 1)
        port = (0x02000004, 2)
        stream = self._lcd_raw_streams.get(port)
        if stream is not None:
            stream.clear()
        self._lcd_raw_counts[port] = 0
        return True

    def _lcd_selector_feed(self, size: int, value: int) -> bool:
        """Consume one word from a controller-proven selector window."""
        if not self._lcd_selector_expected:
            return False
        if (size != 2 or (self._lcd_selector_format == "rgb666"
                         and not len(self._lcd_selector_words) % 2
                         and value & ~3)):
            self._lcd_selector_reset()
            return False
        self._lcd_selector_words.append(value & 0xFFFF)
        if len(self._lcd_selector_words) < self._lcd_selector_expected:
            return True
        window = self._lcd_selector_window
        pixel_format = self._lcd_selector_format
        words = self._lcd_selector_words
        assert window is not None and pixel_format is not None
        x0, y0, x1, y1 = window
        geometry = self._lcd_full_window_geometry([x0, x1], [y0, y1])
        current = (self.config.width, self.config.height)
        known = KNOWN_SCREENS.get(getattr(self.config, "model", ""))
        if (geometry is not None and (geometry == current
                                      or (known is None
                                          and current == (176, 220)))):
            self._set_display_geometry(*geometry)
        if x1 < self.config.width and y1 < self.config.height:
            step = 2 if pixel_format == "rgb666" else 1
            width = x1 - x0 + 1
            for index in range(0, len(words), step):
                if pixel_format == "rgb666":
                    pixel = (words[index] & 3) << 16 | words[index + 1]
                    rgb565 = ((pixel >> 13 & 0x1F) << 11
                              | (pixel >> 6 & 0x3F) << 5
                              | (pixel >> 1 & 0x1F))
                else:
                    rgb565 = words[index]
                pixel_index = index // step
                x, y = pixel_index % width + x0, pixel_index // width + y0
                self._pixel(y * self.config.width + x, rgb565)
            self._lcd_protocol = f"selector-{pixel_format}"
            self._publish_frame()
        self._lcd_selector_reset()
        return True

    @staticmethod
    def _lcd_bgr444_rgb565(value: int) -> int:
        blue, green, red = value >> 8 & 0xF, value >> 4 & 0xF, value & 0xF
        return (((red << 1 | red >> 3) << 11)
                | ((green << 2 | green >> 2) << 5)
                | (blue << 1 | blue >> 3))

    def _lcd_bgr444_finish_run(self) -> None:
        if self._lcd_bgr444_run_origin is None or not self._lcd_bgr444_run_words:
            return
        x, y = self._lcd_bgr444_run_origin
        self._lcd_bgr444_runs.append((x, y, tuple(self._lcd_bgr444_run_words)))
        self._lcd_bgr444_run_origin = None
        self._lcd_bgr444_run_words.clear()

    def _lcd_bgr444_raster_geometry(self) -> tuple[int, int] | None:
        if not self._lcd_bgr444_runs:
            return None
        x, y, words = self._lcd_bgr444_runs[0]
        width = len(words)
        if x or y or not 64 <= width <= 320:
            return None
        height = 0
        for x, y, words in self._lcd_bgr444_runs:
            if x or y != height or len(words) != width:
                break
            height += 1
        if not 64 <= height <= 320 or width * height < 0x2000:
            return None
        return width, height

    def _lcd_bgr444_flush(self) -> None:
        if not self._lcd_bgr444_dirty:
            return
        self._lcd_bgr444_finish_run()
        geometry = self._lcd_bgr444_raster_geometry()
        if (geometry is not None
                and geometry != (self.config.width, self.config.height)
                and self.frame_sequence == 0):
            self._set_display_geometry(*geometry, force=True)
            for x0, y, words in self._lcd_bgr444_runs:
                for offset, word in enumerate(words):
                    x = x0 + offset
                    if x < self.config.width and y < self.config.height:
                        self._pixel(y * self.config.width + x,
                                    self._lcd_bgr444_rgb565(word))
        self._lcd_protocol = "cursor-bgr444"
        self._publish_frame()
        self._lcd_bgr444_dirty = False
        self._lcd_bgr444_streamed_pixels = 0
        self._lcd_bgr444_runs.clear()

    def _lcd_bgr444_begin_command(self, size: int, value: int) -> bool:
        """Qualify the cursor-addressed BGR444 command sequence."""
        if size != 2:
            return False
        command = value & 0xFFFF
        if command == 0x03:
            self._lcd_bgr444_finish_run()
            self._lcd_bgr444_command = command
            self._lcd_bgr444_axis_state = 0
            return True
        if command == 0x05 and self._lcd_bgr444_axis_state == 1:
            self._lcd_bgr444_command = command
            return True
        if command == 0x0B and self._lcd_bgr444_axis_state == 3:
            self._lcd_bgr444_command = command
            self._lcd_bgr444_qualified = True
            self._lcd_bgr444_run_origin = tuple(self._lcd_bgr444_cursor)
            self._lcd_bgr444_run_words.clear()
            return True
        if self._lcd_bgr444_qualified:
            self._lcd_bgr444_flush()
        self._lcd_bgr444_command = None
        self._lcd_bgr444_axis_state = 0
        return False

    def _lcd_bgr444_feed(self, size: int, value: int) -> bool:
        """Consume one register or pixel word from the proven BGR444 bus."""
        command = self._lcd_bgr444_command
        if size != 2 or command is None:
            return False
        value &= 0xFFFF
        if command == 0x03:
            self._lcd_bgr444_cursor[0] = value
            self._lcd_bgr444_axis_state = 1
            return True
        if command == 0x05 and self._lcd_bgr444_axis_state == 1:
            self._lcd_bgr444_cursor[1] = value
            self._lcd_bgr444_axis_state = 3
            return True
        if command != 0x0B or not self._lcd_bgr444_qualified:
            return False
        if value & 0xF000:
            self._lcd_bgr444_qualified = False
            return False
        x, y = self._lcd_bgr444_cursor
        if self._lcd_bgr444_run_origin is None:
            self._lcd_bgr444_run_origin = (x, y)
        self._lcd_bgr444_run_words.append(value)
        if 0 <= x < self.config.width and 0 <= y < self.config.height:
            self._pixel(y * self.config.width + x,
                        self._lcd_bgr444_rgb565(value))
            self._lcd_bgr444_dirty = True
        self._lcd_bgr444_cursor[0] += 1
        self._lcd_bgr444_streamed_pixels += 1
        if self._lcd_bgr444_streamed_pixels >= self.config.width * self.config.height:
            self._lcd_bgr444_flush()
        return True

    def _lcd_lowbyte_page_reset(self, *, replay: bool) -> None:
        """Discard a failed sidecar only after restoring its raw FIFO words."""
        words = self._lcd_lowbyte_page_words
        self._lcd_lowbyte_page_stage = ""
        self._lcd_lowbyte_page_page = -1
        self._lcd_lowbyte_page_last = -1
        self._lcd_lowbyte_page_high = -1
        self._lcd_lowbyte_page_rows = 0
        self._lcd_lowbyte_page_words = []
        if replay:
            for word in words:
                self._capture_raw_lcd_stream(
                    0x02000004, 2, word, lowbyte_page_sidecar=False
                )

    def _lcd_lowbyte_page_event(self, address: int, size: int, value: int) -> None:
        """Track a strict sidecar candidate without changing normal routing."""
        stage = self._lcd_lowbyte_page_stage
        data = (address == 0x02000004 and size == 2 and 0 <= value <= 0xFF)
        if stage == "data" and data:
            return
        command = (value if address == 0x02000000 and size == 1
                   and 0 <= value <= 0xFF else None)
        if stage == "high" and command is not None and 0x10 <= command <= 0x1F:
            self._lcd_lowbyte_page_high = command & 0x0F
            self._lcd_lowbyte_page_stage = "low"
            return
        if stage == "low" and command is not None and 0 <= command <= 0x0F:
            if (self._lcd_lowbyte_page_high << 4 | command) == 4:
                self._lcd_lowbyte_page_stage = "data"
                return
        if (stage == "next" and command is not None and 0xB0 <= command <= 0xB7
                and (command & 0x0F) == self._lcd_lowbyte_page_last + 1):
            self._lcd_lowbyte_page_page = command & 0x0F
            self._lcd_lowbyte_page_stage = "high"
            return
        if stage:
            self._lcd_lowbyte_page_reset(replay=True)
        if command is not None and 0xB0 <= command <= 0xB7:
            self._lcd_lowbyte_page_page = command & 0x0F
            self._lcd_lowbyte_page_stage = "high"

    def _lcd_lowbyte_page_raw_word(self, address: int, size: int, value: int) -> bool:
        """Buffer one strict candidate word; suppress only after two rows."""
        if (self._lcd_lowbyte_page_stage != "data" or address != 0x02000004
                or size != 2 or not 0 <= value <= 0xFF):
            return False
        self._lcd_lowbyte_page_words.append(value)
        if len(self._lcd_lowbyte_page_words) % 96:
            return True
        self._lcd_lowbyte_page_last = self._lcd_lowbyte_page_page
        self._lcd_lowbyte_page_rows = min(2, self._lcd_lowbyte_page_rows + 1)
        self._lcd_lowbyte_page_stage = "next"
        if self._lcd_lowbyte_page_rows == 2:
            self._lcd_lowbyte_page_words.clear()
        return True

    def _capture_raw_lcd_stream(self, address: int, size: int, value: int,
                                *, lowbyte_page_sidecar: bool = True) -> None:
        """Render a proven full FIFO stream from an otherwise unknown LCD port.

        Older handsets move RGB565 pixels through board-specific addresses in
        the 0x02000000 LCD aperture.  Their controller programming is still
        firmware-owned, so this fallback deliberately does *not* invent a
        command response: it merely exposes a full, sustained pixel-sized
        write stream after it has happened.  The ordinary command decoders
        take precedence and therefore remain lossless for known panels.
        """
        if (lowbyte_page_sidecar
                and self._lcd_lowbyte_page_raw_word(address, size, value)):
            return
        if size != 2 or not (
                0x02000000 <= address < 0x02001000
                or address in (0x02800004, 0x0280000C)
                or 0x02800020 <= address < 0x02801000):
            return
        # 0x020000FA is the packed LG stream handled above.  Capturing its
        # halfwords again would desynchronise the already validated decoder.
        if address == 0x020000FA:
            return
        pixels = self.config.width * self.config.height
        if pixels <= 0:
            return
        port = (address, size)
        stream = self._lcd_raw_streams.get(port)
        if stream is None:
            stream = deque(maxlen=pixels)
            self._lcd_raw_streams[port] = stream
        stream.append(value & 0xFFFF)
        self._lcd_raw_counts[port] += 1
        # X800-class boards use +2 as a raw RGB565 FIFO.  Preserve each
        # command-delimited transfer separately so an exact 128x160 raster
        # cannot be obscured by later short register/rectangle writes.
        if port == (0x02000002, 2):
            segment = self._lcd_raw_segment_streams.get(port)
            if segment is None:
                segment = deque(maxlen=128 * 160)
                self._lcd_raw_segment_streams[port] = segment
            segment.append(value & 0xFFFF)
            self._lcd_raw_segment_counts[port] += 1
        count = self._lcd_raw_counts[port]
        commands = tuple(self._lcd_recent_commands)
        if (port == (0x02000004, 2) and count == 96
                and len(commands) >= 3 and 0xB0 <= commands[-3] <= 0xB7
                and commands[-2:] == (0x12, 0x00)
                and not any(pixel > 0xFF for pixel in stream)):
            # X150 sends 96 low-byte page words after this exact grammar.
            # They are not fragments of a rolling RGB565 raster.
            stream.clear()
            self._lcd_raw_counts[port] = 0
            return
        # A 128x160 RGB565 scanout is common on the unknown-name Samsung/KTF
        # dumps.  When an otherwise unclassified +4 FIFO reaches *exactly*
        # that full raster before the generic 176x220 threshold, it is stronger
        # evidence than the filename fallback.  Known model geometry is left
        # untouched, as a 128x160 transfer can also be a rectangle update.
        if self.frame_sequence == 0:
            if ((self.config.width, self.config.height) == (176, 220)
                    and address in (0x02000004, 0x02800004, 0x02C00004)
                    and count == 128 * 160):
                self._set_display_geometry(128, 160)
            # The KP8500/LP2400-style FIFO has a fixed 160x240 transfer at
            # an otherwise unused LCD aperture.  Its exact 38,400-pixel run
            # is sufficient proof of panel size before publishing a frame.
            elif ((self.config.width, self.config.height) == (176, 220)
                  and address in (0x02000080, 0x02800080)
                  and count == 160 * 240):
                self._set_display_geometry(160, 240)
            # SCH-E135-class panels issue a command-delimited, exact 128x128
            # RGB565 transfer through the indexed +4 FIFO.  The preceding
            # 0x51/0x43/0x42 programming sequence distinguishes it from a
            # 128x160 panel's first 16K rectangle update.
            elif (address == 0x02800004 and count == 128 * 128
                  and tuple(self._lcd_recent_commands)[-7:]
                  == (0x51, 0x43, 0x00, 0x7F, 0x42, 0x00, 0x7F)):
                values = tuple(stream)
                self._set_display_geometry(128, 128)
                for index, pixel in enumerate(values):
                    self._pixel(index, pixel)
                self._lcd_raw_frames[port] += 1
                self._lcd_raw_port = port
                self._lcd_protocol = f"raw-fifo@0x{address:08X}"
                self._publish_frame()
                return
        pixels = self.config.width * self.config.height
        # A partial transfer is often a command table or a rectangle update;
        # require a complete scanout before treating it as a framebuffer.
        if count < pixels or count % pixels:
            return
        values = tuple(stream)
        if len(values) != pixels or not any(values):
            return
        for index, pixel in enumerate(values):
            self._pixel(index, pixel)
        self._lcd_raw_frames[port] += 1
        self._lcd_raw_port = port
        self._lcd_protocol = f"raw-fifo@0x{address:08X}"
        self._publish_frame()

    def _finish_020_raw_segment(self, incoming_command: int) -> None:
        """Promote the one proven +2 command-delimited 128x160 raster."""
        port = (0x02000002, 2)
        count = self._lcd_raw_segment_counts[port]
        stream = self._lcd_raw_segment_streams.get(port)
        if (stream is not None and count == 128 * 160
                and (self.config.width, self.config.height) == (176, 220)
                and self.frame_sequence == 0
                and incoming_command & 0xFF == 0x43):
            values = tuple(stream)
            if len(values) == 128 * 160 and any(values):
                self._set_display_geometry(128, 160)
                for index, pixel in enumerate(values):
                    self._pixel(index, pixel)
                self._lcd_raw_frames[port] += 1
                self._lcd_raw_port = port
                self._lcd_protocol = "raw-fifo@0x02000002"
                self._publish_frame()
        if stream is not None:
            stream.clear()
        self._lcd_raw_segment_counts[port] = 0

    def _lcd_set_axis(self, command: int, value: int) -> bool:
        """Apply common 8-bit LCD window/cursor registers.

        Samsung's 176x220 BSPs use 0x16/0x17 and 0x22, while later panels
        commonly use 0x2A/0x2B/0x2C or 0x50..0x53.  Values are accepted in
        the compact low-byte/high-byte pair form emitted by the former.
        """
        pair = [value & 0xFF, value >> 8 & 0xFF]
        if command == 0x16:
            self._lcd_x[:] = pair
            return True
        if command == 0x17:
            self._lcd_y[:] = pair
            return True
        if command == 0x50:
            self._lcd_x[0] = value & 0xFF
            return True
        if command == 0x51:
            self._lcd_x[1] = value & 0xFF
            return True
        if command == 0x52:
            self._lcd_y[0] = value & 0xFF
            return True
        if command == 0x53:
            self._lcd_y[1] = value & 0xFF
            return True
        if command == 0x05:
            self._lcd_packed_21_state = int(
                self._lcd_protocol == "parallel-2" and value == 0x0230
                and self._lcd_x == [0, 127] and self._lcd_y == [0, 159]
                and (self.config.width, self.config.height) == (128, 160)
            )
            return bool(self._lcd_packed_21_state)
        if command == 0x20:
            coordinate = value & 0xFF or (value >> 8 & 0xFF)
            self._lcd_cursor[0] = coordinate
            self._lcd_gram_cursor[0] = coordinate
            self._lcd_gram_addressed = True
            self._lcd_packed_21_state = (
                2 if self._lcd_packed_21_state == 1 and value == 0 else 0
            )
            return True
        if command == 0x21:
            if self._lcd_packed_21_state == 2 and value > 0xFF:
                x, y = value & 0xFF, value >> 8 & 0xFF
                if x < self.config.width and y < self.config.height:
                    self._lcd_cursor[:] = [x, y]
                    self._lcd_gram_cursor[:] = [x, y]
                    self._lcd_gram_addressed = True
                    return True
                self._lcd_packed_21_state = 0
            coordinate = value & 0xFF or (value >> 8 & 0xFF)
            self._lcd_cursor[1] = coordinate
            self._lcd_gram_cursor[1] = coordinate
            self._lcd_gram_addressed = True
            return True
        return False

    def _lcd_begin_command(self, value: int) -> None:
        """Start a controller command on any observed command/data transport."""
        self._lcd_finish_direct_args()
        self._lcd_finish_direct_frame()
        # Raw FIFOs are only promoted after a sustained, command-delimited
        # transfer.  Resetting incomplete captures here prevents two partial
        # rectangle updates from being mistaken for one panel-sized frame.
        for port, stream in self._lcd_raw_streams.items():
            # Indexed +4 is the only observed port whose adjacent controller
            # transactions can otherwise merge distinct 128-line rasters.
            # Other raw apertures deliberately retain their rolling capture:
            # their command writes are often unrelated setup traffic.
            if (port[0] == 0x02800004
                    and self._lcd_raw_counts[port]
                    % max(1, self.config.width * self.config.height)):
                stream.clear()
                self._lcd_raw_counts[port] = 0
        self._lcd_command = value & 0xFFFF
        if self._lcd_command not in (0x20, 0x21, 0x22):
            self._lcd_packed_21_state = 0
        self._lcd_recent_commands.append(self._lcd_command & 0xFF)
        self._lcd_args.clear()
        self._lcd_data_byte_latch.clear()
        if (self._lcd_command in LCD_MEMORY_WRITE_COMMANDS
                and not (self._lcd_protocol == "parallel-2"
                         and self._lcd_command == 0x22
                         and self._lcd_gram_addressed)):
            self._lcd_start_direct_frame()
        elif (self._lcd_protocol == "parallel-2" and self._lcd_command == 0x22
              and self._lcd_gram_addressed):
            self._lcd_promote_gram_geometry()

    def _lcd_feed_data(self, address: int, size: int, value: int) -> None:
        """Consume one controller data word shared by the parallel transports."""
        value &= 0xFFFF
        if (self._lcd_protocol == "parallel-2" and self._lcd_command == 0x22
                and self._lcd_gram_addressed):
            self._lcd_write_gram_pixel(value)
            return
        if self._lcd_command in LCD_MEMORY_WRITE_COMMANDS:
            self._lcd_direct_data(value)
            return
        if self._lcd_set_axis(self._lcd_command, value):
            return
        if self._lcd_command in (0x15, 0x75, 0x2A, 0x2B):
            # 0x15/0x75 use compact byte writes on the older Samsung panels;
            # 0x2A/0x2B arrive as 16-bit words on most ILI-style panels.
            if self._lcd_command in (0x2A, 0x2B):
                self._lcd_args.extend((value >> 8 & 0xFF, value & 0xFF))
            else:
                self._lcd_args.append(value & 0xFF)
            if len(self._lcd_args) >= 4:
                pair = [self._lcd_args[0] << 8 | self._lcd_args[1],
                        self._lcd_args[2] << 8 | self._lcd_args[3]]
                target = self._lcd_x if self._lcd_command in (0x15, 0x2A) else self._lcd_y
                target[:] = pair
                self._lcd_args.clear()
            return
        self._capture_raw_lcd_stream(address, size, value)

    def _lcd_feed_parallel_data(self, address: int, size: int, value: int) -> None:
        """Feed a data-port write, joining byte-wide RGB565 transfers safely."""
        if size == 1 and self._lcd_command in LCD_MEMORY_WRITE_COMMANDS:
            first = self._lcd_data_byte_latch.pop(address, None)
            if first is None:
                self._lcd_data_byte_latch[address] = value & 0xFF
                return
            # Parallel LCD buses send the high RGB565 byte first.
            self._lcd_feed_data(address, 2, first << 8 | value & 0xFF)
            return
        self._lcd_feed_data(address, size, value)

    def _lcd_write_gram_pixel(self, value: int) -> None:
        """Write a cursor-addressed ILI/Hitachi GRAM pixel without full copies."""
        x, y = self._lcd_gram_cursor
        if 0 <= x < self.config.width and 0 <= y < self.config.height:
            self._pixel(y * self.config.width + x, value)
            self._lcd_gram_dirty = True
        x += 1
        if x >= self.config.width:
            x, y = 0, y + 1
        self._lcd_gram_cursor[:] = [x, y]

    def _lcd_packed_begin_command(self, value: int) -> bool:
        """Handle the controller-proven +8/+C packed-RGB332 dialect.

        Its 0x45..0x48 registers are a window in *word columns* and 0x4A is
        the only pixel stream command.  A normal 0x22 is merely a register
        write on this bus, so the dialect is enabled only after the complete
        window-programming sequence proves it.
        """
        command = value & 0xFF
        if command in PACKED_RGB332_WINDOW_COMMANDS:
            expected = (0x45 + len(self._lcd_packed_window_order))
            self._lcd_packed_window_order = (
                [command] if command == 0x45
                else [*self._lcd_packed_window_order, command]
                if command == expected else []
            )
            self._lcd_packed_command = command
            return True
        if command == 0x4A:
            self._lcd_packed_command = command
            if self._lcd_packed_window_order != [0x45, 0x46, 0x47, 0x48]:
                return self._lcd_packed_qualified
            self._lcd_packed_window_order.clear()
            x0 = self._lcd_packed_registers.get(0x45, -1)
            y0 = self._lcd_packed_registers.get(0x46, -1)
            x1 = self._lcd_packed_registers.get(0x47, -1)
            y1 = self._lcd_packed_registers.get(0x48, -1)
            columns, rows = x1 - x0 + 1, y1 - y0 + 1
            if not (0 <= x0 <= x1 < 160 and 0 <= y0 <= y1 < 320
                    and 32 <= columns <= 160 and 32 <= rows <= 320):
                return self._lcd_packed_qualified
            width, height = columns * 2, rows
            if (64 <= width <= 320 and 64 <= height <= 320
                    and (self.frame_sequence == 0 or not self._lcd_packed_qualified)
                    and x0 == y0 == 0):
                # Earlier +8 register traffic can look like a tiny generic
                # 0x22 frame.  A complete packed-window sequence is stronger
                # evidence, so it may replace that provisional geometry once.
                self._set_display_geometry(
                    width, height, force=not self._lcd_packed_qualified
                )
            if (x0 * 2 >= self.config.width or x1 * 2 + 1 >= self.config.width
                    or y1 >= self.config.height):
                return self._lcd_packed_qualified
            self._lcd_packed_qualified = True
            self._lcd_packed_window[:] = [x0, y0, x1, y1]
            self._lcd_packed_cursor[:] = [x0, y0]
            self._lcd_packed_expected_words = columns * rows
            self._lcd_packed_streamed_words = 0
            return True
        if self._lcd_packed_qualified:
            self._lcd_packed_command = command
            return True
        return False

    def _lcd_packed_feed_data(self, value: int) -> bool:
        """Consume +C data for a validated packed-RGB332 controller."""
        command = self._lcd_packed_command
        if command in PACKED_RGB332_WINDOW_COMMANDS:
            self._lcd_packed_registers[command] = value & 0xFF
            return True
        if command != 0x4A:
            return self._lcd_packed_qualified
        if not self._lcd_packed_qualified or not self._lcd_packed_expected_words:
            return False
        x, y = self._lcd_packed_cursor
        _x0, _y0, x1, _y1 = self._lcd_packed_window
        high, low = value >> 8 & 0xFF, value & 0xFF
        pixel_x = x * 2
        if 0 <= y < self.config.height and pixel_x + 1 < self.config.width:
            for offset, packed in enumerate((high, low)):
                rgb565 = ((packed & 0xE0) << 8
                          | (packed & 0x1C) << 6
                          | (packed & 0x03) << 3)
                self._pixel(y * self.config.width + pixel_x + offset, rgb565)
        x += 1
        if x > x1:
            x, y = self._lcd_packed_window[0], y + 1
        self._lcd_packed_cursor[:] = [x, y]
        self._lcd_packed_streamed_words += 1
        if self._lcd_packed_streamed_words >= self._lcd_packed_expected_words:
            self._publish_frame()
            self._lcd_packed_expected_words = 0
        return True

    def _lcd_028_direct_probe_write(self, address: int, size: int,
                                    value: int) -> bool:
        """Consume only a complete old Samsung direct-window grammar."""
        base, data = 0x02800000, 0x02800004
        expected: tuple[tuple[int, int, int | None], ...] = (
            (base, 2, 0x75),
            (data, 2, None),
            (data, 2, None),
            (base, 2, 0x15),
            (data, 2, None),
            (data, 2, None),
            (base, 2, 0x5C),
        )
        event = (address, size, value)
        probe = self._lcd_028_direct_probe
        if not probe:
            if self._lcd_protocol == "parallel-2" and event == expected[0]:
                probe.append(event)
                return True
            return False
        wanted_address, wanted_size, wanted_value = expected[len(probe)]
        matches = (address == wanted_address and size == wanted_size
                   and (value <= 0xFF if wanted_value is None
                        else value == wanted_value))
        if not matches:
            held = tuple(probe)
            probe.clear()
            for held_event in held:
                self._lcd_byte_rgb565_interrupt(*held_event[:2])
                self._lcd_write_028_legacy(*held_event)
            return False
        probe.append(event)
        if len(probe) < len(expected):
            return True
        held = tuple(probe)
        probe.clear()
        self._lcd_protocol = "direct"
        for held_event in held:
            self._lcd_byte_rgb565_interrupt(*held_event[:2])
            self._lcd_write_028_legacy(*held_event)
        return True

    def _lcd_write_028_legacy(self, address: int, size: int, value: int) -> None:
        """Handle one 0x028 command/data write outside the direct probe."""
        offset = address - 0x02800000
        if offset == 0:
            self._lcd_byte_rgb565_begin_command(size, value)
            self._lcd_page_begin_command(address, size, value)
            if self._lcd_protocol in ("direct", "parallel-2") or value not in (0, 1):
                if self._lcd_protocol != "parallel-2":
                    self._lcd_protocol = "direct"
                self._lcd_begin_command(value)
                return
            self._lcd_mode = value & 1
            return
        if offset != 4:
            return
        if self._lcd_page_feed_data(address, size, value):
            return
        if self._lcd_protocol == "direct":
            self._lcd_feed_data(address, size, value)
            return
        if not self._lcd_mode:
            self._lcd_begin_command(value)
            return
        self._lcd_feed_data(address, size, value)

    def _lcd_write(self, uc: Uc, access: int, address: int, size: int,
                   value: int, user_data: object) -> None:
        self.lcd_writes += 1
        self.lcd_port_writes[(address, size)] += 1
        self._lcd_lowbyte_page_event(address, size, value)
        # Match every LCD write while a direct-window candidate is held: an
        # intervening aperture access is a mismatch, not a later continuation.
        if self._lcd_028_direct_probe_write(address, size, value & 0xFFFF):
            return
        self._lcd_byte_rgb565_interrupt(address, size)
        if address == 0x020000FA:
            self._lg_pixels.append(value & ((1 << (size * 8)) - 1))
            count = self.config.width * self.config.height * 2
            if len(self._lg_pixels) >= count:
                for index in range(0, count, 2):
                    first, second = self._lg_pixels[index:index + 2]
                    pixel = (((first & 3) << 14) | ((second >> 2) & 0x3800)
                             | ((second >> 1) & 0x07FF))
                    self._pixel(index // 2, pixel)
                del self._lg_pixels[:count]
                self._publish_frame()
            return
        # Two-wire parallel LCD controllers occur at both 0x020 and 0x02C.
        # A few boards instead use the base address as a 0/1 command/data
        # selector and +4 as its payload port.  Keep that transport distinct
        # until a non-selector base value proves an address-line controller.
        if address in (0x02000000, 0x02C00000):
            if (address == 0x02000000 and size == 1
                    and self._lcd_page_begin_command(
                        address, size, value, byte_wide=True
                    )
                    and self._lcd_page_qualified):
                return
            if (value in (0, 1)
                    and self._lcd_protocol not in (
                        "parallel-2", "direct", "cursor-bgr444")):
                if address == 0x02000000 and not value and self._lcd_selector_expected:
                    self._lcd_selector_reset()
                self._lcd_protocol = "selector-4"
                self._lcd_mode = value & 1
            else:
                if address == 0x02000000:
                    self._finish_020_raw_segment(value)
                    if self._lcd_bgr444_begin_command(size, value):
                        return
                self._lcd_protocol = "parallel-2"
                self._lcd_begin_command(value)
            return
        if address in (0x02000002,):
            if self._lcd_bgr444_feed(size, value):
                return
            self._lcd_protocol = "parallel-2"
            self._lcd_feed_parallel_data(address, size, value)
            return
        if address in (0x02000004, 0x02C00004):
            if (address == 0x02000004 and size == 1
                    and self._lcd_page_feed_data(address, size, value)):
                return
            if self._lcd_protocol == "selector-4":
                if self._lcd_mode:
                    if (address == 0x02000004
                            and self._lcd_selector_feed(size, value)):
                        return
                    self._lcd_feed_parallel_data(address, size, value)
                else:
                    if (address == 0x02000004
                            and self._lcd_selector_begin_command(size, value)):
                        return
                    self._lcd_begin_command(value)
            else:
                self._lcd_protocol = "parallel-2"
                self._lcd_feed_parallel_data(address, size, value)
            return
        # Some MSM5500 board designs use the same direct command/data scheme
        # at 0x02800000/+2.  Observe it before the indexed +4 decoder.
        if address == 0x02800002:
            if self._lcd_byte_rgb565_feed_data(address, size, value):
                return
            self._lcd_protocol = "parallel-2"
            self._lcd_feed_parallel_data(address, size, value)
            return
        # A later MSM5500 LCD board variant moves the same command/data pair
        # to +8/+C.  It is distinct from the indexed +16 register path below.
        if address == 0x02800008:
            if self._lcd_packed_begin_command(value):
                return
            self._lcd_protocol = "parallel-8"
            self._lcd_begin_command(value)
            return
        if address == 0x0280000C:
            if self._lcd_packed_feed_data(value):
                return
            self._lcd_protocol = "parallel-8"
            self._lcd_feed_parallel_data(address, size, value)
            return
        if not 0x02800000 <= address <= 0x0280001A:
            self._capture_raw_lcd_stream(address, size, value)
            return
        value &= 0xFFFF
        if address == 0x02800018:
            self._lcd_index = (self._lcd_index & 0xFFFF) | value << 16
            return
        if address == 0x0280001A:
            self._lcd_index = (self._lcd_index & 0xFFFF0000) | value
            return
        if address == 0x02800016:
            self._pixel(self._lcd_index, value)
            pixels = self.config.width * self.config.height
            self._lcd_index = (self._lcd_index + 1) % pixels
            self._lcd_indexed_dirty = True
            if self._lcd_index == 0:
                self._flush_indexed_frame()
            return
        self._lcd_write_028_legacy(address, size, value)

    def _lcd_start_direct_frame(self) -> None:
        spans = [(end - start + 1 if end >= start else ((end - start) & 0xFF) + 1)
                 for start, end in (self._lcd_x, self._lcd_y)]
        # A full 0-based controller window is stronger evidence than the
        # generic 176x220 fallback used for unknown handset names.  Do this
        # only before any frame and never turn a small rectangle update into a
        # new screen size.
        if (self._lcd_full_window_geometry(self._lcd_x, self._lcd_y) is not None
                and spans[0] <= self.config.width and spans[1] <= self.config.height):
            self._set_display_geometry(*spans)
        screen = (self.config.width, self.config.height)
        for axis, (start, span, visible) in enumerate(zip(
                (self._lcd_x[0], self._lcd_y[0]), spans, screen)):
            if span == visible:
                self._lcd_direct_origin[axis] = start
                self._lcd_direct_calibrated[axis] = True
            elif span > visible and not self._lcd_direct_calibrated[axis]:
                self._lcd_direct_origin[axis] = (start + (span - visible) // 2) & 0xFF
        self._lcd_direct_window = spans
        self._lcd_direct_cursor = [0, 0]
        self._lcd_expected = spans[0] * spans[1]
        self._lcd_streamed = 0

    def _lcd_finish_direct_args(self) -> None:
        if self._lcd_command not in (0x15, 0x75) or len(self._lcd_args) < 2:
            return
        if len(self._lcd_args) >= 4:
            pair = [self._lcd_args[0] | self._lcd_args[1] << 8,
                    self._lcd_args[2] | self._lcd_args[3] << 8]
        else:
            pair = self._lcd_args[:2]
        target = self._lcd_x if self._lcd_command == 0x15 else self._lcd_y
        target[:] = pair

    def _lcd_finish_direct_frame(self) -> None:
        if (self._lcd_command in LCD_MEMORY_WRITE_COMMANDS
                and self._lcd_expected and self._lcd_streamed):
            self._publish_frame()
            self._lcd_expected = 0

    def _lcd_direct_data(self, value: int) -> None:
        if self._lcd_command in (0x15, 0x75):
            if len(self._lcd_args) < 4:
                self._lcd_args.append(value & 0xFF)
            return
        if self._lcd_set_axis(self._lcd_command, value):
            return
        if (self._lcd_command not in LCD_MEMORY_WRITE_COMMANDS
                or not self._lcd_expected):
            return
        column, row = self._lcd_direct_cursor
        raw_x = (self._lcd_x[0] + column) & 0xFF
        raw_y = (self._lcd_y[0] + row) & 0xFF
        x = (raw_x - self._lcd_direct_origin[0]) & 0xFF
        y = (raw_y - self._lcd_direct_origin[1]) & 0xFF
        if x < self.config.width and y < self.config.height:
            self._pixel(y * self.config.width + x, value)
        column += 1
        if column >= self._lcd_direct_window[0]:
            column, row = 0, row + 1
        self._lcd_direct_cursor = [column, row]
        self._lcd_streamed += 1
        if self._lcd_streamed >= self._lcd_expected:
            self._publish_frame()
            self._lcd_expected = 0

    def _apply_linker(self) -> None:
        layout = self.config.linker
        if layout is None:
            return
        source = self.config.load_address + layout.data_source
        data = bytes(self.uc.mem_read(source, layout.data_size))
        self.uc.mem_write(layout.data_target, data)
        self.uc.mem_write(layout.bss_target, b"\0" * layout.bss_size)
        for overlay in self.config.overlays:
            data = bytes(self.uc.mem_read(self.config.load_address + overlay.source,
                                          overlay.size))
            self.uc.mem_write(overlay.target, data)
        self.fast_boot_used = True

    def _fast_boot_hook(self, uc: Uc, address: int, size: int,
                        user_data: object) -> None:
        if self.config.linker is None:
            return
        try:
            if bytes(uc.mem_read(address, len(FAST_BOOT_SIGNATURE))) != FAST_BOOT_SIGNATURE:
                return
        except UcError:
            return
        if not self.fast_boot_used:
            self._apply_linker()
        if not self.fast_boot_used:
            return
        lr = uc.reg_read(UC_ARM_REG_LR)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_PC, lr & ~1)
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x20 if lr & 1 else cpsr & ~0x20)

    @staticmethod
    def _thumb_loop_exit(uc: Uc, address: int) -> int | None:
        branch = struct.unpack("<H", uc.mem_read(address + 2, 2))[0]
        if branch & 0xFF00 != 0xD200:  # BHS
            return None
        displacement = (branch & 0xFF) * 2
        if displacement & 0x100:
            displacement -= 0x200
        return address + 6 + displacement

    def _original_runtime_bytes(self, address: int, length: int) -> bytes | None:
        """Map relocated runtime code back to the pristine firmware image."""
        end = address + length
        if length <= 0 or not 0 <= address < end <= ADDRESS_SPACE:
            return None
        offsets: list[int] = []
        for overlay in self.config.overlays:
            if overlay.target <= address and end <= overlay.target + overlay.size:
                offsets.append(overlay.source + address - overlay.target)
        if not offsets:
            layout = self.config.linker
            if (layout is not None and layout.data_target <= address
                    and end <= layout.data_target + layout.data_size):
                offsets.append(layout.data_source + address - layout.data_target)
            elif (self.config.load_address <= address
                  and end <= self.config.load_address + self.config.flash_size):
                offsets.append(address - self.config.load_address)
            else:
                return None
        original = self.original_image
        candidates = [original[offset:offset + length] for offset in offsets
                      if 0 <= offset and offset + length <= len(original)]
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        # Several runtime overlays can deliberately reuse the same internal-RAM
        # target.  Resolve the active bank from the bytes firmware actually
        # copied instead of treating the first table entry as permanent.
        try:
            runtime = bytes(self.uc.mem_read(address, length))
        except UcError:
            return None
        matching = [candidate for candidate in candidates if candidate == runtime]
        return matching[0] if matching else None

    def _thumb_runtime_matches(self, uc: Uc, address: int,
                               signature: bytes | None = None,
                               prefix_size: int = 32) -> bool:
        """Accept HLE only while Thumb code still matches its pristine body."""
        try:
            if not uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                return False
            expected = (signature if signature is not None
                        else self._original_runtime_bytes(address, prefix_size))
            return (expected is not None
                    and bytes(uc.mem_read(address, len(expected))) == expected)
        except UcError:
            return False

    def _hle_destination_is_ram(self, address: int, length: int) -> bool:
        end = address + length
        return (0 <= address <= end <= ADDRESS_SPACE
                and (self.config.ram_base <= address <= end
                     <= self.config.ram_base + self.config.ram_size
                     or 0x03800000 <= address <= end <= 0x03A00000))

    def _hle_destination_is_declared(self, address: int, length: int) -> bool:
        """Accept structural Thumb HLE only for a proven load destination.

        A valid Thumb clear/copy shape by itself is not enough: old BSPs also
        use the same loop for temporary work areas whose lifetime depends on
        device callbacks.  The automatic HLE therefore restricts itself to
        the detected scatter-load data/BSS interval or a boot overlay target.
        Explicit per-signature HLEs retain their existing RAM checks.
        """
        if not self._hle_destination_is_ram(address, length):
            return False
        end = address + length
        ranges: list[tuple[int, int]] = []
        if self.config.linker is not None:
            ranges.append((
                self.config.linker.data_target,
                self.config.linker.bss_target + self.config.linker.bss_size,
            ))
        ranges.extend((overlay.target, overlay.target + overlay.size)
                      for overlay in self.config.overlays)
        return any(start <= address <= end <= stop for start, stop in ranges)

    def _bootstrap_hle_is_early(self) -> bool:
        """Keep the inferred scatter-chain lease out of normal runtime code."""
        return (self.reset_entries == 1 and self.instructions <= 1_000_000
                and not self.lcd_writes and not self.frame_sequence
                and not self.rex_ticks and not self.input_events)

    def _primary_nor_contains(self, address: int, end: int) -> bool:
        return (self.flash.phase == "idle"
                and self.config.load_address <= address <= end
                <= self.primary_rom_end)

    def _thumb_watchdog_strobe(self, address: int) -> bool:
        """Recognise a local one-to-zero write to MSM hardware after init work."""
        try:
            one, literal, store_one, zero, store_zero = struct.unpack(
                "<5H", self.uc.mem_read(address, 10)
            )
        except UcError:
            return False
        value_register = one >> 8 & 7
        base_register = literal >> 8 & 7
        zero_register = zero >> 8 & 7
        if (one & 0xF800 != 0x2000 or one & 0xFF != 1
                or literal & 0xF800 != 0x4800
                or store_one & 0xF800 != 0x7000
                or store_one >> 6 & 0x1F
                or store_one & 7 != value_register
                or store_one >> 3 & 7 != base_register
                or zero & 0xF800 != 0x2000 or zero & 0xFF
                or store_zero & 0xF800 != 0x7000
                or store_zero >> 6 & 0x1F
                or store_zero & 7 != zero_register
                or store_zero >> 3 & 7 != base_register):
            return False
        literal_address = ((address + 2 + 4) & ~3) + (literal & 0xFF) * 4
        try:
            target = struct.unpack("<I", self.uc.mem_read(literal_address, 4))[0]
        except UcError:
            return False
        return 0x03000000 <= target < 0x03800000

    def _bootstrap_copy_stage(self, destination: int, source: int, limit: int,
                              source_end: int, exit_address: int) -> str | None:
        """Return the one permitted bootstrap-copy stage, if proven."""
        if (not self._bootstrap_hle_is_early()
                or not self._primary_nor_contains(source, source_end)
                or not self._thumb_watchdog_strobe(exit_address)):
            return None
        ram_start = self.config.ram_base
        ram_end = ram_start + self.config.ram_size
        if (self._bootstrap_data_end is None
                and ram_start <= destination <= ram_start + BOOTSTRAP_HLE_SLACK
                and ram_start < limit <= ram_end):
            return "data"
        if (self._bootstrap_bss_complete and self._bootstrap_iram_end is None
                and self._bootstrap_rom_end is not None
                and self._bootstrap_rom_end
                <= source <= self._bootstrap_rom_end + BOOTSTRAP_HLE_SLACK
                and 0x03800000 <= destination
                <= 0x03800000 + BOOTSTRAP_HLE_SLACK
                and 0x03800000 < limit <= 0x03A00000):
            return "iram"
        return None

    def _bootstrap_clear_stage(self, destination: int, stop: int,
                               full_limit: int | None,
                               strobe_address: int | None) -> str | None:
        """Lease only the BSS span immediately following a bootstrap copy."""
        if (full_limit is None or strobe_address is None
                or not self._bootstrap_hle_is_early()
                or not self._thumb_watchdog_strobe(strobe_address)):
            return None
        ram_end = self.config.ram_base + self.config.ram_size
        if (self._bootstrap_bss_end is None
                and self._bootstrap_data_end is not None
                and self._bootstrap_data_end <= destination
                <= self._bootstrap_data_end + BOOTSTRAP_HLE_SLACK
                and destination < stop <= full_limit <= ram_end):
            return "open"
        if (self._bootstrap_bss_end is not None
                and self._bootstrap_data_end is not None
                and full_limit == self._bootstrap_bss_end
                and self._bootstrap_data_end <= destination < stop
                <= self._bootstrap_bss_end):
            return "continue"
        return None

    def _hle_source_is_safe(self, address: int, length: int) -> bool:
        end = address + length
        if not 0 <= address <= end <= ADDRESS_SPACE:
            return False
        ranges = [
            (self.config.ram_base, self.config.ram_base + self.config.ram_size),
            (0x03800000, 0x03A00000),
            *((item.target, item.target + item.size)
              for item in self.config.overlays),
        ]
        if self.flash.phase == "idle":
            ranges.append((self.config.load_address,
                           self.config.load_address + self.config.flash_size))
        secondary = self.config.secondary_flash_address
        if (secondary not in (None, 0) and self.secondary_flash is not None
                and self.secondary_flash.phase == "idle"):
            ranges.append((secondary,
                           secondary + self.config.secondary_flash_size))
        return any(start <= address <= end <= stop for start, stop in ranges)

    @staticmethod
    def _thumb_unconditional_target(address: int, instruction: int) -> int | None:
        """Return the target of a 16-bit Thumb unconditional branch."""
        if instruction & 0xF800 != 0xE000:
            return None
        displacement = (instruction & 0x7FF) << 1
        if displacement & 0x800:
            displacement -= 0x1000
        return address + 4 + displacement

    @staticmethod
    def _thumb_conditional_target(address: int, instruction: int) -> int | None:
        """Return the target of a 16-bit Thumb conditional branch."""
        if instruction & 0xF000 != 0xD000:
            return None
        displacement = (instruction & 0xFF) << 1
        if displacement & 0x100:
            displacement -= 0x200
        return address + 4 + displacement

    @staticmethod
    def _thumb_add3(instruction: int) -> tuple[int, int, int] | None:
        """Decode ``ADDS Rd, Rs, #imm3`` (including the MOV alias)."""
        if instruction & 0xFE00 != 0x1C00:
            return None
        return instruction & 7, instruction >> 3 & 7, instruction >> 6 & 7

    @staticmethod
    def _thumb_memory_zero(instruction: int, opcode: int) -> tuple[int, int] | None:
        """Decode a zero-offset Thumb LDR/STR word as (Rt, Rn)."""
        if (instruction & 0xF800) != opcode or (instruction >> 6 & 0x1F):
            return None
        return instruction & 7, instruction >> 3 & 7

    @staticmethod
    def _thumb_movs_zero(instruction: int) -> int | None:
        if instruction & 0xF800 != 0x2000 or instruction & 0xFF:
            return None
        return instruction >> 8 & 7

    @staticmethod
    def _thumb_lsls_immediate(instruction: int) -> tuple[int, int, int] | None:
        if instruction & 0xF800:
            return None
        return instruction & 7, instruction >> 3 & 7, instruction >> 6 & 0x1F

    @staticmethod
    def _set_thumb_cmp_equal_flags(uc: Uc) -> None:
        """Leave the flags produced by an equal unsigned CMP (Z=1, C=1)."""
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        cpsr &= ~0x90000000  # N and V
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x60000020)

    def _complete_hot_copy(self, uc: Uc, destination_register: int,
                           source_register: int, end_register: int,
                           source_temp: int, destination_temp: int,
                           exit_address: int) -> bool:
        """Bulk-complete one validated forward Thumb word copy loop."""
        registers = [uc.reg_read(register) & 0xFFFFFFFF
                     for register in THUMB_LOW_REGISTERS]
        destination = registers[destination_register]
        source = registers[source_register]
        limit = registers[end_register]
        length = limit - destination
        source_end = source + length
        bootstrap_stage = self._bootstrap_copy_stage(
            destination, source, limit, source_end, exit_address,
        )
        if (length <= 0 or length & 3 or length > self.config.ram_size
                or source_end > ADDRESS_SPACE
                or not (self._hle_destination_is_declared(destination, length)
                        or bootstrap_stage is not None)
                or not self._hle_source_is_safe(source, length)
                or max(destination, source) < min(limit, source_end)):
            return False
        try:
            data = bytes(uc.mem_read(source, length))
            # Validate the destination before changing it.  The range helper
            # is deliberately not a substitute for Unicorn's real mapping.
            uc.mem_read(destination, length)
        except UcError:
            return False
        uc.mem_write(destination, data)
        uc.ctl_remove_cache(destination, limit)
        # Preserve the instruction-order semantics of the final update block.
        uc.reg_write(THUMB_LOW_REGISTERS[source_temp], source_end)
        uc.reg_write(THUMB_LOW_REGISTERS[source_register],
                     uc.reg_read(THUMB_LOW_REGISTERS[source_temp]))
        uc.reg_write(THUMB_LOW_REGISTERS[destination_temp], limit)
        uc.reg_write(THUMB_LOW_REGISTERS[destination_register],
                     uc.reg_read(THUMB_LOW_REGISTERS[destination_temp]))
        self._set_thumb_cmp_equal_flags(uc)
        # In a block hook, an aligned PC write can make Unicorn clear T after
        # the flags register was sampled.  Commit Thumb state first and retain
        # the architectural branch bit on the target write.
        uc.reg_write(UC_ARM_REG_PC, exit_address | 1)
        if bootstrap_stage == "data":
            self._bootstrap_data_end = limit
            self._bootstrap_rom_end = source_end
        elif bootstrap_stage == "iram":
            self._bootstrap_iram_end = limit
        self.fast_memory_copies += 1
        return True

    def _complete_hot_clear(self, uc: Uc, destination_register: int,
                            temporary_register: int, zero_register: int,
                            stop: int, next_pc: int,
                            equal_flags: bool,
                            bootstrap_limit: int | None = None,
                            bootstrap_strobe: int | None = None) -> bool:
        """Clear a validated RAM span and resume at firmware-owned control flow."""
        destination = uc.reg_read(THUMB_LOW_REGISTERS[destination_register])
        length = stop - destination
        bootstrap_stage = self._bootstrap_clear_stage(
            destination, stop, bootstrap_limit, bootstrap_strobe,
        )
        if (length <= 0 or length & 3 or length > self.config.ram_size
                or not (self._hle_destination_is_declared(destination, length)
                        or bootstrap_stage is not None)):
            return False
        try:
            uc.mem_read(destination, length)
        except UcError:
            return False
        uc.mem_write(destination, b"\0" * length)
        uc.ctl_remove_cache(destination, stop)
        uc.reg_write(THUMB_LOW_REGISTERS[zero_register], 0)
        if equal_flags:
            # The native final update leaves both aliases pointing at ``stop``.
            uc.reg_write(THUMB_LOW_REGISTERS[temporary_register], stop)
            uc.reg_write(THUMB_LOW_REGISTERS[destination_register], stop)
            self._set_thumb_cmp_equal_flags(uc)
        else:
            uc.reg_write(THUMB_LOW_REGISTERS[destination_register], stop)
            uc.reg_write(UC_ARM_REG_CPSR, uc.reg_read(UC_ARM_REG_CPSR) | 0x20)
        uc.reg_write(UC_ARM_REG_PC, next_pc | 1)
        if bootstrap_stage == "open":
            assert bootstrap_limit is not None
            self._bootstrap_bss_end = bootstrap_limit
        if (bootstrap_stage in ("open", "continue")
                and self._bootstrap_bss_end is not None
                and stop == self._bootstrap_bss_end):
            self._bootstrap_bss_complete = True
        self.fast_memory_clears += 1
        return True

    def _try_hot_thumb_memory_loop(self, uc: Uc, address: int) -> bool:
        """Recognise tightly-scoped, compiler-shaped Thumb RAM init loops.

        Partial handset dumps often retain valid boot code but omit enough
        peripherals that spending millions of interpreted instructions in a
        BSS/scatter-load loop prevents reaching the first LCD task.  The HLE
        is intentionally structural rather than signature based: it accepts
        only pristine Thumb code, only after 64 repeated blocks, and only a
        fully verified header/update/body CFG whose destination is real RAM.
        """
        count = self.hot[address]
        if count < 64 or count & 0x3F:
            return False
        if not self._thumb_runtime_matches(uc, address, prefix_size=0x40):
            return False
        try:
            words = struct.unpack("<32H", uc.mem_read(address, 0x40))
        except UcError:
            return False
        compare, branch_high_or_same, skip_to_body = words[:3]
        if (compare & 0xFFC0 != 0x4280
                or branch_high_or_same & 0xFF00 != 0xD200):
            return False
        body = self._thumb_unconditional_target(address + 4, skip_to_body)
        exit_address = self._thumb_conditional_target(address + 2,
                                                      branch_high_or_same)
        if (body is None or exit_address is None
                or not address + 6 <= body <= address + 0x20
                or body >= exit_address):
            return False
        destination_register = compare & 7
        end_register = compare >> 3 & 7
        if destination_register == end_register:
            return False
        update = address + 6
        body_index = (body - address) // 2

        # Forward word copy:
        #   adds tmp,src,#4; adds src,tmp,#0;
        #   adds tmp2,dst,#4; adds dst,tmp2,#0; b header
        # body: ldr word,[src]; str word,[dst]; b update
        copy_adds = [self._thumb_add3(word) for word in words[3:7]]
        if (body == update + 10 and body_index == 8
                and all(item is not None for item in copy_adds)
                and self._thumb_unconditional_target(update + 8, words[7])
                == address and body_index + 2 < len(words)):
            source_temp, source_register, source_increment = copy_adds[0]  # type: ignore[misc]
            move_source, source_from_temp, source_move = copy_adds[1]  # type: ignore[misc]
            destination_temp, destination_from, destination_increment = copy_adds[2]  # type: ignore[misc]
            move_destination, destination_from_temp, destination_move = copy_adds[3]  # type: ignore[misc]
            load = self._thumb_memory_zero(words[body_index], 0x6800)
            store = self._thumb_memory_zero(words[body_index + 1], 0x6000)
            if (source_increment == destination_increment == 4
                    and source_move == destination_move == 0
                    and move_source == source_register
                    and source_from_temp == source_temp
                    and destination_from == destination_register
                    and move_destination == destination_register
                    and destination_from_temp == destination_temp
                    and self._thumb_unconditional_target(
                        body + 4, words[body_index + 2]
                    ) == update
                    and load is not None and store is not None
                    and load[1] == source_register and store[1] == destination_register
                    and load[0] == store[0]
                    and len({destination_register, source_register, end_register}) == 3
                    and source_temp not in {
                        destination_register, source_register, end_register
                    }
                    and destination_temp not in {
                        destination_register, source_register, end_register
                    }):
                return self._complete_hot_copy(
                    uc, destination_register, source_register, end_register,
                    source_temp, destination_temp, exit_address,
                )

        # Simple word clear:
        #   adds tmp,dst,#4; adds dst,tmp,#0; b header
        # body: movs zero,#0; str zero,[dst]; b update
        clear_adds = [self._thumb_add3(word) for word in words[3:5]]
        if (body == update + 6 and body_index == 6
                and all(item is not None for item in clear_adds)
                and self._thumb_unconditional_target(update + 4, words[5])
                == address and body_index + 2 < len(words)):
            temporary_register, source_register, increment = clear_adds[0]  # type: ignore[misc]
            move_destination, temporary_source, move = clear_adds[1]  # type: ignore[misc]
            zero_register = self._thumb_movs_zero(words[body_index])
            store = self._thumb_memory_zero(words[body_index + 1], 0x6000)
            if (increment == 4 and move == 0
                    and source_register == destination_register
                    and move_destination == destination_register
                    and temporary_source == temporary_register
                    and temporary_register not in {destination_register, end_register}
                    and zero_register is not None and store is not None
                    and store == (zero_register, destination_register)
                    and self._thumb_unconditional_target(
                        body + 4, words[body_index + 2]
                    ) == update):
                stop = uc.reg_read(THUMB_LOW_REGISTERS[end_register])
                return self._complete_hot_clear(
                    uc, destination_register, temporary_register, zero_register,
                    stop, exit_address, equal_flags=True,
                )

        # Progress clear, used by KP2000-like boot code.  Its zero-boundary
        # fallthrough often kicks a watchdog, so stop at the next boundary and
        # let the native firmware execute that single boundary iteration.
        if (body == update + 6 and body_index == 6
                and all(item is not None for item in clear_adds)
                and self._thumb_unconditional_target(update + 4, words[5])
                == address and body_index + 3 < len(words)):
            temporary_register, source_register, increment = clear_adds[0]  # type: ignore[misc]
            move_destination, temporary_source, move = clear_adds[1]  # type: ignore[misc]
            zero_register = self._thumb_movs_zero(words[body_index])
            store = self._thumb_memory_zero(words[body_index + 1], 0x6000)
            shift = self._thumb_lsls_immediate(words[body_index + 2])
            bne = words[body_index + 3]
            has_fallthrough_branch = any(
                self._thumb_unconditional_target(address + index * 2, word)
                == update
                for index, word in enumerate(words[body_index + 4:], body_index + 4)
                if address + index * 2 < exit_address
            )
            if (increment == 4 and move == 0
                    and source_register == destination_register
                    and move_destination == destination_register
                    and temporary_source == temporary_register
                    and temporary_register not in {destination_register, end_register}
                    and zero_register is not None and store is not None
                    and store == (zero_register, destination_register)
                    and shift is not None and shift[1] == destination_register
                    and 1 <= shift[2] <= 31
                    and bne & 0xFF00 == 0xD100
                    and self._thumb_conditional_target(body + 6, bne) == update
                    and has_fallthrough_branch):
                destination = uc.reg_read(THUMB_LOW_REGISTERS[destination_register])
                limit = uc.reg_read(THUMB_LOW_REGISTERS[end_register])
                period = 1 << (32 - shift[2])
                next_boundary = min(limit, (destination + period - 1) & -period)
                if next_boundary == destination:
                    return False
                return self._complete_hot_clear(
                    uc, destination_register, temporary_register, zero_register,
                    next_boundary, address, equal_flags=False,
                    bootstrap_limit=limit, bootstrap_strobe=body + 8,
                )
        return False

    def _fast_memory_clear(self, uc: Uc, address: int, size: int,
                           user_data: object) -> None:
        try:
            if not uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                return
            old_loop = (bytes(uc.mem_read(
                address, len(MEMORY_CLEAR_LOOP_SIGNATURE)
            )) == MEMORY_CLEAR_LOOP_SIGNATURE)
            unrolled = bytes(uc.mem_read(address, 0x80))
        except UcError:
            return
        start = uc.reg_read(UC_ARM_REG_R4)
        end = uc.reg_read(UC_ARM_REG_R6)
        target = self._thumb_loop_exit(uc, address) if old_loop else None
        if (not old_loop
                and unrolled.startswith(MEMORY_CLEAR_128_SIGNATURE)
                and uc.reg_read(UC_ARM_REG_R0) == 0):
            tail = unrolled.find(bytes.fromhex("8034b442"))
            if 0 <= tail <= len(unrolled) - 6:
                branch = struct.unpack_from("<H", unrolled, tail + 4)[0]
                displacement = (branch & 0xFF) * 2
                if displacement & 0x100:
                    displacement -= 0x200
                branch_address = address + tail + 4
                if (branch & 0xFF00 == 0xD300
                        and branch_address + 4 + displacement <= address):
                    target = branch_address + 2
        ram_end = self.config.ram_base + self.config.ram_size
        if (target is None or not self.config.ram_base <= start <= end <= ram_end
                or end - start > self.config.ram_size):
            return
        length = end - start
        uc.mem_write(start, b"\0" * length)
        if length:
            uc.ctl_remove_cache(start, end)
        uc.reg_write(UC_ARM_REG_R4, end)
        uc.reg_write(UC_ARM_REG_PC, target)
        uc.reg_write(UC_ARM_REG_CPSR, uc.reg_read(UC_ARM_REG_CPSR) | 0x20)
        self.fast_memory_clears += 1

    def _fast_memory_copy(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        try:
            if (not uc.reg_read(UC_ARM_REG_CPSR) & 0x20
                    or bytes(uc.mem_read(address, len(MEMORY_COPY_LOOP_SIGNATURE)))
                    != MEMORY_COPY_LOOP_SIGNATURE):
                return
        except UcError:
            return
        destination = uc.reg_read(UC_ARM_REG_R4)
        source = uc.reg_read(UC_ARM_REG_R5)
        end = uc.reg_read(UC_ARM_REG_R6)
        target = self._thumb_loop_exit(uc, address)
        ram_end = self.config.ram_base + self.config.ram_size
        length = end - destination
        source_end = source + length
        source_ranges = [
            (self.config.ram_base, ram_end),
            (0x03800000, 0x03A00000),
            *((overlay.target, overlay.target + overlay.size)
              for overlay in self.config.overlays),
        ]
        if self.flash.phase == "idle":
            source_ranges.append((
                self.config.load_address,
                self.config.load_address + self.config.flash_size,
            ))
        secondary = self.config.secondary_flash_address
        if (secondary not in (None, 0) and self.secondary_flash is not None
                and self.secondary_flash.phase == "idle"):
            source_ranges.append((
                secondary, secondary + self.config.secondary_flash_size,
            ))
        source_is_backed = any(
            start <= source <= source_end <= stop for start, stop in source_ranges
        )
        overlaps = (destination != source
                    and max(destination, source) < min(end, source_end))
        if (target is None
                or not self.config.ram_base <= destination <= end <= ram_end
                or length > self.config.ram_size
                or source_end > ADDRESS_SPACE or not source_is_backed or overlaps):
            return
        try:
            data = bytes(uc.mem_read(source, length))
            if length:
                uc.mem_read(destination, length)
        except UcError:
            return
        uc.mem_write(destination, data)
        if length:
            uc.ctl_remove_cache(destination, end)
        uc.reg_write(UC_ARM_REG_R4, end)
        uc.reg_write(UC_ARM_REG_R5, source + len(data))
        uc.reg_write(UC_ARM_REG_PC, target)
        uc.reg_write(UC_ARM_REG_CPSR, uc.reg_read(UC_ARM_REG_CPSR) | 0x20)
        self.fast_memory_copies += 1

    def _fast_register_ramp(self, uc: Uc, address: int, size: int,
                            user_data: object) -> None:
        """Collapse redundant writes in a validated 50-count hardware ramp."""
        prefix_address = address - len(REGISTER_RAMP_PREFIX)
        if (not self._thumb_runtime_matches(
                uc, prefix_address, REGISTER_RAMP_PREFIX)
                or uc.reg_read(UC_ARM_REG_R0) <= 50):
            return
        try:
            loop = bytes(uc.mem_read(address, 8))
            if loop != bytes.fromhex("3c8032383228fbdc"):
                return
            target = uc.reg_read(UC_ARM_REG_R7)
            uc.mem_write(target, struct.pack("<H", uc.reg_read(UC_ARM_REG_R4) & 0xFFFF))
        except UcError:
            return
        value = uc.reg_read(UC_ARM_REG_R0)
        # Leave one final original loop iteration so flags and the following
        # interpolation calculation remain firmware-owned.
        uc.reg_write(UC_ARM_REG_R0, (value - 1) % 50 + 51)
        self.fast_register_ramps += 1

    def _fast_arm_memory_copy(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Accelerate the ARM ADS forward copier without hiding unsafe calls."""
        if uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
            return
        try:
            runtime_prefix = bytes(uc.mem_read(
                address, len(ARM_MEMORY_COPY_SIGNATURE)
            ))
            runtime_tail = bytes(uc.mem_read(
                address + ARM_MEMORY_COPY_TAIL_OFFSET,
                len(ARM_MEMORY_COPY_TAIL),
            ))
        except UcError:
            return
        if (runtime_prefix != ARM_MEMORY_COPY_SIGNATURE
                or runtime_tail != ARM_MEMORY_COPY_TAIL):
            return
        destination = uc.reg_read(UC_ARM_REG_R0)
        source = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        destination_end = destination + length
        source_end = source + length
        ram_end = self.config.ram_base + self.config.ram_size
        destination_is_ram = (
            self.config.ram_base <= destination <= destination_end <= ram_end
            or 0x03800000 <= destination <= destination_end <= 0x03A00000
        )
        source_ranges = [
            (self.config.ram_base, ram_end),
            (0x03800000, 0x03A00000),
            *((overlay.target, overlay.target + overlay.size)
              for overlay in self.config.overlays),
        ]
        if self.flash.phase == "idle":
            source_ranges.append((
                self.config.load_address,
                self.config.load_address + self.config.flash_size,
            ))
        secondary = self.config.secondary_flash_address
        if (secondary not in (None, 0) and self.secondary_flash is not None
                and self.secondary_flash.phase == "idle"):
            source_ranges.append((
                secondary, secondary + self.config.secondary_flash_size,
            ))
        source_is_backed = any(
            start <= source <= source_end <= end for start, end in source_ranges
        )
        overlaps = (destination != source
                    and max(destination, source) < min(destination_end, source_end))
        if (not destination_is_ram or not source_is_backed
                or length > self.config.ram_size
                or destination_end > ADDRESS_SPACE or source_end > ADDRESS_SPACE
                or overlaps):
            return
        try:
            data = bytes(uc.mem_read(source, length))
            if length:
                # Validate the whole destination before changing any byte.
                uc.mem_read(destination, length)
                uc.mem_write(destination, data)
                uc.ctl_remove_cache(destination, destination_end)
        except UcError:
            return
        # The detected ADS routine advances both pointer arguments.  R2/R3/IP
        # are caller-clobbered; callers may still rely on the returned end ptr.
        uc.reg_write(UC_ARM_REG_R0, destination_end)
        uc.reg_write(UC_ARM_REG_R1, source_end)
        self._return_to_lr(uc, address, size, user_data)
        self.fast_arm_memory_copies += 1

    def _flash_write(self, uc: Uc, access: int, address: int, size: int,
                     value: int, user_data: object) -> None:
        board = self.config.board_revision_register
        if (board is not None
                and max(address, board) < min(address + size, board + 4)):
            return
        base, flash = user_data
        relative = address - base
        replacement = flash.write(relative, size, value)
        if replacement is None:
            return
        if flash.modified_range is not None:
            start, end = flash.modified_range
            uc.mem_write(base + start, bytes(flash.data[start:end]))
            uc.ctl_remove_cache(base + start, base + end)
        self._flash_restore[address] = replacement

    def _flash_read(self, uc: Uc, access: int, address: int, size: int,
                    value: int, user_data: object) -> None:
        board = self.config.board_revision_register
        if (board is not None
                and max(address, board) < min(address + size, board + 4)):
            return
        # Unicorn write hooks observe a store just before it lands.  Restore on
        # the following read so same-basic-block RAM probes still see real NOR.
        self._restore_flash_once(uc, address, size, user_data)
        base, flash = user_data
        if flash is self.flash and flash.phase == "autoselect" and flash.ids is None:
            flash.ids = self._detect_primary_flash_ids()
        relative = address - base
        uc.mem_write(address, flash.read(relative, size))

    def _ensure_eeprom(self, uc: Uc) -> bool:
        """Load the proven 24LCxx capacity and its persistent byte image."""
        geometry = self.config.eeprom_geometry_address
        if not self.eeprom_enabled or geometry is None:
            return False
        try:
            descriptor = bytes(uc.mem_read(geometry, 4))
            capacity = int.from_bytes(descriptor[:2], "little")
        except UcError:
            return False
        # The currently proven driver configuration is a 24LC256.  Other
        # descriptor layouts stay on the native GPIO path until evidenced.
        if capacity != 0x8000 or descriptor[2:] != b"\x01\x00":
            self.eeprom_error = f"unsupported 24LCxx descriptor {descriptor.hex()}"
            return False
        if self.eeprom_data:
            if len(self.eeprom_data) != capacity:
                self.eeprom_error = "24LCxx capacity changed during execution"
                return False
            self.eeprom_error = None
            return True
        try:
            with exclusive_path_lock(self.eeprom_state_path):
                state_exists = self.eeprom_state_path.is_file()
                saved = self.eeprom_state_path.read_bytes() if state_exists else b""
        except (OSError, TimeoutError) as error:
            self.eeprom_error = f"24LCxx state load failed: {error}"
            return False
        if state_exists and len(saved) != capacity:
            self.eeprom_error = (
                f"24LCxx state is 0x{len(saved):X} bytes, expected 0x{capacity:X}"
            )
            return False
        self.eeprom_capacity = capacity
        self.eeprom_original = b"\xff" * capacity
        self.eeprom_data = bytearray(saved if state_exists else self.eeprom_original)
        self.eeprom_loaded = bytes(self.eeprom_data)
        self.eeprom_loaded_from_state = state_exists
        self.eeprom_error = None
        return True

    def _eeprom_read_fast(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        for signature in (EEPROM_24LCXX_X430_READ_PREFIX,
                          EEPROM_24LCXX_X270_READ_PREFIX,
                          EEPROM_24LCXX_X7700_READ_PREFIX):
            if (self._original_runtime_bytes(address, len(signature))
                    == signature):
                if self._thumb_runtime_matches(uc, address, signature):
                    break
                return
        else:
            if not self._thumb_runtime_matches(
                    uc, address, EEPROM_24LCXX_READ_SIGNATURE):
                return
        destination = uc.reg_read(UC_ARM_REG_R0)
        offset = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if not self._ensure_eeprom(uc):
            return
        if length == 0:
            valid = 0 <= offset < self.eeprom_capacity
            self.eeprom_reads += int(valid)
            uc.reg_write(UC_ARM_REG_R0, 0 if valid else 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        if not self._hle_destination_is_ram(destination, length):
            return
        valid = (0 < length < self.eeprom_capacity
                 and 0 <= offset < self.eeprom_capacity
                 and offset + length < self.eeprom_capacity)
        try:
            if not valid:
                raise ValueError
            uc.mem_read(destination, length)
            uc.mem_write(destination,
                         bytes(self.eeprom_data[offset:offset + length]))
            uc.ctl_remove_cache(destination, destination + length)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.eeprom_reads += 1
        self.eeprom_read_bytes += length
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _eeprom_write_fast(self, uc: Uc, address: int, size: int,
                           user_data: object) -> None:
        original = self._original_runtime_bytes(
            address, len(EEPROM_24LCXX_WRITE_PREFIX)
        )
        if original is not None and eeprom_24lcxx_write_at(original, 0):
            signature = original
        else:
            signature = next(
                (candidate for candidate in (
                    EEPROM_24LCXX_X430_WRITE_PREFIX,
                    EEPROM_24LCXX_X270_WRITE_PREFIX,
                    EEPROM_24LCXX_X7700_WRITE_PREFIX,
                ) if self._original_runtime_bytes(address, len(candidate))
                == candidate),
                None,
            )
        if signature is None or not self._thumb_runtime_matches(uc, address, signature):
            return
        source = uc.reg_read(UC_ARM_REG_R0)
        offset = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if not self._ensure_eeprom(uc):
            return
        if length == 0:
            valid = 0 <= offset < self.eeprom_capacity
            self.eeprom_writes += int(valid)
            uc.reg_write(UC_ARM_REG_R0, 0 if valid else 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        if not self._hle_source_is_safe(source, length):
            return
        valid = (0 < length < self.eeprom_capacity
                 and 0 <= offset < self.eeprom_capacity
                 and offset + length < self.eeprom_capacity)
        try:
            if not valid:
                raise ValueError
            incoming = bytes(uc.mem_read(source, length))
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.eeprom_data[offset:offset + length] = incoming
        self.eeprom_operations.append((offset, incoming))
        self.eeprom_writes += 1
        self.eeprom_write_bytes += length
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _secondary_flash_read_fast(self, uc: Uc, address: int, size: int,
                                   user_data: object) -> None:
        known = LEGACY_SECONDARY_FLASH_READ_SIGNATURE
        signature = (known if self._original_runtime_bytes(address, len(known)) == known
                     else None)
        if not self._thumb_runtime_matches(uc, address, signature):
            return
        assert self.secondary_flash is not None
        destination = uc.reg_read(UC_ARM_REG_R0)
        offset = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if not self._hle_destination_is_ram(destination, length):
            return
        valid = (0 < length <= len(self.secondary_flash.data)
                 and 0 <= offset <= len(self.secondary_flash.data) - length)
        try:
            if not valid:
                raise ValueError
            uc.mem_read(destination, length)
            uc.mem_write(destination,
                         bytes(self.secondary_flash.data[offset:offset + length]))
            uc.ctl_remove_cache(destination, destination + length)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.secondary_flash_reads += 1
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _secondary_flash_write_fast(self, uc: Uc, address: int, size: int,
                                    user_data: object) -> None:
        known = LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE
        base = self.config.secondary_flash_address
        original = self._original_runtime_bytes(address, 0x90)
        bulk = (base not in (None, 0) and original is not None
                and fujitsu_x16_bulk_write_at(original, 0, int(base)))
        signature = (original if bulk else known
                     if self._original_runtime_bytes(address, len(known)) == known
                     else None)
        if not self._thumb_runtime_matches(uc, address, signature):
            return
        assert self.secondary_flash is not None
        source = uc.reg_read(UC_ARM_REG_R0)
        destination = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if bulk and (source | destination | length) & 1:
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        if bulk and length == 0:
            self.secondary_flash_writes += 1
            uc.reg_write(UC_ARM_REG_R0, 0)
            self._return_to_lr(uc, address, size, user_data)
            return
        if not self._hle_source_is_safe(source, length):
            return
        offset = destination
        if bulk:
            if not (int(base) <= destination
                    <= int(base) + len(self.secondary_flash.data) - length):
                return
            offset -= int(base)
        elif (base not in (None, 0)
              and int(base) <= destination
              < int(base) + len(self.secondary_flash.data)):
            offset -= int(base)
        valid = (0 < length <= len(self.secondary_flash.data)
                 and 0 <= offset <= len(self.secondary_flash.data) - length)
        try:
            if not valid:
                raise ValueError
            incoming = bytes(uc.mem_read(source, length))
        except (UcError, ValueError):
            if bulk:
                return
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        if bulk:
            current = self.secondary_flash.data[offset:offset + length]
            if (self.secondary_flash.phase != "bypass"
                    or any(old & new != new for old, new in zip(current, incoming))):
                return
        programmed = self.secondary_flash.program(offset, incoming)
        if programmed is None:
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        base = self.config.secondary_flash_address
        if base not in (None, 0):
            uc.mem_write(base + offset, programmed)
        self.secondary_flash_writes += 1
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _legacy_efs_page_read(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Read one x16 small-page NAND view backed by the EFS data image."""
        if (self.secondary_flash is None
                or not self._thumb_runtime_matches(
                    uc, address, LEGACY_EFS_PAGE_READ_SIGNATURE)):
            return
        destination = uc.reg_read(UC_ARM_REG_R0)
        page = uc.reg_read(UC_ARM_REG_R1)
        column = uc.reg_read(UC_ARM_REG_R2)
        length = uc.reg_read(UC_ARM_REG_R3)
        ram_end = self.config.ram_base + self.config.ram_size
        destination_end = destination + length
        destination_is_ram = (
            self.config.ram_base <= destination <= destination_end <= ram_end
            or 0x03800000 <= destination <= destination_end <= 0x03A00000
        )
        page_size = 512
        raw_page_size = 528
        page_count = len(self.secondary_flash.data) // page_size
        try:
            if (not destination_is_ram or not 0 <= page < page_count
                    or not 0 <= column < raw_page_size
                    or not 0 < length <= raw_page_size - column):
                raise ValueError
            uc.mem_read(destination, length)
            data_length = min(length, max(0, page_size - column))
            start = page * page_size + column
            data = bytes(self.secondary_flash.data[start:start + data_length])
            data += b"\xff" * (length - len(data))
            uc.mem_write(destination, data)
            uc.ctl_remove_cache(destination, destination_end)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 2)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.legacy_efs_page_reads += 1
        uc.reg_write(UC_ARM_REG_R0, 1)
        self._return_to_lr(uc, address, size, user_data)

    def _nand_command(self, uc: Uc, access: int, address: int, size: int,
                      value: int, user_data: object) -> None:
        command = value & 0xFF
        if len(self.nand_commands) < 256:
            self.nand_commands.append(command)
        if command == 0x70:
            self.nand_mode = "status"
            uc.mem_write(0x01800000, b"\xc0")
        elif command in (0x00, 0x50):
            self.nand_mode = "read-spare" if command == 0x50 else "read"
            self.nand_spare_latched = command == 0x50
            self.nand_address.clear()
            uc.mem_write(0x01800000, b"\xff\xff")
        elif command == 0xFF:
            self.nand_mode = "idle"
            self.nand_spare_latched = False
            self.nand_address.clear()
            uc.mem_write(0x01800000, b"\xff\xff")
        elif command in (0x80, 0x60):
            self.nand_mode = (
                "program-spare" if command == 0x80
                and getattr(self, "nand_spare_latched", False)
                else "program" if command == 0x80 else "erase"
            )
            if command == 0x60:
                self.nand_spare_latched = False
            self.nand_address.clear()
            self.nand_program.clear()
        elif command == 0x10 and self.nand_mode.startswith("program"):
            end = min(len(self.nand_image), self.nand_cursor + len(self.nand_program))
            self._nand_program_bytes(
                self.nand_cursor, bytes(self.nand_program[:end - self.nand_cursor])
            )
            self.nand_writes += max(0, end - self.nand_cursor)
            self.nand_mode = "status"
            self.nand_spare_latched = False
        elif command == 0xD0 and self.nand_mode == "erase" and self.nand_address:
            page = sum(byte << (8 * index)
                       for index, byte in enumerate(self.nand_address))
            block_pages = self.config.nand_pages_per_block
            start = page // block_pages * block_pages * self.nand_raw_page_size
            end = min(len(self.nand_image),
                      start + block_pages * self.nand_raw_page_size)
            if start < len(self.nand_image):
                self._nand_erase_bytes(start, end)
                self.nand_writes += end - start
            self.nand_mode = "status"

    def _nand_address_write(self, uc: Uc, access: int, address: int, size: int,
                            value: int, user_data: object) -> None:
        if not (self.nand_mode.startswith("read")
                or self.nand_mode.startswith("program")
                or self.nand_mode == "erase"):
            return
        self.nand_address.append(value & 0xFF)
        if self.nand_mode == "erase":
            page = sum(byte << (8 * index)
                       for index, byte in enumerate(self.nand_address))
            self.nand_cursor = page * self.nand_raw_page_size
        else:
            # Small-page NAND uses one column cycle; large-page NAND uses two
            # before its row cycles.  Recompute as extra row cycles arrive.
            column_cycles = 2 if self.config.nand_page_size > 512 else 1
            if len(self.nand_address) < column_cycles + 2:
                return
            column_units = sum(
                byte << (8 * index)
                for index, byte in enumerate(self.nand_address[:column_cycles])
            )
            column = column_units * self.config.nand_bus_width
            if self.nand_mode in ("read-spare", "program-spare"):
                column += self.config.nand_page_size
            page = sum(byte << (8 * index)
                       for index, byte in enumerate(
                           self.nand_address[column_cycles:]))
            self.nand_cursor = page * self.nand_raw_page_size + column

    def _nand_data_write(self, uc: Uc, access: int, address: int, size: int,
                         value: int, user_data: object) -> None:
        if self.nand_mode.startswith("program"):
            page_remaining = self.nand_raw_page_size - (self.nand_cursor
                                                        % self.nand_raw_page_size)
            available = max(0, page_remaining - len(self.nand_program))
            self.nand_program.extend(value.to_bytes(size, "little")[:available])

    def _nand_program_bytes(self, start: int, incoming: bytes,
                            *, record: bool = True) -> None:
        end = min(len(self.nand_image), start + len(incoming))
        payload = incoming[:max(0, end - start)]
        for index, byte in enumerate(payload):
            self.nand_image[start + index] &= byte
        if record and payload:
            operations = getattr(self, "nand_operations", None)
            if operations is not None:
                operations.append(("program", start, payload))

    def _nand_erase_bytes(self, start: int, end: int,
                          *, record: bool = True) -> None:
        start = max(0, start)
        end = min(len(self.nand_image), end)
        if start >= end:
            return
        self.nand_image[start:end] = b"\xff" * (end - start)
        if record:
            operations = getattr(self, "nand_operations", None)
            if operations is not None:
                operations.append(("erase", start, end))

    def _nand_bad_block(self, uc: Uc, address: int, size: int,
                        user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, NAND_BAD_BLOCK_SIGNATURE):
            return
        page = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFF
        marker = page * self.nand_raw_page_size + self.config.nand_page_size
        valid = (bool(self.nand_image) and 0 <= page < self.nand_page_count
                 and marker + 2 <= len(self.nand_image))
        good = valid and self.nand_image[marker:marker + 2] == b"\xff\xff"
        uc.reg_write(UC_ARM_REG_R0, 1 if good else 2)
        self.nand_bad_block_probes += 1
        lr = uc.reg_read(UC_ARM_REG_LR)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_PC, lr & ~1)
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x20 if lr & 1 else cpsr & ~0x20)

    def _nand_read_fast(self, uc: Uc, address: int, size: int,
                        user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, NAND_READ_SIGNATURE):
            return
        destination = uc.reg_read(UC_ARM_REG_R0)
        page = uc.reg_read(UC_ARM_REG_R1)
        column = uc.reg_read(UC_ARM_REG_R2)
        length = uc.reg_read(UC_ARM_REG_R3)
        if not self._hle_destination_is_ram(destination, length):
            return
        start = page * self.nand_raw_page_size + column
        valid = (bool(self.nand_image)
                 and 0 < length <= self.nand_raw_page_size
                 and 0 <= column < self.nand_raw_page_size
                 and length <= self.nand_raw_page_size - column
                 and 0 <= page < self.nand_page_count
                 and start + length <= len(self.nand_image))
        try:
            if not valid:
                raise ValueError
            uc.mem_read(destination, length)
            data = bytes(self.nand_image[start:start + length])
            uc.mem_write(destination, data)
            uc.ctl_remove_cache(destination, destination + length)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 2)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.nand_reads += length
        uc.reg_write(UC_ARM_REG_R0, 1)
        self._return_to_lr(uc, address, size, user_data)

    def _nand_write_fast(self, uc: Uc, address: int, size: int,
                         user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, NAND_WRITE_SIGNATURE):
            return
        source = uc.reg_read(UC_ARM_REG_R0)
        page = uc.reg_read(UC_ARM_REG_R1)
        column = uc.reg_read(UC_ARM_REG_R2)
        length = uc.reg_read(UC_ARM_REG_R3)
        transfer_length = length
        if self.config.nand_bus_width == 2:
            column &= ~1
            transfer_length = (length + 1) & ~1
        if not self._hle_source_is_safe(source, transfer_length):
            return
        start = page * self.nand_raw_page_size + column
        valid = (bool(self.nand_image)
                 and 0 < transfer_length <= self.nand_raw_page_size
                 and 0 <= column < self.nand_raw_page_size
                 and transfer_length <= self.nand_raw_page_size - column
                 and 0 <= page < self.nand_page_count
                 and start + transfer_length <= len(self.nand_image))
        try:
            if not valid:
                raise ValueError
            incoming = bytes(uc.mem_read(source, transfer_length))
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 2)
            self._return_to_lr(uc, address, size, user_data)
            return
        self._nand_program_bytes(start, incoming)
        self.nand_writes += transfer_length
        uc.reg_write(UC_ARM_REG_R0, 1)
        self._return_to_lr(uc, address, size, user_data)

    def _return_if_thumb_signature(self, uc: Uc, address: int, size: int,
                                   user_data: object) -> None:
        if (isinstance(user_data, bytes)
                and self._thumb_runtime_matches(uc, address, user_data)):
            self._return_to_lr(uc, address, size, user_data)

    def _ma2_silent_boot(self, uc: Uc, address: int, size: int,
                         user_data: object) -> None:
        """Acknowledge a proven MA2 wait without inventing device registers."""
        if not self._thumb_runtime_matches(uc, address, prefix_size=0x60):
            return
        self.ma2_silent_boot_calls += 1
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    @staticmethod
    def _return_to_lr(uc: Uc, address: int, size: int, user_data: object) -> None:
        lr = uc.reg_read(UC_ARM_REG_LR)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_PC, lr & ~1)
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x20 if lr & 1 else cpsr & ~0x20)

    def _rex_irq_status_write(self, uc: Uc, access: int, address: int,
                              size: int, value: int,
                              user_data: object) -> None:
        """Apply partial guest W1C writes to two 16-bit status banks."""
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is None or size <= 0:
            return
        incoming = value.to_bytes(size, "little")
        for index, bank in enumerate((status, status + 4)):
            left = max(address, bank)
            right = min(address + size, bank + 2)
            if left < right:
                offset = left - address
                clear = int.from_bytes(
                    incoming[offset:offset + right - left], "little"
                ) << ((left - bank) * 8)
                self._rex_irq_pending[index] &= ~clear & 0xFFFF

    def _rex_irq_status_read(self, uc: Uc, access: int, address: int,
                             size: int, value: int,
                             user_data: object) -> None:
        """Refresh guest backing from controller status shadow before reads."""
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is not None:
            uc.mem_write(status, struct.pack("<I", self._rex_irq_pending[0]))
            uc.mem_write(status + 4,
                         struct.pack("<I", self._rex_irq_pending[1]))

    def _rex_firmware_matches(self, uc: Uc, target: int, length: int,
                              validator=None) -> bool:
        expected = self._original_runtime_bytes(target, length)
        try:
            return (
                expected is not None
                and (validator is None or validator(expected, 0) is not None)
                and bytes(uc.mem_read(target, length)) == expected
            )
        except UcError:
            return False

    @staticmethod
    def _rex_irq_stack_mapped(uc: Uc, stack: int) -> bool:
        return (stack & 3 == 0 and any(
            begin <= stack - 0x40 and stack - 1 <= end
            and permissions & UC_PROT_WRITE
            for begin, end, permissions in uc.mem_regions()
        ))

    def _rex_irq_route_valid(self, uc: Uc, *, stack: bool = False) -> bool:
        wrapper = getattr(self.config, "rex_irq_wrapper_address", None)
        handler = getattr(self.config, "rex_irq_handler_address", None)
        handler_slot = getattr(self.config, "rex_irq_handler_slot", None)
        callback_slot = getattr(self.config, "rex_irq_callback_slot", None)
        tick = getattr(self.config, "rex_tick_address", None)
        status = getattr(self.config, "rex_irq_status_address", None)
        enable = getattr(self.config, "rex_irq_enable_address", None)
        mask = getattr(self.config, "rex_irq_mask", 0)
        if (wrapper is None or handler is None or handler_slot is None
                or callback_slot is None or tick is None or status is None
                or status & 3 or enable != status + 8 or mask != 0x0200
                or not self._rex_firmware_matches(
                    uc, wrapper, REX_IRQ_WRAPPER_RUNTIME_SIZE)
                or not self._rex_firmware_matches(
                    uc, handler, REX_IRQ_HANDLER_RUNTIME_SIZE)
                or not self._rex_firmware_matches(
                    uc, tick, REX_5MS_CALLBACK_SIZE, rex_5ms_callback_at)):
            return False
        try:
            installed_handler = struct.unpack(
                "<I", bytes(uc.mem_read(handler_slot, 4))
            )[0]
            installed_tick = struct.unpack(
                "<I", bytes(uc.mem_read(callback_slot, 4))
            )[0]
            vector = arm_b_word_target(struct.unpack(
                "<I", bytes(uc.mem_read(0x18, 4))
            )[0], 0x18)
            if (vector is None
                    or not self.config.ram_base <= vector
                    <= self.config.ram_base + self.config.ram_size - 4):
                return False
            routed_wrapper = arm_b_word_target(struct.unpack(
                "<I", bytes(uc.mem_read(vector, 4))
            )[0], vector)
        except UcError:
            return False
        if (installed_handler != handler | 1
                or installed_tick != tick | 1
                or routed_wrapper != wrapper):
            return False
        if stack:
            old = uc.reg_read(UC_ARM_REG_CPSR)
            if old & 0x1F in (0x11, 0x12):
                return False
            try:
                uc.reg_write(UC_ARM_REG_CPSR, (old & ~0xBF) | 0x92)
                irq_stack = uc.reg_read(UC_ARM_REG_SP)
                uc.reg_write(UC_ARM_REG_CPSR, (old & ~0xBF) | 0x9F)
                system_stack = uc.reg_read(UC_ARM_REG_SP)
            finally:
                uc.reg_write(UC_ARM_REG_CPSR, old)
            if not all(self._rex_irq_stack_mapped(uc, value)
                       for value in (irq_stack, system_stack)):
                return False
        return True

    def _rex_irq_boundary(self, uc: Uc, address: int) -> bool:
        """Enter one latched, enabled IRQ at a firmware block boundary."""
        enable = getattr(self.config, "rex_irq_enable_address", None)
        mask = getattr(self.config, "rex_irq_mask", 0)
        if (enable is None or not self._rex_irq_pending[0] & mask):
            return False
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        if cpsr & 0x80 or cpsr & 0x1F in (0x11, 0x12):
            return False
        try:
            enabled = struct.unpack("<H", bytes(uc.mem_read(enable, 2)))[0]
        except UcError:
            return False
        if not enabled & mask:
            return False
        if not self._rex_irq_route_valid(uc, stack=True):
            return False
        irq_cpsr = (cpsr & ~0xBF) | 0x92
        uc.reg_write(UC_ARM_REG_CPSR, irq_cpsr)
        irq_stack = uc.reg_read(UC_ARM_REG_SP)
        if not self._rex_irq_stack_mapped(uc, irq_stack):
            uc.reg_write(UC_ARM_REG_CPSR, cpsr)
            return False
        uc.reg_write(UC_ARM_REG_SPSR, cpsr)
        uc.reg_write(UC_ARM_REG_LR, address + 4)
        uc.reg_write(UC_ARM_REG_PC, 0x18)
        self.rex_irq_deliveries += 1
        return True

    def _rex_tick(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if getattr(self, "_rex_tick_return_address", None) == address:
            for register, value in self._rex_tick_context or ():
                uc.reg_write(register, value)
            self._rex_tick_return_address = None
            self._rex_tick_context = None
            return
        post_sleep = False
        if self.config.rex_tick_ms == 5:
            start = address - 46
            expected_sleep = self._original_runtime_bytes(start, 56)
            try:
                post_sleep = (
                    expected_sleep is not None
                    and rex_sleep_call_at(expected_sleep, 0) == 42
                    and bytes(uc.mem_read(start, len(expected_sleep)))
                    == expected_sleep
                )
            except UcError:
                post_sleep = False
        if (not post_sleep
                and not self._thumb_runtime_matches(uc, address, prefix_size=4)):
            return
        self.rex_idle_entries += 1
        tick_address = self.config.rex_tick_address
        tick_matches = (tick_address is not None
                        and self._thumb_runtime_matches(
                            uc, tick_address, REX_TICK_SIGNATURE))
        if tick_address is not None and not tick_matches:
            tick_matches = self._rex_firmware_matches(
                uc,
                tick_address, REX_5MS_CALLBACK_SIZE, rex_5ms_callback_at
            )
        if (tick_address is None
                or not tick_matches
                or not self.config.rex_tick_ms
                or self.instructions < self.rex_next_instruction):
            return
        if self.config.rex_tick_ms == 5:
            if (not post_sleep
                    or getattr(self.config, "rex_irq_wrapper_address", None) is None
                    or not self._rex_irq_route_valid(uc, stack=True)):
                return
        self.rex_next_instruction = self.instructions + REX_TICK_INTERVAL
        self.rex_ticks += 1
        self.rex_elapsed_ms += self.config.rex_tick_ms
        if self.config.rex_tick_ms == 5:
            self._rex_irq_pending[0] |= self.config.rex_irq_mask
            return
        if post_sleep:
            registers = (
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_CPSR,
            )
            self._rex_tick_context = tuple(
                (register, uc.reg_read(register)) for register in registers
            )
            self._rex_tick_return_address = address
        uc.reg_write(UC_ARM_REG_R0, self.config.rex_tick_ms)
        uc.reg_write(UC_ARM_REG_LR, address | 1 if post_sleep else address + 5)
        uc.reg_write(UC_ARM_REG_PC, tick_address | 1)

    def _board_adc_reader_entry(self, uc: Uc, address: int, size: int,
                                user_data: object) -> None:
        if not self._thumb_runtime_matches(
                uc, address, prefix_size=BOARD_ADC_READER_SIZE):
            self._board_adc_reader_channel = None
            return
        self._board_adc_reader_channel = uc.reg_read(UC_ARM_REG_R0)

    def _board_adc_reader_data_read(self, uc: Uc, address: int,
                                    size: int) -> None:
        reader = self.config.board_adc_reader_address
        if (reader is None
                or address != BOARD_ADC_READER_DATA_ADDRESS
                or size != 2
                or uc.reg_read(UC_ARM_REG_PC) & ~1
                != reader + BOARD_ADC_READER_READ_OFFSET
                or not self._thumb_runtime_matches(
                    uc, reader, prefix_size=BOARD_ADC_READER_SIZE)):
            return
        channel = self._board_adc_reader_channel
        self._board_adc_reader_channel = None
        if channel != 2:
            return
        try:
            current = int.from_bytes(uc.mem_read(address, size), "little")
        except UcError:
            return
        value = (current & ~0xFF) | (self.config.board_adc_value & 0xFF)
        uc.mem_write(address, value.to_bytes(size, "little"))
        self.board_adc_reads += 1

    def _board_adc(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if (not self._thumb_runtime_matches(uc, address, BOARD_ADC_SIGNATURE)
                or uc.reg_read(UC_ARM_REG_R0) != 0):
            return
        self.board_adc_reads += 1
        uc.reg_write(UC_ARM_REG_R0, self.config.board_adc_value)
        self._return_to_lr(uc, address, size, user_data)

    def _flash_id(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, FLASH_ID_SIGNATURE):
            return
        self.flash_id_reads += 1
        uc.reg_write(UC_ARM_REG_R0, self.config.flash_id_value)
        self._return_to_lr(uc, address, size, user_data)

    def _crc16_fast(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, CRC16_SIGNATURE):
            return
        seed = uc.reg_read(UC_ARM_REG_R0) & 0xFFFF
        source = uc.reg_read(UC_ARM_REG_R1)
        raw_length = uc.reg_read(UC_ARM_REG_R2)
        length = (0 if raw_length == 0 or raw_length & 0x80000000
                  else ((raw_length - 1) & 0xFFFF) + 1)
        if length and not self._hle_source_is_safe(source, length):
            return
        try:
            data = bytes(uc.mem_read(source, length)) if length else b""
        except UcError:
            return
        result = (~binascii.crc_hqx(data, (~seed) & 0xFFFF)) & 0xFFFF
        uc.reg_write(UC_ARM_REG_R0, result)
        uc.reg_write(UC_ARM_REG_R1, source + length)
        uc.reg_write(UC_ARM_REG_R2, 0)
        self.fast_crc16_calls += 1
        self._return_to_lr(uc, address, size, user_data)

    def _dmd_download_fast(self, uc: Uc, address: int, size: int,
                           user_data: object) -> None:
        """Complete the DSP download only for the proven Qualcomm routine."""
        try:
            signature = bytes(uc.mem_read(address, len(DMD_DOWNLOAD_SIGNATURE)))
            flag, control, _, dmd = struct.unpack(
                "<4I", uc.mem_read(address + 0xE0, 16)
            )
            file_load = struct.unpack("<H", uc.mem_read(address + 0xD4, 2))[0]
            if file_load == 0x4906:  # LDR r1, [pc, #24]
                filename = struct.unpack("<I", uc.mem_read(address + 0xF0, 4))[0]
            elif file_load == 0xA106:  # ADR r1, #24; inline filename follows
                filename = address + 0xF0
            else:
                return
            source_name = bytes(uc.mem_read(filename, 12))
        except (UcError, struct.error):
            return
        ram_end = self.config.ram_base + self.config.ram_size
        if (signature != DMD_DOWNLOAD_SIGNATURE
                or control != 0x03000050 or dmd != 0x030007E0
                or not self.config.ram_base <= flag < ram_end
                or not source_name.startswith(b"dmddown_")):
            return
        uc.mem_write(flag, b"\x02")
        uc.mem_write(control + 0x0C, b"\x01")
        uc.mem_write(dmd + 8, b"\0\0\0\0\0\0")
        uc.reg_write(UC_ARM_REG_R0, 1)
        self.fast_dmd_downloads += 1
        self._return_to_lr(uc, address, size, user_data)

    def _detect_primary_flash_ids(self) -> tuple[int, int] | None:
        """Infer NOR autoselect IDs only from one unambiguous firmware descriptor."""
        address = self.config.primary_flash_probe_address
        if address is None:
            return None
        try:
            signature = bytes(self.uc.mem_read(address, len(PRIMARY_FLASH_PROBE_SIGNATURE)))
            _, flash_base_global, table_global = struct.unpack(
                "<3I", self.uc.mem_read(
                    address + len(PRIMARY_FLASH_PROBE_SIGNATURE), 12
                )
            )
            flash_base = struct.unpack("<I", self.uc.mem_read(flash_base_global, 4))[0]
            first, terminator = struct.unpack("<2I", self.uc.mem_read(table_global, 8))
            manufacturer, device = struct.unpack(
                "<2H", self.uc.mem_read(first + 0x124, 4)
            )
        except (UcError, struct.error):
            return None
        flash_end = self.config.load_address + self.config.flash_size
        ram_end = self.config.ram_base + self.config.ram_size
        if (signature != PRIMARY_FLASH_PROBE_SIGNATURE or not first or terminator
                or not self.config.ram_base <= flash_base_global <= ram_end - 4
                or not self.config.ram_base <= table_global <= ram_end - 8
                or not self.config.load_address <= flash_base < flash_end
                or not self.config.load_address <= first <= flash_end - 0x128
                or manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)):
            return None
        return manufacturer, device

    def _nand_data_read(self, uc: Uc, access: int, address: int, size: int,
                        value: int, user_data: object) -> None:
        if self.nand_mode == "status":
            uc.mem_write(address, b"\xc0" * size)
            return
        if not self.nand_mode.startswith("read"):
            return
        start, end = self.nand_cursor, self.nand_cursor + size
        data = bytes(self.nand_image[start:end])
        if len(data) < size:
            data += b"\xff" * (size - len(data))
        uc.mem_write(address, data)
        self.nand_cursor = end
        self.nand_reads += size

    def _restore_flash_once(self, uc: Uc, address: int, size: int,
                            user_data: object) -> None:
        for target, data in self._flash_restore.items():
            uc.mem_write(target, data)
            uc.ctl_remove_cache(target, target + len(data))
        self._flash_restore.clear()

    def save_flash(self) -> None:
        self.flash.save()
        if self.secondary_flash is not None:
            self.secondary_flash.save()

    def _save_eeprom(self) -> None:
        if not self.eeprom_data:
            return
        operations = list(self.eeprom_operations)
        current = bytes(self.eeprom_data)
        if not operations and current != self.eeprom_loaded:
            operations.append((0, current))
        if not operations:
            return
        with exclusive_path_lock(self.eeprom_state_path):
            latest = bytearray(self.eeprom_original)
            if self.eeprom_state_path.is_file():
                saved = self.eeprom_state_path.read_bytes()
                if len(saved) != self.eeprom_capacity:
                    raise ValueError(
                        f"24LCxx state is 0x{len(saved):X} bytes, "
                        f"expected 0x{self.eeprom_capacity:X}"
                    )
                latest[:] = saved
            for offset, payload in operations:
                latest[offset:offset + len(payload)] = payload
            if bytes(latest) == self.eeprom_original:
                durable_unlink(self.eeprom_state_path)
                LOGGER.info("EEPROM state removed/empty path=%s operations=%d",
                            self.eeprom_state_path, len(operations))
            else:
                atomic_write_bytes(self.eeprom_state_path, bytes(latest))
                LOGGER.info("EEPROM state saved path=%s bytes=%d operations=%d",
                            self.eeprom_state_path, len(latest), len(operations))
            self.eeprom_data[:] = latest
            self.eeprom_loaded = bytes(latest)
            self.eeprom_loaded_from_state = self.eeprom_state_path.is_file()
            self.eeprom_operations.clear()

    def _audio_play(self, uc: Uc, address: int, size: int,
                    user_data: object) -> None:
        self._play_mmf_arguments(uc)

    def _play_mmf_arguments(self, uc: Uc, discovery: bool = False,
                            submit: bool = True) -> bool:
        if self.audio_player is None:
            return False
        pointer = uc.reg_read(UC_ARM_REG_R1)
        requested = uc.reg_read(UC_ARM_REG_R2)
        if not 8 <= requested <= 0x01000000:
            return False
        try:
            header = bytes(uc.mem_read(pointer, 8))
            if header[:4] != b"MMMD":
                return False
            declared = int.from_bytes(header[4:8], "big") + 8
            if not 8 <= declared <= 0x01000000:
                return False
            if discovery and requested != declared:
                return False
            data = bytes(uc.mem_read(pointer, declared))
        except UcError:
            return False
        if submit:
            self.audio_play_requests += 1
            self.audio_last_size = len(data)
            self.audio_player.play_mmf(data)
        return True

    def _probe_audio_call(self, uc: Uc, address: int) -> None:
        if not uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
            return
        try:
            prologue = int.from_bytes(uc.mem_read(address, 2), "little")
        except UcError:
            return
        if (prologue & 0xFF00 != 0xB500
                or not self._play_mmf_arguments(uc, True, submit=True)):
            return
        self.audio_discovered_address = address
        self._audio_probe_hook = uc.hook_add(UC_HOOK_CODE, self._audio_play,
                                             begin=address, end=address)

    def close(self) -> None:
        LOGGER.info("emulator close begin model=%s instructions=%d fault=%r",
                    self.config.model, self.instructions, self.fault)
        try:
            self.save_flash()
            self._save_eeprom()
            self._save_nand()
        finally:
            if self.audio_player is not None:
                self.audio_player.close()
        LOGGER.info("emulator close complete model=%s", self.config.model)

    def _save_nand(self) -> None:
        if not self.nand_image:
            return
        operations = list(self.nand_operations)
        current = bytes(self.nand_image)
        if not operations and current != self.nand_loaded:
            # Direct mutation remains supported for diagnostic tools.
            operations.append(("replace", 0, current))
        if not operations and not self.nand_needs_rewrite:
            return
        with exclusive_path_lock(self.config.flash_state):
            latest = bytearray(self.nand_original)
            if self.nand_state_path.is_file():
                self._validate_nand_metadata()
                latest = self._normalise_nand(
                    self.nand_state_path.read_bytes(), len(latest), "NAND state"
                )
            for operation, start, payload in operations:
                if operation == "replace":
                    latest[:] = bytes(payload)
                elif operation == "erase":
                    latest[start:int(payload)] = b"\xff" * (int(payload) - start)
                else:
                    data = bytes(payload)
                    for index, byte in enumerate(data):
                        latest[start + index] &= byte
            if bytes(latest) == self.nand_original:
                durable_unlink(self.nand_state_path)
                durable_unlink(self.nand_metadata_path)
                LOGGER.info("NAND state removed/empty path=%s operations=%d",
                            self.nand_state_path, len(operations))
            else:
                atomic_write_bytes(self.nand_state_path, bytes(latest))
                atomic_write_text(
                    self.nand_metadata_path,
                    json.dumps(self._nand_metadata(), separators=(",", ":")),
                )
                LOGGER.info("NAND state saved path=%s bytes=%d operations=%d",
                            self.nand_state_path, len(latest), len(operations))
            self.nand_image[:] = latest
            self.nand_loaded = bytes(latest)
            self.nand_operations.clear()
            self.nand_needs_rewrite = False

    def set_key(self, bit: int, pressed: bool) -> None:
        """Change one physical key bit; firmware owns debounce and hold timing."""
        if not 0 <= bit < HANDSET_KEY_COUNT:
            raise ValueError("key bit has no handset mapping")
        if pressed == (bit in self.held_keys):
            return
        key_start = self.config.key_register
        for address, size in tuple(self.ready_bits):
            if max(address, key_start) < min(address + size, key_start + 4):
                del self.ready_bits[(address, size)]
        value = int.from_bytes(self.uc.mem_read(self.config.key_register, 4),
                               "little")
        if self.input_profile is not None:
            family = "LG" if self.input_profile[0] == "lg-decoded" else "Samsung"
            self.input_error = (
                f"{family} keypad startup task is not ready; physical register only"
            )
        mask = 1 << bit
        if pressed:
            self.held_keys.add(bit)
            self.key_baselines[bit] = value & mask
            active = not self.config.key_active_low
            value = value | mask if active else value & ~mask
        else:
            self.held_keys.remove(bit)
            baseline = self.key_baselines.pop(bit)
            value = value & ~mask | baseline
        self.uc.mem_write(self.config.key_register, struct.pack("<I", value))
        LOGGER.info("key bit=%d pressed=%s register=0x%08X value=0x%08X",
                    bit, pressed, self.config.key_register, value)

    def _input_entry_observed(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Record firmware-side keypad producer consumption without injection."""
        self.input_events += 1
        if self.held_keys:
            self.firmware_key_events += 1
            self.input_error = ""

    def _host_backend_checkpoint(self, next_pc: int,
                                 count: int) -> dict[str, object]:
        """Capture only Python state and pre-call Unicorn reads for a terminal error."""
        identity_method = getattr(self.config, "firmware_identity", None)
        identity = (identity_method() if callable(identity_method) else {
            "basename": "unknown", "bytes": None, "sha256": None,
        })
        registers = {
            **{f"r{index}": f"0x{self.uc.reg_read(register) & 0xFFFFFFFF:08X}"
               for index, register in enumerate((
                   UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                   UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                   UC_ARM_REG_R6, UC_ARM_REG_R7,
               ))},
            "sp": f"0x{self.uc.reg_read(UC_ARM_REG_SP) & 0xFFFFFFFF:08X}",
            "pc": f"0x{self.uc.reg_read(UC_ARM_REG_PC) & 0xFFFFFFFF:08X}",
            "lr": f"0x{self.uc.reg_read(UC_ARM_REG_LR) & 0xFFFFFFFF:08X}",
            "cpsr": f"0x{self.uc.reg_read(UC_ARM_REG_CPSR) & 0xFFFFFFFF:08X}",
        }
        try:
            width, height, frame = self.display_snapshot()
        except AttributeError:  # Minimal test harnesses need no GUI snapshot.
            width = int(getattr(self.config, "width", 0))
            height = int(getattr(self.config, "height", 0))
            frame = bytes(getattr(self, "display_frame", b""))
        reads = (getattr(self, "mmio_read_totals", None)
                 or getattr(self, "mmio_reads", None))
        hottest = max(reads.items(), key=lambda item: item[1]) if reads else None
        last_unmapped = getattr(self, "last_unmapped", None)
        safe_unmapped = None
        if last_unmapped is not None:
            safe_unmapped = {
                "access": last_unmapped.get("access"),
                "address": f"0x{last_unmapped['address']:08X}",
                "size": last_unmapped.get("size"),
                "value": f"0x{last_unmapped['value']:X}",
            }
        secondary = getattr(self, "secondary_flash", None)
        return {
            "firmware": identity,
            "model": getattr(self.config, "model", "unknown"),
            "chipset": getattr(self.config, "chipset", "unknown"),
            "next_pc": f"0x{next_pc & 0xFFFFFFFF:08X}",
            "chunk_steps": count,
            "instructions": self.instructions,
            "registers": registers,
            "tail": [f"0x{address:08X}" for address in self.tail],
            "display": {
                "width": width,
                "height": height,
                "sha256": hashlib.sha256(frame).hexdigest(),
                "frame_sequence": self.frame_sequence,
                "firmware_frame_sequence": self.firmware_frame_sequence,
            },
            "counters": {
                "reset_entries": self.reset_entries,
                "lcd_writes": self.lcd_writes,
                "rex_idle_entries": self.rex_idle_entries,
                "rex_ticks": self.rex_ticks,
                "rex_elapsed_ms": self.rex_elapsed_ms,
                "storage": {
                    "eeprom_reads": self.eeprom_reads,
                    "eeprom_writes": self.eeprom_writes,
                    "eeprom_changed_bytes": sum(
                        byte != 0xFF for byte in self.eeprom_data
                    ),
                    "secondary_nor_reads": self.secondary_flash_reads,
                    "secondary_nor_writes": self.secondary_flash_writes,
                    "secondary_nor_changed_pages": len(
                        getattr(secondary, "changed_pages", ())
                    ),
                    "nand_reads": self.nand_reads,
                    "nand_writes": self.nand_writes,
                    "nand_commands": len(self.nand_commands),
                },
            },
            "dynamic_pages": len(self.dynamic_pages),
            "last_unmapped": safe_unmapped,
            "hottest_mmio_read": (
                {"pc": f"0x{hottest[0][0]:08X}",
                 "address": f"0x{hottest[0][1]:08X}",
                 "size": hottest[0][2], "reads": hottest[1]}
                if hottest is not None else None
            ),
        }

    def run(self, steps: int, fast_boot_probe: int = 100_000) -> dict[str, object]:
        host_backend_fault = getattr(self, "_host_backend_fault", None)
        if host_backend_fault is not None:
            raise host_backend_fault
        if steps < 0 or fast_boot_probe <= 0:
            raise ValueError("steps must be non-negative and probe size positive")
        # Compatibility for focused harnesses built with __new__().  Normal
        # sessions install the trace hook once during construction.
        if getattr(self, "_trace_hook", None) is None:
            self._trace_hook = self.uc.hook_add(UC_HOOK_BLOCK, self._trace)
        if self.instructions:
            next_pc = self.uc.reg_read(UC_ARM_REG_PC)
            if self.uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                next_pc |= 1
        else:
            next_pc = self.config.load_address + self.config.entry
        if not hasattr(self, "_poll_window_remaining"):
            self._poll_window_remaining = POLL_OBSERVATION_STEPS
        remaining = steps
        try:
            while remaining:
                if self._poll_window_remaining == POLL_OBSERVATION_STEPS:
                    self.hot.clear()
                    self.mmio_reads.clear()
                count = min(remaining, fast_boot_probe,
                            self._poll_window_remaining)
                self._chunk_unmapped = None
                checkpoint = self._host_backend_checkpoint(next_pc, count)
                try:
                    self.uc.emu_start(next_pc, 0xFFFFFFFF, count=count)
                except OSError as error:
                    host_backend_fault = HostBackendFault(error, checkpoint)
                    self._host_backend_fault = host_backend_fault
                    LOGGER.error("host backend failure diagnostic=%s",
                                 json.dumps(host_backend_fault.diagnostic,
                                            ensure_ascii=False, sort_keys=True))
                    raise host_backend_fault from error
                remaining -= count
                if self.fault:
                    break
                self.instructions += count
                self._poll_window_remaining -= count
                if not self._poll_window_remaining:
                    # Samsung boot ROMs expose primary scatter-load tuple at 0x10028.
                    # LG tables found elsewhere describe small overlays, not reset init.
                    can_fast_boot = (not self.fast_boot_used
                                     and self.config.fast_boot_address is None
                                     and not self.hot_loop_hle_used
                                     and self.config.linker is not None
                                     and self.config.linker.table_offset == 0x10028
                                     and self.config.linker.data_size >= 0x1000)
                    repeated = self.hot.most_common(1)[0][1] if self.hot else 0
                    lr = self.uc.reg_read(UC_ARM_REG_LR)
                    if can_fast_boot and repeated >= 100 and lr:
                        self._apply_linker()
                        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
                        self.uc.reg_write(UC_ARM_REG_CPSR,
                                          cpsr | 0x20 if lr & 1 else cpsr & ~0x20)
                        self.uc.reg_write(UC_ARM_REG_PC, lr & ~1)
                    else:
                        self._release_hardware_poll()
                    self._poll_window_remaining = POLL_OBSERVATION_STEPS
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                if self.uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                    pc |= 1
                next_pc = pc
                if not remaining:
                    break
        except UcError as error:
            if self.fault is None:
                pc = self.uc.reg_read(UC_ARM_REG_PC) & 0xFFFFFFFF
                error_detail = f"{error}{self._unmapped_fault_detail()}"
                missing_overlay = next((
                    item for item in self.config.missing_overlays
                    if item.target <= pc < item.target + item.size
                ), None)
                if missing_overlay is not None:
                    self.fault = self._missing_overlay_error(missing_overlay)
                executable = (
                    self.config.load_address <= pc
                    < self.config.load_address + len(self.image)
                    or self.config.ram_base <= pc
                    < self.config.ram_base + self.config.ram_size
                    or 0x03800000 <= pc < 0x03A00000
                )
                if self.fault is not None:
                    pass
                elif not executable:
                    self.fault = (
                        f"execution entered missing dump/device region "
                        f"0x{pc:08X}: {error_detail}"
                    )
                else:
                    self.fault = error_detail
        finally:
            if getattr(self, "_host_backend_fault", None) is None:
                self._restore_flash_once(self.uc, 0, 0, None)
        if (self.config.framebuffer_address is not None
                and self.config.framebuffer_flush_address is None
                and self.config.framebuffer_rect_flush_address is None):
            self._render_framebuffer_region(
                0, 0, self.config.width - 1, self.config.height - 1, force=False
            )
        self._lcd_page_flush_current()
        self._flush_indexed_frame()
        fault_context = self._fault_context()
        if self.fault is not None and self.fault != self._logged_fault:
            LOGGER.error("emulation fault model=%s pc=0x%08X instructions=%d "
                         "context=%s: %s",
                         self.config.model, self.uc.reg_read(UC_ARM_REG_PC),
                         self.instructions,
                         json.dumps(fault_context, sort_keys=True), self.fault)
            self._logged_fault = self.fault
        sink_instruction = b""
        if self.tail:
            try:
                sink_instruction = bytes(self.uc.mem_read(self.tail[-1], 4))
            except UcError:
                pass
        control_sink = self._control_sink_from_tail(self.tail, sink_instruction)
        return {
            "config": self.config.to_dict(),
            "cpu_model": "TI925T (ARMv4T stand-in for ARM7TDMI)",
            "instructions": self.instructions,
            "reset_entries": self.reset_entries,
            "pc": f"0x{self.uc.reg_read(UC_ARM_REG_PC):08X}",
            "lr": f"0x{self.uc.reg_read(UC_ARM_REG_LR):08X}",
            "registers": {
                **{f"r{index}": f"0x{self.uc.reg_read(register):08X}"
                   for index, register in enumerate((
                       UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                       UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                       UC_ARM_REG_R6, UC_ARM_REG_R7,
                   ))},
                "sp": f"0x{self.uc.reg_read(UC_ARM_REG_SP):08X}",
                "cpsr": f"0x{self.uc.reg_read(UC_ARM_REG_CPSR):08X}",
            },
            "fast_boot_used": self.fast_boot_used,
            "fast_memory_clears": self.fast_memory_clears,
            "fast_memory_copies": self.fast_memory_copies,
            "fast_register_ramps": self.fast_register_ramps,
            "fast_arm_memory_copies": self.fast_arm_memory_copies,
            "hot_loop_hle_used": self.hot_loop_hle_used,
            "fast_crc16_calls": self.fast_crc16_calls,
            "fast_dmd_downloads": self.fast_dmd_downloads,
            "primary_flash_ids": ({"manufacturer": self.flash.ids[0],
                                   "device": self.flash.ids[1]}
                                  if self.flash.ids is not None else None),
            "primary_flash_telemetry": self.flash.telemetry(),
            "ram_seed_size": self.ram_seed_size,
            "fault": self.fault,
            "fault_context": fault_context,
            "dynamic_pages": len(self.dynamic_pages),
            "control_sink": (f"0x{control_sink:08X}"
                             if control_sink is not None else None),
            "last_unmapped": ({**self.last_unmapped,
                               "address_hex": f"0x{self.last_unmapped['address']:08X}"}
                              if self.last_unmapped is not None else None),
            "lcd_writes": self.lcd_writes,
            "lcd_protocol": self._lcd_protocol,
            "lcd_frame_protocol": self._lcd_frame_protocol,
            "lcd_port_writes": [
                {"address": f"0x{address:08X}", "size": size, "writes": writes}
                for (address, size), writes in self.lcd_port_writes.most_common()
            ],
            "frame_sequence": self.frame_sequence,
            "firmware_frame_sequence": self.firmware_frame_sequence,
            "rex_idle_entries": self.rex_idle_entries,
            "rex_ticks": self.rex_ticks,
            "rex_elapsed_ms": self.rex_elapsed_ms,
            "rex_irq_deliveries": self.rex_irq_deliveries,
            "board_adc_reads": self.board_adc_reads,
            "flash_id_reads": self.flash_id_reads,
            "secondary_flash_reads": self.secondary_flash_reads,
            "secondary_flash_writes": self.secondary_flash_writes,
            "legacy_efs_page_reads": self.legacy_efs_page_reads,
            "secondary_flash_changed_pages": (len(self.secondary_flash.changed_pages)
                                                if self.secondary_flash is not None else 0),
            "secondary_flash_telemetry": (
                self.secondary_flash.telemetry()
                if self.secondary_flash is not None else None
            ),
            "eeprom_capacity": self.eeprom_capacity,
            "eeprom_reads": self.eeprom_reads,
            "eeprom_read_bytes": self.eeprom_read_bytes,
            "eeprom_writes": self.eeprom_writes,
            "eeprom_write_bytes": self.eeprom_write_bytes,
            "eeprom_changed_bytes": sum(byte != 0xFF for byte in self.eeprom_data),
            "eeprom_loaded_from_state": self.eeprom_loaded_from_state,
            "eeprom_state": (str(self.eeprom_state_path)
                              if self.eeprom_enabled else None),
            "eeprom_error": self.eeprom_error,
            "input_profile": self.input_profile[0] if self.input_profile else "gpio",
            "input_mode": ("firmware-consumed" if self.firmware_key_events
                           else "physical-register"),
            "input_entry": (f"0x{self.input_profile[1]:08X}"
                            if self.input_profile else None),
            "input_error": self.input_error,
            "input_events": self.input_events,
            "firmware_key_events": self.firmware_key_events,
            "audio_play_address": (f"0x{self.config.audio_play_address:08X}"
                                   if self.config.audio_play_address is not None else None),
            "audio_discovered_address": (f"0x{self.audio_discovered_address:08X}"
                                         if self.audio_discovered_address is not None else None),
            "audio_play_requests": self.audio_play_requests,
            "audio_last_size": self.audio_last_size,
            "ma2_silent_boot_address": (
                f"0x{self.config.ma2_silent_boot_address:08X}"
                if self.config.ma2_silent_boot_address is not None else None
            ),
            "ma2_silent_boot_calls": self.ma2_silent_boot_calls,
            "audio_backend": (self.audio_player.backend if self.audio_player is not None
                              else "disabled"),
            "audio_error": (self.audio_player.last_error if self.audio_player is not None else ""),
            "nand_commands": self.nand_commands,
            "nand_backing_size": len(self.nand_image),
            "nand_reads": self.nand_reads,
            "nand_writes": self.nand_writes,
            "nand_bad_block_probes": self.nand_bad_block_probes,
            "poll_escapes": [{**item, "pc_hex": f"0x{item['pc']:08X}",
                              "address_hex": f"0x{item['address']:08X}"}
                             for item in self.poll_escapes],
            "tail": [f"0x{address:08X}" for address in self.tail],
        }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("firmware", type=Path)
    result.add_argument("--detect-only", action="store_true")
    result.add_argument("--steps", type=integer, default=2_000_000)
    result.add_argument("--chunk-steps", type=integer, default=0,
                        help="run in GUI-sized chunks (0 = one continuous run)")
    result.add_argument("--until-visible", action="store_true",
                        help=("treat --steps as a visual-boot budget and stop "
                              "after the first non-black display frame"))
    result.add_argument("--display-metrics", action="store_true",
                        help="include immutable frame geometry/visible-pixel metrics")
    result.add_argument("--model")
    result.add_argument("--chipset", choices=("MSM5000", "MSM5100", "MSM5500", "MSM5xxx"))
    result.add_argument("--width", type=integer)
    result.add_argument("--height", type=integer)
    result.add_argument("--framebuffer-address", type=integer)
    result.add_argument("--framebuffer-stride", type=integer)
    result.add_argument("--framebuffer-format", choices=FRAMEBUFFER_FORMATS)
    result.add_argument("--framebuffer-flush-address", type=integer)
    result.add_argument("--framebuffer-rect-flush-address", type=integer)
    result.add_argument("--board-revision")
    result.add_argument("--board-revision-register", type=integer)
    result.add_argument("--board-revision-value", type=integer)
    result.add_argument("--image-offset", type=integer)
    result.add_argument("--load-address", type=integer)
    result.add_argument("--flash-size", type=integer)
    result.add_argument("--secondary-flash-address", type=integer)
    result.add_argument("--secondary-flash-size", type=integer)
    result.add_argument("--secondary-flash-image")
    result.add_argument("--secondary-flash-state")
    result.add_argument("--secondary-flash-read-address", type=integer)
    result.add_argument("--secondary-flash-write-address", type=integer)
    result.add_argument("--legacy-efs-page-read-address", type=integer)
    result.add_argument("--eeprom-read-address", type=integer)
    result.add_argument("--eeprom-write-address", type=integer)
    result.add_argument("--eeprom-geometry-address", type=integer)
    result.add_argument("--ram-base", type=integer)
    result.add_argument("--ram-size", type=integer)
    result.add_argument("--ram-image-offset", type=integer)
    result.add_argument("--ram-image-size", type=integer)
    result.add_argument("--entry", type=integer)
    result.add_argument("--key-register", type=integer)
    result.add_argument("--key-active-high", dest="key_active_low", action="store_false")
    result.add_argument("--audio-play-address", type=integer)
    result.add_argument("--fast-boot-address", type=integer)
    result.add_argument("--delay-address", type=integer)
    result.add_argument("--busy-delay-address", type=integer)
    result.add_argument("--flash-state")
    result.add_argument("--nand-enabled", action=argparse.BooleanOptionalAction)
    result.add_argument("--nand-image")
    result.add_argument("--nand-data-size", type=integer)
    result.add_argument("--nand-page-size", type=integer)
    result.add_argument("--nand-spare-size", type=integer)
    result.add_argument("--nand-pages-per-block", type=integer)
    result.add_argument("--nand-bus-width", type=integer)
    result.add_argument("--nand-bad-block-address", type=integer)
    result.add_argument("--nand-read-address", type=integer)
    result.add_argument("--nand-write-address", type=integer)
    result.add_argument("--rex-idle-address", type=integer)
    result.add_argument("--rex-tick-address", type=integer)
    result.add_argument("--rex-irq-wrapper-address", type=integer)
    result.add_argument("--rex-tick-ms", type=integer)
    result.add_argument("--board-adc-address", type=integer)
    result.add_argument("--board-adc-value", type=integer)
    result.add_argument("--flash-id-address", type=integer)
    result.add_argument("--flash-id-value", type=integer)
    result.add_argument("--crc16-address", type=integer)
    result.add_argument("--dmd-download-address", type=integer)
    result.add_argument("--primary-flash-probe-address", type=integer)
    result.set_defaults(key_active_low=None)
    result.add_argument("--json", type=Path)
    return result


def main() -> int:
    from ..diagnostics.runtime_log import install_runtime_logging, record_diagnostic

    session_log = install_runtime_logging("cli")
    args = parser().parse_args()
    config = detect(args.firmware, args)
    LOGGER.info("CLI request firmware=%s detect_only=%s steps=%d log=%s build=%s",
                json.dumps(config.firmware_identity(), sort_keys=True),
                args.detect_only, args.steps, session_log.name, BUILD_CODENAME)
    LOGGER.info("detected model=%s chipset=%s image_offset=0x%X load=0x%X "
                "flash=0x%X screen=%dx%d board_revision=%s",
                config.model, config.chipset, config.image_offset,
                config.load_address, config.flash_size, config.width,
                config.height, config.board_revision)
    if args.detect_only:
        state = config.to_dict()
    else:
        emulator = GenericMSMEmulator(config)
        try:
            if args.steps < 0 or args.chunk_steps < 0:
                raise ValueError("steps and chunk steps must be non-negative")
            remaining = args.steps
            state: dict[str, object] = {}
            visible_pixels = 0
            while remaining:
                # A visual boot probe must sample immutable GUI-equivalent
                # frames.  Do not let a long single Unicorn run hide the
                # first panel update behind the full instruction budget.
                chunk_size = args.chunk_steps or (25_000 if args.until_visible else remaining)
                chunk = min(remaining, chunk_size)
                state = emulator.run(chunk)
                remaining -= chunk
                if args.until_visible:
                    _width, _height, frame = emulator.display_snapshot()
                    visible_pixels = sum(
                        any(frame[offset:offset + 3])
                        for offset in range(0, len(frame), 3)
                    )
                    if state["firmware_frame_sequence"] and visible_pixels:
                        state["visual_booted"] = True
                        break
                if state["fault"]:
                    break
            if not state:
                state = emulator.run(0)
            if args.display_metrics or args.until_visible:
                width, height, frame = emulator.display_snapshot()
                state.update({
                    "display_width": width,
                    "display_height": height,
                    "visible_pixels": (visible_pixels or sum(
                        any(frame[offset:offset + 3])
                        for offset in range(0, len(frame), 3)
                    )),
                })
                if args.until_visible:
                    state["visual_booted"] = bool(
                        state["firmware_frame_sequence"]
                        and state["visible_pixels"]
                    )
        except HostBackendFault as error:
            payload = {
                **error.diagnostic,
                "firmware": config.firmware_identity(),
                "model": config.model,
                "chipset": config.chipset,
            }
            artifact = record_diagnostic("host_backend_fault", payload)
            LOGGER.error("CLI host backend fault model=%s diagnostic=%s",
                         config.model,
                         artifact.name if artifact is not None else "unavailable")
            return 1
        finally:
            emulator.close()
    output = json.dumps(state, ensure_ascii=False, indent=2)
    if args.json:
        args.json.write_text(output + "\n", encoding="utf-8")
        LOGGER.info("JSON result saved file=%s", args.json.name)
    LOGGER.info("CLI complete model=%s fault=%r", config.model,
                state.get("fault") if isinstance(state, dict) else None)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
