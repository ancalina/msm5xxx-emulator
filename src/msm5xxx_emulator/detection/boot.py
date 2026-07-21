"""Firmware boot and guarded-HLE signature detection."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target
from .signatures import find_all


AUDIO_PLAY_SIGNATURE = bytes.fromhex(
    "ffb5071c0e1c27490868400838d38868002835db002f33db042f31da002e2fd0c"
    "c207843441824342078012828d1e51d1d35281cfff76afa039b0120002b00d1"
)
SECONDARY_FLASH_WRAPPER_PATTERN = re.compile(
    rb"\xf0\xb5.\x4e\x07\x1c\x30\x68\x15\x1c\x0c\x1c\x00\x28.\xd1"
    rb".{4}\xff\x20.\x30.\x49.{4}.\x48\x00\x79\x01\x28\x02\xd1"
    rb"\xf0\xbc\x08\xbc\x18\x47\x30\x68\x2a\x1c\xff\x30.\x30"
    rb"(?P<dispatch>\xc3\x6b|\x03\x68)\x21\x1c\x38\x1c.{4}",
    re.S,
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
BUSY_DELAY_REGISTER_SIGNATURE = bytes.fromhex("094309430943401efadcf746")
BUSY_DELAY_SIGNATURES = (BUSY_DELAY_SIGNATURE, BUSY_DELAY_REGISTER_SIGNATURE)
OPTIONAL_RAM_PROBE_SIGNATURE = bytes.fromhex(
    "0c480d4940080968400040180188aa22028002881206120e"
    "aa2a06d15522028002881206120e552a01d0002070470180"
    "01207047"
)
OPTIONAL_RAM_CALLER_PATTERN = bytes.fromhex(
    "f0b500250e4c0f4e0020256030602f1c0320c0052060"
    "00000000"
    "002802d1"
    "00000000"
    "30603068002800d12760ff300030c069"
    "00000000"
    "2571f0bc08bc1847"
)
OPTIONAL_RAM_CALLER_WILDCARDS = frozenset((
    *range(0x16, 0x1A), *range(0x1E, 0x22), 0x2E, *range(0x32, 0x36),
))
REGISTER_RAMP_PREFIX = bytes.fromhex(
    "32234b439d1822237b43341ceb1a9b1100d41c1c0f4f3c80"
    "32234b4332389b189b1101d41c1c00e0341c2404240c01e0"
)
BOARD_ADC_SIGNATURE = bytes.fromhex(
    "f1b584b00027049a002521492e1c009700200024895cd2000392ca1f033a0a31"
)
BOARD_ADC_READER_READ_OFFSET = 0x7E
FLASH_ID_SIGNATURE = bytes.fromhex(
    "30b50e4b011ccc18084d094b258023800b4bca18074b1380074b238008884b88"
    "00041b04000c"
)
CRC16_SIGNATURE = bytes.fromhex(
    "90b4c0430004000c0a4f0ce00c78031263405b00fb5a000258400004000c013a"
    "1204120c0131002af0dcc0430004000c90bc7047"
)
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
# ARM ADS bootstrap clear loop.  HLE stops at each native watchdog boundary;
# the firmware still performs every MMIO strobe and final tail comparison.
ARM_MEMORY_CLEAR_CHUNK_SIGNATURE = bytes.fromhex(
    "003041e0200053e30a00003aa332a0e1ff3ad3e30100000a"
    "c41fa0e8f7ffffeaa4409fe50150a0e3005084e50050a0e3"
    "005084e5f7ffffea010050e104208034fcffff3a"
)
ARM_MEMORY_CLEAR_STROBE_PERIOD = 0x20000
DMD_DOWNLOAD_SIGNATURE = bytes.fromhex("f0b5002701250024354901200870")
DMD_DOWNLOAD_510X_SIGNATURE = bytes.fromhex(
    "f0b539480027006801250024002800d060e0"
)
PRIMARY_FLASH_PROBE_SIGNATURE = bytes.fromhex(
    "16481749006b096840004018aa221101411881b04a81552215239b01c3189a82"
    "90224a81018800ab198041885980f02101800c480ce000abff3121311a888b88"
    "9a4204d100ab5a88c9888a4203d0043001680029efd1006801b07047"
)


def busy_delay_addresses(image: bytes, load_address: int,
                         configured_address: int | None) -> list[int]:
    """Return all exact primary-ROM busy-delay entries, including overrides."""
    addresses = {load_address + offset for signature in BUSY_DELAY_SIGNATURES
                 for offset in find_all(image, signature)}
    if configured_address is not None:
        addresses.add(configured_address)
    return sorted(addresses)


def absent_optional_ram_probe_addresses(image: bytes, load_address: int,
                                        ram_base: int,
                                        ram_size: int) -> list[int]:
    """Find cross-checked probes for an absent expansion bank beyond RAM."""
    if ram_base + ram_size != 0x01800000:
        return []
    probes: set[int] = set()
    for caller in find_all(image, OPTIONAL_RAM_CALLER_PATTERN[:0x16]):
        if caller & 1 or caller + len(OPTIONAL_RAM_CALLER_PATTERN) > len(image):
            continue
        candidate = image[caller:caller + len(OPTIONAL_RAM_CALLER_PATTERN)]
        if any(index not in OPTIONAL_RAM_CALLER_WILDCARDS
               and value != OPTIONAL_RAM_CALLER_PATTERN[index]
               for index, value in enumerate(candidate)):
            continue
        if candidate[0x2E] not in (0x01, 0x81):
            continue
        status, object_global = struct.unpack_from("<2I", image, caller + 0x40)
        probe = thumb_bl_target(image, caller + 0x16)
        if (status == object_global or probe is None
                or image[probe:probe + len(OPTIONAL_RAM_PROBE_SIGNATURE)]
                != OPTIONAL_RAM_PROBE_SIGNATURE
                or probe + 0x3C > len(image)
                or struct.unpack_from("<I", image, probe + 0x34)[0] != 0x007FFFDE
                or struct.unpack_from("<I", image, probe + 0x38)[0] != status
                or thumb_bl_target(image, caller + 0x1E) is None
                or thumb_bl_target(image, caller + 0x32) is None):
            continue
        probes.add(load_address + probe)
    return sorted(probes)


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
