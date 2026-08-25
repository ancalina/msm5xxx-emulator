"""Firmware storage-driver detection."""
from __future__ import annotations

import hashlib
import re
import struct

from .arm import arm_vector_score, thumb_bl_target, thumb_literal_value
from .boot import (
    DIRECT_INTEL_X16_PROBE_SIGNATURE,
    FLASH_ID_SIGNATURE,
    PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE,
    PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE,
    PRIMARY_FLASH_PROBE_SIGNATURE,
)
from .signatures import find_all


FUJITSU_MB84VD2219X_IDS = (0x0004, 0x005F)
FUJITSU_X16_BULK_WRITE_MAX_SIZE = 0x118
PRIMARY_FSD_AMD_X16_WRITER_PREFIX = bytes.fromhex(
    "f0b5544b8f181b68ff3381339c696400a74200d962e0504f"
)
PRIMARY_FSD_AMD_X16_WRITER_SIZE = 0x152
PRIMARY_FSD_AMD_X16_WRITER_CALLS = (0x4A,)
PRIMARY_FSD_AMD_X16_WRITER_HASH = (
    "4e6e8bf7a24612fe68352426367bc562796e239f8e9148153aed31c7eb7e7769"
)
ADJACENT_AMD_X16_WRITER_PREFIX = bytes.fromhex(
    "f7b5041c161c86b07df08cf88a4f0125b989ad032943b981b9893a681180"
)
ADJACENT_AMD_X16_WRITER_SIZE = 0x23C
ADJACENT_AMD_X16_WRITER_CALLS = (
    0x08, 0x22, 0x28, 0xC8, 0xF0, 0x10A, 0x144,
    0x168, 0x182, 0x1BA, 0x1DE, 0x1F8, 0x210, 0x22A,
)
ADJACENT_AMD_X16_WRITER_HASH = (
    "fdf4394e4809829af42a7cc4ff86017a71fd719fe807904db2bd52c85a4f050d"
)
ADJACENT_AMD_X16_RECORD_PREFIX = bytes.fromhex("b8b50420")
ADJACENT_AMD_X16_RECORD_MARKER = bytes.fromhex("5555")
ADJACENT_AMD_X16_RECORD_LOG = b"Record_Init() - "
PRIMARY_FSD_AMD_X16_ID_ROUTINE = bytes.fromhex(
    "30b50e4b011ccc18084d094b258023800b4bca18074b1380074b238008884b88"
    "00041b04000c184325800be0f0000000aa0000005500000090000000aa0a0000"
    "5405000030bd"
)
FUJITSU_X16_BULK_WRITE_HASHED_SHAPES = (
    (
        bytes.fromhex(
            "f8b5041c8818171c3c4a1268ff32c132936b5b00984205d8"
        ),
        0xFC, 0x104, (0xAAA0, 0x5540),
        (0x4A, 0x64, 0x6C, 0xA2, 0xBE, 0xC6, 0xD4, 0xE8, 0xF2),
        "0d6ec61f9c5574193e392fa98e95219cd1b7897993fb9a96f9f8488cf49bc62f",
    ),
    (
        bytes.fromhex(
            "f8b5041c3c488b18171c42688032556b6d00ab4201d90120"
        ),
        0xF8, 0xFC, (0x5540, 0xAAA0),
        (0x46, 0x60, 0x68, 0xA4, 0xC0, 0xC8, 0xD4, 0xE8, 0xF0),
        "975c74b1238c4877172250f17d79d064290c18b6aa3b677b9b1d9241ec29bd9b",
    ),
    (
        bytes.fromhex(
            "f8b5041c8818171c3b4a12688032536b5b00984205d8394b"
        ),
        0xF8, 0x100, (0xAAA0, 0x5540),
        (0x48, 0x62, 0x6A, 0xA0, 0xBC, 0xC4, 0xD2, 0xE6, 0xF0),
        "d8eaaac4d169ad91c278fcbfadee8ffa6bc6ade2dfe3dbea8909a611bb9b429c",
    ),
    (
        bytes.fromhex(
            "f8b5041c8818171c3b4a12688032536b5b00984205d8394b"
        ),
        0xF8, 0x100, (0xAAA0, 0x5540),
        (0x48, 0x62, 0x6A, 0xA0, 0xBC, 0xC4, 0xD2, 0xE6, 0xF0),
        "6074b6f9c6cf75cbc978cca8a482709c82482234a73b0a70bcb28da747926579",
    ),
)
FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX = bytes.fromhex(
    "f0b50f1c041c151c400803d2780801d2680802d3"
)
FUJITSU_X16_BULK_WRITE_LEGACY_CALLS = (
    0x1E, 0x2C, 0x3C, 0x46, 0x54, 0x6A, 0x72,
)
FUJITSU_X16_BULK_WRITE_LEGACY_HASH = (
    "16e6f343004a5392fc97d35ef170209ff59e462aad0bb209d7c25d1793f5ec13"
)


PAGE = 0x1000
DIRECT_INTEL_X16_CALLER_PREFIX = bytes.fromhex(
    "b0b50e4d00240e4f2c6000203860"
)
DIRECT_AMD_X16_PROBE_SIGNATURE = bytes.fromhex(
    "164817494069096840004018aa221101411881b04a81552215239b01c3189a82"
    "90224a81018800ab198041885980f02101800c480ce000abff3101311a880b89"
    "9a4204d100ab5a8849898a4203d0043001680029efd1006801b07047"
)
DIRECT_AMD_X16_CALLER_PREFIX = bytes.fromhex(
    "f0b500240f4e271c0f4d002034602860"
)
MAPPED_PRIMARY_INTEL_X16_SIGNATURES = (
    (0, bytes.fromhex(
        "b0b401246405e70a62090925ed04072800d382e0"
    )),
    (0x60, bytes.fromhex(
        "33a048600120000788600d20c004c8600320c00408612b484a610338c8610022"
        "8a61022008844a8433e0"
    )),
    (0x164, bytes.fromhex(
        "80b50b4f0220396824f1aefe0121090648087a6824f182fe0121890509208005"
        "7a6824f17bfe80bc08bc01201847"
    )),
    (-0x25AB4, bytes.fromhex(
        "f8b5051c0e1c141c1848c06840190090281916494968884203d90020f8bc08bc"
        "18470027a74210d202e0781c071cf9e7f05d0099c95d8843f7d0231c321c291c"
        "0b48bff758f90020e8e7221c311c0098c4f72cfc002806d14af13cfc05493f20"
        "400151f76ff90120d8e7"
    )),
    (0x12252, bytes.fromhex(
        "00b500f002f808bc1847fcb5071c0d1c141c12f1bcfd6f4a012391899b031943"
        "9181918912681180002800d0afe012f1b6fdace0"
    )),
    (0x12286, bytes.fromhex(
        "780825d37f087f00388800ab60211880287801355022ff2658704020388000ab"
        "188838803888000afcd33888800806d33a803980d02038803888000afcd33e80"
        "388800ab"
    )),
    (0x12434, bytes.fromhex(
        "f0b5071c12f1d2fc244a012391899b0319439181918912681180002801d112f1"
        "cdfc602150222025ff243a803980d02038803e88330afcd33c803d80388038880"
        "00afcd338888008efd2388802231840134d06d012f1cafc291c1d20400119f7fd"
        "f93888000905d312f1c0fc291c0d4819f7f4f93c80"
    )),
)

# Thumb copy loop: load size/source/target through adjacent scatter-tuple
# field pointers, then copy five words until the target end is reached.
PRIMARY_STATIC_TABLE_COPY_PATTERN = re.compile(
    rb".\x48\x02\x68\x00\x92.\x48\x00\x68.\x49\x09\x68"
    rb"\x00\x9a\x8a\x18\xf8\xc8\xf8\xc1\x91\x42\xfb\xdb",
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


EEPROM_24LCXX_WRITE_PREFIX = bytes.fromhex(
    "f7b593b001267603149c171cb442f94902db8878012802d10020149c06e0"
    "c878149c01235b03e21a1404240c0a880625b24202d089780229"
)
EEPROM_24LCXX_READ_SIGNATURE = bytes.fromhex(
    "f0b5151c01225203071cfa48914202db8378012b02d100240e1c05e001235b03"
    "c91ac4780e04360c0188914202d08078"
)
# Older ADS driver class proven across nine Samsung images.  This class uses
# an inclusive 0x1FFF maximum (8 KiB), not the later 24LC256 descriptor.
EEPROM_24LC64_CLASS_A_WRITE_PREFIX = bytes.fromhex(
    "f7b5f9498cb0ca1d1932051c01230d9c5b039c4202db9078012802d100200d9c"
    "05e0d0780d9cf14be3181c04240c0f8c"
)
EEPROM_24LC64_CLASS_A_READ_PREFIX = bytes.fromhex(
    "f0b5151cf84a071cd01d193001235b03994202db8378012b02d100260c1c04e0"
)
EEPROM_24LC64_CLASS_A_SENTINEL = bytes.fromhex(
    "0649aa200f396118c873f0bc08bc1847"
)
# Older 8 KiB transport with capacity encoded directly in both entry guards.
EEPROM_24LC64_CLASS_B_WRITE_PREFIX = bytes.fromhex(
    "f7b5151c01235b03994283b0f64e02dbb078012802d100200f1c04e0f34af078"
)
EEPROM_24LC64_CLASS_B_READ_PREFIX = bytes.fromhex(
    "f0b5141c051c01235b039942f74a02db9078012802d100260f1c04e0f448d678"
)
EEPROM_24LC64_CLASS_B_BOUND = bytes.fromhex("01235b039942")
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
    "f0b5041c151c01235b039942f74802db8278012a02d100270e1c04e0f44ac778"
    "89180e04360c011c0088f14bd84202d08978022909d1700b400703d17019400b"
    "40071fd0eb49ec4816e001239b0398420ad1b00b800703d17019800b800711d0"
    "e548e449083007e0300c02d27019000c08d3e148df490e30"
)
EEPROM_24LCXX_X270_INIT_SIGNATURE = bytes.fromhex(
    "01200449c0030880012088700020c8707047"
)
# Same paired transport grammar with the writer geometry literal four bytes
# earlier than the X270 class.  Admission still requires the common read,
# initializer, marker, and one shared RAM geometry global.
EEPROM_24LCXX_F6F7_WRITE_PREFIX = bytes.fromhex(
    "f7b5161c93b0149901235b039942f64a02db9078012802d10020149c05e0d078"
    "1499f24bc9180c04240c1188ef4bd94202d09278022a09d1610b490703d1a119"
    "490b490716d0ea49ea481de001239b0399420ad1a10b890703d1a119890b8907"
    "08d0e448e24908300ee0210c09d2a119090c06d20e231840a0210843129000f0"
    "00fbdc48da490e30"
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


FLASH_IDS_BY_SIZE = {
    0x200000: 0x222D0001,  # AMD AM29DL162BT
    0x400000: 0x22500001,  # AMD AM29DL323DT
    0x800000: 0x227E0001,  # AMD AM29DL640G
}

FS_DEVICE_LOOKUP_TAIL = bytes.fromhex(
    "07e080310a89498909041143b94203d0043001680029f4d1006890bd"
)
FS_DEVICE_OUTER_RESET = bytes.fromhex("002727606760")
FS_DEVICE_LOOKUP_PREFIX = bytes.fromhex(
    "90b5104810494069096840004718"
)


def find_fs_device_flash_id(
        image: bytes, flash_id_address: int | None) -> int | None:
    """Return the uniquely linked fs_dev NOR descriptor ID."""
    signature_sites = find_all(image, FLASH_ID_SIGNATURE)
    if flash_id_address is None or len(signature_sites) != 1:
        return None
    signature_site = signature_sites[0]
    tails = find_all(image, FS_DEVICE_LOOKUP_TAIL)
    if len(tails) != 1:
        return None
    lookup = tails[0] - 0x28
    if (lookup < 0 or lookup & 1 or lookup + 0x54 > len(image)
            or image[lookup:lookup + 0xE] != FS_DEVICE_LOOKUP_PREFIX
            or image[lookup + 0x12:lookup + 0x18]
            != bytes.fromhex("041c381c0d49")
            or image[lookup + 0x1C:lookup + 0x22]
            != bytes.fromhex("071c002c01d1")):
        return None

    descriptor = thumb_literal_value(image, lookup + 2, 0)
    module_base = thumb_literal_value(image, lookup + 4, 1)
    trampoline = thumb_literal_value(image, lookup + 0x16, 1)
    table = thumb_literal_value(image, lookup + 0x26, 0)
    if any(value is None for value in (
            descriptor, module_base, trampoline, table)):
        return None
    assert descriptor is not None and module_base is not None
    assert trampoline is not None and table is not None
    veneer = thumb_bl_target(image, lookup + 0x18)
    if (thumb_bl_target(image, lookup + 0x0E) is None
            or veneer is None or not 0 <= veneer <= len(image) - 2
            or image[veneer:veneer + 2] != b"\x08\x47"
            or thumb_bl_target(image, lookup + 0x22) is None
            or not 0x01000000 <= module_base < 0x02000000
            or not 0x01000000 <= table < 0x02000000
            or trampoline != table + 9
            or trampoline & ~1 != flash_id_address
            or len(find_all(image, struct.pack("<I", table))) != 1
            or len(find_all(image, struct.pack("<I", trampoline))) != 1):
        return None

    entry = descriptor - 0x80
    if (entry < 0 or descriptor + 0x1C > len(image)
            or signature_site < 8
            or struct.unpack_from("<2I", image, signature_site - 8)
            != (entry, 0)):
        return None
    sector_count = struct.unpack_from("<I", image, entry + 4)[0]
    if not 1 <= sector_count <= (0x80 - 8) // 4:
        return None
    sector_end = entry + 8 + sector_count * 4
    if sector_end > descriptor:
        return None
    sectors = struct.unpack_from(f"<{sector_count}I", image, entry + 8)
    device_id = struct.unpack_from("<I", image, descriptor + 8)[0]
    banks = struct.unpack_from("<I", image, descriptor + 0x10)[0]
    base_words = struct.unpack_from("<I", image, descriptor + 0x14)[0]
    usable_words = struct.unpack_from("<I", image, descriptor + 0x18)[0]
    manufacturer, device = device_id & 0xFFFF, device_id >> 16
    if (manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)
            or banks != 1 or base_words == 0 or usable_words == 0
            or (base_words * 2) & (PAGE - 1)
            or any(size < PAGE or size > 0x100000 or size & (PAGE - 1)
                   for size in sectors)
            or sum(sectors) != usable_words * 2):
        return None

    outers = []
    for reset in find_all(image, FS_DEVICE_OUTER_RESET):
        outer = reset - 4
        if (outer >= 0
                and image[outer:outer + 4] == b"\x90\xb5\x08\x4c"
                and thumb_literal_value(image, outer + 2, 4) == module_base
                and thumb_bl_target(image, outer + 10) == lookup
                and image[outer + 0xE:outer + 0x12]
                == b"\x60\x60\x00\x28"
                and struct.unpack_from("<H", image, outer + 0x12)[0] & 0xFF00
                == 0xD100):
            outers.append(outer)
    return device_id if len(outers) == 1 else None


def flash_id_for_size(size: int) -> int | None:
    """Return a firmware-supported AMD NOR ID for a complete dump."""
    for capacity, device_id in FLASH_IDS_BY_SIZE.items():
        if capacity - PAGE <= size <= capacity:
            return device_id
    return None


def _primary_fsd_amd_x16_writer_at(image: bytes, position: int) -> bool:
    if (position < 0
            or position + PRIMARY_FSD_AMD_X16_WRITER_SIZE > len(image)
            or image[position:position + len(PRIMARY_FSD_AMD_X16_WRITER_PREFIX)]
               != PRIMARY_FSD_AMD_X16_WRITER_PREFIX):
        return False
    body = bytearray(
        image[position:position + PRIMARY_FSD_AMD_X16_WRITER_SIZE]
    )
    calls: list[int] = []
    for offset in range(0, len(body) - 3, 2):
        if thumb_bl_target(image, position + offset) is None:
            continue
        calls.append(offset)
        body[offset:offset + 4] = b"\0" * 4
    return (tuple(calls) == PRIMARY_FSD_AMD_X16_WRITER_CALLS
            and hashlib.sha256(body).hexdigest()
            == PRIMARY_FSD_AMD_X16_WRITER_HASH)


def find_primary_fsd_amd_x16_nor(
        image: bytes, flash_id_address: int | None, flash_size: int,
) -> tuple[int, int, int, int, int] | None:
    """Return a uniquely linked writable primary x16 NOR tail profile."""
    if (b"fsd_amd.c\0" not in image or flash_id_address is None
            or flash_size <= 0 or flash_size > len(image)):
        return None
    writers = [
        position
        for position in find_all(image, PRIMARY_FSD_AMD_X16_WRITER_PREFIX)
        if _primary_fsd_amd_x16_writer_at(image, position)
    ]
    if len(writers) != 1:
        return None
    writer = writers[0]
    profiles: list[tuple[int, int, int, int, int]] = []
    for reference in find_all(image, struct.pack("<I", writer | 1)):
        descriptor = reference - 0x1C
        if descriptor < 0 or descriptor + 0x34 > flash_size:
            continue
        device_id, reserved, banks, base_words, usable_words = (
            struct.unpack_from("<5I", image, descriptor)
        )
        functions = struct.unpack_from("<7I", image, descriptor + 0x14)
        name_address = descriptor + 0x30
        name_end = image.find(b"\0", name_address, name_address + 32)
        manufacturer, device = device_id & 0xFFFF, device_id >> 16
        base, size = base_words * 2, usable_words * 2
        if (reserved != 0 or banks != 1 or functions[2] != writer | 1
                or any(not pointer & 1 or pointer & ~1 >= flash_size
                       for pointer in functions)
                or name_end < name_address + 4
                or any(not 0x21 <= byte <= 0x7E
                       for byte in image[name_address:name_end])
                or manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)
                or base <= 0 or size <= 0 or base + size != flash_size):
            continue
        geometries: list[tuple[int, int]] = []
        for sector_count in range(1, min(512, (descriptor - 8) // 4) + 1):
            entry = descriptor - 8 - sector_count * 4
            if (struct.unpack_from("<2I", image, entry)
                    != (name_address, sector_count)):
                continue
            sectors = struct.unpack_from(
                f"<{sector_count}I", image, entry + 8
            )
            sector_size = sectors[0]
            if (all(value == sector_size for value in sectors)
                    and PAGE <= sector_size <= 0x100000
                    and not sector_size & (PAGE - 1)
                    and sum(sectors) == size
                    and not base % sector_size):
                geometries.append((entry, sector_size))
        if len(geometries) != 1:
            continue
        entry, sector_size = geometries[0]
        if (flash_id_address < 12
                or struct.unpack_from("<3I", image, flash_id_address - 12)
                   != (0, entry, 0)
                or image[flash_id_address:
                         flash_id_address + len(PRIMARY_FSD_AMD_X16_ID_ROUTINE)]
                   != PRIMARY_FSD_AMD_X16_ID_ROUTINE):
            continue
        profiles.append((base, size, sector_size, manufacturer, device))
    return profiles[0] if len(profiles) == 1 else None


def _adjacent_amd_x16_writer_at(image: bytes, position: int) -> bool:
    if (position < 0
            or position + ADJACENT_AMD_X16_WRITER_SIZE > len(image)
            or image[position:position + len(ADJACENT_AMD_X16_WRITER_PREFIX)]
               != ADJACENT_AMD_X16_WRITER_PREFIX):
        return False
    body = bytearray(
        image[position:position + ADJACENT_AMD_X16_WRITER_SIZE]
    )
    calls: list[int] = []
    for offset in range(0, len(body) - 3, 2):
        if thumb_bl_target(image, position + offset) is None:
            continue
        calls.append(offset)
        body[offset:offset + 4] = b"\0" * 4
    return (tuple(calls) == ADJACENT_AMD_X16_WRITER_CALLS
            and hashlib.sha256(body).hexdigest()
            == ADJACENT_AMD_X16_WRITER_HASH)


def find_adjacent_amd_x16_nor(
        image: bytes, flash_size: int,
) -> tuple[int, int, int, int] | None:
    """Return one temporary exact adjacent AMD x16 NOR profile."""
    marker = b"fsd_toshiba.c\0"
    if (flash_size != 0x800000 or len(image) < flash_size
            or image[:flash_size].count(marker) != 1):
        return None
    primary = image[:flash_size]
    writers = [
        position
        for position in find_all(primary, ADJACENT_AMD_X16_WRITER_PREFIX)
        if _adjacent_amd_x16_writer_at(primary, position)
    ]
    records = [
        position
        for position in find_all(primary, ADJACENT_AMD_X16_RECORD_PREFIX)
        if (position + 0x120 <= len(primary)
            and primary[position + 0x10C:position + 0x10E]
            == ADJACENT_AMD_X16_RECORD_MARKER
            and primary[position + 0x110:position + 0x120]
            == ADJACENT_AMD_X16_RECORD_LOG)
    ]
    identity = flash_id_for_size(flash_size)
    if len(writers) != 1 or len(records) != 1 or identity is None:
        return None
    return flash_size, flash_size, identity & 0xFFFF, identity >> 16


def direct_amd_x16_nor_profile(
        image: bytes, load_address: int, flash_size: int, image_offset: int,
        ram_base: int, ram_size: int,
) -> tuple[tuple[int, int, int, int, int, int] | None, str | None]:
    """Decode one exact ordered-descriptor direct AMD x16 NOR probe."""
    flash_end = load_address + flash_size
    ram_end = ram_base + ram_size
    primary_end = min(len(image), image_offset + flash_size)
    primary = image[image_offset:primary_end]

    def primary_offset(address: int, size: int) -> int | None:
        offset = address - load_address
        if (load_address <= address <= flash_end - size
                and 0 <= offset <= len(primary) - size):
            return offset
        return None

    probes = find_all(primary, DIRECT_AMD_X16_PROBE_SIGNATURE)
    if not probes:
        return None, None
    if len(probes) != 1:
        return None, "probe-shape-mismatch"
    probe = probes[0]
    literal_offset = probe + len(DIRECT_AMD_X16_PROBE_SIGNATURE)
    if literal_offset + 12 > len(primary):
        return None, "probe-shape-mismatch"
    descriptor_view, flash_base_global, table_global = struct.unpack_from(
        "<3I", primary, literal_offset
    )
    if (descriptor_view & 3 or flash_base_global & 3 or table_global & 3
            or not ram_base <= flash_base_global <= ram_end - 4
            or not ram_base <= table_global <= ram_end - 4):
        return None, "probe-global-range-mismatch"

    callers = [
        caller for caller in find_all(primary, DIRECT_AMD_X16_CALLER_PREFIX)
        if (caller + 0x50 <= len(primary)
            and all(thumb_bl_target(primary, caller + offset) is not None
                    for offset in (0x10, 0x1E, 0x2E, 0x38))
            and thumb_bl_target(primary, caller + 0x18) == probe
            and primary[caller + 0x14:caller + 0x18]
                == bytes.fromhex("002804d1")
            and primary[caller + 0x1C:caller + 0x1E]
                == bytes.fromhex("2860")
            and primary[caller + 0x22:caller + 0x2E]
                == bytes.fromhex("2868002800d13760002806d1")
            and primary[caller + 0x32:caller + 0x38]
                == bytes.fromhex("ff2089300549")
            and primary[caller + 0x3C:caller + 0x44]
                == bytes.fromhex("3471f0bc08bc1847")
            and thumb_literal_value(primary, caller + 4, 6)
                == flash_base_global
            and (return_global := thumb_literal_value(
                primary, caller + 8, 5
            )) is not None
            and not return_global & 3
            and ram_base <= return_global <= ram_end - 4
            and (log_string := thumb_literal_value(
                primary, caller + 0x36, 1
            )) is not None
            and primary_offset(log_string, 4) is not None)
    ]
    if len(callers) != 1:
        return None, "probe-caller-mismatch"

    candidates: list[tuple[int, tuple[int, ...]]] = []
    for sector_count in range(1, 513):
        entry = descriptor_view - sector_count * 4
        entry_offset = primary_offset(entry, 8 + sector_count * 4)
        if entry_offset is None:
            continue
        name_address, count = struct.unpack_from("<2I", primary, entry_offset)
        if count != sector_count:
            continue
        descriptor = descriptor_view + 8
        descriptor_offset = primary_offset(descriptor, 0x30)
        name_offset = primary_offset(name_address, 4)
        if (descriptor_offset is None or name_offset is None
                or name_address != descriptor + 0x30):
            continue
        sectors = struct.unpack_from(
            f"<{sector_count}I", primary, entry_offset + 8
        )
        candidates.append((descriptor_offset, sectors))
    if len(candidates) != 1:
        return None, "descriptor-shape-mismatch"

    descriptor_offset, sectors = candidates[0]
    (device_id, reserved, device_control_options, base_words, usable_words,
     *functions) = struct.unpack_from("<12I", primary, descriptor_offset)
    manufacturer, device = device_id & 0xFFFF, device_id >> 16
    base_address = base_words * 2
    size = usable_words * 2
    name_offset = descriptor_offset + 0x30
    name_end = primary.find(
        b"\0", name_offset, min(name_offset + 64, len(primary))
    )
    if (reserved != 0 or device_control_options != 1
            or len(functions) != 7
            or any(not (pointer & 1)
                   or not load_address <= (pointer & ~1) < flash_end
                   for pointer in functions)
            or name_end < name_offset + 4
            or any(not 0x20 <= byte <= 0x7E
                   for byte in primary[name_offset:name_end])
            or manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)
            or not ram_base <= base_address < ram_end or size <= 0
            or base_address + size > ram_end
            or base_address + size > 0x100000000
            or sum(sectors) != size):
        return None, "descriptor-content-mismatch"
    sector_size = sectors[0]
    if (sector_size < PAGE or sector_size > 0x100000
            or sector_size & (sector_size - 1)
            or any(sector != sector_size for sector in sectors)
            or base_address % sector_size or size % sector_size):
        return None, "geometry-sector-mismatch"
    return (base_address, size, sector_size, manufacturer, device,
            device_control_options), None


def direct_intel_x16_nor_profile(
        image: bytes, probe_address: int | None, load_address: int,
        flash_size: int, image_offset: int, ram_base: int, ram_size: int,
) -> tuple[tuple[int, int, int, int, int] | None, str | None]:
    """Decode one ordered-descriptor direct Intel x16 NOR probe."""
    if probe_address is None:
        return None, None
    flash_end = load_address + flash_size
    primary_end = min(len(image), image_offset + flash_size)
    ram_end = ram_base + ram_size

    def primary_offset(address: int, size: int) -> int | None:
        offset = image_offset + address - load_address
        if (load_address <= address <= flash_end - size
                and image_offset <= offset <= primary_end - size):
            return offset
        return None

    signature = DIRECT_INTEL_X16_PROBE_SIGNATURE
    probe = primary_offset(probe_address, len(signature) + 12)
    if (probe is None or image[probe:probe + len(signature)] != signature
            or image.find(signature, image_offset, primary_end) != probe
            or image.find(signature, probe + 1, primary_end) >= 0):
        return None, "probe-shape-mismatch"
    descriptor_view, flash_base_global, table_global = struct.unpack_from(
        "<3I", image, probe + len(signature)
    )
    if (descriptor_view & 3 or flash_base_global & 3 or table_global & 3
            or not ram_base <= flash_base_global <= ram_end - 4
            or not ram_base <= table_global <= ram_end - 4):
        return None, "probe-global-range-mismatch"

    primary = image[image_offset:primary_end]
    probe_position = probe - image_offset
    callers = [
        caller for caller in find_all(primary, DIRECT_INTEL_X16_CALLER_PREFIX)
        if (caller + 68 <= len(primary)
            and thumb_bl_target(primary, caller + 14) == probe_position
            and primary[caller + 18:caller + 24]
                == bytes.fromhex("3860002806d1")
            and primary[caller + 28:caller + 34]
                == bytes.fromhex("ff2089300849")
            and primary[caller + 38:caller + 46]
                == bytes.fromhex("3868ff300130c069")
            and primary[caller + 50:caller + 58]
                == bytes.fromhex("2c71b0bc08bc1847")
            and all(thumb_bl_target(primary, caller + offset) is not None
                    for offset in (24, 34, 46))
            and thumb_literal_value(primary, caller + 2, 5)
                == flash_base_global
            and (return_global := thumb_literal_value(
                primary, caller + 6, 7
            )) is not None
            and not return_global & 3
            and ram_base <= return_global <= ram_end - 4)
    ]
    if len(callers) != 1:
        return None, "probe-caller-mismatch"

    candidates: list[tuple[int, tuple[int, ...]]] = []
    for sector_count in range(1, 513):
        entry = descriptor_view - sector_count * 4
        entry_offset = primary_offset(entry, 8 + sector_count * 4)
        if entry_offset is None:
            continue
        name_address, count = struct.unpack_from("<2I", image, entry_offset)
        if count != sector_count:
            continue
        descriptor = descriptor_view + 8
        descriptor_offset = primary_offset(descriptor, 0x30)
        name_offset = primary_offset(name_address, 4)
        if (descriptor_offset is None or name_offset is None
                or name_address != descriptor + 0x30):
            continue
        sectors = struct.unpack_from(
            f"<{sector_count}I", image, entry_offset + 8
        )
        candidates.append((descriptor_offset, sectors))
    if len(candidates) != 1:
        return None, "descriptor-shape-mismatch"

    descriptor_offset, sectors = candidates[0]
    (device_id, reserved, banks, base_words, usable_words,
     *functions) = struct.unpack_from("<12I", image, descriptor_offset)
    manufacturer, device = device_id & 0xFFFF, device_id >> 16
    base_address = base_words * 2
    size = usable_words * 2
    name_offset = descriptor_offset + 0x30
    name_end = image.find(b"\0", name_offset,
                          min(name_offset + 64, primary_end))
    if (reserved != 0 or banks != 1 or len(functions) != 7
            or any(not (pointer & 1)
                   or not load_address <= (pointer & ~1) < flash_end
                   for pointer in functions)
            or name_end < name_offset + 4
            or any(not 0x20 <= byte <= 0x7E
                   for byte in image[name_offset:name_end])
            or manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)
            or base_address != ram_end or size <= 0
            or base_address + size > 0x100000000
            or sum(sectors) != size):
        return None, "descriptor-content-mismatch"
    sector_size = sectors[0]
    if (sector_size < PAGE or sector_size > 0x100000
            or sector_size & (sector_size - 1)
            or any(sector != sector_size for sector in sectors)
            or base_address % sector_size or size % sector_size):
        return None, "geometry-sector-mismatch"
    return (base_address, size, sector_size, manufacturer, device), None


def mapped_primary_intel_x16_nor_profile(
        image: bytes, flash_size: int, ram_base: int,
) -> tuple[tuple[int, int, int, int] | None, str | None]:
    """Admit one temporary exact-signature mapped primary NOR profile."""
    primary = image[:flash_size]
    anchor_signature = MAPPED_PRIMARY_INTEL_X16_SIGNATURES[0][1]
    anchors = find_all(primary, anchor_signature)
    if not anchors:
        return None, None
    if len(anchors) != 1:
        return None, "code-anchor-mismatch"
    anchor = anchors[0]
    for index, (delta, signature) in enumerate(
            MAPPED_PRIMARY_INTEL_X16_SIGNATURES):
        position = anchor + delta
        if (position < 0
                or primary[position:position + len(signature)] != signature
                or find_all(primary, signature) != [position]):
            return None, f"code-signature-{index}-mismatch"

    logical_base = 0x00000000
    physical_base = 0x00800000
    size = 0x00800000
    sector_size = 0x00010000
    if (len(primary) != flash_size or logical_base + size != flash_size
            or physical_base + size != ram_base
            or physical_base < flash_size or size % sector_size):
        return None, "mapped-geometry-mismatch"
    return (logical_base, physical_base, size, sector_size), None


def primary_probe_x16_nor_profile(
        image: bytes, probe_address: int | None, load_address: int,
        flash_size: int, image_offset: int, ram_base: int,
        ram_image_offset: int, ram_image_size: int,
        ram_size: int | None = None,
) -> tuple[
    tuple[int, int, tuple[tuple[int, int], ...], int, int] | None,
    str | None,
]:
    """Decode one descriptor-linked primary x16 NOR probe profile."""
    if probe_address is None:
        return None, None
    flash_end = load_address + flash_size
    mapped_ram_size = ram_image_size if ram_size is None else ram_size
    ram_end = ram_base + mapped_ram_size
    primary_end = min(len(image), image_offset + flash_size)

    def primary_offset(address: int, size: int) -> int | None:
        offset = image_offset + address - load_address
        if (load_address <= address <= flash_end - size
                and image_offset <= offset <= len(image) - size):
            return offset
        return None

    def ram_offset(address: int, size: int) -> int | None:
        relative = address - ram_base
        offset = image_offset + ram_image_offset + relative
        return offset if (0 <= relative <= ram_image_size - size
                          and 0 <= offset <= len(image) - size) else None

    signature_size = len(PRIMARY_FLASH_PROBE_SIGNATURE)
    probe = primary_offset(probe_address, signature_size + 12)
    if probe is None:
        return None, "probe-shape-mismatch"
    candidate = image[probe:probe + signature_size]
    if candidate == PRIMARY_FLASH_PROBE_SIGNATURE:
        signature = PRIMARY_FLASH_PROBE_SIGNATURE
        static_descriptor = False
        external_static_descriptor = False
    elif candidate == PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE:
        signature = PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE
        static_descriptor = True
        external_static_descriptor = False
    elif candidate == PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE:
        signature = PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE
        static_descriptor = True
        external_static_descriptor = True
    else:
        return None, "probe-shape-mismatch"
    if (flash_size <= 0 or mapped_ram_size <= 0
            or image.find(signature, image_offset, primary_end) != probe
            or image.find(signature, probe + 1, primary_end) >= 0
            or any(image.find(other, image_offset, primary_end) >= 0
                   for other in (
                       PRIMARY_FLASH_PROBE_SIGNATURE,
                       PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE,
                       PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE,
                   ) if other != signature)):
        return None, "probe-shape-mismatch"
    descriptor_base, flash_base_global, table_global = struct.unpack_from(
        "<3I", image, probe + len(signature)
    )

    if (flash_base_global & 3 or table_global & 3):
        return None, "probe-global-alignment-mismatch"
    if (not ram_base <= flash_base_global <= ram_end - 4
            or not ram_base <= table_global <= ram_end - 8):
        return None, "probe-global-range-mismatch"
    static_runtime_table = False
    if static_descriptor:
        primary = image[image_offset:primary_end]
        probe_position = probe - image_offset
        if external_static_descriptor:
            wrappers = [
                wrapper for wrapper in find_all(primary, b"\x00\xb5")
                if (thumb_bl_target(primary, wrapper + 2) == probe_position
                    and primary[wrapper + 6:wrapper + 10]
                    == b"\x08\xbc\x18\x47")
            ]
            if wrappers != [probe_position - 0x44]:
                return None, "probe-external-wrapper-mismatch"
            descriptor_address = descriptor_base + 8
            static_offset = primary_offset(descriptor_address, 0x38)
            if static_offset is None:
                return None, "probe-external-descriptor-mismatch"
            usable_words = struct.unpack_from(
                "<I", image, static_offset + 0x10
            )[0]
            entries: list[int] = []
            for sector_count in range(1, 513):
                candidate_entry = descriptor_address - 8 - sector_count * 4
                candidate_offset = primary_offset(candidate_entry, 8)
                if candidate_offset is None:
                    continue
                name_address, count = struct.unpack_from(
                    "<2I", image, candidate_offset
                )
                sectors_offset = candidate_offset + 8
                if (count != sector_count
                        or name_address != descriptor_address + 0x38
                        or sectors_offset + sector_count * 4 > len(image)
                        or sum(struct.unpack_from(
                            f"<{sector_count}I", image, sectors_offset
                        )) != usable_words * 2):
                    continue
                entries.append(candidate_entry)
            if len(entries) != 1:
                return None, "probe-external-descriptor-mismatch"
            entry, terminator, flash_base = entries[0], 0, 0
        else:
            wrapper = probe_position - 0x4C
            if (wrapper < 0
                    or primary[wrapper:wrapper + 2] != b"\x00\xb5"
                    or thumb_bl_target(primary, wrapper + 2) != probe_position
                    or primary[wrapper + 6:wrapper + 10]
                       != b"\x08\xbc\x18\x47"):
                return None, "probe-static-initializer-mismatch"
            callers: list[int] = []
            for caller in find_all(primary, b"\xb0\xb5\x01\x20\xc0\x05"):
                object_global = thumb_literal_value(primary, caller + 8, 7)
                consumer = thumb_bl_target(primary, caller + 22)
                if (caller + 30 <= len(primary)
                        and thumb_literal_value(primary, caller + 6, 4)
                        == flash_base_global
                        and object_global is not None
                        and not (object_global & 3)
                        and ram_base <= object_global <= ram_end - 4
                        and primary[caller + 10:caller + 16]
                        == b"\x00\x25\x20\x60\x3d\x60"
                        and thumb_bl_target(primary, caller + 16) == wrapper
                        and primary[caller + 20:caller + 22] == b"\x38\x60"
                        and consumer is not None
                        and 0 <= consumer < flash_size
                        and primary[caller + 26:caller + 30]
                        == b"\x38\x68\x00\x28"):
                    callers.append(caller)
            if len(callers) != 1:
                return None, "probe-static-initializer-mismatch"
            flash_base = 1 << 23
            copy_links: list[tuple[int, int]] = []
            for match in PRIMARY_STATIC_TABLE_COPY_PATTERN.finditer(primary):
                copy = match.start()
                size_field = thumb_literal_value(primary, copy, 0)
                source_field = thumb_literal_value(primary, copy + 6, 0)
                target_field = thumb_literal_value(primary, copy + 10, 1)
                if (copy & 1 or size_field is None or source_field is None
                        or source_field & 3
                        or target_field != source_field + 4
                        or size_field != source_field + 8):
                    continue
                tuple_offset = primary_offset(source_field, 20)
                if tuple_offset is None:
                    continue
                source, target, size, bss, bss_size = struct.unpack_from(
                    "<5I", image, tuple_offset
                )
                if (source & 3 or target & 3 or size < 8 or size & 3
                        or primary_offset(source, size) is None
                        or not ram_base <= target <= table_global
                        or size > ram_end - target
                        or table_global > target + size - 8
                        or target + size != bss
                        or bss_size <= 0 or bss_size > ram_end - bss):
                    continue
                table_source = source + table_global - target
                table_offset = primary_offset(table_source, 8)
                if table_offset is None:
                    continue
                entry, terminator = struct.unpack_from(
                    "<2I", image, table_offset
                )
                if terminator == 0 and load_address <= entry < flash_end:
                    copy_links.append((copy, entry))
            if len(copy_links) != 1:
                return None, "probe-global-linkage-mismatch"
            _, entry = copy_links[0]
            terminator = 0
    else:
        if ram_image_size > 0:
            base_offset = ram_offset(flash_base_global, 4)
            table_offset = ram_offset(table_global, 8)
            if base_offset is None or table_offset is None:
                return None, "probe-runtime-snapshot-missing"
            flash_base = struct.unpack_from("<I", image, base_offset)[0]
            entry, terminator = struct.unpack_from("<2I", image, table_offset)
        else:
            primary = image[image_offset:primary_end]
            probe_position = probe - image_offset
            wrapper = probe_position - 0x4C
            if (wrapper < 0
                    or primary[wrapper:wrapper + 2] != b"\x00\xb5"
                    or thumb_bl_target(primary, wrapper + 2) != probe_position
                    or primary[wrapper + 6:wrapper + 10]
                       != b"\x08\xbc\x18\x47"):
                return None, "probe-static-initializer-mismatch"
            callers: list[tuple[int, int]] = []
            for caller in find_all(primary, b"\xb0\xb5"):
                if caller + 30 > len(primary):
                    continue
                move, shift = struct.unpack_from("<2H", primary, caller + 2)
                object_global = thumb_literal_value(primary, caller + 8, 7)
                consumer = thumb_bl_target(primary, caller + 22)
                if (move & 0xFF00 != 0x2000
                        or shift & 0xF83F
                        or thumb_literal_value(primary, caller + 6, 4)
                           != flash_base_global
                        or object_global is None or object_global & 3
                        or table_global != object_global + 0x78
                        or not ram_base <= object_global <= ram_end - 4
                        or primary[caller + 10:caller + 16]
                           != b"\x00\x25\x20\x60\x3d\x60"
                        or thumb_bl_target(primary, caller + 16) != wrapper
                        or primary[caller + 20:caller + 22] != b"\x38\x60"
                        or consumer is None or consumer + 20 > len(primary)
                        or primary[caller + 26:caller + 30]
                           != b"\x38\x68\x00\x28"
                        or primary[consumer:consumer + 12]
                           != bytes.fromhex("044800b50068ff3041300069")
                        or thumb_literal_value(primary, consumer, 0)
                           != object_global
                        or thumb_bl_target(primary, consumer + 12) is None
                        or primary[consumer + 16:consumer + 20]
                           != b"\x08\xbc\x18\x47"):
                    continue
                callers.append((caller, (move & 0xFF) << (shift >> 6 & 0x1F)))
            if len(callers) != 1:
                return None, "probe-static-initializer-mismatch"
            _, flash_base = callers[0]
            copy_links: list[int] = []
            for offset in range(0, min(len(primary) - 20, 0x20000) + 1, 4):
                source, target, size, bss, bss_size = struct.unpack_from(
                    "<5I", primary, offset
                )
                source_offset = primary_offset(source, size)
                if (source & 3 or target & 3 or size < 8 or size & 3
                        or source_offset is None
                        or not ram_base <= target <= table_global
                        or size > ram_end - target
                        or table_global > target + size - 8
                        or target + size != bss
                        or bss_size <= 0 or bss_size > ram_end - bss):
                    continue
                table_source = source + table_global - target
                table_offset = primary_offset(table_source, 8)
                if table_offset is None:
                    continue
                candidate_entry, candidate_terminator = struct.unpack_from(
                    "<2I", image, table_offset
                )
                if (candidate_terminator == 0
                        and load_address <= candidate_entry < flash_end):
                    copy_links.append(candidate_entry)
            if len(copy_links) != 1:
                return None, "probe-global-linkage-mismatch"
            entry, terminator = copy_links[0], 0
            static_runtime_table = True
    entry_offset = primary_offset(entry, 8)
    if (terminator != 0 or entry_offset is None
            or not load_address <= entry < flash_end):
        return None, "descriptor-table-mismatch"
    name_address, sector_count = struct.unpack_from(
        "<2I", image, entry_offset
    )
    if not 1 <= sector_count <= 512:
        return None, "geometry-count-mismatch"
    sectors_offset = entry_offset + 8
    descriptor = entry + 8 + sector_count * 4
    descriptor_offset = primary_offset(descriptor, 0x38)
    name_offset = primary_offset(name_address, 4)
    if ((not static_descriptor and descriptor != entry + 0x124)
            or descriptor_base != descriptor - (8 if static_descriptor else 0x24)
            or descriptor_offset is None or name_offset is None
            or name_address != descriptor + 0x38
            or sectors_offset + sector_count * 4 > len(image)):
        return None, "descriptor-shape-mismatch"
    sectors = struct.unpack_from(
        f"<{sector_count}I", image, sectors_offset
    )
    (device_id, reserved, banks, base_words, usable_words,
     *functions) = struct.unpack_from("<14I", image, descriptor_offset)
    manufacturer, device = device_id & 0xFFFF, device_id >> 16
    base_address = flash_base + base_words * 2
    size = usable_words * 2
    name_end = image.find(b"\0", name_offset,
                          min(name_offset + 64, primary_end))
    physical_end = base_address + size
    external_range = (
        load_address == 0
        and base_address < ram_base
        and size <= ram_base - base_address
        and physical_end > base_address
        and not physical_end & (physical_end - 1)
        and (flash_end <= base_address or physical_end == flash_end)
    )
    dumped_end = load_address + primary_end - image_offset
    linked_tail_range = (
        static_runtime_table
        and dumped_end <= base_address < physical_end <= ram_base
        and flash_end < physical_end
    )
    contained_range = (
        load_address <= base_address < flash_end
        and size <= flash_end - base_address
    )
    range_valid = (external_range if external_static_descriptor
                   else contained_range or linked_tail_range)
    if (reserved != 0 or banks != 1 or len(functions) != 9
            or any(not (pointer & 1)
                   or not load_address <= (pointer & ~1) < flash_end
                   for pointer in functions)
            or name_end < name_offset + 4
            or any(not 0x20 <= byte <= 0x7E
                   for byte in image[name_offset:name_end])
            or manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)
            or size <= 0
            or not range_valid
            or sum(sectors) != size):
        return None, "descriptor-content-mismatch"
    regions: list[tuple[int, int]] = []
    offset = 0
    for sector_size in sectors:
        if (sector_size < PAGE or sector_size > 0x100000
                or sector_size & (sector_size - 1)
                or offset % sector_size):
            return None, "geometry-sector-mismatch"
        if regions and regions[-1][1] == sector_size:
            count, _ = regions[-1]
            regions[-1] = count + 1, sector_size
        else:
            regions.append((1, sector_size))
        offset += sector_size
    if not 1 <= len(regions) <= 4:
        return None, "geometry-region-count-mismatch"
    if (base_address - load_address) % regions[0][1]:
        return None, "geometry-base-alignment-mismatch"
    return (
        base_address - load_address, size, tuple(regions),
        manufacturer, device,
    ), None


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


def eeprom_24lcxx_write_at(image: bytes, position: int) -> bool:
    """Match the common ADS 24LCxx writer while ignoring its literal reach."""
    prefix = EEPROM_24LCXX_WRITE_PREFIX
    return (position & 1 == 0
            and 0 <= position <= len(image) - len(prefix)
            and image[position:position + 14] == prefix[:14]
            and image[position + 15:position + len(prefix)] == prefix[15:])


def eeprom_24lc64_class_a_write_at(image: bytes, position: int) -> bool:
    """Match both proven relocation variants of the old 8 KiB writer."""
    return (position & 1 == 0
            and 0 <= position <= len(image) - 48
            and image[position:position + 2] == b"\xf7\xb5"
            and image[position + 4:position + 6] == b"\x8c\xb0"
            and image[position + 10:position + 22]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[10:22]
            and image[position + 23:position + 34]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[23:34]
            and image[position + 35:position + 46]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[35:46]
            and image[position + 47:position + 48]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[47:48])


def find_24lc64_class_a_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the uniquely bound old 8 KiB read/write/max-literal class."""
    if b"nv24lcxx.c\0" not in image.lower():
        return None
    writes = [position for position in find_all(image, b"\xf7\xb5")
              if eeprom_24lc64_class_a_write_at(image, position)]
    reads = find_all(image, EEPROM_24LC64_CLASS_A_READ_PREFIX)
    if len(writes) != 1 or len(reads) != 1:
        return None
    write, read = writes[0], reads[0]
    if read - write not in (0x764, 0x768, 0x784):
        return None

    bindings: list[int] = []
    for delta in (0xAC8, 0xACC):
        geometry = read + delta
        if (geometry < 0x1A or geometry + 4 > len(image)
                or struct.unpack_from("<I", image, geometry)[0] != 0x1FFF
                or image[geometry - 0x1A:geometry - 0xA]
                != EEPROM_24LC64_CLASS_A_SENTINEL):
            continue
        for call in range(geometry - 0x38, geometry - 0x27, 2):
            if (call < 6 or call + 4 > len(image)
                    or image[call - 6:call - 2] != b"\x00\x21\x20\x1c"
                    or thumb_bl_target(image, call) != read):
                continue
            operation = struct.unpack_from("<H", image, call - 2)[0]
            literal = (((call + 2) & ~3) + (operation & 0xFF) * 4)
            if (operation & 0xF800 == 0x4800
                    and operation >> 8 & 7 == 2
                    and literal == geometry):
                bindings.append(geometry)
    return (read, write, bindings[0]) if len(bindings) == 1 else None


def find_24lc64_class_b_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the unique static-capacity 8 KiB transport class."""
    writes = find_all(image, EEPROM_24LC64_CLASS_B_WRITE_PREFIX)
    reads = find_all(image, EEPROM_24LC64_CLASS_B_READ_PREFIX)
    if len(writes) != 1 or len(reads) != 1:
        return None
    if len(find_all(image.lower(), b"nv24lcxx.c\0")) != 1:
        return None
    write, read = writes[0], reads[0]
    if (write & 1 or read & 1
            or image[write + 4:write + 10] != EEPROM_24LC64_CLASS_B_BOUND
            or image[read + 6:read + 12] != EEPROM_24LC64_CLASS_B_BOUND):
        return None
    return read, write, 0x2000


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


def find_24lcxx_f6f7_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the uniquely paired F6-writer/F7-reader compiler class."""
    marker = b"nv24lcxx.c\0"
    if len(find_all(image.lower(), marker)) != 1:
        return None
    writes = find_all(image, EEPROM_24LCXX_F6F7_WRITE_PREFIX)
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
            image, write, 0xE, 0x3E8, geometry
    ) and _eeprom_24lcxx_variant_geometry_at(
            image, read, 0xC, 0x3EC, geometry
    ) and _eeprom_f6f7_gpio_shape(image, write, read)):
        return None
    return read, write, geometry


def _eeprom_f6f7_gpio_shape(image: bytes, write: int, read: int) -> bool:
    """Require the paired byte-level GPIO leaves and their local call shape."""
    start = max(0, write - 0x400)
    end = min(len(image) - 4, read + 0x1000)
    calls: dict[int, int] = {}
    for position in range(start, end, 2):
        target = thumb_bl_target(image, position)
        if target is not None and 0 <= target <= len(image) - 4:
            calls[target] = calls.get(target, 0) + 1

    def literals(target: int) -> set[int]:
        values = set()
        for position in range(target, min(len(image) - 2, target + 0x100), 2):
            word = struct.unpack_from("<H", image, position)[0]
            register = word >> 8 & 7
            value = thumb_literal_value(image, position, register)
            if word & 0xF800 == 0x4800 and value is not None:
                values.add(value)
        return values

    writers = [target for target, count in calls.items()
               if count == 16
               and image[target:target + 4] == b"\xf0\xb5\x07\x1c"
               and {0x03000660, 0x03000668} <= literals(target)]
    readers = [target for target, count in calls.items()
               if count == 2
               and image[target:target + 4] == b"\xf0\xb5\x00\x27"
               and 0x03000668 in literals(target)]
    return len(writers) == len(readers) == 1


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


def find_24lcxx_f7f6_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the cross-linked F7-writer/F6-reader compiler class."""
    marker = b"nv24lcxx.c\0"
    if len(find_all(image.lower(), marker)) != 1:
        return None
    writes = find_all(image, EEPROM_24LCXX_X7700_WRITE_PREFIX)
    reads = find_all(image, EEPROM_24LCXX_X430_READ_PREFIX)
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
    return (find_24lc64_class_a_driver(image)
            or find_24lcxx_x430_driver(image)
            or find_24lcxx_x270_driver(image)
            or find_24lcxx_f6f7_driver(image)
            or find_24lcxx_x7700_driver(image)
            or find_24lcxx_f7f6_driver(image))


def fujitsu_x16_bulk_write_mode_at(
        image: bytes, position: int, secondary_base: int,
) -> str | None:
    for pattern, literal_offset, unlock_offset in FUJITSU_X16_BULK_WRITE_PATTERNS:
        if (pattern.match(image, position) is not None
                and position + literal_offset + 4 <= len(image)
                and struct.unpack_from("<I", image, position + literal_offset)[0]
                == secondary_base + unlock_offset):
            return "unlock-bypass"
    if (0 <= position <= len(image) - 0x94
            and image[position:position + len(
                FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX
            )] == FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX
            and struct.unpack_from("<I", image, position + 0x90)[0]
            == secondary_base + 0xAA0):
        body = bytearray(image[position:position + 0x7E])
        calls: list[int] = []
        for offset in range(0, len(body) - 3, 2):
            if thumb_bl_target(image, position + offset) is None:
                continue
            calls.append(offset)
            body[offset:offset + 4] = b"\0" * 4
        if (tuple(calls) == FUJITSU_X16_BULK_WRITE_LEGACY_CALLS
                and hashlib.sha256(body).hexdigest()
                == FUJITSU_X16_BULK_WRITE_LEGACY_HASH):
            return "unlock-bypass"
    for (prefix, body_size, literal_offset, literal_deltas,
         expected_calls, body_hash) in FUJITSU_X16_BULK_WRITE_HASHED_SHAPES:
        if (position < 0
                or position + max(body_size, literal_offset + 8) > len(image)
                or image[position:position + len(prefix)] != prefix
                or struct.unpack_from("<2I", image, position + literal_offset)
                   != tuple(secondary_base + delta
                            for delta in literal_deltas)):
            continue
        body = bytearray(image[position:position + body_size])
        calls: list[int] = []
        for offset in range(0, len(body) - 3, 2):
            if thumb_bl_target(image, position + offset) is None:
                continue
            calls.append(offset)
            body[offset:offset + 4] = b"\0" * 4
        if (tuple(calls) == expected_calls
                and hashlib.sha256(body).hexdigest() == body_hash):
            return "per-word-unlock"
    return None


def fujitsu_x16_bulk_write_at(image: bytes, position: int,
                              secondary_base: int) -> bool:
    return fujitsu_x16_bulk_write_mode_at(
        image, position, secondary_base
    ) is not None


def find_fujitsu_x16_bulk_write(image: bytes, secondary_base: int) -> int | None:
    if b"fs_fujitsu.c\0" not in image:
        return None
    candidates = {
        match.start()
        for pattern, _literal_offset, _unlock_offset in FUJITSU_X16_BULK_WRITE_PATTERNS
        for match in pattern.finditer(image)
    }
    for prefix, *_rest in FUJITSU_X16_BULK_WRITE_HASHED_SHAPES:
        candidates.update(find_all(image, prefix))
    candidates.update(find_all(image, FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX))
    matches = [position for position in sorted(candidates)
               if fujitsu_x16_bulk_write_at(
                   image, position, secondary_base
               )]
    return matches[0] if len(matches) == 1 else None


def find_adjacent_fujitsu_x16_nor(
        image: bytes, flash_size: int,
) -> tuple[int, int, int, int] | None:
    """Return a uniquely linked adjacent Fujitsu command-bus region."""
    device_id = FUJITSU_MB84VD2219X_IDS[0] | (
        FUJITSU_MB84VD2219X_IDS[1] << 16
    )
    if b"fs_fujitsu.c\0" not in image or flash_size <= 0:
        return None
    complete_primary = flash_size <= len(image)
    profiles: list[tuple[int, int, int, int]] = []
    for descriptor in find_all(image, struct.pack("<I", device_id)):
        if (descriptor & 3
                or descriptor + 0x2C > min(flash_size, len(image))):
            continue
        identity, reserved, banks, usable_base, usable_size = (
            struct.unpack_from("<5I", image, descriptor)
        )
        functions = struct.unpack_from("<6I", image, descriptor + 0x14)

        # Some MB84VD2219X layouts expose only the usable range after one or
        # more 8 KiB boot sectors.  The descriptor, exact writer literals,
        # function table, and remaining-sector geometry jointly own the
        # adjacent physical device; a bare address or truncated dump does not.
        command_base = flash_size
        writer = find_fujitsu_x16_bulk_write(image, command_base)
        reserved_boot = usable_base - command_base
        physical_size = reserved_boot + usable_size
        if (identity == device_id and reserved == 0 and banks == 1
                and writer is not None
                and (functions[1] & ~1) == writer
                and all(pointer & 1 and pointer & ~1 < len(image)
                        for pointer in functions)
                and 0 <= reserved_boot <= 0x10000
                and reserved_boot % 0x2000 == 0
                and physical_size in (0x200000, 0x400000, 0x800000)
                and command_base % physical_size == 0
                and physical_size >= 0x10000
                and (physical_size - 0x10000) % 0x10000 == 0):
            small_sectors = (0x10000 - reserved_boot) // 0x2000
            large_sectors = (physical_size - 0x10000) // 0x10000
            sector_sizes = ((0x2000,) * small_sectors
                            + (0x10000,) * large_sectors)
            geometry = struct.pack(
                f"<{len(sector_sizes) + 1}I",
                len(sector_sizes), *sector_sizes,
            )
            geometry_records = []
            for position in find_all(image, geometry):
                record = position - 4
                if record < 0:
                    continue
                name = struct.unpack_from("<I", image, record)[0]
                end = image.find(b"\0", name, min(len(image), name + 64))
                if (0 <= name < len(image) and end >= name + 4
                        and all(0x20 <= byte <= 0x7E
                                for byte in image[name:end])):
                    geometry_records.append(record)
            if len(geometry_records) == 1:
                partition_end = command_base + physical_size
                for candidate_size in (0x400000, 0x800000):
                    if (candidate_size <= physical_size
                            or command_base % candidate_size):
                        continue
                    boundaries = (
                        list(range(command_base,
                                   command_base + 0x10000, 0x2000))
                        + list(range(command_base + 0x10000,
                                     command_base + candidate_size,
                                     0x10000))
                    )
                    table = struct.pack(
                        f"<{len(boundaries)}I", *boundaries
                    )
                    if len(find_all(image, table)) != 1:
                        continue
                    resource_runs = []
                    for position in find_all(
                            image, struct.pack("<I", partition_end)):
                        if position & 3 or position + 0x40 > len(image):
                            continue
                        values = struct.unpack_from("<16I", image, position)
                        deltas = tuple(
                            right - left
                            for left, right in zip(values, values[1:])
                        )
                        if (all(not value & 0xF
                                and partition_end <= value
                                < command_base + candidate_size
                                for value in values)
                                and all(delta >= 0 for delta in deltas)
                                and any(0 < delta < 0x10000
                                        for delta in deltas)):
                            resource_runs.append(position)
                    if len(resource_runs) == 1:
                        physical_size = candidate_size
                profiles.append((command_base, physical_size,
                                 *FUJITSU_MB84VD2219X_IDS))
                continue

        if not complete_primary:
            continue
        command_base = usable_base - 0x10000
        writer = find_fujitsu_x16_bulk_write(image, command_base)
        if (identity != device_id or reserved != 0 or banks != 1
                or command_base != flash_size
                or usable_base != command_base + 0x10000
                or usable_size <= 0 or usable_size % 0x10000
                or writer is None
                or any(not pointer & 1 or pointer & ~1 >= flash_size
                       for pointer in functions)
                # The established +0x60 class keeps its existing transport
                # fallback and persistent-state extent.  This detector owns
                # only the newly closed adjacent +0x6C class.
                or writer - (functions[3] & ~1) != 0x6C):
            continue

        sectors = usable_size // 0x10000
        usable_geometry = (struct.pack("<I", sectors)
                           + struct.pack(f"<{sectors}I",
                                         *(0x10000,) * sectors))
        geometry_records = []
        for position in find_all(image, usable_geometry):
            record = position - 4
            if record < 0:
                continue
            name = struct.unpack_from("<I", image, record)[0]
            end = image.find(b"\0", name, min(flash_size, name + 64))
            if (0 <= name < flash_size and end >= name + 4
                    and all(0x20 <= byte <= 0x7E
                            for byte in image[name:end])):
                geometry_records.append(record)
        if len(geometry_records) != 1:
            continue

        physical_sizes = []
        for size in (0x200000, 0x400000, 0x800000):
            boundaries = (
                list(range(command_base, command_base + 0x10000, 0x2000))
                + list(range(command_base + 0x10000,
                             command_base + size, 0x10000))
                + [0]
            )
            table = struct.pack(f"<{len(boundaries)}I", *boundaries)
            if len(find_all(image, table)) == 1:
                physical_sizes.append(size)
        if (len(physical_sizes) != 1
                or 0x10000 + usable_size > physical_sizes[0]
                or command_base % physical_sizes[0]):
            continue
        profiles.append((command_base, physical_sizes[0],
                         *FUJITSU_MB84VD2219X_IDS))
    return profiles[0] if len(profiles) == 1 else None


def find_embedded_fujitsu_x16_nor(
        image: bytes, flash_size: int,
) -> tuple[int, int, int, int] | None:
    """Return a uniquely linked Fujitsu command-bus region in the dump."""
    device_size = 0x200000
    device_id = FUJITSU_MB84VD2219X_IDS[0] | (
        FUJITSU_MB84VD2219X_IDS[1] << 16
    )
    if (b"fs_fujitsu.c\0" not in image or flash_size <= 0
            or flash_size > len(image)):
        return None
    profiles: list[tuple[int, int, int, int]] = []
    for descriptor in find_all(image, struct.pack("<I", device_id)):
        if descriptor & 3 or descriptor + 0x2C > flash_size:
            continue
        identity, reserved, banks, usable_base, usable_size = (
            struct.unpack_from("<5I", image, descriptor)
        )
        command_base = usable_base - 0x10000
        if (identity != device_id or reserved != 0 or banks != 1
                or command_base <= 0 or command_base % device_size
                or command_base + device_size > flash_size
                or usable_base != command_base + 0x10000
                or usable_size <= 0 or usable_size % 0x10000
                or usable_base + usable_size > command_base + device_size):
            continue
        functions = struct.unpack_from("<6I", image, descriptor + 0x14)
        writer = find_fujitsu_x16_bulk_write(image, command_base)
        if (writer is None
                or any(not pointer & 1 or pointer & ~1 >= flash_size
                       for pointer in functions)
                or (functions[3] & ~1) + 0x60 != writer):
            continue
        sectors = usable_size // 0x10000
        geometry = (struct.pack("<I", sectors)
                    + struct.pack(f"<{sectors}I", *(0x10000,) * sectors))
        geometry_records: list[int] = []
        for position in find_all(image, geometry):
            record = position - 4
            if record < 0:
                continue
            name = struct.unpack_from("<I", image, record)[0]
            end = image.find(b"\0", name, min(flash_size, name + 64))
            if (0 <= name < flash_size and end >= name + 4
                    and all(0x20 <= byte <= 0x7E
                            for byte in image[name:end])):
                geometry_records.append(record)
        if len(geometry_records) != 1:
            continue
        profiles.append((command_base, device_size,
                         *FUJITSU_MB84VD2219X_IDS))
    return profiles[0] if len(profiles) == 1 else None


def find_compound_fujitsu_layout(
        image: bytes, load_address: int = 0) -> tuple[int, int] | None:
    """Return primary/secondary sizes for a complete Fujitsu 4+2 MiB dump."""
    secondary_size = 0x200000
    found: list[tuple[int, int]] = []
    for primary_size in (0x200000, 0x400000, 0x800000):
        if len(image) != primary_size + secondary_size:
            continue
        primary = image[:primary_size]
        secondary = image[primary_size:]
        marker = secondary.find(b"\x0b$USER_DIRS\0")
        storage = (not secondary.strip(b"\xff")
                   or (marker >= 0 and marker & 0xFF == 0x1C
                       and b"nvm/" in secondary))
        if (arm_vector_score(primary) >= 2
                and b"fs_fujitsu.c\0" in primary
                and find_fujitsu_x16_bulk_write(
                    primary, load_address + primary_size) is not None
                and arm_vector_score(secondary) < 2
                and storage):
            found.append((primary_size, secondary_size))
    return found[0] if len(found) == 1 else None


def fujitsu_x16_flash_ids(image: bytes, writer_address: int | None,
                          load_address: int,
                          secondary_base: int) -> tuple[int, int] | None:
    position = -1 if writer_address is None else writer_address - load_address
    if (position >= 0
            and fujitsu_x16_bulk_write_at(image, position, secondary_base)):
        return FUJITSU_MB84VD2219X_IDS
    return None
