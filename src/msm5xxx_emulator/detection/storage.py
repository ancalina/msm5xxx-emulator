"""Firmware storage-driver detection."""
from __future__ import annotations

import hashlib
import re
import struct

from .arm import arm_vector_score, thumb_bl_target, thumb_literal_value
from .boot import FLASH_ID_SIGNATURE
from .signatures import find_all


FUJITSU_MB84VD2219X_IDS = (0x0004, 0x005F)
FUJITSU_X16_BULK_WRITE_MAX_SIZE = 0x118
FUJITSU_X16_BULK_WRITE_F8_PREFIX = bytes.fromhex(
    "f8b5041c8818171c3c4a1268ff32c132936b5b00984205d8"
)
FUJITSU_X16_BULK_WRITE_F8_BODY_HASH = (
    "0d6ec61f9c5574193e392fa98e95219cd1b7897993fb9a96f9f8488cf49bc62f"
)
FUJITSU_X16_BULK_WRITE_F8_CALLS = (
    0x4A, 0x64, 0x6C, 0xA2, 0xBE, 0xC6, 0xD4, 0xE8, 0xF2,
)


PAGE = 0x1000

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
            or find_24lcxx_x7700_driver(image))


def fujitsu_x16_bulk_write_mode_at(
        image: bytes, position: int, secondary_base: int,
) -> str | None:
    for pattern, literal_offset, unlock_offset in FUJITSU_X16_BULK_WRITE_PATTERNS:
        if (pattern.match(image, position) is not None
                and position + literal_offset + 4 <= len(image)
                and struct.unpack_from("<I", image, position + literal_offset)[0]
                == secondary_base + unlock_offset):
            return "unlock-bypass"
    if (position < 0
            or position + FUJITSU_X16_BULK_WRITE_MAX_SIZE > len(image)
            or image[position:position + len(FUJITSU_X16_BULK_WRITE_F8_PREFIX)]
               != FUJITSU_X16_BULK_WRITE_F8_PREFIX
            or struct.unpack_from("<2I", image, position + 0x104)
               != (secondary_base + 0xAAA0, secondary_base + 0x5540)):
        return None
    body = bytearray(image[position:position + 0xFC])
    calls: list[int] = []
    for offset in range(0, len(body) - 3, 2):
        if thumb_bl_target(image, position + offset) is None:
            continue
        calls.append(offset)
        body[offset:offset + 4] = b"\0" * 4
    return ("per-word-unlock" if (
        tuple(calls) == FUJITSU_X16_BULK_WRITE_F8_CALLS
        and hashlib.sha256(body).hexdigest()
        == FUJITSU_X16_BULK_WRITE_F8_BODY_HASH
    ) else None)


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
    candidates.update(find_all(image, FUJITSU_X16_BULK_WRITE_F8_PREFIX))
    matches = [position for position in sorted(candidates)
               if fujitsu_x16_bulk_write_at(
                   image, position, secondary_base
               )]
    return matches[0] if len(matches) == 1 else None


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
