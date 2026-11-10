from __future__ import annotations
from msm5xxx_emulator.detection.contracts import _normalized_thumb_sha256
import re

FUJITSU_MB84VD2219X_IDS = (0x0004, 0x005F)
FUJITSU_X16_BULK_WRITE_MAX_SIZE = 0x118
PRIMARY_FSD_AMD_X16_WRITER_PREFIX = bytes.fromhex("f0b5544b8f181b68ff3381339c696400a74200d962e0504f")
PRIMARY_FSD_AMD_X16_WRITER_SIZE = 0x152
PRIMARY_FSD_AMD_X16_WRITER_CALLS = (0x4A,)
PRIMARY_FSD_AMD_X16_WRITER_HASH = ("4e6e8bf7a24612fe68352426367bc562796e239f8e9148153aed31c7eb7e7769")
ADJACENT_AMD_X16_WRITER_PREFIX = bytes.fromhex("f7b5041c161c86b07df08cf88a4f0125b989ad032943b981b9893a681180")
ADJACENT_AMD_X16_WRITER_SIZE = 0x23C
ADJACENT_AMD_X16_WRITER_CALLS = (0x08, 0x22, 0x28, 0xC8, 0xF0, 0x10A, 0x144, 0x168, 0x182, 0x1BA, 0x1DE, 0x1F8, 0x210, 0x22A,)
ADJACENT_AMD_X16_WRITER_HASH = ("fdf4394e4809829af42a7cc4ff86017a71fd719fe807904db2bd52c85a4f050d")
ADJACENT_AMD_X16_RECORD_PREFIX = bytes.fromhex("b8b50420")
ADJACENT_AMD_X16_RECORD_MARKER = bytes.fromhex("5555")
ADJACENT_AMD_X16_RECORD_LOG = b"Record_Init() - "
RECORD_AMD_X16_WRITER_PREFIX = bytes.fromhex("feb5071c0c1c151c")
RECORD_AMD_X16_WRITER_SIZE = 0x1C0
RECORD_AMD_X16_WRITER_CALLS = (0x08, 0x2A, 0x106, 0x13C, 0x15E, 0x192, 0x1B4)
RECORD_AMD_X16_WRITER_HASH = ("179547732b28103d941c2a0ca6117aa0190f7905050162fe6e6746175e990783")
RECORD_AMD_X16_ERASER_PREFIX = bytes.fromhex("f3b582b0051c2f1c")
RECORD_AMD_X16_ERASER_SIZE = 0x106
RECORD_AMD_X16_ERASER_CALLS = (0x10, 0x32, 0x36, 0x56, 0xA6, 0xD8, 0xF8)
RECORD_AMD_X16_ERASER_HASH = ("4bc322f2695f824d36548a8567b75a991eca6c00810c5d2415145f8d884265fe")
RECORD_AMD_X16_MAPPER_PREFIX = bytes.fromhex("90b592b0")
RECORD_AMD_X16_MAPPER_SIZE = 0x98
RECORD_AMD_X16_MAPPER_CALLS = (0x04, 0x0C, 0x18, 0x24, 0x30, 0x34, 0x3C, 0x52, 0x8A)
RECORD_AMD_X16_MAPPER_HASH = ("0b00ab9c38059abc1e721e98192bc820f945b25fddaa3392050061dedc48b3ea")
RECORD_AMD_X16_ERASE_WRAPPER_PREFIX = bytes.fromhex("fcb5071c0d1c002f03d10020fcbc08bc1847")
RECORD_AMD_X16_ERASE_WRAPPER_SIZE = 0x44
RECORD_AMD_X16_ERASE_WRAPPER_CALLS = (0x3C,)
RECORD_AMD_X16_ERASE_WRAPPER_HASH = ("4295cb416ea17b8330c5ca8de211d835dce95eecb1a2c515b55d51c1b1738715")
RECORD_AMD_X16_COPY_WRAPPER_PREFIX = bytes.fromhex("f7b5ffb0ffb086b0041c002c06d100207fb07fb009b0f0bc")
RECORD_AMD_X16_COPY_WRAPPER_SIZE = 0xC4
RECORD_AMD_X16_COPY_WRAPPER_CALLS = (0x68, 0x84, 0x92, 0x9A, 0xA2)
RECORD_AMD_X16_COPY_WRAPPER_HASH = ("b6483682852e22edfe219788780247fb4d0487fd563aa945c52127697393ff01")
RECORD_AMD_X16_INIT_PREFIX = bytes.fromhex("b8b50320")
RECORD_AMD_X16_INIT_SIZE = 0x130
RECORD_AMD_X16_INIT_CALLS = (0x04, 0x4E, 0x5E, 0x7A, 0x96, 0xA2, 0xAA, 0xB6, 0xCC, 0xD4, 0xDC, 0xE4, 0xE8, 0xF8,)
RECORD_AMD_X16_INIT_HASH = ("76ea7e08a5b33ab74faa8195f8df3daaa68a8603b09599de881dcc5f5a668677")
RECORD_AMD_X16_ENUMERATOR_PREFIX = bytes.fromhex("b0b4532401256d05ef0a6a09052800d363e0")
RECORD_AMD_X16_ENUMERATOR_SIZE = 0xDA
RECORD_AMD_X16_ENUMERATOR_HASH = ("36aef1142efc77fcc9cce15a0cf35aa3d2504c57a4bbaa50c7f466ad319bd756")
RECORD_AMD_X16_PROFILE = (0xA80000, 0x380000, 0x10000)
CATALOG_AMD_X16_PROFILE = (0x1200000, 0x600000, 0x10000)
PRIMARY_FSD_AMD_X16_ID_ROUTINE = bytes.fromhex("30b50e4b011ccc18084d094b258023800b4bca18074b1380074b238008884b88"
    "00041b04000c184325800be0f0000000aa0000005500000090000000aa0a0000" "5405000030bd")
FUJITSU_X16_BULK_WRITE_HASHED_SHAPES = ((bytes.fromhex("f8b5041c8818171c3c4a1268ff32c132936b5b00984205d8"), 0xFC, 0x104, (0xAAA0, 0x5540), (0x4A, 0x64, 0x6C,
    0xA2, 0xBE, 0xC6, 0xD4, 0xE8, 0xF2), "0d6ec61f9c5574193e392fa98e95219cd1b7897993fb9a96f9f8488cf49bc62f",), (bytes.fromhex("f8b5041c3c488b18171c42688032556b6d00ab4201d90120"),
    0xF8, 0xFC, (0x5540, 0xAAA0), (0x46, 0x60, 0x68, 0xA4, 0xC0, 0xC8, 0xD4, 0xE8, 0xF0), "975c74b1238c4877172250f17d79d064290c18b6aa3b677b9b1d9241ec29bd9b",),
    (bytes.fromhex("f8b5041c8818171c3b4a12688032536b5b00984205d8394b"), 0xF8, 0x100, (0xAAA0, 0x5540), (0x48, 0x62, 0x6A, 0xA0, 0xBC, 0xC4, 0xD2, 0xE6, 0xF0),
    "d8eaaac4d169ad91c278fcbfadee8ffa6bc6ade2dfe3dbea8909a611bb9b429c",), (bytes.fromhex("f8b5041c8818171c3b4a12688032536b5b00984205d8394b"), 0xF8, 0x100, (0xAAA0,
    0x5540), (0x48, 0x62, 0x6A, 0xA0, 0xBC, 0xC4, 0xD2, 0xE6, 0xF0), "6074b6f9c6cf75cbc978cca8a482709c82482234a73b0a70bcb28da747926579",), (bytes.fromhex("f8b5041c8818171c3b4a1268ff32c13293695b00984205d8"),
    0xF8, 0x100, (0xAAA0, 0x5540), (0x4A, 0x64, 0x6C, 0xA2, 0xBE, 0xC6, 0xD4, 0xE8, 0xF0), "365e0cc0de8399c3ce08d94ebecb1ebf3dfc45c98a9ca13951c801af15917f7c",),)
FUJITSU_X16_BULK_WRITE_LEGACY_PREFIX = bytes.fromhex("f0b50f1c041c151c400803d2780801d2680802d3")
FUJITSU_X16_BULK_WRITE_LEGACY_CALLS = (0x1E, 0x2C, 0x3C, 0x46, 0x54, 0x6A, 0x72,)
FUJITSU_X16_BULK_WRITE_LEGACY_HASH = ("16e6f343004a5392fc97d35ef170209ff59e462aad0bb209d7c25d1793f5ec13")
PAGE = 0x1000
DIRECT_INTEL_X16_CALLER_PREFIX = bytes.fromhex("b0b50e4d00240e4f2c6000203860")
DIRECT_AMD_X16_PROBE_SIGNATURE = bytes.fromhex("164817494069096840004018aa221101411881b04a81552215239b01c3189a82"
    "90224a81018800ab198041885980f02101800c480ce000abff3101311a880b89" "9a4204d100ab5a8849898a4203d0043001680029efd1006801b07047")
DIRECT_AMD_X16_CALLER_PREFIX = bytes.fromhex("f0b500240f4e271c0f4d002034602860")
MAPPED_PRIMARY_INTEL_X16_SIGNATURES = ((0, bytes.fromhex("b0b401246405e70a62090925ed04072800d382e0")), (0x60, bytes.fromhex("33a048600120000788600d20c004c8600320c00408612b484a610338c8610022"
    "8a61022008844a8433e0")), (0x164, bytes.fromhex("80b50b4f0220396824f1aefe0121090648087a6824f182fe0121890509208005" "7a6824f17bfe80bc08bc01201847")), (-0x25AB4,
    bytes.fromhex("f8b5051c0e1c141c1848c06840190090281916494968884203d90020f8bc08bc" "18470027a74210d202e0781c071cf9e7f05d0099c95d8843f7d0231c321c291c"
    "0b48bff758f90020e8e7221c311c0098c4f72cfc002806d14af13cfc05493f20" "400151f76ff90120d8e7")), (0x12252, bytes.fromhex("00b500f002f808bc1847fcb5071c0d1c141c12f1bcfd6f4a012391899b031943"
    "9181918912681180002800d0afe012f1b6fdace0")), (0x12286, bytes.fromhex("780825d37f087f00388800ab60211880287801355022ff2658704020388000ab"
    "188838803888000afcd33888800806d33a803980d02038803888000afcd33e80" "388800ab")), (0x12434, bytes.fromhex("f0b5071c12f1d2fc244a012391899b0319439181918912681180002801d112f1"
    "cdfc602150222025ff243a803980d02038803e88330afcd33c803d80388038880" "00afcd338888008efd2388802231840134d06d012f1cafc291c1d20400119f7fd"
    "f93888000905d312f1c0fc291c0d4819f7f4f93c80")),)
PRIMARY_STATIC_TABLE_COPY_PATTERN = re.compile(rb".\x48\x02\x68\x00\x92.\x48\x00\x68.\x49\x09\x68" rb"\x00\x9a\x8a\x18\xf8\xc8\xf8\xc1\x91\x42\xfb\xdb", re.S,)
FUJITSU_X16_BULK_WRITE_PATTERNS = ((re.compile(rb"\xf0\xb5\x14\x1c\x05\x1c\x0f\x1c\x40\x08\x03\xd2" rb"\x78\x08\x01\xd2\x60\x08\x02\xd3.{20}\x2e\x88.{4}"
    rb"\x15\x4a\xa0\x21\x51\x81\x3e\x80\x00\x28\x01\xd1.{4}" rb"\x01\x22\x38\x1c\x31\x1c.{4}\x00\x28.{10}\x01\x20"
    rb"\xf0\xbd\x01\x20\xc0\x05\x02\x3c\x02\x35\x02\x37.{12}" rb"\x00\x2c\xda\xd1\x00\x20\xf0\xbd", re.S,), 0x84, 0xAA0), (re.compile(rb"\xf0\xb5\x0f\x1c\x04\x1c\x15\x1c\x40\x08\x03\xd2"
    rb"\x78\x08\x01\xd2\x68\x08\x03\xd3.{24}\x26\x88.{4}" rb"\x16\x4a\xa0\x21\x51\x81\x3e\x80\x00\x28\x01\xd1.{4}"
    rb"\x01\x22\x31\x1c\x38\x1c.{4}\x00\x28.{10}\x01\x20" rb"\xf0\xbc\x08\xbc\x18\x47\x02\x34\x02\x37\x02\x3d.{16}" rb"\x00\x2d\xd8\xd1\x00\x20\xed\xe7", re.S,),
    0x8C, 0xAAA0),)
FLASH_IDS_BY_SIZE = {
    0x200000: 0x222D0001,  # AMD AM29DL162BT
    0x400000: 0x22500001,  # AMD AM29DL323DT
    0x800000: 0x227E0001,  # AMD AM29DL640G
}
FS_DEVICE_LOOKUP_TAIL = bytes.fromhex("07e080310a89498909041143b94203d0043001680029f4d1006890bd")
FS_DEVICE_OUTER_RESET = bytes.fromhex("002727606760")
FS_DEVICE_LOOKUP_PREFIX = bytes.fromhex("90b5104810494069096840004718")

def find_fs_device_flash_id(image: bytes, flash_id_address: int | None) -> int | None:
    """Return the uniquely linked fs_dev NOR descriptor ID."""
    from . import FLASH_ID_SIGNATURE, FS_DEVICE_LOOKUP_PREFIX, FS_DEVICE_LOOKUP_TAIL, FS_DEVICE_OUTER_RESET, PAGE, facts_for, find_all, parse_sector_table, struct
    signature_sites = find_all(image, FLASH_ID_SIGNATURE)
    if flash_id_address is None or len(signature_sites) != 1:
        return None
    signature_site = signature_sites[0]
    tails = find_all(image, FS_DEVICE_LOOKUP_TAIL)
    if len(tails) != 1:
        return None
    lookup = tails[0] - 0x28
    if (lookup < 0 or lookup & 1 or lookup + 0x54 > len(image) or image[lookup:lookup + 0xE] != FS_DEVICE_LOOKUP_PREFIX or image[lookup + 0x12:lookup + 0x18] !=
        bytes.fromhex("041c381c0d49") or image[lookup + 0x1C:lookup + 0x22] != bytes.fromhex("071c002c01d1")):
        return None
    descriptor = facts_for(image).thumb_literal_value(lookup + 2, 0)
    module_base = facts_for(image).thumb_literal_value(lookup + 4, 1)
    trampoline = facts_for(image).thumb_literal_value(lookup + 0x16, 1)
    table = facts_for(image).thumb_literal_value(lookup + 0x26, 0)
    if any(value is None for value in (descriptor, module_base, trampoline, table)):
        return None
    assert descriptor is not None and module_base is not None
    assert trampoline is not None and table is not None
    veneer = facts_for(image).thumb_call_target(lookup + 0x18)
    if (facts_for(image).thumb_call_target(lookup + 0x0E) is None or veneer is None or not 0 <= veneer <= len(image) - 2 or image[veneer:veneer + 2] !=
        b"\x08\x47" or facts_for(image).thumb_call_target(lookup + 0x22) is None or not 0x01000000 <= module_base < 0x02000000 or not 0x01000000 <= table <
        0x02000000 or trampoline != table + 9 or trampoline & ~1 != flash_id_address or len(find_all(image, struct.pack("<I", table))) != 1 or len(find_all(image,
        struct.pack("<I", trampoline))) != 1):
        return None
    entry = descriptor - 0x80
    if (entry < 0 or descriptor + 0x1C > len(image) or signature_site < 8 or struct.unpack_from("<2I", image, signature_site - 8) != (entry, 0)):
        return None
    table = parse_sector_table(lambda address, size: (image[address:address + size] if 0 <= address <= len(image) - size else None), entry, max_count=(0x80 - 8)
        // 4,)
    if table is None:
        return None
    sector_end = entry + 8 + table.count * 4
    if sector_end > descriptor:
        return None
    sectors = table.sectors
    device_id = struct.unpack_from("<I", image, descriptor + 8)[0]
    banks = struct.unpack_from("<I", image, descriptor + 0x10)[0]
    base_words = struct.unpack_from("<I", image, descriptor + 0x14)[0]
    usable_words = struct.unpack_from("<I", image, descriptor + 0x18)[0]
    manufacturer, device = device_id & 0xFFFF, device_id >> 16
    if (manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF) or banks != 1 or base_words == 0 or usable_words == 0 or (base_words * 2) & (PAGE - 1) or any(size
        < PAGE or size > 0x100000 or size & (PAGE - 1) for size in sectors) or sum(sectors) != usable_words * 2):
        return None
    outers = []
    for reset in find_all(image, FS_DEVICE_OUTER_RESET):
        outer = reset - 4
        if (outer >= 0 and image[outer:outer + 4] == b"\x90\xb5\x08\x4c" and facts_for(image).thumb_literal_value(outer + 2, 4) == module_base and facts_for(image).thumb_call_target(outer
            + 10) == lookup and image[outer + 0xE:outer + 0x12] == b"\x60\x60\x00\x28" and struct.unpack_from("<H", image, outer + 0x12)[0] & 0xFF00 == 0xD100):
            outers.append(outer)
    return device_id if len(outers) == 1 else None

def flash_id_for_size(size: int) -> int | None:
    """Return a firmware-supported AMD NOR ID for a complete dump."""
    from . import FLASH_IDS_BY_SIZE, PAGE
    for capacity, device_id in FLASH_IDS_BY_SIZE.items():
        if capacity - PAGE <= size <= capacity:
            return device_id
    return None

def _primary_fsd_amd_x16_writer_at(image: bytes, position: int) -> bool:
    from . import PRIMARY_FSD_AMD_X16_WRITER_CALLS, PRIMARY_FSD_AMD_X16_WRITER_HASH, PRIMARY_FSD_AMD_X16_WRITER_PREFIX, PRIMARY_FSD_AMD_X16_WRITER_SIZE, facts_for, hashlib
    if (position < 0 or position + PRIMARY_FSD_AMD_X16_WRITER_SIZE > len(image) or image[position:position + len (PRIMARY_FSD_AMD_X16_WRITER_PREFIX)] !=
        PRIMARY_FSD_AMD_X16_WRITER_PREFIX):
        return False
    return _normalized_thumb_sha256(image, position, PRIMARY_FSD_AMD_X16_WRITER_SIZE) == (PRIMARY_FSD_AMD_X16_WRITER_HASH, PRIMARY_FSD_AMD_X16_WRITER_CALLS)

def find_primary_fsd_amd_x16_nor(image: bytes, flash_id_address: int | None, flash_size: int,) -> tuple[int, int, int, int, int] | None:
    """Return a uniquely linked writable primary x16 NOR tail profile."""
    from . import PAGE, PRIMARY_FSD_AMD_X16_ID_ROUTINE, PRIMARY_FSD_AMD_X16_WRITER_PREFIX, _primary_fsd_amd_x16_writer_at, find_all, struct
    if (b"fsd_amd.c\0" not in image or flash_id_address is None or flash_size <= 0 or flash_size > len(image)):
        return None
    writers = [position for position in find_all(image, PRIMARY_FSD_AMD_X16_WRITER_PREFIX) if _primary_fsd_amd_x16_writer_at(image, position)]
    if len(writers) != 1:
        return None
    writer = writers[0]
    profiles: list[tuple[int, int, int, int, int]] = []
    for reference in find_all(image, struct.pack("<I", writer | 1)):
        descriptor = reference - 0x1C
        if descriptor < 0 or descriptor + 0x34 > flash_size:
            continue
        device_id, reserved, device_control_options, base_words, usable_words = (struct.unpack_from("<5I", image, descriptor))
        functions = struct.unpack_from("<7I", image, descriptor + 0x14)
        name_address = descriptor + 0x30
        name_end = image.find(b"\0", name_address, name_address + 32)
        manufacturer, device = device_id & 0xFFFF, device_id >> 16
        base, size = base_words * 2, usable_words * 2
        if (reserved != 0 or device_control_options != 1 or functions[2] != writer | 1 or any(not pointer & 1 or pointer & ~1 >= flash_size for pointer in
            functions) or name_end < name_address + 4 or any(not 0x21 <= byte <= 0x7E for byte in image[name_address:name_end]) or manufacturer in (0, 0xFFFF)
            or device in (0, 0xFFFF) or base <= 0 or size <= 0 or base + size != flash_size):
            continue
        geometries: list[tuple[int, int]] = []
        for sector_count in range(1, min(512, (descriptor - 8) // 4) + 1):
            entry = descriptor - 8 - sector_count * 4
            if (struct.unpack_from("<2I", image, entry) != (name_address, sector_count)):
                continue
            sectors = struct.unpack_from(
                f"<{sector_count}I", image, entry + 8
            )
            sector_size = sectors[0]
            if (all(value == sector_size for value in sectors) and PAGE <= sector_size <= 0x100000 and not sector_size & (PAGE - 1) and sum(sectors) == size and
                not base % sector_size):
                geometries.append((entry, sector_size))
        if len(geometries) != 1:
            continue
        entry, sector_size = geometries[0]
        if (flash_id_address < 12 or struct.unpack_from("<3I", image, flash_id_address - 12) != (0, entry, 0) or image[flash_id_address: flash_id_address + len(PRIMARY_FSD_AMD_X16_ID_ROUTINE)]
            != PRIMARY_FSD_AMD_X16_ID_ROUTINE):
            continue
        profiles.append((base, size, sector_size, manufacturer, device))
    return profiles[0] if len(profiles) == 1 else None

def _adjacent_amd_x16_writer_at(image: bytes, position: int) -> bool:
    from . import ADJACENT_AMD_X16_WRITER_CALLS, ADJACENT_AMD_X16_WRITER_HASH, ADJACENT_AMD_X16_WRITER_PREFIX, ADJACENT_AMD_X16_WRITER_SIZE, facts_for, hashlib
    if (position < 0 or position + ADJACENT_AMD_X16_WRITER_SIZE > len(image) or image[position:position + len(ADJACENT_AMD_X16_WRITER_PREFIX)] !=
        ADJACENT_AMD_X16_WRITER_PREFIX):
        return False
    return _normalized_thumb_sha256(image, position, ADJACENT_AMD_X16_WRITER_SIZE) == (ADJACENT_AMD_X16_WRITER_HASH, ADJACENT_AMD_X16_WRITER_CALLS)

def find_adjacent_amd_x16_nor(image: bytes, flash_size: int,) -> tuple[int, int, int, int] | None:
    """Return one temporary exact adjacent AMD x16 NOR profile."""
    from . import ADJACENT_AMD_X16_RECORD_LOG, ADJACENT_AMD_X16_RECORD_MARKER, ADJACENT_AMD_X16_RECORD_PREFIX, ADJACENT_AMD_X16_WRITER_PREFIX, _adjacent_amd_x16_writer_at, find_all, flash_id_for_size
    marker = b"fsd_toshiba.c\0"
    if (flash_size != 0x800000 or len(image) < flash_size or image[:flash_size].count(marker) != 1):
        return None
    primary = image[:flash_size]
    writers = [position for position in find_all(primary, ADJACENT_AMD_X16_WRITER_PREFIX) if _adjacent_amd_x16_writer_at(primary, position)]
    records = [position for position in find_all(primary, ADJACENT_AMD_X16_RECORD_PREFIX) if (position + 0x120 <= len(primary) and primary[position + 0x10C:position
        + 0x10E] == ADJACENT_AMD_X16_RECORD_MARKER and primary[position + 0x110:position + 0x120] == ADJACENT_AMD_X16_RECORD_LOG)]
    identity = flash_id_for_size(flash_size)
    if len(writers) != 1 or len(records) != 1 or identity is None:
        return None
    return flash_size, flash_size, identity & 0xFFFF, identity >> 16

def _record_amd_x16_shape_at(image: bytes, position: int, prefix: bytes, size: int, expected_calls: tuple[int, ...], expected_hash: str,) -> bool:
    from . import facts_for, hashlib
    if (position < 0 or position + size > len(image) or image[position:position + len(prefix)] != prefix):
        return False
    return _normalized_thumb_sha256(image, position, size) == (expected_hash, expected_calls)
