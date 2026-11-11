"""Source-linked AMD bank enclosing a bounded filesystem partition."""
from __future__ import annotations

import struct

from ...facts import facts_for
from .rules import PRIMARY_FSD_AMD_X16_ID_ROUTINE


def _word(image: bytes, address: int) -> int | None:
    if address < 0 or address + 2 > len(image):
        return None
    return struct.unpack_from('<H', image, address)[0]


def _mov_shift(image: bytes, mov: int, shift: int, register: int) -> int | None:
    m, s = _word(image, mov), _word(image, shift)
    if (m is None or s is None or m & 0xff00 != 0x2000 | register << 8
            or s & 0xf83f != register | register << 3):
        return None
    return (m & 255) << ((s >> 6) & 31)


def _bounded_writer(image: bytes, writer: int, start: int, end: int) -> bool:
    if writer < 0 or writer + 0x46 > len(image):
        return False
    # The writer computes start, end, and maximum length before its stores.
    fixed = {0: 0xb5f0, 0x20: 0x1901, 0x2a: 0x4291, 0x32: 0xd308,
             0x38: 0x194a, 0x3a: 0x429a, 0x3c: 0xd803,
             0x42: 0x4295, 0x44: 0xd92a}
    return (all(_word(image, writer + off) == word for off, word in fixed.items())
            and _mov_shift(image, writer + 0x24, writer + 0x28, 2) == start
            and _mov_shift(image, writer + 0x34, writer + 0x36, 3) == end
            and _mov_shift(image, writer + 0x3e, writer + 0x40, 2) == end - start)


def _enumerator(image: bytes, descriptor: int, ram_base: int, ram_size: int) -> bool:
    reference = struct.pack('<I', descriptor - 4)
    at = image.find(reference)
    matches = 0
    while at >= 0:
        for entry in range(max(0, at - 0x400) & ~1, at, 2):
            if (facts_for(image).thumb_literal_value( entry, 0) != descriptor - 4
                    or _word(image, entry + 2) != 0xb5b0
                    or _word(image, entry + 6) != 0x6980
                    or _word(image, entry + 8) != 0x6809
                    or _word(image, entry + 0xa) != 0x0040
                    or _word(image, entry + 0xc) != 0x1844):
                continue
            query = facts_for(image).thumb_literal_value( entry + 0x18, 1)
            table = facts_for(image).thumb_literal_value( entry + 0x28, 0)
            if (query is not None and table is not None and query == table + 17
                    and ram_base <= table and table + 16 + len(PRIMARY_FSD_AMD_X16_ID_ROUTINE)
                    <= ram_base + ram_size):
                matches += 1
        at = image.find(reference, at + 1)
    return matches == 1


def find_descriptor_bank(image: bytes, flash_id_address: int | None,
                         flash_size: int, ram_base: int, ram_size: int):
    """Return the smallest aligned NOR bank enclosing one linked partition."""
    if (not isinstance(image, bytes) or type(flash_id_address) is not int
            or not 0 < flash_size <= len(image) or flash_size & (flash_size - 1)
            or flash_id_address < 16 or flash_id_address + len(PRIMARY_FSD_AMD_X16_ID_ROUTINE) > flash_size
            or image[flash_id_address:flash_id_address + len(PRIMARY_FSD_AMD_X16_ID_ROUTINE)]
            != PRIMARY_FSD_AMD_X16_ID_ROUTINE):
        return None
    pointers = struct.unpack_from('<4I', image, flash_id_address - 16)
    if pointers[-1] != 0 or any(p & 3 or p >= flash_size for p in pointers[:-1]):
        return None
    table = pointers[0]
    if table + 8 > flash_size:
        return None
    name, count = struct.unpack_from('<2I', image, table)
    if not 1 <= count <= 512 or table + 8 + 4 * count + 0x40 > flash_size:
        return None
    sectors = struct.unpack_from(f'<{count}I', image, table + 8)
    sector = sectors[0]
    if (sector < 0x1000 or sector & (sector - 1)
            or any(value != sector for value in sectors)):
        return None
    descriptor = table + 8 + 4 * count
    ident, reserved, flags, _, _, start_words, length_words = struct.unpack_from(
        '<7I', image, descriptor)
    start, length = 2 * start_words, 2 * length_words
    end = start + length
    writer = struct.unpack_from('<I', image, descriptor + 0x24)[0]
    if (not ident & 0xffff or ident & 0xffff == 0xffff
            or not ident >> 16 or ident >> 16 == 0xffff or reserved
            or flags != (count << 16) | 1 or length != count * sector
            or start % sector or end + sector != flash_size
            or name < 0 or name >= flash_size or not writer & 1
            or not _bounded_writer(image, writer - 1, start, end)
            or not _enumerator(image, descriptor, ram_base, ram_size)):
        return None
    size = 1 << (length - 1).bit_length()
    while (start & ~(size - 1)) + size < end:
        size <<= 1
    bank = start & ~(size - 1)
    if not bank or bank + size != flash_size or bank % sector:
        return None
    return bank, size, sector, ident & 0xffff, ident >> 16


def find_truncated_descriptor_bank(image: bytes, flash_id_address: int | None,
                                   configured_size: int, ram_base: int,
                                   ram_size: int):
    """Infer an erased missing tail only from a fully linked partition."""
    if (not isinstance(image, bytes) or type(flash_id_address) is not int
            or type(configured_size) is not int or not 16 <= flash_id_address < len(image)
            or len(image) > configured_size or flash_id_address + 4 > len(image)):
        return None
    table = struct.unpack_from('<I', image, flash_id_address - 16)[0]
    if table & 3 or table + 8 > len(image):
        return None
    name, count = struct.unpack_from('<2I', image, table)
    if not 1 <= count <= 512 or name >= len(image):
        return None
    descriptor = table + 8 + count * 4
    if descriptor + 0x28 > len(image):
        return None
    sector = struct.unpack_from('<I', image, table + 8)[0]
    start_words, length_words = struct.unpack_from('<2I', image, descriptor + 0x14)
    extent = 2 * (start_words + length_words) + sector
    if (extent <= configured_size or extent > 0x4000000
            or extent & (extent - 1) or extent > configured_size * 2):
        return None
    padded = image.ljust(extent, b'\xff')
    profile = find_descriptor_bank(padded, flash_id_address, extent, ram_base, ram_size)
    if profile is None or not profile[0] <= len(image):
        return None
    return extent, profile


def source_prefix_matches(image: bytes, loaded: bytes, profile: tuple) -> bool:
    """Require the immutable code prefix to match the loaded state."""
    if (not isinstance(image, bytes) or not isinstance(loaded, bytes)
            or not isinstance(profile, tuple) or len(profile) != 5
            or type(profile[0]) is not int or not 0 < profile[0] <= len(image)
            or profile[0] > len(loaded)):
        return False
    return image[:profile[0]] == loaded[:profile[0]]
