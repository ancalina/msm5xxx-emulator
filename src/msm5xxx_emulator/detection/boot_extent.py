"""Primary NOR extent from a reset-linked boot and download descriptor class.

Hashes cover reviewed functions and descriptors, never a complete firmware.
The extent is a virtual source requirement, not physical flash identification.
"""
from __future__ import annotations

import hashlib
import struct

from .chipset import detect_chipset


_SPANS = (
    (0, 0x20, "6aa584893eeb93c81de5ed9c77084b03fba81e53134f043105c2d2ba8fcdd6b2"),
    (0x1250, 0x12D0, "280b935f4ca1cb912e34f92ef04eb49c85dbfb3ccf52871d1969e2cdbc580ee0"),
    (0x2000, 0x2018, "43205c0f8cb5d28b14eb5eb457a54e51bea3e7610610ecbe7035d47e7b93eb7d"),
    (0x3674, 0x36CC, "00d3e149097a99ea0dd03e39748d825d32e82151761f42781b248994772eb592"),
    (0x7B8, 0x810, "9d954f460eab4eb0f38889568bcedcf3f53713e229bf21ea2f612bc93bc4e5a7"),
    (0xC3E, 0xC9A, "c39f21bdaf5c771d5d8012b4bb4cae1d1507608d826a0d2c8d43b4635540bf42"),
    (0x648, 0x7CE, "d94c983d278dae2089a8f5f2521b3a8320b70b7606a999cea22f1f5ff7228820"),
    (0xE04, 0xE64, "dca3e5d26b29d134dec36e6d993ca9fcb59a8821ee3c60b033c3712a4c23e7fe"),
)


def boot_nor_extent(image: bytes, load_address: int = 0) -> int:
    """Return a closed 16 MiB boot extent, otherwise leave inference unchanged."""
    if load_address != 0 or len(image) < 0x10004:
        return 0
    for start, end, digest in _SPANS:
        if hashlib.sha256(image[start:end]).hexdigest() != digest:
            return 0
    if detect_chipset(image, "") != "MSM5500":
        return 0
    source, target, size = struct.unpack_from("<III", image, 0x2000)
    if (source, target, size) != (0x200C, 0x03800000, 0x5FA4):
        return 0
    if source + size > len(image):
        return 0
    # Active constructors store count 270, table, program and erase callbacks.
    table = target + 0x74A0 - source
    for pool in (0x3694, 0x36C0):
        if struct.unpack_from("<III", image, pool) != (
            table, 0x03801769, 0x038016CB
        ):
            return 0
    sectors = (*range(0, 0x10000, 0x2000),
               *range(0x10000, 0xFF0000, 0x10000),
               *range(0xFF0000, 0x1000000, 0x2000))
    if struct.unpack_from("<270I", image, 0x74A0) != sectors:
        return 0
    # Reset's interworking stages own both setup functions through the RCR store.
    if struct.unpack_from("<III", image, 0x144C) != (0x649, 0x127D, 0x1280):
        return 0
    if struct.unpack_from("<III", image, 0x1440) != (0x811, 0x1265, 0x1268):
        return 0
    if struct.unpack_from("<III", image, 0x1458) != (0x691, 0x1295, 0x1298):
        return 0
    # The actual boot store is inside this extent; its value is not a device ID.
    if struct.unpack_from("<III", image, 0x804) != (0x6060, 0x00CFF400, 0x0404):
        return 0
    if struct.unpack_from("<I", image, 0xD18)[0] != 0x00BFFFC0:
        return 0
    return 0x1000000
