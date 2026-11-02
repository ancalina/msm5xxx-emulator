"""Source-structure matcher for the SD810 GPIO720 bit reader.

Checks use Thumb instruction fields and the address-valued source expression.
"""
from __future__ import annotations

import struct

from .arm import thumb_bl_target


GPIO_PORT_POINTER_GLOBAL = 0x01816618
GPIO_PORT_ADDRESS = 0x03000720


def _u16(image: bytes, address: int) -> int | None:
    if address < 0 or address + 2 > len(image):
        return None
    return struct.unpack_from("<H", image, address)[0]


def _u32(image: bytes, address: int) -> int | None:
    if address < 0 or address + 4 > len(image):
        return None
    return struct.unpack_from("<I", image, address)[0]


def _ldr_literal_target(image: bytes, pc: int, register: int) -> int | None:
    """Return value loaded by Thumb LDR Rd,[PC,#imm] at file offset pc."""
    insn = _u16(image, pc)
    if insn is None or insn & 0xF800 != 0x4800 or (insn >> 8) & 7 != register:
        return None
    pool = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
    return _u32(image, pool)


def sd810_gpio_reader_sites(image: bytes) -> list[int]:
    """Find exact verified GPIO720 bit-0 reader/control-flow sites.

    The caller must require exactly one site before creating a profile. The
    pointer global and control-flow shape were verified against all three
    supplied SD810 images; the extended state-byte/branch/call checks make
    this narrower than the common halfword/bit-test idiom.
    """
    # `ldr r0,[r0,#4]; ldrh r0,[r0]; lsls r1,r0,#31; lsrs r1,r1,#31;
    # movs r2,#0x7f` is the start of the source expression. Construct the
    # search needle from semantic instruction words rather than a firmware
    # byte signature.
    needle = struct.pack("<5H", 0x6840, 0x8800, 0x07C1, 0x0FC9, 0x227F)
    sites: list[int] = []
    offset = 0
    while (hit := image.find(needle, offset)) >= 0:
        offset = hit + 2
        start = hit - 2  # preceding LDR-literal R0
        if start < 0 or start & 1:
            continue
        if _ldr_literal_target(image, start, 0) != GPIO_PORT_POINTER_GLOBAL:
            continue
        # Continue with the state-byte computation and bit-dependent path.
        base = hit + 10
        if (_u16(image, base) is None
                or _u16(image, base) & 0xF800 != 0x4800
                or (_u16(image, base) >> 8) & 7 != 0):
            continue
        if (_u16(image, base + 2) != 0x0112       # lsls r2,#4
                or _u16(image, base + 4) != 0x1810 # adds r0,r2,r0
                or _u16(image, base + 6) != 0x2900):  # cmp r1,#0
            continue
        status_lit = _u16(image, base + 8)
        branch = _u16(image, base + 10)
        if (status_lit is None or status_lit & 0xF800 != 0x4800
                or (status_lit >> 8) & 7 != 4
                or branch is None or branch & 0xFF00 != 0xD100):
            continue
        # Both observed branch paths write the status byte and call the same
        # helpers with values 8 and 0xff. Check Thumb BL pair structure.
        calls = (_u16(image, base + 16), _u16(image, base + 18),
                 _u16(image, base + 22), _u16(image, base + 24))
        if (_u16(image, base + 12) != 0x7141
                or _u16(image, base + 14) != 0x2008
                or calls[0] is None or calls[0] & 0xF800 != 0xF000
                or calls[1] is None or calls[1] & 0xF800 != 0xF800
                or _u16(image, base + 20) != 0x20FF
                or calls[2] is None or calls[2] & 0xF800 != 0xF000
                or calls[3] is None or calls[3] & 0xF800 != 0xF800):
            continue
        sites.append(start)
    return sites


def sd810_gpio_board_status_profile(image: bytes) -> tuple[int, int, int] | None:
    """Return address/mask/asserted-default only for one proven reader site."""
    return ((GPIO_PORT_ADDRESS, 1, 1)
            if len(sd810_gpio_reader_sites(image)) == 1 else None)


def sd810_fold_event_source(image: bytes, raw_enqueue: int) -> bool:
    """Close both GPIO status branches over the scanner's raw event sink.

    This establishes the firmware's open/closed event convention; it does not
    identify the physical component connected to the input.
    """
    sites = sd810_gpio_reader_sites(image)
    if len(sites) != 1 or type(raw_enqueue) is not int:
        return False
    base = sites[0]
    if base + 110 > len(image):
        return False
    branch = _u16(image, base + 22)
    if (branch is None or branch & 0xff00 != 0xd100
            or base + 26 + ((branch & 0xff) << 1) != base + 94):
        return False
    # High stores logical 1 and emits raw 6; low stores logical 0 and emits
    # raw 8. Both paths enqueue FF after the transition event.
    if tuple(_u16(image, base + offset) for offset in (24, 26, 32, 94, 96, 98, 104)) != (
            0x7141, 0x2008, 0x20ff, 0x2101, 0x7141, 0x2006, 0x20ff):
        return False
    return all(thumb_bl_target(image, base + offset) == raw_enqueue
               for offset in (28, 34, 100, 106))
