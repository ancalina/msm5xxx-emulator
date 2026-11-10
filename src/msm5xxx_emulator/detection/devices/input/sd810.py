"""Source-structure matcher for the SD810 GPIO720 bit reader.

Checks use Thumb instruction fields and the address-valued source expression.
"""
from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match
from msm5xxx_emulator.detection.facts import facts_for
import struct

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
        if (_u16(image, base) is None or _u16(image, base) & 0xF800 != 0x4800 or (_u16(image, base) >> 8) & 7 != 0):
            continue
        if (_u16(image, base + 2) != 0x0112       # lsls r2,#4
                or _u16(image, base + 4) != 0x1810 # adds r0,r2,r0
                or _u16(image, base + 6) != 0x2900):  # cmp r1,#0
            continue
        status_lit = _u16(image, base + 8)
        branch = _u16(image, base + 10)
        if (status_lit is None or status_lit & 0xF800 != 0x4800 or (status_lit >> 8) & 7 != 4 or branch is None or branch & 0xFF00 != 0xD100):
            continue
        # Both observed branch paths write the status byte and call the same
        # helpers with values 8 and 0xff. Check Thumb BL pair structure.
        calls = (_u16(image, base + 16), _u16(image, base + 18), _u16(image, base + 22), _u16(image, base + 24))
        if (_u16(image, base + 12) != 0x7141 or _u16(image, base + 14) != 0x2008 or calls[0] is None or calls[0] & 0xF800 != 0xF000 or calls[1] is None or calls[1]
            & 0xF800 != 0xF800 or _u16(image, base + 20) != 0x20FF or calls[2] is None or calls[2] & 0xF800 != 0xF000 or calls[3] is None or calls[3] & 0xF800
            != 0xF800):
            continue
        sites.append(start)
    return sites

def sd810_gpio_board_status_profile(image: bytes) -> tuple[int, int, int] | None:
    """Return address/mask/asserted-default only for one proven reader site."""
    return ((GPIO_PORT_ADDRESS, 1, 1) if len(sd810_gpio_reader_sites(image)) == 1 else None)

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
    if (branch is None or branch & 0xff00 != 0xd100 or base + 26 + ((branch & 0xff) << 1) != base + 94):
        return False
    # High stores logical 1 and emits raw 6; low stores logical 0 and emits
    # raw 8. Both paths enqueue FF after the transition event.
    if tuple(_u16(image, base + offset) for offset in (24, 26, 32, 94, 96, 98, 104)) != (0x7141, 0x2008, 0x20ff, 0x2101, 0x7141, 0x2006, 0x20ff):
        return False
    return all(facts_for(image).thumb_call_target(base + offset) == raw_enqueue for offset in (28, 34, 100, 106))

def sd810_fold_irq_source(image: bytes, raw_enqueue: int, route: dict[str, object],) -> tuple[int, int, int, int, int] | None:
    """Close GPIO0's edge callback and parent IRQ over the same image."""
    if not sd810_fold_event_source(image, raw_enqueue):
        return None
    if (not fields_match(route, (('controller_class', 'legacy-c80-two-bank-group10-v1'), ('status', 50334848), ('enable', 50334868)))):
        return None
    base = sd810_gpio_reader_sites(image)[0]
    if base + 120 > len(image) or tuple(_u16(image, base + offset) for offset in (0x54, 0x56, 0x6e, 0x70, 0x72)) != (0x1c22, 0x2101, 0x1c22, 0x2100, 0x2000):
        return None
    callback = facts_for(image).thumb_literal_value(base + 0x14, 4)
    setter = facts_for(image).thumb_call_target(base + 0x74)
    if callback is None or not callback & 1 or setter is None:
        return None
    callback_code = callback & ~1
    if (callback_code + 0x36 > len(image) or tuple(_u16(image, callback_code + offset) for offset in (2, 4, 6)) != (0x2200, 0x2101, 0x2000) or facts_for(image).thumb_call_target(callback_code
        + 8) != setter):
        return None
    publish = facts_for(image).thumb_call_target(callback_code + 0x32)
    if (publish is None or publish + 0x1a > len(image) or _u16(image, publish + 0x12) != 0x2104 or facts_for(image).thumb_call_target(publish + 0x16) is None or
        (wait_mask := facts_for(image).thumb_literal_value(base + 0x80, 0)) is None or not wait_mask & 4):
        return None
    target_task = facts_for(image).thumb_literal_value(publish + 0x14, 0)
    if type(target_task) is not int or not 0x01000000 <= target_task < 0x02000000:
        return None
    group = facts_for(image).thumb_literal_value(setter + 0x2c, 3)
    vector = facts_for(image).thumb_literal_value(setter + 0x2e, 6)
    if (type(group) is not int or type(vector) is not int or not 0x01000000 <= group <= 0x01ffffa8 or group & 3 or not 0x01000000 <= vector <= 0x01ffff40 or
        vector & 3 or route.get("callback_slot") != group - 0x38):
        return None
    # Validate the copied GPIO-bank descriptor and adjacent parent line 29.
    sources = []
    for pos in range(0, min(len(image) - 20, 0x40000) + 1, 4):
        source, target, size, bss, bss_size = struct.unpack_from("<5I", image, pos)
        if (0 < size <= 0x800000 and source + size <= len(image) and 0x01000000 <= target <= group - 0x68 and group + 16 <= target + size == bss and 0 <
            bss_size <= 0x2000000 and bss + bss_size <= 0x04000000):
            origin = source + group - target
            if (origin >= 0x68 and struct.unpack_from("<4I", image, origin) == (0x03000c88, 0x03000ca4, 0x03000cb0, 0x0300074c) and struct.unpack_from("<3I",
                image, origin - 0x68) == (0x03000c84, 0x03000c98, 0x2000)):
                sources.append(origin)
    if len(sources) != 1:
        return None
    handler_file = route.get("handler_file_offset")
    registrar_file = route.get("registrar_file_offset")
    if type(handler_file) is not int or type(registrar_file) is not int:
        return None
    installs = []
    for pos in range(handler_file, min(len(image) - 8, handler_file + 0x1800), 2):
        if (_u16(image, pos + 2) != 0x201d or facts_for(image).thumb_call_target(pos + 4) != registrar_file):
            continue
        candidate = facts_for(image).thumb_literal_value(pos, 1)
        if candidate is not None and candidate & 1:
            installs.append(candidate & ~1)
    if len(installs) != 1:
        return None
    group_isr = installs[0]
    if (group_isr + 0x50 > len(image) or facts_for(image).thumb_literal_value(group_isr + 2, 4) != 0x03000c80 or facts_for(image).thumb_literal_value(group_isr
        + 6, 1) != group or facts_for(image).thumb_literal_value(group_isr + 0x26, 1) != vector or tuple(_u16(image, group_isr + offset) for offset in (0, 4, 8,
        10, 0x46, 0x4c)) != (0xb5b0, 0x8920, 0x8a0a, 0x4002, 0x5808, 0x8127) or facts_for(image).thumb_call_target(group_isr + 0x48) is None):
        return None
    return group, vector, callback, group - 0x54, group_isr | 1
