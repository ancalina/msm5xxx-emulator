"""Firmware display-layout detection."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target


LCD_PIXEL_RE = re.compile(rb"m\.LCD_PIXEL\x00{1,4}(\d{3})(\d{3})\x00")
FRAMEBUFFER_DESCRIPTOR_PATTERN = re.compile(
    rb"\x10\x22\x00\x28\x07\xd1(?P<width>.)\x20\x08\x60"
    rb"(?P<height>.)\x20\x48\x60\x8a\x60\xca\x60\x08\x48\x08\xe0"
    rb"\x01\x28\x09\xd1(?P<sub_width>.)\x20\x08\x60\x48\x60.\x20"
    rb"\x88\x60\x04\x48\xca\x60\x08\x61\x01\x20\x70\x47"
    rb"\x00\x20\x70\x47\x00\x00(?P<main>.{4})(?P<sub>.{4})"
    rb"\x00\x48\x70\x47(?P<end>.{4})",
    re.S,
)


def detect_lcd_width_hint(image: bytes) -> int | None:
    """Return one plausible firmware-declared UI width, never its viewport height."""
    widths = {
        int(match.group(1))
        for match in LCD_PIXEL_RE.finditer(image)
        if 64 <= int(match.group(1)) <= 320
        and 32 <= int(match.group(2)) <= 320
    }
    return widths.pop() if len(widths) == 1 else None


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
