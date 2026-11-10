"""Source evidence for a selector/data LCD bridge and its clear extent."""
from __future__ import annotations
import struct

def find_selector_lcd_profile(image: bytes) -> tuple[dict | None, str]:
    """Require window programming and a matching nested pixel-clear loop."""
    if not isinstance(image, bytes):
        return None, 'selector-lcd-image-not-bytes'
    prefix = struct.pack('<6H', 0x2000, 0x8020, 0x2044, 0x8060, 0x2001, 0x8020)
    found = []
    at = 0
    while True:
        at = image.find(prefix, at)
        if at < 0:
            break
        start = at
        at += 2
        if start & 1 or start + 34 > len(image):
            continue
        words = struct.unpack_from('<17H', image, start)
        if (words[6] & 0xff00 != 0x2100 or words[7:14] != (0x0209, 0x8061, 0x2100, 0x8021, 0x2145, 0x8061, 0x8020) or words[14] & 0xff00 != 0x2000 or words[15:]
            != (0x0200, 0x8060)):
            continue
        width, height = (words[6] & 0xff) + 1, (words[14] & 0xff) + 1
        if not 1 < width < 256 or not 1 < height < 256:
            continue
        bases = []
        for pc in range(max(0, start - 32), start - 3, 2):
            if struct.unpack_from('<3H', image, pc) == (0x2407, 0x2000, 0x06a4):
                bases.append(pc)
        if len(bases) != 1:
            continue
        clear = struct.pack('<6H', 0x802b, 0x806c, 0x3101, 0x0609, 0x0e09, 0x2900 | width)
        stops = []
        for pc in range(start + 34, min(start + 0x180, len(image) - 28), 2):
            if image[pc:pc + 12] != clear:
                continue
            loop = struct.unpack_from('<14H', image, pc)
            if loop[6] != 0xd3f8 or loop[9:14] != (0x3201, 0x0612, 0x0e12, 0x2a00 | height, 0xd3f0):
                continue
            # Between rows, service the watchdog through the established
            # output register without replacing the pixel-write route.
            if loop[7:9] != (0x703b, 0x703e):
                continue
            if struct.unpack_from('<H', image, pc - 2)[0] != 0x2100:
                continue
            stops.append(pc)
        if len(stops) != 1:
            continue
        found.append({'base': 0x1c000000, 'mode': 'selector-data', 'width': width, 'height': height, 'evidence':[{'span':[bases[0], start + 34 - bases[0]]}, {'span':[stops[0]
            - 2, 30]}]})
    if len(found) != 1:
        return None, 'selector-lcd-absent-or-ambiguous'
    return found[0], 'accepted'
