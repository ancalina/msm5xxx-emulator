"""Firmware evidence for display writer selection."""
from __future__ import annotations
import struct
from ...facts import facts_for


def find_source_packed_cursor(image):
    if not isinstance(image, bytes):
        return None
    limit = min(len(image), 0x10000)
    marker = struct.pack('<H', 0x2321)
    fixed = {0:0x803c, 2:0x2321, 4:0x807b, 6:0x803e, 8:0x1813,
             0xa:0x021b, 0xc:0x185b, 0xe:0x807b, 0x10:0x803c,
             0x12:0x2322, 0x14:0x807b, 0x16:0x803e, 0x1a:0x5c25,
             0x1e:0x2480, 0x20:0x40dc, 0x22:0x402c, 0x24:0x803e,
             0x28:0x241f, 0x2c:0x2410, 0x2e:0x43e4, 0x30:0x807c}
    matches = []
    at = image.find(marker, 0, limit)
    while at >= 0:
        pos = at - 2
        entry = pos - 0xd6
        if (entry >= 0 and not entry & 1 and pos + 0x32 <= limit
                and struct.unpack_from('<H', image, entry)[0] == 0xb5f3
                and struct.unpack_from('<2H', image, pos - 0x36) == (0x2707, 0x06bf)
                and all(struct.unpack_from('<H', image, pos + off)[0] == op
                        for off, op in fixed.items())):
            calls = tuple(call for call in range(0, limit - 4, 2)
                          if image[call + 1] & 0xf8 == 0xf0
                          and facts_for(image).thumb_call_target( call) == entry)
            if calls:
                matches.append((entry, pos, calls))
        at = image.find(marker, at + 1, limit)
    return matches[0] if len(matches) == 1 else None
