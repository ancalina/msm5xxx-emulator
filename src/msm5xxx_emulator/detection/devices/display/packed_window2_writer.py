"""Firmware evidence for display writer selection."""
from __future__ import annotations
import struct
from ...facts import facts_for


def has_packed_window2_writer(image):
    """Find a linked window setup and four-cell byte writer in boot code."""
    prefix = struct.pack('<4H', 0xb470, 0x240d, 0x255c, 0x0664)
    setup = struct.pack('<16H', 0x7025, 0x2615, 0x7026, 0x3205,
                        0x0892, 0x3208, 0x7122, 0x3301,
                        0x089a, 0x3208, 0x7122, 0x2275,
                        0x7022, 0x3011, 0x7120, 0x3111)
    mode = struct.pack('<7H', 0x7121, 0x20fb, 0x7020, 0x2007,
                       0x7020, 0x7025, 0xbc70)
    limit = min(len(image), 0x10000)
    candidate = image.find(prefix, 0, limit)
    while candidate >= 0:
        if (not candidate & 1 and image[candidate + 8:candidate + 40] == setup
                and image[candidate + 40:candidate + 54] == mode):
            # A boot writer calls this setup, loops over four source pixels,
            # and combines the four 2-bit fields before a byte store.
            start = 0
            while True:
                call = image.find(b'\xff\xf7', start, limit - 4)
                if call < 0:
                    break
                if not call & 1 and facts_for(image).thumb_call_target( call) == candidate:
                    body = image[call + 4: min(call + 0xa0, limit)]
                    fields = (b'\x04\x29', b'\xc0\x27', b'\x30\x27',
                              b'\x0c\x23', b'\x08\x71')
                    if all(field in body for field in fields):
                        return True
                start = call + 2
        candidate = image.find(prefix, candidate + 2, limit)
    return False
