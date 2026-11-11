"""Firmware evidence for display writer selection."""
from __future__ import annotations
import struct
from ...facts import facts_for


def find_reverse565_writer(image):
    if not isinstance(image, bytes):
        return None
    destination = 0x03800000
    descriptor = image.find(struct.pack('<I', destination), 0, min(len(image), 0x20000))
    matches = []
    fixed = {0:0xe92d4ff0, 4:0xe1a07001, 8:0xe1a09002, 0xc:0xe1a06003,
             0x28:0xe3560077, 0x2c:0xc3a06077, 0x34:0xe3580084,
             0x38:0xc3a08084, 0x3c:0xe0800087, 0x40:0xe0691209,
             0x50:0xe3a0b780, 0x74:0xe3a00004, 0x78:0xe5cb0004,
             0x7c:0xe2870006, 0x80:0xe5cb0004, 0x84:0xe3a00005,
             0x88:0xe5cb0004, 0x8c:0xe5cb9004, 0x90:0xe3a00006,
             0x94:0xe5cb0004, 0x98:0xe2860006, 0x9c:0xe5cb0004,
             0xa0:0xe3a00007, 0xa4:0xe5cb0004, 0xa8:0xe5cb8004,
             0xc0:0xe1d400b0, 0xcc:0x05cb0000, 0xd0:0x01a00440,
             0xd4:0x05cb0000, 0xf8:0xe28a40f0}
    marker = struct.pack('<3H', 0x263f, 0x0176, 0x402e)
    while descriptor >= 0:
        if descriptor >= 4 and not descriptor & 3 and descriptor+8 <= len(image):
            source, size = struct.unpack_from('<I4xI', image, descriptor-4)
            if (0 < size <= 0x40000 and source+size <= len(image) and size >= 0xfc
                    and all(struct.unpack_from('<I', image, source+off)[0] == op
                            for off,op in fixed.items())):
                thunk = image.find(struct.pack('<2H2I', 0x4778, 0x46c0,
                                               0xe51ff004, destination), 0, min(len(image),0x400000))
                color = image.find(marker, 0, min(len(image),0x400000))
                while thunk >= 0 and color >= 0:
                    if (not color & 1 and color >= 0x26
                            and struct.unpack_from('<H',image,color-0x10)[0] == 0x8c5d
                            and struct.unpack_from('<H',image,color+0xe)[0] == 0x06eb
                            and struct.unpack_from('<H',image,color+0x10)[0] == 0x0edb):
                        buffer = facts_for(image).thumb_literal_value(color-0x26,6)
                        if buffer is not None:
                            for call in range(0,min(len(image)-4,0x400000),2):
                                if (image[call+1]&0xf8 == 0xf0
                                        and facts_for(image).thumb_call_target(call)==thunk):
                                    for at in range(max(0,call-0x100)&~1,call,2):
                                        if (image[at+1]&0xf8 == 0x48
                                                and facts_for(image).thumb_literal_value(at,(image[at+1]&7)) == buffer):
                                            matches.append((descriptor,source,size,thunk,color,buffer))
                                            break
                    color=image.find(marker,color+1,min(len(image),0x400000))
        descriptor=image.find(struct.pack('<I',destination),descriptor+1,min(len(image),0x20000))
    matches = set(matches)
    return next(iter(matches)) if len(matches)==1 else None
