"""Firmware evidence for display writer selection."""
from __future__ import annotations
import struct
from ...facts import facts_for


def has_paired_page_writer(image):
    if not isinstance(image, bytes):
        return False
    clear = struct.pack('<16H', 0x2200, 0x2555, 0x1dd3, 0x33a9, 0x803b,
                        0x2310, 0x803b, 0x803c, 0x2300, 0x807c, 0x807d,
                        0x3301, 0x2b80, 0xdbfa, 0x3201, 0x2a10)
    glyph = struct.pack('<6H', 0x189f, 0x3f20, 0x7b3c, 0x8074, 0x7b3f, 0x8077)
    limit = min(len(image), 0x10000)
    pos = image.find(clear, 0, limit)
    while pos >= 0:
        entry = pos - 0x1c
        if (entry >= 0 and not entry & 1 and image[entry:entry+2] == b'\xf3\xb5'
                and image[pos+0xb2:pos+0xb2+len(glyph)] == glyph):
            for at in range(0, limit-4, 2):
                if image[at+1] & 0xf8 == 0xf0 and facts_for(image).thumb_call_target( at) == entry:
                    return True
        pos = image.find(clear, pos + 1, limit)
    return False

def has_byte_paired_page_writer(image):
    if not isinstance(image, bytes):
        return False
    limit = min(len(image), 0x10000)
    stores = struct.pack('<10H', 0x2201,0x0652,0x9b06,0xe005,0x0118,
                         0x5c29,0x7091,0x5c20,0x7090,0x3301)
    clear = struct.pack('<14H',0x5c68,0x70b0,0x5c68,0x70b0,0x3701,
                        0x043f,0x0c3f,0x2f80,0xdbf2,0x3401,0x0424,
                        0x0c24,0x2c10,0xdbdd)
    copy_bound = struct.pack('<7H', 0x310e,0x320e,0x370e,0x300e,
                             0x3601,0x2e78,0xdbd1)
    pos = image.find(stores, 0, limit)
    while pos >= 0:
        writer = pos - 0x4a
        if writer < 0 or image[writer:writer+2] != b'\xff\xb5':
            pos = image.find(stores, pos+1, limit)
            continue
        copy = facts_for(image).thumb_call_target( writer+0x1c)
        if (copy is None or image[copy+0x86:copy+0x86+len(copy_bound)] != copy_bound):
            pos = image.find(stores, pos+1, limit)
            continue
        c = image.find(clear, 0, limit)
        while c >= 0:
            init = c - 0x86
            if init >= 0 and image[init:init+2] == b'\xfe\xb5':
                for call in range(0, limit-0x80, 2):
                    if (image[call+1] & 0xf8 == 0xf0
                            and facts_for(image).thumb_call_target( call) == init):
                        for later in range(call+4, call+0x80, 2):
                            if (image[later+1] & 0xf8 == 0xf0
                                    and facts_for(image).thumb_call_target( later) == writer):
                                return True
            c = image.find(clear, c+1, limit)
        pos = image.find(stores, pos+1, limit)
    return False

def has_separate_mono_page_writer(image):
    if not isinstance(image, bytes):
        return False
    limit = min(len(image), 0x10000)
    clear = struct.pack('<28H', 0x2700,0x2f08,0xda18,0xe002,0x1c78,0x1c07,
                        0xe7f9,0x1df8,0x30a9,0x2101,0x0649,0x7008,0x2010,
                        0x7008,0x2000,0x7008,0x2600,0x2e80,0xdaf0,0xe002,
                        0x1c70,0x1c06,0xe7f9,0x2000,0x2111,0x0549,0x7088,0xe7f7)
    glyph = struct.pack('<4H', 0x7800,0x2111,0x0549,0x7088)
    pos = image.find(clear, 0, limit)
    while pos >= 0:
        writer = pos-0x2e
        if (writer >= 0 and image[writer:writer+2] == b'\xf3\xb5'
                and image[writer+0x144:writer+0x144+len(glyph)] == glyph):
            for call in range(0, limit-4, 2):
                if image[call+1] & 0xf8 == 0xf0 and facts_for(image).thumb_call_target( call) == writer:
                    return True
        pos = image.find(clear, pos+1, limit)
    return False

def has_offset_mono_page_writer(image):
    if not isinstance(image, bytes):
        return False
    # Clamp the source viewport, address it at the controller offset, and
    # verify the nearby full-controller clear and display enable.
    fixed = {0: 0xb5ff, 0x1a: 0x2907, 0x28: 0x2c7f,
             0x40: 0x1df8, 0x42: 0x3009, 0x56: 0x1ca8,
             0x58: 0x23b0, 0x5a: 0x4318, 0x5e: 0x0652,
             0x60: 0x7010, 0x78: 0x00c1, 0x7a: 0x5c71,
             0x7c: 0x7091, 0x2ca: 0x2700, 0x2cc: 0x26ff,
             0x2ce: 0x2f0e, 0x2d8: 0x20b0, 0x2dc: 0x7020,
             0x2e6: 0x28a0, 0x2f0: 0x70a6, 0x2f6: 0x20af,
             0x2f8: 0x7020}
    limit = min(len(image), 0x80000)
    marker = struct.pack("<H", 0x2c7f)
    pos = image.find(marker, 0, limit)
    while pos >= 0:
        writer = pos - 0x28
        if (writer >= 0 and not writer & 1 and writer + 0x2fa <= limit
                and all(struct.unpack_from("<H", image, writer+off)[0] == opcode
                        for off,opcode in fixed.items())):
            for call in range(max(0,writer-0x1000)&~1,min(len(image)-4,writer+0x2000),2):
                if image[call+1] & 0xf8 == 0xf0 and facts_for(image).thumb_call_target(call) == writer:
                    return True
        pos = image.find(marker, pos+1, limit)
    return False
