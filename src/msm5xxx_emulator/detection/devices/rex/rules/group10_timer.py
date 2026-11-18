"""Structural checks for a copied two-bank interrupt table and timer list."""
from __future__ import annotations

import struct


def group10_handler(image, position, masks, status, vector_copy, descriptor):
    from . import facts_for
    if position < 0 or position + 0x250 > len(image):
        return False
    f = facts_for(image)
    words = {0: 0xb5f0, 2: 0xb088, 4: 0x2080, 6: 0x9001,
             0x4c: 0x2001, 0x4e: 0x9007,
             0x52: 0x230a, 0x56: 0x4358, 0x58: 0x1840, 0xa6: 0x201c,
             0xaa: 0x4370, 0xac: 0x1847, 0xd2: 0x6978,
             0xf0: 0x8008, 0x178: 0x8088,
             0x180: 0x9802, 0x182: 0x7a40, 0x184: 0x42b0, 0x186: 0xdb03,
             0x188: 0x2d00, 0x18a: 0xd18c, 0x18c: 0x2c00, 0x18e: 0xd18a,
             0x19a: 0x2804, 0x19c: 0xda00, 0x19e: 0xe757,
             0x248: 0xb008, 0x24e: 0x4718}
    if any(struct.unpack_from('<H', image, position + off)[0] != word
           for off, word in words.items()):
        return False
    literals = ((0x10, 7, masks), (0x1a, 7, status), (0x1e, 2, masks),
                (0x78, 2, masks), (0x7c, 7, status),
                (0xa8, 1, masks + 12), (0xec, 1, status),
                (0x174, 1, status))
    if any(f.thumb_literal_value(position + off, reg) != value
           for off, reg, value in literals):
        return False
    dispatch = f.thumb_call_target(position + 0xda)
    if (dispatch is None or dispatch < 0 or dispatch + 2 > len(image) or
            struct.unpack_from('<H', image, dispatch)[0] != 0x4700):
        return False
    group = f.thumb_literal_value(position + 0x54, 1)
    source, target, size, _ = vector_copy
    row = masks + 12 + 30 * 28
    if (group is None or group != row + 32 or source + row - target != descriptor
            or not target <= masks < row + 28 <= target + size
            or not target <= group <= target + size - 40):
        return False
    at = source + group + 30 - target
    return (0 <= at <= len(image) - 10 and
            struct.unpack_from('<4H2B', image, at) == (0x200, 0, 0x200, 4, 30, 30))


def group10_registrar(image, position, masks, default):
    from . import facts_for
    if position < 0 or position + 0xa4 > len(image):
        return None
    f = facts_for(image)
    words = {0: 0xb5f8, 2: 0x1c07, 4: 0x1c0c, 0x46: 0x201c,
             0x4a: 0x4378, 0x4c: 0x1840, 0x4e: 0x2f00, 0x50: 0xd117,
             0x82: 0x6144,
             0x9e: 0x6802, 0xa0: 0x8011}
    if (any(struct.unpack_from('<H', image, position + off)[0] != word
            for off, word in words.items()) or
            f.thumb_literal_value(position + 0x10, 4) != default or
            f.thumb_literal_value(position + 0x48, 1) != masks + 12 or
            f.thumb_literal_value(position + 0x84, 1) != default):
        return None
    return masks + 12


def group10_callback(image, position):
    from . import facts_for
    if position < 0 or position + 0x54 > len(image):
        return None
    f = facts_for(image)
    words = {2: 0xb580, 4: 0x6808, 0x16: 0x28a5,
             0x30: 0x2105, 0x4e: 0x2005}
    if any(struct.unpack_from('<H', image, position + off)[0] != word
           for off, word in words.items()):
        return None
    walker = f.thumb_call_target(position + 0x50)
    if walker is None or walker < 0 or walker + 0x3c > len(image):
        return None
    walker_words = {0: 0xb5f0, 2: 0x1c04, 0x10: 0x6807,
                    0x14: 0x68b8, 0x34: 0x1b00, 0x36: 0x60b8,
                    0x3a: 0x42b7}
    if any(struct.unpack_from('<H', image, walker + off)[0] != word
           for off, word in walker_words.items()):
        return None
    return walker
