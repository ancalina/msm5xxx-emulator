"""Closed ARM writer bundle with a natural primary-ROM content entry."""
from __future__ import annotations

import hashlib
import struct


def _shape(image, at, size, digest, literals=(), calls=()):
    if at & 3 or not 0 <= at <= len(image)-size:
        return None
    body = bytearray(image[at:at+size]); pools = []; values = {}; targets = {}
    for offset in literals:
        word = struct.unpack_from('<I', body, offset)[0]
        if word & 0x0f7f0000 != 0x051f0000:
            return None
        pool = at+offset+8 + (word & 4095)*(1 if word & 0x800000 else -1)
        if pool & 3 or not 0 <= pool <= len(image)-4:
            return None
        pools.append((pool, pool+4))
        values[offset] = struct.unpack_from('<I', image, pool)[0]
        struct.pack_into('<I', body, offset, word & ~4095)
    for offset in calls:
        word = struct.unpack_from('<I', body, offset)[0]
        if word >> 24 != 0xeb:
            return None
        displacement = word & 0xffffff
        if displacement & 0x800000:
            displacement -= 0x1000000
        target = at+offset+8+displacement*4
        if not 0 <= target <= len(image)-4:
            return None
        targets[offset] = target
        struct.pack_into('<I', body, offset, word & 0xff000000)
    if hashlib.sha256(body).hexdigest() != digest:
        return None
    return values, pools, targets


def writer_bundle(image, full, source_end):
    if full+0x138 > source_end:
        return None
    shape = _shape(image, full, 0x58,
        '0e31eb493442ff721f9974276e0dd5c7211edbc217fdd97424dbef6e78c8b7d2', (0x30,))
    if shape is None or shape[1] != [(full+0x58, full+0x5c)]:
        return None
    if (_shape(image, full+0x5c, 0x74,
            '0b25c29af713cff2533d11e2bbc85972302b97ab51f32be149f808326cd9866e') is None
            or _shape(image, full+0xd0, 0x68,
            '889bc6852542325e03010884fb41af108f52f3143ef8bbc0dca61fac76571234') is None):
        return None
    return shape[0][0x30]


def content_owner(image, entry, header, ram_ranges):
    shape = _shape(image, entry, 0xd4,
        '1d71d336e282930fc242dd8b81d13dcb98437cd8fcc33f056010e401f0543e0e',
        (0x34, 0xc4, 0xd0), (0x28,))
    if shape is None or not 0 <= header <= len(image)-10:
        return None
    values, pools, calls = shape
    callee = calls[0x28]
    if _shape(image, callee, 0x2c,
            '9398d66d7169dda69f35471fbd486659a560d08b2dd5e0de4f252263030ea013') is None:
        return None
    scalar = values[0x34]-0x3fc
    references = (values[0xc4], values[0xd0])
    def ram(at, size):
        return any(a <= at < at+size <= b for a, b in ram_ranges)
    if (scalar & 3 or not ram(scalar, 8)
            or any(at & 3 or not ram(at, 4) for at in references)
            or len(set(references)) != 2
            or any(scalar <= at < scalar+8 for at in references)):
        return None
    code = [(entry, entry+0xd4), (callee, callee+0x2c)]
    data = [(header, header+10)]
    def overlap(a, b):
        return a[0] < b[1] and b[0] < a[1]
    if (overlap(*code) or any(overlap(a, b) for a in code for b in pools+data)
            or any(overlap(a, b) for a in pools for b in data)
            or any(overlap(a, b) for i, a in enumerate(pools) for b in pools[i+1:])):
        return None
    return dict(code=code, pools=pools, data=data, ram=[(scalar, scalar+8)],
        metadata=dict(entry=entry, prefix_size=0xd4, header_callee=callee,
            bitmap_header=header, scalar_cells=[scalar, scalar+4],
            ram_address_constants=list(references), remainder='unclaimed-natural-guest-execution'))
