"""Close the halfword bus/byte framebuffer consumer of the mixed descriptor."""
from __future__ import annotations

import re
import struct
from .arm import thumb_bl_target, thumb_literal_value
from .display import find_byte_main_page_secondary


def find_halfword_rgb332_main(image: bytes) -> tuple[int, int] | None:
    """Require byte allocation, same-object clamps, byte loads and bus leaves."""
    if find_byte_main_page_secondary(image) != (
            0x02000000, 'temporary-mixed-descriptor-consumer-awaiting-runtime'):
        return None

    def words(at: int, *expected: int) -> bool:
        return image[at:at + len(expected) * 2] == struct.pack('<' + 'H' * len(expected), *expected)

    # The already validated initializer loads its common descriptor into r5.
    prefix = struct.pack('<4H', 0xb5b0, 0x1c14, 0x1c1f, 0x2800)
    objects = {thumb_literal_value(image, m.start() + 8, 5)
               for m in re.finditer(re.escape(prefix), image) if not m.start() & 1}
    objects.discard(None)
    if len(objects) != 1:
        return None
    descriptor = objects.pop()
    found = []
    for match in re.finditer(re.escape(struct.pack('<H', 0xb5f0)), image):
        start = match.start()
        if start & 1 or start + 0xcc > len(image):
            continue
        if any(thumb_literal_value(image, start + off, register) != descriptor
               for off, register in ((0x0a, 7), (0x9e, 0), (0xb0, 0), (0xba, 7))):
            continue
        gate = thumb_literal_value(image, start + 2, 1)
        if gate is None or not 0x01000000 <= gate < 0x02000000:
            continue
        # Force/clamp x to 0..119 and y to 0..148 in the same object.
        shapes = {
            4: (0x7809, 0x2900, 0xd05f),
            0x0c: (0x2800, 0xd007, 0x2000, 0x63b8, 0x2177, 0x63f9,
                   0x64b8, 0x2094, 0x64f8, 0xe014),
            0x20: (0x6bb9, 0x1c38, 0x2900, 0xda01, 0x2100, 0x6381,
                   0x6bc1, 0x2977, 0xdd01, 0x2177, 0x63c1,
                   0x6c81, 0x2900, 0xda01, 0x2100, 0x6481,
                   0x6cc1, 0x2994, 0xdd01, 0x2194, 0x64c1),
            0x4a: (0x1df8, 0x3049, 0x7800, 0x2800, 0xd001, 0x250b,
                   0xe000, 0x2500, 0x2075),
            0x60: (0x6cb8, 0x300b, 0x1b40),
            0x6a: (0x6cf8, 0x300b),
            0x72: (0x2015,), 0x78: (0x6bb8,), 0x7e: (0x6bf8,),
            0x84: (0x205c,), 0x8a: (0x6cbc, 0xe010),
            0x8e: (0x8b02, 0x1c21, 0x4351, 0x6bc2, 0x188e,
                   0x6b82, 0x188f, 0xe005),
            0xa0: (0x6ac0, 0x5dc0),  # G+2c buffer, LDRB [buffer,column].
            0xa8: (0x3701, 0x42b7, 0xddf7, 0x3401),
            0xb2: (0x6cc1, 0x1949, 0x42a1, 0xdae9),
            0xbc: (0x2094, 0x64b8, 0x2177, 0x63b9, 0x2000,
                   0x63f8, 0x64f8, 0xbdf0),
        }
        if any(not words(start + off, *shape) for off, shape in shapes.items()):
            continue
        command = thumb_bl_target(image, start + 0x5c)
        data = thumb_bl_target(image, start + 0xa4)
        if (command is None or data is None or min(command, data) < 0
                or not words(command, 0x2105, 0x05c9, 0x8008, 0x46f7)
                or not words(data, 0x2105, 0x05c9, 0x8088, 0x46f7)
                or any(thumb_bl_target(image, start + off) != command for off in (0x74, 0x86))
                or any(thumb_bl_target(image, start + off) != data for off in (0x66, 0x6e, 0x7a, 0x80))):
            continue
        found.append(start)
    return (120, 160) if len(found) == 1 else None
