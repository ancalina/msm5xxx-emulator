"""Cross-linked Thumb halfword transport for a low-byte 96x64 page panel."""
from __future__ import annotations

import re
import struct
from .arm import thumb_bl_target, thumb_literal_value


def _words(*values: int) -> bytes:
    return struct.pack('<' + 'H' * len(values), *values)


def find_halfword_page_secondary(image: bytes) -> int | None:
    """Require a unique initializer, bounded byte consumer and geometry object.

    Two compiler layouts place the dirty rectangle at different displacements.
    Neither model names nor execution addresses participate in admission.
    """
    def word(at: int) -> int:
        return struct.unpack_from('<H', image, at)[0] if 0 <= at <= len(image) - 2 else -1

    def same(at: int, *values: int) -> bool:
        return image[at:at + 2 * len(values)] == _words(*values)

    # MOVS r1,#5; LSLS r1,#23; STRH r0,[r1{,#2}]; BX lr.
    commands = [m.start() for m in re.finditer(re.escape(_words(0x2105, 0x05c9, 0x8008, 0x4770)), image)
                if not m.start() & 1]
    data = [m.start() for m in re.finditer(re.escape(_words(0x2105, 0x05c9, 0x8048, 0x4770)), image)
            if not m.start() & 1]
    if len(commands) != 1 or len(data) != 1:
        return None
    command, payload = commands[0], data[0]
    found = []
    for match in re.finditer(re.escape(_words(0xb580)), image):
        setup = match.start()
        if setup & 1 or setup + 0x90 > len(image):
            continue
        # All initialization opcodes must travel through the same command leaf.
        if any(word(setup + 6 + i * 6) != 0x2000 | value
               or thumb_bl_target(image, setup + 8 + i * 6) != command
               for i, value in enumerate((0xae, 0x40, 0xa1, 0x10, 0, 0xa6, 0xa3, 0xc0, 0x2c))):
            continue
        for shift, field in ((0, 4), (-2, 0x28)):
            if shift == 0:
                if not same(setup + 0x3c, 0x277d, 0x00ff, 0x1c38):
                    continue
            elif thumb_literal_value(image, setup + 0x3c, 7) != 50000 or word(setup + 0x3e) != 0x1c38:
                continue
            if any(word(setup + off + shift) != 0x2000 | value
                   or thumb_bl_target(image, setup + off + 2 + shift) != command
                   for off, value in ((0x46, 0x2e), (0x52, 0x2f), (0x5e, 0x24), (0x64, 0x81), (0x6a, 0x23))):
                continue
            delays = [thumb_bl_target(image, setup + off + shift) for off in (0x42, 0x4e, 0x5a)]
            if delays[0] is None or not 0 <= delays[0] < len(image) or len(set(delays)) != 1:
                continue
            dirty = thumb_literal_value(image, setup + 0x70 + shift, 1)
            if not same(setup + 0x72 + shift, 0x2007, 0x6008 | (field + 12) // 4 << 6,
                        0x2200, 0x600a | (field + 8) // 4 << 6, 0x205f,
                        0x6008 | (field + 4) // 4 << 6, 0x600a | field // 4 << 6):
                continue
            refresh = thumb_bl_target(image, setup + 0x80 + shift)
            wait = thumb_bl_target(image, setup + 2)
            if (dirty is None or dirty % 4 or not 0x01000000 <= dirty < 0x02000000 - 0x40
                    or refresh is None or refresh < 0 or refresh + 0xb4 > len(image)
                    or wait is None or not 0 <= wait < len(image)
                    or word(refresh) != 0xb5f0
                    or thumb_literal_value(image, refresh + 2, 4) != dirty
                    or thumb_bl_target(image, refresh + 0x2c) != wait):
                continue
            # Four clamp-and-store blocks share the dirty object and exact bounds.
            valid = True
            for off, displacement, bound, branch in ((4, field, 0, 0xda01), (0xe, field + 4, 96, 0xdd01),
                                                     (0x18, field + 8, 0, 0xda01), (0x22, field + 12, 7, 0xdd01)):
                valid &= same(refresh + off, 0x6820 | displacement // 4 << 6,
                              0x2800 | bound, branch, 0x2000 | bound,
                              0x6020 | displacement // 4 << 6)
            if not valid:
                continue
            geometry = thumb_literal_value(image, refresh + 0x32, 5)
            if shift == 0:
                if word(refresh + 0x3a) != 0x3d40:
                    continue
                geometry = geometry - 0x40 if geometry is not None else None
            if geometry is None or geometry % 4 or not 0x01000000 <= geometry < 0x02000000 - 0x30:
                continue
            if (any(thumb_bl_target(image, refresh + off + shift) != command for off in (0x44, 0x50, 0x5c))
                    or thumb_bl_target(image, refresh + 0x74 + shift) != payload
                    or not same(refresh + 0x68 + shift, 0x8aa9, 0x1c38, 0x4348, 0x6aa9, 0x1840, 0x5c80)
                    or not same(refresh + 0x3e + shift, 0x0638, 0x0e00, 0x30b0)
                    or not same(refresh + 0x48 + shift, 0x6820 | field // 4 << 6, 0x3004, 0x1100, 0x4330)
                    or not same(refresh + 0x54 + shift, 0x6820 | field // 4 << 6, 0x3004, 0x0700, 0x0f00)
                    or word(refresh + 0x84 + shift) != 0x2a60
                    or word(refresh + 0x94 + shift) != 0x2f08):
                continue
            # Geometry initializer: MOVS/STRH width96,height64,pages8; STR buffer.
            geometry_stores = _words(0x2060, 0x82b8, 0x2040, 0x82f8, 0x2008, 0x84b8, 0x62b9)
            geometry_links = []
            for g in re.finditer(re.escape(geometry_stores), image):
                at = g.start()
                if at & 1:
                    continue
                # The immediately preceding descriptor literal load is in this block.
                for load in range(max(0, at - 0x40), at, 2):
                    if thumb_literal_value(image, load, 7) == geometry:
                        geometry_links.append((at, load))
            if len(geometry_links) == 1:
                found.append((setup, refresh, geometry))
    return 0x02800000 if len(found) == 1 else None
