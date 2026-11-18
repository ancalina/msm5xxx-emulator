"""Find a copied halfword writer with a complete padded row loop."""
from __future__ import annotations

import struct
from ...facts import facts_for


def find_padded_gray_writer(image, overlays):
    if not isinstance(image, bytes):
        return None
    matches = []
    # The register list and stores prove the actual transfer order; literal
    # loads below establish its port and loop counts.
    fixed = {0: 0xe92d40f0, 8: 0xe2877010, 0x10: 0xe1a06026,
             0x28: 0xe8b04078, 0x2c: 0xe1c730b0, 0x30: 0xe1a03823,
             0x34: 0xe1c730b0, 0x38: 0xe1c740b0, 0x3c: 0xe1a04824,
             0x40: 0xe1c740b0, 0x44: 0xe1c750b0, 0x48: 0xe1a05825,
             0x4c: 0xe1c750b0, 0x50: 0xe1c760b0, 0x54: 0xe1a06826,
             0x58: 0xe1c760b0, 0x5c: 0xe1c7e0b0, 0x60: 0xe1a0e82e,
             0x64: 0xe1c7e0b0, 0x68: 0xe2511001, 0x6c: 0x1affffed,
             0x70: 0xe1a06026, 0x94: 0xe2522001, 0x98: 0x1affffe1,
             0x9c: 0xe8bd40f0, 0xa0: 0xe12fff1e}
    fixed.update({off: 0xe1c760b0 for off in (*range(0x14, 0x24, 4),
                                               *range(0x74, 0x94, 4))})
    marker = struct.pack('<I', fixed[0])
    palette_builder = struct.pack('<5H', 0x08ed, 0x02ed, 0x08b6, 0x0176, 0x4335)
    palette_renderer = struct.pack('<5I', 0xe4d32001, 0xe1520006,
                                   0x11a02082, 0x119420b2, 0x11c120b0)
    for overlay in overlays or ():
        source = getattr(overlay, 'source', None)
        target = getattr(overlay, 'target', None)
        size = getattr(overlay, 'size', None)
        table = getattr(overlay, 'table_offset', None)
        if (any(type(v) is not int for v in (source, target, size, table)) or
                source < 0 or size < 0xa4 or source + size > len(image) or
                table < 0 or table + 12 > len(image) or
                struct.unpack_from('<3I', image, table) != (source, target, size)):
            continue
        pos = image.find(marker, source, source + size)
        while pos >= 0:
            if (pos % 4 == 0 and pos + 0xa4 <= source + size and pos >= source + 4
                    and struct.unpack_from('<2H', image, pos-4) in
                        ((0x4778, 0), (0x4778, 0x46c0))
                    and all(struct.unpack_from('<I', image, pos+off)[0] == op
                            for off, op in fixed.items())):
                literals = []
                for off, register in ((4, 7), (0xc, 2), (0x24, 1)):
                    instruction = struct.unpack_from('<I', image, pos+off)[0]
                    if instruction & 0xfffff000 != 0xe59f0000 | register << 12:
                        break
                    location = pos + off + 8 + (instruction & 0xfff)
                    if location + 4 > source + size:
                        break
                    literals.append(struct.unpack_from('<I', image, location)[0])
                if literals == [0x02800000, 160, 12]:
                    # The indexed renderer stores halfword palette entries
                    # into the framebuffer. Its asset format is also built by
                    # code that packs 8-bit components into 5/6/5 fields.
                    renderer = image.find(palette_renderer, source, source + size)
                    builders = []
                    builder = image.find(palette_builder, 0, source)
                    while builder >= 0:
                        if (not builder & 1 and builder >= 0x1c and builder + 0x14 <= source and
                                struct.unpack_from('<5H', image, builder - 0x1c) ==
                                    (0x80a1, 0x80e7, 0x2101, 0x70a1, 0x70e1) and
                                struct.unpack_from('<3H', image, builder + 0x0c) ==
                                    (0x08f6, 0x432e, 0x9d04) and
                                struct.unpack_from('<H', image, builder + 0x12)[0] == 0x802e):
                            builders.append(builder)
                        builder = image.find(palette_builder, builder + 2, source)
                    if (renderer < 0 or renderer & 3 or len(builders) != 1 or
                            image.find(palette_renderer, renderer + 4, source + size) >= 0):
                        pos = image.find(marker, pos+4, source+size)
                        continue
                    runtime = target + pos - source - 4 | 1
                    thunk_pattern = struct.pack('<2H3I', 0x4778, 0x46c0,
                                                0xe59fc000, 0xe12fff1c, runtime)
                    thunk = image.find(thunk_pattern, 0, min(source, len(image)))
                    if thunk >= 0 and thunk % 4 == 0:
                        facts = facts_for(image)
                        for call in range(0, min(source, len(image)-4), 2):
                            if (image[call+1] & 0xf8 == 0xf0 and
                                    facts.thumb_call_target(call) == thunk):
                                matches.append((table, source, size, pos, thunk, call))
                                break
            pos = image.find(marker, pos+4, source+size)
    return matches[0] if len(matches) == 1 else None
