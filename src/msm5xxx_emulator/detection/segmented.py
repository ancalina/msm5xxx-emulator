"""Temporary segmented-row protocol candidates; runtime raster proof required."""
from __future__ import annotations
import re
import struct
from .arm import thumb_bl_target, thumb_literal_value

def branch(image, address, condition):
    word = struct.unpack_from('<H', image, address)[0]
    if word >> 8 != condition:
        return None
    offset = word & 255
    return address + 4 + (offset if offset < 128 else offset - 256) * 2


def _row_hits(image):
    hits = []
    upper = bytes.fromhex('42212180c11d08310904090c21802180')
    copy = bytes.fromhex('13880232a3800131')
    for match in re.finditer(re.escape(b'\x42\x28'), image):
        start = match.start()
        if start < 20 or start % 2 or start + 256 > len(image):
            continue
        target = branch(image, start + 2, 0xDA)
        if target is None or not start + 12 <= target <= start + 96:
            continue
        if image[start + 4:start + 10] != bytes.fromhex('42212180811d'):
            continue
        jump = struct.unpack_from('<H', image, start + 10)[0]
        displacement = jump & 2047
        if displacement >= 1024:
            displacement -= 2048
        if jump >> 11 != 28 or start + 14 + displacement * 2 != target + 8:
            continue
        if image[target:target + len(upper)] != upper:
            continue
        end = start + 256
        copies = [m.start() for m in re.finditer(re.escape(copy), image[target:end])]
        if len(copies) != 1:
            continue
        writer = target + copies[0]
        if bytes.fromhex('c1018918') not in image[target:writer]:
            continue
        if not any(branch(image, p, 0xDD) == start
                   for p in range(writer + 8, end - 2, 2)):
            continue
        # One local register allocation has a fully bounded port/descriptor prefix.
        prefix = image[start - 20:start]
        port = descriptor = None
        if (prefix[:6] == bytes.fromhex('0524e4052080')
                and prefix[7] == 0x4e
                and prefix[8:20] == bytes.fromhex('b0692080f0692080306a44e0')
                and image[start+0x8a:start+0x94] == bytes.fromhex('0004716a000c8842b5dd')):
            literal = ((start - 14 + 4) & ~3) + prefix[6] * 4
            if literal + 4 <= len(image):
                descriptor = struct.unpack_from('<I', image, literal)[0]
                if descriptor % 4 == 0 and 0x01000000 <= descriptor < 0x02000000:
                    port = 5 << 23
        hits.append({'row_branch': start, 'upper_bias': target, 'copy': writer,
                     'locally_derived_port': port, 'descriptor': descriptor})
    return hits



def _long_port(image: bytes, row: int) -> int | None:
    # Constructor, conditional bypass, and direct branch to the register setup.
    if row < 0x2cc or image[row-0x2cc:row-0x2c4] != bytes.fromhex("0525ed05002800d1"):
        return None
    jump = struct.unpack_from("<H", image, row-0x2c4)[0]
    displacement = jump & 2047
    if displacement & 1024:
        displacement -= 2048
    if jump >> 11 != 28 or row-0x2c0+displacement*2 != row-0xca:
        return None
    if image[row-0xca:row-0xc6] != bytes.fromhex("2c202880"):
        return None
    # Only straight-line register constants/stores and two verified delay calls.
    cursor, calls = row-0xca, []
    while cursor < row-0x16:
        word = struct.unpack_from("<H", image, cursor)[0]
        if word >> 11 == 30:
            target = thumb_bl_target(image, cursor)
            if target is None or cursor+4 > row-0x16:
                return None
            calls.append(target)
            cursor += 4
            continue
        immediate = word & 0xf800 == 0x2000 and (word >> 8) & 7 in (0,1,2,4)
        store = word in (0x8028,0x8029,0x802a,0x802c,0x802e)
        if not (immediate or store or word == 0x1c20):
            return None
        cursor += 2
    if len(calls) != 2 or calls[0] != calls[1]:
        return None
    helper = calls[0]
    # Bounded Thumb delay shape preserves r4/r5 and returns via BX LR.
    tail = bytes.fromhex("152201e00a8032383228fbdc002806dd1b235843363000d53f30801108807047")
    if not 0 <= helper <= len(image)-2-len(tail) or image[helper+2:helper+2+len(tail)] != tail:
        return None
    if thumb_literal_value(image, helper, 1) is None:
        return None
    if image[row-0x1a:row-0x12] != bytes.fromhex("201c28802c1c174d"):
        return None
    if image[row-0x14:row] != bytes.fromhex("174de8692080286a2080686a194e0004000c44e0"):
        return None
    if image[row+0x8a:row+0x90] != bytes.fromhex("a96a8842b7dd"):
        return None
    descriptor = thumb_literal_value(image, row-0x14, 5)
    if descriptor is None or descriptor % 4 or not 0x01000000 <= descriptor < 0x02000000:
        return None
    for position, register in ((row+0x2c,2),(row-8,6)):
        source = thumb_literal_value(image, position, register)
        if source is None or source & 1 or not 0x01000000 <= source < 0x02000000:
            return None
    return 5 << 23


def detect_segmented_panel(image: bytes) -> tuple[int | None, str]:
    """Require one row-copy shape, a derived port and packed565 software evidence.

    Row remapping and RGB565 are an experimental software presentation class,
    not a claim about physical glass or channel order. Ambiguity keeps fallback.
    """
    hits = _row_hits(image)
    if len(hits) != 1:
        return None, "segmented-writer-missing-or-ambiguous"
    # Shared field extraction/recomposition helper; no image hash or fixed address.
    prefix = bytes.fromhex("90b4c706ff0e3f225201024052091f23db021840c00a904203d1b84201d1ba42")
    suffix = bytes.fromhex("00d500201f2800dd1f200004800a0004000c1104090c084340010004000c3904090c084390bc")
    colors = [m.start() for m in re.finditer(re.escape(prefix), image)
              if m.start() % 2 == 0 and image[m.start()+0x64:m.start()+0x8a] == suffix]
    if len(colors) != 1:
        return None, "packed565-helper-missing-or-ambiguous"
    hit = hits[0]
    port = hit["locally_derived_port"] or _long_port(image, hit["row_branch"])
    if port is None:
        return None, "segmented-port-path-unproven"
    return port, "temporary-row-copy-and-packed565-signatures"
