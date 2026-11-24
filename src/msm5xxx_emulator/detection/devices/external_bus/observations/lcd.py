from __future__ import annotations


def has_lcd029_output(image: bytes, ram_base: int, ram_size: int) -> bool:
    """Find the halfword output sequence and its guest RAM mirror."""
    if type(ram_base) is not int or type(ram_size) is not int or ram_size <= 0:
        return False
    tail = bytes.fromhex('292212050880108008888023184308801080')
    found = image.find(tail)
    while found >= 0:
        start = found - 4
        if start >= 0 and not start & 1 and image[start:start + 2] == bytes.fromhex('0820'):
            load = int.from_bytes(image[start + 2:start + 4], 'little')
            if load & 0xff00 == 0x4900:
                literal = ((start + 6) & ~3) + (load & 0xff) * 4
                if literal <= len(image) - 4:
                    mirror = int.from_bytes(image[literal:literal + 4], 'little')
                    if not mirror & 1 and ram_base <= mirror and mirror + 2 <= ram_base + ram_size:
                        return True
        found = image.find(tail, found + 1)
    return False

def detect_external_lcd(image: bytes) -> tuple[dict | None, str]:
    """Detect narrow writes through LCD bus windows or a bit-21 poll."""
    from . import _bit21_spins, _external_lcd_writers
    if not isinstance(image, (bytes, bytearray)):
        return None, "external-lcd-image-not-bytes"
    writers = _external_lcd_writers(image)
    spins = _bit21_spins(image)
    if not writers and not spins:
        return None, "external-lcd-writer-and-bit21-absent"
    return { "behaviour": "external_lcd", "reason": "accepted", "writers": writers, "bit21": spins, }, "accepted"
