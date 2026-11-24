from __future__ import annotations

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
