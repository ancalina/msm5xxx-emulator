"""Source evidence for the indexed byte panel protocol."""
from __future__ import annotations

_WRITERS = ((bytes.fromhex("07203080321cf86a908008201080386b908009201080786b90800a201080b86b908004201080f86a281a908005201080786b90800c201080786b0104090c13e0f86a0004000c60234b4307e03d695d192d182d78958001300004000c3d6ba842f4dd01310904090cb86b8142e8dd"),
    95), (bytes.fromhex("07202880a98008202880aa8009202880a9800a202880af8004202880206ba88005202880a06ba8800c202880a06b0104090c13e0206b0004000c60234b4307e066699e1936183678ae8001300004000c666bb042f4dd01310904090ce06b8142e8dd"),
    0),)

def find_indexed_byte_panel(image: bytes) -> int | None:
    """Return the initial full-window cursor only for one unambiguous writer."""
    matches = []
    for signature, cursor in _WRITERS:
        offset = image.find(signature)
        if offset >= 0:
            if offset % 2 or image.find(signature, offset + 1) >= 0:
                return None
            distance, port_code = ((20, bytes.fromhex("01267606")) if cursor == 95 else (10, bytes.fromhex("01256d06")))
            if offset < distance or image[offset-distance:offset-distance+4] != port_code:
                return None
            matches.append(cursor)
    return matches[0] if len(matches) == 1 else None
