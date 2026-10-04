"""Experimental indexed byte raster; color and optical orientation unverified."""
from __future__ import annotations

# Paired firmware writer shapes: bounded 96-byte rows, byte loads forwarded
# unchanged as halfwords, indexed axes and cursor. No filename/model selection.
_WRITERS = (
    (bytes.fromhex("07203080321cf86a908008201080386b908009201080786b90800a201080b86b908004201080f86a281a908005201080786b90800c201080786b0104090c13e0f86a0004000c60234b4307e03d695d192d182d78958001300004000c3d6ba842f4dd01310904090cb86b8142e8dd"), 95),
    (bytes.fromhex("07202880a98008202880aa8009202880a9800a202880af8004202880206ba88005202880a06ba8800c202880a06b0104090c13e0206b0004000c60234b4307e066699e1936183678ae8001300004000c666bb042f4dd01310904090ce06b8142e8dd"), 0),
)


def find_indexed_byte_panel(image: bytes) -> int | None:
    """Return the initial full-window cursor only for one unambiguous writer."""
    matches = []
    for signature, cursor in _WRITERS:
        offset = image.find(signature)
        if offset >= 0:
            if offset % 2 or image.find(signature, offset + 1) >= 0:
                return None
            distance, port_code = ((20, bytes.fromhex("01267606")) if cursor == 95
                                   else (10, bytes.fromhex("01256d06")))
            if offset < distance or image[offset-distance:offset-distance+4] != port_code:
                return None
            matches.append(cursor)
    return matches[0] if len(matches) == 1 else None


class IndexedBytePanel:
    """Observe bounded byte rasters independently; never consume native traffic.

    This is a byte-value preview, not a grayscale hardware model. Unsupported
    windows cannot publish; the last complete raw capture remains available.
    Exact payload prefixes publish immediately; later excess data cannot revise
    that completed frame. Partial updates require a complete full-frame base.
    """
    port = 0x02000000
    width, height = 96, 64

    def __init__(self, cursor: int):
        if cursor not in (0, 95):
            raise ValueError("unsupported static cursor convention")
        self.cursor = cursor
        self.raw = b""
        self.frame = bytes(self.width * self.height * 3)
        self.sequence = 0
        self.reason = "awaiting-full-byte-window"
        self._header = []
        self._pixels = bytearray()
        self._writing = False
        self._bounds = (0, 95, 0, 63)
        self._area = 6144

    def write(self, address: int, size: int, value: int) -> None:
        if address not in (self.port, self.port + 4):
            return
        if size != 2 or not 0 <= value <= 255:
            self._reset("unsupported-transfer")
            return
        if self._writing:
            if address == self.port + 4 and len(self._pixels) < self._area:
                self._pixels.append(value)
                if len(self._pixels) == self._area:
                    left, right, top, bottom = self._bounds
                    if self._area == 6144:
                        self.raw = bytes(self._pixels)
                    elif len(self.raw) == 6144:
                        raw = bytearray(self.raw)
                        span = right - left + 1
                        for row in range(bottom - top + 1):
                            start = (top + row) * self.width + left
                            raw[start:start + span] = self._pixels[row * span:(row + 1) * span]
                        self.raw = bytes(raw)
                    else:
                        self.reason = "partial-without-complete-base"
                        return
                    frame = bytearray(6144 * 3)
                    frame[0::3] = frame[1::3] = frame[2::3] = self.raw
                    self.frame = bytes(frame)
                    self.sequence += 1
                    self.reason = "complete-byte-preview-color-unverified"
                return
            self._reset("window-ended" if address == self.port else "window-overflow")
        commands = (7, 8, 9, 10, 4, 5, 12)
        index = len(self._header)
        # The cursor95 writer supplies dynamic inclusive bounds. Cursor0 is
        # independently evidenced only for full windows.
        fixed = (0, 95, 0, 63, self.cursor, 0)
        valid = (address == self.port and value == commands[index // 2]
                 if index % 2 == 0 else
                 address == self.port + 4 and
                 (self.cursor == 95 or value == fixed[index // 2]))
        if not valid:
            self._reset("unsupported-or-incomplete-window")
            if address != self.port or value != 7:
                return
        self._header.append(value)
        if len(self._header) == 13:
            left, right, top, bottom, x, y = self._header[1:12:2]
            if not (0 <= left <= right < self.width and
                    0 <= top <= bottom < self.height and
                    x == self.cursor - left and y == top):
                self._reset("invalid-window-bounds-or-cursor")
                return
            self._bounds = (left, right, top, bottom)
            self._area = (right - left + 1) * (bottom - top + 1)
            self._pixels.clear()
            self._writing = True

    def _reset(self, reason: str) -> None:
        self._header.clear()
        self._pixels.clear()
        self._writing = False
        self.reason = reason

    def snapshot(self) -> dict[str, object]:
        return {"width": self.width, "height": self.height, "frame": self.frame,
                "qualified": bool(self.sequence), "enabled": None,
                "port": self.port, "column_offset": None, "rejection": None,
                "detection": "indexed-byte-writer-and-full-window",
                "encoding": "unverified-byte-preview", "sequence": self.sequence,
                "observation": self.reason}
