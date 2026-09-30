"""Experimental retained-axis RGB565 observer; static admission is required."""
from __future__ import annotations


class WindowPanel:
    """Publish complete windows after a full raster establishes the viewport."""

    def __init__(self, port: int, width: int, height: int) -> None:
        self.port = port
        if not (1 <= width <= 256 and 1 <= height <= 256):
            raise ValueError("invalid statically admitted geometry")
        self.width, self.height = width, height
        self.frame = b""
        self.sequence = 0
        self.qualified = False
        self.rejection: str | None = None
        self._ram = bytearray()
        self._axes: dict[int, tuple[int, int]] = {}
        self._mode: int | None = None
        self._pending: int | None = None
        self._args: list[int] = []
        self._pixels: list[int] = []
        self._complete = False

    def _reject(self, reason: str) -> None:
        self.rejection = reason
        self.qualified = False
        self._pixels.clear()

    def write(self, address: int, size: int, value: int) -> None:
        if self.rejection or address not in (self.port, self.port + 4):
            return
        if address == self.port:
            if size != 1 or not 0 <= value <= 255:
                self._reject("non-byte-command")
                return
            if self._pixels and not self._complete:
                self._reject("incomplete-window")
                return
            self._pixels.clear()
            self._complete = False
            if self._pending is not None:
                self._args.append(value)
                if len(self._args) == (1 if self._pending == 0x40 else 2):
                    if self._pending == 0x40:
                        self._mode = value
                        if value not in (0, 2):
                            self._reject("unsupported-entry-mode")
                    elif self._args[0] > self._args[1]:
                        self._reject("reversed-window")
                    else:
                        self._axes[self._pending] = tuple(self._args)
                    self._pending = None
                    self._args.clear()
            elif value in (0x40, 0x42, 0x43):
                self._pending = value
            # Observed no-argument post-clear strobe; retain RAM (experimental).
            elif value == 0x51:
                pass
            elif self.qualified:
                self._reject("unsupported-command")
            return
        if size != 2 or not 0 <= value <= 65535 or self._pending is not None:
            self._reject("invalid-pixel-transfer")
            return
        x, y = self._axes.get(0x43), self._axes.get(0x42)
        if x is None or y is None or self._mode not in (0, 2):
            self._reject("missing-window-or-mode")
            return
        if not self.qualified:
            if x != (0, self.width - 1) or y != (0, self.height - 1):
                self._reject("missing-full-raster")
                return
        if x[1] >= self.width or y[1] >= self.height:
            self._reject("window-outside-viewport")
            return
        expected = (x[1] - x[0] + 1) * (y[1] - y[0] + 1)
        if self._complete:
            self._reject("window-overflow")
            return
        self._pixels.append(value)
        if len(self._pixels) != expected:
            return
        if not self._ram:
            self._ram = bytearray(self.width * self.height * 3)
        for i, word in enumerate(self._pixels):
            if self._mode == 2:
                dx, dy = divmod(i, y[1] - y[0] + 1)
            else:
                dy, dx = divmod(i, x[1] - x[0] + 1)
            offset = ((y[0] + dy) * self.width + x[0] + dx) * 3
            self._ram[offset:offset + 3] = bytes(
                ((word >> 8 & 248) | (word >> 13),
                 (word >> 3 & 252) | (word >> 9 & 3),
                 (word << 3 & 248) | (word >> 2 & 7)))
        self.frame = bytes(self._ram)
        self.sequence += 1
        self.qualified = self._complete = True
