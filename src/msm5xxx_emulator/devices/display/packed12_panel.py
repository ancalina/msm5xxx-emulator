"""Experimental byte-wide packed12 observer; caller must qualify the writer first."""
from __future__ import annotations


class Packed12Panel:
    """Retain complete rasters; native decoding remains available on rejection.

    Hypothesis: one column unit is two RGB444 samples. Only complete-window
    publication is supported. Trailing samples are buffered, never published as
    a partial replacement; window wrapping requires further hardware evidence.
    """

    # Temporary observed initialization grammar; differing setup stays native.
    _SETUP = {0x94: (), 0xD1: (), 0xCA: (0, 40, 20), 0xBB: (1,),
              0xA7: (), 0x20: (31,), 0x81: (29, 3), 0x82: (3,), 0xAF: ()}

    def __init__(self, port: int) -> None:
        self.port = port
        self.width = self.height = 0
        self.frame = b""
        self.sequence = 0
        self.qualified = False
        self.rejection: str | None = None
        self.command: int | None = None
        self._args: list[int] = []
        self._axes: dict[int, tuple[int, int]] = {}
        self._mode: tuple[int, ...] | None = None
        self._payload = bytearray()
        self._expected = 0
        self._viewport: tuple[tuple[int, int], tuple[int, int]] | None = None
        self.trailing_bytes = 0

    def _reject(self, reason: str) -> None:
        self.rejection = reason
        self.qualified = False
        self._payload.clear()
        self._expected = 0

    def write(self, address: int, size: int, value: int) -> None:
        if address not in (self.port, self.port + 2) or self.rejection:
            return
        if size != 1 or not 0 <= value <= 255:
            self._reject("non-byte-transfer")
            return
        if address == self.port:
            if self.command == 0x5C and 0 < len(self._payload) < self._expected:
                self._reject("incomplete-raster")
                return
            if self.command in (0x15, 0x75, 0xBC):
                expected = 3 if self.command == 0xBC else 2
                if len(self._args) != expected:
                    self._reject("incomplete-register")
                    return
            if self.command in self._SETUP and tuple(self._args) != self._SETUP[self.command]:
                self._reject("unsupported-setup")
                return
            if value not in (*self._SETUP, 0x15, 0x75, 0xBC, 0x5C):
                self._reject("unsupported-command")
                return
            self.command = value
            self._args.clear()
            self._payload.clear()
            self._expected = 0
            if value == 0x5C:
                x, y = self._axes.get(0x15), self._axes.get(0x75)
                if self._mode != (2, 0, 2) or x is None or y is None:
                    return
                width, height = (x[1] - x[0] + 1) * 2, y[1] - y[0] + 1
                if self.qualified and (x, y) != self._viewport:
                    self._reject("unsupported-window-change")
                    return
                self._viewport = (x, y)
                self.width, self.height = width, height
                self._expected = width * height * 3 // 2
            return
        if self.command in (0x15, 0x75, 0xBC):
            expected = 3 if self.command == 0xBC else 2
            self._args.append(value)
            if len(self._args) > expected:
                self._reject("extra-register-argument")
            elif len(self._args) == expected:
                if self.command == 0xBC:
                    self._mode = tuple(self._args)
                    if self.qualified and self._mode != (2, 0, 2):
                        self._reject("unsupported-pixel-mode")
                elif self._args[0] > self._args[1]:
                    self._reject("reversed-window")
                else:
                    self._axes[self.command] = tuple(self._args)
        elif self.command in self._SETUP:
            self._args.append(value)
            expected = self._SETUP[self.command]
            if tuple(self._args) != expected[:len(self._args)] or len(self._args) > len(expected):
                self._reject("unsupported-setup")
        elif self.command == 0x5C and self._expected:
            if len(self._payload) == self._expected:
                self.trailing_bytes += 1
                return
            self._payload.append(value)
            if len(self._payload) == self._expected:
                self.frame = bytes(n * 17 for byte in self._payload
                                   for n in (byte >> 4, byte & 15))
                self.sequence += 1
                self.qualified = True
