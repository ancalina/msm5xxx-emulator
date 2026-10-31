"""Retained monochrome boot messages on the shifted halfword LCD aperture."""
from __future__ import annotations


class ShiftedBootPanel:
    """Admit a complete clear before retaining partial glyph-window updates.

    Black and white are unambiguous without a recovered colour-mode contract.
    Other pixel values relinquish this observer instead of guessing a format.
    """

    command_port, data_port = 0x02800034, 0x02800036
    width, height = 176, 220
    viewport = (2, 177, 0, 219)

    def __init__(self) -> None:
        self.qualified = False
        self.rejection: str | None = None
        self.sequence = 0
        self.frame = bytes(self.width * self.height * 3)
        self._ram = bytearray(self.frame)
        self._command: int | None = None
        self._args: list[int] = []
        self._axes: dict[int, tuple[int, int]] = {}
        self._window: tuple[int, int, int, int] | None = None
        self._cursor = 0
        self._dirty = False
        self._enabled: bool | None = None

    def _reject(self, reason: str) -> None:
        self.rejection = reason
        self.qualified = False

    def _publish(self) -> None:
        if self.qualified and self._enabled and self._dirty:
            self.frame = bytes(self._ram)
            self.sequence += 1
            self._dirty = False

    def _finish(self) -> None:
        if self._command in (0x15, 0x75):
            if len(self._args) != 4:
                self._reject("incomplete-axis")
                return
            start = self._args[0] | self._args[1] << 8
            end = self._args[2] | self._args[3] << 8
            if self._command == 0x15:
                lo, hi = self.viewport[:2] if self.qualified else (0, 177)
            else:
                lo, hi = (0, 219)
            if not lo <= start <= end <= hi:
                self._reject("axis-outside-viewport")
                return
            self._axes[self._command] = (start, end)
        elif self._command == 0x5C:
            # Once GRAM is initialized, unwritten glyph rows retain the clear.
            self._publish()

    def write(self, address: int, size: int, value: int) -> None:
        if address not in (self.command_port, self.data_port) or self.rejection:
            return
        if size != 2 or not 0 <= value <= 0xFFFF:
            self._reject("unsupported-transfer")
            return
        if address == self.command_port:
            if value > 0xFF:
                self._reject("unsupported-command")
                return
            self._finish()
            if self.rejection:
                return
            self._command = value
            self._args.clear()
            self._window = None
            self._cursor = 0
            if value == 0x5C:
                x, y = self._axes.get(0x15), self._axes.get(0x75)
                if x is not None and y is not None:
                    window = (*x, *y)
                    # Both observed column origins require a complete raster;
                    # partial windows cannot choose or change the viewport.
                    if not self.qualified and window in (
                        (0, 175, 0, 219), (2, 177, 0, 219)
                    ):
                        self.viewport = window
                        self._window = window
                    elif self.qualified:
                        self._window = window
            elif value == 0xAF:
                if self._enabled is not True and self.qualified:
                    self._dirty = True
                self._enabled = True
                self._publish()
            elif value == 0xAE:
                self._enabled = False
                if self.qualified:
                    self.frame = bytes(len(self._ram))
                    self.sequence += 1
            return
        if self._command in (0x15, 0x75):
            if value > 255 or len(self._args) == 4:
                self._reject("invalid-axis-argument")
            else:
                self._args.append(value)
            return
        if self._command != 0x5C or self._window is None:
            return
        if value not in (0, 0xFFFF):
            self._reject("colour-mode-unverified")
            return
        x0, x1, y0, y1 = self._window
        columns = x1 - x0 + 1
        count = columns * (y1 - y0 + 1)
        if self._cursor >= count:
            self._reject("raster-overflow")
            return
        x = x0 - self.viewport[0] + self._cursor % columns
        y = y0 + self._cursor // columns
        offset = (y * self.width + x) * 3
        self._ram[offset:offset + 3] = b"\xff\xff\xff" if value else b"\0\0\0"
        self._cursor += 1
        self._dirty = True
        if self._cursor == count:
            if self._window == self.viewport:
                self.qualified = True
            self._publish()
