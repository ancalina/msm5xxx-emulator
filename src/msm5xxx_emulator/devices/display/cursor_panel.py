"""Temporary RGB565 scanout hypothesis for the packed-cursor 0x028 trace class."""
from __future__ import annotations


class PackedCursorPanel:
    """Observe a bounded 0x028 command/data grammar without consuming writes."""

    width = 128
    height = 160
    _PIXELS = width * height
    _FULL_WINDOW = (0, 127, 0, 159)
    _GLYPH_X_WINDOW = (0, 126)

    def __init__(self, port: int) -> None:
        self.port = port
        self.command: int | None = None
        self.mode: int | None = None
        self.window_x: tuple[int, int] | None = None
        self.window_y: tuple[int, int] | None = None
        self.cursor: tuple[int, int] | None = None
        self._ram = [0] * self._PIXELS
        self._frame = bytes(self._PIXELS * 3)
        self._sequence = 0
        self._stream_count = 0
        self._stream_limit = 0
        self._stream_kind: str | None = None
        self._baseline_ready = False
        self._setup_stage = 0
        self._closed_data_command = False
        self._command_has_data = False
        self.qualified = False
        self.rejection: str | None = None

    @property
    def frame(self) -> bytes:
        return self._frame

    @property
    def sequence(self) -> int:
        return self._sequence

    def _reject(self, reason: str) -> bool:
        if self.rejection is None:
            self.rejection = reason
        self.qualified = False
        self._stream_kind = None
        self._stream_count = 0
        self._stream_limit = 0
        return False

    @staticmethod
    def _rgb565(value: int) -> tuple[int, int, int]:
        red = (value >> 11) & 0x1F
        green = (value >> 5) & 0x3F
        blue = value & 0x1F
        return ((red << 3) | (red >> 2),
                (green << 2) | (green >> 4),
                (blue << 3) | (blue >> 2))

    def _publish(self) -> None:
        frame = bytearray(self._PIXELS * 3)
        for index, value in enumerate(self._ram):
            offset = index * 3
            frame[offset:offset + 3] = bytes(self._rgb565(value))
        self._frame = bytes(frame)
        self._sequence += 1

    def _finish_stream(self) -> None:
        kind, count = self._stream_kind, self._stream_count
        if kind is None:
            return
        if kind == "baseline" and count == self._PIXELS:
            self._baseline_ready = True
        if kind == "glyph" and count == 96:
            self.qualified = True
        if count:
            self._publish()
        self._stream_kind = None
        self._stream_count = 0
        self._stream_limit = 0

    def _start_stream(self) -> bool:
        if self.mode not in (0x1030, 0x1038):
            return self._reject("unsupported or unset entry mode")
        if self.window_x is None or self.window_y is None or self.cursor is None:
            return self._reject("memory write without complete window/cursor")
        x0, x1 = self.window_x
        y0, y1 = self.window_y
        x, y = self.cursor
        if not (0 <= x0 <= x <= x1 < self.width
                and 0 <= y0 <= y <= y1 < self.height):
            return self._reject("invalid memory window/cursor")

        if not self._baseline_ready and self.mode == 0x1030:
            if self.window_x == (0, 127) and self.window_y == (0, 159) and (x, y) == (0, 0):
                self._stream_kind, self._stream_limit = "baseline", self._PIXELS
                return True
            return self._reject("invalid baseline window/cursor")

        if self.mode == 0x1030 and self.window_x == (0, 127) and self.window_y == (0, 159):
            self._stream_kind, self._stream_limit = "raster", self._PIXELS
            return True

        if self.mode == 0x1038 and self._baseline_ready:
            if (self.window_x != self._GLYPH_X_WINDOW or y1 - y0 != 15
                    or (not self.qualified and self._setup_stage != 4)
                    or (not self.qualified and (x, y) != (1, y0))):
                return self._reject("invalid glyph setup/window/cursor")
            self._stream_kind, self._stream_limit = "glyph", 96
            return True
        return self._reject("unqualified window/mode transaction")

    def _advance(self) -> None:
        assert self.cursor is not None and self.window_x is not None
        assert self.window_y is not None and self.mode is not None
        x, y = self.cursor
        x0, x1 = self.window_x
        y0, y1 = self.window_y
        if self.mode & 0x0008:
            y += 1
            if y > y1:
                y = y0
                x = x0 if x >= x1 else x + 1
        else:
            x += 1
            if x > x1:
                x = x0
                y = y0 if y >= y1 else y + 1
        self.cursor = (x, y)

    def _pixel(self, value: int) -> bool:
        if self._stream_kind is None and not self._start_stream():
            return False
        if self._stream_count >= self._stream_limit:
            return self._reject("data exceeds qualified transfer width")
        assert self.cursor is not None
        x, y = self.cursor
        self._ram[y * self.width + x] = value
        self._stream_count += 1
        self._advance()
        if self._stream_count == self._stream_limit:
            self._finish_stream()
            self._closed_data_command = True
        return True

    def write(self, address: int, size: int, value: int) -> bool:
        """Observe a write; unrelated ports are ignored, native routing is external."""
        if address not in (self.port, self.port + 4):
            return True
        if self.rejection is not None:
            return False
        if size != 2 or not 0 <= value <= 0xFFFF:
            return self._reject("unsupported transfer width/value")
        if address == self.port:
            if value > 0xFF:
                return self._reject("non-byte command")
            self._finish_stream()
            if (self.command in (0x05, 0x16, 0x17, 0x21)
                    and not self._command_has_data):
                self._setup_stage = 0
            self._closed_data_command = False
            self._command_has_data = False
            if value not in (0x05, 0x16, 0x17, 0x21, 0x22):
                if self.qualified:
                    return self._reject(f"unsupported command {value:#04x}")
                self.command = None  # Ignore pre-qualification init commands and their data.
                self._setup_stage = 0
                return True
            self.command = value
            return True

        if self.command is None:
            return True
        self._command_has_data = True
        if self.command == 0x22:
            if self._closed_data_command:
                return self._reject("data exceeds qualified transfer width")
            return self._pixel(value)
        if self.command == 0x05:
            if value not in (0x1030, 0x1038):
                return self._reject(f"unsupported entry mode {value:#06x}")
            self.mode = value
            self._setup_stage = 1 if self._baseline_ready and value == 0x1038 else 0
            return True
        if self.command == 0x16:
            x0, x1 = value & 0xFF, value >> 8
            if not 0 <= x0 <= x1 < self.width:
                return self._reject("invalid x window")
            self.window_x = (x0, x1)
            self._setup_stage = 2 if self._setup_stage == 1 else 0
            return True
        if self.command == 0x17:
            y0, y1 = value & 0xFF, value >> 8
            if not 0 <= y0 <= y1 < self.height:
                return self._reject("invalid y window")
            self.window_y = (y0, y1)
            self._setup_stage = 3 if self._setup_stage == 2 else 0
            return True
        if self.command == 0x21:
            x, y = value & 0xFF, value >> 8  # Packed Y is the full high byte.
            if self.window_x is not None and self.window_y is not None:
                if not (self.window_x[0] <= x <= self.window_x[1]
                        and self.window_y[0] <= y <= self.window_y[1]):
                    return self._reject("invalid packed cursor")
            if self._setup_stage == 3 and not self.qualified:
                if (self.mode == 0x1038 and self.window_x == self._GLYPH_X_WINDOW
                        and self.window_y is not None
                        and self.window_y[1] - self.window_y[0] == 15
                        and (x, y) == (1, self.window_y[0])):
                    self._setup_stage = 4
                else:
                    self._setup_stage = 0
            self.cursor = (x, y)
            return True
        return True
