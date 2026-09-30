"""Independent scanout for the descriptor-bound 96x64 page-panel class."""
from __future__ import annotations


class PagePanel:
    def __init__(self, port: int) -> None:
        self.port = port
        self.ram = bytearray(8 * 256)
        self.page = -1
        self.high: int | None = None
        self.column: int | None = None
        self.start = 0
        self.count = 0
        self.last_row: tuple[int, int] | None = None
        self.bias: int | None = None
        self.committed = False
        self.enabled: bool | None = None
        self.argument = False
        self.dirty = False
        self.frame = bytes(96 * 64 * 3)
        self.rejection: str | None = None
        self.pending: list[tuple[int, int, int]] = []

    def _finish_row(self) -> None:
        if self.count:
            if self.count == 96 and self.start <= 160:
                if self.last_row == (self.page - 1, self.start):
                    if self.bias is None:
                        self.bias = self.start
                        self.dirty = True
                self.last_row = (self.page, self.start)
            elif self.bias is None:
                self.last_row = None
        self.flush()
        self.count = 0

    def write(self, address: int, size: int, value: int) -> bool:
        """False means unsupported grammar; caller restores its native fallback."""
        if size not in (1, 2) or not 0 <= value <= 255:
            self.rejection = "non-byte page transfer"
            return False
        if address == self.port + 4:
            if self.column is None or self.page < 0 or self.column >= 256:
                self.rejection = "data without bounded page/column"
                return False
            self.ram[self.page * 256 + self.column] = value
            self.column += 1
            self.count += 1
            self.dirty = True
            return True
        if address != self.port:
            self.rejection = "unbound port"
            return False
        self._finish_row()
        if self.argument:
            self.argument = False  # Contrast argument is not a column command.
            return True
        if 0xB0 <= value <= 0xB7:
            self.page = value - 0xB0
            self.high = None
            self.column = None
        elif 0x10 <= value <= 0x1F:
            self.high = value & 15
            self.column = None
        elif value <= 15 and self.high is not None:
            self.column = self.start = self.high * 16 + value
        else:
            self.high = None
            self.column = None
            if value in (0xAE, 0xAF):
                self.enabled = value == 0xAF
            elif value == 0x81:
                self.argument = True
            elif (0x20 <= value <= 0x27 or 0x2C <= value <= 0x2F
                  or 0x40 <= value <= 0x7F
                  or value in (0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
                               0xA6, 0xA7, 0xC0, 0xC8, 0xE3)):
                pass
            else:
                self.rejection = f"unsupported page command {value:#04x}"
                return False
        return True

    def flush(self) -> None:
        if self.bias is None or not self.dirty:
            return
        # Experimental raw page-RAM view: orientation/optical polarity still
        # require panel evidence. Power state is exposed separately, never
        # inferred from nonzero pixels or a host fold request.
        frame = bytearray(96 * 64 * 3)
        for page in range(8):
            for x in range(96):
                value = self.ram[page * 256 + self.bias + x]
                for bit in range(8):
                    offset = ((page * 8 + bit) * 96 + x) * 3
                    shade = 255 if value & (1 << bit) else 0
                    frame[offset:offset + 3] = bytes((shade,)) * 3
        self.frame = bytes(frame)
        self.dirty = False
