"""Source-gated descending 96-column page panel; optical properties provisional."""
from __future__ import annotations
from .page_panel import PagePanel


class ArmPagePanel(PagePanel):
    data_offset = 2
    pending_limit = 2048

    def __init__(self, port: int, source_profile: dict | None = None) -> None:
        super().__init__(port)
        self.source_profile = source_profile
        self.source_validated = False
        self.started = False
        self.complete_pages: set[int] = set()

    def _finish_row(self) -> None:
        if self.count:
            if self.count == 96 and self.start <= 160:
                if self.last_row != (self.page + 1, self.start):
                    self.complete_pages.clear()
                self.complete_pages.add(self.page)
                if self.bias is None and self.complete_pages == set(range(8)):
                    self.bias = self.start
                    self.dirty = True
                self.last_row = (self.page, self.start)
            elif self.bias is None:
                self.last_row = None
                self.complete_pages.clear()
        self.flush()
        self.count = 0

    def write(self, address: int, size: int, value: int) -> bool:
        if size != 1 or not 0 <= value <= 255:
            self.rejection = 'non-byte page transfer'
            return False
        if address not in (self.port, self.port + self.data_offset):
            self.rejection = 'unbound port'
            return False
        if address == self.port + self.data_offset:
            if self.column is None or self.page < 0 or self.column >= 256 or self.count >= 104:
                self.rejection = 'data without bounded page/column'
                return False
            self.ram[self.page * 256 + self.column] = value
            self.column += 1
            self.count += 1
            self.dirty = True
            return True
        if address == self.port and value < 16 and self.high is None and not self.argument:
            self._finish_row()
            self.column = self.start = value
            return True
        if address == self.port and value == 0xe2:
            self._finish_row()
            self.page, self.high, self.column, self.argument = -1, None, None, False
            return True
        return super().write(address, size, value)

    def flush(self) -> None:
        if self.bias is None or not self.dirty:
            return
        frame = bytearray(96 * 64 * 3)
        for page in range(8):
            for x in range(96):
                value = self.ram[page * 256 + self.bias + x]
                for bit in range(8):
                    # Readable source orientation; physical glass is unverified.
                    y = 63 - (page * 8 + bit)
                    shade = 0 if value & (1 << bit) else 255
                    offset = (y * 96 + x) * 3
                    frame[offset:offset + 3] = bytes((shade,)) * 3
        self.frame = bytes(frame)
        self.dirty = False
