"""Source-qualified monochrome scanout with an external command/data bit."""
from __future__ import annotations


class MuxPagePanel:
    def __init__(self):
        self.mode = None
        self.reset_position = 0
        self.started = self.qualified = False
        self.enabled = None
        self.dirty = False
        self.rejection = None
        self.page = -1
        self.high = self.column = None
        self.origin = None
        self.start = self.count = self.rows = 0
        self.clear_zero = True
        self.ram = bytearray(10*96)
        self.frame = bytes(96*64*3)
        self.sequence = 0

    def _finish(self):
        if not self.qualified and self.count:
            if (self.page == self.rows and self.count == 96 and self.clear_zero
                    and (self.rows == 0 or self.start == self.origin)):
                if self.rows == 0:
                    self.origin = self.start
                self.rows += 1
                self.qualified = self.rows == 10
            else:
                self.rows = 0
        self.count = 0
        self.clear_zero = True
        if self.qualified and self.enabled and self.dirty:
            self._publish()

    def _publish(self):
        frame = bytearray(96*64*3)
        for page in range(8):
            for x in range(96):
                byte = self.ram[page*96+x]
                for bit in range(8):
                    offset = ((page*8+bit)*96+x)*3
                    frame[offset:offset+3] = bytes([255 if byte & (1 << bit) else 0])*3
        if bytes(frame) != self.frame or not self.sequence:
            self.frame = bytes(frame)
            self.sequence += 1
        self.dirty = False

    def _reset(self):
        self.qualified = False
        self.enabled = None
        self.dirty = False
        self.page = -1
        self.high = self.column = None
        self.origin = None
        self.start = self.count = self.rows = 0
        self.clear_zero = True
        self.ram[:] = bytes(len(self.ram))

    def write(self, address, size, value):
        if self.started and 0x02000000 <= address < 0x02001000 and address != 0x02000000:
            self.rejection = 'foreign-main-aperture-owner'
            return False
        if address not in (0x02000000, 0x02800000) or self.rejection:
            return False
        if size != 1 or not 0 <= value <= 255:
            if self.started:
                self.rejection = 'source-byte-mux-width-required'
            return False
        if address == 0x02800000:
            self.mode = bool(value & 0x10)
            return self.qualified
        if self.mode is None:
            return False
        if not self.started:
            if self.mode:
                self.reset_position = 0
                return False
            prefix = (0, 0xe2, 0xa4)
            if value == prefix[self.reset_position]:
                self.reset_position += 1
                if self.reset_position == len(prefix):
                    self.started = True
                    self.reset_position = 0
                    self._reset()
            else:
                self.reset_position = int(value == prefix[0])
            return False
        if self.mode:
            origin = self.origin if self.qualified else self.start
            logical = self.column-origin if self.column is not None else -1
            if (self.page < 0 or not 0 <= logical < 96
                    or self.column >= 256 or self.count >= 96):
                self.rejection = 'data-outside-source-page-column'
                return False
            index = self.page*96+logical
            self.dirty |= self.ram[index] != value
            self.ram[index] = value
            self.clear_zero &= value == 0
            self.column += 1
            self.count += 1
            return self.qualified
        self._finish()
        if value == 0xe2:
            self._reset()
        elif 0xb0 <= value <= 0xb9:
            self.page = value-0xb0
            self.high = self.column = None
        elif 0x10 <= value <= 0x1f and self.page >= 0:
            self.high = value & 15
            self.column = None
        elif value <= 15 and self.page >= 0 and self.high is not None:
            self.column = self.start = self.high*16+value
            outside = (self.column+96 > 256 if not self.qualified else
                       not self.origin <= self.column < self.origin+96)
            if outside:
                self.rejection = 'column-outside-source-viewport'
        else:
            if value == 0xae:
                self.enabled = False
            if value == 0xaf and self.qualified:
                self.enabled = True
                self._publish()
            self.page = -1
            self.high = self.column = None
        return self.qualified and not self.rejection
