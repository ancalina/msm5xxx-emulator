"""DCS command/data windows with complete, observed RGB565 scanout."""
from __future__ import annotations

from .window51 import Window51


class DcsWindow(Window51):
    geometry_source = 'runtime:dcs-window'
    protocol = 'dcs-rgb565'

    def __init__(self, width, height, x_origin=0, y_origin=0):
        super().__init__(width, height, x_origin, y_origin)
        self.display_on = False
        self.writing = False
        self.seen = bytearray(width * height)
        self.seen_count = 0

    def write(self, address, size, value):
        if address not in (0x02000000, 0x02000002):
            return False, None
        if size != 2 or type(value) is not int or not 0 <= value <= 0xffff:
            self.pending = None
            self.writing = False
            self.window = None
            return True, None
        if address == 0x02000000:
            self.pending = None
            self.writing = False
            if value == 1:
                self.__init__(self.width, self.height, self.x_origin, self.y_origin)
            elif value in (0x2a, 0x2b):
                self.pending = value
                self.parameters = []
            elif value == 0x2c:
                self._select_window()
                self.writing = self.window is not None
            elif value in (0x10, 0x28):
                self.display_on = False
            elif value == 0x29:
                self.display_on = True
                if self.seen_count == len(self.seen):
                    return True, bytes(self.rgb)
            return True, None
        if self.pending is not None:
            if value > 255:
                self.bounds.pop(0x43 if self.pending == 0x2a else 0x42, None)
                self.pending = None
                self.window = None
                return True, None
            self.parameters.append(value)
            if len(self.parameters) == 4:
                start = self.parameters[0] << 8 | self.parameters[1]
                end = self.parameters[2] << 8 | self.parameters[3]
                self.bounds[0x43 if self.pending == 0x2a else 0x42] = (start, end)
                self.pending = None
            return True, None
        if not self.writing or self.window is None:
            return True, None
        x0, x1, y0, y1 = self.window
        width = x1 - x0 + 1
        pixel = ((y0 + self.cursor // width - self.y_origin) * self.width
                 + x0 + self.cursor % width - self.x_origin)
        if not self.seen[pixel]:
            self.seen[pixel] = 1
            self.seen_count += 1
        consumed, frame = super().write(address, size, value)
        return consumed, frame if self.display_on and self.seen_count == len(self.seen) else None
