"""Halfword window commands and a separate RGB565 pixel FIFO."""
from __future__ import annotations


class Window51:
    geometry_source = 'runtime:window51'
    protocol = 'window51-rgb565'

    def __init__(self, width, height, x_origin=0, y_origin=0):
        if type(width) is not int or type(height) is not int or not 1 < width <= 255 or not 1 < height <= 255:
            raise ValueError('invalid window dimensions')
        if (type(x_origin) is not int or type(y_origin) is not int
                or not 0 <= x_origin <= 256 - width or not 0 <= y_origin <= 256 - height):
            raise ValueError('invalid window origin')
        self.width, self.height = width, height
        self.x_origin, self.y_origin = x_origin, y_origin
        self.rgb = bytearray(width * height * 3)
        self.bounds = {}
        self.pending = None
        self.parameters = []
        self.cursor = 0
        self.window = None

    def _select_window(self):
        self.cursor = 0
        self.window = None
        if 0x42 in self.bounds and 0x43 in self.bounds:
            x0, x1 = self.bounds[0x43]
            y0, y1 = self.bounds[0x42]
            if (self.x_origin <= x0 <= x1 < self.x_origin + self.width
                    and self.y_origin <= y0 <= y1 < self.y_origin + self.height):
                self.window = (x0, x1, y0, y1)

    def write(self, address, size, value):
        if address not in (0x02000000, 0x02000002):
            return False, None
        if size != 2 or not 0 <= value <= 0xffff:
            self.pending = None
            self.window = None
            return True, None
        if address == 0x02000000:
            if self.pending is not None:
                self.parameters.append(value)
                count = 2 if self.pending in (0x42, 0x43) else 1
                if len(self.parameters) == count:
                    if self.pending in (0x42, 0x43):
                        self.bounds[self.pending] = tuple(self.parameters)
                        self._select_window()
                    self.pending = None
                return True, None
            if value in (0x42, 0x43, 0x60, 0x61):
                self.pending = value
                self.parameters = []
            elif value == 0x51:
                self._select_window()
            return True, None
        if self.window is None:
            return True, None
        x0, x1, y0, y1 = self.window
        width = x1 - x0 + 1
        expected = width * (y1 - y0 + 1)
        x, y = x0 + self.cursor % width, y0 + self.cursor // width
        offset = 3 * ((y - self.y_origin) * self.width + x - self.x_origin)
        red, green, blue = value >> 11, (value >> 5) & 63, value & 31
        self.rgb[offset:offset + 3] = bytes(((red << 3) | (red >> 2),
                                           (green << 2) | (green >> 4),
                                           (blue << 3) | (blue >> 2)))
        self.cursor += 1
        if self.cursor == expected:
            self.cursor = 0
            return True, bytes(self.rgb)
        return True, None
