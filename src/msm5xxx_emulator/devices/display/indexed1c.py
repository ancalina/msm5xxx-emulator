"""Indexed halfword GRAM stream observed on the 1C display bus."""
from __future__ import annotations


class Indexed1C:
    geometry_source = 'runtime:indexed1c'
    protocol = 'indexed1c-rgb565'
    disable_fast = True

    def __init__(self, width, height, *, command_port=0x02000000,
                 data_port=0x02000004):
        if (type(width) is not int or type(height) is not int
                or not 1 < width <= 512 or not 1 < height <= 512):
            raise ValueError('invalid indexed panel dimensions')
        if (type(command_port) is not int or type(data_port) is not int
                or not 0 <= command_port <= 0xfffffffe
                or not 0 <= data_port <= 0xfffffffe
                or command_port % 2 or data_port % 2
                or command_port == data_port):
            raise ValueError('invalid indexed panel ports')
        self.width, self.height = width, height
        self.command_port, self.data_port = command_port, data_port
        self.rgb = bytearray(width * height * 3)
        self.seen = bytearray(width * height)
        self.seen_count = 0
        self.registers = {}
        self.command = None
        self.written = 0
        self.x = self.y = None

    def _window(self):
        x0, y0, x1, y1 = (self.registers.get(index)
                          for index in (0x220, 0x222, 0x224, 0x226))
        values = (x0, x1, y0, y1)
        if (any(value is None for value in values)
                or not 0 <= values[0] <= values[1] < self.width
                or not 0 <= values[2] <= values[3] < self.height):
            return None
        return values

    def write(self, address, size, value):
        if address == self.command_port:
            if size != 2 or type(value) is not int or not 0 <= value <= 0xffff:
                self.command = None
                self.written = 0
                return True, None
            self.command = value
            self.written = 0
            if value == 0x28:
                window = self._window()
                self.x, self.y = (window[0], window[2]) if window else (None, None)
            return True, None
        if address != self.data_port:
            return False, None
        if size != 2 or type(value) is not int or not 0 <= value <= 0xffff:
            self.command = None
            self.written = 0
            return True, None
        if self.command != 0x28:
            if self.command is not None:
                self.registers[self.command] = value
            return True, None
        window = self._window()
        if window is None or self.x is None or self.y is None:
            return True, None
        x0, x1, y0, y1 = window
        if not x0 <= self.x <= x1 or not y0 <= self.y <= y1:
            return True, None
        offset = 3 * (self.y * self.width + self.x)
        red, green, blue = value >> 11, (value >> 5) & 63, value & 31
        self.rgb[offset:offset + 3] = bytes((
            (red << 3) | (red >> 2),
            (green << 2) | (green >> 4),
            (blue << 3) | (blue >> 2)))
        at = self.y * self.width + self.x
        if not self.seen[at]:
            self.seen[at] = 1
            self.seen_count += 1
        self.x += 1
        if self.x > x1:
            self.x = x0
            self.y += 1
        if self.y > y1:
            self.y = y0
        self.written += 1
        if (self.written == (x1 - x0 + 1) * (y1 - y0 + 1)
                and self.seen_count == self.width * self.height):
            self.written = 0
            return True, bytes(self.rgb)
        return True, None
