"""Indexed RGB565 GRAM, cursor, and rectangular pixel writes."""
from __future__ import annotations


class Indexed28:
    geometry_source = 'runtime:indexed28'
    protocol = 'indexed28-rgb565'
    disable_fast = True

    def __init__(self, width, height, *, command_port=0x28000000,
                 data_port=0x28000100, x_origin=0, y_origin=0,
                 data_aperture=2):
        if (type(width) is not int or type(height) is not int
                or not 1 < width <= 512 or not 1 < height <= 512):
            raise ValueError('invalid indexed panel dimensions')
        if (type(command_port) is not int or type(data_port) is not int
                or not 0 <= command_port <= 0xfffffffe
                or not 0 <= data_port <= 0xfffffffe
                or command_port % 2 or data_port % 2
                or type(data_aperture) is not int or data_aperture not in (2, 32)
                or command_port < data_port + data_aperture
                and data_port < command_port + 2
                or data_port + data_aperture > 0x100000000):
            raise ValueError('invalid indexed panel ports')
        if (type(x_origin) is not int or type(y_origin) is not int
                or not 0 <= x_origin <= 0xffff - width
                or not 0 <= y_origin <= 0xffff - height):
            raise ValueError('invalid indexed panel origin')
        self.width, self.height = width, height
        self.command_port, self.data_port = command_port, data_port
        self.data_aperture = data_aperture
        self.x_origin, self.y_origin = x_origin, y_origin
        self.rgb = bytearray(width * height * 3)
        self.registers = {}
        self.command = None
        self.written = 0
        self.x = self.y = None

    def _window(self):
        values = tuple(self.registers.get(index) for index in range(0x210, 0x214))
        if (any(value is None for value in values)
                or not self.x_origin <= values[0] <= values[1] < self.x_origin + self.width
                or not self.y_origin <= values[2] <= values[3] < self.y_origin + self.height):
            return None
        return values

    def write(self, address, size, value):
        if address == self.command_port:
            if size != 2 or not 0 <= value <= 0xffff:
                self.command = None
                self.written = 0
                return True, None
            self.command = value
            self.written = 0
            if value == 0x202:
                self.x, self.y = (self.registers.get(index) for index in (0x200, 0x201))
            return True, None
        offset = address - self.data_port
        if not 0 <= offset < self.data_aperture:
            return False, None
        if size == 4 and self.data_aperture == 32:
            if (offset % 4 or address % 4 or offset + size > self.data_aperture
                    or not 0 <= value <= 0xffffffff):
                return False, None
            result = None
            for pixel in (value & 0xffff, value >> 16):
                _, frame = self._write_data(pixel)
                if frame is not None:
                    result = frame
            return True, result
        if (size != 2 or offset % 2 or address % 2
                or offset + size > self.data_aperture or not 0 <= value <= 0xffff):
            self.command = None
            self.written = 0
            return True, None
        return True, self._write_data(value)[1]

    def _write_data(self, value):
        if self.command != 0x202:
            if self.command is not None:
                self.registers[self.command] = value
            return True, None
        window = self._window()
        if window is None or self.x is None or self.y is None:
            return True, None
        x0, x1, y0, y1 = window
        if not x0 <= self.x <= x1 or not y0 <= self.y <= y1:
            return True, None
        offset = 3 * ((self.y - self.y_origin) * self.width
                      + self.x - self.x_origin)
        red, green, blue = value >> 11, value >> 5 & 63, value & 31
        self.rgb[offset:offset + 3] = bytes(((red << 3) | (red >> 2),
            (green << 2) | (green >> 4), (blue << 3) | (blue >> 2)))
        self.x += 1
        if self.x > x1:
            self.x = x0
            self.y += 1
        if self.y > y1:
            self.y = y0
        self.written += 1
        if self.written == (x1 - x0 + 1) * (y1 - y0 + 1):
            self.written = 0
            return True, bytes(self.rgb)
        return True, None
