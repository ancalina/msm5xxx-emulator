"""Packed byte bounds and cursor registers on an indexed RGB565 panel."""
from .indexed28 import Indexed28


class Indexed44(Indexed28):
    geometry_source = 'runtime:indexed44'
    protocol = 'indexed44-rgb565'

    def __init__(self, width, height, *, command_port=0x18000000,
                 data_port=0x18000010, x_origin=0, y_origin=0):
        super().__init__(width, height, command_port=command_port,
            data_port=data_port, x_origin=x_origin, y_origin=y_origin)
        if x_origin + width > 256 or y_origin + height > 256:
            raise ValueError('packed indexed coordinates exceed one byte')

    def _window(self):
        x = self.registers.get(0x44)
        y = self.registers.get(0x45)
        if x is None or y is None:
            return None
        bounds = x & 255, x >> 8, y & 255, y >> 8
        if (not self.x_origin <= bounds[0] <= bounds[1] < self.x_origin + self.width
                or not self.y_origin <= bounds[2] <= bounds[3] < self.y_origin + self.height):
            return None
        return bounds

    def write(self, address, size, value):
        if address == self.command_port and size == 2 and value == 0x202:
            self.command = None
            self.written = 0
            return True, None
        if address == self.command_port and size == 2 and value == 0x22:
            cursor = self.registers.get(0x21)
            for index in (0x200, 0x201):
                self.registers.pop(index, None)
            if cursor is not None:
                self.registers[0x200] = cursor & 255
                self.registers[0x201] = cursor >> 8
            value = 0x202
        return super().write(address, size, value)
