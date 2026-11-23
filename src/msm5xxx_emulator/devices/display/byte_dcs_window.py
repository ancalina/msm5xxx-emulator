"""Byte-wide DCS windows with RGB565 pixel pairs."""
from .dcs_window import DcsWindow


class ByteDcsWindow(DcsWindow):
    geometry_source = 'runtime:byte-dcs-window'
    protocol = 'byte-dcs-rgb565'

    def __init__(self, width=128, height=128, x_origin=0, y_origin=0):
        super().__init__(width, height, x_origin, y_origin)
        self.byte_parameters = []
        self.pixel_byte = None

    def write(self, address, size, value):
        if address not in (0x40000000, 0x401e0004):
            return False, None
        if size != 1 or type(value) is not int or not 0 <= value <= 0xff:
            self.pending = self.window = self.pixel_byte = None
            self.byte_parameters = []
            self.writing = False
            return True, None
        if address == 0x40000000:
            self.byte_parameters = []
            self.pixel_byte = None
            return super().write(0x02000000, 2, value)
        if self.pending is not None:
            self.byte_parameters.append(value)
            if len(self.byte_parameters) == 2:
                start, end = self.byte_parameters
                self.byte_parameters = []
                axis = self.pending
                if end - start + 1 == (self.width if axis == 0x2a else self.height):
                    previous = self.x_origin if axis == 0x2a else self.y_origin
                    if previous != start:
                        self.seen = bytearray(self.width * self.height)
                        self.seen_count = 0
                    if axis == 0x2a:
                        self.x_origin = start
                    else:
                        self.y_origin = start
                for part in (0, start, 0, end):
                    consumed, frame = super().write(0x02000002, 2, part)
                return consumed, frame
            return True, None
        if self.writing:
            if self.pixel_byte is None:
                self.pixel_byte = value
                return True, None
            pixel = self.pixel_byte << 8 | value
            self.pixel_byte = None
            return super().write(0x02000002, 2, pixel)
        return True, None
