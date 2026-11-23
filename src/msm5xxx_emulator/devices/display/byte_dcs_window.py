"""Byte-wide DCS windows with RGB565 pixel pairs."""
from .dcs_window import DcsWindow


class ByteDcsWindow(DcsWindow):
    geometry_source = 'runtime:byte-dcs-window'
    protocol = 'byte-dcs-rgb565'

    def __init__(self, width=128, height=128, x_origin=0, y_origin=0):
        super().__init__(width, height, x_origin, y_origin)
        self.byte_parameters = []
        self.pixel_byte = None
        self.address_mode = 0
        self.address_mode_pending = False
        self.standard_window = False
        self.orientation_reference = None

    def _oriented(self, frame):
        mode = self.address_mode ^ (self.orientation_reference or 0)
        if frame is None or not mode & 0xe0:
            return frame
        if mode & 0x20 and self.width != self.height:
            return None
        rotated = bytearray(len(frame))
        for y in range(self.height):
            for x in range(self.width):
                dx, dy = (y, x) if mode & 0x20 else (x, y)
                if mode & 0x40:
                    dx = self.width - dx - 1
                if mode & 0x80:
                    dy = self.height - dy - 1
                source = (y * self.width + x) * 3
                target = (dy * self.width + dx) * 3
                rotated[target:target + 3] = frame[source:source + 3]
        return bytes(rotated)

    def _window_parameters(self):
        values = self.byte_parameters
        self.byte_parameters = []
        if len(values) == 2:
            values = (0, values[0], 0, values[1])
        elif len(values) == 4:
            self.standard_window = True
        if len(values) != 4:
            self.pending = None
            return
        start = values[0] << 8 | values[1]
        end = values[2] << 8 | values[3]
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
        for part in values:
            super().write(0x02000002, 2, part)

    def write(self, address, size, value):
        if address not in (0x40000000, 0x401e0004):
            return False, None
        if size != 1 or type(value) is not int or not 0 <= value <= 0xff:
            self.pending = self.window = self.pixel_byte = None
            self.byte_parameters = []
            self.address_mode_pending = False
            self.writing = False
            return True, None
        if address == 0x40000000:
            if self.pending is not None:
                self._window_parameters()
            self.byte_parameters = []
            self.pixel_byte = None
            self.address_mode_pending = value == 0x36
            consumed, frame = super().write(0x02000000, 2, value)
            return consumed, self._oriented(frame)
        if self.address_mode_pending:
            self.address_mode_pending = False
            self.address_mode = value
            # shortcut: standard-panel mounting follows its first address mode;
            # upgrade when the board's physical orientation is identified.
            if self.standard_window and self.orientation_reference is None:
                self.orientation_reference = value & 0xe0
            return True, None
        if self.pending is not None:
            self.byte_parameters.append(value)
            if len(self.byte_parameters) == 4:
                self._window_parameters()
            return True, None
        if self.writing:
            if self.pixel_byte is None:
                self.pixel_byte = value
                return True, None
            pixel = self.pixel_byte << 8 | value
            self.pixel_byte = None
            consumed, frame = super().write(0x02000002, 2, pixel)
            return consumed, self._oriented(frame)
        return True, None
