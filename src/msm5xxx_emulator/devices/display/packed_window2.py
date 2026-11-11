"""Byte-addressed, four-cell window transfers on a parallel panel."""
from __future__ import annotations






class PackedWindow2:
    """Observe a configured byte window and complete 2-bit cell transfers."""

    def __init__(self):
        self.row_bounds = None
        self.mode = False
        self.command = None
        self.args = []
        self.header = []
        self.window = None
        self.payload = bytearray()
        self.canvas = None
        self.frame = None

    def write(self, address, size, value):
        """Return a completed (width, height, RGB) frame, if one arrives."""
        if size != 1 or address not in (0x02000000, 0x02000004):
            if self.window is not None:
                self.window = None
                self.payload.clear()
            self.header.clear()
            return None
        value &= 255
        command_port = address == 0x02000000
        if self.window is not None:
            if not command_port:
                self.payload.append(value)
                x0, x1, y0, y1 = self.window
                if len(self.payload) == (x1 - x0 + 1) * (y1 - y0 + 1):
                    result = self._complete()
                    self.window = None
                    self.payload.clear()
                    return result
                return None
            self.window = None
            self.payload.clear()
        if self.mode:
            expected = (0x5c, 0x15, None, None, 0x75, None, None, 0xfb, 7, 0x5c)
            ports = (True, True, False, False, True, False, False, True, True, True)
            pos = len(self.header)
            if command_port == ports[pos] and (expected[pos] is None or value == expected[pos]):
                self.header.append(value)
                if len(self.header) == len(expected):
                    _, _, x0, x1, _, y0, y1, _, _, _ = self.header
                    self.header.clear()
                    width, height = 4 * (x1 - x0 + 1), y1 - y0 + 1
                    if (x0 <= x1 and y0 <= y1 and width <= 320 and height <= 320
                            and (self.canvas is not None
                                 or (width >= 64 and height >= 64
                                     and self.row_bounds == (y0, y1)))):
                        if self.canvas is None or (self.canvas[0] <= x0 <= x1 <= self.canvas[1]
                                                   and self.canvas[2] <= y0 <= y1 <= self.canvas[3]):
                            self.window = (x0, x1, y0, y1)
                            self.payload.clear()
                return None
            self.header = [value] if command_port and value == 0x5c else []
        if command_port:
            self.command, self.args = value, []
        elif self.command == 0xa8 and len(self.args) < 2:
            self.args.append(value)
            if len(self.args) == 2 and self.args[0] <= self.args[1]:
                self.row_bounds = tuple(self.args)
        elif self.command == 0xfb and not self.args:
            self.args.append(value)
            self.mode = value == 7 and self.row_bounds is not None
        return None

    def _complete(self):
        x0, x1, y0, y1 = self.window
        if self.canvas is None:
            self.canvas = self.window
            width, height = 4 * (x1 - x0 + 1), y1 - y0 + 1
            self.frame = bytearray(width * height * 3)
        cx0, cx1, cy0, cy1 = self.canvas
        width, height = 4 * (cx1 - cx0 + 1), cy1 - cy0 + 1
        row_bytes = x1 - x0 + 1
        for i, value in enumerate(self.payload):
            x = 4 * (x0 - cx0 + i % row_bytes)
            y = y0 - cy0 + i // row_bytes
            for j, shift in enumerate((6, 4, 2, 0)):
                gray = ((value >> shift) & 3) * 85
                at = (y * width + x + j) * 3
                self.frame[at:at + 3] = bytes((gray, gray, gray))
        return width, height, bytes(self.frame)
