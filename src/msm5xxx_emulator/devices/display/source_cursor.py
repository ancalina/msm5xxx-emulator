"""Source-linked packed cursor on a selector-controlled display."""
from __future__ import annotations




class SourcePackedCursor:
    def __init__(self):
        self.stage = 0

    def coordinate(self, command, value, x_window, y_window, geometry):
        if command == 1:
            self.stage = 1 if value == 0x090c else 0
        elif command == 2:
            self.stage = 2 if self.stage in (1, 2) and value == 0x0200 else 0
        elif command == 3:
            self.stage = 3 if self.stage in (2, 3) and value == 0x1030 else 0
        elif command == 0:
            self.stage = 0
        if (command != 0x21 or self.stage != 3 or geometry != (128, 160)
                or x_window != [0, 127] or y_window != [0, 159]
                or not 0 <= value <= 0xffff):
            return None
        x, y = value & 0xff, value >> 8
        return (x, y) if x < 128 and y < 160 else None
