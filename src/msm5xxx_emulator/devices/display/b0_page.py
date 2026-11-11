"""Linked two-plane page writer and its observed page stream."""
from __future__ import annotations





class PairedPage:
    height = 128
    def __init__(self, width=128, access_width=2):
        if (width, access_width) not in ((128, 2), (120, 1)):
            raise ValueError("unsupported source page layout")
        self.width, self.access_width = width, access_width
        self.ram = bytearray(16*128*2)
        self.rgb = bytearray(width*128*3)
        self.page = self.high = self.low = self.column = None
        self.plane = 0
        self.seen = bytearray(len(self.ram))
        self.seen_count = 0
        self.qualified = False

    def write(self, address, size, value):
        """Return ownership and an optional frame from actual writes."""
        if address not in (0x02000000, 0x02000002):
            return False, None
        if size != self.access_width or not 0 <= value <= 255:
            self.page = self.column = None
            return False, None
        if address == 0x02000000:
            if 0xb0 <= value <= 0xbf:
                self.page = value - 0xb0
                self.high = self.low = self.column = None
                self.plane = 0
            elif 0x10 <= value <= 0x1f:
                self.high = (value & 15) << 4
                self.column = None if self.low is None else self.high | self.low
                self.plane = 0
            elif 0 <= value <= 15:
                self.low = value
                self.column = None if self.high is None else self.high | self.low
                self.plane = 0
            else:
                self.page = self.high = self.low = self.column = None
                self.plane = 0
            return True, None
        if self.page is None or self.column is None or self.column >= 128:
            return True, None
        at = (self.page * 128 + self.column) * 2 + self.plane
        self.ram[at] = value
        if not self.seen[at]:
            self.seen[at] = 1
            self.seen_count += 1
        self.plane += 1
        complete_pair = self.plane == 2
        if complete_pair:
            self.plane = 0
            if self.column < self.width:
                self._render(self.page, self.column)
            self.column += 1
        if not self.qualified and self.seen_count == len(self.seen):
            self.qualified = True
            return True, bytes(self.rgb)
        if self.qualified and complete_pair:
            return True, bytes(self.rgb)
        return True, None

    def _render(self, page, column):
        cell = (page * 128 + column) * 2
        a, b = self.ram[cell:cell+2]
        for bit in range(8):
            level = ((a >> bit) & 1) * 2 + ((b >> bit) & 1)
            shade = 255 - level * 85
            at = ((page * 8 + bit) * self.width + column) * 3
            self.rgb[at:at+3] = bytes((shade, shade, shade))






class MonoPage:
    width, height = 128, 64
    def __init__(self):
        self.ram = bytearray(8*128)
        self.rgb = bytearray(128*64*3)
        self.page = self.high = self.low = self.column = None
        self.seen = bytearray(len(self.ram))
        self.seen_count = 0
        self.qualified = False

    def write(self, address, size, value):
        if address not in (0x02000000, 0x02200002):
            return False, None
        if size != 1 or not 0 <= value <= 255:
            self.page = self.column = None
            return False, None
        if address == 0x02000000:
            if 0xb0 <= value <= 0xb7:
                self.page = value - 0xb0
                self.high = self.low = self.column = None
            elif 0x10 <= value <= 0x1f:
                self.high = (value & 15) << 4
                self.column = None if self.low is None else self.high | self.low
            elif 0 <= value <= 15:
                self.low = value
                self.column = None if self.high is None else self.high | self.low
            else:
                self.page = self.high = self.low = self.column = None
            return True, None
        if self.page is None or self.column is None or self.column >= 128:
            return True, None
        at = self.page * 128 + self.column
        self.ram[at] = value
        if not self.seen[at]:
            self.seen[at] = 1
            self.seen_count += 1
        for bit in range(8):
            shade = 0 if (value >> bit) & 1 else 255
            off = ((self.page*8+bit)*128+self.column)*3
            self.rgb[off:off+3] = bytes((shade,shade,shade))
        self.column += 1
        if not self.qualified and self.seen_count == len(self.seen):
            self.qualified = True
            return True, bytes(self.rgb)
        return True, bytes(self.rgb) if self.qualified else None




class OffsetMonoPage(MonoPage):
    def write(self, address, size, value):
        if address not in (0x02000000,0x02000002):
            return False,None
        if size != 1 or not 0 <= value <= 255:
            self.page = self.column = None
            return False,None
        if address == 0x02000000:
            if 0xb0 <= value <= 0xbd:
                self.page = value-0xb0
                self.high = self.low = self.column = None
            elif 0x10 <= value <= 0x1f:
                self.high = (value & 15) << 4
                self.column = None if self.low is None else self.high | self.low
            elif 0 <= value <= 15:
                self.low = value
                self.column = None if self.high is None else self.high | self.low
            else:
                self.page = self.high = self.low = self.column = None
            return True,None
        if self.page is None or self.column is None or self.column >= 160:
            return True,None
        page, column = self.page-2, self.column-16
        self.column += 1
        if not (0 <= page < 8 and 0 <= column < 128):
            return True,None
        at = page*128+column
        self.ram[at] = value
        if not self.seen[at]:
            self.seen[at] = 1
            self.seen_count += 1
        for bit in range(8):
            shade = 0 if (value >> bit) & 1 else 255
            off = ((page*8+bit)*128+column)*3
            self.rgb[off:off+3] = bytes((shade,shade,shade))
        if not self.qualified and self.seen_count == len(self.seen):
            self.qualified = True
            return True, bytes(self.rgb)
        return True, bytes(self.rgb) if self.qualified else None
