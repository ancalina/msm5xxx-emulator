"""Packed register window followed by the complete source RGB565 boot blit."""
from __future__ import annotations


class Rgb565BootPanel:
    width, height = 120, 133
    window = (0x047d, 0x0584, 0x0606, 0x0700)

    def __init__(self):
        self.step = self.pixels = self.sequence = 0
        self.active = self.qualified = False
        self.rejection = None
        self.rgb = bytearray(self.width * self.height * 3)
        self.frame = bytes(self.rgb)

    def write(self, address, size, value):
        if address not in (0x02000000, 0x02000002) or self.rejection:
            return False
        if size != 2 or not 0 <= value <= 0xffff:
            self.rejection = 'source-halfword-required'
            return False
        if address == 0x02000002:
            if value == 0x1819 and self.active and self.pixels == self.width*self.height:
                self.frame = bytes(self.rgb)
                self.sequence += 1
                self.qualified = True
                self.active = False
            elif value == self.window[self.step]:
                self.active = False
                self.pixels = 0
                self.step += 1
                if self.step == len(self.window):
                    self.step = 0
                    self.pixels = 0
                    self.active = True
            else:
                self.step = int(value == self.window[0])
                self.active = False
                self.pixels = 0
            return self.qualified
        if not self.active:
            return self.qualified
        if self.pixels >= self.width*self.height:
            self.rejection = 'pixels-outside-source-window'
            return False
        r, g, b = (value >> 11) & 31, (value >> 5) & 63, value & 31
        offset = self.pixels*3
        self.rgb[offset:offset+3] = bytes(((r<<3)|(r>>2), (g<<2)|(g>>4), (b<<3)|(b>>2)))
        self.pixels += 1
        return self.qualified
