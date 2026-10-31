"""Source-sized 104x80 raster with two byte-valued halfwords per RGB565 pixel."""
from __future__ import annotations


class BytePair565Panel:
    width, height = 104, 80
    window = (0xf8,0xf4,0,0xf5,0,0xf6,103,0xf7,79,0xf9)

    def __init__(self):
        self.step = self.pixels = self.sequence = 0
        self.high = None
        self.enabled = self.active = self.qualified = False
        self.rejection = None
        self.rgb = bytearray([255])*(self.width*self.height*3)
        self.frame = bytes(self.rgb)

    def write(self,address,size,value):
        if address not in (0x02000000,0x02400000) or self.rejection:
            return False
        if size != 2 or not 0 <= value <= 255:
            self.rejection = 'source-halfword-byte-value-required'
            return False
        if address == 0x02000000:
            self.active = False
            self.high = None
            self.pixels = 0
            if value == 0xaf:
                self.enabled = True
                self.step = 0
            elif value == 0xae:
                self.enabled = False
                self.step = 0
            elif value == self.window[self.step]:
                self.step += 1
                if self.step == len(self.window):
                    self.active = self.enabled
                    self.step = 0
            else:
                self.step = int(value == self.window[0])
            return self.qualified
        if not self.active:
            return self.qualified
        if self.high is None:
            self.high = value
            return self.qualified
        pixel = (self.high<<8)|value
        self.high = None
        red,green,blue = (pixel>>11)&31,(pixel>>5)&63,pixel&31
        at = self.pixels*3
        self.rgb[at:at+3] = bytes(((red<<3)|(red>>2),(green<<2)|(green>>4),(blue<<3)|(blue>>2)))
        self.pixels += 1
        if self.pixels == self.width*self.height:
            self.frame = bytes(self.rgb)
            self.sequence += 1
            self.qualified = True
            self.active = False
        return self.qualified
