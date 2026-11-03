"""Bounded source-admitted legacy windows and raw direct VRAM previews.

Only actual bus writes populate retained RAM. No frame is exposed before every
pixel (every byte for direct VRAM) has been covered. A new window can finish a
source producer's short prefix without claiming its unwritten remainder.
"""
from __future__ import annotations


class LegacyPanel:
    port = 0x02800000

    def __init__(self, protocol: str):
        self.protocol = protocol
        self.width, self.height, self.bits = {
            'byte31': (128, 128, 8), 'column16': (128, 160, 16),
            'direct16': (176, 220, 16), 'half43': (128, 144, 16),
            'byte565_boot': (120, 133, 16),
        }[protocol]
        if protocol == 'byte565_boot':
            self.port = 0x02000000
        self.byte565_phase = 0
        self.byte565_low = None
        self.sequence = 0
        self.frame = b''
        self.qualified = False
        self.rejection = None
        self.ram = bytearray(self.width*self.height*3)
        count = self.width*self.height*(2 if protocol == 'direct16' else 1)
        self.covered = bytearray(count)
        self.coverage = 0
        self.raw = bytearray(count) if protocol == 'direct16' else None
        self.window = None
        self.cursor = 0
        self.column_major = False
        self.mode = None
        self.pending = None
        self.args = []
        self.axes = {}
        self.origin = None
        self.dirty = False

    def _publish(self):
        if self.dirty and self.coverage == len(self.covered):
            self.qualified = True
            self.frame = bytes(self.ram)
            self.sequence += 1
        self.dirty = False

    def _finish(self):
        self._publish()
        self.window = None
        self.cursor = 0

    def _begin(self, window, *, rows=None):
        x0,y0,x1,y1 = window
        self._finish()
        if rows is None:
            rows = self.height
        if 0 <= x0 <= x1 < self.width and 0 <= y0 <= y1 < rows:
            self.window = window

    def _rgb(self, value):
        if self.bits == 8:
            return bytes(((value>>5)*255//7, (value>>2&7)*255//7, (value&3)*255//3))
        return bytes(((value>>11)*255//31, (value>>5&63)*255//63, (value&31)*255//31))

    def _pixel(self, value):
        if self.window is None:
            return
        x0,y0,x1,y1 = self.window
        w,h = x1-x0+1,y1-y0+1
        i = self.cursor
        if self.column_major:
            x,y = x0+i//h,y0+i%h
        else:
            x,y = x0+i%w,y0+i//w
        # Controller address RAM can extend below the visible glass. Its
        # cursor still advances there, but those writes cover no visible pixel.
        if y < self.height:
            at = y*self.width+x
            if not self.covered[at]:
                self.covered[at] = 1
                self.coverage += 1
            self.ram[at*3:at*3+3] = self._rgb(value)
            self.dirty = True
        self.cursor += 1
        if self.cursor == w*h:
            self._finish()

    def write(self, address: int, size: int, value: int):
        if self.protocol == 'direct16':
            self._direct(address, size, value)
        elif self.protocol == 'byte31':
            self._byte31(address, size, value)
        elif self.protocol == 'half43':
            self._half43(address, size, value)
        elif self.protocol == 'byte565_boot':
            self._byte565_boot(address, size, value)
        else:
            self._column16(address, size, value)

    def _byte565_boot(self, address, size, value):
        """Retain one complete byte-pair boot canvas after its observed setup."""
        if address not in (self.port, self.port + 2):
            return
        if size != 1 or not 0 <= value <= 255:
            self.byte565_phase = 0
            self.byte565_low = None
            self.window = None
            return
        if address == self.port + 2:
            self.window = None
            self.byte565_low = None
            self.byte565_phase = (1 if value == 8 else
                                  3 if value == 9 and self.byte565_phase == 2 else 0)
            return
        if self.byte565_phase == 1:
            self.byte565_phase = 2 if value == 0 else 0
        elif self.byte565_phase == 2:
            self.byte565_phase = 0
        elif self.byte565_phase == 3:
            if value != 0x40:
                self.byte565_phase = 0
                return
            # Do not assemble a full frame from separate partial transfers.
            self.covered = bytearray(len(self.covered))
            self.coverage = 0
            self.ram = bytearray(len(self.ram))
            self._begin((0, 0, self.width - 1, self.height - 1))
            self.byte565_phase = 4
        elif self.byte565_phase == 4:
            if self.byte565_low is None:
                self.byte565_low = value
            else:
                pixel = self.byte565_low | value << 8
                self.byte565_low = None
                self._pixel(pixel)
                if self.window is None:
                    self.byte565_phase = 0

    def _direct(self, address, size, value):
        off = address-self.port
        if size not in (1,2,4) or not 0 <= value < 1 << (8*size):
            return
        if not 0 <= off <= len(self.raw)-size:
            return
        self.raw[off:off+size] = value.to_bytes(size,'little')
        for at in range(off,off+size):
            if not self.covered[at]:
                self.covered[at] = 1
                self.coverage += 1
        for pixel in range(off//2,(off+size-1)//2+1):
            v = int.from_bytes(self.raw[pixel*2:pixel*2+2],'little')
            self.ram[pixel*3:pixel*3+3] = self._rgb(v)
        self.dirty = True
        if off+size == len(self.raw):
            self._publish()

    def _byte31(self, address, size, value):
        if address not in (self.port,self.port+4):
            return
        if size != 1 or not 0 <= value <= 255:
            self._finish();self.pending=None;self.axes={}
            return
        if address == self.port+4:
            if self.pending is None:
                self._pixel(value)
            return
        if self.pending is not None:
            self.args.append(value)
            needed = 1 if self.pending == 7 else 2
            if len(self.args) < needed:
                return
            if self.pending == 7:
                self.mode = value
                self.column_major = value == 0x2d
            else:
                self.axes[self.pending] = tuple(self.args)
            self.pending = None
            self.args = []
            if len(self.axes) == 2 and self.mode in (0x0d,0x2d):
                x0,x1 = self.axes[0x31];y0,y1 = self.axes[0x21]
                self._begin((x0,y0,x1,y1));self.axes={}
            return
        self._finish()
        if value in (7,0x31,0x21):
            self.pending = value
            self.args = []
            if value == 7:
                self.axes = {}
        else:
            self.axes = {}

    def _column16(self, address, size, value):
        if address not in (self.port,self.port+4):
            return
        if size != 2 or not 0 <= value <= 65535:
            self._finish();self.pending=None;self.axes={}
            return
        if address == self.port:
            self._finish()
            if value in (0x75,0x15):
                self.pending = value;self.args = []
                if value == 0x75:
                    self.axes = {}
            elif value == 0x5c and set(self.axes) == {0x75,0x15}:
                y0,y1 = self.axes[0x75]
                lo0,hi0,lo1,hi1 = self.axes[0x15]
                x0,x1 = lo0|hi0<<8,lo1|hi1<<8
                # The admitted boot producer programs rows 0..175 but sends
                # only the 128x160 visible prefix; command 63 receives 160.
                choices = [(x,y) for x,y in ((140,0),(4,16))
                           if x <= x0 <= x1 < x+128 and
                           y <= y0 <= y1 < y+(176 if (x,y) == (140,0) else 160)]
                if len(choices) == 1:
                    origin = choices[0]
                    if self.origin is not None and origin != self.origin:
                        self.covered = bytearray(len(self.covered));self.coverage=0
                        self.ram = bytearray(len(self.ram));self.qualified=False
                    self.origin = origin
                    self._begin((x0-origin[0],y0-origin[1],x1-origin[0],y1-origin[1]),
                                rows=176 if origin == (140,0) else 160)
                self.pending = None;self.axes={}
            else:
                self.pending = None;self.axes={}
            return
        if self.pending is not None:
            if value > 255:
                self.pending=None;self.axes={};return
            self.args.append(value)
            if len(self.args) == (2 if self.pending == 0x75 else 4):
                self.axes[self.pending] = tuple(self.args);self.pending=None
        else:
            self._pixel(value)

    def _half43(self, address, size, value):
        if address not in (self.port,self.port+2):
            return
        if address == self.port+2:
            if size == 2 and 0 <= value <= 65535 and self.pending is None:
                self._pixel(value)
            return
        if size != 1 or not 0 <= value <= 255:
            self._finish();self.pending=None;self.axes={}
            return
        if self.pending is not None:
            self.args.append(value)
            if len(self.args) == 2:
                self.axes[self.pending] = tuple(self.args)
                self.pending = None;self.args=[]
                if set(self.axes) == {0x43,0x42}:
                    x0,x1=self.axes[0x43];y0,y1=self.axes[0x42]
                    self._begin((x0,y0,x1,y1));self.axes={}
            return
        self._finish()
        if value in (0x43,0x42):
            self.pending=value;self.args=[]
        else:
            self.axes={}
