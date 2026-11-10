"""Temporary producer-bound FA split RGB565 observer."""
from __future__ import annotations
from msm5xxx_emulator.detection.registry import device_domain
find_split565_port = device_domain("display.split565").find_split565_port

def decode_split565(first: int, second: int) -> int:
    if not 0 <= first <= 3 or not 0 <= second <= 0xffff or second & 0x1001:
        raise ValueError('invalid-split565-pair')
    return first << 14 | (second >> 2 & 0x3800) | (second >> 1 & 0x7ff)

class Split565Panel:
    """Observe complete 120x160 rasters independently of native decoding."""

    def __init__(self, port: int = 0x02000000) -> None:
        if port != 0x02000000:
            raise ValueError('unproved split565 bus')
        self.port = port
        self.width, self.height = 120, 160
        self.enabled = None
        self.reset()

    def snapshot(self) -> dict[str, object]:
        return {"width": self.width, "height": self.height,
                "frame": self.frame, "qualified": self.qualified,
                "enabled": self.enabled, "port": self.port,
                "rejection": self.rejection, "observation": self.observation,
                "sequence": self.sequence}

    def reset(self) -> None:
        self.frame = b''
        self.sequence = 0
        self.qualified = False
        self.rejection: str | None = None
        self.observation = 'awaiting-full-raster'
        self._order: list[int] = []
        self._window = False
        self._words: list[int] = []

    def _reject(self, reason: str) -> None:
        self.rejection = self.observation = reason
        self.qualified = False
        self._order.clear()
        self._words.clear()
        self._window = False

    def flush(self) -> None:
        if self.rejection or len(self._words) != 38400:
            return
        frame = bytearray(120*160*3)
        for index in range(0,38400,2):
            pixel = decode_split565(self._words[index], self._words[index+1])
            frame[index//2*3:index//2*3+3] = bytes((
                (pixel >> 8 & 248) | (pixel >> 13),
                (pixel >> 3 & 252) | (pixel >> 9 & 3),
                (pixel << 3 & 248) | (pixel >> 2 & 7)))
        self.frame = bytes(frame)
        self.sequence += 1
        self.qualified = True
        self.observation = 'complete-split565-raster'
        self._words.clear()
        self._window = False

    def write(self, address: int, size: int, value: int) -> None:
        if self.rejection or address not in (self.port+0x78,self.port+0xfa):
            return
        if size != 2 or not 0 <= value <= 65535:
            self._reject('invalid-halfword-transfer')
            return
        if address == self.port+0x78:
            self.flush()
            if self._words:
                self._reject('incomplete-raster')
                return
            register = value >> 8
            if register in (2,8):
                self._order = [value]
                self._window = False
            elif self._order and register == (self._order[0] >> 8)+len(self._order):
                self._order.append(value)
            else:
                self._order.clear()
            if len(self._order) == 4:
                a,b,c,d = [word & 255 for word in self._order]
                bounds = (a,b,c,d) if self._order[0] >> 8 == 2 else (a,c,b,d)
                self._order.clear()
                if bounds != (0,0,119,159):
                    self._reject('unsupported-window')
                else:
                    self._window = True
            return
        if not self._window:
            self._reject('missing-full-window')
            return
        if len(self._words) >= 38400:
            self._reject('raster-overflow')
            return
        if (value > 3 if len(self._words)%2 == 0 else value & 0x1001):
            self._reject('invalid-split565-pair')
            return
        self._words.append(value)
