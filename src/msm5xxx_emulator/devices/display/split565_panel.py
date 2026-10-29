"""Temporary producer-bound FA split RGB565 observer."""
from __future__ import annotations
import struct

_PRODUCER = bytes.fromhex(
    'b200d4e04027a0e1ba2fc3e1e02d00e20221a0e1f80cc0e3800082e1ba0fc3e1')
_WINDOW_HELPER = bytes.fromhex(
    'f0402de90370a0e10260a0e10150a0e10040a0e1b80c00eb770066e2800f80e3'
    '8067a0e3b807c6e1b30c00ebc00f85e3b807c6e1b00c00eb770064e2400e80e3'
    'b807c6e1ac0c00eb500e87e3b807c6e1f040bde81eff2fe1')


def find_split565_port(image: bytes) -> tuple[int | None, str]:
    """Require producer, base register, 120-wide loop and linked window helper."""
    witnesses = []
    start = 0
    while (offset := image.find(_PRODUCER, start)) >= 0:
        start = offset+1
        if offset < 76 or offset % 4:
            continue
        if (image[offset-76:offset-64] != bytes.fromhex('7720a0e30610a0e10000a0e3')
                or image[offset-52:offset-48] != bytes.fromhex('80a7a0e3')
                or image[offset-16:offset-12] != bytes.fromhex('0a30a0e1')
                or image[offset-8:offset-4] != bytes.fromhex('7810a0e3')
                or image[offset+228:offset+260] != _PRODUCER
                or image[offset+296:offset+300] != bytes.fromhex('a00056e3')):
            continue
        call = struct.unpack_from('<I', image, offset-64)[0]
        if call >> 24 != 0xeb:
            continue
        displacement = call & 0xffffff
        if displacement & 0x800000:
            displacement -= 0x1000000
        target = offset-64+8+displacement*4
        helper = image[target:target+len(_WINDOW_HELPER)] if target >= 0 else b''
        if len(helper) != len(_WINDOW_HELPER):
            continue
        valid = True
        for index in range(0, len(helper), 4):
            if index in (20,40,52,68):
                valid &= helper[index+3] == 0xeb
            else:
                valid &= helper[index:index+4] == _WINDOW_HELPER[index:index+4]
        if valid:
            witnesses.append(offset)
    if len(witnesses) == 1:
        return 0x02000000, 'split565-producer-window-bound'
    return None, ('ambiguous-split565-writers' if witnesses
                  else 'writer-signature-not-found')


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
