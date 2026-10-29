"""Temporary statically bound split16+2 monochrome LCD observer."""
from __future__ import annotations


_SPLIT = bytes.fromhex('8700d459240c6c80d759bf07bf0f6f80')
_PORT = bytes.fromhex('0121c9028f033980')
_LOOPS = bytes.fromhex('013101308028ecd30133a02be5d3')
_GLYPH = bytes.fromhex(
    'f0b400011149002743180124104d64061a7807210020161c0e41760802d300266680'
    '01e065800326668001390904090c01300006000e0828eddb013301373f063f0e102f'
    'e4dbf0bc7047')
_WINDOW = bytes.fromhex(
    'fcb5041c0025002728010721090201430e1cc11d08310b22120211430191d11ff939'
    '014300912078002827d0f8000121c902014301225206118000991180c11d09231b02'
    '194311800199118003214902084310801680')


def find_split18_port(image: bytes) -> tuple[int | None, str]:
    """Bind original producer, bus construction, dimensions and window caller."""
    witnesses = []
    start = 0
    while (offset := image.find(_SPLIT, start)) >= 0:
        if (offset % 2 == 0 and offset >= 126 and image[offset-126:offset-118] == _PORT
                and image[offset+30:offset+44] == _LOOPS):
            witnesses.append(offset)
        start = offset + 1
    start = 0
    while (offset := image.find(_GLYPH, start)) >= 0:
        if (offset % 2 == 0 and image[offset+80:offset+82] == b'\xff\xff'
                and image[offset+84:offset+84+len(_WINDOW)] == _WINDOW):
            witnesses.append(offset)
        start = offset + 1
    if len(witnesses) == 1:
        return 0x02000000, 'split18-producer-window-bound'
    return None, ('ambiguous-split18-writers' if witnesses
                  else 'writer-signature-not-found')


class Split18Panel:
    """Retain exact complete windows; native writes remain independently owned."""

    def __init__(self, port: int = 0x02000000) -> None:
        if port != 0x02000000:
            raise ValueError('unproved split18 bus')
        self.port = port
        self.width, self.height = 128, 160
        self.enabled = None
        self.reset()

    def reset(self) -> None:
        self.frame = b''
        self.sequence = 0
        self.qualified = False
        self.rejection: str | None = None
        self.observation = 'awaiting-full-raster'
        self._registers: dict[int, int] = {}
        self._words: list[int] = []
        self._window: tuple[int, int, int, int] | None = None
        self._ram = bytearray(self.width * self.height * 3)

    def _reject(self, reason: str) -> None:
        self.rejection = reason
        self.observation = reason
        self.qualified = False
        self._registers.clear()
        self._words.clear()
        self._window = None

    def flush(self) -> None:
        """A boundary commits an exact window; a trailing extra word rejects it."""
        if not self._words or self.rejection:
            return
        assert self._window is not None
        x0, y0, x1, y1 = self._window
        expected = 2 * (x1-x0+1) * (y1-y0+1)
        if len(self._words) != expected:
            return
        for index in range(0, expected, 2):
            y, x = divmod(index // 2, x1-x0+1)
            offset = ((y+y0)*self.width+x+x0)*3
            level = 255 if self._words[index] else 0
            self._ram[offset:offset+3] = bytes((level, level, level))
        self.frame = bytes(self._ram)
        self.sequence += 1
        self.qualified = True
        self.observation = 'complete-monochrome-window'
        self._words.clear()
        self._window = None
        self._registers.clear()

    def write(self, address: int, size: int, value: int) -> None:
        if self.rejection:
            return
        if address not in (self.port, self.port+2):
            return
        if size != 2 or not 0 <= value <= 0xffff:
            self._reject('invalid-halfword-transfer')
            return
        if address == self.port:
            self.flush()
            if self._words:
                self._reject('incomplete-window')
                return
            register, argument = value >> 8, value & 255
            if register in (6, 7, 8, 9, 10, 11):
                self._registers[register] = argument
            else:
                self._registers.clear()
            return
        if self._window is None:
            r = self._registers
            if not all(key in r for key in (6, 7, 8, 9, 10, 11)):
                self._reject('missing-window-or-cursor')
                return
            x0, y0, x1, y1 = r[8], r[10], r[9], r[11]
            if x0 > x1 or y0 > y1:
                self._reject('reversed-window')
                return
            if x1 >= self.width or y1 >= self.height:
                self._reject('window-outside-viewport')
                return
            if (r[6], r[7]) != (x0, y0):
                self._reject('cursor-window-mismatch')
                return
            if not self.qualified and (x0, y0, x1, y1) != (0, 0, 127, 159):
                self._reject('missing-full-raster')
                return
            self._window = x0, y0, x1, y1
        x0, y0, x1, y1 = self._window
        if len(self._words) >= 2*(x1-x0+1)*(y1-y0+1):
            self._reject('window-overflow')
            return
        # shortcut: monochrome witnesses only; admit color after channel proof.
        valid = (value in (0, 0xffff) if len(self._words) % 2 == 0
                 else value == (3 if self._words[-1] else 0))
        if not valid:
            self._reject('unproved-color-packing')
            return
        self._words.append(value)

    def snapshot(self) -> dict[str, object]:
        return {"width": self.width, "height": self.height, "frame": self.frame,
                "qualified": self.qualified, "enabled": self.enabled, "port": self.port,
                "rejection": self.rejection, "observation": self.observation,
                "sequence": self.sequence}
