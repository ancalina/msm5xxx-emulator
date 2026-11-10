"""Producer-bound halfword pixels on separate FA command/data transport."""
from __future__ import annotations
from msm5xxx_emulator.detection.registry import device_domain
find_fa_direct_port = device_domain("display.fa_direct").find_fa_direct_port

class FaDirectPanel:
    width, height = 128, 160
    _SETUP = ((5, 0x1030), (0x16, 0x7F00), (0x17, 0x9F00), (0x21, 0))
    _CONTROL = ((7, 4), (3, 2), (7, 4), (13, 1027), (14, 5661), (1, 275), (2, 1792), (5, 4144), (6, 0), (11, 16384), (12, 1), (3, 148), (4, 0), (14, 13853), (13, 1043), (33, 0), (48, 771), (49, 771), (50, 771), (51, 771), (52, 1028), (53, 1028), (54, 1028), (55, 771), (15, 0), (17, 0), (20, 40704), (21, 0), (22, 32512), (23, 40704), (58, 7939), (59, 2574), (7, 37), (7, 37), (7, 39), (7, 55), (5, 4144))

    def __init__(self, port: int = 0x02000000) -> None:
        if port != 0x02000000:
            raise ValueError('unproved FA direct bus')
        self.port = port
        self.frame = b''
        self.sequence = 0
        self.qualified = False
        self.enabled = None
        self.rejection: str | None = None
        self.observation = 'awaiting-full-raster'
        self._stage = 0
        self._argument = False
        self._pixels: list[int] | None = None
        self._control_event: int | None = None
        self._holding = False

    def _reject(self, reason: str) -> None:
        self.qualified = False
        self.rejection = self.observation = reason
        self._stage = 0
        self._argument = False
        self._pixels = None
        self._control_event = None
        self._holding = False

    def flush(self) -> None:
        if self._pixels is None or len(self._pixels) != self.width*self.height:
            return
        frame = bytearray()
        for pixel in self._pixels:
            frame.extend(((pixel >> 8 & 248) | (pixel >> 13),
                          (pixel >> 3 & 252) | (pixel >> 9 & 3),
                          (pixel << 3 & 248) | (pixel >> 2 & 7)))
        self.frame = bytes(frame)
        self.sequence += 1
        self.qualified = True
        self.rejection = None
        self.observation = 'complete-fa-direct-raster'
        self._pixels = None
        self._stage = 0
        self._holding = False

    def _waiting_observation(self) -> str:
        return ('provisional-last-complete-image' if self._holding and self.qualified
                else 'awaiting-full-raster')

    def _control_write(self, address: int, value: int) -> None:
        event = self._control_event
        assert event is not None
        pair = self._CONTROL[event // 2]
        expected = (self.port+0x78, pair[0]) if event % 2 == 0 else (self.port+0xFA, pair[1])
        if (address, value) != expected:
            self._reject('unsupported-control-reinit')
            return
        self._control_event = event+1 if event+1 < len(self._CONTROL)*2 else None
        self.observation = 'provisional-last-complete-image'

    def write(self, address: int, size: int, value: int) -> None:
        if address not in (self.port+0x78, self.port+0xFA):
            return
        if size != 2 or type(value) is not int or not 0 <= value <= 0xFFFF:
            self._reject('invalid-halfword-transfer')
            return
        if self._control_event is not None:
            self._control_write(address, value)
            return
        command = address == self.port+0x78
        if self._pixels is not None:
            if not command:
                if len(self._pixels) == self.width*self.height:
                    self._reject('raster-overflow')
                else:
                    self._pixels.append(value)
                return
            self.flush()
            if self._pixels is not None:
                self._reject('interrupted-partial-raster')
                return
        if command:
            if self.qualified and self._stage == 0 and not self._argument and value == 7:
                # shortcut: hold presentation through exact reinit; physical power/GRAM retention is unproved.
                self._control_event = 0
                self._holding = True
                self._control_write(address, value)
                return
            if value == 5 and not self._argument:
                self._stage = 0
            expected = self._SETUP[self._stage][0] if self._stage < 4 else 0x22
            if self._argument or value != expected:
                self._reject('unsupported-controller-command')
            elif self._stage == 4:
                self._pixels = []
                self.observation = self._waiting_observation()
            else:
                self._argument = True
            return
        if not self._argument or value != self._SETUP[self._stage][1]:
            self._reject('unsupported-controller-argument')
            return
        self._argument = False
        self._stage += 1
        self.rejection = None
        self.observation = self._waiting_observation()

    def snapshot(self) -> dict[str, object]:
        return {'width': self.width, 'height': self.height, 'frame': self.frame,
                'qualified': self.qualified, 'enabled': self.enabled, 'port': self.port,
                'rejection': self.rejection, 'observation': self.observation,
                'sequence': self.sequence}
