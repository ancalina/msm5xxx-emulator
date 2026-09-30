"""Temporary segmented-row observer; requires static protocol-class admission.

Geometry is a software viewport, not a physical panel identity. Unknown traffic
revokes visibility; native rendering must continue as fallback.
"""
from __future__ import annotations

ROWS = tuple(range(6, 72)) + tuple(range(81, 143))

class _Raster:
    def __init__(self, port):
        self.port = port
        self.admissions = 0
        self.invalidations = 0
        self.last_reason = "no complete raster"
        self.frame = None
        self.display_enabled = True
        self.qualified = False
        self.reset()

    def reset(self, start=False):
        self.state = "xargs" if start else "xcmd"
        self.args = []
        self.row = 0
        self.pixels = []
        self.work = [0] * (128 * 128) if start else None
        if start:
            self.qualified = False

    def event(self, kind, size, addr, value):
        if addr not in (self.port, self.port + 4):
            return
        if kind != 1 or size != 2 or not 0 <= value <= 0xffff:
            if addr == self.port and self.frame is not None:
                self.display_enabled = None
            self.invalidations += 1
            self.qualified = False
            self.last_reason = "same-port record is not a halfword LCD write"
            self.reset()
            return
        if addr == self.port:
            # Experimental paired control, only after a complete admitted raster.
            transitions = {("seek", 0x50): "power-off-pending",
                           ("power-off-pending", 0x2D): "off",
                           ("off", 0x2C): "power-on-pending",
                           ("power-on-pending", 0x51): "seek"}
            following = transitions.get((self.state, value))
            if self.frame is not None and following is not None:
                self.state = following
                self.qualified = following in ("off", "seek")
                self.display_enabled = following == "seek"
                self.last_reason = "experimental paired display control: " + following
                return
            if self.state in ("xcmd", "seek") and value == 0x43:
                self.reset(start=True)
                return
            if self.state == "rowcmd" and value == 0x43:
                self.state, self.args = "xargs", []
                return
            if self.state == "xargs":
                self.args.append(value)
                if len(self.args) == 2:
                    if self.args != [0, 127]:
                        self.fail("X axis is not exactly 0..127")
                    else:
                        self.state, self.args = "rowcmd", []
                return
            if self.state == "rowargs":
                self.args.append(value)
                if len(self.args) == 2:
                    expected = ROWS[self.row]
                    if self.args != [expected, expected]:
                        self.fail(f"row {self.row} axis is not singleton {expected}")
                    else:
                        self.state, self.args, self.pixels = "data", [], []
                return
            if self.state == "rowcmd" and value == 0x42:
                self.state = "rowargs"
                self.args = []
                return
            self.fail(f"unexpected command/value 0x{value:04x} in {self.state}")
            return
        if self.state != "data":
            self.fail(f"data outside expected row in {self.state}")
            return
        self.pixels.append(value)
        if len(self.pixels) == 128:
            self.work[self.row * 128:(self.row + 1) * 128] = self.pixels
            self.row += 1
            if self.row == len(ROWS):
                self.frame = self.work[:]
                self.admissions += 1
                self.qualified = self.display_enabled is not None
                self.last_reason = "complete exact segmented raster"
                self.state = "seek"
            else:
                self.state = "rowcmd"
        elif len(self.pixels) > 128:
            self.fail("row exceeds 128 halfwords")

    def snapshot(self):
        if not self.qualified:
            return None
        return rgb565(self.frame) if self.display_enabled else bytes(128 * 128 * 3)

    def fail(self, reason):
        self.invalidations += 1
        self.qualified = False
        if reason.startswith("unexpected command/value") and self.frame is not None:
            self.display_enabled = None
        self.last_reason = reason
        self.reset()


def rgb565(values):
    out = bytearray(128 * 128 * 3)
    for i, p in enumerate(values):
        out[i * 3:i * 3 + 3] = bytes(((p >> 8 & 248) | (p >> 13),
                                      (p >> 3 & 252) | (p >> 9 & 3),
                                      (p << 3 & 248) | (p >> 2 & 7)))
    return bytes(out)


class SegmentedPanel:
    def __init__(self, port):
        self.port = port
        self.width = self.height = 128
        self.raster = _Raster(port)
        self.ram = {}
        self.active = self.qualified = False
        self.enabled = True
        self.state = 'idle'
        self.axes = {}
        self.args = []
        self.payload = []
        self.rectangles = 0
        self.reason = 'no complete raster'

    def fail(self, reason):
        self.active = self.qualified = False
        if reason == 'unexpected command or incomplete rectangle':
            self.enabled = None
        self.reason = reason

    def write(self, addr, size, value):
        kind = 1
        if addr not in (self.port, self.port + 4):
            return
        before = self.raster.admissions
        self.raster.event(kind, size, addr, value)
        if self.raster.admissions > before:
            self.ram = {(x, y): self.raster.frame[row * 128 + x]
                        for row, y in enumerate(ROWS) for x in range(128)}
            self.active = True
            self.qualified = self.enabled is not None
            self.state, self.axes = 'complete', {0x43: (0, 127), 0x42: (142, 142)}
            self.reason = 'complete raster'
            return
        if not self.active:
            return
        if kind != 1 or size != 2 or not 0 <= value <= 0xffff:
            if addr == self.port:
                self.enabled = None
            self.fail('non-halfword same-port write')
            return
        if addr == self.port:
            if self.state == 'complete':
                self.state = 'idle'
            if self.state == 'args':
                self.args.append(value)
                if len(self.args) == 2:
                    lo, hi = self.args
                    valid = 0 <= lo <= hi <= 143 if self.axis == 0x43 else (
                        6 <= lo <= hi <= 71 or 81 <= lo <= hi <= 143)
                    if not valid:
                        self.fail('axis outside observed domain')
                        return
                    self.axes[self.axis] = (lo, hi)
                    self.state = 'idle'
                    self.qualified = self.enabled is not None
                return
            following = {('idle', 0x50): 'off-pending', ('off-pending', 0x2d): 'off',
                         ('off', 0x2c): 'on-pending', ('on-pending', 0x51): 'idle'}.get((self.state, value))
            if following:
                self.state = following
                self.qualified = following in ('idle', 'off')
                if self.qualified:
                    self.enabled = following == 'idle'
                self.reason = 'paired control: ' + following
                return
            if self.state in ('idle', 'axes') and value in (0x42, 0x43):
                self.payload = []
                self.axis, self.args, self.state = value, [], 'args'
                self.qualified = False
                return
            self.fail('unexpected command or incomplete rectangle')
            return
        if self.state not in ('idle', 'pixels') or len(self.axes) != 2:
            self.fail('pixel without complete retained axes')
            return
        if self.state == 'idle':
            self.payload = []
        self.state = 'pixels'
        self.qualified = False
        self.payload.append(value)
        x0, x1 = self.axes[0x43]
        y0, y1 = self.axes[0x42]
        width = x1 - x0 + 1
        if len(self.payload) == width * (y1 - y0 + 1):
            for i, pixel in enumerate(self.payload):
                self.ram[x0 + i % width, y0 + i // width] = pixel
            self.rectangles += 1
            self.state, self.qualified = 'complete', self.enabled is not None
            self.reason = 'complete rectangle'

    def scanout_snapshot(self):
        """Keep committed RAM visible during a valid, incomplete pixel transaction."""
        if not self.active or self.enabled is None or self.state in ('off-pending', 'on-pending'):
            return None
        return (rgb565([self.ram[x, y] for y in ROWS for x in range(128)])
                if self.enabled else bytes(128 * 128 * 3))

    def snapshot(self):
        if not self.qualified or self.enabled is None:
            return None
        return (rgb565([self.ram[x, y] for y in ROWS for x in range(128)])
                if self.enabled else bytes(128 * 128 * 3))
