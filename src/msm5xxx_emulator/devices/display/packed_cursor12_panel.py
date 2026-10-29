"""Evidence-gated halfword bus carrying two RGB444 samples in three bytes."""
from __future__ import annotations

_PRODUCER = bytes.fromhex("b030d1e12332a0e1b230cbe1b230d1e0b0c0d1e1010080e2033205e04cc40ee003308ce1b230cbe1400bc0e3b030d1e1ff3003e2b230cbe1021081e2")
_HEADER = bytes.fromhex("b090cbe10000a0e3b200cbe1b080cbe1ff0002e2b200cbe1b070cbe1")

# Complete relative producer shape: transport, row headers, packing and loop bounds.
_THUMB_PRODUCER = bytes.fromhex("feb5002601277f063e80142000f0fafa40207880142000f0f5fa2b203880142000f0f0fa7e80142000f0ecfa00ab1e71324d012451e003203880142000f0e2fa7e80142000f0defa05203880142000f0d9fa00ab18797880142000f0d3fa0b20388000ab1e722ee000ab1879197ac00140184000285a000978801879c101187a1a7a0130187288184000285a0001f023184000ab18801879197ac00140184000285a1988000a0007000f084378801879197ac00140184000285a0006000e7880187a0130187200ab187a8028ccdb0c480470067018790130187100ab1879a028a9db2b203880142000f08cfa7c80142000f088fafebc08bc")
_THUMB_DELAYS = (12, 22, 32, 40, 60, 68, 78, 90, 232, 240)


def _thumb_producers(image: bytes) -> list[int]:
    hits = []
    start = 0
    while (at := image.find(_THUMB_PRODUCER[:12], start)) >= 0:
        start = at + 1
        block = image[at:at + len(_THUMB_PRODUCER)]
        if at % 2 or len(block) != len(_THUMB_PRODUCER):
            continue
        masked = bytearray(block)
        targets = set()
        for offset in _THUMB_DELAYS:
            first = int.from_bytes(block[offset:offset+2], "little")
            second = int.from_bytes(block[offset+2:offset+4], "little")
            if first & 0xF800 != 0xF000 or second & 0xF800 != 0xF800:
                break
            displacement = (first & 0x7FF) << 12 | (second & 0x7FF) << 1
            if displacement & (1 << 22):
                displacement -= 1 << 23
            targets.add(at + offset + 4 + displacement)
            masked[offset:offset+4] = _THUMB_PRODUCER[offset:offset+4]
        else:
            if len(targets) == 1 and masked == _THUMB_PRODUCER:
                hits.append(at)
    return hits

def find_packed_cursor12_port(image: bytes) -> tuple[int | None, str]:
    """Require one aligned producer with its own transport and width bindings."""
    hits = _thumb_producers(image)
    start = 0
    while (at := image.find(_PRODUCER, start)) >= 0:
        start = at + 1
        if (at >= 0x160 and at % 4 == 0
                and image[at-0x160:at-0x15c] == bytes.fromhex("80b7a0e3")
                and image[at-0x124:at-0x118] == bytes.fromhex("0b70a0e30580a0e30390a0e3")
                and image[at-0x114:at-0x110] == bytes.fromhex("0fe0a0e3")
                and image[at-0x4c:at-0x30] == _HEADER
                and image[at+60:at+76] == bytes.fromhex("010080e2400bc0e3800050e3e7ffffba")):
            hits.append(at)
    if len(hits) != 1:
        return None, "producer-binding-absent-or-ambiguous"
    return 0x02000000, "bound-packed12-row-producer"


class PackedCursor12Panel:
    width, height = 128, 160
    _SETUP = ((2, 1), (0x20, 8), (0x22, 8), (0x20, 15), (0, 0),
              (1, 0), (6, 0), (0x26, 0), (0x26, 1), (0, 0x40), (0x2B, 0))
    _PREFIX = ((0x22, 0), (0x20, 0))

    def __init__(self, port: int) -> None:
        self.port = port
        self.frame = bytes(self.width * self.height * 3)
        self.sequence = 0
        self.qualified = False
        self.enabled = None
        self.rejection: str | None = None
        self.observation = "awaiting-complete-raster"
        self._next_row = 0
        self._staging = True
        self._setup_index: int | None = None
        self._setup_argument = False
        self._raster = bytearray(self.frame)
        self._phase = "header"
        self._y = 0
        self._payload = bytearray()

    def _reset(self, reason: str) -> None:
        self.qualified = False
        self.rejection = reason
        self.observation = reason
        self._next_row = 0
        self._staging = True
        self._setup_index: int | None = None
        self._setup_argument = False
        self._raster = bytearray(self.frame)
        self._phase = "header"
        self._payload.clear()

    def _finish(self) -> bool:
        if self._phase != "pixels" or len(self._payload) != 192:
            self._reset("incomplete-row")
            return False
        if self._staging and self._y != self._next_row:
            self._reset("unordered-initial-raster")
            return False
        row = bytearray()
        for i in range(0, 192, 3):
            a, b, c = self._payload[i:i+3]
            for pixel in ((a << 4) | (b >> 4), ((b & 15) << 8) | c):
                row.extend(((pixel >> 8) * 17, (pixel >> 4 & 15) * 17, (pixel & 15) * 17))
        offset = self._y * self.width * 3
        self._raster[offset:offset+len(row)] = row
        if self._staging:
            self._next_row += 1
            if self._next_row == self.height:
                self._staging = False
                self.qualified = True
                self.frame = bytes(self._raster)
                self.sequence += 1
        else:
            self.frame = bytes(self._raster)
            self.sequence += 1
        self.rejection = None
        self.observation = ("provisional-last-complete-image" if self.qualified and self._staging
                            else "complete-raster" if self.qualified else "awaiting-complete-raster")
        self._payload.clear()
        self._phase = "header"
        return True

    def flush(self) -> None:
        if self._phase == "pixels" and len(self._payload) == 192:
            self._finish()

    def _setup_write(self, address: int, value: int) -> None:
        index = self._setup_index
        assert index is not None
        if not self._setup_argument:
            # The observed first nine pairs can restart as one bounded prefix.
            if index == 9 and value == 2:
                index = self._setup_index = 0
            pair = self._PREFIX[index + 2] if index < 0 else self._SETUP[index]
            if address != self.port or value != pair[0]:
                self._reset("unsupported-setup-command")
                return
            self._setup_argument = True
            return
        pair = self._PREFIX[index + 2] if index < 0 else self._SETUP[index]
        if address != self.port + 2 or value != pair[1]:
            self._reset("unsupported-setup-argument")
            return
        self._setup_argument = False
        self._setup_index = index + 1
        if self._setup_index == len(self._SETUP):
            self._setup_index = None
            self._phase = "header"
            self._staging = True
            self._next_row = 0
            self._raster = bytearray(self.frame)

    def write(self, address: int, size: int, value: int) -> None:
        if address not in (self.port, self.port + 2):
            self.flush()
            if self._setup_index is not None:
                return
            if self._phase != "header":
                if self.qualified:
                    self._phase = "header"
                    self._payload.clear()
                    self.observation = "foreign-aperture-partial-dropped"
                else:
                    self._reset("foreign-aperture")
            return
        if size != 2 or type(value) is not int or not 0 <= value <= 255:
            self._reset("unsupported-transfer")
            return
        if self._setup_index is not None:
            self._setup_write(address, value)
            return
        if address == self.port:
            if self._phase == "pixels":
                if not self._finish():
                    return
            if self.qualified and self._phase == "header" and value in (2, 0x22):
                # shortcut: hold the last image through exact reinit; physical GRAM retention is unproved.
                self._setup_index = 0 if value == 2 else -2
                self._setup_argument = False
                self.observation = "provisional-last-complete-image"
                self._setup_write(address, value)
                return
            # Observed display-control register follows complete raster transfers.
            if value == 0x2B and self._phase == "header":
                self._phase = "control"
                return
            expected = {"header": 3, "x-done": 5, "y-done": 11}.get(self._phase)
            if value != expected:
                self._reset("reset-or-unsupported-header")
                return
            self._phase = {3: "x", 5: "y", 11: "pixels"}[value]
            return
        if self._phase == "control" and value in (0, 1):
            self._phase = "header"
        elif self._phase == "x" and value == 0:
            self._phase = "x-done"
        elif self._phase == "y" and value < self.height:
            self._y = value
            self._phase = "y-done"
        elif self._phase == "pixels" and len(self._payload) < 193:
            self._payload.append(value)
            if len(self._payload) == 193:
                self._reset("overlong-row")
        else:
            self._reset("unsupported-row-header")

    def snapshot(self) -> dict[str, object]:
        return {"width": self.width, "height": self.height, "frame": self.frame,
                "qualified": self.qualified, "enabled": self.enabled, "port": self.port,
                "rejection": self.rejection, "observation": self.observation,
                "sequence": self.sequence}
