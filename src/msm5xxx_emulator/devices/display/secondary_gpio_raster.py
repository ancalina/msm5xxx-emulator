"""Secondary monochrome canvas decoded from its serialized 2-bit raster."""
from __future__ import annotations


class SecondaryGpioRaster:
    gpio_raster = True
    port = 0x03000728
    data_offset = 0
    bias = 0
    enabled = True

    def __init__(self) -> None:
        self.frame = bytes([255]) * (128 * 48 * 3)
        self.committed = False
        self.rejection = None
        self.sequence = 0
        self._bits = 0
        self._byte = 0
        self._payload = bytearray()
        self._active = False

    def flush(self) -> None:
        # A partial serial raster is never a publishable frame.
        pass

    def write(self, address: int, size: int, value: int) -> bool:
        if address != self.port:
            return False
        if size != 2 or value & ~0xc001:
            self._active = False
            return True
        if value & 0x8000:
            self._active = True
            self._bits = self._byte = 0
            self._payload.clear()
        if not self._active:
            return True
        self._byte = (self._byte << 1) | (value & 1)
        self._bits += 1
        if self._bits == 8:
            self._payload.append(self._byte)
            self._bits = self._byte = 0
        if value & 0x4000:
            self._active = False
            if self._bits or len(self._payload) != 1600:
                return True
            rgb = bytearray(128 * 48 * 3)
            for y in range(48):
                for x in range(128):
                    byte = self._payload[y * 32 + (x // 8) * 2 + (x % 8) // 4]
                    pixel = byte >> ((2 * x) & 7) & 3
                    if pixel not in (0, 3):
                        return True
                    shade = 0 if pixel else 255
                    offset = (y * 128 + x) * 3
                    rgb[offset:offset + 3] = bytes((shade,)) * 3
            self.frame = bytes(rgb)
            self.committed = True
            self.sequence += 1
        return True
