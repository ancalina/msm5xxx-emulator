"""Source-raster view for the mixed-bit-order 89-column GPIO display bus."""
from __future__ import annotations


class GpioSerial89Panel:
    def __init__(self):
        self.clock = None
        self.active = False
        self.mode = None
        self.bits = self.value = 0
        self.page = -1
        self.column = None
        self.column_prefix = False
        self.seen = bytearray(89*8)
        self.coverage = 0
        self.ram = bytearray(89*8)
        self.rgb = bytearray([255])*(89*64*3)
        self.frame = bytes(self.rgb)
        self.qualified = self.dirty = False
        self.rejection = None
        self.sequence = 0
        self.commands = self.data_bytes = 0

    def _publish(self):
        if self.qualified and (self.dirty or not self.sequence):
            self.frame = bytes(self.rgb)
            self.sequence += 1
            self.dirty = False

    def _byte(self, data, value):
        if not data:
            self.commands += 1
            if 0x40 <= value <= 0x47:
                self.page = value-0x40
                self.column = None
                self.column_prefix = False
            elif value == 0 and self.page >= 0:
                self.column = None
                self.column_prefix = True
            elif 0x80 <= value < 0x80+89 and self.page >= 0:
                self.column = value & 127
            else:
                self.page = -1
                self.column = None
                self.column_prefix = False
                # Unclaimed controls cannot retain a previous raster lease.
                self.qualified = False
                self.coverage = 0
                self.seen[:] = bytes(len(self.seen))
            return
        self.data_bytes += 1
        if self.page < 0 or self.column is None or self.column >= 89:
            if self.qualified:
                self.rejection = 'data-without-source-page-column'
            return
        at = self.page*89+self.column
        if not self.seen[at]:
            self.seen[at] = 1
            self.coverage += 1
        if self.ram[at] != value:
            self.ram[at] = value
            self.dirty = True
            # Invert the source bitmap transform, including its cyclic
            # one-bit page crossing. This exposes the input memory canvas,
            # not an inferred orientation or polarity of the physical panel.
            for bit in range(8):
                input_page = 7-self.page if bit == 7 else (6-self.page) & 7
                input_bit = 0 if bit == 7 else bit+1
                x,y = 88-self.column,input_page*8+input_bit
                offset = (y*89+x)*3
                shade = 0 if value & (1 << bit) else 255
                self.rgb[offset:offset+3] = bytes([shade])*3
        self.column += 1
        self.qualified = self.coverage == 89*8

    def write(self, address, size, value):
        if address != 0x03000660 or self.rejection:
            return False
        if size != 2 or not 0 <= value <= 0xffff:
            self.rejection = 'source-halfword-required'
            return False
        clock, active, data = bool(value & 0x40), not bool(value & 0x20), bool(value & 0x100)
        if not active:
            if self.bits:
                self.rejection = 'incomplete-byte-at-chip-select'
                return False
            self._publish()
            self.active = False
            self.clock = clock
            self.mode = None
            return self.qualified
        if not self.active:
            self.bits = self.value = 0
            self.mode = data
        elif self.bits and self.mode != data:
            self.rejection = 'mode-changed-within-byte'
            return False
        if not self.bits:
            self.mode = data
        if self.clock is False and clock:
            bit = (value >> 7) & 1
            if data:
                self.value |= bit << self.bits
            else:
                self.value = (self.value << 1) | bit
            self.bits += 1
            if self.bits == 8:
                self._byte(data, self.value)
                self.bits = self.value = 0
        self.active = True
        self.clock = clock
        return self.qualified and self.rejection is None
