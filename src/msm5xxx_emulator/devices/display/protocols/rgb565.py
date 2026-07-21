"""Display methods owned by protocols/rgb565."""
from __future__ import annotations

from ....core.constants import BYTE_RGB565_BOOT_COMMANDS
from ....core.constants import BYTE_RGB565_BOOT_HEIGHT
from ....core.constants import BYTE_RGB565_BOOT_WIDTH


class Rgb565ProtocolMixin:
    def _lcd_byte_rgb565_reset(self) -> None:
        self._lcd_byte_rgb565_commands.clear()
        self._lcd_byte_rgb565_payload = None

    def _lcd_byte_rgb565_begin_command(self, size: int, value: int) -> None:
        """Recognise one complete byte-bus controller setup before pixels."""
        if size != 1:
            self._lcd_byte_rgb565_reset()
            return
        if self._lcd_byte_rgb565_payload is not None:
            self._lcd_byte_rgb565_reset()
        command = value & 0xFF
        position = len(self._lcd_byte_rgb565_commands)
        if (position < len(BYTE_RGB565_BOOT_COMMANDS)
                and command == BYTE_RGB565_BOOT_COMMANDS[position]):
            self._lcd_byte_rgb565_commands.append(command)
            if len(self._lcd_byte_rgb565_commands) == len(BYTE_RGB565_BOOT_COMMANDS):
                self._lcd_byte_rgb565_payload = bytearray()
            return
        self._lcd_byte_rgb565_commands[:] = (
            bytes((command,)) if command == BYTE_RGB565_BOOT_COMMANDS[0] else b""
        )

    def _lcd_byte_rgb565_feed_data(self, address: int, size: int, value: int) -> bool:
        """Render the exact byte-wide, big-endian 96x64 RGB565 boot stream."""
        payload = self._lcd_byte_rgb565_payload
        if payload is None:
            return False
        if address != 0x02800002 or size != 1:
            self._lcd_byte_rgb565_reset()
            return False
        payload.append(value & 0xFF)
        expected = BYTE_RGB565_BOOT_WIDTH * BYTE_RGB565_BOOT_HEIGHT * 2
        if len(payload) > expected:
            self._lcd_byte_rgb565_reset()
            return False
        if len(payload) < expected:
            return True
        if not any(payload):
            self._lcd_byte_rgb565_reset()
            return True
        # A full payload is stronger evidence than the unknown-model default
        # geometry.  Never replace a previously rendered, unrelated panel.
        self._set_display_geometry(
            BYTE_RGB565_BOOT_WIDTH, BYTE_RGB565_BOOT_HEIGHT,
            force=self.frame_sequence == 0,
        )
        if (self.config.width, self.config.height) == (
                BYTE_RGB565_BOOT_WIDTH, BYTE_RGB565_BOOT_HEIGHT):
            for index in range(BYTE_RGB565_BOOT_WIDTH * BYTE_RGB565_BOOT_HEIGHT):
                offset = index * 2
                self._pixel(index, payload[offset] << 8 | payload[offset + 1])
            self._publish_frame()
        self._lcd_byte_rgb565_reset()
        return True

    def _lcd_byte_rgb565_interrupt(self, address: int, size: int) -> None:
        """Reject a partial fingerprint when another LCD transport intervenes."""
        if (not self._lcd_byte_rgb565_commands
                and self._lcd_byte_rgb565_payload is None):
            return
        if address == 0x02800000 and size == 1:
            return
        if (address == 0x02800002 and size == 1
                and self._lcd_byte_rgb565_payload is not None):
            return
        self._lcd_byte_rgb565_reset()

    def _lcd_window_rgb565_reset(self) -> None:
        self._lcd_window_rgb565_header.clear()
        self._lcd_window_rgb565_window = None
        self._lcd_window_rgb565_pixels.clear()
        self._lcd_window_rgb565_high = None

    def _lcd_window_rgb565_write(self, address: int, size: int, value: int) -> bool:
        """Decode a complete byte-window RGB565 rectangle at 0x02000010/+11."""
        byte = value & 0xFF
        window = self._lcd_window_rgb565_window
        if window is not None:
            if size == 1 and address == 0x02000010:
                self._lcd_window_rgb565_high = byte
                return True
            if (size == 1 and address == 0x02000011
                    and self._lcd_window_rgb565_high is not None):
                self._lcd_window_rgb565_pixels.append(
                    self._lcd_window_rgb565_high << 8 | byte
                )
                self._lcd_window_rgb565_high = None
                x0, y0, x1, y1 = window
                expected = (x1 - x0 + 1) * (y1 - y0 + 1)
                if len(self._lcd_window_rgb565_pixels) < expected:
                    return True
                if any(self._lcd_window_rgb565_pixels):
                    width = x1 - x0 + 1
                    for index, pixel in enumerate(self._lcd_window_rgb565_pixels):
                        x, y = x0 + index % width, y0 + index // width
                        self._pixel(y * self.config.width + x, pixel)
                    self._lcd_protocol = "window-byte-rgb565"
                    self._publish_frame()
                self._lcd_window_rgb565_reset()
                return True
            self._lcd_window_rgb565_reset()
        header = self._lcd_window_rgb565_header
        expected_address = 0x0200001A + len(header)
        if size == 1 and address == expected_address:
            header.append(byte)
            if len(header) < 4:
                return True
            x0, y0, x1, y1 = header
            pixels = (x1 - x0 + 1) * (y1 - y0 + 1)
            if (x0 <= x1 < self.config.width and y0 <= y1 < self.config.height
                    and pixels >= 0x2000):
                self._lcd_window_rgb565_window = (x0, y0, x1, y1)
                header.clear()
                return True
            self._lcd_window_rgb565_reset()
            return False
        if header:
            self._lcd_window_rgb565_reset()
        return False
