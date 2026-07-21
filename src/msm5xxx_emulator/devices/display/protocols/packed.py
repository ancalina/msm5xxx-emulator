"""Display methods owned by protocols/packed."""
from __future__ import annotations

from ....detection.firmware import KNOWN_SCREENS
from ....core.constants import PACKED_RGB332_WINDOW_COMMANDS


class PackedProtocolMixin:
    def _lcd_selector_reset(self) -> None:
        self._lcd_selector_words.clear()
        self._lcd_selector_expected = 0
        self._lcd_selector_window = None
        self._lcd_selector_format = None

    def _lcd_selector_begin_command(self, size: int, value: int) -> bool:
        """Recognise the packed-register selector's exact pixel window."""
        if size != 2:
            self._lcd_selector_reset()
            return False
        if self._lcd_selector_expected:
            self._lcd_selector_reset()
        register, argument = value >> 8 & 0xFF, value & 0xFF
        self._lcd_selector_registers[register] = argument
        mode = self._lcd_selector_registers.get(0x0D)
        if register != 0x0E or argument or mode not in (0, 1):
            return False
        window = tuple(self._lcd_selector_registers.get(register, -1)
                       for register in (0x02, 0x03, 0x04, 0x05))
        x0, y0, x1, y1 = window
        if not (0 <= x0 <= x1 < 320 and 0 <= y0 <= y1 < 320):
            return False
        pixels = (x1 - x0 + 1) * (y1 - y0 + 1)
        self._lcd_selector_window = window
        self._lcd_selector_format = "rgb666" if mode == 0 else "rgb565"
        self._lcd_selector_expected = pixels * (2 if mode == 0 else 1)
        port = (0x02000004, 2)
        stream = self._lcd_raw_streams.get(port)
        if stream is not None:
            stream.clear()
        self._lcd_raw_counts[port] = 0
        return True

    def _lcd_selector_feed(self, size: int, value: int) -> bool:
        """Consume one word from a controller-proven selector window."""
        if not self._lcd_selector_expected:
            return False
        if (size != 2 or (self._lcd_selector_format == "rgb666"
                         and not len(self._lcd_selector_words) % 2
                         and value & ~3)):
            self._lcd_selector_reset()
            return False
        self._lcd_selector_words.append(value & 0xFFFF)
        if len(self._lcd_selector_words) < self._lcd_selector_expected:
            return True
        window = self._lcd_selector_window
        pixel_format = self._lcd_selector_format
        words = self._lcd_selector_words
        assert window is not None and pixel_format is not None
        x0, y0, x1, y1 = window
        geometry = self._lcd_full_window_geometry([x0, x1], [y0, y1])
        current = (self.config.width, self.config.height)
        known = KNOWN_SCREENS.get(getattr(self.config, "verified_model", ""))
        if (geometry is not None and (geometry == current
                                      or (known is None
                                          and current == (176, 220)))):
            self._set_display_geometry(*geometry)
        if x1 < self.config.width and y1 < self.config.height:
            step = 2 if pixel_format == "rgb666" else 1
            width = x1 - x0 + 1
            for index in range(0, len(words), step):
                if pixel_format == "rgb666":
                    pixel = (words[index] & 3) << 16 | words[index + 1]
                    rgb565 = ((pixel >> 13 & 0x1F) << 11
                              | (pixel >> 6 & 0x3F) << 5
                              | (pixel >> 1 & 0x1F))
                else:
                    rgb565 = words[index]
                pixel_index = index // step
                x, y = pixel_index % width + x0, pixel_index // width + y0
                self._pixel(y * self.config.width + x, rgb565)
            self._lcd_protocol = f"selector-{pixel_format}"
            self._publish_frame()
        self._lcd_selector_reset()
        return True

    def _lcd_packed_begin_command(self, value: int) -> bool:
        """Handle the controller-proven +8/+C packed-RGB332 dialect.

        Its 0x45..0x48 registers are a window in *word columns* and 0x4A is
        the only pixel stream command.  A normal 0x22 is merely a register
        write on this bus, so the dialect is enabled only after the complete
        window-programming sequence proves it.
        """
        command = value & 0xFF
        if command in PACKED_RGB332_WINDOW_COMMANDS:
            expected = (0x45 + len(self._lcd_packed_window_order))
            self._lcd_packed_window_order = (
                [command] if command == 0x45
                else [*self._lcd_packed_window_order, command]
                if command == expected else []
            )
            self._lcd_packed_command = command
            return True
        if command == 0x4A:
            self._lcd_packed_command = command
            if self._lcd_packed_window_order != [0x45, 0x46, 0x47, 0x48]:
                return self._lcd_packed_qualified
            self._lcd_packed_window_order.clear()
            x0 = self._lcd_packed_registers.get(0x45, -1)
            y0 = self._lcd_packed_registers.get(0x46, -1)
            x1 = self._lcd_packed_registers.get(0x47, -1)
            y1 = self._lcd_packed_registers.get(0x48, -1)
            columns, rows = x1 - x0 + 1, y1 - y0 + 1
            if not (0 <= x0 <= x1 < 160 and 0 <= y0 <= y1 < 320
                    and 32 <= columns <= 160 and 32 <= rows <= 320):
                return self._lcd_packed_qualified
            width, height = columns * 2, rows
            if (64 <= width <= 320 and 64 <= height <= 320
                    and (self.frame_sequence == 0 or not self._lcd_packed_qualified)
                    and x0 == y0 == 0):
                # Earlier +8 register traffic can look like a tiny generic
                # 0x22 frame.  A complete packed-window sequence is stronger
                # evidence, so it may replace that provisional geometry once.
                self._set_display_geometry(
                    width, height, force=not self._lcd_packed_qualified
                )
            if (x0 * 2 >= self.config.width or x1 * 2 + 1 >= self.config.width
                    or y1 >= self.config.height):
                return self._lcd_packed_qualified
            self._lcd_packed_qualified = True
            self._lcd_packed_window[:] = [x0, y0, x1, y1]
            self._lcd_packed_cursor[:] = [x0, y0]
            self._lcd_packed_expected_words = columns * rows
            self._lcd_packed_streamed_words = 0
            return True
        if self._lcd_packed_qualified:
            self._lcd_packed_command = command
            return True
        return False

    def _lcd_packed_feed_data(self, value: int) -> bool:
        """Consume +C data for a validated packed-RGB332 controller."""
        command = self._lcd_packed_command
        if command in PACKED_RGB332_WINDOW_COMMANDS:
            self._lcd_packed_registers[command] = value & 0xFF
            return True
        if command != 0x4A:
            return self._lcd_packed_qualified
        if not self._lcd_packed_qualified or not self._lcd_packed_expected_words:
            return False
        x, y = self._lcd_packed_cursor
        _x0, _y0, x1, _y1 = self._lcd_packed_window
        high, low = value >> 8 & 0xFF, value & 0xFF
        pixel_x = x * 2
        if 0 <= y < self.config.height and pixel_x + 1 < self.config.width:
            for offset, packed in enumerate((high, low)):
                rgb565 = ((packed & 0xE0) << 8
                          | (packed & 0x1C) << 6
                          | (packed & 0x03) << 3)
                self._pixel(y * self.config.width + pixel_x + offset, rgb565)
        x += 1
        if x > x1:
            x, y = self._lcd_packed_window[0], y + 1
        self._lcd_packed_cursor[:] = [x, y]
        self._lcd_packed_streamed_words += 1
        if self._lcd_packed_streamed_words >= self._lcd_packed_expected_words:
            self._publish_frame()
            self._lcd_packed_expected_words = 0
        return True
