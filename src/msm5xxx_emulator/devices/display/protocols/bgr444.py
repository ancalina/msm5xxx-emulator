"""Display methods owned by protocols/bgr444."""
from __future__ import annotations

class Bgr444ProtocolMixin:
    @staticmethod
    def _lcd_bgr444_rgb565(value: int) -> int:
        blue, green, red = value >> 8 & 0xF, value >> 4 & 0xF, value & 0xF
        return (((red << 1 | red >> 3) << 11)
                | ((green << 2 | green >> 2) << 5)
                | (blue << 1 | blue >> 3))

    def _lcd_bgr444_finish_run(self) -> None:
        if self._lcd_bgr444_run_origin is None or not self._lcd_bgr444_run_words:
            return
        x, y = self._lcd_bgr444_run_origin
        self._lcd_bgr444_runs.append((x, y, tuple(self._lcd_bgr444_run_words)))
        self._lcd_bgr444_run_origin = None
        self._lcd_bgr444_run_words.clear()

    def _lcd_bgr444_raster_geometry(self) -> tuple[int, int] | None:
        if not self._lcd_bgr444_runs:
            return None
        x, y, words = self._lcd_bgr444_runs[0]
        width = len(words)
        if x or y or not 64 <= width <= 320:
            return None
        height = 0
        for x, y, words in self._lcd_bgr444_runs:
            if x or y != height or len(words) != width:
                break
            height += 1
        if not 64 <= height <= 320 or width * height < 0x2000:
            return None
        return width, height

    def _lcd_bgr444_flush(self) -> None:
        if not self._lcd_bgr444_dirty:
            return
        self._lcd_bgr444_finish_run()
        geometry = self._lcd_bgr444_raster_geometry()
        if (geometry is not None
                and geometry != (self.config.width, self.config.height)
                and self.frame_sequence == 0):
            self._set_display_geometry(*geometry, force=True)
            for x0, y, words in self._lcd_bgr444_runs:
                for offset, word in enumerate(words):
                    x = x0 + offset
                    if x < self.config.width and y < self.config.height:
                        self._pixel(y * self.config.width + x,
                                    self._lcd_bgr444_rgb565(word))
        self._lcd_protocol = "cursor-bgr444"
        self._publish_frame()
        self._lcd_bgr444_dirty = False
        self._lcd_bgr444_streamed_pixels = 0
        self._lcd_bgr444_runs.clear()

    def _lcd_bgr444_begin_command(self, size: int, value: int) -> bool:
        """Qualify the cursor-addressed BGR444 command sequence."""
        if size != 2:
            return False
        command = value & 0xFFFF
        if command == 0x03:
            self._lcd_bgr444_finish_run()
            self._lcd_bgr444_command = command
            self._lcd_bgr444_axis_state = 0
            return True
        if command == 0x05 and self._lcd_bgr444_axis_state == 1:
            self._lcd_bgr444_command = command
            return True
        if command == 0x0B and self._lcd_bgr444_axis_state == 3:
            self._lcd_bgr444_command = command
            self._lcd_bgr444_qualified = True
            self._lcd_bgr444_run_origin = tuple(self._lcd_bgr444_cursor)
            self._lcd_bgr444_run_words.clear()
            return True
        if self._lcd_bgr444_qualified:
            self._lcd_bgr444_flush()
        self._lcd_bgr444_command = None
        self._lcd_bgr444_axis_state = 0
        return False

    def _lcd_bgr444_feed(self, size: int, value: int) -> bool:
        """Consume one register or pixel word from the proven BGR444 bus."""
        command = self._lcd_bgr444_command
        if size != 2 or command is None:
            return False
        value &= 0xFFFF
        if command == 0x03:
            self._lcd_bgr444_cursor[0] = value
            self._lcd_bgr444_axis_state = 1
            return True
        if command == 0x05 and self._lcd_bgr444_axis_state == 1:
            self._lcd_bgr444_cursor[1] = value
            self._lcd_bgr444_axis_state = 3
            return True
        if command != 0x0B or not self._lcd_bgr444_qualified:
            return False
        if value & 0xF000:
            self._lcd_bgr444_qualified = False
            return False
        x, y = self._lcd_bgr444_cursor
        if self._lcd_bgr444_run_origin is None:
            self._lcd_bgr444_run_origin = (x, y)
        self._lcd_bgr444_run_words.append(value)
        if 0 <= x < self.config.width and 0 <= y < self.config.height:
            self._pixel(y * self.config.width + x,
                        self._lcd_bgr444_rgb565(value))
            self._lcd_bgr444_dirty = True
        self._lcd_bgr444_cursor[0] += 1
        self._lcd_bgr444_streamed_pixels += 1
        if self._lcd_bgr444_streamed_pixels >= self.config.width * self.config.height:
            self._lcd_bgr444_flush()
        return True
