"""Display methods owned by controller."""
from __future__ import annotations

from ...detection.firmware import KNOWN_SCREENS
from ...core.constants import LCD_MEMORY_WRITE_COMMANDS
from unicorn import Uc


class DisplayControllerMixin:
    def _pixel(self, index: int, value: int) -> None:
        if not 0 <= index < self.config.width * self.config.height:
            return
        offset = index * 3
        self.framebuffer[offset] = (value >> 8 & 0xF8) | (value >> 13)
        self.framebuffer[offset + 1] = (value >> 3 & 0xFC) | (value >> 9 & 3)
        self.framebuffer[offset + 2] = (value << 3 & 0xF8) | (value >> 2 & 7)

    def _publish_frame(self, *, firmware_originated: bool = True) -> None:
        """Atomically expose only a complete scanout to the GUI thread."""
        frame = bytes(self.framebuffer)
        with self._display_lock:
            self.display_frame = frame
            self.frame_sequence += 1
            if firmware_originated:
                self.firmware_frame_sequence = (
                    getattr(self, "firmware_frame_sequence", 0) + 1
                )
            self._lcd_frame_protocol = self._lcd_protocol

    def display_snapshot(self) -> tuple[int, int, bytes]:
        """Return a geometry/frame triple which is safe for a GUI consumer."""
        with self._display_lock:
            width, height = self.config.width, self.config.height
            frame = self.display_frame
        # The lock makes this invariant unconditional; retain the guard as a
        # useful failure boundary for future display producers.
        if len(frame) != width * height * 3:
            raise RuntimeError("inconsistent display snapshot")
        return width, height, frame

    @staticmethod
    def _lcd_full_window_geometry(x_axis: list[int],
                                  y_axis: list[int]) -> tuple[int, int] | None:
        """Return a controller-proven full-screen window, if one is present."""
        spans = tuple(
            end - start + 1 if end >= start else ((end - start) & 0xFF) + 1
            for start, end in (x_axis, y_axis)
        )
        if (x_axis[0] != 0 or y_axis[0] != 0
                or not (64 <= spans[0] <= 320 and 64 <= spans[1] <= 320)
                or spans[0] * spans[1] < 0x2000):
            return None
        return spans

    def _set_display_geometry(self, width: int, height: int, *, force: bool = False) -> None:
        """Adopt a controller-proven panel geometry before its first visible frame."""
        if (width, height) == (self.config.width, self.config.height):
            return
        visible = self.framebuffer.count(0) != len(self.framebuffer)
        if ((visible and not force)
                or not (64 <= width <= 320 and 64 <= height <= 320)):
            return
        with self._display_lock:
            self.config.width, self.config.height = width, height
            self.framebuffer = bytearray(width * height * 3)
            self.display_frame = bytes(self.framebuffer)
        self._lcd_direct_calibrated = [False, False]
        self._lcd_raw_streams.clear()
        self._lcd_raw_counts.clear()
        self._lcd_raw_frames.clear()
        self._lcd_raw_port = None
        self._lcd_raw_segment_streams.clear()
        self._lcd_raw_segment_counts.clear()

    def _lcd_promote_gram_geometry(self) -> None:
        """Use an addressed full GRAM window before cursor-wrapped pixels."""
        geometry = self._lcd_full_window_geometry(self._lcd_x, self._lcd_y)
        current = (self.config.width, self.config.height)
        known = KNOWN_SCREENS.get(getattr(self.config, "verified_model", ""))
        # GRAM dimensions can be larger than the glass.  They may replace the
        # generic 176x220 fallback (as on SC-7080), but never overwrite a
        # known model panel or a previously detected/manual non-default size.
        if (geometry is not None and (geometry == current
                                      or (known is None
                                          and current == (176, 220)))):
            self._set_display_geometry(*geometry)

    def _flush_indexed_frame(self) -> None:
        if self._lcd_indexed_dirty:
            self._publish_frame()
            self._lcd_indexed_dirty = False
        if self._lcd_gram_dirty:
            self._publish_frame()
            self._lcd_gram_dirty = False

    def _lcd_set_axis(self, command: int, value: int) -> bool:
        """Apply common 8-bit LCD window/cursor registers.

        Samsung's 176x220 BSPs use 0x16/0x17 and 0x22, while later panels
        commonly use 0x2A/0x2B/0x2C or 0x50..0x53.  Values are accepted in
        the compact low-byte/high-byte pair form emitted by the former.
        """
        pair = [value & 0xFF, value >> 8 & 0xFF]
        if command == 0x16:
            self._lcd_x[:] = pair
            return True
        if command == 0x17:
            self._lcd_y[:] = pair
            return True
        if command == 0x50:
            self._lcd_x[0] = value & 0xFF
            return True
        if command == 0x51:
            self._lcd_x[1] = value & 0xFF
            return True
        if command == 0x52:
            self._lcd_y[0] = value & 0xFF
            return True
        if command == 0x53:
            self._lcd_y[1] = value & 0xFF
            return True
        if command == 0x05:
            self._lcd_packed_21_state = int(
                self._lcd_protocol == "parallel-2" and value == 0x0230
                and self._lcd_x == [0, 127] and self._lcd_y == [0, 159]
                and (self.config.width, self.config.height) == (128, 160)
            )
            return bool(self._lcd_packed_21_state)
        if command == 0x20:
            coordinate = value & 0xFF or (value >> 8 & 0xFF)
            self._lcd_cursor[0] = coordinate
            self._lcd_gram_cursor[0] = coordinate
            self._lcd_gram_addressed = True
            self._lcd_packed_21_state = (
                2 if self._lcd_packed_21_state == 1 and value == 0 else 0
            )
            return True
        if command == 0x21:
            if self._lcd_packed_21_state == 2 and value > 0xFF:
                x, y = value & 0xFF, value >> 8 & 0xFF
                if x < self.config.width and y < self.config.height:
                    self._lcd_cursor[:] = [x, y]
                    self._lcd_gram_cursor[:] = [x, y]
                    self._lcd_gram_addressed = True
                    return True
                self._lcd_packed_21_state = 0
            coordinate = value & 0xFF or (value >> 8 & 0xFF)
            self._lcd_cursor[1] = coordinate
            self._lcd_gram_cursor[1] = coordinate
            self._lcd_gram_addressed = True
            return True
        return False

    def _lcd_begin_command(self, value: int) -> None:
        """Start a controller command on any observed command/data transport."""
        self._lcd_finish_direct_args()
        self._lcd_finish_direct_frame()
        # Raw FIFOs are only promoted after a sustained, command-delimited
        # transfer.  Resetting incomplete captures here prevents two partial
        # rectangle updates from being mistaken for one panel-sized frame.
        for port, stream in self._lcd_raw_streams.items():
            # Indexed +4 is the only observed port whose adjacent controller
            # transactions can otherwise merge distinct 128-line rasters.
            # Other raw apertures deliberately retain their rolling capture:
            # their command writes are often unrelated setup traffic.
            if (port[0] == 0x02800004
                    and self._lcd_raw_counts[port]
                    % max(1, self.config.width * self.config.height)):
                stream.clear()
                self._lcd_raw_counts[port] = 0
        self._lcd_command = value & 0xFFFF
        if self._lcd_command not in (0x20, 0x21, 0x22):
            self._lcd_packed_21_state = 0
        self._lcd_recent_commands.append(self._lcd_command & 0xFF)
        self._lcd_args.clear()
        self._lcd_data_byte_latch.clear()
        spans = tuple(
            end - start + 1 if end >= start else ((end - start) & 0xFF) + 1
            for start, end in (self._lcd_x, self._lcd_y)
        )
        gram_cursor_stream = (
            self._lcd_protocol == "parallel-2"
            and self._lcd_command == 0x22
            and self._lcd_gram_addressed
            and (self._lcd_packed_21_state != 0
                 or spans == (self.config.width, self.config.height))
        )
        if (self._lcd_command in LCD_MEMORY_WRITE_COMMANDS
                and not gram_cursor_stream):
            if self._lcd_command == 0x22:
                self._lcd_gram_addressed = False
            self._lcd_start_direct_frame()
        elif gram_cursor_stream:
            self._lcd_promote_gram_geometry()

    def _lcd_feed_data(self, address: int, size: int, value: int) -> None:
        """Consume one controller data word shared by the parallel transports."""
        value &= 0xFFFF
        if (self._lcd_protocol == "parallel-2" and self._lcd_command == 0x22
                and self._lcd_gram_addressed):
            self._lcd_write_gram_pixel(value)
            return
        if self._lcd_command in LCD_MEMORY_WRITE_COMMANDS:
            self._lcd_direct_data(value)
            return
        if self._lcd_set_axis(self._lcd_command, value):
            return
        if self._lcd_command in (0x15, 0x75, 0x2A, 0x2B):
            # 0x15/0x75 use compact byte writes on the older Samsung panels;
            # 0x2A/0x2B arrive as 16-bit words on most ILI-style panels.
            if self._lcd_command in (0x2A, 0x2B):
                self._lcd_args.extend((value >> 8 & 0xFF, value & 0xFF))
            else:
                self._lcd_args.append(value & 0xFF)
            if len(self._lcd_args) >= 4:
                pair = [self._lcd_args[0] << 8 | self._lcd_args[1],
                        self._lcd_args[2] << 8 | self._lcd_args[3]]
                target = self._lcd_x if self._lcd_command in (0x15, 0x2A) else self._lcd_y
                target[:] = pair
                self._lcd_args.clear()
            return
        self._capture_raw_lcd_stream(address, size, value)

    def _lcd_feed_parallel_data(self, address: int, size: int, value: int) -> None:
        """Feed a data-port write, joining byte-wide RGB565 transfers safely."""
        if size == 1 and self._lcd_command in LCD_MEMORY_WRITE_COMMANDS:
            first = self._lcd_data_byte_latch.pop(address, None)
            if first is None:
                self._lcd_data_byte_latch[address] = value & 0xFF
                return
            # Parallel LCD buses send the high RGB565 byte first.
            self._lcd_feed_data(address, 2, first << 8 | value & 0xFF)
            return
        self._lcd_feed_data(address, size, value)

    def _lcd_write_gram_pixel(self, value: int) -> None:
        """Write a cursor-addressed ILI/Hitachi GRAM pixel without full copies."""
        x, y = self._lcd_gram_cursor
        if 0 <= x < self.config.width and 0 <= y < self.config.height:
            self._pixel(y * self.config.width + x, value)
            self._lcd_gram_dirty = True
        x += 1
        if x >= self.config.width:
            x, y = 0, y + 1
        self._lcd_gram_cursor[:] = [x, y]

    def _lcd_write(self, uc: Uc, access: int, address: int, size: int,
                   value: int, user_data: object) -> None:
        self.lcd_writes += 1
        self.lcd_port_writes[(address, size)] += 1
        if self._lcd_split_port_write(address, size, value):
            return
        if self._lcd_byte_raster_write(address, size, value):
            return
        if self._lcd_byte_020_row_write(address, size, value):
            return
        self._lcd_route_write(uc, access, address, size, value, user_data)

    def _lcd_route_write(self, uc: Uc, access: int, address: int, size: int,
                         value: int, user_data: object) -> None:
        self._lcd_lowbyte_page_event(address, size, value)
        # Match every LCD write while a direct-window candidate is held: an
        # intervening aperture access is a mismatch, not a later continuation.
        if self._lcd_028_direct_probe_write(address, size, value & 0xFFFF):
            return
        self._lcd_byte_rgb565_interrupt(address, size)
        if self._lcd_window_rgb565_write(address, size, value):
            return
        if address == 0x020000FA:
            self._lg_pixels.append(value & ((1 << (size * 8)) - 1))
            count = self.config.width * self.config.height * 2
            if len(self._lg_pixels) >= count:
                for index in range(0, count, 2):
                    first, second = self._lg_pixels[index:index + 2]
                    pixel = (((first & 3) << 14) | ((second >> 2) & 0x3800)
                             | ((second >> 1) & 0x07FF))
                    self._pixel(index // 2, pixel)
                del self._lg_pixels[:count]
                self._publish_frame()
            return
        # Two-wire parallel LCD controllers occur at both 0x020 and 0x02C.
        # A few boards instead use the base address as a 0/1 command/data
        # selector and +4 as its payload port.  Keep that transport distinct
        # until a non-selector base value proves an address-line controller.
        if address in (0x02000000, 0x02C00000):
            if (address == 0x02000000 and size == 1
                    and self._lcd_page_begin_command(
                        address, size, value, byte_wide=True
                    )
                    and self._lcd_page_qualified):
                return
            if (value in (0, 1)
                    and self._lcd_protocol not in (
                        "parallel-2", "direct", "cursor-bgr444")):
                if address == 0x02000000 and not value and self._lcd_selector_expected:
                    self._lcd_selector_reset()
                self._lcd_protocol = "selector-4"
                self._lcd_mode = value & 1
            else:
                if address == 0x02000000:
                    self._finish_020_raw_segment(value)
                    if self._lcd_bgr444_begin_command(size, value):
                        return
                self._lcd_protocol = "parallel-2"
                self._lcd_begin_command(value)
            return
        if address in (0x02000002,):
            if self._lcd_bgr444_feed(size, value):
                return
            self._lcd_protocol = "parallel-2"
            self._lcd_feed_parallel_data(address, size, value)
            return
        if address in (0x02000004, 0x02C00004):
            if (address == 0x02000004 and size == 1
                    and self._lcd_page_feed_data(address, size, value)):
                return
            if self._lcd_protocol == "selector-4":
                if self._lcd_mode:
                    if (address == 0x02000004
                            and self._lcd_selector_feed(size, value)):
                        return
                    self._lcd_feed_parallel_data(address, size, value)
                else:
                    if (address == 0x02000004
                            and self._lcd_selector_begin_command(size, value)):
                        return
                    self._lcd_begin_command(value)
            else:
                self._lcd_protocol = "parallel-2"
                self._lcd_feed_parallel_data(address, size, value)
            return
        # Some MSM5500 board designs use the same direct command/data scheme
        # at 0x02800000/+2.  Observe it before the indexed +4 decoder.
        if address == 0x02800002:
            if self._lcd_byte_rgb565_feed_data(address, size, value):
                return
            self._lcd_protocol = "parallel-2"
            self._lcd_feed_parallel_data(address, size, value)
            return
        # A later MSM5500 LCD board variant moves the same command/data pair
        # to +8/+C.  It is distinct from the indexed +16 register path below.
        if address == 0x02800008:
            if self._lcd_packed_begin_command(value):
                return
            self._lcd_protocol = "parallel-8"
            self._lcd_begin_command(value)
            return
        if address == 0x0280000C:
            if self._lcd_packed_feed_data(value):
                return
            self._lcd_protocol = "parallel-8"
            self._lcd_feed_parallel_data(address, size, value)
            return
        if not 0x02800000 <= address <= 0x0280001A:
            self._capture_raw_lcd_stream(address, size, value)
            return
        value &= 0xFFFF
        if address == 0x02800018:
            self._lcd_index = (self._lcd_index & 0xFFFF) | value << 16
            return
        if address == 0x0280001A:
            self._lcd_index = (self._lcd_index & 0xFFFF0000) | value
            return
        if address == 0x02800016:
            self._pixel(self._lcd_index, value)
            pixels = self.config.width * self.config.height
            self._lcd_index = (self._lcd_index + 1) % pixels
            self._lcd_indexed_dirty = True
            if self._lcd_index == 0:
                self._flush_indexed_frame()
            return
        self._lcd_write_028_legacy(address, size, value)
