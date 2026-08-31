"""Display methods owned by protocols/page."""
from __future__ import annotations

from collections import deque


_WINDOW_RAW8_SEPARATE_COMMAND_PORT = 0x02000000
_WINDOW_RAW8_SEPARATE_DATA_PORT = 0x02200002
_WINDOW_RAW8_SEPARATE_WIDTH = 64
_WINDOW_RAW8_SEPARATE_HEIGHT = 96
_RAW_LCD_STREAM_PORT_LIMIT = 32


class PageProtocolMixin:
    @staticmethod
    def _lcd_decode_shifted_pair_rgb565(
            values: tuple[int, ...], *, allow_blank: bool = False,
    ) -> list[int] | None:
        """Decode a full stream only when every shifted pair is exact."""
        if len(values) & 1 or (not allow_blank and not any(values)):
            return None
        pixels = []
        for first, second in zip(values[::2], values[1::2]):
            pixel = (second >> 1) | ((first & 0x100) << 7)
            expected_first = (
                ((pixel >> 8) & 0x7) | ((pixel >> 7) & 0x1F0)
            )
            if (first != expected_first
                    or second != (pixel << 1) & 0xFFFF):
                return None
            pixels.append(pixel)
        return pixels

    def _lcd_page_set_geometry(self) -> None:
        """Adopt a geometry proved by a byte-wide page-controller scan."""
        if (not self._lcd_page_qualified or not self._lcd_page_width
                or not self._lcd_page_height):
            return
        target = (self._lcd_page_width, self._lcd_page_height)
        changed = target != (self.config.width, self.config.height)
        if changed:
            # A 128-pixel-high panel identifies itself by reaching page B8
            # during its blank first scan, before we have published pixels.
            # Preserve an already visible frame rather than guessing its
            # geometry during a later rectangle update.
            self._set_display_geometry(
                *target, source=f"runtime:page-{self._lcd_page_bits_per_pixel}bpp",
                force=self.frame_sequence == 0,
            )
        if (target == (self.config.width, self.config.height)
                and (changed or not self._lcd_page_geometry_rendered)):
            self._lcd_page_geometry_rendered = True
            if self._lcd_page_render_all():
                self._lcd_protocol = f"page-{self._lcd_page_bits_per_pixel}bpp"
                self._publish_frame()

    @staticmethod
    def _lcd_page_layout(row_bytes: int,
                         width_hint: int | None) -> tuple[int, int]:
        """Separate physical columns from interleaved page bitplanes."""
        if (width_hint is not None and row_bytes % width_hint == 0
                and row_bytes // width_hint in (1, 2)):
            return width_hint, row_bytes // width_hint
        return row_bytes, 1

    def _lcd_page_render_column(self, page: int, column: int) -> bool:
        """Render one physical column from one or two interleaved bitplanes."""
        if not (0 <= page < self.config.height // 8
                and 0 <= column < self.config.width):
            return False
        bits_per_pixel = self._lcd_page_bits_per_pixel
        raw = page * 256 + column * bits_per_pixel
        ram = self._lcd_page_ram
        if raw + bits_per_pixel > len(ram):
            return False
        if bits_per_pixel not in (1, 2):
            planes = ram[raw:raw + bits_per_pixel]
            changed = False
            for bit in range(8):
                offset = ((page * 8 + bit) * self.config.width + column) * 3
                before = self.framebuffer[offset:offset + 3]
                level = 0
                for plane_index, value in enumerate(planes):
                    level |= ((value >> bit) & 1) << (
                        bits_per_pixel - plane_index - 1
                    )
                shade = level * 255 // ((1 << bits_per_pixel) - 1)
                self.framebuffer[offset:offset + 3] = bytes((shade,) * 3)
                changed |= before != self.framebuffer[offset:offset + 3]
            return changed
        first = ram[raw]
        second = ram[raw + 1] if bits_per_pixel == 2 else 0
        cache = getattr(self, "_lcd_page_shade_cache", None)
        if cache is None:
            cache = self._lcd_page_shade_cache = {}
        key = bits_per_pixel << 16 | second << 8 | first
        shades = cache.get(key)
        if shades is None:
            if bits_per_pixel == 1:
                shades = bytes(
                    ((first >> bit) & 1) * 255 for bit in range(8)
                )
            else:
                shades = bytes(
                    ((((first >> bit) & 1) << 1)
                     | ((second >> bit) & 1)) * 85
                    for bit in range(8)
                )
            # ponytail: bounded glyph cache; raise only if high-entropy page
            # panels are measured to benefit from a larger working set.
            if len(cache) < 1024:
                cache[key] = shades
        framebuffer = self.framebuffer
        width = self.config.width
        offset = (page * 8 * width + column) * 3
        stride = width * 3
        end = offset + stride * 8
        changed = (
            framebuffer[offset:end:stride] != shades
            or framebuffer[offset + 1:end:stride] != shades
            or framebuffer[offset + 2:end:stride] != shades
        )
        framebuffer[offset:end:stride] = shades
        framebuffer[offset + 1:end:stride] = shades
        framebuffer[offset + 2:end:stride] = shades
        return changed

    def _lcd_page_render_current(self) -> bool:
        """Apply the current page transfer after its protocol is validated."""
        if (not self._lcd_page_qualified or self._lcd_page_current < 0
                or not self._lcd_page_data_count):
            return False
        self._lcd_page_set_geometry()
        if (self.config.width, self.config.height) != (
                self._lcd_page_width, self._lcd_page_height):
            return False
        changed = False
        for column in range(self._lcd_page_width):
            changed |= self._lcd_page_render_column(self._lcd_page_current, column)
        return changed

    def _lcd_page_render_all(self) -> bool:
        """Restore page RAM after the first controller-proven geometry change."""
        if (self.config.width, self.config.height) != (
                self._lcd_page_width, self._lcd_page_height):
            return False
        changed = False
        for page in range(self._lcd_page_height // 8):
            for column in range(self._lcd_page_width):
                changed |= self._lcd_page_render_column(page, column)
        return changed

    def _lcd_page_flush_current(self) -> None:
        """Publish a validated partial page without treating a chunk as a row end."""
        if not self._lcd_page_dirty:
            return
        changed = self._lcd_page_render_current()
        self._lcd_page_dirty = False
        if changed:
            self._lcd_protocol = f"page-{self._lcd_page_bits_per_pixel}bpp"
            self._publish_frame()

    def _lcd_page_finish_transfer(self) -> None:
        """Close a page transfer when firmware selects the next command."""
        page = self._lcd_page_current
        count = self._lcd_page_data_count
        whole_row = (self._lcd_page_start_column == 0 and count in (128, 256))
        if whole_row:
            if not self._lcd_page_row_bytes:
                self._lcd_page_row_bytes = count
                (self._lcd_page_width,
                 self._lcd_page_bits_per_pixel) = self._lcd_page_layout(
                    count, self._lcd_page_width_hint
                )
                self._lcd_page_candidate_rows = 1
            elif (count == self._lcd_page_row_bytes
                  and page == self._lcd_page_last_finished + 1):
                self._lcd_page_candidate_rows += 1
            elif count == self._lcd_page_row_bytes:
                self._lcd_page_candidate_rows = 1
            elif not self._lcd_page_qualified:
                self._lcd_page_row_bytes = count
                (self._lcd_page_width,
                 self._lcd_page_bits_per_pixel) = self._lcd_page_layout(
                    count, self._lcd_page_width_hint
                )
                self._lcd_page_candidate_rows = 1
            self._lcd_page_last_finished = page
            if self._lcd_page_candidate_rows >= 2:
                self._lcd_page_qualified = True
        elif count and not self._lcd_page_qualified:
            self._lcd_page_candidate_rows = 0
        self._lcd_page_flush_current()

    def _lcd_page_begin_command(self, address: int, size: int, value: int,
                                *, byte_wide: bool = False) -> bool:
        """Recognise a page-LCD command grammar on its command port."""
        if (size not in (1, 2) or (size == 2 and value > 0xFF)
                or (byte_wide and size != 1)):
            return False
        command = value & 0xFF
        if 0xB0 <= command <= 0xBF:
            self._lcd_page_finish_transfer()
            page = command & 0x0F
            self._lcd_page_current = page
            self._lcd_page_port = address
            self._lcd_page_column_high = None
            self._lcd_page_column_ready = False
            self._lcd_page_column = 0
            self._lcd_page_start_column = 0
            self._lcd_page_data_count = 0
            self._lcd_page_seen.add(page)
            if page >= 8:
                self._lcd_page_height = 128
            elif (page == 0 and not self._lcd_page_height
                  and all(index in self._lcd_page_seen for index in range(8))):
                # A B0 restart after B0..B7 is a complete 64-pixel page scan.
                self._lcd_page_height = 64
            self._lcd_page_set_geometry()
            return True
        if (self._lcd_page_current < 0 or self._lcd_page_port != address):
            return False
        if 0x10 <= command <= 0x1F:
            if byte_wide and command != 0x10:
                self._lcd_page_finish_transfer()
                self._lcd_page_current = -1
                self._lcd_page_port = None
                self._lcd_page_column_high = None
                self._lcd_page_column_ready = False
                return False
            self._lcd_page_finish_transfer()
            self._lcd_page_data_count = 0
            self._lcd_page_column_high = command & 0x0F
            self._lcd_page_column_ready = False
            return True
        if 0x00 <= command <= 0x0F and self._lcd_page_column_high is not None:
            if byte_wide and (command or self._lcd_page_column_high):
                self._lcd_page_finish_transfer()
                self._lcd_page_current = -1
                self._lcd_page_port = None
                self._lcd_page_column_high = None
                self._lcd_page_column_ready = False
                return False
            self._lcd_page_finish_transfer()
            self._lcd_page_start_column = (
                self._lcd_page_column_high << 4 | command & 0x0F
            )
            self._lcd_page_column = self._lcd_page_start_column * (
                self._lcd_page_bits_per_pixel if self._lcd_page_qualified else 1
            )
            self._lcd_page_data_count = 0
            self._lcd_page_column_ready = True
            return True
        # A different command ends a page span; do not let its future data
        # bytes be mistaken for a continuation of the previous column run.
        self._lcd_page_finish_transfer()
        self._lcd_page_data_count = 0
        self._lcd_page_column_high = None
        self._lcd_page_column_ready = False
        if byte_wide:
            self._lcd_page_current = -1
            self._lcd_page_port = None
        return False

    def _lcd_page_feed_data(self, address: int, size: int, value: int) -> bool:
        """Record page-RAM data and consume it once the grammar is proven."""
        if (self._lcd_page_port is None
                or address != self._lcd_page_port + 4
                or size not in (1, 2)
                or (size == 2 and value > 0xFF)
                or (self._lcd_page_port == 0x02000000 and size != 1
                    and not self._lcd_page_qualified)
                or self._lcd_page_current < 0
                or not self._lcd_page_column_ready):
            return False
        column = self._lcd_page_column
        if 0 <= column < 256:
            self._lcd_page_ram[self._lcd_page_current * 256 + column] = value & 0xFF
            self._lcd_page_dirty = True
        self._lcd_page_column += 1
        self._lcd_page_data_count += 1
        return self._lcd_page_qualified

    def _lcd_lowbyte_page_reset(self, *, replay: bool) -> None:
        """Discard a failed sidecar only after restoring its raw FIFO words."""
        words = self._lcd_lowbyte_page_words
        self._lcd_lowbyte_page_stage = ""
        self._lcd_lowbyte_page_page = -1
        self._lcd_lowbyte_page_last = -1
        self._lcd_lowbyte_page_high = -1
        self._lcd_lowbyte_page_rows = 0
        self._lcd_lowbyte_page_words = []
        if replay:
            for word in words:
                self._capture_raw_lcd_stream(
                    0x02000004, 2, word, lowbyte_page_sidecar=False
                )

    def _lcd_lowbyte_page_event(self, address: int, size: int, value: int) -> None:
        """Track a strict sidecar candidate without changing normal routing."""
        stage = self._lcd_lowbyte_page_stage
        data = (address == 0x02000004 and size == 2 and 0 <= value <= 0xFF)
        if stage == "data" and data:
            return
        command = (value if address == 0x02000000 and size == 1
                   and 0 <= value <= 0xFF else None)
        if stage == "high" and command is not None and 0x10 <= command <= 0x1F:
            self._lcd_lowbyte_page_high = command & 0x0F
            self._lcd_lowbyte_page_stage = "low"
            return
        if stage == "low" and command is not None and 0 <= command <= 0x0F:
            if (self._lcd_lowbyte_page_high << 4 | command) == 4:
                self._lcd_lowbyte_page_stage = "data"
                return
        if (stage == "next" and command is not None and 0xB0 <= command <= 0xB7
                and (command & 0x0F) == self._lcd_lowbyte_page_last + 1):
            self._lcd_lowbyte_page_page = command & 0x0F
            self._lcd_lowbyte_page_stage = "high"
            return
        if stage:
            self._lcd_lowbyte_page_reset(replay=True)
        if command is not None and 0xB0 <= command <= 0xB7:
            self._lcd_lowbyte_page_page = command & 0x0F
            self._lcd_lowbyte_page_stage = "high"

    def _lcd_lowbyte_page_raw_word(self, address: int, size: int, value: int) -> bool:
        """Buffer one strict candidate word; suppress only after two rows."""
        if (self._lcd_lowbyte_page_stage != "data" or address != 0x02000004
                or size != 2 or not 0 <= value <= 0xFF):
            return False
        self._lcd_lowbyte_page_words.append(value)
        if len(self._lcd_lowbyte_page_words) % 96:
            return True
        self._lcd_lowbyte_page_last = self._lcd_lowbyte_page_page
        self._lcd_lowbyte_page_rows = min(2, self._lcd_lowbyte_page_rows + 1)
        self._lcd_lowbyte_page_stage = "next"
        if self._lcd_lowbyte_page_rows == 2:
            self._lcd_lowbyte_page_words.clear()
        return True

    def _capture_raw_lcd_stream(self, address: int, size: int, value: int,
                                *, lowbyte_page_sidecar: bool = True) -> None:
        """Render a proven full FIFO stream from an otherwise unknown LCD port.

        Older handsets move RGB565 pixels through board-specific addresses in
        the 0x02000000 LCD aperture.  Their controller programming is still
        firmware-owned, so this fallback deliberately does *not* invent a
        command response: it merely exposes a full, sustained pixel-sized
        write stream after it has happened.  The ordinary command decoders
        take precedence and therefore remain lossless for known panels.
        """
        if (lowbyte_page_sidecar
                and self._lcd_lowbyte_page_raw_word(address, size, value)):
            return
        if size != 2 or not (
                0x02000000 <= address < 0x02001000
                or address in (0x02800004, 0x0280000C)
                or 0x02800020 <= address < 0x02801000):
            return
        # 0x020000FA is the packed LG stream handled above.  Capturing its
        # halfwords again would desynchronise the already validated decoder.
        if address == 0x020000FA:
            return
        pixels = self.config.width * self.config.height
        if pixels <= 0:
            return
        port = (address, size)
        source = getattr(
            self.config, "display_geometry_source", "external-config"
        )
        shifted_pair_qualified = (
            source == "runtime:shifted-pair-fifo-rgb565"
            and (self.config.width, self.config.height) == (176, 220)
            and self._lcd_raw_port == port
        )
        shifted_pair_candidate = (
            0x02000000 <= address < 0x02001000
            and (self.config.width, self.config.height) == (176, 220)
            and (source == "auto-default" or shifted_pair_qualified)
        )
        stream = self._lcd_raw_streams.get(port)
        if stream is None:
            if len(self._lcd_raw_streams) >= _RAW_LCD_STREAM_PORT_LIMIT:
                victim = next((candidate for candidate in self._lcd_raw_streams
                               if candidate != self._lcd_raw_port), None)
                if victim is None:
                    return
                self._lcd_raw_streams.pop(victim, None)
                self._lcd_raw_counts.pop(victim, None)
                self._lcd_raw_frames.pop(victim, None)
                self._lcd_raw_segment_streams.pop(victim, None)
                self._lcd_raw_segment_counts.pop(victim, None)
            stream = deque(maxlen=2 * pixels if shifted_pair_candidate else pixels)
            self._lcd_raw_streams[port] = stream
        stream.append(value & 0xFFFF)
        self._lcd_raw_counts[port] += 1
        # X800-class boards use +2 as a raw RGB565 FIFO.  Preserve each
        # command-delimited transfer separately so an exact 128x160 raster
        # cannot be obscured by later short register/rectangle writes.
        if port == (0x02000002, 2):
            segment = self._lcd_raw_segment_streams.get(port)
            if segment is None:
                segment = deque(maxlen=2 * 176 * 220)
                self._lcd_raw_segment_streams[port] = segment
            segment.append(value & 0xFFFF)
            self._lcd_raw_segment_counts[port] += 1
        count = self._lcd_raw_counts[port]
        commands = tuple(self._lcd_recent_commands)
        if (port == (0x02000004, 2) and count == 96
                and len(commands) >= 3 and 0xB0 <= commands[-3] <= 0xB7
                and commands[-2:] == (0x12, 0x00)
                and not any(pixel > 0xFF for pixel in stream)):
            # X150 sends 96 low-byte page words after this exact grammar.
            # They are not fragments of a rolling RGB565 raster.
            stream.clear()
            self._lcd_raw_counts[port] = 0
            return
        if (port == (0x02800004, 2) and len(commands) >= 6
                and commands[-6] == 0x43 and commands[-3] == 0x42):
            x0, x1 = commands[-5:-3]
            y0, y1 = commands[-2:]
            width, height = x1 - x0 + 1, y1 - y0 + 1
            expected = width * height
            if width > 0 and height > 0 and count == expected:
                geometry = self._lcd_full_window_geometry(
                    [x0, x1], [y0, y1]
                )
                source = getattr(
                    self.config, "display_geometry_source", "external-config"
                )
                if (geometry is not None
                        and (geometry == (self.config.width, self.config.height)
                             or source == "auto-default")):
                    self._set_display_geometry(
                        *geometry, source="runtime:window-fifo"
                    )
                    self._lcd_028_window_fifo_qualified = (
                        geometry == (self.config.width, self.config.height)
                    )
                if (self._lcd_028_window_fifo_qualified
                        and x1 < self.config.width
                        and y1 < self.config.height):
                    for index, pixel in enumerate(stream):
                        x = x0 + index % width
                        y = y0 + index // width
                        self._pixel(y * self.config.width + x, pixel)
                    self._lcd_raw_frames[port] += 1
                    self._lcd_raw_port = port
                    self._lcd_protocol = "window-fifo-rgb565"
                    self._publish_frame()
                    stream.clear()
                    self._lcd_raw_counts[port] = 0
                    return
        # A 128x160 RGB565 scanout is common on the unknown-name Samsung/KTF
        # dumps.  When an otherwise unclassified +4 FIFO reaches *exactly*
        # that full raster before the generic 176x220 threshold, it is stronger
        # evidence than the filename fallback.  Known model geometry is left
        # untouched, as a 128x160 transfer can also be a rectangle update.
        if shifted_pair_candidate:
            words = 2 * pixels
            if shifted_pair_qualified and count < words:
                return
            if count in (pixels, words):
                values = tuple(stream)
                decoded = self._lcd_decode_shifted_pair_rgb565(
                    values, allow_blank=shifted_pair_qualified
                ) if len(values) == count else None
                if decoded is not None and count == pixels:
                    return
                if decoded is not None:
                    self._set_display_geometry(
                        176, 220, source="runtime:shifted-pair-fifo-rgb565"
                    )
                    for index, pixel in enumerate(decoded):
                        self._pixel(index, pixel)
                    self._lcd_raw_frames[port] += 1
                    self._lcd_raw_port = port
                    self._lcd_protocol = "shifted-pair-fifo-rgb565"
                    self._lcd_expected = 0
                    self._lcd_streamed = 0
                    self._publish_frame()
                    segment = self._lcd_raw_segment_streams.get(port)
                    if segment is not None:
                        segment.clear()
                    self._lcd_raw_segment_counts[port] = 0
                    stream.clear()
                    self._lcd_raw_counts[port] = 0
                    return
                if shifted_pair_qualified:
                    stream.clear()
                    self._lcd_raw_counts[port] = 0
                    return
                # Preserve the generic RGB565 path after a near miss.
                stream = deque(values[-pixels:], maxlen=pixels)
                self._lcd_raw_streams[port] = stream
        paired_qualified = (
            source == "runtime:paired-fifo-rgb565"
            and (self.config.width, self.config.height) == (120, 160)
            and self._lcd_protocol == "paired-fifo-rgb565"
        )
        if paired_qualified and port == (0x02000080, 2):
            if count < 2 * 120 * 160:
                return
            if count == 2 * 120 * 160:
                values = tuple(stream)
                paired = len(values) == 2 * 120 * 160 and any(values)
                if paired:
                    for index in range(0, len(values), 2):
                        first, second = values[index], values[index + 1]
                        if (first & 0x0400 or second & 1
                                or (first & 0x03FF)
                                != (second >> 2 & 0x03FF)):
                            paired = False
                            break
                if paired:
                    for index in range(0, len(values), 2):
                        first, second = values[index], values[index + 1]
                        self._pixel(
                            index // 2,
                            (first & 0xF800) | (second >> 1 & 0x07FF),
                        )
                    self._lcd_raw_frames[port] += 1
                    self._lcd_raw_port = port
                    self._lcd_protocol = "paired-fifo-rgb565"
                    self._publish_frame()
                stream.clear()
                self._lcd_raw_counts[port] = 0
                return
        packed_rgb666_qualified = (
            source == "runtime:packed-fifo-rgb666"
            and (self.config.width, self.config.height) == (120, 160)
        )
        # This FIFO stays two-halfword RGB666 after its first full frame.
        # Hold the complete pair stream so the generic RGB565 fallback cannot
        # publish each 19,200-word half as a separate corrupted frame.
        if (port == (0x02000080, 2)
                and ((self.frame_sequence == 0 and source == "auto-default")
                     or packed_rgb666_qualified)):
            if packed_rgb666_qualified and count < 2 * 120 * 160:
                return
            if count == 2 * 120 * 160:
                values = tuple(stream)
                packed_rgb666 = (
                    len(values) == 2 * 120 * 160 and any(values)
                    and all(not (first & ~0x3) for first in values[::2])
                )
                if packed_rgb666:
                    if not packed_rgb666_qualified:
                        self._set_display_geometry(
                            120, 160, source="runtime:packed-fifo-rgb666"
                        )
                    framebuffer = self.framebuffer
                    for offset in range(0, len(values), 2):
                        pixel = values[offset] << 16 | values[offset + 1]
                        output = offset // 2 * 3
                        framebuffer[output] = (pixel >> 12 & 0x3F) * 255 // 63
                        framebuffer[output + 1] = (
                            (pixel >> 6 & 0x3F) * 255 // 63
                        )
                        framebuffer[output + 2] = (pixel & 0x3F) * 255 // 63
                    self._lcd_raw_frames[port] += 1
                    self._lcd_raw_port = port
                    self._lcd_protocol = "packed-fifo-rgb666"
                    self._publish_frame()
                    stream.clear()
                    # Initial geometry promotion clears these dictionaries.
                    self._lcd_raw_streams[port] = stream
                    self._lcd_raw_counts[port] = 0
                    return
                if packed_rgb666_qualified:
                    stream.clear()
                    self._lcd_raw_counts[port] = 0
                    return
        if self.frame_sequence == 0:
            # Some boards split one RGB565 pixel into two adjacent halfwords:
            # the first retains red and the upper ten low-color bits, and the
            # second is the original word shifted left once.  Require every
            # pair before replacing the ordinary 160x240 raw-FIFO fallback.
            if (getattr(self.config, "display_geometry_source", "external-config")
                    == "auto-default"
                    and port == (0x02000080, 2)
                    and count == 2 * 120 * 160):
                values = tuple(stream)
                paired = len(values) == 2 * 120 * 160 and any(values)
                if paired:
                    for index in range(0, len(values), 2):
                        first, second = values[index], values[index + 1]
                        if (first & 0x0400 or second & 1
                                or (first & 0x03FF) != (second >> 2 & 0x03FF)):
                            paired = False
                            break
                if paired:
                    self._set_display_geometry(
                        120, 160, source="runtime:paired-fifo-rgb565"
                    )
                    for index in range(0, len(values), 2):
                        first, second = values[index], values[index + 1]
                        self._pixel(
                            index // 2,
                            (first & 0xF800) | (second >> 1 & 0x07FF),
                        )
                    self._lcd_raw_frames[port] += 1
                    self._lcd_raw_port = port
                    self._lcd_protocol = "paired-fifo-rgb565"
                    self._publish_frame()
                    stream.clear()
                    # Geometry promotion clears the raw dictionaries. Keep
                    # this proven port and its full-pair capacity for frame 2+.
                    self._lcd_raw_streams[port] = stream
                    self._lcd_raw_counts[port] = 0
                    return
            if (getattr(self.config, "display_geometry_source", "external-config")
                    == "auto-default"
                    and address in (0x02000004, 0x02800004, 0x02C00004)
                    and count == 128 * 160):
                self._set_display_geometry(
                    128, 160, source="runtime:raw-fifo"
                )
            # The KP8500/LP2400-style FIFO has a fixed 160x240 transfer at
            # an otherwise unused LCD aperture.  Its exact 38,400-pixel run
            # is sufficient proof of panel size before publishing a frame.
            elif (getattr(self.config, "display_geometry_source", "external-config")
                  == "auto-default"
                  and address in (0x02000080, 0x02800080)
                  and count == 160 * 240):
                self._set_display_geometry(
                    160, 240, source="runtime:raw-fifo"
                )
        pixels = self.config.width * self.config.height
        # A partial transfer is often a command table or a rectangle update;
        # require a complete scanout before treating it as a framebuffer.
        if count < pixels or count % pixels:
            return
        values = tuple(stream)
        if len(values) != pixels or not any(values):
            return
        for index, pixel in enumerate(values):
            self._pixel(index, pixel)
        self._lcd_raw_frames[port] += 1
        self._lcd_raw_port = port
        self._lcd_protocol = f"raw-fifo@0x{address:08X}"
        self._publish_frame()

    def _finish_020_raw_segment(self, incoming_command: int) -> None:
        """Promote controller-delimited +2 raw RGB565 rasters."""
        port = (0x02000002, 2)
        count = self._lcd_raw_segment_counts[port]
        stream = self._lcd_raw_segment_streams.get(port)
        source = getattr(
            self.config, "display_geometry_source", "external-config"
        )
        shifted_pair_qualified = (
            source == "runtime:shifted-pair-fifo-rgb565"
            and (self.config.width, self.config.height) == (176, 220)
            and self._lcd_raw_port == port
        )
        if (stream is not None and count == 2 * 176 * 220
                and (source == "auto-default" or shifted_pair_qualified)):
            values = tuple(stream)
            decoded = self._lcd_decode_shifted_pair_rgb565(
                values, allow_blank=shifted_pair_qualified
            )
            if decoded is not None:
                self._set_display_geometry(
                    176, 220, source="runtime:shifted-pair-fifo-rgb565"
                )
                for index, pixel in enumerate(decoded):
                    self._pixel(index, pixel)
                self._lcd_raw_frames[port] += 1
                self._lcd_raw_port = port
                self._lcd_protocol = "shifted-pair-fifo-rgb565"
                self._lcd_expected = 0
                self._lcd_streamed = 0
                self._publish_frame()
                self._lcd_raw_streams[port] = deque(maxlen=2 * 176 * 220)
                self._lcd_raw_counts[port] = 0
        elif (stream is not None and count == 128 * 160
                and getattr(self.config, "display_geometry_source",
                            "external-config") == "auto-default"
                and self.frame_sequence == 0
                and incoming_command & 0xFF == 0x43):
            values = tuple(stream)
            if len(values) == 128 * 160 and any(values):
                self._set_display_geometry(
                    128, 160, source="runtime:raw-fifo"
                )
                for index, pixel in enumerate(values):
                    self._pixel(index, pixel)
                self._lcd_raw_frames[port] += 1
                self._lcd_raw_port = port
                self._lcd_protocol = "raw-fifo@0x02000002"
                self._publish_frame()
        elif (stream is not None and count == 120 * 160
              and incoming_command == 0x1002
              and getattr(self.config, "display_geometry_source",
                          "external-config") in (
                              "auto-default", "runtime:raw-fifo-120x160")):
            # A full-word 0x1002 terminator closes an exact 120x160 RGB565
            # scanout on this command/data pair.  Ignore a blank clear pass;
            # a nonzero complete pass proves both the geometry and encoding.
            values = tuple(stream)
            if len(values) == 120 * 160 and any(values):
                self._set_display_geometry(
                    120, 160, source="runtime:raw-fifo-120x160"
                )
                if (self.config.width, self.config.height) == (120, 160):
                    for index, pixel in enumerate(values):
                        self._pixel(index, pixel)
                    self._lcd_raw_frames[port] += 1
                    self._lcd_raw_port = port
                    self._lcd_protocol = "raw-fifo@0x02000002"
                    self._publish_frame()
        if stream is not None:
            stream.clear()
        self._lcd_raw_segment_counts[port] = 0

    def _lcd_window_raw8_separate_reset(self, *, replay: bool) -> None:
        """Reject an incomplete separate-data raw8 candidate without loss."""
        events = tuple(self._lcd_window_raw8_separate_events)
        self._lcd_window_raw8_separate_events.clear()
        self._lcd_window_raw8_separate_stage = ""
        self._lcd_window_raw8_separate_axis.clear()
        self._lcd_window_raw8_separate_window = None
        self._lcd_window_raw8_separate_payload.clear()
        if replay:
            for address, size, value in events:
                self._lcd_route_write(None, 0, address, size, value, None)

    def _lcd_window_raw8_separate_publish(
        self, window: tuple[int, int, int, int], payload: bytes,
    ) -> bool:
        """Render a complete 64x96 raw8 window as a grayscale preview."""
        x0, x1, y0, y1 = window
        if not self._lcd_window_raw8_separate_qualified:
            if window != (0, _WINDOW_RAW8_SEPARATE_WIDTH - 1,
                          0, _WINDOW_RAW8_SEPARATE_HEIGHT - 1):
                return False
            self._set_display_geometry(
                _WINDOW_RAW8_SEPARATE_WIDTH, _WINDOW_RAW8_SEPARATE_HEIGHT,
                source="runtime:window-raw8",
            )
            if (self.config.width, self.config.height) != (
                    _WINDOW_RAW8_SEPARATE_WIDTH, _WINDOW_RAW8_SEPARATE_HEIGHT):
                return False
            self._lcd_window_raw8_separate_qualified = True
        elif (self.config.width, self.config.height) != (
                _WINDOW_RAW8_SEPARATE_WIDTH, _WINDOW_RAW8_SEPARATE_HEIGHT):
            return False
        ram = self._lcd_window_raw8_separate_ram
        width = x1 - x0 + 1
        for index, shade in enumerate(payload):
            x = x0 + index % width
            y = y0 + index // width
            ram[y * _WINDOW_RAW8_SEPARATE_WIDTH + x] = shade
            offset = (y * self.config.width + x) * 3
            self.framebuffer[offset:offset + 3] = bytes((shade,)) * 3
        self._lcd_protocol = "window-raw8-gray"
        self._publish_frame()
        return True

    def _lcd_window_raw8_separate_mismatch(
        self, event: tuple[int, int, int],
    ) -> bool:
        self._lcd_window_raw8_separate_reset(replay=True)
        if event == (_WINDOW_RAW8_SEPARATE_COMMAND_PORT, 1, 0x07):
            self._lcd_window_raw8_separate_events.append(event)
            self._lcd_window_raw8_separate_stage = "x"
            return True
        return False

    def _lcd_window_raw8_separate_write(self, address: int, size: int,
                                        value: int) -> bool:
        """Recognise 07/x/06/y/08 raw8 windows on a separate data aperture."""
        event = (address, size, value)
        stage = self._lcd_window_raw8_separate_stage
        data = (address == _WINDOW_RAW8_SEPARATE_DATA_PORT and size == 1
                and 0 <= value <= 0xFF)
        if not stage:
            if event == (_WINDOW_RAW8_SEPARATE_COMMAND_PORT, 1, 0x07):
                self._lcd_window_raw8_separate_events.append(event)
                self._lcd_window_raw8_separate_stage = "x"
                return True
            return False
        if stage == "x":
            if not data:
                return self._lcd_window_raw8_separate_mismatch(event)
            self._lcd_window_raw8_separate_events.append(event)
            self._lcd_window_raw8_separate_axis.append(value)
            if len(self._lcd_window_raw8_separate_axis) < 2:
                return True
            x0, x1 = self._lcd_window_raw8_separate_axis
            if not (0 <= x0 <= x1 < _WINDOW_RAW8_SEPARATE_WIDTH):
                self._lcd_window_raw8_separate_events.pop()
                return self._lcd_window_raw8_separate_mismatch(event)
            self._lcd_window_raw8_separate_axis.clear()
            self._lcd_window_raw8_separate_window = (x0, x1, -1, -1)
            self._lcd_window_raw8_separate_stage = "y-command"
            return True
        if stage == "y-command":
            if event == (_WINDOW_RAW8_SEPARATE_COMMAND_PORT, 1, 0x06):
                self._lcd_window_raw8_separate_events.append(event)
                self._lcd_window_raw8_separate_stage = "y"
                return True
            return self._lcd_window_raw8_separate_mismatch(event)
        if stage == "y":
            if not data:
                return self._lcd_window_raw8_separate_mismatch(event)
            self._lcd_window_raw8_separate_events.append(event)
            self._lcd_window_raw8_separate_axis.append(value)
            if len(self._lcd_window_raw8_separate_axis) < 2:
                return True
            y0, y1 = self._lcd_window_raw8_separate_axis
            if not (0 <= y0 <= y1 < _WINDOW_RAW8_SEPARATE_HEIGHT):
                self._lcd_window_raw8_separate_events.pop()
                return self._lcd_window_raw8_separate_mismatch(event)
            x0, x1, _, _ = self._lcd_window_raw8_separate_window
            self._lcd_window_raw8_separate_axis.clear()
            self._lcd_window_raw8_separate_window = (x0, x1, y0, y1)
            self._lcd_window_raw8_separate_stage = "pixels-command"
            return True
        if stage == "pixels-command":
            if event == (_WINDOW_RAW8_SEPARATE_COMMAND_PORT, 1, 0x08):
                self._lcd_window_raw8_separate_events.append(event)
                self._lcd_window_raw8_separate_stage = "pixels"
                return True
            return self._lcd_window_raw8_separate_mismatch(event)
        if not data:
            return self._lcd_window_raw8_separate_mismatch(event)
        self._lcd_window_raw8_separate_events.append(event)
        self._lcd_window_raw8_separate_payload.append(value)
        x0, x1, y0, y1 = self._lcd_window_raw8_separate_window
        expected = (x1 - x0 + 1) * (y1 - y0 + 1)
        if len(self._lcd_window_raw8_separate_payload) < expected:
            return True
        if self._lcd_window_raw8_separate_publish(
                self._lcd_window_raw8_separate_window,
                bytes(self._lcd_window_raw8_separate_payload)):
            self._lcd_window_raw8_separate_reset(replay=False)
        else:
            self._lcd_window_raw8_separate_reset(replay=True)
        return True

    def _lcd_window_raw8_reset(self, *, replay: bool) -> None:
        """Drop one incomplete byte-window candidate without losing traffic."""
        header = tuple(self._lcd_window_raw8_header)
        payload = bytes(self._lcd_window_raw8_payload)
        self._lcd_window_raw8_header.clear()
        self._lcd_window_raw8_payload.clear()
        self._lcd_window_raw8_window = None
        if not replay:
            return
        for address, size, value in header:
            self._lcd_route_write(None, 0, address, size, value, None)
        for value in payload:
            self._lcd_route_write(
                None, 0, 0x02000002, 1, value, None
            )

    def _lcd_window_raw8_publish(self) -> None:
        """Render one area-closed raw8 window as an encoding-neutral preview."""
        window = self._lcd_window_raw8_window
        if window is None:
            return
        rgb332 = bool(
            self._lcd_window_raw8_header
            and self._lcd_window_raw8_header[0][2] == 0x21
        )
        x0, y0, x1, y1 = window
        payload = bytes(self._lcd_window_raw8_payload)
        if not self._lcd_window_raw8_qualified:
            self._set_display_geometry(
                128, 128, source="runtime:window-raw8-preview"
            )
            if (self.config.width, self.config.height) != (128, 128):
                self._lcd_window_raw8_reset(replay=True)
                return
            self._lcd_window_raw8_qualified = True
        width = x1 - x0 + 1
        cursor = 0
        for y in range(y0, y1 + 1):
            row = payload[cursor:cursor + width]
            cursor += width
            raw = y * 128 + x0
            self._lcd_window_raw8_ram[raw:raw + width] = row
            if rgb332:
                for index, packed in enumerate(row):
                    self._lcd_028_rgb332_pixel(raw + index, packed)
            else:
                rgb = bytearray(width * 3)
                rgb[0::3] = row
                rgb[1::3] = row
                rgb[2::3] = row
                offset = raw * 3
                self.framebuffer[offset:offset + len(rgb)] = rgb
        self._lcd_window_raw8_header.clear()
        self._lcd_window_raw8_payload.clear()
        self._lcd_window_raw8_window = None
        self._lcd_protocol = (
            "window-raw8-rgb332" if rgb332 else "window-raw8-preview"
        )
        self._publish_frame()

    def _lcd_window_raw8_write(self, address: int, size: int,
                               value: int) -> bool:
        """Recognise area-closed byte windows, including proven axis reorder."""
        start_31 = (0x02000000, 1, 0x31)
        start_21 = (0x02000000, 1, 0x21)
        starts = ((start_31, start_21) if self._lcd_window_raw8_qualified
                  else (start_31,))
        event = (address, size, value)
        header = self._lcd_window_raw8_header
        window = self._lcd_window_raw8_window
        if window is not None:
            if event in starts:
                self._lcd_window_raw8_reset(replay=True)
                header.append(event)
                return True
            if address == 0x02000000 and size == 1 and 0 <= value <= 0xFF:
                # Observed controller commands can interleave a payload.
                self._lcd_route_write(None, 0, address, size, value, None)
                return True
            if address == 0x02000002 and size == 1 and 0 <= value <= 0xFF:
                self._lcd_window_raw8_payload.append(value)
                x0, y0, x1, y1 = window
                if len(self._lcd_window_raw8_payload) == (
                        (x1 - x0 + 1) * (y1 - y0 + 1)):
                    self._lcd_window_raw8_publish()
                return True
            self._lcd_window_raw8_reset(replay=True)
            self._lcd_route_write(None, 0, address, size, value, None)
            return True
        if not header:
            if event not in starts:
                return False
            header.append(event)
            return True
        expected_axis = 0x21 if header[0][2] == 0x31 else 0x31
        if (event in starts
                and not (len(header) == 3 and value == expected_axis)):
            self._lcd_window_raw8_reset(replay=True)
            header.append(event)
            return True
        if address != 0x02000000 or size != 1 or not 0 <= value <= 0xFF:
            self._lcd_window_raw8_reset(replay=True)
            self._lcd_route_write(None, 0, address, size, value, None)
            return True
        if len(header) == 3 and value != expected_axis:
            header.append(event)
            self._lcd_window_raw8_reset(replay=True)
            return True
        header.append(event)
        if len(header) < 6:
            return True
        first0, first1, second0, second1 = (
            header[1][2], header[2][2], header[4][2], header[5][2])
        if header[0][2] == 0x31:
            y0, y1, x0, x1 = first0, first1, second0, second1
        else:
            # The qualified UI writer uses 0x21 for its y bounds, then 0x31
            # for x, and streams x-fast RGB332 rows.
            y0, y1, x0, x1 = first0, first1, second0, second1
        valid = (
            0 <= x0 <= x1 < 128 and 0 <= y0 <= y1 < 128
            and (self._lcd_window_raw8_qualified
                 or (x0, y0, x1, y1) == (0, 0, 127, 127))
            and (not self._lcd_window_raw8_qualified
                 or (self.config.width, self.config.height) == (128, 128))
        )
        if not valid:
            self._lcd_window_raw8_reset(replay=True)
            return True
        self._lcd_window_raw8_window = (x0, y0, x1, y1)
        return True

    def _lcd_byte_020_row_reset(self, *, replay: bool) -> None:
        """Reject an incomplete byte-row candidate without swallowing traffic."""
        events = tuple(self._lcd_byte_020_row_events)
        self._lcd_byte_020_row_probe.clear()
        self._lcd_byte_020_row_events.clear()
        self._lcd_byte_020_row_stage = ""
        self._lcd_byte_020_row_y = -1
        self._lcd_byte_020_row_words.clear()
        if replay:
            for address, size, value in events:
                self._lcd_route_write(None, 0, address, size, value, None)

    def _lcd_byte_020_row_commit(self, command: int, word: int) -> bool:
        """Consume one proven byte-row packet, or fail closed to legacy LCD paths."""
        if command == 0x05 and word == 0x14 and self._lcd_byte_020_row_stage in ("", "ready"):
            self._lcd_byte_020_row_stage = "x"
            return True
        if command == 0x10 and word == 0 and self._lcd_byte_020_row_stage == "x":
            self._lcd_byte_020_row_stage = "y"
            return True
        if (command == 0x11 and self._lcd_byte_020_row_stage == "y"
                and self.config.width >= 128 and 0 <= word < self.config.height):
            self._lcd_byte_020_row_y = word
            self._lcd_byte_020_row_stage = "data"
            self._lcd_byte_020_row_words.clear()
            return True
        if command == 0x12 and self._lcd_byte_020_row_stage == "data":
            words = self._lcd_byte_020_row_words
            words.append(word)
            if len(words) < 128:
                return True
            if len(words) == 128:
                y, row = self._lcd_byte_020_row_y, tuple(words)
                self._lcd_byte_020_row_events.clear()
                self._lcd_byte_020_row_stage = "ready"
                self._lcd_byte_020_row_y = -1
                words.clear()
                was_published = self._lcd_protocol == "byte-row-rgb565"
                for x, pixel in enumerate(row):
                    self._pixel(y * self.config.width + x, pixel)
                if any(row) or was_published:
                    self._lcd_protocol = "byte-row-rgb565"
                    self._publish_frame()
                return True
        self._lcd_byte_020_row_reset(replay=True)
        return True

    def _lcd_byte_020_row_write(self, address: int, size: int, value: int) -> bool:
        """Recognise exact 0x02000000/+2 byte-row RGB565 packets."""
        event = (address, size, value)
        probe = self._lcd_byte_020_row_probe
        expected = ((0x02000000, 1), (0x02000000, 1),
                    (0x02000002, 1), (0x02000002, 1))
        if not probe:
            if (address, size, value) != (0x02000000, 1, 0):
                if self._lcd_byte_020_row_stage not in ("", "ready"):
                    self._lcd_byte_020_row_events.append(event)
                    self._lcd_byte_020_row_reset(replay=True)
                    return True
                return False
            probe.append(event)
            self._lcd_byte_020_row_events.append(event)
            return True
        wanted_address, wanted_size = expected[len(probe)]
        if ((address, size) != (wanted_address, wanted_size)
                or not 0 <= value <= 0xFF):
            self._lcd_byte_020_row_events.append(event)
            self._lcd_byte_020_row_reset(replay=True)
            return True
        probe.append(event)
        self._lcd_byte_020_row_events.append(event)
        if len(probe) < len(expected):
            return True
        _zero, command, high, low = probe
        probe.clear()
        return self._lcd_byte_020_row_commit(
            command[2], high[2] << 8 | low[2]
        )

    def _lcd_byte_raster_write(self, address: int, size: int,
                               value: int) -> bool:
        """Observe a complete 128x160 byte-command RGB565 raster."""
        if size != 1 or address not in (0x02000000, 0x02000002):
            return False
        stage = self._lcd_byte_raster_stage
        if address == 0x02000000:
            expected = {"": 0x05, "x-command": 0x03,
                        "pixels-command": 0x0B, "done-command": 0x2B}
            if expected.get(stage) == value:
                self._lcd_byte_raster_stage = {
                    "": "row", "x-command": "x",
                    "pixels-command": "pixels", "done-command": "done",
                }[stage]
            else:
                self._lcd_byte_raster_stage = "row" if value == 0x05 else ""
                self._lcd_byte_raster_row = 0
                self._lcd_byte_raster_pixels.clear()
            return False
        if stage == "row" and value == self._lcd_byte_raster_row:
            self._lcd_byte_raster_stage = "x-command"
        elif stage == "x" and value == 0:
            self._lcd_byte_raster_stage = "pixels-command"
        elif stage == "pixels":
            self._lcd_byte_raster_pixels.append(value)
            row_bytes = len(self._lcd_byte_raster_pixels) - self._lcd_byte_raster_row * 256
            if row_bytes == 256:
                self._lcd_byte_raster_row += 1
                self._lcd_byte_raster_stage = (
                    "done-command" if self._lcd_byte_raster_row == 160 else ""
                )
        elif stage == "done" and value == 1:
            payload = bytes(self._lcd_byte_raster_pixels)
            self._set_display_geometry(
                128, 160, source="runtime:byte-raster-rgb565", force=True
            )
            if (self.config.width, self.config.height) != (128, 160):
                self._lcd_byte_raster_stage = "qualified"
                return True
            for index in range(0, len(payload), 2):
                self._pixel(index // 2, payload[index] << 8 | payload[index + 1])
            self._lcd_protocol = "byte-raster-rgb565"
            self._publish_frame()
            self._lcd_byte_raster_stage = "qualified"
            return True
        else:
            self._lcd_byte_raster_stage = ""
            self._lcd_byte_raster_row = 0
            self._lcd_byte_raster_pixels.clear()
        return False
