"""Display methods owned by protocols/page."""
from __future__ import annotations

from collections import deque


class PageProtocolMixin:
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
            self._set_display_geometry(*target, force=self.frame_sequence == 0)
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
        planes = self._lcd_page_ram[raw:raw + bits_per_pixel]
        if len(planes) != bits_per_pixel:
            return False
        changed = False
        for bit in range(8):
            index = (page * 8 + bit) * self.config.width + column
            offset = index * 3
            before = self.framebuffer[offset:offset + 3]
            level = 0
            for plane_index, value in enumerate(planes):
                level |= ((value >> bit) & 1) << (
                    bits_per_pixel - plane_index - 1
                )
            shade = level * 255 // ((1 << bits_per_pixel) - 1)
            self.framebuffer[offset:offset + 3] = bytes((shade, shade, shade))
            changed |= before != self.framebuffer[offset:offset + 3]
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
        if self._lcd_page_render_current():
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
                or (self._lcd_page_port == 0x02000000 and size != 1)
                or self._lcd_page_current < 0
                or not self._lcd_page_column_ready):
            return False
        column = self._lcd_page_column
        if 0 <= column < 256:
            self._lcd_page_ram[self._lcd_page_current * 256 + column] = value & 0xFF
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
        stream = self._lcd_raw_streams.get(port)
        if stream is None:
            stream = deque(maxlen=pixels)
            self._lcd_raw_streams[port] = stream
        stream.append(value & 0xFFFF)
        self._lcd_raw_counts[port] += 1
        # X800-class boards use +2 as a raw RGB565 FIFO.  Preserve each
        # command-delimited transfer separately so an exact 128x160 raster
        # cannot be obscured by later short register/rectangle writes.
        if port == (0x02000002, 2):
            segment = self._lcd_raw_segment_streams.get(port)
            if segment is None:
                segment = deque(maxlen=128 * 160)
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
        # A 128x160 RGB565 scanout is common on the unknown-name Samsung/KTF
        # dumps.  When an otherwise unclassified +4 FIFO reaches *exactly*
        # that full raster before the generic 176x220 threshold, it is stronger
        # evidence than the filename fallback.  Known model geometry is left
        # untouched, as a 128x160 transfer can also be a rectangle update.
        if self.frame_sequence == 0:
            if ((self.config.width, self.config.height) == (176, 220)
                    and address in (0x02000004, 0x02800004, 0x02C00004)
                    and count == 128 * 160):
                self._set_display_geometry(128, 160)
            # The KP8500/LP2400-style FIFO has a fixed 160x240 transfer at
            # an otherwise unused LCD aperture.  Its exact 38,400-pixel run
            # is sufficient proof of panel size before publishing a frame.
            elif ((self.config.width, self.config.height) == (176, 220)
                  and address in (0x02000080, 0x02800080)
                  and count == 160 * 240):
                self._set_display_geometry(160, 240)
            # SCH-E135-class panels issue a command-delimited, exact 128x128
            # RGB565 transfer through the indexed +4 FIFO.  The preceding
            # 0x51/0x43/0x42 programming sequence distinguishes it from a
            # 128x160 panel's first 16K rectangle update.
            elif (address == 0x02800004 and count == 128 * 128
                  and tuple(self._lcd_recent_commands)[-7:]
                  == (0x51, 0x43, 0x00, 0x7F, 0x42, 0x00, 0x7F)):
                values = tuple(stream)
                self._set_display_geometry(128, 128)
                for index, pixel in enumerate(values):
                    self._pixel(index, pixel)
                self._lcd_raw_frames[port] += 1
                self._lcd_raw_port = port
                self._lcd_protocol = f"raw-fifo@0x{address:08X}"
                self._publish_frame()
                return
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
        """Promote the one proven +2 command-delimited 128x160 raster."""
        port = (0x02000002, 2)
        count = self._lcd_raw_segment_counts[port]
        stream = self._lcd_raw_segment_streams.get(port)
        if (stream is not None and count == 128 * 160
                and (self.config.width, self.config.height) == (176, 220)
                and self.frame_sequence == 0
                and incoming_command & 0xFF == 0x43):
            values = tuple(stream)
            if len(values) == 128 * 160 and any(values):
                self._set_display_geometry(128, 160)
                for index, pixel in enumerate(values):
                    self._pixel(index, pixel)
                self._lcd_raw_frames[port] += 1
                self._lcd_raw_port = port
                self._lcd_protocol = "raw-fifo@0x02000002"
                self._publish_frame()
        if stream is not None:
            stream.clear()
        self._lcd_raw_segment_counts[port] = 0

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
            self._set_display_geometry(128, 160, force=True)
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
