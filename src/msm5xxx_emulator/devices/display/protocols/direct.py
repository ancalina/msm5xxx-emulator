"""Display methods owned by protocols/direct."""
from __future__ import annotations

from ....core.constants import LCD_MEMORY_WRITE_COMMANDS

_SPLIT_COMMAND_PORT = 0x02000000
_SPLIT_DATA_PORT = 0x02200000
_SPLIT_PREFIX_HEAD = (
    (_SPLIT_COMMAND_PORT, 2, 0), (_SPLIT_COMMAND_PORT, 2, 0x16),
    (_SPLIT_DATA_PORT, 2, 0x7F), (_SPLIT_DATA_PORT, 2, 0),
    (_SPLIT_COMMAND_PORT, 2, 0), (_SPLIT_COMMAND_PORT, 2, 0x17),
    (_SPLIT_DATA_PORT, 2, 0x7F), (_SPLIT_DATA_PORT, 2, 0),
)
_SPLIT_PREFIXES = (
    _SPLIT_PREFIX_HEAD + (
        (_SPLIT_COMMAND_PORT, 2, 0), (_SPLIT_COMMAND_PORT, 2, 0x21),
        (_SPLIT_DATA_PORT, 2, 0), (_SPLIT_DATA_PORT, 2, 0),
        (_SPLIT_COMMAND_PORT, 2, 0), (_SPLIT_COMMAND_PORT, 2, 0x22),
    ),
    _SPLIT_PREFIX_HEAD + (
        (_SPLIT_COMMAND_PORT, 2, 0), (_SPLIT_COMMAND_PORT, 2, 0x20),
        (_SPLIT_DATA_PORT, 2, 0), (_SPLIT_DATA_PORT, 2, 0),
        (_SPLIT_COMMAND_PORT, 2, 0), (_SPLIT_COMMAND_PORT, 2, 0x21),
        (_SPLIT_DATA_PORT, 2, 0), (_SPLIT_DATA_PORT, 2, 0),
        (_SPLIT_COMMAND_PORT, 2, 0), (_SPLIT_COMMAND_PORT, 2, 0x22),
    ),
)


class DirectProtocolMixin:
    def _lcd_split_port_reset(self) -> None:
        self._lcd_split_port_stage = 0
        self._lcd_split_port_variant = 0
        self._lcd_split_port_payload.clear()

    def _lcd_split_port_write(self, address: int, size: int,
                              value: int) -> bool:
        """Promote one exact split-byte 128x128 RGB565 bus grammar."""
        stage = self._lcd_split_port_stage
        if (not stage and not (address == _SPLIT_COMMAND_PORT
                               and size == 2 and value == 0)):
            return False
        event = (address, size, value)
        qualified = self._lcd_split_port_qualified
        variant = self._lcd_split_port_variant
        if not variant:
            matches = tuple(index for index, prefix in enumerate(_SPLIT_PREFIXES)
                            if stage < len(prefix) and event == prefix[stage])
            if matches:
                if len(matches) == 1:
                    self._lcd_split_port_variant = matches[0] + 1
                self._lcd_split_port_stage = stage + 1
                return qualified
        else:
            prefix = _SPLIT_PREFIXES[variant - 1]
            if stage < len(prefix):
                if event == prefix[stage]:
                    self._lcd_split_port_stage = stage + 1
                    return qualified
            elif address == _SPLIT_DATA_PORT and size == 2 and 0 <= value <= 0xFF:
                payload = self._lcd_split_port_payload
                payload.append(value)
                if len(payload) < 128 * 128 * 2:
                    return qualified
                self._lcd_split_port_stage = 0
                self._lcd_split_port_variant = 0
                self._lcd_split_port_payload = bytearray()
                self._set_display_geometry(128, 128, force=True)
                for index in range(128 * 128):
                    offset = index * 2
                    self._pixel(index, payload[offset] << 8 | payload[offset + 1])
                self._lcd_split_port_qualified = True
                self._lcd_protocol = "split-byte-rgb565"
                self._publish_frame()
                return True

        if stage:
            self._lcd_split_port_reset()
        if event == _SPLIT_PREFIXES[0][0]:
            self._lcd_split_port_stage = 1
            return qualified
        return False

    def _lcd_028_direct_probe_write(self, address: int, size: int,
                                    value: int) -> bool:
        """Consume only a complete old Samsung direct-window grammar."""
        base, data = 0x02800000, 0x02800004
        expected: tuple[tuple[int, int, int | None], ...] = (
            (base, 2, 0x75),
            (data, 2, None),
            (data, 2, None),
            (base, 2, 0x15),
            (data, 2, None),
            (data, 2, None),
            (base, 2, 0x5C),
        )
        event = (address, size, value)
        probe = self._lcd_028_direct_probe
        if not probe:
            if self._lcd_protocol == "parallel-2" and event == expected[0]:
                probe.append(event)
                return True
            return False
        wanted_address, wanted_size, wanted_value = expected[len(probe)]
        matches = (address == wanted_address and size == wanted_size
                   and (value <= 0xFF if wanted_value is None
                        else value == wanted_value))
        if not matches:
            held = tuple(probe)
            probe.clear()
            for held_event in held:
                self._lcd_byte_rgb565_interrupt(*held_event[:2])
                self._lcd_write_028_legacy(*held_event)
            return False
        probe.append(event)
        if len(probe) < len(expected):
            return True
        held = tuple(probe)
        probe.clear()
        self._lcd_protocol = "direct"
        for held_event in held:
            self._lcd_byte_rgb565_interrupt(*held_event[:2])
            self._lcd_write_028_legacy(*held_event)
        return True

    def _lcd_write_028_legacy(self, address: int, size: int, value: int) -> None:
        """Handle one 0x028 command/data write outside the direct probe."""
        offset = address - 0x02800000
        if offset == 0:
            self._lcd_byte_rgb565_begin_command(size, value)
            self._lcd_page_begin_command(address, size, value)
            if self._lcd_protocol in ("direct", "parallel-2") or value not in (0, 1):
                if self._lcd_protocol != "parallel-2":
                    self._lcd_protocol = "direct"
                self._lcd_begin_command(value)
                return
            self._lcd_mode = value & 1
            return
        if offset != 4:
            return
        if self._lcd_page_feed_data(address, size, value):
            return
        if self._lcd_protocol == "direct":
            self._lcd_feed_data(address, size, value)
            return
        if not self._lcd_mode:
            self._lcd_begin_command(value)
            return
        self._lcd_feed_data(address, size, value)

    def _lcd_start_direct_frame(self) -> None:
        spans = [(end - start + 1 if end >= start else ((end - start) & 0xFF) + 1)
                 for start, end in (self._lcd_x, self._lcd_y)]
        # A full 0-based controller window is stronger evidence than the
        # generic 176x220 fallback used for unknown handset names.  Do this
        # only before any frame and never turn a small rectangle update into a
        # new screen size.
        if (self._lcd_full_window_geometry(self._lcd_x, self._lcd_y) is not None
                and spans[0] <= self.config.width and spans[1] <= self.config.height):
            self._set_display_geometry(*spans)
        screen = (self.config.width, self.config.height)
        for axis, (start, span, visible) in enumerate(zip(
                (self._lcd_x[0], self._lcd_y[0]), spans, screen)):
            if span == visible:
                self._lcd_direct_origin[axis] = start
                self._lcd_direct_calibrated[axis] = True
            elif span > visible and not self._lcd_direct_calibrated[axis]:
                self._lcd_direct_origin[axis] = (start + (span - visible) // 2) & 0xFF
        self._lcd_direct_window = spans
        self._lcd_direct_cursor = [0, 0]
        self._lcd_expected = spans[0] * spans[1]
        self._lcd_streamed = 0

    def _lcd_finish_direct_args(self) -> None:
        if self._lcd_command not in (0x15, 0x75) or len(self._lcd_args) < 2:
            return
        if len(self._lcd_args) >= 4:
            pair = [self._lcd_args[0] | self._lcd_args[1] << 8,
                    self._lcd_args[2] | self._lcd_args[3] << 8]
        else:
            pair = self._lcd_args[:2]
        target = self._lcd_x if self._lcd_command == 0x15 else self._lcd_y
        target[:] = pair

    def _lcd_finish_direct_frame(self) -> None:
        if (self._lcd_command in LCD_MEMORY_WRITE_COMMANDS
                and self._lcd_expected and self._lcd_streamed):
            self._publish_frame()
            self._lcd_expected = 0

    def _lcd_direct_data(self, value: int) -> None:
        if self._lcd_command in (0x15, 0x75):
            if len(self._lcd_args) < 4:
                self._lcd_args.append(value & 0xFF)
            return
        if self._lcd_set_axis(self._lcd_command, value):
            return
        if (self._lcd_command not in LCD_MEMORY_WRITE_COMMANDS
                or not self._lcd_expected):
            return
        column, row = self._lcd_direct_cursor
        raw_x = (self._lcd_x[0] + column) & 0xFF
        raw_y = (self._lcd_y[0] + row) & 0xFF
        x = (raw_x - self._lcd_direct_origin[0]) & 0xFF
        y = (raw_y - self._lcd_direct_origin[1]) & 0xFF
        if x < self.config.width and y < self.config.height:
            self._pixel(y * self.config.width + x, value)
        column += 1
        if column >= self._lcd_direct_window[0]:
            column, row = 0, row + 1
        self._lcd_direct_cursor = [column, row]
        self._lcd_streamed += 1
        if self._lcd_streamed >= self._lcd_expected:
            self._publish_frame()
            self._lcd_expected = 0
