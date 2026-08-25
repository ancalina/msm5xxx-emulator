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

_028_BE_WORD_COMMAND_PORT = 0x02800000
_028_BE_WORD_DATA_PORT = 0x02800002
_028_BE_WORD_PREFIX = (
    (0x0000, 0x0001),
    (0x0003, 0x6478),
    (0x000C, 0x0001),
    (0x0004, 0x0648),
    (0x0003, 0x6C78),
)

# A split-lane 0x028 controller sends a logical command/data pair as
# base:0, base:command<<8, +0x80:data-high, +0x80:data-low<<8.  Keep this
# dialect separate from the ordinary +2 and indexed 0x028 paths.
_028_SPLIT16_COMMAND_PORT = 0x02800000
_028_SPLIT16_DATA_PORT = 0x02800080
_028_SPLIT16_PREFIX = (
    (0x00, 0x0001), (0x07, 0x0000), (0x11, 0x0001), (0x12, 0x000A),
    (0x13, 0x131F), (0x10, 0x0004), (0x10, 0x0064), (0x11, 0x0001),
    (0x12, 0x001A), (0x13, 0x331F), (0x10, 0x0760), (0x15, 0x0002),
    (0x01, 0x0113), (0x02, 0x0700), (0x03, 0x1030), (0x08, 0x0808),
    (0x09, 0x0000), (0x0B, 0x000B), (0x0C, 0x0000), (0x0D, 0x3229),
    (0x0E, 0x0000), (0x23, 0x0000), (0x24, 0x0000), (0x30, 0x0002),
    (0x31, 0x0204), (0x32, 0x0504), (0x33, 0x0105), (0x34, 0x0000),
    (0x35, 0x0003), (0x36, 0x0004), (0x37, 0x0701), (0x38, 0x0009),
    (0x39, 0x0009), (0x40, 0x0000), (0x41, 0x0000), (0x42, 0x9F00),
    (0x43, 0xFFA0), (0x44, 0x7B04), (0x45, 0x9F00), (0x44, 0x0300),
    (0x45, 0x9F00), (0x21, 0x0000),
)
_028_SPLIT16_PHYSICAL_WIDTH = 128
_028_SPLIT16_VISIBLE_X = 4
_028_SPLIT16_VISIBLE_WIDTH = 120
_028_SPLIT16_HEIGHT = 160
_028_SPLIT16_BOOTSTRAP_WINDOWS = (
    (0, 3, 0, 159), (124, 127, 0, 159), (4, 123, 0, 159),
)


class DirectProtocolMixin:
    def _lcd_028_split16_replay(
        self, events: tuple[tuple[int, int, int], ...]
    ) -> None:
        """Return an unproven split-lane stream to the established paths."""
        replaying = getattr(self, "_lcd_028_split16_replaying", False)
        self._lcd_028_split16_replaying = True
        try:
            for address, size, value in events:
                self._lcd_route_write(None, 0, address, size, value, None)
        finally:
            self._lcd_028_split16_replaying = replaying

    def _lcd_028_split16_emit(self, command: int, value: int) -> bool:
        """Consume one qualified logical pair without touching guest state."""
        expected = self._lcd_028_split16_expected
        if command == 0x44:
            x0, x1 = value & 0xFF, value >> 8
            if expected or not 0 <= x0 <= x1 < _028_SPLIT16_PHYSICAL_WIDTH:
                return False
            self._lcd_028_split16_pending_x = (x0, x1)
            return True
        if command == 0x45:
            pending_x = self._lcd_028_split16_pending_x
            y0, y1 = value & 0xFF, value >> 8
            if (expected or pending_x is None
                    or not 0 <= y0 <= y1 < _028_SPLIT16_HEIGHT):
                return False
            self._lcd_028_split16_window = (*pending_x, y0, y1)
            self._lcd_028_split16_pending_x = None
            return True
        if command == 0x21:
            window = self._lcd_028_split16_window
            if expected or window is None or value != window[0]:
                return False
            x0, x1, y0, y1 = window
            self._lcd_028_split16_expected = (x1 - x0 + 1) * (y1 - y0 + 1)
            self._lcd_028_split16_streamed = 0
            return True
        if command != 0x22:
            return not expected

        window = self._lcd_028_split16_window
        streamed = self._lcd_028_split16_streamed
        if window is None or not expected or streamed >= expected:
            return False
        x0, x1, y0, _y1 = window
        width = x1 - x0 + 1
        x, y = x0 + streamed % width, y0 + streamed // width
        offset = (y * _028_SPLIT16_PHYSICAL_WIDTH + x) * 2
        self._lcd_028_split16_ram[offset] = value >> 8
        self._lcd_028_split16_ram[offset + 1] = value & 0xFF
        if self._lcd_028_split16_frame_ready:
            if _028_SPLIT16_VISIBLE_X <= x < (_028_SPLIT16_VISIBLE_X
                                               + _028_SPLIT16_VISIBLE_WIDTH):
                self._pixel(y * _028_SPLIT16_VISIBLE_WIDTH
                            + x - _028_SPLIT16_VISIBLE_X, value)
        self._lcd_028_split16_streamed = streamed + 1
        if self._lcd_028_split16_streamed < expected:
            return True

        self._lcd_028_split16_expected = 0
        if not self._lcd_028_split16_frame_ready:
            stage = self._lcd_028_split16_bootstrap_stage
            if (stage >= len(_028_SPLIT16_BOOTSTRAP_WINDOWS)
                    or window != _028_SPLIT16_BOOTSTRAP_WINDOWS[stage]):
                return False
            self._lcd_028_split16_bootstrap_stage = stage + 1
            if self._lcd_028_split16_bootstrap_stage < len(
                    _028_SPLIT16_BOOTSTRAP_WINDOWS):
                return True
            self._set_display_geometry(
                _028_SPLIT16_VISIBLE_WIDTH, _028_SPLIT16_HEIGHT,
                source="runtime:split-halfword-rgb565",
            )
            if (self.config.width, self.config.height) != (
                    _028_SPLIT16_VISIBLE_WIDTH, _028_SPLIT16_HEIGHT):
                return False
            for row in range(_028_SPLIT16_HEIGHT):
                source = (row * _028_SPLIT16_PHYSICAL_WIDTH
                          + _028_SPLIT16_VISIBLE_X) * 2
                for column in range(_028_SPLIT16_VISIBLE_WIDTH):
                    pixel = (self._lcd_028_split16_ram[source] << 8
                             | self._lcd_028_split16_ram[source + 1])
                    self._pixel(row * _028_SPLIT16_VISIBLE_WIDTH + column, pixel)
                    source += 2
            self._lcd_028_split16_frame_ready = True
            self._lcd_protocol = "split-halfword-rgb565"
            self._publish_frame()
            return True

        if (x0 < _028_SPLIT16_VISIBLE_X + _028_SPLIT16_VISIBLE_WIDTH
                and x1 >= _028_SPLIT16_VISIBLE_X):
            self._lcd_protocol = "split-halfword-rgb565"
            self._publish_frame()
        return True

    def _lcd_028_split16_write(self, address: int, size: int,
                               value: int) -> bool:
        """Promote only the complete proven split-lane 128x160 grammar."""
        if getattr(self, "_lcd_028_split16_disabled", False):
            return False
        event = (address, size, value)
        events = self._lcd_028_split16_events
        if not events:
            if event != (_028_SPLIT16_COMMAND_PORT, 2, 0):
                return False
            events.append(event)
            return True

        slot = len(events) % 4
        expected_port = (_028_SPLIT16_COMMAND_PORT if slot < 2
                         else _028_SPLIT16_DATA_PORT)
        if (address != expected_port or size != 2 or not 0 <= value <= 0xFFFF
                or (slot == 0 and value != 0)
                or (slot in (1, 3) and value & 0xFF)):
            held = tuple(events) + (event,)
            events.clear()
            self._lcd_028_split16_replay(held)
            return True

        events.append(event)
        if len(events) % 4:
            return True
        command = events[-3][2] >> 8
        data = events[-2][2] & 0xFF00 | events[-1][2] >> 8
        if not self._lcd_028_split16_qualified:
            prefix_index = len(events) // 4 - 1
            if (prefix_index >= len(_028_SPLIT16_PREFIX)
                    or (command, data) != _028_SPLIT16_PREFIX[prefix_index]):
                held = tuple(events)
                events.clear()
                self._lcd_028_split16_replay(held)
                return True
            if prefix_index + 1 < len(_028_SPLIT16_PREFIX):
                return True
            source = getattr(self.config, "display_geometry_source",
                             "external-config")
            if ((self.config.width, self.config.height) != (
                    _028_SPLIT16_VISIBLE_WIDTH, _028_SPLIT16_HEIGHT)
                    and (source != "auto-default"
                         or self.framebuffer.count(0) != len(self.framebuffer))):
                held = tuple(events)
                events.clear()
                self._lcd_028_split16_replay(held)
                return True
            self._lcd_028_split16_qualified = True
            for prefix_command, prefix_data in _028_SPLIT16_PREFIX:
                if not self._lcd_028_split16_emit(prefix_command, prefix_data):
                    raise AssertionError("split-lane prefix state")
            events.clear()
            return True

        held = tuple(events)
        events.clear()
        if self._lcd_028_split16_emit(command, data):
            return True
        self._lcd_028_split16_disabled = True
        self._lcd_028_split16_replay(held)
        return True

    def _lcd_028_be_word_replay(self,
                                 events: tuple[tuple[int, int, int], ...]) -> None:
        """Return an unproven byte packet stream to the existing 0x028 paths."""
        replaying = getattr(self, "_lcd_028_be_word_replaying", False)
        self._lcd_028_be_word_replaying = True
        try:
            for address, size, value in events:
                self._lcd_route_write(None, 0, address, size, value, None)
        finally:
            self._lcd_028_be_word_replaying = replaying

    def _lcd_028_be_word_emit(self, command: int, value: int) -> None:
        """Feed one proven big-endian command/data pair to the common LCD path."""
        self._lcd_protocol = "parallel-2"
        if not (command == 0x22 and self._lcd_command == 0x22
                and self._lcd_expected):
            self._lcd_begin_command(command)
        self._lcd_feed_parallel_data(_028_BE_WORD_DATA_PORT, 2, value)

    def _lcd_028_be_word_write(self, address: int, size: int,
                               value: int) -> bool:
        """Promote only a zero-prefixed 16-bit 0x028 command/data grammar."""
        event = (address, size, value)
        events = getattr(self, "_lcd_028_be_word_events", None)
        if events is None:
            events = []
            self._lcd_028_be_word_events = events
        qualified = getattr(self, "_lcd_028_be_word_qualified", False)
        if not events:
            if event != (_028_BE_WORD_COMMAND_PORT, 1, 0):
                return False
            events.append(event)
            return True

        slot = len(events) % 4
        expected_port = (_028_BE_WORD_COMMAND_PORT if slot < 2
                         else _028_BE_WORD_DATA_PORT)
        if (address != expected_port or size != 1 or not 0 <= value <= 0xFF
                or (slot == 0 and value != 0)):
            held = tuple(events) + (event,)
            events.clear()
            self._lcd_028_be_word_qualified = False
            self._lcd_028_be_word_replay(held)
            return True

        events.append(event)
        if len(events) % 4:
            return True
        command = events[-3][2]
        data = events[-2][2] << 8 | events[-1][2]
        if not qualified:
            prefix_index = len(events) // 4 - 1
            if (prefix_index >= len(_028_BE_WORD_PREFIX)
                    or (command, data) != _028_BE_WORD_PREFIX[prefix_index]):
                held = tuple(events)
                events.clear()
                self._lcd_028_be_word_qualified = False
                self._lcd_028_be_word_replay(held)
                return True
            if prefix_index + 1 < len(_028_BE_WORD_PREFIX):
                return True
            self._lcd_028_be_word_qualified = True
            for index in range(0, len(events), 4):
                self._lcd_028_be_word_emit(
                    events[index + 1][2],
                    events[index + 2][2] << 8 | events[index + 3][2],
                )
            events.clear()
            return True

        events.clear()
        self._lcd_028_be_word_emit(command, data)
        return True

    def _lcd_028_rgb332_replay(self, events: list[tuple[int, int, int]]) -> None:
        """Return an unproven stream to the established 0x028 decoders."""
        for address, size, value in events:
            self._lcd_byte_rgb565_interrupt(address, size)
            self._lcd_write_028_legacy(address, size, value)

    def _lcd_028_rgb332_pixel(self, index: int, value: int) -> None:
        """Store one native RGB332 pixel without passing through RGB565."""
        if not 0 <= index < self.config.width * self.config.height:
            return
        offset = index * 3
        self.framebuffer[offset] = (value >> 5) * 255 // 7
        self.framebuffer[offset + 1] = (value >> 2 & 7) * 255 // 7
        self.framebuffer[offset + 2] = (value & 3) * 255 // 3

    def _lcd_028_rgb332_write(self, address: int, size: int,
                               value: int) -> bool:
        """Promote only complete low-byte 0x028 RGB332 window transfers."""
        base, data = 0x02800000, 0x02800004
        probe = self._lcd_028_rgb332_probe
        event = (address, size, value)
        if not probe:
            if (address == base and value == 0x75
                    and (size == 1
                         or (size == 2 and self._lcd_028_rgb332_qualified))):
                probe.append(event)
                return True
            return False
        transfer_size = probe[0][1]
        setup = ((data, transfer_size, None), (data, transfer_size, None),
                 (base, transfer_size, 0x15),
                 (data, transfer_size, None), (data, transfer_size, None),
                 (base, transfer_size, 0x5C))
        if len(probe) <= len(setup):
            wanted_address, wanted_size, wanted_value = setup[len(probe) - 1]
            if (address != wanted_address or size != wanted_size or not 0 <= value <= 0xFF
                    or (wanted_value is not None and value != wanted_value)):
                held = list(probe)
                probe.clear()
                self._lcd_028_rgb332_replay(held)
                return False
            probe.append(event)
            if len(probe) != len(setup) + 1:
                return True
            y_axis = [probe[1][2], probe[2][2]]
            x_axis = [probe[4][2], probe[5][2]]
            geometry = self._lcd_full_window_geometry(x_axis, y_axis)
            if geometry is not None:
                self._lcd_028_rgb332_window = (x_axis[0], y_axis[0], *geometry)
                return True
            if (self._lcd_028_rgb332_qualified and x_axis[0] <= x_axis[1]
                    and y_axis[0] <= y_axis[1] and x_axis[1] < self.config.width
                    and y_axis[1] < self.config.height):
                self._lcd_028_rgb332_window = (
                    x_axis[0], y_axis[0], x_axis[1] - x_axis[0] + 1,
                    y_axis[1] - y_axis[0] + 1,
                )
                return True
            else:
                held = list(probe)
                probe.clear()
                self._lcd_028_rgb332_replay(held)
                return True
        x0, y0, width, height = self._lcd_028_rgb332_window
        if address != data or size != transfer_size or not 0 <= value <= 0xFF:
            held = list(probe)
            probe.clear()
            self._lcd_028_rgb332_replay(held)
            return False
        probe.append(event)
        if len(probe) < len(setup) + 1 + width * height:
            return True
        if not self._lcd_028_rgb332_qualified:
            self._set_display_geometry(
                width, height, source="runtime:direct-rgb332"
            )
        if x0 + width <= self.config.width and y0 + height <= self.config.height:
            for index, (_address, _size, packed) in enumerate(probe[len(setup) + 1:]):
                x, y = x0 + index % width, y0 + index // width
                self._lcd_028_rgb332_pixel(y * self.config.width + x, packed)
            self._lcd_028_rgb332_qualified = True
            self._lcd_protocol = "direct-rgb332"
            self._publish_frame()
        probe.clear()
        return True

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
                self._set_display_geometry(
                    128, 128, source="runtime:split-byte-rgb565", force=True
                )
                if (self.config.width, self.config.height) != (128, 128):
                    return True
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
        if self._lcd_028_rgb332_write(address, size, value):
            return True
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
        axes_programmed = self._lcd_window_axis_mask == 0xF
        if (axes_programmed
                and self._lcd_full_window_geometry(self._lcd_x, self._lcd_y) is not None
                and spans[0] <= self.config.width and spans[1] <= self.config.height):
            self._set_display_geometry(*spans, source="runtime:direct-window")
        screen = (self.config.width, self.config.height)
        for axis, (start, span, visible) in enumerate(zip(
                (self._lcd_x[0], self._lcd_y[0]), spans, screen)):
            if axes_programmed and span == visible:
                self._lcd_direct_origin[axis] = start
                self._lcd_direct_calibrated[axis] = True
            elif (axes_programmed and span > visible
                  and not self._lcd_direct_calibrated[axis]):
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
        self._lcd_window_axis_mask |= (
            0x3 if target is self._lcd_x else 0xC
        )

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
