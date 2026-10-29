"""Display methods owned by controller."""
from __future__ import annotations

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
        if (getattr(self, "_lcd_source_window_owned", False)
                and not getattr(self, "_lcd_source_window_publishing", False)):
            return
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
            source_window = getattr(self, "_lcd_source_window_panel", None)
            if (getattr(self, "_lcd_source_window_owned", False)
                    and source_window is not None and source_window.sequence):
                return source_window.width, source_window.height, source_window.frame
            segmented = getattr(self, "_lcd_segmented_panel", None)
            if segmented is not None:
                candidate = segmented.scanout_snapshot()
                if candidate is not None:
                    return segmented.width, segmented.height, candidate
            for name in ("_lcd_packed_cursor12_panel", "_lcd_packed2_panel", "_lcd_split18_panel", "_lcd_split565_panel", "_lcd_fa_direct_panel"):
                panel = getattr(self, name, None)
                if panel is not None:
                    snapshot = panel.snapshot()
                    if (snapshot["qualified"] and not snapshot.get("rejection")
                            and self._parallel_panel_owns_display(snapshot)):
                        return snapshot["width"], snapshot["height"], snapshot["frame"]
            window = getattr(self, "_lcd_window_panel", None)
            if window is not None and window.qualified and window.rejection is None:
                return window.width, window.height, window.frame
            packed12 = getattr(self, "_lcd_packed12_panel", None)
            if packed12 is not None and packed12.qualified and packed12.rejection is None:
                return packed12.width, packed12.height, packed12.frame
            cursor_panel = getattr(self, "_lcd_cursor_panel", None)
            if (cursor_panel is not None and cursor_panel.qualified
                    and cursor_panel.rejection is None):
                return cursor_panel.width, cursor_panel.height, cursor_panel.frame
            width, height = self.config.width, self.config.height
            frame = self.display_frame
        # The lock makes this invariant unconditional; retain the guard as a
        # useful failure boundary for future display producers.
        if len(frame) != width * height * 3:
            raise RuntimeError("inconsistent display snapshot")
        panel = getattr(self, "_lcd_secondary_panel", None)
        if (not getattr(self, "_lcd_paired_state_ports", None)
                and panel is not None and panel.committed and panel.rejection is None
                and getattr(self, "_lcd_primary_enabled", None) is False):
            frame = bytes(len(frame))
        if (getattr(self, "_lcd_paired_state_enabled", None) is False
                and getattr(self, "_lcd_page_qualified", False)
                and getattr(self, "_lcd_frame_protocol", None) == "page-2bpp"):
            frame = bytes(len(frame))
        return width, height, frame

    def packed_cursor_snapshot(self) -> dict[str, object]:
        """Report experimental scanout admission separately from native counters."""
        with self._display_lock:
            panel = getattr(self, "_lcd_cursor_panel", None)
            return {"class": "temporary-packed-cursor",
                    "admitted": panel is not None,
                    "qualified": bool(panel is not None and panel.qualified),
                    "rejection": (panel.rejection if panel is not None
                                  else "writer-signature-not-found"),
                    "sequence": panel.sequence if panel is not None else 0,
                    "port": panel.port if panel is not None else None}

    def packed12_snapshot(self) -> dict[str, object]:
        """Experimental observer admission and rejection, separate from native state."""
        with self._display_lock:
            panel = getattr(self, "_lcd_packed12_panel", None)
            return {"class": "temporary-packed12", "admitted": panel is not None,
                    "qualified": bool(panel and panel.qualified),
                    "rejection": panel.rejection if panel else None,
                    "sequence": panel.sequence if panel else 0,
                    "trailing_bytes": panel.trailing_bytes if panel else 0}

    def segmented_panel_snapshot(self) -> dict[str, object]:
        """Report temporary segmented-row admission separately from native state."""
        with self._display_lock:
            panel = getattr(self, "_lcd_segmented_panel", None)
            return {"class": "temporary-segmented-row", "admitted": panel is not None,
                    "qualified": bool(panel and panel.qualified),
                    "reason": panel.reason if panel else getattr(self, "_lcd_segmented_reason", "writer-signature-not-found"),
                    "static_reason": getattr(self, "_lcd_segmented_reason", None),
                    "enabled": panel.enabled if panel else None,
                    "rasters": panel.raster.admissions if panel else 0,
                    "rectangles": panel.rectangles if panel else 0}

    def window_panel_snapshot(self) -> dict[str, object]:
        """Expose temporary retained-window admission independently of native state."""
        with self._display_lock:
            source = getattr(self, "_lcd_source_window_panel", None)
            if source is not None:
                return {"class": "source-copied-half128", "admitted": True,
                        "qualified": source.qualified,
                        "owned": getattr(self, "_lcd_source_window_owned", False),
                        "rejection": source.rejection, "sequence": source.sequence,
                        "optical_properties": None}
            panel = getattr(self, "_lcd_window_panel", None)
            return {"class": "temporary-retained-window", "admitted": panel is not None,
                    "qualified": bool(panel and panel.qualified),
                    "rejection": panel.rejection if panel else None,
                    "sequence": panel.sequence if panel else 0}

    def _lcd_bind_source_window(self, original: bytes, loaded: bytes, *,
                                ram_claimed: bool = False) -> None:
        """Stage a source candidate; only a complete bus raster acquires ownership."""
        from ...detection.copied_window import find_copied_window_profile
        from .window_panel import WindowPanel

        self._lcd_source_window_panel = None
        self._lcd_source_window_owned = False
        self._lcd_source_window_reason = "source-layout-unverified"
        cfg = self.config
        if (not isinstance(original, bytes) or not isinstance(loaded, bytes)
                or getattr(cfg, "image_kind", None) != "firmware"
                or any(type(getattr(cfg, field, None)) is not int
                       for field in ("load_address", "image_offset", "entry",
                                     "flash_size", "ram_base", "ram_size"))
                or (cfg.load_address, cfg.image_offset, cfg.entry) != (0, 0, 0)
                or not 0 < cfg.flash_size <= 0xFFFFFFFF
                or len(loaded) != getattr(cfg, "flash_size", None)
                or len(original) < len(loaded)):
            return
        profile, reason = find_copied_window_profile(original)
        self._lcd_source_window_reason = reason
        if profile is None:
            return
        if (ram_claimed or getattr(cfg, "ram_bootstrap_profile", None) is not None
                or getattr(cfg, "missing_overlays", None)):
            self._lcd_source_window_reason = "source-memory-owner-unclosed"
            return
        if ((cfg.width, cfg.height) != (128, 128)
                and getattr(cfg, "display_geometry_source", "external-config") != "auto-default"):
            self._lcd_source_window_reason = "source-geometry-owner-conflict"
            return
        for field, begin, end in (
                ("ram_intervals", cfg.ram_base, cfg.ram_base + cfg.ram_size),
                ("iram_intervals", 0x03800000, 0x03A00000)):
            spans = profile.get(field)
            if (not isinstance(spans, (list, tuple)) or not spans
                    or any(not isinstance(span, (list, tuple)) or len(span) != 2
                           or any(type(v) is not int for v in span)
                           or not begin <= span[0] < span[1] <= end for span in spans)):
                self._lcd_source_window_reason = "source-" + field + "-unverified"
                return
        for field in ("code_intervals", "literal_intervals", "data_intervals", "boot_guard_intervals"):
            spans = profile.get(field)
            if (not isinstance(spans, (list, tuple)) or not spans
                    or any(not isinstance(span, (list, tuple)) or len(span) != 2
                           or any(type(v) is not int for v in span)
                           or not 0 <= span[0] < span[1] <= len(loaded)
                           or original[span[0]:span[1]] != loaded[span[0]:span[1]]
                           for span in spans)):
                self._lcd_source_window_reason = "source-loaded-bytes-unverified"
                return
        current, _ = find_copied_window_profile(loaded)
        if current != profile:
            self._lcd_source_window_reason = "source-loaded-owner-mismatch"
            return
        if (profile.get("signature") != "copied-byte-range-half128-v1"
                or profile.get("admission") != "temporary-evidence-gated"
                or profile.get("role") != "main"
                or profile.get("protocol") != "copied-half128"
                or (profile.get("command_port"), profile.get("data_port"),
                    profile.get("command_width"), profile.get("access_width"),
                    profile.get("width"), profile.get("height")) !=
                   (0x02000000, 0x02000002, 1, 2, 128, 128)):
            self._lcd_source_window_reason = "source-register-contract-unclosed"
            return
        try:
            self._lcd_source_window_panel = WindowPanel(
                profile["command_port"], profile["width"], profile["height"],
                protocol=profile["protocol"], source_init=tuple(profile["init_commands"]),
                source_controls=tuple(tuple(v) for v in profile["opaque_control_sequences"]))
        except (KeyError, TypeError, ValueError):
            self._lcd_source_window_reason = "source-window-profile-malformed"
            return
        self._lcd_source_window_reason = "static-source-candidate-awaiting-full-raster"

    def _lcd_source_window_write(self, address: int, size: int, value: int) -> bool:
        panel = getattr(self, "_lcd_source_window_panel", None)
        if panel is None or address not in (panel.port, panel.port + 2):
            return False
        owned = getattr(self, "_lcd_source_window_owned", False)
        with self._display_lock:
            before = panel.sequence
            panel.write(address, size, value)
            commit = panel.sequence != before and panel.qualified and panel.rejection is None
            frame = panel.frame if commit else None
        if commit:
            if not owned:
                self._set_display_geometry(128, 128, source="runtime:source-copied-half128")
                if (self.config.width, self.config.height) != (128, 128):
                    self._lcd_source_window_reason = "source-geometry-owner-conflict"
                    self._lcd_source_window_panel = None
                    return False
                self._lcd_source_window_owned = owned = True
            with self._display_lock:
                self.framebuffer[:] = frame
            self._lcd_protocol = "source-copied-half128"
            self._lcd_source_window_publishing = True
            try:
                self._publish_frame()
            finally:
                self._lcd_source_window_publishing = False
            self._lcd_source_window_reason = "complete-source-window"
        return owned

    def secondary_display_snapshot(self) -> dict[str, object] | None:
        panel = getattr(self, "_lcd_secondary_panel", None)
        if panel is None:
            indexed = getattr(self, "_lcd_indexed_byte_panel", None)
            if indexed is not None:
                with self._display_lock:
                    return indexed.snapshot()
            return None
        with self._display_lock:
            return {"width": 96, "height": 64, "frame": panel.frame,
                    "qualified": panel.committed and panel.rejection is None,
                    "enabled": panel.enabled, "column_offset": panel.bias,
                    "rejection": panel.rejection, "port": panel.port,
                    "detection": getattr(self, "_lcd_secondary_reason", None)}

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

    def _set_display_geometry(self, width: int, height: int, *,
                              source: str, force: bool = False) -> None:
        """Adopt a controller-proven panel geometry before its first visible frame."""
        if (getattr(self, "_lcd_source_window_owned", False)
                and source != "runtime:source-copied-half128"):
            return
        current_source = getattr(self.config, "display_geometry_source",
                                 "external-config")
        if (width, height) == (self.config.width, self.config.height):
            if (current_source == "auto-default"
                    or (force and current_source.startswith("runtime:"))):
                self.config.display_geometry_source = source
            return
        visible = self.framebuffer.count(0) != len(self.framebuffer)
        if ((current_source != "auto-default"
             and not (force and current_source.startswith("runtime:")))
                or (visible and not force)
                or not (64 <= width <= 320 and 64 <= height <= 320)):
            return
        with self._display_lock:
            self.config.width, self.config.height = width, height
            self.config.display_geometry_source = source
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
        # GRAM dimensions can be larger than the glass. They may replace only
        # an auto-detected fallback, never descriptor/manual geometry.
        if (geometry is not None and (geometry == current
                                      or getattr(self.config,
                                                 "display_geometry_source",
                                                 "external-config") == "auto-default")):
            self._set_display_geometry(*geometry, source="runtime:gram")

    def _lcd_lgfa_register(self, size: int, value: int) -> None:
        """Observe the paired-pixel controller's exact full-window grammar."""
        order = self._lcd_lgfa_window_order
        if size != 2:
            order.clear()
            return
        register = value >> 8 & 0xFF
        if register in (2, 8):
            order[:] = [value & 0xFFFF]
        elif (order and len(order) < 4
              and register == (order[0] >> 8) + len(order)):
            order.append(value & 0xFFFF)
        else:
            order.clear()
            return
        if len(order) != 4:
            return
        base = order[0] >> 8
        arguments = [word & 0xFF for word in order]
        axes = (([arguments[0], arguments[2]], [arguments[1], arguments[3]])
                if base == 2 else
                ([arguments[0], arguments[1]], [arguments[2], arguments[3]]))
        self._lcd_lgfa_window = self._lcd_full_window_geometry(*axes)
        self._lg_pixels.clear()
        order.clear()

    def _lcd_promote_lgfa_geometry(self) -> None:
        geometry = self._lcd_lgfa_window
        if geometry is None:
            return
        current = (self.config.width, self.config.height)
        if (geometry == current or getattr(self.config, "display_geometry_source",
                                           "external-config") == "auto-default"):
            self._set_display_geometry(*geometry, source="runtime:lgfa")

    def _flush_indexed_frame(self) -> None:
        with self._display_lock:
            for name in ("_lcd_packed_cursor12_panel", "_lcd_packed2_panel", "_lcd_split18_panel", "_lcd_split565_panel", "_lcd_fa_direct_panel"):
                panel = getattr(self, name, None)
                if panel is not None:
                    panel.flush()
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
            self._lcd_window_axis_mask |= 0x3
            return True
        if command == 0x17:
            self._lcd_y[:] = pair
            self._lcd_window_axis_mask |= 0xC
            return True
        if command == 0x50:
            self._lcd_x[0] = value & 0xFF
            self._lcd_window_axis_mask |= 0x1
            return True
        if command == 0x51:
            self._lcd_x[1] = value & 0xFF
            self._lcd_window_axis_mask |= 0x2
            return True
        if command == 0x52:
            self._lcd_y[0] = value & 0xFF
            self._lcd_window_axis_mask |= 0x4
            return True
        if command == 0x53:
            self._lcd_y[1] = value & 0xFF
            self._lcd_window_axis_mask |= 0x8
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
        if self._lcd_command != 0x45:
            self._lcd_020_compact_44 = None
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

    def _parallel_panel_owns_display(self, state: dict[str, object]) -> bool:
        source = getattr(self.config, "display_geometry_source", "external-config")
        return (source == "auto-default" or source.startswith("runtime:")
                or (state["width"], state["height"]) == (self.config.width, self.config.height))

    def parallel_candidates_snapshot(self) -> dict[str, object]:
        names = ("packed_cursor12", "packed2", "split18", "split565", "fa_direct")
        result = {name: {"qualified": False,
                         "static_reason": getattr(self, "_lcd_" + name + "_reason", "not-initialized")}
                  for name in names}
        panels = [(name, getattr(self, "_lcd_" + name + "_panel", None)) for name in names]
        if not any(panel is not None for _, panel in panels):
            return result
        with self._display_lock:
            for name, panel in panels:
                if panel is not None:
                    state = panel.snapshot()
                    result[name].update({key: state.get(key) for key in (
                        "qualified", "width", "height", "port", "sequence", "rejection", "observation")})
                    owner = self._parallel_panel_owns_display(state)
                    result[name]["display_owner"] = bool(state["qualified"] and not state.get("rejection") and owner)
                    result[name]["ownership_reason"] = "compatible-geometry" if owner else "explicit-geometry-mismatch"
        return result

    def direct_cursor_snapshot(self) -> dict[str, object]:
        return {"class": "ordered-16-17-packed21", "stage": getattr(self, "_lcd_packed_cursor_stage", 0),
                "accepted": getattr(self, "_lcd_packed_cursor_accepts", 0),
                "reason": getattr(self, "_lcd_packed_cursor_reason", "setup-incomplete")}

    def _lcd_packed_cursor_data(self, address: int, size: int, value: int) -> bool:
        """Keep packed XY separate from the scalar 0x20/0x21 dialect."""
        if address != 0x02000002:
            return False
        if size != 2 or self._lcd_protocol != "parallel-2":
            self._lcd_packed_cursor_stage = 0
            self._lcd_packed_cursor_reason = "unsupported-bus"
            return False
        command = self._lcd_command
        stage = getattr(self, "_lcd_packed_cursor_stage", 0)
        if command == 1:
            stage = 1 if value == 0x0113 else 0
        elif command == 2:
            stage = 2 if stage == 1 and value == 0x0700 else 0
        elif command == 5:
            stage = 3 if stage >= 2 and value in (0x1030, 0x1230) else 0
        elif command == 0:
            stage = 0
        self._lcd_packed_cursor_stage = stage
        if command != 0x21 or stage != 3:
            self._lcd_packed_cursor_reason = "setup-closed" if stage == 3 else "setup-incomplete"
            return False
        # shortcut: two independently observed entry modes until more classes close.
        if (self._lcd_window_axis_mask != 0xF or self._lcd_x != [0, 127]
                or self._lcd_y not in ([0, 159], [0, 175])
                or self.config.width != 128 or self.config.height not in (160, 176)
                or (self.config.height == 176 and self._lcd_y != [0, 175])):
            self._lcd_packed_cursor_reason = "viewport-not-closed"
            return False
        x, y = value & 0xFF, value >> 8 & 0xFF
        if not 0 <= value <= 0xFFFF or x >= self.config.width or y >= self.config.height:
            self._lcd_packed_cursor_reason = "cursor-outside-viewport"
            return False
        self._lcd_cursor[:] = [x, y]
        self._lcd_gram_cursor[:] = [x, y]
        self._lcd_gram_addressed = True
        self._lcd_packed_cursor_accepts = getattr(self, "_lcd_packed_cursor_accepts", 0) + 1
        self._lcd_packed_cursor_reason = "packed-xy"
        return True

    def _lcd_feed_data(self, address: int, size: int, value: int) -> None:
        """Consume one controller data word shared by the parallel transports."""
        if self._lcd_packed_cursor_data(address, size, value):
            return
        value &= 0xFFFF
        source = getattr(
            self.config, "display_geometry_source", "external-config"
        )
        # A relation-qualified full raster owns its data aperture.  A smaller
        # direct window on another aperture may be a second panel; it cannot
        # replace the main scanout without its own full-screen transfer.
        if (source == "runtime:shifted-pair-fifo-rgb565"
                and self._lcd_raw_port != (address, size)
                and self._lcd_command in LCD_MEMORY_WRITE_COMMANDS
                and 0 < self._lcd_expected
                < self.config.width * self.config.height):
            return
        if (source == "runtime:shifted-pair-fifo-rgb565"
                and self._lcd_raw_port == (address, size)
                and self._lcd_command in LCD_MEMORY_WRITE_COMMANDS
                and self.shifted_orientation_snapshot()["qualified"]):
            # This doubled-command dialect's control words are not GRAM pixels.
            self._capture_raw_lcd_stream(address, size, value)
            return
        if (self._lcd_protocol == "parallel-2" and self._lcd_command == 0x22
                and self._lcd_gram_addressed):
            self._lcd_write_gram_pixel(value)
            return
        if self._lcd_command in LCD_MEMORY_WRITE_COMMANDS:
            self._lcd_direct_data(value)
            return
        # Temporary evidence-gated class: exact ordered compact window writes
        # on the observed +2 halfword transport.  Near misses stay raw.
        compact_port = (self._lcd_protocol == "parallel-2"
                        and address == 0x02000002 and size == 2)
        if self._lcd_command == 0x44:
            self._lcd_020_compact_44 = (
                value if compact_port and value == 0x7F00 else None
            )
            if self._lcd_020_compact_44 is not None:
                return
        elif self._lcd_command == 0x45:
            x_value = self._lcd_020_compact_44
            self._lcd_020_compact_44 = None
            if compact_port and x_value == 0x7F00 and value == 0x9F00:
                self._lcd_x[:] = [0, 0x7F]
                self._lcd_y[:] = [0, 0x9F]
                self._lcd_window_axis_mask = 0xF
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
                self._lcd_window_axis_mask |= (
                    0x3 if target is self._lcd_x else 0xC
                )
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

    def _lcd_observe_paired_state(self, address: int, size: int, value: int) -> None:
        """Temporary helper-bound display state; never consume native writes."""
        ports = getattr(self, "_lcd_paired_state_ports", None)
        if not ports:
            return
        arguments = self._lcd_paired_state_arguments
        candidate = self._lcd_paired_state_candidate
        self._lcd_paired_state_candidate = None
        if address in ports and size in (1, 2) and 0 <= value <= 255:
            if address in arguments:
                arguments.remove(address)
                self._lcd_paired_state_reason = "contrast-argument"
                return
            if value == 0x81:
                arguments.add(address)
                self._lcd_paired_state_reason = "contrast-argument-pending"
                return
        if not (getattr(self, "_lcd_page_qualified", False)
                and getattr(self, "_lcd_frame_protocol", None) == "page-2bpp"):
            self._lcd_paired_state_enabled = None
            self._lcd_paired_state_reason = "page-protocol-unqualified"
            return
        if address not in ports or size != 2 or value not in (0xAE, 0xAF):
            self._lcd_paired_state_reason = "intervening-command-or-data"
            return
        if candidate is not None and candidate == (ports[1 - ports.index(address)], value):
            self._lcd_paired_state_enabled = value == 0xAF
            self._lcd_paired_state_reason = "paired-command-confirmed"
        else:
            self._lcd_paired_state_candidate = (address, value)
            self._lcd_paired_state_reason = "awaiting-peer-command"

    def _lcd_write(self, uc: Uc, access: int, address: int, size: int,
                   value: int, user_data: object) -> None:
        if self._audio_transport_owns_write(uc, address, size):
            return
        self.lcd_writes += 1
        self.lcd_port_writes[(address, size)] += 1
        if self._lcd_source_window_write(address, size, value):
            return
        self._lcd_observe_shifted_orientation(address, size, value)
        self._lcd_packed_window_observe(address, size, value)
        with self._display_lock:
            for name in ("_lcd_packed_cursor12_panel", "_lcd_packed2_panel", "_lcd_split18_panel", "_lcd_split565_panel", "_lcd_fa_direct_panel"):
                panel = getattr(self, name, None)
                if panel is not None:
                    panel.write(address, size, value)
        indexed = getattr(self, "_lcd_indexed_byte_panel", None)
        if indexed is not None:
            with self._display_lock:
                indexed.write(address, size, value)
        segmented = getattr(self, "_lcd_segmented_panel", None)
        if segmented is not None:
            with self._display_lock:
                segmented.write(address, size, value)
        cursor_panel = getattr(self, "_lcd_cursor_panel", None)
        if cursor_panel is not None:
            with self._display_lock:
                cursor_panel.write(address, size, value)
        packed12 = getattr(self, "_lcd_packed12_panel", None)
        if packed12 is not None:
            with self._display_lock:
                packed12.write(address, size, value)
        window = getattr(self, "_lcd_window_panel", None)
        if window is not None:
            with self._display_lock:
                window.write(address, size, value)
        # Continue native routing even after qualification, preserving fallback.
        self._lcd_observe_paired_state(address, size, value)
        panel = getattr(self, "_lcd_secondary_panel", None)
        primary_port = getattr(self, "_lcd_primary_page_port", None)
        mixed_port = getattr(self, "_lcd_mixed_primary_power_port", None)
        if mixed_port is not None and panel is not None and panel.committed and panel.rejection is None:
            previous = getattr(self, "_lcd_mixed_primary_power_candidate", None)
            if address == mixed_port and size == 2 and 0 <= value <= 255:
                if (previous, value) == (0xAE, 0x95):
                    self._lcd_primary_enabled = False
                elif (previous, value) == (0x94, 0xAF):
                    self._lcd_primary_enabled = True
                self._lcd_mixed_primary_power_candidate = value if value in (0xAE, 0x94) else None
            else:
                self._lcd_mixed_primary_power_candidate = None
        if (not getattr(self, "_lcd_paired_state_ports", None)
                and primary_port is not None and panel is not None and panel.committed
                and panel.rejection is None
                and getattr(self, "_lcd_page_qualified", False)):
            commands = self._lcd_primary_power_commands
            if address == primary_port and size in (1, 2) and 0 <= value <= 255:
                if self._lcd_primary_power_argument:
                    self._lcd_primary_power_argument = False
                    commands.clear()
                elif value == 0x81:
                    self._lcd_primary_power_argument = True
                    commands.clear()
                else:
                    commands.append(value)
                del commands[:-4]
                # Experimental paired-page class: require the complete power
                # transaction, not an isolated opcode or host fold state.
                if commands == [0xAE, 0x2D, 0x2C, 0x28]:
                    self._lcd_primary_enabled = False
                elif commands == [0x2C, 0x2E, 0x2F, 0xAF]:
                    self._lcd_primary_enabled = True
            elif address in (primary_port, primary_port + 4):
                commands.clear()
        pending = []
        if panel is not None and getattr(panel, "source_profile", None) is not None:
            profile = panel.source_profile
            if not panel.source_validated and panel.rejection is None:
                loaded = getattr(self, "_lcd_page_loaded_image", self.image)
                base, length = getattr(self.config, "ram_base", None), getattr(self.config, "ram_size", None)
                descriptor = profile["descriptor"]
                if (not isinstance(loaded, bytes) or type(base) is not int or type(length) is not int
                        or not base <= descriptor < descriptor + 0x2c4 <= base + length
                        or any(not 0 <= a < b <= min(len(self.image), len(loaded))
                               or self.image[a:b] != loaded[a:b]
                               for a, b in profile["source_intervals"])):
                    panel.rejection = "source-or-ram-owner-unverified"
                else:
                    panel.source_validated = True
            if address == panel.port and size == 2 and value == 0:
                # Source-owned bus reinitialization requires fresh page proof.
                self._lcd_secondary_panel = type(panel)(panel.port, profile)
                panel = None
            elif not panel.started:
                if address == panel.port and size == 1 and value == 0xe2 and panel.rejection is None:
                    panel.started = True
                else:
                    panel = None
            elif address not in (panel.port, panel.port + panel.data_offset):
                panel = None
        if panel is not None:
            with self._display_lock:
                data_port = panel.port + getattr(panel, "data_offset", 4)
                if panel.committed and address in (panel.port, data_port):
                    if getattr(panel, "source_profile", None) is None:
                        # Preserve the legacy panel's committed ownership.
                        if panel.rejection is None:
                            panel.write(address, size, value)
                        return
                    if panel.rejection is None and panel.write(address, size, value):
                        return
                    panel.committed = False
                if (panel.rejection is None
                        and (panel.pending or address in (panel.port, data_port))):
                    secondary = address in (panel.port, data_port)
                    panel.pending.append((address, size, value))
                    accepted = secondary and panel.write(address, size, value)
                    if not secondary:
                        panel.rejection = "interleaved ports before page qualification"
                    if len(panel.pending) > getattr(panel, "pending_limit", 1024):
                        panel.rejection = "page qualification budget exceeded"
                        accepted = False
                    if accepted:
                        if panel.bias is not None:
                            panel.committed = True
                            panel.pending.clear()
                        return
                    pending = panel.pending
                    panel.pending = []
        # Native fallback may publish a frame and acquire the same lock.
        if pending:
            for old_address, old_size, old_value in pending:
                self._lcd_write_fallback(uc, access, old_address, old_size,
                                         old_value, user_data)
            return
        self._lcd_write_fallback(uc, access, address, size, value, user_data)

    def _lcd_write_fallback(self, uc: Uc, access: int, address: int, size: int,
                            value: int, user_data: object) -> None:
        if self._lcd_split_port_write(address, size, value):
            return
        if self._lcd_window_raw8_separate_write(address, size, value):
            return
        if self._lcd_window_raw8_write(address, size, value):
            return
        if self._lcd_byte_raster_write(address, size, value):
            return
        if self._lcd_byte_020_row_write(address, size, value):
            return
        self._lcd_route_write(uc, access, address, size, value, user_data)

    def _lcd_selector_reacquire_replay(
        self, protocol: str, words: tuple[int, ...]
    ) -> None:
        self._lcd_protocol = protocol
        self._lcd_selector_reacquire_replaying = True
        try:
            self._lcd_route_write(None, 0, 0x02000000, 2, 0, None)
            for word in words:
                self._lcd_route_write(
                    None, 0, 0x02000004, 2, word, None
                )
        finally:
            self._lcd_selector_reacquire_replaying = False

    def _lcd_selector_reacquire_finish(
        self, *, replay: bool
    ) -> tuple[tuple[int, ...], str]:
        words = tuple(getattr(self, "_lcd_selector_reacquire_words", ()))
        protocol = getattr(
            self, "_lcd_selector_reacquire_protocol", "unknown"
        )
        self._lcd_selector_reacquire_index = None
        self._lcd_selector_reacquire_words.clear()
        self._lcd_selector_reacquire_protocol = "unknown"
        if replay:
            self._lcd_selector_reacquire_replay(protocol, words)
        return words, protocol

    def _lcd_route_write(self, uc: Uc, access: int, address: int, size: int,
                         value: int, user_data: object) -> None:
        if (address in (0x02000000, 0x02000001, 0x02000002, 0x02000003)
                or getattr(self, "_lcd_odd_page_state", {}).get("profile")):
            if self._lcd_odd_page_write(address, size, value):
                return
        selector_refresh_order = (0x02, 0x03, 0x04, 0x05, 0x15, 0x0E)
        reacquire = getattr(self, "_lcd_selector_reacquire_index", None)
        if not getattr(self, "_lcd_selector_reacquire_replaying", False):
            if (reacquire is None
                    and (address, size, value) == (0x02000000, 2, 0)
                    and self._lcd_selector_full_transfers
                    and not self._lcd_selector_expected
                    and self._lcd_selector_registers.get(0x0D) in (0, 1)):
                self._lcd_selector_reacquire_index = 0
                self._lcd_selector_reacquire_words = []
                self._lcd_selector_reacquire_protocol = self._lcd_protocol
                return
            if reacquire is not None:
                if address == 0x02000004:
                    register, argument = value >> 8 & 0xFF, value & 0xFF
                    if (size == 2 and reacquire < len(selector_refresh_order)
                            and register == selector_refresh_order[reacquire]
                            and (reacquire != 4 or argument == 0)
                            and (reacquire != len(selector_refresh_order) - 1
                                 or argument == 0)):
                        self._lcd_selector_reacquire_words.append(value & 0xFFFF)
                        self._lcd_selector_reacquire_index = reacquire + 1
                        return
                    self._lcd_selector_reacquire_finish(replay=True)
                elif (reacquire == len(selector_refresh_order)
                      and (address, size, value) == (0x02000000, 2, 1)):
                    words, protocol = self._lcd_selector_reacquire_finish(
                        replay=False
                    )
                    registers = dict(self._lcd_selector_registers)
                    accepted = False
                    for command in words:
                        accepted = self._lcd_selector_begin_command(2, command)
                    if accepted:
                        self._lcd_protocol = "selector-4"
                        self._lcd_mode = 1
                        return
                    self._lcd_selector_registers.clear()
                    self._lcd_selector_registers.update(registers)
                    self._lcd_selector_reset()
                    self._lcd_selector_reacquire_replay(protocol, words)
                else:
                    self._lcd_selector_reacquire_finish(replay=True)
        if (not getattr(self, "_lcd_028_split16_replaying", False)
                and self._lcd_028_split16_write(address, size, value)):
            return
        if (not getattr(self, "_lcd_028_be_word_replaying", False)
                and self._lcd_028_be_word_write(address, size, value)):
            return
        self._lcd_lowbyte_page_event(address, size, value)
        if address == 0x02000078:
            self._lcd_lgfa_register(size, value)
        # Match every LCD write while a direct-window candidate is held: an
        # intervening aperture access is a mismatch, not a later continuation.
        if self._lcd_028_direct_probe_write(address, size, value & 0xFFFF):
            return
        self._lcd_byte_rgb565_interrupt(address, size)
        if self._lcd_window_rgb565_write(address, size, value):
            return
        if address == 0x020000FA:
            self._lcd_promote_lgfa_geometry()
            self._lg_pixels.append(value & ((1 << (size * 8)) - 1))
            count = self.config.width * self.config.height * 2
            if len(self._lg_pixels) >= count:
                for index in range(0, count, 2):
                    first, second = self._lg_pixels[index:index + 2]
                    pixel = ((first & 0xF800) | ((first & 0x03F0) << 1)
                             | ((first & 0x000F) << 1) | (second >> 1 & 1))
                    self._pixel(index // 2, pixel)
                del self._lg_pixels[:count]
                self._lcd_protocol = "lg-paired-rgb565"
                self._publish_frame()
            return
        # Two-wire parallel LCD controllers occur at both 0x020 and 0x02C.
        # A few boards instead use the base address as a 0/1 command/data
        # selector and +4 as its payload port.  Keep that transport distinct
        # until a non-selector base value proves an address-line controller.
        if address in (0x02000000, 0x02C00000):
            if (address == 0x02000000
                    and (size == 1 or (size == 2
                                       and self._lcd_page_qualified
                                       and self._lcd_page_port == address))
                    and self._lcd_page_begin_command(
                        address, size, value, byte_wide=size == 1
                    )
                    and self._lcd_page_qualified):
                return
            if (value in (0, 1)
                    and (self._lcd_protocol not in (
                        "parallel-2", "direct", "cursor-bgr444")
                         or (address, size) == (
                             getattr(self, "_lcd_selector_static_port", None), 2))):
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
            if (address == 0x02000004
                    and (size == 1 or (size == 2
                                       and self._lcd_page_qualified
                                       and self._lcd_page_port == 0x02000000))
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
