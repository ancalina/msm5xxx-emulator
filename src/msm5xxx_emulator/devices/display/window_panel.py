"""Experimental retained-axis RGB565 observer; static admission is required."""
from __future__ import annotations


_COPIED_HALF128_CONTROLS = (
    (0x51,),
    (0x2C, 0x51),
    (0x50, 0x2D),
    (0x50, 0x2D, 0x26, 0x00, 0x02, 0x00),
)


class WindowPanel:
    """Publish complete windows after a full raster establishes the viewport."""

    def __init__(self, port: int, width: int, height: int,
                 protocol: str = "retained-axis",
                 source_init: tuple[int, ...] | None = None,
                 source_controls: tuple[tuple[int, ...], ...] | None = None) -> None:
        self.port = port
        if protocol not in ("retained-axis", "copied-half128"):
            raise ValueError("unsupported window protocol")
        if not (1 <= width <= 256 and 1 <= height <= 256):
            raise ValueError("invalid statically admitted geometry")
        if protocol == "copied-half128" and (port, width, height) != (
                0x02000000, 128, 128):
            raise ValueError("copied-half128 requires its admitted port and geometry")
        if protocol == "copied-half128":
            if (not isinstance(source_init, tuple) or len(source_init) != 27 or
                    any(type(value) is not int or not 0 <= value <= 0xFF
                        for value in source_init) or
                    source_init[:2] != (0x2C, 0x02) or
                    source_init[9:11] != (0x40, 0x01) or
                    source_init[19:25] !=
                    (0x43, 0x00, 0x7F, 0x42, 0x00, 0x7F) or
                    source_init[25:27] != (0x10, 0x02)):
                raise ValueError("copied-half128 requires a verified 27-byte init profile")
            if (not isinstance(source_controls, tuple) or
                    any(not isinstance(seq, tuple) or
                        any(type(value) is not int or not 0 <= value <= 0xFF
                            for value in seq)
                        for seq in source_controls) or
                    len(source_controls) != len(set(source_controls)) or
                    set(source_controls) != set(_COPIED_HALF128_CONTROLS)):
                raise ValueError("copied-half128 requires verified source controls")
        self.protocol = protocol
        self._source_init = source_init
        self._source_controls = source_controls or ()
        self._source_sequences = (source_init,) + self._source_controls if source_init else ()
        self._source_sequence: list[int] = []
        self.width, self.height = width, height
        self.frame = b""
        self.sequence = 0
        self.qualified = False
        self.rejection: str | None = None
        self._ram = bytearray()
        self._axes: dict[int, tuple[int, int]] = {}
        self._mode: int | None = None
        self._pixel_mode: int | None = None
        self._source_initialized = False
        self._source_window_stage = 0
        self._pending: int | None = None
        self._args: list[int] = []
        self._pixels: list[int] = []
        self._complete = False

    def _reject(self, reason: str) -> None:
        self.rejection = reason
        self.qualified = False
        self._pixels.clear()

    def write(self, address: int, size: int, value: int) -> None:
        if self.protocol == "copied-half128":
            self._write_copied_half128(address, size, value)
            return
        if self.rejection or address not in (self.port, self.port + 4):
            return
        if address == self.port:
            if size != 1 or not 0 <= value <= 255:
                self._reject("non-byte-command")
                return
            if self._pixels and not self._complete:
                self._reject("incomplete-window")
                return
            self._pixels.clear()
            self._complete = False
            if self._pending is not None:
                self._args.append(value)
                if len(self._args) == (1 if self._pending == 0x40 else 2):
                    if self._pending == 0x40:
                        self._mode = value
                        if value not in (0, 2):
                            self._reject("unsupported-entry-mode")
                    elif self._args[0] > self._args[1]:
                        self._reject("reversed-window")
                    else:
                        self._axes[self._pending] = tuple(self._args)
                    self._pending = None
                    self._args.clear()
            elif value in (0x40, 0x42, 0x43):
                self._pending = value
            # Observed no-argument post-clear strobe; retain RAM (experimental).
            elif value == 0x51:
                pass
            elif self.qualified:
                self._reject("unsupported-command")
            return
        if size != 2 or not 0 <= value <= 65535 or self._pending is not None:
            self._reject("invalid-pixel-transfer")
            return
        x, y = self._axes.get(0x43), self._axes.get(0x42)
        if x is None or y is None or self._mode not in (0, 2):
            self._reject("missing-window-or-mode")
            return
        if not self.qualified:
            if x != (0, self.width - 1) or y != (0, self.height - 1):
                self._reject("missing-full-raster")
                return
        if x[1] >= self.width or y[1] >= self.height:
            self._reject("window-outside-viewport")
            return
        expected = (x[1] - x[0] + 1) * (y[1] - y[0] + 1)
        if self._complete:
            self._reject("window-overflow")
            return
        self._pixels.append(value)
        if len(self._pixels) != expected:
            return
        if not self._ram:
            self._ram = bytearray(self.width * self.height * 3)
        for i, word in enumerate(self._pixels):
            if self._mode == 2:
                dx, dy = divmod(i, y[1] - y[0] + 1)
            else:
                dy, dx = divmod(i, x[1] - x[0] + 1)
            offset = ((y[0] + dy) * self.width + x[0] + dx) * 3
            self._ram[offset:offset + 3] = bytes(
                ((word >> 8 & 248) | (word >> 13),
                 (word >> 3 & 252) | (word >> 9 & 3),
                 (word << 3 & 248) | (word >> 2 & 7)))
        self.frame = bytes(self._ram)
        self.sequence += 1
        self.qualified = self._complete = True

    def _reject_copied_half128(self, reason: str) -> None:
        self._reject(reason)
        self._pending = None
        self._args.clear()
        self._source_sequence.clear()
        self._axes.clear()
        self._source_window_stage = 0
        self._complete = False

    def _reinitialize_copied_half128(self) -> None:
        self.rejection = None
        self.qualified = False
        self._source_initialized = True
        self._axes = {0x43: (0, 127), 0x42: (0, 127)}
        self._mode, self._pixel_mode = 1, 2
        self._source_window_stage = 2
        self._pending = None
        self._args.clear()
        self._pixels.clear()
        self._complete = False

    def _finish_copied_half128_sequence(self, sequence: tuple[int, ...]) -> None:
        if sequence == self._source_init:
            self._reinitialize_copied_half128()
        elif self._pixels and not self._complete:
            self._reject_copied_half128("incomplete-window")

    def _drain_copied_half128_commands(self) -> None:
        while self._source_sequence:
            buffered = tuple(self._source_sequence)
            prefixes = [seq for seq in self._source_sequences
                        if seq[:len(buffered)] == buffered]
            if prefixes:
                exact = [seq for seq in prefixes if len(seq) == len(buffered)]
                longer = any(len(seq) > len(buffered) for seq in prefixes)
                if exact and not longer:
                    self._source_sequence.clear()
                    self._finish_copied_half128_sequence(exact[0])
                return

            complete = [seq for seq in self._source_sequences
                        if len(seq) <= len(buffered) and buffered[:len(seq)] == seq]
            if complete:
                sequence = max(complete, key=len)
                del self._source_sequence[:len(sequence)]
                self._finish_copied_half128_sequence(sequence)
                if self.rejection:
                    self._source_sequence.clear()
                    return
                continue

            value = self._source_sequence.pop(0)
            self._parse_copied_half128_command(value)
            if self.rejection:
                self._source_sequence.clear()
                return

    def _finish_copied_half128_before_data(self) -> bool:
        if not self._source_sequence:
            return True
        while self._source_sequence:
            buffered = tuple(self._source_sequence)
            complete = [seq for seq in self._source_controls
                        if len(seq) <= len(buffered) and buffered[:len(seq)] == seq]
            if not complete:
                self._reject_copied_half128("incomplete-source-control")
                return False
            sequence = max(complete, key=len)
            del self._source_sequence[:len(sequence)]
            self._finish_copied_half128_sequence(sequence)
            if self.rejection:
                return False
        return True

    def _parse_copied_half128_command(self, value: int) -> None:
        if self.rejection:
            return
        if not self._source_initialized:
            self._reject_copied_half128("missing-source-initialize")
            return
        if self._pending is not None:
            self._args.append(value)
            if len(self._args) < (2 if self._pending in (0x42, 0x43) else 1):
                return
            command, args = self._pending, self._args.copy()
            self._pending = None
            self._args.clear()
            if command == 0x40:
                if args[0] != 1:
                    self._reject_copied_half128("unsupported-entry-mode")
                else:
                    self._mode = 1
            elif command == 0x10:
                if args[0] != 2:
                    self._reject_copied_half128("unsupported-pixel-mode")
                else:
                    self._pixel_mode = 2
            elif command == 0x43:
                if self._source_window_stage == 1:
                    self._reject_copied_half128("unexpected-x-window")
                elif args[0] > args[1] or args[1] >= 128:
                    self._reject_copied_half128("invalid-window")
                else:
                    self._axes[0x43] = (args[0], args[1])
                    self._axes.pop(0x42, None)
                    self._source_window_stage = 1
            elif self._source_window_stage != 1:
                self._reject_copied_half128("missing-x-window")
            elif args[0] > args[1] or args[1] >= 128:
                self._reject_copied_half128("invalid-window")
            else:
                self._axes[0x42] = (args[0], args[1])
                self._source_window_stage = 2
            return
        if self._pixels and not self._complete:
            self._reject_copied_half128("incomplete-window")
            return
        self._pixels.clear()
        self._complete = False
        if value in (0x10, 0x40, 0x42, 0x43):
            self._pending = value
            self._args.clear()
        else:
            self._reject_copied_half128("unsupported-command")

    def _write_copied_half128(self, address: int, size: int, value: int) -> None:
        data_port = self.port + 2
        if address not in (self.port, data_port):
            return
        if address == self.port:
            if size != 1 or not 0 <= value <= 0xFF:
                self._reject_copied_half128("non-byte-command")
                return
            if self._pending is not None:
                self._parse_copied_half128_command(value)
                return
            self._source_sequence.append(value)
            self._drain_copied_half128_commands()
            return

        if (self._source_sequence and
                self._source_init[:len(self._source_sequence)] == tuple(self._source_sequence)):
            self._reject_copied_half128("data-during-source-init")
            return
        if not self._finish_copied_half128_before_data():
            return
        if self.rejection:
            return
        if not self._source_initialized:
            self._reject_copied_half128("missing-source-initialize")
            return
        if self._pending is not None:
            self._reject_copied_half128("incomplete-command")
            return
        if size != 2 or not 0 <= value <= 0xFFFF:
            self._reject_copied_half128("invalid-pixel-transfer")
            return
        if self._mode != 1 or self._pixel_mode != 2:
            self._reject_copied_half128("missing-known-mode")
            return
        if self._complete:
            self._reject_copied_half128("window-overflow")
            return
        if self._source_window_stage != 2:
            self._reject_copied_half128(
                "missing-x-window" if self._source_window_stage == 0
                else "missing-y-window")
            return
        x, y = self._axes.get(0x43), self._axes.get(0x42)
        if x is None or y is None:
            self._reject_copied_half128("missing-window")
            return
        if not self.qualified and (x != (0, 127) or y != (0, 127)):
            self._reject_copied_half128("missing-full-raster")
            return
        expected = (x[1] - x[0] + 1) * (y[1] - y[0] + 1)
        self._pixels.append(value)
        if len(self._pixels) < expected:
            return
        if len(self._pixels) > expected:
            self._reject_copied_half128("window-overflow")
            return

        pixels = bytearray(self._ram or bytes(self.width * self.height * 3))
        window_width = x[1] - x[0] + 1
        for i, word in enumerate(self._pixels):
            dy, dx = divmod(i, window_width)
            offset = ((y[0] + dy) * self.width + x[0] + dx) * 3
            pixels[offset:offset + 3] = bytes(
                ((word >> 8 & 248) | (word >> 13),
                 (word >> 3 & 252) | (word >> 9 & 3),
                 (word << 3 & 248) | (word >> 2 & 7)))
        self._ram = pixels
        self.frame = bytes(pixels)
        self.sequence += 1
        self.qualified = self._complete = True
        self._pixels.clear()
        self._axes.clear()
        self._source_window_stage = 0
