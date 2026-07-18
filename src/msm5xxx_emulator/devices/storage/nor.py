"""Small AMD/Fujitsu command-set NOR flash with sparse persistent pages."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from pathlib import Path

from ...state_io import atomic_write_text, durable_unlink, exclusive_path_lock


LOGGER = logging.getLogger("nor")


PAGE = 0x1000
FUJITSU_MB84VD2219X_IDS = (0x0004, 0x005F)


class NORFlash:
    def __init__(self, image: bytes, state_path: Path) -> None:
        self.original = bytes(image)
        self.data = bytearray(image)
        self.state_path = state_path
        self.phase = "idle"
        self.command_base = 0
        self.ids: tuple[int, int] | None = None
        self.changed_pages: set[int] = set()
        self.modified_range: tuple[int, int] | None = None
        self._operations: list[tuple[str, int, bytes | int]] = []
        self._load()
        self._baseline = bytes(self.data)
        self.read_operations = 0
        self.read_bytes = 0
        self.last_read_address: int | None = None
        self.command_writes = 0
        self.command_write_bytes = 0
        self.last_command_address: int | None = None
        self.program_operations = 0
        self.program_bytes = 0
        self.last_program_address: int | None = None
        self.erase_operations = 0
        self.erase_bytes = 0
        self.last_erase_address: int | None = None

    @staticmethod
    def _first_unlock(address: int) -> bool:
        return address & 0xFFF in (0xAAA, 0x555)

    @staticmethod
    def _second_unlock(address: int) -> bool:
        return address & 0xFFF in (0x554, 0x2AA)

    def _current(self, address: int, size: int) -> bytes:
        return bytes(self.data[address:address + size])

    def _sector_bounds(self, address: int) -> tuple[int, int]:
        """Return the physical erase sector containing a byte address."""
        device = self.ids[1] if self.ids is not None else None
        size = len(self.data)
        if self.ids == FUJITSU_MB84VD2219X_IDS:
            # Firmware's MB84VD2219X table starts with eight 8 KiB sectors;
            # every remaining sector is 64 KiB.
            sector_size = 0x2000 if address < 0x10000 else 0x10000
            start = address // sector_size * sector_size
        elif device in (0x222D, 0x2250):
            # AM29DL162BT/323DT: top eight 8 KiB boot sectors, otherwise 64 KiB.
            boot = max(0, size - 0x10000)
            sector_size = 0x2000 if address >= boot else 0x10000
            start = (boot + (address - boot) // sector_size * sector_size
                     if address >= boot else address // sector_size * sector_size)
        elif device == 0x227E:
            # AM29DL640G has eight 8 KiB sectors at both ends; the middle is 64 KiB.
            if address < 0x10000:
                sector_size = 0x2000
                start = address // sector_size * sector_size
            elif address >= size - 0x10000:
                sector_size = 0x2000
                start = (size - 0x10000
                         + (address - (size - 0x10000)) // sector_size * sector_size)
            else:
                sector_size = 0x10000
                start = address // sector_size * sector_size
        else:
            # Unknown CFI descriptors stay conservative at the common 64 KiB unit.
            sector_size = 0x10000
            start = address // sector_size * sector_size
        return start, min(size, start + sector_size)

    def read(self, address: int, size: int) -> bytes:
        self.read_operations += 1
        self.read_bytes += size
        self.last_read_address = address
        if self.phase == "autoselect" and self.ids is not None:
            offset = address - self.command_base
            words = {0: self.ids[0], 2: self.ids[1]}
            if self.ids[1] == 0x227E:  # AM29DL640G continuation identifiers
                words.update({0x1C: 0x2202, 0x1E: 0x2201})
            result = bytearray(self._current(address, size))
            for word_offset, value in words.items():
                encoded = value.to_bytes(2, "little")
                for index in range(size):
                    selected = offset + index - word_offset
                    if selected in (0, 1):
                        result[index] = encoded[selected]
            return bytes(result)
        return self._current(address, size)

    def program(self, address: int, incoming: bytes) -> bytes | None:
        """Apply one NOR 1-to-0 program operation and record device telemetry."""
        size = len(incoming)
        if not size or not 0 <= address <= len(self.data) - size:
            return None
        current = self._current(address, size)
        programmed = bytes(old & new for old, new in zip(current, incoming))
        self.data[address:address + size] = programmed
        self._operations.append(("program", address, incoming))
        self._mark_changed(address, address + size)
        self.modified_range = (address, address + size)
        self.program_operations += 1
        self.program_bytes += size
        self.last_program_address = address
        return programmed

    def _erase(self, start: int, end: int) -> None:
        self.data[start:end] = b"\xff" * (end - start)
        self._operations.append(("erase", start, end))
        self._mark_changed(start, end)
        self.modified_range = (start, end)
        self.erase_operations += 1
        self.erase_bytes += end - start
        self.last_erase_address = start

    def telemetry(self) -> dict[str, int | None]:
        return {
            "reads": self.read_operations,
            "read_bytes": self.read_bytes,
            "last_read_address": self.last_read_address,
            "command_writes": self.command_writes,
            "command_write_bytes": self.command_write_bytes,
            "last_command_address": self.last_command_address,
            "programs": self.program_operations,
            "program_bytes": self.program_bytes,
            "last_program_address": self.last_program_address,
            "erases": self.erase_operations,
            "erase_bytes": self.erase_bytes,
            "last_erase_address": self.last_erase_address,
            "changed_pages": len(self.changed_pages),
        }

    def write(self, address: int, size: int, value: int) -> bytes | None:
        """Return the bytes that must remain visible after a CPU store.

        This object is only installed over the mapped NOR image.  Ordinary
        stores therefore cannot turn ROM into RAM; only a completed flash
        command sequence changes the backing bytes.
        """
        self.modified_range = None
        if not 0 <= address < len(self.data) or address + size > len(self.data):
            return None
        self.command_writes += 1
        self.command_write_bytes += size
        self.last_command_address = address
        command = value & 0xFF
        current = self._current(address, size)
        # A programmed data byte/word is data, even when its low byte happens
        # to be the reset opcode (F0).  Checking F0 before these phases made
        # files containing e.g. ``F0 04`` silently fail verification.
        if self.phase in ("program", "bypass_program"):
            incoming = value.to_bytes(size, "little")
            programmed = self.program(address, incoming)
            assert programmed is not None
            self.phase = "bypass" if self.phase == "bypass_program" else "idle"
            return programmed
        if command == 0xF0:
            self.phase = "idle"
            return current
        if self.phase == "idle":
            if command == 0xAA and self._first_unlock(address):
                self.command_base = address & ~0xFFF
                self.phase = "unlock1"
                return current
            return current
        if self.phase == "unlock1":
            self.phase = "unlock2" if command == 0x55 and self._second_unlock(address) else "idle"
            return current
        if self.phase == "unlock2":
            if command == 0xA0 and self._first_unlock(address):
                self.phase = "program"
            elif command == 0x80 and self._first_unlock(address):
                self.phase = "erase1"
            elif command == 0x20 and self._first_unlock(address):
                # AMD unlock-bypass mode: old Qualcomm drivers enter it once,
                # then issue A0/data pairs at each destination word.
                self.phase = "bypass"
            elif command == 0x90 and self._first_unlock(address):
                # Some firmware constructs its supported-device descriptor in
                # RAM during boot.  The emulator may therefore learn IDs only
                # when this first real autoselect transaction occurs.
                self.phase = "autoselect"
            else:
                self.phase = "idle"
            return current
        if self.phase == "bypass":
            if command == 0xA0:
                self.phase = "bypass_program"
            elif command == 0x90:
                self.phase = "bypass_exit"
            return current
        if self.phase == "bypass_exit":
            self.phase = "idle" if command == 0 else "bypass"
            return current
        if self.phase == "erase1":
            self.phase = "erase2" if command == 0xAA and self._first_unlock(address) else "idle"
            return current
        if self.phase == "erase2":
            self.phase = "erase3" if command == 0x55 and self._second_unlock(address) else "idle"
            return current
        if self.phase == "erase3":
            if command == 0x10 and self._first_unlock(address):
                self._erase(0, len(self.data))
            elif command == 0x30:
                start, end = self._sector_bounds(address)
                self._erase(start, end)
            self.phase = "idle"
            return self._current(address, size)
        self.phase = "idle"
        return current

    def _mark_changed(self, start: int, end: int) -> None:
        if end > start:
            self.changed_pages.update(range(start // PAGE, (end - 1) // PAGE + 1))

    @staticmethod
    def _apply_operations(data: bytearray,
                          operations: list[tuple[str, int, bytes | int]]) -> None:
        for operation, start, value in operations:
            if operation == "program":
                incoming = value
                assert isinstance(incoming, bytes)
                end = start + len(incoming)
                data[start:end] = bytes(old & new for old, new in
                                        zip(data[start:end], incoming))
            elif operation == "erase":
                assert isinstance(value, int)
                data[start:value] = b"\xff" * (value - start)
            else:  # Direct data edits retain the legacy save() behaviour.
                replacement = value
                assert isinstance(replacement, bytes)
                data[start:start + len(replacement)] = replacement

    def _unlogged_operations(self) -> list[tuple[str, int, bytes | int]]:
        expected = bytearray(self._baseline)
        self._apply_operations(expected, self._operations)
        operations: list[tuple[str, int, bytes | int]] = []
        start = 0
        while start < len(self.data):
            if self.data[start] == expected[start]:
                start += 1
                continue
            end = start + 1
            while end < len(self.data) and self.data[end] != expected[end]:
                end += 1
            replacement = bytes(self.data[start:end])
            operation = ("program" if all(new & old == new for old, new in
                                           zip(expected[start:end], replacement))
                         else "replace")
            operations.append((operation, start, replacement))
            start = end
        return operations

    def _pages(self, data: bytes | bytearray) -> dict[str, str]:
        pages: dict[str, str] = {}
        for index in range((len(data) + PAGE - 1) // PAGE):
            start = index * PAGE
            current = bytes(data[start:start + PAGE])
            if current != self.original[start:start + PAGE]:
                pages[str(index)] = base64.b64encode(current).decode("ascii")
        return pages

    def save(self) -> None:
        operations = [*self._operations, *self._unlogged_operations()]
        with exclusive_path_lock(self.state_path):
            latest = self._read_state()
            self._apply_operations(latest, operations)
            pages = self._pages(latest)
            if pages:
                payload = {"sha256": hashlib.sha256(self.original).hexdigest(),
                           "pages": pages}
                atomic_write_text(self.state_path,
                                  json.dumps(payload, separators=(",", ":")))
                LOGGER.info("NOR state saved path=%s pages=%d operations=%d",
                            self.state_path, len(pages), len(operations))
            else:
                durable_unlink(self.state_path)
                LOGGER.info("NOR state removed/empty path=%s operations=%d",
                            self.state_path, len(operations))
        self.data[:] = latest
        self._baseline = bytes(latest)
        self._operations.clear()
        self.changed_pages = {int(index) for index in pages}

    def _load(self) -> None:
        self.data[:] = self._read_state()
        self.changed_pages = {int(index) for index in self._pages(self.data)}

    def _read_state(self) -> bytearray:
        data = bytearray(self.original)
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return data
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid flash state: {self.state_path}") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("pages", {}), dict):
            raise ValueError(f"invalid flash state structure: {self.state_path}")
        if payload.get("sha256") != hashlib.sha256(self.original).hexdigest():
            raise ValueError(f"flash state firmware mismatch: {self.state_path}")
        for key, encoded in payload.get("pages", {}).items():
            try:
                index = int(key)
                page = base64.b64decode(encoded, validate=True)
            except (TypeError, ValueError, binascii.Error) as error:
                raise ValueError(f"invalid flash page {key}: {self.state_path}") from error
            start = index * PAGE
            if (index < 0 or start >= len(data)
                    or len(page) != min(PAGE, len(data) - start)):
                raise ValueError(f"invalid flash page {index}: {self.state_path}")
            data[start:start + len(page)] = page
        return data
