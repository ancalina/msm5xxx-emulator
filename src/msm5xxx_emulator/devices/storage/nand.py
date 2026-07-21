"""Storage behavior owned by nand."""
from __future__ import annotations

from ...detection.boot import LEGACY_EFS_PAGE_READ_SIGNATURE
from ...detection.boot import NAND_BAD_BLOCK_SIGNATURE
from ...detection.boot import NAND_READ_SIGNATURE
from ...detection.boot import NAND_WRITE_SIGNATURE
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_R3
from unicorn import Uc
from unicorn import UcError
from ...state_io import atomic_write_bytes
from ...state_io import atomic_write_text
from ...state_io import durable_unlink
from ...state_io import exclusive_path_lock
import hashlib
import json
import logging

LOGGER = logging.getLogger("msm5xxx")

class NandMixin:
    def _normalise_nand(self, payload: bytes, expected: int, label: str) -> bytearray:
        """Accept current raw-page files plus legacy data-only/smaller saves."""
        if len(payload) == expected:
            return bytearray(payload)
        raw = self.nand_raw_page_size
        data = self.config.nand_page_size
        if len(payload) <= expected and len(payload) % raw == 0:
            return bytearray(payload + b"\xff" * (expected - len(payload)))
        if len(payload) <= self.config.nand_data_size and len(payload) % data == 0:
            converted = bytearray()
            spare = b"\xff" * self.config.nand_spare_size
            for offset in range(0, len(payload), data):
                converted.extend(payload[offset:offset + data])
                converted.extend(spare)
            converted.extend(b"\xff" * (expected - len(converted)))
            return converted
        raise ValueError(f"{label} size/geometry mismatch: got 0x{len(payload):X}, "
                         f"expected 0x{expected:X}")

    def _nand_metadata(self) -> dict[str, object]:
        return {
            "format": 1,
            "firmware_sha256": hashlib.sha256(self.flash.original).hexdigest(),
            "seed_sha256": hashlib.sha256(self.nand_original).hexdigest(),
            "geometry": {
                "data_size": self.config.nand_data_size,
                "page_size": self.config.nand_page_size,
                "spare_size": self.config.nand_spare_size,
                "pages_per_block": self.config.nand_pages_per_block,
                "bus_width": self.config.nand_bus_width,
            },
        }

    def _validate_nand_metadata(self) -> None:
        if not self.nand_metadata_path.is_file():
            return  # legacy save; it will be rewritten with metadata on close
        try:
            metadata = json.loads(self.nand_metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid NAND metadata: {self.nand_metadata_path}") from error
        expected = self._nand_metadata()
        for key in ("firmware_sha256", "seed_sha256", "geometry"):
            if metadata.get(key) != expected[key]:
                raise ValueError(f"NAND state {key} mismatch: {self.nand_metadata_path}")

    def _legacy_efs_page_read(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Read one x16 small-page NAND view backed by the EFS data image."""
        if (self.secondary_flash is None
                or not self._thumb_runtime_matches(
                    uc, address, LEGACY_EFS_PAGE_READ_SIGNATURE)):
            return
        destination = uc.reg_read(UC_ARM_REG_R0)
        page = uc.reg_read(UC_ARM_REG_R1)
        column = uc.reg_read(UC_ARM_REG_R2)
        length = uc.reg_read(UC_ARM_REG_R3)
        ram_end = self.config.ram_base + self.config.ram_size
        destination_end = destination + length
        destination_is_ram = (
            self.config.ram_base <= destination <= destination_end <= ram_end
            or 0x03800000 <= destination <= destination_end <= 0x03A00000
        )
        page_size = 512
        raw_page_size = 528
        page_count = len(self.secondary_flash.data) // page_size
        try:
            if (not destination_is_ram or not 0 <= page < page_count
                    or not 0 <= column < raw_page_size
                    or not 0 < length <= raw_page_size - column):
                raise ValueError
            uc.mem_read(destination, length)
            data_length = min(length, max(0, page_size - column))
            start = page * page_size + column
            data = bytes(self.secondary_flash.data[start:start + data_length])
            data += b"\xff" * (length - len(data))
            uc.mem_write(destination, data)
            uc.ctl_remove_cache(destination, destination_end)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 2)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.legacy_efs_page_reads += 1
        uc.reg_write(UC_ARM_REG_R0, 1)
        self._return_to_lr(uc, address, size, user_data)

    def _nand_command(self, uc: Uc, access: int, address: int, size: int,
                      value: int, user_data: object) -> None:
        command = value & 0xFF
        if len(self.nand_commands) < 256:
            self.nand_commands.append(command)
        if command == 0x70:
            self.nand_mode = "status"
            uc.mem_write(0x01800000, b"\xc0")
        elif command in (0x00, 0x50):
            self.nand_mode = "read-spare" if command == 0x50 else "read"
            self.nand_spare_latched = command == 0x50
            self.nand_address.clear()
            uc.mem_write(0x01800000, b"\xff\xff")
        elif command == 0xFF:
            self.nand_mode = "idle"
            self.nand_spare_latched = False
            self.nand_address.clear()
            uc.mem_write(0x01800000, b"\xff\xff")
        elif command in (0x80, 0x60):
            self.nand_mode = (
                "program-spare" if command == 0x80
                and getattr(self, "nand_spare_latched", False)
                else "program" if command == 0x80 else "erase"
            )
            if command == 0x60:
                self.nand_spare_latched = False
            self.nand_address.clear()
            self.nand_program.clear()
        elif command == 0x10 and self.nand_mode.startswith("program"):
            end = min(len(self.nand_image), self.nand_cursor + len(self.nand_program))
            self._nand_program_bytes(
                self.nand_cursor, bytes(self.nand_program[:end - self.nand_cursor])
            )
            self.nand_writes += max(0, end - self.nand_cursor)
            self.nand_mode = "status"
            self.nand_spare_latched = False
        elif command == 0xD0 and self.nand_mode == "erase" and self.nand_address:
            page = sum(byte << (8 * index)
                       for index, byte in enumerate(self.nand_address))
            block_pages = self.config.nand_pages_per_block
            start = page // block_pages * block_pages * self.nand_raw_page_size
            end = min(len(self.nand_image),
                      start + block_pages * self.nand_raw_page_size)
            if start < len(self.nand_image):
                self._nand_erase_bytes(start, end)
                self.nand_writes += end - start
            self.nand_mode = "status"

    def _nand_address_write(self, uc: Uc, access: int, address: int, size: int,
                            value: int, user_data: object) -> None:
        if not (self.nand_mode.startswith("read")
                or self.nand_mode.startswith("program")
                or self.nand_mode == "erase"):
            return
        self.nand_address.append(value & 0xFF)
        if self.nand_mode == "erase":
            page = sum(byte << (8 * index)
                       for index, byte in enumerate(self.nand_address))
            self.nand_cursor = page * self.nand_raw_page_size
        else:
            # Small-page NAND uses one column cycle; large-page NAND uses two
            # before its row cycles.  Recompute as extra row cycles arrive.
            column_cycles = 2 if self.config.nand_page_size > 512 else 1
            if len(self.nand_address) < column_cycles + 2:
                return
            column_units = sum(
                byte << (8 * index)
                for index, byte in enumerate(self.nand_address[:column_cycles])
            )
            column = column_units * self.config.nand_bus_width
            if self.nand_mode in ("read-spare", "program-spare"):
                column += self.config.nand_page_size
            page = sum(byte << (8 * index)
                       for index, byte in enumerate(
                           self.nand_address[column_cycles:]))
            self.nand_cursor = page * self.nand_raw_page_size + column

    def _nand_data_write(self, uc: Uc, access: int, address: int, size: int,
                         value: int, user_data: object) -> None:
        if self.nand_mode.startswith("program"):
            page_remaining = self.nand_raw_page_size - (self.nand_cursor
                                                        % self.nand_raw_page_size)
            available = max(0, page_remaining - len(self.nand_program))
            self.nand_program.extend(value.to_bytes(size, "little")[:available])

    def _nand_program_bytes(self, start: int, incoming: bytes,
                            *, record: bool = True) -> None:
        end = min(len(self.nand_image), start + len(incoming))
        payload = incoming[:max(0, end - start)]
        for index, byte in enumerate(payload):
            self.nand_image[start + index] &= byte
        if record and payload:
            operations = getattr(self, "nand_operations", None)
            if operations is not None:
                operations.append(("program", start, payload))

    def _nand_erase_bytes(self, start: int, end: int,
                          *, record: bool = True) -> None:
        start = max(0, start)
        end = min(len(self.nand_image), end)
        if start >= end:
            return
        self.nand_image[start:end] = b"\xff" * (end - start)
        if record:
            operations = getattr(self, "nand_operations", None)
            if operations is not None:
                operations.append(("erase", start, end))

    def _nand_bad_block(self, uc: Uc, address: int, size: int,
                        user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, NAND_BAD_BLOCK_SIGNATURE):
            return
        page = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFF
        marker = page * self.nand_raw_page_size + self.config.nand_page_size
        valid = (bool(self.nand_image) and 0 <= page < self.nand_page_count
                 and marker + 2 <= len(self.nand_image))
        good = valid and self.nand_image[marker:marker + 2] == b"\xff\xff"
        uc.reg_write(UC_ARM_REG_R0, 1 if good else 2)
        self.nand_bad_block_probes += 1
        lr = uc.reg_read(UC_ARM_REG_LR)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_PC, lr & ~1)
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x20 if lr & 1 else cpsr & ~0x20)

    def _nand_read_fast(self, uc: Uc, address: int, size: int,
                        user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, NAND_READ_SIGNATURE):
            return
        destination = uc.reg_read(UC_ARM_REG_R0)
        page = uc.reg_read(UC_ARM_REG_R1)
        column = uc.reg_read(UC_ARM_REG_R2)
        length = uc.reg_read(UC_ARM_REG_R3)
        if not self._hle_destination_is_ram(destination, length):
            return
        start = page * self.nand_raw_page_size + column
        valid = (bool(self.nand_image)
                 and 0 < length <= self.nand_raw_page_size
                 and 0 <= column < self.nand_raw_page_size
                 and length <= self.nand_raw_page_size - column
                 and 0 <= page < self.nand_page_count
                 and start + length <= len(self.nand_image))
        try:
            if not valid:
                raise ValueError
            uc.mem_read(destination, length)
            data = bytes(self.nand_image[start:start + length])
            uc.mem_write(destination, data)
            uc.ctl_remove_cache(destination, destination + length)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 2)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.nand_reads += length
        uc.reg_write(UC_ARM_REG_R0, 1)
        self._return_to_lr(uc, address, size, user_data)

    def _nand_write_fast(self, uc: Uc, address: int, size: int,
                         user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, NAND_WRITE_SIGNATURE):
            return
        source = uc.reg_read(UC_ARM_REG_R0)
        page = uc.reg_read(UC_ARM_REG_R1)
        column = uc.reg_read(UC_ARM_REG_R2)
        length = uc.reg_read(UC_ARM_REG_R3)
        transfer_length = length
        if self.config.nand_bus_width == 2:
            column &= ~1
            transfer_length = (length + 1) & ~1
        if not self._hle_source_is_safe(source, transfer_length):
            return
        start = page * self.nand_raw_page_size + column
        valid = (bool(self.nand_image)
                 and 0 < transfer_length <= self.nand_raw_page_size
                 and 0 <= column < self.nand_raw_page_size
                 and transfer_length <= self.nand_raw_page_size - column
                 and 0 <= page < self.nand_page_count
                 and start + transfer_length <= len(self.nand_image))
        try:
            if not valid:
                raise ValueError
            incoming = bytes(uc.mem_read(source, transfer_length))
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 2)
            self._return_to_lr(uc, address, size, user_data)
            return
        self._nand_program_bytes(start, incoming)
        self.nand_writes += transfer_length
        uc.reg_write(UC_ARM_REG_R0, 1)
        self._return_to_lr(uc, address, size, user_data)

    def _nand_data_read(self, uc: Uc, access: int, address: int, size: int,
                        value: int, user_data: object) -> None:
        if self.nand_mode == "status":
            uc.mem_write(address, b"\xc0" * size)
            return
        if not self.nand_mode.startswith("read"):
            return
        start, end = self.nand_cursor, self.nand_cursor + size
        data = bytes(self.nand_image[start:end])
        if len(data) < size:
            data += b"\xff" * (size - len(data))
        uc.mem_write(address, data)
        self.nand_cursor = end
        self.nand_reads += size

    def _save_nand(self) -> None:
        if not self.nand_image:
            return
        operations = list(self.nand_operations)
        current = bytes(self.nand_image)
        if not operations and current != self.nand_loaded:
            # Direct mutation remains supported for diagnostic tools.
            operations.append(("replace", 0, current))
        if not operations and not self.nand_needs_rewrite:
            return
        with exclusive_path_lock(self.config.flash_state):
            latest = bytearray(self.nand_original)
            if self.nand_state_path.is_file():
                self._validate_nand_metadata()
                latest = self._normalise_nand(
                    self.nand_state_path.read_bytes(), len(latest), "NAND state"
                )
            for operation, start, payload in operations:
                if operation == "replace":
                    latest[:] = bytes(payload)
                elif operation == "erase":
                    latest[start:int(payload)] = b"\xff" * (int(payload) - start)
                else:
                    data = bytes(payload)
                    for index, byte in enumerate(data):
                        latest[start + index] &= byte
            if bytes(latest) == self.nand_original:
                durable_unlink(self.nand_state_path)
                durable_unlink(self.nand_metadata_path)
                LOGGER.info("NAND state removed/empty path=%s operations=%d",
                            self.nand_state_path, len(operations))
            else:
                atomic_write_bytes(self.nand_state_path, bytes(latest))
                atomic_write_text(
                    self.nand_metadata_path,
                    json.dumps(self._nand_metadata(), separators=(",", ":")),
                )
                LOGGER.info("NAND state saved path=%s bytes=%d operations=%d",
                            self.nand_state_path, len(latest), len(operations))
            self.nand_image[:] = latest
            self.nand_loaded = bytes(latest)
            self.nand_operations.clear()
            self.nand_needs_rewrite = False
