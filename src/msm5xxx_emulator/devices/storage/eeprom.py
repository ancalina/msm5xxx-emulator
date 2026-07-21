"""Storage behavior owned by eeprom."""
from __future__ import annotations

from ...detection.storage import EEPROM_24LC64_CLASS_A_READ_PREFIX
from ...detection.storage import EEPROM_24LCXX_READ_SIGNATURE
from ...detection.storage import EEPROM_24LCXX_WRITE_PREFIX
from ...detection.storage import EEPROM_24LCXX_X270_READ_PREFIX
from ...detection.storage import EEPROM_24LCXX_X270_WRITE_PREFIX
from ...detection.storage import EEPROM_24LCXX_X430_READ_PREFIX
from ...detection.storage import EEPROM_24LCXX_X430_WRITE_PREFIX
from ...detection.storage import EEPROM_24LCXX_X7700_READ_PREFIX
from ...detection.storage import EEPROM_24LCXX_X7700_WRITE_PREFIX
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn import Uc
from unicorn import UcError
from ...state_io import atomic_write_bytes
from ...state_io import durable_unlink
from ...detection.storage import eeprom_24lc64_class_a_write_at
from ...detection.storage import eeprom_24lcxx_write_at
from ...state_io import exclusive_path_lock
import logging

LOGGER = logging.getLogger("msm5xxx")

class EepromMixin:
    def _ensure_eeprom(self, uc: Uc) -> bool:
        """Load the proven 24LCxx capacity and its persistent byte image."""
        geometry = self.config.eeprom_geometry_address
        if not self.eeprom_enabled or geometry is None:
            return False
        try:
            descriptor = bytes(uc.mem_read(geometry, 4))
        except UcError:
            return False
        if descriptor == b"\xff\x1f\x00\x00":
            capacity = 0x2000  # proven inclusive maximum from the old driver
        elif descriptor == b"\x00\x80\x01\x00":
            capacity = 0x8000
        else:
            self.eeprom_error = f"unsupported 24LCxx descriptor {descriptor.hex()}"
            return False
        if self.eeprom_data:
            if len(self.eeprom_data) != capacity:
                self.eeprom_error = "24LCxx capacity changed during execution"
                return False
            self.eeprom_error = None
            return True
        try:
            with exclusive_path_lock(self.eeprom_state_path):
                state_exists = self.eeprom_state_path.is_file()
                saved = self.eeprom_state_path.read_bytes() if state_exists else b""
        except (OSError, TimeoutError) as error:
            self.eeprom_error = f"24LCxx state load failed: {error}"
            return False
        if state_exists and len(saved) != capacity:
            self.eeprom_error = (
                f"24LCxx state is 0x{len(saved):X} bytes, expected 0x{capacity:X}"
            )
            return False
        self.eeprom_capacity = capacity
        self.eeprom_original = b"\xff" * capacity
        self.eeprom_data = bytearray(saved if state_exists else self.eeprom_original)
        self.eeprom_loaded = bytes(self.eeprom_data)
        self.eeprom_loaded_from_state = state_exists
        self.eeprom_error = None
        return True

    def _eeprom_read_fast(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        for signature in (EEPROM_24LC64_CLASS_A_READ_PREFIX,
                          EEPROM_24LCXX_X430_READ_PREFIX,
                          EEPROM_24LCXX_X270_READ_PREFIX,
                          EEPROM_24LCXX_X7700_READ_PREFIX):
            if (self._original_runtime_bytes(address, len(signature))
                    == signature):
                if self._thumb_runtime_matches(uc, address, signature):
                    break
                return
        else:
            if not self._thumb_runtime_matches(
                    uc, address, EEPROM_24LCXX_READ_SIGNATURE):
                return
        destination = uc.reg_read(UC_ARM_REG_R0)
        offset = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if not self._ensure_eeprom(uc):
            return
        if length == 0:
            valid = 0 <= offset < self.eeprom_capacity
            self.eeprom_reads += int(valid)
            uc.reg_write(UC_ARM_REG_R0, 0 if valid else 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        if not self._hle_destination_is_ram(destination, length):
            return
        valid = (0 < length <= self.eeprom_capacity
                 and 0 <= offset <= self.eeprom_capacity - length)
        try:
            if not valid:
                raise ValueError
            uc.mem_read(destination, length)
            uc.mem_write(destination,
                         bytes(self.eeprom_data[offset:offset + length]))
            uc.ctl_remove_cache(destination, destination + length)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.eeprom_reads += 1
        self.eeprom_read_bytes += length
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _eeprom_write_fast(self, uc: Uc, address: int, size: int,
                           user_data: object) -> None:
        signature = None
        original = self._original_runtime_bytes(address, 48)
        if original is not None and eeprom_24lc64_class_a_write_at(original, 0):
            signature = original
        else:
            original = self._original_runtime_bytes(
                address, len(EEPROM_24LCXX_WRITE_PREFIX)
            )
        if original is not None and eeprom_24lcxx_write_at(original, 0):
            signature = original
        elif signature is None:
            signature = next(
                (candidate for candidate in (
                    EEPROM_24LCXX_X430_WRITE_PREFIX,
                    EEPROM_24LCXX_X270_WRITE_PREFIX,
                    EEPROM_24LCXX_X7700_WRITE_PREFIX,
                ) if self._original_runtime_bytes(address, len(candidate))
                == candidate),
                None,
            )
        if signature is None or not self._thumb_runtime_matches(uc, address, signature):
            return
        source = uc.reg_read(UC_ARM_REG_R0)
        offset = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if not self._ensure_eeprom(uc):
            return
        if length == 0:
            valid = 0 <= offset < self.eeprom_capacity
            self.eeprom_writes += int(valid)
            uc.reg_write(UC_ARM_REG_R0, 0 if valid else 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        if not self._hle_source_is_safe(source, length):
            return
        valid = (0 < length <= self.eeprom_capacity
                 and 0 <= offset <= self.eeprom_capacity - length)
        try:
            if not valid:
                raise ValueError
            incoming = bytes(uc.mem_read(source, length))
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 6)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.eeprom_data[offset:offset + length] = incoming
        self.eeprom_operations.append((offset, incoming))
        self.eeprom_writes += 1
        self.eeprom_write_bytes += length
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _save_eeprom(self) -> None:
        if not self.eeprom_data:
            return
        operations = list(self.eeprom_operations)
        current = bytes(self.eeprom_data)
        if not operations and current != self.eeprom_loaded:
            operations.append((0, current))
        if not operations:
            return
        with exclusive_path_lock(self.eeprom_state_path):
            latest = bytearray(self.eeprom_original)
            if self.eeprom_state_path.is_file():
                saved = self.eeprom_state_path.read_bytes()
                if len(saved) != self.eeprom_capacity:
                    raise ValueError(
                        f"24LCxx state is 0x{len(saved):X} bytes, "
                        f"expected 0x{self.eeprom_capacity:X}"
                    )
                latest[:] = saved
            for offset, payload in operations:
                latest[offset:offset + len(payload)] = payload
            if bytes(latest) == self.eeprom_original:
                durable_unlink(self.eeprom_state_path)
                LOGGER.info("EEPROM state removed/empty path=%s operations=%d",
                            self.eeprom_state_path, len(operations))
            else:
                atomic_write_bytes(self.eeprom_state_path, bytes(latest))
                LOGGER.info("EEPROM state saved path=%s bytes=%d operations=%d",
                            self.eeprom_state_path, len(latest), len(operations))
            self.eeprom_data[:] = latest
            self.eeprom_loaded = bytes(latest)
            self.eeprom_loaded_from_state = self.eeprom_state_path.is_file()
            self.eeprom_operations.clear()
