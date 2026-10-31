"""Storage behavior owned by eeprom."""
from __future__ import annotations

from ...state_io import atomic_write_bytes
from ...state_io import durable_unlink
from ...state_io import exclusive_path_lock
import logging

LOGGER = logging.getLogger("msm5xxx")

class EepromMixin:


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
