"""Storage behavior owned by nand."""
from __future__ import annotations

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
