"""Storage behavior owned by nor."""
from __future__ import annotations

from ...detection.boot import LEGACY_SECONDARY_FLASH_READ_SIGNATURE
from ...detection.boot import LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn import Uc
from unicorn import UcError
from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_UNMAPPED,
                     UC_MEM_WRITE_UNMAPPED, UC_PROT_ALL)
from ...state_io import atomic_write_text
import base64
import binascii
from ...state_io import durable_unlink
from ...state_io import exclusive_path_lock
from ...detection.firmware import MAX_FLASH_SIZE
from ...detection.storage import (FUJITSU_MB84VD2219X_IDS, flash_id_for_size,
                               fujitsu_x16_bulk_write_at,
                               fujitsu_x16_flash_ids, qualcomm_efs_seed)
import hashlib
import json
import logging

LOGGER = logging.getLogger("nor")


PAGE = 0x1000


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

class NorStorageMixin:
    def _attach_lazy_secondary_nor(self, uc: Uc, access: int, address: int,
                                   size: int, value: int) -> bool:
        """Attach an erased second AMD NOR only when firmware proves its bus.

        A number of early MSM5000/5500 dumps contain only the program NOR;
        their EFS/NV chip is a separate, initially erased device immediately
        after it.  Mapping it as anonymous RAM turns AMD unlock traffic into
        all-ones callback pointers.  A data read in that exact adjacent bank,
        or the canonical first AMD unlock write (base + 0xAAA, 0xAA), is
        sufficient device evidence without relying on a handset name.
        """
        if self.secondary_flash is not None or access == UC_MEM_FETCH_UNMAPPED:
            return False
        base = self.config.load_address + self.config.flash_size
        gap = self.config.ram_base - base
        if not (0 < base < self.config.ram_base and gap >= 0x200000):
            return False
        capacity = min(self.config.flash_size, gap, MAX_FLASH_SIZE)
        capacity &= -PAGE
        if capacity < 0x200000 or address < base or address >= base + capacity:
            return False
        unlock = (access == UC_MEM_WRITE_UNMAPPED
                  and address == base + 0xAAA and (value & 0xFF) == 0xAA)
        adjacent_read = access == UC_MEM_READ_UNMAPPED
        if not (unlock or adjacent_read) or base in self._lazy_secondary_attempted:
            return False
        self._lazy_secondary_attempted.add(base)
        # Detection normally gives every image a default ``.efs`` state name,
        # even when it did not prove a secondary chip at construction time.
        # Do not reuse that potentially stale state after a runtime attach:
        # the capacity and erased/GEFS seed are part of the device identity.
        state_path = Path(self.config.flash_state).with_name(
            Path(self.config.flash_state).stem
            + f".lazy-secondary-{base:08x}-{capacity:x}.json"
        )
        try:
            seed = (qualcomm_efs_seed(capacity, self.config.chipset)
                    if b"\x0b$USER_DIRS\0" in self.original_image
                    else b"\xff" * capacity)
            secondary = NORFlash(seed, state_path)
            ids = fujitsu_x16_flash_ids(
                self.original_image, self.config.secondary_flash_write_address,
                self.config.load_address, base
            )
            identity = flash_id_for_size(capacity)
            if ids is not None:
                secondary.ids = ids
            elif identity is not None:
                secondary.ids = (identity & 0xFFFF, identity >> 16 & 0xFFFF)
            uc.mem_map(base, capacity, UC_PROT_ALL)
            uc.mem_write(base, bytes(secondary.data))
            uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                        begin=base, end=base + capacity - 1,
                        user_data=(base, secondary))
            uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                        begin=base, end=base + capacity - 1,
                        user_data=(base, secondary))
            if self.config.secondary_flash_read_address is not None:
                uc.hook_add(
                    UC_HOOK_CODE, self._secondary_flash_read_fast,
                    begin=self.config.secondary_flash_read_address,
                    end=self.config.secondary_flash_read_address,
                )
            if self.config.secondary_flash_write_address is not None:
                uc.hook_add(
                    UC_HOOK_CODE, self._secondary_flash_write_fast,
                    begin=self.config.secondary_flash_write_address,
                    end=self.config.secondary_flash_write_address,
                )
        except (OSError, UcError, ValueError) as error:
            LOGGER.debug("lazy secondary NOR rejected base=0x%08X: %s", base, error)
            return False
        self.secondary_flash = secondary
        self.secondary_base = base
        self.config.secondary_flash_address = base
        self.config.secondary_flash_size = capacity
        self.config.secondary_flash_state = str(state_path.resolve())
        evidence = "AMD unlock" if unlock else "adjacent-bank read"
        self.config.detection_notes.append(
            f"lazy secondary NOR 0x{base:08X}+0x{capacity:X} attached from {evidence}"
        )
        LOGGER.info("lazy secondary NOR attached base=0x%08X size=0x%X evidence=%s",
                    base, capacity, evidence)
        return True

    def _flash_write(self, uc: Uc, access: int, address: int, size: int,
                     value: int, user_data: object) -> None:
        board = self.config.board_revision_register
        if (board is not None
                and max(address, board) < min(address + size, board + 4)):
            return
        base, flash = user_data
        self._observe_parallel_nor_direct_write(uc, address, size, value, flash)
        relative = address - base
        replacement = flash.write(relative, size, value)
        if replacement is None:
            return
        if flash.modified_range is not None:
            start, end = flash.modified_range
            uc.mem_write(base + start, bytes(flash.data[start:end]))
            uc.ctl_remove_cache(base + start, base + end)
        self._flash_restore[address] = replacement

    def _flash_read(self, uc: Uc, access: int, address: int, size: int,
                    value: int, user_data: object) -> None:
        board = self.config.board_revision_register
        if (board is not None
                and max(address, board) < min(address + size, board + 4)):
            return
        # Unicorn write hooks observe a store just before it lands.  Restore on
        # the following read so same-basic-block RAM probes still see real NOR.
        if self._flash_restore:
            self._restore_flash_once(uc, address, size, user_data)
        base, flash = user_data
        if flash is self.flash and flash.phase == "autoselect" and flash.ids is None:
            flash.ids = self._detect_primary_flash_ids()
        relative = address - base
        data = flash.read(relative, size)
        self._observe_parallel_nor_direct_read(address, size, data, flash)
        uc.mem_write(address, data)

    def _observe_parallel_nor_direct_write(self, uc: Uc, address: int,
                                           size: int, value: int,
                                           flash: NORFlash) -> None:
        """Record, but do not emulate, a complete direct Intel NOR ID probe."""
        if flash is not self.flash:
            return
        pending = self._parallel_nor_direct_probe
        if size != 2:
            self._parallel_nor_direct_probe = None
            return
        command = value & 0xFFFF
        if (flash.phase == "idle" and command == 0x90
                and address & 0xFFF == 0):
            self._parallel_nor_direct_probe = {
                "start_pc": uc.reg_read(UC_ARM_REG_PC),
                "base": address,
            }
            return
        if (pending is None or address != pending["base"] or command != 0xFF
                or "raw_id_word_0" not in pending
                or "raw_id_word_2" not in pending):
            self._parallel_nor_direct_probe = None
            return
        if len(self.primary_parallel_nor_direct_id_probes) < 16:
            self.primary_parallel_nor_direct_id_probes.append({
                **pending,
                "reset_pc": uc.reg_read(UC_ARM_REG_PC),
            })
        self._parallel_nor_direct_probe = None

    def _observe_parallel_nor_direct_read(self, address: int, size: int,
                                          data: bytes, flash: NORFlash) -> None:
        if flash is not self.flash or size != 2:
            if flash is self.flash:
                self._parallel_nor_direct_probe = None
            return
        pending = self._parallel_nor_direct_probe
        if pending is None:
            return
        if address == pending["base"] and "raw_id_word_0" not in pending:
            pending["raw_id_word_0"] = int.from_bytes(data, "little")
        elif (address == pending["base"] + 2
              and "raw_id_word_0" in pending
              and "raw_id_word_2" not in pending):
            pending["raw_id_word_2"] = int.from_bytes(data, "little")
        else:
            self._parallel_nor_direct_probe = None

    def _secondary_flash_read_fast(self, uc: Uc, address: int, size: int,
                                   user_data: object) -> None:
        known = LEGACY_SECONDARY_FLASH_READ_SIGNATURE
        signature = (known if self._original_runtime_bytes(address, len(known)) == known
                     else None)
        if not self._thumb_runtime_matches(uc, address, signature):
            return
        assert self.secondary_flash is not None
        destination = uc.reg_read(UC_ARM_REG_R0)
        offset = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if not self._hle_destination_is_ram(destination, length):
            return
        valid = (0 < length <= len(self.secondary_flash.data)
                 and 0 <= offset <= len(self.secondary_flash.data) - length)
        try:
            if not valid:
                raise ValueError
            uc.mem_read(destination, length)
            uc.mem_write(destination,
                         bytes(self.secondary_flash.data[offset:offset + length]))
            uc.ctl_remove_cache(destination, destination + length)
        except (UcError, ValueError):
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        self.secondary_flash_reads += 1
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _secondary_flash_write_fast(self, uc: Uc, address: int, size: int,
                                    user_data: object) -> None:
        known = LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE
        base = self.config.secondary_flash_address
        original = self._original_runtime_bytes(address, 0x90)
        bulk = (base not in (None, 0) and original is not None
                and fujitsu_x16_bulk_write_at(original, 0, int(base)))
        signature = (original if bulk else known
                     if self._original_runtime_bytes(address, len(known)) == known
                     else None)
        if not self._thumb_runtime_matches(uc, address, signature):
            return
        assert self.secondary_flash is not None
        source = uc.reg_read(UC_ARM_REG_R0)
        destination = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        if bulk and (source | destination | length) & 1:
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        if bulk and length == 0:
            self.secondary_flash_writes += 1
            uc.reg_write(UC_ARM_REG_R0, 0)
            self._return_to_lr(uc, address, size, user_data)
            return
        if not self._hle_source_is_safe(source, length):
            return
        offset = destination
        if bulk:
            if not (int(base) <= destination
                    <= int(base) + len(self.secondary_flash.data) - length):
                return
            offset -= int(base)
        elif (base not in (None, 0)
              and int(base) <= destination
              < int(base) + len(self.secondary_flash.data)):
            offset -= int(base)
        valid = (0 < length <= len(self.secondary_flash.data)
                 and 0 <= offset <= len(self.secondary_flash.data) - length)
        try:
            if not valid:
                raise ValueError
            incoming = bytes(uc.mem_read(source, length))
        except (UcError, ValueError):
            if bulk:
                return
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        if bulk:
            current = self.secondary_flash.data[offset:offset + length]
            if (self.secondary_flash.phase != "bypass"
                    or any(old & new != new for old, new in zip(current, incoming))):
                return
        programmed = self.secondary_flash.program(offset, incoming)
        if programmed is None:
            uc.reg_write(UC_ARM_REG_R0, 1)
            self._return_to_lr(uc, address, size, user_data)
            return
        base = self.config.secondary_flash_address
        if base not in (None, 0):
            uc.mem_write(base + offset, programmed)
        self.secondary_flash_writes += 1
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _restore_flash_once(self, uc: Uc, address: int, size: int,
                            user_data: object) -> None:
        for target, data in self._flash_restore.items():
            uc.mem_write(target, data)
            uc.ctl_remove_cache(target, target + len(data))
        self._flash_restore.clear()

    def save_flash(self) -> None:
        self.flash.save()
        if self.secondary_flash is not None:
            self.secondary_flash.save()
