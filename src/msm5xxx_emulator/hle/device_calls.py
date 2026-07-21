"""HLE behavior owned by device_calls."""
from __future__ import annotations

from ..detection.boot import BOARD_ADC_SIGNATURE
from ..detection.boot import BUSY_DELAY_SIGNATURES
from ..detection.boot import CRC16_SIGNATURE
from ..detection.boot import DMD_DOWNLOAD_510X_SIGNATURE
from ..detection.boot import DMD_DOWNLOAD_SIGNATURE
from ..detection.boot import FLASH_ID_SIGNATURE
from ..detection.boot import OPTIONAL_RAM_PROBE_SIGNATURE
from ..detection.boot import PRIMARY_FLASH_PROBE_SIGNATURE
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn import Uc
from unicorn import UcError
import binascii
import struct


class DeviceCallsHleMixin:
    def _return_busy_delay(self, uc: Uc, address: int, size: int,
                           user_data: object) -> None:
        """Preserve the exact terminal R0/NZCV state of the delay loop."""
        if (not isinstance(user_data, bytes)
                or user_data not in BUSY_DELAY_SIGNATURES
                or not self._thumb_runtime_matches(uc, address, user_data)):
            return
        uc.reg_write(UC_ARM_REG_R0, 0)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_CPSR, (cpsr & ~0xF0000000) | 0x60000000)
        self._return_to_lr(uc, address, size, user_data)

    def _absent_optional_ram_probe(self, uc: Uc, address: int, size: int,
                                   user_data: object) -> None:
        """Fail a proven destructive probe for an absent expansion bank."""
        if not self._thumb_runtime_matches(
                uc, address, OPTIONAL_RAM_PROBE_SIGNATURE):
            return
        uc.reg_write(UC_ARM_REG_R0, 0)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_CPSR, (cpsr & ~0xC0000000) | 0x40000000)
        self._return_to_lr(uc, address, size, user_data)

    def _ma2_silent_boot(self, uc: Uc, address: int, size: int,
                         user_data: object) -> None:
        """Acknowledge a proven MA2 wait without inventing device registers."""
        if not self._thumb_runtime_matches(uc, address, prefix_size=0x60):
            return
        self.ma2_silent_boot_calls += 1
        uc.reg_write(UC_ARM_REG_R0, 0)
        self._return_to_lr(uc, address, size, user_data)

    def _board_adc(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if (not self._thumb_runtime_matches(uc, address, BOARD_ADC_SIGNATURE)
                or uc.reg_read(UC_ARM_REG_R0) != 0):
            return
        self.board_adc_reads += 1
        uc.reg_write(UC_ARM_REG_R0, self.config.board_adc_value)
        self._return_to_lr(uc, address, size, user_data)

    def _flash_id(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, FLASH_ID_SIGNATURE):
            return
        self.flash_id_reads += 1
        uc.reg_write(UC_ARM_REG_R0, self.config.flash_id_value)
        self._return_to_lr(uc, address, size, user_data)

    def _crc16_fast(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if not self._thumb_runtime_matches(uc, address, CRC16_SIGNATURE):
            return
        seed = uc.reg_read(UC_ARM_REG_R0) & 0xFFFF
        source = uc.reg_read(UC_ARM_REG_R1)
        raw_length = uc.reg_read(UC_ARM_REG_R2)
        length = (0 if raw_length == 0 or raw_length & 0x80000000
                  else ((raw_length - 1) & 0xFFFF) + 1)
        if length and not self._hle_source_is_safe(source, length):
            return
        try:
            data = bytes(uc.mem_read(source, length)) if length else b""
        except UcError:
            return
        result = (~binascii.crc_hqx(data, (~seed) & 0xFFFF)) & 0xFFFF
        uc.reg_write(UC_ARM_REG_R0, result)
        uc.reg_write(UC_ARM_REG_R1, source + length)
        uc.reg_write(UC_ARM_REG_R2, 0)
        self.fast_crc16_calls += 1
        self._return_to_lr(uc, address, size, user_data)

    def _dmd_download_fast(self, uc: Uc, address: int, size: int,
                           user_data: object) -> None:
        """Complete the DSP download only for the proven Qualcomm routine."""
        try:
            clear_dmd = False
            dmd_ready = None
            if (bytes(uc.mem_read(address, len(DMD_DOWNLOAD_SIGNATURE)))
                    == DMD_DOWNLOAD_SIGNATURE):
                flag, control, _, dmd = struct.unpack(
                    "<4I", uc.mem_read(address + 0xE0, 16)
                )
                file_load = struct.unpack("<H", uc.mem_read(address + 0xD4, 2))[0]
                if file_load == 0x4906:  # LDR r1, [pc, #24]
                    filename = struct.unpack("<I", uc.mem_read(address + 0xF0, 4))[0]
                elif file_load == 0xA106:  # ADR r1, #24; inline filename follows
                    filename = address + 0xF0
                else:
                    return
                completion = flag
                clear_dmd = True
            elif (bytes(uc.mem_read(address, len(DMD_DOWNLOAD_510X_SIGNATURE)))
                    == DMD_DOWNLOAD_510X_SIGNATURE):
                guard = struct.unpack("<I", uc.mem_read(address + 0xE8, 4))[0]
                completion = struct.unpack("<I", uc.mem_read(address + 0xEC, 4))[0]
                control = struct.unpack("<I", uc.mem_read(address + 0xF0, 4))[0]
                dmd = struct.unpack("<I", uc.mem_read(address + 0xF8, 4))[0]
                filename = struct.unpack("<I", uc.mem_read(address + 0xFC, 4))[0]
                if struct.unpack("<I", uc.mem_read(guard, 4))[0] != 0:
                    return
                dmd_ready = guard
            else:
                return
            source_name = bytes(uc.mem_read(filename, 12))
        except (UcError, struct.error):
            return
        ram_end = self.config.ram_base + self.config.ram_size
        if (control != 0x03000050 or dmd != 0x030007E0
                or not self.config.ram_base <= completion < ram_end
                or not source_name.startswith(b"dmddown_")):
            return
        if dmd_ready is not None:
            uc.mem_write(dmd_ready, b"\x02")
        uc.mem_write(completion, b"\x02")
        uc.mem_write(control + 0x0C, b"\x01")
        if clear_dmd:
            uc.mem_write(dmd + 8, b"\0\0\0\0\0\0")
        else:
            uc.mem_write(dmd + 8, b"\0")
            uc.mem_write(dmd + 12, b"\0")
        uc.reg_write(UC_ARM_REG_R0, 1)
        self.fast_dmd_downloads += 1
        self._return_to_lr(uc, address, size, user_data)

    def _detect_primary_flash_ids(self) -> tuple[int, int] | None:
        """Infer NOR autoselect IDs only from one unambiguous firmware descriptor."""
        address = self.config.primary_flash_probe_address
        if address is None:
            return None
        try:
            signature = bytes(self.uc.mem_read(address, len(PRIMARY_FLASH_PROBE_SIGNATURE)))
            _, flash_base_global, table_global = struct.unpack(
                "<3I", self.uc.mem_read(
                    address + len(PRIMARY_FLASH_PROBE_SIGNATURE), 12
                )
            )
            flash_base = struct.unpack("<I", self.uc.mem_read(flash_base_global, 4))[0]
            first, terminator = struct.unpack("<2I", self.uc.mem_read(table_global, 8))
            manufacturer, device = struct.unpack(
                "<2H", self.uc.mem_read(first + 0x124, 4)
            )
        except (UcError, struct.error):
            return None
        flash_end = self.config.load_address + self.config.flash_size
        ram_end = self.config.ram_base + self.config.ram_size
        if (signature != PRIMARY_FLASH_PROBE_SIGNATURE or not first or terminator
                or not self.config.ram_base <= flash_base_global <= ram_end - 4
                or not self.config.ram_base <= table_global <= ram_end - 8
                or not self.config.load_address <= flash_base < flash_end
                or not self.config.load_address <= first <= flash_end - 0x128
                or manufacturer in (0, 0xFFFF) or device in (0, 0xFFFF)):
            return None
        return manufacturer, device
