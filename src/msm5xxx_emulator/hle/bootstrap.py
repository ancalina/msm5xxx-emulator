"""HLE behavior owned by bootstrap."""
from __future__ import annotations

from ..core.constants import BOOTSTRAP_HLE_SLACK
from ..detection.boot import FAST_BOOT_SIGNATURE
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn import Uc
from unicorn import UcError
import struct


class BootstrapHleMixin:
    def _apply_linker(self) -> None:
        layout = self.config.linker
        if layout is None:
            return
        source = self.config.load_address + layout.data_source
        data = bytes(self.uc.mem_read(source, layout.data_size))
        self.uc.mem_write(layout.data_target, data)
        self.uc.mem_write(layout.bss_target, b"\0" * layout.bss_size)
        for overlay in self.config.overlays:
            data = bytes(self.uc.mem_read(self.config.load_address + overlay.source,
                                          overlay.size))
            self.uc.mem_write(overlay.target, data)
        self.fast_boot_used = True

    def _fast_boot_hook(self, uc: Uc, address: int, size: int,
                        user_data: object) -> None:
        if self.config.linker is None:
            return
        try:
            if bytes(uc.mem_read(address, len(FAST_BOOT_SIGNATURE))) != FAST_BOOT_SIGNATURE:
                return
        except UcError:
            return
        if not self.fast_boot_used:
            self._apply_linker()
        if not self.fast_boot_used:
            return
        lr = uc.reg_read(UC_ARM_REG_LR)
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        uc.reg_write(UC_ARM_REG_PC, lr & ~1)
        uc.reg_write(UC_ARM_REG_CPSR, cpsr | 0x20 if lr & 1 else cpsr & ~0x20)

    def _bootstrap_hle_is_early(self) -> bool:
        """Keep the inferred scatter-chain lease out of normal runtime code."""
        return (self.reset_entries == 1 and self.instructions <= 1_000_000
                and not self.lcd_writes and not self.frame_sequence
                and not self.rex_ticks and not self.input_events)

    def _thumb_watchdog_strobe(self, address: int) -> bool:
        """Recognise a local one-to-zero write to MSM hardware after init work."""
        try:
            one, literal, store_one, zero, store_zero = struct.unpack(
                "<5H", self.uc.mem_read(address, 10)
            )
        except UcError:
            return False
        value_register = one >> 8 & 7
        base_register = literal >> 8 & 7
        zero_register = zero >> 8 & 7
        if (one & 0xF800 != 0x2000 or one & 0xFF != 1
                or literal & 0xF800 != 0x4800
                or store_one & 0xF800 != 0x7000
                or store_one >> 6 & 0x1F
                or store_one & 7 != value_register
                or store_one >> 3 & 7 != base_register
                or zero & 0xF800 != 0x2000 or zero & 0xFF
                or store_zero & 0xF800 != 0x7000
                or store_zero >> 6 & 0x1F
                or store_zero & 7 != zero_register
                or store_zero >> 3 & 7 != base_register):
            return False
        literal_address = ((address + 2 + 4) & ~3) + (literal & 0xFF) * 4
        try:
            target = struct.unpack("<I", self.uc.mem_read(literal_address, 4))[0]
        except UcError:
            return False
        return 0x03000000 <= target < 0x03800000

    def _bootstrap_copy_stage(self, destination: int, source: int, limit: int,
                              source_end: int, exit_address: int) -> str | None:
        """Return the one permitted bootstrap-copy stage, if proven."""
        if (not self._bootstrap_hle_is_early()
                or not self._primary_nor_contains(source, source_end)
                or not self._thumb_watchdog_strobe(exit_address)):
            return None
        ram_start = self.config.ram_base
        ram_end = ram_start + self.config.ram_size
        if (self._bootstrap_data_end is None
                and ram_start <= destination <= ram_start + BOOTSTRAP_HLE_SLACK
                and ram_start < limit <= ram_end):
            return "data"
        if (self._bootstrap_bss_complete and self._bootstrap_iram_end is None
                and self._bootstrap_rom_end is not None
                and self._bootstrap_rom_end
                <= source <= self._bootstrap_rom_end + BOOTSTRAP_HLE_SLACK
                and 0x03800000 <= destination
                <= 0x03800000 + BOOTSTRAP_HLE_SLACK
                and 0x03800000 < limit <= 0x03A00000):
            return "iram"
        return None

    def _bootstrap_clear_stage(self, destination: int, stop: int,
                               full_limit: int | None,
                               strobe_address: int | None) -> str | None:
        """Lease only the BSS span immediately following a bootstrap copy."""
        if (full_limit is None or strobe_address is None
                or not self._bootstrap_hle_is_early()
                or not self._thumb_watchdog_strobe(strobe_address)):
            return None
        ram_end = self.config.ram_base + self.config.ram_size
        if (self._bootstrap_bss_end is None
                and self._bootstrap_data_end is not None
                and self._bootstrap_data_end <= destination
                <= self._bootstrap_data_end + BOOTSTRAP_HLE_SLACK
                and destination < stop <= full_limit <= ram_end):
            return "open"
        if (self._bootstrap_bss_end is not None
                and self._bootstrap_data_end is not None
                and full_limit == self._bootstrap_bss_end
                and self._bootstrap_data_end <= destination < stop
                <= self._bootstrap_bss_end):
            return "continue"
        return None
