"""Legacy Unicorn CPU setup around the shared device lifecycle."""
from __future__ import annotations

from .config import FirmwareConfig
from .constants import NAND_MMIO_RANGES
from .constants import STABLE_MSM_MMIO
from ..detection.boot import BUSY_DELAY_SIGNATURE
from ..detection.boot import BUSY_DELAY_SIGNATURES
from ..detection.boot import DELAY_SIGNATURE
from ..detection.boot import DMD_DOWNLOAD_5500_SIZE
from ..detection.boot import absent_optional_ram_probe_addresses
from ..detection.boot import busy_delay_addresses
from ..detection.boot import is_dmd_download_5500
from ..detection.memory_layout import interval_gaps

from .device_state import ApproximateSmafPlayer, DeviceStateMixin


class LifecycleMixin(DeviceStateMixin):
    _uses_cpu = True

    def _initialize_memory(
            self, config: FirmwareConfig, secondary_base: int | None,
            ram_end: int, ram_seed: bytes) -> None:
        from unicorn import UC_ARCH_ARM
        from unicorn.arm_const import UC_ARM_REG_CPSR
        from unicorn.arm_const import UC_ARM_REG_SP
        from unicorn.arm_const import UC_CPU_ARM_TI925T
        from unicorn import UC_HOOK_MEM_READ
        from unicorn import UC_MODE_ARM
        from unicorn import UC_PROT_ALL
        from unicorn import Uc, UcError

        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_TI925T)
        from .initial_state import initial_register_state

        def stable_hook(address, value):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._stable_mmio_read,
                             begin=address, end=address + len(value) - 1,
                             user_data=(address, value))

        self._map_and_seed_memory(
            config, secondary_base, ram_seed,
            lambda address, size: self.uc.mem_map(address, size, UC_PROT_ALL),
            self.uc.mem_write, self.uc.mem_read, (UcError,), stable_hook,
        )
        registers = initial_register_state(config)
        self.uc.reg_write(UC_ARM_REG_CPSR, registers["cpsr"])
        self.uc.reg_write(UC_ARM_REG_SP, registers["sp"])

    def _install_remaining_hooks(
            self, config: FirmwareConfig, secondary_base: int | None,
            eeprom_enabled: bool) -> None:
        from unicorn import UC_HOOK_BLOCK
        from unicorn import UC_HOOK_CODE
        from unicorn import UC_HOOK_MEM_READ
        from unicorn import UC_HOOK_MEM_UNMAPPED
        from unicorn import UC_HOOK_MEM_WRITE
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x03000000, end=0x03FFFFFF)
        self._install_sbi_hooks()
        if self.upper_flash is None:
            self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x02800000, end=0x02800FFF)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x02C00000, end=0x02C00FFF)
        if self.audio_transport.static_status == "accepted":
            audio_end = self.audio_transport.base + self.audio_transport.data_offset
            self.uc.hook_add(
                UC_HOOK_MEM_WRITE, self._audio_transport_write,
                begin=self.audio_transport.base, end=audio_end,
            )
            self.uc.hook_add(
                UC_HOOK_MEM_READ, self._audio_transport_read,
                begin=self.audio_transport.base, end=audio_end,
            )
        flash_end = config.load_address + len(self.image)
        open_bus_exclusions = [
            *NAND_MMIO_RANGES,
            (0x02000000, 0x02801000),  # LCD buses and indexed registers
            (0x02C00000, 0x02C01000),
            (0x03000000, 0x04000000),  # MSM MMIO plus internal RAM
            *((address, address + len(value))
              for address, value in STABLE_MSM_MMIO),
        ]
        if config.key_register is not None:
            open_bus_exclusions.append((config.key_register,
                                        config.key_register + 4))
        if config.board_revision_register is not None:
            open_bus_exclusions.append((config.board_revision_register,
                                        config.board_revision_register + 4))
        if secondary_base is not None:
            open_bus_exclusions.append((
                secondary_base, secondary_base + config.secondary_flash_size
            ))
        if self.upper_base is not None:
            open_bus_exclusions.append((self.upper_base,
                                        self.upper_base + config.upper_flash_size))
        for left, right in interval_gaps(
                flash_end, config.ram_base, open_bus_exclusions):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._open_bus_read,
                             begin=left, end=right - 1)
        # The old MSMs commonly expose one 8 MiB SDRAM bank.  A permissive
        # backing arena must not make a physically absent second bank writable.
        absent_start = config.ram_base + config.ram_size
        if absent_start < 0x02000000:
            for left, right in interval_gaps(
                    absent_start, 0x02000000, open_bus_exclusions):
                self.uc.hook_add(UC_HOOK_MEM_READ, self._open_bus_read,
                                 begin=left, end=right - 1)
        if (config.board_revision_register is not None
                and config.board_revision_value is not None):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._board_revision_read,
                             begin=config.board_revision_register,
                             end=config.board_revision_register + 3)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._lcd_write,
                         begin=0x02000000,
                         end=0x027FFFFF if self.upper_flash is not None else 0x02800FFF)
        if self.upper_flash is None:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._lcd_write,
                             begin=0x02C00000, end=0x02C00FFF)
        if config.framebuffer_flush_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._framebuffer_rows,
                             begin=config.framebuffer_flush_address,
                             end=config.framebuffer_flush_address)
        if config.framebuffer_rect_flush_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._framebuffer_rect,
                             begin=config.framebuffer_rect_flush_address,
                             end=config.framebuffer_rect_flush_address)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                         begin=config.load_address,
                         end=config.load_address + len(self.image) - 1,
                         user_data=(config.load_address, self.flash))
        self.uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                         begin=config.load_address,
                         end=config.load_address + len(self.image) - 1,
                         user_data=(config.load_address, self.flash))
        if secondary_base is not None and self.secondary_flash is not None:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                             begin=secondary_base,
                             end=secondary_base + config.secondary_flash_size - 1,
                             user_data=(secondary_base, self.secondary_flash))
            self.uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                             begin=secondary_base,
                             end=secondary_base + config.secondary_flash_size - 1,
                             user_data=(secondary_base, self.secondary_flash))
            if config.secondary_flash_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._secondary_flash_read_fast,
                                 begin=config.secondary_flash_read_address,
                                 end=config.secondary_flash_read_address)
            if config.secondary_flash_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._secondary_flash_write_fast,
                                 begin=config.secondary_flash_write_address,
                                 end=config.secondary_flash_write_address)
        if self.upper_base is not None and self.upper_flash is not None:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                             begin=self.upper_base,
                             end=self.upper_base + config.upper_flash_size - 1,
                             user_data=(self.upper_base, self.upper_flash))
            self.uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                             begin=self.upper_base,
                             end=self.upper_base + config.upper_flash_size - 1,
                             user_data=(self.upper_base, self.upper_flash))
        if eeprom_enabled:
            if config.eeprom_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._eeprom_read_fast,
                                 begin=config.eeprom_read_address,
                                 end=config.eeprom_read_address)
            if config.eeprom_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._eeprom_write_fast,
                                 begin=config.eeprom_write_address,
                                 end=config.eeprom_write_address)
        if config.legacy_efs_page_read_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._legacy_efs_page_read,
                             begin=config.legacy_efs_page_read_address,
                             end=config.legacy_efs_page_read_address)
        if self._legacy_nand_enabled:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_command,
                             begin=0x01A00000, end=0x01A00000)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_address_write,
                             begin=0x01900000, end=0x01900000)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._nand_data_read,
                             begin=0x01800000, end=0x01800003)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_data_write,
                             begin=0x01800000, end=0x01800003)
        if config.audio_play_address:
            self.uc.hook_add(UC_HOOK_CODE, self._audio_play,
                             begin=config.audio_play_address,
                             end=config.audio_play_address)
        if config.ma2_silent_boot_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._ma2_silent_boot,
                             begin=config.ma2_silent_boot_address,
                             end=config.ma2_silent_boot_address)
        if config.fast_boot_address and config.linker is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_boot_hook,
                             begin=config.fast_boot_address,
                             end=config.fast_boot_address)
        if self._legacy_nand_enabled:
            if config.nand_bad_block_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_bad_block,
                                 begin=config.nand_bad_block_address,
                                 end=config.nand_bad_block_address)
            if config.nand_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_read_fast,
                                 begin=config.nand_read_address,
                                 end=config.nand_read_address)
            if config.nand_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_write_fast,
                                 begin=config.nand_write_address,
                                 end=config.nand_write_address)
        if config.delay_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._return_if_thumb_signature,
                             begin=config.delay_address, end=config.delay_address,
                             user_data=DELAY_SIGNATURE)
        for address in busy_delay_addresses(self.original_image,
                                            config.load_address,
                                            config.busy_delay_address):
            offset = address - config.load_address
            signature = next((candidate for candidate in BUSY_DELAY_SIGNATURES
                              if self.original_image[
                                  offset:offset + len(candidate)] == candidate),
                             BUSY_DELAY_SIGNATURE)
            self.uc.hook_add(UC_HOOK_CODE, self._return_busy_delay,
                             begin=address, end=address,
                             user_data=signature)
        for address in absent_optional_ram_probe_addresses(
                self.original_image, config.load_address,
                config.ram_base, config.ram_size):
            self.uc.hook_add(UC_HOOK_CODE, self._absent_optional_ram_probe,
                             begin=address, end=address)
        if config.rex_idle_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._rex_tick,
                             begin=config.rex_idle_address, end=config.rex_idle_address)
        aperture = self._rex_irq_controller_aperture
        if (config.rex_irq_wrapper_address is not None
                and config.rex_irq_status_address is not None):
            if not (isinstance(aperture, tuple) and len(aperture) == 2):
                aperture = (
                    config.rex_irq_status_address,
                    config.rex_irq_status_address + 8,
                )
            self.uc.hook_add(
                UC_HOOK_MEM_WRITE, self._rex_irq_status_write,
                begin=int(aperture[0]), end=int(aperture[1]) - 1,
            )
            self.uc.hook_add(
                UC_HOOK_MEM_READ, self._rex_irq_status_read,
                begin=int(aperture[0]), end=int(aperture[1]) - 1,
            )
        self._install_rex_irq_arm_hook(config)
        if config.board_adc_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._board_adc,
                             begin=config.board_adc_address, end=config.board_adc_address)
        if config.board_adc_reader_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._board_adc_reader_entry,
                             begin=config.board_adc_reader_address,
                             end=config.board_adc_reader_address)
        if config.flash_id_address is not None and config.flash_id_value is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._flash_id,
                             begin=config.flash_id_address, end=config.flash_id_address)
        if config.crc16_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._crc16_fast,
                             begin=config.crc16_address, end=config.crc16_address)
        if config.dmd_download_address is not None:
            routine = (
                self._original_runtime_bytes(
                    config.dmd_download_address, DMD_DOWNLOAD_5500_SIZE
                )
                or b""
            )
            if is_dmd_download_5500(routine):
                self._dmd_5500_pending = False
                self.uc.hook_add(
                    UC_HOOK_MEM_WRITE, self._dmd_5500_start,
                    begin=0x030F0124, end=0x030F0125,
                )
                self.uc.hook_add(
                    UC_HOOK_CODE, self._dmd_5500_complete,
                    begin=config.dmd_download_address + 0x32,
                    end=config.dmd_download_address + 0x32,
                )
            else:
                self.uc.hook_add(UC_HOOK_CODE, self._dmd_download_fast,
                                 begin=config.dmd_download_address,
                                 end=config.dmd_download_address)
        for address in config.memory_clear_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_memory_clear,
                             begin=address, end=address)
        for address in config.memory_copy_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_memory_copy,
                             begin=address, end=address)
        for address in config.register_ramp_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_register_ramp,
                             begin=address, end=address)
        for address in config.arm_memory_copy_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_arm_memory_copy,
                             begin=address, end=address)
        # GUI execution uses small run() chunks.  Keep this observer for the
        # session instead of repeatedly creating and deleting a Unicorn block
        # hook; long Windows sessions otherwise churn the backend hook list.
        self._trace_hook = self.uc.hook_add(UC_HOOK_BLOCK, self._trace)
