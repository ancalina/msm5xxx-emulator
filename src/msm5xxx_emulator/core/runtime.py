"""Runtime behavior owned by runtime."""
from __future__ import annotations

from collections import Counter
from .errors import HostBackendFault
from .constants import POLL_OBSERVATION_STEPS
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_R4
from unicorn.arm_const import UC_ARM_REG_R5
from unicorn.arm_const import UC_ARM_REG_R6
from unicorn.arm_const import UC_ARM_REG_R7
from unicorn.arm_const import UC_ARM_REG_SP
from unicorn import UC_HOOK_BLOCK
from unicorn import UcError
import json
import logging

LOGGER = logging.getLogger("msm5xxx")


class RuntimeMixin:
    def run(self, steps: int, fast_boot_probe: int = 100_000) -> dict[str, object]:
        host_backend_fault = getattr(self, "_host_backend_fault", None)
        if host_backend_fault is not None:
            raise host_backend_fault
        if steps < 0 or fast_boot_probe <= 0:
            raise ValueError("steps must be non-negative and probe size positive")
        # Compatibility for focused harnesses built with __new__().  Normal
        # sessions install the trace hook once during construction.
        if getattr(self, "_trace_hook", None) is None:
            self._trace_hook = self.uc.hook_add(UC_HOOK_BLOCK, self._trace)
        if self.instructions:
            next_pc = self.uc.reg_read(UC_ARM_REG_PC)
            if self.uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                next_pc |= 1
        else:
            next_pc = self.config.load_address + self.config.entry
        if not hasattr(self, "_poll_window_remaining"):
            self._poll_window_remaining = POLL_OBSERVATION_STEPS
        remaining = steps
        try:
            while remaining:
                if self._poll_window_remaining == POLL_OBSERVATION_STEPS:
                    self.hot.clear()
                    self.mmio_reads.clear()
                count = min(remaining, fast_boot_probe,
                            self._poll_window_remaining)
                self._chunk_unmapped = None
                checkpoint = self._host_backend_checkpoint(next_pc, count)
                try:
                    self.uc.emu_start(next_pc, 0xFFFFFFFF, count=count)
                except OSError as error:
                    host_backend_fault = HostBackendFault(error, checkpoint)
                    self._host_backend_fault = host_backend_fault
                    LOGGER.error("host backend failure diagnostic=%s",
                                 json.dumps(host_backend_fault.diagnostic,
                                            ensure_ascii=False, sort_keys=True))
                    raise host_backend_fault from error
                remaining -= count
                if self.fault:
                    break
                self.instructions += count
                self._poll_window_remaining -= count
                if not self._poll_window_remaining:
                    # Samsung boot ROMs expose primary scatter-load tuple at 0x10028.
                    # LG tables found elsewhere describe small overlays, not reset init.
                    can_fast_boot = (not self.fast_boot_used
                                     and self.config.fast_boot_address is None
                                     and not self.hot_loop_hle_used
                                     and self.config.linker is not None
                                     and self.config.linker.table_offset == 0x10028
                                     and self.config.linker.data_size >= 0x1000)
                    repeated = self.hot.most_common(1)[0][1] if self.hot else 0
                    lr = self.uc.reg_read(UC_ARM_REG_LR)
                    if can_fast_boot and repeated >= 100 and lr:
                        self._apply_linker()
                        cpsr = self.uc.reg_read(UC_ARM_REG_CPSR)
                        self.uc.reg_write(UC_ARM_REG_CPSR,
                                          cpsr | 0x20 if lr & 1 else cpsr & ~0x20)
                        self.uc.reg_write(UC_ARM_REG_PC, lr & ~1)
                    else:
                        self._release_hardware_poll()
                    self._poll_window_remaining = POLL_OBSERVATION_STEPS
                pc = self.uc.reg_read(UC_ARM_REG_PC)
                if self.uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                    pc |= 1
                next_pc = pc
                if not remaining:
                    break
        except UcError as error:
            if self.fault is None:
                pc = self.uc.reg_read(UC_ARM_REG_PC) & 0xFFFFFFFF
                error_detail = f"{error}{self._unmapped_fault_detail()}"
                missing_overlay = next((
                    item for item in self.config.missing_overlays
                    if item.target <= pc < item.target + item.size
                ), None)
                if missing_overlay is not None:
                    self.fault = self._missing_overlay_error(missing_overlay)
                executable = (
                    self.config.load_address <= pc
                    < self.config.load_address + len(self.image)
                    or self.config.ram_base <= pc
                    < self.config.ram_base + self.config.ram_size
                    or 0x03800000 <= pc < 0x03A00000
                )
                if self.fault is not None:
                    pass
                elif not executable:
                    self.fault = (
                        f"execution entered missing dump/device region "
                        f"0x{pc:08X}: {error_detail}"
                    )
                else:
                    self.fault = error_detail
        finally:
            if getattr(self, "_host_backend_fault", None) is None:
                self._restore_flash_once(self.uc, 0, 0, None)
        if (self.config.framebuffer_address is not None
                and self.config.framebuffer_flush_address is None
                and self.config.framebuffer_rect_flush_address is None):
            self._render_framebuffer_region(
                0, 0, self.config.width - 1, self.config.height - 1, force=False
            )
        self._lcd_page_flush_current()
        self._flush_indexed_frame()
        fault_context = self._fault_context()
        if self.fault is not None and self.fault != self._logged_fault:
            LOGGER.error("emulation fault model=%s pc=0x%08X instructions=%d "
                         "context=%s: %s",
                         self.config.model, self.uc.reg_read(UC_ARM_REG_PC),
                         self.instructions,
                         json.dumps(fault_context, sort_keys=True), self.fault)
            self._logged_fault = self.fault
        sink_instruction = b""
        if self.tail:
            try:
                sink_instruction = bytes(self.uc.mem_read(self.tail[-1], 4))
            except UcError:
                pass
        control_sink = self._control_sink_from_tail(self.tail, sink_instruction)
        return {
            "config": self.config.to_dict(),
            "cpu_model": "TI925T (ARMv4T stand-in for ARM7TDMI)",
            "instructions": self.instructions,
            "reset_entries": self.reset_entries,
            "pc": f"0x{self.uc.reg_read(UC_ARM_REG_PC):08X}",
            "lr": f"0x{self.uc.reg_read(UC_ARM_REG_LR):08X}",
            "registers": {
                **{f"r{index}": f"0x{self.uc.reg_read(register):08X}"
                   for index, register in enumerate((
                       UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                       UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                       UC_ARM_REG_R6, UC_ARM_REG_R7,
                   ))},
                "sp": f"0x{self.uc.reg_read(UC_ARM_REG_SP):08X}",
                "cpsr": f"0x{self.uc.reg_read(UC_ARM_REG_CPSR):08X}",
            },
            "fast_boot_used": self.fast_boot_used,
            "fast_memory_clears": self.fast_memory_clears,
            "fast_memory_copies": self.fast_memory_copies,
            "fast_register_ramps": self.fast_register_ramps,
            "fast_arm_memory_copies": self.fast_arm_memory_copies,
            "hot_loop_hle_used": self.hot_loop_hle_used,
            "fast_crc16_calls": self.fast_crc16_calls,
            "fast_dmd_downloads": self.fast_dmd_downloads,
            "primary_flash_ids": ({"manufacturer": self.flash.ids[0],
                                   "device": self.flash.ids[1]}
                                  if self.flash.ids is not None else None),
            "primary_flash_telemetry": self.flash.telemetry(),
            "primary_parallel_nor_direct_id_probes": list(
                getattr(self, "primary_parallel_nor_direct_id_probes", ())
            ),
            "ram_seed_size": self.ram_seed_size,
            "fault": self.fault,
            "fault_context": fault_context,
            "dynamic_pages": len(self.dynamic_pages),
            "control_sink": (f"0x{control_sink:08X}"
                             if control_sink is not None else None),
            "last_unmapped": ({**self.last_unmapped,
                               "address_hex": f"0x{self.last_unmapped['address']:08X}"}
                              if self.last_unmapped is not None else None),
            "unmapped_accesses": [
                {**event, "address_hex": f"0x{event['address']:08X}",
                 **({"pc_hex": f"0x{event['pc']:08X}"} if "pc" in event else {})}
                for event in getattr(self, "unmapped_accesses", ())
            ],
            "dynamic_page_first_accesses": [
                {**event, "address_hex": f"0x{event['address']:08X}",
                 "page_hex": f"0x{event['page']:08X}",
                 **({"pc_hex": f"0x{event['pc']:08X}"} if "pc" in event else {})}
                for event in getattr(self, "dynamic_page_first_accesses", ())
            ],
            "lcd_writes": self.lcd_writes,
            "lcd_protocol": self._lcd_protocol,
            "lcd_frame_protocol": self._lcd_frame_protocol,
            "lcd_port_writes": [
                {"address": f"0x{address:08X}", "size": size, "writes": writes}
                for (address, size), writes in self.lcd_port_writes.most_common()
            ],
            "frame_sequence": self.frame_sequence,
            "firmware_frame_sequence": self.firmware_frame_sequence,
            "rex_idle_entries": self.rex_idle_entries,
            "rex_ticks": self.rex_ticks,
            "rex_elapsed_ms": self.rex_elapsed_ms,
            "rex_irq_deliveries": self.rex_irq_deliveries,
            "board_adc_reads": self.board_adc_reads,
            "flash_id_reads": self.flash_id_reads,
            "secondary_flash_reads": self.secondary_flash_reads,
            "secondary_flash_writes": self.secondary_flash_writes,
            "legacy_efs_page_reads": self.legacy_efs_page_reads,
            "secondary_flash_changed_pages": (len(self.secondary_flash.changed_pages)
                                                if self.secondary_flash is not None else 0),
            "secondary_flash_telemetry": (
                self.secondary_flash.telemetry()
                if self.secondary_flash is not None else None
            ),
            "eeprom_capacity": self.eeprom_capacity,
            "eeprom_reads": self.eeprom_reads,
            "eeprom_read_bytes": self.eeprom_read_bytes,
            "eeprom_writes": self.eeprom_writes,
            "eeprom_write_bytes": self.eeprom_write_bytes,
            "eeprom_changed_bytes": (
                len(self.eeprom_data) - self.eeprom_data.count(0xFF)
            ),
            "eeprom_loaded_from_state": self.eeprom_loaded_from_state,
            "eeprom_state": (str(self.eeprom_state_path)
                              if self.eeprom_enabled else None),
            "eeprom_error": self.eeprom_error,
            "input_profile": self.input_profile[0] if self.input_profile else "gpio",
            "input_mode": ("firmware-consumed" if self.firmware_key_events else
                           "candidate-register" if self.config.key_register is not None else
                           "not-detected"),
            "input_entry": (f"0x{self.input_profile[1]:08X}"
                            if self.input_profile else None),
            "input_error": self.input_error,
            "input_events": self.input_events,
            "firmware_key_events": self.firmware_key_events,
            "input_register_reads": getattr(self, "key_register_reads", 0),
            "input_register_read_pcs": [
                {"pc": f"0x{pc:08X}", "reads": reads}
                for pc, reads in getattr(self, "key_register_read_pcs", Counter()).most_common(16)
            ],
            "input_transport": (
                "candidate-register+consumer" if self.firmware_key_events else
                "candidate-register-observed" if getattr(self, "key_register_reads", 0) else
                "candidate-register-unobserved" if self.config.key_register is not None else
                "not-detected"
            ),
            "audio_play_address": (f"0x{self.config.audio_play_address:08X}"
                                   if self.config.audio_play_address is not None else None),
            "audio_discovered_address": (f"0x{self.audio_discovered_address:08X}"
                                         if self.audio_discovered_address is not None else None),
            "audio_play_requests": self.audio_play_requests,
            "audio_last_size": self.audio_last_size,
            "ma2_silent_boot_address": (
                f"0x{self.config.ma2_silent_boot_address:08X}"
                if self.config.ma2_silent_boot_address is not None else None
            ),
            "ma2_silent_boot_calls": self.ma2_silent_boot_calls,
            "audio_backend": (self.audio_player.backend if self.audio_player is not None
                              else "disabled"),
            "audio_error": (self.audio_player.last_error if self.audio_player is not None else ""),
            "nand_commands": self.nand_commands,
            "nand_backing_size": len(self.nand_image),
            "nand_reads": self.nand_reads,
            "nand_writes": self.nand_writes,
            "nand_bad_block_probes": self.nand_bad_block_probes,
            "poll_escapes": [{**item, "pc_hex": f"0x{item['pc']:08X}",
                              "address_hex": f"0x{item['address']:08X}"}
                             for item in self.poll_escapes],
            "tail": [f"0x{address:08X}" for address in self.tail],
        }
