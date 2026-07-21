"""SoC behavior owned by rex."""
from __future__ import annotations

from ..detection.rex import REX_5MS_CALLBACK_SIZE
from ..detection.rex import REX_IRQ_HANDLER_RUNTIME_SIZE
from ..detection.rex import REX_IRQ_WRAPPER_RUNTIME_SIZE
from ..core.constants import REX_TICK_INTERVAL
from ..detection.rex import REX_TICK_SIGNATURE
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R12
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_SP
from unicorn.arm_const import UC_ARM_REG_SPSR
from unicorn import UC_PROT_WRITE
from unicorn import Uc
from unicorn import UcError
from ..detection.arm import arm_b_word_target
from ..detection.rex import rex_5ms_callback_at
from ..detection.rex import rex_sleep_call_at
import struct


class RexMixin:
    def _rex_irq_status_write(self, uc: Uc, access: int, address: int,
                              size: int, value: int,
                              user_data: object) -> None:
        """Apply partial guest W1C writes to two 16-bit status banks."""
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is None or size <= 0:
            return
        incoming = value.to_bytes(size, "little")
        for index, bank in enumerate((status, status + 4)):
            left = max(address, bank)
            right = min(address + size, bank + 2)
            if left < right:
                offset = left - address
                clear = int.from_bytes(
                    incoming[offset:offset + right - left], "little"
                ) << ((left - bank) * 8)
                self._rex_irq_pending[index] &= ~clear & 0xFFFF

    def _rex_irq_status_read(self, uc: Uc, access: int, address: int,
                             size: int, value: int,
                             user_data: object) -> None:
        """Refresh guest backing from controller status shadow before reads."""
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is not None:
            uc.mem_write(status, struct.pack("<I", self._rex_irq_pending[0]))
            uc.mem_write(status + 4,
                         struct.pack("<I", self._rex_irq_pending[1]))

    def _rex_firmware_matches(self, uc: Uc, target: int, length: int,
                              validator=None) -> bool:
        expected = self._original_runtime_bytes(target, length)
        try:
            return (
                expected is not None
                and (validator is None or validator(expected, 0) is not None)
                and bytes(uc.mem_read(target, length)) == expected
            )
        except UcError:
            return False

    @staticmethod
    def _rex_irq_stack_mapped(uc: Uc, stack: int) -> bool:
        return (stack & 3 == 0 and any(
            begin <= stack - 0x40 and stack - 1 <= end
            and permissions & UC_PROT_WRITE
            for begin, end, permissions in uc.mem_regions()
        ))

    def _rex_irq_route_valid(self, uc: Uc, *, stack: bool = False) -> bool:
        wrapper = getattr(self.config, "rex_irq_wrapper_address", None)
        handler = getattr(self.config, "rex_irq_handler_address", None)
        handler_slot = getattr(self.config, "rex_irq_handler_slot", None)
        callback_slot = getattr(self.config, "rex_irq_callback_slot", None)
        tick = getattr(self.config, "rex_tick_address", None)
        status = getattr(self.config, "rex_irq_status_address", None)
        enable = getattr(self.config, "rex_irq_enable_address", None)
        mask = getattr(self.config, "rex_irq_mask", 0)
        if (wrapper is None or handler is None or handler_slot is None
                or callback_slot is None or tick is None or status is None
                or status & 3 or enable != status + 8 or mask != 0x0200
                or not self._rex_firmware_matches(
                    uc, wrapper, REX_IRQ_WRAPPER_RUNTIME_SIZE)
                or not self._rex_firmware_matches(
                    uc, handler, REX_IRQ_HANDLER_RUNTIME_SIZE)
                or not self._rex_firmware_matches(
                    uc, tick, REX_5MS_CALLBACK_SIZE, rex_5ms_callback_at)):
            return False
        try:
            installed_handler = struct.unpack(
                "<I", bytes(uc.mem_read(handler_slot, 4))
            )[0]
            installed_tick = struct.unpack(
                "<I", bytes(uc.mem_read(callback_slot, 4))
            )[0]
            vector = arm_b_word_target(struct.unpack(
                "<I", bytes(uc.mem_read(0x18, 4))
            )[0], 0x18)
            if (vector is None
                    or not self.config.ram_base <= vector
                    <= self.config.ram_base + self.config.ram_size - 4):
                return False
            routed_wrapper = arm_b_word_target(struct.unpack(
                "<I", bytes(uc.mem_read(vector, 4))
            )[0], vector)
        except UcError:
            return False
        if (installed_handler != handler | 1
                or installed_tick != tick | 1
                or routed_wrapper != wrapper):
            return False
        if stack:
            old = uc.reg_read(UC_ARM_REG_CPSR)
            if old & 0x1F in (0x11, 0x12):
                return False
            try:
                uc.reg_write(UC_ARM_REG_CPSR, (old & ~0xBF) | 0x92)
                irq_stack = uc.reg_read(UC_ARM_REG_SP)
                uc.reg_write(UC_ARM_REG_CPSR, (old & ~0xBF) | 0x9F)
                system_stack = uc.reg_read(UC_ARM_REG_SP)
            finally:
                uc.reg_write(UC_ARM_REG_CPSR, old)
            if not all(self._rex_irq_stack_mapped(uc, value)
                       for value in (irq_stack, system_stack)):
                return False
        return True

    def _rex_irq_boundary(self, uc: Uc, address: int) -> bool:
        """Enter one latched, enabled IRQ at a firmware block boundary."""
        enable = getattr(self.config, "rex_irq_enable_address", None)
        if enable is None or not self._rex_irq_pending[0]:
            return False
        cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        if cpsr & 0x80 or cpsr & 0x1F in (0x11, 0x12):
            return False
        try:
            enabled = struct.unpack("<H", bytes(uc.mem_read(enable, 2)))[0]
        except UcError:
            return False
        if not enabled & self._rex_irq_pending[0]:
            return False
        if not self._rex_irq_route_valid(uc, stack=True):
            return False
        irq_cpsr = (cpsr & ~0xBF) | 0x92
        uc.reg_write(UC_ARM_REG_CPSR, irq_cpsr)
        irq_stack = uc.reg_read(UC_ARM_REG_SP)
        if not self._rex_irq_stack_mapped(uc, irq_stack):
            uc.reg_write(UC_ARM_REG_CPSR, cpsr)
            return False
        uc.reg_write(UC_ARM_REG_SPSR, cpsr)
        uc.reg_write(UC_ARM_REG_LR, address + 4)
        uc.reg_write(UC_ARM_REG_PC, 0x18)
        self.rex_irq_deliveries += 1
        return True

    def _rex_tick(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if getattr(self, "_rex_tick_return_address", None) == address:
            for register, value in self._rex_tick_context or ():
                uc.reg_write(register, value)
            self._rex_tick_return_address = None
            self._rex_tick_context = None
            return
        post_sleep = False
        if self.config.rex_tick_ms == 5:
            start = address - 46
            expected_sleep = self._original_runtime_bytes(start, 56)
            try:
                post_sleep = (
                    expected_sleep is not None
                    and rex_sleep_call_at(expected_sleep, 0) == 42
                    and bytes(uc.mem_read(start, len(expected_sleep)))
                    == expected_sleep
                )
            except UcError:
                post_sleep = False
        if (not post_sleep
                and not self._thumb_runtime_matches(uc, address, prefix_size=4)):
            return
        self.rex_idle_entries += 1
        tick_address = self.config.rex_tick_address
        tick_matches = (tick_address is not None
                        and self._thumb_runtime_matches(
                            uc, tick_address, REX_TICK_SIGNATURE))
        if tick_address is not None and not tick_matches:
            tick_matches = self._rex_firmware_matches(
                uc,
                tick_address, REX_5MS_CALLBACK_SIZE, rex_5ms_callback_at
            )
        if (tick_address is None
                or not tick_matches
                or not self.config.rex_tick_ms
                or self.instructions < self.rex_next_instruction):
            return
        if self.config.rex_tick_ms == 5:
            if (not post_sleep
                    or getattr(self.config, "rex_irq_wrapper_address", None) is None
                    or not self._rex_irq_route_valid(uc, stack=True)):
                return
        self.rex_next_instruction = self.instructions + REX_TICK_INTERVAL
        self.rex_ticks += 1
        self.rex_elapsed_ms += self.config.rex_tick_ms
        if self.config.rex_tick_ms == 5:
            self._rex_irq_pending[0] |= self.config.rex_irq_mask
            return
        if post_sleep:
            registers = (
                UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_CPSR,
            )
            self._rex_tick_context = tuple(
                (register, uc.reg_read(register)) for register in registers
            )
            self._rex_tick_return_address = address
        uc.reg_write(UC_ARM_REG_R0, self.config.rex_tick_ms)
        uc.reg_write(UC_ARM_REG_LR, address | 1 if post_sleep else address + 5)
        uc.reg_write(UC_ARM_REG_PC, tick_address | 1)
