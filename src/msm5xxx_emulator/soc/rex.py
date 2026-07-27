"""SoC behavior owned by rex."""
from __future__ import annotations

from ..detection.rex import REX_5MS_CALLBACK_SIZE
from ..detection.rex import REX_IRQ_HANDLER_RUNTIME_SIZE
from ..detection.rex import REX_IRQ_WRAPPER_RUNTIME_SIZE
from ..detection.rex import REX_LEGACY_5MS_CALLBACK_SIZE
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
from ..detection.rex import rex_legacy_5ms_callback_shape_at
from ..detection.rex import rex_sleep_call_at
import struct


class RexMixin:
    def _rex_legacy_irq_route(self) -> dict[str, object] | None:
        profile = getattr(self, "direct_input_profile", None)
        bridge = (
            profile.get("timer_bridge")
            if isinstance(profile, dict) else None
        )
        route = (
            bridge.get("irq_route")
            if isinstance(bridge, dict)
            and bridge.get("signature") == "legacy-rex-5ms-scanner-timer-v1"
            else None
        )
        return (
            route if isinstance(route, dict)
            and route.get("controller_class") in {
                "legacy-c80-two-bank-group10-v1",
                "legacy-c80-three-bank-group14-v1",
            }
            and self._rex_legacy_irq_route_metadata_valid(route)
            else None
        )

    @staticmethod
    def _rex_legacy_irq_route_metadata_valid(route: dict[str, object]) -> bool:
        """Keep runtime hooks inside a detector-closed controller grammar."""
        status = route.get("status")
        enable = route.get("enable")
        if not isinstance(status, int) or not isinstance(enable, int):
            return False
        controller_class = route.get("controller_class")
        if controller_class == "legacy-c80-two-bank-group10-v1":
            banks = (status, status + 4)
            clear_banks = banks
            writes = (enable, enable + 4)
            count, row_size, aperture = 2, 10, (status, enable + 6)
        elif controller_class == "legacy-c80-three-bank-group14-v1":
            banks = (status, status + 4, status + 0x30)
            clear_banks = (status, status + 4, enable + 0x38)
            writes = (enable, enable + 4, enable + 0x30)
            count, row_size, aperture = 3, 14, (status, enable + 0x3A)
        else:
            return False
        return (
            route.get("status_banks") == banks
            and route.get("clear_banks") == clear_banks
            and route.get("controller_write_banks") == writes
            and route.get("controller_aperture") == aperture
            and route.get("status_bank_count") == count
            and route.get("group_row_size") == row_size
        )

    def _rex_irq_status_write(self, uc: Uc, access: int, address: int,
                              size: int, value: int,
                              user_data: object) -> None:
        """Apply partial guest W1C writes to detector-closed status banks."""
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is None or size <= 0:
            return
        route = self._rex_legacy_irq_route()
        if not self._rex_irq_shadow_access_allowed(uc, route):
            return
        incoming = value.to_bytes(size, "little")
        banks = route["clear_banks"] if route is not None else (
            status, status + 4,
        )
        for index, bank in enumerate(banks):
            left = max(address, bank)
            right = min(address + size, bank + 2)
            if left < right:
                offset = left - address
                clear = int.from_bytes(
                    incoming[offset:offset + right - left], "little"
                ) << ((left - bank) * 8)
                if index < len(self._rex_irq_pending):
                    self._rex_irq_pending[index] &= ~clear & 0xFFFF

    def _rex_irq_status_read(self, uc: Uc, access: int, address: int,
                             size: int, value: int,
                             user_data: object) -> None:
        """Refresh guest backing from controller status shadow before reads."""
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is None:
            return
        route = self._rex_legacy_irq_route()
        if not self._rex_irq_shadow_access_allowed(uc, route):
            return
        if route is None or route["status_bank_count"] == 2:
            uc.mem_write(status, struct.pack("<I", self._rex_irq_pending[0]))
            uc.mem_write(status + 4,
                         struct.pack("<I", self._rex_irq_pending[1]))
            return
        banks = route["status_banks"]
        for index, bank in enumerate(banks):
            if index < len(self._rex_irq_pending):
                uc.mem_write(bank, struct.pack("<H", self._rex_irq_pending[index]))

    @staticmethod
    def _rex_irq_shadow_access_allowed(
            uc: Uc, route: dict[str, object] | None) -> bool:
        """Keep group14 boot-time controller accesses guest-owned."""
        if (route is None or route.get("controller_class")
                != "legacy-c80-three-bank-group14-v1"):
            return True
        handler = route.get("handler")
        length = route.get("handler_validation_size")
        return (
            isinstance(handler, int)
            and isinstance(length, int)
            and length > 0
            and handler <= (uc.reg_read(UC_ARM_REG_PC) & ~1) < handler + length
        )

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
                or status & 3 or mask != 0x0200):
            return False
        legacy = self._rex_legacy_irq_route()
        if legacy is None:
            valid_firmware = enable == status + 8 and (
                self._rex_firmware_matches(
                    uc, wrapper, REX_IRQ_WRAPPER_RUNTIME_SIZE
                )
                and self._rex_firmware_matches(
                    uc, handler, REX_IRQ_HANDLER_RUNTIME_SIZE
                )
                and self._rex_firmware_matches(
                    uc, tick, REX_5MS_CALLBACK_SIZE, rex_5ms_callback_at
                )
            )
        else:
            wrapper_size = legacy.get("wrapper_validation_size")
            handler_size = legacy.get("handler_validation_size")
            if not all(
                isinstance(length, int) and length > 0
                for length in (wrapper_size, handler_size)
            ):
                return False
            route_fields = {
                "outer_callback": tick,
                "wrapper": wrapper,
                "handler": handler,
                "handler_slot": handler_slot,
                "callback_slot": callback_slot,
                "status": status,
                "enable": enable,
                "mask": mask,
            }
            valid_firmware = (
                all(value == legacy.get(field)
                    for field, value in route_fields.items())
                and status is not None
                and enable == status + 0x14
                and self._rex_firmware_matches(
                    uc, wrapper, wrapper_size
                )
                and self._rex_firmware_matches(
                    uc, handler, handler_size
                )
                and self._rex_firmware_matches(
                    uc, tick, REX_LEGACY_5MS_CALLBACK_SIZE,
                    rex_legacy_5ms_callback_shape_at,
                )
            )
        if not valid_firmware:
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
        legacy = self._rex_legacy_irq_route()
        if self.config.rex_tick_ms == 5 and legacy is None:
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
            tick_matches = (
                self._rex_firmware_matches(
                    uc, tick_address, REX_LEGACY_5MS_CALLBACK_SIZE,
                    rex_legacy_5ms_callback_shape_at,
                )
                if legacy is not None else
                self._rex_firmware_matches(
                    uc, tick_address, REX_5MS_CALLBACK_SIZE,
                    rex_5ms_callback_at,
                )
            )
        if (tick_address is None
                or not tick_matches
                or not self.config.rex_tick_ms
                or self.instructions < self.rex_next_instruction):
            return
        if self.config.rex_tick_ms == 5:
            if ((legacy is None and not post_sleep)
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
