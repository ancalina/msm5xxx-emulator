"""SoC behavior owned by rex."""
from __future__ import annotations

from ..detection.rex import REX_5MS_CALLBACK_SIZE
from ..detection.rex import REX_IRQ_HANDLER_RUNTIME_SIZE
from ..detection.rex import REX_IRQ_WRAPPER_RUNTIME_SIZE
from ..detection.rex import REX_LEGACY_5MS_CALLBACK_SIZE
from ..core.constants import REX_TICK_INTERVAL
from ..detection.rex import REX_TICK_SIGNATURE
from unicorn import UC_HOOK_MEM_READ
from unicorn import UC_HOOK_MEM_WRITE
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
    _rex_copied_c40_gate_pending = False
    _rex_copied_c40_route: dict[str, object] | None = None

    def _install_rex_irq_arm_hook(self, config: object) -> None:
        arm = getattr(config, "rex_irq_arm_address", None)
        route = (getattr(config, "rex_tick_ms", None) == 5
                 and all(isinstance(getattr(config, field, None), int) for field in (
                     "rex_tick_address", "rex_irq_wrapper_address", "rex_irq_handler_address",
                     "rex_irq_status_address", "rex_irq_enable_address"))
                 and bool(getattr(config, "rex_irq_mask", 0)))
        self._rex_irq_arm_required = isinstance(arm, int) and route
        self._rex_irq_armed = not self._rex_irq_arm_required
        if self._rex_irq_arm_required:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._rex_irq_arm_write, begin=arm, end=arm)
            return
        observation = getattr(
            config, "rex_static_c40_controller_observation", None
        )
        if (isinstance(observation, dict) and observation.get("accepted")
                and observation.get("controller_class")
                == "c40-copied-vector-selector0-delta5-v1"
                and observation.get("time_tick_control_address")
                == 0x030006E0):
            self.uc.hook_add(
                UC_HOOK_MEM_WRITE, self._rex_copied_c40_arm_write,
                begin=0x030006E0, end=0x030006E0,
            )

    def _rex_irq_arm_write(self, uc: Uc, access: int, address: int, size: int,
                           value: int, user_data: object) -> None:
        del uc, access, user_data
        arm = getattr(self.config, "rex_irq_arm_address", None)
        if address != arm:
            return
        self.rex_irq_arm_writes += 1
        self.rex_irq_arm_last_value = value
        if size == 1 and value == 0x02:
            self._rex_irq_armed = True
            self.rex_irq_arm_accepts += 1
            self.rex_irq_arm_instruction = self.instructions

    def _rex_copied_c40_arm_write(
            self, uc: Uc, access: int, address: int, size: int, value: int,
            user_data: object,
    ) -> None:
        """Latch exact firmware arm; runtime route still needs installation."""
        del uc, access, user_data
        self.rex_irq_arm_writes += 1
        self.rex_irq_arm_last_value = value
        if address == 0x030006E0 and size == 1 and value == 0x02:
            self._rex_irq_armed = True
            self._rex_copied_c40_gate_pending = True
            self.rex_irq_arm_accepts += 1
            self.rex_irq_arm_instruction = self.instructions

    def _rex_direct_legacy_irq_route(self) -> dict[str, object] | None:
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

    def _rex_legacy_irq_route(self) -> dict[str, object] | None:
        direct = self._rex_direct_legacy_irq_route()
        if direct is not None:
            return direct
        candidate = getattr(self, "_rex_candidate_route", None)
        return (
            candidate if isinstance(candidate, dict)
            and candidate.get("signature")
            == "experimental-static-c80-controller-route-v1"
            and self._rex_legacy_irq_route_metadata_valid(candidate)
            else None
        )

    def _rex_copied_c40_irq_route(self) -> dict[str, object] | None:
        route = getattr(self, "_rex_copied_c40_route", None)
        return (
            route if isinstance(route, dict)
            and route.get("signature")
            == "runtime-c40-copied-vector-selector0-v1"
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
        pending_before = self._rex_irq_pending[0]
        incoming = value.to_bytes(size, "little")
        banks = (
            route["clear_banks"] if route is not None
            else (status, status + 4)
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
        if ((route is not None
                and route is getattr(self, "_rex_candidate_route", None)
                or self._rex_copied_c40_irq_route() is not None)
                and pending_before & 0x0200
                and not self._rex_irq_pending[0] & 0x0200):
            self.rex_controller_pending_acks += 1

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

    def _rex_copied_c40_runtime_route(
            self, uc: Uc,
    ) -> tuple[dict[str, object] | None, str, bool]:
        observation = getattr(
            self.config, "rex_static_c40_controller_observation", None
        )
        required = {
            "signature": "static-c40-copied-vector-selector0-v1",
            "controller_class": "c40-copied-vector-selector0-delta5-v1",
            "accepted": True, "active": False,
            "promotion": "telemetry-only", "vector": 0x18,
            "vector_target": 0x01000000, "mask": 0x0200,
            "selector": 0, "time_tick_control_address": 0x030006E0,
            "time_tick_arm_value": 2, "time_tick_period_ms": 5,
        }
        if (not isinstance(observation, dict)
                or any(observation.get(field) != value
                       for field, value in required.items())):
            return None, "copied-c40-metadata-invalid", True
        integer_fields = (
            "wrapper_file_offset", "handler_file_offset", "handler_slot",
            "callback_file_offset", "callback_slot",
        )
        if any(type(observation.get(field)) is not int
               for field in integer_fields):
            return None, "copied-c40-metadata-invalid", True
        status_banks = tuple(observation.get("status_banks", ()))
        enable_banks = tuple(observation.get("enable_banks", ()))
        if (status_banks != (0x03000C40, 0x03000C44)
                or enable_banks != (0x03000C54, 0x03000C58)):
            return None, "copied-c40-metadata-invalid", True
        wrapper = int(observation["wrapper_file_offset"])
        handler = int(observation["handler_file_offset"])
        handler_slot = int(observation["handler_slot"])
        callback = int(observation["callback_file_offset"])
        callback_slot = int(observation["callback_slot"])
        ram_end = self.config.ram_base + self.config.ram_size
        if any(address & 3 or not self.config.ram_base <= address <= ram_end - 4
               for address in (handler_slot, callback_slot)):
            return None, "copied-c40-metadata-invalid", True
        try:
            vector = arm_b_word_target(struct.unpack(
                "<I", bytes(uc.mem_read(0x18, 4))
            )[0], 0x18)
            routed_wrapper = arm_b_word_target(struct.unpack(
                "<I", bytes(uc.mem_read(0x01000000, 4))
            )[0], 0x01000000)
            installed_handler = struct.unpack(
                "<I", bytes(uc.mem_read(handler_slot, 4))
            )[0]
            installed_callback = struct.unpack(
                "<I", bytes(uc.mem_read(callback_slot, 4))
            )[0]
            enabled = struct.unpack(
                "<H", bytes(uc.mem_read(0x03000C54, 2))
            )[0]
        except UcError:
            return None, "copied-c40-runtime-state-unavailable", False
        if (vector != 0x01000000 or routed_wrapper != wrapper
                or installed_handler != handler | 1
                or installed_callback != callback | 1
                or not enabled & 0x0200):
            return None, "copied-c40-runtime-route-not-installed", False
        for address, length in ((wrapper, 0x20), (handler, 2),
                                (callback, 0x80)):
            if not self._rex_firmware_matches(uc, address, length):
                return None, "copied-c40-runtime-code-mismatch", True
        return {
            "signature": "runtime-c40-copied-vector-selector0-v1",
            "controller_class": "c40-copied-vector-selector0-delta5-v1",
            "status": 0x03000C40, "enable": 0x03000C54,
            "mask": 0x0200,
            "status_banks": (0x03000C40, 0x03000C44),
            "clear_banks": (0x03000C40, 0x03000C44),
            "controller_write_banks": (0x03000C54, 0x03000C58),
            "controller_aperture": (0x03000C40, 0x03000C5A),
            "vector": 0x18, "vector_target": 0x01000000,
            "wrapper": wrapper, "handler": handler,
            "handler_slot": handler_slot, "callback_slot": callback_slot,
            "outer_callback": callback,
        }, "", False

    def _rex_try_copied_c40_route(self, uc: Uc) -> bool:
        if self._rex_copied_c40_irq_route() is not None:
            return True
        if (not getattr(self, "_rex_copied_c40_gate_pending", False)
                or getattr(self, "_rex_copied_c40_gate_terminal", False)
                or self.instructions
                < getattr(self, "_rex_copied_c40_gate_next_instruction", 0)):
            return False
        route_fields = (
            "rex_tick_address", "rex_irq_wrapper_address",
            "rex_irq_handler_address", "rex_irq_handler_slot",
            "rex_irq_callback_slot", "rex_irq_status_address",
            "rex_irq_enable_address",
        )
        if (any(getattr(self.config, field, None) is not None
                for field in route_fields)
                or getattr(self.config, "rex_irq_mask", 0)):
            self.rex_controller_gate_reason = "existing-route-fields-priority"
            self._rex_copied_c40_gate_terminal = True
            return False
        self.rex_controller_gate_attempts += 1
        route, reason, terminal = self._rex_copied_c40_runtime_route(uc)
        if route is None:
            self.rex_controller_gate_reason = reason
            self._rex_copied_c40_gate_terminal = terminal
            self._rex_copied_c40_gate_next_instruction = (
                self.instructions + REX_TICK_INTERVAL
            )
            return False
        prior = {field: getattr(self.config, field) for field in (
            *route_fields, "rex_irq_mask", "rex_tick_ms",
            "rex_irq_arm_address",
        )}
        prior_aperture = self._rex_irq_controller_aperture

        def restore() -> None:
            for field, value in prior.items():
                setattr(self.config, field, value)
            self._rex_copied_c40_route = None
            self._rex_irq_controller_aperture = prior_aperture

        self.config.rex_tick_address = int(route["outer_callback"])
        self.config.rex_irq_wrapper_address = int(route["wrapper"])
        self.config.rex_irq_handler_address = int(route["handler"])
        self.config.rex_irq_handler_slot = int(route["handler_slot"])
        self.config.rex_irq_callback_slot = int(route["callback_slot"])
        self.config.rex_irq_status_address = int(route["status"])
        self.config.rex_irq_enable_address = int(route["enable"])
        self.config.rex_irq_arm_address = 0x030006E0
        self.config.rex_irq_mask = int(route["mask"])
        self.config.rex_tick_ms = 5
        self._rex_copied_c40_route = route
        self._rex_irq_controller_aperture = tuple(
            int(value) for value in route["controller_aperture"]
        )
        self._rex_irq_arm_required = True
        if not self._rex_irq_route_valid(uc, stack=True):
            restore()
            self.rex_controller_gate_reason = "runtime-route-validator-rejected"
            self._rex_copied_c40_gate_next_instruction = (
                self.instructions + REX_TICK_INTERVAL
            )
            return False
        begin, end = self._rex_irq_controller_aperture
        hooks: list[int] = []
        try:
            hooks.append(uc.hook_add(
                UC_HOOK_MEM_WRITE, self._rex_irq_status_write,
                begin=begin, end=end - 1,
            ))
            hooks.append(uc.hook_add(
                UC_HOOK_MEM_READ, self._rex_irq_status_read,
                begin=begin, end=end - 1,
            ))
        except UcError:
            for hook in hooks:
                uc.hook_del(hook)
            restore()
            self.rex_controller_gate_reason = "runtime-shadow-hook-failed"
            self._rex_copied_c40_gate_terminal = True
            return False
        self._rex_copied_c40_shadow_hooks = hooks
        self._rex_irq_pending = [0, 0]
        self.rex_next_instruction = self.instructions + REX_TICK_INTERVAL
        self.rex_controller_gate_accepts += 1
        self.rex_controller_gate_reason = None
        self.rex_controller_activation_instruction = self.instructions
        return True

    def _rex_copied_c40_timer_source(self, uc: Uc) -> None:
        """Assert one deterministic 5 ms source for the closed C40 class."""
        if not self._rex_try_copied_c40_route(uc):
            return
        if (not self._rex_irq_armed
                or self.instructions < self.rex_next_instruction
                or self._rex_irq_pending[0] & 0x0200):
            return
        self.rex_next_instruction = self.instructions + REX_TICK_INTERVAL
        self._rex_irq_pending[0] |= 0x0200
        self.rex_ticks += 1
        self.rex_elapsed_ms += 5
        self.rex_controller_pending_assertions += 1

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
        copied_c40 = self._rex_copied_c40_irq_route()
        if copied_c40 is not None:
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
                all(value == copied_c40.get(field)
                    for field, value in route_fields.items())
                and enable == status + 0x14
                and self._rex_firmware_matches(uc, wrapper, 0x20)
                and self._rex_firmware_matches(uc, handler, 2)
                and self._rex_firmware_matches(uc, tick, 0x80)
            )
        elif legacy is None:
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
                if copied_c40 is None:
                    uc.reg_write(UC_ARM_REG_CPSR, (old & ~0xBF) | 0x9F)
                    system_stack = uc.reg_read(UC_ARM_REG_SP)
            finally:
                uc.reg_write(UC_ARM_REG_CPSR, old)
            stacks = ((irq_stack,) if copied_c40 is not None
                      else (irq_stack, system_stack))
            if not all(self._rex_irq_stack_mapped(uc, value)
                       for value in stacks):
                return False
        return True

    def _rex_static_candidate_runtime_route(
            self, uc: Uc,
    ) -> tuple[dict[str, object] | None, str, bool]:
        """Close one static C80 candidate against installed runtime state."""
        candidate = getattr(
            self.config, "rex_static_controller_candidate", None
        )
        if not isinstance(candidate, dict) or not candidate.get("accepted"):
            return None, "static-candidate-unavailable", True
        required = {
            "signature": "static-c80-controller-callback-v1",
            "controller_class":
                "legacy-c80-index1e-delta5-controller-candidate-v1",
            "active": False,
            "vector": 0x18,
            "mask": 0x0200,
            "callback_delta": 5,
            "callback_validation_size": REX_LEGACY_5MS_CALLBACK_SIZE,
        }
        if any(candidate.get(field) != value
               for field, value in required.items()):
            return None, "static-candidate-metadata-invalid", True
        integer_fields = (
            "vector_target", "status", "enable", "mask_table",
            "handler_file_offset", "callback_file_offset",
            "wrapper_file_offset", "handler_slot", "callback_slot",
            "handler_validation_size", "wrapper_validation_size",
        )
        if any(type(candidate.get(field)) is not int
               for field in integer_fields):
            return None, "static-candidate-metadata-invalid", True
        vector_target = int(candidate["vector_target"])
        status = int(candidate["status"])
        enable = int(candidate["enable"])
        handler_slot = int(candidate["handler_slot"])
        callback_slot = int(candidate["callback_slot"])
        handler_size = int(candidate["handler_validation_size"])
        wrapper_size = int(candidate["wrapper_validation_size"])
        callback_size = int(candidate["callback_validation_size"])
        ram_end = self.config.ram_base + self.config.ram_size

        def metadata_tuple(field: str) -> tuple[object, ...]:
            value = candidate.get(field)
            return tuple(value) if isinstance(value, (list, tuple)) else ()

        if (vector_target != self.config.ram_base
                or enable != status + 0x14
                or handler_size <= 0 or wrapper_size <= 0
                or any(address & 3 or not self.config.ram_base <= address
                       <= ram_end - 4
                       for address in (handler_slot, callback_slot))
                or metadata_tuple("status_banks")
                   != (status, status + 4)
                or metadata_tuple("clear_banks")
                   != (status, status + 4)
                or metadata_tuple("controller_write_banks")
                   != (enable, enable + 4)
                or metadata_tuple("controller_aperture")
                   != (status, enable + 6)):
            return None, "static-candidate-metadata-invalid", True

        offsets = {
            "wrapper": int(candidate["wrapper_file_offset"]),
            "handler": int(candidate["handler_file_offset"]),
            "callback": int(candidate["callback_file_offset"]),
        }
        lengths = {
            "wrapper": wrapper_size,
            "handler": handler_size,
            "callback": callback_size,
        }
        expected: dict[str, bytes] = {}
        for name, offset in offsets.items():
            length = lengths[name]
            if not 0 <= offset <= len(self.original_image) - length:
                return None, "static-candidate-source-range-invalid", True
            expected[name] = self.original_image[offset:offset + length]
        try:
            raw_vector = arm_b_word_target(
                struct.unpack("<I", bytes(uc.mem_read(0x18, 4)))[0], 0x18
            )
            if raw_vector != vector_target:
                return None, "runtime-vector-not-installed", False
            wrapper = arm_b_word_target(
                struct.unpack(
                    "<I", bytes(uc.mem_read(vector_target, 4))
                )[0],
                vector_target,
            )
            installed_handler = struct.unpack(
                "<I", bytes(uc.mem_read(handler_slot, 4))
            )[0]
            installed_callback = struct.unpack(
                "<I", bytes(uc.mem_read(callback_slot, 4))
            )[0]
        except UcError:
            return None, "runtime-route-state-unavailable", False
        if wrapper is None or wrapper & 3:
            return None, "runtime-wrapper-not-installed", False
        if not installed_handler & 1:
            return None, "runtime-handler-not-installed", False
        if not installed_callback & 1:
            return None, "runtime-callback-not-installed", False
        handler = installed_handler & ~1
        callback = installed_callback & ~1
        runtime_addresses = {
            "wrapper": wrapper, "handler": handler, "callback": callback,
        }
        try:
            for name, runtime_address in runtime_addresses.items():
                pristine = self._original_runtime_bytes(
                    runtime_address, lengths[name]
                )
                if (pristine != expected[name]
                        or bytes(uc.mem_read(
                            runtime_address, lengths[name]
                        )) != expected[name]):
                    return None, f"runtime-{name}-bytes-mismatch", False
        except UcError:
            return None, "runtime-route-code-unavailable", False
        callback_shape = rex_legacy_5ms_callback_shape_at(
            expected["callback"], 0
        )
        if (callback_shape is None
                or tuple(candidate.get("callback_validation_shape", ()))
                != tuple(callback_shape)):
            return None, "runtime-callback-shape-mismatch", True
        route = {
            "signature": "experimental-static-c80-controller-route-v1",
            "controller_class": "legacy-c80-two-bank-group10-v1",
            "index": 0x1E,
            "status": status,
            "enable": enable,
            "mask": 0x0200,
            "status_banks": (status, status + 4),
            "clear_banks": (status, status + 4),
            "controller_write_banks": (enable, enable + 4),
            "controller_aperture": (status, enable + 6),
            "status_bank_count": 2,
            "group_row_size": 10,
            "vector": 0x18,
            "vector_target": vector_target,
            "wrapper": wrapper,
            "wrapper_validation_size": wrapper_size,
            "handler": handler,
            "handler_validation_size": handler_size,
            "handler_slot": handler_slot,
            "callback_slot": callback_slot,
            "outer_callback": callback,
        }
        if not self._rex_legacy_irq_route_metadata_valid(route):
            return None, "runtime-route-metadata-invalid", True
        return route, "", False

    def _rex_try_static_candidate_route(self, uc: Uc) -> bool:
        """Promote a fully installed candidate without weakening fallback."""
        if getattr(self, "_rex_candidate_route", None) is not None:
            return True
        if self._rex_direct_legacy_irq_route() is not None:
            self.rex_controller_gate_reason = "direct-route-priority"
            return False
        if (getattr(self, "_rex_candidate_gate_terminal", False)
                or self.instructions
                < getattr(self, "_rex_candidate_gate_next_instruction", 0)):
            return False
        candidate = getattr(
            self.config, "rex_static_controller_candidate", None
        )
        if not isinstance(candidate, dict) or not candidate.get("accepted"):
            return False
        if not getattr(
                self.config, "rex_static_controller_experimental", False):
            self.rex_controller_gate_reason = "experimental-opt-in-required"
            return False
        route_fields = (
            "rex_tick_address", "rex_irq_wrapper_address",
            "rex_irq_handler_address", "rex_irq_handler_slot",
            "rex_irq_callback_slot", "rex_irq_status_address",
            "rex_irq_enable_address",
        )
        if (any(getattr(self.config, field, None) is not None
                for field in route_fields)
                or getattr(self.config, "rex_irq_mask", 0)):
            self.rex_controller_gate_reason = "existing-route-fields-priority"
            self._rex_candidate_gate_terminal = True
            return False
        self.rex_controller_gate_attempts += 1
        route, reason, terminal = self._rex_static_candidate_runtime_route(uc)
        if route is None:
            self.rex_controller_gate_reason = reason
            self._rex_candidate_gate_terminal = terminal
            self._rex_candidate_gate_next_instruction = (
                self.instructions + REX_TICK_INTERVAL
            )
            return False

        prior = {
            field: getattr(self.config, field) for field in (
                *route_fields, "rex_irq_mask", "rex_tick_ms",
                "rex_irq_arm_address",
            )
        }
        prior_aperture = self._rex_irq_controller_aperture

        def restore() -> None:
            for field, value in prior.items():
                setattr(self.config, field, value)
            self._rex_candidate_route = None
            self._rex_irq_controller_aperture = prior_aperture

        self.config.rex_tick_address = int(route["outer_callback"])
        self.config.rex_irq_wrapper_address = int(route["wrapper"])
        self.config.rex_irq_handler_address = int(route["handler"])
        self.config.rex_irq_handler_slot = int(route["handler_slot"])
        self.config.rex_irq_callback_slot = int(route["callback_slot"])
        self.config.rex_irq_status_address = int(route["status"])
        self.config.rex_irq_enable_address = int(route["enable"])
        self.config.rex_irq_mask = int(route["mask"])
        self.config.rex_tick_ms = 5
        self.config.rex_irq_arm_address = None
        self._rex_candidate_route = route
        self._rex_irq_controller_aperture = tuple(
            int(value) for value in route["controller_aperture"]
        )
        if not self._rex_irq_route_valid(uc, stack=True):
            restore()
            self.rex_controller_gate_reason = "runtime-route-validator-rejected"
            self._rex_candidate_gate_next_instruction = (
                self.instructions + REX_TICK_INTERVAL
            )
            return False
        begin, end = self._rex_irq_controller_aperture
        hooks: list[int] = []
        try:
            hooks.append(uc.hook_add(
                UC_HOOK_MEM_WRITE, self._rex_irq_status_write,
                begin=begin, end=end - 1,
            ))
            hooks.append(uc.hook_add(
                UC_HOOK_MEM_READ, self._rex_irq_status_read,
                begin=begin, end=end - 1,
            ))
        except UcError:
            for hook in hooks:
                uc.hook_del(hook)
            restore()
            self.rex_controller_gate_reason = "runtime-shadow-hook-failed"
            self._rex_candidate_gate_terminal = True
            return False
        self._rex_candidate_shadow_hooks = hooks
        self._rex_irq_pending = [0, 0]
        self.rex_controller_gate_accepts += 1
        self.rex_controller_gate_reason = None
        self.rex_controller_activation_instruction = self.instructions
        return True

    def _rex_controller_telemetry(self) -> dict[str, object]:
        candidate = getattr(
            self.config, "rex_static_controller_candidate", None
        )
        copied_candidate = getattr(
            self.config, "rex_static_c40_controller_observation", None
        )
        direct = self._rex_direct_legacy_irq_route() is not None
        c80_active = getattr(self, "_rex_candidate_route", None) is not None
        copied_active = self._rex_copied_c40_irq_route() is not None
        active = c80_active or copied_active
        if copied_active:
            status = "active"
        elif (isinstance(copied_candidate, dict)
                and copied_candidate.get("accepted")
                and copied_candidate.get("controller_class")
                == "c40-copied-vector-selector0-delta5-v1"):
            status = (
                "rejected" if self._rex_copied_c40_gate_terminal else "waiting"
            )
        elif active:
            status = "active"
        elif direct:
            status = "direct-route-priority"
        elif isinstance(candidate, dict) and candidate.get("accepted"):
            if not getattr(
                    self.config, "rex_static_controller_experimental", False):
                status = "experimental-disabled"
            else:
                status = (
                    "rejected"
                    if self._rex_candidate_gate_terminal else "waiting"
                )
        elif isinstance(candidate, dict):
            status = "static-rejected"
        else:
            status = "not-detected"
        return {
            "profile": (
                "runtime-c40-copied-vector-selector0-v1"
                if copied_active else
                "experimental-static-c80-controller-route-v1"
                if c80_active else None
            ),
            "status": status,
            "experimental": c80_active,
            "scope": (
                "cross-firmware-closed"
                if copied_active else
                "single-runtime-witness-temporary"
                if isinstance(candidate, dict) and candidate.get("accepted")
                else None
            ),
            "cadence": (
                "deterministic-host-instruction-model"
                if copied_active else
                "host-instruction-interval-assumption" if c80_active else None
            ),
            "gate_attempts": getattr(
                self, "rex_controller_gate_attempts", 0
            ),
            "gate_accepts": getattr(
                self, "rex_controller_gate_accepts", 0
            ),
            "last_reason": getattr(
                self, "rex_controller_gate_reason", None
            ),
            "activation_instruction":
                getattr(self, "rex_controller_activation_instruction", None),
            "pending_assertions": getattr(
                self, "rex_controller_pending_assertions", 0
            ),
            "pending_acks": getattr(
                self, "rex_controller_pending_acks", 0
            ),
            "arm": {
                "required": getattr(self, "_rex_irq_arm_required", False),
                "armed": getattr(self, "_rex_irq_armed", True),
                "writes": getattr(self, "rex_irq_arm_writes", 0),
                "accepts": getattr(self, "rex_irq_arm_accepts", 0),
                "last_value": getattr(self, "rex_irq_arm_last_value", None),
                "instruction": getattr(self, "rex_irq_arm_instruction", None),
            },
        }

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
        if legacy is None:
            self._rex_try_static_candidate_route(uc)
            legacy = self._rex_legacy_irq_route()
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
            if (getattr(self, "_rex_irq_arm_required", False)
                    and not getattr(self, "_rex_irq_armed", False)):
                return
        self.rex_next_instruction = self.instructions + REX_TICK_INTERVAL
        self.rex_ticks += 1
        self.rex_elapsed_ms += self.config.rex_tick_ms
        if self.config.rex_tick_ms == 5:
            if (legacy is not None
                    and legacy is getattr(self, "_rex_candidate_route", None)
                    and not self._rex_irq_pending[0] & self.config.rex_irq_mask):
                self.rex_controller_pending_assertions += 1
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
