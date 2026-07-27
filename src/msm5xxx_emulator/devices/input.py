"""Runtime behavior owned by input."""
from __future__ import annotations

from collections import Counter
from collections import deque
from ..core.config import FirmwareConfig
from ..core.constants import HANDSET_KEY_COUNT
from ..core.constants import THUMB_LOW_REGISTERS
from ..detection.input import detect_input_profile
from ..detection.input_descriptor import resolve_lg_descriptor_input
from ..detection.input_descriptor import LG_DESCRIPTOR_RAW
from ..detection.input_matrix import LG_RING256
from ..detection.input_matrix import SAMSUNG_RING32
from ..detection.input_matrix import resolve_direct_matrix_input
from ..detection.rex import find_rex_legacy_5ms_irq_route
from ..detection.rex import find_rex_legacy_5ms_timer_bridge
from unicorn import UC_HOOK_CODE
from unicorn import Uc
from unicorn import UcError
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_R0
import struct
import logging

LOGGER = logging.getLogger("msm5xxx")
DIRECT_MATRIX_NUMERIC_KEY_EVENTS = dict(zip(range(11, 23), b"123456789*0#"))
DIRECT_MATRIX_SAMSUNG_KEY_EVENTS = {
    # Native X7509 key switch names these table events; X150/X350 runtime
    # confirms each mapped control's shared scanner-to-queue path.
    0: 0x5B,   # MENU
    1: 0x54,   # UP
    2: 0x52,   # CLR / cancel
    3: 0x50,   # SEND / call
    4: 0x65,   # LEFT
    6: 0x66,   # RIGHT
    9: 0x55,   # DOWN
    **DIRECT_MATRIX_NUMERIC_KEY_EVENTS,
}


class InputMixin:
    def _init_input_state(self, config: FirmwareConfig) -> None:
        self.held_keys: set[int] = set()
        self.key_baselines: dict[int, int] = {}
        self.key_press_read_epochs: dict[int, int] = {}
        self.key_read_epoch = 0
        self.key_register_reads = 0
        self.key_register_read_pcs: Counter[int] = Counter()
        self.input_profile = detect_input_profile(self.image, config.load_address)
        if config.key_register is None:
            (
                self.direct_input_profile,
                self.direct_input_detection,
                self.direct_input_rejections,
            ) = resolve_direct_matrix_input(self.image, config.load_address)
            if self.direct_input_profile is None:
                descriptor, status, rejected = resolve_lg_descriptor_input(
                    self.image
                )
                self.direct_input_rejections.extend(rejected)
                if descriptor is not None:
                    overlays = config.overlays

                    def file_to_runtime(position: int) -> int:
                        for overlay in overlays:
                            if (overlay.source <= position
                                    < overlay.source + overlay.size):
                                return (
                                    overlay.target + position - overlay.source
                                )
                        layout = config.linker
                        if (layout is not None
                                and layout.data_source <= position
                                < layout.data_source + layout.data_size):
                            return (
                                layout.data_target
                                + position - layout.data_source
                            )
                        return config.load_address + position

                    def runtime_to_file(address: int) -> int | None:
                        for overlay in overlays:
                            if (overlay.target <= address
                                    < overlay.target + overlay.size):
                                return (
                                    overlay.source + address - overlay.target
                                )
                        layout = config.linker
                        if (layout is not None
                                and layout.data_target <= address
                                < layout.data_target + layout.data_size):
                            return (
                                layout.data_source
                                + address - layout.data_target
                            )
                        position = address - config.load_address
                        return position if 0 <= position < len(self.image) else None

                    bridge = find_rex_legacy_5ms_timer_bridge(
                        self.image, int(descriptor["function"]),
                        file_to_runtime, runtime_to_file,
                    )
                    route = (find_rex_legacy_5ms_irq_route(
                        self.image, bridge, file_to_runtime, runtime_to_file,
                    ) if bridge is not None else None)
                    reasons = []
                    if config.rex_idle_address is None:
                        reasons.append("rex-idle-address-missing")
                    if (descriptor.get("row_state_evidence") is None
                            and descriptor.get("row_register_evidence") is None):
                        reasons.append("row-source-unclosed")
                    global_senses = descriptor.get("global_sense_sites", ())
                    row_senses = descriptor.get("row_sense_sites", ())
                    if (len(global_senses) != 1 or not row_senses
                            or descriptor["sense_site"] not in row_senses):
                        reasons.append("sense-roles-unclosed")
                    if bridge is None:
                        reasons.append("legacy-timer-bridge-unclosed")
                    elif bridge["scanner"] != file_to_runtime(
                            int(descriptor["function"])):
                        reasons.append("scanner-timer-callback-mismatch")
                    elif route is None:
                        reasons.append("legacy-irq-route-unclosed")
                    elif route.get("controller_class") not in {
                            "legacy-c80-two-bank-group10-v1",
                            "legacy-c80-three-bank-group14-v1",
                    }:
                        reasons.append(
                            "legacy-irq-controller-class-unverified"
                        )
                    elif not self._rex_legacy_irq_route_metadata_valid(route):
                        reasons.append(
                            "legacy-irq-controller-class-unverified"
                        )
                    elif route.get("outer_callback") != bridge["outer_callback"]:
                        reasons.append("legacy-timer-route-mismatch")
                    elif (route["vector_target"] != config.ram_base
                          or not all(
                              config.ram_base <= int(route[field])
                              <= config.ram_base + config.ram_size - 4
                              for field in ("handler_slot", "callback_slot"))):
                        reasons.append("legacy-irq-route-ram-unclosed")
                    if reasons:
                        self.direct_input_rejections.append({
                            "function": descriptor["function"],
                            "grammar_fingerprint": descriptor[
                                "grammar_fingerprint"
                            ],
                            "reasons": reasons,
                        })
                        status = "rejected"
                    else:
                        scalar_fields = [
                            "function", "prologue", "sense_site",
                            "raw_enqueue", "raw_enqueue_callsite",
                        ]
                        scalar_fields.extend(
                            field for field in (
                                "raw_enqueue_store", "raw_dequeue",
                                "raw_dequeue_return", "raw_task_entry",
                            ) if descriptor.get(field) is not None
                        )
                        if descriptor.get("row_state_evidence") is not None:
                            scalar_fields.append("row_state_site")
                        list_fields = (
                            "sense_sites", "global_sense_sites",
                            "row_sense_sites", "raw_enqueue_callsites",
                        )
                        descriptor = {
                            **descriptor,
                            **{
                                field: file_to_runtime(int(descriptor[field]))
                                for field in scalar_fields
                            },
                            **{
                                field: [
                                    file_to_runtime(int(position))
                                    for position in descriptor[field]
                                ]
                                for field in list_fields
                            },
                            "register": int(
                                descriptor["absolute_roles"]["sense"]
                            ),
                            "event_sink_family": descriptor["family"],
                            "event_sink_validation":
                                "validated-raw-enqueue-callsites",
                            "timer_bridge": {**bridge, "irq_route": route},
                        }
                        descriptor["event_sink"] = descriptor["raw_enqueue"]
                        descriptor["event_sink_callsite"] = descriptor[
                            "raw_enqueue_callsite"
                        ]
                        descriptor["event_sink_callsites"] = descriptor[
                            "raw_enqueue_callsites"
                        ]
                        self.direct_input_profile = descriptor
                        config.rex_tick_address = int(bridge["outer_callback"])
                        config.rex_tick_ms = 5
                        config.rex_irq_wrapper_address = int(route["wrapper"])
                        config.rex_irq_handler_address = int(route["handler"])
                        config.rex_irq_handler_slot = int(route["handler_slot"])
                        config.rex_irq_callback_slot = int(route["callback_slot"])
                        config.rex_irq_status_address = int(route["status"])
                        config.rex_irq_enable_address = int(route["enable"])
                        config.rex_irq_mask = int(route["mask"])
                        config.rex_irq_arm_address = None
                        self._rex_irq_pending = [0] * int(
                            route["status_bank_count"]
                        )
                        self._rex_irq_controller_aperture = tuple(
                            int(value) for value in route["controller_aperture"]
                        )
                        status = "accepted"
                if (status != "not-found"
                        or self.direct_input_detection == "not-found"):
                    self.direct_input_detection = status
        else:
            self.direct_input_profile = None
            self.direct_input_detection = "explicit-key-register-override"
            self.direct_input_rejections = []
        self.direct_input_positions = self._direct_matrix_positions(
            self.direct_input_profile
        )
        self.direct_key_positions: dict[int, tuple[int, int, int]] = {}
        self.direct_key_scan_epochs: dict[int, int] = {}
        self.direct_matrix_scans = 0
        self.direct_matrix_active_reads = 0
        self.direct_matrix_sink_events = 0
        self.direct_matrix_raw_enqueue_events = 0
        self.direct_matrix_dequeue_events = 0
        self.direct_matrix_task_consumer_events = 0
        self._direct_matrix_pending_events: deque[int] = deque()
        self._direct_matrix_pending_dequeue: int | None = None
        self._direct_matrix_raw_enqueue_marker: int | None = None
        self.input_error = ""
        self.input_events = 0
        self.firmware_key_events = 0
        if self.direct_input_profile is not None:
            self.uc.hook_add(
                UC_HOOK_CODE,
                self._direct_input_event_observed,
                begin=int(self.direct_input_profile["event_sink"]),
                end=int(self.direct_input_profile["event_sink"]),
            )
            queue_fields = (
                "raw_ring", "raw_ring_capacity", "raw_enqueue_store",
                "raw_enqueue_register", "raw_dequeue",
                "raw_dequeue_return", "raw_task_entry", "raw_task_register",
                "raw_consumer_evidence",
            )
            if all(self.direct_input_profile.get(field) is not None
                   for field in queue_fields):
                profile = self.direct_input_profile
                self.uc.hook_add(
                    UC_HOOK_CODE, self._direct_raw_enqueue_store_observed,
                    begin=int(profile["raw_enqueue_store"]),
                    end=int(profile["raw_enqueue_store"]),
                )
                self.uc.hook_add(
                    UC_HOOK_CODE, self._direct_raw_dequeue_return_observed,
                    begin=int(profile["raw_dequeue_return"]),
                    end=int(profile["raw_dequeue_return"]),
                )
                self.uc.hook_add(
                    UC_HOOK_CODE, self._direct_raw_task_observed,
                    begin=int(profile["raw_task_entry"]),
                    end=int(profile["raw_task_entry"]),
                )
        elif self.input_profile is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._input_entry_observed,
                             begin=self.input_profile[1], end=self.input_profile[1])


    def can_set_key(self, bit: int, event_code: int | None = None) -> bool:
        """Report whether one GUI key can use an evidenced physical path."""
        if not 0 <= bit < HANDSET_KEY_COUNT:
            return False
        if self.config.key_register is not None:
            return event_code is None
        return self._direct_matrix_position(bit, event_code) is not None

    def set_key(self, bit: int, pressed: bool,
                event_code: int | None = None) -> None:
        """Change one physical key bit; firmware owns debounce and hold timing."""
        if not 0 <= bit < HANDSET_KEY_COUNT:
            raise ValueError("key bit has no handset mapping")
        if pressed == (bit in self.held_keys):
            return
        key_start = self.config.key_register
        direct = getattr(self, "direct_input_profile", None)
        position = (
            self._direct_matrix_position(bit, event_code)
            if pressed else
            getattr(self, "direct_key_positions", {}).get(bit)
        )
        if key_start is None and direct is not None:
            if position is None:
                self.input_error = (
                    f"manual matrix event 0x{event_code:02X} is absent or ambiguous"
                    if event_code is not None else
                    "automatic matrix detected; this key semantic is not proven"
                )
                return
            if pressed and self.held_keys:
                self.input_error = (
                    "automatic matrix supports one evidenced key at a time"
                )
                return
            if pressed:
                self.held_keys.add(bit)
                self.direct_key_positions[bit] = position
                self.direct_key_scan_epochs[bit] = self.direct_matrix_scans
                self.key_press_read_epochs[bit] = self.key_read_epoch
            else:
                self.held_keys.remove(bit)
                self.direct_key_positions.pop(bit, None)
                self.direct_key_scan_epochs.pop(bit, None)
                self.key_press_read_epochs.pop(bit, None)
            self.input_error = ""
            LOGGER.info(
                "matrix key bit=%d event=0x%02X row=%d column=%d pressed=%s",
                bit, position[0], position[1], position[2], pressed,
            )
            return
        if key_start is None:
            self.input_error = (
                "automatic keypad transport not detected; "
                "physical register override required"
            )
            return
        for address, size in tuple(self.ready_bits):
            if max(address, key_start) < min(address + size, key_start + 4):
                del self.ready_bits[(address, size)]
        value = int.from_bytes(self.uc.mem_read(key_start, 4),
                               "little")
        if self.input_profile is not None:
            family = "LG" if self.input_profile[0] == "lg-decoded" else "Samsung"
            self.input_error = (
                f"{family} keypad queue candidate not observed while key held; "
                "physical register only"
            )
        mask = 1 << bit
        if pressed:
            self.held_keys.add(bit)
            self.key_baselines[bit] = value & mask
            self.key_press_read_epochs[bit] = self.key_read_epoch
            active = not self.config.key_active_low
            value = value | mask if active else value & ~mask
        else:
            self.held_keys.remove(bit)
            baseline = self.key_baselines.pop(bit)
            self.key_press_read_epochs.pop(bit, None)
            value = value & ~mask | baseline
        self.uc.mem_write(key_start, struct.pack("<I", value))
        LOGGER.info("key bit=%d pressed=%s register=0x%08X value=0x%08X",
                    bit, pressed, key_start, value)

    @staticmethod
    def _direct_matrix_positions(
            profile: dict[str, object] | None) -> dict[int, tuple[int, int, int]]:
        if profile is None:
            return {}
        events = list(profile["event_codes"])
        rows = int(profile["rows"])
        family = profile.get("event_sink_family", profile.get("family"))
        if family == SAMSUNG_RING32:
            key_events = DIRECT_MATRIX_SAMSUNG_KEY_EVENTS
        elif family in (LG_RING256, LG_DESCRIPTOR_RAW):
            key_events = DIRECT_MATRIX_NUMERIC_KEY_EVENTS
        else:
            return {}
        result: dict[int, tuple[int, int, int]] = {}
        for bit, event in key_events.items():
            matches = [index for index, value in enumerate(events)
                       if value == event]
            if len(matches) == 1:
                index = matches[0]
                result[bit] = event, index % rows, index // rows
        return result if len(result) == len(key_events) else {}

    def _direct_matrix_position(
            self, bit: int, event_code: int | None
    ) -> tuple[int, int, int] | None:
        if event_code is None:
            return getattr(self, "direct_input_positions", {}).get(bit)
        profile = getattr(self, "direct_input_profile", None)
        if profile is None or not 0 <= event_code <= 0xFF:
            return None
        events = list(profile["event_codes"])
        matches = [index for index, value in enumerate(events)
                   if value == event_code]
        if len(matches) != 1:
            return None
        rows = int(profile["rows"])
        columns = int(profile["columns"])
        index = matches[0]
        row, column = index % rows, index // rows
        if row >= rows or column >= columns:
            return None
        senses = list(profile["single_key_column_sense"])
        return ((event_code, row, column)
                if column < len(senses) else None)

    def _direct_matrix_nibble(self, uc: Uc) -> int | None:
        profile = getattr(self, "direct_input_profile", None)
        if profile is None:
            return None
        if not self.held_keys:
            return int(profile["no_key"])
        bit = next(iter(self.held_keys))
        position = self._active_direct_matrix_position(bit)
        if position is None:
            return int(profile["no_key"])
        _event, target_row, column = position
        row_register = THUMB_LOW_REGISTERS[int(profile["row_register"])]
        row = uc.reg_read(row_register) & 0xFF
        return (
            int(profile["single_key_column_sense"][column])
            if row == target_row else int(profile["no_key"])
        )

    def _active_direct_matrix_position(
            self, bit: int
    ) -> tuple[int, int, int] | None:
        return getattr(self, "direct_key_positions", {}).get(
            bit, self.direct_input_positions.get(bit)
        )

    def _descriptor_matrix_sense(self, uc: Uc, pc: int) -> int | None:
        profile = getattr(self, "direct_input_profile", None)
        if profile is None or profile.get("family") != LG_DESCRIPTOR_RAW:
            return None
        global_sites = {
            int(site) + 2 for site in profile["global_sense_sites"]
        }
        row_sites = {
            int(site) + 2 for site in profile["row_sense_sites"]
        }
        if pc not in global_sites | row_sites:
            return None
        if not self.held_keys:
            return int(profile["no_key"])
        bit = next(iter(self.held_keys))
        position = self._active_direct_matrix_position(bit)
        if position is None:
            return int(profile["no_key"])
        _event, target_row, column = position
        if pc in row_sites:
            if profile.get("row_state_evidence") is not None:
                try:
                    index = bytes(uc.mem_read(
                        int(profile["row_state_address"])
                        + int(profile["row_state_offset"]), 1
                    ))[0]
                except (KeyError, UcError):
                    return int(profile["no_key"])
            else:
                row_register = profile.get("row_register")
                if (row_register is None
                        or profile.get("row_register_evidence") is None):
                    return int(profile["no_key"])
                index = uc.reg_read(
                    THUMB_LOW_REGISTERS[int(row_register)]
                ) & 0xFF
            order = tuple(int(value) for value in profile["row_order"])
            if index >= len(order) or order[index] != target_row:
                return int(profile["no_key"])
        return int(profile["single_key_column_sense"][column])

    def _direct_input_event_observed(
            self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """Confirm the exact scanner argument edge, not another queue caller."""
        self._direct_matrix_raw_enqueue_marker = None
        profile = self.direct_input_profile
        if profile is None:
            return
        callsites = profile.get(
            "event_sink_callsites", (profile["event_sink_callsite"],)
        )
        if uc.reg_read(UC_ARM_REG_LR) not in {
                int(callsite) + 5 for callsite in callsites}:
            return
        event = uc.reg_read(UC_ARM_REG_R0) & 0xFF
        self._direct_matrix_raw_enqueue_marker = event
        self.input_events += 1
        self.direct_matrix_sink_events += 1
        for bit in self.held_keys:
            position = self._active_direct_matrix_position(bit)
            if (position is not None and event == position[0]
                    and self.direct_matrix_scans
                    > self.direct_key_scan_epochs.get(
                        bit, self.direct_matrix_scans
                    )):
                self.firmware_key_events += 1
                self.input_error = ""
                break

    def _direct_raw_enqueue_store_observed(
            self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """Observe a validated raw ring store; never change guest state."""
        marker = self._direct_matrix_raw_enqueue_marker
        self._direct_matrix_raw_enqueue_marker = None
        profile = self.direct_input_profile
        if marker is None or profile is None:
            return
        register = THUMB_LOW_REGISTERS[int(profile["raw_enqueue_register"])]
        if (uc.reg_read(register) & 0xFF) != marker:
            return
        pending = self._direct_matrix_pending_events
        if len(pending) >= int(profile["raw_ring_capacity"]):
            return
        pending.append(marker)
        self.direct_matrix_raw_enqueue_events += 1

    def _direct_raw_dequeue_return_observed(
            self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """Observe only FIFO-head dequeue returns from the proven queue ABI."""
        pending = self._direct_matrix_pending_events
        stale = self._direct_matrix_pending_dequeue
        if stale is not None:
            if pending and pending[0] == stale:
                pending.popleft()
            self._direct_matrix_pending_dequeue = None
        if not pending:
            return
        event = uc.reg_read(UC_ARM_REG_R0) & 0xFF
        if event != pending[0]:
            return
        self._direct_matrix_pending_dequeue = event
        self.direct_matrix_dequeue_events += 1

    def _direct_raw_task_observed(
            self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """Observe task receipt of an already validated dequeue event."""
        event = self._direct_matrix_pending_dequeue
        profile = self.direct_input_profile
        if event is None or profile is None:
            return
        register = THUMB_LOW_REGISTERS[int(profile["raw_task_register"])]
        if (uc.reg_read(register) & 0xFF) != event:
            pending = self._direct_matrix_pending_events
            if pending and pending[0] == event:
                pending.popleft()
            self._direct_matrix_pending_dequeue = None
            return
        pending = self._direct_matrix_pending_events
        if not pending or pending[0] != event:
            return
        pending.popleft()
        self._direct_matrix_pending_dequeue = None
        self.direct_matrix_task_consumer_events += 1

    def _input_entry_observed(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Record firmware-side keypad producer consumption without injection."""
        self.input_events += 1
        if any(self.key_read_epoch > self.key_press_read_epochs.get(bit,
                                                                      self.key_read_epoch)
               for bit in self.held_keys):
            self.firmware_key_events += 1
            self.input_error = ""
