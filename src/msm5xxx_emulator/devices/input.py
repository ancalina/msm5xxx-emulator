"""Runtime behavior owned by input."""
from __future__ import annotations

from ..core.constants import HANDSET_KEY_COUNT
from ..core.constants import THUMB_LOW_REGISTERS
from ..detection.input_matrix import LG_RING256
from ..detection.input_matrix import SAMSUNG_RING32
from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_R0
import struct
import logging

LOGGER = logging.getLogger("msm5xxx")
DIRECT_MATRIX_NUMERIC_KEY_EVENTS = dict(zip(range(11, 23), b"123456789*0#"))
DIRECT_MATRIX_SAMSUNG_KEY_EVENTS = {
    0: 0x5B,
    **DIRECT_MATRIX_NUMERIC_KEY_EVENTS,
}


class InputMixin:
    def set_key(self, bit: int, pressed: bool) -> None:
        """Change one physical key bit; firmware owns debounce and hold timing."""
        if not 0 <= bit < HANDSET_KEY_COUNT:
            raise ValueError("key bit has no handset mapping")
        if pressed == (bit in self.held_keys):
            return
        key_start = self.config.key_register
        direct = getattr(self, "direct_input_profile", None)
        position = getattr(self, "direct_input_positions", {}).get(bit)
        if key_start is None and direct is not None:
            if position is None:
                self.input_error = (
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
                self.direct_key_scan_epochs[bit] = self.direct_matrix_scans
                self.key_press_read_epochs[bit] = self.key_read_epoch
            else:
                self.held_keys.remove(bit)
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
        family = profile["event_sink_family"]
        if family == SAMSUNG_RING32:
            key_events = DIRECT_MATRIX_SAMSUNG_KEY_EVENTS
        elif family == LG_RING256:
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

    def _direct_matrix_nibble(self, uc: Uc) -> int | None:
        profile = getattr(self, "direct_input_profile", None)
        if profile is None:
            return None
        if not self.held_keys:
            return int(profile["no_key"])
        bit = next(iter(self.held_keys))
        position = self.direct_input_positions.get(bit)
        if position is None:
            return int(profile["no_key"])
        _event, target_row, column = position
        row_register = THUMB_LOW_REGISTERS[int(profile["row_register"])]
        row = uc.reg_read(row_register) & 0xFF
        return (
            int(profile["single_key_column_sense"][column])
            if row == target_row else int(profile["no_key"])
        )

    def _direct_input_event_observed(
            self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """Confirm the exact scanner argument edge, not another queue caller."""
        profile = self.direct_input_profile
        if profile is None:
            return
        expected_lr = int(profile["event_sink_callsite"]) + 5
        if uc.reg_read(UC_ARM_REG_LR) != expected_lr:
            return
        event = uc.reg_read(UC_ARM_REG_R0) & 0xFF
        self.input_events += 1
        self.direct_matrix_sink_events += 1
        for bit in self.held_keys:
            position = self.direct_input_positions.get(bit)
            if (position is not None and event == position[0]
                    and self.direct_matrix_scans
                    > self.direct_key_scan_epochs.get(
                        bit, self.direct_matrix_scans
                    )):
                self.firmware_key_events += 1
                self.input_error = ""
                break

    def _input_entry_observed(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Record firmware-side keypad producer consumption without injection."""
        self.input_events += 1
        if any(self.key_read_epoch > self.key_press_read_epochs.get(bit,
                                                                      self.key_read_epoch)
               for bit in self.held_keys):
            self.firmware_key_events += 1
            self.input_error = ""
