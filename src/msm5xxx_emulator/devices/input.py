"""Runtime behavior owned by input."""
from __future__ import annotations

from ..core.constants import HANDSET_KEY_COUNT
from unicorn import Uc
import struct
import logging

LOGGER = logging.getLogger("msm5xxx")


class InputMixin:
    def set_key(self, bit: int, pressed: bool) -> None:
        """Change one physical key bit; firmware owns debounce and hold timing."""
        if not 0 <= bit < HANDSET_KEY_COUNT:
            raise ValueError("key bit has no handset mapping")
        if pressed == (bit in self.held_keys):
            return
        key_start = self.config.key_register
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

    def _input_entry_observed(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Record firmware-side keypad producer consumption without injection."""
        self.input_events += 1
        if any(self.key_read_epoch > self.key_press_read_epochs.get(bit,
                                                                      self.key_read_epoch)
               for bit in self.held_keys):
            self.firmware_key_events += 1
            self.input_error = ""
