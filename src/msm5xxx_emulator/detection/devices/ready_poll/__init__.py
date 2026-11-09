"""Evidence and machine projection for ready-poll devices."""
from .helpers import _THUMB_BL, _UART_RX_EMPTY_READ, thumb_bl_target, thumb_literal_value
from .semantic import _called_mmio_candidates, _find_control_ready_poll_profile
from .uart_profiles import _find_control_uart_rx_empty_profile
from .display import (
    find_ready_poll_profile, find_arm_tx_empty_ready_poll_profile,
)
from .projection import (
    ready_poll_property, ready_poll_plan, ready_poll_runtime_plan,
    runtime_ready_poll_property,
)


def capture_profile(image: bytes, *, unresolved_startup_mapping=False):
    profile = find_ready_poll_profile(image)
    if profile is not None and unresolved_startup_mapping:
        return None, ("pulse-ready profile unverified for reset-linked SDRAM class; "
                      "native device behavior retained",)
    return profile, (("exact firmware ready-poll class detected",) if profile is not None else ())


__all__ = [
    "capture_profile",
    "find_ready_poll_profile", "find_arm_tx_empty_ready_poll_profile",
    "ready_poll_property", "ready_poll_plan", "ready_poll_runtime_plan",
    "runtime_ready_poll_property", "_THUMB_BL", "_UART_RX_EMPTY_READ",
    "_called_mmio_candidates", "_find_control_ready_poll_profile",
    "_find_control_uart_rx_empty_profile", "thumb_bl_target", "thumb_literal_value",
]
