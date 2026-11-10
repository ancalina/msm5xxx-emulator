"""UART console ownership and its detector profiles."""

from .legacy_dd import _DD_MASKS
from .legacy_probe import (_CLOCK_SPECS, _FFCC_ROOT, _PROBE_APP, _PROBE_DIVIDE, _PROBE_MEMCPY_44, _PROBE_RESET, _PROBE_SPECS, _PROBE_TEMPLATE,
    _find_previous_uart_console_profile, _probe_shape, _probe_specs, find_legacy_uart_console_profile)
from .legacy_half_ff import (_FF_IRQ_RESTORE, _FF_IRQ_SAVE, _FF_RESET, _FF_SPECS, _FF_THUNK,)
from .legacy_simple import _BYTE_EXTENDED_ROOT, _BYTE_LAYOUTS, _byte_profile_at
from ...arm import thumb_bl_target

def find_uart_console_profile(image, ready_profile=None, *, chipset=None):
    """Resolve the UART-owned evidence and its narrowly scoped admission."""
    profile, reason = find_legacy_uart_console_profile(image, ready_profile)
    if (chipset is not None and profile is not None and profile.get("clock_guard", {}).get("config_diagnostic") is not None and chipset not in ("MSM5100",
        "MSM5105")):
        return None, "console-probe-scope-unclosed"
    return profile, reason

def detection_note(profile, reason, ready_profile=None):
    """Return the existing user-facing note for a UART profile or rejection."""
    if profile is not None:
        return ("bound UART console class: provisional synchronous TX sink, " "empty RX; physical line timing and FIFO depth unverified")
    if (ready_profile is not None or reason.startswith("console-byte-") or reason == "console-protocol-ownership-ambiguous"):
        return f"UART console class rejected: {reason}; native fallback"
    return None

from .projection import (qemu_loaded_uart_console_property, qemu_uart_console_property, requires_loaded_source, permits_tail_padding, resource_windows)

from .configuration import configuration_fields
