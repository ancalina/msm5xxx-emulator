"""Evidence-gated high-level emulation helpers."""

from .bootstrap import BootstrapHleMixin
from .common import HleCommonMixin
from .device_calls import DeviceCallsHleMixin
from .memory_ops import MemoryOpsHleMixin


class HleMixin(
    HleCommonMixin, BootstrapHleMixin, MemoryOpsHleMixin, DeviceCallsHleMixin,
):
    """Complete evidence-gated HLE behavior."""


__all__ = ("HleMixin",)
