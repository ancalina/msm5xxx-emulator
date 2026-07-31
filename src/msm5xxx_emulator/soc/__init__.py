"""MSM interrupt, timer, and ADC behavior."""

from .adc import AdcMixin
from .rex import RexMixin
from .sbi import SbiMixin


class SocMixin(RexMixin, AdcMixin, SbiMixin):
    """Complete SoC peripheral behavior."""


__all__ = ("SocMixin",)
