"""MSM interrupt, timer, and ADC behavior."""

from .adc import AdcMixin
from .rex import RexMixin


class SocMixin(RexMixin, AdcMixin):
    """Complete SoC peripheral behavior."""


__all__ = ("SocMixin",)
