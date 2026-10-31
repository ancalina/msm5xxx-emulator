"""CPU-free device configuration and firmware detection."""

from .config import FirmwareConfig
from ..detection.firmware import detect

__all__ = ("FirmwareConfig", "detect")
