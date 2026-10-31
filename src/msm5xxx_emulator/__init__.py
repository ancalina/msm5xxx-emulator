"""Public detection and configuration API for MSM5xxx emulation."""

from .core.config import FirmwareConfig
from .detection.firmware import detect

__all__ = ("FirmwareConfig", "detect")
