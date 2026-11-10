"""Public detection and configuration API for MSM5xxx emulation."""

from .core.config import FirmwareConfig
import msm5xxx_emulator.detection.plan as boot_plan
from msm5xxx_emulator.detection.registry import device_domain
detect = boot_plan.detect

__all__ = ("FirmwareConfig", "detect")
