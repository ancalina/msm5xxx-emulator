"""Public API for MSM5xxx emulator."""

from .core.config import FirmwareConfig
from .core.emulator import GenericMSMEmulator
from .core.errors import HostBackendFault
from .detection.firmware import detect

__all__ = ("FirmwareConfig", "GenericMSMEmulator", "HostBackendFault", "detect")
