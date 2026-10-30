"""Public API for MSM5xxx emulator."""

from .core.config import FirmwareConfig
from .core.errors import HostBackendFault
from .detection.firmware import detect

__all__ = ("FirmwareConfig", "GenericMSMEmulator", "HostBackendFault", "detect")


def __getattr__(name):
    if name == "GenericMSMEmulator":
        from .core.emulator import GenericMSMEmulator
        return GenericMSMEmulator
    raise AttributeError(name)
