"""CPU, memory map, MMIO, and emulator session implementation."""

from .config import FirmwareConfig
from .errors import HostBackendFault
from ..detection.firmware import detect

__all__ = ("FirmwareConfig", "GenericMSMEmulator", "HostBackendFault", "detect")


def __getattr__(name):
    if name == "GenericMSMEmulator":
        from .emulator import GenericMSMEmulator
        return GenericMSMEmulator
    raise AttributeError(name)
