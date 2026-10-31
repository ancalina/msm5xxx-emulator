"""CPU-free persistent storage devices."""

from .eeprom import EepromMixin
from .nand import NandMixin
from .nor import NORFlash, NorStorageMixin


class StorageMixin(NorStorageMixin, EepromMixin, NandMixin):
    """Complete storage-device behavior."""


__all__ = ("NORFlash", "StorageMixin")
