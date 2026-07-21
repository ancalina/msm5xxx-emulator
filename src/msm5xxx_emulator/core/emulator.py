"""GenericMSMEmulator assembly."""

from ..devices.audio import AudioMixin
from ..devices.display import DisplayMixin
from ..devices.input import InputMixin
from ..devices.storage import StorageMixin
from ..hle import HleMixin
from ..soc import SocMixin

from .lifecycle import LifecycleMixin
from .memory_bus import MemoryBusMixin
from .runtime import RuntimeMixin
from .checkpoint import CheckpointMixin


class GenericMSMEmulator(
    LifecycleMixin, CheckpointMixin, MemoryBusMixin, DisplayMixin, HleMixin,
    StorageMixin, SocMixin, AudioMixin, InputMixin, RuntimeMixin,
):
    """Firmware-first ARMv4T runner; unknown data MMIO pages become zero-backed."""


__all__ = ("GenericMSMEmulator",)
