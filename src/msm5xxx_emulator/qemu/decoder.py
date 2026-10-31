"""Device and display decoding for QEMU, without a second CPU."""
from __future__ import annotations

from ..core.initial_state import InitialMemory
from ..core.device_state import DeviceStateMixin
from ..devices.audio import AudioMixin
from ..devices.display import DisplayMixin
from ..devices.input import InputMixin
from ..devices.storage import StorageMixin


class QemuDecoder(DeviceStateMixin, DisplayMixin, StorageMixin,
                  AudioMixin, InputMixin):
    """Decode device writes and retain CPU-free device state."""

    # LCD callbacks retain their existing signature; there is no CPU context.
    uc = None

    def _initialize_memory(self, config, secondary_base, ram_end, ram_seed):
        self.initial_memory = InitialMemory()
        self._map_and_seed_memory(
            config, secondary_base, ram_seed,
            self.initial_memory.map, self.initial_memory.write,
            self.initial_memory.read, (ValueError,),
        )

    def _read_framebuffer_memory(self, address: int, size: int) -> bytes:
        return self.initial_memory.read(address, size)
