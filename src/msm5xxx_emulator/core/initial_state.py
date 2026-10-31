"""CPU-independent reset state for the QEMU guest and display decoder."""
from __future__ import annotations

from ..detection.memory_layout import aligned

REGISTER_NAMES = tuple(f"r{index}" for index in range(13)) + (
    "sp", "lr", "pc", "cpsr",
)


def initial_register_state(config) -> dict[str, int]:
    """Return the register values after board initialization, before execution."""
    ram_end = config.ram_base + config.ram_size
    stack = ram_end - 4
    if config.linker:
        candidate = aligned(config.linker.bss_target + config.linker.bss_size
                            + 0x100000) - 4
        if config.ram_base <= candidate < ram_end:
            stack = candidate
    return {**dict.fromkeys(REGISTER_NAMES, 0), "sp": stack, "cpsr": 0xD3}


class InitialMemory:
    """Sparse, zero-filled reset memory; no execution or CPU interface."""

    def __init__(self):
        self._ranges = []
        self._writes = []

    def map(self, address: int, size: int) -> None:
        self._ranges.append((address, address + size))

    def _check(self, address: int, size: int) -> None:
        if size < 0 or not any(left <= address <= address + size <= right
                               for left, right in self._ranges):
            raise ValueError("read or write outside initial memory")

    def write(self, address: int, data: bytes) -> None:
        self._check(address, len(data))
        self._writes.append((address, bytes(data)))

    def read(self, address: int, size: int) -> bytes:
        self._check(address, size)
        result = bytearray(size)
        for start, data in self._writes:
            left, right = max(address, start), min(address + size, start + len(data))
            if left < right:
                result[left - address:right - address] = data[left - start:right - start]
        return bytes(result)
