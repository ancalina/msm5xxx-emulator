"""Closed boot-time instruction evidence owned by this domain."""
from __future__ import annotations
import re
import struct
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.signatures import find_all

OPTIONAL_RAM_PROBE_SIGNATURE = bytes.fromhex("0c480d4940080968400040180188aa22028002881206120e" "aa2a06d15522028002881206120e552a01d0002070470180" "01207047")
OPTIONAL_RAM_CALLER_PATTERN = bytes.fromhex("f0b500250e4c0f4e0020256030602f1c0320c0052060" "00000000" "002802d1" "00000000" "30603068002800d12760ff300030c069"
    "00000000" "2571f0bc08bc1847")
OPTIONAL_RAM_CALLER_WILDCARDS = frozenset((*range(0x16, 0x1A), *range(0x1E, 0x22), 0x2E, *range(0x32, 0x36),))
REGISTER_RAMP_PREFIX = bytes.fromhex("32234b439d1822237b43341ceb1a9b1100d41c1c0f4f3c80" "32234b4332389b189b1101d41c1c00e0341c2404240c01e0")
MEMORY_CLEAR_LOOP_SIGNATURE = bytes.fromhex("b4420dd202e0211d0c1cf9e700212160a103f8d1")

# ARM ADS emits this 128-byte unrolled BSS loop in several later Samsung BSPs.
# The complete tail is validated dynamically before HLE is applied.
MEMORY_CLEAR_128_SIGNATURE = bytes.fromhex("20606060a060e06020616061a061e061" "20626062a062e06220636063a063e063")
MEMORY_COPY_LOOP_SIGNATURE = bytes.fromhex("b44208d204e0291d0d1c211d0c1cf7e729682160f7e7")

# ARM ADS bootstrap clear loop.  HLE stops at each native watchdog boundary;
# the firmware still performs every MMIO strobe and final tail comparison.
ARM_MEMORY_CLEAR_CHUNK_SIGNATURE = bytes.fromhex("003041e0200053e30a00003aa332a0e1ff3ad3e30100000a" "c41fa0e8f7ffffeaa4409fe50150a0e3005084e50050a0e3"
    "005084e5f7ffffea010050e104208034fcffff3a")
ARM_MEMORY_CLEAR_STROBE_PERIOD = 0x20000

def absent_optional_ram_probe_addresses(image: bytes, load_address: int, ram_base: int, ram_size: int) -> list[int]:
    """Find cross-checked probes for an absent expansion bank beyond RAM."""
    if ram_base + ram_size != 0x01800000:
        return []
    probes: set[int] = set()
    for caller in find_all(image, OPTIONAL_RAM_CALLER_PATTERN[:0x16]):
        if caller & 1 or caller + len(OPTIONAL_RAM_CALLER_PATTERN) > len(image):
            continue
        candidate = image[caller:caller + len(OPTIONAL_RAM_CALLER_PATTERN)]
        if any(index not in OPTIONAL_RAM_CALLER_WILDCARDS and value != OPTIONAL_RAM_CALLER_PATTERN[index] for index, value in enumerate(candidate)):
            continue
        if candidate[0x2E] not in (0x01, 0x81):
            continue
        status, object_global = struct.unpack_from("<2I", image, caller + 0x40)
        probe = facts_for(image).thumb_call_target(caller + 0x16)
        if (status == object_global or probe is None or image[probe:probe + len(OPTIONAL_RAM_PROBE_SIGNATURE)] != OPTIONAL_RAM_PROBE_SIGNATURE or probe + 0x3C >
            len(image) or struct.unpack_from("<I", image, probe + 0x34)[0] != 0x007FFFDE or struct.unpack_from("<I", image, probe + 0x38)[0] != status or
            facts_for(image).thumb_call_target(caller + 0x1E) is None or facts_for(image).thumb_call_target(caller + 0x32) is None):
            continue
        probes.add(load_address + probe)
    return sorted(probes)
