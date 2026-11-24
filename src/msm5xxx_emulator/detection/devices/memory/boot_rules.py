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


def has_boot_event_control_reset(image: bytes) -> bool:
    """Resolve the reset sequence that initializes the two control banks."""
    if len(image) < 4:
        return False
    vector = struct.unpack_from('<I', image)[0]
    if vector & 0xff000000 != 0xea000000:
        return False
    displacement = (vector & 0xffffff) << 2
    if displacement & 0x02000000:
        displacement -= 0x04000000
    entry = 8 + displacement
    if entry < 0 or entry + 36 > min(len(image), 0x10000):
        return False
    words = struct.unpack_from('<9I', image, entry)
    if (words[0] & 0xfffff000 != 0xe59f0000 or
            words[3] & 0xfffff000 != 0xe59f0000 or
            words[1:3] != (0xe3a02000, 0xe5802000) or
            words[4:] != (0xe3a01008, 0xe1c010b0, 0xe3a00458,
                          0xe3a01008, 0xe1c010b0)):
        return False
    literals = (entry + 8 + (words[0] & 0xfff),
                entry + 20 + (words[3] & 0xfff))
    return all(0 <= at <= len(image) - 4 for at in literals) and tuple(
        struct.unpack_from('<I', image, at)[0] for at in literals
    ) == (0x80001600, 0x58000008)


def callback_control_address(image: bytes) -> int | None:
    """Find a control write surrounding a BLX constructor loop."""
    # shortcut: only early initialization is scanned; upgrade when later call paths are linked to reset.
    limit = min(len(image), 0x20000)
    prefix = bytes.fromhex('d3f021e3')
    position = image.find(prefix, 0, limit)
    found = set()
    while position >= 0:
        if not position & 3 and position + 88 <= limit:
            words = struct.unpack_from('<22I', image, position)
            fixed = {2: 0xe3a00003, 3: 0xe5810000, 6: 0xe4940004,
                     7: 0xe3500000, 8: 0x0a000009, 9: 0xe321f0d2,
                     10: 0xe1a0e004, 11: 0xe321f0d3, 12: 0xe12fff30,
                     13: 0xe3500000, 15: 0xe321f0d2, 16: 0xe1a0400e,
                     17: 0xe321f0d3, 18: 0xeafffff2, 20: 0xe3a00000,
                     21: 0xe5810000}
            if (all(words[index] == value for index, value in fixed.items()) and
                    words[1] & 0xfffff000 == 0xe59f1000 and
                    words[19] & 0xfffff000 == 0xe59f1000 and
                    words[4] & 0xfffff000 == 0xe59fd000 and
                    words[5] & 0xfffff000 == 0xe59f4000 and
                    words[14] & 0xff000000 == 0x1a000000):
                refs = (position + 12 + (words[1] & 0xfff),
                        position + 84 + (words[19] & 0xfff))
                if all(at <= len(image) - 4 for at in refs):
                    addresses = tuple(struct.unpack_from('<I', image, at)[0] for at in refs)
                    if addresses[0] == addresses[1] and addresses[0] in (0x60000240, 0x80000320):
                        found.add(addresses[0])
        position = image.find(prefix, position + 1, limit)
    return next(iter(found)) if len(found) == 1 else None


def _event_500_sequence(image: bytes, entry: int, stack: int = 0xffff2000) -> bool:
    if entry < 0 or entry + 48 > len(image):
        return False
    words = struct.unpack_from('<12I', image, entry)
    fixed = {1: 0xe1a0d000, 3: 0xe3a02000, 4: 0xe5802000,
             6: 0xe5802000, 8: 0xe3a02f40, 9: 0xe5802000,
             10: 0xe3a02000, 11: 0xe5802000}
    if not all(words[i] == value for i, value in fixed.items()):
        return False
    for index, value in ((0, stack), (2, 0x80000500),
                         (5, 0x80000504), (7, 0x8000050c)):
        instruction = words[index]
        literal = entry + index * 4 + 8 + (instruction & 0xfff)
        if (instruction & 0xfffff000 != 0xe59f0000 or literal > len(image) - 4 or
                struct.unpack_from('<I', image, literal)[0] != value):
            return False
    return True


def has_boot_event_500_reset(image: bytes) -> bool:
    """Find the reset control sequence and its high-memory interworking call."""
    if len(image) < 4:
        return False
    vector = struct.unpack_from('<I', image)[0]
    if vector & 0xff000000 != 0xea000000:
        return False
    displacement = (vector & 0xffffff) << 2
    if displacement & 0x02000000:
        displacement -= 0x04000000
    entry = 8 + displacement
    if entry + 48 > min(len(image), 0x10000) or not _event_500_sequence(image, entry):
        return False
    # shortcut: only nearby reset calls are scanned; upgrade when later boot flow is linked.
    for pc in range(entry + 48, min(entry + 0x200, len(image) - 7), 4):
        instruction, call = struct.unpack_from('<2I', image, pc)
        literal = pc + 8 + (instruction & 0xfff)
        if (instruction & 0xfffff000 == 0xe59f0000 and call == 0xe12fff30 and
                literal <= len(image) - 4 and
                0xffff0001 <= struct.unpack_from('<I', image, literal)[0] < 0xffff2000 and
                struct.unpack_from('<I', image, literal)[0] & 1):
            return True
    return False


def has_high_context_reset(image: bytes) -> bool:
    """Find reset context stores and their high stack and control literals."""
    if len(image) < 4:
        return False
    vector = struct.unpack_from('<I', image)[0]
    if vector & 0xff000000 != 0xea000000:
        return False
    displacement = (vector & 0xffffff) << 2
    if displacement & 0x02000000:
        displacement -= 0x04000000
    entry = 8 + displacement
    if entry < 0 or entry + 32 > min(len(image), 0x10000):
        return False
    words = struct.unpack_from('<8I', image, entry)
    if words[1:] != (0xe8ac67ff, 0xe10fb000, 0xe8ac0800, 0xe14fb000,
                      0xe8ac0800, 0xe10f1000, 0xe3c1201f):
        return False
    literal = entry + 8 + (words[0] & 0xfff)
    if (words[0] & 0xfffff000 != 0xe59fc000 or literal > len(image) - 4 or
            struct.unpack_from('<I', image, literal)[0] != 0xffff2f00):
        return False
    # shortcut: only the nearby reset sequence is scanned; upgrade when later boot flow is linked.
    return any(_event_500_sequence(image, pc, stack)
               for pc in range(entry + 32, min(entry + 0x200, len(image) - 47), 4)
               for stack in (0xffff2000, 0xffff2f00))


def has_high_handoff(image: bytes) -> bool:
    """Find the high SRAM handoff and its ARM interworking calls."""
    marker = bytes.fromhex('101010e5')
    found = image.find(marker)
    while found >= 0:
        position = found - 4
        if position >= 0 and not position & 3 and position + 0x5c <= len(image):
            words = struct.unpack_from('<23I', image, position)
            if (words[0] & 0xfffff000 == 0xe59f0000 and
                    words[2] & 0xfffff000 == 0xe59f2000 and
                    words[3] == 0xe1520001 and words[4] & 0xff000000 == 0x1a000000 and
                    words[5:8] == (0xe321f0d1, 0xe500e010, 0xe321f0d3) and
                    words[8] & 0xfffff000 == 0xe59f0000 and
                    words[9:12] == (0xe5901000, 0xe2011004, 0xe3510004) and
                    words[18] == words[22] == 0xe12fff30):
                first = position + 8 + (words[0] & 0xfff)
                second = position + 16 + (words[2] & 0xfff)
                displacement = (words[4] & 0xffffff) << 2
                if displacement & 0x02000000:
                    displacement -= 0x04000000
                target = position + 24 + displacement
                if (first <= len(image) - 4 and second <= len(image) - 4 and
                        0 <= target < len(image) and
                        struct.unpack_from('<I', image, first)[0] == 0xffffe000 and
                        struct.unpack_from('<I', image, second)[0] == 0x12345678):
                    return True
        found = image.find(marker, found + 1)
    return False


def has_boot_output_880(image: bytes) -> bool:
    """Find the linked Thumb initialization writes to the control banks."""
    # shortcut: only early initialization is scanned; upgrade when later boot flow is linked.
    limit = min(len(image), 0x10000)
    marker = bytes.fromhex('00240460')
    found = image.find(marker, 0, limit)
    while found >= 0:
        start = found - 2
        if start >= 0 and not start & 1 and start + 18 <= limit:
            words = struct.unpack_from('<9H', image, start)
            if (words[0] & 0xff00 == 0x4800 and words[3] & 0xff00 == 0x4900 and
                    words[6] & 0xff00 == 0x4800 and
                    (words[1], words[2], words[4], words[5], words[7], words[8]) ==
                    (0x2400, 0x6004, 0x2007, 0x7208, 0x2501, 0x6105)):
                refs = tuple(((start + index * 2 + 4) & ~3) + (words[index] & 0xff) * 4
                             for index in (0, 3, 6))
                if (all(at <= len(image) - 4 for at in refs) and
                        tuple(struct.unpack_from('<I', image, at)[0] for at in refs) ==
                        (0x80001600, 0x80000740, 0x88004000)):
                    return True
        found = image.find(marker, found + 1, limit)
    return False

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
