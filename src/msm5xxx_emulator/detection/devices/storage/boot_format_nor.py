"""Extra x16 AMD bank owned by a copied cold-boot formatter.

The accepted instructions erase 0x01800000..0x01ffffff.  This is distinct
from both the low NV bank (whose format marker is at 0x0080f000) and RAM.
The compatible 0x0001/0x227e identity selects the guest's 8 MiB descriptor;
the original physical part and its extended ID bytes are unverified.
"""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.detection.fact_patterns import mov, cmp_imm, lsl, halfword, match

# Device commands, formatter control and watchdog service, expressed as
# Thumb instructions and descriptor values rather than firmware-span hashes.
_CODE = ((0x722500, halfword(False, 5, 4)), (0x722502, halfword(False, 3, 4)), (0x72250a, halfword(False, 3, 2)), (0x8eb8e, mov(5, 9)), (0x8eb92, lsl(5, 5, 6)),
    (0xea4, mov(0, 1)), (0xea8, mov(2, 0)), (0x7bde, mov(4, 3)), (0x7be2, mov(1, 0x1f)), (0x7be4, lsl(1, 1, 0x17)), (0x7cae, mov(7, 3)), (0x7cb0, lsl(7, 7, 0x17)),
    (0x7cb2, mov(4, 1)), (0x7cb4, lsl(4, 4, 0xd)), (0x7cbc, cmp_imm(0, 0)), (0x39490, 0x6a00), (0x39492, 0x0840), (0x2e9a90, 0x4778), (0x7d7e, cmp_imm(0, 0)), (0x7d82,
    mov(0, 1)), (0x83de8, cmp_imm(0, 0)), (0x83dee, mov(0, 1)), (0x83df2, mov(0, 0)), (0x83e24, mov(2, 1)), (0x83e26, lsl(2, 2, 0xb)),)

def find_boot_format_nor(image: bytes, ram_base: int, ram_size: int) -> dict | None:
    """Recognize the source-closed formatter; never seed its success marker."""
    if (ram_base, ram_size) != (0x01000000, 0x00800000):
        return None
    if len(image) < 0x722534 or not match(image, _CODE):
        return None
    # The descriptor selects the ID and defines all 142 erase sectors.
    if (struct.unpack_from('<7I', image, 0x7224d8) != (0x3f5a48, 0x3f57c8, 0x3f5cc8, 0x3f6448, 0x3f66d0, 0x3f61c8, 0) or struct.unpack_from('<I', image, 0x83dfc)[0]
        != 0x03001080 or struct.unpack_from('<I', image, 0x3f61cc)[0] != 142 or struct.unpack_from('<142I', image, 0x3f61d0) != (0x2000,) * 8 + (0x10000,) * 126
        + (0x2000,) * 8 or struct.unpack_from('<I', image, 0x3f6408)[0] != 0x227e0001 or struct.unpack_from('<I', image, 0x3f6418)[0] != 0x800000):
        return None
    # Reset calls the guest copy at 0xea0. The exact copied span contains the
    # formatter and its marker descriptor; BX PC then BX IP reaches that copy.
    if (image[0x50A8:0x50C0] != bytes.fromhex("d0419fe5010014e3c4e19f15c8e19f0514ff2fe178470000") or struct.unpack_from("<I", image, 0x5280)[0] != 0xEA1 or
        struct.unpack_from("<5I", image, 0x6318) != (0x6344, 0x015F0000, 0x5FD4, 0x015F5FD4, 0) or struct.unpack_from("<9I", image, 0xC0C4) != (0x800000,
        0x802000, 0x804000, 0x806000, 0x808000, 0x80C000, 0x80D000, 0x80E000, 0x80F000) or facts_for(image).thumb_call_target(0x39512) != 0x2E9A90):
        return None
    return { "signature": "copied-boot-format-amd-x16-v1", "base": 0x01800000, "size": 0x00800000, "id0": 0x0001, "id1": 0x227E, "part_descriptor": 0x3F61C8,
        "erase_regions": ((8, 0x2000), (126, 0x10000), (8, 0x2000)), "overlay_source": 0x6344, "overlay_target": 0x015F0000, "overlay_size": 0x5FD4, "formatter":
        0x015F1968, "erase": 0x015F1898, "marker_address": 0x0080F000, "marker_values": (0xFFF0, 0xF000), "watchdog_register": 0x03001080, "watchdog_mask": 1,
        "watchdog_service": 0x83DE4, "watchdog_reset_wait": 0x015F1A4E, }
