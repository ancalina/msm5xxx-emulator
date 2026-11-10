"""Close a NOR branch veneer through the firmware's actual boot copier."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.detection.arm import arm_b_word_target

# Literal displacements vary; every erased literal is checked below.  These are
# opcode grammars, not handset names, dump hashes, or a scan for data pointers.
_RESET = bytes.fromhex('00409fe5010014e300e09f1500e09f0514ff2fe178470000' '00409fe5010014e300e09f1500e09f0514ff2fe178470000'
    '00409fe5010014e300e09f1500e09f0514ff2fe178470000' 'd7f021e300d09fe5dbf021e300d09fe5d3f021e300d09fe5' '00409fe5010014e300e09f1500e09f0514ff2fe178470000'
    '00409fe5010014e300e09f1500e09f0514ff2fe178470000' '000050e30000001a000000ea')
_RESET_LITERALS = (0, 8, 12, 24, 32, 36, 48, 56, 60, 76, 84, 92, 96, 104, 108, 120, 128, 132)
_COPY = bytes.fromhex('004980b40120087000230b700048004f02683f68d619004a15680468' '012005e02a68226008700b7004350434b442f7d30a1c0870191c1370'
    '004b004c1f6824683e193c1c03e02160107011700434b442f9d310701170' '004b004c1f6824683e19004f3d681c6805e02b6823601070117004350434'
    'b442f7d310701170004b004c1f6824683e19004f3d681c6805e02b682360' '1070117004350434b442f7d31070117080bc7047')
_COPY_LITERALS = (0, 12, 14, 22, 56, 58, 86, 88, 96, 124, 126, 134)

def find_nor_veneer_vector_copy(image: bytes, *, ram_base: int, ram_size: int,) -> dict[str, object] | None:
    """Prove reset/copy, vector -> NOR B -> copied RAM B -> ROM wrapper."""
    dependencies: list[list[int]] = []
    def rom(address: int, size: int) -> bool:
        return 0 <= address <= len(image) - size
    def ram(address: int, size: int) -> bool:
        end = ram_base + ram_size
        return (0 <= ram_base < end <= 0x100000000 and size > 0 and ram_base <= address <= end - size)
    def word(address: int) -> int:
        dependencies.append([address, 4])
        return struct.unpack_from('<I', image, address)[0]
    def branch(address: int) -> int | None:
        return arm_b_word_target(word(address), address) if rom(address, 4) else None
    def stage(vector: int) -> tuple[int, dict[int, int], int] | None:
        entry = branch(vector)
        if entry is None or entry & 3 or not rom(entry, len(_RESET)):
            return None
        code = bytearray(image[entry:entry + len(_RESET)])
        values = {}
        for offset in _RESET_LITERALS:
            instruction = struct.unpack_from('<I', code, offset)[0]
            if instruction & 0x0F7F0000 != 0x051F0000:
                return None
            pool = entry + offset + 8 + (instruction & 4095) * (1 if instruction & 0x800000 else -1)
            if pool & 3 or not rom(pool, 4):
                return None
            values[offset] = word(pool)
            struct.pack_into('<I', code, offset, instruction & ~4095)
        next_stage = branch(entry + 0x98)
        if next_stage is None or next_stage & 3 or not rom(next_stage, 4):
            return None
        struct.pack_into('<I', code, 0x98, 0xEA000000)
        if code != _RESET:
            return None
        for offset in (0, 0x18, 0x30, 0x60, 0x78):
            pointer = values[offset]
            if (not rom(pointer & ~1, 2) or (not pointer & 1 and pointer & 3) or values[offset + 8] != ((entry + offset + 20) | 1) or values[offset + 12] !=
                entry + offset + 24):
                return None
        dependencies.append([entry, len(_RESET)])
        return entry, values, next_stage
    if not rom(0, 0x20):
        return None
    veneer = branch(0x18)
    if (veneer is None or veneer < 0x20 or veneer & 3 or not rom(veneer, 4) or ram(veneer, 4)):
        return None
    target = branch(veneer)
    if target is None or target & 3 or not ram(target, 4):
        return None
    first = stage(0)
    if first is None or first[2] != veneer - 0x18:
        return None
    second = stage(first[2])
    if second is None:
        return None
    copier = second[1][0x60]
    if not copier & 1 or not rom(copier - 1, len(_COPY)):
        return None
    copier -= 1
    code = bytearray(image[copier:copier + len(_COPY)])
    literals = {}
    for offset in _COPY_LITERALS:
        instruction = struct.unpack_from('<H', code, offset)[0]
        if instruction & 0xF800 != 0x4800:
            return None
        value = facts_for(image).thumb_literal_value(copier + offset, instruction >> 8 & 7)
        if value is None:
            return None
        literals[offset] = value
        dependencies.append([((copier + offset + 4) & ~3) + (instruction & 255) * 4, 4])
        code[offset] = 0
    if code != _COPY or literals[0] != 0x03000700:
        return None
    dependencies.append([copier, len(_COPY)])
    records = []
    for source_at, target_at, size_at in ((22, 12, 14), (96, 86, 88), (134, 124, 126)):
        table = literals[source_at]
        if (literals[target_at] != table + 4 or literals[size_at] != table + 8 or table & 3 or not rom(table, 12)):
            return None
        source, destination, size = struct.unpack_from('<3I', image, table)
        if (not size or (source | destination | size) & 3 or not rom(source, size) or destination + size > 0x100000000):
            return None
        dependencies.append([table, 12])
        records.append((table, source, destination, size))
    table, source, destination, size = records[1]
    if (destination != target or not ram(target, size) or not rom(table, 20) or table != second[2] + 0x28 or word(table + 12) != target + size):
        return None
    bss_size = word(table + 16)
    if bss_size & 3 or target + size + bss_size > ram_base + ram_size:
        return None
    zero_start, zero_size = literals[56], literals[58]
    if zero_size != zero_start + 4 or not rom(zero_start, 8):
        return None
    zero_start, zero_size = word(zero_start), word(zero_size)
    if (zero_start | zero_size) & 3 or zero_start + zero_size > 0x100000000:
        return None
    if max(zero_start, target) < min(zero_start + zero_size, target + size):
        return None
    for _table, _source, other_target, other_size in (records[0], records[2]):
        if max(other_target, target) < min(other_target + other_size, target + size):
            return None
    wrapper = arm_b_word_target(word(source), target)
    if wrapper is None or wrapper & 3 or not rom(wrapper, 4):
        return None
    return { 'signature': 'arm-nor-branch-word-copy-ram-vector-v1', 'vector': 0x18, 'nor_veneer': veneer, 'reset_entries':[first[0], second[0]], 'copier':
        copier, 'copy_table': table, 'copy_source': source, 'copy_target': target, 'copy_size': size, 'bss_start': target + size, 'bss_size': bss_size,
        'zero_start': zero_start, 'zero_size': zero_size, 'wrapper': wrapper, 'nor_dependencies':[list(pair) for pair in sorted({tuple(p) for p in dependencies})],
        }
