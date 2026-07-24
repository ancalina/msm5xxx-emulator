"""Firmware memory-layout detection."""
from __future__ import annotations

import struct

from ..core.config import CopyLayout, LinkerLayout

from .arm import arm_vector_score, thumb_literal_value
from .signatures import find_all


PAGE = 0x1000

_BOOT_REGISTER_TABLE_LOOP = bytes.fromhex(
    "c100004a5158002900d0c10089188988c200004b9a581180"
    "411c0904090c081c00e7"
)
_BOOT_REGISTER_TABLE_WILDCARDS = frozenset((2, 8, 18, 32))
_BOOT_REGISTER_DESTINATIONS = (0x048000A0, 0x03000738, 0x0300073C)


ARM_MEMORY_COPY_SIGNATURE = bytes.fromhex(
    "030052e33e00009a03c010e20800000a0130d1e402005ce3"
    "0c2082e001c0d1940130c0e40130d134"
)
ARM_MEMORY_COPY_TAIL = bytes.fromhex(
    "043080241040bde81eff2f01822fb0e10120d1440130d124"
    "01c0d1240120c0440130c02401c0c0241eff2fe1"
)
ARM_MEMORY_COPY_TAIL_OFFSET = 0xF8

_BOOTSTRAP_PROGRESS_CLEAR = bytes.fromhex(
    "b4420dd202e0201d041cf9e700202060a003f8d1"
)


def _bootstrap_ram_base(image: bytes) -> int | None:
    """Recover the SDRAM bank from the reset clear loop's own descriptor."""
    found: set[int] = set()
    for position in find_all(image, _BOOTSTRAP_PROGRESS_CLEAR):
        if position < 18:
            continue
        words = struct.unpack_from("<9H", image, position - 18)
        if not (
            words[0] & 0xFF00 == 0x4800
            and words[1] == 0x6800
            and words[2] & 0xFF00 == 0x4900
            and words[3:6] == (0x6809, 0x1840, 0x1C06)
            and words[6] & 0xFF00 == 0x4800
            and words[7:] == (0x6800, 0x1C04)
        ):
            continue
        start_pointer = thumb_literal_value(image, position - 18, 0)
        size_pointer = thumb_literal_value(image, position - 14, 1)
        if (
            start_pointer is None
            or start_pointer != thumb_literal_value(image, position - 6, 0)
            or not 0 <= start_pointer <= len(image) - 4
            or not 0 <= size_pointer <= len(image) - 4
        ):
            continue
        start = struct.unpack_from("<I", image, start_pointer)[0]
        size = struct.unpack_from("<I", image, size_pointer)[0]
        for base in (0x01000000, 0x01800000):
            if base <= start < start + size <= base + 0x00800000:
                found.add(base)
    return next(iter(found)) if len(found) == 1 else None


def _boot_register_table_pointer(image: bytes) -> int | None:
    """Return the common reset loop's table pointer when uniquely observed."""
    limit = min(len(image), 0x4000)
    size = len(_BOOT_REGISTER_TABLE_LOOP)
    found: set[int] = set()
    for position in range(0, limit - size + 1, 2):
        candidate = image[position:position + size]
        if any(index not in _BOOT_REGISTER_TABLE_WILDCARDS
               and candidate[index] != expected
               for index, expected in enumerate(_BOOT_REGISTER_TABLE_LOOP)):
            continue
        pointers: list[int] = []
        for instruction_position in (position + 2, position + 18):
            instruction = struct.unpack_from(
                "<H", image, instruction_position
            )[0]
            literal = ((instruction_position + 4) & ~3
                       ) + (instruction & 0xFF) * 4
            if literal + 4 > len(image):
                break
            pointers.append(struct.unpack_from("<I", image, literal)[0])
        if len(pointers) != 2 or pointers[0] != pointers[1]:
            continue
        found.add(pointers[0])
    return next(iter(found)) if len(found) == 1 else None


def _is_boot_register_table(image: bytes, offset: int) -> bool:
    if not 0 <= offset <= len(image) - 32:
        return False
    entries = struct.unpack_from("<8I", image, offset)
    return (entries[0::2] == (*_BOOT_REGISTER_DESTINATIONS, 0)
            and entries[1::2][-1] == 0)


def restore_sparse_nor_gap(image: bytes) -> tuple[bytes, tuple[int, int] | None]:
    """Restore a cross-validated erased 0x20-byte hole in a sparse NOR dump."""
    gap_offset, gap_size = 0x1000, 0x20
    if len(image) < 0x4040 or arm_vector_score(image) < 7:
        return image, None
    table = _boot_register_table_pointer(image)
    if (table is None or table <= gap_offset + gap_size
            or _is_boot_register_table(image, table)
            or not _is_boot_register_table(image, table - gap_size)):
        return image, None
    targets: list[int] = []
    for index, word in enumerate(struct.unpack_from("<8I", image), 0):
        if index == 0:
            continue
        if word & 0x0E000000 != 0x0A000000:
            return image, None
        displacement = (word & 0x00FFFFFF) << 2
        if displacement & 0x02000000:
            displacement -= 0x04000000
        targets.append((index * 4 + 8 + displacement) & 0xFFFFFFFF)
    vector_block = min(targets) - 4
    shifted = vector_block - gap_size
    if (vector_block <= gap_offset
            or arm_vector_score(image, vector_block) >= 4
            or arm_vector_score(image, shifted) < 7):
        return image, None
    return (image[:gap_offset] + b"\xff" * gap_size + image[gap_offset:],
            (gap_offset, gap_size))


def find_arm_vector_offset(image: bytes) -> tuple[int, int]:
    """Return the best small dump-header offset and validated vector score."""
    candidates = [(0, arm_vector_score(image, 0))]
    for offset in range(4, min(0x100, len(image) - 32) + 1, 4):
        candidates.append((offset, arm_vector_score(image, offset)))
    best_score = max(score for _offset, score in candidates)
    return next(item for item in candidates if item[1] == best_score)


def infer_ram_base(layout: LinkerLayout | None, chipset: str,
                   image: bytes = b"") -> int:
    """Select the 8 MiB SDRAM bank that contains linker data and BSS."""
    if layout is not None:
        first = layout.data_target
        last = layout.bss_target + layout.bss_size
        for base in (0x01000000, 0x01800000):
            if base <= first and last <= base + 0x00800000:
                return base
    if image:
        if (bootstrap_base := _bootstrap_ram_base(image)) is not None:
            return bootstrap_base
        # Linker tables are absent in several partial builds.  Literal pools
        # in the reset/driver region still reveal which external SDRAM bank
        # the image was linked against.  Requiring a 3:1 margin avoids random
        # resource words deciding the result.
        counts: list[int] = []
        sample = image[:min(len(image), 0x20000)]
        sample = sample[:len(sample) & ~3]
        words = tuple(value[0] for value in struct.iter_unpack("<I", sample))
        for base in (0x01000000, 0x01800000):
            counts.append(sum(base <= value < base + 0x00800000
                              for value in words))
        if max(counts, default=0) >= 32:
            if counts[0] >= counts[1] * 3:
                return 0x01000000
            if counts[1] >= counts[0] * 3:
                return 0x01800000
    return 0x01000000 if chipset in ("MSM5000", "MSM5500") else 0x01800000


def plausible_ram_seed_size(image_size: int, flash_size: int,
                            ram_size: int = 0x00800000) -> int:
    """Reject tiny capture trailers while preserving real RAM snapshots."""
    tail = max(0, image_size - flash_size)
    return min(tail, ram_size) if tail >= 0x10000 else 0


def aligned(value: int) -> int:
    return (value + PAGE - 1) & -PAGE


def interval_gaps(start: int, end: int,
                  excluded: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Subtract half-open intervals and return remaining half-open gaps."""
    if start >= end:
        return []
    gaps: list[tuple[int, int]] = []
    cursor = start
    for left, right in sorted(excluded):
        left, right = max(start, left), min(end, right)
        if left >= right or right <= cursor:
            continue
        if cursor < left:
            gaps.append((cursor, left))
        cursor = max(cursor, right)
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def normalised_flash_size(size: int, address_limit: int) -> int:
    """Recover physical NOR capacity from partial dumps and small trailers."""
    capacities = (0x200000, 0x400000, 0x800000, 0x1000000,
                  0x1800000, 0x2000000)
    for capacity in capacities:
        if capacity <= address_limit and size <= capacity:
            return capacity
        # A short trailer beyond an exact NOR capacity is normally a captured
        # RAM prefix, not a non-standard flash chip size.
        if capacity < address_limit and capacity < size <= capacity + 0x10000:
            return capacity
    return min(size, address_limit)


def referenced_flash_extent(image: bytes, load_address: int = 0) -> int:
    """Infer NOR capacity from boot copy tables even when their source is absent."""
    extent = 0
    for offset in range(0, min(len(image) - 12, 0x20000) + 1, 4):
        source_address, target, size = struct.unpack_from("<3I", image, offset)
        if not (0x03800000 <= target < 0x03A00000
                and target % PAGE == 0 and 0x100 <= size <= 0x200000):
            continue
        source = source_address - load_address
        if (0x1000 <= source < 0x02000000
                and source > offset + 0x20
                and source + size <= 0x02000000):
            extent = max(extent, source + size)
    return extent


def _image_offset(address: int, image_size: int, load_address: int) -> int | None:
    if load_address and load_address <= address < load_address + image_size:
        return address - load_address
    if 0 <= address < image_size:
        return address
    return None


def find_linker_layout(image: bytes, load_address: int = 0) -> LinkerLayout | None:
    """Find Qualcomm scatter-load data/BSS tuple without model addresses."""
    limit = min(len(image) - 20, 0x20000)
    preferred = (0x10028,)
    offsets = (*preferred, *(range(0, limit + 1, 4)))
    seen: set[int] = set()
    for offset in offsets:
        if offset in seen or offset + 20 > len(image):
            continue
        seen.add(offset)
        source_address, target, size, bss, bss_size = struct.unpack_from(
            "<5I", image, offset
        )
        source = _image_offset(source_address, len(image), load_address)
        valid = (
            source is not None
            and 0 < size <= 0x800000
            and source + size <= len(image)
            # The supported MSM5000/5100/5500 boards expose external SDRAM in
            # the 0x01000000 or 0x01800000 8 MiB bank.  Repeated 0x00800000 /
            # 0x00010000 tables in resources are not scatter-load metadata.
            and 0x01000000 <= target < 0x02000000
            and target + size == bss
            and 0 < bss_size <= 0x2000000
            and bss + bss_size <= 0x08000000
        )
        if valid:
            return LinkerLayout(offset, source, target, size, bss, bss_size)
    return None


def find_overlays(image: bytes, load_address: int = 0) -> list[CopyLayout]:
    """Find boot tables that relocate MSM internal-RAM executable overlays."""
    found: list[CopyLayout] = []
    for offset in range(0, min(len(image) - 12, 0x20000) + 1, 4):
        source_address, target, size = struct.unpack_from("<3I", image, offset)
        source = _image_offset(source_address, len(image), load_address)
        internal_ram = 0x03800000 <= target < 0x03A00000 and target % PAGE == 0
        runtime_rom = (0x01400000 <= target < 0x01800000
                       and target % PAGE == 0 and source is not None
                       and 0 < source - offset <= 0x40)
        if (source is not None and 0x100 <= size <= 0x200000
                and source + size <= len(image) and (internal_ram or runtime_rom)):
            candidate = CopyLayout(offset, source, target, size)
            if not any(item.target == target and item.size == size for item in found):
                found.append(candidate)
    return found


def find_missing_overlays(image: bytes, flash_size: int,
                          load_address: int = 0) -> list[CopyLayout]:
    """Find boot copy entries whose executable ROM source was not dumped."""
    found: list[CopyLayout] = []
    for offset in range(0, min(len(image) - 12, 0x20000) + 1, 4):
        source_address, target, size = struct.unpack_from("<3I", image, offset)
        source = source_address - load_address
        if (0x1000 <= source < flash_size
                and source > offset + 0x20
                and 0x03800000 <= target < 0x03A00000
                and target % PAGE == 0
                and 0x100 <= size <= 0x200000
                and source + size <= flash_size
                and source + size > len(image)):
            candidate = CopyLayout(offset, source, target, size)
            if candidate not in found:
                found.append(candidate)
    return found


def find_runtime_overlays(image: bytes, ram_base: int,
                          ram_size: int) -> list[CopyLayout]:
    """Find structural SDRAM-to-internal-RAM overlay copy candidates.

    A tuple alone does not prove a NAND/partition loader: bootstrap code can
    also initialize its SDRAM source from supplied NOR or scratch memory.
    """
    found: list[CopyLayout] = []
    ram_end = ram_base + ram_size
    for offset in range(0, min(len(image) - 12, 0x40000) + 1, 4):
        source, target, size = struct.unpack_from("<3I", image, offset)
        if (ram_base <= source < source + size <= ram_end
                and 0x03800000 <= target < target + size <= 0x03A00000
                and source & 1 == 0 and target & 1 == 0
                and 0x100 <= size <= 0x200000):
            candidate = CopyLayout(offset, source, target, size)
            if candidate not in found:
                found.append(candidate)
    return found


def find_arm_memory_copy_addresses(image: bytes, overlays: list[CopyLayout],
                                   linker: LinkerLayout | None = None,
                                   load_address: int = 0) -> list[int]:
    """Locate the validated ARM copier in ROM and every proven runtime copy.

    The instruction hook performs its own full prefix/tail, CPU-state, source,
    destination, and overlap validation.  Discovery can therefore include all
    aligned exact bodies in primary NOR instead of assuming the copier always
    lives in an internal-RAM overlay; several MSM5000/5100 BSPs call it from
    ROM or from the linker-relocated data bank.
    """
    found: set[int] = set()
    for position in find_all(image, ARM_MEMORY_COPY_SIGNATURE):
        if (position & 3
                or image[position + ARM_MEMORY_COPY_TAIL_OFFSET:
                         position + ARM_MEMORY_COPY_TAIL_OFFSET
                         + len(ARM_MEMORY_COPY_TAIL)] != ARM_MEMORY_COPY_TAIL):
            continue
        found.add(load_address + position)
        if (linker is not None
                and linker.data_source <= position
                < linker.data_source + linker.data_size):
            found.add(linker.data_target + position - linker.data_source)
        for overlay in overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                found.add(overlay.target + position - overlay.source)
    return sorted(found)
