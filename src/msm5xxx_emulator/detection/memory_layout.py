"""Firmware memory-layout detection."""
from __future__ import annotations

import hashlib
import struct

from ..core.config import CopyLayout, LinkerLayout

from .arm import arm_vector_score, thumb_bl_target, thumb_literal_value
from .signatures import find_all


PAGE = 0x1000

# Closed ARM walking-bit/address/byte readback test, shared by independent
# reset images. Descriptor pointers are outside this instruction signature.
_HIGH_RAM_TEST_PREFIX = bytes.fromhex("54019fe5000090e50110a0e30020a0e3")
_HIGH_RAM_TEST_SHA256 = (
    "6b3b59b43cc612c0e58a369709895a11607f138d5229d75121df6852ae4c89e8"
)


def _high_ram_readback_layout(image: bytes, position: int) -> tuple[int, int] | None:
    layouts = []
    if position >= 28 and struct.unpack_from('<I', image, position-28)[0] == 0x14000000:
        layouts.append((position-28, position))
    if (position >= 60 and not position & 3
            and image[position-20:position] == bytes.fromhex(
                '5c019fe558019fe554019fe554019fe554019fe5')
            and struct.unpack_from('<I', image, position-60)[0] == 0x14000000):
        table, entry = position-60, position-20
        valid = True
        for offset, field in ((0, 28), (4, 28), (8, 28), (12, 32), (16, 36)):
            instruction = struct.unpack_from('<I', image, entry+offset)[0]
            literal = entry+offset+8+(instruction & 0xFFF)
            if (literal > len(image)-4
                    or struct.unpack_from('<I', image, literal)[0] != table+field):
                valid = False
                break
        if valid:
            layouts.append((table, entry))
    return layouts[0] if len(layouts) == 1 else None


def find_high_ram_readback_tests(image: bytes) -> list[int]:
    """Find the complete readback body with one closed descriptor layout."""
    return [position for position in find_all(image[:0x10000], _HIGH_RAM_TEST_PREFIX)
            if _high_ram_readback_layout(image, position) is not None
            and hashlib.sha256(image[position:position + 0x150]).hexdigest()
            == _HIGH_RAM_TEST_SHA256]


def _reset_copy_covers_upper_half(image: bytes, called: set[int],
                                  base: int, size: int) -> bool:
    """Match a closed literal-descriptor copy, including its loop operands."""
    shapes = (
        (0x4800, 0x6804, 0x4800, 0x6800, 0x1826, 0x4800,
         0x6805, 0xE001, 0xCD01, 0xC401, 0x42B4, 0xD3FB),
        (0x4A00, 0x6814, 0x4A00, 0x6812, 0x18A6, 0x4A00,
         0x6815, 0xE001, 0xCD04, 0xC404, 0x42B4, 0xD3FB),
    )
    for target in called:
        if not target & 1:
            continue
        start = target & ~1
        for pc in range(start, min(start + 0x400, len(image) - 23), 2):
            words = struct.unpack_from('<12H', image, pc)
            normalized = tuple(word & 0xFF00 if i in (0, 2, 5) else word
                               for i, word in enumerate(words))
            if normalized not in shapes:
                continue
            register = (words[0] >> 8) & 7
            pointers = [thumb_literal_value(image, pc + offset, register)
                        for offset in (0, 4, 10)]
            if any(p is None or p & 3 or p > len(image) - 4 for p in pointers):
                continue
            destination_ptr, length_ptr, source_ptr = pointers
            if (length_ptr != destination_ptr + 4
                    or source_ptr != destination_ptr - 4):
                continue
            destination, length, source = (
                struct.unpack_from('<I', image, p)[0] for p in pointers)
            if (not (destination | length | source) & 3 and length > 0
                    and source + length <= len(image)
                    and base + size // 2 <= destination
                    < destination + length <= base + size):
                return True
    return False


def high_ram_bootstrap_profile(image: bytes) -> tuple[int, int] | None:
    """Require a closed extent table and a reset-linked RAM consumer."""
    if len(image) < 4:
        return None
    vector = struct.unpack_from("<I", image)[0]
    if vector & 0xFF000000 != 0xEA000000:
        return None
    displacement = (vector & 0xFFFFFF) << 2
    if displacement & 0x02000000:
        displacement -= 0x04000000
    reset = 8 + displacement
    if not 0 <= reset < min(len(image) - 24, 0x10000):
        return None
    called: set[int] = set()
    for pc in range(reset, min(reset + 0x400, len(image) - 24), 4):
        words = struct.unpack_from("<5I", image, pc)
        if (words[0] & 0xFFFFF000 == 0xE59F4000
                and words[1] == 0xE3140001
                and words[2] & 0xFFFFF000 == 0x159FE000
                and words[3] & 0xFFFFF000 == 0x059FE000
                and words[4] == 0xE12FFF14):
            literal = pc + 8 + (words[0] & 0xFFF)
            return_literal = pc + 20 + (words[3] & 0xFFF)
            if (literal <= len(image) - 4 and return_literal <= len(image) - 4
                    and struct.unpack_from("<I", image, return_literal)[0]
                    == pc + 24):
                target = struct.unpack_from("<I", image, literal)[0]
                if target & 1:
                    thumb_return = pc + 16 + (words[2] & 0xFFF)
                    if (thumb_return > len(image) - 4
                            or struct.unpack_from('<I', image, thumb_return)[0]
                            != (pc + 20) | 1
                            or struct.unpack_from('<H', image, pc + 20)[0]
                            != 0x4778):  # Thumb BX PC returns to aligned ARM.
                        continue
                called.add(target)
    found: set[tuple[int, int]] = set()
    for position in find_high_ram_readback_tests(image):
        if position < 28 or position + 0x178 > len(image):
            continue
        layout = _high_ram_readback_layout(image, position)
        if layout is None:
            continue
        table, entry = layout
        base, extent, stride, word, half, byte, watchdog = struct.unpack_from(
            "<7I", image, table
        )
        if (base != 0x14000000 or extent not in
                (0x3FFDFF, 0x3FFFFF, 0x7FFDFF, 0x7FFFFF)
                or (stride, word, half, byte, watchdog) !=
                (0x10, 0x55AA0F, 0xAA0F, 0x55, 0x030006D0)):
            continue
        valid = True
        for offset, field in ((0, 0), (0x10, 8), (0x40, 24), (0x6C, 4),
                              (0x80, 4), (0xF4, 12), (0x108, 16), (0x11C, 20)):
            instruction = struct.unpack_from("<I", image, position + offset)[0]
            literal = position + offset + 8 + (instruction & 0xFFF)
            if (literal > len(image) - 4 or
                    struct.unpack_from("<I", image, literal)[0] != table + field):
                valid = False
                break
        size = (extent + PAGE) & ~(PAGE - 1)
        linked = (entry in called or (entry == position and
                  _reset_copy_covers_upper_half(image, called, base, size)))
        if valid and linked:
            found.add((base, size))
    return next(iter(found)) if len(found) == 1 else None

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

# ARM reset helper: read 0x0300072C bit 1, then set bit 0 in the low SDRAM
# boot flag before dispatching into the firmware image.
_DUAL_SDRAM_BOOTSTRAP = bytes.fromhex(
    "8c009fe50000d0e5020000e2020050e30300000a7c009fe5"
    "0010d0e5011081e30010c0e570209fe512ff2fe1"
)
_DUAL_SDRAM_STATUS_LITERAL_OFFSET = 0x94
_DUAL_SDRAM_FLAG_LITERAL_OFFSET = 0x98
_DUAL_SDRAM_DISPATCH_LITERAL_OFFSET = 0x9C
_DUAL_SDRAM_LOW_BASE = 0x01000000
_DUAL_SDRAM_HIGH_BASE = 0x01800000
_DUAL_SDRAM_END = 0x02000000

# Thumb bootstrap: materialize 0x01800000, pass it to one reader entry, then
# call the reader's two post-read continuations.  The nested reader and its
# consumer are checked below so a literal alone cannot widen RAM.
_HIGH_BANK_READER_BOOTSTRAP = bytes.fromhex("0321c905081c00b5")
_HIGH_BANK_READER_BOOTSTRAP_TAIL = bytes.fromhex("002008bc1847")
_HIGH_BANK_READER_ENTRY = bytes.fromhex("f3b5184e0d1c30780128")
_HIGH_BANK_READER = bytes.fromhex("ffb5061c1c1c86b00025")
_HIGH_BANK_READER_ASSIGN = bytes.fromhex("b8631c2000ab1870381c")
_HIGH_BANK_READER_CONSUMER = bytes.fromhex(
    "b8b5041c002000ab1870084d0027a06ba26f291c"
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


def has_dual_sdram_bootstrap(image: bytes,
                             layout: LinkerLayout | None) -> bool:
    """Require one closed reset path before widening high-bank SDRAM."""
    if layout is None:
        return False
    high_end = layout.bss_target + layout.bss_size
    if not (_DUAL_SDRAM_HIGH_BASE <= layout.data_target
            and layout.data_target + layout.data_size <= high_end
            and high_end <= _DUAL_SDRAM_END):
        return False
    matches: list[int] = []
    for position in find_all(image, _DUAL_SDRAM_BOOTSTRAP):
        dispatch_offset = position + _DUAL_SDRAM_DISPATCH_LITERAL_OFFSET
        if dispatch_offset + 4 > len(image):
            continue
        status = struct.unpack_from(
            "<I", image, position + _DUAL_SDRAM_STATUS_LITERAL_OFFSET
        )[0]
        flag = struct.unpack_from(
            "<I", image, position + _DUAL_SDRAM_FLAG_LITERAL_OFFSET
        )[0]
        dispatch = struct.unpack_from("<I", image, dispatch_offset)[0]
        if (status != 0x0300072C
                or flag != _DUAL_SDRAM_LOW_BASE + 0x110
                or (dispatch & 1) == 0
                or not 0x1000 <= (dispatch & ~1) < len(image)):
            continue
        matches.append(position)
    return len(matches) == 1


def has_high_bank_reader_bootstrap(image: bytes) -> bool:
    """Accept one complete Thumb bootstrap that consumes high-bank SDRAM."""
    matches: list[int] = []
    for position in find_all(image, _HIGH_BANK_READER_BOOTSTRAP):
        if image[position + 20:position + 26] != _HIGH_BANK_READER_BOOTSTRAP_TAIL:
            continue
        reader_entry = thumb_bl_target(image, position + 8)
        if (reader_entry is None
                or image[reader_entry:reader_entry + len(_HIGH_BANK_READER_ENTRY)]
                != _HIGH_BANK_READER_ENTRY):
            continue
        reader = thumb_bl_target(image, reader_entry + 0x3C)
        if (reader is None
                or image[reader:reader + len(_HIGH_BANK_READER)]
                != _HIGH_BANK_READER
                or image[reader + 0x5C:reader + 0x5C
                         + len(_HIGH_BANK_READER_ASSIGN)]
                != _HIGH_BANK_READER_ASSIGN):
            continue
        consumer = thumb_bl_target(image, reader + 0x66)
        if (consumer is None
                or image[consumer:consumer + len(_HIGH_BANK_READER_CONSUMER)]
                != _HIGH_BANK_READER_CONSUMER
                or thumb_bl_target(image, position + 12) is None
                or thumb_bl_target(image, position + 16) is None):
            continue
        matches.append(position)
    return len(matches) == 1


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
    """Infer NOR capacity from closed references into an absent dump tail."""
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
    sentinel_extents: set[int] = set()
    for middle in find_all(image, bytes.fromhex("00689842")):
        position = middle - 4
        if position < 0 or position & 1 or position + 10 > len(image):
            continue
        first, second, _load, _compare, branch = struct.unpack_from(
            "<5H", image, position
        )
        if (first & 0xFF00 != 0x4800
                or second & 0xFF00 != 0x4B00
                or branch & 0xFF00 != 0xD000):
            continue
        displacement = (branch & 0xFF) << 1
        if displacement & 0x100:
            displacement -= 0x200
        success = position + 12 + displacement
        if not 0 <= success <= len(image) - 2:
            continue
        address = thumb_literal_value(image, position, 0)
        expected = thumb_literal_value(image, position + 2, 3)
        if address is None or expected in (None, 0, 0xFFFFFFFF, address):
            continue
        source = address - load_address
        if (0x00800000 <= source < 0x01000000
                and source % PAGE == 0 and source >= len(image)):
            sentinel_extents.add(source + 4)
    if len(sentinel_extents) == 1:
        extent = max(extent, next(iter(sentinel_extents)))
    return extent


def _image_offset(address: int, image_size: int, load_address: int) -> int | None:
    if load_address and load_address <= address < load_address + image_size:
        return address - load_address
    if 0 <= address < image_size:
        return address
    return None


def _contiguous_address_length_array(image: bytes, offset: int) -> bool:
    """Require nine page-aligned extents containing the candidate's three pairs."""
    pair_start = offset-4
    for first in range(pair_start-6*8, pair_start+1, 8):
        if first < 0 or first+9*8 > len(image):
            continue
        pairs = tuple(struct.iter_unpack('<2I', image[first:first+9*8]))
        if any(not length or address % PAGE or length % PAGE
               or address+length > 0x100000000 for address,length in pairs):
            continue
        if all(address+length == following[0]
               for (address,length),following in zip(pairs,pairs[1:])):
            return True
    return False


def find_linker_layout(image: bytes, load_address: int = 0, *,
                       required_span: tuple[int, int] | None = None) -> LinkerLayout | None:
    """Find scatter-load metadata; a required data span must have one mapping."""
    if required_span is not None:
        if (not isinstance(required_span, tuple) or len(required_span) != 2
                or any(type(value) is not int for value in required_span)
                or required_span[0] < 0 or required_span[1] <= 0
                or sum(required_span) > 0x100000000):
            return None
    matches = []
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
        if valid and not _contiguous_address_length_array(image, offset):
            layout = LinkerLayout(offset, source, target, size, bss, bss_size)
            if required_span is None:
                return layout
            address, length = required_span
            if length <= size and target <= address <= target + size - length:
                matches.append(layout)
                if len(matches) > 1:
                    return None
    return matches[0] if matches else None


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


# Typed reset/private initialization and normal scatter consumer compiler class.
_DUAL_STAGE_RESET = bytes.fromhex("24429fe5010014e320e29f1520e29f0514ff2fe17847000018429fe5010014e314e29f1514e29f0514ff2fe1784700000c429fe5010014e308e29f1508e29f0514ff2fe178470000d7f021e3a4d19fe5dbf021e3f4d19fe5d3f021e3f0d19fe5f0419fe5010014e3ece19f15ece19f0514ff2fe178470000e4419fe5010014e3e0e19f15e0e19f0514ff2fe178470000d8419fe5010014e3d4e19f15d4e19f0514ff2fe178470000000050e30300001ac63f00ea")
_DUAL_STAGE_PRIVATE = bytes.fromhex("80b400201f4a0121002711701770013000041d4b000c9842f7db1c4bd88bd88bd88bd88b1a48d8831a48d8831a48d88300201170177001300004134b000c9842f7db117017701548154c036824681e19144b1d68046801e001cd01c4b442fbd3117017701048114c036824681e191c1c00e080c4b442fcd3117017701170177080bc7047")
_DUAL_STAGE_NORMAL = bytes.fromhex("d2f021e388d09fe5dff021e384d09fe5d1f021e30dd02de07cd09fe5d3f021e378009fe5010010e374e09f1574e09f0510ff2fe1784700006c209fe512ff2fe1")
_DUAL_STAGE_SCATTER = bytes.fromhex("884900b50120087000200870874a864b1568874a1f6814687f09012211e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2784b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870744b1f68744b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d26b4b1f68bb085f077f0f02e001c40a700870013ffad20a700870664b1f68664b7f091d68664b1c6811e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2584b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870544b1f68544b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d24b4b1f68bb085f077f0f03e0002001c40a700870013ff9d24848474b056848481f6804687f09002011e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2394b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870354b1f68354b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d22c4b1f68bb085f077f0f03e0002001c40a700870013ff9d228488280294b27481d68284b07681c687f090fe008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c4013fedd20768b80847077f0f01e001cd01c4013ffbd20a70002008700a700870")
_DUAL_STAGE_ROUTE = bytes.fromhex("80b50027fff7ccff3c4908703b480078002803d1012080bc08bc18470020384b18810022052a00db66e004e0501c0004000c021cf6e71f20314b98820620314b18802f488089c106c90e1f2901d10020e1e7")


def dual_stage_ram_profile(image: bytes, linker: LinkerLayout | None,
                           load_address: int = 0) -> tuple[dict | None, str | None]:
    """Derive a logical RAM allocation from linked private and normal writes.

    The allocation is not a physical capacity or device identification.
    """
    if (type(load_address) is not int or load_address < 0 or load_address & 3
            or load_address + len(image) > 0x100000000):
        return None, "dual-stage-load-invalid"

    def word(offset):
        if offset < 0 or offset + 4 > len(image):
            return None
        return struct.unpack_from("<I", image, offset)[0]

    def arm_literal(pc):
        value = word(pc)
        return None if value is None else word(pc + 8 + (value & 0xfff))

    def literal(pc):
        if pc < 0 or pc + 2 > len(image):
            return None
        return thumb_literal_value(image, pc, image[pc + 1] & 7)

    def offset(address):
        return -1 if address is None else address - load_address

    def branch(pc):
        value = word(pc)
        if value is None or value >> 24 != 0xea:
            return -1
        displacement = value & 0xffffff
        if displacement & 0x800000:
            displacement -= 0x1000000
        return pc + 8 + 4 * displacement

    def table(at):
        if at < 0 or at & 3 or at + 20 > len(image):
            return None
        source, target, size, zero, zero_size = struct.unpack_from("<5I", image, at)
        if (not size or not zero_size or (source | target | size | zero | zero_size) & 3
                or source < load_address or source + size > load_address + len(image)
                or target + size != zero
                or zero + zero_size > 0x100000000):
            return None
        return source, target, size, zero, zero_size

    root = branch(0)
    if root < 0 or root & 3 or image[root:root + len(_DUAL_STAGE_RESET)] != _DUAL_STAGE_RESET:
        return None, None
    # Every interworking return rejoins the matched ARM sequence.
    for gate in (root, root + 0x18, root + 0x30, root + 0x60, root + 0x78, root + 0x90):
        if (arm_literal(gate + 8) != load_address + gate + 0x15
                or arm_literal(gate + 12) != load_address + gate + 0x18):
            return None, "dual-stage-reset-return-unclosed"
    private = offset(arm_literal(root + 0x78)) - 1
    route = offset(arm_literal(root + 0x90)) - 1
    normal = branch(root + 0xb0)
    if (private & 3 or route & 1 or normal & 3 or min(private, route, normal) < 0
            or image[private:private + len(_DUAL_STAGE_PRIVATE)] != _DUAL_STAGE_PRIVATE
            or image[route:route + len(_DUAL_STAGE_ROUTE)] != _DUAL_STAGE_ROUTE
            or image[normal:normal + len(_DUAL_STAGE_NORMAL)] != _DUAL_STAGE_NORMAL):
        return None, "dual-stage-entry-unclosed"
    scatter = offset(arm_literal(normal + 0x20)) - 1
    if (scatter < 0 or scatter & 3
            or image[scatter:scatter + len(_DUAL_STAGE_SCATTER)] != _DUAL_STAGE_SCATTER
            or arm_literal(normal + 0x28) != load_address + normal + 0x35
            or arm_literal(normal + 0x2c) != load_address + normal + 0x38):
        return None, "dual-stage-scatter-unclosed"
    # Unlinked duplicates do not establish an additional memory owner.
    private_table = offset(literal(private + 0x50))
    if [literal(private + pc) for pc in (0x46, 0x48, 0x50, 0x64, 0x66)] != [
            load_address + private_table + field for field in (4, 8, 0, 12, 16)]:
        return None, "dual-stage-private-pointers-unclosed"
    private_fields = table(private_table)
    if private_fields is None or private_fields[2] != 8:
        return None, "dual-stage-private-table-unclosed"
    normal_table = offset(literal(scatter + 0xc))
    # Dereferenced pointers in all three copy/zero segments, including remainder.
    links = ((0xc, 0), (0xe, 8), (0x12, 4), (0x46, 8),
             (0x62, 16), (0x66, 12), (0x86, 16),
             (0xa0, 28), (0xa4, 20), (0xaa, 24), (0xd8, 28),
             (0xf4, 36), (0xf8, 32), (0x118, 36),
             (0x130, 40), (0x132, 48), (0x136, 44), (0x16a, 48),
             (0x186, 56), (0x18a, 52), (0x1aa, 56))
    if any(literal(scatter + pc) != load_address + normal_table + field for pc, field in links):
        return None, "dual-stage-normal-pointers-unclosed"
    fields = [table(normal_table + i * 20) for i in range(3)]
    if any(item is None for item in fields):
        return None, "dual-stage-normal-table-unclosed"
    if fields[0][3] + fields[0][4] != fields[1][1]:
        return None, "dual-stage-normal-span-disconnected"
    required = [(item[1], item[3] + item[4]) for item in fields]
    required.append((private_fields[1], private_fields[3] + private_fields[4]))
    if any(a < d and c < b for i, (a, b) in enumerate(required)
           for c, d in required[i + 1:]):
        return None, "dual-stage-write-overlap"
    bus_base = literal(private + 0x1a)
    commands = [literal(private + pc) for pc in (0x24, 0x28, 0x2c)]
    if (bus_base is None or bus_base + 0x20 > 0x100000000
            or not fields[0][3] <= bus_base + 0x1e < fields[0][3] + fields[0][4]
            or any(value is None for value in commands)
            or [value & 0xffff for value in commands] != [0xb2b2, 0xd0d0, 0xffff]
            or literal(private + 4) != 0x03000700 or literal(private + 0x12) != 0xfff):
        return None, "dual-stage-private-init-unclosed"
    stacks = [arm_literal(normal + pc) for pc in (4, 12, 24)]
    reset_stacks = [arm_literal(root + pc) for pc in (0x4c, 0x54, 0x5c)]
    if any(value is None or value & 3 or not private_fields[1] <= value <= required[-1][1]
           for value in stacks + reset_stacks):
        return None, "dual-stage-stack-unclosed"
    allowed = [(private_table, private_fields), *[(normal_table + i * 20, item) for i, item in enumerate(fields)]]
    if linker is None or not any(
            (linker.table_offset, linker.data_source, linker.data_target, linker.data_size,
             linker.bss_target, linker.bss_size) ==
            (at, item[0] - load_address, item[1], item[2], item[3], item[4])
            for at, item in allowed):
        return None, "dual-stage-linker-conflict"
    base = min(a for a, _ in required)
    end = max(b for _, b in required)
    if base & (PAGE - 1):
        return None, "dual-stage-base-unaligned"
    # Raw input may contain appended RAM snapshots. Only source-owned ROM
    # intervals, not the whole file length, must be disjoint from RAM.
    code = ((root, _DUAL_STAGE_RESET), (private, _DUAL_STAGE_PRIVATE),
            (route, _DUAL_STAGE_ROUTE), (normal, _DUAL_STAGE_NORMAL),
            (scatter, _DUAL_STAGE_SCATTER))
    rom_intervals = [(at, at + len(signature)) for at, signature in code]
    for at, signature in code:
        step = 4 if at in (root, normal) else 2
        for pc in range(at, at + len(signature), step):
            instruction = int.from_bytes(image[pc:pc + step], "little")
            if step == 4 and instruction & 0x0f7f0000 == 0x051f0000:
                pool = pc + 8 + (instruction & 0xfff)
                rom_intervals.append((pool, pool + 4))
            elif step == 2 and instruction & 0xf800 == 0x4800:
                pool = ((pc + 4) & ~3) + (instruction & 0xff) * 4
                rom_intervals.append((pool, pool + 4))
    for at, item in allowed:
        rom_intervals.extend(((at, at + 20),
                              (item[0] - load_address, item[0] - load_address + item[2])))
    # The last scatter copy has a separate, unclassified destination. Its ROM
    # source is still bounded; it does not contribute a RAM span.
    if [literal(scatter + pc) for pc in (0x1c6, 0x1c8, 0x1cc)] != [
            load_address + normal_table + field for field in (60, 68, 64)]:
        return None, "dual-stage-tail-pointers-unclosed"
    if normal_table + 72 > len(image):
        return None, "dual-stage-tail-source-unclosed"
    tail_source, _, tail_size = struct.unpack_from("<3I", image, normal_table + 60)
    if not tail_size or (tail_source | tail_size) & 3:
        return None, "dual-stage-tail-source-unclosed"
    rom_intervals.extend(((normal_table + 60, normal_table + 72),
                          (tail_source - load_address, tail_source - load_address + tail_size)))
    if any(not 0 <= begin < finish <= len(image) or load_address + finish > base
           for begin, finish in rom_intervals):
        return None, "dual-stage-rom-ram-overlap"
    size = 1 << (end - base - 1).bit_length()
    # Match the existing core 128 MiB allocation ceiling without importing
    # its legacy CPU-register dependency into static detection.
    if size > 0x08000000 or base + size > 0x100000000:
        return None, "dual-stage-allocation-overflow"
    return {"signature": "arm-thumb-dual-stage-scatter-ram-v1",
            "admission": "temporary-evidence-gated", "ram_base": base, "ram_size": size,
            "required_end": end, "rom_intervals": [[load_address + a, load_address + b] for a, b in rom_intervals], "required_spans": [list(span) for span in required],
            "stacks": stacks, "reset_stacks": reset_stacks, "reset_entry": load_address + root,
            "normal_entry": load_address + normal, "scatter_entry": load_address + scatter,
            "private_entry": load_address + private,
            "private_table": load_address + private_table,
            "normal_table": load_address + normal_table,
            "code_intervals": [[load_address + p, load_address + p + len(signature)] for p, signature in
                               ((root, _DUAL_STAGE_RESET), (private, _DUAL_STAGE_PRIVATE),
                                (route, _DUAL_STAGE_ROUTE), (normal, _DUAL_STAGE_NORMAL),
                                (scatter, _DUAL_STAGE_SCATTER))]}, None
