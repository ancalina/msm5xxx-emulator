"""Bounded data observations shared by storage profile predicates."""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Callable


@dataclass(frozen=True, slots=True)
class SectorTableFacts:
    address: int
    name_address: int
    sectors: tuple[int, ...]

    @property
    def count(self) -> int:
        return len(self.sectors)


@dataclass(frozen=True, slots=True)
class X16DescriptorFacts:
    address: int
    device_id: int
    reserved: int
    mode: int
    base_words: int
    usable_words: int
    callbacks: tuple[int, ...]

    @property
    def manufacturer(self) -> int:
        return self.device_id & 0xFFFF

    @property
    def device(self) -> int:
        return self.device_id >> 16


def u32_at(data: bytes, address: int) -> int | None:
    """Read one bounded little-endian word from supplied bytes."""
    if (type(address) is not int or address < 0
            or address > len(data) - 4):
        return None
    return struct.unpack_from('<I', data, address)[0]


def parse_u32_array(data: bytes, address: int, count: int, *,
                    max_count: int = 512) -> tuple[int, ...] | None:
    """Decode a bounded little-endian word array from supplied bytes."""
    if (type(address) is not int or type(count) is not int
            or address < 0 or not 0 <= count <= max_count
            or address + count * 4 > len(data)):
        return None
    return struct.unpack_from(f'<{count}I', data, address) if count else ()


def parse_sector_table(read_at: Callable[[int, int], bytes | None], address: int,
                       *, max_count: int = 512) -> SectorTableFacts | None:
    """Read one ``name,count,sectors[]`` table without crossing a hole/bound."""
    header = read_at(address, 8)
    if header is None:
        return None
    name_address, count = struct.unpack('<2I', header)
    if not 1 <= count <= max_count or address + 8 + count * 4 > 1 << 32:
        return None
    payload = read_at(address, 8 + count * 4)
    if payload is None:
        return None
    sectors = parse_u32_array(payload, 8, count, max_count=max_count)
    if sectors is None:
        return None
    return SectorTableFacts(address, name_address, sectors)


def sector_tables_before(read_at: Callable[[int, int], bytes | None],
                         descriptor: int, *, expected_name: int,
                         max_count: int = 512,
                         facts=None, cache_key=()) -> tuple[SectorTableFacts, ...]:
    """Find bounded count-prefixed sector arrays immediately before a descriptor."""
    if facts is not None:
        return facts.memo(
            'storage-sector-tables', (cache_key, descriptor, expected_name, max_count),
            lambda: sector_tables_before(
                read_at, descriptor, expected_name=expected_name,
                max_count=max_count,
            ),
        )
    found = []
    for count in range(1, max_count + 1):
        address = descriptor - 8 - count * 4
        if address < 0:
            break
        table = parse_sector_table(read_at, address, max_count=max_count)
        if table is not None and table.count == count and table.name_address == expected_name:
            found.append(table)
    return tuple(found)


def parse_x16_descriptor(data: bytes, offset: int, *, callback_count: int,
                         address: int = 0) -> X16DescriptorFacts | None:
    """Decode the common leading fields of a supplied x16 descriptor."""
    words = 5 + callback_count
    if offset < 0 or callback_count < 0 or offset + words * 4 > len(data):
        return None
    values = struct.unpack_from(f'<{words}I', data, offset)
    return X16DescriptorFacts(address, *values[:5], tuple(values[5:]))


def uniform_sector_size(sectors: tuple[int, ...], *, minimum: int,
                        maximum: int = 0x100000) -> int | None:
    """Return a supported uniform power-of-two size, else no geometry claim."""
    if not sectors:
        return None
    size = sectors[0]
    if (size < minimum or size > maximum or size & (size - 1)
            or any(item != size for item in sectors)):
        return None
    return size


def sector_regions(sectors: tuple[int, ...], *, minimum: int,
                   maximum: int = 0x100000,
                   max_regions: int = 4) -> tuple[tuple[tuple[int, int], ...] | None, str | None]:
    """Group ordered sector sizes while checking size and run alignment."""
    regions: list[tuple[int, int]] = []
    offset = 0
    for size in sectors:
        if size < minimum or size > maximum or size & (size - 1) or offset % size:
            return None, 'geometry-sector-mismatch'
        if regions and regions[-1][1] == size:
            count, _ = regions[-1]
            regions[-1] = count + 1, size
        else:
            regions.append((1, size))
        offset += size
    if not 1 <= len(regions) <= max_regions:
        return None, 'geometry-region-count-mismatch'
    return tuple(regions), None


def printable_name_end(data: bytes, start: int, bound: int,
                       *, max_length: int = 64, minimum_length: int = 4) -> int | None:
    """Return the NUL position for a bounded printable descriptor name."""
    if start < 0 or start >= bound or bound > len(data):
        return None
    end = data.find(b'\0', start, min(start + max_length, bound))
    if (end < start + minimum_length
            or any(not 0x20 <= byte <= 0x7E for byte in data[start:end])):
        return None
    return end
