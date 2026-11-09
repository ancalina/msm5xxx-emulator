"""Compact, shared index for aligned raw memory-layout table candidates."""
from __future__ import annotations

from itertools import chain
from ..core.config import LinkerLayout

from array import array
from collections.abc import Iterator
import struct
from typing import Callable, Hashable, TypeVar

from .facts import FirmwareFacts, facts_for


_INDEX_LIMIT = 0x40000
_T = TypeVar("_T")


class LayoutFacts:
    """Cached raw aligned words and immutable query results for one image.

    The index is built on the first layout query. It stores one native array of
    decoded words rather than allocating Python tuples for every overlapping
    triple and quintuple. Candidate rows are cheap views over that shared index;
    device-specific validation remains with each caller.
    """

    def __init__(self, context: FirmwareFacts):
        self.context = context
        self.image = context.image
        self._words: array | None = None

    def _word_index(self) -> array:
        if self._words is None:
            # Candidate starts stop at 0x40000; the last start still needs its
            # complete five-word row in the compact word index.
            end = min(len(self.image), _INDEX_LIMIT + 20) & ~3
            self._words = array(
                "I", (row[0] for row in struct.iter_unpack("<I", self.image[:end]))
            )
        return self._words

    def words(self, offset: int, count: int) -> tuple[int, ...] | None:
        """Return aligned indexed words, or None for an unavailable span."""
        if (offset < 0 or count < 0 or offset & 3
                or offset + count * 4 > min(len(self.image), _INDEX_LIMIT)):
            return None
        if not self.context.view.covers(offset, count * 4, phase='reset', bank='primary'):
            return None
        start = offset // 4
        index = self._word_index()
        return tuple(index[start:start + count])

    def row(self, width: int, offset: int) -> tuple[int, ...] | None:
        """Return one aligned raw triple/quintuple including its file offset."""
        if (width not in (3, 5) or offset < 0 or offset & 3
                or offset > _INDEX_LIMIT):
            return None
        if offset + width * 4 > len(self.image):
            return None
        if not self.context.view.covers(offset, width * 4, phase='reset', bank='primary'):
            return None
        start = offset // 4
        index = self._word_index()
        if start + width > len(index):
            # Tables beyond the shared index are deliberately not in this
            # candidate set; callers may still read non-candidate words via
            # their existing bounded helpers.
            return None
        return (offset, *index[start:start + width])

    def rows(self, width: int, max_offset: int) -> Iterator[tuple[int, ...]]:
        """Iterate every aligned candidate row through max_offset inclusive."""
        if width not in (3, 5) or max_offset < 0:
            return
        last = min(_INDEX_LIMIT, len(self.image) - width * 4, max_offset) & ~3
        if last < 0:
            return
        for offset in range(0, last + 1, 4):
            row = self.row(width, offset)
            if row is not None:
                yield row

    def query(self, name: str, parameters: tuple[Hashable, ...],
              compute: Callable[[], _T]) -> _T:
        return self.context.memo('layout-' + name, parameters, compute)

    def select_rows(self, name: str, width: int, max_offset: int,
                    parameters: tuple[Hashable, ...], predicate) -> tuple[tuple[int, ...], ...]:
        """Cache a device-specific subset without duplicating raw word scans."""
        return self.query(
            f"rows:{name}", (*parameters, width, max_offset),
            lambda: tuple(row for row in self.rows(width, max_offset)
                          if predicate(row)),
        )


def layout_facts_for(image: bytes) -> LayoutFacts:
    """Attach layout indexing to the shared per-image firmware context."""
    if type(image) is not bytes:
        image = bytes(image)
    context = facts_for(image)
    return context.memo("layout-facts", (), lambda: LayoutFacts(context))


PAGE = 0x1000


def _image_offset(address: int, image_size: int, load_address: int) -> int | None:
    if load_address and load_address <= address < load_address + image_size:
        return address - load_address
    if 0 <= address < image_size:
        return address
    return None

def _contiguous_address_length_array(image: bytes, offset: int) -> bool:
    """Require nine page-aligned extents containing the candidate's three pairs."""
    pair_start = offset-4
    facts = layout_facts_for(image)
    for first in range(pair_start-6*8, pair_start+1, 8):
        if first < 0 or first+9*8 > len(image):
            continue
        words = facts.words(first, 18)
        if words is None:
            continue
        pairs = tuple(zip(words[::2], words[1::2]))
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
    facts = layout_facts_for(image)

    def extract() -> tuple[int, ...] | None:
        matches = []
        limit = min(len(image) - 20, 0x20000)
        preferred = facts.row(5, 0x10028)
        rows = facts.rows(5, limit)
        if preferred is not None and preferred[0] <= limit:
            ordered_rows = chain((preferred,),
                                 (row for row in rows if row[0] != 0x10028))
        else:
            ordered_rows = rows
        for row in ordered_rows:
            offset, source_address, target, size, bss, bss_size = row
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
                values = (offset, source, target, size, bss, bss_size)
                if required_span is None:
                    return values
                address, length = required_span
                if length <= size and target <= address <= target + size - length:
                    matches.append(values)
                    if len(matches) > 1:
                        return None
        return matches[0] if matches else None

    values = facts.query("linker-layout", (load_address, required_span), extract)
    return LinkerLayout(*values) if values is not None else None
