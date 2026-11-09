"""Shared indexes queries; no device selection."""
from __future__ import annotations

from .arm import thumb_bl_target as thumb_call_target
from .values import CodeAddress
import re
import struct


_THUMB_LITERAL_ACCESS_CANDIDATE = re.compile(rb'(?=(.[\x48-\x4f]..))', re.S)
_ARM_LITERAL_ACCESS_CANDIDATE = re.compile(
    rb'(?=(..(?:\x1f|\x9f)(?:\x05|\x15|\x25|\x35|\x45|\x55|\x65|\x75'
    rb'|\x85|\x95|\xa5|\xb5|\xc5|\xd5|\xe5)))', re.S)


class FactIndexes:
    def _search_regions(self, phase, bank):
        def extract():
            return tuple((start, self.view.read(start, end - start,
                                                phase=phase, bank=bank))
                         for start, end in self.view.contiguous_ranges(
                             phase=phase, bank=bank))
        return self.memo('search-regions', (phase, bank), extract)

    def call_candidates(self, isa='thumb', *, phase='reset', bank='primary'):
        """Index direct-call candidates at their execution addresses."""
        if isa not in ('arm', 'thumb'):
            raise ValueError('unsupported instruction set')

        def extract():
            calls = []
            for base, data in self._search_regions(phase, bank):
                if isa == 'thumb':
                    for match in re.finditer(rb'(?=(.[\xf0-\xf7].[\xf8-\xff]))', data, re.S):
                        at = match.start()
                        if (base + at) & 1:
                            continue
                        target = thumb_call_target(data, at)
                        if target is not None:
                            calls.append((base + at, base + target))
                else:
                    for at in range((-base) & 3, len(data) - 3, 4):
                        word = struct.unpack_from('<I', data, at)[0]
                        if word >> 28 != 15 and word & 0x0F000000 == 0x0B000000:
                            delta = (word & 0xFFFFFF) << 2
                            calls.append((base + at, base + at + 8
                                          + (delta - (1 << 26) if delta & (1 << 25) else delta)))
            return tuple(calls)
        return self.memo('call-candidates', (isa, phase, bank), extract)

    def string_candidates(self, value: bytes, *, phase='reset', bank='primary'):
        """Index supplied byte candidates, including copied code and data."""
        if not value:
            raise ValueError('empty string anchor')
        pattern = re.compile(rb'(?=(' + re.escape(value) + rb'))', re.S)
        return self.memo('strings', (value, phase, bank), lambda:
                         tuple(base + match.start()
                               for base, data in self._search_regions(phase, bank)
                               for match in pattern.finditer(data)))

    def pointer_candidates(self, address: int, *, phase='reset', bank='primary'):
        return self.string_candidates(struct.pack('<I', address), phase=phase, bank=bank)

    def _literal_reference_index(self, phase, bank):
        def index():
            references = {}
            thumb = re.compile(rb'(?=(.[\x48-\x4f]))', re.S)
            for base, data in self._search_regions(phase, bank):
                sites = []
                for match in thumb.finditer(data):
                    at = match.start()
                    pc = base + at
                    if pc & 1:
                        continue
                    word = struct.unpack_from('<H', data, at)[0]
                    sites.append((CodeAddress(pc, 'thumb', phase, bank),
                                  ((pc + 4) & ~3) + (word & 255) * 4))
                for match in _ARM_LITERAL_ACCESS_CANDIDATE.finditer(data):
                    at = match.start()
                    pc = base + at
                    if pc & 3:
                        continue
                    word = struct.unpack_from('<I', data, at)[0]
                    displacement = word & 0xFFF
                    sites.append((CodeAddress(pc, 'arm', phase, bank),
                                  pc + 8 + (displacement if word & (1 << 23)
                                            else -displacement)))
                for pc, pool in sites:
                    raw = self.view.read(pool, 4, phase=phase, bank=bank)
                    if raw is not None:
                        references.setdefault(int.from_bytes(raw, 'little'), []).append(pc)
            return {value: tuple(sorted(sites, key=lambda pc: (pc.address, pc.isa)))
                    for value, sites in references.items()}

        return self.memo('literal-reference-index', (phase, bank), index)

    def literal_references(self, value: int, *, phase='reset', bank='primary'):
        """Return lexical ARM/Thumb pool xrefs; callers establish execution linkage."""
        if type(value) is not int or not 0 <= value < 1 << 32:
            return ()
        candidates = self._literal_reference_index(phase, bank)
        return self.memo('literal-references', (value, phase, bank), lambda:
                         tuple(literal for pc in candidates.get(value, ())
                               if (literal := self.literal(pc)) is not None
                               and literal.value == value))

    def literal_references_in(self, ranges, *, phase='reset', bank='primary'):
        """Query pool values in address intervals without decoding unrelated code."""
        ranges = tuple(sorted((lo, hi) for lo, hi in ranges
                              if type(lo) is int and type(hi) is int
                              and 0 <= lo < hi <= 1 << 32))
        def extract():
            index = self._literal_reference_index(phase, bank)
            return tuple(literal for value in sorted(index)
                         if any(lo <= value < hi for lo, hi in ranges)
                         for literal in self.literal_references(value, phase=phase, bank=bank))
        return self.memo('literal-references-in', (ranges, phase, bank), extract)

    def string_xrefs(self, value: bytes, *, phase='reset', bank='primary'):
        """Locate string-address pool loads without inferring a driver from text."""
        return tuple((address, literal)
                     for address in self.string_candidates(value, phase=phase, bank=bank)
                     for literal in self.literal_references(address, phase=phase, bank=bank))
