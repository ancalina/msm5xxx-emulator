"""Immutable mappings from supplied firmware bytes to guest addresses."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


ADDRESS_SPACE = 1 << 32
MAX_ZERO_FILL_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """A byte range in one supplied segment, with optional expected bytes."""

    segment: int
    begin: int
    end: int
    role: str = "code"
    expected: bytes = b""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected", bytes(self.expected))
        if self.segment < 0 or self.begin < 0 or self.end < self.begin:
            raise ValueError("invalid source span")
        if self.expected and len(self.expected) != self.end - self.begin:
            raise ValueError("expected bytes must cover the source span")


@dataclass(frozen=True, slots=True)
class Mapping:
    """Map a supplied segment range into one guest address view."""

    source_segment: int
    source_offset: int
    guest_base: int
    size: int
    phase: str = "reset"
    bank: str = "primary"
    kind: str = "direct"
    evidence: tuple[int, ...] = ()
    source_spans: tuple[SourceSpan, ...] = ()
    dependencies: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "source_spans", tuple(self.source_spans))
        object.__setattr__(self, "dependencies", tuple(self.dependencies))
        if (self.source_segment < 0 or self.source_offset < 0 or self.size <= 0
                or self.guest_base < 0 or self.guest_base + self.size > ADDRESS_SPACE):
            raise ValueError("invalid mapping bounds")
        if not self.phase or not self.bank or not self.kind:
            raise ValueError("mapping phase, bank, and kind must be named")
        if self.kind != "direct" and not self.evidence:
            raise ValueError("derived mappings require evidence")


@dataclass(frozen=True, slots=True)
class LoadOperation:
    """An evidenced copy, zero fill, or unknown write in one analysis phase."""

    kind: str
    source_address: int | None
    target: int
    size: int
    evidence: tuple[int, ...]
    phase: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if self.kind not in ("copy", "zero", "invalidate"):
            raise ValueError("load operation must be copy, zero, or invalidate")
        if self.size <= 0 or self.target < 0 or self.target + self.size > ADDRESS_SPACE:
            raise ValueError("load operation target bounds are invalid")
        if self.kind == "copy":
            if (self.source_address is None or self.source_address < 0
                    or self.source_address + self.size > ADDRESS_SPACE):
                raise ValueError("copy source bounds are invalid")
        elif self.source_address is not None:
            raise ValueError("non-copy operation must not have a source address")
        if not self.evidence:
            raise ValueError("load operation requires evidence")


@dataclass(frozen=True, slots=True)
class ImageView:
    """Supplied byte segments and their address mappings; holes stay absent."""

    segments: tuple[bytes, ...]
    mappings: tuple[Mapping, ...]
    origin: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "segments", tuple(bytes(data) for data in self.segments))
        object.__setattr__(self, "mappings", tuple(self.mappings))
        if not 0 <= self.origin < ADDRESS_SPACE:
            raise ValueError("origin outside 32-bit address space")
        for mapping in self.mappings:
            if (mapping.source_segment >= len(self.segments)
                    or mapping.source_offset + mapping.size
                    > len(self.segments[mapping.source_segment])):
                raise ValueError("mapping exceeds supplied segment")
            for span in mapping.source_spans:
                if (span.segment >= len(self.segments)
                        or span.end > len(self.segments[span.segment])):
                    raise ValueError("source span exceeds supplied segment")
        ordered = sorted(self.mappings,
                         key=lambda item: (item.phase, item.bank, item.guest_base))
        previous: dict[tuple[str, str], Mapping] = {}
        for mapping in ordered:
            key = (mapping.phase, mapping.bank)
            prior = previous.get(key)
            if prior is not None and mapping.guest_base < prior.guest_base + prior.size:
                raise ValueError("overlapping mappings in the same phase and bank")
            previous[key] = mapping

    def contiguous_ranges(self, *, phase: str = "reset", bank: str = "primary"):
        """Return supplied or materialised address intervals, excluding holes."""
        ranges = []
        for mapping in sorted((item for item in self.mappings
                               if item.phase == phase and item.bank == bank),
                              key=lambda item: item.guest_base):
            end = mapping.guest_base + mapping.size
            if ranges and ranges[-1][1] == mapping.guest_base:
                ranges[-1] = (ranges[-1][0], end)
            else:
                ranges.append((mapping.guest_base, end))
        return tuple(ranges)

    @classmethod
    def raw(cls, data: bytes, base: int = 0, *, phase: str = "reset",
            bank: str = "primary") -> ImageView:
        """Map one complete raw image at its supplied guest load address."""
        payload = bytes(data)
        mappings = ((Mapping(0, 0, base, len(payload), phase, bank,
                             source_spans=(SourceSpan(0, 0, len(payload), "supplied"),)),)
                    if payload else ())
        return cls((payload,), mappings, base)

    @classmethod
    def sparse(cls, segments: Iterable[Sequence[object]], *,
               origin: int | None = None, phase: str = "reset",
               bank: str = "primary") -> ImageView:
        """Map supplied ``(guest_base, bytes)`` segments without filling holes.

        A third tuple item may name an explicit source offset within the
        segment bytes; it is useful when a caller carries a larger backing
        buffer while mapping only one range.
        """
        payloads: list[bytes] = []
        mappings: list[Mapping] = []
        first: int | None = None
        for item in segments:
            if len(item) not in (2, 3):
                raise ValueError("sparse segment must have two or three items")
            guest_base, data = item[:2]
            source_offset = int(item[2]) if len(item) == 3 else 0
            payload = bytes(data)  # type: ignore[arg-type]
            if not payload:
                raise ValueError("sparse segments must not be empty")
            if source_offset < 0 or source_offset >= len(payload):
                raise ValueError("source offset outside segment")
            segment_index = len(payloads)
            payloads.append(payload)
            mappings.append(Mapping(
                segment_index, source_offset, int(guest_base),
                len(payload) - source_offset, phase, bank,
                source_spans=(SourceSpan(segment_index, source_offset, len(payload), "supplied"),),
            ))
            first = int(guest_base) if first is None else min(first, int(guest_base))
        if not payloads:
            raise ValueError("sparse image must contain a segment")
        return cls(tuple(payloads), tuple(mappings), first if origin is None else origin)

    def view(self, *, phase: str | None = None,
             bank: str | None = None) -> ImageView:
        """Return a view limited to the requested phase and/or bank."""
        selected = tuple(mapping for mapping in self.mappings
                         if (phase is None or mapping.phase == phase)
                         and (bank is None or mapping.bank == bank))
        return ImageView(self.segments, selected, self.origin)

    def normalized(self, image_offset: int = 0, size: int | None = None,
                   gap: tuple[int, int] | None = None,
                   base: int = 0) -> ImageView:
        """Trim a dense-image header and rebase supplied bytes to ``base``.

        ``gap`` is ``(offset, size)`` in the trimmed image. It shifts supplied
        bytes at and after that offset but contributes no segment bytes, so
        reads through the inserted range remain absent. Existing sparse holes,
        phase/bank labels, and source provenance are retained.
        """
        if image_offset < 0:
            raise ValueError("image offset cannot be negative")
        if size is not None and size < 0:
            raise ValueError("normalized size cannot be negative")
        if not 0 <= base < ADDRESS_SPACE:
            raise ValueError("normalized base outside 32-bit address space")
        gap_offset, gap_size = gap if gap is not None else (None, 0)
        if gap is not None and (gap_offset < 0 or gap_size <= 0):
            raise ValueError("normalized gap must have a nonnegative offset and positive size")

        source_start = self.origin + image_offset
        source_end = max((item.guest_base + item.size for item in self.mappings),
                         default=self.origin)
        available = max(0, source_end - source_start)
        inserted_gap = gap_size if gap is not None and gap_offset <= available else 0
        normalized_size = (available + inserted_gap) if size is None else size
        normalized_end = base + normalized_size
        if normalized_end > ADDRESS_SPACE:
            raise ValueError("normalized image exceeds 32-bit address space")

        def source_spans(item: Mapping, delta: int, length: int) -> tuple[SourceSpan, ...]:
            source_begin = item.source_offset + delta
            source_limit = source_begin + length
            spans = []
            for span in item.source_spans:
                begin = max(span.begin, source_begin)
                end = min(span.end, source_limit)
                if begin >= end:
                    continue
                expected = (span.expected[begin - span.begin:end - span.begin]
                            if span.expected else b"")
                spans.append(SourceSpan(span.segment, begin, end, span.role, expected))
            return tuple(spans)

        mappings: list[Mapping] = []
        for item in self.mappings:
            begin = max(item.guest_base, source_start)
            end = min(item.guest_base + item.size, source_end)
            if begin >= end:
                continue
            # Split at the insertion point so no mapping claims the unknown gap.
            if gap is None:
                pieces = [(begin, end, 0)]
            else:
                gap_address = source_start + gap_offset
                pieces = [(begin, min(end, gap_address), 0)]
                if end > gap_address:
                    pieces.append((max(begin, gap_address), end, gap_size))
            for piece_begin, piece_end, shift in pieces:
                if piece_begin >= piece_end:
                    continue
                relative = piece_begin - source_start
                guest_base = base + relative + shift
                length = piece_end - piece_begin
                if guest_base >= normalized_end:
                    continue
                if guest_base + length > normalized_end:
                    length = normalized_end - guest_base
                if length <= 0:
                    continue
                delta = piece_begin - item.guest_base
                mappings.append(Mapping(
                    item.source_segment, item.source_offset + delta,
                    guest_base, length, item.phase, item.bank, item.kind,
                    item.evidence, source_spans(item, delta, length),
                    item.dependencies,
                ))
        mappings.sort(key=lambda item: (item.phase, item.bank, item.guest_base))
        return ImageView(self.segments, tuple(mappings), base)

    def materialize(self, operations: Iterable[LoadOperation], *,
                    source_phase: str = "reset", phase: str = "post-copy",
                    bank: str = "primary",
                    max_zero_bytes: int = MAX_ZERO_FILL_SIZE) -> ImageView:
        """Build an evidenced post-copy view; source data remains immutable.

        Source-phase mappings are carried into the new phase first. Each
        ordered operation then replaces its destination, splitting prior
        mappings as needed. A copy may read bytes produced by an earlier
        operation in this phase. Numerically overlapping copy source and
        destination ranges are rejected because memmove direction is unknown.
        """
        if not source_phase or not phase or not bank or source_phase == phase:
            raise ValueError("source and destination phases must be distinct")
        if max_zero_bytes < 0:
            raise ValueError("zero-fill limit cannot be negative")
        if max_zero_bytes > MAX_ZERO_FILL_SIZE:
            raise ValueError("zero-fill limit exceeds 64 MiB")
        segments = list(self.segments)
        mappings = list(self.mappings) + [Mapping(
            mapping.source_segment, mapping.source_offset, mapping.guest_base,
            mapping.size, phase, bank, mapping.kind, mapping.evidence,
            mapping.source_spans, mapping.dependencies,
        ) for mapping in self.mappings
            if mapping.phase == source_phase and mapping.bank == bank]
        dependency_base = 1 + max((dependency for mapping in self.mappings
                                   for dependency in mapping.dependencies), default=-1)
        zero_bytes = 0

        def pieces(address: int, size: int, selected_phase: str):
            result = []
            cursor, end = address, address + size
            while cursor < end:
                hits = [item for item in mappings
                        if item.phase == selected_phase and item.bank == bank
                        and item.guest_base <= cursor < item.guest_base + item.size]
                if len(hits) != 1:
                    return None
                item = hits[0]
                take = min(end - cursor, item.guest_base + item.size - cursor)
                delta = cursor - item.guest_base
                result.append((item, delta, take))
                cursor += take
            return result

        def span_slice(span: SourceSpan, begin: int, size: int) -> SourceSpan:
            expected = span.expected[begin:begin + size] if span.expected else b""
            return SourceSpan(span.segment, span.begin + begin,
                              span.begin + begin + size, span.role, expected)

        def split_mapping(item: Mapping, begin: int, end: int) -> list[Mapping]:
            old_begin, old_end = item.guest_base, item.guest_base + item.size
            result = []
            for keep_begin, keep_end in ((old_begin, min(begin, old_end)),
                                         (max(end, old_begin), old_end)):
                if keep_begin >= keep_end:
                    continue
                delta = keep_begin - old_begin
                length = keep_end - keep_begin
                spans = tuple(span_slice(span, delta, length)
                              for span in item.source_spans
                              if span.end - span.begin == item.size)
                result.append(Mapping(
                    item.source_segment, item.source_offset + delta,
                    keep_begin, length, item.phase, item.bank, item.kind,
                    item.evidence, spans, item.dependencies,
                ))
            return result

        for operation_index, operation in enumerate(tuple(operations), dependency_base):
            if operation.phase is not None and operation.phase != phase:
                raise ValueError("load operation phase does not match materialized view")
            if operation.kind == "invalidate":
                new_mappings = []
            elif operation.kind == "zero":
                zero_bytes += operation.size
                if zero_bytes > max_zero_bytes:
                    raise ValueError("zero-fill materialization limit exceeded")
                segment = len(segments)
                segments.append(bytes(operation.size))
                new_mappings = [Mapping(
                    segment, 0, operation.target, operation.size, phase, bank,
                    "zero", operation.evidence,
                    (SourceSpan(segment, 0, operation.size, "zero"),),
                    (operation_index,),
                )]
            else:
                source = operation.source_address
                assert source is not None
                source_end, target_end = source + operation.size, operation.target + operation.size
                if source < target_end and operation.target < source_end:
                    raise ValueError("overlapping copy source and destination")
                source_pieces = pieces(source, operation.size, phase)
                # This phase already carries all source-phase mappings. A
                # hole now means unavailable or invalidated bytes, never an
                # invitation to recover stale bytes from the earlier phase.
                if source_pieces is None:
                    raise ValueError("copy source is missing or ambiguous")
                new_mappings = []
                target = operation.target
                for item, delta, take in source_pieces:
                    source_offset = item.source_offset + delta
                    spans = (tuple(span_slice(span, delta, take)
                                   for span in item.source_spans
                                   if span.end - span.begin == item.size)
                             or (SourceSpan(item.source_segment, source_offset,
                                            source_offset + take, "copy-source"),))
                    evidence = tuple(dict.fromkeys(item.evidence + operation.evidence))
                    dependencies = tuple(dict.fromkeys(item.dependencies + (operation_index,)))
                    new_mappings.append(Mapping(
                        item.source_segment, source_offset, target, take,
                        phase, bank, "copy", evidence, spans, dependencies,
                    ))
                    target += take
                if target != target_end:
                    raise ValueError("copy source is missing or ambiguous")

            begin, end = operation.target, operation.target + operation.size
            kept = []
            for item in mappings:
                if (item.phase == phase and item.bank == bank
                        and item.guest_base < end
                        and begin < item.guest_base + item.size):
                    kept.extend(split_mapping(item, begin, end))
                else:
                    kept.append(item)
            mappings = kept + new_mappings
        mappings.sort(key=lambda item: (item.phase, item.bank, item.guest_base))
        return ImageView(tuple(segments), tuple(mappings), self.origin)

    def with_copy(self, source_segment: int, source_offset: int, guest_base: int,
                  size: int, *, phase: str, bank: str,
                  evidence: Iterable[int]) -> ImageView:
        """Add a copied-byte mapping after recording its evidence sites."""
        spans = (SourceSpan(source_segment, source_offset, source_offset + size,
                            "copy-source"),)
        mapping = Mapping(source_segment, source_offset, guest_base, size,
                          phase, bank, "copy", tuple(evidence), spans)
        return ImageView(self.segments, self.mappings + (mapping,), self.origin)

    def source_offset(self, guest_address: int, size: int = 1, *,
                      phase: str | None = None,
                      bank: str | None = None) -> int | None:
        """Return the segment-local source offset for a directly mapped range."""
        if size <= 0:
            return None
        matches = [mapping for mapping in self.mappings
                   if mapping.guest_base <= guest_address
                   and guest_address + size <= mapping.guest_base + mapping.size
                   and (phase is None or mapping.phase == phase)
                   and (bank is None or mapping.bank == bank)]
        if len(matches) != 1:
            return None
        mapping = matches[0]
        return mapping.source_offset + guest_address - mapping.guest_base

    def original_address(self, address: int, size: int, *, phase: str,
                         source_phase: str = "reset", bank: str = "primary") -> int | None:
        """Trace a contiguous execution range back to one supplied address range.

        Segment identity, rather than equal byte values, establishes provenance.
        Aliases with multiple possible original addresses remain ambiguous.
        """
        if size <= 0 or not self.covers(address, size, phase=phase, bank=bank):
            return None
        cursor, original = address, None
        while cursor < address + size:
            item = next(mapping for mapping in self.mappings
                        if mapping.phase == phase and mapping.bank == bank
                        and mapping.guest_base <= cursor < mapping.guest_base + mapping.size)
            if item.kind == "zero":
                return None
            offset = item.source_offset + cursor - item.guest_base
            take = min(address + size - cursor, item.guest_base + item.size - cursor)
            sources = [mapping.guest_base + offset - mapping.source_offset
                       for mapping in self.mappings
                       if mapping.phase == source_phase and mapping.bank == bank
                       and mapping.kind == "direct"
                       and mapping.source_segment == item.source_segment
                       and mapping.source_offset <= offset
                       and offset + take <= mapping.source_offset + mapping.size]
            if len(sources) != 1:
                return None
            if original is None:
                original = sources[0]
            elif sources[0] != original + cursor - address:
                return None
            cursor += take
        return original

    def covers(self, guest_address: int, size: int, *,
               phase: str | None = None,
               bank: str | None = None) -> bool:
        """Return whether a range is supplied without materializing its bytes."""
        if size < 0 or guest_address < 0 or guest_address + size > ADDRESS_SPACE:
            return False
        if size == 0:
            return True
        matches = [mapping for mapping in self.mappings
                   if mapping.guest_base <= guest_address < mapping.guest_base + mapping.size
                   and (phase is None or mapping.phase == phase)
                   and (bank is None or mapping.bank == bank)]
        if len(matches) != 1:
            return False
        selected_phase, selected_bank = matches[0].phase, matches[0].bank
        address, end = guest_address, guest_address + size
        while address < end:
            current = [mapping for mapping in self.mappings
                       if mapping.phase == selected_phase
                       and mapping.bank == selected_bank
                       and mapping.guest_base <= address < mapping.guest_base + mapping.size]
            if len(current) != 1:
                return False
            address = min(end, current[0].guest_base + current[0].size)
        return True

    def read(self, guest_address: int, size: int = 1, *,
             phase: str | None = None,
             bank: str | None = None) -> bytes | None:
        """Read fully supplied bytes, returning ``None`` for holes/ambiguity."""
        if not self.covers(guest_address, size, phase=phase, bank=bank):
            return None
        if size == 0:
            return b""
        matches = [mapping for mapping in self.mappings
                   if mapping.guest_base <= guest_address < mapping.guest_base + mapping.size
                   and (phase is None or mapping.phase == phase)
                   and (bank is None or mapping.bank == bank)]
        mapping = matches[0]
        selected_phase, selected_bank = mapping.phase, mapping.bank
        output = bytearray()
        address = guest_address
        end = guest_address + size
        while address < end:
            current = [candidate for candidate in self.mappings
                       if candidate.phase == selected_phase
                       and candidate.bank == selected_bank
                       and candidate.guest_base <= address < candidate.guest_base + candidate.size]
            if len(current) != 1:
                return None
            candidate = current[0]
            take = min(end - address, candidate.guest_base + candidate.size - address)
            offset = candidate.source_offset + address - candidate.guest_base
            output.extend(self.segments[candidate.source_segment][offset:offset + take])
            address += take
        return bytes(output)
