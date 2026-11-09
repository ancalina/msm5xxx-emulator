"""Immutable result types for startup relocation proofs."""
from __future__ import annotations

from dataclasses import dataclass

from .facts import CodeAddress
from .stack_facts import StackAccess

@dataclass(frozen=True, slots=True)
class StartupSideEffectWrite:
    """A concrete non-copy write retained for an owning device to claim."""

    instruction: CodeAddress
    address: int
    width: int
    value: int | None

@dataclass(frozen=True, slots=True)
class StartupStackWrite:
    """A concrete stack write killed by a later proved transfer."""

    instruction: CodeAddress
    address: int
    width: int
    register: int
    overwrite_edge: tuple[int, int]

@dataclass(frozen=True, slots=True)
class StartupProcedureProof:
    """Memory effects closed through return or an explicit pre-call snapshot."""

    entry: CodeAddress
    rows: tuple['StartupCopyRow', ...]
    loop_edges: tuple[tuple[int, int], ...]
    side_effect_writes: tuple[StartupSideEffectWrite, ...]
    stack_writes: tuple[StartupStackWrite, ...]
    stack_accesses: tuple[StackAccess, ...]
    helper_code_spans: tuple[tuple[int, int], ...] = ()
    unknown_stack_writes: tuple[StartupSideEffectWrite, ...] = ()
    completion: CodeAddress | None = None

@dataclass(frozen=True, slots=True)
class CopyConsumerProof:
    """Local instruction proof that a function consumes one copy/zero row."""

    table: int
    entry: CodeAddress
    copy_back_edge: tuple[int, int]
    zero_back_edge: tuple[int, int] | None
    fields: tuple[tuple[int, CodeAddress], ...]
    side_effect_writes: tuple[StartupSideEffectWrite, ...] = ()
    procedure: StartupProcedureProof | None = None

@dataclass(frozen=True, slots=True)
class StartupCopyRow:
    """A supplied three-word relocation row and optional independent zero row."""

    table: int
    source: int
    target: int
    size: int
    zero_table: int | None = None
    zero_target: int | None = None
    zero_size: int | None = None

    @property
    def zero_row(self):
        if self.zero_table is None:
            return None
        return self.zero_table, self.zero_target, self.zero_size

@dataclass(frozen=True, slots=True)
class CopyLoopTransfer:
    """One locally proven word loop with its statically evaluated exit."""

    back_edge: tuple[int, int]
    compare: CodeAddress
    cursor_register: int
    source_register: int | None
    initial_cursor: int
    bound: int
    stride: int
    iterations: int
    final_cursor: int
    initial_source: int | None = None
    final_source: int | None = None
    exit: CodeAddress | None = None

@dataclass(frozen=True, slots=True)
class OrderedCopyTransfer:
    """Ordered, contiguous copy and clear spans derived from loop transfers."""

    entry: CodeAddress
    copy_loops: tuple[CopyLoopTransfer, ...]
    clear_loops: tuple[CopyLoopTransfer, ...]
    copy_spans: tuple[tuple[int, int, int, int], ...]
    clear_spans: tuple[tuple[int, int], ...]
    copied_source: tuple[int, int]
    copied_target: tuple[int, int]
    cleared_target: tuple[int, int]
    completion: CodeAddress | None = None
    side_effect_writes: tuple[StartupSideEffectWrite, ...] = ()

@dataclass(frozen=True, slots=True)
class ResetPrefixProof:
    """A reset-root CFG links transfer completion to its normal continuation."""

    reset_entry: CodeAddress
    transfer_entry: CodeAddress
    completion: CodeAddress
    continuation_site: CodeAddress | None
    continuation_target: CodeAddress | None

@dataclass(frozen=True, slots=True)
class VectorCopyRow:
    """Candidate relocation row; it does not establish that copying ran."""
    table: int
    source: int
    target: int
    size: int
    end: int
    wrapper: int

    def source_address(self, guest_address: int, size: int = 1) -> int | None:
        """Map a candidate guest span to the claimed source offset.

        Callers must verify that the returned bytes are supplied in the source
        view before using them as evidence.
        """
        offset = guest_address - self.target
        if (type(guest_address) is not int or type(size) is not int
                or size <= 0 or offset < 0 or offset + size > self.size):
            return None
        return self.source + offset

