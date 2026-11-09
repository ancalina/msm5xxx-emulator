"""Immutable observations produced by shared image analysis."""
from __future__ import annotations

from .values import CodeAddress
from .values import SymbolicValue
from capstone import arm as a

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Literal:
    instruction: CodeAddress
    pool: int
    register: int
    value: int

@dataclass(frozen=True, slots=True)
class MemoryAccess:
    instruction: CodeAddress
    operation: str
    address: int
    width: int
    value: int | None
    evidence: tuple[int, ...]
    predicate: int = a.ARM_CC_AL

@dataclass(frozen=True, slots=True)
class SymbolicAccess:
    instruction: CodeAddress
    operation: str
    address: SymbolicValue
    width: int
    value: SymbolicValue | None = None
    predicate: int = a.ARM_CC_AL

@dataclass(frozen=True, slots=True)
class Reference:
    value: int
    instruction: CodeAddress
    kind: str
    width: int = 4
    literal: int | None = None
    dereference: int | None = None

@dataclass(frozen=True, slots=True)
class ReachabilityFacts:
    references: tuple[Reference, ...]
    calls: tuple[CodeAddress, ...]
    entries: tuple[CodeAddress, ...]
    complete: bool
    entry_budget_exhausted: bool = False
    source_sites: tuple[tuple[CodeAddress, int, str], ...] = ()

@dataclass(frozen=True, slots=True)
class LiteralAccessCandidate:
    load: CodeAddress
    use: CodeAddress
    literal: int
    address: int
    width: int
    operation: str
    predicate: int

@dataclass(frozen=True, slots=True)
class BitTest:
    read: MemoryAccess
    mask: int
    branch: CodeAddress
    target: int
    when_set: bool

@dataclass(frozen=True, slots=True)
class CallSiteFacts:
    site: CodeAddress
    target: CodeAddress
    registers: tuple[tuple[int, int | SymbolicValue | None], ...]

@dataclass(frozen=True, slots=True)
class BranchCondition:
    """Conditional branch and source lineage of its live flag producer."""

    site: CodeAddress
    condition: int
    origin: SymbolicValue | None

@dataclass(frozen=True, slots=True)
class FunctionFacts:
    entry: CodeAddress
    instructions: tuple[CodeAddress, ...]
    calls: tuple[tuple[CodeAddress, CodeAddress], ...]
    literals: tuple[Literal, ...]
    accesses: tuple[MemoryAccess, ...]
    back_edges: tuple[tuple[int, int], ...]
    mode_stacks: tuple[tuple[int, int, int], ...]
    unresolved: tuple[CodeAddress, ...]
    complete: bool
    flow_targets: tuple[CodeAddress, ...] = ()
    symbolic_accesses: tuple['SymbolicAccess', ...] = ()
    control_edges: tuple[tuple[CodeAddress, CodeAddress], ...] = ()
    call_sites: tuple[CallSiteFacts, ...] = ()
    branch_conditions: tuple[BranchCondition, ...] = ()
    loop_frontiers: tuple[tuple[CodeAddress, CodeAddress], ...] = ()
    truncated: bool = False
    scope_exits: tuple[CodeAddress, ...] = ()
    scope_escapes: tuple[CodeAddress, ...] = ()
    initial_registers: tuple[tuple[int, int | SymbolicValue], ...] = ()
    scope_before: tuple[CodeAddress, ...] = ()

    def linear_path(self, start: CodeAddress, end: CodeAddress, *, allowed_calls=()):
        """Return a closed single-successor path, excluding opaque call effects.

        This proves only the recorded local path. It does not establish that
        reset reaches the function or that an entry condition takes this path.
        """
        instructions = set(self.instructions)
        if start not in instructions or end not in instructions:
            return None
        edges = {}
        for source, target in self.control_edges:
            edges.setdefault(source, set()).add(target)
        calls = {site for site, _ in self.calls} - set(allowed_calls)
        current, path, seen = start, [], set()
        while current not in seen and current in instructions:
            if (current.phase, current.bank) != (start.phase, start.bank):
                return None
            path.append(current)
            if current == end:
                return tuple(path)
            seen.add(current)
            successors = edges.get(current, ())
            if current in calls or len(successors) != 1:
                return None
            current = next(iter(successors))
        return None

    def dominates(self, source: CodeAddress, target: CodeAddress) -> bool:
        """Whether every path from this complete local entry passes source."""
        instructions = set(self.instructions)
        if (not self.complete or self.unresolved or self.entry not in instructions
                or source not in instructions or target not in instructions
                or any(a not in instructions or b not in instructions
                       for a, b in self.control_edges)):
            return False
        edges = {}
        for start, end in self.control_edges:
            edges.setdefault(start, set()).add(end)
        def reaches(blocked=None):
            pending, seen = [self.entry], set()
            while pending:
                current = pending.pop()
                if current == blocked or current in seen:
                    continue
                if current == target:
                    return True
                seen.add(current)
                pending.extend(edges.get(current, ()))
            return False
        return reaches() and not reaches(source)

    def peripheral_map(self, ranges=((0x03000000, 0x10000000),)):
        return tuple(use for use in self.accesses
                     if any(lo <= use.address and use.address + use.width <= hi
                            for lo, hi in ranges))

    @property
    def polls(self):
        # A loop-contained read is a poll candidate, not a ready-bit contract.
        return tuple(use for use in self.accesses if use.operation == 'read'
                     and any(target <= use.instruction.address <= branch
                             for branch, target in self.back_edges))

@dataclass(frozen=True, slots=True)
class ScatterCandidate:
    table: int
    source: int
    target: int
    size: int
    zero_target: int | None = None
    zero_size: int | None = None
