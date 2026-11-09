"""Evidence-based capability selection and immutable machine planning."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping


def _freeze(value: Any) -> Any:
    """Copy common containers into immutable values suitable for a plan."""
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, dict):
        return tuple(sorted(((_freeze(key), _freeze(item)) for key, item in value.items()),
                            key=lambda pair: repr(pair[0])))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, bytes, int, float, bool)):
        return value
    raise TypeError(f"unsupported mutable or opaque value: {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class Evidence:
    """A static fact extracted from image contents."""

    name: str
    value: Any
    locations: tuple[int, ...] = ()
    kind: str = "instruction"

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("evidence name must not be empty")
        if self.kind not in {"instruction", "literal", "linkage", "data"}:
            raise ValueError("evidence kind must identify static code or data")
        object.__setattr__(self, "value", _freeze(self.value))
        object.__setattr__(self, "locations", tuple(self.locations))
        if any(type(location) is not int or location < 0 for location in self.locations):
            raise ValueError("evidence locations must be non-negative addresses")


@dataclass(frozen=True, slots=True)
class ResourceClaim:
    """An exclusive hardware resource claim, optionally shared by contract."""

    kind: str
    resource: str
    start: int
    end: int
    address_space: str = "physical"
    phase: str = "runtime"
    mask: int | None = None
    shared_resource: str | None = None
    semantics: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"address", "gpio"}:
            raise ValueError("resource kind must be 'address' or 'gpio'")
        if (not self.resource or type(self.start) is not int or type(self.end) is not int
                or not 0 <= self.start < self.end <= 1 << 32):
            raise ValueError("resource claim must have a name and non-empty range")
        if self.kind == "gpio" and (type(self.mask) is not int or self.mask <= 0):
            raise ValueError("GPIO claims require a non-zero bit mask")
        if self.kind == "gpio" and self.mask.bit_length() > (self.end - self.start) * 8:
            raise ValueError("GPIO mask exceeds its register width")
        if self.kind == "address" and self.mask is not None:
            raise ValueError("address claims cannot carry a GPIO mask")
        if self.shared_resource is not None and not self.semantics:
            raise ValueError("shared resource claims require semantics")


@dataclass(frozen=True, slots=True)
class Capability:
    """One device/profile choice backed by all of its required static evidence."""

    name: str
    required_evidence: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    properties: tuple[tuple[str, Any], ...] = ()
    claims: tuple[ResourceClaim, ...] = ()
    priority: int = 0
    refines: tuple[str, ...] = ()
    alternative_group: str | None = None
    parameters: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.required_evidence:
            raise ValueError("capability requires a name and static evidence")
        object.__setattr__(self, "required_evidence", tuple(self.required_evidence))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "properties", _properties(self.properties))
        object.__setattr__(self, "parameters", _properties(self.parameters))
        object.__setattr__(self, "claims", tuple(self.claims))
        object.__setattr__(self, "refines", tuple(self.refines))
        if type(self.priority) is not int:
            raise ValueError("capability priority must be an integer")
        facts = {fact_name: {_freeze(item.value) for item in self.evidence
                             if item.name == fact_name}
                 for fact_name in self.required_evidence}
        missing = {name for name, values in facts.items() if not values}
        if missing:
            raise ValueError(f"capability lacks required evidence: {sorted(missing)}")
        ambiguous = {name for name, values in facts.items() if len(values) > 1}
        if ambiguous:
            raise ValueError(f"capability has ambiguous evidence: {sorted(ambiguous)}")
        unlocated = {name for name in self.required_evidence
                     if not any(item.name == name and item.locations for item in self.evidence)}
        if unlocated:
            raise ValueError(f"capability evidence lacks source locations: {sorted(unlocated)}")


@dataclass(frozen=True, slots=True)
class Decision:
    """Result of evaluating one rule or combining accepted capabilities."""

    status: str
    capability: Capability | None = None
    missing_evidence: tuple[str, ...] = ()
    reason: str | None = None
    plan: MachinePlan | None = None

    def __post_init__(self) -> None:
        if self.status not in {"accepted", "missing", "ambiguous", "conflict", "superseded"}:
            raise ValueError(f"unknown decision status: {self.status}")
        object.__setattr__(self, "missing_evidence", tuple(self.missing_evidence))
        if self.status == "accepted" and ((self.capability is None) == (self.plan is None)):
            raise ValueError("accepted decisions require exactly one capability or plan")


@dataclass(frozen=True, slots=True)
class MachinePlan:
    """Immutable aggregate of compatible capability properties and claims."""

    capabilities: tuple[Capability, ...]
    properties: tuple[tuple[str, Any], ...]
    claims: tuple[ResourceClaim, ...]
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        object.__setattr__(self, "properties", _properties(self.properties))
        object.__setattr__(self, "claims", tuple(self.claims))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        assignments: dict[str, Any] = {}
        for capability in self.capabilities:
            for name, value in capability.properties:
                if name in assignments and assignments[name] != value:
                    raise ValueError(f"conflicting plan property {name!r}")
                assignments[name] = value
        if _properties(assignments.items()) != self.properties:
            raise ValueError("plan properties do not match its capabilities")
        claims = [claim for capability in self.capabilities for claim in capability.claims]
        for index, claim in enumerate(claims):
            if any(_claims_conflict(claim, prior) for prior in claims[:index]):
                raise ValueError("plan contains conflicting resource claims")
        if tuple(claims) != self.claims:
            raise ValueError("plan claims do not match its capabilities")
        required = {(fact.name, fact.value, fact.locations, fact.kind)
                    for capability in self.capabilities for fact in capability.evidence}
        supplied = {(fact.name, fact.value, fact.locations, fact.kind) for fact in self.evidence}
        if not required <= supplied:
            raise ValueError("plan omits capability evidence")


def _properties(properties: Iterable[tuple[str, Any]]) -> tuple[tuple[str, Any], ...]:
    result = tuple(sorted((name, _freeze(value)) for name, value in properties))
    if any(not name for name, _ in result):
        raise ValueError("property names must not be empty")
    names = [name for name, _ in result]
    if len(set(names)) != len(names):
        raise ValueError("property names must be unique")
    return result


@dataclass(frozen=True, slots=True)
class CapabilityPredicate:
    """Registered Python evidence predicate and its explicit resolution metadata."""

    name: str
    prerequisites: tuple[str, ...]
    predicate: Callable[[Any], Decision | Capability | tuple[Capability, ...] | None]
    alternative_group: str | None = None
    priority: int = 0
    refines: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not callable(self.predicate):
            raise ValueError("predicate registration requires a name and callable")
        object.__setattr__(self, "prerequisites", tuple(self.prerequisites))
        object.__setattr__(self, "refines", tuple(self.refines))
        if type(self.priority) is not int:
            raise ValueError("predicate priority must be an integer")


@dataclass(frozen=True, slots=True)
class Resolution:
    """Resolved compatible plan plus diagnostics for every predicate proposal."""

    plan: MachinePlan
    decisions: tuple[Decision, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "decisions", tuple(self.decisions))


class CapabilityRegistry:
    """Run registered evidence predicates and resolve only related proposals."""

    def __init__(self) -> None:
        self._registrations: list[CapabilityPredicate] = []
        self._names: set[str] = set()

    def register(self, registration: CapabilityPredicate) -> None:
        if registration.name in self._names:
            raise ValueError(f"duplicate predicate registration: {registration.name}")
        self._names.add(registration.name)
        self._registrations.append(registration)

    def resolve(self, facts: Any, evidence: Iterable[Evidence] = ()) -> Resolution:
        if evidence:
            available = tuple(evidence)
        elif isinstance(facts, (tuple, list)) and all(isinstance(x, Evidence) for x in facts):
            available = tuple(facts)
        elif isinstance(facts, Mapping) and "evidence" in facts:
            available = tuple(facts["evidence"])
        else:
            available = tuple(getattr(facts, "evidence", ()))
        proposals: list[Decision] = []
        for registration in self._registrations:
            missing = tuple(name for name in registration.prerequisites
                            if not any(item.name == name for item in available))
            if missing:
                proposals.append(Decision("missing", missing_evidence=missing,
                                          reason=f"{registration.name}: prerequisites absent"))
                continue
            result = registration.predicate(facts)
            if result is None:
                proposals.append(Decision("missing", reason=f"{registration.name}: no match"))
                continue
            results = result if isinstance(result, tuple) else (result,)
            if isinstance(result, tuple) and not result:
                proposals.append(Decision("missing", reason=f"{registration.name}: no proposals"))
                continue
            for item in results:
                if isinstance(item, Capability):
                    item = Decision("accepted", capability=item)
                if not isinstance(item, Decision):
                    raise TypeError("predicate must return a Decision, Capability, tuple, or None")
                if item.status == "accepted":
                    capability = item.capability
                    if capability is None:
                        raise ValueError("predicate proposals must be accepted capabilities")
                    if capability.alternative_group not in (None, registration.alternative_group):
                        raise ValueError("predicate result contradicts its alternative group")
                    capability = replace(
                        capability,
                        priority=registration.priority,
                        refines=registration.refines,
                        alternative_group=registration.alternative_group,
                    )
                    item = replace(item, capability=capability)
                proposals.append(item)
        return resolve_proposals(proposals)


def resolve_proposals(decisions: Iterable[Decision]) -> Resolution:
    """Apply explicit refinement, then isolate conflicts to affected proposals."""
    decisions = list(decisions)
    accepted = [index for index, item in enumerate(decisions)
                if item.status == "accepted" and item.capability is not None]
    superseded: dict[int, int] = {}
    for strong_index in accepted:
        strong = decisions[strong_index].capability
        for weak_index in accepted:
            if strong_index == weak_index:
                continue
            weak = decisions[weak_index].capability
            if (weak.name in strong.refines
                    and strong.alternative_group is not None
                    and strong.alternative_group == weak.alternative_group
                    and strong.priority > weak.priority
                    and set(weak.required_evidence) <= set(strong.required_evidence)
                    and {(item.name, item.value) for item in weak.evidence
                         if item.name in weak.required_evidence}
                        <= {(item.name, item.value) for item in strong.evidence}
                    and set(dict(weak.properties)) <= set(dict(strong.properties))
                    and set(dict(weak.parameters)) <= set(dict(strong.parameters))
                    and all(any(_claim_covers(candidate, claim)
                                for candidate in strong.claims)
                            for claim in weak.claims)):
                superseded[weak_index] = strong_index
    for weak_index, strong_index in superseded.items():
        weak, strong = decisions[weak_index].capability, decisions[strong_index].capability
        decisions[weak_index] = Decision(
            "superseded", capability=weak,
            reason=f"refined by {strong.name} in {strong.alternative_group}")
    active = [index for index in accepted if index not in superseded]

    ambiguous: set[int] = set()
    by_group: dict[str, list[int]] = {}
    for index in active:
        group = decisions[index].capability.alternative_group
        if group is not None:
            by_group.setdefault(group, []).append(index)
    for indices in by_group.values():
        if len(indices) > 1:
            ambiguous.update(indices)
    for index in sorted(ambiguous):
        capability = decisions[index].capability
        decisions[index] = Decision("ambiguous", capability=capability,
                                    reason="multiple incomparable proposals in alternative group")
    active = [index for index in active if index not in ambiguous]

    conflicts: dict[int, set[int]] = {}
    for position, left_index in enumerate(active):
        left = decisions[left_index].capability
        for right_index in active[position + 1:]:
            right = decisions[right_index].capability
            property_conflict = any(
                name in dict(right.properties) and dict(right.properties)[name] != value
                for name, value in left.properties)
            claim_conflict = any(_claims_conflict(a, b)
                                 for a in left.claims for b in right.claims)
            if property_conflict or claim_conflict:
                conflicts.setdefault(left_index, set()).add(right_index)
                conflicts.setdefault(right_index, set()).add(left_index)
        if any(_claims_conflict(a, b) for i, a in enumerate(left.claims)
               for b in left.claims[:i]):
            conflicts.setdefault(left_index, set()).add(left_index)
    for index, peers in conflicts.items():
        capability = decisions[index].capability
        names = sorted({decisions[peer].capability.name for peer in peers})
        decisions[index] = Decision("conflict", capability=capability,
                                    reason="conflicts with: " + ", ".join(names))
    conflicted = set(conflicts)
    survivors = tuple(decisions[index] for index in active if index not in conflicted)
    combined = build_machine_plan(survivors)
    if combined.status != "accepted" or combined.plan is None:
        # Keep independent proposals usable even if a malformed input bypassed
        # pairwise checks; expose its diagnostic and return the surviving subset.
        fallback = []
        for decision in survivors:
            trial = build_machine_plan((*fallback, decision))
            if trial.status == "accepted":
                fallback.append(decision)
            else:
                decisions.append(Decision("conflict", capability=decision.capability,
                                          reason=trial.reason))
        combined = build_machine_plan(fallback)
    return Resolution(combined.plan, tuple(decisions))


def _claims_conflict(left: ResourceClaim, right: ResourceClaim) -> bool:
    if left.address_space != right.address_space:
        return False
    overlaps = left.start < right.end and right.start < left.end
    if overlaps and left.kind != right.kind:
        return True
    if (overlaps and left.kind == right.kind == "gpio"
            and left.mask is not None and right.mask is not None):
        # Masks describe little-endian register values. A byte access and a
        # word access can reserve the same physical pin at different offsets.
        if left.start <= right.start:
            overlaps = bool((left.mask >> (8 * (right.start - left.start))) & right.mask)
        else:
            overlaps = bool((right.mask >> (8 * (left.start - right.start))) & left.mask)
    if not overlaps:
        return False
    if left.phase != right.phase:
        # Analysis phase cannot reassign a live native resource.
        return True
    return not (left.shared_resource is not None
                and left.shared_resource == right.shared_resource
                and left.semantics == right.semantics)


def _claim_covers(candidate: ResourceClaim, required: ResourceClaim) -> bool:
    """Return whether a refinement retains one weaker resource reservation."""
    if (candidate.kind != required.kind or candidate.resource != required.resource
            or candidate.address_space != required.address_space
            or candidate.phase != required.phase
            or candidate.shared_resource != required.shared_resource
            or candidate.semantics != required.semantics):
        return False
    if candidate.kind == "gpio":
        return (candidate.start <= required.start and candidate.end >= required.end
                and candidate.mask is not None and required.mask is not None
                and (candidate.mask >> (8 * (required.start - candidate.start)))
                    & required.mask == required.mask)
    return candidate.start <= required.start and candidate.end >= required.end


def build_machine_plan(decisions: Iterable[Decision]) -> Decision:
    """Combine accepted capabilities, reporting missing, ambiguity, or conflicts."""
    decisions = tuple(decisions)
    unresolved = [item for item in decisions if item.status in {"ambiguous", "conflict"}]
    if unresolved:
        return unresolved[0]
    capabilities = tuple(item.capability for item in decisions
                         if item.status == "accepted" and item.capability is not None)
    planned = [item for item in decisions if item.status == "accepted" and item.plan is not None]
    if planned:
        if len(decisions) == 1:
            return planned[0]
        return Decision("conflict", reason="prebuilt plans cannot be combined with rule decisions")
    assignments: dict[str, Any] = {}
    claims: list[ResourceClaim] = []
    facts: dict[tuple[str, Any, tuple[int, ...], str], Evidence] = {}
    for capability in capabilities:
        # Revalidate the evidence invariant even for externally built decisions.
        available = {item.name for item in capability.evidence}
        if set(capability.required_evidence) - available:
            return Decision("missing", capability=capability,
                            missing_evidence=tuple(sorted(
                                set(capability.required_evidence) - available)))
        for name, value in capability.properties:
            value = _freeze(value)
            if name in assignments and assignments[name] != value:
                return Decision("conflict", capability=capability,
                                reason=f"property {name!r} has differing assignments")
            assignments[name] = value
        for claim in capability.claims:
            conflict = next((other for other in claims if _claims_conflict(claim, other)), None)
            if conflict is not None:
                return Decision("conflict", capability=capability,
                                reason=f"resource {claim.resource!r} overlaps an existing claim")
            claims.append(claim)
        for fact in capability.evidence:
            facts[(fact.name, _freeze(fact.value), fact.locations, fact.kind)] = fact
    plan = MachinePlan(capabilities, tuple(assignments.items()), tuple(claims),
                       tuple(facts.values()))
    return Decision("accepted", plan=plan)
