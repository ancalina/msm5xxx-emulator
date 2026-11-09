"""Semantic AMD x16 command observations over shared function facts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from capstone import arm as a
from capstone.arm import ARM_CC_AL

from .facts import (
    CodeAddress, FirmwareFacts, FunctionFacts, SymbolicValue,
)
from .startup_facts import CopyConsumerProof


@dataclass(frozen=True, slots=True)
class NORDeviceProfile:
    window_base: int
    capacity: int
    manufacturer_id: int
    device_id: int


@dataclass(frozen=True, slots=True)
class NORWrite:
    instruction: CodeAddress
    offset: int
    value: int | None
    width: int
    predicate: int


@dataclass(frozen=True, slots=True)
class AMDProtocolSummary:
    writes: tuple[NORWrite, ...]
    operations: tuple[str, ...]
    complete: bool


@dataclass(frozen=True, slots=True)
class NORHardwareEvidence:
    """Compiled-compatible device evidence, separate from RTOS correctness."""

    profile: NORDeviceProfile
    callbacks: tuple[tuple[str, CodeAddress], ...]
    helpers: tuple[tuple[str, CodeAddress], ...]
    copy_consumer: CopyConsumerProof
    command_writes: tuple[tuple[str, tuple[NORWrite, ...]], ...] = ()


def prove_amd_x16_hardware_contract(
        device_id: int, sectors: tuple[int, ...],
        callback_entries: Mapping[str, CodeAddress], facts: FirmwareFacts,
        copy_consumer: CopyConsumerProof, *, window_base=0x00400000,
        window_size=0x00200000) -> NORHardwareEvidence | None:
    """Prove hardware capability from a copied descriptor and direct helpers.

    This selects the compiled-compatible device contract. It does not certify
    that every RTOS read/program path implements a correct flash operation.
    """
    profile = known_amd_x16_profile(device_id, sectors)
    required = ('read', 'program', 'erase')
    if (profile is None or profile.window_base != window_base
            or profile.capacity != window_size
            or any(name not in callback_entries for name in required)):
        return None

    formal = {getattr(a, f'ARM_REG_R{i}'): SymbolicValue.arg(i)
              for i in range(13)}
    formal[a.ARM_REG_SP] = SymbolicValue.arg(13)
    callback_facts = {}
    for name in required:
        entry = callback_entries[name]
        if entry.isa != 'thumb' or facts.decode(entry) is None:
            return None
        if name != 'read':
            function = facts.function(entry, budget=4096)
            if not function.complete:
                return None
            callback_facts[name] = function

    helpers = {}
    command_writes = {}
    for name, operation, callback in (
            ('bypass-enter', 'bypass-enter', 'program'),
            ('sector-erase', 'sector-erase', 'erase')):
        matches = []
        for _, target in callback_facts[callback].calls:
            if target.address < 0 or target.address >= len(facts.image):
                continue
            helper = facts.function(target, budget=4096,
                                    symbolic_registers=formal)
            summary = summarize_amd_x16(
                helper, window_base=window_base, window_size=window_size)
            events = tuple((item.offset, item.value, item.width, item.predicate)
                           for item in summary.writes)
            if operation == 'bypass-enter':
                expected = ((0xAAA, 0xAA), (0x554, 0x55), (0xAAA, 0x20))
            else:
                expected = ((0xAAA, 0xAA), (0x554, 0x55), (0xAAA, 0x80),
                            (0xAAA, 0xAA), (0x554, 0x55), (0x000, 0x30))
            exact_events = tuple((offset, value, 2, ARM_CC_AL)
                                 for offset, value in expected)
            if (helper.complete and summary.complete
                    and operation in summary.operations
                    and events == exact_events):
                matches.append((target, summary))
        if len({item[0] for item in matches}) != 1:
            return None
        target, summary = matches[0]
        if not summary.writes:
            return None
        helpers[name] = target
        command_writes[name] = summary.writes

    return NORHardwareEvidence(
        profile,
        tuple((name, callback_entries[name]) for name in required),
        tuple(sorted(helpers.items())),
        copy_consumer,
        tuple(sorted(command_writes.items())),
    )


def known_amd_x16_profile(device_id: int,
                          sectors: tuple[int, ...]) -> NORDeviceProfile | None:
    """Map an image descriptor code and uniform geometry to a profile."""
    if (type(device_id) is not int or device_id != 0x005F0004
            or len(sectors) != 14
            or any(type(size) is not int or size != 0x10000 for size in sectors)):
        return None
    return NORDeviceProfile(0x00400000, 0x00200000, 4, 95)


def _constant(value: SymbolicValue | int | None) -> int | None:
    if type(value) is int:
        return value & 0xFFFFFFFF
    if isinstance(value, SymbolicValue) and value.kind == 'const':
        return value.value if type(value.value) is int else None
    return None


def _argument_offset(value: SymbolicValue | int | None,
                     argument: int) -> tuple[int | None, int] | None:
    """Return (argument, offset) for a bounded linear address expression."""
    if isinstance(value, SymbolicValue):
        if value.kind == 'arg' and type(value.value) is int:
            return value.value, 0
        if value.kind == 'const' and type(value.value) is int:
            return None, value.value
        if value.kind == 'op' and value.value == 'add' and len(value.operands) == 2:
            left = _argument_offset(value.operands[0], argument)
            right = _argument_offset(value.operands[1], argument)
            if left is None or right is None:
                return None
            if left[0] is None and right[0] is None:
                return None, (left[1] + right[1]) & 0xFFFFFFFF
            if left[0] is None:
                return right[0], (left[1] + right[1]) & 0xFFFFFFFF
            if right[0] is None:
                return left[0], (left[1] + right[1]) & 0xFFFFFFFF
            return None
    return None


def _relative_offset(value: SymbolicValue | int | None, argument: int,
                     window_base: int) -> int | None:
    relation = _argument_offset(value, argument)
    if relation is None:
        return None
    arg, offset = relation
    if arg == argument:
        return offset
    if arg is None and window_base <= offset < window_base + 0x10000000:
        return offset - window_base
    return None


def summarize_amd_x16(function: FunctionFacts, *, base_argument: int = 0,
                       window_base: int = 0x00400000,
                       window_size: int = 0x00200000) -> AMDProtocolSummary:
    """Summarize closed AMD command writes within the device aperture."""
    literal_sites = {item.instruction for item in function.literals}
    symbolic = tuple(item for item in function.symbolic_accesses
                     if item.instruction not in literal_sites)
    writes: list[NORWrite] = []
    closed = function.complete

    for access in symbolic:
        relation = _argument_offset(access.address, base_argument)
        absolute = _constant(access.address)
        offset = _relative_offset(access.address, base_argument, window_base)
        if (access.operation == 'write'
                and ((isinstance(access.address, SymbolicValue)
                      and access.address.kind == 'unknown')
                     or relation is None and absolute is None)):
            closed = False
        if offset is None or not 0 <= offset < window_size:
            continue
        if access.operation == 'write':
            value = _constant(access.value)
            writes.append(NORWrite(access.instruction, offset, value,
                                   access.width, access.predicate))
            if value is None or access.width != 2 or access.predicate != ARM_CC_AL:
                closed = False

    writes.sort(key=lambda item: (item.instruction.address, item.instruction.isa,
                                  item.instruction.phase, item.instruction.bank))
    events = tuple((item.offset, item.value) for item in writes)
    ports_a = {item.offset for item in writes if item.value == 0xAA}
    ports_b = {item.offset for item in writes if item.value == 0x55}
    operations = []
    for port_a in ports_a:
        for port_b in ports_b - {port_a}:
            patterns = {
                'bypass-enter': ((port_a, 0xAA), (port_b, 0x55), (port_a, 0x20)),
                'sector-erase-setup': ((port_a, 0xAA), (port_b, 0x55),
                                       (port_a, 0x80), (port_a, 0xAA),
                                       (port_b, 0x55)),
            }
            for name, sequence in patterns.items():
                for start in range(len(events) - len(sequence) + 1):
                    segment = writes[start:start + len(sequence)]
                    path_closed = all(function.linear_path(
                        left.instruction, right.instruction) is not None
                        for left, right in zip(segment, segment[1:]))
                    if events[start:start + len(sequence)] == sequence and path_closed:
                        if name == 'sector-erase-setup':
                            terminal = start + len(sequence)
                            if (terminal < len(events)
                                    and events[terminal][1] == 0x30
                                    and function.linear_path(
                                        segment[-1].instruction,
                                        writes[terminal].instruction) is not None):
                                operations.append('sector-erase')
                        else:
                            operations.append(name)
                        break
    operations = list(dict.fromkeys(operations))
    return AMDProtocolSummary(tuple(writes), tuple(operations), closed)


