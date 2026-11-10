"""UART2 byte transmit readiness proved from the polling and data paths."""
from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match
from dataclasses import dataclass
from capstone import arm as a
from msm5xxx_emulator.detection.capabilities import Capability, Evidence, MachinePlan, ResourceClaim
from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for, source_prefix

STATUS = 0x030007C0
DATA = 0x030007B8
PULSE = 0x03000600
_UNCONDITIONAL = (a.ARM_CC_AL, a.ARM_CC_INVALID)

@dataclass(frozen=True, slots=True)
class TransmitProof:
    entry: CodeAddress
    read: CodeAddress
    write: CodeAddress
    branch: CodeAddress

def _path_events(function, path):
    sites = set(path)
    return tuple((access.operation, access.address, access.width, access.value if access.operation == 'write' else None) for pc in path for access in function.symbolic_accesses
        if access.instruction == pc and pc in sites and not any(literal.instruction == pc for literal in function.literals))

def _transmit_proof(facts, entry):
    function = facts.function(entry, budget=128, symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
    if not function.complete or function.calls or facts.unmodelled_memory(function) != ():
        return None
    ports = [access for access in function.accesses if access.operation == 'read' and access.address == STATUS and access.width == 1]
    writes = [access for access in function.symbolic_accesses if access.operation == 'write' and access.address == SymbolicValue.const(DATA) and access.width ==
        1 and access.value == SymbolicValue.arg(0)]
    if len(ports) != 1 or len(writes) != 1:
        return None
    read, write = ports[0].instruction, writes[0].instruction
    prefix = function.linear_path(entry, read)
    if prefix is None:
        return None
    for branch in function.instructions:
        ins = facts.decode(branch)
        if (ins is None or ins.id != a.ARM_INS_B or ins.cc in _UNCONDITIONAL or not ins.operands or ins.operands[0].type != a.ARM_OP_IMM or function.linear_path(read,
            branch) is None):
            continue
        predicate = facts.branch_predicate(function, branch)
        if (predicate is None or len(predicate.read_sources) != 1 or predicate.read_sources[0].site != read or predicate.read_sources[0].width != 1 or predicate.read_sources[0].signed
            or predicate.read_sources[0].address != SymbolicValue.const(STATUS)):
            continue
        ready = predicate.evaluate({read: 1})
        if (ready is None or any(predicate.evaluate({read: value}) != (ready if value & 1 else not ready) for value in range(256))):
            continue
        taken = CodeAddress(ins.operands[0].imm & 0xFFFFFFFF, entry.isa, entry.phase, entry.bank)
        fallthrough = CodeAddress(branch.address + ins.size, entry.isa, entry.phase, entry.bank)
        accepted = function.linear_path(taken if ready else fallthrough, write)
        waiting = function.linear_path(fallthrough if ready else taken, read)
        if accepted is None or waiting is None:
            continue
        one, zero = SymbolicValue.const(1), SymbolicValue.const(0)
        pulse = SymbolicValue.const(PULSE)
        if (_path_events(function, accepted) != (('write', pulse, 1, zero), ('write', SymbolicValue.const(DATA), 1, SymbolicValue.arg(0))) or _path_events(function,
            waiting[:-1]) != (('write', pulse, 1, one),)):
            continue
        # Every memory operation belongs to the proved transaction or its
        # supplied literal pools; unrelated accesses cannot borrow readiness.
        transaction = set(prefix) | set(accepted) | set(waiting) | set(function.linear_path(read, branch))
        if any(access.instruction not in transaction for access in function.symbolic_accesses):
            continue
        if any(access.predicate not in _UNCONDITIONAL for access in function.symbolic_accesses):
            continue
        prefix_events = _path_events(function, prefix)
        if _path_events(function, function.linear_path(read, branch)) != prefix_events:
            continue
        if prefix_events != (('read', SymbolicValue.const(STATUS), 1, None),):
            continue
        return TransmitProof(entry, read, write, branch)
    return None

def transmit_proofs(image: bytes) -> tuple[TransmitProof, ...]:
    facts = facts_for(image)
    def extract():
        calls = facts.call_candidates('thumb')
        entries = {target for _, target in calls}
        candidates = set()
        for access in facts.literal_access_candidates(((STATUS, STATUS + 1),), limit=0x02000000):
            if access.operation == 'read' and access.width == 1 and access.use.isa == 'thumb':
                candidates.update(target for target in entries if access.load.address - 0x80 <= target <= access.load.address)
        proofs = [_transmit_proof(facts, CodeAddress(entry)) for entry in sorted(candidates)]
        return tuple(proof for proof in proofs if proof is not None)
    return facts.memo('uart2-byte-transmit', (), extract)

def find_uart2_tx_ready_pc(image: bytes) -> int | None:
    proofs = transmit_proofs(image)
    reads = {proof.read.address for proof in proofs}
    return next(iter(reads)) if len(reads) == 1 else None

def uart2_tx_plan(original: bytes, loaded: bytes, config: object, *, claimed=False) -> MachinePlan:
    empty = MachinePlan((), (), (), ())
    size = getattr(config, 'flash_size', None)
    find_ready_poll_profile = _required_ready_poll_find_ready_poll_profile
    if (claimed or getattr(config, 'image_kind', None) != 'firmware' or any(type(getattr(config, name, None)) is not int or getattr(config, name) != 0 for name
        in ('load_address', 'image_offset', 'entry')) or getattr(config, 'uart_console', None) is not None or type(size) is not int or len(loaded) != size):
        return empty
    source = source_prefix(original, size)
    ready = getattr(config, 'ready_poll', None)
    if (not isinstance(ready, dict) or find_ready_poll_profile(source) != ready or (not fields_match(ready, (('signature', 'thumb-uart-csr-sr-rx-empty-v1'), ('status_address',
        50333620), ('mask', 8)))) or (ready.get('pulse_address') != PULSE)):
        return empty
    proof = transmit_proofs(source)
    if len(proof) != 1 or transmit_proofs(loaded) != proof:
        return empty
    proof = proof[0]
    # A driver caller must invoke both the independently proved CSR wait and
    # the transmit helper; a disconnected port-shaped routine is insufficient.
    facts = facts_for(source)
    wait_entries = set(ready.get('entries', ()))
    linked = []
    for site, target in facts.call_candidates('thumb'):
        if target not in wait_entries:
            continue
        caller = facts.function(CodeAddress(site), budget=2048)
        if not caller.complete or (CodeAddress(site), CodeAddress(target)) not in caller.calls:
            continue
        for transmit_site, callee in caller.calls:
            if callee != proof.entry:
                continue
            exits = set(caller.instructions) - {start for start, _ in caller.control_edges}
            if (exits and caller.dominates(CodeAddress(site), transmit_site) and all(caller.dominates(transmit_site, end) for end in exits)):
                linked.append(site)
                break
    if not linked:
        return empty
    evidence = (Evidence('uart2-transmit-path', (STATUS, DATA, PULSE), (proof.entry.address, proof.read.address, proof.write.address)), Evidence('uart2-driver-link',
        tuple(sorted(linked)), tuple(sorted(linked)), 'linkage'))
    capability = Capability('uart2-transmit', tuple(item.name for item in evidence), evidence,
                            properties=(('uart2-tx-ready', f'{proof.read.address:x}'),),
                            claims=(ResourceClaim('address', 'uart2-transmit', STATUS, STATUS + 1),))
    return MachinePlan((capability,), capability.properties, capability.claims, evidence)

def uart2_tx_property(original, loaded, config, *, claimed=False):
    properties = uart2_tx_plan(original, loaded, config, claimed=claimed).properties
    return ','.join(f'{name}={value}' for name, value in properties) or None

REQUIRES = {'_required_ready_poll_find_ready_poll_profile': ('ready_poll', 'find_ready_poll_profile')}
