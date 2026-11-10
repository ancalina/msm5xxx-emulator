"""Source-grounded ready-poll member recognition."""
from __future__ import annotations
import struct
from bisect import bisect_left, bisect_right
from capstone import CS_GRP_RET
from capstone import arm as a
from ...facts import CodeAddress, facts_for
from .helpers import _UART_CLOCK_RX_DRAIN, _UART_CLOCK_SETUP_PREFIX, _supplied

def _thumb_return(facts, site: CodeAddress) -> bool:
    instruction = facts.decode(site)
    if instruction is None:
        return False
    ops = instruction.operands
    return (instruction.group(CS_GRP_RET) or instruction.id == a.ARM_INS_BX and len(ops) == 1 and ops[0].type == a.ARM_OP_REG and ops[0].reg == a.ARM_REG_LR or
        instruction.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len (ops) == 2 and ops[0].type == a.ARM_OP_REG and ops[0].reg == a.ARM_REG_PC and ops[1].type == a.ARM_OP_REG
        and ops[1].reg == a.ARM_REG_LR or instruction.id == a.ARM_INS_POP and any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC for op in ops))

_PULSE_BRANCH_SHAPES = (
    # read, branch, branch target, return, branch condition
    (2, 6, 20, 20, a.ARM_CC_HS),
    (16, 20, 12, 24, a.ARM_CC_LO),
    (20, 24, 16, 28, a.ARM_CC_LO),
)

def _required_branch(facts, entry, branch_offset, target_offset, return_offset, condition):
    """Cheap necessary control-flow check before a whole-function analysis."""
    branch = CodeAddress(entry + branch_offset, 'thumb')
    returned = CodeAddress(entry + return_offset, 'thumb')
    instruction = facts.decode(branch)
    if (instruction is None or instruction.id != a.ARM_INS_B or instruction.cc != condition or len(instruction.operands) != 1 or instruction.operands[0].type !=
        a.ARM_OP_IMM or instruction.operands[0].imm != entry + target_offset or not _thumb_return(facts, returned)):
        return None
    return branch, returned, instruction

def _pulse_branch_shapes(facts, entry):
    shapes = {}
    for read, branch, target, returned, condition in _PULSE_BRANCH_SHAPES:
        decoded = _required_branch(facts, entry, branch, target, returned, condition)
        if decoded is not None:
            shapes[read] = decoded
    return shapes

def _control_branch_shape(facts, entry):
    """Cheap mandatory HS exit check for the source-PC-bound control class."""
    return _required_branch(facts, entry, 8, 38, 38, a.ARM_CC_HS)

def _closed_peripheral_accesses(facts, function):
    events = tuple(access for access in function.accesses if 0x03000000 <= access.address < 0x04000000)
    sites = {access.instruction for access in events}
    if any(access.address.kind != 'const' or (0x03000000 <= access.address.value < 0x04000000 and access.instruction not in sites) or (not 0x03000000 <= access.address.value
        < 0x04000000 and (access.operation != 'read' or facts.literal(access.instruction) is None)) for access in function.symbolic_accesses):
        return None
    unmodelled = facts.unmodelled_memory(function)
    frame = facts.stack_frame(function)
    stack_sites = {access.site for access in frame.accesses} if frame and frame.complete else set()
    if (unmodelled is None or set(unmodelled) - stack_sites or (unmodelled and (frame is None or not frame.balanced))):
        return None
    return events

def _semantic_pulse_member(facts, entry: int) -> dict[str, object] | None:
    """Bind one called Thumb byte-status loop to its exact native accesses."""
    shapes = _pulse_branch_shapes(facts, entry)
    if not shapes:
        return None
    owner = CodeAddress(entry, 'thumb')
    function = facts.function(owner, budget=128, symbolic_registers={})
    if (not function.complete or function.truncated or function.unresolved or function.calls or len(function.back_edges) != 1):
        return None
    peripheral = _closed_peripheral_accesses(facts, function)
    if peripheral is None:
        return None
    reads = tuple(access for access in peripheral if access.operation == 'read')
    writes = tuple(access for access in peripheral if access.operation == 'write')
    if (len(reads) != 1 or reads[0].width != 1 or len(writes) != 2 or any(access.width != 1 for access in writes) or writes[0].address != writes[1].address or (writes[0].value,
        writes[1].value) != (1, 0)):
        return None
    status, set_pulse, clear_pulse = reads[0], writes[0], writes[1]
    read_offset = status.instruction.address - entry
    set_offset = set_pulse.instruction.address - entry
    clear_offset = clear_pulse.instruction.address - entry
    shape = shapes.get(read_offset)
    expected_writes = ((12, 16) if read_offset == 2 else (read_offset - 4, read_offset - 2))
    if shape is None or (set_offset, clear_offset) != expected_writes:
        return None
    compact = read_offset == 2
    rotated = not compact
    branch, return_site, instruction = shape
    predicate = facts.branch_predicate(function, branch)
    if (predicate is None or predicate.operation != 'lsr' or predicate.shift != 4 or predicate.condition != (a.ARM_CC_HS if compact else a.ARM_CC_LO) or len(predicate.read_sources)
        != 1 or (read := predicate.read_sources[0]).site != status.instruction or read.width != 1 or read.address.kind != 'const' or read.address.value !=
        status.address or not function.dominates(status.instruction, branch) or function.linear_path(status.instruction, branch) is None):
        return None
    back_source, back_target = function.back_edges[0]
    back_source = CodeAddress(back_source, 'thumb', branch.phase, branch.bank)
    back_target = CodeAddress(back_target, 'thumb', branch.phase, branch.bank)
    fallthrough = CodeAddress(branch.address + instruction.size, 'thumb', branch.phase, branch.bank)
    if compact and (back_source.address, back_target.address) != (entry + 18, entry):
        return None
    if compact and (function.linear_path(fallthrough, set_pulse.instruction) is None or function.linear_path(set_pulse.instruction, clear_pulse.instruction) is
        None or function.linear_path(clear_pulse.instruction, back_source) is None or function.linear_path(back_target, status.instruction) is None):
        return None
    if rotated and ((back_source, back_target) != (branch, set_pulse.instruction) or function.linear_path(fallthrough, return_site) is None or function.linear_path(clear_pulse.instruction,
        status.instruction) is None):
        return None
    if (not function.linear_path(set_pulse.instruction, clear_pulse.instruction) or not function.dominates(set_pulse.instruction, clear_pulse.instruction)):
        return None
    status_address, pulse_address = status.address, set_pulse.address
    if (not 0x03000000 <= status_address < 0x04000000 or not 0x03000000 <= pulse_address < 0x04000000 or status_address & 3 or pulse_address & 3 or
        status_address == pulse_address):
        return None
    if compact:
        return { 'signature': 'thumb-lsrs-bhs-pulse-v1', 'status_address': status_address, 'mask': 0x08, 'pulse_address': pulse_address, 'entries':[entry], }
    return {'signature': 'thumb-lsrs-bcc-pulse-rotated-v1', 'admission': 'temporary-evidence-gated', 'status_address': status_address, 'mask': 0x08,
        'pulse_address': pulse_address, 'status_read_pc_offset': read_offset, 'pulse_set_pc_offset': set_offset, 'pulse_clear_pc_offset': clear_offset,
        'entries':[entry]}

def _semantic_pulse_members(image: bytes) -> list[dict[str, object]]:
    facts = facts_for(image)
    targets = _called_mmio_candidates(facts, 'thumb')
    return [profile for target in targets if (profile := _semantic_pulse_member(facts, target)) is not None]

def _called_mmio_candidates(facts, isa: str) -> tuple[int, ...]:
    """Limit function decoding to calls near validated MMIO literal xrefs."""
    def extract():
        accesses = facts.literal_access_candidates(((0x03000000, 0x04000000),), limit=1 << 32)
        sites = {item.use.address for item in accesses if item.use.isa == isa}
        sites.update(reference.instruction.address for reference in facts.literal_references_in(((0x03000000, 0x04000000),)) if reference.instruction.isa == isa)
        targets = sorted(target for _site, target in facts.call_candidates(isa))
        found = set()
        # Current wire profiles admit status reads no later than entry+20;
        # their literal base loads precede those reads. The control class also
        # has a source-site at +34, but its status-base xref is at +2.
        for site in sites:
            lo, hi = bisect_left(targets, site - 31), bisect_right(targets, site)
            found.update(targets[lo:hi])
        return tuple(sorted(found))
    return facts.memo('ready-poll-mmio-call-candidates', (isa,), extract)

def _find_compact_ready_poll_profile(image: bytes) -> dict[str, object] | None:
    candidates = [member for member in _semantic_pulse_members(image) if member['signature'] == 'thumb-lsrs-bhs-pulse-v1']
    contracts = {(member['status_address'], member['mask'], member['pulse_address']) for member in candidates}
    if not candidates or len(contracts) != 1:
        return None
    first = candidates[0]
    return {**first, 'entries':[entry for member in candidates for entry in member['entries']]}

def _find_rotated_ready_poll_profile(image: bytes) -> dict[str, object] | None:
    profiles = [member for member in _semantic_pulse_members(image) if member['signature'] == 'thumb-lsrs-bcc-pulse-rotated-v1']
    if not profiles:
        return None
    common = (profiles[0]['status_address'], profiles[0]['mask'], profiles[0]['pulse_address'])
    return (profiles[0] if len(profiles) == 1 else { 'signature': 'thumb-byte-ready-pulse-variants-v1', 'admission': 'temporary-evidence-gated',
        'status_address': common[0], 'mask': common[1], 'pulse_address': common[2], 'variants': profiles, })

def _find_rotated_uart_csr_sr_profile(image: bytes, rotated: dict[str, object]) -> dict[str, object] | None:
    """Close the mapped byte-UART clock setup and empty-RX drain together."""
    # This class has no incoming UART data. Accepted SR reads use the existing
    # UART idle response at all PCs, keeping CSR writes out of SR readback.
    # Other status maps retain the original ready-poll response.
    if rotated["status_address"] not in (0x030007B4, 0x030003B4):
        return None
    entry = rotated["entries"][0]
    calls = facts_for(image).call_candidates()
    called_entries = {target for _callsite, target in calls}
    candidates: list[int] = []
    cursor = 8
    while True:
        setup = image.find(_UART_CLOCK_RX_DRAIN, cursor)
        if setup < 0:
            break
        cursor = setup + 2
        read = setup + 0x28
        if setup & 1 or setup + 0x34 > len(image):
            continue
        producer = struct.unpack_from("<4H", image, setup - 8)
        if (producer[0] & 0xF800 != 0x4800 or producer[0] >> 8 & 7 != 2 or producer[1:] != (0x2034, 0x3270, 0x7010) or facts_for(image).thumb_literal_value(setup
            - 8, 2) != rotated["status_address"] - 4 - 0x70):
            continue
        words = struct.unpack_from("<12H", image, setup + 0x1C)
        if (words[0] & 0xF800 != 0x4800 or words[0] >> 8 & 7 != 1 or facts_for(image).thumb_literal_value(setup + 0x1C, 1) != rotated["pulse_address"] or words[1:]
            != (0x2300, 0xE002, 0x7A17, 0x7008, 0x700B, 0x7917, 0x087F, 0xD2F9, 0xBC80, 0xBC08, 0x4718)):
            continue
        helper = setup - 0x5E
        if (helper < 0 or helper not in called_entries or not _supplied(image, helper, setup + 0x34) or not _UART_CLOCK_SETUP_PREFIX.fullmatch(image[helper:setup
            - 8]) or facts_for(image).thumb_call_target(helper + 0x24) != entry or any(facts_for(image).thumb_literal_value(helper + offset, 1) != rotated["status_address"]
            - 4 - 0x70 for offset in (0x28, 0x38, 0x40, 0x4E)) or not any(target == helper and callsite >= 4 and facts_for(image).thumb_call_target(callsite - 4)
            == entry for callsite, target in calls) or not 0 < read - entry <= 0x1000):
            continue
        candidates.append(read)
    if len(candidates) != 1:
        return None
    return { **rotated, "signature": "thumb-uart-csr-sr-rx-empty-v1", "uart_rx_empty_read_pc_offset": candidates[0] - entry, }

def _find_control_ready_poll_profile(image: bytes) -> dict[str, object] | None:
    """Find called, source-closed byte-ready/pulse/control loops."""
    facts = facts_for(image)
    candidates = [member for target in _called_mmio_candidates(facts, 'thumb') if (member := _semantic_control_member(facts, target)) is not None]
    entries = [member['entry'] for member in candidates]
    contracts = {(member['status_address'], 0x08, member['pulse_address'], member['control_address'], 0x20) for member in candidates}
    if not entries or len(contracts) != 1:
        return None
    status_address, mask, pulse_address, control_address, control_value = contracts.pop()
    return { "signature": "thumb-byte-ready-pulse-control-v1", "admission": "temporary-evidence-gated", "status_address": status_address, "mask": mask,
        "pulse_address": pulse_address, "control_address": control_address, "control_value": control_value, "status_read_pc_offset": 4, "pulse_set_pc_offset":
        0x18, "pulse_clear_pc_offset": 0x1C, "control_pc_offset": 0x22, "entries": entries, }

def _semantic_control_member(facts, entry: int) -> dict[str, object] | None:
    """Derive the native control-loop contract from its executed MMIO events."""
    first_shape = _control_branch_shape(facts, entry)
    if first_shape is None:
        return None
    owner = CodeAddress(entry, 'thumb')
    function = facts.function(owner, budget=128, symbolic_registers={})
    if (not function.complete or function.truncated or function.unresolved or function.calls or len(function.back_edges) != 2):
        return None
    peripheral = _closed_peripheral_accesses(facts, function)
    if peripheral is None:
        return None
    reads = tuple(access for access in peripheral if access.operation == 'read')
    writes = tuple(access for access in peripheral if access.operation == 'write')
    if (len(reads) != 1 or reads[0].width != 1 or len(writes) != 3 or any(access.width != 1 for access in writes) or (writes[0].value, writes[1].value, writes[2].value)
        != (1, 0, 0x20) or writes[0].address != writes[1].address or writes[2].address in (reads[0].address, writes[0].address)):
        return None
    status, set_pulse, clear_pulse, control = reads[0], *writes
    # These offsets are part of the existing native source-PC contract. Their
    # instruction meaning and all peripheral operands are recovered from facts.
    if tuple(access.instruction.address - entry for access in (status, set_pulse, clear_pulse, control)) != (4, 24, 28, 34):
        return None
    branch, ret, first = first_shape
    poll_branch = CodeAddress(entry + 18, 'thumb', owner.phase, owner.bank)
    tail_branch = CodeAddress(entry + 36, 'thumb', owner.phase, owner.bank)
    repeat, tail = (facts.decode(site) for site in (poll_branch, tail_branch))
    if (repeat is None or repeat.id != a.ARM_INS_B or tail is None or tail.id != a.ARM_INS_B):
        return None
    if (function.back_edges != ((entry + 18, entry + 2), (entry + 36, entry + 2))):
        return None
    predicate = facts.branch_predicate(function, branch)
    if (predicate is None or predicate.operation != 'lsr' or predicate.shift != 4 or predicate.condition != a.ARM_CC_HS or len(predicate.read_sources) != 1 or (source
        := predicate.read_sources[0]).site != status.instruction or source.width != 1 or source.address.kind != 'const' or source.address.value != status.address):
        return None
    if (first.operands[0].imm != ret.address or repeat.operands[0].imm != entry + 2 or tail.operands[0].imm != entry + 2 or not function.linear_path(status.instruction,
        branch) or not function.linear_path(set_pulse.instruction, clear_pulse.instruction) or not function.linear_path(clear_pulse.instruction, control.instruction)
        or not function.dominates(set_pulse.instruction, clear_pulse.instruction) or not function.dominates(clear_pulse.instruction, control.instruction)):
        return None
    addresses = (status.address, set_pulse.address, control.address)
    if (any(not 0x03000000 <= address < 0x04000000 for address in addresses) or any(address & 3 for address in addresses) or len(set(addresses)) != 3):
        return None
    return {'entry': entry, 'status_address': status.address, 'pulse_address': set_pulse.address, 'control_address': control.address}
