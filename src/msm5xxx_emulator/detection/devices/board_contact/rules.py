"""Local evidence that a halfword contact selects the display-open event."""
from dataclasses import dataclass
import struct
from ....core.config import BoardStatusInput
from ...facts import facts_for
from .clock import periodic_caller
from ...startup_entry import startup_copy_contexts, startup_load_operations
from capstone import arm as a
from ...facts import CodeAddress, SymbolicValue, evaluate_value

@dataclass(frozen=True, slots=True)
class ContactProof:
    entry: CodeAddress
    read: CodeAddress
    address: int
    mask: int
    state: int
    event_call: CodeAddress
    event_sink: CodeAddress
    display_guard: CodeAddress

def _constant_origins(facts, function, use, register):
    origins = facts.register_origins(function, use, register)
    if not origins:
        return None
    values = set()
    for site, reg in origins:
        ins = facts.decode(site)
        if (ins.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS) or len(ins.operands) != 2 or ins.operands[1].type != a.ARM_OP_IMM):
            return None
        values.add(ins.operands[1].imm & 0xffffffff)
    return values

def _mandatory_writes(function, value):
    exits = set(function.instructions) - {source for source, _ in function.control_edges}
    if not exits:
        return set()
    return {access.address.value for access in function.symbolic_accesses if access.operation == 'write' and access.width == 1 and access.address.kind ==
        'const' and access.value == SymbolicValue.const(value) and all(function.dominates(access.instruction, end) for end in exits)}

def _panel_writer_call(facts, entry):
    """Find a direct closed command/data writer in the guarded routine."""
    body = facts.function(entry, budget=1024)
    for site, target in body.calls:
        leaf = facts.function(target, budget=64)
        ports = {(item.address, item.width) for item in leaf.accesses if item.operation == 'write'}
        if (leaf.complete and not leaf.calls and facts.unmodelled_memory(leaf) == () and len(ports) == 2):
            (command, width), (data, other_width) = sorted(ports)
            if (width == other_width == 2 and data == command + 2 and 0x02000000 <= command <= 0x027ffffc):
                return site
    return None

def _display_guard(facts, flag, *, phase='reset', bank='primary'):
    """Close only the flag guard and its balanced early-return path."""
    pc = lambda address: CodeAddress(address, 'thumb', phase, bank)
    for literal in facts.literal_references(flag, phase=phase, bank=bank):
        if literal.instruction.isa != 'thumb':
            continue
        load = literal.instruction.address
        for at in range(load + 2, load + 16, 2):
            branch = pc(at)
            ins = facts.decode(branch)
            if (ins is None or ins.id != a.ARM_INS_B or ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                continue
            edges = (pc(ins.operands[0].imm), pc(at + ins.size))
            for entry in range(load - 2, max(facts.base - 1, load - 16), -2):
                first = facts.decode(pc(entry))
                if (first is None or first.id != a.ARM_INS_PUSH or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR for op in first.operands)):
                    continue
                prefix = facts.function_region(pc(entry), stop_before=edges, budget=32)
                predicate = facts.branch_predicate(prefix, branch)
                if (not prefix.complete or predicate is None or len(predicate.read_sources) != 1):
                    continue
                source = predicate.read_sources[0]
                if (source.width != 1 or source.signed or source.address != SymbolicValue.const(flag)):
                    continue
                zero = predicate.evaluate({source.site: 0})
                if zero is None or any(predicate.evaluate({source.site: value}) == zero for value in range(1, 256)):
                    continue
                normal, blocked = edges if zero else edges[::-1]
                tail = facts.function(blocked, budget=32)
                returns = set(tail.instructions) - {source for source, _ in tail.control_edges}
                if not tail.complete or tail.calls or len(returns) != 1:
                    continue
                end = next(iter(returns))
                if (tail.linear_path(blocked, end) is None or any(access.operation == 'write' for access in tail.symbolic_accesses)):
                    continue
                region = facts.function_region(pc(entry), stop_before=(normal, end), budget=64, symbolic_registers={a.ARM_REG_LR: SymbolicValue.arg(14)})
                frame = facts.stack_frame(region)
                end_ins = facts.decode(end)
                return_register = (end_ins.operands[0].reg if end_ins.id == a.ARM_INS_BX and end_ins.operands and end_ins.operands[0].type == a.ARM_OP_REG else
                    None)
                if (not region.complete or region.calls or frame is None or frame.offset_at(end) != 0 or return_register is None or facts.register_value(region,
                    end, return_register, follow_stack= True) != SymbolicValue.arg(14)):
                    continue
                unknown = facts.unmodelled_memory(region)
                if unknown is None or any(facts.decode(site).id not in (a.ARM_INS_PUSH, a.ARM_INS_POP) for site in unknown):
                    continue
                reads = [access for access in region.symbolic_accesses if not any(item.instruction == access.instruction for item in region.literals)]
                if len(reads) == 1 and reads[0].operation == 'read' and reads[0].instruction == source.site:
                    if _panel_writer_call(facts, pc(entry)) is not None:
                        return pc(entry)
    return None

def contact_semantics(facts, entry, descriptor, pointer):
    """Check local input/state/event/display linkage; pointer provenance is external."""
    pc = lambda address: CodeAddress(address, entry.isa, entry.phase, entry.bank)
    function = facts.function(entry, budget=1024, symbolic_registers={})
    frame = facts.stack_frame(function)
    if not function.complete or frame is None or not frame.balanced:
        return None
    read = pc(entry.address + 6)
    source = pc(entry.address + 4)
    ins = facts.decode(read)
    if (ins is None or ins.id != a.ARM_INS_LDRH or ins.operands[0].type != a.ARM_OP_REG):
        return None
    register = ins.operands[0].reg
    unknown = facts.unmodelled_memory(function)
    if (unknown is None or any(facts.decode(site).id not in (a.ARM_INS_PUSH, a.ARM_INS_POP) for site in unknown) or any(not facts.view.covers(target.address, 2,
        phase=target.phase, bank=target.bank) for _, target in function.calls)):
        return None
    literal_sites = {item.instruction for item in function.literals}
    for access in function.symbolic_accesses:
        if access.instruction in literal_sites or access.instruction == read:
            continue
        if (access.predicate not in (a.ARM_CC_AL, a.ARM_CC_INVALID) or access.address.kind != 'const' or not 0x01000000 <= access.address.value <= 0x02000000 -
            access.width):
            return None
    for branch in function.instructions:
        if not read.address < branch.address < read.address + 24:
            continue
        predicate = facts.branch_predicate(function, branch)
        if predicate is None or {s.site for s in predicate.read_sources} != {source, read}:
            continue
        sources = {s.site: s for s in predicate.read_sources}
        if (sources[source].address != SymbolicValue.const(descriptor + 0x24) or sources[source].width != 4 or sources[read].width != 2 or sources[source].signed
            or sources[read].signed or evaluate_value(sources[read].address, reads={source: pointer}) != pointer):
            continue
        zero = predicate.evaluate({source: pointer, read: 0})
        bits = [1 << bit for bit in range(16) if predicate.evaluate({source: pointer, read: 1 << bit}) != zero]
        if zero is None or len(bits) != 1:
            continue
        mask = bits[0]
        if any(predicate.evaluate({source: pointer, read: value}) != (not zero if value & mask else zero) for value in range(65536)):
            continue
        paths = tuple(facts.function(pc(read.address + ins.size), budget=1024, initial_registers={register: value}, symbolic_registers={}) for value in (mask, 0))
        high, low = paths
        if not high.complete or not low.complete:
            continue
        fields = _mandatory_writes(high, 0) & _mandatory_writes(low, 1)
        if len(fields) != 1:
            continue
        field = next(iter(fields))
        events = []
        for site, target in high.calls:
            if ((site, target) in low.calls and _constant_origins(facts, high, site, a.ARM_REG_R0) == {0x5f} and _constant_origins(facts, low, site, a.ARM_REG_R0)
                == {0x60}):
                consumer = facts.function(target, budget=1024, symbolic_registers={})
                if consumer.complete and any(access.operation == 'read' and access.width == 1 and access.address == field for access in consumer.accesses):
                    events.append((site, target))
        if len(events) != 1:
            continue
        guard = _display_guard(facts, field, phase=entry.phase, bank=entry.bank)
        if guard is None:
            continue
        site, target = events[0]
        return ContactProof(entry, read, pointer, mask, field, site, target, guard)
    return None

def _copy_views(facts):
    def extract():
        contexts = startup_copy_contexts(facts, target_ranges=((0x01000000, 0x02000000), (0x03800000, 0x03a00000)), zero_ranges=((0x01000000, 0x02000000),),
            extra_write_ranges=((0x03000600, 0x03000780),))
        views = []
        for context in contexts:
            destinations, sources = [],[]
            for row, proof in context.rows:
                destinations.append((row.target, row.target + row.size))
                sources.append((row.source, row.source + row.size))
                if row.zero_row is not None:
                    destinations.append((row.zero_target, row.zero_target + row.zero_size))
            # Disjoint transfers have the same result in every execution order.
            if (any(a < d and c < b for i, (a, b) in enumerate(destinations) for c, d in destinations[i + 1:]) or any(a < d and c < b for a, b in destinations
                for c, d in sources)):
                continue
            try:
                views.append(facts.after_loads(startup_load_operations(context.rows)))
            except ValueError:
                continue
        return tuple(views)
    return facts.memo('contact-copy-views', (), extract)

def indirect_scanner_at(image: bytes, start: int) -> tuple[BoardStatusInput | None, str]:
    """Select the source-proven level that leaves a periodic display gate open."""
    if (type(start) is not int or start < 0 or start & 1 or start + 12 > len(image) or image[start + 4:start + 8] != b'\x40\x6a\x00\x88'):
        return None, ''
    saved = struct.unpack_from('<H', image, start + 2)[0]
    if saved & 0xff00 != 0xb500:
        return None, ''
    facts = facts_for(image)
    literal = facts.literal(CodeAddress(start))
    if (literal is None or literal.register != a.ARM_REG_R0 or not 0x01000000 <= literal.value <= 0x02000000 - 0x28):
        return None, ''
    descriptor = literal.value
    profiles = set()
    for loaded in _copy_views(facts):
        source = loaded.view.original_address(descriptor + 0x24, 4, phase='post-copy')
        raw = loaded.view.read(descriptor + 0x24, 4, phase='post-copy', bank='primary')
        if source is None or raw is None:
            continue
        pointer = struct.unpack('<I', raw)[0]
        if pointer & 1 or not 0x03000000 <= pointer <= 0x03800000 - 2:
            continue
        proof = loaded.memo('indirect-contact', (start, descriptor, pointer), lambda: contact_semantics(loaded, CodeAddress(start, phase='post-copy'),
            descriptor, pointer))
        if proof is not None:
            profiles.add(BoardStatusInput(proof.address, proof.mask, proof.mask))
    if len(profiles) != 1 or not periodic_caller(image, start):
        return None, 'indirect-scanner-copy-or-contact-unclosed'
    return next(iter(profiles)), ''
