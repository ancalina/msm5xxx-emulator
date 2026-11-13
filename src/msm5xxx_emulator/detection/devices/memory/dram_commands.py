"""Source proof for externally addressed SDRAM command-mode probe pages."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


_MEMORY_CONTROLLER_MODE = 0x63800020
_EXTERNAL_WINDOW_BASE = 0x08000000
_PAGE_SIZE = 0x1000
_HIGH_ROM_BASE = 0xffff0000
_HIGH_ROM_SIZE = 0x4000


def _span(facts, function):
    addresses = [pc.address for pc in function.instructions]
    if not addresses:
        return None
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {
        "span": [min(addresses) - facts.base, end - min(addresses)],
        "extra_spans": [[literal.pool - facts.base, 4]
                        for literal in function.literals],
    }


def _reference_spans(facts, references):
    sites = sorted((site.address - facts.base, size)
                   for site, size, _ in references.source_sites)
    merged = []
    for begin, size in sites:
        end = begin + size
        if merged and begin <= merged[-1][0] + merged[-1][1] + 4:
            old_begin, old_size = merged[-1]
            merged[-1] = (old_begin, max(old_begin + old_size, end) - old_begin)
        else:
            merged.append((begin, size))
    return [{"span": [begin, size]} for begin, size in merged]


def _mov_immediate(instruction):
    """Decode an ARM data-processing immediate through Capstone operands."""
    if (instruction is None or instruction.id != a.ARM_INS_MOV
            or len(instruction.operands) < 2
            or instruction.operands[0].type != a.ARM_OP_REG
            or instruction.operands[1].type != a.ARM_OP_IMM):
        return None
    value = instruction.operands[1].imm
    if len(instruction.operands) >= 3:
        value &= 0xff
        if instruction.operands[2].type != a.ARM_OP_IMM:
            return None
        # Capstone exposes the encoded rotate as the effective bit count.
        rotate = instruction.operands[2].imm & 31
        value = ((value >> rotate) | (value << ((32 - rotate) & 31))) & 0xffffffff
    return instruction.operands[0].reg, value


def _dead_result(function, facts, load, register):
    """Require every local successor path to overwrite a dummy-load result."""
    nodes = set(function.instructions)
    successors = {}
    for source, target in function.control_edges:
        if source not in nodes or target not in nodes:
            return False
        successors.setdefault(source, set()).add(target)
    pending = list(successors.get(load, ()))
    if not pending:
        return False
    visited = set()
    while pending:
        pc = pending.pop()
        if pc in visited:
            continue
        visited.add(pc)
        instruction = facts.decode(pc)
        if instruction is None:
            return False
        try:
            reads, writes = instruction.regs_access()
        except (AttributeError, RuntimeError):
            return False
        if register in reads:
            return False
        if register in writes:
            continue
        next_pcs = successors.get(pc, ())
        if not next_pcs:
            # r2/r3 are scratch at an ordinary ARM return; the observed
            # command reads are not a returned value.
            if (a.ARM_REG_PC in writes
                    and register not in (a.ARM_REG_R0, a.ARM_REG_R1)):
                continue
            return False
        pending.extend(next_pcs)
    return True


def _probe_sequence(facts, function):
    """Find four adjacent immediate-addressed word reads with dead results."""
    instructions = {pc: facts.decode(pc) for pc in function.instructions}
    ordered = sorted(function.instructions, key=lambda pc: pc.address)
    paths = set()
    for start in ordered:
        first = instructions.get(start)
        if first is None or first.id != a.ARM_INS_MOV:
            continue
        cursor = start
        reads = []
        valid = True
        for _ in range(4):
            pcs = [CodeAddress(cursor.address + offset, cursor.isa, cursor.phase, cursor.bank)
                   for offset in (0, 4, 8)]
            setup, base_setup, load = (instructions.get(pc) for pc in pcs)
            left = _mov_immediate(setup)
            right = _mov_immediate(base_setup)
            if (left is None or right is None or load is None
                    or setup.cc != a.ARM_CC_AL or base_setup.cc != a.ARM_CC_AL
                    or load.cc != a.ARM_CC_AL
                    or load.id != a.ARM_INS_LDR or len(load.operands) != 2
                    or load.operands[0].type != a.ARM_OP_REG
                    or load.operands[1].type != a.ARM_OP_MEM):
                valid = False
                break
            dest, offset = left
            base_reg, base = right
            memory = load.operands[1].mem
            if (memory.base != base_reg or memory.index != dest or memory.disp != 0
                    or memory.scale != 1 or memory.lshift != 0
                    or load.operands[0].reg != dest):
                valid = False
                break
            target = (base + offset) & 0xffffffff
            load_pc = pcs[2]
            if not _dead_result(function, facts, load_pc, dest):
                valid = False
                break
            reads.append((load_pc, target))
            cursor = CodeAddress(cursor.address + 12, cursor.isa, cursor.phase, cursor.bank)
        if valid:
            path = function.linear_path(start, reads[-1][0])
            if path is not None and len(path) == 12:
                paths.add(tuple(reads))
    if len(paths) != 1:
        return None
    return next(iter(paths))


def _controller_mode_path(facts, function, reads):
    events = sorted((access for access in function.accesses
                     if access.width == 4 and access.address == _MEMORY_CONTROLLER_MODE
                     and access.operation in ("read", "write")),
                    key=lambda access: access.instruction.address)
    first_read, last_read = reads[0][0], reads[-1][0]
    paths = []
    for index in range(len(events) - 5):
        group = events[index:index + 6]
        if ([event.operation for event in group]
                != ["read", "write", "read", "write", "read", "write"]):
            continue
        if (group[0].instruction.address >= first_read.address
                or group[3].instruction.address >= first_read.address
                or group[-1].instruction.address <= last_read.address):
            continue
        path = function.linear_path(group[0].instruction, group[-1].instruction)
        if path is None or any(pc not in path for pc, _ in reads):
            continue
        paths.append(path)
    return paths[0] if len(paths) == 1 else None


def find_dram_command_profile(image: bytes, *, code_size=0x2000):
    """Derive page windows probed during a reset-linked SDRAM command sequence.

    Only closed, reset-reachable ARM code is considered. Reads below the
    external window are already covered by ordinary low memory; only aligned
    pages at or above the external window are returned.
    """
    if (not isinstance(image, bytes) or type(code_size) is not int
            or code_size <= 0 or code_size > _HIGH_ROM_SIZE or len(image) < 0x100):
        return None
    source = image[:min(code_size, len(image))]
    facts = facts_for(source, base=_HIGH_ROM_BASE)
    reset = facts.reset_references(CodeAddress(_HIGH_ROM_BASE, "arm"),
                                   limit_address=_HIGH_ROM_BASE + len(source))
    candidates = sorted({entry for entry in reset.calls if entry.isa == "arm"},
                        key=lambda entry: entry.address)
    matches = []
    for entry in candidates:
        function = facts.function(entry, budget=2048)
        if (function.truncated or not function.instructions
                or function.entry.isa != "arm"):
            continue
        reads = _probe_sequence(facts, function)
        if reads is None:
            continue
        mode_path = _controller_mode_path(facts, function, reads)
        if mode_path is None:
            continue
        external = sorted({address & ~(_PAGE_SIZE - 1) for _, address in reads
                           if address >= _EXTERNAL_WINDOW_BASE})
        if not external:
            continue
        windows = [{"base": base, "length": _PAGE_SIZE} for base in external]
        matches.append((function, reads, mode_path, windows))
    if len(matches) != 1:
        return None
    function, reads, mode_path, windows = matches[0]
    evidence = [*_reference_spans(facts, reset), _span(facts, function)]
    evidence = [item for item in evidence if item is not None]
    return {
        "windows": windows,
        "probe_reads": [address for _, address in reads],
        "evidence": evidence,
    }
