"""Semantic evidence for the synchronous UART console hardware contract."""
from __future__ import annotations
from capstone import arm as a
from ...facts import CodeAddress, SymbolicValue, facts_for

def _typed_tx_evidence(image, calls, base):
    """Prove a forwarded input byte is sent only along the ready-bit branch."""
    facts = facts_for(image)
    def extract():
        targets = {target for _site, target in calls if 0 <= target < len(image) and not target & 1}
        # Discover only callees near a literal-backed access to this UART's
        # ISR/FIFO. This keeps per-function analysis bounded on large images.
        accesses = facts.literal_access_candidates(((base + 0x14, base + 0x15), (base + 0x0C, base + 0x0D)), limit=len(image))
        candidates = set()
        for access in accesses:
            if access.load.isa != 'thumb':
                continue
            candidates.update(target for target in targets if target <= access.load.address and access.load.address - target <= 0x100)
        def events(function, path):
            sites = set(path)
            return tuple((access.operation, access.address, access.width, access.value if access.operation == 'write' else None) for pc in path for access in
                function.symbolic_accesses if pc in sites and access.instruction == pc and not any(item.instruction == pc for item in function.literals))
        proved = {}
        def argument_derived(value):
            if not isinstance(value, SymbolicValue):
                return False
            if value.kind == 'arg':
                return True
            if value.kind == 'const':
                return True
            return (value.kind == 'op' and value.value in ('add', 'sub', 'and', 'or', 'xor', 'lsl', 'lsr') and len(value.operands) == 2 and all(argument_derived(item)
                for item in value.operands) and any(item.kind == 'arg' or _contains_argument(item) for item in value.operands))
        def _contains_argument(value):
            return (isinstance(value, SymbolicValue) and (value.kind == 'arg' or any(_contains_argument(item) for item in value.operands)))
        for target in sorted(candidates):
            owner = CodeAddress(target, 'thumb')
            function = facts.function(owner, budget=192, symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0), a.ARM_REG_R1: SymbolicValue.arg(1), a.ARM_REG_R2:
                SymbolicValue.arg(2), a.ARM_REG_R3: SymbolicValue.arg(3)})
            if (not function.complete or function.truncated or function.unresolved or function.calls or facts.unmodelled_memory(function) != () or not function.back_edges):
                continue
            reads = [access for access in function.accesses if access.operation == 'read' and access.address == base + 0x14 and access.width == 1]
            writes = [access for access in function.symbolic_accesses if access.operation == 'write' and access.address == SymbolicValue.const(base + 0x0C) and
                access.width == 1 and argument_derived(access.value) and _contains_argument(access.value)]
            if len(reads) != 1 or len(writes) != 1:
                continue
            read, write = reads[0].instruction, writes[0].instruction
            prefix = function.linear_path(owner, read)
            if prefix is None:
                continue
            for branch in function.instructions:
                instruction = facts.decode(branch)
                if (instruction is None or instruction.id != a.ARM_INS_B or instruction.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID) or not instruction.operands or
                    instruction.operands[0].type != a.ARM_OP_IMM or function.linear_path(read, branch) is None):
                    continue
                predicate = facts.branch_predicate(function, branch)
                if (predicate is None or len(predicate.read_sources) != 1 or predicate.read_sources[0].site != read or predicate.read_sources[0].width != 1 or
                    predicate.read_sources[0].signed or predicate.read_sources[0].address != SymbolicValue.const(base + 0x14)):
                    continue
                ready = predicate.evaluate({read: 1})
                if (ready is None or any(predicate.evaluate({read: value}) != (ready if value & 1 else not ready) for value in range(256))):
                    continue
                taken = CodeAddress(instruction.operands[0].imm & 0xFFFFFFFF, owner.isa, owner.phase, owner.bank)
                fallthrough = CodeAddress(branch.address + instruction.size, owner.isa, owner.phase, owner.bank)
                accepted = function.linear_path(taken if ready else fallthrough, write)
                waiting = function.linear_path(fallthrough if ready else taken, read)
                if accepted is None or waiting is None:
                    continue
                if events(function, accepted) != (('write', SymbolicValue.const(base + 0x0C), 1, writes[0].value),):
                    continue
                transaction = (set(prefix) | set(accepted) | set(waiting) | set(function.linear_path(read, branch)))
                if (any(access.instruction not in transaction for access in function.symbolic_accesses) or any(access.predicate != a.ARM_CC_AL for access in
                    function.symbolic_accesses)):
                    continue
                if events(function, prefix) != (('read', SymbolicValue.const(base + 0x14), 1, None),):
                    continue
                proved[target] = (tuple(site for site, called in calls if called == target), read.address, write.address)
                break
        return proved
    return facts.memo('uart-console-typed-tx', (base,), extract)
