"""Shared queries queries; no device selection."""
from __future__ import annotations
from .fact_models import FunctionFacts
from .values import CodeAddress, SymbolicValue
from capstone import arm as a
import capstone as cs

class FactQueries:
    def _reaching_sites(self, function, use, removed, include_entry, defines):
        """Walk complete local predecessors with a register/memory write query."""
        nodes = set(function.instructions)
        if (not function.complete or function.unresolved or use not in nodes or function.entry not in nodes):
            return None
        predecessors, successors = {}, {}
        for source, target in function.control_edges:
            if source not in nodes or target not in nodes:
                return None
            if (source, target) not in removed:
                predecessors.setdefault(target, set()).add(source)
                successors.setdefault(source, set()).add(target)
        pending, reached = [function.entry], set()
        while pending:
            pc = pending.pop()
            if pc not in reached:
                reached.add(pc)
                pending.extend(successors.get(pc, ()))
        if use not in reached or use == function.entry and not include_entry:
            return None
        pending = [pc for pc in predecessors.get(use, ()) if pc in reached]
        definitions = {None} if include_entry and use == function.entry else set()
        if not pending and use != function.entry:
            return None
        seen = set()
        while pending:
            pc = pending.pop()
            if pc in seen:
                continue
            seen.add(pc)
            written = defines(pc)
            if written is None:
                return None
            if written:
                definitions.add(pc)
                continue
            previous = tuple(source for source in predecessors.get(pc, ()) if source in reached)
            if pc == function.entry:
                if not include_entry:
                    return None
                definitions.add(None)
            elif not previous:
                return None
            pending.extend(previous)
        return (tuple(sorted(definitions, key=lambda pc: (-1, '', '', '') if pc is None else (pc.address, pc.isa, pc.phase, pc.bank))) if definitions else None)

    def reaching_definitions(self, function: FunctionFacts, use: CodeAddress, register: int, *, cut_edges=(), include_entry=False):
        """Find the last register writes on every local path reaching a use.

        ``None`` denotes an entry value, opaque call result, conditional write
        or incomplete graph. Multiple returned sites are explicit alternatives.
        Optional cut edges support a separately justified first-iteration query.
        Calls use the same caller-saved register convention as function facts.
        With ``include_entry``, a None item in the returned tuple denotes the
        explicit query entry state; an outer None still denotes unknown flow.
        """
        with self._lock:
            if id(function) not in self._function_ids:
                return None
        removed = frozenset(cut_edges)
        key = (id(function), use, register, removed, include_entry)
        def extract():
            calls = {site for site, _ in function.calls}
            caller_saved = {a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3, a.ARM_REG_R12, a.ARM_REG_LR, a.ARM_REG_CPSR}
            def defines(pc):
                instruction = self.decode(pc)
                if instruction is None:
                    return None
                if (instruction.id == a.ARM_INS_SVC or register in caller_saved and (pc in calls or instruction.id in (a.ARM_INS_BL, a.ARM_INS_BLX))):
                    return None
                if (instruction.id == a.ARM_INS_MSR and instruction.operands and instruction.operands[0].type == a.ARM_OP_SYSREG and instruction.operands[0].reg
                    & a.ARM_SYSREG_CPSR_C and not instruction.operands[0].reg & ~(a.ARM_SYSREG_CPSR_C | a.ARM_SYSREG_CPSR_X | a.ARM_SYSREG_CPSR_S | a.ARM_SYSREG_CPSR_F)
                    and register in {a.ARM_REG_SP, a.ARM_REG_LR, a.ARM_REG_R8, a.ARM_REG_R9, a.ARM_REG_R10, a.ARM_REG_R11, a.ARM_REG_R12}):
                    return None
                try:
                    _, writes = instruction.regs_access()
                except (AttributeError, RuntimeError, cs.CsError):
                    return None
                written = register in writes or register == a.ARM_REG_CPSR and (instruction.update_flags or instruction.id == a.ARM_INS_MSR)
                if written and instruction.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID):
                    return None
                return written
            return self._reaching_sites(function, use, removed, include_entry, defines)
        return self.memo('reaching-definitions', key, extract)

    def memory_definitions(self, function: FunctionFacts, use: CodeAddress, address: int, *, width: int, cut_edges=(), include_entry=False, allowed_calls=()):
        """Find exact scalar stores reaching one concrete memory cell.

        Partial/wider overlaps, unknown aliases, conditional writes, opaque
        calls and unmodelled memory effects are unknown. Distinct exact stores
        are explicit alternatives; they do not establish equal stored values.
        Allowed callsites require a separately proved non-aliasing effect
        summary, just as cut edges require a separately justified iteration.
        """
        with self._lock:
            if id(function) not in self._function_ids:
                return None
        if (type(address) is not int or type(width) is not int or width not in (1, 2, 4) or not 0 <= address < address + width <= 1 << 32):
            return None
        removed = frozenset(cut_edges)
        allowed = frozenset(allowed_calls)
        def extract():
            unknown = self.unmodelled_memory(function)
            if unknown is None:
                return None
            unknown = set(unknown)
            calls = {site for site, _ in function.calls}
            writes = {access.instruction: access for access in function.accesses if access.operation == 'write'}
            writes.update({access.instruction: access for access in function.symbolic_accesses if access.operation == 'write'})
            def defines(pc):
                instruction = self.decode(pc)
                if (instruction is None or pc in unknown or instruction.id == a.ARM_INS_SVC or pc not in allowed and (pc in calls or instruction.id in (a.ARM_INS_BL,
                    a.ARM_INS_BLX))):
                    return None
                if instruction.id not in (a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH):
                    return False
                access = writes.get(pc)
                if access is None:
                    return None
                target = access.address
                if isinstance(target, SymbolicValue):
                    target = target.value if target.kind == 'const' else None
                if type(target) is not int:
                    return None
                if target + access.width <= address or address + width <= target:
                    return False
                if (target != address or access.width != width or access.predicate not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                    return None
                return True
            return self._reaching_sites(function, use, removed, include_entry, defines)
        return self.memo('memory-definitions', (id(function), use, address, width, removed, include_entry, allowed), extract)

    def ordered_events(self, function: FunctionFacts, sites, *, repeat_edges=()):
        """Order mandatory instruction sites by CFG relationships, not layout.

        Every normal exit must follow the last site. Event-containing cycles
        reject unless their separately proved recurrence edges are supplied.
        This does not close unlisted effects, conditional instruction effects,
        callee semantics or termination; device predicates must establish those.
        """
        with self._lock:
            if id(function) not in self._function_ids:
                return None
        selected, removed = frozenset(sites), frozenset(repeat_edges)
        def extract():
            nodes, edges = set(function.instructions), set(function.control_edges)
            if (not function.complete or function.unresolved or not selected <= nodes or not removed <= edges or any(source not in nodes or target not in nodes
                for source, target in edges)):
                return None
            if not selected:
                return ()
            sequence = tuple(sorted(selected, key=lambda site: sum(function.dominates(other, site) for other in selected)))
            if any(not function.dominates(left, right) for left, right in zip(sequence, sequence[1:])):
                return None
            exits = nodes - {source for source, _ in edges}
            if not exits or any(not function.dominates(sequence[-1], end) for end in exits):
                return None
            successors = {}
            for source, target in edges - removed:
                successors.setdefault(source, set()).add(target)
            for site in selected:
                pending, seen = list(successors.get(site, ())), set()
                while pending:
                    pc = pending.pop()
                    if pc == site:
                        return None
                    if pc not in seen:
                        seen.add(pc)
                        pending.extend(successors.get(pc, ()))
            return sequence
        return self.memo('ordered-events', (id(function), selected, removed), extract)

    def register_origins(self, function: FunctionFacts, use: CodeAddress, register: int, *, cut_edges=()):
        """Trace all local register copies to their original defining writes.

        Results retain the register written at each origin. Only unconditional
        MOV and zero-offset ADD/SUB copies are transparent; other operations
        remain explicit definitions. Unknown entries or cyclic copies fail.
        """
        with self._lock:
            if id(function) not in self._function_ids:
                return None
        removed = frozenset(cut_edges)
        def extract():
            results = {}
            def visit(site, reg, active):
                key = (site, reg)
                if key in results:
                    return results[key]
                if key in active or len(active) >= 64:
                    return None
                definitions = self.reaching_definitions(function, site, reg, cut_edges=removed)
                if definitions is None:
                    return None
                origins = set()
                for definition in definitions:
                    ins = self.decode(definition)
                    source = None
                    if (reg != a.ARM_REG_CPSR and ins is not None and ins.cc in (a.ARM_CC_AL, a.ARM_CC_INVALID) and not any(op.shift.type for op in ins.operands)):
                        ops = ins.operands
                        if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS) and len(ops) == 2 and ops[0].type == a.ARM_OP_REG and ops[0].reg == reg and ops[1].type ==
                            a.ARM_OP_REG):
                            source = ops[1].reg
                        elif (ins.id in (a.ARM_INS_ADD, a.ARM_INS_SUB) and len(ops) in (2, 3) and ops[0].type == a.ARM_OP_REG and ops[0].reg == reg and ops[-1].type
                            == a.ARM_OP_IMM and ops[-1].imm == 0 and ops[-2].type == a.ARM_OP_REG):
                            source = ops[-2].reg
                    if source is None:
                        origins.add((definition, reg))
                    else:
                        earlier = visit(definition, source, active | {key})
                        if earlier is None:
                            return None
                        origins.update(earlier)
                result = tuple(sorted(origins, key=lambda item: (item[0].address, item[0].isa, item[0].phase, item[0].bank, item[1])))
                results[key] = result
                return result
            return visit(use, register, frozenset())
        return self.memo('register-origins', (id(function), use, register, removed), extract)

    def stack_frame(self, function: FunctionFacts):
        """Query relative stack accesses without assuming a physical SP."""
        from .stack_facts import stack_frame
        return stack_frame(self, function)

    def register_value(self, function: FunctionFacts, use: CodeAddress, register: int, *, cut_edges=(), follow_stack=False, allowed_calls=()):
        """Query values, optionally closing exact stack spill/reload dependencies.

        Preserved calls require separately proved non-aliasing memory effects;
        this never suppresses the normal caller-saved register clobbers.
        """
        from .value_query import register_value
        return register_value(self, function, use, register, cut_edges=cut_edges, follow_stack=follow_stack, allowed_calls=allowed_calls)

    def branch_predicate(self, function: FunctionFacts, branch: CodeAddress, *, cut_edges=()):
        """Link a conditional branch to its flag producer and opaque reads."""
        from .value_query import branch_predicate
        return branch_predicate(self, function, branch, cut_edges=cut_edges)

    def unmodelled_memory(self, function: FunctionFacts) -> tuple[CodeAddress, ...] | None:
        """Locate memory instructions absent from the scalar access model.

        CFG completeness alone does not establish complete memory effects.
        Protocol predicates must close these sites within their active region;
        stack operations are included rather than silently treated as harmless.
        """
        with self._lock:
            if id(function) not in self._function_ids:
                return None
        scalar = {a.ARM_INS_LDR, a.ARM_INS_LDRB, a.ARM_INS_LDRH, a.ARM_INS_LDRSB, a.ARM_INS_LDRSH, a.ARM_INS_STR, a.ARM_INS_STRB, a.ARM_INS_STRH}
        def extract():
            unknown = []
            for pc in function.instructions:
                instruction = self.decode(pc)
                if instruction is None:
                    return None
                if pc in function.scope_before or instruction.id in scalar:
                    continue
                if (any(op.type == a.ARM_OP_MEM for op in instruction.operands) or instruction.mnemonic.startswith(('ldm', 'stm', 'push', 'pop', 'swp', 'vld',
                    'vst', 'ldr', 'str', 'ldc', 'stc', 'rfe', 'srs'))):
                    unknown.append(pc)
            return tuple(unknown)
        return self.memo('unmodelled-memory', (id(function),), extract)

    def function_region(self, entry: CodeAddress, stop_at=(), budget=1024, *, stop_before=(), **options):
        """Analyze a region through explicit, non-transfer endpoint instructions.

        A complete region has supplied code on every local path, reaches an
        endpoint, and has no early return or unresolved escape. Loops can still
        wait indefinitely; completion is CFG coverage, not a termination proof.
        Stop-at effects are included, while their successors are outside scope.
        Stop-before endpoints may transfer control: their input states are
        observed, and neither their effects nor successors belong to the region.
        """
        exits = (stop_at,) if isinstance(stop_at, CodeAddress) else tuple(stop_at)
        before = ((stop_before,) if isinstance(stop_before, CodeAddress) else tuple(stop_before))
        if (not exits and not before or not all(isinstance(pc, CodeAddress) for pc in (*exits, *before)) or set(exits) & set(before)):
            raise ValueError('region endpoints must be distinct explicit code addresses')
        for pc in exits:
            ins = self.decode(pc)
            if ins is not None:
                try:
                    _, writes = ins.regs_access()
                except cs.CsError:
                    writes = ()
                if (any(ins.group(group) for group in (cs.CS_GRP_CALL, cs.CS_GRP_JUMP, cs.CS_GRP_INT)) or a.ARM_REG_PC in writes):
                    raise ValueError('region endpoints cannot transfer control')
        return self.function(entry, budget, _stop_after=frozenset(exits), _stop_before=frozenset(before), ** options)
