"""Shared references queries; no device selection."""
from __future__ import annotations

from .fact_models import FunctionFacts

from .fact_indexes import _ARM_LITERAL_ACCESS_CANDIDATE, _THUMB_LITERAL_ACCESS_CANDIDATE
from .fact_models import (
    BitTest, LiteralAccessCandidate, ReachabilityFacts, Reference, ScatterCandidate,
)
from .values import CodeAddress
from capstone import arm as a
from dataclasses import replace
import struct


class FactReferences:
    def vectors(self, address: int | None = None, *, phase: str = 'reset',
                bank: str = 'primary'):
        start = self.base if address is None else address
        result = []
        for at in range(start, start + 32, 4):
            pc = CodeAddress(at, 'arm', phase, bank)
            ins = self.decode(pc)
            literal = self.literal(pc)
            if ins is not None and ins.id == a.ARM_INS_B and ins.operands[0].type == a.ARM_OP_IMM:
                result.append((pc, CodeAddress(ins.operands[0].imm & 0xFFFFFFFF,
                                               'arm', phase, bank)))
            elif literal is not None and literal.register == a.ARM_REG_PC:
                result.append((pc, CodeAddress(literal.value & ~1,
                                               'thumb' if literal.value & 1 else 'arm',
                                               phase, bank)))
        return tuple(result)

    def literal_access_candidates(self, ranges, *, phase='reset', bank='primary',
                                  limit=0x400000):
        """Find lexical load/access candidates in a selected execution view.

        ``limit`` bounds execution addresses below ``base + limit``. Copied
        high-memory code requires a correspondingly high bound. These byte
        shapes are discovery candidates, not evidence that a path executes.
        """
        normalized = tuple(sorted((int(lo), int(hi)) for lo, hi in ranges
                                  if 0 <= int(lo) < int(hi) <= 1 << 32))
        end = min(self.base + max(0, int(limit)), 1 << 32)
        cache_key = (phase, bank, end)
        if not normalized:
            return ()

        def extract():
            found = []
            for base, data in self._search_regions(phase, bank):
                scan_end = min(len(data), max(0, end - base))
                if not scan_end:
                    continue
                thumb_candidates = {match.start() for match in
                                    _THUMB_LITERAL_ACCESS_CANDIDATE.finditer(data, 0, scan_end)}
                arm_candidates = {match.start() for match in
                                  _ARM_LITERAL_ACCESS_CANDIDATE.finditer(data, 0, scan_end)}
                for off in sorted(thumb_candidates | arm_candidates):
                    guest = base + off
                    if (off in thumb_candidates
                            and off + 4 <= scan_end and guest % 2 == 0):
                        first = struct.unpack_from('<H', data, off)[0]
                        if (first & 0xF800 == 0x4800
                                and self.view.covers(guest, 4, phase=phase, bank=bank)):
                            register = first >> 8 & 7
                            pool = ((guest + 4) & ~3) + (first & 0xFF) * 4
                            raw = self.view.read(pool, 4, phase=phase, bank=bank)
                            word = struct.unpack_from('<H', data, off + 2)[0]
                            opcode = word & 0xF800
                            widths = {0x6000: 4, 0x6800: 4, 0x7000: 1,
                                      0x7800: 1, 0x8000: 2, 0x8800: 2}
                            width = widths.get(opcode)
                            if (raw is not None and width is not None
                                    and (word >> 3) & 7 == register):
                                pointer = int.from_bytes(raw, 'little')
                                address = pointer + ((word >> 6 & 31) * width)
                                if (0 <= address and address + width <= 1 << 32):
                                    found.append(LiteralAccessCandidate(
                                        CodeAddress(guest, 'thumb', phase, bank),
                                        CodeAddress(guest + 2, 'thumb', phase, bank),
                                        pool, address, width,
                                        'read' if opcode in (0x6800, 0x7800, 0x8800) else 'write',
                                        a.ARM_CC_AL,
                                    ))
                    if off not in arm_candidates or (guest % 4 or off + 8 > scan_end
                            or not self.view.covers(guest, 8, phase=phase, bank=bank)):
                        continue
                    first = struct.unpack_from('<I', data, off)[0]
                    condition = first >> 28
                    if (condition == 0xF or first & 0x0E000000 != 0x04000000
                            or first & ((1 << 25) | (1 << 22) | (1 << 21))
                            or not first & (1 << 24) or not first & (1 << 20)
                            or (first >> 16 & 15) != 15 or (first >> 12 & 15) == 15):
                        continue
                    register = first >> 12 & 15
                    displacement = first & 0xFFF
                    pool = guest + 8 + (displacement if first & (1 << 23) else -displacement)
                    raw = self.view.read(pool, 4, phase=phase, bank=bank)
                    if raw is None:
                        continue
                    pointer = int.from_bytes(raw, 'little')
                    use = struct.unpack_from('<I', data, off + 4)[0]
                    use_condition = use >> 28
                    destination = use >> 12 & 15
                    if (use_condition == 15 or use & 0x0C000000 != 0x04000000
                            or use & ((1 << 25) | (1 << 21)) or not use & (1 << 24)
                            or use >> 16 & 15 != register or destination == 15
                            or (condition != 14 and use_condition != condition)):
                        continue
                    width = 1 if use & (1 << 22) else 4
                    displacement = use & 0xFFF
                    address = pointer + (displacement if use & (1 << 23) else -displacement)
                    if 0 <= address and address + width <= 1 << 32:
                        found.append(LiteralAccessCandidate(
                            CodeAddress(guest, 'arm', phase, bank),
                            CodeAddress(guest + 4, 'arm', phase, bank),
                            pool, address, width,
                            'read' if use & (1 << 20) else 'write', use_condition + 1,
                        ))
            return tuple(sorted(found, key=lambda item: (
                item.load.address, 0 if item.load.isa == 'thumb' else 1)))
        candidates = self.memo('literal-access-shapes', cache_key, extract)
        return tuple(item for item in candidates
                     if any(lo <= item.address and item.address + item.width <= hi
                            for lo, hi in normalized))

    def bit_tests(self, function: FunctionFacts) -> tuple[BitTest, ...]:
        """Observe single-bit sign tests immediately following scalar reads."""
        with self._lock:
            if id(function) not in self._function_ids:
                return ()
        def extract():
            result = []
            covered = set(function.instructions)
            for read in function.accesses:
                if (read.operation != 'read'
                        or read.predicate not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
                    continue
                pc = read.instruction
                load = self.decode(pc)
                if load is None or not load.operands or load.operands[0].type != a.ARM_OP_REG:
                    continue
                shift_pc = replace(pc, address=pc.address + load.size)
                shift = self.decode(shift_pc)
                if (shift is None or shift.id != a.ARM_INS_LSL
                        or shift_pc not in covered
                        or shift.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                        or len(shift.operands) != 3
                        or shift.operands[0].type != a.ARM_OP_REG
                        or shift.operands[1].type != a.ARM_OP_REG
                        or shift.operands[1].reg != load.operands[0].reg
                        or shift.operands[2].type != a.ARM_OP_IMM
                        or not 0 <= shift.operands[2].imm <= 31
                        or not shift.update_flags):
                    continue
                branch_pc = replace(pc, address=shift_pc.address + shift.size)
                branch = self.decode(branch_pc)
                if (branch is None or branch.id != a.ARM_INS_B
                        or branch_pc not in covered
                        or branch.cc not in (a.ARM_CC_MI, a.ARM_CC_PL)
                        or not branch.operands or branch.operands[0].type != a.ARM_OP_IMM):
                    continue
                result.append(BitTest(read, 1 << (31 - shift.operands[2].imm),
                                      branch_pc, branch.operands[0].imm & 0xFFFFFFFF,
                                      branch.cc == a.ARM_CC_MI))
            return tuple(result)
        return self.memo('bit-tests', id(function), extract)

    def reset_references(self, entry: CodeAddress, *, budget=8192,
                         max_entries=96, limit_address=0x400000):
        """Collect bounded static references and calls reachable from reset code."""
        key = (entry, min(max(1, int(budget)), 8192), min(max(1, int(max_entries)), 96),
               int(limit_address))

        def extract():
            pending = [(entry, None)]
            visited = set()
            link_insensitive = set()
            references, calls, source_sites = set(), set(), set()
            max_insns = key[1]
            analyses_complete = True

            def readonly_range(address, size, phase, bank):
                cursor, end = address, address + size
                while cursor < end:
                    matches = [mapping for mapping in self.view.mappings
                               if mapping.phase == phase and mapping.bank == bank
                               and mapping.guest_base <= cursor
                               < mapping.guest_base + mapping.size]
                    if len(matches) != 1 or matches[0].kind not in ('direct', 'alias'):
                        return False
                    cursor = min(end, matches[0].guest_base + matches[0].size)
                return True

            while pending and len(visited) < key[2]:
                start, initial_lr = pending.pop()
                visit_key = (start, initial_lr)
                if (visit_key in visited or start in link_insensitive or start.address < 0
                        or start.address >= min(len(self.image) + self.base, key[3])):
                    continue
                visited.add(visit_key)
                initial_regs = {a.ARM_REG_LR: initial_lr} if initial_lr is not None else None
                result = self.function(start, budget=min(1024, max_insns),
                                       initial_registers=initial_regs,
                                       stop_at_initial_return=True)
                analyses_complete &= result.complete
                if result.complete:
                    reads_link = False
                    for pc in result.instructions:
                        ins = self.decode(pc)
                        read, _ = ins.regs_access()
                        if a.ARM_REG_LR not in read or ins.id == a.ARM_INS_PUSH:
                            continue
                        operands = ins.operands
                        normal_return = (
                            ins.id == a.ARM_INS_BX and operands
                            and operands[0].type == a.ARM_OP_REG
                            and operands[0].reg == a.ARM_REG_LR)
                        normal_return |= (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                            and len(operands) == 2 and operands[0].type == a.ARM_OP_REG
                            and operands[0].reg == a.ARM_REG_PC
                            and operands[1].type == a.ARM_OP_REG
                            and operands[1].reg == a.ARM_REG_LR)
                        reads_link |= not normal_return
                    if not reads_link:
                        link_insensitive.add(start)
                for instruction in result.instructions:
                    decoded = self.decode(instruction)
                    if decoded is not None:
                        source_sites.add((instruction, decoded.size, 'instruction'))
                for literal in result.literals:
                    references.add(Reference(literal.value, literal.instruction,
                                             'literal', 4, literal=literal.pool))
                    pool_site = CodeAddress(literal.pool, literal.instruction.isa,
                                            literal.instruction.phase,
                                            literal.instruction.bank)
                    source_sites.add((pool_site, 4, 'literal'))
                literal_instructions = {literal.instruction for literal in result.literals}
                for access in result.accesses:
                    if (access.operation != 'read'
                            or access.instruction in literal_instructions):
                        continue
                    references.add(Reference(access.address, access.instruction,
                                             'dereference', access.width,
                                             dereference=access.address))
                    if readonly_range(access.address, access.width,
                                      access.instruction.phase,
                                      access.instruction.bank):
                        data_site = CodeAddress(access.address,
                                                access.instruction.isa,
                                                access.instruction.phase,
                                                access.instruction.bank)
                        source_sites.add((data_site, access.width, 'dereference'))
                    if (access.width == 4 and readonly_range(
                            access.address, 4, access.instruction.phase,
                            access.instruction.bank)):
                        raw = self.view.read(access.address, 4,
                                             phase=access.instruction.phase,
                                             bank=access.instruction.bank)
                        if raw is not None:
                            references.add(Reference(int.from_bytes(raw, 'little'),
                                                     access.instruction, 'literal', 4,
                                                     literal=access.address))
                for _, target in result.calls:
                    calls.add(target)
                covered = set(result.instructions)
                pending.extend((target, initial_lr) for target in result.flow_targets
                               if target not in covered
                               and (initial_lr is None or target != CodeAddress(
                                   initial_lr & ~1, 'thumb' if initial_lr & 1 else 'arm',
                                   start.phase, start.bank))
                               and (target, initial_lr) not in visited)
                for callsite, target in result.calls:
                    ins = self.decode(callsite)
                    if ins is not None:
                        return_lr = (callsite.address + ins.size) | (
                            1 if callsite.isa == 'thumb' else 0)
                        if (target, return_lr) not in visited:
                            pending.append((target, return_lr))
            entry_budget_exhausted = bool(
                len(visited) >= key[2]
                and any((candidate, lr) not in visited
                        and candidate not in link_insensitive
                        and 0 <= candidate.address
                        < min(len(self.image) + self.base, key[3])
                        for candidate, lr in pending))
            return ReachabilityFacts(
                tuple(sorted(references, key=lambda ref: (ref.instruction.address,
                             ref.kind, ref.value, ref.literal or -1,
                             ref.dereference or -1))),
                tuple(sorted(calls, key=lambda pc: (pc.address, pc.isa, pc.phase, pc.bank))),
                tuple(sorted({pc for pc, _ in visited},
                             key=lambda pc: (pc.address, pc.isa, pc.phase, pc.bank))),
                analyses_complete and not entry_budget_exhausted,
                entry_budget_exhausted,
                tuple(sorted(source_sites, key=lambda item: (
                    item[0].address, item[0].isa, item[0].phase, item[0].bank,
                    item[1], item[2]))),
            )
        return self.memo('reset-references', key, extract)

    def scatter_candidates(self, limit=0x20000):
        def extract():
            result = []
            for off in range(0, min(len(self.image) - 11, limit), 4):
                if not self.view.covers(self.base + off, 12,
                                        phase='reset', bank='primary'):
                    continue
                source, target, size = struct.unpack_from('<3I', self.image, off)
                if (not size or size > 0x2000000 or source + size > 1 << 32
                        or target + size > 1 << 32 or source == target
                        or not self.view.covers(source, size, phase='reset', bank='primary')):
                    continue
                zero, zero_size = None, None
                if (off + 20 <= len(self.image)
                        and self.view.covers(self.base + off + 12, 8,
                                              phase='reset', bank='primary')):
                    z, n = struct.unpack_from('<2I', self.image, off + 12)
                    if z == target + size and 0 < n <= 0x2000000 and z + n <= 1 << 32:
                        zero, zero_size = z, n
                result.append(ScatterCandidate(self.base + off, source, target, size, zero, zero_size))
            return tuple(result)
        return self.memo('scatter', limit, extract)
