"""Code evidence for the word-command small-page NAND bootstrap."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


_HIGH = 0xffff0000
_HIGH_SIZE = 0x4000
_LOW_RAM_END = 0x04000000


def _span(facts, function, source_offset=0):
    addresses = [pc.address for pc in function.instructions]
    if not addresses:
        return None
    begin = min(addresses)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {'span': [source_offset + begin - facts.base, end - begin],
            'extra_spans': [[source_offset + literal.pool - facts.base, 4]
                            for literal in function.literals]}


def _reference_spans(facts, references, source_offset=0):
    sites = sorted((source_offset + site.address - facts.base, size)
                   for site, size, _ in references.source_sites)
    merged = []
    for begin, size in sites:
        end = begin + size
        if merged and begin <= merged[-1][0] + merged[-1][1] + 4:
            old_begin, old_size = merged[-1]
            merged[-1] = (old_begin, max(old_begin + old_size, end) - old_begin)
        else:
            merged.append((begin, size))
    return [{'span': [begin, size]} for begin, size in merged]


def _function(facts, pointer, *, budget=512):
    if not pointer & 1:
        return facts.function(CodeAddress(pointer, 'arm'), budget=budget)
    return facts.function(CodeAddress(pointer & ~1, 'thumb'), budget=budget)


def _entry_function(facts, entry, *, budget=512):
    return facts.function(entry, budget=budget)


def _getter(facts, pointer, field):
    function = _function(facts, pointer, budget=64)
    if (not function.complete or function.unresolved or function.truncated
            or function.calls or function.accesses):
        return None
    instructions = [facts.decode(pc) for pc in function.instructions]
    if len(instructions) != (4 if field == 'capacity' else 2):
        return None
    if field == 'capacity':
        first, second, subtract, ret = instructions
        good = (first.id == a.ARM_INS_LDR and first.operands[0].reg == a.ARM_REG_R1
                and first.operands[1].type == a.ARM_OP_MEM
                and first.operands[1].mem.base == a.ARM_REG_R0
                and first.operands[1].mem.disp == 0x60
                and second.id == a.ARM_INS_LDR and second.operands[0].reg == a.ARM_REG_R0
                and second.operands[1].type == a.ARM_OP_MEM
                and second.operands[1].mem.base == a.ARM_REG_R0
                and second.operands[1].mem.disp == 0x5c
                and subtract.id == a.ARM_INS_SUB
                and subtract.operands[0].reg == a.ARM_REG_R0
                and subtract.operands[1].reg == a.ARM_REG_R1
                and ret.id == a.ARM_INS_BX and ret.operands[0].reg == a.ARM_REG_LR)
    else:
        load, ret = instructions
        good = (load.id == a.ARM_INS_LDR and load.operands[0].reg == a.ARM_REG_R0
                and load.operands[1].type == a.ARM_OP_MEM
                and load.operands[1].mem.base == a.ARM_REG_R0
                and load.operands[1].mem.disp == field
                and ret.id == a.ARM_INS_BX and ret.operands[0].reg == a.ARM_REG_LR)
    return function if good else None


def _copy_provider(facts, pointer):
    function = _function(facts, pointer, budget=128)
    if (not function.complete or function.unresolved or function.truncated
            or function.calls):
        return None
    instructions = [facts.decode(pc) for pc in function.instructions]
    loads = [ins for ins in instructions if ins.id == a.ARM_INS_LDM]
    stores = [ins for ins in instructions if ins.id == a.ARM_INS_STM]
    count_subtract = any(ins.id == a.ARM_INS_SUB and len(ins.operands) == 3
        and ins.operands[0].reg == a.ARM_REG_R2
        and ins.operands[1].reg == a.ARM_REG_R2
        and ins.operands[2].type == a.ARM_OP_IMM and ins.operands[2].imm == 0x20
        for ins in instructions)
    if not loads or not stores or not count_subtract:
        return None
    if not any(ins.operands[0].reg == a.ARM_REG_R1 and ins.writeback
               for ins in loads if ins.operands):
        return None
    if not any(ins.operands[0].reg == a.ARM_REG_R0 and ins.writeback
               for ins in stores if ins.operands):
        return None
    return function


def _selector(facts, function, table, high_references):
    instructions = {pc.address: facts.decode(pc) for pc in function.instructions}
    literals = {literal.value for literal in function.literals}
    if table not in literals:
        return None
    tests = []
    for address, ins in instructions.items():
        if (ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or ins.operands[0].reg != a.ARM_REG_R3
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.disp != 0x14):
            continue
        source = ins.operands[1].mem.base
        candidates = [instructions.get(address + offset) for offset in (2, 4)]
        if (candidates[0] is None or candidates[0].id != a.ARM_INS_CMP
                or candidates[0].operands[0].reg != a.ARM_REG_R3
                or candidates[0].operands[1].reg != a.ARM_REG_R1
                or candidates[1] is None or candidates[1].id != a.ARM_INS_B
                or candidates[1].cc != a.ARM_CC_NE):
            continue
        field18 = next((pc.address for pc in function.instructions
            if (item := instructions.get(pc.address)) is not None
            and item.id == a.ARM_INS_LDR and len(item.operands) == 2
            and item.operands[0].reg == a.ARM_REG_R3
            and item.operands[1].type == a.ARM_OP_MEM
            and item.operands[1].mem.base == source
            and item.operands[1].mem.disp == 0x18
            and pc.address > address + 4), None)
        if field18 is None:
            continue
        cmp18, branch18 = instructions.get(field18 + 2), instructions.get(field18 + 4)
        if (cmp18 is None or cmp18.id != a.ARM_INS_CMP
                or cmp18.operands[0].reg != a.ARM_REG_R3
                or cmp18.operands[1].reg != a.ARM_REG_R2
                or branch18 is None or branch18.id != a.ARM_INS_B
                or branch18.cc != a.ARM_CC_NE):
            continue
        discriminator = next((pc.address for pc in function.instructions
            if (item := instructions.get(pc.address)) is not None
            and item.id == a.ARM_INS_LDR and len(item.operands) == 2
            and item.operands[0].reg == a.ARM_REG_R0
            and item.operands[1].type == a.ARM_OP_MEM
            and item.operands[1].mem.disp == 0x1c
            and pc.address > field18 + 4), None)
        if discriminator is None:
            continue
        cmp_disc, branch_disc = instructions.get(discriminator + 2), instructions.get(discriminator + 4)
        if (cmp_disc is None or cmp_disc.id != a.ARM_INS_CMP
                or cmp_disc.operands[1].type != a.ARM_OP_IMM
                or cmp_disc.operands[1].imm != 2
                or branch_disc is None or branch_disc.id != a.ARM_INS_B
                or branch_disc.cc != a.ARM_CC_EQ):
            continue
        tests.append((address, field18, discriminator))
    if not tests:
        return None

    copies = {}
    for site in function.call_sites:
        registers = dict(site.registers)
        size = registers.get(a.ARM_REG_R2)
        if site.target.isa != 'arm' or size not in (0x5c, 0x24):
            continue
        body = _copy_provider(facts, site.target.address)
        if body is not None:
            copies.setdefault(site.target, {})[size] = body
    provider = next((target for target, sizes in copies.items()
                     if {0x5c, 0x24} <= set(sizes)), None)
    if provider is None:
        return None
    sites = [site for site in function.call_sites if site.target == provider]
    sizes = {dict(site.registers).get(a.ARM_REG_R2): site for site in sites}
    if (set((0x5c, 0x24)) - set(sizes)
            or dict(sizes[0x5c].registers).get(a.ARM_REG_R1) != table - 0x5c):
        return None
    # The object receives a zeroed descriptor and the selected block count.
    installed = False
    for address, instruction in instructions.items():
        if instruction.id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS) or len(instruction.operands) != 2:
            continue
        register = instruction.operands[0].reg
        if (register != a.ARM_REG_R0 or instruction.operands[1].type != a.ARM_OP_IMM
                or instruction.operands[1].imm != 0):
            continue
        clear = instructions.get(address + 2)
        load_blocks = instructions.get(address + 4)
        store_blocks = instructions.get(address + 6)
        if (clear is not None and clear.id == a.ARM_INS_STR
                and clear.operands[0].reg == register
                and clear.operands[1].type == a.ARM_OP_MEM
                and clear.operands[1].mem.disp == 0x5c
                and load_blocks is not None and load_blocks.id == a.ARM_INS_LDR
                and load_blocks.operands[1].type == a.ARM_OP_MEM
                and load_blocks.operands[1].mem.disp == 4
                and store_blocks is not None and store_blocks.id == a.ARM_INS_STR
                and store_blocks.operands[0].reg == load_blocks.operands[0].reg
                and store_blocks.operands[1].type == a.ARM_OP_MEM
                and store_blocks.operands[1].mem.disp == 0x60):
            installed = True
            break
    if not installed:
        return None

    return function, tuple(copies[provider][size] for size in (0x5c, 0x24))


def _fixed_row_installer(facts, function, table):
    """Prove an installer that copies row zero after rejecting mode two."""
    if (not function.complete or function.unresolved or function.truncated
            or table not in {literal.value for literal in function.literals}):
        return None
    instructions = {pc.address: facts.decode(pc) for pc in function.instructions}
    selected_table = False
    for address, load in instructions.items():
        if (load.id != a.ARM_INS_LDR or len(load.operands) != 2
                or load.operands[0].reg != a.ARM_REG_R1
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.base != a.ARM_REG_PC):
            continue
        pool = ((address + 4) & ~3) + load.operands[1].mem.disp
        offset = pool - facts.base
        if (0 <= offset <= len(facts.image) - 4
                and struct.unpack_from('<I', facts.image, offset)[0] == table):
            before = [instructions.get(address - step) for step in (2, 4, 6)]
            after = instructions.get(address + load.size)
            if (all(before) and before[0].id == a.ARM_INS_MUL
                    and before[0].operands[0].reg == a.ARM_REG_R0
                    and before[0].operands[1].reg == a.ARM_REG_R3
                    and before[0].operands[2].reg == a.ARM_REG_R0
                    and before[1].id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    and before[1].operands[0].reg == a.ARM_REG_R3
                    and before[1].operands[1].type == a.ARM_OP_IMM
                    and before[1].operands[1].imm == 0x24
                    and before[2].id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    and before[2].operands[0].reg == a.ARM_REG_R0
                    and before[2].operands[1].type == a.ARM_OP_IMM
                    and before[2].operands[1].imm == 0
                    and after is not None and after.id == a.ARM_INS_ADD
                    and after.operands[0].reg == a.ARM_REG_R5
                    and after.operands[1].reg == a.ARM_REG_R0
                    and after.operands[2].reg == a.ARM_REG_R1):
                selected_table = True
                break
    if not selected_table:
        return None

    reject = False
    success_targets = set()
    for address, load in instructions.items():
        if (load.id != a.ARM_INS_LDR or len(load.operands) != 2
                or load.operands[0].reg != a.ARM_REG_R0
                or load.operands[1].type != a.ARM_OP_MEM
                or load.operands[1].mem.base != a.ARM_REG_R5
                or load.operands[1].mem.disp != 0x1c):
            continue
        compare = instructions.get(address + load.size)
        branch = instructions.get(address + load.size + (compare.size if compare else 0))
        if (compare is not None and compare.id == a.ARM_INS_CMP
                and compare.operands[1].type == a.ARM_OP_IMM
                and compare.operands[1].imm == 2
                and branch is not None and branch.id == a.ARM_INS_B
                and branch.cc == a.ARM_CC_NE):
            failure_address = address + load.size + compare.size + branch.size
            failure = instructions.get(failure_address)
            returned = instructions.get(failure_address + failure.size) if failure else None
            if (failure is None or failure.id not in (a.ARM_INS_SUB, a.ARM_INS_SUBS)
                    or failure.operands[-1].type != a.ARM_OP_IMM
                    or failure.operands[-1].imm != 3
                    or returned is None or returned.id != a.ARM_INS_POP
                    or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC
                               for op in returned.operands)):
                continue
            reject = True
            branch_site = address + load.size + compare.size
            success_targets = {target.address for source, target in function.control_edges
                               if source.address == branch_site}
            break
    if not reject:
        return None

    copies = {}
    if len(function.call_sites) != 2:
        return None
    for site in function.call_sites:
        registers = dict(site.registers)
        size = registers.get(a.ARM_REG_R2)
        if site.target.isa != 'arm' or size not in (0x5c, 0x24):
            continue
        body = _copy_provider(facts, site.target.address)
        if body is not None:
            copies.setdefault(site.target, {})[size] = body
    provider = next((target for target, sizes in copies.items()
                     if {0x5c, 0x24} <= set(sizes)), None)
    if provider is None:
        return None
    sites = [site for site in function.call_sites if site.target == provider]
    sizes = {dict(site.registers).get(a.ARM_REG_R2): site for site in sites}
    if (set((0x5c, 0x24)) - set(sizes)
            or dict(sizes[0x5c].registers).get(a.ARM_REG_R1) != table - 0x5c):
        return None
    if sizes[0x5c].site.address - 8 not in success_targets:
        return None
    for size, site in sizes.items():
        call_at = site.site.address
        r2 = dict(site.registers).get(a.ARM_REG_R2)
        if r2 != size:
            return None
        before = [instructions.get(call_at - step) for step in (2, 4, 6, 8)]
        if size == 0x5c:
            if (before[0] is None or before[0].id != a.ARM_INS_ADD
                    or before[0].operands[0].reg != a.ARM_REG_R0
                    or before[0].operands[1].reg != a.ARM_REG_R4
                    or before[1] is None or before[1].id not in (a.ARM_INS_SUB, a.ARM_INS_SUBS)
                    or before[1].operands[-1].type != a.ARM_OP_IMM
                    or before[1].operands[-1].imm != 0x5c
                    or before[2] is None or before[2].id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    or before[2].operands[0].reg != a.ARM_REG_R2
                    or before[2].operands[1].type != a.ARM_OP_IMM
                    or before[2].operands[1].imm != 0x5c):
                return None
        else:
            if (before[0] is None or before[0].id != a.ARM_INS_ADD
                    or before[0].operands[0].reg != a.ARM_REG_R0
                    or before[0].operands[-1].type != a.ARM_OP_IMM
                    or before[0].operands[-1].imm != 0x64
                    or before[1] is None or before[1].id != a.ARM_INS_ADD
                    or before[1].operands[0].reg != a.ARM_REG_R0
                    or before[1].operands[1].reg != a.ARM_REG_R4
                    or before[2] is None or before[2].id != a.ARM_INS_ADD
                    or before[2].operands[0].reg != a.ARM_REG_R1
                    or before[2].operands[1].reg != a.ARM_REG_R5
                    or before[3] is None or before[3].id not in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    or before[3].operands[0].reg != a.ARM_REG_R2
                    or before[3].operands[1].type != a.ARM_OP_IMM
                    or before[3].operands[1].imm != 0x24):
                return None
        if size == 0x24:
            if dict(site.registers).get(a.ARM_REG_R1) is not None:
                return None

    # The two calls install the selected template and selected row in the
    # same object; then the row's block count is published at +0x60.
    installed_template = False
    installed_row = False
    for address, instruction in instructions.items():
        if (instruction.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                and len(instruction.operands) == 2
                and instruction.operands[1].type == a.ARM_OP_IMM
                and instruction.operands[1].imm == 0
                and instruction.operands[0].reg == a.ARM_REG_R0):
            clear = instructions.get(address + instruction.size)
            if (clear is not None and clear.id == a.ARM_INS_STR
                    and clear.operands[1].type == a.ARM_OP_MEM
                    and clear.operands[1].mem.base == a.ARM_REG_R4
                    and clear.operands[1].mem.disp == 0x5c):
                installed_template = True
        if (instruction.id == a.ARM_INS_LDR
                and len(instruction.operands) == 2
                and instruction.operands[1].type == a.ARM_OP_MEM
                and instruction.operands[1].mem.disp == 4):
            store = instructions.get(address + instruction.size)
            if (store is not None and store.id == a.ARM_INS_STR
                    and store.operands[0].reg == instruction.operands[0].reg
                    and store.operands[1].type == a.ARM_OP_MEM
                    and store.operands[1].mem.base == a.ARM_REG_R4
                    and store.operands[1].mem.disp == 0x60):
                installed_row = True
    if not (installed_template and installed_row):
        return None
    return function, tuple(copies[provider][size] for size in (0x5c, 0x24))


def _word_poll(facts, function, address, mask, compare=None):
    instructions = {pc.address: facts.decode(pc) for pc in function.instructions}
    for access in function.accesses:
        if (access.operation, access.address, access.width) != ('read', address, 4):
            continue
        shift = instructions.get(access.instruction.address + 2)
        if shift is None or shift.id != a.ARM_INS_LSL or len(shift.operands) != 3:
            continue
        left = shift.operands[0].reg
        if (shift.operands[1].reg != left or shift.operands[2].type != a.ARM_OP_IMM):
            continue
        next_shift = instructions.get(access.instruction.address + 4)
        cmp = instructions.get(access.instruction.address + 6)
        branch = instructions.get(access.instruction.address + 8)
        if compare is None and mask == 0x2000:
            if (shift.operands[2].imm != 18 or next_shift is None
                    or next_shift.id != a.ARM_INS_B
                    or next_shift.cc != a.ARM_CC_MI):
                continue
            target = next_shift.operands[0].imm
            if not any(pc.address == (target & 0xffffffff)
                       and facts.decode(pc).id == a.ARM_INS_POP
                       for pc in function.instructions):
                continue
            return True
        if shift.operands[2].imm != 17:
            continue
        if (next_shift is None or next_shift.id != a.ARM_INS_LSR
                or next_shift.operands[0].reg != left or next_shift.operands[1].reg != left
                or next_shift.operands[2].type != a.ARM_OP_IMM
                or next_shift.operands[2].imm != 30):
            continue
        if compare is not None:
            if (cmp is None or cmp.id != a.ARM_INS_CMP
                    or cmp.operands[1].type != a.ARM_OP_IMM
                    or cmp.operands[1].imm != compare
                    or branch is None or branch.id != a.ARM_INS_B
                    or branch.cc != a.ARM_CC_EQ):
                continue
        elif mask is not None:
            ands = cmp
            if (ands is None or ands.id != a.ARM_INS_CMP
                    or ands.operands[0].reg != left):
                continue
        return True
    return False


def _operation(facts, pointer, command):
    function = _function(facts, pointer, budget=1024)
    instructions = {pc.address: facts.decode(pc) for pc in function.instructions}
    writes = [use.value for use in function.accesses
              if use.operation == 'write' and use.address == 0x64000300
              and use.width == 4]
    if command == 1:
        if (1 not in writes or not any(use.operation == 'read'
                and use.address == 0x64000308 and use.width == 4
                for use in function.accesses)
                or not any(use.operation == 'write' and use.address == 0x64000304
                and use.width == 4 for use in function.accesses)):
            return None
        copy_calls = [site for site in function.call_sites
                      if dict(site.registers).get(a.ARM_REG_R2) == 512
                      and dict(site.registers).get(a.ARM_REG_R1) == 0x64000000]
        if len(copy_calls) != 1:
            return None
    else:
        wanted = 3 if command == 3 else 4
        if (wanted not in writes or 6 not in writes
                or not any(use.operation == 'read' and use.address == 0x64000308
                           and use.width == 4 for use in function.accesses)
                or not any(use.operation == 'write' and use.address == 0x64000304
                           and use.width == 4 for use in function.accesses)):
            return None
        if not any(use.operation == 'read' and use.address == 0x64000308
                   and use.width == 4 for use in function.accesses):
            return None
    if not any(use.operation == 'write' and use.address == 0x80000904
               and use.width == 4 and use.value == 0x4000 for use in function.accesses):
        return None
    if not any(use.operation == 'write' and use.address == 0x80000904
               and use.width == 4 and use.value == 0x2000 for use in function.accesses):
        return None
    waits = {target for _, target in function.calls}
    if not any(target.isa == 'thumb' and _word_poll(facts, facts.function(target,
            budget=128), 0x80000950, 0x2000 if command == 1 else 0x6000,
            compare=None if command == 1 else 3) for target in waits):
        return None
    if command in (3, 4):
        if not any((ands := instructions.get(pc.address)) is not None
                   and ands.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                   and len(ands.operands) == 2
                   and ands.operands[1].type == a.ARM_OP_IMM
                   and ands.operands[1].imm == 0x88
                   for pc in function.instructions):
            return None
    return function


def _input_profile(stage_facts, reset, source):
    instructions = {pc.address: stage_facts.decode(pc) for pc in reset.instructions}
    for access in reset.accesses:
        if (access.operation, access.address, access.width) != ('read', 0x48000050, 4):
            continue
        pc = access.instruction.address
        load = instructions.get(pc)
        shifts = [instructions.get(pc + 2), instructions.get(pc + 4)]
        compare = instructions.get(pc + 6)
        branch = instructions.get(pc + 8)
        if (load is None or load.id != a.ARM_INS_LDR
                or shifts[0] is None or shifts[0].id != a.ARM_INS_LSL
                or shifts[1] is None or shifts[1].id != a.ARM_INS_LSR
                or shifts[0].operands[2].imm != 27 or shifts[1].operands[2].imm != 27
                or shifts[0].operands[0].reg != shifts[0].operands[1].reg
                or shifts[1].operands[0].reg != shifts[0].operands[0].reg
                or compare is None or compare.id != a.ARM_INS_CMP
                or compare.operands[1].type != a.ARM_OP_IMM or compare.operands[1].imm != 31
                or branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_EQ):
            continue
        if not any(use.operation == 'write' and 0x48000000 <= use.address < 0x48000050
                   and use.instruction.address < access.instruction.address
                   for use in reset.accesses):
            continue
        return {'span': [source + min(pc.address for pc in reset.instructions),
                         max(pc.address + stage_facts.decode(pc).size
                             for pc in reset.instructions)
                         - min(pc.address for pc in reset.instructions)]}
    return None


def _uart_source(stage_facts, references):
    for entry in references.entries:
        if entry not in references.calls or entry.isa != 'thumb':
            continue
        function = stage_facts.function(entry, budget=256)
        if (not function.complete or function.unresolved or function.truncated
                or function.calls):
            continue
        literals = {literal.value for literal in function.literals}
        if not {0x80001400, 0x80001500} <= literals:
            continue
        accesses = {use.instruction.address: use for use in function.accesses
                    if use.operation == 'read' and use.width == 4}
        ready = set()
        instructions = {pc.address: stage_facts.decode(pc) for pc in function.instructions}
        for address, use in accesses.items():
            if use.address not in (0x80001408, 0x80001508):
                continue
            load = instructions.get(address)
            shift, branch = instructions.get(address + 2), instructions.get(address + 4)
            if (load is None or load.id != a.ARM_INS_LDR or len(load.operands) != 2
                    or load.operands[1].type != a.ARM_OP_MEM
                    or load.operands[1].mem.disp != 8
                    or shift is None or shift.id != a.ARM_INS_LSL
                    or shift.operands[2].imm != 28
                    or shift.operands[0].reg != load.operands[0].reg
                    or shift.operands[1].reg != load.operands[0].reg
                    or branch is None or branch.id != a.ARM_INS_B
                    or branch.cc != a.ARM_CC_PL
                    or branch.operands[0].imm >= address):
                continue
            ready.add(use.address)
        if ready == {0x80001408, 0x80001508}:
            return function
    return None


def _stack_setup(stage_facts, reset):
    for literal in reset.literals:
        table = literal.value
        if table & 3 or not 0 <= table <= len(stage_facts.image) - 4:
            continue
        callbacks = []
        for offset in range(table, min(table + 0x80, len(stage_facts.image) - 3), 4):
            pointer = struct.unpack_from('<I', stage_facts.image, offset)[0]
            if pointer == 0:
                break
            if not 0 <= (pointer & ~1) < len(stage_facts.image):
                callbacks = []
                break
            callbacks.append(pointer)
        for pointer in callbacks:
            function = _function(stage_facts, pointer, budget=128)
            if not function.complete or function.unresolved or function.truncated:
                continue
            instructions = [stage_facts.decode(pc) for pc in function.instructions]
            stack_literals = [item.value for item in function.literals
                             if 0x03fe0000 <= item.value < _LOW_RAM_END]
            modes = [ins.operands[1].imm for ins in instructions
                     if ins.id == a.ARM_INS_MSR and len(ins.operands) == 2
                     and ins.operands[1].type == a.ARM_OP_IMM]
            stack_loads = [ins for ins in instructions if ins.id == a.ARM_INS_LDR
                           and ins.operands[0].reg == a.ARM_REG_SP]
            if (0x03ff5000 not in stack_literals or len(set(modes)) < 4
                    or len(stack_loads) < 4):
                continue
            return {'table': [table, offset + 4 - table], 'function': function,
                    'stack_end': max(stack_literals)}
    return None


