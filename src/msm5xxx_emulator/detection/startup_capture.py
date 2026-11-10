"""Closed reset, mode-stack and copied-startup observations."""
from capstone import arm as a
from .arm import arm_b_target
from .facts import CodeAddress, facts_for
from .startup_facts import proven_startup_rows
from ..core.config import CopyLayout, LinkerLayout
from .contracts import (SourceContractError as _Unclosed, require_source as _need, source_word as _word, source_thumb_literal as _literal, within_ram as _in_ram)

def _arm_literal(image, pc, expected):
    word = _word(image, pc)
    _need(word & 0xfffff000 == expected, 'arm-literal-producer')
    literal = facts_for(image).literal(CodeAddress(pc, 'arm'))
    _need(literal is not None, 'arm-literal-source')
    return literal.value

def normal_startup_copy(image, ram_base, ram_size):
    root = arm_b_target(image,0)
    _need(root is not None and not root & 3, 'reset-owner')
    def group(pc):
        _need(_word(image,pc+4)==0xe3140001 and _word(image,pc+16)==0xe12fff14 and _word(image,pc+20)==0x4778, 'reset-interwork')
        target = _arm_literal(image,pc,0xe59f4000)
        _need(target & 1 and target < len(image), 'reset-callee')
        _need(_arm_literal(image,pc+8,0x159fe000)==pc+21 and _arm_literal(image,pc+12,0x059fe000)==pc+24, 'reset-return')
    pc = root
    for _ in range(3):
        group(pc);pc += 24
    mode_stacks = {}
    for mode in (0xe321f0d7,0xe321f0db,0xe321f0d3):
        _need(_word(image,pc)==mode,'reset-stack')
        sp = _arm_literal(image,pc+4,0xe59fd000)
        _need(not sp & 3 and ram_base < sp <= ram_base+ram_size,'stack-outside-ram')
        mode_stacks[mode] = sp
        pc += 8
    count = 0
    while count < 4 and _word(image,pc)!=0xe3500000:
        group(pc);pc += 24;count += 1
    _need(count in (3,4) and _word(image,pc)==0xe3500000 and _word(image,pc+4)==0x1a000003,'normal-route')
    normal = arm_b_target(image,pc+8)
    _need(normal is not None and not normal & 3,'normal-entry')
    fixed = {0:0xe321f0d2,8:0xe321f0df,16:0xe321f0d1,20:0xe02dd00d, 28:0xe321f0d3,36:0xe3100001,48:0xe12fff10,52:0x4778,60:0xe12fff12}
    _need(all(_word(image,normal+off)==value for off,value in fixed.items()),'normal-gate')
    for off in (4,12,24):
        sp = _arm_literal(image,normal+off,0xe59fd000)
        _need(not sp & 3 and ram_base < sp <= ram_base+ram_size,'normal-stack')
    copy_value = _arm_literal(image,normal+32,0xe59f0000)
    _need(copy_value & 1,'copy-isa')
    copy = copy_value & ~1
    _need(_arm_literal(image,normal+40,0x159fe000)==normal+53 and _arm_literal(image,normal+44,0x059fe000)== normal+56,'copy-return')
    _need(_literal(image,copy,1)==0x03000700 and _literal(image,copy+0xd6,3)==0x048000a0,'copy-io-domain')
    # Keep the bounded ARM route above as the existing reset/normal-mode
    # contract, then bind its Thumb target and active SVC stack to the shared
    # startup-copy consumer proof.
    facts = facts_for(image)
    target_ranges = ((ram_base, ram_base + ram_size), (0x03800000, 0x03a00000))
    stack_pointer = mode_stacks[0xe321f0d3]
    function = facts.function(CodeAddress(copy, 'thumb'), budget=4096, initial_registers={a.ARM_REG_SP: stack_pointer}, symbolic_registers={})
    _need(function.complete and not function.truncated and not function.unresolved, 'copy-function-source')
    # The descriptor and row tables are initialized before the first call.
    # They describe this copy-complete epoch; the native consumers separately
    # check the active object/descriptor at each guarded access.
    calls = {site for site, _target in function.calls}
    frontiers = {site for site in calls if all(site == other or function.dominates(site, other) for other in calls)}
    _need(not calls or len(frontiers) == 1, 'copy-completion-ambiguous')
    completion = next(iter(frontiers), None)
    rows_with_proofs = proven_startup_rows(facts, CodeAddress(copy, 'thumb'), target_ranges=target_ranges, zero_ranges=((ram_base, ram_base + ram_size),),
        extra_write_ranges=((0x03000600, 0x03000780), (0x048000a4, 0x048000a6)), initial_sp=stack_pointer, completion=completion)
    _need(len(rows_with_proofs) == 4, 'copy-startup-context')
    rows = [row for row, _proof in rows_with_proofs]
    procedure = rows_with_proofs[0][1].procedure
    _need(procedure is not None, 'copy-procedure-source')
    side_effect_addresses = {write.address for write in procedure.side_effect_writes}
    _need(0x03000700 in side_effect_addresses and any(write.address == 0x048000a4 and write.width == 2 for write in procedure.side_effect_writes),
        'copy-io-domain')
    _need(rows[0].zero_target is not None and rows[1].zero_target is not None and rows[2].zero_target is not None and rows[3].zero_target is None,
        'copy-zero-rows')
    _need(_in_ram(rows[0].target, rows[0].size, ram_base, ram_size) and _in_ram(rows[0].zero_target, rows[0].zero_size, ram_base, ram_size), 'copy-outside-ram')
    copies = [CopyLayout(row.table, row.source, row.target, row.size) for row in rows]
    layout = LinkerLayout(rows[0].table, rows[0].source, rows[0].target, rows[0].size, rows[0].zero_target, rows[0].zero_size)
    writes = [(rows[0].zero_target, rows[0].zero_size)]
    writes.extend((row.target, row.size) for row in rows[1:])
    writes.extend((row.zero_target, row.zero_size) for row in rows[1:3])
    literal_spans = {(literal.pool, literal.pool + 4) for literal in function.literals}
    copy_code_spans = []
    for site in function.instructions:
        instruction = facts.decode(site)
        if instruction is None:
            raise _Unclosed('copy-instruction-source')
        copy_code_spans.append((site.address, site.address + instruction.size))
    copy_code_spans.extend(procedure.helper_code_spans)
    table_spans = [(row.table, row.table + (20 if row.zero_table is not None else 12)) for row in rows]
    return dict(root=root, decision=pc, normal=normal, copy=copy, layout=layout, copies=copies, writes=writes, startup_code_intervals=sorted(set(copy_code_spans)),
        startup_literal_intervals=sorted(literal_spans), startup_table_intervals=table_spans)
