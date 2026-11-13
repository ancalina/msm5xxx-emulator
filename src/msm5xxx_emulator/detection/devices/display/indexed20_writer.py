"""Code-linked indexed halfword LCD writer on the 0x20000000 bus."""
from __future__ import annotations

import struct

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue

REQUIRES = {
    'find_boot_nand': ('storage.boot_nand', 'find_bootstrap_nand'),
    '_reset_called': ('external_bus.observations', 'reset_called'),
    'call_prefixes': ('display.indexed20_asset', 'call_prefixes'),
    'linked_stack_arguments': ('display.indexed20_asset', 'linked_stack_arguments'),
}


def _rgb332_palette():
    values = []
    for index in range(256):
        red, green, blue = index >> 5, index >> 2 & 7, index & 3
        red = red << 2 | red >> 1
        green = green << 3 | green
        blue = blue << 3 | blue << 1 | blue >> 1
        values.append(red << 11 | green << 5 | blue)
    return struct.pack('<256H', *values)


def _has_rgb565_indexed_palette(stage, start):
    """Require all 256 source colors to follow the linked RGB332→RGB565 map."""
    return (type(start) is int and 0 <= start <= len(stage) - 512
            and stage[start:start + 512] == _rgb332_palette())


def _span(facts, function, source):
    start = min(pc.address for pc in function.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {'span': [source + start, end - start], 'extra_spans': [
        [source + literal.pool, 4] for literal in function.literals]}


def _writes(function, port):
    return tuple((use.address, use.value) for use in function.accesses
                 if use.operation == 'write' and use.width == 2
                 and use.address == port and use.predicate == a.ARM_CC_AL)


def _owners(facts, site, limit=0x1000):
    for address in range(max(0, site - limit) & ~1, site, 2):
        ins = facts.decode(CodeAddress(address))
        if (ins is None or ins.id != a.ARM_INS_PUSH
                or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR
                           for op in ins.operands)):
            continue
        function = facts.function(CodeAddress(address), budget=768)
        if (function.complete and not function.unresolved and not function.truncated
                and CodeAddress(site) in function.instructions):
            yield function


def _pixel_count_loops(function, facts, data_port, width, height, *, after=None):
    pixels = [use for use in function.accesses if use.operation == 'write'
              and use.address == data_port and use.width == 2
              and type(use.value) is int and 0 <= use.value <= 0xffff
              and (after is None or use.instruction.address > after)]
    for pixel in pixels:
        loops = []
        for source, target in function.back_edges:
            if not target <= pixel.instruction.address <= source:
                continue
            branch = facts.decode(CodeAddress(source))
            sub = facts.decode(CodeAddress(source - 2))
            if (branch is None or branch.id != a.ARM_INS_B or branch.cc != a.ARM_CC_HS
                    or sub is None or sub.id != a.ARM_INS_SUB
                    or len(sub.operands) != 2 or sub.operands[1].type != a.ARM_OP_IMM):
                continue
            loops.append((target, source, sub))
        for inner in loops:
            for outer in loops:
                if not outer[0] < inner[0] < inner[1] < outer[1]:
                    continue
                inner_initializers = []
                for address in range(max(0, inner[0] - 8), pixel.instruction.address, 2):
                    ins = facts.decode(CodeAddress(address))
                    if (ins is not None and ins.id in (a.ARM_INS_MOVS, a.ARM_INS_MOV)
                            and len(ins.operands) == 2
                            and ins.operands[1].type == a.ARM_OP_IMM):
                        inner_initializers.append(ins.operands[1].imm)
                cut_edges = tuple((CodeAddress(start), CodeAddress(end))
                                  for start, end in function.back_edges)
                remaining = facts.register_value(function, CodeAddress(outer[1]),
                    outer[2].operands[0].reg, cut_edges=cut_edges)
                if (width in inner_initializers and isinstance(remaining, SymbolicValue)
                        and remaining.kind == 'const'
                        and remaining.value + outer[2].operands[1].imm == height):
                    return True
    return False


def _candidate_functions(facts):
    calls = facts.call_candidates('thumb')
    targets = {target for _, target in calls}
    windows = []
    cursors = []
    for target in targets:
        function = facts.function(CodeAddress(target), budget=128,
            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 1,
                               a.ARM_REG_R2: 0, a.ARM_REG_R3: 1})
        if not function.complete or function.unresolved or function.truncated or function.calls:
            continue
        command_writes = [(use.address, use.value) for use in function.accesses
                          if use.operation == 'write' and use.width == 2
                          and use.value in (0x210, 0x211, 0x212, 0x213)]
        if tuple(value for _, value in command_writes) == (0x210, 0x211, 0x212, 0x213):
            command_port = command_writes[0][0]
            if all(address == command_port for address, _ in command_writes):
                data_addresses = {use.address for use in function.accesses
                                  if use.operation == 'write' and use.width == 2
                                  and use.address != command_port}
                for data_port in data_addresses:
                    data_writes = [use for use in function.accesses
                                   if use.operation == 'write' and use.width == 2
                                   and use.address == data_port]
                    if len(data_writes) == 4:
                        windows.append((target, command_port, data_port))
        position = facts.function(CodeAddress(target), budget=96,
            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 0})
        if not position.complete or position.unresolved or position.truncated or position.calls:
            continue
        commands = [(use.address, use.value) for use in position.accesses
                    if use.operation == 'write' and use.width == 2
                    and use.value in (0x200, 0x201)]
        if tuple(value for _, value in commands) == (0x200, 0x201):
            command_port = commands[0][0]
            data_addresses = {use.address for use in position.accesses
                              if use.operation == 'write' and use.width == 2
                              and use.address != command_port}
            for data_port in data_addresses:
                writes = [use for use in position.accesses if use.operation == 'write'
                          and use.width == 2 and use.address == data_port]
                if len(writes) == 2:
                    cursors.append((target, command_port, data_port))
    return calls, windows, cursors


def _decoder_shape(function, facts, palette_start, asset_register, *, indexed_palette=False):
    instruction_pcs = set(function.instructions)
    if indexed_palette:
        addresses = [pc.address for pc in function.instructions]
        low, high = min(addresses, default=0), max(addresses, default=-1)
        for reference in facts.literal_references(palette_start):
            if low <= reference.instruction.address <= high:
                related = facts.function(reference.instruction, budget=2048)
                instruction_pcs.update(related.instructions)
    instructions = [facts.decode(pc) for pc in sorted(instruction_pcs,
        key=lambda pc: pc.address)]
    has_table = False
    has_halfword_output = False
    saves_r2 = False
    reloads_stack_r2 = False
    loaded_offsets = {}
    header_offsets = set()
    magic_checks = set()
    function_addresses = [pc.address for pc in function.instructions]
    low = min(function_addresses, default=0)
    high = max(function_addresses, default=-1)
    palette_registers = {literal.register for literal in facts.literal_references(palette_start)
                         if low <= literal.instruction.address <= high}
    tainted = set()
    lookup_registers = set()
    scaled_indices = set()
    asset_reads = 0
    for ins in instructions:
        if ins is None:
            continue
        if ins.id == a.ARM_INS_PUSH and any(
                op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_R2
                for op in ins.operands):
            saves_r2 = True
            tainted.add(a.ARM_REG_R2)
        if (saves_r2 and ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                and ins.operands[0].reg == a.ARM_REG_R2
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == a.ARM_REG_SP):
            reloads_stack_r2 = True
            tainted.add(a.ARM_REG_R2)
        if (ins.id == a.ARM_INS_LDRH and len(ins.operands) == 2
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.index
                and ins.operands[1].mem.base in palette_registers):
            has_table = True
            lookup_registers.add(ins.operands[0].reg)
            if ins.operands[1].mem.index in scaled_indices:
                scaled_indices.add(ins.operands[0].reg)
        if (ins.id == a.ARM_INS_LSL
                and len(ins.operands) >= 2
                and ins.operands[0].reg == ins.operands[1].reg
                and ((len(ins.operands) == 3 and ins.operands[2].type == a.ARM_OP_IMM
                      and ins.operands[2].imm == 1)
                     or (len(ins.operands) == 2 and ins.operands[1].type == a.ARM_OP_IMM
                         and ins.operands[1].imm == 1))):
            scaled_indices.add(ins.operands[0].reg)
        if (ins.id in (a.ARM_INS_ADD, a.ARM_INS_MOV) and len(ins.operands) >= 2
                and any(op.type == a.ARM_OP_REG and op.reg in tainted
                        for op in ins.operands[1:])):
            tainted.add(ins.operands[0].reg)
        if (saves_r2 and ins.id == a.ARM_INS_STRH
                and len(ins.operands) == 2 and ins.operands[0].reg in lookup_registers
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base in tainted):
            has_halfword_output = True
        if (ins.id == a.ARM_INS_LDRB and len(ins.operands) == 2
                and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base == asset_register):
            asset_reads += 1
            offset = ins.operands[1].mem.disp
            if offset in (0, 1, 3, 4):
                header_offsets.add(offset)
                loaded_offsets[ins.operands[0].reg] = offset
        if (ins.id == a.ARM_INS_CMP and len(ins.operands) == 2
                and ins.operands[0].reg in loaded_offsets
                and ins.operands[1].type == a.ARM_OP_IMM
                and ins.operands[1].imm in (0x49, 0x43)):
            magic_checks.add((loaded_offsets[ins.operands[0].reg], ins.operands[1].imm))
    if not (has_table and has_halfword_output and scaled_indices & lookup_registers):
        return False
    if indexed_palette:
        return asset_reads >= 3 and {3, 4} <= header_offsets
    return (header_offsets == {0, 1, 3, 4}
            and magic_checks == {(0, 0x49), (1, 0x43)})


def _pixel_blitter(function, facts, framebuffer, data_port):
    if not any(literal.value == framebuffer for literal in function.literals):
        return False
    instructions = [facts.decode(pc) for pc in function.instructions]
    halfword_reads = [ins for ins in instructions if ins is not None
                      and ins.id == a.ARM_INS_LDRH and len(ins.operands) == 2]
    halfword_writes = [ins for ins in instructions if ins is not None
                       and ins.id == a.ARM_INS_STRH and len(ins.operands) == 2]
    if not halfword_reads or not halfword_writes:
        return False
    loaded_regs = {ins.operands[0].reg for ins in instructions if ins is not None
                   and ins.id == a.ARM_INS_LDR and len(ins.operands) == 2
                   and ins.operands[1].type == a.ARM_OP_MEM
                   and ins.operands[1].mem.base == a.ARM_REG_PC
                   and any(pool.instruction.address == ins.address and pool.value == framebuffer
                           for pool in function.literals)}
    tainted = set(loaded_regs)
    reads_buffer = False
    for ins in instructions:
        if ins is None or len(ins.operands) < 2:
            continue
        if (ins.id == a.ARM_INS_LDRH and ins.operands[1].type == a.ARM_OP_MEM
                and ins.operands[1].mem.base in tainted):
            reads_buffer = True
        if ins.id in (a.ARM_INS_ADD, a.ARM_INS_MOV):
            destination = ins.operands[0].reg
            if any(op.type == a.ARM_OP_REG and op.reg in tainted for op in ins.operands[1:]):
                tainted.add(destination)
    writes_port = any(use.address == data_port and use.operation == 'write'
                      and use.width == 2 for use in function.accesses)
    return bool(reads_buffer and writes_port)


def _linked_asset(stage, facts, reset_targets, palette_start,
                  data_port, window_target, cursor_target, width, height):
    calls = facts.call_candidates('thumb')
    targets = {target for _, target in calls}
    for at in facts.literal_references(palette_start):
        pc = at.instruction
        if pc.isa != 'thumb':
            continue
        for target in targets:
            if not 0 <= pc.address - target < 0x1000:
                continue
            decoder = facts.function(CodeAddress(target), budget=2048)
            decoder_addresses = [item.address for item in decoder.instructions]
            if (not decoder.complete or decoder.unresolved or decoder.truncated
                    or not decoder_addresses
                    or not min(decoder_addresses) <= pc.address <= max(decoder_addresses)):
                continue
            asset_literals = [literal for pc in decoder.instructions
                              if (literal := facts.literal(pc)) is not None
                              and type(literal.value) is int
                              and 0 <= literal.value < len(stage)]
            assets = [(literal.value, literal.register) for literal in asset_literals
                      if literal.value <= len(stage) - 5
                      and stage[literal.value:literal.value + 2] == b'IC']
            assets.extend((literal.value, literal.register) for literal in asset_literals
                          if literal.value <= len(stage) - 5
                          and literal.value not in {value for value, _ in assets})
            asset, asset_register, indexed_palette = next(((value, register, False)
                for value, register in assets
                if _decoder_shape(decoder, facts, palette_start, register)),
                (None, None, False))
            if asset is None:
                asset, asset_register, indexed_palette = next(((literal.value, literal.register, True)
                    for literal in asset_literals
                    if _decoder_shape(decoder, facts, palette_start, literal.register,
                                      indexed_palette=True)), (None, None, False))
            decoder_calls = [(site, callee) for site, callee in calls if callee == target]
            for reset_target in reset_targets:
                if not reset_target & 1:
                    continue
                reset_caller = facts.function(CodeAddress(reset_target & ~1), budget=2048)
                if not reset_caller.instructions:
                    continue
                reset_addresses = [pc.address for pc in reset_caller.instructions]
                reset_low, reset_high = min(reset_addresses), max(reset_addresses)
                computed_dispatch = any(
                    (ins := facts.decode(pc)) is not None
                    and ins.id == a.ARM_INS_ADD
                    and ins.operands and ins.operands[0].reg == a.ARM_REG_PC
                    for pc in reset_caller.instructions)
                if not computed_dispatch:
                    continue
                for call_site, _ in decoder_calls:
                    if not reset_low <= call_site < reset_high:
                        continue
                    for caller in call_prefixes(facts, call_site):
                        sites = sorted(caller.call_sites, key=lambda site: site.site.address)
                        index = next((n for n, item in enumerate(sites)
                                      if item.site.address == call_site and item.target.address == target), None)
                        if index is None:
                            continue
                        call = sites[index]
                        stack_link = linked_stack_arguments(
                            stage, facts, caller, call, decoder, palette_start,
                            data_port, window_target, cursor_target, width, height,
                            _decoder_shape, _pixel_blitter)
                        if stack_link is not None:
                            return (decoder, reset_caller, caller, stack_link[0],
                                    stack_link[1], stack_link[2], stack_link[3],
                                    stack_link[4], stack_link[5])
                    if asset is None:
                        continue
                    caller = facts.function(CodeAddress(max(0, call_site - 8)), budget=256)
                    if not caller.complete or caller.unresolved or caller.truncated:
                        continue
                    sites = sorted(caller.call_sites, key=lambda site: site.site.address)
                    index = next((n for n, item in enumerate(sites)
                                  if item.site.address == call_site and item.target.address == target), None)
                    if index is None:
                        continue
                    call = sites[index]
                    args = dict(call.registers)
                    framebuffer = args.get(a.ARM_REG_R2)
                    if (call.target.address != target or type(framebuffer) is not int
                            or not 0x01000000 <= framebuffer <= 0x04000000 - 2):
                        continue
                    x0, y0 = args.get(a.ARM_REG_R0), args.get(a.ARM_REG_R1)
                    if type(x0) is not int or type(y0) is not int:
                        continue
                    for following in sites[index + 1:]:
                        if following.site.address - call.site.address > 0x40:
                            break
                        blit_args = dict(following.registers)
                        x1, y1 = blit_args.get(a.ARM_REG_R2), blit_args.get(a.ARM_REG_R3)
                        if (blit_args.get(a.ARM_REG_R0) != x0
                                or blit_args.get(a.ARM_REG_R1) != y0
                                or type(x1) is not int or type(y1) is not int
                                or not 2 <= x1 - x0 <= width
                                or not 2 <= y1 - y0 <= height):
                            continue
                        writer = facts.function(following.target, budget=256)
                        veneer = None
                        if len(writer.calls) == 1 and not writer.accesses:
                            veneer = writer
                            writer = facts.function(writer.calls[0][1], budget=256)
                        if (not writer.complete or writer.unresolved or writer.truncated
                                or {site.target.address for site in writer.call_sites}
                                != {window_target, cursor_target}
                                or not _pixel_blitter(writer, facts, framebuffer, data_port)):
                            continue
                        asset_width = (stage[asset + 3] if not indexed_palette else x1 - x0)
                        asset_height = (stage[asset + 4] if not indexed_palette else y1 - y0)
                        if (not 2 <= asset_width <= width or not 2 <= asset_height <= height
                                or x1 - x0 != asset_width or y1 - y0 != asset_height
                                or x0 + asset_width > width or y0 + asset_height > height):
                            continue
                        return decoder, reset_caller, caller, veneer, writer, x0, y0, framebuffer, asset
    return None


def _window_geometry(arguments):
    values = tuple(arguments.get(register) for register in
                   (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3))
    if (any(type(value) is not int for value in values)
            or values[0] != 0 or values[2] != 0
            or not 1 <= values[1] <= 511 or not 1 <= values[3] <= 511):
        return None
    return values[1] + 1, values[3] + 1


def _clear_setups(clear, facts, command_port, data_port, window_target,
                  cursor_targets, window_targets):
    """Pair each source-set window/cursor with a following pixel clear."""
    if not any(literal.value == data_port for literal in clear.literals):
        return ()
    calls = sorted((site for site in clear.call_sites
                    if site.target.address == window_target
                    or site.target.address in cursor_targets),
                   key=lambda site: site.site.address)
    window_calls = [site for site in calls if site.target.address == window_target]
    cursor_calls = [site for site in calls if site.target.address in cursor_targets]
    pixel_commands = [use for use in clear.accesses
                      if use.operation == 'write' and use.address == command_port
                      and use.width == 2 and use.value == 0x202]
    setups = []
    for window in window_calls:
        geometry = _window_geometry(dict(window.registers))
        if geometry is None:
            continue
        width, height = geometry
        cursor = next((site for site in calls
                       if site.site.address > window.site.address), None)
        if cursor is not None and cursor.target.address not in cursor_targets:
            cursor = None
        if (cursor is None or dict(cursor.registers).get(a.ARM_REG_R0) != 0
                or dict(cursor.registers).get(a.ARM_REG_R1) != 0):
            continue
        next_setup = min((site.site.address for site in calls
                          if site.site.address > cursor.site.address), default=1 << 32)
        command = next((item for item in pixel_commands
                        if cursor.site.address < item.instruction.address < next_setup), None)
        if command is not None and _pixel_count_loops(
                clear, facts, data_port, width, height,
                after=command.instruction.address):
            setups.append((window, cursor, command, width, height))
    return tuple(setups)


def _select_profile(profiles):
    if not profiles:
        return None
    keys = {(item['width'], item['height'], item['x_origin'], item['y_origin'],
             item['command_port'], item['data_port'], item.get('_clear_owner'))
            for item in profiles}
    if len(keys) == 1:
        selected = dict(profiles[0])
        selected.pop('_clear_owner', None)
        return selected
    if (len({(item['command_port'], item['data_port']) for item in profiles}) != 1
            or len({item.get('_clear_owner') for item in profiles}) != 1
            or None in {item.get('_clear_owner') for item in profiles}):
        return None
    largest = max(item['width'] * item['height'] for item in profiles)
    winners = [item for item in profiles if item['width'] * item['height'] == largest]
    winner_keys = {(item['width'], item['height'], item['x_origin'], item['y_origin'])
                   for item in winners}
    if len(winner_keys) != 1:
        return None
    primary = winners[0]
    if any(primary['width'] < item['width'] or primary['height'] < item['height']
           for item in profiles):
        return None
    for index, left in enumerate(profiles):
        for right in profiles[index + 1:]:
            x_overlap = (left['x_origin'] < right['x_origin'] + right['width']
                         and right['x_origin'] < left['x_origin'] + left['width'])
            y_overlap = (left['y_origin'] < right['y_origin'] + right['height']
                         and right['y_origin'] < left['y_origin'] + left['height'])
            if x_overlap and y_overlap:
                return None
    selected = dict(primary)
    selected.pop('_clear_owner', None)
    return selected


def find_indexed20(image: bytes, bootstrap=None):
    bootstrap = find_boot_nand(image) if bootstrap is None else bootstrap
    if not isinstance(bootstrap, dict):
        return None
    source, length = bootstrap.get('stage_source'), bootstrap.get('stage_size')
    if (type(source) is not int or type(length) is not int
            or not 0 <= source < source + length <= len(image)):
        return None
    stage = image[source:source + length]
    facts = facts_for(stage)
    palette_blob = _rgb332_palette()
    palette_start = stage.find(palette_blob)
    indexed_palettes = {palette_start} if palette_start >= 0 else set()
    if not indexed_palettes:
        # A source-linked byte-indexed decoder can define its own 256-entry
        # halfword palette. Candidate bases come only from its literal loads;
        # _decoder_shape then proves indexed lookup and framebuffer output.
        for site, target in facts.call_candidates('thumb'):
            function = facts.function(CodeAddress(target), budget=2048)
            if not function.complete or function.unresolved or function.truncated:
                continue
            addresses = [pc.address for pc in function.instructions]
            if not addresses:
                continue
            references = facts.literal_references_in(((min(addresses), max(addresses) + 1),))
            asset_registers = {ref.register for item in function.instructions
                               if (ref := facts.literal(item)) is not None
                               and type(ref.value) is int
                               and 0 <= ref.value < len(stage)}
            for literal in references:
                if (type(literal.value) is int
                        and _has_rgb565_indexed_palette(stage, literal.value)
                        and any(_decoder_shape(function, facts, literal.value, register,
                                               indexed_palette=True)
                                for register in asset_registers)):
                    indexed_palettes.add(literal.value)
    if not indexed_palettes:
        return None
    calls, windows, cursors = _candidate_functions(facts)
    reset_targets = _reset_called(stage) or ()
    profiles = []
    for window_target, command_port, window_data_port in windows:
        window_calls = [(site, target) for site, target in calls if target == window_target]
        for window_site, _ in window_calls:
            for clear in _owners(facts, window_site):
                if not any(use.operation == 'write' and use.address == command_port
                           and use.width == 2 and use.value == 0x202
                           for use in clear.accesses):
                    continue
                data_ports = {use.address for use in clear.accesses
                              if use.operation == 'write' and use.width == 2
                              and type(use.value) is int
                              and 0 <= use.value <= 0xffff
                              and use.address == window_data_port}
                for data_port in data_ports:
                    cursor_targets = {target for target, _, port in cursors
                                      if port == data_port}
                    setups = _clear_setups(clear, facts, command_port, data_port,
                                           window_target, cursor_targets,
                                           {item[0] for item in windows})
                    for window, cursor, pixel_command, width, height in setups:
                        window_fn = facts.function(CodeAddress(window_target), budget=128,
                            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: width - 1,
                                               a.ARM_REG_R2: 0, a.ARM_REG_R3: height - 1})
                        cursor_fn = facts.function(CodeAddress(cursor.target.address), budget=96,
                            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 0})
                        if any(not body.complete or body.unresolved or body.truncated or body.calls
                               for body in (window_fn, cursor_fn)):
                            continue
                        command_writes = _writes(window_fn, command_port)
                        data_writes = _writes(window_fn, data_port)
                        cursor_commands = _writes(cursor_fn, command_port)
                        cursor_data = _writes(cursor_fn, data_port)
                        if (tuple(value for _, value in command_writes) != (0x210, 0x211, 0x212, 0x213)
                                or len(data_writes) != 4
                                or data_writes[0][1:2] != (0,)
                                or data_writes[1][1:2] != (width - 1,)
                                or tuple(value for _, value in cursor_commands) != (0x200, 0x201)
                                or len(cursor_data) != 2 or cursor_data[0][1] != 0):
                                continue
                        y_origin = data_writes[2][1]
                        if (type(y_origin) is not int or data_writes[3][1] != y_origin + height - 1
                                or cursor_data[1][1] != y_origin):
                            continue
                        for cursor_target, cursor_port, cursor_data_port in cursors:
                            if (cursor_target != cursor.target.address
                                    or cursor_port != command_port or cursor_data_port != data_port):
                                continue
                            for palette_start in indexed_palettes:
                                linked = _linked_asset(stage, facts, reset_targets, palette_start,
                                    data_port, window_target, cursor_target, width, height)
                                if linked is None:
                                    continue
                                decoder, reset_caller, caller, veneer, writer, x_asset, y_asset, framebuffer, asset = linked
                                evidence = [*bootstrap.get('evidence', ()),
                                            {'span': [source + palette_start, 512]}]
                                for function in (clear, window_fn, cursor_fn, decoder,
                                                 reset_caller, caller, writer):
                                    evidence.append(_span(facts, function, source))
                                if asset is not None:
                                    evidence.append({'span': [source + asset, 5]})
                                if veneer is not None:
                                    evidence.append(_span(facts, veneer, source))
                                profiles.append({'protocol': 'indexed20-rgb565', 'width': width,
                                    'height': height, 'x_origin': 0, 'y_origin': y_origin,
                                    'command_port': command_port, 'data_port': data_port,
                                    '_clear_owner': clear.entry.address,
                                    'evidence': evidence})
    return _select_profile(profiles)
