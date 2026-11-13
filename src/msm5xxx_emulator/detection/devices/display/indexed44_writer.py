"""Code proof for the indexed halfword LCD command/data port pair."""
from __future__ import annotations

from bisect import bisect_left
import struct

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for


_COMMANDS = (0x44, 0x45)
_CURSOR = 0x21
_PIXELS = 0x22
_RAM_LOW = 0x10000000
_RAM_HIGH = 0x20000000


def _body_ok(body):
    return (body.complete and not body.unresolved and not body.truncated
            and bool(body.instructions))


def _span(facts, body):
    low = min(pc.address for pc in body.instructions)
    high = max(pc.address + facts.decode(pc).size for pc in body.instructions)
    return {'span': [low, high - low], 'extra_spans': [
        [literal.pool, 4] for literal in body.literals]}


def _writes(body, address):
    return tuple(use for use in body.accesses
                 if use.operation == 'write' and use.width == 2
                 and use.address == address
                 and use.predicate == a.ARM_CC_AL)


def _closed_direct_helpers(facts, body, command_port):
    helpers = tuple(facts.function(target, budget=160)
                    for _, target in body.calls)
    if not all(_body_ok(helper) for helper in helpers):
        return None
    data_port = command_port + 0x10
    for helper in helpers:
        for use in helper.accesses:
            if use.operation != 'write':
                continue
            if use.address == command_port:
                if use.width != 2 or use.value not in (0x03, *_COMMANDS):
                    return None
            elif use.address == data_port:
                if use.width != 2:
                    return None
            elif not (type(use.address) is int
                      and _RAM_LOW <= use.address < _RAM_HIGH):
                return None
    return helpers


def _window_candidates(facts):
    calls = facts.call_candidates('thumb')
    targets = sorted({target for _, target in calls})
    command44, command45 = [], []
    for register in range(8):
        command44.extend(facts.string_candidates(
            struct.pack('<H', 0x2000 | (register << 8) | 0x44)))
        command45.extend(facts.string_candidates(
            struct.pack('<H', 0x2000 | (register << 8) | 0x45)))
    command44.sort()
    command45.sort()

    # Command setters in this protocol materialize both command bytes as
    # Thumb MOVS immediates within the short leaf body. Use those source
    # anchors to avoid building facts for every unrelated call target.
    possible = []
    for target in targets:
        first = bisect_left(command44, target)
        stop = bisect_left(command44, target + 0x100, first)
        if first == stop:
            continue
        second = bisect_left(command45, target)
        second_stop = bisect_left(command45, target + 0x100, second)
        if second < second_stop:
            possible.append(target)
    candidates = {}
    for target in possible:
        body = facts.function(CodeAddress(target), budget=160,
            initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 1,
                               a.ARM_REG_R2: 0, a.ARM_REG_R3: 1})
        if not _body_ok(body):
            continue
        commands = [use for use in body.accesses
                    if use.operation == 'write' and use.width == 2
                    and use.value in _COMMANDS]
        if tuple(use.value for use in commands) != _COMMANDS:
            continue
        command_port = commands[0].address
        if any(use.address != command_port for use in commands):
            continue
        if _closed_direct_helpers(facts, body, command_port) is None:
            continue
        data_writes = [use for use in body.accesses
                       if use.operation == 'write' and use.width == 2
                       and use.address != command_port]
        if (len(data_writes) != 2
                or any(use.address != command_port + 0x10 for use in data_writes)
                or any(type(use.value) is not int or not 0 <= use.value <= 0xffff
                       for use in data_writes)):
            continue
        x_origin, x_end = data_writes[0].value & 0xff, data_writes[0].value >> 8
        y_origin, y_end = data_writes[1].value & 0xff, data_writes[1].value >> 8
        if x_end - x_origin != 1 or y_end - y_origin != 1:
            continue
        candidates[target] = (body, command_port, command_port + 0x10,
                              x_origin, y_origin)
    return calls, candidates


def _owners(facts, site, limit=0x800):
    low = max(0, site - limit) & ~1
    for address in range(low, site, 2):
        ins = facts.decode(CodeAddress(address))
        if (ins is None or ins.id != a.ARM_INS_PUSH
                or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR
                           for op in ins.operands)):
            continue
        body = facts.function(CodeAddress(address), budget=768)
        if _body_ok(body) and CodeAddress(site) in body.instructions:
            yield body


def _call_args(body, site, target):
    return next((dict(call.registers) for call in body.call_sites
                 if call.site.address == site
                 and call.target.address == getattr(target, 'address', target)), None)


def _clear_counts(facts, body, data_port):
    """Return counted nested halfword-loop extents enclosing a solid clear."""
    backs = []
    for source, target in body.back_edges:
        branch = facts.decode(CodeAddress(source))
        decrement = facts.decode(CodeAddress(source - 2))
        if (branch is None or branch.id != a.ARM_INS_B
                or branch.cc != a.ARM_CC_NE or decrement is None
                or decrement.id != a.ARM_INS_SUB
                or len(decrement.operands) != 2
                or decrement.operands[1].type != a.ARM_OP_IMM
                or decrement.operands[1].imm != 1):
            continue
        backs.append((target, source, decrement.operands[0].reg))
    for store in _writes(body, data_port):
        if store.value != 0xffff:
            continue
        loops = [item for item in backs
                 if item[0] <= store.instruction.address <= item[1]]
        for inner in loops:
            for outer in loops:
                if not outer[0] < inner[0] < inner[1] < outer[1]:
                    continue
                counts = []
                for target, _, register in (inner, outer):
                    initial = None
                    for pc in sorted(body.instructions, key=lambda item: item.address):
                        if not target - 8 <= pc.address < target:
                            continue
                        ins = facts.decode(pc)
                        if (ins is not None and ins.id in (a.ARM_INS_MOVS, a.ARM_INS_MOV)
                                and len(ins.operands) == 2
                                and ins.operands[0].type == a.ARM_OP_REG
                                and ins.operands[0].reg == register
                                and ins.operands[1].type == a.ARM_OP_IMM):
                            initial = ins.operands[1].imm
                    if initial is None:
                        break
                    counts.append(initial)
                if len(counts) == 2 and all(1 < count <= 512 for count in counts):
                    return tuple(counts)
    return None


def _initial_cursor_proven(data_values, x_origin, y_origin):
    return (x_origin | (y_origin << 8)) in data_values


def _clear_profile(facts, body, window_target, command_port, data_port,
                   x_origin, y_origin):
    commands = tuple(use.value for use in _writes(body, command_port))
    if _CURSOR not in commands or _PIXELS not in commands:
        return None
    data_values = {use.value for use in _writes(body, data_port)}
    if (not _initial_cursor_proven(data_values, x_origin, y_origin)
            or 0xffff not in data_values):
        return None
    if _clear_counts(facts, body, data_port) is None:
        return None
    for site, target in body.calls:
        if target.address != window_target:
            continue
        args = _call_args(body, site.address, target.address)
        if args is None:
            continue
        x0, x1 = args.get(a.ARM_REG_R0), args.get(a.ARM_REG_R1)
        y0, y1 = args.get(a.ARM_REG_R2), args.get(a.ARM_REG_R3)
        if not all(type(value) is int for value in (x0, x1, y0, y1)):
            continue
        width, height = x1 - x0 + 1, y1 - y0 + 1
        loops = _clear_counts(facts, body, data_port)
        if (width < 2 or height < 2 or loops != (width, height)
                or x0 + x_origin != 0 or y0 + y_origin != y_origin):
            continue
        return width, height, x0, y0, site.address
    return None


def _has_stride132(body, facts, width):
    """Check the framebuffer row stride from its actual address arithmetic."""
    if width <= 0:
        return False
    instructions = [facts.decode(pc) for pc in sorted(body.instructions,
                                                     key=lambda item: item.address)]
    instructions = [ins for ins in instructions if ins is not None]
    for index, first in enumerate(instructions):
        if (first.id != a.ARM_INS_LSL or len(first.operands) != 3
                or first.operands[2].type != a.ARM_OP_IMM
                or first.operands[2].imm != 5):
            continue
        row_reg, source_reg = first.operands[0].reg, first.operands[1].reg
        for second_index in range(index + 1, min(len(instructions), index + 6)):
            second = instructions[second_index]
            if (second.id != a.ARM_INS_ADD or len(second.operands) != 3
                    or second.operands[0].reg != row_reg
                    or {second.operands[1].reg, second.operands[2].reg}
                       != {row_reg, source_reg}):
                continue
            for third in instructions[second_index + 1:second_index + 6]:
                if (third.id == a.ARM_INS_LSL and len(third.operands) == 3
                        and third.operands[0].reg == row_reg
                        and third.operands[1].reg == row_reg
                        and third.operands[2].type == a.ARM_OP_IMM
                        and third.operands[2].imm == 2
                        and width == 132):
                    return True
    return False


def _contains_load_site(value, site):
    return (isinstance(value, SymbolicValue)
            and ((value.kind == 'load' and value.width == 2 and value.site == site)
                 or any(_contains_load_site(item, site)
                        for item in value.operands)))


def _pixel_store_consumes(body, facts, source_load, command_port, data_port):
    if not isinstance(source_load, CodeAddress):
        return False
    load = facts.decode(source_load)
    if (load is None or load.id != a.ARM_INS_LDRH or len(load.operands) != 2
            or load.operands[1].type != a.ARM_OP_MEM):
        return False
    source_base = load.operands[1].mem.base
    symbolic_registers = {source_base: SymbolicValue.arg(0)}
    initial_registers = {}
    for use in body.accesses:
        if (use.operation != 'write' or use.width != 2
                or use.address != data_port or use.instruction.address <= source_load.address):
            continue
        store_ins = facts.decode(use.instruction)
        if (store_ins is None or len(store_ins.operands) != 2
                or store_ins.operands[1].type != a.ARM_OP_MEM):
            continue
        register = store_ins.operands[1].mem.base
        value = facts.register_value(body, source_load, register)
        if isinstance(value, SymbolicValue) and value.kind == 'const':
            initial_registers[register] = value.value
        elif type(value) is int:
            initial_registers[register] = value
    if source_base in initial_registers:
        return False
    symbolic = facts.function(source_load, budget=128,
        initial_registers=initial_registers,
        symbolic_registers=symbolic_registers,
        follow_back_edges=False)
    if symbolic.truncated:
        return False
    command_sites = tuple(use.instruction for use in _writes(body, command_port)
                          if use.value == _PIXELS)
    for store in symbolic.symbolic_accesses:
        if (store.operation != 'write' or store.width != 2
                or store.address.kind != 'const'
                or store.address.value != data_port
                or store.value is None
                or not _contains_load_site(store.value, source_load)):
            continue
        if (symbolic.linear_path(source_load, store.instruction) is not None
                and any(command in body.instructions
               and body.dominates(command, store.instruction)
               for command in command_sites)):
            return True
    return False


def _rgb565_swap(body, facts, command_port, data_port):
    """Prove a linked RGB565 red/blue swap using the 5/6/5 field widths."""
    if not _body_ok(body):
        return None
    instructions = [(pc, facts.decode(pc)) for pc in body.instructions]
    instructions = [(pc, ins) for pc, ins in instructions if ins is not None]
    has_command = any(use.value == _PIXELS for use in _writes(body, command_port))
    has_pixel_store = any(use.address == data_port for use in _writes(body, data_port))
    if not has_command or not has_pixel_store:
        return None
    for load_index, (load_pc, load) in enumerate(instructions):
        if (load.id != a.ARM_INS_LDRH or len(load.operands) != 2
                or load.operands[0].type != a.ARM_OP_REG):
            continue
        source = load.operands[0].reg
        prefix = instructions[load_index + 1:load_index + 20]
        masks = []
        green = []
        high_fields = []
        merges = []
        shifts = []
        for index, (_, ins) in enumerate(prefix):
            if (ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
                    and len(ins.operands) == 2
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[1].type == a.ARM_OP_IMM
                    and ins.operands[1].imm == 0x3f):
                masks.append((index, ins.operands[0].reg))
            if (ins.id == a.ARM_INS_LSL and len(ins.operands) == 3
                    and ins.operands[0].reg == ins.operands[1].reg
                    and ins.operands[2].type == a.ARM_OP_IMM):
                shifts.append((index, ins.operands[0].reg, ins.operands[2].imm))
            if (ins.id == a.ARM_INS_AND and len(ins.operands) == 2
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[1].type == a.ARM_OP_REG):
                green.append((index, ins.operands[0].reg, ins.operands[1].reg))
            if (ins.id == a.ARM_INS_LSR and len(ins.operands) == 3
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[1].reg == source
                    and ins.operands[2].type == a.ARM_OP_IMM):
                high_fields.append((index, ins.operands[0].reg, ins.operands[2].imm))
            if (ins.id == a.ARM_INS_ORR and len(ins.operands) == 2
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[1].type == a.ARM_OP_REG):
                merges.append((index, ins.operands[0].reg, ins.operands[1].reg))
        for mask_index, mask_reg in masks:
            if not any(index > mask_index and reg == mask_reg and amount == 5
                       for index, reg, amount in shifts):
                continue
            if not any(index > mask_index and destination == mask_reg and other == source
                       for index, destination, other in green):
                continue
            for red_index, red_reg, red_shift in high_fields:
                if red_shift != 11:
                    continue
                if not any(red_index < index
                           and destination == red_reg and other == mask_reg
                           for index, destination, other in merges):
                    continue
                for blue_index, reg, blue_shift in shifts:
                    if reg != source or blue_shift != 11 or blue_index <= red_index:
                        continue
                    if not any(index > blue_index and destination == source and other == red_reg
                               for index, destination, other in merges):
                        continue
                    return load_pc
    return None


def _rgb565_transfer(facts, calls, command_port, data_port,
                     window_targets=None):
    if window_targets is None:
        candidate_entries = sorted({getattr(target, 'address', target)
                                    for _, target in calls})
    else:
        window_targets = {getattr(target, 'address', target)
                          for target in window_targets}
        candidate_entries = set()
        for site, target in calls:
            if getattr(target, 'address', target) not in window_targets:
                continue
            for owner in _owners(facts, site, limit=0x800):
                if any(getattr(called, 'address', called) in window_targets
                       for _, called in owner.calls):
                    candidate_entries.add(owner.instructions[0].address)
        candidate_entries = sorted(candidate_entries)
    for address in candidate_entries:
        body = facts.function(CodeAddress(address), budget=512)
        if not _body_ok(body):
            continue
        source_load = _rgb565_swap(body, facts, command_port, data_port)
        if (source_load is None or not _pixel_store_consumes(
                body, facts, source_load, command_port, data_port)):
            continue
        # A command 44/45 setter must be called by the converter path.
        for _, called in body.calls:
            if (window_targets is not None
                    and getattr(called, 'address', called) not in window_targets):
                continue
            helper = facts.function(called, budget=96)
            if not _body_ok(helper):
                continue
            commands = tuple(use.value for use in _writes(helper, command_port)
                             if use.value in _COMMANDS)
            data = _writes(helper, data_port)
            if commands == _COMMANDS and len(data) == 2:
                return body, helper
    return None


def _has_cursor_stream(commands):
    return any(command == _CURSOR and _PIXELS in commands[index + 1:]
               for index, command in enumerate(commands))


def _main_blitter(body, facts, command_port, data_port, window_target, width,
                  height):
    if not _body_ok(body) or not _has_stride132(body, facts, width):
        return None
    commands = tuple(use.value for use in _writes(body, command_port)
                     if use.value in (_CURSOR, _PIXELS))
    if not _has_cursor_stream(commands):
        return None
    if not _writes(body, data_port):
        return None
    linked_window = any(target.address == window_target for _, target in body.calls)
    return body if linked_window else None


def _find_indexed44(image: bytes):
    """Return the closed main-panel profile, or ``None`` on ambiguity/gaps."""
    facts = facts_for(image)
    calls, windows = _window_candidates(facts)
    if not windows:
        return None
    profiles = []
    window_groups = {}
    for target, (_, command_port, data_port, _, _) in windows.items():
        window_groups.setdefault((command_port, data_port), set()).add(target)
    rgb565_pairs = {ports: _rgb565_transfer(facts, calls, *ports,
        window_targets=targets) for ports, targets in window_groups.items()}
    for window_target, (window, command_port, data_port, x_origin, y_origin) in windows.items():
        window_helpers = _closed_direct_helpers(facts, window, command_port)
        if window_helpers is None:
            continue
        rgb565_pair = rgb565_pairs.get((command_port, data_port))
        if rgb565_pair is None:
            continue
        rgb565, rgb565_window = rgb565_pair
        for site, target in calls:
            if target != window_target:
                continue
            for clear in _owners(facts, site):
                geometry = _clear_profile(facts, clear, window_target,
                    command_port, data_port, x_origin, y_origin)
                if geometry is None:
                    continue
                width, height, _, _, clear_call = geometry
                for blit_site, blit_target in calls:
                    if blit_target != window_target:
                        continue
                    for blitter in _owners(facts, blit_site):
                        body = _main_blitter(blitter, facts, command_port,
                            data_port, window_target, width, height)
                        if body is None:
                            continue
                        evidence = [_span(facts, item) for item in
                                    (window, clear, body, rgb565, rgb565_window)]
                        evidence.extend(_span(facts, helper)
                                        for helper in window_helpers)
                        evidence.append({'span': [site, 4]})
                        evidence.append({'span': [clear_call, 4]})
                        evidence.append({'span': [blit_site, 4]})
                        profiles.append({'protocol': 'indexed44-rgb565',
                            'width': width, 'height': height,
                            'x_origin': x_origin, 'y_origin': y_origin,
                            'command_port': command_port, 'data_port': data_port,
                            'evidence': evidence})
    keys = {(item['width'], item['height'], item['x_origin'],
             item['y_origin'], item['command_port'], item['data_port'])
            for item in profiles}
    if len(keys) != 1:
        return None
    first = profiles[0]
    first['evidence'] = [entry for item in profiles for entry in item['evidence']]
    return first


def find_indexed44(image: bytes):
    """Reuse one immutable source profile across detector and transport."""
    facts = facts_for(image)
    return facts.memo('indexed44-source-writer', (),
                      lambda: _find_indexed44(image))
