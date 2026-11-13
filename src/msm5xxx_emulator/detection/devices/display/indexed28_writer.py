"""Indexed halfword windows in a NAND-loaded bootstrap stage."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from .window51_writer import _clear_candidates

REQUIRES = {
    'find_boot_nand': ('storage.boot_nand', 'find_boot_nand'),
    '_reset_called': ('external_bus.observations', 'reset_called'),
}

_COMMAND = 0x28000000
_DATA = 0x28000100


def _writes(function):
    return tuple((use.address, use.value) for use in function.accesses
                 if use.operation == 'write' and use.width == 2
                 and use.address in (_COMMAND, _DATA)
                 and use.predicate == a.ARM_CC_AL)


def _evidence(facts, function, source):
    start = min(pc.address for pc in function.instructions)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {'span': [source + start, end - start], 'extra_spans': [
        [source + literal.pool, 4] for literal in function.literals]}


def find_indexed28(image: bytes, bootstrap=None):
    bootstrap = find_boot_nand(image) if bootstrap is None else bootstrap
    if bootstrap is None:
        return None
    source, length = bootstrap['stage_source'], bootstrap['stage_size']
    stage = image[source:source + length]
    facts = facts_for(stage)
    calls = facts.call_candidates('thumb')
    profiles = []
    for body, literal, store, width, height in _clear_candidates(
            stage, facts, data_ports=(_DATA,), maximum_height=512):
        entries = {target for _, target in calls
                   if body.entry.address - 8 <= target <= body.entry.address}
        for entry in sorted(entries):
            clear = facts.function(CodeAddress(entry), budget=256)
            if not clear.complete or clear.unresolved or clear.truncated:
                continue
            commands = [use for use in clear.accesses if use.operation == 'write'
                        and use.address == _COMMAND and use.width == 2]
            if len(commands) != 1 or commands[0].value != 0x202:
                continue
            setters = sorted(clear.call_sites, key=lambda site: site.site.address)
            if (len(setters) != 2 or any(site.site.address >= commands[0].instruction.address
                                       for site in setters)):
                continue
            limits, cursor = (dict(site.registers) for site in setters)
            expected = (0, width - 1, 0, height - 1)
            if (tuple(limits.get(register) for register in
                      (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3)) != expected
                    or (cursor.get(a.ARM_REG_R0), cursor.get(a.ARM_REG_R1)) != (0, 0)):
                continue
            window = facts.function(setters[0].target, budget=64,
                initial_registers=dict(zip((a.ARM_REG_R0, a.ARM_REG_R1,
                                            a.ARM_REG_R2, a.ARM_REG_R3), expected)))
            position = facts.function(setters[1].target, budget=64,
                initial_registers={a.ARM_REG_R0: 0, a.ARM_REG_R1: 0})
            if any(not function.complete or function.unresolved or function.calls
                   for function in (window, position)):
                continue
            window_writes = tuple(item for index, value in enumerate(expected)
                                  for item in ((_COMMAND, 0x210 + index), (_DATA, value)))
            if (_writes(window) != window_writes or _writes(position) != (
                    (_COMMAND, 0x200), (_DATA, 0), (_COMMAND, 0x201), (_DATA, 0))):
                continue
            # A second writer uses the same setters before copying pixel data.
            linked = [(site, target) for site, target in calls
                      if target == setters[0].target.address and site != setters[0].site.address]
            if not linked:
                continue
            color = _rgb565_source(stage, facts, setters, width, height)
            if color is None:
                continue
            color_functions, palette = color
            evidence = [*bootstrap['evidence'], {'span': [source + palette, 512]}]
            evidence.extend(_evidence(facts, function, source) for function in color_functions)
            evidence.extend(_evidence(facts, function, source)
                        for function in (clear, window, position))
            evidence.append({'span': [source + linked[0][0], 4]})
            profiles.append({'protocol': 'indexed28-rgb565', 'width': width, 'height': height,
                             'command_port': _COMMAND, 'data_port': _DATA,
                             'evidence': evidence})
    keys = {(item['width'], item['height']) for item in profiles}
    return profiles[0] if len(keys) == 1 else None


def _rgb565_source(stage, facts, setters, width, height):
    """Close a decoder's RGB332 expansion through its framebuffer blitter."""
    import struct
    from msm5xxx_emulator.detection.values import SymbolicValue

    palette = []
    for index in range(256):
        red, green, blue = index >> 5, index >> 2 & 7, index & 3
        red = red << 2 | red >> 1
        green = green << 3 | green
        blue = blue << 3 | blue << 1 | blue >> 1
        palette.append(red << 11 | green << 5 | blue)
    encoded = struct.pack('<256H', *palette)
    start = stage.find(encoded)
    targets = {target for _, target in facts.call_candidates('thumb')}
    reset_calls = _reset_called(stage) or ()
    while start >= 0:
        for literal in facts.literal_references(start):
            at = literal.instruction
            if at.isa != 'thumb':
                continue
            lookup = facts.decode(CodeAddress(at.address + 4))
            store = facts.decode(CodeAddress(at.address + 8))
            if (lookup is None or store is None or lookup.id != a.ARM_INS_LDRH
                    or store.id != a.ARM_INS_STRH
                    or lookup.operands[0].reg != literal.register
                    or lookup.operands[1].mem.base != literal.register
                    or not lookup.operands[1].mem.index
                    or store.operands[0].reg != literal.register):
                continue
            for target in sorted((value for value in targets if 0 <= at.address - value < 0x800), reverse=True):
                decoder = facts.function(CodeAddress(target), budget=2048)
                if (not decoder.complete or decoder.unresolved or at not in decoder.instructions
                        or CodeAddress(at.address + 8) not in decoder.instructions):
                    continue
                for caller_entry in reset_calls:
                    if not caller_entry & 1:
                        continue
                    caller = facts.function(CodeAddress(caller_entry & ~1), budget=2048)
                    if not caller.complete or caller.unresolved:
                        continue
                    sites = sorted(caller.call_sites, key=lambda item: item.site.address)
                    for position, call in enumerate(sites):
                        arguments = dict(call.registers)
                        if (call.target.address != target
                                or (arguments.get(a.ARM_REG_R2), arguments.get(a.ARM_REG_R3)) != (width, height)):
                            continue
                        for pc in caller.instructions:
                            ins = facts.decode(pc)
                            if (ins.id != a.ARM_INS_STR or len(ins.operands) != 2
                                    or ins.operands[1].type != a.ARM_OP_MEM
                                    or ins.operands[1].mem.base != a.ARM_REG_SP
                                    or ins.operands[1].mem.disp != 4
                                    or caller.linear_path(pc, call.site) is None):
                                continue
                            frame = facts.register_value(caller, pc, ins.operands[0].reg)
                            if (not isinstance(frame, SymbolicValue) or frame.kind != 'const'
                                    or not 0x01000000 <= frame.value <= 0x02000000 - width * height * 2):
                                continue
                            for following in sites[position + 1:]:
                                if following.site.address - call.site.address > 0x20:
                                    break
                                arguments = dict(following.registers)
                                if tuple(arguments.get(register) for register in (
                                        a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3)) != (0, 0, width, height):
                                    continue
                                blitter = facts.function(following.target, budget=256)
                                veneer = blitter
                                if len(blitter.calls) == 1 and not blitter.accesses:
                                    blitter = facts.function(blitter.calls[0][1], budget=256)
                                if (not blitter.complete or blitter.unresolved
                                        or {item.target for item in blitter.call_sites} != {item.target for item in setters}
                                        or not any(pool.value == frame.value for pool in blitter.literals)
                                        or not any(use.address == _DATA and use.operation == 'write'
                                                   and use.width == 2 for use in blitter.accesses)):
                                    continue
                                return (decoder, caller, veneer, blitter), start
        start = stage.find(encoded, start + 1)
    return None
