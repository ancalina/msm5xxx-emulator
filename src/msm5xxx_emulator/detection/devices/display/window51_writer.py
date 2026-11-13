"""Window commands and a matching halfword pixel-clear loop."""
from __future__ import annotations

import struct
from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue


def _clear_candidates(image, facts, *, data_ports=(0x18040000, 0x18080000), maximum_height=255):
    for literal in (item for port in data_ports for item in facts.literal_references(port)):
        pc = literal.instruction.address
        if literal.instruction.isa != 'thumb' or not 2 <= pc < min(len(image) - 20, 0x10000):
            continue
        for store in range(pc + 2, min(pc + 24, len(image) - 10), 2):
            words = struct.unpack_from('<7H', image, store - 4)
            if (words[0] & 0xff00 != 0x2000
                    or words[1:] != (0xe000, 0x8014, 0x3801, 0xd2fc, 0x3901, 0xd2f8)):
                continue
            width = words[0] & 0xff
            for owner in range(pc - 2, max(-1, pc - 0x300), -2):
                ins = facts.decode(CodeAddress(owner))
                if (ins is None or ins.id != a.ARM_INS_PUSH
                        or not any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_LR for op in ins.operands)):
                    continue
                function = facts.function(CodeAddress(owner), budget=512)
                if not function.complete or function.unresolved or function.truncated:
                    break
                cuts = tuple((source, target) for source, target in function.control_edges
                             if (source.address, target.address) in function.back_edges)
                rows = facts.register_value(function, CodeAddress(store + 6), a.ARM_REG_R1, cut_edges=cuts)
                if not isinstance(rows, SymbolicValue) or rows.kind != 'const':
                    break
                height = rows.value
                if (type(height) is not int or not 1 < width <= 255 or not 1 < height <= maximum_height
                        or not any(use.instruction.address == store and use.operation == 'write'
                                   and use.address == literal.value and use.width == 2 and use.value == 0xffff
                                   for use in function.accesses)):
                    break
                yield function, literal, CodeAddress(store), width, height
                break


def _profile(facts, function, literal, width, height, x0, y0, *, protocol, helpers=()):
    if not 0 <= x0 <= 256 - width or not 0 <= y0 <= 256 - height:
        return None
    callers = [site for site, target in facts.call_candidates('thumb') if target == function.entry.address]
    if not callers:
        return None
    evidence = []
    for body in (function, *helpers):
        first = min(at.address for at in body.instructions)
        end = max(at.address + facts.decode(at).size for at in body.instructions)
        evidence.append({'span': [first, end - first], 'extra_spans': [
            *[[pool.pool, 4] for pool in body.literals], [callers[0], 4]]})
    return {'width': width, 'height': height, 'x_origin': x0, 'y_origin': y0,
            'data_port': literal.value, 'data_literal': literal.pool, 'protocol': protocol, 'evidence': evidence}


def _unique_profile(found):
    if len({(item['width'], item['height'], item['x_origin'], item['y_origin'], item['data_port']) for item in found}) != 1:
        return None
    return {**found[0], 'evidence': [entry for item in found for entry in item['evidence']]}


def find_window51(image: bytes):
    facts = facts_for(image)
    found = []
    for function, literal, store, width, height in _clear_candidates(image, facts):
        command_writes = [use for use in function.accesses
                          if use.operation == 'write' and use.address == 0x18000000
                          and use.width == 2 and use.predicate == a.ARM_CC_AL]
        commands = tuple(use.value for use in command_writes)
        windows = [commands[index:index + 6] for index in range(len(commands) - 5)
                   if commands[index] == 0x42 and commands[index + 3] == 0x43
                   and all(type(value) is int and 0 <= value <= 255 for value in commands[index:index + 6])]
        if not windows or commands[-1] != 0x51:
            continue
        _, y0, y1, _, x0, x1 = windows[-1]
        if ((x1 - x0 + 1, y1 - y0 + 1) != (width, height)
                or not all(function.dominates(use.instruction, literal.instruction) for use in command_writes)):
            continue
        profile = _profile(facts, function, literal, width, height, x0, y0, protocol='window51')
        if profile is not None:
            found.append(profile)
    return _unique_profile(found)
