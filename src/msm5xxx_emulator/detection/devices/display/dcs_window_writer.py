"""A called DCS window setter paired with its matching boot clear."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.facts import facts_for
from .window51_writer import _clear_candidates, _profile, _unique_profile


def find_dcs_window(image: bytes):
    facts = facts_for(image)
    found = []
    arguments = (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3)
    for function, literal, store, width, height in _clear_candidates(image, facts):
        ram_writes = [use for use in function.accesses if use.operation == 'write'
                      and (use.address, use.width, use.value, use.predicate) == (0x18000000, 2, 0x2c, a.ARM_CC_AL)]
        for call in function.call_sites:
            values = {register: value for register, value in call.registers if register in arguments}
            if len(values) != 4 or any(type(value) is not int for value in values.values()):
                continue
            helper = facts.function(call.target, budget=128, initial_registers=values)
            if not helper.complete or helper.unresolved or helper.truncated or helper.calls:
                continue
            writes = [use for use in helper.accesses if use.operation == 'write']
            ports = (0x18000000, *([literal.value] * 4), 0x18000000, *([literal.value] * 4))
            if (len(writes) != 10 or tuple(use.address for use in writes) != ports
                    or any(use.width != 2 or use.predicate != a.ARM_CC_AL
                           or type(use.value) is not int or not 0 <= use.value <= 255 for use in writes)
                    or writes[0].value != 0x2a or writes[5].value != 0x2b):
                continue
            path = helper.linear_path(writes[0].instruction, writes[-1].instruction)
            if path is None or any(use.instruction not in path for use in writes):
                continue
            x0 = writes[1].value << 8 | writes[2].value
            x1 = writes[3].value << 8 | writes[4].value
            y0 = writes[6].value << 8 | writes[7].value
            y1 = writes[8].value << 8 | writes[9].value
            if ((x1 - x0 + 1, y1 - y0 + 1) != (width, height)
                    or not function.dominates(call.site, store)
                    or not any(use.instruction.address > call.site.address
                               and function.dominates(use.instruction, store) for use in ram_writes)):
                continue
            profile = _profile(facts, function, literal, width, height, x0, y0,
                               protocol='dcs', helpers=(helper,))
            if profile is not None:
                found.append(profile)
    return _unique_profile(found)
