"""Stack-passed image and pixel-buffer arguments for indexed LCD writers."""
from __future__ import annotations

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.values import SymbolicValue


def stack_argument_loads(facts, function):
    frame = facts.stack_frame(function)
    if frame is None or not frame.complete:
        return ()
    result = []
    for site in function.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM):
            continue
        memory = ins.operands[1].mem
        if (memory.index or ins.operands[1].shift.type
                or ins.operands[1].subtracted):
            continue
        definitions = facts.reaching_definitions(function, site, memory.base)
        if definitions is None or len(definitions) != 1:
            continue
        definition = definitions[0]
        address = facts.decode(definition)
        if (address is None or address.id != a.ARM_INS_ADD
                or len(address.operands) != 3
                or address.operands[0].type != a.ARM_OP_REG
                or address.operands[0].reg != memory.base
                or address.operands[1].type != a.ARM_OP_REG
                or address.operands[1].reg != a.ARM_REG_SP
                or address.operands[2].type != a.ARM_OP_IMM
                or address.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
            continue
        sp_offset = frame.offset_at(definition)
        if sp_offset is None:
            continue
        result.append((sp_offset + address.operands[2].imm + memory.disp,
                       ins.operands[0].reg, site))
    return tuple(result)


def _depends_on_stack_load(facts, function, use, register, loads, active=()):
    key = (use, register)
    if key in active:
        return set()
    definitions = facts.reaching_definitions(function, use, register)
    if definitions is None:
        return set()
    load_slots = {site: slot for slot, _, site in loads}
    found = set()
    for definition in definitions:
        if definition in load_slots and next(
                (reg for _, reg, site in loads if site == definition), None) == register:
            found.add(load_slots[definition])
            continue
        ins = facts.decode(definition)
        if (ins is None or ins.id not in (a.ARM_INS_ADD, a.ARM_INS_SUB,
                                          a.ARM_INS_MOV, a.ARM_INS_MOVS)
                or len(ins.operands) < 2):
            continue
        source_regs = [operand.reg for operand in ins.operands[1:]
                       if operand.type == a.ARM_OP_REG and operand.reg != a.ARM_REG_PC]
        for source in source_regs:
            found.update(_depends_on_stack_load(
                facts, function, definition, source, loads, (*active, key)))
    return found


def stack_argument_bindings(facts, caller, call_site, callee):
    """Bind callee SP-relative loads to caller stores with constant origins."""
    caller_frame = facts.stack_frame(caller)
    callee_loads = stack_argument_loads(facts, callee)
    call_offset = caller_frame.offset_at(call_site) if caller_frame else None
    if (caller_frame is None or not caller_frame.complete or call_offset is None
            or not callee_loads):
        return ()
    stores = {}
    for access in caller_frame.accesses:
        if (access.operation != 'write' or access.width != 4
                or access.site.address >= call_site.address
                or not caller.dominates(access.site, call_site)):
            continue
        value = facts.register_value(caller, access.site, access.register)
        definitions = facts.reaching_definitions(caller, access.site, access.register)
        literal = (facts.literal(definitions[0]) if definitions and len(definitions) == 1
                   else None)
        if (isinstance(value, SymbolicValue) and value.kind == 'const'
                and literal is not None and literal.value == value.value):
            stores.setdefault(access.offset, []).append(
                (value.value, access.site, literal))
    result = []
    for slot, register, load_site in callee_loads:
        candidates = stores.get(call_offset + slot, ())
        if len(candidates) == 1:
            value, store_site, literal = candidates[0]
            result.append({'slot': slot, 'register': register, 'value': value,
                           'load': load_site, 'store': store_site,
                           'literal': literal})
    return tuple(result)


def output_stack_slots(facts, decoder, loads):
    """Return stack slots whose loaded pointer reaches an RGB halfword store."""
    slots = set()
    for site in decoder.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_STRH or len(ins.operands) != 2
                or ins.operands[1].type != a.ARM_OP_MEM):
            continue
        memory = ins.operands[1].mem
        for register in (memory.base, memory.index):
            if register:
                slots.update(_depends_on_stack_load(
                    facts, decoder, site, register, loads))
    return frozenset(slots)


def call_prefixes(facts, call_site, reach=0x40):
    """Find locally complete setup prefixes that reach a direct call."""
    target = CodeAddress(call_site)
    for address in range(max(0, call_site - reach) & ~1, call_site, 2):
        entry = CodeAddress(address)
        function = facts.function(entry, budget=256)
        if (function.complete and not function.unresolved and not function.truncated
                and target in function.instructions
                and function.linear_path(entry, target) is not None):
            yield function


def linked_stack_arguments(stage, facts, caller, decoder_call, decoder,
                           palette_start, data_port, window_target,
                           cursor_target, width, height, decoder_shape,
                           pixel_blitter):
    """Close an asset and output buffer passed through the outgoing stack."""
    bindings = stack_argument_bindings(facts, caller, decoder_call.site, decoder)
    if not bindings:
        return None
    header_registers = set()
    for site in decoder.instructions:
        ins = facts.decode(site)
        if (ins is None or ins.id != a.ARM_INS_LDRB or len(ins.operands) != 2
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.disp not in (3, 4)):
            continue
        definitions = facts.reaching_definitions(decoder, site, ins.operands[1].mem.base)
        if definitions and len(definitions) == 1:
            header_registers.add(ins.operands[1].mem.base)
    assets = [item for item in bindings if item['register'] in header_registers
              and 0 <= item['value'] <= len(stage) - 5
              and decoder_shape(decoder, facts, palette_start, item['register'],
                                indexed_palette=True)]
    if not assets:
        return None
    loads = stack_argument_loads(facts, decoder)
    output_slots = output_stack_slots(facts, decoder, loads)
    outputs = [item for item in bindings if item['slot'] in output_slots
               and 0x01000000 <= item['value'] <= 0x04000000 - 2]
    if not outputs:
        return None
    following_sites = [site for site in caller.call_sites
                       if site.site.address > decoder_call.site.address
                       and site.site.address - decoder_call.site.address <= 0x40]
    for asset in assets:
        for output in outputs:
            if asset['slot'] == output['slot']:
                continue
            for following in following_sites:
                args = dict(following.registers)
                x0, y0 = args.get(a.ARM_REG_R0), args.get(a.ARM_REG_R1)
                asset_width, asset_height = args.get(a.ARM_REG_R2), args.get(a.ARM_REG_R3)
                if (any(type(value) is not int for value in
                        (x0, y0, asset_width, asset_height))
                        or not 2 <= asset_width <= width or not 2 <= asset_height <= height
                        or x0 < 0 or y0 < 0 or x0 + asset_width > width
                        or y0 + asset_height > height):
                    continue
                writer = facts.function(following.target, budget=256)
                veneer = None
                if len(writer.calls) == 1 and not writer.accesses:
                    veneer = writer
                    writer = facts.function(writer.calls[0][1], budget=256)
                if (not writer.complete or writer.unresolved or writer.truncated
                        or {site.target.address for site in writer.call_sites}
                        != {window_target, cursor_target}
                        or not pixel_blitter(writer, facts, output['value'], data_port)):
                    continue
                return (veneer, writer, x0, y0, output['value'], asset['value'])
    return None
