"""EEPROM gpio facts owned by the device domain."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
from ...facts import CodeAddress
from capstone import arm
from collections import Counter
import struct

def _code_shapes_match(image: bytes, shapes) -> bool:
    return all(image[position:position + len(expected)] == expected for position, expected in shapes)

def _literal_values_match(image: bytes, literals) -> bool:
    return all(facts_for(image).thumb_literal_value(position, register) == expected for position, register, expected in literals)

def _linked_descriptor_matches(context, linker, descriptor: int, expected: tuple[int, int, int]) -> bool:
    if (linker is None or not linker.data_target <= descriptor <= linker.data_target + linker.data_size - 12):
        return False
    source = linker.data_source + descriptor - linker.data_target
    return (0 <= source and source + 12 <= len(context.image) and context.view.read(source, 12, phase='reset', bank='primary') == struct.pack("<III", *expected))

def _call_counts(function):
    return Counter(target.address for _site, target in function.calls)

def _function_literal(function, address: int, register: int):
    values = {item.value for item in function.literals if item.instruction.address == address and item.register == register}
    return next(iter(values)) if len(values) == 1 else None

def _instruction(facts, function, address: int):
    pc = CodeAddress(address, function.entry.isa, function.entry.phase, function.entry.bank)
    return facts.decode(pc) if pc in function.instructions else None

def _descriptor_pointer_field(facts, function, access, descriptor: int):
    """Resolve a dereference only through its reaching descriptor loads."""
    instruction = _instruction(facts, function, access.instruction.address)
    if instruction is None:
        return None
    memory = next((operand for operand in reversed(instruction.operands) if operand.type == arm.ARM_OP_MEM), None)
    if memory is None:
        return None
    pointer_register = memory.mem.base
    pointer_defs = facts.reaching_definitions(function, access.instruction, pointer_register)
    if pointer_defs is None or len(pointer_defs) != 1:
        return None
    load_pc = pointer_defs[0]
    load = facts.decode(load_pc)
    if (load is None or load.mnemonic != 'ldr' or len(load.operands) != 2 or load.operands[0].reg != pointer_register or load.operands[1].type != arm.ARM_OP_MEM):
        return None
    descriptor_register = load.operands[1].mem.base
    offset = load.operands[1].mem.disp
    descriptor_defs = facts.reaching_definitions(function, load_pc, descriptor_register)
    if descriptor_defs is None or len(descriptor_defs) != 1:
        return None
    literal_pc = descriptor_defs[0]
    if not any(item.instruction == literal_pc and item.register == descriptor_register and item.value == descriptor for item in function.literals):
        return None
    return offset if offset in (0, 4, 8) else None

def _direct_mmio_literal(facts, function, access, address: int) -> bool:
    instruction = _instruction(facts, function, access.instruction.address)
    memory = (next((operand for operand in reversed(instruction.operands) if operand.type == arm.ARM_OP_MEM), None) if instruction is not None else None)
    if memory is None:
        return False
    register = memory.mem.base
    definitions = facts.reaching_definitions(function, access.instruction, register)
    if definitions is None or len(definitions) != 1:
        return False
    definition = definitions[0]
    return any(item.instruction == definition and item.register == register and item.value + memory.mem.disp == address for item in function.literals)

def _gpio_port_uses(facts, function, *, address: int, operation: str, width: int, descriptor: int, field: int, allow_call_argument: bool = False):
    direct = tuple(item for item in function.accesses if item.address == address and item.operation == operation and item.width == width and (_descriptor_pointer_field(facts,
        function, item, descriptor) == field or _direct_mmio_literal(facts, function, item, address) or allow_call_argument and _call_argument_access(facts,
        function, item, address)))
    indirect = tuple(item for item in function.symbolic_accesses if item.operation == operation and item.width == width and item.instruction.address not in {direct_item.instruction.address
        for direct_item in direct} and _descriptor_pointer_field(facts, function, item, descriptor) == field)
    return tuple(sorted(direct + indirect, key=lambda item: item.instruction.address))

def _call_argument_access(facts, function, access, address: int) -> bool:
    """Accept a concrete MMIO operand derived from a captured call argument."""
    initial = dict(function.initial_registers)
    if not initial:
        return False
    instruction = _instruction(facts, function, access.instruction.address)
    memory = (next((operand for operand in reversed(instruction.operands) if operand.type == arm.ARM_OP_MEM), None) if instruction is not None else None)
    if memory is None or memory.mem.base not in initial:
        return False
    value = facts.register_value(function, access.instruction, memory.mem.base)
    return (value.kind == 'const' and type(value.value) is int and value.value + memory.mem.disp == address)

def _unique_def(facts, function, use: CodeAddress, register: int):
    definitions = facts.reaching_definitions(function, use, register)
    return definitions[0] if definitions is not None and len(definitions) == 1 else None

def _sampled_gpio_bit(facts, function, address: int, *, width: int, shift: int, branch_condition: int, descriptor: int, allow_call_argument: bool = False) -> bool:
    """Prove a loaded GPIO byte/halfword is shifted into a conditional branch."""
    for access in _gpio_port_uses(facts, function, address=address, operation='read', width=width, descriptor= descriptor, field=4, allow_call_argument=allow_call_argument):
        load = _instruction(facts, function, access.instruction.address)
        if load is None or not load.operands:
            continue
        register = load.operands[0].reg
        cursor = access.instruction.address + load.size
        for _ in range(3):
            shifted = _instruction(facts, function, cursor)
            if shifted is None:
                break
            if (shifted.mnemonic == 'lsrs' and len(shifted.operands) == 3 and shifted.operands[0].reg == register and shifted.operands[1].reg == register and
                shifted.operands[2].imm == shift):
                branch_pc = cursor + shifted.size
                branch = _instruction(facts, function, branch_pc)
                shift_pc = CodeAddress(cursor, function.entry.isa, function.entry.phase, function.entry.bank)
                branch_code_pc = CodeAddress(branch_pc, function.entry.isa, function.entry.phase, function.entry.bank)
                if (branch is None or not branch.mnemonic.startswith('b') or branch.cc != branch_condition or not branch.operands or branch.operands[0].imm not
                    in {target.address for source, target in function.control_edges if source.address == branch_pc}):
                    continue
                if (_unique_def(facts, function, shift_pc, register) != access.instruction or _unique_def(facts, function, branch_code_pc, arm.ARM_REG_CPSR) !=
                    shift_pc or function.linear_path(access.instruction, shift_pc) is None or function.linear_path(shift_pc, branch_code_pc) is None):
                    continue
                fallthrough = _instruction(facts, function, branch_pc + branch.size)
                target = _instruction(facts, function, branch.operands[0].imm)
                if branch_condition == arm.ARM_CC_HS:
                    if (fallthrough is not None and fallthrough.mnemonic == 'movs' and fallthrough.operands[1].imm == 0 and target is not None and target.mnemonic
                        == 'lsls' and target.operands[2].imm == 24):
                        return True
                elif branch_condition == arm.ARM_CC_LO:
                    if (fallthrough is not None and fallthrough.mnemonic == 'movs' and fallthrough.operands[1].imm == 1):
                        return True
                else:
                    return True
            if shifted.mnemonic.startswith('b'):
                break
            cursor += shifted.size
    return False

def _gpio_store_transitions(facts, function, accesses):
    transitions = []
    for access in accesses:
        store = _instruction(facts, function, access.instruction.address)
        if (store is None or not store.mnemonic.startswith('str') or not store.operands or store.operands[0].type != arm.ARM_OP_REG):
            transitions.append(None)
            continue
        source = store.operands[0].reg
        definition = _unique_def(facts, function, access.instruction, source)
        update = facts.decode(definition) if definition is not None else None
        reads = function.accesses + function.symbolic_accesses
        if (update is not None and update.mnemonic in ('ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh') and any(item.operation == 'read' and item.address == access.address
            and item.width == access.width and item.instruction == definition for item in reads)):
            transitions.append(('same', 0))
            continue
        if (update is None or update.mnemonic not in ('orrs', 'bics') or len(update.operands) < 2 or update.operands[0].reg != source or update.operands[1].type
            != arm.ARM_OP_REG):
            transitions.append(None)
            continue
        mask_register = update.operands[1].reg
        mask = facts.register_value(function, definition, mask_register)
        if mask.kind != 'const' or type(mask.value) is not int:
            transitions.append(None)
            continue
        old_value = _unique_def(facts, function, definition, source)
        if old_value is None or not any(item.operation == 'read' and item.address == access.address and item.width == access.width and item.instruction ==
            old_value for item in reads):
            transitions.append(None)
            continue
        transitions.append((update.mnemonic, mask.value))
    return tuple(transitions)

def _gpio_output_transitions(facts, function, accesses):
    """Resolve output writes through a preceding descriptor-backed value cell."""
    result = []
    for access in accesses:
        direct = _gpio_store_transitions(facts, function, (access,))[0]
        if direct is not None:
            result.append(direct)
            continue
        store = _instruction(facts, function, access.instruction.address)
        if (store is None or not store.mnemonic.startswith('str') or not store.operands or store.operands[0].type != arm.ARM_OP_REG):
            result.append(None)
            continue
        value_load = _unique_def(facts, function, access.instruction, store.operands[0].reg)
        load = facts.decode(value_load) if value_load is not None else None
        if (load is None or not load.mnemonic.startswith('ldr') or not any(item.operation == 'read' and item.instruction == value_load for item in function.accesses
            + function.symbolic_accesses)):
            result.append(None)
            continue
        source_reads = tuple(item for item in function.accesses if item.instruction == value_load and item.operation == 'read')
        candidates = []
        for source_read in source_reads:
            definitions = facts.memory_definitions(function, value_load, source_read.address, width=source_read.width)
            if definitions is None or len(definitions) != 1:
                continue
            source_write = next((item for item in function.accesses if item.operation == 'write' and item.instruction == definitions[0]), None)
            if source_write is None:
                continue
            transition = _gpio_store_transitions(facts, function, (source_write,))[0]
            if (transition is not None and transition[0] != 'same' and function.linear_path(source_write.instruction, value_load) is not None):
                candidates.append(transition)
        result.append(candidates[0] if len(candidates) == 1 else None)
    return tuple(result)
