"""EEPROM wire rules owned by the device domain."""
from __future__ import annotations

from ...facts import CodeAddress, FirmwareFacts, SymbolicValue, facts_for
from ...image_view import LoadOperation
from .gpio_facts import (
    _call_counts, _function_literal, _gpio_output_transitions, _gpio_port_uses,
    _linked_descriptor_matches, _sampled_gpio_bit,
)
from capstone import arm


def _descriptor_runtime_context(context, descriptor, evidence):
    # The scatter target names writable RAM. A same-offset file byte belongs
    # to the supplied dump, and cannot establish that RAM's runtime contents.
    view = context.view.materialize((LoadOperation(
        'invalidate', None, descriptor, 12, (evidence,)),),
        phase='eeprom-wire')
    return FirmwareFacts(context.image, context.base, view)


def _halfword_gpio_evidence(facts, ack, writer, reader, *, data_port: int,
                            direction_port: int, ack_entry: int,
                            descriptor: int) -> bool:
    """Prove the descriptor's physical SDA/SCL ports and sampled input bit.

    The backend maps the pins and capacity; firmware code retains ownership of
    byte sequencing, ACK return values, and loop counts.
    """
    if not all(item.complete and not item.truncated
               for item in (ack, writer, reader)):
        return False
    ack_data_writes = _gpio_port_uses(
        facts, ack, address=data_port, operation='write', width=2,
        descriptor=descriptor, field=0)
    ack_data_reads = _gpio_port_uses(
        facts, ack, address=data_port, operation='read', width=2,
        descriptor=descriptor, field=4)
    ack_direction_writes = _gpio_port_uses(
        facts, ack, address=direction_port, operation='write', width=2,
        descriptor=descriptor, field=8)
    ack_data_raw = _gpio_output_transitions(facts, ack, ack_data_writes)
    ack_direction_raw = _gpio_output_transitions(facts, ack, ack_direction_writes)
    ack_data_transitions = tuple(item for item in ack_data_raw
                                 if item is not None and item[0] != 'same')
    ack_direction_transitions = tuple(
        item for item in ack_direction_raw
        if item is not None and item[0] != 'same')
    if (not ack_data_writes or len(ack_data_reads) != 1
            or len(ack_direction_writes) != 2
            or any(item is None for item in ack_data_raw + ack_direction_raw)
            or set(ack_data_transitions) != {('orrs', 0x40), ('bics', 0x40)}
            or set(ack_direction_transitions)
            != {('bics', 0x20), ('orrs', 0x20)}
            or not _sampled_gpio_bit(facts, ack, data_port, width=2, shift=6,
                                     branch_condition=arm.ARM_CC_HS,
                                     descriptor=descriptor)):
        return False

    writer_data_writes = _gpio_port_uses(
        facts, writer, address=data_port, operation='write', width=2,
        descriptor=descriptor, field=0)
    writer_raw = _gpio_output_transitions(facts, writer, writer_data_writes)
    writer_transitions = tuple(item for item in writer_raw
                               if item is not None and item[0] != 'same')
    if (len(writer_data_writes) < 4
            or any(item is None for item in writer_raw)
            or {mask for _operation, mask in writer_transitions}
            != {0x20, 0x40}):
        return False

    reader_data_writes = _gpio_port_uses(
        facts, reader, address=data_port, operation='write', width=2,
        descriptor=descriptor, field=0)
    reader_data_reads = _gpio_port_uses(
        facts, reader, address=data_port, operation='read', width=1,
        descriptor=descriptor, field=4)
    reader_raw = _gpio_output_transitions(facts, reader, reader_data_writes)
    reader_transitions = tuple(item for item in reader_raw
                               if item is not None and item[0] != 'same')
    if (len(reader_data_writes) < 1 or len(reader_data_reads) != 1
            or any(item is None for item in reader_raw) or not reader_transitions
            or not _sampled_gpio_bit(facts, reader, data_port, width=1,
                                     shift=6, branch_condition=arm.ARM_CC_LO,
                                     descriptor=descriptor)
            or not {mask for _operation, mask in reader_transitions}
            <= {0x20, 0x40}
            or 0x40 not in {mask for _operation, mask in reader_transitions}):
        return False

    ack_calls = _call_counts(ack)
    writer_calls = _call_counts(writer)
    reader_calls = _call_counts(reader)
    lock_roles = {target for target, count in ack_calls.items() if count >= 4}
    if (len(lock_roles) != 2
            or not all(writer_calls[target] >= 1 for target in lock_roles)
            or not all(reader_calls[target] >= 1 for target in lock_roles)
            or writer_calls[ack_entry] != 1
            or not any((site.address == back_target and callee.address in lock_roles)
                       for _source, back_target in writer.back_edges
                       for site, callee in writer.calls)
            or not any((site.address == back_target and callee.address in lock_roles)
                       for _source, back_target in reader.back_edges
                       for site, callee in reader.calls)):
        return False
    return True


def _descriptor_gpio_evidence(image: bytes, read: int, write: int, *,
                              linker, load: int, reader_offset: int,
                              discover_linker: bool = False,
                              reader_from_write: bool = False):
    """Validate the shared GPIO wire protocol and linked pointer descriptor."""
    reader_base = write if reader_from_write else read
    writer, reader, ack = write - 0x160, reader_base - reader_offset, write - 0x1FE
    if min(writer, reader, ack) < 0:
        return None, "gpio-line-shape-mismatch"
    context = facts_for(image)
    literal = context.literal(CodeAddress(writer + 0x18, 'thumb'))
    if literal is None or literal.register != arm.ARM_REG_R2:
        return None, "gpio-line-shape-mismatch"
    descriptor = literal.value
    if discover_linker:
        from msm5xxx_emulator.detection.layout_facts import find_linker_layout
        linker = find_linker_layout(
            image, load, required_span=(descriptor, 12))
    if not _linked_descriptor_matches(
            context, linker, descriptor,
            (0x03000720, 0x03000720, 0x0300072C)):
        return None, "gpio-descriptor-linkage-mismatch"
    context = _descriptor_runtime_context(context, descriptor, writer + 0x18)
    ack_facts = context.function(CodeAddress(ack, 'thumb', 'eeprom-wire'), budget=256,
                                 symbolic_registers={})
    writer_facts = context.function(CodeAddress(writer, 'thumb', 'eeprom-wire'), budget=256,
                                    symbolic_registers={})
    reader_facts = context.function(CodeAddress(reader, 'thumb', 'eeprom-wire'), budget=256,
                                    symbolic_registers={})
    if (_function_literal(writer_facts, writer + 0x18, arm.ARM_REG_R2) != descriptor
            or not all(any(item.value == descriptor for item in function.literals)
                       for function in (ack_facts, reader_facts))
            or not _halfword_gpio_evidence(
                context, ack_facts, writer_facts, reader_facts,
                data_port=0x03000720, direction_port=0x0300072C,
                ack_entry=ack, descriptor=descriptor)):
        return None, "gpio-line-shape-mismatch"
    return descriptor, None


def _call_context_tree(facts, call, active=(), budget=64):
    """Close one direct callee tree and preserve its concrete call arguments."""
    if budget <= 0 or call.target in active:
        return None
    arguments = {}
    for register, value in call.registers:
        if not (arm.ARM_REG_R0 <= register <= arm.ARM_REG_R12
                or register == arm.ARM_REG_SP or register == arm.ARM_REG_LR):
            continue
        if isinstance(value, SymbolicValue):
            value = value.value if value.kind == 'const' else None
        if type(value) is int:
            arguments[register] = value
    arguments[arm.ARM_REG_LR] = (call.site.address + 4
                                 | (1 if call.site.isa == 'thumb' else 0))
    function = facts.function(call.target, budget=256,
                              initial_registers=arguments,
                              symbolic_registers={},
                              stop_at_initial_return=True)
    if not _closed_gpio_function(facts, function):
        return None
    result = [function]
    for nested in function.call_sites:
        child = _call_context_tree(facts, nested,
                                  (*active, call.target), budget - 1)
        if child is None:
            return None
        result.extend(child)
        if len(result) > 64:
            return None
    return tuple(result)


def _call_effect_contexts(facts, function):
    contexts = []
    for call in function.call_sites:
        tree = _call_context_tree(facts, call)
        if tree is None:
            return None
        contexts.extend(tree)
        if len(contexts) > 64:
            return None
    return tuple(contexts)


def _closed_gpio_function(facts, function) -> bool:
    if not function.complete or function.truncated or function.unresolved:
        return False
    unmodelled = facts.unmodelled_memory(function)
    frame = facts.stack_frame(function)
    stack_sites = ({access.site for access in frame.accesses}
                   if frame is not None and frame.complete else set())
    if (unmodelled is None or set(unmodelled) - stack_sites
            or unmodelled and (frame is None or not frame.balanced)):
        return False
    concrete_writes = {(access.instruction, access.address, access.width)
                       for access in function.accesses if access.operation == 'write'}
    for access in function.symbolic_accesses:
        if access.operation != 'write' or access.instruction in stack_sites:
            continue
        if access.address.kind != 'const':
            return False
        if (access.instruction, access.address.value, access.width) not in concrete_writes:
            return False
    return True


def _byte_line_transition(contexts, address: int, mask: int) -> bool:
    operations = set()
    for facts, function in contexts:
        accesses = tuple(access for access in function.accesses
                         if access.operation == 'write' and access.address == address
                         and access.width == 1)
        transitions = _gpio_output_transitions(facts, function, accesses)
        if any(item is None for item in transitions):
            return False
        operations.update(operation for operation, value in transitions
                          if operation != 'same' and value == mask)
    return operations >= {'orrs', 'bics'}


def _byte_ack_sample(facts, function, data_address: int, direction_address: int,
                     clock_address: int, data_mask: int, clock_mask: int) -> bool:
    """Tie an ACK decision to SDA sampled during a released, clocked phase."""
    if not data_mask or data_mask & (data_mask - 1):
        return False
    direction_writes = tuple(access for access in function.accesses
                             if access.operation == 'write'
                             and access.address == direction_address
                             and access.width == 1)
    clock_writes = tuple(access for access in function.accesses
                         if access.operation == 'write'
                         and access.address == clock_address and access.width == 1)
    direction_transitions = _gpio_output_transitions(facts, function, direction_writes)
    clock_transitions = _gpio_output_transitions(facts, function, clock_writes)
    direction_events = tuple((access.instruction, transition)
                             for access, transition in zip(direction_writes,
                                                          direction_transitions)
                             if transition in (('orrs', data_mask),
                                               ('bics', data_mask)))
    clock_events = tuple((access.instruction, transition)
                         for access, transition in zip(clock_writes, clock_transitions)
                         if transition in (('orrs', clock_mask),
                                           ('bics', clock_mask)))
    if (not any(item[1] == ('bics', data_mask) for item in direction_events)
            or not any(item[1] == ('orrs', clock_mask) for item in clock_events)
            or not any(item[1] == ('bics', clock_mask) for item in clock_events)):
        return False

    for access in function.accesses:
        if (access.operation != 'read' or access.address != data_address
                or access.width != 1):
            continue
        for branch in function.instructions:
            predicate = facts.branch_predicate(function, branch)
            if predicate is None or len(predicate.read_sources) != 1:
                continue
            source, = predicate.read_sources
            if (source.site != access.instruction or source.width != 1
                    or source.signed or source.address.kind != 'const'
                    or source.address.value != data_address):
                continue
            by_bit = {}
            independent = True
            for value in range(0x100):
                outcome = predicate.evaluate({source.site: value})
                if outcome is None:
                    independent = False
                    break
                bit = bool(value & data_mask)
                if bit in by_bit and by_bit[bit] != outcome:
                    independent = False
                    break
                by_bit[bit] = outcome
            if (not independent or len(by_bit) != 2
                    or by_bit[False] == by_bit[True]):
                continue
            events = (*[site for site, _ in direction_events],
                      *[site for site, _ in clock_events],
                      access.instruction, predicate.branch)
            sequence = facts.ordered_events(function, events)
            if sequence is None:
                continue
            sample_index = sequence.index(access.instruction)
            branch_index = sequence.index(predicate.branch)
            before_sample = sequence[:sample_index]
            after_branch = sequence[branch_index + 1:]
            last_direction = next((site for site in reversed(before_sample)
                                   if any(site == event for event, _ in direction_events)), None)
            last_clock = next((site for site in reversed(before_sample)
                               if any(site == event for event, _ in clock_events)), None)
            direction_kind = next((kind for site, kind in direction_events
                                   if site == last_direction), None)
            clock_kind = next((kind for site, kind in clock_events if site == last_clock), None)
            if (direction_kind == ('bics', data_mask)
                    and clock_kind == ('orrs', clock_mask)
                    and any(any(site == event and kind == ('bics', clock_mask)
                                for event, kind in clock_events)
                            for site in after_branch)):
                return True
    return False


def _byte_gpio_protocol(facts, writer_entry: int, reader_entry: int,
                        ack_entry: int, profile: tuple[int, ...]) -> bool:
    """Prove the backend's byte SDA, SCL and output-direction bindings."""
    base, data_offset, data_mask, clock_offset, clock_mask, direction_offset = profile[:6]
    entries = tuple(facts.function(CodeAddress(entry, 'thumb'), budget=512,
                                   symbolic_registers={})
                    for entry in (writer_entry, reader_entry))
    if not all(_closed_gpio_function(facts, function) for function in entries):
        return False
    writer, reader = entries
    writer_children = _call_effect_contexts(facts, writer)
    reader_children = _call_effect_contexts(facts, reader)
    if writer_children is None or reader_children is None:
        return False
    writer_group = ((facts, writer), *((facts, function) for function in writer_children))
    reader_group = ((facts, reader), *((facts, function) for function in reader_children))
    calls_ack = lambda function: any(target.address == ack_entry
                                     for _site, target in function.calls)
    ack_sites = tuple(call for function in (writer, reader)
                      for call in function.call_sites
                      if call.target.address == ack_entry)
    if not calls_ack(writer) or not calls_ack(reader) or not ack_sites:
        return False
    ack_contexts = []
    for call in ack_sites:
        tree = _call_context_tree(facts, call)
        if tree is None:
            return False
        ack_contexts.extend((facts, function) for function in tree)
        if len(ack_contexts) > 64:
            return False
    contexts = (*writer_group, *reader_group, *ack_contexts)
    if (not _byte_line_transition(contexts, base + data_offset, data_mask)
            or not _byte_line_transition(contexts, base + clock_offset, clock_mask)
            or not _byte_line_transition(contexts, base + direction_offset, data_mask)):
        return False
    return any(_byte_ack_sample(
        facts, function, base + data_offset, base + direction_offset,
        base + clock_offset, data_mask, clock_mask)
        for facts, function in ack_contexts)
