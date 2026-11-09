"""Closed raw-input transactions and source-bound SBI profile projection."""
from itertools import product
from capstone import CS_GRP_JUMP, CS_GRP_RET
from capstone import arm as a
from ...facts import CodeAddress, SymbolicValue, evaluate_value, facts_for
from .protocol import _native_status
from .raw_flow import (
    SBI_BASE, SBI_SIZE, _UNCONDITIONAL, _ARG_REGS, _SELECTORS,
    _Effect, _constant, _typed_equal, bootstrap_profile_matches,
    _stack_access, _closed_dataflow, _selector_cut_edges, _load_sites,
    _possible_values, _peripheral_accesses, _function_return_sites,
    _poll_contract, _owner_function, _callsite, _stable_stack_cuts,
    _source_selector, _argument_indices, _argument_values, _callee_effects,
    _closed_call_sites,
)


def _transaction(facts, entry, selector):
    wire_selector = {0: 0x20, 0x40: 0x40, 0x60: 0x60}.get(selector)
    if wire_selector is None:
        return None
    initial = {a.ARM_REG_R0: selector}
    whole = facts.function(entry, budget=1024, initial_registers=initial,
                           symbolic_registers={})
    data_reads = [access for access in whole.symbolic_accesses
                  if access.operation == 'read' and access.width == 2
                  and access.address.kind == 'const'
                  and access.address.value == SBI_BASE + 0x0C]
    if len(data_reads) != 1:
        return None
    read_site = data_reads[0].instruction
    function = facts.function_region(entry, read_site, budget=1024,
                                     initial_registers=initial,
                                     symbolic_registers={})
    if not _closed_dataflow(facts, function):
        return None
    mmio = []
    call_effects = {}
    call_events = []
    allowed_calls = _closed_call_sites(facts, function)
    if allowed_calls is None:
        return None
    for call in function.call_sites:
        effects = _callee_effects(facts, function, call, selector)
        if effects is None:
            poll = next(((_control, _full, result)
                         for _control, _full in ((0x085F, False),
                                                 (0x086A, False),
                                                 (0x086A, True))
                         if (result := _poll_contract(facts, call.target,
                                                      _control, _full)) is not None), None)
            if poll is not None:
                call_events.append((call.site.address, 'poll', poll))
                continue
            return None
        if not effects:
            continue
        emitted = []
        for effect in effects:
            if effect.address == SBI_BASE + 0x04:
                if effect.width != 2 or effect.value != (0x086A,):
                    return None
                emitted.append(('write', 4, 2, effect.value))
            elif effect.address == SBI_BASE + 0x0C:
                if effect.width != 2:
                    return None
                emitted.append(('write', 0x0C, 2, effect.value))
            elif effect.address == SBI_BASE + 0x10:
                if effect.width != 1:
                    return None
                emitted.append(('write', 0x10, 1, effect.value))
            else:
                return None
        call_effects[call.site.address] = tuple(emitted)
    command_calls = [call for call in function.call_sites
                     if dict(call.registers).get(a.ARM_REG_R0) == 0x0A
                     and facts.ordered_events(function, (call.site, read_site))
                         == (call.site, read_site)
                     and any(effect[1] == 0x0C
                             for effect in call_effects.get(call.site.address, ()))]
    if len(command_calls) != 2:
        return None
    first_args, second_args = (dict(call.registers) for call in command_calls)
    first_source, second_source = (args.get(a.ARM_REG_R1)
                                   for args in (first_args, second_args))
    if (not isinstance(first_source, SymbolicValue) or first_source.kind != 'load'
            or not isinstance(second_source, SymbolicValue) or second_source.kind != 'load'):
        return None
    first_address = first_source.operands[0] if first_source.operands else None
    second_address = second_source.operands[0] if second_source.operands else None
    if (first_address is None or first_address.kind != 'const'
            or second_address != first_address):
        return None
    shadow = first_address.value
    if not 0 <= shadow < 0x100000000:
        return None
    selector_cuts = _selector_cut_edges(facts, function, selector)
    safe_memory_calls = tuple(site for site, _ in function.calls
                              if site in allowed_calls)
    first_values = _possible_values(facts, function, first_source, selector_cuts,
                                    allowed_calls=safe_memory_calls)
    second_values = _possible_values(facts, function, second_source, selector_cuts,
                                     allowed_calls=safe_memory_calls)
    if (first_values is None or second_values is None
            or not first_values or not second_values
            or {value & 0x60 for value in first_values} != {wire_selector}
            or any(not value & 0x80 for value in first_values)
            or {value & 0x60 for value in second_values} != {wire_selector}
            or any(value & 0x80 for value in second_values)
            or {value & 0x7F for value in first_values} != set(second_values)):
        return None
    for access in function.symbolic_accesses:
        if access.operation not in ('read', 'write'):
            continue
        if access.address.kind != 'const':
            if not _stack_access(facts, access.instruction):
                return None
            continue
        address = access.address.value
        if SBI_BASE <= address < SBI_BASE + SBI_SIZE:
            continue
        if access.operation == 'write' and address != shadow:
            return None
        if address == shadow and access.width != 1:
            return None
    direct_reads = [access for access in _peripheral_accesses(function)
                    if access.operation == 'read']
    if (len(direct_reads) != 1 or direct_reads[0].instruction != read_site
            or direct_reads[0].address.value != SBI_BASE + 0x0C
            or direct_reads[0].width != 2):
        return None
    mmio.extend((access.instruction.address, access.operation,
                 access.address.value - SBI_BASE, access.width,
                 (access.value.value,) if access.value.kind == 'const' else None)
                for access in _peripheral_accesses(function)
                if access.operation == 'write')
    event_map = {}
    for item in mmio:
        site = CodeAddress(item[0], 'thumb', entry.phase, entry.bank)
        if site in event_map:
            return None
        event_map[site] = ('mmio', item)
    for address, effects in call_effects.items():
        site = CodeAddress(address, 'thumb', entry.phase, entry.bank)
        if site in event_map:
            return None
        event_map[site] = ('call', effects)
    for item in call_events:
        site = CodeAddress(item[0], 'thumb', entry.phase, entry.bank)
        if site in event_map:
            return None
        event_map[site] = ('poll', item)
    if read_site in event_map:
        return None
    event_map[read_site] = ('read', direct_reads[0])
    ordered_sites = facts.ordered_events(function, event_map)
    if ordered_sites is None:
        return None
    event_stream = []
    for site in ordered_sites:
        kind, item = event_map[site]
        if kind == 'call':
            event_stream.extend(('write', (site.address, *effect)) for effect in item)
        elif kind == 'mmio':
            event_stream.append((item[1], item))
        elif kind == 'poll':
            event_stream.append(('poll', item))
        else:
            event_stream.append(('read', item))
    if tuple(kind for kind, _ in event_stream) != (
            'poll', 'write', 'write', 'write', 'write', 'poll',
            'write', 'poll', 'write', 'poll', 'read'):
        return None
    writes = [item for kind, item in event_stream if kind == 'write']
    call_events = [item for kind, item in event_stream if kind == 'poll']
    if len(writes) != 6 or [item[2] for item in writes] != [4, 0x0C, 0x10,
                                                            0x10, 0x0C, 0x0C]:
        return None
    if (writes[0][4] != (0x086A,) or writes[2][4] != (0,)
            or writes[3][4] != (1,) or writes[5][4] != (0x8B00,)):
        return None
    first_wire, second_wire = writes[1][4], writes[4][4]
    if (not isinstance(first_wire, tuple) or not isinstance(second_wire, tuple)
            or not first_wire or not second_wire
            or any((value & 0xFF80) != 0x0A80 or (value & 0x60) != wire_selector
                   for value in first_wire)
            or any((value & 0xFF80) != 0x0A00 or (value & 0x60) != wire_selector
                   for value in second_wire)
            or {value & 0xFF7F for value in first_wire}
                != {value & 0xFFFF for value in second_wire}):
        return None
    polls = call_events
    if len(polls) != 4:
        return None
    if (any(poll[1] != 'poll' for poll in polls)
            or any(polls[index][2][0] not in (0x085F, 0x086A)
                   or polls[index][2][1] is not False for index in (0, 1, 2))
            or polls[3][2][:2] != (0x086A, True)):
        return None
    selected = {value & 0x60 for value in first_wire}
    if len(selected) != 1:
        return None
    return {
        'entry': entry.address - facts.base,
        'read_pc': read_site.address - facts.base,
        'source_selector': selector,
        'selector_mask': 0x60,
        'selector_value': next(iter(selected)),
        'request_shadow': shadow,
        'function': function,
        'poll_sites': tuple(item[0] for item in polls),
        'call_sites': tuple(site.address for site, _ in function.calls),
    }


def _code_intervals(facts, function):
    spans = []
    for site in sorted(function.instructions, key=lambda pc: (
            pc.address, pc.isa, pc.phase, pc.bank)):
        ins = facts.decode(site)
        if ins is not None:
            spans.append((site.address - facts.base,
                          site.address - facts.base + ins.size))
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _candidate_entries(facts):
    references = facts.literal_references(SBI_BASE)
    targets = {target for _, target in facts.call_candidates('thumb')}
    for target in sorted(targets):
        if any(target <= literal.instruction.address <= target + 0x200
               and literal.instruction.isa == 'thumb'
               for literal in references):
            yield CodeAddress(target, 'thumb')


def find_sbi_raw_input_profile(image, bootstrap_profile, ram_base, ram_size):
    """Prove a linked selector and closed SBI control/poll/data transaction."""
    if bootstrap_profile is None:
        return None, 'bootstrap-prerequisite-missing'
    if not isinstance(bootstrap_profile, dict):
        return None, 'malformed-bootstrap-prerequisite'
    if not bootstrap_profile_matches(image, bootstrap_profile):
        return None, 'bootstrap-prerequisite-unclosed'
    bootstrap, validation = _bootstrap_contract()
    entries = bootstrap_profile.get('entries')
    if (bootstrap_profile.get('signature') != 'thumb-sbi-bootstrap-only-v1'
            or bootstrap_profile.get('admission') != 'temporary-evidence-gated'
            or bootstrap_profile.get('accepted') is not True
            or bootstrap_profile.get('base_address') != SBI_BASE
            or bootstrap_profile.get('bootstrap') != bootstrap
            or bootstrap_profile.get('validation') != validation
            or type(entries) is not list or len(entries) != 1
            or type(entries[0]) is not int or entries[0] & 1
            or not 0 <= entries[0] <= len(image) - 2):
        return None, 'bootstrap-prerequisite-unclosed'
    # Raw-input call discovery below is Thumb-only. The legacy profile keeps
    # integer offsets for its public shape, so establish the instruction-set
    # mode from a fresh source query instead of inferring it from that offset
    # or from the diagnostic layout label.
    from .bootstrap import find_bootstraps
    if not any(entry == entries[0]
               for entry, _ in find_bootstraps(image, 'thumb')):
        return None, 'bootstrap-prerequisite-unclosed'
    if type(ram_base) is not int or type(ram_size) is not int or ram_base < 0 \
            or ram_size <= 0 or ram_base + ram_size > 0x100000000:
        return None, 'invalid-ram-window'

    facts = facts_for(image)
    candidates = []
    for entry in _candidate_entries(facts):
        source = _source_selector(facts, entry)
        if source is None:
            continue
        selector, filter_fn, raw_call, caller, outer_call = source
        transaction = _transaction(facts, entry, selector)
        if transaction is None:
            continue
        shadow = transaction['request_shadow']
        if not ram_base <= shadow < ram_base + ram_size:
            continue
        candidates.append((entry, selector, filter_fn, raw_call, caller,
                           outer_call, transaction))
    if not candidates:
        return None, 'raw-getter-not-closed'
    if len(candidates) != 1:
        return None, 'ambiguous-raw-getters'
    entry, selector, filter_fn, raw_call, caller, outer_call, transaction = candidates[0]
    selected = transaction['selector_value']
    read_pc = transaction['read_pc']
    links = [(site - facts.base, target - facts.base)
             for site, target in facts.call_candidates('thumb')
             if target in (entry.address, filter_fn.entry.address)]
    profile = {
        'signature': 'thumb-sbi-raw-sample-086a-v1',
        'admission': 'temporary-evidence-gated',
        'accepted': True,
        'policy': 'configured-virtual-raw-byte-uncalibrated',
        'base_address': SBI_BASE,
        'control': 0x086A,
        'request_prefix': 0x0A80,
        'read_command': 0x8B00,
        'selector_mask': 0x60,
        'selector_value': selected,
        'source_selector': selector,
        'read_pc': read_pc,
        'entry': transaction['entry'],
        'entries': [transaction['entry']],
        'request_shadow': transaction['request_shadow'],
        'filter_entry': filter_fn.entry.address - facts.base,
        'cache_entry': caller.entry.address - facts.base,
        'filter_parameter': dict(_callsite(caller, outer_call).registers).get(a.ARM_REG_R2),
        'call_links': [dict(call_pc=site, target=target) for site, target in links],
        'code_intervals': _code_intervals(facts, transaction['function']),
    }
    return profile, 'accepted'


def _bootstrap_contract():
    from .bootstrap import compatibility_events
    return compatibility_events()


def qemu_sbi_raw_input_property(config, profile):
    """Serialize only a statically proven SBI raw-data callback and selector."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, 'raw-input-malformed-profile'
    if (profile.get('signature') != 'thumb-sbi-raw-sample-086a-v1'
            or profile.get('admission') != 'temporary-evidence-gated'
            or profile.get('accepted') is not True
            or profile.get('policy') != 'configured-virtual-raw-byte-uncalibrated'):
        return None, 'raw-input-unsupported-contract'
    expected = {'base_address': SBI_BASE, 'control': 0x086A,
                'request_prefix': 0x0A80, 'read_command': 0x8B00,
                'selector_mask': 0x60}
    if any(type(profile.get(key)) is not int or profile[key] != value
           for key, value in expected.items()):
        return None, 'raw-input-malformed-wire'
    source = profile.get('source_selector')
    selected = profile.get('selector_value')
    if (type(source) is not int or type(selected) is not int
            or {0: 0x20, 0x40: 0x40, 0x60: 0x60}.get(source) != selected):
        return None, 'raw-input-selector-unclosed'
    entry, read_pc = profile.get('entry'), profile.get('read_pc')
    size, load = getattr(config, 'flash_size', None), getattr(config, 'load_address', 0)
    if type(load) is not int or load != 0:
        return None, 'raw-input-unverified-code-layout'
    if (type(size) is not int or size <= 0 or type(entry) is not int or entry < 0
            or entry & 1 or type(read_pc) is not int or read_pc & 1
            or read_pc > 0xFFFFFFFE or read_pc + 2 > size
            or profile.get('entries') != [entry]
            or type(profile.get('entries')) is not list
            or any(type(site) is not int for site in profile['entries'])):
        return None, 'raw-input-consumer-unclosed'
    value = getattr(config, 'board_adc_value', None)
    if type(value) is not int or not 0 <= value <= 0xFF:
        return None, 'raw-input-byte-unavailable'
    return f'sbi-raw-input-profile={read_pc:x}:60:{selected:x}', None


def qemu_sbi_raw_input_property_for_images(config, profile, bootstrap_profile,
                                            images, ram_base, ram_size):
    """Serialize only when original and loaded bytes reproduce the profile."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, 'raw-input-malformed-profile'
    if not isinstance(images, (tuple, list)) or not images:
        return None, 'raw-input-source-unavailable'
    expected = None
    for index, image in enumerate(images):
        if not isinstance(image, (bytes, bytearray, memoryview)):
            return None, 'raw-input-source-unavailable'
        detected, _ = find_sbi_raw_input_profile(
            bytes(image), bootstrap_profile, ram_base, ram_size)
        if detected is None:
            return None, 'raw-input-source-unclosed'
        if index == 0:
            expected = detected
            if not _typed_equal(detected, profile):
                return None, 'raw-input-source-mismatch'
        elif not _typed_equal(detected, expected):
            return None, 'raw-input-loaded-source-mismatch'
    return qemu_sbi_raw_input_property(config, profile)


def raw_input_profile_matches(image, bootstrap_profile, profile, ram_base, ram_size):
    """Return whether source bytes reproduce the complete configured profile."""
    if (not isinstance(profile, dict)
            or not isinstance(image, (bytes, bytearray, memoryview))):
        return False
    actual, _ = find_sbi_raw_input_profile(bytes(image), bootstrap_profile,
                                           ram_base, ram_size)
    return actual is not None and _typed_equal(actual, profile)

