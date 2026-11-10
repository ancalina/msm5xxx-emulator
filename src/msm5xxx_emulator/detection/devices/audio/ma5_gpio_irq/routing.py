from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match

def _route(image: bytes, audio: dict, init: dict, scanned: dict, layouts: list[tuple]) -> dict:
    from . import _boot_copy, _check, _direct_accessor, _indirect_call_chain, _mapping, _one, _pointer, _span, facts_for, re, struct
    spans = [init]
    boot_layouts, boot_dependencies = _boot_copy(image)
    nor, ram = list(boot_dependencies),[]
    if boot_layouts:
        boot_row = boot_layouts[0]
        higher = [row for row in layouts if boot_row[2] + boot_row[3] <= row[2] < boot_row[4]]
        if higher:
            boundary = min(row[2] for row in higher)
            nor.extend([[row[0], 20] for row in higher if row[2] == boundary])
    table = init['literals'][0x56]
    callbacks = init['literals'][0x80]
    gpio_entry = _pointer(image, init['literals'][0x9A])
    gpio = _span(image, gpio_entry, 'gpio_dispatch')
    spans.append(gpio)
    gl = gpio['literals']
    _check(gl == {2: 0x03000C80, 6: table, 0x26: callbacks, 0xAE: table + 0x40}, 'gpio-dispatch-table-linkage')
    thunk = gpio['calls'][0x48]
    _check(set(gpio['calls'].values()) == {thunk}, 'gpio-indirect-call-unmatched')
    indirect = _indirect_call_chain(image, thunk)
    nor.extend(indirect['nor_dependencies'])
    default = _pointer(image, init['literals'][0x82])
    _check(image[default:default + 2] == b'\x70\x47', 'gpio-default-unmatched')
    registrar = _one([span for span in scanned['gpio_register'] if span['literals'] == {0x2C: table, 0x2E: callbacks, 0x36: default | 1, 0x48: table}],
        'gpio-registrar-none-or-ambiguous')
    spans.append(registrar)
    lock, unlock = registrar['calls'][0x18], registrar['calls'][0x72]
    _check(all(init['calls'][offset] == lock for offset in (4, 10, 0x26, 0x38)) and all(init['calls'][offset] == unlock for offset in (0x22, 0x34, 0x46, 0x96)),
        'gpio-init-lock-linkage')
    _check(init['literals'][0x18] == init['literals'][0x4A] == 0x03000CA0 and init['literals'][0x4C] == 0xFFFF, 'gpio-init-mmio-unmatched')
    parent_reg = _span(image, init['calls'][0x9E], 'parent_register')
    spans.append(parent_reg)
    table_offset, unlock_offset, error_offset = { 122: (0x26, 0x70, 0x1C), 124: (0x28, 0x72, 0x20), 128: (0x2C, 0x76, 0x24), 134: (0x32, 0x7C, 0x28), }[parent_reg['size']]
    parent_table = parent_reg['literals'][table_offset]
    _check(parent_reg['calls'][6] == lock and parent_reg['calls'][unlock_offset] == unlock, 'parent-registrar-lock-linkage')
    _check(not (table | callbacks | parent_table) & 3, 'route-table-unaligned')
    parent_state = parent_table - 12
    socs = []
    for soc in scanned['soc_dispatch']:
        literals = soc['literals']
        if soc['size'] == 392:
            coherent = (all(literals[o] == 0x03000C80 for o in (0x12, 0x74, 0xA6, 0xCA, 0xD0, 0xEE, 0x11E, 0x16C)) and all(literals[o] == parent_state for o in
                (8, 0x16, 0x70, 0x158)) and literals[0xA0] == parent_table and literals[0x4C] == parent_table + 31 * 28 + 4 and all(soc['calls'][o] == thunk for
                o in (0xB8, 0xF4, 0x10C)) and all(soc['calls'][o] == lock for o in (0x14A, 0x162)) and all(soc['calls'][o] == unlock for o in (0x34, 0x94)))
        elif soc['size'] == 394:
            coherent = (all(literals[o] == 0x03000C80 for o in (0x12, 0x74, 0xA8, 0xCC, 0xD2, 0xF0, 0x120, 0x16E)) and all(literals[o] == parent_state for o in
                (8, 0x16, 0x70, 0xA0, 0x15A)) and literals[0x4C] == parent_table + 31 * 28 + 4 and all(soc['calls'][o] == thunk for o in (0xBA, 0xF6, 0x10E))
                and all(soc['calls'][o] == lock for o in (0x14C, 0x164)) and all(soc['calls'][o] == unlock for o in (0x34, 0x94)))
        elif soc['size'] == 438:
            coherent = (all(literals[o] == 0x03000C80 for o in (0x1C, 0x7E, 0xB0, 0xD4, 0xDA, 0xF8, 0x128, 0x19A)) and all(literals[o] == parent_state for o in
                (8, 0x20, 0x7A, 0x186)) and literals[0x16] == literals[0xAA] == parent_table and literals[0x56] == parent_table + 31 * 28 + 4 and all(soc['calls'][o]
                == thunk for o in (0xC2, 0xFE, 0x116)) and all(soc['calls'][o] == lock for o in (0x178, 0x190)) and all(soc['calls'][o] == unlock for o in (0x3E,
                0x9E)))
        else:
            coherent = (all(literals[o] == 0x03000C80 for o in (0x12, 0x74, 0xA8, 0xCC, 0xE8, 0xEE, 0x10C, 0x13C, 0x18A)) and literals[0xBE] == 0x03000720 and
                all(literals[o] == parent_state for o in (8, 0x16, 0x70, 0xA0, 0x176)) and literals[0x4C] == parent_table + 31 * 28 + 4 and all(soc['calls'][o]
                == thunk for o in (0xD6, 0x112, 0x12A)) and all(soc['calls'][o] == lock for o in (0x168, 0x180)) and all(soc['calls'][o] == unlock for o in (0x34,
                0x94)))
        if coherent:
            socs.append(soc)
    soc = _one(socs, 'soc-dispatcher-none-or-ambiguous')
    spans.append(soc)
    # Parent init registers this actual SoC dispatcher into the exception callback table.
    parent_init = _one([span for span in scanned['parent_init'] if span['literals'][0x46] == soc['entry'] | 1], 'parent-init-none-or-ambiguous')
    spans.append(parent_init)
    _check(parent_init['literals'][0x16] == 0x03000C80 and parent_init['literals'][0x38] == 0xFFFF and all(parent_init['calls'][o] == lock for o in (2, 8, 0x24))
        and all(parent_init['calls'][o] == unlock for o in (0x20, 0x32, 0x42)) and parent_init['calls'][0x4A] == parent_init['calls'][0x52],
        'parent-init-registration-linkage')
    exception = _span(image, parent_init['calls'][0x4A], 'exception_register')
    spans.append(exception)
    _check(not exception['literals'][0] & 3, 'exception-array-unaligned')
    exception_offset = ((struct.unpack_from('<H', image, exception['entry'] + 6)[0] >> 6) & 31) * 4
    other_exception = _pointer(image, parent_init['literals'][0x4E])
    error_pointer = parent_reg['literals'][error_offset]
    _check(0 <= error_pointer < len(image), 'parent-error-literal-unmapped')
    nor.extend([[other_exception, 2],[error_pointer, 1]])
    boot_calls = []
    for match in re.finditer(rb'(?=.[\xf0-\xf7].[\xf8-\xff])', image, re.DOTALL):
        call = match.start()
        if (call >= 4 and not call & 1 and facts_for(image).thumb_call_target(call) == init['entry'] and facts_for(image).thumb_call_target(call - 4) ==
            parent_init['entry']):
            boot_calls.append(call - 4)
    _check(len(boot_calls) == 1, 'init-caller-none-or-ambiguous')
    nor.append([boot_calls[0], 8])
    index = struct.unpack_from('<H', image, init['entry'] + 0x9C)[0] & 255
    _check(0 < index < 31, 'parent-index-unmatched')
    descriptor = parent_table + index * 28
    desc_layout = _mapping(layouts, descriptor, 28, data=True)
    desc_rom = desc_layout[1] + descriptor - desc_layout[2]
    words = list(struct.unpack_from('<7I', image, desc_rom))
    status, enable, mask, shadow, priority, initial, reserved = words
    _check(status == 0x03000C84 and enable == 0x03000C98 and 0 < mask <= 0x8000 and not mask & (mask - 1) and shadow == parent_state + 2 and priority ==
        parent_state + 8 and initial == parent_reg['literals'][0xE] and not reserved, 'parent-descriptor-linkage')
    if soc['size'] in (392, 394):
        stride = 12 if soc['size'] == 394 else 10
        priorities = soc['literals'][0x4C]
        priority_layout = _mapping(layouts, priorities, stride * 4, data=True)
        priority_rom = priority_layout[1] + priorities - priority_layout[2]
        eligible = []
        for row_index in range(1, 4):
            low, high, disable_low, disable_high, first, last = struct.unpack_from('<4H2B', image, priority_rom + row_index * stride)
            _check(0 < first <= last < 31, 'parent-priority-range-unmatched')
            if first <= index <= last and (high if enable == 0x03000C98 else low) & mask:
                eligible.append(row_index)
        _check(len(eligible) == 1, 'parent-priority-owner-unmatched')
        nor.append([priority_rom, stride * 4])
    _pointer(image, initial)
    nor.extend([[desc_layout[0], 12 if any(row[0] == desc_layout[0] for row in boot_layouts) else 20],[desc_rom, 28],[initial - 1, 2]])
    gpio_layout = _mapping(layouts, table, 72, data=True)
    gpio_rom = gpio_layout[1] + table - gpio_layout[2]
    rows = []
    for bank in range(3):
        row = struct.unpack_from('<4I4H', image, gpio_rom + bank * 24)
        expected = (0x03000C88 + 4 * bank, 0x03000CA4 + 4 * bank, 0x03000CB0 + 4 * bank, 0x0300074C + 4 * bank, 0, 0xFFFF, 0, 0)
        _check(row == expected, 'gpio-row-unmatched')
        rows.append({'pending_ack': row[0], 'enable': row[1], 'polarity': row[2], 'trigger': row[3], 'cache_ram': table + bank * 24 + 16, 'initial_cache': list(row[4:])})
    nor.extend([[gpio_layout[0], 12 if any(row[0] == gpio_layout[0] for row in boot_layouts) else 20],[gpio_rom, 72],[default, 2]])
    context_base = audio['structural_evidence']['context_pointer']
    context = context_base + audio['structural_evidence'].get('context_word_offset', 0)
    ctx_layout = _mapping(layouts, context, 4, data=True)
    ctx_rom = ctx_layout[1] + context - ctx_layout[2]
    context_initial = struct.unpack_from('<I', image, ctx_rom)[0]
    nor.extend([[ctx_layout[0], 12 if any(row[0] == ctx_layout[0] for row in boot_layouts) else 20],[ctx_rom, 4]])
    isrs = []
    entries = audio['structural_evidence']['entries']
    for isr in scanned['chip_isr']:
        calls = isr['calls']
        shift = 4 if isr['size'] == 88 else 0
        if (isr['literals'][2 + shift] == context_base and all(calls[o + shift] == entries['select'] for o in (0x14, 0x22, 0x4A)) and all(calls[o + shift] ==
            entries['dataread'] for o in (0x1A, 0x26))):
            isrs.append(isr)
    isr = _one(isrs, 'chip-isr-none-or-ambiguous')
    isr_shift = 4 if isr['size'] == 88 else 0
    wrapper = _span(image, isr['calls'][0x3A + isr_shift], 'chip_wrapper')
    spans.extend([isr, wrapper])
    installers = []
    for install in scanned['install_conditional']:
        if (install['calls'][0x2A] != registrar['entry'] or install['calls'][0x46] != registrar['entry'] or install['literals'][0x20] != isr['entry'] | 1):
            continue
        pin = install['pins'][0x28]
        if not 0 <= pin < 48 or install['pins'][0x44] != pin:
            continue
        deferred = _span(image, _pointer(image, install['literals'][0x24]), 'deferred')
        _check(deferred['calls'][4] == entries['index'] and deferred['literals'][0xC] == install['literals'][0x4E], 'deferred-gate-linkage')
        active, other = install['literals'][2], install['literals'][0x18]
        installers.append((install, { 'profile': 'conditional-install-direct-or-task-v1', 'entry': install['entry'], 'pin': pin, 'polarity_argument': 0,
            'installed_flag': active, 'installed_value': 1, 'direct_callback': isr['entry'] | 1, 'deferred_callback': deferred['entry'] | 1, 'direct_gate': {
            'any':[{'address': active + 0x1D, 'op': 'eq', 'value': 0}, {'address': other, 'op': 'ne', 'value': 0}]}, 'deferred_gate': {'all':[{'address': active
            + 0x1D, 'op': 'ne', 'value': 0}, {'address': other, 'op': 'eq', 'value': 0}]}, 'deferred_signal_tcb': deferred['literals'][0xC],
            'deferred_signal_mask': 0x200000, 'deferred_task_path_verified': False, },[deferred],[[active, 1],[active + 0x1D, 1],[other, 1]]))
    for install in scanned['install_direct']:
        if (install['calls'][0x30] != registrar['entry'] or install['literals'][0x2E] != isr['entry'] | 1):
            continue
        pin = install['pins'][0x24]
        if not 0 <= pin < 48 or install['pins'][0x2C] != pin:
            continue
        sense = _span(image, install['calls'][0x26], 'sense')
        _check(sense['literals'][0x28] == table and sense['calls'][0x16] == lock and sense['calls'][0x48] == unlock and install['calls'][2] == lock and install['calls'][0x1E]
            == unlock, 'direct-install-lock-sense-linkage')
        cache, mirror = install['literals'][6], install['literals'][0x12]
        cache_layout = _mapping(layouts, cache, 32, data=True)
        cache_rom = cache_layout[1] + cache - cache_layout[2]
        _check(struct.unpack_from('<I', image, cache_rom + 0x18)[0] == 0x03000730, 'direct-install-cache-pointer-unmatched')
        _mapping(layouts, mirror, 32, data=True)
        nor.extend([[cache_rom, 32]])
        installers.append((install, { 'profile': 'direct-install-no-flag-v1', 'entry': install['entry'], 'pin': pin, 'polarity_argument': 0, 'trigger_argument':
            0, 'installed_flag': None, 'installed_value': None, 'direct_callback': isr['entry'] | 1, 'deferred_callback': None, 'direct_gate': None,
            'deferred_gate': None, 'deferred_signal_tcb': None, 'deferred_signal_mask': None, },[sense],[[cache, 32],[mirror, 32]]))
    for install in scanned['install_sense']:
        if (install['calls'][0x14] != registrar['entry'] or install['literals'][0x12] != isr['entry'] | 1):
            continue
        pin = install['pins'][4]
        if not 0 <= pin < 48 or install['pins'][0x10] != pin:
            continue
        sense = _span(image, install['calls'][6], 'sense')
        _check(sense['literals'][0x28] == table and sense['calls'][0x16] == lock and sense['calls'][0x48] == unlock, 'sense-table-linkage')
        _check(install['literals'][0xA] == context_initial + 0x480, 'install-context-linkage')
        active = install['literals'][0xA] + 0x14
        installers.append((install, { 'profile': 'explicit-sense-direct-install-v1', 'entry': install['entry'], 'pin': pin, 'polarity_argument': 0,
            'trigger_argument': 0, 'installed_flag': active, 'installed_value': 1, 'direct_callback': isr['entry'] | 1, 'deferred_callback': None, 'direct_gate':
            None, 'deferred_gate': None, },[sense],[[active, 1]]))
    for install in scanned['install_inline']:
        if (install['calls'][14] != registrar['entry'] or install['literals'][12] != isr['entry'] | 1):
            continue
        pin = install['pins'][10]
        if not 0 <= pin < 48:
            continue
        # GPIO initializer writes zero to all trigger/polarity banks before install.
        installers.append((install, { 'profile': 'direct-install-no-flag-v1', 'entry': install['entry'], 'pin': pin, 'polarity_argument': 0, 'trigger_argument':
            0, 'installed_flag': None, 'installed_value': None, 'direct_callback': isr['entry'] | 1, 'deferred_callback': None, 'direct_gate': None,
            'deferred_gate': None, },[],[]))
    _check(len(installers) == 1, 'audio-install-none-or-ambiguous')
    install, installation, extra, gate_ram = installers[0]
    spans.extend([install, *extra])
    pin = installation['pin']
    ram.extend([[table, 72],[callbacks, 48 * 4],[parent_table, 31 * 28],[descriptor, 28],[parent_state, 12],[shadow, 2],[priority, 2],[exception['literals'][0]
        + exception_offset, 8],[context, 4],[context_initial + 0x480, 3], *gate_ram])
    _check(context_initial & 3 == 0, 'initial-context-unaligned')
    _check(init['literals'][0x12] == parent_init['literals'][0x10], 'init-state-linkage')
    init_state = init['literals'][0x12]
    ram.extend([[init_state + 0x64A, 4],[init_state + 0x652, 6]])
    auxiliaries = [{ 'address': table + 0x4A, 'width': 2, 'literal_load': gpio['entry'] + 0xAE, 'accessor': gpio['entry'] + 0xB0, 'path':
        'no-enabled-gpio-pending', 'purpose': 'miss-counter', }]
    # These non-route literals have no invented callee-pointee extent.
    exact_route_addresses = {table, callbacks, context, context_base, parent_table, parent_state, shadow, priority, descriptor, context_initial, init_state,
        init_state + 0x640}
    for span in spans:
        nor.extend(span['dependencies'])
        for offset, value in span['literals'].items():
            if 0x01000000 <= value < 0x02000000:
                _mapping(layouts, value, 1)
                if span is gpio and offset == 0xAE:
                    continue
                if value not in exact_route_addresses:
                    accessor = _direct_accessor(image, span['entry'] + offset, value)
                    if accessor is not None:
                        _check(not accessor['address'] % accessor['width'], 'auxiliary-accessor-unaligned')
                        ram.append([accessor['address'], accessor['width']])
                    auxiliaries.append({'address': value, 'width': None, 'direct_accessor': accessor, 'literal_load': span['entry'] + offset, 'path': ('parent-registrar-index-zero'
                        if span is parent_reg and offset in (0x30, 0x36) else 'uninstall-path' if span is install and offset >= 0x4E else
                        'initialization-or-installation' if span in (init, parent_init, install, *extra) else 'unclassified-other-irq-or-tracing'), 'purpose':
                        'callee-or-auxiliary-path-unverified'})
            elif value >= 0x03000000:
                _check(value in {0x03000C80, 0x03000CA0, 0x03000720}, 'auxiliary-mmio-literal-unmatched')
            elif value > 0xFFFF:
                _check(value < len(image), 'auxiliary-rom-literal-unmapped')
                nor.append([value & ~1, 2])
    for address, size in ram:
        layout = _mapping(layouts, address, size)
        nor.append([layout[0], 12 if any(row[0] == layout[0] for row in boot_layouts) else 20])
    _mapping(layouts, auxiliaries[0]['address'], 2)
    ram.append([auxiliaries[0]['address'], 2])
    auxiliary_calls = []
    bound_calls = { init['entry']: set(init['calls']), registrar['entry']: {0x18, 0x72}, parent_reg['entry']: {6, unlock_offset}, gpio['entry']: set(gpio['calls']),
        isr['entry']: set(isr['calls']) - ({2} if isr_shift else set()), parent_init['entry']: {2, 8, 0x20, 0x24, 0x32, 0x42, 0x4A, 0x52}, exception['entry']:
        set(), }
    bound_calls[install['entry']] = ({0x2A, 0x46} if installation['deferred_callback'] is not None else {6, 0x14 })
    if installation['profile'] == 'direct-install-no-flag-v1':
        bound_calls[install['entry']] = {2, 14} if install['size'] == 22 else {2, 0x1E, 0x26, 0x30}
    for companion in extra:
        bound_calls[companion['entry']] = ({4} if companion['size'] == 22 else set(companion['calls']))
    bound_calls[soc['entry']] = ({0x34, 0x94, 0xB8, 0xF4, 0x10C, 0x14A, 0x162} if soc['size'] == 392 else ({0x3E, 0x9E, 0xC2, 0xFE, 0x116, 0x178, 0x190} if soc['size']
        == 438 else {0x34, 0x94, 0xD6, 0x112, 0x12A, 0x168, 0x180}))
    if soc['size'] == 394:
        bound_calls[soc['entry']] = {0x34, 0x94, 0xBA, 0xF6, 0x10E, 0x14C, 0x164}
    for span in spans:
        for offset, target in span['calls'].items():
            if offset not in bound_calls.get(span['entry'], set()):
                path = ('gpio-chip-source-dispatch' if span is wrapper else 'invalid-parent-index' if span is parent_reg else 'initialization-or-installation'
                    if span in (parent_init, install, *extra) else 'unclassified-other-irq-or-tracing')
                auxiliary_calls.append({'callsite': span['entry'] + offset, 'target': target, 'path': path, 'callee_body_verified': False})
    return {
        'family': 'ma5', 'grammar': 'ma5-gpio-parent-irq-v1', 'status': 'candidate',
        'static_status': 'candidate', 'reject_reason': None, 'runtime_admitted': False,
        'source_profile': 'three-bank-gpio-parent-descriptor-v1',
        'admission_note': 'auxiliary-paths-unverified; live callback/exception proof required',
        'gpio': {'table_ram': table, 'table_rom': gpio_rom, 'rows': rows,
                 'callbacks_ram': callbacks, 'pin': pin, 'bank': pin >> 4,
                 'mask': 1 << (pin & 15), 'callback_slot': callbacks + pin * 4,
                 'registrar': registrar['entry'], 'dispatcher': gpio_entry,
                 'default_callback': default | 1, 'indirect_call_chain': indirect},
        'parent': {'table_ram': parent_table, 'index': index,
                   'descriptor_ram': descriptor, 'descriptor_rom': desc_rom, 'words': words,
                   'status_ack': status, 'enable': enable, 'mask': mask,
                   'enable_shadow': shadow, 'priority_shadow': priority,
                   'callback_slot': descriptor + 20, 'handler_counter': descriptor + 24,
                   'installed_gpio_dispatcher': gpio_entry | 1,
                   'dispatcher': soc['entry'], 'registrar': parent_reg['entry'],
                   'initializer': parent_init['entry'], 'gpio_initializer': init['entry'],
                   'adjacent_boot_registration': boot_calls[0],
                   'exception_registrar': exception['entry'],
                   'exception_callback_slot': exception['literals'][0] + exception_offset,
                   'installed_soc_dispatcher': soc['entry'] | 1},
        'chip': {'isr': isr['entry'], 'selector': entries['select'],
                 'data_reader': entries['dataread'],
                 'data_read_sites': audio['sites'][f"read_{audio['data_offset']}"],
                 'priority_wrapper': wrapper['entry'], 'priority_dispatcher': wrapper['calls'][2],
                 'context_holder': context, 'initial_context': context_initial},
        'installation': installation, 'aux_addresses': auxiliaries,
        'aux_calls': auxiliary_calls,
        'nor_dependencies': [list(span) for span in sorted({tuple(span) for span in nor})],
        'ram_dependencies': [list(span) for span in sorted({tuple(span) for span in ram})],
    }

def find_ma5_gpio_irq_candidate(image: bytes, audio_candidate: object) -> dict:
    """Find one same-image static route; this never enables native IRQ admission."""
    image = bytes(image) if isinstance(image, bytearray) else image
    from . import _Reject, _layouts, _route, _scan, find_ma5_readback_candidate
    rejected = {'family': 'ma5', 'grammar': 'ma5-gpio-parent-irq-v1', 'status': 'rejected', 'static_status': 'rejected', 'runtime_admitted': False,
        'reject_reason': 'route-none'}
    if (not isinstance(audio_candidate, dict) or not fields_match(audio_candidate, (('family', 'ma5'), ('grammar', 'ma5-readback-v1'), ('static_status',
        'candidate'))) or find_ma5_readback_candidate(image) != audio_candidate):
        return {**rejected, 'reject_reason': 'audio-same-image-unmatched'}
    if audio_candidate.get('structural_evidence', {}).get('transport_class') == 'alternate-reset-readback-v1':
        return {**rejected, 'reject_reason': 'audio-class-irq-unverified'}
    try:
        scanned = {role: _scan(image, role) for role in ('gpio_init', 'gpio_register', 'soc_dispatch', 'parent_init', 'chip_isr', 'install_conditional',
            'install_sense', 'install_direct', 'install_inline')}
        layouts = _layouts(image)
        candidates, reasons = [],[]
        for init in scanned['gpio_init']:
            try:
                candidates.append(_route(image, audio_candidate, init, scanned, layouts))
            except _Reject as error:
                reasons.append(str(error))
            if len(candidates) > 1:
                return {**rejected, 'reject_reason': 'route-ambiguous'}
        return candidates[0] if candidates else { **rejected, 'reject_reason': reasons[0] if len(set(reasons)) == 1 else 'route-none'}
    except _Reject as error:
        return {**rejected, 'reject_reason': str(error)}
