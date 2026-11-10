from __future__ import annotations

def _distributed_call_profile(image: bytes, parent: dict):
    """Optional compiled context exit; does not alter other input admission."""
    from . import _DISTRIBUTED_CALL_SPANS, _distributed_branch, _distributed_ram, facts_for
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)
    try:
        require(parent.get('menu_mapping_status') == parent.get('ok_mapping_status') == 'accepted-provisional', 'call-parent-rejected')
        control = parent['control_consumer']
        require(control['grammar'] == 'distributed-queued-direct-word-controls-v1', 'call-parent-grammar')
        handler, status, global_word = [control[k] for k in ('confirm_handler','confirm_status','global_word')]
        require(all(type(v) is int for v in (handler,status,global_word)) and not handler & 1 and 0 <= handler <= len(image)-0x5850 and status % 4 ==
            global_word % 4 == 0 and _distributed_ram(status,0x60) and _distributed_ram(global_word,4) and (status+0x60 <= global_word or global_word+4 <=
            status), 'call-parent-owner-invalid')
        events = parent['event_codes']
        require(isinstance(events,(list,tuple)) and len(events)==24 and all(type(v) is int and 0 <= v <= 255 for v in events) and events.count(0x50)==1,
            'call-event-not-unique')
        owners = dict(status=status,global_word=global_word,mask_constant=0xFFF7)
        for role,relative,register,size,alignment in (('gate_state',-0xF3DE,0,5,4),('cleanup_node',-0x11CC4,0,4,4), ('cleanup_flags',-0x11CBC,0,2,2),('exit_status',0x581C,1,4,4)):
            value=facts_for(image).thumb_literal_value(handler+relative, register)
            require(type(value) is int and value % alignment == 0 and _distributed_ram(value,size), 'call-literal-owner-invalid')
            owners[role]=value
        application = control['application']
        require(type(application) is int and not application & 1 and 0 <= application <= len(image)-0x6C, 'call-application-outside-image')
        mode = facts_for(image).thumb_literal_value(application+0x6A, 1)
        require(type(mode) is int and _distributed_ram(mode,0x3C), 'call-mode-owner-invalid')
        producer=parent['producer']
        roots= [(status,0x60),(global_word,4),(control['menu_status'],0x60), (control['state_owner'],3),(control['secondary_ring'],72),(mode,0x3C), (producer['ring'],34),(producer['state'],producer['state_size']),
            (parent['scanner_state'],parent['scanner_state_size']), (parent['batch_state'],parent['batch_state_size'])]
        roots.extend((port['shadow'],1) for port in parent['gpio_ports'])
        extra= [(owners[k],size) for k,size in (('gate_state',5),('cleanup_node',4),('cleanup_flags',2),('exit_status',4))]
        require(all(type(a) is int and type(size) is int and size>0 for a,size in roots),'call-owned-span-invalid')
        require(all(a+size<=b or b+extent<=a for a,size in extra for b,extent in roots) and all(a+size<=b or b+ extent<=a for i,(a,size) in enumerate(extra) for
            b,extent in extra[:i]), 'call-owned-span-alias')
        for relative,body,literals,calls in _DISTRIBUTED_CALL_SPANS:
            pc=handler+relative;expected=bytes.fromhex(body)
            require(pc>=0 and pc+len(expected)<=len(image),'call-code-outside-image')
            actual=bytearray(image[pc:pc+len(expected)])
            for offset,register,role in literals:
                require(facts_for(image).thumb_literal_value(pc+offset, register)==owners[role], 'call-literal-owner-mismatch')
                actual[offset]=0
            for offset,target_relative in calls:
                target=handler+target_relative
                require(0<=target<=len(image)-4 and facts_for(image).thumb_call_target(pc+offset)==target,'call-relative-call-mismatch')
                actual[offset:offset+4]=bytes(4)
            require(bytes(actual)==expected,'call-context-exit-opcode-mismatch')
            for offset in range(0,len(expected),2):
                word=int.from_bytes(expected[offset:offset+2],'little')
                if word & 0xF800 == 0xE000 or word & 0xF000 == 0xD000:
                    condition=(word>>8)&15 if word & 0xF000 == 0xD000 else None
                    require(_distributed_branch(image,pc+offset,len(image),condition) is not None,'call-branch-outside-image')
        return {3:dict(event=0x50,rule='same-image-distributed-functional-call-v1', semantic_status= 'temporary-evidence-gated-provisional',functional_only=True)},dict(call_mapping_status=
            'accepted-provisional',call_consumer=dict(grammar='distributed-queued-context-exit-v1',handler= handler,status=status,global_word=global_word, event=0x50,request_code=0x32,global_reader=handler+
            0x22E,event_compare=handler+0x264, gate_call=handler+0x9BA,gate=handler-0xF3E0,global_reread=handler +0x9C4, request_store=handler+0x36B8,request_dispatch=handler+0xE0,
            request_table_slot=handler+0x156,cleanup=handler-0x11CC8,normal_return=handler+0x584C, gate_state=owners['gate_state'],cleanup_node= owners['cleanup_node'],
            cleanup_flags=owners['cleanup_flags'],exit_status=owners['exit_status']), call_mapping_limits=
            'Temporary compiled context-exit class; request32/context exit verified. Physical Call meaning is cross-class inference; dialer/call effects and other contexts remain unverified.')
    except (ValueError,KeyError,IndexError,TypeError) as error:
        return {},dict(call_mapping_status='rejected',call_mapping_reject_reasons= [str(error)])

def resolve_distributed_matrix_input(image: bytes, load_address: int = 0):
    """Opt-in distributed GPIO scanner, with optional queued functional controls."""
    from . import ASCII_KEY_EVENTS, MAX_DIRECT_MATRIX_TAILS, SINGLE_KEY_COLUMN_SENSE, _distributed_back_profile, _distributed_branch, _distributed_call_profile, _distributed_clear, _distributed_control_profile, _distributed_gpio_arm, _distributed_hop, _distributed_irq, _distributed_navigation_profile, _distributed_ram, _distributed_ring32, _samsung_sideband_51_family_metadata, _thumb_path_preserves_register, facts_for, find_all
    if load_address != 0:
        return None, 'unsupported-load-address',[]
    candidates, rejected = [],[]
    anchors = find_all(image, bytes.fromhex('f0b587b000276846'))
    if len(anchors) > MAX_DIRECT_MATRIX_TAILS:
        return None, 'candidate-cap',[]
    for start in anchors:
        end = min(start + 0x700, len(image))
        if start & 1 or end < start + 0x560:
            continue
        # A class-local compiled layout: no absolute code/data addresses.
        global_load, sense_load, switch = start + 0xca, start + 0x310, start + 0xe8
        helper = facts_for(image).thumb_call_target(global_load - 4)
        arms = [switch + 16 + 2 * v for v in image[switch + 16:switch + 22]]
        lock = facts_for(image).thumb_call_target(arms[0]) if len(arms) == 6 else None
        unlock = facts_for(image).thumb_call_target(sense_load - 4)
        scanner_state = facts_for(image).thumb_literal_value(start + 0x40, 4)
        reason = None
        if (image[start + 16:start + 18] != bytes.fromhex('0026') or image[global_load + 2:global_load + 10] != bytes.fromhex('01790907090f0f29') or image[sense_load
            + 2:sense_load + 10] != bytes.fromhex('00790007000f0f28') or facts_for(image).thumb_literal_value(global_load, 0) != facts_for(image).thumb_literal_value(sense_load,
            0) or not _distributed_irq(image, lock, False) or not _distributed_irq(image, unlock, True) or not _thumb_path_preserves_register(image, start + 18,
            switch, end, 6) or not _thumb_path_preserves_register(image, start + 0x42, switch, end, 4) or not _distributed_ram(scanner_state, 0xA) or
            _distributed_branch(image, sense_load + 10, end, 0) != sense_load + 76 or not _distributed_hop(image, _distributed_branch(image, global_load + 10,
            end, 0), sense_load + 0x190, start, end) or not _distributed_hop(image, _distributed_branch(image, switch + 4, end, 2), sense_load, switch, end) or
            image[switch:switch + 4] != bytes.fromhex('039a062a') or image[switch + 6:switch + 14] != bytes.fromhex('02a39b5c5b009f44') or len(set(arms)) != 6
            or any(not switch + 22 <= a < sense_load for a in arms)):
            reason = 'scanner-switch-or-read-link'
        rows = [] if reason else[_distributed_gpio_arm(image, a, sense_load, sense_load - 4, lock, unlock) for a in arms]
        if not reason and (any(row is None for row in rows) or helper is None):
            reason = 'gpio-arm-not-closed'
        if not reason:
            ports = [{k: v for k, v in port.items() if k not in ('value', 'store')} for port in rows[0]]
            base = ports[0]['address'] - 12
            masks = [port['mask'] for port in ports]
            flat_mask = sum(mask << (8 * i) for i, mask in enumerate(masks))
            selections = [sum(port['value'] << (8 * i) for i, port in enumerate(row)) for row in rows]
            ordered_bits = [1 << bit for bit in range(24) if flat_mask & (1 << bit)]
            if (not 0x03000000 <= base <= 0x03001000 - 53 or base & 31 or facts_for(image).thumb_literal_value(sense_load, 0) != base + 48 or any([{k: v for k,
                v in port.items() if k not in ('value', 'store')} for port in row] != ports for row in rows) or len({port['shadow'] for port in ports}) != 3 or
                flat_mask.bit_count() != 6 or[flat_mask ^ value for value in selections] != ordered_bits or not _distributed_clear(image, helper, lock, unlock,
                ports)):
                reason = 'gpio-mask-owner-or-clear-link'
        # Exact bounded column enumeration, stack batch store and row loop.
        batch = bytes.fromhex('0107090f0020ca43069201218140069a11400cd006214143')
        batch_tail = bytes.fromhex('8918039a8b5c711c0a06120e311c161c6a4653540a2e0eda01300006000e0428e6db0a2e07da039a501c0206120e0392062a00da')
        table = facts_for(image).thumb_literal_value(sense_load + 36, 2)
        if not reason and (image[sense_load + 12:sense_load + 36] != batch or image[sense_load + 38:sense_load + 90] != batch_tail or _distributed_branch(image,
            sense_load + 90, end) != switch - 4 or facts_for(image).thumb_call_target(sense_load + 92) != helper or facts_for(image).thumb_call_target(switch -
            4) != helper or image[switch - 8:switch - 4] != bytes.fromhex('00220392') or table is None or not 0 <= table <= len(image) - 24):
            reason = 'column-batch-row-loop-link'
        # Single-element batch branch and R7 path through the existing state gate.
        pick, move = sense_load + 0x18a, sense_load + 0x222
        state_load = sense_load + 0x156
        batch_state = facts_for(image).thumb_literal_value(state_load, 2)
        sink = facts_for(image).thumb_call_target(move + 2)
        if not reason and (image[sense_load + 96:sense_load + 100] != bytes.fromhex('012e5edd') or _distributed_branch(image, sense_load + 98, end, 13) !=
            sense_load + 0x122 or _distributed_branch(image, sense_load + 0x122, end) != sense_load + 0x152 or image[sense_load + 0x152:sense_load + 0x154] !=
            bytes.fromhex('012e') or image[state_load + 2:state_load + 6] != bytes.fromhex('517b0029') or not _distributed_ram(batch_state, 0xE) or
            _distributed_branch(image, state_load + 6, end, 13) != pick or image[pick:pick + 4] != bytes.fromhex('00af3f78') or not
            _thumb_path_preserves_register(image, pick + 4, move, end, 7) or image[move:move + 2] != bytes.fromhex('381c') or sink is None):
            reason = 'single-batch-stateful-transfer-link'
        producer = None if reason else _distributed_ring32(image, sink, lock, unlock)
        if not reason and (producer is None or facts_for(image).thumb_literal_value(sense_load + 0x1fc, 0) != batch_state or facts_for(image).thumb_literal_value(sense_load
            + 0x1ac, 1) != producer['state']):
            reason = 'ring32-provenance-or-state-link'
        events = [] if table is None or not 0 <= table <= len(image) - 24 else list(image[table:table + 24])
        if not reason and any(events.count(v) != 1 for v in ASCII_KEY_EVENTS):
            reason = 'numeric-event-missing-or-duplicated'
        if reason:
            rejected.append({'function': start, 'reasons':[reason]})
            continue
        candidates.append({'grammar': 'distributed-six-byte-numeric-v1', 'function': start, 'scanner_state': scanner_state, 'scanner_state_size': 0xA,
            'batch_state': batch_state, 'batch_state_size': 0xE, 'presence_site': global_load + 2, 'sense_site': sense_load + 2, 'register': base + 52,
            'register_width': 1, 'no_key': 15, 'rows': 6, 'columns': 4, 'sense_bits': 4, 'single_key_column_sense': list(SINGLE_KEY_COLUMN_SENSE), 'gpio_ports':
            ports, 'row_values':[[p['value'] for p in row] for row in rows], 'global_values':[0, 0, 0], 'event_table': table, 'event_codes': events,
            'token_cells':[{'token': chr(v), 'event': v, 'row': events.index(v) % 6, 'column': events.index(v) // 6} for v in ASCII_KEY_EVENTS],
            'event_transfer': {'batch_store': sense_load + 56, 'single_pick': pick, 'move': move, 'call': move + 2}, 'producer': producer, 'runtime_admitted':
            False, 'limits': 'Temporary opt-in numeric-only static class; GPIO owner/readback and natural input consumption require runtime validation.' })
    if len(candidates) > 1:
        return None, 'ambiguous-scanners', candidates
    if candidates:
        parent = candidates[0]
        parent.update(_samsung_sideband_51_family_metadata(image, parent['function'], parent['sense_site'], parent['producer']['enqueue'], load_address))
        mappings, metadata = _distributed_control_profile(image, parent)
        parent.update(metadata)
        if mappings:
            parent['provisional_mappings'] = mappings
            parent['limits'] = ('Temporary opt-in GPIO class; functional MENU/confirm labels are provisional, ' 'and input handling remains firmware-owned.')
            events = parent['event_codes']
            parent['token_cells'].extend({'token': token, 'event': event, 'row': events.index(event) % 6, 'column': events.index(event) // 6} for token,event in
                (('M',0x5B),('O',0x53)))
            call, call_metadata = _distributed_call_profile(image,parent)
            parent.update(call_metadata)
            if call:
                parent['provisional_mappings'].update(call)
                parent['token_cells'].append({'token':'S','event':0x50, 'row':events.index(0x50)%6,'column': events.index(0x50)//6})
            navigation, nav_metadata = _distributed_navigation_profile(image, parent)
            parent.update(nav_metadata)
            if navigation:
                parent['provisional_mappings'].update(navigation)
                parent['token_cells'].extend({'token': token,'event': event, 'row':events.index(event)%6, 'column':events.index(event)//6} for token,event in (('U',0x63),('D',0x64),('L',0x65),('R',
                    0x66)))
                back, back_metadata = _distributed_back_profile(image,parent)
                parent.update(back_metadata)
                if back:
                    parent['provisional_mappings'].update(back)
                    parent['token_cells'].append({'token':'C','event':0x52, 'row':events.index(0x52)%6,'column': events.index(0x52)//6})
    return (candidates[0], 'static-candidate', rejected) if candidates else (None, 'rejected' if rejected else 'not-found', rejected)
