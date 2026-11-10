from __future__ import annotations
import re

TAIL = re.compile(b'.J' + re.escape(bytes.fromhex('506b00880007000f0f28')) + b'.\xd0.I' + re.escape(bytes.fromhex('0623085c183958434018445d')) + b'.\xe0' + re.escape(bytes.fromhex('01352d062d0e062d'))
    + b'.\xda.\xe7', re.S)

def interrupt_helper(image, veneer, enable):
    from . import struct
    if veneer is None or not 0 <= veneer <= len(image) - 16:
        return None
    if image[veneer:veneer + 12] != bytes.fromhex('7847c04600c09fe51cff2fe1'):
        return None
    target = struct.unpack_from('<I', image, veneer + 12)[0]
    if not target & 1:
        return None
    entry = target & ~1
    body = entry + 4
    expected = bytes.fromhex('00000fe1c010' + ('c0' if enable else '80') + 'e301f021e1c00000e21eff2fe1')
    if image[entry:entry + 2] != bytes.fromhex('7847') or image[body:body + 20] != expected:
        return None
    return {'veneer': hex(veneer), 'body': hex(body), 'operation': 'clear-cpsr-I-F' if enable else 'set-cpsr-I-F', 'return': 'previous-I-F-mask',
        'registers_written':['r0', 'r1', 'CPSR']}

def row_arms(image, sense, descriptor):
    """Close bounded six-row byte-switch and halfword output shape."""
    from . import _thumb_successors, facts_for, interrupt_helper, struct
    matches = []
    for site in range(max(0, sense - 256), sense - 14, 2):
        if image[site:site + 4] != bytes.fromhex('062d00d3'):
            continue
        adr = struct.unpack_from('<H', image, site + 6)[0]
        if adr & 65280 != 41728 or image[site + 8:site + 14] != bytes.fromhex('5b5d5b009f44'):
            continue
        table = (site + 10 & ~3) + 4 * (adr & 255)
        arms = [site + 16 + 2 * value for value in image[table:table + 6]]
        if len(arms) != 6 or len(set(arms)) != 6:
            continue
        valid = True
        calls = []
        for row, arm in enumerate(arms):
            if not site + 14 <= arm <= sense - 30:
                valid = False
                break
            expected = bytes.fromhex('3f23918b1b029943') + bytes([31 if row == 0 else 63 ^ 1 << row, 35]) + bytes.fromhex('5b02' if row == 0 else '1b02') + bytes.fromhex('19439183918b126911800028')
            if facts_for(image).thumb_literal_value(arm + 4, 2) != descriptor or image[arm + 6:arm + 6 + len(expected)] != expected:
                valid = False
                break
            call = facts_for(image).thumb_call_target(arm)
            if call is None:
                valid = False
                break
            branch = arm + 30
            condition = struct.unpack_from('<H', image, branch)[0] & 65280
            successors = _thumb_successors(image, branch, sense + 2)
            if condition not in (53248, 53504) or len(successors) != 2:
                valid = False
                break
            taken = next((s for s in successors if s != branch + 2), None)
            zero, nonzero = (taken, branch + 2) if condition == 53248 else (branch + 2, taken)
            def one_branch(target):
                if target in (sense, sense - 4):
                    return target
                if target is None or not site <= target <= sense - 2:
                    return None
                if struct.unpack_from('<H', image, target)[0] & 63488 != 57344:
                    return None
                edges = _thumb_successors(image, target, sense + 2)
                return edges[0] if len(edges) == 1 else None
            if one_branch(zero) != sense - 4 or one_branch(nonzero) != sense:
                valid = False
                break
            calls.append(call)
        if valid and len(set(calls)) == 1:
            lock = interrupt_helper(image, calls[0], False)
            unlock = interrupt_helper(image, facts_for(image).thumb_call_target(sense - 4), True)
            if lock is None or unlock is None:
                continue
            matches.append({'switch': hex(site), 'table': hex(table), 'arms':[hex(a) for a in arms], 'output_masks':[hex((63 ^ 1 << r) << 8) for r in range(6)],
                'shared_call': hex(calls[0]), 'interrupt_disable': lock, 'interrupt_enable': unlock, 'shadow_offset': 28, 'output_pointer_offset': 16})
    return matches[0] if len(matches) == 1 else None

def find_indirect_matrix_scanners(image: bytes):
    from . import TAIL, _thumb_reachable_preserving_register, _thumb_successors, classify_matrix_event_sink, detect_keyemu_semantics, facts_for, row_arms, struct
    found = []
    for count, match in enumerate(TAIL.finditer(image)):
        if count >= 64:
            return []
        site = match.start()
        if site % 2:
            continue
        descriptor = facts_for(image).thumb_literal_value(site, 2)
        table = facts_for(image).thumb_literal_value(site + 14, 1)
        if descriptor is None or not 16777216 <= descriptor < 33554432:
            continue
        if table is None or not 24 <= table <= len(image) - 16:
            continue
        if image[table:table + 16] != bytes([0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 0]):
            continue
        rows = row_arms(image, site, descriptor)
        if rows is None:
            continue
        presence = int(rows['switch'], 16) - 32
        if presence < 4 or image[presence - 2:presence + 10] != bytes.fromhex('506b00880007000f0f2800d1'):
            continue
        if facts_for(image).thumb_literal_value(presence - 4, 2) != descriptor:
            continue
        branch = presence + 10
        if struct.unpack_from('<H', image, branch)[0] & 63488 != 57344:
            continue
        exit_targets = _thumb_successors(image, branch, len(image))
        if len(exit_targets) != 1 or not match.end() <= exit_targets[0] < min(len(image), site + 192):
            continue
        sinks = set()
        for p in range(site + 44, min(len(image) - 4, site + 192), 2):
            target = facts_for(image).thumb_call_target(p)
            if target is not None and classify_matrix_event_sink(image, target)['family'] == 'samsung-filtered-ring32-event-queue-v1':
                sinks.add(target)
        if len(sinks) != 1:
            continue
        end = min(len(image), site + 192)
        preserved = _thumb_reachable_preserving_register(image, site + 28, end, 4)
        transfers = []
        for move in sorted(preserved):
            if image[move:move + 2] != bytes.fromhex('201c'):
                continue
            argument = _thumb_reachable_preserving_register(image, move + 2, end, 0)
            calls = [p for p in argument if facts_for(image).thumb_call_target(p) in sinks]
            if len(calls) == 1:
                transfers.append({'move': hex(move), 'call': hex(calls[0]), 'source_register': 4, 'argument_register': 0})
        if len(transfers) != 1:
            continue
        events = list(image[table - 24:table])
        semantics = detect_keyemu_semantics(image)
        cells = []
        if semantics.confidence == 'exact-native':
            for token, values in semantics.event_map:
                if len(values) == 1 and events.count(values[0]) == 1:
                    i = events.index(values[0])
                    cells.append({'token': token, 'event': values[0], 'row': i % 6, 'column': i // 6})
        found.append({'grammar': 'indirect-halfword-six-row-v1', 'presence_site': presence, 'sense_site': site + 4, 'descriptor': descriptor, 'tail': hex(site),
            'rows': 6, 'columns': 4, 'no_key': 15, 'single_key_column_sense':[14, 13, 11, 7], 'event_table': hex(table - 24), 'event_codes': events,
            'token_cells': cells, 'row_selection': rows, 'event_transfer': transfers[0], 'queue_sink': hex(next(iter(sinks))), 'runtime_admitted': False,
            'limits': 'Static candidate only; descriptor ports require live validation; runtime admission is explicit.'})
    return found

def _mapped_irq(image, entry, enable):
    """Direct Thumb-to-ARM IRQ wrapper, confined to the mapped-row grammar."""
    if entry is None or entry < 0:
        return None
    code = '7847000000000fe1c010' + ('c0' if enable else '80') + 'e301f021e1c00000e21eff2fe1'
    if image[entry:entry + 24].hex() != code:
        return None
    return {'veneer': hex(entry), 'body': hex(entry + 4), 'operation': 'clear-cpsr-I-F' if enable else 'set-cpsr-I-F', 'return': 'previous-I-F-mask'}

def _mapped_ring4(image, entry):
    from . import _mapped_irq, _thumb_reachable_preserving_register, facts_for
    if entry < 0 or entry + 0xc2 > len(image):
        return None
    for offset, code in { 0: 'b0b5071c', 0x0c: '602f00d054e0', 0x52: '687829781d308007800f884200d12ce0', 0x68:
        '6878240c2a78411c8907890f914207d040198770687801308007800f687004e0', 0x92: '002c01d1', 0x9c: 'ff2f01d0078002e0ff2101310180', 0xbc: 'b0bc08bc1847', }.items():
        if image[entry + offset:entry + offset + len(code) // 2].hex() != code:
            return None
    ring = facts_for(image).thumb_literal_value(entry + 0x42, 5)
    lock = _mapped_irq(image, facts_for(image).thumb_call_target(entry + 0x62), False)
    unlock = _mapped_irq(image, facts_for(image).thumb_call_target(entry + 0x96), True)
    if ring is None or not 0x1000000 <= ring <= 0x2000000 - 6 or not lock or not unlock:
        return None
    for start, register in ((entry + 4, 7), (entry + 0x44, 5)):
        if entry + 0x7a not in _thumb_reachable_preserving_register(image, start, entry + 0xc2, register):
            return None
    return {'family': 'filtered-byte-ring4-v1', 'entry': hex(entry), 'ring': ring, 'slots': 4, 'wrap_mask': 3, 'read_index_offset': 0, 'write_index_offset': 1,
        'event_offset': 2, 'interrupt_disable': lock, 'interrupt_enable': unlock}

def _mapped_descriptor_copy(image, descriptor):
    # Literal loads must reference the same source/destination/extent tuple.
    from . import facts_for, re, struct
    pattern = re.compile(b'.\x48\x00\x68.\x49\x09\x68\x40\x18\x06\x1c' b'.\x48\x00\x68\x05\x1c.\x48' + re.escape (bytes.fromhex('0068041cb4420dd204e0281d051c201d041cf7e7286820600120')),
        re.S)
    found = []
    for match in pattern.finditer(image):
        pc = match.start()
        if pc & 1:
            continue
        slots = [facts_for(image).thumb_literal_value(pc + off, reg) for off, reg in ((0, 0), (4, 1), (12, 0), (18, 0))]
        if any(s is None or s & 3 or not 0 <= s <= len(image) - 20 for s in slots):
            continue
        dest, size_slot, source_slot, reload = slots
        if (size_slot, source_slot, reload) != (dest + 4, dest - 4, dest):
            continue
        source, target, size, bss, bss_size = struct.unpack_from('<5I', image, source_slot)
        if (not (source | target | size) & 3 and 0 < size <= 0x800000 and source + size <= len(image) and target <= descriptor and descriptor + 0x38 <= target +
            size == bss and 0x1000000 <= target < bss < 0x2000000 and 0 < bss_size <= 0x2000000 and bss + bss_size <= 0x8000000):
            rom = source + descriptor - target
            if {off: struct.unpack_from('<I', image, rom + off)[0] for off in (0, 0x10, 0x20, 0x34)} == { 0: 0x3000720, 0x10: 0x3000724, 0x20: 0x3000728, 0x34:
                0x300072c}:
                found.append({'table': source_slot, 'copy_loop': pc, 'source': source, 'target': target, 'size': size, 'descriptor_rom': rom, 'descriptor_ram':
                    descriptor})
    return found[0] if len(found) == 1 else None

def _mapped_scan_gates(image: bytes, matrix: dict, contact: int, helper: int):
    """Optional exact linked contact/status class; physical defaults unassigned."""
    from . import _normalized_thumb_sha256, _thumb_reachable_preserving_register, facts_for, struct
    descriptor = matrix['descriptor']
    sense = matrix['sense_site']
    move = int(matrix['event_transfer']['move'], 16)
    sink = int(matrix['queue_sink'], 16)
    if matrix['presence_site'] != contact+0x92:
        return None,['scan-gate-contact-presence-relation']
    status = facts_for(image).thumb_call_target(contact - 0x14)
    if status is None or status & 1:
        return None,['scan-gate-status-call']
    shapes = (('contact', contact, 0x8c, '8d6f2c25f40ba03b65fc0099577e4d9e698ad6860966462f80f772d50d5e099a', ()), ('status', status, 0xc4,
        'e972690b625ef4c151dd2eca084c888af1f5a7ec4a1c9ace61476d92fad75c6a', (0x2c, 0x36,0x82,0x88)), ('caller', contact-0x2a, 0x2a,
        '81cfb056ebc2d1db291fcffde72d469df061053e7fba8d3afc34d464a338665d', (0xa,0x12,0x16,0x20)), ('state-load', sense+0x2c, 0x2c,
        'b51bbe8d86e83caa0890faee3d3fdb83ffc92da346d483c355d24baa8ee0d1d2', ()), ('filter', move-0x3e, 0x46,
        '963169fe4bdb799d1db798c407ea1c0f2467eeaaa349552015a6d3eedfc95eb7', (0x34,0x40)),)
    for name, entry, size, digest, calls in shapes:
        if entry & 1 or _normalized_thumb_sha256(image, entry, size) != (digest, calls):
            return None,['scan-gate-' + name + '-shape']
        for offset in calls:
            target = facts_for(image).thumb_call_target(entry+offset)
            if target is None or target & 1 or not 0 <= target <= len(image)-2:
                return None,['scan-gate-' + name + '-call-bounds']
    if (facts_for(image).thumb_call_target(contact+0x8c) != helper or facts_for(image).thumb_call_target(status+ 0x88) != sink or facts_for(image).thumb_call_target(move+2)
        != sink or facts_for(image).thumb_call_target(sense+0x66) != sink):
        return None,['scan-gate-linked-sink-or-helper']
    copy = matrix['descriptor_copy']
    rom = copy['descriptor_rom']
    if (not 0 <= rom <= len(image)-0x38 or {off: struct.unpack_from('<I', image, rom+off)[0] for off in (8,0x24, 0x34)} != { 8:0x300072c, 0x24:0x3000728, 0x34:0x300072c}
        or facts_for(image).thumb_literal_value(status, 0) != descriptor):
        return None,['scan-gate-descriptor-ports']
    state = facts_for(image).thumb_literal_value(status+0x12, 5)
    loads = ((contact+0xe,1),(contact+0x30,1),(contact+0x4a,0), (contact+0x5e,1),(sense+0x30,0),(sense+0x44,6))
    if (type(state) is not int or state & 3 or any(facts_for(image).thumb_literal_value(pc, reg) != state for pc,reg in loads)):
        return None,['scan-gate-shared-state']
    flag = facts_for(image).thumb_literal_value(contact+0xa, 4)
    # Only local accessed extents are proved; service callees remain bounds-only.
    controls = [(facts_for(image).thumb_literal_value(status+off, reg), 1) for off,reg in ((0x10,7),(0x28,0),(0x40,0),(0x48,0), (0x4a,1),(0x4c,2),(0x78,1),(0x7e,0))]
    clear_flag = facts_for(image).thumb_literal_value(sense+0x2c, 0)
    spans = [(descriptor,0x38),(state,0x20),(matrix['producer']['ring'],6), (flag,9),(clear_flag,1),*controls]
    if any(type(p) is not int or not 0x1000000 <= p <= 0x2000000-n for p,n in spans):
        return None,['scan-gate-ram-bounds']
    if (descriptor & 3 or flag & 3 or any(a < b+m and b < a+n for i,(a,n) in enumerate(spans) for b,m in spans[i +1:])):
        return None,['scan-gate-ram-alias-or-alignment']
    if (move-0x3e not in _thumb_reachable_preserving_register(image, sense+0x46, move+8, 6) or move not in _thumb_reachable_preserving_register(image, contact+0x72,
        min(len(image),sense+0x240), 7)):
        return None,['scan-gate-register-flow']
    return {'grammar':'mapped-halfword-contact-status-gates-v1', 'descriptor':descriptor, 'scanner_state':state, 'queue_sink':sink, 'contact_site':contact+4,
        'status_site':status+6, 'contact_mask':16, 'status_mask':2, 'contact_pointer_offset':52, 'configuration_pointer_offset':8, 'status_pointer_offset':36,
        'contact_width':2, 'status_width':2, 'promotion':'temporary-evidence-gated', 'runtime_admitted':False, 'physical_role':None, 'default_level':None,
        'status_state_offset':8, 'status_set_bit_state':0, 'status_clear_bit_state':1, 'status_entry':status, 'filter_site':move-0x34, 'ram_spans':[[p,n] for p,n
        in spans], 'limits': 'Exact local inverse-state/input-filter class; physical role/default and transitive service effects unproved.' },[]

def find_mapped_row_scanners(image: bytes):
    """Seven distinct active-low output bits, linked low4 scanner and ring4."""
    from . import _mapped_descriptor_copy, _mapped_irq, _mapped_ring4, _mapped_scan_gates, _thumb_reachable_preserving_register, _thumb_successors, facts_for, find_all, struct
    found = []
    for count, switch in enumerate(find_all(image, bytes.fromhex('072d00d3'))):
        if count >= 64:
            return []
        if switch & 1 or switch < 34 or switch + 16 > len(image):
            continue
        adr = struct.unpack_from('<H', image, switch + 6)[0]
        if adr & 0xff00 != 0xa300 or image[switch + 8:switch + 14].hex() != '5b5d5b009f44':
            continue
        table = ((switch + 10) & ~3) + 4 * (adr & 255)
        arms = [switch + 16 + 2 * v for v in image[table:table + 7]]
        if len(arms) != 7 or len(set(arms)) != 7:
            continue
        presence = switch - 28
        if image[presence - 2:presence + 10].hex() != '706b00880007000f0f2800d1':
            continue
        helper = facts_for(image).thumb_call_target(presence - 6)
        if helper is None or image[helper:helper + 2].hex() != '00b5':
            continue
        descriptor = facts_for(image).thumb_literal_value(helper + 6, 1)
        preserve = facts_for(image).thumb_literal_value(helper + 8, 3)
        if descriptor is None or descriptor & 3 or preserve is None or preserve >> 16 != 0xffff:
            continue
        mask = preserve ^ 0xffffffff
        if mask.bit_count() != 7 or image[helper + 10:helper + 26].hex() != '8a8b1a408a838a8b09690a80002801d1':
            continue
        lock = _mapped_irq(image, facts_for(image).thumb_call_target(helper + 2), False)
        unlock = _mapped_irq(image, facts_for(image).thumb_call_target(helper + 26), True)
        if not lock or not unlock or image[helper + 30:helper + 34].hex() != '08bc1847':
            continue
        copy = _mapped_descriptor_copy(image, descriptor)
        if copy is None:
            continue
        bits, senses = [], set()
        for arm in arms:
            if not switch + 16 <= arm < min(len(image) - 32, switch + 0x200):
                break
            if facts_for(image).thumb_call_target(arm) != int(lock['veneer'], 16) or image[arm + 4:arm + 6].hex() != 'b18b':
                break
            if facts_for(image).thumb_literal_value(arm + 6, 3) != preserve:
                break
            value = facts_for(image).thumb_literal_value(arm + 8, 2)
            if value is None or image[arm + 10:arm + 12].hex() != '1940':
                break
            pos = arm + 12
            word = struct.unpack_from('<H', image, pos)[0]
            if word & 0xff00 == 0x3a00:
                value -= word & 255
                pos += 2
            selected = mask ^ value
            if value & ~mask or selected <= 0 or selected & (selected - 1):
                break
            if image[pos:pos + 12].hex() != '1143b183b18b326911800028':
                break
            branch = pos + 12
            condition = struct.unpack_from('<H', image, branch)[0] & 0xff00
            if condition not in (0xd000, 0xd100):
                break
            edges = _thumb_successors(image, branch, min(len(image), switch + 0x300))
            destinations = []
            for edge in edges:
                if not switch <= edge <= min(len(image) - 2, switch + 0x300):
                    break
                if struct.unpack_from('<H', image, edge)[0] & 0xf800 == 0xe000:
                    targets = _thumb_successors(image, edge, len(image))
                    if len(targets) != 1:
                        break
                    edge = targets[0]
                if not switch <= edge <= min(len(image) - 4, switch + 0x300):
                    break
                if image[edge:edge + 2].hex() == '706b':
                    destinations.append((edge, False))
                elif facts_for(image).thumb_call_target(edge) == int(unlock['veneer'], 16):
                    destinations.append((edge + 4, True))
            if (len(destinations) != 2 or destinations[0][0] != destinations[1][0] or[unlocks for _, unlocks in destinations] != ([False, True] if condition ==
                0xd000 else[True, False])):
                break
            senses.add(destinations[0][0])
            bits.append(selected.bit_length() - 1)
        if len(bits) != 7 or bits != sorted(set(bits)) or len(senses) != 1:
            continue
        sense = senses.pop()
        if not 0 <= sense <= len(image) - 42:
            continue
        if image[sense:sense + 12].hex() != '706b00880007000f0f2808d0':
            continue
        if image[sense + 16:sense + 36].hex() != '085cc300181a1c394018475d05e001352d062d0e':
            continue
        if image[sense + 36:sense + 42].hex() != '072d00da76e7':
            continue
        if (image[sense + 14:sense + 16].hex() != '1039' or _thumb_successors(image, sense + 40, len(image)) != (switch,)):
            continue
        columns = facts_for(image).thumb_literal_value(sense + 12, 1)
        if columns is None or not 28 <= columns - 16 <= len(image) - 16:
            continue
        if image[columns - 16:columns] != bytes([0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,0]):
            continue
        events = list(image[columns - 44:columns - 16])
        if len(events) != 28 or not all(events.count(v) == 1 for v in b'123456789*0#'):
            continue
        descriptor_loads = [pc for pc in range(max(0, presence - 0x200), presence, 2) if facts_for(image).thumb_literal_value(pc, 6) == descriptor and image[pc
            + 2:pc + 10].hex() == '706b008810231840']
        if len(descriptor_loads) != 1:
            continue
        reachable = _thumb_reachable_preserving_register(image, descriptor_loads[0] + 2, sense + 2, 6)
        if presence not in reachable or sense not in reachable:
            continue
        transfers = []
        for pc in _thumb_reachable_preserving_register(image, sense + 28, min(len(image), sense + 0x240), 7):
            if image[pc:pc + 2].hex() == '381c':
                sink = facts_for(image).thumb_call_target(pc + 2)
                producer = _mapped_ring4(image, sink) if sink is not None else None
                if producer:
                    transfers.append((pc, sink, producer))
        if len(transfers) != 1:
            continue
        move, sink, producer = transfers[0]
        matrix = {'grammar': 'indirect-halfword-mapped-row-v1', 'rows': 7, 'columns': 4, 'no_key': 15, 'sense_values':[14,13,11,7], 'single_key_column_sense':[14,13,11,7],
            'descriptor': descriptor, 'descriptor_copy': copy, 'presence_site': presence, 'sense_site': sense + 2, 'row_select_mask': mask, 'row_select_bits':
            bits, 'row_selection': {'switch': switch, 'arms': arms, 'table': table}, 'event_table': columns - 44, 'event_codes': events, 'token_cells':[{'token':
            chr(v), 'event': v, 'row': events.index(v) % 7, 'column': events.index(v) // 7} for v in b'123456789*0#'], 'queue_sink': hex(sink), 'producer':
            producer, 'event_transfer': {'move': hex(move), 'call': hex(move + 2), 'source_register': 7, 'argument_register': 0}, 'runtime_admitted': False,
            'limits': 'Temporary static candidate; live descriptor/selector/readback and input consumption require opt-in validation.' }
        gates, reasons = _mapped_scan_gates(image, matrix, descriptor_loads[0], helper)
        matrix['scan_gate_status'] = 'accepted-provisional' if gates else 'rejected'
        matrix['scan_gate_reject_reasons'] = reasons
        if gates:
            matrix['scan_gates'] = gates
        found.append(matrix)
    return found

def _loop_descriptor_copy(image, descriptor):
    from . import facts_for, re, struct
    pattern = re.compile(b'.\x48\x00\x68.\x49\x09\x68\x40\x18\x06\x1c' b'.\x48\x00\x68\x05\x1c.\x48' + re.escape (bytes.fromhex('0068041cb44208d204e0281d051c201d041cf7e728682060f7e7')),
        re.S)
    copies = []
    for match in pattern.finditer(image[:0x20000]):
        pc = match.start()
        slots = [facts_for(image).thumb_literal_value(pc + off, reg) for off, reg in ((0,0),(4,1),(12,0),(18,0))]
        if pc & 1 or any(s is None or s & 3 or not 0 <= s <= len(image)-4 for s in slots):
            continue
        dest, size, source, reload = [struct.unpack_from('<I', image, s)[0] for s in slots]
        if (slots[1], slots[2], slots[3]) != (slots[0]+4, slots[0]-4, slots[0]):
            continue
        if (reload != dest or dest != descriptor or (source | dest | size) & 3 or not 0x38 <= size <= 0x100 or source + size > len(image) or not 0x1000000 <=
            dest <= 0x2000000-size):
            continue
        ports = [struct.unpack_from('<I', image, source + off)[0] for off in (0,8,0x20,0x34)]
        if ports ==[0x3000720,0x300072c,0x3000728,0x300072c]:
            copies.append({'copy_loop': pc, 'source': source, 'target': dest, 'size': size})
    return copies[0] if len(copies) == 1 else None
