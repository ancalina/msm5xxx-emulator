"""Exact indirect halfword matrix candidates; runtime admission is separate."""
from __future__ import annotations
import re
import struct
from .arm import thumb_literal_value, thumb_bl_target, _thumb_successors, _thumb_reachable_preserving_register
from .signatures import find_all
from .input_matrix import classify_matrix_event_sink
from .rex import _normalized_thumb_sha256
from .input_semantics import detect_keyemu_semantics
TAIL = re.compile(b'.J' + re.escape(bytes.fromhex('506b00880007000f0f28')) + b'.\xd0.I' + re.escape(bytes.fromhex('0623085c183958434018445d')) + b'.\xe0' + re.escape(bytes.fromhex('01352d062d0e062d')) + b'.\xda.\xe7', re.S)

def interrupt_helper(image, veneer, enable):
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
    return {'veneer': hex(veneer), 'body': hex(body), 'operation': 'clear-cpsr-I-F' if enable else 'set-cpsr-I-F', 'return': 'previous-I-F-mask', 'registers_written': ['r0', 'r1', 'CPSR']}

def row_arms(image, sense, descriptor):
    """Close bounded six-row byte-switch and halfword output shape."""
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
            if thumb_literal_value(image, arm + 4, 2) != descriptor or image[arm + 6:arm + 6 + len(expected)] != expected:
                valid = False
                break
            call = thumb_bl_target(image, arm)
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
            unlock = interrupt_helper(image, thumb_bl_target(image, sense - 4), True)
            if lock is None or unlock is None:
                continue
            matches.append({'switch': hex(site), 'table': hex(table), 'arms': [hex(a) for a in arms], 'output_masks': [hex((63 ^ 1 << r) << 8) for r in range(6)], 'shared_call': hex(calls[0]), 'interrupt_disable': lock, 'interrupt_enable': unlock, 'shadow_offset': 28, 'output_pointer_offset': 16})
    return matches[0] if len(matches) == 1 else None

def find_indirect_matrix_scanners(image: bytes):
    found = []
    for count, match in enumerate(TAIL.finditer(image)):
        if count >= 64:
            return []
        site = match.start()
        if site % 2:
            continue
        descriptor = thumb_literal_value(image, site, 2)
        table = thumb_literal_value(image, site + 14, 1)
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
        if thumb_literal_value(image, presence - 4, 2) != descriptor:
            continue
        branch = presence + 10
        if struct.unpack_from('<H', image, branch)[0] & 63488 != 57344:
            continue
        exit_targets = _thumb_successors(image, branch, len(image))
        if len(exit_targets) != 1 or not match.end() <= exit_targets[0] < min(len(image), site + 192):
            continue
        sinks = set()
        for p in range(site + 44, min(len(image) - 4, site + 192), 2):
            target = thumb_bl_target(image, p)
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
            calls = [p for p in argument if thumb_bl_target(image, p) in sinks]
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
        found.append({'grammar': 'indirect-halfword-six-row-v1', 'presence_site': presence, 'sense_site': site + 4, 'descriptor': descriptor, 'tail': hex(site), 'rows': 6, 'columns': 4, 'no_key': 15, 'single_key_column_sense': [14, 13, 11, 7], 'event_table': hex(table - 24), 'event_codes': events, 'token_cells': cells, 'row_selection': rows, 'event_transfer': transfers[0], 'queue_sink': hex(next(iter(sinks))), 'runtime_admitted': False, 'limits': 'Static candidate only; descriptor ports require live validation; runtime admission is explicit.'})
    return found

def _mapped_irq(image, entry, enable):
    """Direct Thumb-to-ARM IRQ wrapper, confined to the mapped-row grammar."""
    if entry is None or entry < 0:
        return None
    code = '7847000000000fe1c010' + ('c0' if enable else '80') + 'e301f021e1c00000e21eff2fe1'
    if image[entry:entry + 24].hex() != code:
        return None
    return {'veneer': hex(entry), 'body': hex(entry + 4),
            'operation': 'clear-cpsr-I-F' if enable else 'set-cpsr-I-F',
            'return': 'previous-I-F-mask'}


def _mapped_ring4(image, entry):
    if entry < 0 or entry + 0xc2 > len(image):
        return None
    for offset, code in {
        0: 'b0b5071c', 0x0c: '602f00d054e0',
        0x52: '687829781d308007800f884200d12ce0',
        0x68: '6878240c2a78411c8907890f914207d040198770687801308007800f687004e0',
        0x92: '002c01d1', 0x9c: 'ff2f01d0078002e0ff2101310180',
        0xbc: 'b0bc08bc1847',
    }.items():
        if image[entry + offset:entry + offset + len(code) // 2].hex() != code:
            return None
    ring = thumb_literal_value(image, entry + 0x42, 5)
    lock = _mapped_irq(image, thumb_bl_target(image, entry + 0x62), False)
    unlock = _mapped_irq(image, thumb_bl_target(image, entry + 0x96), True)
    if ring is None or not 0x1000000 <= ring <= 0x2000000 - 6 or not lock or not unlock:
        return None
    for start, register in ((entry + 4, 7), (entry + 0x44, 5)):
        if entry + 0x7a not in _thumb_reachable_preserving_register(
                image, start, entry + 0xc2, register):
            return None
    return {'family': 'filtered-byte-ring4-v1', 'entry': hex(entry),
            'ring': ring, 'slots': 4, 'wrap_mask': 3, 'read_index_offset': 0,
            'write_index_offset': 1, 'event_offset': 2,
            'interrupt_disable': lock, 'interrupt_enable': unlock}


def _mapped_descriptor_copy(image, descriptor):
    # Literal loads must reference the same source/destination/extent tuple.
    pattern = re.compile(b'.\x48\x00\x68.\x49\x09\x68\x40\x18\x06\x1c'
                         b'.\x48\x00\x68\x05\x1c.\x48' + re.escape(bytes.fromhex(
                         '0068041cb4420dd204e0281d051c201d041cf7e7286820600120')), re.S)
    found = []
    for match in pattern.finditer(image):
        pc = match.start()
        if pc & 1:
            continue
        slots = [thumb_literal_value(image, pc + off, reg)
                 for off, reg in ((0, 0), (4, 1), (12, 0), (18, 0))]
        if any(s is None or s & 3 or not 0 <= s <= len(image) - 20 for s in slots):
            continue
        dest, size_slot, source_slot, reload = slots
        if (size_slot, source_slot, reload) != (dest + 4, dest - 4, dest):
            continue
        source, target, size, bss, bss_size = struct.unpack_from('<5I', image, source_slot)
        if (not (source | target | size) & 3 and 0 < size <= 0x800000
                and source + size <= len(image) and target <= descriptor
                and descriptor + 0x38 <= target + size == bss
                and 0x1000000 <= target < bss < 0x2000000
                and 0 < bss_size <= 0x2000000 and bss + bss_size <= 0x8000000):
            rom = source + descriptor - target
            if {off: struct.unpack_from('<I', image, rom + off)[0]
                    for off in (0, 0x10, 0x20, 0x34)} == {
                        0: 0x3000720, 0x10: 0x3000724,
                        0x20: 0x3000728, 0x34: 0x300072c}:
                found.append({'table': source_slot, 'copy_loop': pc,
                              'source': source, 'target': target, 'size': size,
                              'descriptor_rom': rom, 'descriptor_ram': descriptor})
    return found[0] if len(found) == 1 else None


def _mapped_scan_gates(image: bytes, matrix: dict, contact: int, helper: int):
    """Optional exact linked contact/status class; physical defaults unassigned."""
    descriptor = matrix['descriptor']
    sense = matrix['sense_site']
    move = int(matrix['event_transfer']['move'], 16)
    sink = int(matrix['queue_sink'], 16)
    if matrix['presence_site'] != contact+0x92:
        return None, ['scan-gate-contact-presence-relation']
    status = thumb_bl_target(image, contact - 0x14)
    if status is None or status & 1:
        return None, ['scan-gate-status-call']
    shapes = (
        ('contact', contact, 0x8c,
         '8d6f2c25f40ba03b65fc0099577e4d9e698ad6860966462f80f772d50d5e099a', ()),
        ('status', status, 0xc4,
         'e972690b625ef4c151dd2eca084c888af1f5a7ec4a1c9ace61476d92fad75c6a', (0x2c,0x36,0x82,0x88)),
        ('caller', contact-0x2a, 0x2a,
         '81cfb056ebc2d1db291fcffde72d469df061053e7fba8d3afc34d464a338665d', (0xa,0x12,0x16,0x20)),
        ('state-load', sense+0x2c, 0x2c,
         'b51bbe8d86e83caa0890faee3d3fdb83ffc92da346d483c355d24baa8ee0d1d2', ()),
        ('filter', move-0x3e, 0x46,
         '963169fe4bdb799d1db798c407ea1c0f2467eeaaa349552015a6d3eedfc95eb7', (0x34,0x40)),
    )
    for name, entry, size, digest, calls in shapes:
        if entry & 1 or _normalized_thumb_sha256(image, entry, size) != (digest, calls):
            return None, ['scan-gate-' + name + '-shape']
        for offset in calls:
            target = thumb_bl_target(image, entry+offset)
            if target is None or target & 1 or not 0 <= target <= len(image)-2:
                return None, ['scan-gate-' + name + '-call-bounds']
    if (thumb_bl_target(image, contact+0x8c) != helper
            or thumb_bl_target(image, status+0x88) != sink
            or thumb_bl_target(image, move+2) != sink
            or thumb_bl_target(image, sense+0x66) != sink):
        return None, ['scan-gate-linked-sink-or-helper']
    copy = matrix['descriptor_copy']
    rom = copy['descriptor_rom']
    if (not 0 <= rom <= len(image)-0x38
            or {off: struct.unpack_from('<I', image, rom+off)[0]
                for off in (8,0x24,0x34)} != {
                    8:0x300072c, 0x24:0x3000728, 0x34:0x300072c}
            or thumb_literal_value(image, status, 0) != descriptor):
        return None, ['scan-gate-descriptor-ports']
    state = thumb_literal_value(image, status+0x12, 5)
    loads = ((contact+0xe,1),(contact+0x30,1),(contact+0x4a,0),
             (contact+0x5e,1),(sense+0x30,0),(sense+0x44,6))
    if (type(state) is not int or state & 3
            or any(thumb_literal_value(image, pc, reg) != state for pc,reg in loads)):
        return None, ['scan-gate-shared-state']
    flag = thumb_literal_value(image, contact+0xa, 4)
    # Only local accessed extents are proved; service callees remain bounds-only.
    controls = [(thumb_literal_value(image, status+off, reg), 1)
                for off,reg in ((0x10,7),(0x28,0),(0x40,0),(0x48,0),
                                (0x4a,1),(0x4c,2),(0x78,1),(0x7e,0))]
    clear_flag = thumb_literal_value(image, sense+0x2c, 0)
    spans = [(descriptor,0x38),(state,0x20),(matrix['producer']['ring'],6),
             (flag,9),(clear_flag,1),*controls]
    if any(type(p) is not int or not 0x1000000 <= p <= 0x2000000-n
           for p,n in spans):
        return None, ['scan-gate-ram-bounds']
    if (descriptor & 3 or flag & 3
            or any(a < b+m and b < a+n for i,(a,n) in enumerate(spans)
                   for b,m in spans[i+1:])):
        return None, ['scan-gate-ram-alias-or-alignment']
    if (move-0x3e not in _thumb_reachable_preserving_register(
            image, sense+0x46, move+8, 6)
            or move not in _thumb_reachable_preserving_register(
                image, contact+0x72, min(len(image),sense+0x240), 7)):
        return None, ['scan-gate-register-flow']
    return {'grammar':'mapped-halfword-contact-status-gates-v1',
            'descriptor':descriptor, 'scanner_state':state, 'queue_sink':sink,
            'contact_site':contact+4, 'status_site':status+6,
            'contact_mask':16, 'status_mask':2,
            'contact_pointer_offset':52, 'configuration_pointer_offset':8,
            'status_pointer_offset':36, 'contact_width':2, 'status_width':2,
            'promotion':'temporary-evidence-gated', 'runtime_admitted':False,
            'physical_role':None, 'default_level':None,
            'status_state_offset':8, 'status_set_bit_state':0,
            'status_clear_bit_state':1, 'status_entry':status,
            'filter_site':move-0x34,
            'ram_spans':[[p,n] for p,n in spans],
            'limits':'Exact local inverse-state/input-filter class; physical role/default and transitive service effects unproved.'}, []


def find_mapped_row_scanners(image: bytes):
    """Seven distinct active-low output bits, linked low4 scanner and ring4."""
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
        helper = thumb_bl_target(image, presence - 6)
        if helper is None or image[helper:helper + 2].hex() != '00b5':
            continue
        descriptor = thumb_literal_value(image, helper + 6, 1)
        preserve = thumb_literal_value(image, helper + 8, 3)
        if descriptor is None or descriptor & 3 or preserve is None or preserve >> 16 != 0xffff:
            continue
        mask = preserve ^ 0xffffffff
        if mask.bit_count() != 7 or image[helper + 10:helper + 26].hex() != '8a8b1a408a838a8b09690a80002801d1':
            continue
        lock = _mapped_irq(image, thumb_bl_target(image, helper + 2), False)
        unlock = _mapped_irq(image, thumb_bl_target(image, helper + 26), True)
        if not lock or not unlock or image[helper + 30:helper + 34].hex() != '08bc1847':
            continue
        copy = _mapped_descriptor_copy(image, descriptor)
        if copy is None:
            continue
        bits, senses = [], set()
        for arm in arms:
            if not switch + 16 <= arm < min(len(image) - 32, switch + 0x200):
                break
            if thumb_bl_target(image, arm) != int(lock['veneer'], 16) or image[arm + 4:arm + 6].hex() != 'b18b':
                break
            if thumb_literal_value(image, arm + 6, 3) != preserve:
                break
            value = thumb_literal_value(image, arm + 8, 2)
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
                elif thumb_bl_target(image, edge) == int(unlock['veneer'], 16):
                    destinations.append((edge + 4, True))
            if (len(destinations) != 2 or destinations[0][0] != destinations[1][0]
                    or [unlocks for _, unlocks in destinations]
                    != ([False, True] if condition == 0xd000 else [True, False])):
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
        if (image[sense + 14:sense + 16].hex() != '1039'
                or _thumb_successors(image, sense + 40, len(image)) != (switch,)):
            continue
        columns = thumb_literal_value(image, sense + 12, 1)
        if columns is None or not 28 <= columns - 16 <= len(image) - 16:
            continue
        if image[columns - 16:columns] != bytes([0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,0]):
            continue
        events = list(image[columns - 44:columns - 16])
        if len(events) != 28 or not all(events.count(v) == 1 for v in b'123456789*0#'):
            continue
        descriptor_loads = [pc for pc in range(max(0, presence - 0x200), presence, 2)
                            if thumb_literal_value(image, pc, 6) == descriptor
                            and image[pc + 2:pc + 10].hex() == '706b008810231840']
        if len(descriptor_loads) != 1:
            continue
        reachable = _thumb_reachable_preserving_register(image, descriptor_loads[0] + 2, sense + 2, 6)
        if presence not in reachable or sense not in reachable:
            continue
        transfers = []
        for pc in _thumb_reachable_preserving_register(image, sense + 28, min(len(image), sense + 0x240), 7):
            if image[pc:pc + 2].hex() == '381c':
                sink = thumb_bl_target(image, pc + 2)
                producer = _mapped_ring4(image, sink) if sink is not None else None
                if producer:
                    transfers.append((pc, sink, producer))
        if len(transfers) != 1:
            continue
        move, sink, producer = transfers[0]
        matrix = {'grammar': 'indirect-halfword-mapped-row-v1',
            'rows': 7, 'columns': 4, 'no_key': 15,
            'sense_values': [14,13,11,7], 'single_key_column_sense': [14,13,11,7],
            'descriptor': descriptor, 'descriptor_copy': copy,
            'presence_site': presence, 'sense_site': sense + 2,
            'row_select_mask': mask, 'row_select_bits': bits,
            'row_selection': {'switch': switch, 'arms': arms, 'table': table},
            'event_table': columns - 44, 'event_codes': events,
            'token_cells': [{'token': chr(v), 'event': v, 'row': events.index(v) % 7,
                             'column': events.index(v) // 7} for v in b'123456789*0#'],
            'queue_sink': hex(sink), 'producer': producer,
            'event_transfer': {'move': hex(move), 'call': hex(move + 2),
                               'source_register': 7, 'argument_register': 0},
            'runtime_admitted': False,
            'limits': 'Temporary static candidate; live descriptor/selector/readback and input consumption require opt-in validation.'}
        gates, reasons = _mapped_scan_gates(image, matrix, descriptor_loads[0], helper)
        matrix['scan_gate_status'] = 'accepted-provisional' if gates else 'rejected'
        matrix['scan_gate_reject_reasons'] = reasons
        if gates:
            matrix['scan_gates'] = gates
        found.append(matrix)
    return found


def _loop_descriptor_copy(image, descriptor):
    pattern = re.compile(b'.\x48\x00\x68.\x49\x09\x68\x40\x18\x06\x1c'
                         b'.\x48\x00\x68\x05\x1c.\x48' + re.escape(bytes.fromhex(
                         '0068041cb44208d204e0281d051c201d041cf7e728682060f7e7')), re.S)
    copies = []
    for match in pattern.finditer(image[:0x20000]):
        pc = match.start()
        slots = [thumb_literal_value(image, pc + off, reg)
                 for off, reg in ((0,0),(4,1),(12,0),(18,0))]
        if pc & 1 or any(s is None or s & 3 or not 0 <= s <= len(image)-4 for s in slots):
            continue
        dest, size, source, reload = [struct.unpack_from('<I', image, s)[0] for s in slots]
        if (slots[1], slots[2], slots[3]) != (slots[0]+4, slots[0]-4, slots[0]):
            continue
        if (reload != dest or dest != descriptor or (source | dest | size) & 3
                or not 0x38 <= size <= 0x100 or source + size > len(image)
                or not 0x1000000 <= dest <= 0x2000000-size):
            continue
        ports = [struct.unpack_from('<I', image, source + off)[0] for off in (0,8,0x20,0x34)]
        if ports == [0x3000720,0x300072c,0x3000728,0x300072c]:
            copies.append({'copy_loop': pc, 'source': source, 'target': dest, 'size': size})
    return copies[0] if len(copies) == 1 else None


def find_loop_row_scanners(image: bytes):
    """Exact loop/dual-selector class; released bit4 is opt-in approximation."""
    found = []
    for entry in find_all(image, bytes.fromhex('f8b5')):
        # A full signature, not a filename or fixed entry, identifies the class.
        if entry & 1 or entry + 0x170 > len(image):
            continue
        if image[entry+0x18:entry+0x24].hex() != '686b0088400901d251276ce0':
            continue
        if _normalized_thumb_sha256(image, entry, 0x170) != (
                '6512e3835bad7cd92142bd67556fbd43a87f9c841a570ef44769a4523cb18e40',
                (0x10,0x24,0x4e,0x76,0x7a,0x94,0xac,0xb0,0xc8,0xe8,0xfa,0x11e,0x140,0x156,0x15c,0x16c)):
            continue
        def call(pc):
            target = thumb_bl_target(image, pc)
            return target if target is not None and 0 <= target <= len(image)-2 else None
        calls = {off: call(entry+off) for off in
                 (0x10,0x24,0x4e,0x76,0x7a,0x94,0xac,0xb0,0xc8,0xe8,0xfa,0x11e,0x140,0x156,0x15c,0x16c)}
        if any(p is None for p in calls.values()) or calls[0x24] != calls[0xfa] or calls[0x11e] != calls[0x140]:
            continue
        task_calls = [calls[d] for d in (0x10,0x156)]
        if any(p & 3 or image[p:p+8] != bytes.fromhex('7847c04604f01fe5')
               or p+12 > len(image) or not 0x3000000 <= struct.unpack_from('<I',image,p+8)[0] < 0x4000000
               or struct.unpack_from('<I',image,p+8)[0] & 3 for p in task_calls):
            continue
        helper, producer = calls[0x24], calls[0x140]
        if (_normalized_thumb_sha256(image, helper, 0x8a) != (
                '4a7cd5a973272db39301a387f52fbb437e0004e3b7e77851062a5c7e41f738f7',
                (2,0xe,0x2a,0x2e,0x4a,0x62,0x66,0x80))
                or _normalized_thumb_sha256(image, producer, 0x54) != (
                'f8a4491f57840e16430d52d7bac84ac1a0f58959dce3b06a3448b508d8c6c4d1',
                (0x1a,0x24,0x4e))):
            continue
        lock, unlock, mode = calls[0x4e], calls[0x76], calls[0xe8]
        edges = [call(helper+d) for d in (2,0xe,0x2a,0x2e,0x4a,0x62,0x66,0x80)]
        if (edges != [mode,lock,unlock,lock,lock,unlock,lock,unlock]
                or any(calls[d] != lock for d in (0x7a,0x94,0xb0))
                or any(calls[d] != unlock for d in (0xac,0xc8))
                or call(producer+0x24) != lock or call(producer+0x4e) != unlock
                or not _mapped_irq(image, lock, False) or not _mapped_irq(image, unlock, True)
                or (lock | unlock) & 3):
            continue
        callback = call(producer+0x1a)
        if callback is None or image[callback:callback+2] != bytes.fromhex('0847'):
            continue
        if image[mode:mode+6] != bytes.fromhex('014800787047'):
            continue
        mode_byte = thumb_literal_value(image, mode, 0)
        live = thumb_literal_value(image, entry+0x14, 5)
        copied = thumb_literal_value(image, entry+0x46, 6)
        state = thumb_literal_value(image, entry+2, 4)
        state_loads = [thumb_literal_value(image, entry+d, 4) for d in (0x36,0xfe)]
        helper_desc = [thumb_literal_value(image, helper+d, r) for d,r in ((6,4),(8,7))]
        enabled = thumb_literal_value(image, producer+4, 0)
        producer_state = thumb_literal_value(image, producer+0xc, 0)
        ring = thumb_literal_value(image, producer+0x28, 3)
        task = thumb_literal_value(image, entry+0xe, 0)
        ram = ((live,0x38),(copied,0x38),(state,5),(mode_byte,1),
               (enabled,1),(producer_state,0x2c),(ring,34),(task,0x10))
        if (any(type(p) is not int or not 0x1000000 <= p <= 0x2000000-n for p,n in ram)
                or live & 3 or copied & 3 or state & 1 or task & 3 or abs(live-copied) < 0x38
                or state_loads != [state,state] or helper_desc != [copied,live]
                or producer_state != state or enabled != state+0x21
                or thumb_literal_value(image, entry+0x154, 0) != task):
            continue
        extents = [(live,0x38),(copied,0x38),(state,0x2c),(mode_byte,1),(ring,34),(task,0x10)]
        if any(a < b+m and b < a+n for i,(a,n) in enumerate(extents) for b,m in extents[i+1:]):
            continue
        copy = _loop_descriptor_copy(image, copied)
        columns = thumb_literal_value(image, entry+0xd8, 1)
        if (copy is None or columns is None or not 24 <= columns <= len(image)-16
                or image[columns:columns+16] != bytes([0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4])):
            continue
        events = list(image[columns-24:columns])
        if any(events.count(v) != 1 for v in b'123456789*0#'):
            continue
        found.append({'grammar':'indirect-halfword-loop-six-row-v1',
            'descriptor':live,'copied_descriptor':copied,'descriptor_copy':copy,
            'contact_site':entry+0x1a,'presence_site':entry+0x2a,'sense_site':entry+0xce,
            'rows':6,'columns':4,'no_key':31,
            'single_key_column_sense':[30,29,27,23],
            'event_table':columns-24,'event_codes':events,
            'token_cells':[{'token':chr(v),'event':v,'row':events.index(v)%6,
                            'column':events.index(v)//6} for v in b'123456789*0#'],
            'row_selection':{'ports':[0x3000728,0x3000720], 'masks':[31,32],
                             'row_values':[(31^(1<<r),32) for r in range(5)]+[(31,0)],
                             'presence_values':[(30,32),(0,0)],'mode_byte':mode_byte},
            'scanner_state':state,'task_record':task,'producer_enabled':enabled,'queue_sink':hex(producer),
            'producer':{'family':'optional-callback-byte-ring32-v1','ring':ring,'slots':32,
                        'write_index_offset':1,'event_offset':2,'callback_offset':0x28},
            'event_transfer':{'move':hex(entry+0x13e),'call':hex(entry+0x140),
                              'release_call':hex(entry+0x11e),'release_event':255},
            'runtime_admitted':False,'promotion':'temporary-evidence-gated',
            'limits':'Opt-in released bit4 approximation; physical role/key51/OK/Menu unknown. Live descriptor/shadow and natural input consumption require validation.'})
    return found


# Temporary same-image functional-confirm class, not a physical keycap claim.
# Each body excludes literal pools; exact BL offsets prevent deleted-link matches.
_LOOP_CONFIRM_RULE = 'same-image-loop-functional-confirm-v1'
_LOOP_CONFIRM_SHAPES = {
    'selection': ('2e49b0b509682e4f498b0329', 0, 0xba,
        '845a7a47bb67db2707b20bcdb5a52a48c46d232d220deb11315b11cdaa435845', (56,62,98,106,138,144,154,174,178)),
    'selection_wrapper': ('021c081c124b111c9a4200b5', 0, 0x50,
        'c380d62ff3ba7f2d0908a1cae36d9858efb8f0de1aaad346369f4c7e439b4cf9', (34,64,74)),
    'save_wrapper': ('031c081c111c1a1c1b4b00b5', 0, 0x78,
        '0ef3196a58cf06eb5e6df7c623c58d0767601f152aeb117830acb241922df219', (46,74,80,86,92,98,104,110)),
    'save': ('b0b57e2800d178e016dcf127', 0, 0x130,
        '130ec359f4cc55049f349ebdd1c883c052795e03199bcaa84fba1c0eb6ba64d1', (36,46,50,78,94,100,112,118,132,140,146,152,160,174,180,186,202,206,214,218,226,236,244,250,258,262,272,286)),
    'commit': ('90b5074c0027b800c0192118', 0, 0x20,
        '6c02f1d11e4dd51af0bbe0f03c81b6e50eb1090e5cc2dbd34b38c0083cb75751', (16,)),
    'record': ('f0b50f1c041c042803d91e49', 0, 0x82,
        '4fce10fe09915d4966045ae70bea87fadebe0aa4f2996ef59e6b042eff200930', (14,48,60,72,84,96,104,120)),
    'registrar': ('f0b5051c1d480e1c', 0, 0x7a,
        '8ed34ad3d68e668a439df0252ce9da09731bac5e79b1c553e566c3afd53a79de', (10,18,22,30,68,84,88,94,102)),
    'lookup': ('0a4b00b500218a009a581288', 0, 0x28,
        'dc2b048eefe04335fa5d7937250698043557a321bb4d1cfea0d704516495f4a1', (34,)),
    'allocator': ('90b50d4c00277800c0190001', 0, 0x38,
        '125b0998f531dd0bbcdb69641dd019ce1907ee89f1b1f71e40eb6a564cd2f824', (38,)),
    'publisher': ('044a11688162034910600860', 0, 0x10,
        '898d0e0f2e151cce017129e29d24dcc40c195efa176b8d3a606b9af6481089d4', ()),
    'action_send': ('b0b4174d2b68dc1c04d56442', 0, 0x5e,
        'a6350958d50d800d70822738f11ca89e9bd8af7867e6bc68076403d2f3e7b0a9', ()),
    'action_drain': ('2e4e2e4f2f4c2f48', 0, 0xae,
        'd161a54ef3a416918b1e1a5016e83373eeb042bf61b7a3c6c24b6f3b369d191a', (8,58,74,94,108,114,154)),
    'typed': ('f7b5071c0120800781b08c4e', 0, 0x23c,
        '5b630d8c71edf18093f33ee9207634782aff47efdc1f88e709bccc2ff35fcdb5', (52,62,102,112,156,164,182,192,208,216,230,234,244,248,260,264,274,314,322,340,350,384,436,460,476,502,516,524,544,556,562,566)),
    'dispatch': ('071c00d1c9e0664d674e062f', 6, 0x1a4,
        '7eb82f89f75175a53df858b4d3b22c62bd10843bdfbdc77ed8076dde57516de6', (2,48,58,68,74,86,96,104,116,160,170,180,186,198,208,214,236,244,264,274,282,290,300,306,324,336,348,368,386,392,402,406)),
}


def _loop_functional_confirm(image: bytes, matrix: dict):
    def reject(reason):
        return {}, {'ok_mapping_status': 'rejected',
                    'ok_mapping_reject_reasons': [reason]}

    events = matrix.get('event_codes', [])
    if len(events) != 24 or events.count(0x53) != 1:
        return reject('confirm-namespace-not-unique')
    # Direct helper avoids resolver recursion; reuse the already closed scanner,
    # callback registration, byte ring and event-preserving dispatcher proof.
    from .input_halfword_status import _loop_status
    status, reason, _ = _loop_status(image, matrix)
    if status is None:
        return reject('confirm-' + reason)

    def ram(p, size):
        return type(p) is int and 0x1000000 <= p <= 0x2000000-size

    def word(p):
        return struct.unpack_from('<I', image, p)[0] if type(p) is int and 0 <= p <= len(image)-4 else None

    def call(p):
        target = thumb_bl_target(image, p)
        return target if target is not None and not target & 1 and 0 <= target <= len(image)-2 else None

    matched = {}
    for name, (anchor, back, size, digest, offsets) in _LOOP_CONFIRM_SHAPES.items():
        hits = [p-back for p in find_all(image, bytes.fromhex(anchor))
                if p >= back and not (p-back) & 1
                and (name != 'action_send' or p-back == call(status['consumer']['dispatch']+0xd0))
                and _normalized_thumb_sha256(image, p-back, size) == (digest, offsets)
                and all(call(p-back+d) is not None for d in offsets)]
        if len(hits) != 1:
            return reject('confirm-shape-' + ('missing-' if not hits else 'ambiguous-') + name)
        matched[name] = hits[0]
    sel, sw, save, vw, commit, record = (matched[n] for n in
        ('selection','selection_wrapper','save','save_wrapper','commit','record'))
    reg, lookup, alloc, pub, send, drain, typed, dispatch = (matched[n] for n in
        ('registrar','lookup','allocator','publisher','action_send','action_drain','typed','dispatch'))
    current = thumb_literal_value(image, pub+6, 1)
    action_ring = thumb_literal_value(image, send+2, 5)
    if (dispatch != status['consumer']['dispatch']
            or call(dispatch+2) != status['consumer']['dequeue']
            or call(dispatch+0xd0) != send
            or call(drain+0x3a) != typed or call(drain+0x9a) != typed
            or not ram(action_ring, 8+32*12) or action_ring & 3
            or thumb_literal_value(image, drain+4, 4) != action_ring
            or not ram(current,4) or current & 3
            or any(thumb_literal_value(image, typed+d,6) != current for d in (0xa,0x162,0x1c0))
            or image[call(typed+0x1cc):call(typed+0x1cc)+2] != bytes.fromhex('1847')
            or thumb_literal_value(image, sel,1) != current
            or thumb_literal_value(image, sw+4,3) != 0x40000001
            or thumb_literal_value(image, vw+0x12,3) != 0x40000001
            or thumb_literal_value(image, typed+0x5c,0) != 0x40000004
            or call(sw+0x4a) != sel or call(vw+0x56) != save
            or call(sel+0xae) != reg
            or call(reg+0x16) != alloc or call(reg+0x1e) != lookup or call(reg+0x5e) != pub
            or thumb_literal_value(image, reg+4,0) != thumb_literal_value(image, pub,2)
            or not ram(thumb_literal_value(image, alloc+2,4),20*48)
            or not ram(thumb_literal_value(image, pub,2),4)
            or not ram(thumb_literal_value(image, sel+0x16,5),0x3c)
            or not ram(thumb_literal_value(image, sel+0x70,2),2)):
        return reject('confirm-typed-registration-link-mismatch')

    # Copy-source provenance for every searched 48-byte descriptor; lookup
    # compares header IDs, never table indices. No absolute ROM/RAM offset gate.
    table = thumb_literal_value(image, lookup,3)
    if type(table) is not int or table & 3 or not 0 <= table <= len(image)-0x97*4:
        return reject('confirm-registry-table-bounds')
    pointers = [word(table+4*i) for i in range(0x97)]
    if any(not ram(p,48) or p & 3 for p in pointers):
        return reject('confirm-registry-pointer-ambiguity')
    pattern = re.compile(b'.\x48\x00\x68.\x49\x09\x68\x40\x18\x06\x1c'
                         b'.\x48\x00\x68\x05\x1c.\x48' + re.escape(bytes.fromhex(
                         '0068041cb44208d204e0281d051c201d041cf7e728682060f7e7')), re.S)
    copies = []
    for match in pattern.finditer(image[:0x20000]):
        pc = match.start()
        slots = [thumb_literal_value(image,pc+d,r) for d,r in ((0,0),(4,1),(12,0),(18,0))]
        if pc & 1 or any(type(p) is not int or p & 3 or not 0 <= p <= len(image)-4 for p in slots):
            continue
        dest,size,source,reload = [word(p) for p in slots]
        if ((slots[1],slots[2],slots[3]) != (slots[0]+4,slots[0]-4,slots[0])
                or reload != dest or (source | dest | size) & 3 or not ram(dest,size)
                or size < 48 or not 0 <= source <= len(image)-size
                or any(not dest <= p <= dest+size-48 for p in pointers)):
            continue
        copies.append((pc,source,dest,size))
    if len(copies) != 1:
        return reject('confirm-registry-copy-missing-or-ambiguous')
    copy_pc,source,dest,size = copies[0]
    descriptors = [source+p-dest for p in pointers]
    ids = [struct.unpack_from('<H',image,p)[0] for p in descriptors]
    registered = []
    for wrapper in (sw,vw):
        matches = [p for p in descriptors if word(p+0xc) == wrapper+1]
        if (len(matches) != 1 or ids.count(struct.unpack_from('<H',image,matches[0])[0]) != 1
                or word(matches[0]+0x20) != 0 or word(matches[0]+0x24) != 0):
            return reject('confirm-registered-callback-missing-or-ambiguous')
        registered.append(matches[0])

    # Independent setting commit and its named result, tied to the raw53 arm.
    strings = call(save+0xe2)
    if (call(save+0xda) != commit or call(commit+0x10) != record
            or call(save+0xec) != strings or strings is None
            or image[strings:strings+8] != bytes.fromhex('0149800008587047')
            or thumb_literal_value(image, record+0x12,0) != 0x36a
            or not ram(thumb_literal_value(image, commit+2,4),25)
            or not ram(thumb_literal_value(image, record+0x14,6),5)
            or not ram(thumb_literal_value(image, record+0x6e,0),25)):
        return reject('confirm-save-link-mismatch')
    text_table = thumb_literal_value(image, strings,1)
    if type(text_table) is not int or text_table & 3 or not 0 <= text_table <= len(image)-4*0x1a1:
        return reject('confirm-save-string-table-bounds')
    for index,text in ((0x11d,'저장했습니다'),(0x1a0,'알림')):
        pointer = word(text_table+4*index)
        raw = text.encode('cp949')+b'\0'
        if type(pointer) is not int or not 0 <= pointer <= len(image)-len(raw) or image[pointer:pointer+len(raw)] != raw:
            return reject('confirm-save-result-string-mismatch')
    mapping = {5: {'event':0x53,'semantic_status':'temporary-evidence-gated-provisional',
        'rule':_LOOP_CONFIRM_RULE,'semantic_grammar_fingerprint':_LOOP_CONFIRM_SHAPES['selection'][3],
        'evidence':'same-image-scanner+typed-dispatch+copied-registry+selection+named-save',
        'functional_only':True,'physical_keycap_proven':False,
        'selection':sel,'save':save,'typed_dispatch':typed,'registry_lookup':lookup,
        'registry_copy':{'loop':copy_pc,'source':source,'target':dest,'size':size},
        'registered_callbacks':[{'rom':p,'ram':dest+p-source,'callback':word(p+0xc)} for p in registered],
        'limits':'Functional confirm is state-dependent; physical keycap and Home/Menu mapping unproven.'}}
    return mapping, {'ok_mapping_status':'accepted-provisional','ok_mapping_reject_reasons':[]}


def resolve_indirect_matrix_input(image: bytes, load_address: int=0):
    """Return only a unique linked scanner with unambiguous semantic cells."""
    if load_address != 0:
        return (None, 'unsupported-load-address', [])
    candidates = find_indirect_matrix_scanners(image) + find_mapped_row_scanners(image) + find_loop_row_scanners(image)
    if not candidates:
        return (None, 'not-found', [])
    if len(candidates) != 1:
        return (None, 'ambiguous-scanners', candidates)
    candidate = candidates[0]
    if not candidate['token_cells']:
        return (None, 'no-exact-semantic-cells', candidates)
    if candidate['grammar'] == 'indirect-halfword-loop-six-row-v1':
        mappings, metadata = _loop_functional_confirm(image, candidate)
        candidate.update(metadata)
        if mappings:
            candidate['provisional_mappings'] = mappings
            events = candidate['event_codes']
            cell = events.index(mappings[5]['event'])
            candidate['token_cells'].append({'token':'O','event':events[cell],
                                             'row':cell%6,'column':cell//6})
    return (candidate, 'static-candidate', [])
