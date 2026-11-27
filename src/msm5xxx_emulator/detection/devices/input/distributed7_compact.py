"""Relocation-closed compact seven-row scanner variant.

Only electrical contacts are projected. Numeric semantics come from unique
ASCII table entries; other events require the caller's explicit event byte.
The guest keeps its own GPIO scanning, debounce, ring writes and UI dispatch.
"""
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.fact_bodies import match_thumb_shape
from msm5xxx_emulator.detection.signatures import find_all
from .distributed7 import _CLEAR, _DEQUEUE, _TIMER

_HEAD = (970, 'a94b9b6eb7a2ba7e4d233df6837405ab2d1f58918f49049d5e9371b53535a4c3', (8, 12, 22, 32, 216, 220, 254, 290, 320, 324, 350, 354, 384, 414, 418, 444, 448, 478, 508, 512, 538, 542, 572, 598, 602, 632, 636, 666, 692, 696, 726, 730, 760, 786, 790, 816, 820, 848, 878, 882, 908, 912, 938), (6, 38, 46, 48, 86, 96, 102, 120, 136, 168, 200, 224, 294, 310, 328, 340, 358, 370, 388, 404, 422, 434, 452, 464, 482, 498, 516, 528, 546, 558, 576, 588, 606, 622, 640, 652, 670, 682, 700, 716, 734, 746, 764, 776, 794, 806, 824, 836, 852, 868, 886, 898, 916, 928, 942, 954))
_TAIL = (244, '8349c2baf59f972e604ff995085df9c31775587cffb3c123961eca34321e3fe3', (12, 20, 76, 198, 222, 232), (24, 32, 38, 48, 64, 82, 126, 164, 220, 228, 230))
_QUEUE = (130, '805760941febeb756b858f06e6d6b4146a26de325434ca634b033c08622e1d3f', (12, 104, 120), (16, 68, 100, 102, 108))
_LID = (330, 'a1a039b38ab90fcd0cc15818c8427747d53652937c217337fb7d142fb0ede011', (2, 8, 58, 136, 142, 168, 178, 192, 216, 254, 272, 296, 318), (16, 20, 36, 64, 72, 82, 126, 172, 182, 196, 198, 208, 262, 290, 308))
_OTHER_GATE = (344, '9f27e6beae645c943d40d23ccff79bb91187c4a1e8a7f87b9a50287bdcc7b71d', (78, 110, 142, 160, 250, 274, 324), (2, 20, 50, 172, 212, 226, 246, 286))
_READER = (62, 'a6d6e65701e53939be59b5daebc70d2135b1a2db9c387e583d2e91e593f90ad6', (24,), (0, 10))

def find_compact_seven_row_profiles(image):
    profiles = []
    facts = facts_for(image)
    for start in find_all(image, bytes.fromhex('f0b500270421')):
        head = match_thumb_shape(image, start, _HEAD)
        tail = match_thumb_shape(image, start + 0x3f4, _TAIL)
        if head is None or tail is None:
            continue
        hc, hl, _ = head
        tc, tl, _ = tail
        clear, queue, lid, gate = hc[0xdc], tc[0x4c], hc[0xc], hc[0x16]
        linked = [match_thumb_shape(image, p, s) for p, s in
                  ((clear, _CLEAR), (queue, _QUEUE), (lid, _LID), (gate, _OTHER_GATE))]
        if any(s is None for s in linked):
            continue
        (cc, cl, _), (qc, ql, _), (lc, ll, _), (gc, gl, _) = linked
        reader = lc[8]
        read = match_thumb_shape(image, reader, _READER)
        if read is None:
            continue
        base, state, ring, table = cl[12], ql[16], ql[68], hl[0x3ba] - 28
        if (base != 0x03000660 or not 0 <= table <= len(image) - 44 or
            any(not 0x01000000 <= p < 0x01800000 for p in (state, ring, cl[6], cl[34], cl[60])) or
            any(hl[o] != base + 0x30 for o in (0x26, 0xe0, 0x3ae)) or
            any(hl[o] != state + 0x30 for o in (0x30, 0x66, 0x88, 0xc8)) or
            any(tl[o] != state + 0x40 for o in (0x20, 0x26, 0x40, 0x52, 0x7e)) or
            ql[0x6c] != ring or ll[0x10] != state or ll[0x40] != state or
            read[1][0] != base or read[1][10] != state + 0x40 or
            any(gl[o] != state + 0x40 for o in (0x14, 0xac, 0xd4, 0xf6)) or
            gl[2] != base or gl[0x11e] != base or
            hc[0xfe] != clear or tc[12] != clear or hc[0xd8] != queue or
            tc[0xc6] != queue or gc[0x144] != queue or
            any(lc[o] != queue for o in (0x88, 0xc0, 0x110, 0x13e)) or
            image[table + 28 + 14] != 0 or image[table + 28 + 13] != 1 or
            image[table + 28 + 11] != 2 or image[table + 28 + 7] != 3):
            continue
        lock, unlock = cc[2], cc[26]
        if (any(cc[o] != lock for o in (30, 56)) or any(cc[o] != unlock for o in (52, 78)) or
            hc[0x20] != lock or tc[0x14] != unlock or lc[2] != lock or lc[0x3a] != unlock or
            tc[0xde] != qc[0x78] or tc[0xe8] != qc[0x68] or
            tl[0xdc] != hl[6] or tl[0xe4] != ql[0x64]):
            continue
        # Decode each full protected GPIO group; masks and branches also remain
        # in the normalized body fingerprint. Relocated owners are checked here.
        row_values = []
        consistent = True
        for off in (0x122, 0x180, 0x1de, 0x23c, 0x29a, 0x2f8, 0x350):
            cursor, row = start + off, []
            for port, mask, shadow in zip((12, 8, 4), (0x66, 6, 0x80), (cl[6], cl[34], cl[60])):
                if (facts.thumb_call_target(cursor) != lock or
                    facts.thumb_literal_value(cursor + 4, 2) != shadow or
                    image[cursor+6:cursor+10] != bytes((mask, 0x23, 0x11, 0x78))):
                    consistent = False
                    break
                cursor += 10
                op = int.from_bytes(image[cursor:cursor+2], 'little')
                if op == 0x4319:
                    value = mask
                    cursor += 2
                elif op == 0x4399:
                    value = 0
                    cursor += 2
                    if image[cursor+1] == 0x23:
                        value = image[cursor]
                        cursor += 4
                else:
                    consistent = False
                    break
                if (facts.thumb_literal_value(cursor+4, 2) != base + 0x30 or
                    image[cursor:cursor+4] != bytes.fromhex('11701178') or
                    image[cursor+6:cursor+10] != bytes((0x30, 0x3a, 0x11, 0x70 | (port >> 2)))):
                    consistent = False
                    break
                row.append(value)
                cursor += 18
            if not consistent:
                break
            row_values.append(row)
        if not consistent or len({tuple(row) for row in row_values}) != 7:
            continue
        dequeues = [p-2 for p in find_all(image, bytes.fromhex('50781178884201d100207047'))
                    if p >= 2 and match_thumb_shape(image, p-2, _DEQUEUE) is not None
                    and facts.thumb_literal_value(p-2, 2) == ring]
        timers = []
        for p in find_all(image, bytes.fromhex('0122009219221923381c')):
            timer = match_thumb_shape(image, p-8, _TIMER)
            if timer is not None and timer[1][18] == start | 1:
                timers.append((p-8, timer[1][0], timer[0][20]))
        events = list(image[table:table+28])
        if len(dequeues) != 1 or len(timers) != 1 or any(events.count(e) != 1 for e in b'123456789*0#'):
            continue
        mappings = {bit: dict(event=e, label=chr(e), rule='unique-source-ASCII-table-entry',
                             semantic_status='source-verified-numeric')
                    for bit, e in zip(range(11, 23), b'123456789*0#')}
        profiles.append(dict(
            grammar='distributed-seven-byte-v1', source_variant='compact-filtered-byte-ring32-v1',
            function=start, family='distributed-filtered-byte-ring32-v1',
            event_sink_family='distributed-filtered-byte-ring32-v1',
            evidence='normalized-complete-scanner+row-switch+ring32+lid-gate+periodic-registration',
            register=base+0x34, register_width=1, presence_site=start+0xe2, sense_site=start+0x3b0,
            rows=7, columns=4, sense_bits=4, no_key=15, single_key_column_sense=[14,13,11,7],
            gpio_ports=[dict(address=base+off, mask=mask, shadow=shadow)
                        for off,mask,shadow in zip((12,8,4),(0x66,6,0x80),(cl[6],cl[34],cl[60]))],
            row_values=row_values, global_values=[0,0,0], clear_function=clear,
            event_table=table, event_codes=events, event_table_formula='event_codes[column * 7 + row]',
            scanner_state=state, debounce_state=state+0x32,
            debounce='two equal nonzero scans; release event 0xff',
            periodic_registration=timers[0][0], timer_object=timers[0][1], clock_register=timers[0][2], period_ms=25,
            producer=dict(family='distributed-filtered-byte-ring32-v1', ring=ring, state=state,
                          enqueue=queue, dequeue=dequeues[0], event_store=queue+0x56,
                          write_index_store=queue+0x60, read_index_store=dequeues[0]+0x18, slots=32, wrap_mask=31),
            lid_input=dict(address=base, mask=1, open_value=1, reader=reader, scanner=lid, closed_flag=state+0x12),
            sideband_input=dict(address=base+0x34, mask=0x10, released_value=0x10,
                                read_site=start+0x28, press_event=0x51),
            provisional_mappings=mappings, unmapped_events=sorted(set(events)-set(b'123456789*0#')-{0}),
            extra_host_keys={}))
    return profiles
