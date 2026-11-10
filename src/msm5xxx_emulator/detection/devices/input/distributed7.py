"""Closed seven-row/four-column GPIO scanner and its byte-ring producer.

The row order is read from the compiled switch, not the order of GPIO bits.
Only source shapes are matched: there is no model name, file hash, or ROM PC.
"""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.fact_bodies import match_thumb_shape as thumb_normalized_source_shape
from msm5xxx_emulator.detection.signatures import find_all

_FIRST = (0x3e8, 'ff1d5fdd588c5799a9305833de5114d5712a25f57c1007774ddd8dbc62b2a76a', (20, 38, 46, 50, 216, 220, 256, 294, 324, 328, 354, 358, 388, 418, 422, 448,
    452, 482, 512, 516, 542, 546, 576, 602, 606, 636, 640, 670, 696, 700, 730, 734, 764, 790, 794, 820, 824, 852, 882, 886, 912, 916, 942), (2, 18, 24, 58, 66,
    68, 134, 200, 224, 298, 314, 332, 344, 362, 374, 392, 408, 426, 438, 456, 468, 486, 502, 520, 532, 550, 562, 580, 592, 610, 626, 644, 656, 674, 686, 704,
    720, 738, 750, 768, 780, 798, 810, 828, 840, 856, 872, 890, 902, 920, 932, 946, 978))
_LAST = (0x224, '73b3a75a44cc1e5c4812a4a6c628fba040b9b9e19b90ff1b6fa8dd08e2239039', (40, 228, 358, 404, 452, 488, 508, 530), (68, 78, 98, 112, 128, 184, 190,
    224, 226, 238, 254, 272, 300, 306, 316, 324, 346, 362, 374, 394, 412, 482, 484, 506, 528))
_CLEAR = (0x58, '4b8828a1dd67c6585950eedc142db0d4c3a796375730584acc02537f4652aedb', (2, 26, 30, 52, 56, 78), (6, 12, 34, 60))
_QUEUE = (0x84, '5ef8ef552beb659ebfc9aab48cc0945831953e9c959284e7d5bd22f137292dbe', (54, 98, 106, 122), (4, 58, 94, 96, 110))
_DEQUEUE = (0x1c, 'c65484df0be9a08ca7435953400aa1f9f2e631468b8234a7612c99a0851ab3b1', (), (0,))
_LID_READ = (0x44, 'a396a5bf6a5faa5e2b20ec364f5aa916d55830f6cb68b385c2a3b7dfeb6385a8', (24,), (0, 10))
_LID_SCAN = (0x94, '0b40b21b0bb585ca6d71086fac776e7cf01756da9cb3503f6a344a54239537df', (2, 64, 72, 78, 84, 122, 128, 134), (12, 28, 68))
_TIMER = (0x18, 'db59bd7e31d4d60da9b416d2bb372b1ee63bf79e336993f543bd83828c77f3a0', (4, 20), (0, 18))

def find_seven_row_input_profile(image: bytes, load_address: int = 0):
    """Return one signature-closed electrical profile, with firmware-owned debounce."""
    if load_address != 0:
        return None, 'unsupported-load-address'
    profiles = []
    # PUSH; relocated LDR r1; stack allocation; initialize temporary key list.
    for anchor in find_all(image, bytes.fromhex('87b0002468460ec90ec00027')):
        start = anchor - 4
        first = thumb_normalized_source_shape(image, start, _FIRST)
        last_at = start + 0x40c
        last = thumb_normalized_source_shape(image, last_at, _LAST)
        if first is None or last is None:
            continue
        calls, literals, _ = first
        last_calls, last_literals, _ = last
        clear = calls[220]
        clear_shape = thumb_normalized_source_shape(image, clear, _CLEAR)
        queue = last_calls[452]
        queue_shape = thumb_normalized_source_shape(image, queue, _QUEUE)
        lid = calls[38]
        lid_shape = thumb_normalized_source_shape(image, lid, _LID_SCAN)
        if clear_shape is None or queue_shape is None or lid_shape is None:
            continue
        cc, cl, _ = clear_shape
        qc, ql, _ = queue_shape
        lc, ll, _ = lid_shape
        lid_reader = lc[2]
        lid_read = thumb_normalized_source_shape(image, lid_reader, _LID_READ)
        if lid_read is None:
            continue
        state, ring, base = ql[4], ql[58], cl[12]
        table = literals[978] - 0x2c
        if (not 0 <= table <= len(image) - 28 or literals[2] != table + 0x2c or literals[58] != base + 0x30 or literals[224] != base + 0x30 or literals[946] !=
            base + 0x30 or base != 0x03000660 or calls[256] != clear or last_calls[40] != clear or calls[216] != queue or last_calls[358] != queue or last_calls[404]
            != queue or lc[78] != queue or lc[128] != queue or lc[134] != queue or ll[12] != state or literals[66] != state or literals[200] != state or ql[110]
            != ring or lid_read[1][0] != base or lid_read[1][10] != state + 0x40 or any(not 0x01000000 <= value < 0x01800000 for value in (state, ring, cl[6],
            cl[34], cl[60]))):
            continue
        lock, unlock = cc[2], cc[26]
        if (any(cc[o] != lock for o in (30, 56)) or any(cc[o] != unlock for o in (52, 78)) or qc[54] != lock or qc[106] != unlock):
            continue
        # The switch has seven complete protected GPIO groups. The signature
        # retains the masks and immediates; also verify all relocated owners.
        arm_offsets = (0x126, 0x184, 0x1e2, 0x240, 0x29e, 0x2fc, 0x354)
        row_values = []
        consistent = True
        for off in arm_offsets:
            cursor, row = start + off,[]
            for port, mask, shadow in zip((12, 8, 4), (0x66, 6, 0x80), (cl[6], cl[34], cl[60])):
                if (facts_for(image).thumb_call_target(cursor) != lock or facts_for(image).thumb_literal_value(cursor + 4, 2) != shadow or image[cursor + 6:cursor
                    + 10] != bytes((mask, 0x23, 0x11, 0x78))):
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
                    if image[cursor + 1] == 0x23:
                        value = image[cursor]
                        cursor += 4  # MOVS r3,#value; ORRS r1,r3
                else:
                    consistent = False
                    break
                if (facts_for(image).thumb_literal_value(cursor + 4, 2) != base + 0x30 or image[cursor:cursor+4] != bytes.fromhex('11701178') or image[cursor+6:cursor+10]
                    != bytes((0x30, 0x3a, 0x11, 0x70 | (port >> 2)))):
                    consistent = False
                    break
                row.append(value)
                cursor += 18
            if not consistent:
                break
            row_values.append(row)
        if not consistent or len({tuple(row) for row in row_values}) != 7:
            continue
        dequeues = [p - 2 for p in find_all(image, bytes.fromhex('50781178884201d100207047')) if p >= 2 and thumb_normalized_source_shape(image, p-2, _DEQUEUE)
            is not None and facts_for(image).thumb_literal_value(p-2, 2) == ring]
        timers = []
        for p in find_all(image, bytes.fromhex('0122009219221923381c')):
            shape = thumb_normalized_source_shape(image, p - 8, _TIMER)
            if shape is not None and shape[1][18] == start | 1:
                timers.append((p - 8, shape[1][0], shape[0][20]))
        if len(dequeues) != 1 or len(timers) != 1:
            continue
        events = list(image[table:table+28])
        if any(events.count(event) != 1 for event in b'123456789*0#'):
            continue
        # Numeric legends are ASCII bytes. Functional control names are checked
        # against this scanner family's UI consumers.
        # Bit 23 exposes the separate service key to headless KEYS= input; it
        # does not change the shared GUI's key count or invent a branded legend.
        mapping = {0: 0x5b, 1: 0x63, 2: 0x52, 3: 0x50, 4: 0x65, 5: 0x53, 6: 0x66, 8: 0x55, 9: 0x64, 10: 0x54, 23: 0x87, **dict(zip(range(11, 23),
            b'123456789*0#'))}
        labels = {0: 'Menu', 1: 'Up', 2: 'Clear', 3: 'Call', 4: 'Left', 5: 'OK', 6: 'Right', 8: 'Volume down', 9: 'Down', 10: 'Volume up', 23:
            'Internet/service connect', **dict(zip(range(11, 23), '123456789*0#'))}
        profiles.append(dict(grammar='distributed-seven-byte-v1', function=start, family= 'distributed-filtered-byte-ring32-v1', event_sink_family='distributed-filtered-byte-ring32-v1',
            evidence='normalized-complete-scanner+row-switch+ring32+periodic-registration', register=base + 0x34, register_width=1, presence_site=start+0xe2,
            sense_site=start+0x3b4, rows=7, columns=4, sense_bits= 4, no_key=15, single_key_column_sense= [14, 13, 11, 7], gpio_ports= [dict(address=base+off,
            mask=mask, shadow=shadow) for off,mask,shadow in zip((12,8,4),(0x66,6,0x80),(cl[6],cl[34],cl[60]))], row_values =row_values, global_values= [0,0,0],
            clear_function=clear, event_table=table, event_codes=events, event_table_formula='event_codes[column * 7 + row]', scanner_state=state,
            debounce_state=state+0x2a, debounce='two equal nonzero scans; release event 0xff', periodic_registration=timers[0][0], timer_object=timers[0][1],
            clock_register=timers[0][2], period_ms=25, producer=dict(family= 'distributed-filtered-byte-ring32-v1', ring=ring, state=state, enqueue=queue,
            dequeue=dequeues[0], event_store=queue+0x50, write_index_store=queue+0x5a, read_index_store=dequeues[0]+0x18, slots=32, wrap_mask=31), lid_input=dict(address=base,
            mask=1, open_value=1, reader=lid_reader, scanner=lid, closed_flag=state+8), sideband_input=dict(address=base+0x34, mask=0x10, released_value=0x10,
            read_site=start+0x3c, press_event=0x51), provisional_mappings={bit:dict(event=event, label=labels[bit], rule='same-image-table-and-functional-controls',
            semantic_status= 'source-verified-functional-control') for bit,event in mapping.items() if events.count(event)==1}, unmapped_events= [],
            extra_host_keys={23: 'Internet/service connect'},))
    return (profiles[0], 'accepted') if len(profiles) == 1 else (None, 'ambiguous' if profiles else 'not-found')
