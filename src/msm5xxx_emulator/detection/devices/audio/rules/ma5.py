from __future__ import annotations
from msm5xxx_emulator.detection.fact_bodies import thumb_body

def _ma5_readback_span(image: bytes, start: int, role: str) -> dict | None:
    from . import _MA5_READBACK_SPANS, _MMIO_MAX, _MMIO_MIN, facts_for, struct
    encoded, calls, literals, base_offset = _MA5_READBACK_SPANS[role]
    expected = bytes.fromhex(encoded)
    if start & 1 or not 0 <= start <= len(image) - len(expected):
        return None
    body = thumb_body(facts_for(image), start, len(expected), call_offsets=calls, literal_offsets=literals)
    if body is None or any(target & 1 or not 0 <= target < len(image) - 1 for _, target in body.calls):
        return None
    code = bytearray(body.normalized)
    targets = [target for _, target in body.calls]
    values = [value for _, _, value, _ in body.literals]
    dependencies = [[start, len(expected)], *[[target, 2] for target in targets], *[[pool, 4] for pool, _ in body.pools]]
    base = None
    if base_offset is not None:
        move, shift = struct.unpack_from("<HH", code, base_offset)
        register = move >> 8 & 7
        template_register = 5 if role in ("block", "timed_block") else 1 if role == "local_index" else 0
        if (move & 0xF800 != 0x2000 or register != template_register or shift & 0xF800 or shift & 7 != register or shift >> 3 & 7 != register):
            return None
        base = (move & 255) << (shift >> 6 & 31)
        if not _MMIO_MIN <= base <= _MMIO_MAX - 3 or base & 3:
            return None
        code[base_offset:base_offset + 4] = b"\0" * 4
    if code != expected:
        return None
    return {"calls": targets, "literals": values, "base": base, "dependencies": dependencies}

def _ma5_readback_transport(image: bytes, common: dict, entries: dict, local: bool) -> dict | None:
    from . import _MMIO_MAX, _MMIO_MIN, _ma5_readback_span
    entries = dict(entries)
    spans = dict(common)
    prefix = "local_" if local else ""
    for role in ("empty", "write", "wait", "dataread"):
        spans[role] = _ma5_readback_span(image, entries[role], prefix + role)
    if any(span is None for span in spans.values()):
        return None
    entries["index"] = spans["select"]["calls"][0]
    entries["status"] = spans["wait"]["calls"][0]
    entries["block"] = entries["write"] + (0x58 if local else 0x20)
    for role in ("index", "status", "block"):
        spans[role] = _ma5_readback_span(image, entries[role], prefix + role)
    if (any(span is None for span in spans.values()) or len(set(entries.values())) != len(entries) or spans["empty"]["calls"] != spans["wait"]["calls"]):
        return None
    context = spans["read"]["literals"][0]
    ram = [[context, 4]]
    evidence = {"entries": entries, "context_pointer": context, "default_ranges":[[0xC0, 0xD0, 0x60],[0xD0, 0xE0, 0x3C]]}
    if local:
        if any(entries[role] != entries["index"] + delta for role, delta in (("status", 0x2A), ("write", 0x52), ("dataread", 0x7E), ("block", 0xAA))):
            return None
        base = spans["index"]["base"]
        direction, dummy = spans["index"]["literals"]
        data = spans["write"]["literals"][2]
        limit = spans["empty"]["literals"][0]
        error = spans["wait"]["calls"][1]
        if (spans["status"]["base"] != base or data != base + 128 or not _MMIO_MIN <= data < _MMIO_MAX or spans["status"]["literals"] !=[direction, dummy] or
            spans["write"]["literals"] !=[direction, dummy, data] or spans["dataread"]["literals"] !=[direction, dummy, data] or spans["block"]["literals"] !=[data]
            or direction <= dummy < direction + 4 or not 0 < limit <= 0xFFFF or image[error:error + 2] != b"\x70\x47"):
            return None
        ram.extend([[direction, 4],[dummy, 1]])
        evidence.update(transport_class="local-counter-literal-data-v1", direction_state=direction, delay_dummy= dummy, wait_limit=281, empty_poll_limit=limit)
        stride, index_site, status_site, write_site, block_site, read_site = 128, 26, 28, 24, 12, 26
    else:
        wrappers = ("index", "status", "write", "block", "dataread")
        bases = {spans[role]["base"] for role in wrappers}
        delays = {target for role in wrappers for target in spans[role]["calls"]}
        poll, limit = spans["wait"]["literals"]
        if (len(bases) != 1 or len(delays) != 1 or spans["empty"]["literals"] !=[poll, limit] or any(spans[role]["literals"] !=[poll] for role in wrappers) or
            not 0 < limit <= 0xFFFF):
            return None
        base = bases.pop()
        ram.append([poll, 8])
        evidence.update(transport_class="ram-counter-synthesized-data-v1", poll_state=poll, poll_limit=limit)
        stride, index_site, status_site, write_site, block_site, read_site = 2, 18, 16, 18, 28, 16
    if any(not 0x01000000 <= address <= 0x02000000 - size or size > 1 and address & 3 for address, size in ram):
        return None
    return {
        "family": "ma5", "grammar": "ma5-readback-v1",
        "static_status": "candidate", "reject_reason": None,
        "protocol_status": "temporary-evidence-gated", "base": base,
        "data_offset": stride,
        "sites": {"write_0": [entries["index"] + index_site],
                  "read_0": [entries["status"] + status_site],
                  f"write_{stride}": [entries["write"] + write_site,
                                      entries["block"] + block_site],
                  f"read_{stride}": [entries["dataread"] + read_site]},
        "block_write_offsets": [entries["block"] + block_site],
        "structural_evidence": evidence, "ram_dependencies": ram,
        "nor_dependencies": [dependency for span in spans.values()
                             for dependency in span["dependencies"]],
    }

def _ma5_timed_transport(image: bytes, common: dict, entries: dict) -> dict | None:
    from . import _MMIO_MAX, _ma5_readback_span, struct
    entries = dict(entries)
    spans = dict(common)
    for role in ("wait", "empty", "write", "dataread"):
        spans[role] = _ma5_readback_span(image, entries[role], "timed_" + role)
    if any(span is None for span in spans.values()):
        return None
    entries["index"] = spans["select"]["calls"][0]
    entries["status"] = spans["wait"]["calls"][0]
    entries["block"] = entries["write"] + 0x2C
    for role in ("index", "status", "block"):
        spans[role] = _ma5_readback_span(image, entries[role], "timed_" + role)
    if (any(span is None for span in spans.values()) or len(set(entries.values())) != len(entries) or spans["wait"]["calls"] != spans["empty"]["calls"]):
        return None
    error = spans["wait"]["calls"][1]
    wrappers = ("index", "status", "write", "block", "dataread")
    bases = {spans[role]["base"] for role in wrappers}
    delays = {target for role in wrappers for target in spans[role]["calls"]}
    direction, write_table = spans["index"]["literals"]
    if (len(bases) != 1 or len(delays) != 1 or image[error:error + 2] != b"\x70\x47" or any(spans[role]["literals"] !=[direction, write_table] for role in ("write",
        "block")) or any(spans[role]["literals"] !=[direction, write_table + 8] for role in ("status", "dataread")) or write_table & 3 or not 0 <= write_table
        <= len(image) - 16):
        return None
    entries["delay"] = delays.pop()
    spans["delay"] = _ma5_readback_span(image, entries["delay"], "timed_delay")
    if spans["delay"] is None:
        return None
    calls = spans["delay"]["calls"]
    threshold = spans["delay"]["literals"][0]
    timing = list(struct.unpack_from("<4I", image, write_table))
    if (calls[1] != calls[2] or len(set((calls[0], calls[1], calls[3]))) != 3 or not 0 < threshold <= 0xFFFFFFFF or any(not 0 < value < threshold for value in
        timing)):
        return None
    context = spans["read"]["literals"][0]
    ram = [[context, 4],[direction, 4]]
    if (context == direction or any(address & 3 or not 0x01000000 <= address <= 0x02000000 - size for address, size in ram)):
        return None
    base = bases.pop()
    if base + 4 >= _MMIO_MAX:
        return None
    return { "family": "ma5", "grammar": "ma5-readback-v1", "static_status": "candidate", "reject_reason": None, "protocol_status": "temporary-evidence-gated",
        "base": base, "data_offset": 4, "sites": {"write_0":[entries["index"] + 26], "read_0":[entries["status"] + 24], "write_4":[entries["write"] + 26,
        entries["block"] + 36], "read_4":[entries["dataread"] + 24]}, "block_write_offsets":[entries["block"] + 36], "structural_evidence": { "transport_class":
        "local-counter-direction-timing-v1", "entries": entries, "context_pointer": context, "direction_state": direction, "timing_table": write_table,
        "timing_values": timing, "wait_limit": 300, "default_ranges":[[0xC0, 0xD0, 0x60],[0xD0, 0xE0, 0x3C]]}, "ram_dependencies": ram, "nor_dependencies":[[write_table,
        16]] +[dependency for span in spans.values() for dependency in span["dependencies"]], }

def _ma5_alternate_readback(image: bytes) -> list[dict[str, object]]:
    """Find the alternate bounded checker linked to its byte-port wrappers."""
    from . import _THUMB_BL, _transport_clusters, facts_for, struct
    def conditional_target(at: int, condition: int) -> int | None:
        op = struct.unpack_from('<H', image, at)[0]
        if op >> 8 != (0xd0 | condition):
            return None
        delta = op & 0xff
        return at + 4 + ((delta - 256 if delta & 0x80 else delta) * 2)
    found = []
    anchor = struct.pack('<H', 0x27c0)  # movs r7, #0xc0
    position = 0
    while (at := image.find(anchor, position)) >= 0:
        position = at + 1
        check = at - 2
        if check < 0 or check & 1 or check + 0x46 > len(image):
            continue
        if any(struct.unpack_from('<H', image, check + off)[0] != opcode for off, opcode in ((0x16, 0x2860), (0x1c, 0x2fd0), (0x20, 0x27d0), (0x30, 0x283c), (0x3e,
            0x2fe0))):
            continue
        if (conditional_target(check + 0x1e, 3) != check + 8 or conditional_target(check + 0x40, 3) != check + 0x22 or conditional_target(check + 0x18, 1) !=
            check + 0x34 or conditional_target(check + 0x32, 0) != check + 0x3c):
            continue
        read = facts_for(image).thumb_call_target(check + 0xa)
        if (read is None or read != facts_for(image).thumb_call_target(check + 0x24) or read < 0 or read + 0x90 > len(image)):
            continue
        if any(struct.unpack_from('<H', image, read + off)[0] != opcode for off, opcode in ((0x14, 0x2003), (0x6c, 0x2080), (0x72, 0x2040), (0x84, 0x2041))):
            continue
        select = facts_for(image).thumb_call_target(read + 0x16)
        empty = facts_for(image).thumb_call_target(read + 0x1a)
        write = facts_for(image).thumb_call_target(read + 0x4a)
        wait = facts_for(image).thumb_call_target(read + 0x74)
        dataread = facts_for(image).thumb_call_target(read + 0x8a)
        if (None in (select, empty, write, wait, dataread) or select != facts_for(image).thumb_call_target(read + 0x86) or any(facts_for(image).thumb_call_target(read
            + off) != write for off in (0x54, 0x5c, 0x68, 0x6e)) or not all(0 <= p <= len(image) - 0x100 for p in (select, empty, write, wait, dataread))):
            continue
        index = facts_for(image).thumb_call_target(select + 0x1e)
        status = facts_for(image).thumb_call_target(wait + 0xa)
        if (index is None or status is None or status != facts_for(image).thumb_call_target(empty + 8)):
            continue
        timed = (status - index in (0x1e, 0x20) and write - status == 0x1c and dataread - write == 0x7c)
        direct = (status - index in (0x12, 0x14) and write - status == 0x14 and dataread - write == 0x34)
        if not (timed or direct):
            continue
        delay = None
        if timed:
            delay_calls = (index + 4, status + 2, write + 4, dataread + 2, write + 0x28, write + 0x3e, write + 0x58, write + 0x6a)
            delay = facts_for(image).thumb_call_target(delay_calls[0])
            if (delay is None or not 0 <= delay <= len(image) - 2 or any(facts_for(image).thumb_call_target(at) != delay for at in delay_calls)):
                continue
        resets = []
        for match in _THUMB_BL.finditer(image, max(0, check - 0x2000), min(len(image), check + 0x2000)):
            call = match.start()
            if (call & 1 or call < 0x18 or call + 14 > len(image) or facts_for(image).thumb_call_target(call) != check):
                continue
            immediates = ((-0x18, 0x2004), (-0x12, 0x2080), (-0xc, 0x2000)) if timed else ((-0x12, 0x2004), (- 0xc, 0x2080), (-6, 0x2000))
            calls = (-0x16, -0x10, -0xa) if timed else (-0x10, -0xa, -4)
            count_compare = struct.unpack_from('<H', image, call + 0xa)[0]
            count_register = count_compare >> 8 & 7
            if (all(struct.unpack_from('<H', image, call + off)[0] == op for off, op in immediates) and count_compare & 0xf8ff == 0x280a and struct.unpack_from('<H',
                image, call + 8)[0] == (0x3001 | count_register << 8) and[facts_for(image).thumb_call_target(call + off) for off in calls] ==[index, write,
                write] and conditional_target(call + 0xc, 3) == call - (0x18 if timed else 0x12)):
                resets.append(call)
        if len(resets) != 1:
            continue
        blocks = [write + 0x3c, write + 0x68] if timed else[write + 0x28]
        load, advance, store = (struct.unpack_from('<H', image, off)[0] for off in (blocks[0] - 4, blocks[0] - 2, blocks[0]))
        source_reg = load >> 3 & 7
        if (load & 0xffc0 != 0x7800 or load & 7 != store & 7 or advance != (0x3001 | source_reg << 8) or store & 0xf800 != 0x7000 or (timed and struct.unpack_from('<H',
            image, blocks[1])[0] & 7 != 4)):
            continue
        context = facts_for(image).thumb_literal_value(read + 4, 0)
        direction_refs = ([(index + 8, 1), (status + 6, 1), (write + 8, 1), (dataread + 6, 1)] if timed else[(index, 2), (status, 1), (write, 2), (dataread, 1)])
        direction = facts_for(image).thumb_literal_value(*direction_refs[0])
        if (context is None or direction is None or facts_for(image).thumb_literal_value(select, 2) != context or any(facts_for(image).thumb_literal_value(*ref)
            != direction for ref in direction_refs) or context & 3 or direction & 3 or not 0x01000000 <= context <= 0x02000000 - (4 if timed else 8) or not
            0x01000000 <= direction <= 0x01fffff8):
            continue
        needed = ({'write_0': index + 0x12, 'read_0': status + 0x10, 'write_2': write + 0x12, 'read_2': dataread + 0x10} if timed else {'write_0': index + 0xa,
            'read_0': status + 0xa, 'write_2': write + 0xa, 'read_2': dataread + 0xa})
        for c in _transport_clusters(image):
            if c['base'] not in ((0x02840000, 0x02c00000) if timed else (0x02c00000,)):
                continue
            sites = {f'{kind}_{port}': [int(s['offset']) for s in c['sites']
                     if s['kind'] == kind and s['port_offset'] == port]
                     for kind in ('read', 'write') for port in (0, 2)}
            if (any(value not in sites[key] for key, value in needed.items()) or any(block not in sites['write_2'] for block in blocks) or any(block not in c['block_write_offsets']
                for block in blocks) or len({x for values in sites.values() for x in values}) > 64):
                continue
            found.append({'family': 'ma5', 'grammar': 'ma5-readback-v1', 'static_status': 'candidate', 'reject_reason': None, 'protocol_status':
                'temporary-evidence-gated', 'base': c['base'], 'data_offset': 2, 'sites': sites, 'block_write_offsets': blocks, 'structural_evidence': {
                'transport_class': ('alternate-reset-readback-v1' if timed else 'alternate-direct-reset-readback-v1'), 'entries': {'check': check, 'read': read,
                'select': select, 'index': index, 'status': status, 'write': write, 'dataread': dataread, 'reset_check': resets[0]}, 'context_pointer': context,
                'context_word_offset': 0 if timed else 4, 'default_ranges':[[0xc0, 0xd0, 0x60],[0xd0, 0xe0, 0x3c]]}, 'ram_dependencies':[[context, 4 if timed
                else 8],[direction, 8]], 'nor_dependencies':[[check, 0x46],[read, 0x90],[select, 0x30],[empty, 0x40],[wait, 0x40],[resets[0] - 0x18, 0x24],[int(c['begin']),
                int(c['end']) - int(c['begin'])]] + ([[delay, 2]] if delay is not None else[]) +[[((off + 4) & ~3) + (struct.unpack_from('<H', image, off)[0] &
                255) * 4, 4] for off in (read + 4, select, *(ref[0] for ref in direction_refs))]})
    return found

def find_ma5_readback_candidate(image: bytes) -> dict[str, object]:
    """Find a closed reset/readback producer; never enable default admission."""
    image = bytes(image) if isinstance(image, bytearray) else image
    from . import _MA5_READBACK_SPANS, _ma5_alternate_readback, _ma5_readback_span, _ma5_readback_transport, _ma5_timed_transport
    rejected = {"family": "ma5", "grammar": "ma5-readback-v1", "static_status": "rejected", "reject_reason": "structural-none"}
    anchor = bytes.fromhex(_MA5_READBACK_SPANS["check"][0])[:10]
    accepted = []
    position = 0
    while (start := image.find(anchor, position)) >= 0:
        position = start + 1
        check = _ma5_readback_span(image, start, "check")
        if check is None or len(set(check["calls"])) != 1:
            continue
        entries = {"check": start, "read": check["calls"][0]}
        read = _ma5_readback_span(image, entries["read"], "read")
        if read is None:
            continue
        calls = read["calls"]
        entries.update(select=calls[0], empty=calls[1], write=calls[3], wait=calls[8], dataread=calls[11])
        if (calls[2] != calls[9] or calls[3:8] !=[entries["write"]] * 5 or calls[10] != entries["select"] or calls[12] != entries["select"]):
            continue
        select = _ma5_readback_span(image, entries["select"], "select")
        context = read["literals"][0]
        if (select is None or read["literals"] !=[context, context] or select["literals"] !=[context]):
            continue
        common = {"check": check, "read": read, "select": select}
        for candidate in (_ma5_readback_transport(image, common, entries, False), _ma5_readback_transport(image, common, entries, True), _ma5_timed_transport(image,
            common, entries)):
            if candidate is not None:
                accepted.append(candidate)
            if len(accepted) > 1:
                return {**rejected, "reject_reason": "structural-ambiguous"}
    if not accepted:
        accepted = _ma5_alternate_readback(image)
    return accepted[0] if len(accepted) == 1 else ({**rejected, 'reject_reason': 'structural-ambiguous'} if accepted else rejected)

def _ma2_callback_irq_profile(image: bytes) -> dict[str, object] | None:
    """Qualify the byte-count, halfword-mask callback dispatcher and route."""
    from . import hashlib, struct
    spans = ((0x159f18, 0x15a000, "287364f2dab8e1d2169acd81d5beda86c5820aeef57e2149d63d057b05d1ce6e"), (0x15a450, 0x15a4a0,
        "d4e31bfea65a89336f0213124adea06da51ec771fe5d0dcad54c3ba20eb856cf"), (0x15b8d4, 0x15b8e8,
        "dc406f62be4d9956b3b0bec293adf9c997ca879e40d0a9b92f549f1cc6b3ac28"), (0x83314, 0x83390,
        "6c4a076c943337e14cc0cc63afdfc0b70592f8b7d1e8fb36c54fd9e520a0ede0"))
    if any(len(image) < end or hashlib.sha256(image[start:end]).hexdigest() != digest for start, end, digest in spans):
        return None
    if len(image) < 0x1dcdd4:
        return None
    state = struct.unpack_from("<I", image, 0x159fb4)[0]
    callback = struct.unpack_from("<I", image, 0x15a49c)[0]
    words = list(struct.unpack_from("<7I", image, 0x1dcdb8))
    if (state != 0x0126964c or callback != 0x15adfd or words !=[0x03000624, 0x0300062c, 8, 0x01182c3e, 0x01182c42, 0x830f9, 0]):
        return None
    return {"status": "candidate", "profile": "byte-count-halfword-mask-v1", "descriptor_address": 0x01182d94, "words": words, "dispatcher_offset": 0x159f38,
        "callback_linkage": {"state_address": state + 0x14, "table_address": state + 8, "callback_offset": callback - 1, "data_read_offset": 0x1595c4},
        "index_restore_site": 0x159f2c}

def _thumb_short_branch_target(image: bytes, offset: int) -> int | None:
    from . import struct
    if offset < 0 or offset + 2 > len(image):
        return None
    op = struct.unpack_from("<H", image, offset)[0]
    if op & 0xF000 == 0xD000 and (op >> 8 & 15) < 14:
        delta = (op & 255) << 1
        if delta & 0x100:
            delta -= 0x200
        return offset + 4 + delta
    if op & 0xF800 == 0xE000:
        delta = (op & 0x7FF) << 1
        if delta & 0x800:
            delta -= 0x1000
        return offset + 4 + delta
    return None

def _thumb_condition(image: bytes, offset: int) -> int | None:
    from . import struct
    if offset < 0 or offset + 2 > len(image):
        return None
    op = struct.unpack_from("<H", image, offset)[0]
    if op & 0xF000 != 0xD000 or (op >> 8 & 15) >= 14:
        return None
    return op >> 8 & 15

def _thumb_bl_targets(image: bytes, start: int, length: int) -> list[int]:
    from . import facts_for
    stop = min(len(image) - 3, start + length)
    targets = []
    for offset in range(start, stop, 2):
        target = facts_for(image).thumb_call_target(offset)
        if target is not None:
            targets.append(target)
    return targets
