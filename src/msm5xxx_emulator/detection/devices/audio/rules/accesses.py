from __future__ import annotations
from msm5xxx_emulator.detection.fact_bodies import thumb_body
import re

_STRONG_MARKERS = {'ma2': (b'ma2main.c', b'ma2lib.c', b'ma2_smw', b'smwemu2'), 'ma3': (b'ma3main.c', b'ma3lib.c', b'ma3_smw', b'smwemu3', b'm3_emusmw3',
    b'ran out of ma3 contorl packets'), 'ma5': (b'ma5_smw', b'm5_emusmw5', b'smafmms5', b'devma5i_port.c', b'\\ma5\\src\\ma5_main.c',
    b'\\madriver\\impl\\ma5\\cmadriver5.cpp')}
_BASE_PREFIX = re.compile(rb"(?=(.[\x20-\x27].[\x00-\x07]))", re.DOTALL)
_THUMB_BL = re.compile(rb"(?=.[\xf0-\xf7].[\xf8-\xff])", re.DOTALL)
_MMIO_MIN = 0x02000000
_MMIO_MAX = 0x03000000
_SEARCH_BYTES = 64
_CLUSTER_GAP = 0x400
_MARKER_CHUNK = 1 << 20
_MARKER_OVERLAP = max(len(pattern) for patterns in _STRONG_MARKERS.values() for pattern in patterns) - 1

def _marker_families(image: bytes) -> list[str]:
    """Scan case-insensitively without copying a full large dump."""
    from . import _MARKER_CHUNK, _MARKER_OVERLAP, _STRONG_MARKERS
    found: set[str] = set()
    for start in range(0, len(image), _MARKER_CHUNK):
        chunk = image[max(0, start - _MARKER_OVERLAP):start + _MARKER_CHUNK].lower()
        for family, patterns in _STRONG_MARKERS.items():
            if (family not in found and any(pattern in chunk for pattern in patterns)):
                found.add(family)
    return sorted(found)

def _synthesized_base_accesses(image: bytes) -> list[dict[str, int | str]]:
    from . import _BASE_PREFIX, _MMIO_MAX, _MMIO_MIN, _SEARCH_BYTES, _thumb_writes_register, struct
    accesses: set[tuple[int, int, int, str]] = set()
    setups: list[tuple[int, int, int]] = []
    for match in _BASE_PREFIX.finditer(image):
        offset = match.start()
        if offset & 1:
            continue
        first, second = struct.unpack_from("<HH", image, offset)
        register = first >> 8 & 7
        if (first & 0xF800 != 0x2000 or second & 0xF800 or second & 7 != register or second >> 3 & 7 != register):
            continue
        base = (first & 0xFF) << (second >> 6 & 0x1F)
        if not _MMIO_MIN <= base < _MMIO_MAX:
            continue
        setups.append((offset, register, base))
    for setup_index, (offset, register, base) in enumerate(setups):
        stop = min(len(image) - 1, offset + _SEARCH_BYTES)
        for next_offset, next_register, _ in setups[setup_index + 1:]:
            if next_offset >= stop:
                break
            if next_register == register:
                stop = next_offset
                break
        for access_offset in range(offset + 4, stop, 2):
            instruction = struct.unpack_from("<H", image, access_offset)[0]
            opcode = instruction & 0xF800
            if (opcode in (0x7000, 0x7800) and instruction >> 3 & 7 == register):
                accesses.add((access_offset, base, instruction >> 6 & 0x1F, "write" if opcode == 0x7000 else "read",))
            if _thumb_writes_register(instruction, register):
                break
    return [{"offset": offset, "base": base, "port_offset": port, "kind": kind} for offset, base, port, kind in sorted(accesses)]

def _has_backedge(image: bytes, write: int) -> bool:
    """Recognize bounded Thumb byte-write loops without naming their purpose."""
    from . import struct
    for position in range(write + 2, min(len(image) - 1, write + 0x20), 2):
        word = struct.unpack_from("<H", image, position)[0]
        if word & 0xF000 == 0xD000 and word & 0x0F00 < 0x0E00:
            displacement = (word & 0xFF) << 1
            if displacement & 0x100:
                displacement -= 0x200
            target = position + 4 + displacement
        elif word & 0xF800 == 0xE000:
            displacement = (word & 0x7FF) << 1
            if displacement & 0x800:
                displacement -= 0x1000
            target = position + 4 + displacement
        else:
            continue
        if write - 0x10 <= target <= write:
            return True
    return False

def _transport_clusters(image: bytes) -> list[dict[str, object]]:
    from . import _CLUSTER_GAP, _has_backedge, _synthesized_base_accesses, defaultdict
    by_base: defaultdict[int, list[dict[str, int | str]]] = defaultdict(list)
    for access in _synthesized_base_accesses(image):
        by_base[int(access["base"])].append(access)
    result: list[dict[str, object]] = []
    for base, accesses in sorted(by_base.items()):
        clusters: list[list[dict[str, int | str]]] = []
        for access in accesses:
            if (not clusters or int(access["offset"]) - int(clusters[-1][-1]["offset"]) > _CLUSTER_GAP):
                clusters.append([])
            clusters[-1].append(access)
        for cluster in clusters:
            modes: defaultdict[int, set[str]] = defaultdict(set)
            writes: defaultdict[int, list[int]] = defaultdict(list)
            for access in cluster:
                port = int(access["port_offset"])
                modes[port].add(str(access["kind"]))
                if access["kind"] == "write":
                    writes[port].append(int(access["offset"]))
            data_ports = [port for port, kinds in modes.items() if port and kinds == {"read", "write"} and len(writes[port]) >= 2]
            indexed = modes.get(0) == {"read", "write"} and len(data_ports) == 1
            # Port 1 is optional: SCH-X350 never writes it (its +1 stores go to a RAM shadow).
            ma2 = (set(modes) in ({0, 2}, {0, 1, 2}) and modes[0] == {"write"} and modes.get(1, {"write"}) == { "write"} and modes[2] == {"read", "write"} and
                len(writes[0]) == 3 and len(writes[1]) <= 2 and len(writes[2]) == 2 and 6 <= len(cluster) <= 8)
            kinds = []
            if indexed:
                kinds.append("indexed-rw-v1")
            if ma2:
                kinds.append("ma2-command-v1")
            result.append({
                "base": base,
                "begin": int(cluster[0]["offset"]),
                "end": int(cluster[-1]["offset"]) + 2,
                "data_offset": data_ports[0] if indexed else 2 if ma2 else None,
                "grammars": kinds,
                "sites": cluster,
                "aperture_write_sites": {
                    f"write_{port}": [
                        int(access["offset"])
                        for access in accesses
                        if access["kind"] == "write"
                        and int(access["port_offset"]) == port
                    ]
                    for port in ((0, data_ports[0]) if indexed else ())
                },
                "block_write_offsets": [
                    offset
                    for port in data_ports
                    for offset in writes[port]
                    if _has_backedge(image, offset)
                ],
            })
    return result

def _command_status_candidates(image: bytes) -> list[dict[str, object]]:
    """Recognize the closed four-wrapper command/status/data call shape."""
    from . import _THUMB_BL, _transport_clusters, defaultdict, facts_for, struct
    if b"MMMD" not in image:
        return []
    result: list[dict[str, object]] = []
    for candidate in _transport_clusters(image):
        begin = int(candidate["begin"])
        sites = candidate["sites"]
        if (candidate["base"] != 0x02880000 or[(int(site["offset"]) - begin, int(site["port_offset"]), site["kind"]) for site in sites] !=[(0, 0, "write"), (0x10,
            0, "read"), (0x24, 2, "write"), (0x34, 2, "read"),]):
            continue
        delay_targets = { facts_for(image).thumb_call_target(begin + offset) for offset in (2, 0x12, 0x26, 0x36) }
        if len(delay_targets) != 1 or None in delay_targets:
            continue
        entries = { begin - 6: "write_0", begin + 0x0A: "read_0", begin + 0x1E: "write_2", begin + 0x2E: "read_2", }
        calls: defaultdict[str, int] = defaultdict(int)
        commands: set[int] = set()
        for match in _THUMB_BL.finditer(image):
            call = match.start()
            if call & 1:
                continue
            kind = entries.get(facts_for(image).thumb_call_target(call))
            if kind is None:
                continue
            calls[kind] += 1
            if kind == "write_0" and call >= 2:
                previous = struct.unpack_from("<H", image, call - 2)[0]
                if previous & 0xFF00 == 0x2000:
                    commands.add(previous & 0xFF)
        if (set(range(7)) <= commands and all(calls[kind] for kind in entries.values())):
            result.append({**candidate, "data_offset": 2})
    return result

def _repeated_status_candidates(image: bytes) -> list[dict[str, object]]:
    """Recognize eight consecutive bit0 tests with a closed accumulator."""
    from . import _THUMB_BL, _transport_clusters, facts_for, struct
    result = []
    for candidate in _transport_clusters(image):
        begin = int(candidate["begin"])
        if[(int(site["offset"]) - begin, site["port_offset"], site["kind"]) for site in candidate["sites"]] !=[(0, 0, "write"), (0x10, 0, "read"), (0x24, 2,
            "write"), (0x34, 2, "read")]:
            continue
        delays = {facts_for(image).thumb_call_target(begin + offset) for offset in (2, 0x12, 0x26, 0x36)}
        if len(delays) != 1 or None in delays:
            continue
        reader = begin + 0x0A
        calls = [match.start() for match in _THUMB_BL.finditer(image) if not match.start() & 1 and facts_for(image).thumb_call_target(match.start()) == reader]
        consumers = []
        for first in calls:
            group = [call for call in calls if first <= call <= first + 0x50]
            if len(group) != 8 or first < 14 or first + 0x78 > len(image):
                continue
            if struct.unpack_from("<H", image, first - 14)[0] != 0xB5F0:
                continue
            offsets = (0, 0xA, 0x16, 0x22, 0x2E, 0x3A, 0x46, 0x50)
            if[call - first for call in group] != list(offsets):
                continue
            # Carry from bit0 must set its corresponding accumulator bit.
            tails = ("400800d30127", "400801d302200743", "400801d304200743", "400801d308200743", "400801d310200743", "400801d320200743", "400800d32f43",
                "400800d33743",)
            if image[first - 10:first] != bytes.fromhex("00204025802620700027"):
                continue
            if not all(image[call + 4:call + 4 + len(tail)] == tail for call, tail in zip(group, map(bytes.fromhex, tails))):
                continue
            if struct.unpack_from("<H", image, first + 0x74)[0] != 0x2FFF:
                continue
            consumers.append(first - 14)
        if consumers:
            result.append({"base": candidate["base"], "data_offset": 2, "status_read_site": begin + 0x10, "status_consumers": consumers, "status_mask": 1,
                "consecutive_samples": 8})
    return result

_SEQUENCE_SPANS = { 'clear': (108, (4, 10, 14, 20, 28, 78), '9675f126bfdc281bbfe015ddfa354405c15c8086cc6a2d40b7a0f7f83d1f3681', 24, '03211448'), 'timer': (170,
    (156,), '459dd739b526e9cb48eb538606e1a561d2a78bd437a3e402c210ac3de7544a0f', 0,
    'fcb51c1c0126f6430328079d07dc012d05dc012c03dc01278740fb0803d0301cfcbc08bc1847214bdb681e1c3e4002d00220c043f4e7061c5006400ea2006d002a43022e16da9b0712d1522400ab1c7082245c708023194300ab99705421d970822119715871802010439871072114e0002015e00121012c00d000210906090e572400ab1c7082245c7098700a43101c8023184300abd87004216846'),
    'timer-stop': (76, (70,), 'bb28418b369c000850c5138c6684e527ac92f4128d2f819db1c5b22c313eb482', 0,
    '98b5021c0020871e022a03dc01219140cb0803d0381c98bc08bc18470b4f0c1cfb689c4302d00020c043f4e75940f960022af0d1582000ab1870822058708020987003216846'), 'sequence':
    (86, (76,), 'f9930cb70961a6008be5dfebd2862dfd265b2231bc66db2dc45012af8f468d4a', 0,
    '9cb501228240930804d00120c0439cbc08bc1847104f7b6a1c1c144002d00220c043f4e71a437a62002812d15e2000ab187082205870c8114006400e98704806400ed8708420187105216846'),
    'sender': (112, (8, 16, 36, 54, 72, 88, 104), '617d12df74a591809f79c9702999c2a17da63c118e1d821291da11398adab7c4', 20, '041c002800da11e0402403e038780137'),
    'init': (36, (2, 8, 14, 20, 26, 32), 'ac98e817387e02c577df3c97cb83ee993067d048f694a9af04ffc0a7bfda1f19', 0, '0420'), 'alternate-init': (36, (2, 8, 14, 20,
    26, 32), 'd5c5308f7b346e69e34da2681d2fe8bdb6559a80338a33e947f3efb17f7c7dea', 0, '0420'), 'reset': (22, (2, 8, 12, 18),
    '37281a886463fd17c7c82483a949b897ac52d446f9640e4f1bd2b50389878055', 0, '0420'), 'ready': (138, (14, 24, 36, 48, 60, 72, 84, 94),
    'd663210c999d59265bb0474f206661ecfda6b43f8a6585bce6dc86dc83eb0fa1', 98, '400800d337432078013020700006000e642805dd00202070c043f0bc08bc1847ff2fc2d10020f8e7'),
    'empty': (224, (4, 14, 26, 38, 50, 62, 78, 94, 120, 130, 142, 154, 166, 178, 188, 198), '7d272772b7cd90bbe51371d0ce1d349b00777e275634db412a9cec5c26024b32',
    98, '022318408026002800d03743002f34d0ff2f2ed00027'), 'wrapper': (72, (8, 24, 44, 60), 'bad45733e7e888201b28d4e83ab1a6a693a60797beb084f822a0ea54b91deae2', 0,
    '4121c90400b50870'), }

def _sequence_span(image: bytes, start: int, role: str) -> list[int] | None:
    from . import _SEQUENCE_SPANS, facts_for
    length, calls, digest, _, _ = _SEQUENCE_SPANS[role]
    if (start < 0 or start & 1 or start + length > len(image) or role in ('sender', 'sequence', 'timer', 'timer-stop', 'ready', 'clear') and start & 3):
        return None
    body = thumb_body(facts_for(image), start, length, call_offsets=calls, literal_offsets=())
    if body is None or body.sha256 != digest or any(target & 1 or not 0 <= target <= len(image) - 2 for _, target in body.calls):
        return None
    return [target for _, target in body.calls]

def _unique_sequence_span(image: bytes, role: str) -> int | None:
    from . import _SEQUENCE_SPANS, _sequence_span
    _, _, _, offset, anchor = _SEQUENCE_SPANS[role]
    matches = []
    start = 0
    anchor = bytes.fromhex(anchor)
    while (position := image.find(anchor, start)) >= 0:
        candidate = position - offset
        if _sequence_span(image, candidate, role) is not None:
            matches.append(candidate)
            if len(matches) > 1:
                return None
        start = position + 1
    return matches[0] if matches else None

def _sequence_clear_profile(image: bytes, entry: int, sender: int, delay: int) -> dict[str, object]:
    from . import _sequence_span, _unique_sequence_span, find_linker_layout, struct
    unavailable = {"control_clear_status": "unavailable", "control_clear_reject_reason": "clear-unmatched-or-ambiguous"}
    clear = _unique_sequence_span(image, "clear")
    if clear is None:
        return unavailable
    if _sequence_span(image, clear, "clear") !=[entry, entry + 0x24, delay, entry + 0x24, sender, entry]:
        return {**unavailable, "control_clear_reject_reason": "clear-linkage-mismatch"}
    if clear + 112 > len(image):
        return {**unavailable, "control_clear_reject_reason": "clear-literal-truncated"}
    payload = struct.unpack_from("<I", image, clear + 108)[0]
    state = struct.unpack_from("<I", image, sender + 112)[0]
    if payload != state + 0x16:
        return {**unavailable, "control_clear_reject_reason": "clear-state-mismatch"}
    layout = find_linker_layout(image, required_span=(payload, 3))
    if (layout is None or not layout.data_target <= payload <= layout.data_target + layout.data_size - 3):
        return {**unavailable, "control_clear_reject_reason": "clear-payload-not-copied"}
    source = layout.data_source + payload - layout.data_target
    if image[source:source + 3] != b"\x60\x82\x84":
        return {**unavailable, "control_clear_reject_reason": "clear-payload-mismatch"}
    return {"control_clear_status": "accepted", "control_clear_reject_reason": None, "control_clear_producer": clear, "control_clear_payload": payload,
        "nor_dependencies":[[clear, 108],[clear + 108, 4],[layout.table_offset, 20],[source, 3]], "ram_dependencies":[[payload + i, 1] for i in range(3)]}

def _sequence_status_profile(image: bytes, candidate: dict[str, object]) -> dict[str, object] | None:
    from . import _sequence_clear_profile, _sequence_span, _unique_sequence_span, struct
    if candidate.get("base") != 0x02080000:
        return None
    begin = int(candidate["status_read_site"]) - 0x10
    entry = begin - 6
    wrapper = _sequence_span(image, entry, "wrapper")
    if (wrapper is None or len(set(wrapper)) != 1 or image[wrapper[0]:wrapper[0] + 2] != b"\x70\x47"):
        return None
    sequence = _unique_sequence_span(image, "sequence")
    sender = _unique_sequence_span(image, "sender")
    timer = _unique_sequence_span(image, "timer")
    timer_stop = _unique_sequence_span(image, "timer-stop")
    init = _unique_sequence_span(image, "init")
    consumers = candidate.get("status_consumers")
    if (sequence is None or sender is None or init is None or timer is None or timer_stop is None or not isinstance(consumers, list) or len(consumers) != 1):
        return None
    ready = int(consumers[0])
    reader = entry + 0x10
    data_writer = entry + 0x24
    pulse_targets = [entry, data_writer, wrapper[0], data_writer]
    if (_sequence_span(image, timer, "timer") !=[sender] or _sequence_span(image, timer_stop, "timer-stop") !=[sender] or _sequence_span(image, sequence,
        "sequence") !=[sender] or _sequence_span(image, sender, "sender") !=[entry, ready, data_writer, ready, entry, data_writer, entry] or _sequence_span(image,
        ready, "ready") !=[reader] * 8 or _sequence_span(image, ready - 0x112, "empty") !=[reader] * 16 or _sequence_span(image, init, "init") !=[entry,
        data_writer] * 3 or _sequence_span(image, init + 0x5e, "alternate-init") !=[entry, data_writer] * 3 or _sequence_span(image, init + 0x3c, "reset") !=
        pulse_targets or _sequence_span(image, init + 0x9a, "reset") != pulse_targets):
        return None
    literals = [sender + 112, sequence + 88, timer + 172, timer_stop + 76, ready + 140]
    if any(offset + 4 > len(image) for offset in literals):
        return None
    if len({struct.unpack_from("<I", image, offset)[0] for offset in literals[1:4]}) != 1:
        return None
    profile = { "family": "opaque", "grammar": "repeated-bit-sequence-v1", "static_status": "accepted", "reject_reason": None, "protocol_status":
        "temporary-evidence-gated", "renderer_status": "unavailable", "requires_runtime_reset": True, "base": 0x02080000, "data_offset": 2, "begin": begin,
        "block_write_offsets":[], "sites": {"write_0":[begin], "read_0":[begin + 0x10], "write_2":[begin + 0x24], "read_2":[begin + 0x34]}, "sequence_producer":
        sequence, "immediate_sender": sender, "timer_producer": timer, "timer_stop_producer": timer_stop, "status_consumers":[ready], "reset_producer": init,
        "nor_dependencies":[[wrapper[0], 2]] +[[offset, 4] for offset in literals], "ram_dependencies":[[struct.unpack_from("<I", image, offset)[0], size] for
        offset, size in ((literals[0], 8), (literals[1], 40), (literals[4], 1))], }
    clear = _sequence_clear_profile(image, entry, sender, wrapper[0])
    for key in ("nor_dependencies", "ram_dependencies"):
        profile[key].extend(clear.pop(key,[]))
    profile.update(clear)
    return profile

_MA5_READBACK_SPANS = { 'check': ('90b5c0270024e443381c00000000002811db0006000e60280cd10137d02ff3d3d027381c00000000002804db0006000e3c2803d0201c90bc08bc18470137e02fefd30020f7e7',
    (10, 36), (), None), 'read': ('f0b5071c004809260068f601801981780131817003200000000000000000041c002805da00000000201cf0bc08bc18478025802f02d22f43381c13e0fc097806400e01239b039f4204d2000000002c43201c07e0000000006006400e00000000b80b28430006000e00000000802000000000402000000000071c002802da0000000011e041200000000000000000071c004800688119887801380006000e887002d1802000000000381cbee7',
    (22, 26, 36, 74, 84, 92, 104, 110, 116, 126, 134, 138, 164), (4, 144), None), 'select': ('004a80b511680923db01c9180f7808701168c9184978012901d14006400e00000000381c80bc08bc1847',
    (30,), (0,), None), 'wait': ('f0b5004d041c00262e8000000000071c2888004b013028802888984209dd0420c0432e80000000000420c043f0bc08bc1847000000002740e7d00020f6e7',
    (10, 36, 50), (2, 18), None), 'empty': ('b0b5004c0025258000000000071c2088004b013020802088984209dd0420c0432580000000000420c043b0bc08bc1847000000007808e7d30020f6e7',
    (8, 34, 48), (2, 16), None), 'index': ('80b5071c0000000000490020486000000000077080bc08bc1847', (4,), (8,), 14), 'status': ('00b50000000000490120486000000000007808bc1847',
    (2,), (6,), 12), 'write': ('80b5071c0000000000490020486000000000877080bc08bc1847', (4,), (8,), 14), 'block': ('b0b5041c0f1c0ed0000000000020004900000000486004e020780134a87000000000013ff8d2b0bc08bc1847',
    (8, 30), (14,), 16), 'dataread': ('00b50000000000490120486000000000807808bc1847', (2,), (6,), 12), "local_wait": ('90b5041c002700000000ff231a339f4208dd0420c043000000000420c04390bc08bc184701372040edd00020f7e7',
    (6, 22), (), None), "local_empty": ('80b5002700000000004b9f4208dd0420c043000000000420c04380bc08bc184701374008eed30020f7e7', (4, 18), (8,), None),
    "local_index": ('004b80b41f680121002f004a00d1117011700021196000000000087080bc7047', (), (0, 10), 22), "local_status": ('004a012013680049002b03d10870087008700870087010600000000000787047',
    (), (0, 6), 24), "local_write": ('004b80b41f680121002f004a00d111701170002119600049087080bc7047', (), (0, 10, 22), None), "local_dataread": ('004a012013680049002b03d1087008700870087008701060004800787047',
    (), (0, 6, 24), None), "local_block": ('002906d0004a02e00378013013700139fad27047', (), (4,), None), 'timed_wait': ('90b5041c002700000000391cff232d330137994208dd0420c043000000000420c04390bc08bc18472040ecd00020f8e7',
    (6, 26), (), None), 'timed_empty': ('80b5002700000000391cff232d330137994208dd0420c043000000000420c04380bc08bc18474008ecd30020f8e7', (4, 24), (), None),
    'timed_index': ('90b5004c071c2068004980000858000000000020206000000000077090bc08bc1847', (14,), (2, 8), 22), 'timed_status': ('80b5004f0049386880000858000000000120386000000000007880bc08bc1847',
    (12,), (2, 4), 20), 'timed_write': ('90b5004c071c2068004980000858000000000020206000000000077190bc08bc1847', (14,), (2, 8), 22), 'timed_block': ('b0b5071c0c1c13d0004d004928688000085800000000002028600000000005e0387801372871e62000000000013cf7d2b0bc08bc1847',
    (18, 40), (8, 10), 26), 'timed_dataread': ('80b5004f0049386880000858000000000120386000000000007980bc08bc1847', (12,), (2, 4), 20), 'timed_delay': ('004b00b5984208d3011c7d20c00000000000012803d80000000008bc1847022802d800000000f6e700000000f5e7',
    (14, 22, 34, 40), (0,), None), }
