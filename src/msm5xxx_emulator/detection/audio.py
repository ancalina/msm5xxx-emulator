"""Evidence-gated Yamaha audio transport detection."""
from __future__ import annotations

from collections import defaultdict
from bisect import bisect_right
import hashlib
import re
import struct

from .arm import _thumb_writes_register, thumb_bl_target, thumb_literal_value
from .audio_irq import find_audio_irq_candidate
from .memory_layout import find_linker_layout


_STRONG_MARKERS = {
    "ma2": (b"ma2main.c", b"ma2lib.c", b"ma2_smw", b"smwemu2"),
    "ma3": (
        b"ma3main.c", b"ma3lib.c", b"ma3_smw", b"smwemu3",
        b"m3_emusmw3", b"ran out of ma3 contorl packets",
    ),
    "ma5": (
        b"ma5_smw", b"m5_emusmw5", b"smafmms5", b"devma5i_port.c",
        b"\\ma5\\src\\ma5_main.c", b"\\madriver\\impl\\ma5\\cmadriver5.cpp",
    ),
}
_BASE_PREFIX = re.compile(rb"(?=(.[\x20-\x27].[\x00-\x07]))", re.DOTALL)
_THUMB_BL = re.compile(rb"(?=.[\xf0-\xf7].[\xf8-\xff])", re.DOTALL)
_MMIO_MIN = 0x02000000
_MMIO_MAX = 0x03000000
_SEARCH_BYTES = 64
_CLUSTER_GAP = 0x400
_MARKER_CHUNK = 1 << 20
_MARKER_OVERLAP = max(
    len(pattern)
    for patterns in _STRONG_MARKERS.values()
    for pattern in patterns
) - 1


def _marker_families(image: bytes) -> list[str]:
    """Scan case-insensitively without copying a full large dump."""
    found: set[str] = set()
    for start in range(0, len(image), _MARKER_CHUNK):
        chunk = image[
            max(0, start - _MARKER_OVERLAP):start + _MARKER_CHUNK
        ].lower()
        for family, patterns in _STRONG_MARKERS.items():
            if (family not in found
                    and any(pattern in chunk for pattern in patterns)):
                found.add(family)
    return sorted(found)


def _synthesized_base_accesses(
        image: bytes) -> list[dict[str, int | str]]:
    accesses: set[tuple[int, int, int, str]] = set()
    setups: list[tuple[int, int, int]] = []
    for match in _BASE_PREFIX.finditer(image):
        offset = match.start()
        if offset & 1:
            continue
        first, second = struct.unpack_from("<HH", image, offset)
        register = first >> 8 & 7
        if (first & 0xF800 != 0x2000
                or second & 0xF800
                or second & 7 != register
                or second >> 3 & 7 != register):
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
            if (opcode in (0x7000, 0x7800)
                    and instruction >> 3 & 7 == register):
                accesses.add((
                    access_offset, base, instruction >> 6 & 0x1F,
                    "write" if opcode == 0x7000 else "read",
                ))
            if _thumb_writes_register(instruction, register):
                break
    return [
        {"offset": offset, "base": base, "port_offset": port, "kind": kind}
        for offset, base, port, kind in sorted(accesses)
    ]


def _has_backedge(image: bytes, write: int) -> bool:
    """Recognize bounded Thumb byte-write loops without naming their purpose."""
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
    by_base: defaultdict[int, list[dict[str, int | str]]] = defaultdict(list)
    for access in _synthesized_base_accesses(image):
        by_base[int(access["base"])].append(access)
    result: list[dict[str, object]] = []
    for base, accesses in sorted(by_base.items()):
        clusters: list[list[dict[str, int | str]]] = []
        for access in accesses:
            if (not clusters
                    or int(access["offset"])
                    - int(clusters[-1][-1]["offset"]) > _CLUSTER_GAP):
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
            data_ports = [
                port for port, kinds in modes.items()
                if port and kinds == {"read", "write"}
                and len(writes[port]) >= 2
            ]
            indexed = modes.get(0) == {"read", "write"} and len(data_ports) == 1
            # Port 1 is optional: SCH-X350 never writes it (its +1 stores go to a RAM shadow).
            ma2 = (
                set(modes) in ({0, 2}, {0, 1, 2})
                and modes[0] == {"write"}
                and modes.get(1, {"write"}) == {"write"}
                and modes[2] == {"read", "write"}
                and len(writes[0]) == 3
                and len(writes[1]) <= 2
                and len(writes[2]) == 2
                and 6 <= len(cluster) <= 8
            )
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
    if b"MMMD" not in image:
        return []
    result: list[dict[str, object]] = []
    for candidate in _transport_clusters(image):
        begin = int(candidate["begin"])
        sites = candidate["sites"]
        if (candidate["base"] != 0x02880000
                or [(int(site["offset"]) - begin,
                     int(site["port_offset"]), site["kind"])
                    for site in sites] != [
                        (0, 0, "write"), (0x10, 0, "read"),
                        (0x24, 2, "write"), (0x34, 2, "read"),
                    ]):
            continue
        delay_targets = {
            thumb_bl_target(image, begin + offset)
            for offset in (2, 0x12, 0x26, 0x36)
        }
        if len(delay_targets) != 1 or None in delay_targets:
            continue
        entries = {
            begin - 6: "write_0", begin + 0x0A: "read_0",
            begin + 0x1E: "write_2", begin + 0x2E: "read_2",
        }
        calls: defaultdict[str, int] = defaultdict(int)
        commands: set[int] = set()
        for match in _THUMB_BL.finditer(image):
            call = match.start()
            if call & 1:
                continue
            kind = entries.get(thumb_bl_target(image, call))
            if kind is None:
                continue
            calls[kind] += 1
            if kind == "write_0" and call >= 2:
                previous = struct.unpack_from("<H", image, call - 2)[0]
                if previous & 0xFF00 == 0x2000:
                    commands.add(previous & 0xFF)
        if (set(range(7)) <= commands
                and all(calls[kind] for kind in entries.values())):
            result.append({**candidate, "data_offset": 2})
    return result


def _repeated_status_candidates(image: bytes) -> list[dict[str, object]]:
    """Recognize eight consecutive bit0 tests with a closed accumulator."""
    result = []
    for candidate in _transport_clusters(image):
        begin = int(candidate["begin"])
        if [(int(site["offset"]) - begin, site["port_offset"], site["kind"])
                for site in candidate["sites"]] != [
                    (0, 0, "write"), (0x10, 0, "read"),
                    (0x24, 2, "write"), (0x34, 2, "read")]:
            continue
        delays = {thumb_bl_target(image, begin + offset)
                  for offset in (2, 0x12, 0x26, 0x36)}
        if len(delays) != 1 or None in delays:
            continue
        reader = begin + 0x0A
        calls = [match.start() for match in _THUMB_BL.finditer(image)
                 if not match.start() & 1
                 and thumb_bl_target(image, match.start()) == reader]
        consumers = []
        for first in calls:
            group = [call for call in calls if first <= call <= first + 0x50]
            if len(group) != 8 or first < 14 or first + 0x78 > len(image):
                continue
            if struct.unpack_from("<H", image, first - 14)[0] != 0xB5F0:
                continue
            offsets = (0, 0xA, 0x16, 0x22, 0x2E, 0x3A, 0x46, 0x50)
            if [call - first for call in group] != list(offsets):
                continue
            # Carry from bit0 must set its corresponding accumulator bit.
            tails = (
                "400800d30127", "400801d302200743",
                "400801d304200743", "400801d308200743",
                "400801d310200743", "400801d320200743",
                "400800d32f43", "400800d33743",
            )
            if image[first - 10:first] != bytes.fromhex("00204025802620700027"):
                continue
            if not all(image[call + 4:call + 4 + len(tail)] == tail
                       for call, tail in zip(group, map(bytes.fromhex, tails))):
                continue
            if struct.unpack_from("<H", image, first + 0x74)[0] != 0x2FFF:
                continue
            consumers.append(first - 14)
        if consumers:
            result.append({"base": candidate["base"], "data_offset": 2,
                           "status_read_site": begin + 0x10,
                           "status_consumers": consumers,
                           "status_mask": 1, "consecutive_samples": 8})
    return result


# shortcut: exact normalized protocol class; widen after independent call-shape proof.
_SEQUENCE_SPANS = {
    'clear': (108, (4, 10, 14, 20, 28, 78), '9675f126bfdc281bbfe015ddfa354405c15c8086cc6a2d40b7a0f7f83d1f3681', 24, '03211448'),
    'timer': (170, (156,), '459dd739b526e9cb48eb538606e1a561d2a78bd437a3e402c210ac3de7544a0f', 0, 'fcb51c1c0126f6430328079d07dc012d05dc012c03dc01278740fb0803d0301cfcbc08bc1847214bdb681e1c3e4002d00220c043f4e7061c5006400ea2006d002a43022e16da9b0712d1522400ab1c7082245c708023194300ab99705421d970822119715871802010439871072114e0002015e00121012c00d000210906090e572400ab1c7082245c7098700a43101c8023184300abd87004216846'),
    'timer-stop': (76, (70,), 'bb28418b369c000850c5138c6684e527ac92f4128d2f819db1c5b22c313eb482', 0, '98b5021c0020871e022a03dc01219140cb0803d0381c98bc08bc18470b4f0c1cfb689c4302d00020c043f4e75940f960022af0d1582000ab1870822058708020987003216846'),
    'sequence': (86, (76,), 'f9930cb70961a6008be5dfebd2862dfd265b2231bc66db2dc45012af8f468d4a', 0, '9cb501228240930804d00120c0439cbc08bc1847104f7b6a1c1c144002d00220c043f4e71a437a62002812d15e2000ab187082205870c8114006400e98704806400ed8708420187105216846'),
    'sender': (112, (8, 16, 36, 54, 72, 88, 104), '617d12df74a591809f79c9702999c2a17da63c118e1d821291da11398adab7c4', 20, '041c002800da11e0402403e038780137'),
    'init': (36, (2, 8, 14, 20, 26, 32), 'ac98e817387e02c577df3c97cb83ee993067d048f694a9af04ffc0a7bfda1f19', 0, '0420'),
    'alternate-init': (36, (2, 8, 14, 20, 26, 32), 'd5c5308f7b346e69e34da2681d2fe8bdb6559a80338a33e947f3efb17f7c7dea', 0, '0420'),
    'reset': (22, (2, 8, 12, 18), '37281a886463fd17c7c82483a949b897ac52d446f9640e4f1bd2b50389878055', 0, '0420'),
    'ready': (138, (14, 24, 36, 48, 60, 72, 84, 94), 'd663210c999d59265bb0474f206661ecfda6b43f8a6585bce6dc86dc83eb0fa1', 98, '400800d337432078013020700006000e642805dd00202070c043f0bc08bc1847ff2fc2d10020f8e7'),
    'empty': (224, (4, 14, 26, 38, 50, 62, 78, 94, 120, 130, 142, 154, 166, 178, 188, 198), '7d272772b7cd90bbe51371d0ce1d349b00777e275634db412a9cec5c26024b32', 98, '022318408026002800d03743002f34d0ff2f2ed00027'),
    'wrapper': (72, (8, 24, 44, 60), 'bad45733e7e888201b28d4e83ab1a6a693a60797beb084f822a0ea54b91deae2', 0, '4121c90400b50870'),
}


def _sequence_span(image: bytes, start: int, role: str) -> list[int] | None:
    length, calls, digest, _, _ = _SEQUENCE_SPANS[role]
    if (start < 0 or start & 1 or start + length > len(image)
            or (role in ("sender", "sequence", "timer", "timer-stop", "ready", "clear")
                and start & 3)):
        return None
    code = bytearray(image[start:start + length])
    targets = []
    for offset in calls:
        target = thumb_bl_target(image, start + offset)
        if target is None or target & 1 or not 0 <= target <= len(image) - 2:
            return None
        targets.append(target)
        code[offset:offset + 4] = b"\0" * 4
    return targets if hashlib.sha256(code).hexdigest() == digest else None


def _unique_sequence_span(image: bytes, role: str) -> int | None:
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


def _sequence_clear_profile(image: bytes, entry: int, sender: int,
                            delay: int) -> dict[str, object]:
    unavailable = {"control_clear_status": "unavailable",
                   "control_clear_reject_reason": "clear-unmatched-or-ambiguous"}
    clear = _unique_sequence_span(image, "clear")
    if clear is None:
        return unavailable
    if _sequence_span(image, clear, "clear") != [
            entry, entry + 0x24, delay, entry + 0x24, sender, entry]:
        return {**unavailable, "control_clear_reject_reason": "clear-linkage-mismatch"}
    if clear + 112 > len(image):
        return {**unavailable, "control_clear_reject_reason": "clear-literal-truncated"}
    payload = struct.unpack_from("<I", image, clear + 108)[0]
    state = struct.unpack_from("<I", image, sender + 112)[0]
    if payload != state + 0x16:
        return {**unavailable, "control_clear_reject_reason": "clear-state-mismatch"}
    layout = find_linker_layout(image, required_span=(payload, 3))
    if (layout is None or not layout.data_target <= payload
            <= layout.data_target + layout.data_size - 3):
        return {**unavailable, "control_clear_reject_reason": "clear-payload-not-copied"}
    source = layout.data_source + payload - layout.data_target
    if image[source:source + 3] != b"\x60\x82\x84":
        return {**unavailable, "control_clear_reject_reason": "clear-payload-mismatch"}
    return {"control_clear_status": "accepted", "control_clear_reject_reason": None,
            "control_clear_producer": clear, "control_clear_payload": payload,
            "nor_dependencies": [[clear, 108], [clear + 108, 4],
                                 [layout.table_offset, 20], [source, 3]],
            "ram_dependencies": [[payload + i, 1] for i in range(3)]}


def _sequence_status_profile(image: bytes,
                             candidate: dict[str, object]) -> dict[str, object] | None:
    if candidate.get("base") != 0x02080000:
        return None
    begin = int(candidate["status_read_site"]) - 0x10
    entry = begin - 6
    wrapper = _sequence_span(image, entry, "wrapper")
    if (wrapper is None or len(set(wrapper)) != 1
            or image[wrapper[0]:wrapper[0] + 2] != b"\x70\x47"):
        return None
    sequence = _unique_sequence_span(image, "sequence")
    sender = _unique_sequence_span(image, "sender")
    timer = _unique_sequence_span(image, "timer")
    timer_stop = _unique_sequence_span(image, "timer-stop")
    init = _unique_sequence_span(image, "init")
    consumers = candidate.get("status_consumers")
    if (sequence is None or sender is None or init is None
            or timer is None or timer_stop is None
            or not isinstance(consumers, list) or len(consumers) != 1):
        return None
    ready = int(consumers[0])
    reader = entry + 0x10
    data_writer = entry + 0x24
    pulse_targets = [entry, data_writer, wrapper[0], data_writer]
    if (_sequence_span(image, timer, "timer") != [sender]
            or _sequence_span(image, timer_stop, "timer-stop") != [sender]
            or _sequence_span(image, sequence, "sequence") != [sender]
            or _sequence_span(image, sender, "sender") !=
            [entry, ready, data_writer, ready, entry, data_writer, entry]
            or _sequence_span(image, ready, "ready") != [reader] * 8
            or _sequence_span(image, ready - 0x112, "empty") != [reader] * 16
            or _sequence_span(image, init, "init") != [entry, data_writer] * 3
            or _sequence_span(image, init + 0x5e, "alternate-init") !=
            [entry, data_writer] * 3
            or _sequence_span(image, init + 0x3c, "reset") != pulse_targets
            or _sequence_span(image, init + 0x9a, "reset") != pulse_targets):
        return None
    literals = [sender + 112, sequence + 88, timer + 172, timer_stop + 76, ready + 140]
    if any(offset + 4 > len(image) for offset in literals):
        return None
    if len({struct.unpack_from("<I", image, offset)[0] for offset in literals[1:4]}) != 1:
        return None
    profile = {
        "family": "opaque", "grammar": "repeated-bit-sequence-v1",
        "static_status": "accepted", "reject_reason": None,
        "protocol_status": "temporary-evidence-gated",
        "renderer_status": "unavailable", "requires_runtime_reset": True,
        "base": 0x02080000, "data_offset": 2, "begin": begin,
        "block_write_offsets": [],
        "sites": {"write_0": [begin], "read_0": [begin + 0x10],
                  "write_2": [begin + 0x24], "read_2": [begin + 0x34]},
        "sequence_producer": sequence, "immediate_sender": sender,
        "timer_producer": timer, "timer_stop_producer": timer_stop,
        "status_consumers": [ready], "reset_producer": init,
        "nor_dependencies": [[wrapper[0], 2]] + [[offset, 4] for offset in literals],
        "ram_dependencies": [[struct.unpack_from("<I", image, offset)[0], size]
                             for offset, size in ((literals[0], 8), (literals[1], 40), (literals[4], 1))],
    }
    clear = _sequence_clear_profile(image, entry, sender, wrapper[0])
    for key in ("nor_dependencies", "ram_dependencies"):
        profile[key].extend(clear.pop(key, []))
    profile.update(clear)
    return profile


# shortcut: one closed producer shape; widen only after independent linkage proof.
_MA5_READBACK_SPANS = {
    'check': ('90b5c0270024e443381c00000000002811db0006000e60280cd10137d02ff3d3d027381c00000000002804db0006000e3c2803d0201c90bc08bc18470137e02fefd30020f7e7', (10, 36), (), None),
    'read': ('f0b5071c004809260068f601801981780131817003200000000000000000041c002805da00000000201cf0bc08bc18478025802f02d22f43381c13e0fc097806400e01239b039f4204d2000000002c43201c07e0000000006006400e00000000b80b28430006000e00000000802000000000402000000000071c002802da0000000011e041200000000000000000071c004800688119887801380006000e887002d1802000000000381cbee7', (22, 26, 36, 74, 84, 92, 104, 110, 116, 126, 134, 138, 164), (4, 144), None),
    'select': ('004a80b511680923db01c9180f7808701168c9184978012901d14006400e00000000381c80bc08bc1847', (30,), (0,), None),
    'wait': ('f0b5004d041c00262e8000000000071c2888004b013028802888984209dd0420c0432e80000000000420c043f0bc08bc1847000000002740e7d00020f6e7', (10, 36, 50), (2, 18), None),
    'empty': ('b0b5004c0025258000000000071c2088004b013020802088984209dd0420c0432580000000000420c043b0bc08bc1847000000007808e7d30020f6e7', (8, 34, 48), (2, 16), None),
    'index': ('80b5071c0000000000490020486000000000077080bc08bc1847', (4,), (8,), 14),
    'status': ('00b50000000000490120486000000000007808bc1847', (2,), (6,), 12),
    'write': ('80b5071c0000000000490020486000000000877080bc08bc1847', (4,), (8,), 14),
    'block': ('b0b5041c0f1c0ed0000000000020004900000000486004e020780134a87000000000013ff8d2b0bc08bc1847', (8, 30), (14,), 16),
    'dataread': ('00b50000000000490120486000000000807808bc1847', (2,), (6,), 12),
    "local_wait": ('90b5041c002700000000ff231a339f4208dd0420c043000000000420c04390bc08bc184701372040edd00020f7e7', (6, 22), (), None),
    "local_empty": ('80b5002700000000004b9f4208dd0420c043000000000420c04380bc08bc184701374008eed30020f7e7', (4, 18), (8,), None),
    "local_index": ('004b80b41f680121002f004a00d1117011700021196000000000087080bc7047', (), (0, 10), 22),
    "local_status": ('004a012013680049002b03d10870087008700870087010600000000000787047', (), (0, 6), 24),
    "local_write": ('004b80b41f680121002f004a00d111701170002119600049087080bc7047', (), (0, 10, 22), None),
    "local_dataread": ('004a012013680049002b03d1087008700870087008701060004800787047', (), (0, 6, 24), None),
    "local_block": ('002906d0004a02e00378013013700139fad27047', (), (4,), None),
    'timed_wait': ('90b5041c002700000000391cff232d330137994208dd0420c043000000000420c04390bc08bc18472040ecd00020f8e7', (6, 26), (), None),
    'timed_empty': ('80b5002700000000391cff232d330137994208dd0420c043000000000420c04380bc08bc18474008ecd30020f8e7', (4, 24), (), None),
    'timed_index': ('90b5004c071c2068004980000858000000000020206000000000077090bc08bc1847', (14,), (2, 8), 22),
    'timed_status': ('80b5004f0049386880000858000000000120386000000000007880bc08bc1847', (12,), (2, 4), 20),
    'timed_write': ('90b5004c071c2068004980000858000000000020206000000000077190bc08bc1847', (14,), (2, 8), 22),
    'timed_block': ('b0b5071c0c1c13d0004d004928688000085800000000002028600000000005e0387801372871e62000000000013cf7d2b0bc08bc1847', (18, 40), (8, 10), 26),
    'timed_dataread': ('80b5004f0049386880000858000000000120386000000000007980bc08bc1847', (12,), (2, 4), 20),
    'timed_delay': ('004b00b5984208d3011c7d20c00000000000012803d80000000008bc1847022802d800000000f6e700000000f5e7', (14, 22, 34, 40), (0,), None),
}


def _ma5_readback_span(image: bytes, start: int, role: str) -> dict | None:
    encoded, calls, literals, base_offset = _MA5_READBACK_SPANS[role]
    expected = bytes.fromhex(encoded)
    if start & 1 or not 0 <= start <= len(image) - len(expected):
        return None
    code = bytearray(image[start:start + len(expected)])
    targets = []
    dependencies = [[start, len(expected)]]
    for offset in calls:
        target = thumb_bl_target(image, start + offset)
        if target is None or target & 1 or not 0 <= target < len(image) - 1:
            return None
        targets.append(target)
        dependencies.append([target, 2])
        code[offset:offset + 4] = b"\0" * 4
    values = []
    for offset in literals:
        word = struct.unpack_from("<H", code, offset)[0]
        if word & 0xF800 != 0x4800:
            return None
        value = thumb_literal_value(image, start + offset, word >> 8 & 7)
        if value is None:
            return None
        values.append(value)
        dependencies.append([((start + offset + 4) & ~3) + (word & 255) * 4, 4])
        code[offset] = 0
    base = None
    if base_offset is not None:
        move, shift = struct.unpack_from("<HH", code, base_offset)
        register = move >> 8 & 7
        template_register = 5 if role in ("block", "timed_block") else 1 if role == "local_index" else 0
        if (move & 0xF800 != 0x2000 or register != template_register
                or shift & 0xF800 or shift & 7 != register
                or shift >> 3 & 7 != register):
            return None
        base = (move & 255) << (shift >> 6 & 31)
        if not _MMIO_MIN <= base <= _MMIO_MAX - 3 or base & 3:
            return None
        code[base_offset:base_offset + 4] = b"\0" * 4
    if code != expected:
        return None
    return {"calls": targets, "literals": values, "base": base,
            "dependencies": dependencies}


def _ma5_readback_transport(image: bytes, common: dict, entries: dict,
                            local: bool) -> dict | None:
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
    if (any(span is None for span in spans.values())
            or len(set(entries.values())) != len(entries)
            or spans["empty"]["calls"] != spans["wait"]["calls"]):
        return None
    context = spans["read"]["literals"][0]
    ram = [[context, 4]]
    evidence = {"entries": entries, "context_pointer": context,
                "default_ranges": [[0xC0, 0xD0, 0x60], [0xD0, 0xE0, 0x3C]]}
    if local:
        if any(entries[role] != entries["index"] + delta for role, delta in
               (("status", 0x2A), ("write", 0x52), ("dataread", 0x7E), ("block", 0xAA))):
            return None
        base = spans["index"]["base"]
        direction, dummy = spans["index"]["literals"]
        data = spans["write"]["literals"][2]
        limit = spans["empty"]["literals"][0]
        error = spans["wait"]["calls"][1]
        if (spans["status"]["base"] != base or data != base + 128
                or not _MMIO_MIN <= data < _MMIO_MAX
                or spans["status"]["literals"] != [direction, dummy]
                or spans["write"]["literals"] != [direction, dummy, data]
                or spans["dataread"]["literals"] != [direction, dummy, data]
                or spans["block"]["literals"] != [data]
                or direction <= dummy < direction + 4
                or not 0 < limit <= 0xFFFF
                or image[error:error + 2] != b"\x70\x47"):
            return None
        ram.extend([[direction, 4], [dummy, 1]])
        evidence.update(transport_class="local-counter-literal-data-v1",
                        direction_state=direction, delay_dummy=dummy,
                        wait_limit=281, empty_poll_limit=limit)
        stride, index_site, status_site, write_site, block_site, read_site = 128, 26, 28, 24, 12, 26
    else:
        wrappers = ("index", "status", "write", "block", "dataread")
        bases = {spans[role]["base"] for role in wrappers}
        delays = {target for role in wrappers for target in spans[role]["calls"]}
        poll, limit = spans["wait"]["literals"]
        if (len(bases) != 1 or len(delays) != 1
                or spans["empty"]["literals"] != [poll, limit]
                or any(spans[role]["literals"] != [poll] for role in wrappers)
                or not 0 < limit <= 0xFFFF):
            return None
        base = bases.pop()
        ram.append([poll, 8])
        evidence.update(transport_class="ram-counter-synthesized-data-v1",
                        poll_state=poll, poll_limit=limit)
        stride, index_site, status_site, write_site, block_site, read_site = 2, 18, 16, 18, 28, 16
    if any(not 0x01000000 <= address <= 0x02000000 - size
           or size > 1 and address & 3 for address, size in ram):
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
    if (any(span is None for span in spans.values())
            or len(set(entries.values())) != len(entries)
            or spans["wait"]["calls"] != spans["empty"]["calls"]):
        return None
    error = spans["wait"]["calls"][1]
    wrappers = ("index", "status", "write", "block", "dataread")
    bases = {spans[role]["base"] for role in wrappers}
    delays = {target for role in wrappers for target in spans[role]["calls"]}
    direction, write_table = spans["index"]["literals"]
    if (len(bases) != 1 or len(delays) != 1
            or image[error:error + 2] != b"\x70\x47"
            or any(spans[role]["literals"] != [direction, write_table]
                   for role in ("write", "block"))
            or any(spans[role]["literals"] != [direction, write_table + 8]
                   for role in ("status", "dataread"))
            or write_table & 3 or not 0 <= write_table <= len(image) - 16):
        return None
    entries["delay"] = delays.pop()
    spans["delay"] = _ma5_readback_span(image, entries["delay"], "timed_delay")
    if spans["delay"] is None:
        return None
    calls = spans["delay"]["calls"]
    threshold = spans["delay"]["literals"][0]
    timing = list(struct.unpack_from("<4I", image, write_table))
    if (calls[1] != calls[2] or len(set((calls[0], calls[1], calls[3]))) != 3
            or not 0 < threshold <= 0xFFFFFFFF
            or any(not 0 < value < threshold for value in timing)):
        return None
    context = spans["read"]["literals"][0]
    ram = [[context, 4], [direction, 4]]
    if (context == direction or any(address & 3 or
            not 0x01000000 <= address <= 0x02000000 - size
            for address, size in ram)):
        return None
    base = bases.pop()
    if base + 4 >= _MMIO_MAX:
        return None
    return {
        "family": "ma5", "grammar": "ma5-readback-v1",
        "static_status": "candidate", "reject_reason": None,
        "protocol_status": "temporary-evidence-gated", "base": base,
        "data_offset": 4,
        "sites": {"write_0": [entries["index"] + 26],
                  "read_0": [entries["status"] + 24],
                  "write_4": [entries["write"] + 26, entries["block"] + 36],
                  "read_4": [entries["dataread"] + 24]},
        "block_write_offsets": [entries["block"] + 36],
        "structural_evidence": {
            "transport_class": "local-counter-direction-timing-v1",
            "entries": entries, "context_pointer": context,
            "direction_state": direction, "timing_table": write_table,
            "timing_values": timing, "wait_limit": 300,
            "default_ranges": [[0xC0, 0xD0, 0x60], [0xD0, 0xE0, 0x3C]]},
        "ram_dependencies": ram,
        "nor_dependencies": [[write_table, 16]] + [dependency
            for span in spans.values() for dependency in span["dependencies"]],
    }


def _ma5_alternate_readback(image: bytes) -> list[dict[str, object]]:
    """Find the alternate bounded checker linked to its byte-port wrappers."""
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
        if any(struct.unpack_from('<H', image, check + off)[0] != opcode
               for off, opcode in ((0x16, 0x2860), (0x1c, 0x2fd0),
                                   (0x20, 0x27d0), (0x30, 0x283c),
                                   (0x3e, 0x2fe0))):
            continue
        if (conditional_target(check + 0x1e, 3) != check + 8
                or conditional_target(check + 0x40, 3) != check + 0x22
                or conditional_target(check + 0x18, 1) != check + 0x34
                or conditional_target(check + 0x32, 0) != check + 0x3c):
            continue
        read = thumb_bl_target(image, check + 0xa)
        if (read is None or read != thumb_bl_target(image, check + 0x24)
                or read < 0 or read + 0x90 > len(image)):
            continue
        if any(struct.unpack_from('<H', image, read + off)[0] != opcode
               for off, opcode in ((0x14, 0x2003), (0x6c, 0x2080),
                                   (0x72, 0x2040), (0x84, 0x2041))):
            continue
        select = thumb_bl_target(image, read + 0x16)
        empty = thumb_bl_target(image, read + 0x1a)
        write = thumb_bl_target(image, read + 0x4a)
        wait = thumb_bl_target(image, read + 0x74)
        dataread = thumb_bl_target(image, read + 0x8a)
        if (None in (select, empty, write, wait, dataread)
                or select != thumb_bl_target(image, read + 0x86)
                or any(thumb_bl_target(image, read + off) != write
                       for off in (0x54, 0x5c, 0x68, 0x6e))
                or not all(0 <= p <= len(image) - 0x100
                           for p in (select, empty, write, wait, dataread))):
            continue
        index = thumb_bl_target(image, select + 0x1e)
        status = thumb_bl_target(image, wait + 0xa)
        if (index is None or status is None
                or status != thumb_bl_target(image, empty + 8)):
            continue
        timed = (status - index in (0x1e, 0x20)
                 and write - status == 0x1c and dataread - write == 0x7c)
        direct = (status - index in (0x12, 0x14)
                  and write - status == 0x14 and dataread - write == 0x34)
        if not (timed or direct):
            continue
        delay = None
        if timed:
            delay_calls = (index + 4, status + 2, write + 4, dataread + 2,
                           write + 0x28, write + 0x3e,
                           write + 0x58, write + 0x6a)
            delay = thumb_bl_target(image, delay_calls[0])
            if (delay is None or not 0 <= delay <= len(image) - 2
                    or any(thumb_bl_target(image, at) != delay for at in delay_calls)):
                continue
        resets = []
        for match in _THUMB_BL.finditer(image, max(0, check - 0x2000),
                                        min(len(image), check + 0x2000)):
            call = match.start()
            if (call & 1 or call < 0x18 or call + 14 > len(image)
                    or thumb_bl_target(image, call) != check):
                continue
            immediates = ((-0x18, 0x2004), (-0x12, 0x2080), (-0xc, 0x2000)) if timed else (
                (-0x12, 0x2004), (-0xc, 0x2080), (-6, 0x2000))
            calls = (-0x16, -0x10, -0xa) if timed else (-0x10, -0xa, -4)
            count_compare = struct.unpack_from('<H', image, call + 0xa)[0]
            count_register = count_compare >> 8 & 7
            if (all(struct.unpack_from('<H', image, call + off)[0] == op
                    for off, op in immediates)
                    and count_compare & 0xf8ff == 0x280a
                    and struct.unpack_from('<H', image, call + 8)[0] ==
                    (0x3001 | count_register << 8)
                    and [thumb_bl_target(image, call + off) for off in calls]
                    == [index, write, write]
                    and conditional_target(call + 0xc, 3) ==
                    call - (0x18 if timed else 0x12)):
                resets.append(call)
        if len(resets) != 1:
            continue
        blocks = [write + 0x3c, write + 0x68] if timed else [write + 0x28]
        load, advance, store = (struct.unpack_from('<H', image, off)[0]
                                for off in (blocks[0] - 4, blocks[0] - 2, blocks[0]))
        source_reg = load >> 3 & 7
        if (load & 0xffc0 != 0x7800 or load & 7 != store & 7
                or advance != (0x3001 | source_reg << 8)
                or store & 0xf800 != 0x7000
                or (timed and struct.unpack_from('<H', image, blocks[1])[0] & 7 != 4)):
            continue
        context = thumb_literal_value(image, read + 4, 0)
        direction_refs = ([(index + 8, 1), (status + 6, 1), (write + 8, 1),
                           (dataread + 6, 1)] if timed else
                          [(index, 2), (status, 1), (write, 2), (dataread, 1)])
        direction = thumb_literal_value(image, *direction_refs[0])
        if (context is None or direction is None
                or thumb_literal_value(image, select, 2) != context
                or any(thumb_literal_value(image, *ref) != direction
                       for ref in direction_refs)
                or context & 3 or direction & 3
                or not 0x01000000 <= context <= 0x02000000 - (4 if timed else 8)
                or not 0x01000000 <= direction <= 0x01fffff8):
            continue
        needed = ({'write_0': index + 0x12, 'read_0': status + 0x10,
                   'write_2': write + 0x12, 'read_2': dataread + 0x10} if timed else
                  {'write_0': index + 0xa, 'read_0': status + 0xa,
                   'write_2': write + 0xa, 'read_2': dataread + 0xa})
        for c in _transport_clusters(image):
            if c['base'] not in ((0x02840000, 0x02c00000) if timed else (0x02c00000,)):
                continue
            sites = {f'{kind}_{port}': [int(s['offset']) for s in c['sites']
                     if s['kind'] == kind and s['port_offset'] == port]
                     for kind in ('read', 'write') for port in (0, 2)}
            if (any(value not in sites[key] for key, value in needed.items())
                    or any(block not in sites['write_2'] for block in blocks)
                    or any(block not in c['block_write_offsets'] for block in blocks)
                    or len({x for values in sites.values() for x in values}) > 64):
                continue
            found.append({'family': 'ma5', 'grammar': 'ma5-readback-v1',
                'static_status': 'candidate', 'reject_reason': None,
                'protocol_status': 'temporary-evidence-gated',
                'base': c['base'], 'data_offset': 2, 'sites': sites,
                'block_write_offsets': blocks,
                'structural_evidence': {'transport_class': (
                    'alternate-reset-readback-v1' if timed else
                    'alternate-direct-reset-readback-v1'),
                    'entries': {'check': check, 'read': read, 'select': select,
                                'index': index, 'status': status, 'write': write,
                                'dataread': dataread, 'reset_check': resets[0]},
                    'context_pointer': context, 'context_word_offset': 0 if timed else 4,
                    'default_ranges': [[0xc0, 0xd0, 0x60], [0xd0, 0xe0, 0x3c]]},
                'ram_dependencies': [[context, 4 if timed else 8], [direction, 8]],
                'nor_dependencies': [[check, 0x46], [read, 0x90],
                    [select, 0x30], [empty, 0x40], [wait, 0x40],
                    [resets[0] - 0x18, 0x24],
                    [int(c['begin']), int(c['end']) - int(c['begin'])]] + (
                        [[delay, 2]] if delay is not None else []) + [
                        [((off + 4) & ~3) + (struct.unpack_from('<H', image, off)[0] & 255) * 4, 4]
                        for off in (read + 4, select, *(ref[0] for ref in direction_refs))]})
    return found


def find_ma5_readback_candidate(image: bytes) -> dict[str, object]:
    """Find a closed reset/readback producer; never enable default admission."""
    rejected = {"family": "ma5", "grammar": "ma5-readback-v1",
                "static_status": "rejected", "reject_reason": "structural-none"}
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
        entries.update(select=calls[0], empty=calls[1], write=calls[3],
                       wait=calls[8], dataread=calls[11])
        if (calls[2] != calls[9] or calls[3:8] != [entries["write"]] * 5
                or calls[10] != entries["select"] or calls[12] != entries["select"]):
            continue
        select = _ma5_readback_span(image, entries["select"], "select")
        context = read["literals"][0]
        if (select is None or read["literals"] != [context, context]
                or select["literals"] != [context]):
            continue
        common = {"check": check, "read": read, "select": select}
        for candidate in (_ma5_readback_transport(image, common, entries, False),
                          _ma5_readback_transport(image, common, entries, True),
                          _ma5_timed_transport(image, common, entries)):
            if candidate is not None:
                accepted.append(candidate)
            if len(accepted) > 1:
                return {**rejected, "reject_reason": "structural-ambiguous"}
    if not accepted:
        accepted = _ma5_alternate_readback(image)
    return accepted[0] if len(accepted) == 1 else (
        {**rejected, 'reject_reason': 'structural-ambiguous'} if accepted else rejected)


def _ma2_callback_irq_profile(image: bytes) -> dict[str, object] | None:
    """Qualify the byte-count, halfword-mask callback dispatcher and route."""
    spans = ((0x159f18, 0x15a000,
              "287364f2dab8e1d2169acd81d5beda86c5820aeef57e2149d63d057b05d1ce6e"),
             (0x15a450, 0x15a4a0,
              "d4e31bfea65a89336f0213124adea06da51ec771fe5d0dcad54c3ba20eb856cf"),
             (0x15b8d4, 0x15b8e8,
              "dc406f62be4d9956b3b0bec293adf9c997ca879e40d0a9b92f549f1cc6b3ac28"),
             (0x83314, 0x83390,
              "6c4a076c943337e14cc0cc63afdfc0b70592f8b7d1e8fb36c54fd9e520a0ede0"))
    if any(len(image) < end or hashlib.sha256(image[start:end]).hexdigest() != digest
           for start, end, digest in spans):
        return None
    if len(image) < 0x1dcdd4:
        return None
    state = struct.unpack_from("<I", image, 0x159fb4)[0]
    callback = struct.unpack_from("<I", image, 0x15a49c)[0]
    words = list(struct.unpack_from("<7I", image, 0x1dcdb8))
    if (state != 0x0126964c or callback != 0x15adfd or
            words != [0x03000624, 0x0300062c, 8, 0x01182c3e,
                      0x01182c42, 0x830f9, 0]):
        return None
    return {"status": "candidate", "profile": "byte-count-halfword-mask-v1",
            "descriptor_address": 0x01182d94, "words": words,
            "dispatcher_offset": 0x159f38,
            "callback_linkage": {"state_address": state + 0x14,
                                 "table_address": state + 8,
                                 "callback_offset": callback - 1,
                                 "data_read_offset": 0x1595c4},
            "index_restore_site": 0x159f2c}


def _thumb_short_branch_target(image: bytes, offset: int) -> int | None:
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
    if offset < 0 or offset + 2 > len(image):
        return None
    op = struct.unpack_from("<H", image, offset)[0]
    if op & 0xF000 != 0xD000 or (op >> 8 & 15) >= 14:
        return None
    return op >> 8 & 15


def _thumb_bl_targets(image: bytes, start: int, length: int) -> list[int]:
    stop = min(len(image) - 3, start + length)
    targets = []
    for offset in range(start, stop, 2):
        target = thumb_bl_target(image, offset)
        if target is not None:
            targets.append(target)
    return targets


def _thumb_readback_verifiers(image: bytes) -> list[tuple[int, int]]:
    """Find a three-range register verifier and its common read helper.

    This recognizes the compiler's loop structure by decoded Thumb fields and
    checks all three calls target one helper. It does not match firmware data.
    """
    found = []
    mov4_90 = 0x2000 | 4 << 8 | 0x90
    mov7_0 = 0x2000 | 7 << 8
    mov1_2 = 0x2000 | 1 << 8 | 2
    add_r0_r4_r7 = 0x1800 | 7 << 6 | 4 << 3
    lsl_r0_24 = 0x0600 | 24 << 6
    lsr_r0_24 = 0x0800 | 24 << 6

    def halfword(offset: int) -> int:
        return struct.unpack_from("<H", image, offset)[0]

    def eq(offset: int, value: int) -> bool:
        return offset + 2 <= len(image) and halfword(offset) == value

    anchor = struct.pack("<HH", mov4_90, mov7_0)
    start = image.find(anchor)
    while start >= 0:
        if start & 1:
            start = image.find(anchor, start + 1)
            continue
        if not (eq(start, mov4_90) and eq(start + 2, mov7_0)
                and eq(start + 4, 0x43FD)
                and eq(start + 6, add_r0_r4_r7)
                and eq(start + 8, mov1_2)
                and eq(start + 14, lsl_r0_24)
                and eq(start + 16, lsr_r0_24)
                and eq(start + 18, 0x2800 | 0x60)
                and eq(start + 22, 0x3000 | 7 << 8 | 1)
                and eq(start + 24, 0x2800 | 7 << 8 | 0x10)
                and _thumb_condition(image, start + 20) == 1
                and _thumb_short_branch_target(image, start + 20) == start + 76
                and _thumb_condition(image, start + 26) == 3
                and _thumb_short_branch_target(image, start + 26) == start + 6
                and eq(start + 28, 0x2000 | 4 << 8 | 0xA0)
                and eq(start + 30, mov7_0)
                and eq(start + 32, add_r0_r4_r7)
                and eq(start + 34, mov1_2)
                and eq(start + 40, lsl_r0_24)
                and eq(start + 42, lsr_r0_24)
                and eq(start + 44, 0x2800 | 0x3C)
                and eq(start + 48, 0x3000 | 7 << 8 | 1)
                and eq(start + 50, 0x2800 | 7 << 8 | 0x10)
                and _thumb_condition(image, start + 46) == 1
                and _thumb_short_branch_target(image, start + 46) == start + 76
                and _thumb_condition(image, start + 52) == 3
                and _thumb_short_branch_target(image, start + 52) == start + 32
                and eq(start + 54, 0x2000 | 4 << 8 | 0xFF)
                and eq(start + 56, 0x3000 | 4 << 8 | 0x4B)
                and eq(start + 58, mov7_0)
                and eq(start + 60, add_r0_r4_r7)
                and eq(start + 62, mov1_2)
                and eq(start + 68, lsl_r0_24)
                and eq(start + 70, lsr_r0_24)
                and eq(start + 72, 0x2800 | 0x40)
                and _thumb_condition(image, start + 74) == 0
                and _thumb_short_branch_target(image, start + 74) == start + 84
                and eq(start + 84, 0x3000 | 7 << 8 | 1)
                and eq(start + 86, 0x2800 | 7 << 8 | 8)
                and _thumb_condition(image, start + 88) == 3
                and _thumb_short_branch_target(image, start + 88) == start + 60):
            start = image.find(anchor, start + 1)
            continue
        calls = [thumb_bl_target(image, start + offset)
                 for offset in (10, 36, 64)]
        if calls[0] is not None and calls[0] == calls[1] == calls[2]:
            found.append((start, calls[0]))
        start = image.find(anchor, start + 1)
    return found


def _thumb_ma3_014_wrappers(
        image: bytes) -> tuple[dict[str, int], int] | None:
    """Find the four indexed byte wrappers built from 5 << 22."""
    wrappers: dict[str, int] = {}
    helper_targets: set[int] = set()
    setup_offsets: list[tuple[int, int]] = []
    for register in range(8):
        anchor = struct.pack(
            "<HH", 0x2005 | register << 8,
            (22 << 6) | register << 3 | register,
        )
        offset = image.find(anchor)
        while offset >= 0:
            if not offset & 1:
                setup_offsets.append((offset, register))
            offset = image.find(anchor, offset + 1)
    setup_offsets.sort()

    for offset, register in setup_offsets:
        # These wrappers preserve LR before their direct byte access.
        if offset + 8 > len(image):
            continue
        push = struct.unpack_from("<H", image, offset + 4)[0]
        access = struct.unpack_from("<H", image, offset + 6)[0]
        if push & 0xFE00 != 0xB400 or not push & 0x100:
            continue
        if (access & 0xF800 not in (0x7000, 0x7800)
                or (access >> 3 & 7) != register):
            continue
        port = access >> 6 & 0x1F
        if port not in (0, 2):
            continue
        kind = "write" if access & 0xF800 == 0x7000 else "read"
        # Require a nearby call to the common bus transaction helper.
        calls = [thumb_bl_target(image, call)
                 for call in range(offset + 8, min(len(image) - 3,
                                                    offset + 0x18), 2)]
        calls = [target for target in calls if target is not None]
        if len(calls) != 1:
            continue
        key = f"{kind}_{port}"
        if key in wrappers:
            return None
        wrappers[key] = offset + 6
        helper_targets.add(calls[0])
    required = {"write_0", "read_0", "write_2", "read_2"}
    if set(wrappers) != required or len(helper_targets) != 1:
        return None
    owned_accesses: set[tuple[str, int, int]] = set()
    for offset, register in setup_offsets:
        for access_offset in range(offset + 4,
                                   min(len(image) - 1, offset + 0x30), 2):
            instruction = struct.unpack_from("<H", image, access_offset)[0]
            opcode = instruction & 0xF800
            if (opcode in (0x7000, 0x7800)
                    and instruction >> 3 & 7 == register):
                owned_accesses.add((
                    "write" if opcode == 0x7000 else "read",
                    instruction >> 6 & 0x1F, access_offset,
                ))
            if (thumb_bl_target(image, access_offset) is not None
                    or _thumb_writes_register(instruction, register)):
                break
    expected_accesses = {
        (name.split("_")[0], int(name.split("_")[1]), site)
        for name, site in wrappers.items()
    }
    if owned_accesses != expected_accesses:
        return None
    return wrappers, next(iter(helper_targets))


def _thumb_ma3_014_fifo_writer(
        image: bytes, wrappers: dict[str, int], poller: int,
) -> list[int] | None:
    """Find a linked FIFO writer with an explicit 64-byte transfer loop."""
    starts = [match.start() for match in re.finditer(rb".\xb5", image)
              if not match.start() & 1]
    data_writer = wrappers["write_2"] - 6
    index_writer = wrappers["write_0"] - 6
    calls_to_data = []
    calls_to_index = []
    calls_to_poller = []
    for match in _THUMB_BL.finditer(image):
        call = match.start()
        if call & 1:
            continue
        target = thumb_bl_target(image, call)
        if target == data_writer:
            calls_to_data.append(call)
        elif target == index_writer:
            calls_to_index.append(call)
        elif target == poller:
            calls_to_poller.append(call)
    matches = []
    for call in calls_to_data:
        loop_start = None
        for position in range(max(0, call - 0x40), call, 2):
            mov = struct.unpack_from("<H", image, position)[0]
            if mov & 0xF800 == 0x2000 and mov & 0xFF == 0x40:
                loop_start = position
        if loop_start is None:
            continue
        if not any(
            call < branch < min(len(image) - 1, call + 0x10)
            and (target := _thumb_short_branch_target(image, branch)) is not None
            and loop_start < target <= call
            for branch in range(call + 4, min(len(image) - 1, call + 0x10), 2)
        ):
            continue
        start_index = bisect_right(starts, loop_start) - 1
        if start_index < 0 or loop_start - starts[start_index] > 0x800:
            continue
        start = starts[start_index]
        end = starts[start_index + 1] if start_index + 1 < len(starts) else len(image)
        has_return = any(
            (word := struct.unpack_from("<H", image, position)[0]) == 0x4770
            or word & 0xFF00 == 0xBD00
            or (word & 0xFF87 == 0x4700 and position >= start + 2
                and (previous := struct.unpack_from(
                    "<H", image, position - 2
                )[0]) & 0xFE00 == 0xBC00
                and previous & (1 << (word >> 3 & 7)))
            for position in range(start, max(start, end - 1), 2)
        )
        if not has_return:
            continue
        relevant_calls = [c for c in calls_to_data + calls_to_index + calls_to_poller
                          if start <= c < end]
        if (not any(c in calls_to_index and c >= start + 2
                    and struct.unpack_from("<H", image, c - 2)[0] & 0xF800 == 0x2000
                    and struct.unpack_from("<H", image, c - 2)[0] & 0xFF == 2
                    for c in relevant_calls)
                or not any(c in calls_to_poller for c in relevant_calls)
                or sum(c in calls_to_data for c in relevant_calls) < 2):
            continue
        matches.append(start)
    unique_matches = sorted(set(matches))
    return unique_matches or None


def find_ma3_indexed_candidate(image: bytes) -> dict[str, object]:
    """Require SC-7080 readback, packet, FIFO, poller and MMIO linkage."""
    rejected = {"family": "ma3", "grammar": "ma3-indexed-v1",
                "static_status": "rejected", "reject_reason": "verifier-none"}
    wrapper_result = _thumb_ma3_014_wrappers(image)
    if wrapper_result is None:
        rejected["reject_reason"] = "indexed-wrappers-unmatched"
        return rejected
    wrappers, wrapper_helper = wrapper_result
    verifiers = _thumb_readback_verifiers(image)
    linked: list[tuple[int, int, int, int]] = []
    for verifier, reader in verifiers:
        reader_calls = set(_thumb_bl_targets(image, reader, 0xC8))
        if not {wrappers["write_0"] - 6, wrappers["write_2"] - 6,
                wrappers["read_2"] - 6} <= reader_calls:
            continue
        pollers = [target for target in reader_calls
                   if wrappers["read_0"] - 6 in
                   _thumb_bl_targets(image, target, 0x1C)]
        for poller in pollers:
            fifo_writer = _thumb_ma3_014_fifo_writer(
                image, wrappers, poller
            )
            if fifo_writer is not None:
                linked.extend((verifier, reader, poller, writer)
                              for writer in fifo_writer)
    if not linked:
        rejected["reject_reason"] = (
            "verifier-reader-fifo-linkage-mismatch"
        )
        return rejected
    if len({entry[:3] for entry in linked}) != 1:
        rejected["reject_reason"] = "verifier-ambiguous"
        return rejected
    verifier, reader, poller = linked[0][:3]
    fifo_writers = sorted({entry[3] for entry in linked})
    return {
        "family": "ma3", "grammar": "ma3-indexed-v1",
        "static_status": "accepted", "reject_reason": None,
        "base": 0x01400000, "data_offset": 2,
        "verifier_entry": verifier, "register_reader": reader,
        "fifo_writers": fifo_writers, "status_poller": poller,
        "wrapper_helper": wrapper_helper,
        "sites": {name: [site] for name, site in wrappers.items()},
        "block_write_offsets": [],
        "register_readback": [[0x90, 0xA0, 0x60],
                              [0xA0, 0xB0, 0x3C],
                              [0x14A, 0x152, 0x40]],
    }


_SV130_MA3_SITES: dict[str, tuple[int, ...]] = {
    "write_0": (
        0x17580C, 0x175840, 0x175858, 0x175870, 0x175888, 0x1758BC,
        0x1758F8, 0x175916, 0x17592E, 0x1759C0, 0x1759D2, 0x1759DC,
        0x175A06, 0x175AD0, 0x175B04, 0x175B28, 0x175BAC, 0x175BC2,
        0x17645E, 0x176480, 0x17653C, 0x176558, 0x17660C, 0x17663C,
        0x1766E4, 0x17679E, 0x176844, 0x17684E, 0x176856, 0x176862,
        0x17686E, 0x176894, 0x1768A2, 0x1768A8, 0x1768B0, 0x1768BC,
        0x1768C6, 0x1768D4, 0x1768E6, 0x17690C, 0x176914, 0x176920,
        0x176954, 0x17695E, 0x17696C, 0x17697C, 0x17698A, 0x176A06,
        0x176A34, 0x176A42, 0x176A50, 0x176A5E, 0x176A6E, 0x176A78,
        0x176A8A, 0x176A9A, 0x176AA2, 0x176ABE, 0x176AC8, 0x176ACE,
        0x176ADE, 0x176B36, 0x176B48, 0x176D6A,
    ),
    "read_0": (
        0x1B66BA, 0x1B66E0, 0x1B6706, 0x1B670E, 0x1B6724, 0x1B672E,
        0x1B6772,
    ),
    "write_128": (
        0x175844, 0x17585E, 0x175892, 0x1758D4, 0x175904, 0x175996,
        0x175A6A, 0x175A8E, 0x175AAC, 0x175AF0,
        0x175B70, 0x175B88, 0x175BB0, 0x176464, 0x176472, 0x176542,
        0x17654E, 0x1765C2, 0x1765CE, 0x1767A2, 0x17684A, 0x176852,
        0x17685A, 0x176866, 0x17686A, 0x176874, 0x176878, 0x17689A,
        0x17689E, 0x1768A6, 0x1768AC, 0x1768B6, 0x1768C0, 0x1768CA,
        0x1768D8, 0x1768DC, 0x1768EC, 0x1768EE, 0x176910, 0x176916,
        0x17692A, 0x176932, 0x176936, 0x17693A, 0x176942, 0x17694E,
        0x176958, 0x176962, 0x176970, 0x176974, 0x176978, 0x17697E,
        0x176994, 0x17699C, 0x1769A0, 0x1769A4, 0x1769A8, 0x1769B2,
        0x1769BA, 0x1769C4, 0x1769C8, 0x1769CA, 0x176A0A, 0x176A38,
        0x176A54, 0x176A6A, 0x176A70, 0x176A80, 0x176A8E, 0x176A9E,
        0x176AA4, 0x176AC4, 0x176ACA, 0x176AD4, 0x176D6E, 0x176D72,
    ),
    "read_128": (0x175810, 0x1759D4),
}


_KP6200_MA3_SITES: dict[str, tuple[int, ...]] = {
    "write_0": (
        0xE2204, 0xE220C, 0xE223E, 0xE2256, 0xE2270, 0xE2282,
        0xE2298, 0xE22B0, 0xE22E6, 0xE2316, 0xE23D6, 0xE2482,
        0xE24AE, 0xE24E4, 0xE2504, 0xE2E28, 0xE2E4A, 0xE2F06,
        0xE2F1E, 0xE2F7C, 0xE2FC6, 0xE2FF4, 0xE309C, 0xE31F8,
        0xE31FE, 0xE3206, 0xE3212, 0xE3222, 0xE3248, 0xE3254,
        0xE325A, 0xE326E, 0xE3274, 0xE327C, 0xE3288, 0xE3298,
        0xE32BE, 0xE32C4, 0xE32D4, 0xE32DA, 0xE32EA, 0xE32F0,
        0xE32FA, 0xE3302, 0xE330A, 0xE331A, 0xE3326, 0xE3340,
        0xE3348, 0xE334E, 0xE3366, 0xE336C, 0xE338A, 0xE33BA,
        0xE33EA, 0xE33F6, 0xE340A, 0xE3418, 0xE3424, 0xE343C,
        0xE3442, 0xE3452, 0xE36F2,
    ),
    "write_4": (
        0xE2240, 0xE225A, 0xE228A, 0xE22C6, 0xE243C, 0xE2462,
        0xE248A, 0xE24D0, 0xE2E2C, 0xE2E3C, 0xE2F0A, 0xE2F16,
        0xE2F80, 0xE2F8C, 0xE31FA, 0xE3202, 0xE320A, 0xE3216,
        0xE321A, 0xE3226, 0xE3228, 0xE324C, 0xE3250, 0xE3258,
        0xE325E, 0xE3270, 0xE3278, 0xE3280, 0xE328C, 0xE3290,
        0xE329C, 0xE329E, 0xE32C0, 0xE32C6, 0xE32D6, 0xE32DE,
        0xE32E2, 0xE32E6, 0xE32EE, 0xE32FE, 0xE3306, 0xE330E,
        0xE331E, 0xE3322, 0xE3324, 0xE332A, 0xE3336, 0xE334A,
        0xE3352, 0xE3356, 0xE335A, 0xE335E, 0xE3368, 0xE3370,
        0xE337A, 0xE337E, 0xE3380, 0xE33BC, 0xE33EC, 0xE33FC,
        0xE3414, 0xE341A, 0xE3426, 0xE343E, 0xE3444, 0xE36F6,
        0xE36F8,
    ),
    "read_0": (
        0x1147F4, 0x11482C, 0x114834, 0x11484A, 0x114854, 0x1148A8,
    ),
    "read_4": (0xE220E,),
}


def find_ma3_kp6200_candidate(image: bytes) -> dict[str, object]:
    """Require the closed KP6200 verifier, reset, FIFO, and callback paths."""
    rejected = {
        "family": "ma3", "grammar": "ma3-kp-readback-fifo-v1",
        "static_status": "rejected", "reject_reason": "verifier-none",
    }
    verifier, reader = 0xE316E, 0xE230C
    verifier_body = verifier - 2
    if (verifier, reader) not in _thumb_readback_verifiers(image):
        rejected["reject_reason"] = "verifier-reader-linkage-mismatch"
        return rejected

    required_calls = {
        (0xE3178, reader), (0xE3192, reader), (0xE31AE, reader),
        (0xE322A, verifier_body), (0xE32A0, verifier_body),
        (0xE22B6, 0x1148A0), (0xE22D6, 0x1148A0),
        (0xE236A, 0x1148A0), (0xE2394, 0x1147EA),
        (0xE1884, 0xE31CC), (0xE189C, 0xE31CC),
        (0xE1B9E, 0xE36B4), (0xE36DA, verifier_body),
        (0xE1C38, 0x8EB0),
    }
    for source, target in required_calls:
        if thumb_bl_target(image, source) != target:
            rejected["reject_reason"] = "verifier-poller-reset-callgraph-mismatch"
            return rejected

    # The byte callback at E21F6 is installed through the same initializer
    # that reaches the verifier-backed device setup.
    if (thumb_literal_value(image, 0x8EE8, 2) != 0xE21F5
            or thumb_bl_target(image, 0xE1C38) != 0x8EB0):
        rejected["reject_reason"] = "fifo-callback-linkage-mismatch"
        return rejected

    expected = {name: list(sites) for name, sites in _KP6200_MA3_SITES.items()}
    actual = [a for a in _synthesized_base_accesses(image)
              if a["base"] == 0x02C00000]
    excluded = {(0x8E9C, "write", 0), (0x1147BC, "read", 0)}
    actual_keys = {
        (int(a["offset"]), str(a["kind"]), int(a["port_offset"]))
        for a in actual
    }
    expected_keys = {
        (site, "write", int(name[6:]))
        for name, sites in expected.items() if name.startswith("write_")
        for site in sites
    } | {
        (site, "read", int(name[5:]))
        for name, sites in expected.items() if name.startswith("read_")
        for site in sites
    }
    if actual_keys != expected_keys | excluded:
        rejected["reject_reason"] = "owned-site-set-mismatch"
        return rejected
    for name, sites in expected.items():
        opcode = 0x7000 if name.startswith("write_") else 0x7800
        for site in sites:
            if struct.unpack_from("<H", image, site)[0] & 0xF800 != opcode:
                rejected["reject_reason"] = "owned-site-opcode-mismatch"
                return rejected

    return {
        "family": "ma3", "grammar": "ma3-kp-readback-fifo-v1",
        "static_status": "accepted", "reject_reason": None,
        "base": 0x02C00000, "data_offset": 4,
        "verifier_entry": verifier, "register_reader": reader,
        "fifo_writers": [0xE22A4],
        "status_pollers": [0x1148A0, 0x1147EA, 0x114824],
        "block_write_offsets": [], "sites": expected,
        "register_readback": [[0x90, 0xA0, 0x60],
                              [0xA0, 0xB0, 0x3C],
                              [0x14A, 0x152, 0x40]],
    }


def find_ma3_packetized_candidate(image: bytes) -> dict[str, object]:
    """Require the closed SV130 readback, packet, FIFO, and poll graph."""
    rejected = {
        "family": "ma3", "grammar": "ma3-readback-fifo-v1",
        "static_status": "rejected", "reject_reason": "verifier-none",
    }
    verifier, reader = 0x1767BE, 0x175924
    if (verifier, reader) not in _thumb_readback_verifiers(image):
        rejected["reject_reason"] = "verifier-reader-linkage-mismatch"
        return rejected

    required_calls = {
        (0x1767C8, reader),
        (0x1767E2, reader),
        (0x1767FE, reader),
        (reader + 0x5E, 0x1B676C),
        (reader + 0x8A, 0x1B66D8),
        (0x17687A, verifier - 2),
        (0x1768F0, verifier - 2),
        (0x176CA4, 0x17681C),
        (0x176CC2, 0x1758B0),
        (0x176CD8, 0x1758B0),
        (0x1758C4, 0x1B676C),
        (0x1758E4, 0x1B676C),
        (0x175710, 0x1B6744),
        (0x1B6748, 0x1B66FE),
        (0x175C50, 0x1759E8),
        (0x175C7E, 0x1759E8),
        (0x175CA6, 0x175B10),
        (0x175D30, reader),
        (0x175DC8, 0x1759E8),
        (0x175DF4, 0x175B10),
        (0x175E00, 0x1759E8),
        (0x175E46, 0x1759E8),
        (0x175E54, 0x175B10),
        (0x175E80, 0x1759E8),
        (0x175EF4, 0x1759E8),
        (0x175F02, 0x175B10),
        (0x175F2A, 0x1759E8),
        (0x1760D6, reader), (0x17610C, reader),
        (0x17612C, 0x1758B0), (0x1761E4, 0x1758B0),
        (0x17621C, reader), (0x176298, 0x1758B0),
        (0x1762AA, reader), (0x1762C8, 0x1758B0),
        (0x1763F2, 0x1766F0), (0x176400, 0x1758B0),
        (0x176442, 0x1766F0), (0x176562, 0x176630),
        (0x176584, 0x1758B0), (0x1765D4, 0x1758B0),
        (0x176670, 0x1758B0), (0x176696, 0x1758B0),
        (0x1766B2, 0x1758B0), (0x176746, 0x1758B0),
        (0x176B22, 0x1758B0),
        (0x176D44, 0x1769F0), (0x176D48, verifier - 2),
        (0x176D74, verifier - 2), (0x176D98, 0x1758B0),
        (0x176DAE, 0x1758B0),
        (0x1BBF72, 0x1763C8), (0x1BBF7A, 0x176630),
        (0x1BBE1E, 0x1766F0), (0x1BC524, 0x1766F0),
        (0x1BC7F8, 0x1769F0), (0x1BC800, 0x1765B4),
        (0x1BCB3C, 0x1769F0),
        (0x1BCB88, 0x1769F0), (0x1BCC4C, 0x1769F0),
    }
    for source, target in required_calls:
        if thumb_bl_target(image, source) != target:
            rejected["reject_reason"] = "packet-poller-callgraph-mismatch"
            return rejected

    # The common state object is used by the bus readback path, packet error
    # handling, and the reset path. This also excludes the isolated early
    # LCD-port initialization store from device ownership.
    shared_state_refs = (
        (0x175812, 2, 0x01872D9C),
        (0x175986, 5, 0x01872D9C),
        (0x176918, 1, 0x01872D9C),
    )
    for position, register, expected in shared_state_refs:
        if thumb_literal_value(image, position, register) != expected:
            rejected["reject_reason"] = "shared-audio-state-unmatched"
            return rejected

    expected = {name: list(sites) for name, sites in _SV130_MA3_SITES.items()}
    for name, sites in expected.items():
        is_write = name.startswith("write_")
        opcode = 0x7000 if is_write else 0x7800
        for site in sites:
            if site < 0 or site + 2 > len(image):
                rejected["reject_reason"] = "owned-site-out-of-range"
                return rejected
            instruction = struct.unpack_from("<H", image, site)[0]
            if instruction & 0xF800 != opcode:
                rejected["reject_reason"] = "owned-site-opcode-mismatch"
                return rejected

    return {
        "family": "ma3", "grammar": "ma3-readback-fifo-v1",
        "static_status": "accepted", "reject_reason": None,
        "base": 0x02800000, "data_offset": 0x80,
        "verifier_entry": verifier, "register_reader": reader,
        "fifo_writers": [0x1758B0, 0x175B10],
        "status_pollers": [0x1B66FE, 0x1B66D8, 0x1B676C],
        "block_write_offsets": [],
        "sites": expected,
        "register_readback": [[0x90, 0xA0, 0x60],
                              [0xA0, 0xB0, 0x3C],
                              [0x14A, 0x152, 0x40]],
    }


def find_ma3_readback_candidate(image: bytes) -> dict[str, object]:
    """Require a linked reset verifier, transaction reader, and MMIO wrappers."""
    indexed = find_ma3_indexed_candidate(image)
    if indexed["static_status"] == "accepted":
        return indexed
    packetized = find_ma3_packetized_candidate(image)
    if packetized["static_status"] == "accepted":
        return packetized
    kp6200 = find_ma3_kp6200_candidate(image)
    if kp6200["static_status"] == "accepted":
        return kp6200
    rejected = {"family": "ma3", "grammar": "ma3-readback-v1",
                "static_status": "rejected", "reject_reason": "verifier-none"}
    # SCH-E140's independently confirmed window. Other bus encodings need their
    # own verifier/helper linkage before this profile can admit them.
    base, stride = 0x02840000, 2
    accesses = [a for a in _synthesized_base_accesses(image)
                if a["base"] == base]
    by_port: defaultdict[int, dict[str, list[int]]] = defaultdict(
        lambda: {"read": [], "write": []})
    for access in accesses:
        by_port[int(access["port_offset"])][str(access["kind"])].append(
            int(access["offset"]))
    if (set(by_port) != {0, stride}
            or any(len(by_port[p][kind]) != 1
                   for p in (0, stride) for kind in ("read", "write"))):
        rejected["reject_reason"] = "wrapper-sites-unmatched"
        return rejected
    wrapper = {f"{kind}_{port}": by_port[port][kind][0] - 6
               for port in (0, stride) for kind in ("read", "write")}
    if any(target < 0 or target & 1 for target in wrapper.values()):
        rejected["reject_reason"] = "wrapper-sites-unmatched"
        return rejected

    verifiers = _thumb_readback_verifiers(image)
    linked = []
    for verifier, reader in verifiers:
        reader_calls = set(_thumb_bl_targets(image, reader, 0xC8))
        required = {wrapper["write_0"], wrapper["write_2"], wrapper["read_2"]}
        if not required <= reader_calls:
            continue
        pollers = reader_calls - required - {wrapper["read_0"]}
        if any(wrapper["read_0"] in _thumb_bl_targets(image, poller, 0x50)
               for poller in pollers):
            linked.append((verifier, reader))
    if len(linked) != 1:
        rejected["reject_reason"] = (
            "verifier-ambiguous" if linked else "verifier-reader-linkage-mismatch")
        return rejected
    verifier, reader = linked[0]
    return {
        "family": "ma3", "grammar": "ma3-readback-v1",
        "static_status": "accepted", "reject_reason": None,
        "base": base, "data_offset": stride,
        "verifier_entry": verifier, "register_reader": reader,
        "sites": {name: [site + 6] for name, site in wrapper.items()},
        "block_write_offsets": [],
        "register_readback": [[0x90, 0xA0, 0x60], [0xA0, 0xB0, 0x3C],
                              [0x14A, 0x152, 0x40]],
    }


def find_audio_transport(image: bytes) -> dict[str, object]:
    """Return static ownership evidence; rejected classes stay fail-closed."""
    families = _marker_families(image)
    if not families:
        family = "opaque"
        grammar = "command-status-data-v1"
        candidates = _command_status_candidates(image)
        if not candidates:
            repeated = _repeated_status_candidates(image)
            if repeated:
                if len(repeated) == 1:
                    profile = _sequence_status_profile(image, repeated[0])
                    if profile is not None:
                        return profile
                return {
                    "family": "opaque", "grammar": "repeated-bit-status-v1",
                    "static_status": "rejected",
                    "reject_reason": ("protocol-unsupported" if len(repeated) == 1
                                      else "transport-ambiguous"),
                    "candidates": repeated,
                }
            ma5 = find_ma5_readback_candidate(image)
            if ma5["static_status"] == "candidate":
                return ma5
            ma3 = find_ma3_readback_candidate(image)
            if ma3["static_status"] == "accepted":
                return ma3
            return {
                "family": "unknown", "grammar": None,
                "static_status": "not-detected", "reject_reason": "marker-none",
            }
    elif len(families) != 1:
        return {
            "family": "unknown", "grammar": None, "static_status": "rejected",
            "reject_reason": "marker-ambiguous",
        }
    else:
        family = families[0]
        if family == "ma3":
            return find_ma3_readback_candidate(image)
        grammar = "ma2-command-v1" if family == "ma2" else "indexed-rw-v1"
        candidates = [
            candidate for candidate in _transport_clusters(image)
            if grammar in candidate["grammars"]
        ]
    if len(candidates) != 1:
        return {
            "family": family, "grammar": grammar, "static_status": "rejected",
            "reject_reason": (
                "transport-none" if not candidates else "transport-ambiguous"
            ),
        }
    selected = candidates[0]
    sites = selected["sites"]
    irq = (find_audio_irq_candidate(image) if family == "ma2" else None)
    profile = (_ma2_callback_irq_profile(image)
               if family == "ma2" and selected["base"] == 0x02880000 else None)
    if profile is not None:
        irq = profile
    result = {
        "family": family,
        "grammar": grammar,
        "static_status": "accepted",
        "reject_reason": None,
        "base": selected["base"],
        "data_offset": selected["data_offset"],
        "begin": selected["begin"],
        "end": selected["end"],
        "sites": {
            f"{kind}_{port}": [
                int(site["offset"]) for site in sites
                if site["kind"] == kind and site["port_offset"] == port
            ]
            for kind in ("read", "write")
            for port in sorted({int(site["port_offset"]) for site in sites})
            if any(site["kind"] == kind and site["port_offset"] == port
                   for site in sites)
        },
        "block_write_offsets": selected["block_write_offsets"],
        **({"irq_controller_candidate": irq} if family == "ma2" else {}),
        **({"aperture_write_sites": selected["aperture_write_sites"]}
           if family == "ma5" else {}),
    }
    if profile is not None:
        result["sites"]["write_0"].append(profile["index_restore_site"])
    return result


__all__ = ("find_audio_transport", "find_ma3_indexed_candidate",
           "find_ma3_kp6200_candidate", "find_ma3_readback_candidate",
           "find_ma5_readback_candidate")
