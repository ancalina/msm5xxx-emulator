"""Evidence-gated Yamaha audio transport detection."""
from __future__ import annotations

from collections import defaultdict
import re
import struct


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
            if opcode not in (0x7000, 0x7800):
                continue
            if instruction >> 3 & 7 != register:
                continue
            accesses.add((
                access_offset, base, instruction >> 6 & 0x1F,
                "write" if opcode == 0x7000 else "read",
            ))
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
            ma2 = (
                set(modes) == {0, 1, 2}
                and modes[0] == {"write"}
                and modes[1] == {"write"}
                and modes[2] == {"read", "write"}
                and len(writes[0]) == 3
                and 1 <= len(writes[1]) <= 2
                and len(writes[2]) == 2
                and 7 <= len(cluster) <= 8
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
                "block_write_offsets": [
                    offset
                    for port in data_ports
                    for offset in writes[port]
                    if _has_backedge(image, offset)
                ],
            })
    return result


def find_audio_transport(image: bytes) -> dict[str, object]:
    """Return static ownership evidence; rejected classes stay fail-closed."""
    families = _marker_families(image)
    if not families:
        return {
            "family": "unknown", "grammar": None, "static_status": "not-detected",
            "reject_reason": "marker-none",
        }
    if len(families) != 1:
        return {
            "family": "unknown", "grammar": None, "static_status": "rejected",
            "reject_reason": "marker-ambiguous",
        }
    family = families[0]
    if family == "ma3":
        return {
            "family": family, "grammar": None, "static_status": "rejected",
            "reject_reason": "protocol-unsupported",
        }
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
    return {
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
    }


__all__ = ("find_audio_transport",)
