"""Samsung/SKT KEYEMUL semantic grammar detector."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import struct

from .arm import _thumb_reachable, thumb_bl_target


KEYEMU_NORMALIZER = bytes.fromhex(
    "c11f5a39192902d8c11f193900e0011c23393529"
)
KEYEMUL_MARKER = b"*SKT*KEYEMUL"
_KEYEMU_EVENTS = (
    ("(", 0x5F), (")", 0x60), ("A", 0x65), ("B", 0x66),
    ("C", 0x52), ("D", 0x64), ("F", 0x54), ("G", 0x55),
    ("M", 0x5B), ("O", 0x53), ("S", 0x50), ("U", 0x63),
)
# Public event exports are compatibility snapshots, not admission sources.
KEYEMU_EVENTS = _KEYEMU_EVENTS
_KEYEMU_PASSTHROUGH = "#*0123456789"
KEYEMU_PASSTHROUGH = _KEYEMU_PASSTHROUGH
_KEYEMU_SEMANTIC_CONTRACT = (
    ("direct_events", _KEYEMU_EVENTS),
    ("passthrough_events", tuple(
        (character, ord(character)) for character in _KEYEMU_PASSTHROUGH
    )),
    ("stateful_E", (0x51, 0x60)),
    ("compound_L", (0x78, 0x101)),
    ("W", (0x87, 0x8C)),
    ("release", 0xFF),
    ("same_dispatcher", (
        "direct-events", "digits", "star", "E", "L", "W", "release",
    )),
)
KEYEMU_SEMANTIC_CONTRACT = _KEYEMU_SEMANTIC_CONTRACT
_KEYEMU_GRAMMAR_FINGERPRINT = hashlib.sha256(
    json.dumps(
        _KEYEMU_SEMANTIC_CONTRACT, sort_keys=True, separators=(",", ":")
    ).encode()
).hexdigest()
KEYEMU_GRAMMAR_FINGERPRINT = _KEYEMU_GRAMMAR_FINGERPRINT


@dataclass(frozen=True)
class KeyemuSemantics:
    """Immutable detection result; callers own any runtime admission."""

    variant: str | None
    addresses: tuple[tuple[str, int], ...]
    event_map: tuple[tuple[str, tuple[int, ...]], ...]
    confidence: str
    evidence: tuple[str, ...]
    grammar_fingerprint: str | None = None
    reject_reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "variant": self.variant,
            "addresses": dict(self.addresses),
            "event_map": {key: list(value) for key, value in self.event_map},
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "grammar_fingerprint": self.grammar_fingerprint,
            "reject_reason": self.reject_reason,
        }


def _reject(reason: str, confidence: str = "rejected") -> KeyemuSemantics:
    return KeyemuSemantics(None, (), (), confidence, (), None, reason)


def _word(image: bytes, address: int) -> int | None:
    return (
        struct.unpack_from("<H", image, address)[0]
        if 0 <= address <= len(image) - 2 else None
    )


def _branch_target(image: bytes, address: int) -> int | None:
    word = _word(image, address)
    if word is None or word & 0xF800 != 0xE000:
        return None
    displacement = (word & 0x7FF) << 1
    if displacement & 0x800:
        displacement -= 0x1000
    return address + 4 + displacement


def _function_start(image: bytes, position: int) -> int:
    for current in range(position & ~1, max(-1, position - 0x400), -2):
        word = _word(image, current)
        if word is not None and word & 0xFE00 == 0xB400:
            return current
    return position


def _targets(
        image: bytes, after: int,
        direct_events: tuple[tuple[str, int], ...] = _KEYEMU_EVENTS,
        passthrough: str = _KEYEMU_PASSTHROUGH,
) -> tuple[str, int, int, dict[str, int]] | None:
    conditional = _word(image, after)
    if conditional is None or conditional & 0xFF00 != 0xD200:
        return None
    pair = (_word(image, after + 2), _word(image, after + 4))
    if pair == (0x004B, 0x449F):
        variant, add_pc, table = "halfword-branch-table", after + 4, after + 8
        target = lambda index: _branch_target(image, table + 2 * index)
    else:
        words = tuple(_word(image, after + offset) for offset in (2, 4, 6, 8))
        if (None in words or words[0] & 0xFF00 != 0xA300
                or words[1:] != (0x5C5B, 0x005B, 0x449F)):
            return None
        variant, add_pc = "byte-offset-table", after + 8
        table = ((after + 6) & ~3) + (words[0] & 0xFF) * 4
        target = lambda index: (
            add_pc + 4 + image[table + index] * 2
            if 0 <= table + index < len(image) else None
        )
    characters = (
        passthrough
        + "".join(sorted((*(key for key, _ in direct_events), "E", "L", "W")))
    )
    targets = {
        character: target(ord(character) - 0x23)
        for character in characters
    }
    if any(
            value is None or not 0 <= value < len(image)
            for value in targets.values()):
        return None
    return variant, add_pc, table, targets  # type: ignore[return-value]


def _direct_event(image: bytes, target: int, event: int) -> int | None:
    return (
        _branch_target(image, target + 2)
        if _word(image, target) == 0x2000 | event else None
    )


def _l_case(image: bytes, start: int, common_call: int) -> bool:
    reached = _thumb_reachable(image, start, common_call)
    hold = any(
        _word(image, current) == 0x2078
        and _branch_target(image, current + 2) == common_call
        for current in reached
    )
    compound = any(
        _word(image, current) == 0x20FF
        and _word(image, current + 2) == 0x3002
        and _branch_target(image, current + 4) == common_call
        for current in reached
    )
    return hold and compound


def _e_case(image: bytes, start: int, common_call: int) -> bool:
    if (_word(image, start) is None or _word(image, start) & 0xF807 != 0x7800
            or _word(image, start + 2) != 0x2800
            or _word(image, start + 4) is None
            or _word(image, start + 4) & 0xFF00 != 0xD000):
        return False
    alternate = start + 8 + ((_word(image, start + 4) & 0xFF) << 1)
    return (_word(image, start + 6) == 0x2060
            and _branch_target(image, start + 8) == common_call
            and _word(image, alternate) == 0x2051
            and _branch_target(image, alternate + 2) == common_call)


def _candidate(
        image: bytes, normalizer: int, load_address: int,
        direct_events: tuple[tuple[str, int], ...] = _KEYEMU_EVENTS,
        passthrough: str = _KEYEMU_PASSTHROUGH,
        grammar_fingerprint: str = _KEYEMU_GRAMMAR_FINGERPRINT,
) -> KeyemuSemantics | None:
    parsed = _targets(
        image, normalizer + len(KEYEMU_NORMALIZER), direct_events, passthrough
    )
    if parsed is None:
        return None
    variant, _add_pc, table, targets = parsed
    common_calls = {
        _direct_event(image, targets[key], value)
        for key, value in direct_events
    }
    if None in common_calls or len(common_calls) != 1:
        return None
    common_call = common_calls.pop()
    dispatcher = thumb_bl_target(image, common_call)
    if dispatcher is None or not 0 <= dispatcher < len(image):
        return None
    if any(targets[digit] != common_call for digit in "0123456789"):
        return None
    star_call = _direct_event(image, targets["*"], ord("*"))
    if (_word(image, targets["#"]) != 0x2023 or targets["#"] + 2 != common_call
            or star_call != common_call):
        return None
    if (not _e_case(image, targets["E"], common_call)
            or not _l_case(image, targets["L"], common_call)):
        return None
    release_calls = [
        current + 2
        for current in _thumb_reachable(
            image, common_call + 4, min(len(image), common_call + 0x30)
        )
        if (_word(image, current) == 0x20FF
            and thumb_bl_target(image, current + 2) == dispatcher)
    ]
    if len(release_calls) != 1:
        return None
    release_call = release_calls[0]
    w_word = _word(image, targets["W"])
    w_call = _direct_event(
        image, targets["W"], w_word & 0xFF if w_word is not None else -1
    )
    if w_call != common_call or w_word not in (0x2087, 0x208C):
        return None
    events = {
        character: (ord(character),)
        for character in passthrough
    }
    events.update({key: (value,) for key, value in direct_events})
    events.update({
        "E": (0x51, 0x60),
        "L": (0x78, 0x101),
        "W": (w_word & 0xFF,),
        "release": (0xFF,),
    })
    addresses = {
        "function": _function_start(image, normalizer), "normalizer": normalizer,
        "table": table, "common_call": common_call, "dispatcher": dispatcher,
        "release_call": release_call,
    }
    return KeyemuSemantics(
        variant,
        tuple(
            (key, load_address + value)
            for key, value in sorted(addresses.items())
        ),
        tuple(sorted(events.items())), "exact-native", (
            "lowercase-ascii-normalizer", "complete-keyemul-switch",
            "paired-flip-tokens",
            "common-dispatcher", "stateful-E", "compound-L",
            "same-dispatcher-release",
        ), grammar_fingerprint, None,
    )


def detect_keyemu_semantics(image: bytes, load_address: int = 0) -> KeyemuSemantics:
    """Accept one exact KEYEMUL parser; reject misses and ambiguous images."""
    matches: list[KeyemuSemantics] = []
    normalizers = 0
    position = image.find(KEYEMU_NORMALIZER)
    while position >= 0:
        normalizers += 1
        candidate = (
            _candidate(image, position, load_address)
            if not position & 1 else None
        )
        if candidate is not None:
            matches.append(candidate)
        position = image.find(KEYEMU_NORMALIZER, position + 1)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return _reject("multiple-exact-grammars", "ambiguous")
    if normalizers:
        return _reject("normalizer-without-exact-grammar")
    if KEYEMUL_MARKER in image:
        return _reject("marker-without-normalizer")
    return _reject("not-found", "not-found")
