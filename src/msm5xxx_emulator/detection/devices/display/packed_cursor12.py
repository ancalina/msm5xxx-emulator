"""Source evidence for the packed cursor12 panel protocol."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.fact_bodies import thumb_body

_PRODUCER = bytes.fromhex("b030d1e12332a0e1b230cbe1b230d1e0b0c0d1e1010080e2033205e04cc40ee003308ce1b230cbe1400bc0e3b030d1e1ff3003e2b230cbe1021081e2")
_HEADER = bytes.fromhex("b090cbe10000a0e3b200cbe1b080cbe1ff0002e2b200cbe1b070cbe1")
_THUMB_PRODUCER = bytes.fromhex("feb5002601277f063e80142000f0fafa40207880142000f0f5fa2b203880142000f0f0fa7e80142000f0ecfa00ab1e71324d012451e003203880142000f0e2fa7e80142000f0defa05203880142000f0d9fa00ab18797880142000f0d3fa0b20388000ab1e722ee000ab1879197ac00140184000285a000978801879c101187a1a7a0130187288184000285a0001f023184000ab18801879197ac00140184000285a1988000a0007000f084378801879197ac00140184000285a0006000e7880187a0130187200ab187a8028ccdb0c480470067018790130187100ab1879a028a9db2b203880142000f08cfa7c80142000f088fafebc08bc")
_THUMB_DELAYS = (12, 22, 32, 40, 60, 68, 78, 90, 232, 240)

def _thumb_producers(image: bytes) -> list[int]:
    facts = facts_for(image)
    template = thumb_body(facts_for(_THUMB_PRODUCER), 0, len(_THUMB_PRODUCER), call_offsets=_THUMB_DELAYS, literal_offsets=())
    hits = []
    for at in facts.string_candidates(_THUMB_PRODUCER[:12]):
        if at & 1:
            continue
        body = thumb_body(facts, at, len(_THUMB_PRODUCER), call_offsets=_THUMB_DELAYS, literal_offsets=())
        if body is not None and body.normalized == template.normalized and len({target for _, target in body.calls}) == 1:
            hits.append(at)
    return hits

def find_packed_cursor12_port(image: bytes) -> tuple[int | None, str]:
    """Require one aligned producer with its own transport and width bindings."""
    hits = _thumb_producers(image)
    start = 0
    while (at := image.find(_PRODUCER, start)) >= 0:
        start = at + 1
        if (at >= 0x160 and at % 4 == 0 and image[at-0x160:at-0x15c] == bytes.fromhex("80b7a0e3") and image[at-0x124:at-0x118] == bytes.fromhex("0b70a0e30580a0e30390a0e3")
            and image[at-0x114:at-0x110] == bytes.fromhex("0fe0a0e3") and image[at-0x4c:at-0x30] == _HEADER and image[at+60:at+76] == bytes.fromhex("010080e2400bc0e3800050e3e7ffffba")):
            hits.append(at)
    if len(hits) != 1:
        return None, "producer-binding-absent-or-ambiguous"
    return 0x02000000, "bound-packed12-row-producer"
