"""Closed boot-time instruction evidence owned by this domain."""
from __future__ import annotations
import re
import struct
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.signatures import find_all

GUEST_OWNED_STATUS_72C_CONSUMER = bytes.fromhex("0d48007b400907d3201c013c002803da0020f0bc08bc1847")
GUEST_OWNED_STATUS_72C_FUNCTION_PREFIX = bytes.fromhex("f0b5071c8408")
GUEST_OWNED_STATUS_72C_POWERDOWN_TAIL = bytes.fromhex("b9890123db029943b981b9893a681180002801d1")
GUEST_OWNED_STATUS_72C_CALL_GATE = bytes.fromhex("002801d1")

def detect_guest_owned_status_72c(image: bytes) -> tuple[bool, str | None]:
    """Recognise the one cross-checked status consumer that owns 0x0300072C."""
    consumers = find_all(image, GUEST_OWNED_STATUS_72C_CONSUMER)
    if not consumers:
        return False, None
    if len(consumers) != 1:
        return False, (
            "0x0300072C guest-owned candidate rejected: "
            f"{len(consumers)} status consumers are ambiguous"
        )
    consumer = consumers[0]
    function = consumer - 0x2E
    if (function < 0 or image[function:function + len(GUEST_OWNED_STATUS_72C_FUNCTION_PREFIX)] != GUEST_OWNED_STATUS_72C_FUNCTION_PREFIX or facts_for(image).thumb_literal_value(consumer,
        0) != 0x03000720):
        return False, ("0x0300072C guest-owned candidate rejected: " "status function or MMIO literal mismatch")
    callers: list[int] = []
    for compare in find_all(image, GUEST_OWNED_STATUS_72C_CALL_GATE):
        caller = compare - 6
        if (caller < 0 or facts_for(image).thumb_call_target(caller + 2) != function or facts_for(image).thumb_literal_value(caller, 0) != 0x2EE):
            continue
        sink = facts_for(image).thumb_call_target(caller + 10)
        if sink is None or not 0 <= sink < len(image):
            continue
        terminal = image.find(GUEST_OWNED_STATUS_72C_POWERDOWN_TAIL, sink, min(len(image), sink + 0x200),)
        unlock = terminal + len(GUEST_OWNED_STATUS_72C_POWERDOWN_TAIL)
        if (terminal < 0 or facts_for(image).thumb_call_target(unlock) is None or image[unlock + 4:unlock + 6] != b"\xfe\xe7"):
            continue
        callers.append(caller)
    if len(callers) != 1:
        return False, ("0x0300072C guest-owned candidate rejected: " "unique timeout caller/control sink relation absent")
    return True, ("temporary evidence-gated 0x0300072C guest-write-owned status " "grammar detected; reset default retained without read reassert")
