"""Source linkage from a repeating timer to a contact scanner."""
from msm5xxx_emulator.detection.facts import facts_for
import re
import struct
from ...facts import facts_for

def periodic_caller(image: bytes, scanner: int, *, callback_window=0x40, callback_push=None, timer_registers=(4, 5)) -> bool:
    """Tie a direct caller to a repeating clock-registration argument grammar."""
    callbacks = set()
    for pc, target in facts_for(image).call_candidates():
        if target != scanner:
            continue
        # A callback invokes the scanner near its entry (guards may return early).
        for entry in range(pc - 2, max(-1, pc - callback_window), -2):
            w = struct.unpack_from('<H', image, entry)[0]
            if (w & 0xFF00 == 0xB500 and (callback_push is None or w == callback_push)):
                callbacks.add(entry | 1)
                break
    if not callbacks:
        return False
    # repeat=1 on stack; equal nonzero initial/repeat periods in r2/r3;
    # timer object in r0; callback literal in r1; direct clock-service call.
    registration = re.compile(rb"\x01\x22\x00\x92(.)\x22(.)\x23(.)\x1c.\x49", re.S)
    for match in registration.finditer(image):
        pc = match.start()
        if (pc & 1 or match[1] != match[2] or match[1] == b'\x00' or match[3][0] not in tuple(0x20 + 8 * (r - 4) for r in timer_registers)):
            continue
        callback = facts_for(image).thumb_literal_value(pc + 10, 1)
        service = facts_for(image).thumb_call_target(pc + 12)
        if callback in callbacks and service is not None and 0 <= service < len(image):
            return True
    return False
