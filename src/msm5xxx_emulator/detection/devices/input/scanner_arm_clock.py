"""Source-closed HIGH-open byte scanner owned by an ARM periodic clock setup."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.fact_bodies import normalized_body, thumb_body
from msm5xxx_emulator.detection.values import CodeAddress
import re
import struct
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.devices.input.scanner_callees import callee_at

# Complete instruction bodies, excluding pools; normalize BL displacement and
# literal-load imm8 only. Register selection, branches, masks and stores remain.
_PROFILES = {'timer_initializer': (28, '4b196c044a5537f86c2b386bf3b929e1c33d35c24c99a57d46967632b417ca11', (20,), ()), 'scanner': (488,
    'be23d9ea6fe7abe9f8ade85d63876b95378fd67d1e18d4b1d27f73ae016b17a4', (40, 60, 64, 88, 92, 114, 118, 144, 148, 170, 174, 216, 236, 240, 264, 268, 288, 292,
    314, 378, 384, 408, 412, 452, 464, 476), ((2, 0), (8, 6), (16, 5), (18, 7), (68, 5), (80, 5), (96, 2), (122, 1), (128, 5), (152, 1), (178, 1), (198, 1), (208,
    2), (244, 5), (250, 6), (296, 2), (322, 0), (332, 2), (340, 1), (420, 4))), 'power': (48, '53494c716007c64a1d716675152b7d18da1f5340afd2729c1f48c73b648c9921',
    (8, 18, 26, 32, 38), ((22, 7),)), 'command_leaf': (8, 'df0a4509958641ab0fed21c7b22ec652c007203df234a4dbb6262c439f9ee909', (), ()), 'event_ring_producer': (130,
    'c624662f3b91c679f50120a376db97faea58cc7f5059e647d09b0cc01e0f2216', (12, 104, 120), ((16, 0), (68, 2), (100, 1), (102, 0), (108, 0))), 'callback_prefix': (32,
    '93b324cfaee08af4cb25131a3d75a669e8950c73e6d2e07321829bfc1187fd86', (18, 22), ((0, 0), (16, 0))), 'clock_registration_service': (70,
    'bc3060f6502df24ec6f66d1586b8df827bf323493e299452a5503ff37138b718', (18, 36, 42, 60), ((14, 1), (16, 0), (30, 0), (32, 1)))}

def _body(image: bytes, start: int, name: str) -> tuple[dict[int, int], dict[int, int]] | None:
    length, digest, calls, literals = _PROFILES[name]
    if start < 0 or start & 1 or start + length > len(image):
        return None
    body = thumb_body(facts_for(image), start, length, limit=len(image), call_offsets=calls, literal_offsets=tuple(offset for offset, _ in literals), call_fill=struct.pack('<HH',
        0xf000, 0xf800), literal_keep_mask=0xff00)
    if body is None or body.sha256 != digest:
        return None
    targets = dict(body.calls)
    if any(not 0 <= target < len(image) for target in targets.values()):
        return None
    if {offset: register for offset, register, _, _ in body.literals} != dict(literals):
        return None
    return targets, {offset: value for offset, _, value, _ in body.literals}

def _ram(value: int, room: int = 0) -> bool:
    return 0x01000000 <= value < 0x01800000 - room

def _thunk(image: bytes, start: int) -> int | None:
    if start < 0 or start & 3 or start + 12 > len(image):
        return None
    load, branch, target = struct.unpack_from('<III', image, start)
    if (load, branch) != (0xe59fc000, 0xe12fff1c) or not target & 1:
        return None
    return target & ~1

def _registration(image: bytes, scanner: int, ring: int) -> bool:
    # ARM: repeat=1 on stack, equal 25-unit initial/repeat arguments, with the
    # same RAM clock object passed to its initializer and registration service.
    anchor = struct.pack('<4I', 0xe3a03001, 0xe58d3000, 0xe3a03019, 0xe3a02019)
    for match in re.finditer(re.escape(anchor), image):
        start = match.start() - 12
        if start < 0 or start & 3 or start + 40 > len(image):
            continue
        body = normalized_body(facts_for(image), CodeAddress(start, 'arm'), 40, limit=len(image), arm_literals=(0, 28), arm_branches=(8, 36), call_fill=b'\0\0\0\xeb')
        if body is None or body.sha256 != 'ded2b71f23c55a6c82edd392d28f9f360555881dd680e9fe40ed095c1ec2fb94':
            continue
        if any(struct.unpack_from('<I', image, start + offset)[0] >> 24 != 0xeb for offset in (8, 36)):
            continue
        literals = {offset: (pool, value) for offset, _, pool, value in body.literals}
        if any(struct.unpack_from('<I', image, start + offset)[0] & 0xffff0000 != 0xe59f0000 or literals[offset][0] & 3 or not 0 <= literals[offset][0] <= len(image)
            - 4 for offset in (0, 28)):
            continue
        values = {offset: value for offset, (_, value) in literals.items()}
        calls = dict(body.branches)
        if (values[0] != ring + 0x24 or not _ram(values[0], 0x40) or not values[28] & 1):
            continue
        callback = _body(image, values[28] & ~1, 'callback_prefix')
        service = _thunk(image, calls[36])
        initializer = _thunk(image, calls[8])
        if (callback is None or callback[0][0x16] != scanner or not _ram(callback[1][0], 8) or not _ram(callback[1][0x10], 0x20) or not callee_at(image,
            callback[0][0x12], 'rex_clr_sigs') or service is None or initializer is None or _body(image, initializer, 'timer_initializer') is None):
            continue
        clock = _body(image, service, 'clock_registration_service')
        init = _body(image, initializer, 'timer_initializer')
        if clock is not None and init is not None:
            calls, _ = clock
            if (calls[0x12] == calls[0x24] and callee_at(image, calls[0x12], 'assert_helper') and callee_at(image, calls[0x2a], 'clock_remove') and callee_at(image,
                calls[0x3c], 'clock_insert') and callee_at(image, init[0][0x14], 'clock_subobject_initializer')):
                return True
    return False

def arm_clock_scanner_at(image: bytes, start: int) -> tuple[BoardStatusInput | None, str]:
    """Prove the complete 2/10-scan 5F/60 input, power and periodic ownership."""
    if image[start + 4:start + 8] != struct.pack('<HH', 0x7800, 0x2308):
        return None, ''
    body = _body(image, start, 'scanner')
    if body is None:
        return None, ''
    calls, values = body
    address, state, shadow, remote = (values[x] for x in (2, 0x12, 0x10, 0x44))
    if (not 0x03000000 <= address < 0x03800000 - 0x20 or any(values[x] != address for x in (8, 0x50, 0x80, 0xfa)) or not all(_ram(v, 0x40) for k, v in values.items()
        if k not in (2, 8, 0x50, 0x80, 0xfa)) or state < 0x01000030 or any(values[x] != state for x in (0xc6, 0x154, 0x1a4)) or values[0x60] != shadow - 2 or
        values[0x128] != shadow - 2 or values[0x7a] != shadow - 1 or values[0xb2] != shadow - 3 or values[0xf4] != remote or values[0x98] != remote - 1 or
        values[0xd0] != values[0x14c]):
        return None, 'arm-clock-scanner-state-mismatch'
    for group in ((0x28, 0x40, 0x5c, 0x76, 0x94, 0xae, 0xd8, 0xf0, 0x10c, 0x124), (0x3c, 0x58, 0x72, 0x90, 0xaa, 0xec, 0x108, 0x120, 0x13a), (0x17a, 0x1c4,
        0x1dc), (0x180, 0x198)):
        if len({calls[x] for x in group}) != 1:
            return None, 'arm-clock-scanner-callee-mismatch'
    for offset, name in ((0x28, 'irq_lock'), (0x3c, 'irq_unlock'), (0x19c, 'scanner_aux_display_message'), (0x1d0, 'scanner_aux_time')):
        if not callee_at(image, calls[offset], name):
            return None, 'arm-clock-scanner-primitive-unclosed'
    power = _body(image, calls[0x180], 'power')
    event = _body(image, calls[0x17a], 'event_ring_producer')
    if power is None or event is None:
        return None, 'arm-clock-scanner-power-or-event-unclosed'
    pc, pv = power
    if (len({pc[x] for x in (8, 0x12, 0x26)}) != 1 or pc[0x1a] != pc[0x20] or pv[0x16] != 50000 or _body(image, pc[8], 'command_leaf') is None or not callee_at(image,
        pc[0x1a], 'power_delay')):
        return None, 'arm-clock-scanner-wake-unclosed'
    ec, ev = event
    if not all(callee_at(image, ec[offset], name) for offset, name in ((0xc, 'event_cancel_timer'), (0x68, 'assert_helper'), (0x78, 'rex_set_sigs'))):
        return None, 'arm-clock-scanner-event-sinks-unclosed'
    ring = ev[0x44]
    if (ev[0x10] != state - 0x30 or ev[0x6c] != ring or not _ram(ring - 8, 0x40) or not 0 <= ev[0x64] < len(image) or not _registration(image, start, ring)):
        return None, 'arm-clock-scanner-periodic-unclosed'
    return BoardStatusInput(address, 8, 8), ''
