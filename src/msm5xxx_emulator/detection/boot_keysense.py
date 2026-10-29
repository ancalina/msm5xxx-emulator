"""Source-bound boot predicate candidates, without a global input default."""
from __future__ import annotations

import struct

from .arm import arm_b_target, thumb_bl_target, thumb_literal_value

_LEAF = bytes.fromhex(
    '3f20164908750020144908701448007d0007000f1249097d0907090f88421ad1'
    '0f48007d0007000f0f2814d000200d49087000200b49087110200a4908720020'
    '084908730020074908740020054908750120f74601e00020fbe7fae7')
_LEAF_LITERALS = {2: (1, 0x03000660), 8: (1, 0x03000660),
                  12: (0, 0x03000680), 20: (1, 0x03000680),
                  32: (0, 0x03000680), 46: (1, 0x030006A0),
                  52: (1, 0x030006A0), 58: (1, 0x030006A0),
                  64: (1, 0x030006A0), 70: (1, 0x030006A0),
                  76: (1, 0x030006A0)}
_RESET_PREFIX = bytes.fromhex(
    '20429fe5010014e31ce29f151ce29f0514ff2fe17847000014429fe5010014e3'
    '10e29f1510e29f0514ff2fe17847000008429fe5010014e304e29f1504e29f05'
    '14ff2fe178470000000050e31e00001a0aa02ae0d7f021e3b4d19fe5dbf021e3'
    'e4d19fe5d3f021e3e0d19fe5e0419fe5010014e3dce19f15dce19f0514ff2fe1'
    '78470000d4a19fe5d4419fe5010014e3d0e19f15d0e19f0514ff2fe178470000'
    '000050e30800001a')
_GATE = bytes.fromhex('c0419fe5010014e3bce19f15bce19f0514ff2fe178470000000050e30b00001a')
_SERVICE = bytes.fromhex('d3f021e34cd19fe558a19fe57c419fe5010014e378e19f1578e19f0514ff2fe178470000')

_PREFIXED = bytes.fromhex('00b5d54501daf7f0d3fa2848007ac007c00f27d000202649088025480088c82806db1fe022480088013021490880f4e702e016f0d6fe37e004e016f0d2fe16f0d0fe31e004e01b480921c90508842be0194816f0b3fe012018490870002017490870dfe70820164908770820144908721f20134908750020114908700b48007d0007000f0949097d0907090f884208d10648007d0007000f0f2802d0012000bd01e00020fbe7fae7f9e7')
_PREFIXED_LITERALS = {10: (0, 50333312), 22: (1, 16778688), 26: (0, 16778688), 36: (0, 16778688), 42: (1, 16778688), 70: (0, 2110), 80: (0, 5000), 88: (1, 50333184), 94: (1, 50333184), 102: (1, 50333280), 108: (1, 50333280), 114: (1, 50333280), 120: (1, 50333280), 124: (0, 50333312), 132: (1, 50333312), 144: (0, 50333312)}
_PREFIXED_CALLS = (6, 0x32, 0x3A, 0x3E, 0x52)
_STACK_FAILURE = bytes.fromhex('7847000001e08ee30d00a0e10e10a0e100200fe10aa02ae054309fe5010013e350e09f1550e09f0513ff2fe178470000feffffea')
_DELAY = bytes.fromhex('15220921c905322802dd0a843238fae7002807dd1b2358432d30002800da3f3080110884f746')


def _u32(image: bytes, at: int) -> int | None:
    return struct.unpack_from('<I', image, at)[0] if 0 <= at <= len(image)-4 else None


def _shape(image: bytes, at: int, pattern: bytes,
           literals: dict[int, tuple[int, int]]) -> bool:
    if at & 1 or at < 0 or at+len(pattern) > len(image):
        return False
    holes = {offset+n for offset in literals for n in (0, 1)}
    return (all(image[at+i] == b for i, b in enumerate(pattern) if i not in holes)
            and all(thumb_literal_value(image, at+offset, reg) == value
                    for offset, (reg, value) in literals.items()))


def _arm_literal(image: bytes, at: int) -> int | None:
    word = _u32(image, at)
    if word is None or word & 0x0F7F0000 != 0x051F0000:
        return None
    return _u32(image, at+8+(word & 0xFFF)*(1 if word & 0x800000 else -1))


def _prefix_helpers(image: bytes, entry: int) -> bool:
    calls = {offset: thumb_bl_target(image, entry+offset) for offset in _PREFIXED_CALLS}
    if any(at is None or at & 1 or not 0 <= at <= len(image)-2 for at in calls.values()):
        return False
    stack, noop, delay = calls[6], calls[0x32], calls[0x52]
    if (calls[0x3A] != noop or calls[0x3E] != noop
            or image[noop:noop+2] != bytes.fromhex('f746')
            or image[delay:delay+len(_DELAY)] != _DELAY
            or image[stack:stack+len(_STACK_FAILURE)] != _STACK_FAILURE
            or _arm_literal(image, stack+0x20) != stack+0x2C
            or _arm_literal(image, stack+0x24) != stack+0x30):
        return False
    diagnostic = _arm_literal(image, stack+0x18)
    if diagnostic is None or not diagnostic & 1:
        return False
    diagnostic -= 1
    # Ordinary diagnostic ABI return reaches the local ARM self-loop.
    if (image[diagnostic:diagnostic+6] != bytes.fromhex('00b5d54501da')
            or thumb_bl_target(image, diagnostic+6) != stack
            or image[diagnostic+0x16:diagnostic+0x18] != bytes.fromhex('00bd')):
        return False
    for offset in (0xA, 0x12):
        target = thumb_bl_target(image, diagnostic+offset)
        if target is None or target & 1 or not 0 <= target <= len(image)-2:
            return False
    return image[diagnostic+0xE:diagnostic+0x12] == bytes.fromhex('02a10348')


def find_boot_keysense_release(image: bytes) -> tuple[dict | None, str]:
    """Admit a unique reset-linked, typed three-read released-low4 predicate."""
    candidates = []
    partial = False
    for pattern, literals, layout in ((_LEAF, _LEAF_LITERALS, 'leaf-low4-three-read'),
                                      (_PREFIXED, _PREFIXED_LITERALS, 'prefixed-low4-three-read')):
        start = 0
        while True:
            at = image.find(pattern[:2], start)
            if at < 0:
                break
            start = at+1
            if layout.startswith('prefixed'):
                holes = {offset+n for offset in _PREFIXED_CALLS for n in range(4)}
                holes.update(offset+n for offset in literals for n in (0, 1))
                shape = (not at & 1 and at+len(pattern) <= len(image)
                         and all(image[at+i] == b for i, b in enumerate(pattern) if i not in holes)
                         and all(thumb_literal_value(image, at+offset, reg) == value
                                 for offset, (reg, value) in literals.items()))
                if shape and not _prefix_helpers(image, at):
                    partial = True
                    continue
            else:
                shape = _shape(image, at, pattern, literals)
            if shape:
                candidates.append((at, layout))
    if len(candidates) != 1 or partial:
        return None, ('predicate-ambiguous' if len(candidates) > 1 else
                      'prefix-callee-contract-unclosed' if partial else 'predicate-not-closed')
    entry, layout = candidates[0]
    reset = arm_b_target(image, 0)
    if reset is None or reset & 3 or reset < 4:
        return None, 'reset-root-unclosed'
    gate = reset+len(_RESET_PREFIX)
    service = gate+0x50
    if (image[reset:gate] != _RESET_PREFIX
            or image[gate:gate+len(_GATE)] != _GATE
            or image[service:service+len(_SERVICE)] != _SERVICE):
        return None, 'reset-route-unclosed'
    if (_arm_literal(image, gate) != entry | 1
            or _arm_literal(image, gate+8) != gate+0x14
            or _arm_literal(image, gate+12) != gate+0x18):
        return None, 'predicate-call-link-unclosed'
    application = arm_b_target(image, gate+0x20)
    service_entry = _arm_literal(image, service+12)
    predicate_end = entry+len(_LEAF if layout.startswith('leaf') else _PREFIXED)
    if (application is None or application & 3 or not 0 <= application < len(image)-4
            or service_entry is None or not service_entry & 1
            or not 0 <= service_entry-1 < len(image)-2
            or application in range(reset, service+len(_SERVICE))
            or entry <= application < predicate_end
            or reset <= service_entry-1 < service+len(_SERVICE)
            or entry <= service_entry-1 < predicate_end
            or application == service_entry-1
            or _arm_literal(image, service+20) != service+0x20
            or _arm_literal(image, service+24) != service+0x24):
        return None, 'route-target-unclosed'
    helper_evidence = None
    if layout.startswith('prefixed'):
        stack = thumb_bl_target(image, entry+6)
        helper_evidence = {
            'stack_failure_entry': stack,
            'stack_failure_terminal_pc': stack+0x30,
            'stack_failure_diagnostic_entry': _arm_literal(image, stack+0x18)-1,
            'delay_entry': thumb_bl_target(image, entry+0x52),
            'noop_entry': thumb_bl_target(image, entry+0x32),
            'unsupported_path': 'ordinary diagnostic ABI return reaches local self-loop; nonlocal diagnostic side effects unproved',
        }
    return {'signature': 'arm-thumb-boot-keysense-release-v1',
            'admission': 'temporary-evidence-gated', 'candidate': True,
            'layout': layout, 'address': 0x03000694,
            'mask': 0xF, 'released': 0xF, 'read_pcs': [entry+x for x in ((14, 22, 34) if layout.startswith('leaf') else (0x7E, 0x86, 0x92))],
            'setup_pc': entry if layout.startswith('leaf') else entry+0x64, 'init_pc': entry, 'predicate_entry': entry,
            'reset_pc': reset, 'reset_call_pc': gate, 'return_pc': gate+0x18,
            'service_route_pc': service, 'service_entry': service_entry-1,
            'application_entry': application, 'helper_evidence': helper_evidence, 'service_result': 1,
            'application_result': 0,
            'code_intervals': [[reset, gate+0x24], [service, service+len(_SERVICE)],
                               [entry, entry+len(_LEAF if layout.startswith('leaf') else _PREFIXED)]]}, 'accepted-source-bound-candidate'
