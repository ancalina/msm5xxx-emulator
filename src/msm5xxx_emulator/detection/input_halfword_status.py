"""Descriptor-backed status candidates; no default level or physical role inferred."""
from __future__ import annotations

import struct

from .arm import (
    _thumb_reachable, _thumb_successors, _thumb_writes_register, thumb_bl_target,
    thumb_literal_value,
)
from .input_halfword import resolve_indirect_matrix_input
from .rex import _normalized_thumb_sha256


# Exact temporary producer/consumer class. BL destinations are checked below;
# unused diagnostic/service callees are bounded, not assigned device semantics.
_LOOP_STATUS_SHAPES = {
    'recurring': (bytes.fromhex('2d4f0120f8712c4f7868008810231840'), 6, 0xba,
                  '35a218f4c1955a8178ab7342408483e07306f62677bc1633700a1c5b0d284ffd', (2, 30, 44, 50, 56, 74, 104, 108, 132, 146, 152, 158, 176)),
    'startup': (bytes.fromhex('b3b581b000ab18790f1c0128'), 0, 0x98,
                'aa514ea0b183e762237b3f6ce8ddd54eea1fb256083c33baf1f0c95ec62f10cc', (26, 54, 78, 90, 102, 112, 132, 136)),
    'assignment': (bytes.fromhex('b0b51027792885b000d164e019dcdd4d'), 0, 0x382,
                   '057ad2b2d21cb533fea22817bf7dda023be25cf9c681f6e63a6b1c4443e77fbd', (36, 40, 52, 60, 82, 108, 118, 122, 130, 136, 140, 154, 164, 170, 176, 184, 200, 216, 222, 228, 236, 252, 260, 268, 294, 304, 308, 316, 322, 326, 338, 344, 350, 354, 360, 364, 370, 378, 384, 388, 394, 398, 404, 412, 416, 426, 430, 434, 438, 450, 458, 466, 478, 486, 494, 502, 518, 540, 548, 556, 562, 570, 580, 588, 600, 608, 618, 632, 638, 644, 650, 662, 674, 678, 682, 690, 696, 700, 706, 722, 730, 740, 746, 750, 754, 764, 776, 788, 796, 822, 828, 832, 840, 844, 850, 856, 864, 868, 872, 876, 886)),
    'registration': (bytes.fromhex('08b50c48'), 0, 0x34,
                     '4420582d563233971f042ee8acf49bae906ced50e6d887cfe716fcbc564acd02', (4, 20, 30, 46)),
    'callback': (bytes.fromhex('81b51e48007900280cd000ab18785128'), 0, 0x7c,
                 '8308f1cc2385f01a0ebd8e92eb52d0f1d2235d47f84e7db23647ac014f533b5d', (36, 106, 114)),
    'dequeue': (bytes.fromhex('0c4b59781878814201d100207047c018'), 0, 0x34,
                'e01851cd6550af5d2aec821c46b7b7c9c268687e31200be7d9c4e38abd3abc21', ()),
    'dispatch': (bytes.fromhex('f0b5'), 0, 0x4a,
                 '276882f1d32a742a7717083b53438466686c5eb8d4f46ca125e68206616a929e', (2, 48, 58, 68)),
    'submit': (bytes.fromhex('80b5071c011c'), 0, 0x20,
               '7a171a568adbc88ce770f728ded372f8ef8efa6d47b5ff2ccc72350ebaebd161', (6, 14, 22)),
    'install': (bytes.fromhex('feb504215848'), 0, 0x166,
                'fbb34e6d0787ee362921c8c0719c20654c28b26bdac296f884e59000b6055be1', (6, 70, 94, 124, 176, 196, 212, 220, 286, 304, 316, 328, 336, 342)),
}


def _loop_status(image: bytes, matrix: dict):
    def ram(p, size):
        return type(p) is int and 0x1000000 <= p <= 0x2000000 - size

    def call(p):
        if type(p) is not int or p & 1 or not 0 <= p <= len(image) - 4:
            return None
        target = thumb_bl_target(image, p)
        return target if target is not None and 0 <= target <= len(image) - 2 else None

    live, copied = matrix.get('descriptor'), matrix.get('copied_descriptor')
    state = matrix.get('scanner_state')
    selection = matrix.get('row_selection')
    mode = selection.get('mode_byte') if type(selection) is dict else None
    contact = matrix.get('contact_site')
    try:
        sink = int(matrix.get('queue_sink', ''), 16)
    except (ValueError, TypeError):
        return None, 'loop-status-matrix-contract', []
    if (not all(ram(p, n) for p, n in ((live, 0x38), (copied, 0x38),
                                      (state, 0x2c), (mode, 1)))
            or (live | copied) & 3 or type(contact) is not int
            or not 0x1a <= contact <= len(image)-2
            or not 0 <= sink <= len(image)-0x54):
        return None, 'loop-status-matrix-contract', []
    entry = contact - 0x1a
    helper, getter = call(entry+0x24), call(entry+0xe8)
    if (helper is None or getter is None or call(helper+2) != getter
            or image[getter:getter+6] != bytes.fromhex('014800787047')
            or thumb_literal_value(image, getter, 0) != mode):
        return None, 'loop-status-mode-reader', []
    matched = {}
    for name, (anchor, back, size, digest, calls) in _LOOP_STATUS_SHAPES.items():
        matches, start = [], 0
        while True:
            hit = image.find(anchor, start)
            if hit < 0:
                break
            start = hit+1
            p = hit-back
            normalized = _normalized_thumb_sha256(image, p, size)
            if (p >= 0 and not p & 1 and normalized is not None
                    and normalized == (digest, calls)
                    and all(call(p+d) is not None for d in normalized[1])):
                matches.append(p)
        if len(matches) != 1:
            return None, 'loop-status-' + ('not-found-' if not matches else 'ambiguous-') + name, []
        matched[name] = matches[0]
    r, s, a, reg, cb, dq, disp = (matched[n] for n in
        ('recurring', 'startup', 'assignment', 'registration', 'callback', 'dequeue', 'dispatch'))
    submit, install = matched['submit'], matched['install']
    setter = call(a+0x27e)
    ring = thumb_literal_value(image, cb+0x28, 2)
    gate = thumb_literal_value(image, cb+2, 0)
    # Same descriptor/copy/state and scanner initialization, both polarities,
    # same sink, and no reinterpretation of a separately found event namespace.
    if (thumb_literal_value(image, r+0xc, 7) != live
            or thumb_literal_value(image, s+0x3a, 4) != live
            or thumb_literal_value(image, r+0x50, 6) != copied
            or any(thumb_literal_value(image, r+d, 7) != state for d in (6,0x22,0x88))
            or thumb_literal_value(image, r+0x1a, 5) != r+1
            or call(r+0x1e) != helper
            or any(call(r+d) != sink for d in (0x2c,0x32,0x38,0x92,0x98,0x9e))
            or any(call(r+d) != call(sink+0x24) for d in (0x4a,0x6c))
            or any(call(r+d) != call(sink+0x4e) for d in (0x68,0x84))
            or setter is None or call(a+0x33c) != setter
            or image[setter:setter+6] != bytes.fromhex('014908707047')
            or thumb_literal_value(image, setter, 1) != mode
            or any(call(a+d) != getter for d in (0x28,0xb8,0xec))
            or thumb_literal_value(image, a+0x42, 7) != copied
            or thumb_literal_value(image, a+0x44, 4) != live
            or call(reg+0x14) != s
            or thumb_literal_value(image, reg+0x12, 1) != cb+1
            or any(image[call(s+d):call(s+d)+2] != bytes.fromhex('3847')
                   for d in (0x4e,0x5a,0x66,0x70,0x84))
            or len({call(s+d) for d in (0x4e,0x5a,0x66,0x70,0x84)}) != 1
            or not ram(ring,34) or not ram(gate,8)
            or thumb_literal_value(image, dq, 3) != ring
            or thumb_literal_value(image, reg+8, 0) != ring-2
            or call(disp+2) != dq or call(disp+0x3a) != a
            or thumb_literal_value(image, disp+0xc, 5) != ring+0x20
            or thumb_literal_value(image, disp+0xe, 6) != gate
            or thumb_literal_value(image, a+0xe, 5) != gate
            or thumb_literal_value(image, a+0x32c, 3) != gate
            or call(s+0x36) != submit
            or not ram(thumb_literal_value(image, submit+0xc, 0),12)
            or thumb_literal_value(image, submit+0xc, 0) != thumb_literal_value(image, install+0x154, 0)
            or not ram(thumb_literal_value(image, submit+0x14, 0),4)
            or thumb_literal_value(image, submit+0x14, 0) != thumb_literal_value(image, install+4, 0)
            or call(submit+0xe) != call(install+0x13c)
            or call(submit+0x16) != call(install+0x148)
            or call(s+0x1a) != call(install+0x156)
            or thumb_literal_value(image, install+0x10a, 1) != state+0x21
            or thumb_literal_value(image, install+0x114, 1) != state+0x20
            or call(install+0x46) != sink or call(install+0xc4) != sink):
        return None, 'loop-status-link-mismatch', []
    return {
        'grammar': 'indirect-halfword-loop-status-events-v1',
        'descriptor': live, 'pointer_offset': 4, 'width': 2, 'mask': 0x10,
        'read_site': r+0x10, 'read_sites': [s+0x40, r+0x10],
        'startup': s, 'helper': r, 'queue_sink': sink,
        'event_sites': {6: r+0x30, 8: r+0x96},
        'polarity': {'mask_set': 6, 'mask_clear': 8},
        'consumer': {'registration': reg, 'callback': cb, 'ring': ring,
                     'dequeue': dq, 'dispatch': disp, 'assignment': a,
                     'setter': setter, 'getter': getter, 'mode_byte': mode,
                     'submit': submit, 'install': install,
                     'enabled': state+0x21, 'callback_word': state+0x28,
                     'event_values': {6: 1, 8: 0}},
        'runtime_admitted': False, 'physical_role': None, 'default_level': None,
        'promotion': 'temporary-evidence-gated',
    }, 'static-candidate', []


def _event_reaches_sink(image: bytes, start: int, lower: int, end: int,
                        sink: int) -> bool:
    """Follow the callee-saved event, including a shared backward queue tail."""
    pending = [start]
    seen = set()
    while pending:
        pc = pending.pop()
        if pc in seen or pc & 1 or not lower <= pc <= end - 2:
            continue
        seen.add(pc)
        if (image[pc:pc + 2] == bytes.fromhex("381c")
                and thumb_bl_target(image, pc + 2) == sink):
            return True
        if not _thumb_writes_register(struct.unpack_from("<H", image, pc)[0], 7):
            pending.extend(_thumb_successors(image, pc, end))
    return False


def resolve_indirect_board_status(image: bytes, load_address: int = 0):
    """Find a unique status helper called before an accepted matrix scanner.

    The descriptor's live +4 pointer, MMIO ownership, and electrical level must
    still be verified by the runtime. A static candidate never enables a device.
    """
    matrix, status, _ = resolve_indirect_matrix_input(image, load_address)
    if matrix is None:
        return None, "matrix-" + status, []
    if matrix.get('grammar') == 'indirect-halfword-loop-six-row-v1':
        return _loop_status(image, matrix)
    presence = matrix["presence_site"]
    sink = int(matrix["queue_sink"], 16)
    found = []
    for call in range(max(0, presence - 0x100), presence - 10, 2):
        helper = thumb_bl_target(image, call)
        if (helper is None or not 0 <= helper < len(image)
                or image[call + 4:call + 8] != bytes.fromhex("002800d0")
                or struct.unpack_from("<H", image, call + 8)[0] & 0xF800 != 0xE000):
            continue
        exits = _thumb_successors(image, call + 8, len(image))
        if len(exits) != 1 or not matrix["sense_site"] < exits[0] < presence + 0x200:
            continue
        if presence not in _thumb_reachable(image, call + 10, presence + 2):
            continue
        limit = min(len(image), helper + 0x200)
        ends = [pc for pc in range(helper, limit - 5, 2)
                if image[pc:pc + 6] == bytes.fromhex("f0bc08bc1847")]
        if len(ends) != 1:
            continue
        end = ends[0]
        reads = [pc for pc in range(helper, min(end - 28, helper + 0x40), 2)
                 if thumb_literal_value(image, pc, 0) == matrix["descriptor"]
                 and image[pc + 2:pc + 14] == bytes.fromhex("406800880423184000260028")]
        if len(reads) != 1:
            continue
        read = reads[0]
        if read not in _thumb_reachable(image, helper, end):
            continue
        # Both status levels are normalized before the event/debounce paths.
        words = struct.unpack_from("<8H", image, read + 14)
        load, branch, one, clear_a, jump, zero, clear_b, _ = words
        register = load >> 8 & 7
        if (load & 0xF800 != 0x4800 or branch != 0xD002 or one != 0x2001
                or jump != 0xE001 or zero != 0x2000
                or any(w & 0xF807 != 0x7006 or (w >> 3 & 7) != register
                       for w in (clear_a, clear_b))):
            continue
        events = {}
        for event in (0x5F, 0x60):
            sites = [pc for pc in range(read + 28, end, 2)
                     if image[pc:pc + 2] == bytes((event, 0x27))
                     and _event_reaches_sink(image, pc + 2, helper, end, sink)]
            if len(sites) == 1:
                events[event] = sites[0]
        if len(events) != 2:
            continue
        # Threshold shapes corroborate the candidate; status-to-event polarity
        # and live debounce behavior still require runtime evidence.
        thresholds = []
        for event, threshold in ((0x5F, 2), (0x60, 3)):
            matches = []
            for pc in range(read + 28, events[event], 2):
                word, branch = struct.unpack_from("<HH", image, pc)
                if word & 0xF8FF == 0x2800 | threshold and branch & 0xFF00 == 0xDB00:
                    targets = _thumb_successors(image, pc + 2, end + 2)
                    if len(targets) == 2 and events[event] < targets[1] <= end:
                        matches.append(pc)
            if len(matches) == 1:
                thresholds.append(matches[0])
        if len(thresholds) != 2:
            continue
        found.append({
            "grammar": "indirect-halfword-status-events-v1",
            "descriptor": matrix["descriptor"], "pointer_offset": 4,
            "read_site": read + 4, "width": 2, "mask": 4,
            "helper": helper, "caller": call, "queue_sink": sink,
            "event_sites": events, "debounce_sites": thresholds,
            "runtime_admitted": False, "physical_role": None,
            "default_level": None,
        })
    if len(found) != 1:
        return None, "not-found" if not found else "ambiguous-status-helpers", found
    return found[0], "static-candidate", []
