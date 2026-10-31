"""Source-closed legacy NV NOR geometry and mandatory storage paths.

Physical geometry is separate from logical read/program bounds. Error-reporting
callees are outside this bounded ownership proof. IDs describe a compatible
virtual device, not an independently identified handset part.
"""
from __future__ import annotations

import hashlib
import struct

from .arm import thumb_literal_value, thumb_bl_target
from .rex import _normalized_thumb_sha256, _legacy_620_vector_copy

_SPEC = {'init': {'size': 28,
          'digest': 'f1641b7c3b95fca408ae322b38db4cda18ae8401bde94861d6be3a121eab528a',
          'calls': ['0xa', '0x14'],
          'literals': [[2, 4, 16784888]]},
 'probe_wrapper': {'size': 16,
                   'digest': '9caaedcb2500e7616521181897b865fa0aa58451f27ab9f302f353827f336aaa',
                   'calls': ['0x2', '0xa'],
                   'literals': []},
 'probe': {'size': 88,
           'digest': 'bd4f8192efa40301e3e09c3da7009a2e935435e73f597ee734c3c3fa5569b95d',
           'calls': [],
           'literals': [[2, 1, 4197024],
                        [8, 1, 4195648],
                        [14, 0, 1610960],
                        [16, 1, 16784888],
                        [50, 0, 16784920]]},
 'sector': {'size': 40,
            'digest': 'b39573dfe9613a0a51c35f963bc03a8e214887dc2b675a074dbf7222ed896a57',
            'calls': ['0x22'],
            'literals': [[2, 1, 16784888]]},
 'read': {'size': 50,
          'digest': '1c5d4637eccf8ea17b16cea3104ebbb32e0c26f48f751f52e3169f39c0b7c521',
          'calls': ['0x2a'],
          'literals': [[2, 4, 16784888]]},
 'erase': {'size': 84,
           'digest': 'cb797f9b919bca1119692c2aba0c8a085fd80c0a94bf00135b8adef7ab8670c9',
           'calls': ['0x20'],
           'literals': [[4, 4, 16784888], [56, 0, 4197024], [58, 1, 4195648]]},
 'poll': {'size': 50,
          'digest': 'e25cfd52f9b8da7f455ef0a455ae716c94edf7a5915fffb4fb2f7cf997a954d3',
          'calls': [],
          'literals': [[2, 0, 16784888]]},
 'program': {'size': 446,
             'digest': '743175dc155247aa9e666b90cee1854d7ebe3cbd190b991d2cd3dcdde297f705',
             'calls': ['0x30', '0xae', '0x14c', '0x196', '0x1b4'],
             'literals': [[10, 6, 16784888],
                          [46, 6, 16784888],
                          [398, 6, 16784888],
                          [426, 6, 16784888]]},
 'watchdog': {'size': 68,
              'digest': '9bc0b863ff7c8f3b9dc98fbc3818995164c99e11ec52d780643cea59f2268e73',
              'calls': ['0xa', '0x26', '0x2a', '0x3e'],
              'literals': [[2, 0, 16784836],
                           [14, 7, 17187352],
                           [16, 3, 65534],
                           [20, 4, 50333184],
                           [48, 3, 65534]]},
 'status': {'size': 92,
            'digest': '04291aaa5bd1d0a94dd88972eb3856238c9a45146bb169f52677ba78697b73b3',
            'calls': ['0x4', '0x26'],
            'literals': [[12, 4, 16784888], [54, 0, 4197024], [56, 1, 4195648]]}}


def find_word_offset_nv_nor(image: bytes, ram_base: int, ram_size: int) -> tuple[int, int, int, int, int, int] | None:

    if (type(ram_base) is not int or type(ram_size) is not int
            or ram_base < 0 or ram_size <= 0
            or ram_base + ram_size > 0x100000000):
        return None

    def raw(at, size, digest):
        return type(at) is int and (not at & 1) and (0 <= at <= len(image) - size) and (hashlib.sha256(image[at:at + size]).hexdigest() == digest)

    def word(at):
        return struct.unpack_from('<I', image, at)[0] if type(at) is int and 0 <= at <= len(image) - 4 else None

    def shape(role, at):
        spec = _SPEC[role]
        return type(at) is int and (not at & 1) and (_normalized_thumb_sha256(image, at, spec['size']) == (spec['digest'], tuple((int(x, 16) for x in spec['calls']))))

    def lit(at, off, reg):
        return thumb_literal_value(image, at + off, reg)
    vec = _legacy_620_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
    if vec is None:
        return None
    source, target, length, _ = vec

    def copied(at, count):
        offset = at - target
        return source + offset if at % 4 == 0 and 0 <= offset <= length - count else None
    found = []
    at = 0
    while (at := image.find(struct.pack('<H', 46480), at)) >= 0:
        init = at
        at += 1
        if not shape('init', init):
            continue
        state = lit(init, 2, 4)
        if type(state) is not int or state & 3 or (not ram_base <= state <= ram_base + ram_size - 32):
            continue
        wrapper = thumb_bl_target(image, init + 10)
        trampoline = thumb_bl_target(image, init + 20)
        if not shape('probe_wrapper', wrapper) or word(trampoline) is None or image[trampoline:trampoline + 2] != struct.pack('<H', 18176):
            continue
        probe = thumb_bl_target(image, wrapper + 2)
        if not shape('probe', probe) or lit(probe, 16, 1) != state:
            continue
        descriptor80, pool = (lit(probe, 14, 0), lit(probe, 50, 0))
        if type(descriptor80) is not int or type(pool) is not int:
            continue
        descriptor = descriptor80 - 128
        pool_source = copied(pool, 16)
        if pool_source is None or word(pool_source) != descriptor or word(pool_source + 12) != 0:
            continue
        if descriptor & 3 or not 0 <= descriptor <= len(image) - 228:
            continue
        count = word(descriptor + 4)
        if count != 32 or any((word(descriptor + 8 + 4 * i) != 65536 for i in range(count))):
            continue
        if word(descriptor + 164) != 576651268 or word(descriptor + 168) != 0 or word(descriptor + 172) != 1:
            continue
        base, capacity = (word(descriptor + 176) * 2, word(descriptor + 180) * 2)
        size = count * 65536
        if base != 4194304 or size != 2097152 or capacity != 1048576 or (base + size > ram_base):
            continue
        if lit(probe, 2, 1) != base + 2720 or lit(probe, 8, 1) != base + 1344:
            continue
        entries = [word(descriptor + x) for x in (184, 188, 192)]
        if any((x is None or not x & 1 for x in entries)):
            continue
        read, program, erase = [x & ~1 for x in entries]
        if not raw(thumb_bl_target(image, read + 42), 134, '0e3aa8e72aab6a126d7073ee5a9fed6c0e24229fb427dc1b2e065fd3651d928a'):
            continue
        stub_ok = True
        for off in (208, 212, 216):
            pointer = word(descriptor + off)
            if pointer is None or not pointer & 1 or (not raw(pointer & ~1, 2, 'abd49ec8111be1f55319f91a44d26daaf5abd7567c169a61abf6c0b031d4b31c')):
                stub_ok = False
        if not stub_ok:
            continue
        if not all((shape(role, p) for role, p in [('read', read), ('program', program), ('erase', erase)])):
            continue
        if lit(read, 2, 4) != state or lit(erase, 4, 4) != state:
            continue
        if lit(erase, 56, 0) != base + 2720 or lit(erase, 58, 1) != base + 1344:
            continue
        if any((lit(program, off, 6) != state for off in (10, 46, 398, 426))):
            continue
        if any((thumb_bl_target(image, program + off) != trampoline for off in (48, 406, 436))) or thumb_bl_target(image, erase + 32) != trampoline:
            continue
        status_ptr = word(descriptor + 196)
        if status_ptr is None or not status_ptr & 1:
            continue
        status = status_ptr & ~1
        if not shape('status', status) or lit(status, 12, 4) != state or lit(status, 54, 0) != base + 2720 or (lit(status, 56, 1) != base + 1344):
            continue
        poll = thumb_bl_target(image, status + 4)
        if not shape('poll', poll) or lit(poll, 2, 0) != state or thumb_bl_target(image, status + 38) != trampoline:
            continue
        watchdog = thumb_bl_target(image, program + 174)
        if not shape('watchdog', watchdog) or thumb_bl_target(image, program + 332) != watchdog:
            continue
        if any((lit(watchdog, off, reg) != value for off, reg, value in _SPEC['watchdog']['literals'])):
            continue
        lock, unlock = (thumb_bl_target(image, watchdog + 10), thumb_bl_target(image, watchdog + 38))
        if not raw(lock, 28, '05bb1a2e651a889ae08f19e98607f956161b40424ed99b20b412b687a6667f10') or not raw(unlock, 28, 'd961305ca13c6c8a3d2a5bd54d508f2977a58483bff33d6de0ae24fa06c4fe82'):
            continue
        if lock & 3 or unlock & 3 or thumb_bl_target(image, watchdog + 42) != lock or (thumb_bl_target(image, watchdog + 62) != unlock):
            continue
        sector = init + 96
        if not shape('sector', sector) or lit(sector, 2, 1) != state:
            continue
        by_r1 = thumb_bl_target(image, sector + 34)
        if by_r1 is None or image[by_r1:by_r1 + 2] != struct.pack('<H', 18184):
            continue
        found.append((base, size, 65536, 4, 8799, 0))
    return found[0] if len(found) == 1 else None
