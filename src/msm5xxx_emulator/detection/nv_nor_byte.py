"""Source-closed legacy NV NOR geometry and mandatory storage paths.

Physical geometry is separate from logical read/program bounds. Error-reporting
callees are outside this bounded ownership proof. IDs describe a compatible
virtual device, not an independently identified handset part.
"""
from __future__ import annotations

import hashlib
import struct

from .arm import thumb_literal_value, thumb_bl_target
from .rex import _normalized_thumb_sha256

_SPEC = {'init': {'size': 80,
          'digest': '7f223ffda12adae04d10b94286755b43bc19d442c892e1968832d249d6bcc1cb',
          'calls': [],
          'literals': [[2, 0, 20476208], [16, 1, 21007568]]},
 'sector': {'size': 56,
            'digest': 'd6f6305459dea0c069c61be97ceef1c7e306820e528598d597d8019263b3463e',
            'calls': ['0x10', '0x32'],
            'literals': [[2, 4, 20476208], [12, 1, 1815636], [14, 0, 935]]},
 'read': {'size': 72,
          'digest': 'b6591566952e4139124413eac0d5f2ab0d06d5a1a54c4096e0f3431d069b7da6',
          'calls': ['0x20', '0x38', '0x40'],
          'literals': [[8, 1, 20476208], [36, 1, 20476208]]},
 'erase': {'size': 100,
           'digest': 'cd32b8813e40ffb05466c7a1d1a8dc334dbe18822d96a72f7c4ad331030f03e8',
           'calls': ['0x22', '0x36', '0x3e', '0x44', '0x56'],
           'literals': [[2, 4, 20476208],
                        [10, 5, 1815636],
                        [58, 0, 21003876],
                        [60, 1, 965],
                        [72, 1, 20476428],
                        [84, 0, 1367]]},
 'erase_command': {'size': 68,
                   'digest': '1e2f06ccc4b919390fb1800c0485b270c0b5e6566de06e19a62aaa296172705d',
                   'calls': ['0x4', '0x24', '0x2c', '0x38'],
                   'literals': [[8, 1, 4197024],
                                [14, 2, 4195648],
                                [52, 1, 1815636],
                                [54, 0, 683]]},
 'program': {'size': 188,
             'digest': '44c974b47b89b8e2aa604cfb185d1544b5156e41e895609007021b56141ccb92',
             'calls': ['0x2c',
                       '0x42',
                       '0x6a',
                       '0x7c',
                       '0x84',
                       '0x90',
                       '0x94',
                       '0xa8',
                       '0xb0',
                       '0xb4'],
             'literals': [[4, 0, 20476208],
                          [110, 2, 4197024],
                          [140, 1, 1815636],
                          [142, 0, 1637],
                          [172, 0, 21003876],
                          [174, 1, 965]]},
 'bypass_enter': {'size': 40,
                  'digest': 'f7915e2d38a701bf49ce117ebb964fec521cd0e83a87eee46af03ab24923092f',
                  'calls': ['0x2', '0x1a'],
                  'literals': [[6, 1, 4197024], [12, 3, 4195648]]},
 'bypass_exit': {'size': 32,
                 'digest': '7d9ce83fc4ab498ada141bef8e2654c8c20c421eace6148d5d8663576846f329',
                 'calls': ['0x2', '0x14'],
                 'literals': [[6, 1, 4194656]]},
 'aligned': {'size': 124,
             'digest': '7075b38721c71e62afc20adc3aac0e2a470b8d8e8abe0e5cf671971172d0aafe',
             'calls': ['0x18', '0x24', '0x2c', '0x34', '0x44', '0x56', '0x5e'],
             'literals': [[20, 1, 1815636],
                          [22, 0, 1478],
                          [40, 0, 21003876],
                          [42, 1, 965],
                          [56, 2, 4197024],
                          [90, 0, 21003876],
                          [92, 1, 965]]},
 'finder': {'size': 40,
            'digest': 'ea0756da1f3360d095e974c938754ae8969dd04d800bcd46c7839ce3d4534ece',
            'calls': [],
            'literals': [[6, 3, 21007568]]},
 'offset': {'size': 30,
            'digest': 'ff7e5c258652a47831585f00b690084fac95524c7fa1a6d1600a2cedcc62db2f',
            'calls': [],
            'literals': [[6, 3, 21007568]]},
 'scatter': {'size': 216,
             'digest': '51b7ea0e248858397ac8c52a11f5996610f9d95a75cbbc1e10ef218812c767aa',
             'calls': [],
             'literals': [[2, 1, 50333184],
                          [10, 0, 9224],
                          [14, 1, 9228],
                          [20, 0, 9220],
                          [24, 0, 9224],
                          [46, 1, 50333184],
                          [58, 1, 50333184],
                          [66, 0, 9232],
                          [70, 1, 9236],
                          [76, 0, 9232],
                          [96, 1, 50333184],
                          [108, 1, 50333184],
                          [116, 0, 16424],
                          [120, 1, 16428],
                          [126, 0, 16420],
                          [130, 0, 16424],
                          [152, 1, 50333184],
                          [164, 1, 50333184],
                          [172, 0, 16432],
                          [176, 1, 16436],
                          [182, 0, 16432],
                          [202, 1, 50333184],
                          [214, 1, 50333184]]},
 'status_poll': {'size': 106,
                 'digest': 'c37f2cd8171e9e5327f4328296efef06328e5d585346a095312fb2c282589e69',
                 'calls': ['0xa', '0x12', '0x18', '0x24'],
                 'literals': [[14, 0, 21003876],
                              [16, 1, 965],
                              [30, 2, 21007556],
                              [44, 2, 21007556]]},
 'noop': {'size': 2,
          'digest': 'abd49ec8111be1f55319f91a44d26daaf5abd7567c169a61abf6c0b031d4b31c',
          'calls': [],
          'literals': []},
 'set_event': {'size': 26,
               'digest': '17dc4cceb081bac259758d57f20f7047225bf69250b9ae6088707f2dd9894310',
               'calls': ['0x4', '0x14'],
               'literals': [[8, 1, 20448908]]},
 'timer_set': {'size': 82,
               'digest': '9b75697abf202912360b145d465afa485909b1be88e0431cf1b16e002eb01aff',
               'calls': ['0x6', '0x38', '0x42', '0x4a'],
               'literals': [[18, 0, 20742936]]},
 'clear_signal': {'size': 30,
                  'digest': '845a84d29978d7bf790bee54853f3bd7f43cc24fbcf956aebbc7f2636d222c70',
                  'calls': ['0x6', '0x16'],
                  'literals': []},
 'status_callback': {'size': 18,
                     'digest': 'c7a50e7d11cd848911086505f92ae3430cac04eb9a8a184fb265d778c7ac7ed5',
                     'calls': [],
                     'literals': [[0, 1, 20476208]]}}


def find_byte_offset_nv_nor(image: bytes, ram_base: int, ram_size: int) -> tuple[int, int, int, int] | None:

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

    def call(at, off):
        return thumb_bl_target(image, at + off)

    def hits(marker):
        at = 0
        while (at := image.find(struct.pack('<H', marker), at)) >= 0:
            yield at
            at += 1
    scatters = [at for at in hits(8193) if shape('scatter', at)]
    if len(scatters) != 1:
        return None
    scatter = scatters[0]
    table = lit(scatter, 126, 0)
    if type(table) is not int or table & 3 or lit(scatter, 116, 0) != table + 4 or (lit(scatter, 120, 1) != table + 8):
        return None
    source, target, length = (word(table), word(table + 4), word(table + 8))
    if any((type(x) is not int or x & 3 for x in (source, target, length))) or source + length > len(image) or (not ram_base <= target <= target + length <= ram_base + ram_size):
        return None
    found = []
    for init in hits(46480):
        if not shape('init', init):
            continue
        state, work = (lit(init, 2, 0), lit(init, 16, 1))
        if any((type(x) is not int or x & 3 for x in (state, work))):
            continue
        descriptor_ram = state + 16
        descriptor = source + descriptor_ram - target
        bss, bss_size = (word(table + 12), word(table + 16))
        if type(bss) is not int or type(bss_size) is not int or bss & 3 or bss_size & 3 or (bss_size <= 0) or (not ram_base <= bss < bss + bss_size <= ram_base + ram_size):
            continue
        if max(bss, state) < min(bss + bss_size, descriptor_ram + 228):
            continue
        if not target <= state <= descriptor_ram + 228 <= target + length or not ram_base <= work <= ram_base + ram_size - 272:
            continue
        if word(descriptor + 4) != 14 or any((word(descriptor + 8 + 4 * i) != 65536 for i in range(14))) or word(descriptor + 164) != 6225924:
            continue
        if word(descriptor + 176) != 4259840 or word(descriptor + 180) != 917504 or word(descriptor + 208) != descriptor_ram:
            continue
        pointers = [word(descriptor + x) for x in (184, 188, 192)]
        if any((x is None or not x & 1 for x in pointers)):
            continue
        read, program, erase = [x & ~1 for x in pointers]
        if not all((shape(role, p) for role, p in [('read', read), ('program', program), ('erase', erase)])):
            continue
        if any((lit(read, off, 1) != state for off in (8, 36))) or lit(program, 4, 0) != state or lit(erase, 2, 4) != state:
            continue
        command = call(erase, 68)
        enter, aligned, leave = (call(program, 44), call(program, 66), call(program, 180))
        if not all((shape(role, p) for role, p in [('erase_command', command), ('bypass_enter', enter), ('bypass_exit', leave), ('aligned', aligned)])):
            continue
        if call(program, 148) != leave:
            continue
        if lit(command, 8, 1) != 4197024 or lit(command, 14, 2) != 4195648 or lit(enter, 6, 1) != 4197024 or (lit(enter, 12, 3) != 4195648):
            continue
        if lit(program, 110, 2) != 4197024 or lit(aligned, 56, 2) != 4197024 or lit(leave, 6, 1) != 4194656:
            continue
        lock, unlock = (call(read, 32), call(read, 64))
        if not raw(call(read, 56), 134, '0e3aa8e72aab6a126d7073ee5a9fed6c0e24229fb427dc1b2e065fd3651d928a'):
            continue
        if not raw(lock, 28, '05bb1a2e651a889ae08f19e98607f956161b40424ed99b20b412b687a6667f10') or not raw(unlock, 28, 'd961305ca13c6c8a3d2a5bd54d508f2977a58483bff33d6de0ae24fa06c4fe82'):
            continue
        if lock & 3 or unlock & 3:
            continue
        if any((call(at, off) != lock for at, off in [(program, 106), (enter, 2), (leave, 2), (command, 4), (aligned, 52)])):
            continue
        if any((call(at, off) != unlock for at, off in [(program, 124), (enter, 26), (leave, 20), (command, 36), (aligned, 68)])):
            continue
        status = call(command, 44)
        if not shape('status_poll', status) or call(program, 132) != status:
            continue
        if any((lit(status, off, reg) != value for off, reg, value in _SPEC['status_poll']['literals'])):
            continue
        event, timer, noop = (call(status, 10), call(status, 18), call(status, 24))
        if not shape('set_event', event) or not shape('timer_set', timer) or (not shape('noop', noop)) or (call(status, 36) != noop):
            continue
        if call(event, 4) != lock or call(event, 20) != unlock or call(timer, 6) != lock or (call(timer, 74) != unlock):
            continue
        if any((lit(event, off, reg) != value for off, reg, value in _SPEC['set_event']['literals'])):
            continue
        if any((lit(timer, off, reg) != value for off, reg, value in _SPEC['timer_set']['literals'])):
            continue
        clear = call(timer, 66)
        if not shape('clear_signal', clear) or call(clear, 6) != lock or call(clear, 22) != unlock:
            continue
        mandatory = [(program, 168, event), (program, 176, timer), (aligned, 36, event), (aligned, 44, timer), (aligned, 86, event), (aligned, 94, timer), (erase, 54, event), (erase, 62, timer)]
        if any((call(at, off) != destination for at, off, destination in mandatory)):
            continue
        if any((any((lit(body, off, reg) != value for off, reg, value in _SPEC[role]['literals'])) for role, body in [('program', program), ('aligned', aligned), ('erase', erase)])):
            continue
        callback = word(descriptor + 196)
        if callback is None or not callback & 1 or (not shape('status_callback', callback & ~1)) or (lit(callback & ~1, 0, 1) != state):
            continue
        finder, offset, sector = (aligned + 124, init - 748, init + 216)
        if not all((shape(role, p) for role, p in [('finder', finder), ('offset', offset), ('sector', sector)])):
            continue
        if lit(finder, 6, 3) != work or lit(offset, 6, 3) != work or lit(sector, 2, 4) != state:
            continue
        by_r1 = call(sector, 50)
        if by_r1 is None or image[by_r1:by_r1 + 2] != struct.pack('<H', 18184):
            continue
        if 6291456 > ram_base:
            continue
        found.append((4194304, 2097152, 4, 95))
    return found[0] if len(found) == 1 else None
