"""Source-bound byte page controller with separate low/high pixel planes.

Instruction digests retain all operations, branch edges and register operands;
only BL relocation fields and literal-load displacements are normalized.
Runtime still requires the complete source initialization and page raster.
"""
from __future__ import annotations
import struct
from .arm import thumb_bl_target, thumb_literal_value, thumb_normalized_source_shape as _function

_LAYOUTS = ({'height': 128, 'installer_shape': (46, 'fc65b9fcdfe84a65e40afada6ef04bed9b49a588978dfbd7597d3106c1261576', (8, 20, 26, 34), (2, 30)),
  'graphics_height': 128,
  'driver_pages': 16,
  'shapes': {'init': (300,
                      '235d5349c1a8ef510d76396be9d2c195580cbaeee863df90ebadf5996de6d23d',
                      (8, 26, 60, 92, 158, 168, 178, 188, 212, 218, 228, 244, 282, 288),
                      (6, 76)),
             'main_mode': (82,
                           '652e96807ef5bb81af4667c96613b27fd9d42b80f8be0e51d651328a8010deae',
                           (66,),
                           (48,)),
             'sub_mode': (82,
                          '4a27ce064906b9134798723de89b0b98e060b1050407fc140634b42a8759415d',
                          (66,),
                          (48,)),
             'contrast': (12,
                          'ccd43f115ad9804b9b1fe514660bfa486c9b78d532ad5bcdf445b62203ce7a53',
                          (),
                          ()),
             'flush': (124,
                       '6c76bdcc07cde7dbb64d2c4021c7acb0a6bacd106ff9e9b3af3e11db5dc52091',
                       (72, 78),
                       ()),
             'off': (16,
                     'e19326d6093f0bf3b0077c76b8dd45f6c1a6d202086cb24358a1bc8fa6a70a48',
                     (),
                     ()),
             'page': (14,
                      'd86fbcbe462062288654d31a099c1c08c6cacd40f11bac448646dbec5f89e05d',
                      (),
                      ()),
             'column': (24,
                        'a9d5669e01d19ef75d58dfa5a0fcfc0dea396ae4334d6b49212ad0b6513d8754',
                        (),
                        ()),
             'pixel_line': (238,
                            '4e8b9dd33901150fb3480233f98bb08f35a9aa6e8a86e19b151a3056c695732e',
                            (226,),
                            (92, 100, 114, 122, 140, 146, 148, 162, 168, 170, 192)),
             'bridge': (50,
                        'd32b8d0db32aa9e9a838de7b635c643f6b6da25dfa22678d37e1e6295bdf3069',
                        (12, 20, 40),
                        (2, 16)),
             'getter': (4,
                        '06936d0536d64e86c623270163a043c1b484bbc978af8fbf56cd1650cbfb6587',
                        (),
                        (0,)),
             'installer': (46,
                           'fc65b9fcdfe84a65e40afada6ef04bed9b49a588978dfbd7597d3106c1261576',
                           (8, 20, 26, 34),
                           (2, 30))},
  'init_page': 212,
  'init_column': 218,
  'pixel_bridge': 226,
  'bridge_dispatch': 40,
  'bridge_state': (2,)},
 {'height': 96, 'installer_shape': (96, '1172a9d7be1a44b1bc0b24a340defb445ebaa161cd11ef49181d4efadf66b8fe', (34, 56, 60, 72, 84), (2, 66)),
  'graphics_height': 80,
  'driver_pages': 12,
  'shapes': {'init': (286,
                      'e25652de3e3549d99faef38e75b2a2cef29acb7bb4bca5f972a83bb7c61192dc',
                      (8, 26, 60, 90, 156, 166, 176, 186, 210, 216, 226, 242),
                      (6,)),
             'main_mode': (72,
                           'cc5b54f76df7983bf4ffe8b4825fc0ff1273cd113deb3d8f3cafc33d18552c64',
                           (56,),
                           ()),
             'sub_mode': (72,
                          'bdf58b6c68cbb86eb0fadb7b6eaa73b81b4e9895f4af5da08a49057844170d3b',
                          (56,),
                          ()),
             'contrast': (12,
                          'ccd43f115ad9804b9b1fe514660bfa486c9b78d532ad5bcdf445b62203ce7a53',
                          (),
                          ()),
             'flush': (126,
                       '6024ad61ada2a88f7d187a753410a3f3b8ac3483796ef7b824ae5c71cc94f553',
                       (72, 78),
                       ()),
             'off': (16,
                     'e19326d6093f0bf3b0077c76b8dd45f6c1a6d202086cb24358a1bc8fa6a70a48',
                     (),
                     ()),
             'page': (14,
                      'd86fbcbe462062288654d31a099c1c08c6cacd40f11bac448646dbec5f89e05d',
                      (),
                      ()),
             'column': (24,
                        'a9d5669e01d19ef75d58dfa5a0fcfc0dea396ae4334d6b49212ad0b6513d8754',
                        (),
                        ()),
             'pixel_line': (244,
                            'c4d3c050f182b7f312f24f8be802c5edf031841bd45d5c0e3dd1e60e6de0dc38',
                            (230,),
                            (94, 102, 116, 122, 142, 152, 168, 178, 200, 226)),
             'bridge': (62,
                        '9efdb2189378f69206aee4beefe489f1136249b7773f49e5e3e21da37daad4f0',
                        (20, 30, 50),
                        (4, 28, 34)),
             'getter': (4,
                        '06936d0536d64e86c623270163a043c1b484bbc978af8fbf56cd1650cbfb6587',
                        (),
                        (0,)),
             'installer': (96,
                           '1172a9d7be1a44b1bc0b24a340defb445ebaa161cd11ef49181d4efadf66b8fe',
                           (34, 56, 60, 72, 84),
                           (2, 66))},
  'init_page': 210,
  'init_column': 216,
  'pixel_bridge': 230,
  'bridge_dispatch': 50,
  'bridge_state': (4, 34)})




def _prefix(image, init, end_offset, context):
    """Interpret the closed branch-free constant command producer only."""
    registers = [None]*8; commands = []; offset = 0
    while offset < end_offset:
        word = struct.unpack_from('<H', image, init+offset)[0]
        kind = word & 0xf800
        if kind == 0xf000:
            if thumb_bl_target(image, init+offset) is None:
                return None
            registers[:4] = [None]*4; offset += 4; continue
        if kind == 0x2000:
            registers[word >> 8 & 7] = word & 255
        elif kind == 0x0000:
            source = registers[word >> 3 & 7]
            registers[word & 7] = ((source << (word >> 6 & 31)) & 0xffffffff
                                    if isinstance(source, int) else None)
        elif kind == 0x1800:
            left = registers[word >> 3 & 7]
            right = (word >> 6 & 7) if word & 0x400 else registers[word >> 6 & 7]
            registers[word & 7] = ((left + (-right if word & 0x200 else right)) & 0xffffffff
                                    if isinstance(left, int) and isinstance(right, int) else None)
        elif kind in (0x3000, 0x3800):
            reg = word >> 8 & 7; old = registers[reg]
            registers[reg] = ((old + (word & 255)*(1 if kind == 0x3000 else -1)) & 0xffffffff
                               if isinstance(old, int) else None)
        elif kind == 0x4800:
            registers[word >> 8 & 7] = thumb_literal_value(image, init+offset, word >> 8 & 7)
        elif word & 0xff00 == 0x4600:
            rd = (word & 7) | (word >> 4 & 8); rs = word >> 3 & 15
            if rd >= 8:
                return None
            registers[rd] = registers[rs] if rs < 8 else None
        elif kind == 0x7800:
            base = registers[word >> 3 & 7]
            if (context is None or base != context or word & 7 != 0
                    or (word >> 6 & 31) != 4):
                return None
            registers[0] = 'contrast'
        elif kind == 0x7000:
            base = registers[word >> 3 & 7]; value = registers[word & 7]
            if base != 0x02000000 or word >> 6 & 31:
                return None
            if value == 'contrast':
                commands.append(None)
            elif isinstance(value, int) and 0 <= value <= 255:
                commands.append(value)
            else:
                return None
        elif word & 0xfe00 != 0xb400:  # Initial PUSH, no control-flow inference.
            return None
        offset += 2
    if (not commands or commands[:2] != [0xe2, 0x48]
            or commands[-2:] != [0xa6, 0xa4]
            or commands.count(None) != (1 if context is not None else 0)):
        return None
    return commands


def _ram(address, size):
    return isinstance(address, int) and 0x01000000 <= address <= 0x02000000-size


def _getter(image, table, state, layout, bridge):
    """Close the getter, installer store, and indirect init-call ABI."""
    candidates = []
    for getter in range(0, min(len(image)-8, 0x10000), 2):
        if (struct.unpack_from('<2H', image, getter) != (0x4800, 0x4770)
                or thumb_literal_value(image, getter, 0) != table):
            continue
        for call in range(6, min(len(image)-16, 0x10000), 2):
            if thumb_bl_target(image, call) != getter:
                continue
            head = struct.unpack_from('<3H', image, call-6)
            tail = struct.unpack_from('<5H', image, call+4)
            if (head[0] & 0xff00 != 0x4f00 or head[1:] != (0x2000, 0x6038)
                    or thumb_literal_value(image, call-6, 7) != state
                    or tail[:2] != (0x6038, 0x2800) or tail[2] & 0xff00 != 0xd000
                    or tail[3] != 0x6840):
                continue
            thunk = thumb_bl_target(image, call+0xc)
            if thunk is None or image[thunk:thunk+2] != struct.pack('<H', 0x4700):
                continue
            offset = 8 if layout['height'] == 128 else 0x48
            entry = call-offset
            found = _function(image, entry, layout['installer_shape'])
            if found is None:
                continue
            if layout['height'] == 128:
                if (found[1][2] != state or found[1][0x1e] != bridge[1][0x10]
                        or found[0][0x1a] != bridge[0][0xc]
                        or found[0][0x22] != bridge[0][0x14]):
                    continue
            elif found[1][0x42] != state or not _ram(found[1][2], 4):
                continue
            candidates.append((getter, call, thunk, entry, found))
    return candidates[0] if len(candidates) == 1 else None


def _candidate(image, table, name, layout):
    shapes = layout['shapes']; methods = struct.unpack_from('<7I', image, table)[1:]
    if any(not value & 1 or not 0 <= value-1 < len(image)-2 for value in methods):
        return None
    roles = ('init', 'main_mode', 'sub_mode', 'contrast', 'flush', 'off')
    entries = dict(zip(roles, (value-1 for value in methods))); matched = {}
    for role, at in entries.items():
        matched[role] = _function(image, at, shapes[role])
        if matched[role] is None:
            return None
    init_calls, init_literals, _ = matched['init']; flush_calls = matched['flush'][0]
    page, column = flush_calls[0x48], flush_calls[0x4e]
    if init_calls[layout['init_page']] != page or init_calls[layout['init_column']] != column:
        return None
    for role, at in (('page', page), ('column', column)):
        entries[role] = at; matched[role] = _function(image, at, shapes[role])
        if matched[role] is None:
            return None
    # Every delay call in the init and mode setters shares one implementation.
    delay_offsets = (0x1a, 0x3c, 0x5c, 0x9e, 0xa8, 0xb2, 0xbc) if layout['height'] == 128 else (0x1a, 0x3c, 0x5a, 0x9c, 0xa6, 0xb0, 0xba)
    delay = init_calls[0x1a]
    if (any(init_calls[o] != delay for o in delay_offsets)
            or any(next(iter(matched[role][0].values())) != delay for role in ('main_mode', 'sub_mode'))):
        return None
    divide_offsets = (0xe4, 0xf4) if layout['height'] == 128 else (0xe2, 0xf2)
    if init_calls[divide_offsets[0]] != init_calls[divide_offsets[1]] or init_literals[6] != name+15 or name+24 > len(image):
        return None
    # The reviewed setter supplies the numeric plane significance and y bit order.
    pixels = []; cursor = 0
    anchor = struct.pack('<H', 0xb5f0)  # Thumb PUSH {r4-r7,lr}; full body checked below.
    while (at := image.find(anchor, cursor, min(len(image), 0x10000))) >= 0:
        cursor = at+2; found = _function(image, at, shapes['pixel_line'])
        if found is not None:
            pixels.append((at, found))
    if len(pixels) != 1:
        return None
    pixel, pixel_shape = pixels[0]; values = pixel_shape[1]
    if layout['height'] == 128:
        state = values[0x5c]; mask = values[0x64]; low = state+0x1c
        if (not all(values[o] == state for o in (0x72, 0x8c, 0xa2, 0xc0))
                or not all(values[o] == mask for o in (0x7a, 0x94, 0xaa))
                or values[0x92] != 0x79c or values[0xa8] != 0x79c):
            return None
    else:
        low = values[0x5e]; state = values[0xc8]; mask = values[0x66]
        if (not all(values[o] == low for o in (0x74, 0x8e, 0xa8, 0xe2))
                or not all(values[o] == mask for o in (0x7a, 0x98, 0xb2))):
            return None
    plane = 120*layout['driver_pages']
    if ((low|state|mask)&3 or not _ram(low, plane*2) or not _ram(state, 4) or not 0 <= mask <= len(image)-128
            or struct.unpack_from('<32I', image, mask) != tuple(1 << bit for bit in range(32))):
        return None
    bridge = pixel_shape[0][layout['pixel_bridge']]
    bridge_shape = _function(image, bridge, shapes['bridge'])
    if bridge_shape is None:
        return None
    bridge_state = bridge_shape[1][layout['bridge_state'][0]]
    if bridge_state&3 or not _ram(bridge_state, 5) or any(bridge_shape[1][o] != bridge_state for o in layout['bridge_state']):
        return None
    dispatch = bridge_shape[0][layout['bridge_dispatch']]
    if image[dispatch:dispatch+2] != struct.pack('<H', 0x4720 if layout['height'] == 128 else 0x4738):
        return None
    if layout['height'] == 128:
        if init_literals[0x4c] != bridge_state or any(matched[r][1][0x30] != bridge_state for r in ('main_mode', 'sub_mode')):
            return None
    getter = _getter(image, table, bridge_state, layout, bridge_shape)
    if getter is None:
        return None
    prefix = _prefix(image, entries['init'], layout['init_page'], bridge_state if layout['height'] == 128 else None)
    if prefix is None:
        return None
    entries.update(pixel_line=pixel, bridge=bridge)
    intervals = [(at, at+shapes[role][0]) for role, at in entries.items()]
    intervals += [(getter[0], getter[0]+4), (getter[3], getter[3]+layout['installer_shape'][0])]
    if len(set(entries.values())) != len(entries) or any(a < d and c < b for i,(a,b) in enumerate(intervals) for c,d in intervals[i+1:]):
        return None
    pools = sorted(set(v for found in list(matched.values())+[pixel_shape, bridge_shape, getter[4]] for v in found[2]))
    filename=bridge_shape[1][0x10 if layout['height']==128 else 0x1c]
    if not 0 <= filename < len(image):return None
    terminator=image.find(bytes(1),filename,min(len(image),filename+128))
    if terminator<=filename or any(not 32<=v<127 for v in image[filename:terminator]):return None
    data = [(getter[0]+4, getter[0]+8), (table, table+28), (name, name+24),
            (mask, mask+128), (filename,terminator+1)]
    ram = [(low, low+plane*2), (state, state+(0x1c if layout['height'] == 128 else 0x1e)),
           (bridge_state, bridge_state+5)]
    def overlap(a, b):
        return a[0] < b[1] and b[0] < a[1]
    if (any(not 0 <= a < b <= len(image) for a,b in intervals+pools+data)
            or any(overlap(a,b) for a in intervals for b in pools+data)
            or any(overlap(a,b) for a in pools for b in data)
            or any(overlap(a,b) for i,a in enumerate(pools) for b in pools[i+1:])
            or any(overlap(a,b) for i,a in enumerate(data) for b in data[i+1:])
            or any(not _ram(a,b-a) for a,b in ram)
            or any(overlap(a,b) for i,a in enumerate(ram) for b in ram[i+1:])):
        return None
    return dict(class_name='source-byte-paired-plane-page-v1', candidate=True,
        evidence_gate='temporary-evidence-gated', width=120, height=layout['height'],
        graphics_height=layout['graphics_height'], driver_pages=layout['driver_pages'],
        bits_per_pixel=2, logical_y_reverse=False, column_bias=0, column_capacity=240,
        command_port=0x02000000, data_port=0x02000004, access_width=1,
        main_pages=list(range(16)), required_pages=16, init_row_bytes=240,
        icon_page=-1, init_commands=prefix, init_entry=entries['init'], producer_entry=entries['flush'],
        controller_part='KS0741', optical_polarity=None, optical_orientation=None,
        device_table=table, device_state=bridge_state, pixel_setter=pixel,
        installer_call=getter[1], getter_entry=getter[0], framebuffer_low=low,
        plane_stride=plane, plane_weights=[2, 1], code_intervals=[list(v) for v in intervals],
        literal_intervals=[list(v) for v in pools], data_intervals=[list(v) for v in data],
        ram_intervals=[list(v) for v in ram])


def find_ks0741_page_profile(image, *, require_boot_family=False):
    """Admit one linked driver and setter class; runtime raster proof follows."""
    complete = []; name = 0
    while (name := image.find(b'Samsung KS0741\0', name)) >= 0:
        needle = struct.pack('<I', name)
        for table in range(0, min(len(image)-28, 0x10000), 4):
            if image[table:table+4] != needle:
                continue
            for layout in _LAYOUTS:
                profile = _candidate(image, table, name, layout)
                if profile is not None:
                    complete.append(profile)
        name += 1
    if len(complete) != 1:
        return None, 'paired-plane-source-ambiguous' if complete else 'paired-plane-source-not-closed'
    if require_boot_family:
        from .boot_contact_5100 import _candidate as boot_candidate, _LAYOUTS as boot_layouts
        if not any(boot_candidate(image,complete[0],layout) is not None for layout in boot_layouts):
            return None,'paired-plane-boot-owner-unclosed'
    return complete[0], 'accepted-source-bound-paired-plane-page'
