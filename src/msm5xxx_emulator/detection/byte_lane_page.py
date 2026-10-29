"""Temporary source-bound BYTE command/data+2 page class; physical optics unknown."""
from __future__ import annotations

import struct

from .mono_page import _shape

# Complete typed compiler bodies; only literal loads and BL encodings relocate.
_SPEC = {
    'init': (bytes.fromhex('f0b4e220012252061070ab20107067201070ae211170a0201070c82010702423137081201070182010702f2010704c20107005201070af201070117056211170137010700021882700240807000fb023184310701020107014700020cb010a4d5b1aed188607b60f3b1cf34093702c5401300006000e7f28f4dd01310906090e0a29e2dbf0bc7047'), (), ((94, 5),)),
    'partial': (bytes.fromhex('feb41c1c0029079f00da00210a2900db09210a2a00db0922002c00da0024772f00dd772700902007000f02907020204003091020184301267606019015e0009843180807000fb02528433070351c0198287002982870201c2e1c03e005015d5db5700130b842f9dd01319142e7dd0020febc7047'), (), ()),
    'lookup': (bytes.fromhex('00487047'), (), ((0, 0),)),
    'init_callback': (bytes.fromhex('00b5fff725ff002008bc1847'), (2,), ()),
    'setup': (bytes.fromhex('80b50b4f0020386000f088f83860002803d0406841f186f805e040f19ffd0549c520e9f7f3ff80bc08bc00201847'), (8, 20, 26, 34), ((2, 7), (30, 1))),
    'outer': (bytes.fromhex('00b508f003fd08bc1847'), (2,), ()),
    'wrapper': (bytes.fromhex('98b50c4c071c2068002806d140f14efdff2006300849e9f7a1ff7f22009220680f22002300214469381c41f127f898bc08bc1847'), (12, 22, 42), ((2, 4), (20, 1))),
    'noop': (bytes.fromhex('00207047'), (), ()),
    'on': (bytes.fromhex('af2001214906087000207047'), (), ()),
    'contrast': (bytes.fromhex('81214a0611708006800e107000207047'), (), ()),
    'off': (bytes.fromhex('ae2001214906087000207047'), (), ()),
    'plane': (bytes.fromhex('7722084800920f2200231c30002108f0dcfefebc08bc1847'), (14,), ((2, 0),)),
    'glyph': (bytes.fromhex('ffb590b08648199d8168d2000f9289580291c168139b01910021da07d20f059104915142002b00db111c0e91591c002b00db191c4b10ea07d20f5142002d0d9300db111c0c91691c019f0b91002f01daf81d00e0381cc110481c7a425207520f52427b075b0f002f00db1a1c0a92002a00d1081c0990c8e00020069010980599674f0c182001c219b3e0654fb8680f99401841680498431c0493081879680027095c069803911199c00007904018089096e001200399b840084046d0002c00da8be00898c11900d587e0772c00dd84e07f2900dd81e00e9b002b0cd04811800010181c3000900368c806460e4d4880591843009b0be04811800010181c300090cb06484e5b0e0068f3589843009b18600d9b002b0bd048118000434b1018c018c906404e490e7158036819430be0481180003d4b1018c018c9063a4e490e71580368c9431940016047e0042d45d0002c43db0898c01940d4772c3edc7f283cdc291c0c9900290cd04111890051181c310091c3062b4e5b0e0968f3581943009b0be04111890051181c310091c306254e5b0e0968f3589943009b1960291c002d00da0b9949100bd0411189001e4b5118c918c0061b4e400e30580b6818430be041118900184b5118c918c006154e400e30580b68c043184008600137082f05da07980199c019884200da62e70698013006900a99002900d1019909980699884200dd42e705990131059102980599814200da31e7029814b0f0bc08bc1847'), (), ((4, 0), (128, 7), (138, 7), (236, 0), (258, 6), (282, 3), (290, 6), (306, 3), (314, 6), (372, 6), (398, 6), (428, 3), (436, 6), (452, 3), (460, 6))),
}
_GLYPH_REFS = ((4, 0, 'context'), (128, 7, 'context'), (138, 7, 'context'), (236, 0, 'mask'), (258, 6, 'mask'), (282, 3, 'plane2'), (290, 6, 'mask'), (306, 3, 'plane2'), (314, 6, 'mask'), (372, 6, 'mask'), (398, 6, 'mask'), (428, 3, 'plane2'), (436, 6, 'mask'), (452, 3, 'plane2'), (460, 6, 'mask'))


def _hits(image, role):
    pattern, calls, literals = _SPEC[role]
    holes = {offset + n for offset in calls for n in range(4)}
    holes.update(offset + n for offset, _ in literals for n in (0, 1))
    runs = []
    start = 0
    while start < len(pattern):
        if start in holes:
            start += 1
            continue
        end = start + 1
        while end < len(pattern) and end not in holes:
            end += 1
        runs.append((start, pattern[start:end]))
        start = end
    offset, anchor = max(runs, key=lambda run: len(run[1]))
    start = 0
    while True:
        hit = image.find(anchor, start)
        if hit < 0:
            return
        start = hit + 1
        at = hit - offset
        result = _shape(image, at, pattern, calls, literals)
        if result is not None:
            yield at, result


def _at(image, at, role):
    return _shape(image, at, *_SPEC[role])


def _overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def _group(image, setup, setup_shape, partial):
    setup_calls, setup_literals = setup_shape
    global_ = setup_literals[2]
    if global_ & 3 or not 0x01000000 <= global_ <= 0x02000000 - 4:
        return None
    lookup = setup_calls[8]
    lookup_shape = _at(image, lookup, 'lookup')
    if lookup_shape is None:
        return None
    object_ = lookup_shape[1][0]
    if object_ & 3 or not 0 <= object_ <= len(image) - 28:
        return None
    words = struct.unpack_from('<7I', image, object_)
    if not 0 <= words[0] < len(image) or any(not value & 1 for value in words[1:]):
        return None
    callbacks = [value - 1 for value in words[1:]]
    if callbacks[4] != partial:
        return None
    roles = {'setup': setup, 'lookup': lookup, 'partial': partial}
    for role, at in zip(('init_callback', 'noop', 'on', 'contrast', 'partial', 'off'), callbacks):
        if _at(image, at, role) is None:
            return None
        roles[role] = at
    init = _at(image, roles['init_callback'], 'init_callback')[0][2]
    init_shape = _at(image, init, 'init')
    if init_shape is None:
        return None
    roles['init'] = init
    cache = init_shape[1][0x5e]
    cache_span = (cache, cache + 9 * 127 + 128)
    if cache & 3 or not 0x01000000 <= cache < cache_span[1] <= 0x02000000 or _overlap(cache_span, (global_, global_ + 4)):
        return None
    init_thunk = setup_calls[20]
    if image[init_thunk:init_thunk + 2] != b'\x00\x47':
        return None
    outers = [(at, shape) for at, shape in _hits(image, 'outer') if shape[0][2] == setup]
    wrappers = [(at, shape) for at, shape in _hits(image, 'wrapper')
                if shape[1][2] == global_]
    if len(outers) != 1 or len(wrappers) != 1:
        return None
    outer, _ = outers[0]
    wrapper, wrapper_shape = wrappers[0]
    partial_thunk = wrapper_shape[0][42]
    if (image[partial_thunk:partial_thunk + 2] != b'\x20\x47' or
            wrapper_shape[0][12] != setup_calls[26] or
            wrapper_shape[0][22] != setup_calls[34]):
        return None
    roles.update(outer=outer, wrapper=wrapper)
    planes = [(at, shape) for at, shape in _hits(image, 'plane') if shape[0][14] == wrapper]
    software = []
    for glyph, shape in _hits(image, 'glyph'):
        values = shape[1]
        context = values[_GLYPH_REFS[0][0]]
        masks = {values[offset] for offset, _, role in _GLYPH_REFS if role == 'mask'}
        if (context & 3 or not 0x01000000 <= context < context + 0x1c + 2 * 120 * 16 <= 0x02000000 or len(masks) != 1 or
                any(values[offset] != context for offset, _, role in _GLYPH_REFS if role == 'context') or
                any(values[offset] != 0x79c for offset, _, role in _GLYPH_REFS if role == 'plane2')):
            continue
        mask = next(iter(masks))
        if (mask & 3 or mask + 128 > len(image) or
                struct.unpack_from('<32I', image, mask) != tuple(1 << bit for bit in range(32))):
            continue
        linked = [(at, sh) for at, sh in planes if sh[1][2] == context]
        if not linked or _overlap((context + 0x1c, context + 0x1c + 3840), (global_, global_ + 4)):
            continue
        software.append((glyph, context, mask, linked))
    if len(software) != 1:
        return None
    glyph, context, mask, linked = software[0]
    roles['glyph'] = glyph
    intervals = [(at, at + len(_SPEC[role][0])) for role, at in roles.items()]
    intervals += [(at, at + len(_SPEC['plane'][0])) for at, _ in linked]
    intervals += [(init_thunk, init_thunk + 2), (partial_thunk, partial_thunk + 2)]
    if any(_overlap(a, b) for i, a in enumerate(intervals) for b in intervals[i + 1:]):
        return None
    pools = []
    for role, at in roles.items():
        for offset, _ in _SPEC[role][2]:
            op = struct.unpack_from('<H', image, at + offset)[0]
            pool = ((at + offset + 4) & ~3) + (op & 255) * 4
            pools.append((pool, pool + 4))
    for at, _ in linked:
        op = struct.unpack_from('<H', image, at + 2)[0]
        pool = ((at + 6) & ~3) + (op & 255) * 4
        pools.append((pool, pool + 4))
    data = pools + [(object_, object_ + 28), (mask, mask + 128)]
    if any(not 0 <= a < b <= len(image) or any(_overlap((a, b), code) for code in intervals)
           for a, b in data):
        return None
    # These diagnostic calls are outside the proven non-null selected path.
    if any(any(a <= target < b for a, b in intervals + data)
           for target in (setup_calls[26], setup_calls[34])):
        return None
    offsets = (2, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 18, 60, 30, 54)
    commands = [struct.unpack_from('<H', image, init + offset)[0] & 255 for offset in offsets]
    return {'class_name': 'byte-lane-page120x80-v1', 'candidate': True,
            'evidence_gate': 'temporary-evidence-gated', 'witness_count': 1,
            'width': 120, 'height': 80, 'logical_width': 120, 'logical_height': 80,
            'column_capacity': 128, 'column_bias': 0, 'bits_per_pixel': 1,
            'command_port': 0x02000000, 'data_port': 0x02000002, 'access_width': 1,
            'main_pages': list(range(10)), 'icon_page': None, 'init_data_argument': None,
            'init_commands': commands, 'init_row_bytes': 128, 'required_pages': 10,
            'init_entry': init, 'producer_entry': partial, 'software_producer': glyph,
            'object': object_, 'object_global': global_, 'initializer_wrapper': setup,
            'partial_wrapper': wrapper, 'context_address': context, 'buffer_address': context + 0x1c,
            'software_width': 120, 'software_height': 128, 'software_column_stride': 16,
            'plane_policy': 'one-selected-plane-raw-byte-no-combine',
            'source_pcs': {'init_command_write': init + 8, 'init_data_write': init + 0x6c,
                           'page_write': partial + 0x4a, 'column_high_write': partial + 0x50,
                           'column_low_write': partial + 0x54, 'data_write': partial + 0x60,
                           'first_plane_calls': [at + 14 for at, _ in linked]},
            'helpers': roles, 'code_intervals': [list(pair) for pair in intervals],
            'literal_intervals': [list(pair) for pair in sorted(set(data))],
            'optical_polarity': None, 'optical_orientation': None, 'controller_part': None,
            'physical_geometry': None, 'unsupported_path': 'null-global diagnostic nonlocal behavior unproved'}


def find_byte_lane_page_profile(image: bytes) -> tuple[dict | None, str]:
    """Admit one complete source-owned group; filenames and hashes are irrelevant."""
    if not isinstance(image, (bytes, bytearray)):
        return None, 'byte-lane-page-image-type-invalid'
    complete = []
    setups = list(_hits(image, 'setup'))
    for partial, _ in _hits(image, 'partial'):
        for setup, shape in setups:
            profile = _group(image, setup, shape, partial)
            if profile is not None:
                complete.append(profile)
    complete.extend(_paired_profiles(image))
    if len(complete) != 1:
        return None, 'byte-lane-page-group-ambiguous' if complete else 'byte-lane-page-links-not-closed'
    return complete[0], 'accepted-source-bound-byte-lane-page-candidate'


# Complete source-owned ARM/Thumb bodies; only typed branches and pools relocate.
_PAIRED_SPECS = {
    'data': (bytes.fromhex('8017a0e30200c1e51eff2fe1'), (), ()),
    'command': (bytes.fromhex('8017a0e30000c1e51eff2fe1'), (), ()),
    'column': (bytes.fromhex('000051e30f0000020410a003802181000020a0110f00a0e3420200e0100080e204e02de5000000eb0f0002e204e09de4000000ea'), (36, 48), ()),
    'page': (bytes.fromhex('0f0050e300f18f90000000ea0e0000ea0f0000ea100000ea110000ea120000ea130000ea140000ea150000ea160000ea170000ea180000ea190000ea1a0000ea1b0000ea1c0000ea1d0000eabf00a0e3000000eabe00a0e3000000eabd00a0e3000000eabc00a0e3000000eabb00a0e3000000eaba00a0e3000000eab900a0e3000000eab800a0e3000000eab700a0e3000000eab600a0e3000000eab500a0e3000000eab400a0e3000000eab300a0e3000000eab200a0e3000000eab100a0e3000000eab000a0e3000000ea'), (8, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200), ()),
    'full': (bytes.fromhex('70402de900501fe50160a0e30040a0e30400a0e1000000eb081295e5c401a0e1800581e0070080e2071004e2013040e00110a0e30000a0e3000000eb0020a0e30202d3e7000000eb820086e08001d3e7000000eb012082e2800052e3f7ffffba010084e2ff4000e2100054e3e7ffffba7040bde81eff2fe1'), (20, 56, 68, 80), (4,)),
    'rect': (bytes.fromhex('f0472de90060a0e10250a0e1000050e30060a0b3000055e30050a0b37f0056e3270000ca7f0055e37f50a0c3c101a0e1c371a0e1070050e1210000ca100050e30f00a0a3100057e30f70a0a3ff4000e200901fe5ff8006e201a0a0e3160000ea0400a0e1000000eb081299e5c401a0e1800581e0070080e2071004e2013040e00110a0e30800a0e1000000eb0620a0e1050000ea0202d3e7000000eb82008ae08001d3e7000000eb012082e2050052e1f7ffffda010084e2ff4000e2070054e1e6ffffdaf047bde81eff2fe1'), (100, 136, 152, 164), (80,)),
    'init': (bytes.fromhex('04e02de5e200a0e3000000ebae00a0e3000000eb4000a0e3000000eb0000a0e3000000ebbf00a0e3000000eb1000a0e3000000eb0000a0e3000000eb2800a0e3000000eb4800a0e3000000eb8000a0e3000000eba000a0e3000000ebc800a0e3000000eba600a0e3000000eb4c00a0e3000000eb1500a0e3000000eba400a0e3000000eb4400a0e3000000eb0000a0e3000000ebab00a0e3000000eb6600a0e3000000eb2700a0e3000000eb8100a0e3000000eb2300a0e3000000eb5600a0e3000000eb9000a0e3000000eb8800a0e3000000eb0000a0e3000000eb8900a0e3000000eb0000a0e3000000eb8a00a0e3000000eb9000a0e3000000eb8b00a0e3000000eb0900a0e3000000eb8c00a0e3000000eb9900a0e3000000eb8d00a0e3000000eb0900a0e3000000eb8e00a0e3000000eb9900a0e3000000eb8f00a0e3000000eb9900a0e3000000eb2f00a0e3000000eb0200a0e3000000ebaf00a0e304e09de4000000ea'), (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256, 264, 272, 280, 288, 296, 304, 312, 320, 328, 336, 344, 356), ()),
    'asset': (bytes.fromhex('30402de90000a0e3000000eb0050a0e10040a0e3ff0004e2000000eb0110a0e30000a0e3000000eb0020a0e3040482e00000d5e7000000eb012082e2400f52e3f9ffffba014084e2100054e3f0ffffba3040bde81eff2fe1'), (8, 24, 36, 52), ()),
    'lookup': (bytes.fromhex('0010a0e140cf51e2bbc05c220000a0e300009f35010190371eff2fe1'), (), (16,)),
    'noop': (bytes.fromhex('1eff2fe1'), (), ()),
    'fullcaller': (bytes.fromhex('00109fe5140094e5080281e5000000eb'), (12,), (0,)),
    'rectcaller': (bytes.fromhex('00109fe5140094e5183084e2080281e50f0093e8000000eb'), (20,), (0,)),
    'pixel': (bytes.fromhex('004f2de9ff002de90170a0e1c01f8fe20260a0e10390a0e10040a0e108008de20c0091e80c0080e80c0091e80d00a0e10c0080e800001fe50050a0e38100d0e5000050e38300001a001094e5000051e3080094a5000050a30c0094c5000050c3790000da061081e0800051e3760000ca000056e3740000da800056e3720000cac0b1a0e1402060e208108de2030091e8000000eb08208de2030082e8040094e50c1094e5010080e0400050e3040000aa402060e208108de2030091e8000000eb030000ea402040e208108de2030091e8000000eb08208de2030082e80000e0e108008de50100e0e10c008de50050a0e3090000ea001094e5850187e0818180e008308de20c0093e8030098e8020000e0031001e0030088e8015085e2060055e1f3ffffba000059e34700000a08005be3450000ca0080a0e3180000ea0050a0e396080ae0120000ea140094e5050080e00a00d0e7042094e5882182e0082082e2402062e2c01fa0e1000000eb0130a0e1001094e50020a0e1850187e0819180e0030099e8020080e1031081e1030089e8015085e2060055e1eaffffba018088e20b0058e1e4ffffba0c0094e50010a0e1000050e3000060b2070000e2000060b2000050e32000000a080060e2ff9000e20050a0e396080ae0190000ea140094e50920a0e1050080e00a00d0e7c01fa0e1000000eb042094e50c3094e5032082e0400052e3020000aa402062e2000000eb010000ea402042e2000000eb003094e5852187e0838182e00130a0e10020a0e1030098e8020080e1031081e1030088e8015085e2060055e1e3ffffba1f00bde8e04fbde81eff2fe1000059e3faffff0a0c0094e5042094e5001082e0011041e23f0051e30a0000aa402060e203009de8000000eb03008de8040094e50c1094e5010080e0402060e203009de8000000eb010000ea03009de8000000eb03008de80000e0e100008de50100e0e104008de50b0000ea080094e5050050e1070000da000094e50c009de8800187e0858180e0030098e8020000e0031001e0030088e8015085e2060055e1f1ffffba0cb094e50080a0e300005be307b08bb2cbb1a0e11d0000eaffffffffffffffff0050a0e396080ae0150000ea080094e5050050e1110000da140094e5050080e00a00d0e7042094e5402062e2882142e0082042e2c01fa0e1000000eb0130a0e1001094e50020a0e1850187e0819180e0030099e8020080e1031081e1030089e8015085e2060055e1e7ffffba018088e20b0058e1e1ffffba0c0094e5000050e3000060b2070000e2000060b2000050e3a6ffff0a0050a0e396080ae0210000ea080094e5050050e11d0000da140094e5050080e00a00d0e70c9094e50980a0e1c01fa0e1000059e3009069b2079009e2009069b2082069e2000000eb042094e5083082e0013043e23f0053e3030000aa402062e28b2142e0092042e0000000eb003094e5852187e0838182e00130a0e10020a0e1030098e8020080e1031081e1030088e8015085e2060055e1dbffffba7effffea'), (144, 188, 208, 360, 496, 524, 536, 640, 668, 680, 852, 1012, 1048), (52,)),
    'glyph': (bytes.fromhex('f04f2de91cd04de20070a0e100009fe50180a0e10c1082e244509de54cb09de514008de5030091e800a0a0e100009fe50240a0e1d05300e580018de8001094e50390a0e108108de5041094e50060a0e30c108de51090cde5042094e50210a0e1000052e3072082b2001061b2071001e2c221a0e1001061b2000051e3ff7002e201108712ff700112001094e5080057e3950101e097a128e0000000ca020059e30010a0e31400000a290000ea000094e5910000e0ff2000e208c082e00000a0e3070000ea0020dce714309de5010080e20220e0e10620c3e7012086e2ff6002e2ff0000e2082094e50520d2e7000052e1f3ffffca010081e2ff1000e2070051e1e9ffffba140000ea000094e5910000e0ff2000e208c082e00000a0e3060000ea0020dce714309de5010080e20620c3e7012086e2ff6002e2ff0000e2082094e50520d2e7000052e1f4ffffca010081e2ff1000e2070051e1eaffffba080094e50130a0e30520d0e748109de50d00a0e1000000eb00005be30000000a'), (152, 368, 376), (12, 44)),
    'glyph_return': (bytes.fromhex('1cd08de2f04fbde81eff2fe1'), (), ()),
    'left': (bytes.fromhex('203052e20400005a203062e21112a0e1301381e11002a0e11eff2fe11013a0e10000a0e31eff2fe1'), (), ()),
    'right': (bytes.fromhex('203052e20400005a203062e23002a0e1110380e13112a0e11eff2fe13103a0e10010a0e31eff2fe1'), (), ()),
    'clear': (bytes.fromhex('30402de900409fe50050a0e3cf52c4e5120000ea000000eb0110a0e30000a0e3000000ebd052c4e5060000ea0000a0e3000000eb0000a0e3000000ebd002d4e5010080e2d002c4e5d002d4e5800050e3f5ffffbacf02d4e5010080e2cf02c4e5cf02d4e5100050e3e9ffffba3040bde81eff2fe1'), (20, 32, 48, 56), (4,)),
    'fill': (bytes.fromhex('04e02de500c0a0e3020000ea8ce180e006008ee801c08ce203005ce1faffffba04e09de41eff2fe1'), (), ()),
    'monitor': (bytes.fromhex('f7b585b0161c0f1c059c004d000000002fa006c801235b0200480000000023e00a2806d1059c6868c719402f00dd49e019e0a968095c04916118802905dd69680024cf19402f00dd3ce000220049039200920291391c2a1c01900023201c0000000004996418013630780028d8d10027381c00000000381c002f00da0730c0100049c00240180730391c002f04da49424907490f494201e04907490f451a0121002000000000002600242878000000000134022cf9db08350136802ef4db0137102fd5db08b0f0bc08bc1847'), (12, 26, 94, 114, 162, 172), ((10, 5), (24, 0), (76, 1), (128, 1))),
    'full_other': (bytes.fromhex('70402de90000a0e3000000eb00501fe50040a0e30160a0e30400a0e1000000ebf81195e5c401a0e1800581e0070080e2071004e2013040e00110a0e30000a0e3000000eb0020a0e30202d3e7000000eb820086e08001d3e7000000eb012082e2800052e3f7ffffba010084e2ff4000e2100054e3e7ffffba7040bde81eff2fe1'), (8, 28, 64, 76, 88), (12,)),
    'rect_other': (bytes.fromhex('f0472de90060a0e10250a0e1000050e30060a0b3000055e30050a0b37f0056e3290000ca7f0055e37f50a0c3c141a0e1c371a0e1070054e1230000ca100054e30f40a0a3100057e30f70a0a30000a0e3000000ebff4004e200901fe5ff8006e201a0a0e3160000ea0400a0e1000000ebf81199e5c401a0e1800581e0070080e2071004e2013040e00110a0e30800a0e1000000eb0620a0e1050000ea0202d3e7000000eb82008ae08001d3e7000000eb012082e2050052e1f7ffffda010084e2ff4000e2070054e1e6ffffdaf047bde8'), (80, 108, 144, 160, 172), (88,)),
    'init_other': (bytes.fromhex('04e02de5e200a0e3000000ebae00a0e3000000eb4000a0e3000000eb0000a0e3000000ebbf00a0e3000000eb1000a0e3000000eb0000a0e3000000eb2800a0e3000000eb4800a0e3000000eb8000a0e3000000eba100a0e3000000ebc800a0e3000000eba600a0e3000000eb4c00a0e3000000eb1500a0e3000000eba400a0e3000000eba200a0e3000000eb4400a0e3000000eb0000a0e3000000ebab00a0e3000000eb6600a0e3000000eb2700a0e3000000eb8100a0e3000000eb2300a0e3000000eb5600a0e3000000eb9000a0e3000000eb8800a0e3000000eb0000a0e3000000eb8900a0e3000000eb0000a0e3000000eb8a00a0e3000000eb9000a0e3000000eb8b00a0e3000000eb0900a0e3000000eb8c00a0e3000000eb9900a0e3000000eb8d00a0e3000000eb0900a0e3000000eb8e00a0e3000000eb9900a0e3000000eb8f00a0e3000000eb9900a0e3000000eb2f00a0e3000000eb0200a0e3000000ebaf00a0e304e09de4000000ea'), (8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 256, 264, 272, 280, 288, 296, 304, 312, 320, 328, 336, 344, 352, 364), ()),
    'asset_other': (bytes.fromhex('30402de90000a0e3000000eb0050a0e10040a0e3ff0004e2000000eb0434a0e10110a0e30000a0e3000000eb0020a0e3030082e00000d5e7000000eb012082e2400f52e3f9ffffba014084e2100054e3efffffba3040bde81eff2fe1'), (8, 24, 40, 56), ()),
    'lookup_other': (bytes.fromhex('0010a0e180cf51e207c05c220000a0e300009f35010190371eff2fe1'), (), (16,)),
    'fullcaller_other': (bytes.fromhex('00101fe5140094e5f80181e5000000eb'), (12,), (0,)),
    'rectcaller_other': (bytes.fromhex('00101fe5140094e5183084e2f80181e50f0093e8000000eb'), (20,), (0,)),
    'startline': (bytes.fromhex('4020a0e38017a0e30020c1e50000c1e51eff2fe10f0050e300f18f902f0000ea0e0000ea0f0000ea100000ea110000ea120000ea130000ea140000ea150000ea160000ea170000ea180000ea190000ea1a0000ea1b0000ea1c0000ea1d0000ea0000a0e3e5ffffea0800a0e3e3ffffea1000a0e3e1ffffea1800a0e3dfffffea2000a0e3ddffffea2800a0e3dbffffea3000a0e3d9ffffea3800a0e3d7ffffea4000a0e3d5ffffea4800a0e3d3ffffea5000a0e3d1ffffea5800a0e3cfffffea6000a0e3cdffffea6800a0e3cbffffea7000a0e3c9ffffea7800a0e3c7ffffea0000a0e3c5ffffea'), (), ()),
    'clear_other': (bytes.fromhex('30402de900401fe50050a0e3c652c4e5140000ea000000eb0110a0e30000a0e3000000ebc752c4e5080000ea0020a0e30000a0e3000000eb012082e2020052e3faffffbac702d4e5010080e2c702c4e5c702d4e5800050e3f3ffffbac602d4e5010080e2c602c4e5c602d4e5100050e3e7ffffba3040bde81eff2fe1'), (20, 32, 52), (4,)),
    'fill_other': (bytes.fromhex('f0402de90070a0e14c008fe20360a0e10250a0e10c0090e80140a0e10400a0e1030055e102005001'), (), ()),
    'monitor_other': (bytes.fromhex('f7b585b0161c0f1c059c004d0000000030a006c801235b0200480000000023e00a2806d1059c6868c719402f00dd4ae019e0a968095c04916118802905dd69680024cf19402f00dd3de000220049039200920291391c2a1c01900023201c0000000004996418013630780028d8d100273806000e00000000381c002f00da0730c0100049c00240180730391c002f04da49424907490f494201e04907490f451a0121002000000000002600242878000000000134022cf9db08350136802ef4db0137102fd4db08b0f0bc08bc1847'), (12, 26, 94, 116, 164, 174), ((10, 5), (24, 0), (76, 1), (130, 1))),
}
_PAIRED_VARIANTS = [{'data': 'data', 'command': 'command', 'column': 'column', 'page': 'page', 'full': 'full', 'rect': 'rect', 'init': 'init', 'asset': 'asset', 'lookup': 'lookup', 'noop': 'noop', 'fullcaller': 'fullcaller', 'rectcaller': 'rectcaller', 'pixel': 'pixel', 'glyph': 'glyph', 'glyph_return': 'glyph_return', 'left': 'left', 'right': 'right', 'clear': 'clear', 'fill': 'fill', 'monitor': 'monitor'}, {'data': 'data', 'command': 'command', 'column': 'column', 'page': 'page', 'full': 'full_other', 'rect': 'rect_other', 'init': 'init_other', 'asset': 'asset_other', 'lookup': 'lookup_other', 'noop': 'noop', 'fullcaller': 'fullcaller_other', 'rectcaller': 'rectcaller_other', 'startline': 'startline', 'pixel': 'pixel', 'glyph': 'glyph', 'glyph_return': 'glyph_return', 'left': 'left', 'right': 'right', 'clear': 'clear_other', 'fill': 'fill_other', 'monitor': 'monitor_other'}]

_PAIRED_LINKS = [{'data': {}, 'command': {}, 'column': {36: 'command', 48: 'command'}, 'page': {8: 'diagnostic', 80: 'command', 88: 'command', 96: 'command', 104: 'command', 112: 'command', 120: 'command', 128: 'command', 136: 'command', 144: 'command', 152: 'command', 160: 'command', 168: 'command', 176: 'command', 184: 'command', 192: 'command', 200: 'command'}, 'full': {20: 'page', 56: 'column', 68: 'data', 80: 'data'}, 'rect': {100: 'page', 136: 'column', 152: 'data', 164: 'data'}, 'init': {8: 'command', 16: 'command', 24: 'command', 32: 'command', 40: 'command', 48: 'command', 56: 'command', 64: 'command', 72: 'command', 80: 'command', 88: 'command', 96: 'command', 104: 'command', 112: 'command', 120: 'command', 128: 'command', 136: 'command', 144: 'command', 152: 'command', 160: 'command', 168: 'command', 176: 'command', 184: 'command', 192: 'command', 200: 'command', 208: 'command', 216: 'command', 224: 'command', 232: 'command', 240: 'command', 248: 'command', 256: 'command', 264: 'command', 272: 'command', 280: 'command', 288: 'command', 296: 'command', 304: 'command', 312: 'command', 320: 'command', 328: 'command', 336: 'command', 344: 'noop', 356: 'command'}, 'asset': {8: 'lookup', 24: 'page', 36: 'column', 52: 'data'}, 'lookup': {}, 'noop': {}, 'fullcaller': {12: 'full'}, 'rectcaller': {20: 'rect'}, 'pixel': {144: 'right', 188: 'left', 208: 'right', 360: 'left', 496: 'right', 524: 'left', 536: 'right', 640: 'right', 668: 'left', 680: 'right', 852: 'left', 1012: 'right', 1048: 'left'}, 'glyph': {152: 'glyph_return', 368: 'pixel', 376: 'glyph_return'}, 'glyph_return': {}, 'left': {}, 'right': {}, 'clear': {20: 'page', 32: 'column', 48: 'data', 56: 'data'}, 'fill': {}}, {'data': {}, 'command': {}, 'column': {36: 'command', 48: 'command'}, 'page': {8: 'diagnostic', 80: 'command', 88: 'command', 96: 'command', 104: 'command', 112: 'command', 120: 'command', 128: 'command', 136: 'command', 144: 'command', 152: 'command', 160: 'command', 168: 'command', 176: 'command', 184: 'command', 192: 'command', 200: 'command'}, 'full': {8: 'startline', 28: 'page', 64: 'column', 76: 'data', 88: 'data'}, 'rect': {80: 'startline', 108: 'page', 144: 'column', 160: 'data', 172: 'data'}, 'init': {8: 'initbridge', 16: 'initbridge', 24: 'initbridge', 32: 'initbridge', 40: 'initbridge', 48: 'initbridge', 56: 'initbridge', 64: 'initbridge', 72: 'initbridge', 80: 'initbridge', 88: 'initbridge', 96: 'initbridge', 104: 'initbridge', 112: 'initbridge', 120: 'initbridge', 128: 'initbridge', 136: 'initbridge', 144: 'initbridge', 152: 'initbridge', 160: 'initbridge', 168: 'initbridge', 176: 'initbridge', 184: 'initbridge', 192: 'initbridge', 200: 'initbridge', 208: 'initbridge', 216: 'initbridge', 224: 'initbridge', 232: 'initbridge', 240: 'initbridge', 248: 'initbridge', 256: 'initbridge', 264: 'initbridge', 272: 'initbridge', 280: 'initbridge', 288: 'initbridge', 296: 'initbridge', 304: 'initbridge', 312: 'initbridge', 320: 'initbridge', 328: 'initbridge', 336: 'initbridge', 344: 'initbridge', 352: 'noop', 364: 'initbridge'}, 'asset': {8: 'lookup', 24: 'page', 40: 'column', 56: 'data'}, 'lookup': {}, 'noop': {}, 'fullcaller': {12: 'full'}, 'rectcaller': {20: 'rect'}, 'startline': {}, 'pixel': {144: 'right', 188: 'left', 208: 'right', 360: 'left', 496: 'right', 524: 'left', 536: 'right', 640: 'right', 668: 'left', 680: 'right', 852: 'left', 1012: 'right', 1048: 'left'}, 'glyph': {152: 'glyph_return', 368: 'pixel', 376: 'glyph_return'}, 'glyph_return': {}, 'left': {}, 'right': {}, 'clear': {20: 'page', 32: 'column', 52: 'data'}, 'fill': {}}]


def _paired_arm_shape(image, at, spec):
    pattern, branches, literals = spec
    if at < 0 or at & 3 or at + len(pattern) > len(image):
        return None
    calls, values, pools = {}, {}, []
    for off in range(0, len(pattern), 4):
        op = struct.unpack_from('<I', image, at + off)[0]
        expected = struct.unpack_from('<I', pattern, off)[0]
        mask = 0xff000000 if off in branches else 0xfffff000 if off in literals else 0xffffffff
        if op & mask != expected:
            return None
        if off in branches:
            delta = op & 0xffffff
            if delta & 0x800000:
                delta -= 0x1000000
            target = at + off + 8 + delta * 4
            if target < 0 or target & 3 or target + 4 > len(image):
                return None
            calls[off] = target
        if off in literals:
            pool = at + off + 8 + ((op & 4095) if op & 0x800000 else -(op & 4095))
            if pool < 0 or pool & 3 or pool + 4 > len(image):
                return None
            values[off] = struct.unpack_from('<I', image, pool)[0]
            pools.append((pool, pool + 4))
    return calls, values, pools


def _paired_hits(image, spec, thumb=False):
    pattern, branches, literals = spec
    holes = {off + n for off in branches for n in range(4)}
    for reference in literals:
        off = reference[0] if thumb else reference
        holes.update((off, off + 1))
    runs, start = [], 0
    while start < len(pattern):
        if start in holes:
            start += 1
            continue
        end = start + 1
        while end < len(pattern) and end not in holes:
            end += 1
        runs.append((start, pattern[start:end]))
        start = end
    offset, anchor = max(runs, key=lambda item: len(item[1]))
    start = 0
    while True:
        hit = image.find(anchor, start)
        if hit < 0:
            return
        start = hit + 1
        at = hit - offset
        shape = _shape(image, at, *spec) if thumb else _paired_arm_shape(image, at, spec)
        if shape is not None:
            yield at, shape


def _paired_ram(at, length):
    return not at & 3 and 0x01000000 <= at < at + length <= 0x02000000


def _paired_profiles(image):
    cache = {}
    def hits(key, thumb=False):
        token = key, thumb
        if token not in cache:
            cache[token] = list(_paired_hits(image, _PAIRED_SPECS[key], thumb))
        return cache[token]

    for variant_index, variant in enumerate(_PAIRED_VARIANTS):
        links = _PAIRED_LINKS[variant_index]
        def fresh():
            return {'entries': {}, 'shapes': {}, 'code': [], 'pools': [], 'outside': []}
        def clone(state):
            return {key: value.copy() for key, value in state.items()}
        def bind(state, role, at):
            entries = state['entries']
            if role in entries:
                return entries[role] == at
            if role == 'initbridge':
                if at < 0 or at & 3 or at + 12 > len(image):
                    return False
                op, bx = struct.unpack_from('<II', image, at)
                if op & 0xfffff000 != 0xe59fc000 or bx != 0xe12fff1c:
                    return False
                pool = at + 8 + (op & 4095)
                if pool + 4 > len(image):
                    return False
                pointer = struct.unpack_from('<I', image, pool)[0]
                if not pointer & 1 or image[pointer - 1:pointer + 7] != bytes.fromhex('0121490608707047'):
                    return False
                entries[role] = at
                state['code'].extend(((at, at + 8), (pointer - 1, pointer + 7)))
                state['pools'].append((pool, pool + 4))
                return True
            spec = _PAIRED_SPECS[variant[role]]
            shape = _paired_arm_shape(image, at, spec)
            if shape is None:
                return False
            entries[role] = at
            state['shapes'][role] = shape
            state['code'].append((at, at + len(spec[0])))
            state['pools'].extend(shape[2])
            for off, child in links[role].items():
                target = shape[0][off]
                if child == 'diagnostic':
                    state['outside'].append(target)
                elif not bind(state, child, target):
                    return False
            return True
        def select(state, role):
            candidates = []
            for at, _ in hits(variant[role]):
                trial = clone(state)
                if bind(trial, role, at):
                    candidates.append(trial)
            return candidates[0] if len(candidates) == 1 else None

        for full, _ in hits(variant['full']):
            state = fresh()
            if not bind(state, 'full', full):
                continue
            for role in ('rect', 'fullcaller', 'rectcaller', 'init', 'asset'):
                state = select(state, role)
                if state is None:
                    break
            if state is None:
                continue
            entries, shapes = state['entries'], state['shapes']
            full_context = next(iter(shapes['full'][1].values()))
            if (not _paired_ram(full_context, 0x400) or
                    any(set(shapes[role][1].values()) != {full_context}
                        for role in ('rect', 'fullcaller', 'rectcaller')) or
                    entries['rectcaller'] != entries['fullcaller'] + 20):
                continue
            # The two selected dispatcher arms store the same live buffer owner.
            exits = []
            for role in ('fullcaller', 'rectcaller'):
                at = entries[role] + len(_PAIRED_SPECS[variant[role]][0])
                if at + 4 > len(image):
                    break
                op = struct.unpack_from('<I', image, at)[0]
                if op & 0xff000000 != 0xea000000:
                    break
                delta = op & 0xffffff
                if delta & 0x800000:
                    delta -= 0x1000000
                exits.append(at + 8 + 4 * delta)
                state['code'].append((at, at + 4))
            if len(exits) != 2 or exits[0] != exits[1] or not 0 <= exits[0] <= len(image) - 4:
                continue
            monitors = []
            for monitor, shape in hits(variant['monitor'], True):
                trial = clone(state)
                targets = shape[0]
                valid = True
                for off, role in zip(_PAIRED_SPECS[variant['monitor']][1],
                                     ('clear', 'fill', 'glyph', 'page', 'column', 'data')):
                    veneer = targets[off]
                    if (veneer & 3 or image[veneer:veneer + 8] != bytes.fromhex('7847c04604f01fe5')
                            or veneer + 12 > len(image)):
                        valid = False
                        break
                    target = struct.unpack_from('<I', image, veneer + 8)[0]
                    if not bind(trial, role, target):
                        valid = False
                        break
                    trial['code'].append((veneer, veneer + 8))
                    trial['pools'].append((veneer + 8, veneer + 12))
                if not valid:
                    continue
                values = shape[1]
                font = values[0xa]
                buffer = values[0x18]
                if (values[0x4c] != buffer or values[0x80 if variant_index == 0 else 0x82] != buffer
                        or not _paired_ram(buffer, 4096) or font < 0 or font + 24 > len(image)):
                    continue
                width, height, widths, glyphs, zero, count = struct.unpack_from('<6I', image, font)
                size = width * ((height + 7) // 8) * count
                if (not 1 <= width <= 128 or not 1 <= height <= 64 or zero != 0 or count != 256 or
                        widths < 0 or widths + count > len(image) or
                        glyphs < 0 or glyphs + size > len(image) or
                        any(value > width for value in image[widths:widths + count])):
                    continue
                # ADR's two-word fill source is local and must really be zero.
                adr = struct.unpack_from('<H', image, monitor + 0x10)[0]
                zero_at = ((monitor + 0x14) & ~3) + (adr & 255) * 4
                if adr & 0xf800 != 0xa000 or image[zero_at:zero_at + 8] != bytes(8):
                    continue
                trial['entries']['monitor'] = monitor
                trial['code'].append((monitor, monitor + len(_PAIRED_SPECS[variant['monitor']][0])))
                for off, _ in _PAIRED_SPECS[variant['monitor']][2]:
                    op = struct.unpack_from('<H', image, monitor + off)[0]
                    pool = ((monitor + off + 4) & ~3) + (op & 255) * 4
                    trial['pools'].append((pool, pool + 4))
                trial['font_data'] = [(font, font + 24), (widths, widths + count),
                                      (glyphs, glyphs + size), (zero_at, zero_at + 8)]
                trial['buffer'] = buffer
                if set(trial['shapes']['clear'][1].values()) != {full_context}:
                    continue
                # Every literal base used by the selected bitmap path is RAM.
                if any(not 0x01000400 <= value <= 0x01fff000
                       for role in ('pixel', 'glyph') for value in trial['shapes'][role][1].values()):
                    continue
                buffer_span = (buffer, buffer + 4096)
                glyph_values = trial['shapes']['glyph'][1]
                pixel_flag = next(iter(trial['shapes']['pixel'][1].values())) + 0x81
                scratch = glyph_values[0xc]
                context_store = glyph_values[0x2c] - 0x3d0
                if any(_overlap(buffer_span, span) for span in (
                        (full_context, full_context + 0x400), (pixel_flag, pixel_flag + 1),
                        (scratch, scratch + 256), (context_store, context_store + 4))):
                    continue
                monitors.append(trial)
            if len(monitors) != 1:
                continue
            state = monitors[0]
            entries, shapes = state['entries'], state['shapes']
            # The same boot arm calls this exact initializer then selected asset.
            roots = []
            for at in range(0, len(image) - 7, 4):
                a, b = struct.unpack_from('<II', image, at)
                if a & 0xff000000 != 0xeb000000 or b & 0xff000000 != 0xeb000000:
                    continue
                def target(op, pc):
                    d = op & 0xffffff
                    return pc + 8 + 4 * (d - 0x1000000 if d & 0x800000 else d)
                if target(a, at) == entries['init'] and target(b, at + 4) == entries['asset']:
                    roots.append(at)
            if len(roots) != 1:
                continue
            state['code'].append((roots[0], roots[0] + 8))
            table = shapes['lookup'][1][0x10]
            if table & 3 or not 0 <= table <= len(image) - 4:
                continue
            asset = struct.unpack_from('<I', image, table)[0]
            if asset < 0 or asset + 4096 > len(image):
                continue
            code = state['code']
            data = state['pools'] + state['font_data'] + [(table, table + 4), (asset, asset + 4096)]
            if (any(_overlap(a, b) for i, a in enumerate(code) for b in code[i + 1:]) or
                    any(not 0 <= a < b <= len(image) or any(_overlap((a, b), c) for c in code)
                        for a, b in data) or
                    any(any(a <= target < b for a, b in code + data) for target in state['outside'])):
                continue
            commands = []
            for off, child in links['init'].items():
                if child not in ('command', 'initbridge'):
                    continue
                op = struct.unpack_from('<I', image, entries['init'] + off - 4)[0]
                if op == 0xe49de004:
                    op = struct.unpack_from('<I', image, entries['init'] + off - 8)[0]
                if op & 0xfffff000 != 0xe3a00000:
                    commands = []
                    break
                value, rotate = op & 255, ((op >> 8) & 15) * 2
                commands.append(((value >> rotate) | (value << (32 - rotate))) & 0xffffffff if rotate else value)
            if not commands or commands[0] != 0xe2 or commands[-1] != 0xaf:
                continue
            yield {'class_name': 'descending-paired-byte-page128-v1', 'candidate': True,
                   'evidence_gate': 'temporary-evidence-gated', 'width': 128, 'height': 128,
                   'logical_width': 128, 'logical_height': 128, 'bits_per_pixel': 2,
                   'command_port': 0x02000000, 'data_port': 0x02000002, 'access_width': 1,
                   'column_bias': 0, 'column_capacity': 256, 'main_pages': list(range(15, -1, -1)),
                   'icon_page': None, 'init_data_argument': None, 'init_commands': commands,
                   'init_row_bytes': 256, 'required_pages': 16, 'page_step': -1,
                   'logical_y_reverse': True, 'logical_plane_weights': [2, 1],
                   'plane_policy': 'logical-first-second-plane-convention-not-optical-calibration',
                   'optical_polarity': None, 'optical_orientation': None,
                   'physical_geometry': None, 'controller_part': None,
                   'init_entry': entries['init'], 'producer_entry': entries['rect'],
                   'full_producer': full, 'software_producer': entries['pixel'],
                   'buffer_address': state['buffer'], 'context_address': full_context,
                   'selected_asset': asset, 'source_table': table, 'initializer_wrapper': roots[0],
                   'helpers': entries, 'code_intervals': [list(v) for v in sorted(set(code))],
                   'literal_intervals': [list(v) for v in sorted(set(state['pools']))],
                   'data_intervals': [list(v) for v in sorted(set(state['font_data'] + [(table, table + 4), (asset, asset + 4096)]))],
                   'source_intervals': [list(v) for v in sorted(set(code + data))],
                   'ram_intervals': [[state['buffer'], state['buffer'] + 4096], [full_context, full_context + 0x400]],
                   'logical_pixel_mapping': 'Y=8*(15-page)+(7-bit);X=paired-column',
                   'unsupported_path': 'out-of-range page diagnostic is outside the selected bounded source path'}
