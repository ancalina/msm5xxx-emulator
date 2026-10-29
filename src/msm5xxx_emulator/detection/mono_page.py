"""Temporary source-bound odd BYTE page raster; optical properties unproved."""
from __future__ import annotations

import struct

from .arm import thumb_bl_target, thumb_literal_value

_RASTER = bytes.fromhex('ffb5d54501daabf049fd171c1c1c81b0002800da00200299072901dd07210291002f00da00277f2c00dd7f2414490a69002a01d1134a0a62096a0091051c02998d4219dc01e00135f9e700984619b0202843012252065070381c00f088f8381c01225206a04206dc01e00130fae7c100715cd170f9e7e6e701b004b0f0bd')
_RASTER_CALLS = (6, 90)
_RASTER_LITERALS = ((44, 1), (52, 2))
_COLUMN = bytes.fromhex('043001110907090f0906090e102319430122520651700107090f5170f746')
_CLEAR = bytes.fromhex('00b5d54501daacf0fef8094801229202ff21a8f0fcf807480069002805d17f2300220721002000f0a0fb01200349c87000bd')
_CLEAR_CALLS = (6, 18, 38)
_CLEAR_LITERALS = ((10, 0), (22, 0), (44, 1))
_ICON_CLEAR = bytes.fromhex('90b5d54501daacf01bf90406240eb82001277f067870002000f07bfc002001210022842808da01e00130fae7002c01d0f97000e0fa70f7e790bd')
_ICON_CLEAR_CALLS = (6, 24)
_ICONS = bytes.fromhex('90b5d54501daacf0bff8b82001277f067870012000f021fc0024fc70062000f01cfcfc70082000f018fcfc700a2000f014fcfc700c2000f010fcfc700f2000f00cfcfc70122000f008fcfc70172000f004fcfc701e2000f000fcfc70272000f0fcfbfc70362000f0f8fbfc70462000f0f4fbfc70512000f0f0fbfc70612000f0ecfbfc70752000f0e8fbfc707b2000f0e4fbfc707c2000f0e0fbfc707d2000f0dcfbfc707e2000f0d8fbfc7090bd')
_ICONS_CALLS = (6, 20, 30, 38, 46, 54, 62, 70, 78, 86, 94, 102, 110, 118, 126, 134, 142, 150, 158, 166)
_INIT = bytes.fromhex('b0b5d54501daabf04efc232001277f067870f02078700220f870f878244c2071e2207870a1207870c82078702c2078707d20c000cbf73df82e2078707d20c000cbf737f82f2078707d20c000cbf731f820793821014081200025182907d1222179707870172078700120208005e0272179707870202078702580a2207870fff70ffb0120fff7effaaf207870')
_INIT_CALLS = (6, 52, 64, 76, 126, 132)
_INIT_LITERALS = ((28, 4),)
_FILL = bytes.fromhex('8446830705d0521e12d30170401c8307f9d1083a07d30b0219430b0419430b1c0ac0083afcd2d21d02d38154521efcd260467047')
_DELAY = bytes.fromhex('15220921c905322802dd0a843238fae7002807dd1b2358432d30002800da3f3080110884f746')
_STACK = bytes.fromhex('7847000001e08ee30d00a0e10e10a0e100200fe10aa02ae054309fe5010013e350e09f1550e09f0513ff2fe178470000feffffea')


def _shape(image: bytes, at: int, pattern: bytes, calls=(), literals=()):
    if at < 0 or at & 1 or at+len(pattern) > len(image):
        return None
    holes = {offset+n for offset in calls for n in range(4)}
    holes.update(offset+n for offset, _register in literals for n in (0, 1))
    if any(image[at+i] != value for i,value in enumerate(pattern) if i not in holes):
        return None
    targets = {offset:thumb_bl_target(image,at+offset) for offset in calls}
    values = {offset:thumb_literal_value(image,at+offset,register)
              for offset,register in literals}
    if (any(v is None or v & 1 or not 0 <= v <= len(image)-2 for v in targets.values())
            or any(v is None for v in values.values())):
        return None
    return targets, values


def _hits(image: bytes, pattern: bytes, calls=(), literals=()):
    start = 0
    while True:
        at = image.find(pattern[:6],start)
        if at < 0:
            return
        start = at+1
        result = _shape(image,at,pattern,calls,literals)
        if result is not None:
            yield at, result


def _stack(image: bytes, at: int) -> bool:
    if image[at:at+len(_STACK)] != _STACK or at+0x80 > len(image):
        return False
    # Ordinary diagnostic ABI return reaches the local ARM self-loop.
    return struct.unpack_from('<II',image,at+0x78) == (at+0x2C,at+0x30)


def find_odd_byte_page_profile(image: bytes) -> tuple[dict | None, str]:
    """Find one complete init/consumer/helper group, never a lone port literal."""
    rasters = list(_hits(image,_RASTER,_RASTER_CALLS,_RASTER_LITERALS))
    if not rasters:
        return None, 'odd-byte-page-producer-not-closed'
    inits = list(_hits(image,_INIT,_INIT_CALLS,_INIT_LITERALS))
    icons = list(_hits(image,_ICONS,_ICONS_CALLS))
    complete = []
    for raster,(r_calls,r_literals) in rasters:
        stack,column = r_calls[6],r_calls[0x5A]
        if (not _stack(image,stack) or _shape(image,column,_COLUMN) is None):
            continue
        context,buffer = r_literals[0x2C],r_literals[0x34]
        if (context & 3 or buffer != context+0x24
                or not 0x01000000 <= context <= 0x01800000-0x424):
            continue
        linked_icons = [at for at,(calls,_values) in icons
                        if calls[6] == stack and all(calls[o] == column for o in _ICONS_CALLS if o != 6)]
        if len(linked_icons) > 1:
            return None, 'odd-byte-page-icon-owner-ambiguous'
        if not linked_icons:
            continue
        for init,(i_calls,i_literals) in inits:
            if i_calls[6] != stack:
                continue
            clear,icon_clear,delay = i_calls[0x7E],i_calls[0x84],i_calls[0x34]
            clear_shape = _shape(image,clear,_CLEAR,_CLEAR_CALLS,_CLEAR_LITERALS)
            icon_shape = _shape(image,icon_clear,_ICON_CLEAR,_ICON_CLEAR_CALLS)
            if (clear_shape is None or icon_shape is None
                    or i_calls[0x40] != delay or i_calls[0x4C] != delay
                    or _shape(image,delay,_DELAY) is None):
                continue
            c_calls,c_literals = clear_shape
            b_calls,_ = icon_shape
            flags = i_literals[0x1C]
            if (c_calls[6] != stack or c_calls[0x26] != raster
                    or b_calls[6] != stack or b_calls[0x18] != column
                    or c_literals[0xA] != buffer or c_literals[0x16] != context
                    or c_literals[0x2C] != flags
                    or flags & 1 or not 0x01000000 <= flags <= 0x01800000-6
                    or (flags < buffer+1024 and flags+6 > context)
                    or _shape(image,c_calls[0x12],_FILL) is None):
                continue
            roles = {'raster':(raster,len(_RASTER)), 'column':(column,len(_COLUMN)),
                     'main_clear':(clear,len(_CLEAR)), 'icon_clear':(icon_clear,len(_ICON_CLEAR)),
                     'icons':(linked_icons[0],len(_ICONS)), 'init':(init,len(_INIT)),
                     'fill':(c_calls[0x12],len(_FILL)), 'delay':(delay,len(_DELAY)),
                     'stack_guard':(stack,0x80)}
            intervals = sorted((at,at+length) for at,length in roles.values())
            if any(a[1] > b[0] for a,b in zip(intervals,intervals[1:])):
                continue
            complete.append({'class_name':'odd-byte-page128x64-v1', 'candidate':True,
                'evidence_gate':'temporary-evidence-gated', 'width':128,'height':64,
                'logical_width':128,'logical_height':64,'column_bias':4,
                'command_port':0x02000001,'data_port':0x02000003,'access_width':1,
                'main_pages':list(range(8)),'icon_page':8,
                'icon_policy':'separate-page-8-not-main-raster-height',
                'init_data_argument':{'command':0xF0,'value':2,'pixel':False},
                'init_entry':init,'producer_entry':raster,'column_helper':column,
                'main_clear_entry':clear,'icon_clear_entry':icon_clear,
                'icon_entry':linked_icons[0],'context_address':context,
                'buffer_address':buffer,'flags_address':flags,
                'source_pcs':{'page_write':raster+0x56,'data_write':raster+0x72,
                    'column_high_write':column+0x14,'column_low_write':column+0x1A,
                    'init_argument_write':init+0x18,'init_argument_read':init+0x1A},
                'helpers':{role:at for role,(at,_length) in roles.items()},
                'code_intervals':[list(pair) for pair in intervals],
                'optical_polarity':None,'optical_orientation':None,'controller_part':None,
                'unsupported_path':'stack-limit diagnostic nonlocal side effects unproved'})
    if len(complete) != 1:
        return None, 'odd-byte-page-group-ambiguous' if complete else 'odd-byte-page-links-not-closed'
    return complete[0], 'accepted-source-bound-odd-byte-page-candidate'
