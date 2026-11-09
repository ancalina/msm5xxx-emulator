"""Legacy reset-probe console families pending a shared startup rule."""
from __future__ import annotations

import hashlib
import re
import struct

from ...arm import arm_b_target, thumb_bl_target, thumb_literal_value
from ...facts import facts_for
from .legacy_constants import HIGH_RAM_TEST_SHA256
from .legacy_half_ff import (
    _FF_IRQ_RESTORE, _FF_IRQ_SAVE, _FF_RESET, _FF_SPECS, _FF_THUNK,
    _HalfFFUnclosed, _ff_overlap, _ff_profile_at, _ff_ram, _ff_shape,
    _ff_thunk, _ff_u32, _find_half_ff_uart_console_profile,
    _source_thumb_shape, find_uart_console_profile,
)
from .legacy_simple import _word

_PROBE_SPECS = {
    'root': ('80b5????????ff20????????0a20????????????????071c3806000e0c2808d1????????????????????012080bc08bc1847dd20????????0020f7e7', (2, 8, 14, 18, 32, 38, 52), ((36, 0),)),
    'init': ('80b5071c????????0020????087100210920????????????????c020????10390871b22008727d2008731c20????08700020????2039087088811e2008810020????403988813420????30390870081c0771302008731020087308732020087308730120087304200873????30380079400800d208e0????3038027a0120????087000200870f0e780bc08bc1847', (4, 18, 22), ((10, 1), (28, 1), (44, 1), (50, 1), (64, 1), (72, 1), (106, 0), (118, 0), (126, 1))),
    'primary': ('2020????08730873????0079000905d20120????087000200870f5e77047', (), ((2, 1), (8, 0), (18, 1))),
    'setup': ('f0b58bb02c226846????????????????????05042d0c????????????0722d2018f183988????????1940398039881170002801d1????????????????????032212028c18a188????????023b194080221143a180a1883181002801d1????????????????a188????????023b1940a180a1883181002801d1????????????????3988????????7c3319400222114339803988????1170002801d1????????????????3988????????7c331940398039881170002801d1????????????????????0f20????????0420????????6846????????0120????????????????2188????4904490c218021881180002801d1????????????????1921490171184a8a????7c331a404a82498a????a03a1171002801d1????????????0222f0380272????????????8024b98b2143b983b98b3a691180002801d1????????????????f98b2143f983f98bba691180002801d1????????002d00d001e0????????0bb0f0bc08bc1847', (10, 14, 22, 52, 56, 92, 96, 120, 124, 154, 158, 182, 188, 194, 200, 206, 212, 216, 238, 242, 274, 286, 310, 314, 334, 344), ((8, 1), (26, 1), (36, 3), (38, 2), (60, 1), (70, 3), (72, 6), (102, 3), (104, 6), (130, 3), (132, 6), (146, 2), (164, 3), (166, 2), (186, 0), (222, 2), (254, 3), (264, 2), (278, 0), (290, 7))),
    'config': ('b0b5????0c1c????290c8f18072813d0092820d1????????798a????1940c022224011437982798aa980002801d1????????b0bc08bc1847????????798a????bd331940a207920f11437982798aa9800028ecd0ede7????????????????e8e7', (20, 46, 56, 90), ((2, 5), (6, 2), (26, 3), (62, 3), (86, 1), (88, 0))),
    'copy': ('0120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb44206d202e0201d041cf9e700202060f9e70120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb4420dd202e0201d041cf9e700202060a003f8d10120????087000200870f2e70120????0870002008707047', (), ((2, 1), (10, 0), (14, 1), (22, 0), (28, 0), (58, 1), (66, 0), (70, 1), (78, 0), (104, 1), (112, 0), (116, 1), (124, 0), (130, 0), (160, 1), (168, 0), (172, 1), (180, 0), (208, 1), (220, 1))),
    'delay': ('f0b4????978c116a79437a013f239a1a0026322809dc4843222179438018401a801100d4061c????22e032234b439d1822237b43341ceb1a9b1100d41c1c????3c8032234b4332389b189b1101d41c1c00e0341c2404240c01e03c8032383228fbdc002805dd48438018801100d4061c3e80f0bc7047', (), ((2, 2), (38, 7), (62, 7))),
    'pinset': ('80b5071c????????????032212028918ca89ba433a43ca81c989????1173002801d1????????80bc08bc1847', (4, 34), ((8, 1), (26, 2))),
    'clockset': ('f0b5????????290c8f180a28????1bd1????????0404240c????00200870????????????????????????3988326d91431143398039882980002801d1????????002c00d026e023e0c400305900280cd0????????3a8831598a431143398039882980002801d1????????a4196068002800d10fe0????????398a6268914311433982398a????20321180002800d001e0????????f0bc08bc1847', (16, 30, 34, 38, 60, 80, 102, 116, 144), ((2, 5), (4, 2), (12, 6), (24, 1), (132, 2))),
    'apply': ('f0b5071c????????0404240c2c22391c????????????????0321090247183d883e8a0420????????????????????????????????????798a3f2352889b0219409205920d11437982798a????9180002801d1????????????????39890907090f03229203114339813989????203a1182002801d1????????3d803e82????????3988????39803988203a1180002801d1????????????????398a????3982398a1180002801d1????????????????002c00d001e0????????f0bc08bc1847', (4, 18, 36, 40, 44, 48, 82, 86, 116, 124, 144, 148, 166, 170, 180), ((16, 0), (22, 0), (52, 2), (74, 2), (106, 2), (130, 2), (154, 2))),
    'clockclear': ('f0b5c4000026????0321????090228598f1800280dd0????????39882a599143314339803988????1180002801d1????????6419606800280ed0????????398a6268914331433982398a????20321180002801d1????????f0bc08bc1847', (22, 46, 58, 84), ((6, 5), (10, 2), (38, 2), (74, 2))),
}
# Configuration error arm: MOVS r0,#0x3b; LSLS r0,#5; LDR r1; BL; B.
# The active configuration prefix is identical; keep the actual longer tail.
_PROBE_CONFIG_SHIFTED_LINE = (
    _PROBE_SPECS['config'][0][:0x56 * 2]
        + struct.pack('<2H', 0x2000 | 0x3b, 5 << 6).hex()
        + '??49????????'
        + struct.pack('<H', 0xe000 | (((0x32-0x60-4)//2) & 0x7ff)).hex(),
    (0x14, 0x2e, 0x38, 0x5c),
    ((2, 5), (6, 2), (0x1a, 3), (0x3e, 3), (0x5a, 1)),
)
_PROBE_RESET = bytes.fromhex('58429fe5010014e354e29f1554e29f0514ff2fe1784700004c429fe5010014e348e29f1548e29f0514ff2fe17847000040429fe5010014e33ce29f153ce29f0514ff2fe17847000034429fe5010014e330e29f1530e29f0514ff2fe178470000000050e31600001ad7f021e3c8d19fe5dbf021e314d29fe5d3f021e310d29fe510429fe5010014e30ce29f150ce29f0514ff2fe17847000004429fe5010014e300e29f1500e29f0514ff2fe178470000000050e30100000a9c019fe510ff2fe1045c07ead3f021e3c4d19fe57c119fe5010011e3d4e19f15d4e19f0511ff2fe1784700005419a0e30000a0e10000a0e10000a0e1c0319fe50140a0e3004083e50040a0e3004083e5011041e2000051e3f4ffff1aa4119fe5010011e394e19f159ce19f0511ff2fe17847000078470000d3f021e358d19fe58c419fe5010014e380e19f1584e19f0514ff2fe1784700001eff2fe178470000')
_PROBE_APP = bytes.fromhex('d2f021e328d09fe5dff021e324d09fe5d1f021e30dd02de01cd09fe5d3f021e318209fe512ff2fe1')
_PROBE_TEMPLATE = bytes.fromhex('6755a8000004faef020a550150f10208290003008000a3026000000002000000007d00001000020001000000')
# Only the aligned 44-byte path: 32 + 8 + 4 bytes, saved R4/LR restored.
_PROBE_MEMCPY_44 = bytes.fromhex('7847000010402de9202052e20500003a1850b1281850a0281850b1281850a02820205222f9ffff2a02ceb0e11850b1281850a0281800b1481800a04802cfb0e104309124043080241040bde81eff2f01')



_CLOCK_SPECS = {'clock_commit': ('ffb5??486f460fc80fc7082601240925??4aed05??49383a01984968d71d1937884222d330329079012804d100ab1878????????03e000ab1878????????00ab58892871387b002804d09889304328722c7304e000ab1889287000202873387b002800d000243c7318e0387b002805d000ab9889304328722c7304e000ab1889287000202873387b002800d000243c7300ab588928711878????????00ab5889042802da5e89013604e000ab5889042800d0102637043f0c7d20c0000199????????391c????????6846??4f0fc80fc7ffbc08bc1847',
                  (48, 58, 152, 190, 196),
                  ((2, 0), (16, 2), (20, 1), (202, 7))),
 'clock_regs': ('80b5??????????4f??4a032339881b02d2185181??4a9182002801d1????????b888??494031088338898883f888??496031088078890881f8898881b889088280bc08bc1847',
                (2, 28),
                ((6, 7), (8, 2), (20, 2), (34, 1), (46, 1))),
 'clock_version': ('90b5??4f??4c788a2072????????d5231b02984201db802000e00020398a0843a081072020719620????????90bc08bc1847',
                   (10, 40),
                   ((2, 7), (4, 4))),
 'clock_select_a': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??481130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49??48????????e1e7',
                    (86,),
                    ((22, 0),
                     (24, 1),
                     (28, 0),
                     (38, 0),
                     (42, 1),
                     (46, 0),
                     (54, 0),
                     (56, 1),
                     (60, 0),
                     (66, 0),
                     (70, 1),
                     (74, 0),
                     (82, 1),
                     (84, 0))),
 'clock_select_b': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??480130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49??48????????e1e7',
                    (86,),
                    ((22, 0),
                     (24, 1),
                     (28, 0),
                     (38, 0),
                     (42, 1),
                     (46, 0),
                     (54, 0),
                     (56, 1),
                     (60, 0),
                     (66, 0),
                     (70, 1),
                     (74, 0),
                     (82, 1),
                     (84, 0))),
 'clock_select_c': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??481130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49b1208000????????e0e7',
                    (88,),
                    ((22, 0),
                     (24, 1),
                     (28, 0),
                     (38, 0),
                     (42, 1),
                     (46, 0),
                     (54, 0),
                     (56, 1),
                     (60, 0),
                     (66, 0),
                     (70, 1),
                     (74, 0),
                     (82, 1))),
 'clock_update': ('90b5071c0c1c??????????4900280f628c8401d1????????90bc08bc1847', (6, 20), ((10, 1),)),
 'clock_version_get': ('??490879002807d101200871??48007b??49487000200870??482a38408d7047',
                       (),
                       ((0, 1), (12, 0), (16, 1), (24, 0))),
 'clock_select_b_old': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??480130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??4929200001????????e0e7',
                        (88,),
                        ((22, 0),
                         (24, 1),
                         (28, 0),
                         (38, 0),
                         (42, 1),
                         (46, 0),
                         (54, 0),
                         (56, 1),
                         (60, 0),
                         (66, 0),
                         (70, 1),
                         (74, 0),
                         (82, 1))),
 'clock_select_c_old': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??481130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49??48????????e1e7',
                        (86,),
                        ((22, 0),
                         (24, 1),
                         (28, 0),
                         (38, 0),
                         (42, 1),
                         (46, 0),
                         (54, 0),
                         (56, 1),
                         (60, 0),
                         (66, 0),
                         (70, 1),
                         (74, 0),
                         (82, 1),
                         (84, 0)))}
_FFCC_ROOT = ('9cb5??48006801900027022f30da02e0781c071cf9e7????????002f03d1ff20????????02e0cc20????????0a20????????0024022c08da02e0601c041cf9e7????????69460855f7e700ab187919788842ddd1587959788842d9d1??????????48a038????????01209cbc08bc18479920????????0020f7e7', (22, 32, 40, 46, 64, 92, 100, 114), ((2, 0), (96, 0)))
_PROBE_DIVIDE = bytes.fromhex('784700000020a0e3a1c170e02000003a21c470e00f00003a0004a0e1ff2482e321c270e01700003a21c470e00900003a0004a0e1ff2882e321c470e00004a021ff2c822321c270e00e00003a00c070e29500002a2004a021a1c370e0801341200220a2e021c370e0001341200220a2e0a1c270e0801241200220a2e021c270e0001241200220a2e0a1c170e0801141200220a2e021c170e0001141200220a2e0a1c070e0801041200220a2e001c070e0001041200220b2e0e5ffff2a0200a0e11eff2fe1')

class _ProbeUnclosed(ValueError):
    pass


def _probe_need(condition, reason):
    if not condition:
        raise _ProbeUnclosed('console-probe-' + reason)


def _probe_u32(image, at):
    _probe_need(type(at) is int and 0 <= at <= len(image)-4, 'source-bounds')
    return struct.unpack_from('<I', image, at)[0]


def _probe_specs(role, ffcc=False, config_shifted=False, clock_2022=False):
    if role == 'config' and config_shifted:
        return _PROBE_CONFIG_SHIFTED_LINE
    if role in _CLOCK_SPECS:
        key = role + '_old' if not ffcc and role in ('clock_select_b','clock_select_c') else role
        spec = _CLOCK_SPECS[key]
        if clock_2022 and role in ('clock_select_a', 'clock_select_b', 'clock_select_c'):
            _probe_need(ffcc, 'clock-2022-uart-owner')
            pattern = bytearray.fromhex(spec[0].replace('??', '00'))
            # Three coherent selector layouts retain all other source operands.
            struct.pack_into('<H', pattern, 0x44, 0x3811)
            if role != 'clock_select_a':
                struct.pack_into('<H', pattern, 0x28,
                                 0x3011 if role == 'clock_select_b' else 0x3021)
            mask = ''.join('??' if spec[0][i*2:i*2+2] == '??' else f'{b:02x}'
                           for i, b in enumerate(pattern))
            return mask, spec[1], spec[2]
        return spec
    if ffcc and role == 'root':
        return _FFCC_ROOT
    if ffcc and role == 'copy':
        return _FF_SPECS['copy']
    if ffcc and role == 'init':
        mask,calls,literals = _PROBE_SPECS[role]
        return mask[:28] + '8021' + mask[32:],calls,literals
    return (_PROBE_SPECS if role in _PROBE_SPECS else _FF_SPECS)[role]


def _probe_shape(image, at, role, ffcc=False, clock_2022=False):
    mask,calls,literals = _probe_specs(role,ffcc,clock_2022=clock_2022)
    pattern = bytearray.fromhex(mask.replace('??','00'))
    # Diagnostic line immediates differ; the fixed template selects argument2,
    # so this out-of-range diagnostic path is not an active clock operation.
    if (role == 'clock_select_b' and not ffcc) or (role == 'clock_select_c' and ffcc):
        line = _word(image,at+0x54)
        _probe_need(line is not None and line & 0xff00 == 0x2000,'clock-diagnostic-operand')
        shift = _word(image,at+0x56)
        _probe_need(shift is not None and shift & 0xf83f == 0,'clock-diagnostic-shift')
        struct.pack_into('<2H',pattern,0x54,line,shift)
    found = _source_thumb_shape(image, at, bytes(pattern), calls, literals)
    if found is None and role == 'config' and ffcc:
        mask, calls, literals = _probe_specs(role, ffcc, config_shifted=True)
        found = _source_thumb_shape(image, at,
            bytes.fromhex(mask.replace('??', '00')), calls, literals)
    _probe_need(found is not None, role + '-body')
    return found


def _probe_roots(image, ffcc=False):
    mask,calls,literals = _probe_specs('root',ffcc)
    runs=[(m.start()//2,bytes.fromhex(m.group())) for m in re.finditer(r'(?:[0-9a-f]{2})+',mask)]
    offset,anchor=max(runs,key=lambda pair:len(pair[1]));start=0
    while (hit:=image.find(anchor,start)) >= 0:
        start=hit+1;at=hit-offset
        try:shape=_probe_shape(image,at,'root',ffcc)
        except _ProbeUnclosed:continue
        yield at,shape


def _probe_clock_closure(image, entries, shapes, copies, zeros, timeout, delay_state,
                         sv, irqsave, irqrestore, memcpy, code, pools, data, ram, iram, ffcc):
    def need(value, reason):
        _probe_need(value,'clock-'+reason)
    def zero(address, size):
        return _ff_ram(address,size) and any(a<=address and address+size<=b for a,b in zeros)
    clock_2022 = False
    def add(role, address):
        need(address not in entries.values(),'callee-alias')
        entries[role]=address;shapes[role]=_probe_shape(image,address,role,ffcc,clock_2022=clock_2022)
        return shapes[role]
    apply, av=shapes['apply'];cs,cl=shapes['clockset'];clear,clv=shapes['clockclear'];pin,pv=shapes['pinset']
    need(apply[4]==irqsave and apply[0x12]==memcpy and apply[0x24]==entries['clockset'],'apply-links')
    need(all(apply[o]==irqsave for o in (0x30,0x56,0x7c,0x94)) and
         all(apply[o]==irqrestore for o in (0x52,0x74,0x90,0xa6,0xb4)),'apply-irq')
    need(pin[4]==irqsave and pin[0x22]==irqrestore and pv[8]==sv[0x1a] and pv[0x1a]==0x03000610,'pin-links')
    need(all(cs[o]==irqsave for o in (0x10,0x26,0x50,0x74)) and
         all(cs[o]==irqrestore for o in (0x3c,0x66,0x90)) and
         clear[0x16]==clear[0x3a]==irqsave and clear[0x2e]==clear[0x54]==irqrestore,'selector-irq')
    need(cl[2]==cl[0x84]==clv[0x26]==clv[0x4a]==0x03000600 and
         cl[4]==clv[0xa]==sv[0x1a] and cl[0x18]==0x03000400,'selector-domain')
    table=cl[0xc]
    need(not table&3 and table==clv[6] and 0<=table<=len(image)-40,'selector-table')
    # Only source constants4 (set) and1 (clear) index this table. Argument10's
    # delay/diagnostic branch is native and not selected by the fixed template.
    need(struct.unpack_from('<2I',image,table+8)==(0x737f,8) and
         struct.unpack_from('<2I',image,table+32)==(0xff7f,15),'selector-rows')
    data.extend(((table+8,table+16),(table+32,table+40)))
    def owned(address,size):
        if zero(address,size):return True
        matches=[c for c in copies if c['target']<=address and address+size<=c['target']+c['size']]
        if len(matches)!=1:return False
        c=matches[0];raw=c['source']+address-c['target'];data.append((raw,raw+size));return True
    params=av[0x10]
    need(not params&3 and params==copies[0]['target'] and
         av[0x34]==params and av[0x16]==sv[0x1a] and owned(params,0x48),'parameter-state')
    regs,rl=add('clock_regs',apply[0x28]);version,vl=add('clock_version',apply[0x2c]);commit,ml=add('clock_commit',apply[0xaa])
    need(regs[2]==irqsave and regs[0x1c]==irqrestore and rl[6]==params and
         rl[8]==sv[0x1a] and all(rl[o]==0x03000600 for o in (0x14,0x22,0x2e)),'register-apply')
    need(vl[2]==params and vl[4]==0x03000640 and version[0x28]==entries['delay'],'version-domain')
    need(ml[2]==params+0x1c and ml[0x10]==ml[0x14]==ml[0xca]==params+0x38,'commit-state')
    word1=0x1033 if ffcc else 0x833
    diagnostic_offset = 0x5c if 0x5c in shapes['config'][0] else 0x5a
    diagnostic=shapes['config'][0][diagnostic_offset]
    if ffcc:
        try:
            _probe_shape(image, commit[0x98], 'clock_select_a', ffcc)
        except _ProbeUnclosed:
            _probe_shape(image, commit[0x98], 'clock_select_a', ffcc, clock_2022=True)
            clock_2022 = True
    for role,offset in (('clock_select_a',0x98),('clock_select_b',0x30),('clock_select_c',0x3a)):
        calls,values=add(role,commit[offset])
        need(len(calls)==1 and next(iter(calls.values()))==diagnostic,'selector-diagnostic-link')
        need(all(values[o]==(0x2022 if clock_2022 else 0x2033) for o in (0x16,0x26,0x36,0x42)) and
             all(values[o]==0x04800080 for o in (0x18,0x2a,0x38,0x46)) and
             all(values[o]==word1 for o in (0x1c,0x2e,0x3c,0x4a)),'selector-literals')
    update,uv=add('clock_update',commit[0xc4]);get,gl=add('clock_version_get',version[0xa])
    need(update[6]==irqsave and update[0x14]==irqrestore and uv[0xa]==params+0x88 and
         owned(uv[0xa],0x26),'update-state')
    need(gl[0]==params+0xb8 and gl[0xc]==0x030007a0 and gl[0x10]==gl[0x18] and
         not gl[0x10]&1 and owned(gl[0],5) and zero(gl[0x10],2),'version-state')
    roles=[(params,params+0x48),(uv[0xa],uv[0xa]+0x26),(gl[0],gl[0]+5),
           (gl[0x10],gl[0x10]+2),(delay_state,delay_state+0x26),
           (timeout,timeout+1),(sv[0x1a],sv[0x1a]+0x382)]
    # Both typed users share this copied state; other semantic roles stay disjoint.
    need(roles[1]==roles[4] and not any(_ff_overlap(a,b) for i,a in enumerate(roles) for j,b in enumerate(roles[i+1:],i+1) if not (i==1 and j==4)), 'state-alias')
    ram.extend(roles[:4])
    target=commit[0xbe];veneer=None
    if image[target:target+12]==_FF_THUNK:
        veneer=target;target=_ff_thunk(image,target)
        code.append((veneer,veneer+12));pools.append((veneer+12,veneer+16))
    owners=[]
    if 0<=target<=len(image)-len(_PROBE_DIVIDE):owners.append((target,'rom'))
    for copy in copies:
        if copy['target']<=target and target+len(_PROBE_DIVIDE)<=copy['target']+copy['size']:
            owners.append((copy['source']+target-copy['target'],'copied'))
    need(len(owners)==1,'divide-owner');raw,owner=owners[0]
    actual=bytearray(image[raw:raw+len(_PROBE_DIVIDE)]);expected=bytearray(_PROBE_DIVIDE)
    branch=struct.unpack_from('<I',actual,0x50)[0]
    need(branch>>24==0x2a,'divide-zero-branch')
    delta=branch&0xffffff
    if delta&0x800000:delta-=0x1000000
    zero_target=target+0x50+8+delta*4
    need(not zero_target&3 and 0<=zero_target<=len(image)-4,'divide-zero-owner')
    struct.pack_into('<I',actual,0x50,branch&0xff000000)
    struct.pack_into('<I',expected,0x50,struct.unpack_from('<I',expected,0x50)[0]&0xff000000)
    need(actual==expected,'divide-nonzero-abi')
    code.append((raw,raw+len(_PROBE_DIVIDE)))
    if owner=='copied':iram.append((target,target+len(_PROBE_DIVIDE)))
    result = dict(parameter_state=params,update_state=uv[0xa],version_cache=gl[0],version_output=gl[0x10],
                selector_table=table,selector_indices=[1,4],division_entry=target,
                division_source=raw,division_veneer=veneer)
    if clock_2022:
        result['selector_layout'] = 'coherent-2022-1033-v1'
    return result


def _probe_profile(image, console, console_shape, ffcc=False):
    reset=arm_b_target(image,0)
    _probe_need(reset is not None and reset>=4 and not reset&3 and reset+len(_PROBE_RESET)<=len(image),'reset-owner')
    code=[(reset,reset+len(_PROBE_RESET))];pools=[];data=[];ram=[];iram=[]
    def u32(at):return _probe_u32(image,at)
    def arm_literal(pc):
        op=u32(pc);_probe_need(op&0x0f7f0000==0x051f0000,'arm-literal')
        pool=pc+8+(op&4095);pools.append((pool,pool+4));return u32(pool)
    for off in range(0,len(_PROBE_RESET),4):
        expected=struct.unpack_from('<I',_PROBE_RESET,off)[0];actual=u32(reset+off)
        mask=0xfffff000 if expected&0x0f7f0000==0x051f0000 else 0xffffffff
        if off==0xc0:mask=0xff000000
        _probe_need(actual&mask==expected&mask,'reset-body')
        if mask==0xfffff000:arm_literal(reset+off)
    for off in (0,0x18,0x30,0x48,0x80,0x98,0x138):
        pc=reset+off;target=arm_literal(pc)
        _probe_need(0<=target<len(image) and (target&1 or not target&3) and
                    arm_literal(pc+8)==pc+21 and arm_literal(pc+12)==pc+24,'reset-return')
    _probe_need(arm_literal(reset+0x98)==console|1,'root-reset-link')
    stacks=[arm_literal(reset+off) for off in (0x6c,0x74,0x7c,0xc8,0x134)]
    _probe_need(all(not sp&3 and _ff_ram(sp-56,56) for sp in stacks),'stack-range')
    ram.extend((sp-56,sp) for sp in stacks)
    test=arm_literal(reset+0x48);table=test-28
    _probe_need(not test&3 and table>=0 and test+0x150<=len(image) and
                hashlib.sha256(image[test:test+0x150]).hexdigest()==HIGH_RAM_TEST_SHA256,'ram-test-body')
    base,extent,stride,word,half,byte,pulse=struct.unpack_from('<7I',image,table)
    _probe_need((base,extent,stride,word,half,byte,pulse)==
                (0x01000000,0x3fffff if ffcc else 0x1fffff,16,0x55aa0f,0xaa0f,0x55,0x03000700),'ram-test-span')
    for off,field in ((0,0),(0x10,8),(0x40,24),(0x6c,4),(0x80,4),(0xf4,12),(0x108,16),(0x11c,20)):
        _probe_need(arm_literal(test+off)==table+field,'ram-test-field')
    _probe_need(arm_literal(test+0x148)!=0,'ram-test-failure-return')
    code.append((test,test+0x150));data.append((table,table+28));ram.append((base,base+extent+1))
    copy=arm_literal(reset+0x80)-1;cc,cv=_probe_shape(image,copy,'copy',ffcc)
    _probe_need(not cc and all(cv[o]==pulse for o in (2,0x3a,0x68,0xa0,0xd0,0xdc)),'copy-domain')
    copies=[];zeros=[]
    for so,to,no,ro,zs,zn,zr in ((0x16,0xa,0xe,0x1c,0x42,0x46,0x4e),(0x7c,0x70,0x74,0x82,0xa8,0xac,0xb4)):
        at=cv[so]
        _probe_need(not at&3 and cv[to]==cv[ro]==at+4 and cv[no]==at+8 and
                    cv[zs]==cv[zr]==at+12 and cv[zn]==at+16,'copy-fields')
        src,dst,size,za,zn=struct.unpack_from('<5I',image,at) if 0<=at<=len(image)-20 else (0,0,0,0,0)
        _probe_need(size>0 and zn>0 and not(src|dst|size|za|zn)&3 and
                    0<=src<=len(image)-size and _ff_ram(dst,size) and za==dst+size and _ff_ram(za,zn),'copy-span')
        copies.append(dict(table_offset=at,source=src,target=dst,size=size));zeros.append((za,za+zn))
        data.extend(((at,at+20),(src,src+size)));ram.extend(((dst,dst+size),(za,za+zn)))
    if ffcc:
        table=cv[0xf0]
        _probe_need(not table&3 and cv[0xe4]==cv[0xf6]==table+4 and cv[0xe8]==table+8,'iram-copy-fields')
        src,dst,size=struct.unpack_from('<3I',image,table) if 0<=table<=len(image)-12 else (0,0,0)
        _probe_need(size>0 and not(src|dst|size)&3 and 0<=src<=len(image)-size and
                    0x03800000<=dst<dst+size<=0x03a00000,'iram-copy-span')
        copies.append(dict(table_offset=table,source=src,target=dst,size=size))
        data.extend(((table,table+12),(src,src+size)));iram.append((dst,dst+size))
    _probe_need(not _ff_overlap((copies[0]['target'],copies[0]['target']+copies[0]['size']),
                                (copies[1]['target'],copies[1]['target']+copies[1]['size'])),'copy-ambiguity')
    _probe_need(not any(_ff_overlap(z,(c['target'],c['target']+c['size'])) for z in zeros for c in copies),'zero-copy-overlap')
    def source(address,size):
        owners=[c for c in copies if c['target']<=address and address+size<=c['target']+c['size']]
        _probe_need(len(owners)==1 and not any(_ff_overlap((address,address+size),z) for z in zeros),'copied-field')
        return owners[0]['source']+address-owners[0]['target']
    entries={'root':console,'copy':copy};shapes={'root':console_shape,'copy':(cc,cv)}
    rc,rv=console_shape
    marker=None; peer_branch=None
    if ffcc:
        _probe_need(rc[0x20]==rc[0x28]==rc[0x72],'ffcc-init-links')
        # No-peer RX never reaches these calls. Preserve source targets without
        # claiming or replacing the external-download peripheral graph.
        _probe_need(all(0<=rc[o]<=len(image)-2 for o in (0x5c,0x64)), 'ffcc-peer-target-bounds')
        peer_branch=dict(call_pcs=[console+0x5c,console+0x64],
            targets=[rc[0x5c],rc[0x64]],argument_literal=rv[0x60],
            policy='unreachable-while-owned-null-rx-empty',semantics='unsupported-external-peer-path')
        marker=rv[2]
        _probe_need(u32(marker)==0x6c64,'ffcc-response-marker')
        data.append((marker,marker+4))
        rc={2:rc[0x16],8:rc[0x20],14:rc[0x2e],18:rc[0x40],0x34:rc[0x72]}
    primary,init,tx,wrapper=rc[2],rc[8],rc[14],rc[18]
    _probe_need(rc[0x34]==init and len({primary,init,tx,wrapper,console,copy})==6,'root-call-links')
    for role,at in (('primary',primary),('init',init),('tx',tx),('wrapper',wrapper)):
        entries[role]=at;shapes[role]=_probe_shape(image,at,role,ffcc)
    ic,iv=shapes['init'];setup,config=ic[4],ic[0x12]
    _probe_need(ic[0x16]==primary,'init-drain-link')
    for role,at in (('setup',setup),('config',config)):
        entries[role]=at;shapes[role]=_probe_shape(image,at,role,ffcc)
    _probe_need(set(iv.values())=={0x03000f40,pulse},'init-domain')
    base=0x03000f0c
    pl=shapes['primary'][1];tl=shapes['tx'][1]
    _probe_need(set(pl.values())=={base+4,pulse} and tl[0]==base+0x14 and
                tl[10]==pulse and tl[20]==base+0x14,'poll-transmit-domain')
    wc,wl=shapes['wrapper'];rx=wc[12]
    _probe_need(wc[22]==rx and wl[2]==wl[32]==wl[84] and
                wl[52]==wl[66]==wl[76]==base+4,'receive-call-links')
    entries['rx']=rx;shapes['rx']=_probe_shape(image,rx,'rx');rl=shapes['rx'][1]
    _probe_need(rl[8]==200000 and rl[22]==rl[54]==base+4 and rl[38]==rl[68]==pulse,'receive-domain')
    timeout=wl[2];timeout_source=source(timeout,1)
    _probe_need(image[timeout_source]==1,'receive-timeout-source')
    ram.append((timeout,timeout+1));data.append((timeout_source,timeout_source+1))
    sc,sv=shapes['setup'];fc,fl=shapes['config']
    config_diagnostic = None
    if 0x5c in fc:
        filename = fl[0x5a]
        _probe_need(0 <= filename < len(image), 'config-diagnostic-filename')
        end = image.find(b'\0', filename, min(len(image), filename + 256))
        _probe_need(end > filename and
                    all(32 <= byte <= 126 for byte in image[filename:end]),
                    'config-diagnostic-filename')
        data.append((filename, end + 1))
        config_diagnostic = dict(layout='immediate-line-shift-v1',
            entry=config, call_pc=config+0x5c, target=fc[0x5c],
            filename_literal_pc=config+0x5a, filename_address=filename,
            line=0x3b << 5, code_interval=[config, config+0x62],
            policy='inactive-for-fixed-configuration-argument')
    irqsave,irqrestore=fc[0x14],fc[0x2e]
    _probe_need(fc[0x38]==irqsave and image[irqsave:irqsave+24]==_FF_IRQ_SAVE and
                image[irqrestore:irqrestore+24]==_FF_IRQ_RESTORE,'irq-source')
    code.extend(((irqsave,irqsave+24),(irqrestore,irqrestore+24)))
    _probe_need(all(sc[o]==irqsave for o in (0xe,0x16,0x38,0x60,0x7c,0x9e,0xd8,0xf2,0x11e,0x13a)) and
                all(sc[o]==irqrestore for o in (0x34,0x5c,0x78,0x9a,0xb6,0xee,0x112,0x136,0x14e,0x158)),'setup-irq-links')
    _probe_need(fl[2]==0x03000620 and fl[0x1a]==fl[0x3e]==0xff3f and fl[6]==sv[0x1a],'config-nine-domain')
    _probe_need(sv[0x1a]==sv[0x3c]==sv[0x84] and _ff_ram(sv[0x1a],0x382) and
                all(sv[o]==0xff81 for o in (0x24,0x46,0x66,0x82,0xa4,0xfe)) and
                all(sv[o]==pulse for o in (0x26,0x92,0xa6,0x108,0x116)) and
                all(sv[o]==0x03000600 for o in (0x48,0x68,0xde)) and sv[0xba]==20000,'setup-domain')
    template=sv[8]
    _probe_need(not template&3 and image[template:template+44]==_PROBE_TEMPLATE,'setup-template')
    data.append((template,template+44));ram.append((sv[0x1a],sv[0x1a]+0x382))
    memcpy=sc[0xa];memcpy_source=memcpy
    if ffcc:
        target=_ff_thunk(image,memcpy)
        memcpy_source=source(target,len(_PROBE_MEMCPY_44))
        _probe_need(copies[2]['target']<=target<target+len(_PROBE_MEMCPY_44)<=copies[2]['target']+copies[2]['size'],'setup-copy-iram-owner')
        code.append((memcpy,memcpy+12));pools.append((memcpy+12,memcpy+16))
        iram.append((target,target+len(_PROBE_MEMCPY_44)))
    _probe_need(image[memcpy_source:memcpy_source+len(_PROBE_MEMCPY_44)]==_PROBE_MEMCPY_44,'setup-template-copy-abi')
    code.append((memcpy_source,memcpy_source+len(_PROBE_MEMCPY_44)))
    for off,role in ((0xbc,'delay'),(0xc2,'pinset'),(0xc8,'clockset'),(0xce,'apply'),(0xd4,'clockclear')):
        entries[role]=sc[off];shapes[role]=_probe_shape(image,sc[off],role)
    delay_values=shapes['delay'][1]
    delay_state=delay_values[2]
    _probe_need(delay_values[0x26]==delay_values[0x3e]==0x04800020,'delay-strobe-domain')
    _probe_need(not delay_state&3 and delay_state==copies[0]['target']+0x88 and
                _ff_ram(delay_state,0x26),'delay-state-role')
    delay_source=source(delay_state,0x26)
    _probe_need(not _ff_overlap((delay_state,delay_state+0x26),(timeout,timeout+1)) and
                u32(delay_source+0x20)>0 and
                struct.unpack_from('<H',image,delay_source+0x24)[0]>0,'delay-state-fields')
    data.append((delay_source,delay_source+0x26));ram.append((delay_state,delay_state+0x26))
    descriptor=sv[0x122];desc_source=source(descriptor,44)
    fields=struct.unpack_from('<11I',image,desc_source)
    _probe_need(tuple(fields[i]for i in (0,1,2,4,5,6,8,9,10))==
                (0x03000720,0x03000720,0x0300072c,0x03000724,0x03000724,0x03000730,0x03000728,0x03000728,0x03000734),'setup-descriptor')
    ram.append((descriptor,descriptor+44));data.append((desc_source,desc_source+44))
    clock_metadata=_probe_clock_closure(image,entries,shapes,copies,zeros,timeout,delay_state,sv,irqsave,irqrestore,memcpy,code,pools,data,ram,iram,ffcc)
    normal=arm_b_target(image,reset+0xc0)
    _probe_need(normal is not None and normal>=0 and normal+len(_PROBE_APP)<=len(image),'application-owner')
    for off in range(0,len(_PROBE_APP),4):
        expect=struct.unpack_from('<I',_PROBE_APP,off)[0];mask=0xfffff000 if expect&0x0f7f0000==0x051f0000 else 0xffffffff
        _probe_need(u32(normal+off)&mask==expect&mask,'application-body')
    for off in (4,12,24):
        sp=arm_literal(normal+off);_probe_need(not sp&3 and _ff_ram(sp-56,56),'application-stack');ram.append((sp-56,sp))
    app=arm_literal(normal+32)
    app_size=6 if ffcc else 4
    _probe_need(app&1 and 0<=app-1<=len(image)-app_size,'application-thumb-entry')
    if ffcc:
        _probe_need(_word(image,app-1)==0xb50f and (_word(image,app+1)or 0)&0xff00==0xa100 and
                    _word(image,app+3)==0x201f,'application-thumb-entry')
    else:
        _probe_need(image[app-1:app+3]==bytes.fromhex('0fb50022'),'application-thumb-entry')
    code.extend(((normal,normal+len(_PROBE_APP)),(app-1,app-1+app_size)))
    for role,at in entries.items():
        spec=_probe_specs(role,ffcc,config_shifted=(role == 'config' and 0x5c in shapes[role][0]),
                          clock_2022=clock_metadata.get('selector_layout') == 'coherent-2022-1033-v1')
        code.append((at,at+len(spec[0])//2))
        for off,_ in spec[2]:
            op=_word(image,at+off);pool=((at+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
    _probe_need(len(set(entries.values()))==len(entries) and not any(_ff_overlap(a,b)for i,a in enumerate(code)for b in code[i+1:]),'code-overlap')
    _probe_need(all(0<=a<b<=len(image) and not any(_ff_overlap((a,b),c)for c in code)for a,b in pools),'literal-owner')
    _probe_need(all(0<=a<b<=len(image) for a,b in data) and not any(_ff_overlap((app-1,app+3),v)for v in pools+data),'data-owner')
    if marker is not None:
        _probe_need(not any(_ff_overlap((marker,marker+4),v)for v in code+pools),'ffcc-marker-owner')
    guards=sorted(set(code+pools+data+[(0,4)]))
    writes=[dict(pc=init+off,address=address,size=width,value=value) for off,address,width,value in
            ((0x36,base+0x14,1,0),(0x38,base+0x20,2,0),(0x3c,base+0x1c,2,0x1e),
             (0x44,base,2,0),(0x4c,base+4,1,0x34),(0x50,base+8,1,0xff),
             *((off,base+0x10,1,value) for off,value in ((0x54,0x30),(0x58,0x10),(0x5a,0x10),(0x5e,0x20),(0x60,0x20),(0x64,1),(0x68,4))))]
    profile=dict(signature='thumb-byte-uart-finite-ff-cc-99-console-v1' if ffcc else 'thumb-byte-uart-finite-ff-dd-console-v1',admission='temporary-evidence-gated',
        policy='provisional-synchronous-null-console',register_width=2,csr_value=0xff,csr_sequence=[0xff,0xcc,0x99] if ffcc else [0xff,0xdd],
        base=base,status_address=base+8,control_address=base+0x10,isr_address=base+0x14,fifo_address=base+0xc,
        pulse_address=pulse,primary_entry=primary,primary_status_pc=primary+0xa,primary_control_pc=primary+4,
        init_entry=init,tx_entry=tx,console_root=console,receive_entry=rx,receive_wrapper=wrapper,
        init_writes=writes,rx_drain_pc=init+0x7a,
        tx_isr_pc=tx+2,tx_fifo_pc=tx+24,tx_callers=[console+(0x2e if ffcc else 14)],clock_setup=(0xc0,0xb2,0x7d,0x1c),
        code_intervals=[list(v)for v in sorted(set(code))],literal_intervals=[list(v)for v in sorted(set(pools))],
        data_intervals=[list(v)for v in sorted(set(data))],boot_guard_intervals=[[0,4],[reset,reset+len(_PROBE_RESET)],[normal,normal+len(_PROBE_APP)]],
        guard_intervals=[list(v)for v in guards],ram_intervals=[list(v)for v in sorted(set(ram))],iram_intervals=[list(v)for v in sorted(set(iram))],
        receive_timeout_flag=timeout,receive_timeout_source=timeout_source,copy_layouts=copies,zero_ranges=[list(z)for z in zeros],
        reset_entry=reset,copy_entry=copy,application_entry=app-1,setup_entry=setup,setup_template=template,
        setup_memcpy_entry=memcpy,delay_entry=entries['delay'],delay_state=delay_state,delay_state_source=delay_source,
        runtime_source_policy='defer-until-postpatch-primary-reparse-and-immutable-byte-match')
    if config_diagnostic is not None:
        clock_metadata['config_diagnostic'] = config_diagnostic
    profile.update(clock_guard=clock_metadata)
    if ffcc:
        profile.update(outside_config_drains=[4,4,2],lf_stages=[True,True,False],
            response_bytes=2,response_marker_address=marker,response_marker_word=0x6c64,
            config9_argument=0x80,setup_memcpy_source=memcpy_source,
            external_peer_branch=peer_branch)
    else:
        profile['reset_reentry']=dict(write_pcs=[primary+4,primary+6],status_read_pc=primary+0xa,
            root_lr=(console+2+4)|1,config_lr=(init+0x16+4)|1,address=base+0x10,
            width=1,value=0x20,status_address=base+8,status_mask=8)
    return profile


_find_fixed_uart_console_profile = find_uart_console_profile


def _find_previous_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    prior,reason=_find_fixed_uart_console_profile(image,ready_profile)
    if prior is not None or 'ambiguous' in reason:
        return prior,reason
    roots=list(_probe_roots(image))
    if not roots:return prior,reason
    if len(roots)!=1:return None,'console-probe-roots-ambiguous'
    try:return _probe_profile(image,*roots[0]),'accepted'
    except (_ProbeUnclosed,struct.error,TypeError,ValueError) as error:
        return None,str(error) if isinstance(error,_ProbeUnclosed) else 'console-probe-malformed-source'


def find_legacy_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    prior,reason=_find_previous_uart_console_profile(image,ready_profile)
    complete=[];failures=[]
    for at,shape in _probe_roots(image,True):
        try:complete.append(_probe_profile(image,at,shape,True))
        except (_ProbeUnclosed,_HalfFFUnclosed,struct.error,TypeError,ValueError) as error:
            failures.append(str(error))
    if len(complete)>1:return None,'console-ffcc-profiles-ambiguous'
    if complete:
        if prior is not None or 'ambiguous' in reason:return None,'console-protocol-ownership-ambiguous'
        return complete[0],'accepted'
    if prior is not None or 'ambiguous' in reason:return prior,reason
    return None,failures[0] if len(failures)==1 else 'console-ffcc-candidates-unclosed' if failures else reason
