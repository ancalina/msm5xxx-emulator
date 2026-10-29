"""Temporary source-owned copied halfword-window candidate; optics uncalibrated."""
from __future__ import annotations
import struct
from .arm import arm_b_target
from .mono_page import _shape

# Exact typed compiler bodies; only source literal loads and call encodings relocate.
_SPEC = {'init': ('00b52c2000f066f80a2000f000fc022000f060f8012000f05df80a2000f0f7fb202000f057f8052000f054f8222000f051f8112000f04ef8262000f04bf80f2000f048f8402000f045f8012000f042f8532000f03ff8002000f03cf8342000f039f8862000f036f8302000f033f8002000f030f82a2000f02df8cc2000f02af80a2000f0c4fb432000f024f8002000f021f87f2000f01ef8422000f01bf8002000f018f87f2000f015f8102000f012f8022000f00ff800200121490600224a80013001239b039842f9db512000f002f808bc1847', (4, 10, 16, 22, 28, 34, 40, 46, 52, 58, 64, 70, 76, 82, 88, 94, 100, 106, 112, 118, 124, 130, 136, 142, 148, 154, 160, 166, 172, 178, 204), ()), 'command': ('0121490608707047', (), ()), 'data': ('0121490648807047', (), ()), 'fill': ('00225300c852013201239b039a42f8db7047', (), ()), 'command_wrapper': ('00b5fff765fc08bc1847', (2,), ()), 'data_wrapper': ('00b5fff76efc08bc1847', (2,), ()), 'init_wrapper': ('00b5fff7e5fb08bc1847', (2,), ()), 'logo': ('8cb50a4f0b48796afff7abfb802280210192009100230022796a064800f0a9fe786a00f0a0fe8cbc08bc1847', (8, 28, 34), ((2, 7), (4, 0), (26, 0))), 'off': ('00b55020fff79aff2d20fff797ff08bc1847', (4, 10), ()), 'on': ('00b52c20fff791ff5120fff78eff08bc1847', (4, 10), ()), 'power': ('00b55020fff788ff2d20fff785ff2620fff782ff0020fff77fff0220fff77cff0020fff779ff08bc1847', (4, 10, 16, 22, 28, 34), ()), 'contrast': ('021c342000b5fff772ff101cfff76fff5120fff76cff08bc1847', (6, 12, 18), ()), 'copy': ('0120474908700020087046480068464909684018061c45480068051c41480068041cb44208d204e0281d051c201d041cf7e728682060f7e7012039490870002008703b4800683b4909684018061c38480068041cb44206d202e0201d041cf9e700202060f9e701202d4908700020087031480068314909684018061c30480068051c2d480068041cb44208d204e0281d051c201d041cf7e728682060f7e701201f4908700020087026480068264909684018061c23480068041cb4420dd202e0201d041cf9e700202060a003f8d101201349087000200870f2e70120104908700020087019480068194909684018061c18480068051c15480068041cb44208d204e0281d051c201d041cf7e728682060f7e7012002490870002008707047', (), ((2, 1), (10, 0), (14, 1), (22, 0), (28, 0), (58, 1), (66, 0), (70, 1), (78, 0), (104, 1), (112, 0), (116, 1), (124, 0), (130, 0), (160, 1), (168, 0), (172, 1), (180, 0), (208, 1), (220, 1), (228, 0), (232, 1), (240, 0), (246, 0), (276, 1)))}
_RESET = bytes.fromhex('8c439fe5010014e388e39f1588e39f0514ff2fe17847000080439fe5010014e37ce39f157ce39f0514ff2fe17847000074439fe5010014e370e39f1570e39f0514ff2fe17847000068439fe5010014e364e39f1564e39f0514ff2fe178470000000050e31600001ad7f021e3fcd29fe5dbf021e348d39fe5d3f021e344d39fe544439fe5010014e340e39f1540e39f0514ff2fe178470000')
_FULL = bytes.fromhex('4310a0e380c7a0e30010cce50020a0e30020cce57f30a0e30030cce54210a0e30010cce50020cce50030cce52c309fe50010a0e3002093e5000052e31eff2fd18120a0e1b22090e1b220cce1002093e5011081e2020051e1f8ffffba1eff2fe1')
_PARTIAL = bytes.fromhex('70402de910409de58057a0e343c0a0e300c0c5e50010c5e50030c5e542c0a0e300c0c5e50020c5e50040c5e582c3a0e102e0a0e1040052e17040bdc81eff2fc10120a0e1030051e1060000ca02608ce08660a0e1b66090e1b260c5e1012082e2030052e1f8ffffda01e08ee204005ee180c08ce2f1ffffda7040bde81eff2fe1')
_CONTIGUOUS = bytes.fromhex('10402de908c09de543e0a0e38047a0e300e0c4e50010c4e50030c4e542e0a0e300e0c4e50020c4e500c0c4e5011043e002204ce0013082e2011081e2930102e0000052e31040bd980010a0e31eff2f918130a0e1b33090e1b230c4e1011081e2020051e1f9ffff3a1040bde81eff2fe1')
_VENEER = bytes.fromhex("7847c04604f01fe5")
_INIT_COMMANDS = [0x2c,2,1,0x20,5,0x22,0x11,0x26,15,0x40,1,0x53,0,0x34,0x86,0x30,0,0x2a,0xcc,0x43,0,127,0x42,0,127,0x10,2]

class _Unclosed(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise _Unclosed('copied-window-' + reason)


def _word(image, at):
    _need(type(at) is int and 0 <= at <= len(image)-4, 'literal-bounds')
    return struct.unpack_from('<I', image, at)[0]


def _overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def _at(image, at, role):
    pattern, calls, literals = _SPEC[role]
    found = _shape(image, at, bytes.fromhex(pattern), calls, literals)
    _need(found is not None, role + '-body')
    return found


def _hits(image, role):
    text, calls, literals = _SPEC[role]
    pattern = bytes.fromhex(text)
    holes = {o+n for o in calls for n in range(4)}
    holes.update(o+n for o, _ in literals for n in (0, 1))
    runs=[];start=0
    while start < len(pattern):
        if start in holes:
            start+=1;continue
        end=start+1
        while end < len(pattern) and end not in holes:end+=1
        runs.append((start,pattern[start:end]));start=end
    offset, anchor=max(runs,key=lambda pair:len(pair[1]));start=0
    while (hit:=image.find(anchor,start)) >= 0:
        start=hit+1;at=hit-offset
        try:yield at,_at(image,at,role)
        except _Unclosed:pass


def _copy_owner(image):
    reset=arm_b_target(image,0)
    _need(reset is not None and reset>=4 and not reset&3 and reset+len(_RESET)<=len(image),'reset-owner')
    code=[(0,4),(reset,reset+len(_RESET))];pools=[];data=[];ram=[]
    def literal(pc):
        op=_word(image,pc)
        _need(op&0x0f7f0000==0x051f0000,'reset-literal')
        pool=pc+8+(op&4095);pools.append((pool,pool+4))
        return _word(image,pool)
    for off in range(0,len(_RESET),4):
        expected=struct.unpack_from('<I',_RESET,off)[0]
        mask=0xfffff000 if expected&0x0f7f0000==0x051f0000 else 0xffffffff
        _need(_word(image,reset+off)&mask==expected&mask,'reset-body')
        if mask==0xfffff000:literal(reset+off)
    for off in (0,0x18,0x30,0x48,0x80):
        target=literal(reset+off)
        _need(0<=target<len(image) and (target&1 or not target&3) and
              literal(reset+off+8)==reset+off+21 and
              literal(reset+off+12)==reset+off+24,'reset-call-return')
    for off in (0x6c,0x74,0x7c):
        sp=literal(reset+off)
        _need(not sp&3 and 0x01000000<=sp-56<sp<=0x02000000,'reset-stack')
        ram.append((sp-56,sp))
    copy=literal(reset+0x80)-1;calls,values=_at(image,copy,'copy')
    _need(not calls and all(values[o]==0x03000700 for o in(2,0x3a,0x68,0xa0,0xd0,0xdc,0x114)),'copy-domain')
    code.append((copy,copy+len(_SPEC['copy'][0])//2))
    for off,_ in _SPEC['copy'][2]:
        op=struct.unpack_from('<H',image,copy+off)[0];pool=((copy+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
    copies=[];zeros=[]
    for so,to,no,ro,zs,zn,zr in((0x16,0xa,0xe,0x1c,0x42,0x46,0x4e),(0x7c,0x70,0x74,0x82,0xa8,0xac,0xb4)):
        table=values[so]
        _need(not table&3 and values[to]==values[ro]==table+4 and values[no]==table+8 and
              values[zs]==values[zr]==table+12 and values[zn]==table+16,'copy-fields')
        source,target,size,zero,length=tuple(_word(image,table+n*4)for n in range(5))
        _need(size>0 and length>0 and not(source|target|size|zero|length)&3 and
              source+size<=len(image) and zero==target+size and
              0x01000000<=target<zero<zero+length<=0x02000000,'copy-span')
        copies.append(dict(table_offset=table,source=source,target=target,size=size));zeros.append((zero,zero+length))
        data.extend(((table,table+20),(source,source+size)));ram.extend(((target,target+size),(zero,zero+length)))
    table=values[0xf0]
    _need(not table&3 and values[0xe4]==values[0xf6]==table+4 and values[0xe8]==table+8,'iram-copy-fields')
    source,target,size=tuple(_word(image,table+n*4)for n in range(3))
    _need(size>0 and not(source|target|size)&3 and source+size<=len(image) and
          0x03800000<=target<target+size<=0x03a00000,'iram-copy-span')
    copies.append(dict(table_offset=table,source=source,target=target,size=size));data.extend(((table,table+12),(source,source+size)))
    dest=[(c['target'],c['target']+c['size'])for c in copies]+zeros
    _need(not any(_overlap(a,b)for i,a in enumerate(dest)for b in dest[i+1:]),'copy-zero-alias')
    sources=[(c['source'],c['source']+c['size'])for c in copies]
    _need(not any(_overlap(a,b)for i,a in enumerate(sources)for b in sources[i+1:]),'copy-source-alias')
    return reset,copy,copies,zeros,code,pools,data,ram


def _profile(image, owner, init, init_shape, full):
    reset,copy,copies,zeros,code,pools,data,ram=owner
    code=list(code);pools=list(pools);data=list(data);ram=list(ram)
    c=copies[2];runtime=c['target']+full-c['source']
    _need(not runtime&3 and image[full:full+len(_FULL)]==_FULL and
          image[full+0x64:full+0xe4]==_PARTIAL and
          image[full+0xe4:full+0x154]==_CONTIGUOUS and full+0x154<=c['source']+c['size'],'writer-bundle')
    count_table=_word(image,full+0x60)
    _need(not count_table&3 and _word(image,count_table)==0x4000,'pixel-count')
    code.extend(((full,full+0x60),(full+0x64,full+0xe4),(full+0xe4,full+0x154)))
    pools.append((full+0x60,full+0x64));data.append((count_table,count_table+4))
    calls,_=init_shape;delay=calls[10];command=calls[4]
    _need(all(calls[o]==delay for o in(10,28,130)) and
          all(target==command for o,target in calls.items()if o not in(10,28,130)),'init-call-links')
    _at(image,command,'command');_need(image[delay:delay+2]==b'\x70\x47','init-delay-return')
    roles={'init':init,'command':command};shapes={'init':init_shape,'command':_at(image,command,'command')}
    def linked(role,predicate):
        found=[(at,shape)for at,shape in _hits(image,role)if predicate(at,shape)]
        _need(len(found)==1,role+'-ownership')
        at,shape=found[0];roles[role]=at;shapes[role]=shape;return at,shape
    cmd_wrapper,_=linked('command_wrapper',lambda at,s:s[0][2]==command)
    linked('init_wrapper',lambda at,s:s[0][2]==init)
    for role in('off','on','power','contrast'):
        linked(role,lambda at,s:all(v==cmd_wrapper for v in s[0].values()))
    logos=[]
    for at,shape in _hits(image,'logo'):
        calls,values=shape;veneer=calls[34]
        if image[veneer:veneer+8]!=_VENEER or _word(image,veneer+8)!=runtime:continue
        try:_at(image,calls[8],'fill')
        except _Unclosed:continue
        context=values[2]
        if values[4]!=0xffff or not any(a<=context and context+0x28<=b for a,b in zeros):continue
        blit=calls[28]
        if image[blit:blit+8]!=_VENEER:continue
        blit_target=_word(image,blit+8)
        if blit_target&3 or not c['target']<=blit_target<blit_target+4<=c['target']+c['size']:continue
        if not 0<=values[26]<=len(image)-4:continue
        logos.append((at,shape,veneer,blit,blit_target))
    _need(len(logos)==1,'full-caller-owner')
    logo,shape,veneer,blit,blit_target=logos[0];roles['logo']=logo;shapes['logo']=shape
    roles['fill']=shape[0][8];shapes['fill']=_at(image,roles['fill'],'fill')
    context=shape[1][2];ram.append((context,context+0x28))
    code.extend(((veneer,veneer+8),(blit,blit+8),(delay,delay+2)))
    pools.extend(((veneer+8,veneer+12),(blit+8,blit+12)))
    # The blitter executes naturally; only its copied entry ownership is claimed.
    blit_source=c['source']+blit_target-c['target'];code.append((blit_source,blit_source+4))
    for role,at in roles.items():
        spec=_SPEC[role];code.append((at,at+len(spec[0])//2))
        for off,_ in spec[2]:
            op=struct.unpack_from('<H',image,at+off)[0];pool=((at+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
    _need(len(set(roles.values()))==len(roles) and not any(_overlap(a,b)for i,a in enumerate(code)for b in code[i+1:]),'code-alias')
    _need(all(0<=a<b<=len(image)and not any(_overlap((a,b),v)for v in code)for a,b in pools),'literal-owner')
    _need(all(0<=a<b<=len(image)for a,b in data),'data-bounds')
    base=min(v[0]for v in ram)
    _need(all(b<=base for a,b in code+pools+data),'rom-ram-overlap')
    code=sorted(set(code));pools=sorted(set(pools));data=sorted(set(data));guards=sorted(set(code+pools+data))
    return dict(signature='copied-byte-range-half128-v1',admission='temporary-evidence-gated',
        role='main',code_basis='low-primary-nor',protocol='copied-half128',width=128,height=128,command_port=0x02000000,
        data_port=0x02000002,command_width=1,access_width=2,bits_per_pixel=16,
        mode_control=0x40,entry_mode=1,pixel_control=0x10,pixel_mode=2,
        init_commands=list(_INIT_COMMANDS),after_clear_command=0x51,
        opaque_control_sequences=[[0x51],[0x2c,0x51],[0x50,0x2d],[0x50,0x2d,0x26,0,2,0]],
        init_control_values={'34':0x86,'30':0,'40':1,'10':2},
        runtime_qualification='complete-source-init-fullwindow-16384-halfwords',
        init_upper_caller='unproved-static-candidate-only',
        content_blitter='copied-entry-only-natural-guest-execution-not-replaced',
        command_arity='unclaimed-exact-source-sequences-only',pixel_convention='existing-rgb565-optics-unqualified',
        physical_controller=None,optical_properties=None,source_pcs=roles,
        full_entry=runtime,partial_entry=runtime+0x64,contiguous_entry=runtime+0xe4,
        count_table=count_table,framebuffer_pointer_cell=context+0x24,
        copy_entry=copy,reset_entry=reset,copy_layouts=copies,zero_ranges=[list(v)for v in zeros],
        code_intervals=[list(v)for v in code],literal_intervals=[list(v)for v in pools],
        data_intervals=[list(v)for v in data],boot_guard_intervals=[[0,4],[reset,reset+len(_RESET)]],
        guard_intervals=[list(v)for v in guards],ram_intervals=[list(v)for v in sorted(set(ram))],
        iram_intervals=[[c['target'],c['target']+c['size']]])


def find_copied_window_profile(image: bytes) -> tuple[dict | None, str]:
    """Static candidate only; observed full initialization must claim runtime ownership."""
    try:owner=_copy_owner(image)
    except _Unclosed as error:return None,str(error)
    candidates=[];failures=[];c=owner[2][2];start=c['source']
    fulls=[]
    while (full:=image.find(_FULL,start,c['source']+c['size']))>=0:
        fulls.append(full);start=full+1
    for init,shape in _hits(image,'init'):
        for full in fulls:
            try:candidates.append(_profile(image,owner,init,shape,full))
            except (_Unclosed,struct.error)as error:failures.append(str(error))
    if len(candidates)>1:return None,'copied-window-complete-groups-ambiguous'
    if candidates:return candidates[0],'accepted-static-runtime-unqualified'
    return None,failures[0]if len(failures)==1 else 'copied-window-complete-links-unclosed'
