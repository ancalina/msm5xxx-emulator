"""Narrow source-only protected x16 NOR detector, for review before integration.

Input is an already offset/extent-bounded primary image. No physical part, timing,
readback ID, storage mutation or RAM initialization is supplied by this module.
"""
from __future__ import annotations
from dataclasses import asdict
import re
import struct
from ..core.config import CopyLayout, LinkerLayout
from .arm import arm_b_target, thumb_bl_target, thumb_literal_value
from .memory_layout import find_linker_layout

_MASKS = {
    'copy': (
        '??4980b50120087000230b70??48??4f02683f68d619??4a15680468012005e02a68226008700b7004350434b442f7d3'
        '0a1c0870191c1370??4b??4c1f6824683e193c1c03e02160107011700434b442f9d310701170??4b??4c1f6824683e19'
        '??4f3d681c6805e02b6823601070117004350434b442f7d310701170??4b??4c1f6824683e193c1c03e0216010701170'
        '0434b442f9d3??4b??4c1f6824683e19??4f3d681c6805e02b6823601070117004350434b442f7d310701170??4b??4c'
        '1f6824683e193c1c03e02160107011700434b442f9d3??4b9880??4b??4c1f6824683e19??4f3d681c6801e008cd08c4'
        'b442fbd3107011701070117017a11f20????????80bc08bc18470000'
    ),
    'selector': (
        '??4890b5??49006b096840004718ff203880????????0404240c381c??49????????002c01d1??????????48006890bc'
        '08bc1847'
    ),
    'init': (
        'b0b5??4c0027??4d27602f60????????28600028??d1'
    ),
    'read': (
        '??4b90b51b688f1880335c6b6400a74200d903e0??4f3c79012c03d1012090bc08bc18471b6b3f685b00db195918????'
        '????0020f3e7'
    ),
    'program': (
        'f0b5061c151c??4a002086b002901079002800d05de0??4800688030006b1268400080184418ff2001300906090e401a'
        '0490059152e00598002817d1ff2301339d4213d3271c201c????????4120388000204100725a7a5201308028f9dbff3d'
        'ff360136013dff34013426e00499281ca94200d2049867087f00ff23013398421bd8307803970090388801900398????'
        '????600803d2ff210902009802e000980002ff2108430199039a084040211180039a1080013d01360134702139803888'
        '020afbd350213980ff213980c008800704d0012006b0f0bc08bc1847002daad80298f7e7'
    ),
    'erase': (
        '90b5??4c071c207900280dd0012805d0022809d1012090bc08bc1847??????????49??48??????????4800688030006b'
        '79084018a060216840004018071c????????20203880d0203880012020710020e1e7'
    ),
    'poll': (
        'f0b5??49002588680a6840008718702038803888020a01d215252ce050223a80ff223a8000230b71800901d3012522e0'
        '381c????????77203880d02038803c88200afcd3e008400711d0??4801250088??4e032805dc0023221c391c301c????'
        '????0023221c391c301c????????50223a80ff223a80281cf0bc08bc1847'
    ),
    'poll_guarded': (
        'f0b5??49002588680a6840008718702038803888020a01d2152530e050223a80ff223a8000230b71800901d3012526e0'
        '????????002822d0381c????????77203880d02038803c88200afcd3e008400711d0??4801250088??4e032805dc0023'
        '221c391c301c????????0023221c391c301c????????50223a80ff223a80281cf0bc08bc1847'
    ),
    'suspend': (
        '??4a9068116840004018b021018001880b0afcd340231940ff23002905d15021018003800020002102e0038015200221'
        '11717047'
    ),
    'resume': (
        '??4988680a6840008218d02010800120087100207047'
    ),
    'protect': (
        '0123db05984201d33f2100e07f2160220280020c131c0b400380ac230380914301807b2101807047'
    ),
    'protect_reordered': (
        '0123db05984201d27f2100e03f2160220280020c131c0b400380ac230380914301807b2101807047'
    ),
    'prefix': (
        '90b5??4c071c2068002806d1????????ff204b30??49????????00200021226804e08b009b189b6818180131b942f8db'
        'c0321168????????90bc08bc1847'
    ),
    'prefix_relocated': (
        '90b5??4c071c2068002806d1????????ff207030??49????????00200021226804e08b009b189b6818180131b942f8db'
        'c0321168????????90bc08bc1847'
    ),
    'wrapper': (
        'f0b5??4e071c3068151c0c1c002806d1????????ff202330??49??????????480079012802d1f0bc08bc184730682a1c'
        '8030c36b211c381c????????f3e7'
    ),
    'wrapper_relocated': (
        'f0b5??4e071c3068151c0c1c002806d1????????ff204830??49??????????480079012802d1f0bc08bc184730682a1c'
        '8030c36b211c381c????????f3e7'
    ),
    'geometry': (
        '??480068002800d1704704307047'
    ),
    'flag': (
        '??480078012800d1704700207047'
    ),
    'probe': (
        '902101804188090402881143ff220280081cf746'
    ),
    'irq_save': '7847000000000fe1c01080e301f021e1c00000e21eff2fe1',
    'irq_restore': '7847000000000fe1c010c0e301f021e1c00000e21eff2fe1',
}
_PATTERNS = {role: re.compile(b''.join(b'.' if mask[i:i+2] == '??' else
    re.escape(bytes([int(mask[i:i+2],16)])) for i in range(0,len(mask),2)),re.DOTALL)
    for role,mask in _MASKS.items()}

class _Unclosed(ValueError):
    pass

def _need(condition, reason):
    if not condition:
        raise _Unclosed(reason)

def _word(image, at, size=4):
    _need(type(at) is int and 0 <= at <= len(image)-size, 'source-bounds')
    return int.from_bytes(image[at:at+size], 'little')

def _literal(image, at, reg):
    value = thumb_literal_value(image, at, reg)
    _need(value is not None, 'literal-source')
    return value

def _call(image, at):
    target = thumb_bl_target(image, at)
    _need(target is not None and 0 <= target < len(image)-1, 'call-source')
    return target

def _code(image, at, role):
    if type(at) is not int or at & 1 or not 0 <= at <= len(image)-len(_MASKS[role])//2:
        return False
    if _PATTERNS[role].match(image, at) is None:
        return False
    mask = _MASKS[role]
    try:
        off = 0
        while off < len(mask)//2:
            if mask[off*2:off*2+8] == '????????':
                _call(image,at+off);off += 4;continue
            word = _word(image,at+off,2)
            if word & 0xf800 == 0x4800:
                _literal(image,at+off,word>>8&7)
            off += 2
    except _Unclosed:
        return False
    return True

def _hits(image, role):
    # A literal-first function still needs a nonempty anchor; never scan per byte in Python.
    mask = _MASKS[role]
    runs = [(match.start()//2,bytes.fromhex(match.group()))
            for match in re.finditer(r'(?:[0-9a-f]{2})+',mask)]
    offset,prefix = max(runs,key=lambda pair:len(pair[1]))
    start = 0
    while True:
        hit = image.find(prefix,start)
        if hit < 0:
            return
        start = hit+1
        at = hit-offset
        if _code(image,at,role):
            yield at

def _arm_literal(image, pc, expected):
    word = _word(image,pc)
    _need(word & 0xfffff000 == expected, 'arm-literal-producer')
    return _word(image,pc+8+(word&4095))

def _in_ram(address, size, ram_base, ram_size):
    return type(address) is int and ram_base <= address and size <= ram_base+ram_size-address

def _normal_copy(image, ram_base, ram_size):
    root = arm_b_target(image,0)
    _need(root is not None and not root & 3, 'reset-owner')
    def group(pc):
        _need(_word(image,pc+4)==0xe3140001 and _word(image,pc+16)==0xe12fff14
              and _word(image,pc+20)==0x4778, 'reset-interwork')
        target = _arm_literal(image,pc,0xe59f4000)
        _need(target & 1 and target < len(image), 'reset-callee')
        _need(_arm_literal(image,pc+8,0x159fe000)==pc+21
              and _arm_literal(image,pc+12,0x059fe000)==pc+24,'reset-return')
    pc = root
    for _ in range(3):
        group(pc);pc += 24
    for mode in (0xe321f0d7,0xe321f0db,0xe321f0d3):
        _need(_word(image,pc)==mode,'reset-stack')
        sp = _arm_literal(image,pc+4,0xe59fd000)
        _need(not sp & 3 and ram_base < sp <= ram_base+ram_size,'stack-outside-ram')
        pc += 8
    count = 0
    while count < 4 and _word(image,pc)!=0xe3500000:
        group(pc);pc += 24;count += 1
    _need(count in (3,4) and _word(image,pc)==0xe3500000
          and _word(image,pc+4)==0x1a000003,'normal-route')
    normal = arm_b_target(image,pc+8)
    _need(normal is not None and not normal & 3,'normal-entry')
    fixed = {0:0xe321f0d2,8:0xe321f0df,16:0xe321f0d1,20:0xe02dd00d,
             28:0xe321f0d3,36:0xe3100001,48:0xe12fff10,52:0x4778,60:0xe12fff12}
    _need(all(_word(image,normal+off)==value for off,value in fixed.items()),'normal-gate')
    for off in (4,12,24):
        sp = _arm_literal(image,normal+off,0xe59fd000)
        _need(not sp & 3 and ram_base < sp <= ram_base+ram_size,'normal-stack')
    copy = _arm_literal(image,normal+32,0xe59f0000)
    _need(copy & 1,'copy-isa');copy &= ~1
    _need(_arm_literal(image,normal+40,0x159fe000)==normal+53
          and _arm_literal(image,normal+44,0x059fe000)==normal+56,'copy-return')
    main = _arm_literal(image,normal+56,0xe59f2000)
    _need(main & 1 and main < len(image) and _code(image,copy,'copy'),'copy-body')
    _need(_literal(image,copy,1)==0x03000700
          and _literal(image,copy+0xd6,3)==0x048000a0,'copy-io-domain')
    source_at = _literal(image,copy+0x16,2)
    _need(_literal(image,copy+0xc,0)==source_at+4
          and _literal(image,copy+0xe,7)==source_at+8,'copy-tuple')
    _need(_literal(image,copy+0x38,3)==source_at+12
          and _literal(image,copy+0x3a,4)==source_at+16,'zero-tuple')
    source,target,size,zero,zero_size = (_word(image,source_at+i) for i in (0,4,8,12,16))
    _need(size > 0 and zero_size > 0 and not (source|target|size|zero|zero_size)&3
          and source+size <= len(image) and target+size==zero
          and zero+zero_size <= 0x100000000,'copy-span')
    _need(_in_ram(target,size,ram_base,ram_size)
          and _in_ram(zero,zero_size,ram_base,ram_size),'copy-outside-ram')
    layout = LinkerLayout(source_at,source,target,size,zero,zero_size)
    writes = [(zero,zero_size)]
    copies = [CopyLayout(source_at,source,target,size)]
    for toff,noff,soff in ((0x56,0x58,0x60),(0x96,0x98,0xa0),(0xda,0xdc,0xe4)):
        dest,count,src = (_word(image,_literal(image,copy+off,reg))
                          for off,reg in ((toff,3),(noff,4),(soff,7)))
        _need(not (dest|count|src)&3 and src+count <= len(image)
              and dest+count <= 0x100000000,'other-copy-span')
        table_at = _literal(image,copy+soff,7)
        _need(_literal(image,copy+toff,3)==table_at+4
              and _literal(image,copy+noff,4)==table_at+8,'other-copy-tuple')
        _need(_in_ram(dest,count,ram_base,ram_size)
              or 0x03800000<=dest<=dest+count<=0x03a00000,'other-copy-owner')
        copies.append(CopyLayout(table_at,src,dest,count))
        writes.append((dest,count))
    for layout_,(toff,noff) in zip(copies[1:3],((0x7c,0x7e),(0xbc,0xbe))):
        target_at,count_at = _literal(image,copy+toff,3),_literal(image,copy+noff,4)
        _need(target_at==layout_.table_offset+12
              and count_at==layout_.table_offset+16,'zero-tuple')
        dest,count = _word(image,target_at),_word(image,count_at)
        _need(not (dest|count)&3 and dest+count<=0x100000000
              and _in_ram(dest,count,ram_base,ram_size),'zero-span')
        writes.append((dest,count))
    return dict(root=root,decision=pc,normal=normal,copy=copy,layout=layout,copies=copies,writes=writes)

def _profile_at(image, init, context, ram_base, ram_size):
    selected = _call(image,init+0xc)
    _need(_code(image,selected,'selector'),'selector')
    state,objglobal = _literal(image,init+2,4),_literal(image,init+6,5)
    _need(_in_ram(state,12,ram_base,ram_size) and _in_ram(objglobal,4,ram_base,ram_size), 'runtime-global-range')
    _need(_literal(image,selected+4,1)==state,'selector-state')
    branch = _word(image,init+0x14,2)
    _need(branch&0xff00==0xd100,'init-branch')
    imm = branch&255;imm -= 256 if imm&128 else 0
    success = init+0x18+2*imm
    _need(image[success:success+8]==bytes.fromhex('2771b0bc08bc1847'),'init-mode-return')
    layout=context['layout']
    def source(ram,size):
        _need(_in_ram(ram,size,ram_base,ram_size) and layout.data_target <= ram
              and ram+size <= layout.data_target+layout.data_size,'copy-provenance')
        return layout.data_source+ram-layout.data_target
    probe = _literal(image,selected+0x1c,1)
    cell = _literal(image,selected+0x2a,0)
    _need(probe&1 and not (cell|objglobal|state)&3,'pointer-alignment');probe &= ~1
    object_ = _word(image,source(cell,4))
    _need(_word(image,source(objglobal,4))==0 and not object_&3
          and object_+0xd0 <= len(image),'selected-object')
    _need(_literal(image,selected,0)==object_+0x80,'selector-object')
    probe_source = source(probe,20)
    _need(_code(image,probe_source,'probe'),'discarded-query')
    for address,size in ((cell,4),(objglobal,4),(probe,20)):
        _need(all(not(dest<address+size and address<dest+count)
                  for dest,count in context['writes']),'copy-zero-conflict')
    linked = find_linker_layout(image,required_span=(cell,4))
    if linked is not None:
        _need((linked.data_source,linked.data_target,linked.data_size,linked.bss_target,linked.bss_size)==
              (layout.data_source,layout.data_target,layout.data_size,layout.bss_target,layout.bss_size),'linker-conflict')
    save,restore,thunk = (_call(image,selected+off)for off in (0x12,0x26,0x1e))
    _need(_code(image,save,'irq_save') and _code(image,restore,'irq_restore')
          and _word(image,thunk,2)==0x4708,'query-return-ownership')
    count = _word(image,object_+4)
    _need(0<count and 8+4*count<=0xb0,'geometry-count')
    sectors = [_word(image,object_+8+4*i)for i in range(count)]
    begin,length = _word(image,object_+0xb0)*2,_word(image,object_+0xb4)*2
    _need(all(n>0 and not n&1 for n in sectors) and sum(sectors)==length
          and begin+length<=len(image) and begin+length<=0x100000000,'geometry-or-seed-gap')
    methods={}
    roles={}
    for role,off in (('read',0xb8),('program',0xbc),('erase',0xc0),('poll',0xc4),('suspend',0xc8),('resume',0xcc)):
        address = _word(image,object_+off)
        _need(address&1,'callback-isa');address &= ~1
        options=('poll','poll_guarded')if role=='poll'else(role,)
        matched=[name for name in options if _code(image,address,name)]
        _need(len(matched)==1,'callback-'+role)
        methods[role]=address;roles[role]=matched[0]
    read,program,erase = (methods[k]for k in ('read','program','erase'))
    terms=((read,3,objglobal),(read+0x14,7,state),(program+6,2,state),
           (program+0x16,0,objglobal),(erase+2,4,state),(erase+0x28,0,objglobal),
           (methods['poll']+2,1,state),(methods['suspend'],2,state),(methods['resume'],1,state))
    _need(all(_literal(image,at,reg)==value for at,reg,value in terms),'callback-globals')
    protect = _call(image,program+0x48)
    protection=[role for role in ('protect','protect_reordered')if _code(image,protect,role)]
    _need(len(protection)==1 and _call(image,program+0x8e)==protect
          and _call(image,erase+0x3e)==protect,'protect-call-family')
    guarded=roles['poll']=='poll_guarded';post=methods['poll'];flag=None;getter=None
    _need(_call(image,post+(0x3a if guarded else 0x32))==protect,'post-protect-link')
    if guarded:
        getter=_call(image,post+0x30)
        _need(_code(image,getter,'flag'),'post-flag-getter')
        flag=_literal(image,getter,0);source(flag,1)
    extras={}
    for role,choices,checks in (
        ('prefix',('prefix','prefix_relocated'),((2,4,objglobal),)),
        ('wrapper',('wrapper','wrapper_relocated'),((2,6,objglobal),(0x1e,0,state))),
        ('geometry',('geometry',),((0,0,objglobal),))):
        found={(at,name)for name in choices for at in _hits(image,name)
               if all(_literal(image,at+off,reg)==value for off,reg,value in checks)}
        _need(len(found)==1,role+'-ownership')
        extras[role]=next(iter(found))
    _need(_call(image,extras['prefix'][0]+0x34)==thunk,'prefix-erase-thunk')
    program_thunk=_call(image,extras['wrapper'][0]+0x38)
    _need(_word(image,program_thunk,2)==0x4718,'program-thunk')
    code=[(context['root'],context['decision']+12),
          (context['normal'],context['normal']+0x40),(context['copy'],context['copy']+0x10c),
          (init,success+8),(selected,selected+0x34),(save,save+24),(restore,restore+24),
          (probe_source,probe_source+20),(protect,protect+0x28)]
    code += [(at,at+len(_MASKS[roles[role]])//2)for role,at in methods.items()]
    code += [(at,at+len(_MASKS[name])//2)for at,name in extras.values()]
    if getter is not None:code.append((getter,getter+0xe))
    pools=[]
    for lo,hi in ((context['root'],context['decision']+12),(context['normal'],context['normal']+0x40)):
        for pc in range(lo,hi,4):
            op=_word(image,pc)
            if op&0x0fff0000==0x059f0000:
                at=pc+8+(op&4095);_word(image,at);pools.append((at,at+4))
    thumb_roles=[(context['copy'],'copy'),(init,'init'),(selected,'selector'),
                 (protect,protection[0]),(probe_source,'probe')]
    thumb_roles += [(at,roles[role])for role,at in methods.items()]
    thumb_roles += list(extras.values())
    if getter is not None:thumb_roles.append((getter,'flag'))
    for at,name in thumb_roles:
        mask=_MASKS[name];off=0
        while off<len(mask)//2:
            if mask[off*2:off*2+8]=='????????':off+=4;continue
            op=_word(image,at+off,2)
            if op&0xf800==0x4800:
                pool=((at+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
            off+=2
    tables=[(copy.table_offset,copy.table_offset+(20 if i<3 else 12))
            for i,copy in enumerate(context['copies'])]
    protected=code+pools+tables+[(object_,object_+0xd0),(source(cell,4),source(cell,4)+4)]
    protected += [(copy.source,copy.source+copy.size)for copy in context['copies']]
    _need(all(0<=a<b<=len(image) and not(a<begin+length and begin<b)for a,b in protected),'aperture-source-conflict')
    return dict(signature='arm-thumb-copy-selected-protected-nor-x16-v1',admission='temporary-evidence-gated',
        bus_width=2,address=begin,size=length,sector_sizes=sectors,selected_object=object_,
        object_global=objglobal,selection_cell=cell,state_global=state,initial_base=0,
        normal_entry=context['normal'],copy_producer=context['copy'],normal_copy=asdict(layout),
        initializer=init,selector=selected,methods=methods,protect_entry=protect,
        protect_form=protection[0],post_erase_form='flag-equals-one'if guarded else'always',
        post_erase_getter=getter,post_erase_flag=flag,
        discarded_probe=dict(address=probe,source=probe_source,size=20,thunk=thunk),
        runtime_guards=dict(active_object=objglobal,expected_object=object_,selection_cell=cell,
            expected_selection=object_,base_address=state,expected_base=0,mode_address=state+4,
            operation_address=state+8,query_object_before_init=0),
        data_intervals=[[object_,object_+0xd0],[probe_source,probe_source+20],
            [source(cell,4),source(cell,4)+4],[source(objglobal,4),source(objglobal,4)+4]],
        geometry_entry=extras['geometry'][0],sector_prefix_entry=extras['prefix'][0],
        program_wrapper=extras['wrapper'][0],code_intervals=[list(p)for p in code],
        literal_intervals=[list(p)for p in sorted(set(pools+tables))],
        copy_layouts=[asdict(c)for c in context['copies']],
        copy_tail_call=_call(image,context['copy']+0x100),
        physical_id=None,timing='unverified',readback_policy='requires-native-validation')

def find_protected_nor_profile(image: bytes, ram_base: int, ram_size: int,
                               load_address: int = 0) -> tuple[dict | None,str]:
    """Return a complete source contract. RAM guards are expectations, not writes."""
    if (not isinstance(image,(bytes,bytearray)) or any(type(x)is not int for x in(ram_base,ram_size,load_address))
            or ram_base<0 or ram_size<=0 or ram_base+ram_size>0x100000000 or load_address!=0):
        return None,'protected-nor-layout-unverified'
    try:
        context=_normal_copy(image,ram_base,ram_size)
    except _Unclosed as error:
        return None,'protected-nor-'+str(error)
    profiles=[];reasons=[]
    for init in _hits(image,'init'):
        try:profiles.append(_profile_at(image,init,context,ram_base,ram_size))
        except _Unclosed as error:reasons.append(str(error))
    if len(profiles)>1:return None,'protected-nor-profiles-ambiguous'
    if profiles:return profiles[0],'accepted'
    return None,'protected-nor-'+(reasons[0]if len(reasons)==1 else'candidates-unclosed'if reasons else'not-found')
