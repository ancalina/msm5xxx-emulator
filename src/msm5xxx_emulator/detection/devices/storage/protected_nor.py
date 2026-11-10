"""Narrow source-only protected x16 NOR detector, for review before integration.

Input is an already offset/extent-bounded primary image. No physical part, timing,
readback ID, storage mutation or RAM initialization is supplied by this module.
"""
from __future__ import annotations
from dataclasses import asdict
from capstone import arm as a
from msm5xxx_emulator.detection.contracts import BodySpec
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.layout_queries import find_linker_layout

_MASKS = {'copy':
    '??4980b50120087000230b70??48??4f02683f68d619??4a15680468012005e02a68226008700b7004350434b442f7d30a1c0870191c1370??4b??4c1f6824683e193c1c03e02160107011700434b442f9d310701170??4b??4c1f6824683e19??4f3d681c6805e02b6823601070117004350434b442f7d310701170??4b??4c1f6824683e193c1c03e02160107011700434b442f9d3??4b??4c1f6824683e19??4f3d681c6805e02b6823601070117004350434b442f7d310701170??4b??4c1f6824683e193c1c03e02160107011700434b442f9d3??4b9880??4b??4c1f6824683e19??4f3d681c6801e008cd08c4b442fbd3107011701070117017a11f20????????80bc08bc18470000',
    'selector': '??4890b5??49006b096840004718ff203880????????0404240c381c??49????????002c01d1??????????48006890bc08bc1847', 'init':
    'b0b5??4c0027??4d27602f60????????28600028??d1', 'read':
    '??4b90b51b688f1880335c6b6400a74200d903e0??4f3c79012c03d1012090bc08bc18471b6b3f685b00db195918????????0020f3e7', 'program':
    'f0b5061c151c??4a002086b002901079002800d05de0??4800688030006b1268400080184418ff2001300906090e401a0490059152e00598002817d1ff2301339d4213d3271c201c????????4120388000204100725a7a5201308028f9dbff3dff360136013dff34013426e00499281ca94200d2049867087f00ff23013398421bd8307803970090388801900398????????600803d2ff210902009802e000980002ff2108430199039a084040211180039a1080013d01360134702139803888020afbd350213980ff213980c008800704d0012006b0f0bc08bc1847002daad80298f7e7',
    'erase':
    '90b5??4c071c207900280dd0012805d0022809d1012090bc08bc1847??????????49??48??????????4800688030006b79084018a060216840004018071c????????20203880d0203880012020710020e1e7',
    'poll':
    'f0b5??49002588680a6840008718702038803888020a01d215252ce050223a80ff223a8000230b71800901d3012522e0381c????????77203880d02038803c88200afcd3e008400711d0??4801250088??4e032805dc0023221c391c301c????????0023221c391c301c????????50223a80ff223a80281cf0bc08bc1847',
    'poll_guarded':
    'f0b5??49002588680a6840008718702038803888020a01d2152530e050223a80ff223a8000230b71800901d3012526e0????????002822d0381c????????77203880d02038803c88200afcd3e008400711d0??4801250088??4e032805dc0023221c391c301c????????0023221c391c301c????????50223a80ff223a80281cf0bc08bc1847',
    'suspend': '??4a9068116840004018b021018001880b0afcd340231940ff23002905d15021018003800020002102e003801520022111717047', 'resume':
    '??4988680a6840008218d02010800120087100207047', 'protect': '0123db05984201d33f2100e07f2160220280020c131c0b400380ac230380914301807b2101807047',
    'protect_reordered': '0123db05984201d27f2100e03f2160220280020c131c0b400380ac230380914301807b2101807047', 'prefix':
    '90b5??4c071c2068002806d1????????ff204b30??49????????00200021226804e08b009b189b6818180131b942f8dbc0321168????????90bc08bc1847', 'prefix_relocated':
    '90b5??4c071c2068002806d1????????ff207030??49????????00200021226804e08b009b189b6818180131b942f8dbc0321168????????90bc08bc1847', 'wrapper':
    'f0b5??4e071c3068151c0c1c002806d1????????ff202330??49??????????480079012802d1f0bc08bc184730682a1c8030c36b211c381c????????f3e7', 'wrapper_relocated':
    'f0b5??4e071c3068151c0c1c002806d1????????ff204830??49??????????480079012802d1f0bc08bc184730682a1c8030c36b211c381c????????f3e7', 'geometry':
    '??480068002800d1704704307047', 'flag': '??480078012800d1704700207047', 'probe': '902101804188090402881143ff220280081cf746'}
def _body_spec(mask):
    """Compile one masked Thumb body into shared instruction contracts."""
    size = len(mask) // 2
    calls, literals, words = [],[],[]
    offset = 0
    while offset < size:
        if mask[offset * 2:offset * 2 + 8] == '????????':
            calls.append(offset)
            offset += 4
            continue
        first = mask[offset * 2:offset * 2 + 2]
        second = mask[offset * 2 + 2:offset * 2 + 4]
        if first == '??' and second in {f'{value:02x}' for value in range(0x48, 0x50)}:
            literals.append((offset, int(second, 16) - 0x48))
            offset += 2
            continue
        expected = value_mask = 0
        for byte_index, token in enumerate((first, second)):
            if token == '??':
                continue
            shift = byte_index * 8
            expected |= int(token, 16) << shift
            value_mask |= 0xff << shift
        if value_mask:
            words.append((offset, expected, value_mask))
        offset += 2
    return BodySpec(size, tuple(words), tuple(literals), tuple(calls))

_BODY_SPECS = {role: _body_spec(mask) for role, mask in _MASKS.items()}

def _body(image, at, role):
    if type(at) is not int or at & 1:
        return None
    return _BODY_SPECS[role].match(facts_for(image), at)

def _code(image, at, role):
    if role in ('irq_save', 'irq_restore'):
        return irq_primitive_matches(image, at, role)
    return _body(image, at, role) is not None

def _hits(image, role):
    for body in _BODY_SPECS[role].find(facts_for(image)):
        yield body.entry

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
        _need(_in_ram(ram,size,ram_base,ram_size) and layout.data_target <= ram and ram+size <= layout.data_target+layout.data_size,'copy-provenance')
        return layout.data_source+ram-layout.data_target
    probe = _literal(image,selected+0x1c,1)
    cell = _literal(image,selected+0x2a,0)
    _need(probe&1 and not (cell|objglobal|state)&3,'pointer-alignment');probe &= ~1
    object_ = _word(image,source(cell,4))
    _need(_word(image,source(objglobal,4))==0 and not object_&3 and object_+0xd0 <= len(image),'selected-object')
    _need(_literal(image,selected,0)==object_+0x80,'selector-object')
    probe_source = source(probe,20)
    _need(_code(image,probe_source,'probe'),'discarded-query')
    for address,size in ((cell,4),(objglobal,4),(probe,20)):
        _need(all(not(dest<address+size and address<dest+count) for dest,count in context['writes']), 'copy-zero-conflict')
    linked = find_linker_layout(image,required_span=(cell,4))
    if linked is not None:
        _need((linked.data_source,linked.data_target,linked.data_size,linked.bss_target,linked.bss_size)== (layout.data_source,layout.data_target,layout.data_size,layout.bss_target,layout.bss_size),
            'linker-conflict')
    save,restore,thunk = (_call(image,selected+off)for off in (0x12,0x26,0x1e))
    _need(_code(image,save,'irq_save') and _code(image,restore,'irq_restore') and _word(image,thunk,2)==0x4708, 'query-return-ownership')
    count = _word(image,object_+4)
    _need(0<count and 8+4*count<=0xb0,'geometry-count')
    sectors = [_word(image,object_+8+4*i)for i in range(count)]
    begin,length = _word(image,object_+0xb0)*2,_word(image,object_+0xb4)*2
    _need(all(n>0 and not n&1 for n in sectors) and sum(sectors)==length and begin+length<=len(image) and begin+ length<=0x100000000,'geometry-or-seed-gap')
    methods={}
    roles={}
    for role,off in (('read',0xb8),('program',0xbc),('erase',0xc0),('poll',0xc4),('suspend',0xc8),('resume',0xcc)):
        address = _word(image,object_+off)
        _need(address&1,'callback-isa');address &= ~1
        options=('poll','poll_guarded')if role=='poll'else(role,)
        matched= [name for name in options if _code(image,address,name)]
        _need(len(matched)==1,'callback-'+role)
        methods[role]=address;roles[role]=matched[0]
    read,program,erase = (methods[k]for k in ('read','program','erase'))
    terms=((read,3,objglobal),(read+0x14,7,state),(program+6,2,state), (program+0x16,0,objglobal),(erase+2,4, state),(erase+0x28,0,objglobal), (methods['poll']+2,1,state),(methods['suspend'],2,state),(methods['resume'],1,state))
    _need(all(_literal(image,at,reg)==value for at,reg,value in terms),'callback-globals')
    protect = _call(image,program+0x48)
    protection= [role for role in ('protect','protect_reordered')if _code(image,protect,role)]
    _need(len(protection)==1 and _call(image,program+0x8e)==protect and _call(image,erase+0x3e)==protect, 'protect-call-family')
    guarded=roles['poll']=='poll_guarded';post=methods['poll'];flag=None;getter=None
    _need(_call(image,post+(0x3a if guarded else 0x32))==protect,'post-protect-link')
    if guarded:
        getter=_call(image,post+0x30)
        _need(_code(image,getter,'flag'),'post-flag-getter')
        flag=_literal(image,getter,0);source(flag,1)
    extras={}
    for role,choices,checks in (('prefix',('prefix','prefix_relocated'),((2,4,objglobal),)), ('wrapper',('wrapper','wrapper_relocated'),((2,6,objglobal),(0x1e,0,state))),
        ('geometry',('geometry',),((0,0, objglobal),))):
        found={(at,name)for name in choices for at in _hits(image,name) if all(_literal(image,at+off,reg)==value for off,reg,value in checks)}
        _need(len(found)==1,role+'-ownership')
        extras[role]=next(iter(found))
    _need(_call(image,extras['prefix'][0]+0x34)==thunk,'prefix-erase-thunk')
    program_thunk=_call(image,extras['wrapper'][0]+0x38)
    _need(_word(image,program_thunk,2)==0x4718,'program-thunk')
    code= [(context['root'],context['decision']+12), (context['normal'],context['normal']+0x40), (init,success+8),(selected,selected+0x34),(save,save+24),(restore,restore+24),
        (probe_source,probe_source+20),(protect, protect+0x28)]
    code += context['startup_code_intervals']
    code +=[(at,at+len(_MASKS[roles[role]])//2)for role,at in methods.items()]
    code +=[(at,at+len(_MASKS[name])//2)for at,name in extras.values()]
    if getter is not None:code.append((getter,getter+0xe))
    pools= []
    for lo,hi in ((context['root'],context['decision']+12),(context['normal'],context['normal']+0x40)):
        for pc in range(lo,hi,4):
            op=_word(image,pc)
            if op&0x0fff0000==0x059f0000:
                at=pc+8+(op&4095);_word(image,at);pools.append((at,at+4))
    thumb_roles= [(init,'init'),(selected,'selector'), (protect,protection[0]),(probe_source,'probe')]
    thumb_roles +=[(at,roles[role])for role,at in methods.items()]
    thumb_roles += list(extras.values())
    if getter is not None:thumb_roles.append((getter,'flag'))
    for at,name in thumb_roles:
        body = _body(image, at, name)
        _need(body is not None, 'body-source')
        pools.extend((pool, pool + 4) for pool in body.pools)
    tables= [(copy.table_offset,copy.table_offset+(20 if i<3 else 12)) for i,copy in enumerate(context['copies'])]
    protected=code+pools+tables+[(object_,object_+0xd0),(source(cell,4),source(cell,4)+4)]
    protected +=[(copy.source,copy.source+copy.size)for copy in context['copies']]
    _need(all(0<=a<b<=len(image) and not(a<begin+length and begin<b)for a,b in protected),'aperture-source-conflict')
    return dict(signature='arm-thumb-copy-selected-protected-nor-x16-v1',admission='temporary-evidence-gated', bus_width=2,address=begin,size=length,sector_sizes=sectors,selected_object=object_,
        object_global= objglobal,selection_cell=cell,state_global=state,initial_base=0, normal_entry=context['normal'], copy_producer=context['copy'],normal_copy=asdict(layout),
        initializer=init,selector=selected,methods= methods,protect_entry=protect, protect_form=protection[0],post_erase_form='flag-equals-one'if guarded else'always',
        post_erase_getter=getter,post_erase_flag=flag, discarded_probe=dict(address=probe,source= probe_source,size=20,thunk=thunk), runtime_guards=dict(active_object=objglobal,expected_object=object_,
        selection_cell=cell, expected_selection=object_,base_address=state,expected_base=0,mode_address=state+4, operation_address=state+8,query_object_before_init=0),
        data_intervals= [[object_,object_+0xd0],[probe_source,probe_source+20],[source(cell,4),source(cell,4)+4],[source(objglobal,4),source(objglobal,4)+4]],
        geometry_entry=extras['geometry'][0],sector_prefix_entry=extras['prefix'][0], program_wrapper= extras['wrapper'][0],code_intervals= [list(p)for p in
        code], literal_intervals= [list(p)for p in sorted(set(pools+tables))], copy_layouts= [asdict(c)for c in context['copies']], copy_tail_call=_call(image,
        context['copy']+0x100), physical_id=None,timing='unverified',readback_policy= 'requires-native-validation')

def find_protected_nor_profile(image: bytes, ram_base: int, ram_size: int, load_address: int = 0) -> tuple[dict | None,str]:
    """Return a complete source contract. RAM guards are expectations, not writes."""
    if (not isinstance(image,(bytes,bytearray)) or any(type(x)is not int for x in(ram_base,ram_size,load_address)) or ram_base<0 or ram_size<=0 or ram_base+ram_size>0x100000000
        or load_address!=0):
        return None,'protected-nor-layout-unverified'
    try:
        context=_normal_copy(image,ram_base,ram_size)
    except _Unclosed as error:
        return None,'protected-nor-'+str(error)
    profiles= [];reasons= []
    for init in _hits(image,'init'):
        try:profiles.append(_profile_at(image,init,context,ram_base,ram_size))
        except _Unclosed as error:reasons.append(str(error))
    if len(profiles)>1:return None,'protected-nor-profiles-ambiguous'
    if profiles:return profiles[0],'accepted'
    return None,'protected-nor-'+(reasons[0]if len(reasons)==1 else'candidates-unclosed'if reasons else'not-found')

from msm5xxx_emulator.detection.contracts import (SourceContractError as _Unclosed, require_source as _need, source_word as _word, source_thumb_literal as
    _literal, source_thumb_call as _call, within_ram as _in_ram, irq_primitive_matches)
from msm5xxx_emulator.detection.startup_capture import normal_startup_copy as _normal_copy
