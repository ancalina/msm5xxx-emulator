"""Exact reset/key source classes for one released boot contact read."""
from __future__ import annotations
from msm5xxx_emulator.detection.arm import arm_b_target
from msm5xxx_emulator.detection.fact_bodies import match_thumb_shape as thumb_normalized_source_shape
from msm5xxx_emulator.detection.fact_bodies import normalized_body
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.values import CodeAddress

_LAYOUTS = ({'mask': 4, 'root_size': 244, 'root_digest': 'fb391fd9f1f5bf32c8a7883a1631b65cc730bdbed8e105ec61c3b79f4d606249', 'key_shape': (90,
    'c4e98178f387bfe73f10d649277574861c7c18a976dfda3da46a6f50e5002a7c', (36, 80), (2, 10, 42, 56, 64)), 'root_literals': ((0, 3852419072), (8, 362799104), (12,
    94363648), (24, 3852419072), (32, 362799104), (36, 94363648), (48, 3852419072), (56, 362799104), (60, 94363648), (72, 3852419072), (80, 362799104), (84,
    94363648), (108, 3852455936), (116, 3852455936), (124, 3852455936), (128, 3852419072), (136, 362799104), (140, 94363648), (152, 3852419072), (160, 362799104),
    (164, 94363648), (184, 3852419072), (192, 362799104), (196, 94363648), (216, 3852455936), (220, 3852406784), (228, 362799104), (232, 94363648)),
    'root_branches': (208,), 'groups': (0, 24, 48, 72, 128, 152, 184), 'tail': 220}, {'mask': 2, 'root_size': 272, 'root_digest':
    'e02a2c5a143dad8a212704a4b5bbce0d34875c2718e08da70aa885703bb104b7', 'key_shape': (90, 'ffd286706bc247ac3621f267d4dd30ef9fccd60a40adeffb6dbc4d04743d147e', (36,
    80), (2, 10, 42, 56, 64)), 'root_literals': ((0, 3852419072), (8, 362799104), (12, 94363648), (24, 3852419072), (32, 362799104), (36, 94363648), (48,
    3852419072), (56, 362799104), (60, 94363648), (72, 3852419072), (80, 362799104), (84, 94363648), (108, 3852455936), (116, 3852455936), (124, 3852455936), (128,
    3852419072), (136, 362799104), (140, 94363648), (152, 3852419072), (160, 362799104), (164, 94363648), (184, 3852419072), (192, 362799104), (196, 94363648),
    (208, 3852419072), (216, 362799104), (220, 94363648), (240, 3852455936), (248, 3852406784), (256, 362799104), (260, 94363648)), 'root_branches': (232, 244),
    'groups': (0, 24, 48, 72, 128, 152, 184, 208), 'tail': 248})

def _arm_shape(image, at, size, digest, literal_roles, branches):
    if at < 0 or at & 3 or at+size > len(image):
        return None
    body=normalized_body(facts_for(image),CodeAddress(at,'arm'),size,limit=len(image), arm_literals=None, arm_branches=None,call_fill=None,
        preserve_internal_branches=True)
    if body is None or body.sha256!=digest:
        return None
    actual_roles=tuple((offset,int.from_bytes(body.normalized[offset:offset+4],'little')) for offset,_,_,_ in body.literals)
    literals={offset:value for offset,_,_,value in body.literals}
    externals={}
    for offset,target in body.branches:
        if at<=target<at+size:
            continue
        word=int.from_bytes(body.normalized[offset:offset+4],'little')
        if word>>24!=0xea or target&3 or not 0<=target<=len(image)-4:
            return None
        externals[offset]=target
    if actual_roles!=literal_roles or tuple(externals)!=branches:
        return None
    pools= [(pool,pool+4) for _,_,pool,_ in body.literals]
    if any(pool&3 or not 0<=pool<=len(image)-4 for pool,_ in pools):
        return None
    return literals,pools,externals

def _callee(image, target):
    if not isinstance(target,int) or (not target&1 and target&3):return None
    at=target&~1;size=2 if target&1 else 4
    if not 0 <= at <= len(image)-size or image[at:at+size] in (bytes(size),bytes([255])*size):
        return None
    return at,at+size

def _candidate(image, display, layout):
    root=arm_b_target(image,0)
    if root is None or root < 4:return None
    found=_arm_shape(image,root,layout['root_size'],layout['root_digest'], layout['root_literals'],layout['root_branches'])
    if found is None:return None
    values,pools,branches=found;key=values[0xb8]-1
    if not values[0xb8]&1:return None
    key_shape=thumb_normalized_source_shape(image,key,layout['key_shape'])
    if key_shape is None:return None
    calls,literals,key_pools=key_shape
    if (any(literals[o] != 0x03000660 for o in (2,0x2a,0x38,0x40)) or literals[0xa] != 0x04800020 or calls[0x50] != root+layout['root_size']):
        return None
    # The common delay is a source link, independent of LCD dimensions/model.
    if calls[0x24] != facts_for(image).thumb_call_target(display['init_entry']+0x1a):return None
    code= [(0,4),(root,root+layout['root_size']),(key,key+0x5a)]
    delay_span=_callee(image,calls[0x24]|1)
    if delay_span is None:return None
    callees= [delay_span]
    for off in layout['groups']:
        target=values[off];span=_callee(image,target)
        if span is None or values[off+8]!=root+off+0x15 or values[off+12]!=root+off+0x18:
            return None
        if off != 0xb8:callees.append(span)
    if sum(values[o]==key|1 for o in layout['groups'])!=1:return None
    tail=layout['tail'];tail_span=_callee(image,values[tail])
    if (tail_span is None or values[tail+8]!=root+tail+0x15 or values[tail+12]!=root+tail+0x19):return None
    callees.append(tail_span)
    apps=set(branches.values())
    if len(apps)!=1:return None
    app=next(iter(apps))
    if app<0x10000 or _callee(image,app) is None:return None
    callees.append((app,app+4))
    download=calls[0x50]
    stub=_arm_shape(image,download,0x28, 'c1f0d1aa9b106caa522a638cbd2d29c7c72b3e39b1993194f9991c47383b06c9', ((8,0xe59fd000),(12,0xe59f4000),(20,0x159fe000),(24,0x059fe000)),())
    if stub is None:return None
    sv,stub_pools,_=stub
    span=_callee(image,sv[12])
    if (span is None or not sv[12]&1 or sv[8]!=values[0x7c] or sv[20]!=download+0x21 or sv[24]!=download+0x24):return None
    code.append((download,download+0x28));callees.append(span)
    stack_offsets= [off for off,op in layout['root_literals'] if (op>>12)&15==13]
    stacks=sorted(set(values[off] for off in stack_offsets))
    if (len(stacks)!=3 or any(b-a<64 for a,b in zip(stacks,stacks[1:])) or any(sp&3 or not 0x01000040<=sp<= 0x02000000 for sp in stacks) or values[stack_offsets[-1]]!=values[0x7c]):return None
    def overlap(a,b):return a[0]<b[1] and b[0]<a[1]
    pools=sorted(set(pools+key_pools+stub_pools))
    owned=code+callees
    if (any(overlap(a,b) for i,a in enumerate(code) for b in code[i+1:]) or any(overlap(a,b) for a in code for b in callees) or any(overlap(a,b) for a in pools
        for b in owned) or any(overlap(a,b) for i,a in enumerate(pools) for b in pools[i+1:])):
        return None
    # Shared literals/helpers may have identical ownership, never partial aliases.
    callee_set=sorted(set(callees))
    display_code= [tuple(v) for v in display['code_intervals']]
    display_pools= [tuple(v) for v in display['literal_intervals']]
    display_data= [tuple(v) for v in display['data_intervals']]
    if (any(overlap(a,b) for i,a in enumerate(callee_set) for b in callee_set[i+1:]) or any(overlap(a,b) for a in code for b in display_code+display_pools+display_data)
        or any(overlap(a,b) and a!=b for a in callee_set for b in display_code) or any(overlap(a,b) for a in callee_set for b in display_pools+ display_data) or
        any(overlap(a,b) for a in pools for b in display_code+display_data) or any(overlap(a,b) and a!=b for a in pools for b in display_pools) or any(overlap((sp-64,sp),v)
        for sp in stacks for v in display['ram_intervals'])):
        return None
    return dict(signature='arm-thumb-single-boot-contact-v1',admission='temporary-evidence-gated', address= 0x0300066c,mask=layout['mask'],released=layout['mask'],width=1,
        read_pcs= [key+0x4a],predicate_entry=key, reset_pc=root,reset_call_pc=root+0xb8, return_pc=root+0xd0,service_entry=download,application_entry=app,
        code_intervals= [list(v) for v in sorted(set([(0,4)]+code+callees))], literal_intervals= [list(v) for v in pools],ram_intervals= [[sp-64,sp] for sp in
        stacks], display_source_intervals=display['code_intervals']+ display['literal_intervals']+display['data_intervals'], display_ram_intervals=display['ram_intervals'])

def find_boot_contact_release(image):
    display,_=find_ks0741_page_profile(image)
    if display is None:return None,'boot-contact-display-source-unclosed'
    matches= [profile for layout in _LAYOUTS if (profile:=_candidate(image,display,layout)) is not None]
    if len(matches)!=1:return None,'boot-contact-reset-key-source-unclosed'
    return matches[0],'accepted-source-bound-single-boot-contact'

# Required evidence providers are bound by registry discovery.
REQUIRES = {'find_ks0741_page_profile': ('display.ks0741', 'find_ks0741_page_profile')}

def boot_family_matches(image, display_profile):
    return any(_candidate(image, display_profile, layout) is not None for layout in _LAYOUTS)
