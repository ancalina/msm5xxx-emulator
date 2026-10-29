"""Temporary source-owned AMD x16 logical bank; not a physical part identity."""
from __future__ import annotations

import struct
from .arm import arm_b_target, arm_b_word_target
from .mono_page import _shape

_SPEC = {
    'copy': (bytes.fromhex('0120474908700020087046480068464909684018061c45480068051c41480068041cb44208d204e0281d051c201d041cf7e728682060f7e7012039490870002008703b4800683b4909684018061c38480068041cb44206d202e0201d041cf9e700202060f9e701202d4908700020087031480068314909684018061c30480068051c2d480068041cb44208d204e0281d051c201d041cf7e728682060f7e701201f4908700020087026480068264909684018061c23480068041cb4420dd202e0201d041cf9e700202060a003f8d101201349087000200870f2e70120104908700020087019480068194909684018061c18480068051c15480068041cb44208d204e0281d051c201d041cf7e728682060f7e7012002490870002008707047'), (), ((2, 1), (10, 0), (14, 1), (22, 0), (28, 0), (58, 1), (66, 0), (70, 1), (78, 0), (104, 1), (112, 0), (116, 1), (124, 0), (130, 0), (160, 1), (168, 0), (172, 1), (180, 0), (208, 1), (220, 1), (228, 0), (232, 1), (240, 0), (246, 0), (276, 1))),
    'init': (bytes.fromhex('f0b5154d0024154f2c600020386000f051f9002802d100f06ff938603868104e002806d152f12cfe311cff20a930fcf77ff838688030806953f106f9002806d052f11efe311cff20af30fcf771f82c71f0bc08bc1847'), (14, 22, 36, 46, 56, 64, 74), ((2, 5), (6, 7), (30, 6))),
    'ramtest': (bytes.fromhex('0e48002800da01300d4940100968400040180188aa22028002881206120eaa2a06d15522028002881206120e552a01d000207047018001207047'), (), ((0, 0), (8, 1))),
    'lookup': (bytes.fromhex('90b5074c0027b800205852f1a1ff002802d10137012ff6d390bc08bc1847'), (10,), ((2, 4),)),
    'probe': (bytes.fromhex('164888b416490069096840004018f0210180aa231a018218538155231527bf01c719bb8290235381028800ab1a8042885a8001800b480be000ab1a8880318b889a4204d100ab5a88c9888a4203d0043001680029f0d1006888bc7047'), (), ((0, 0), (4, 1), (52, 0))),
    'reset': (bytes.fromhex('00207047'), (), ()),
    'read': (bytes.fromhex('0d4b90b51b688f1880335c696400a74200d903e0094f3c79012c03d1012090bc08bc18471b693f685b00db19591853f13ffa0020f3e7'), (46,), ((0, 3), (20, 7))),
    'program': (bytes.fromhex('fcb50f1c8918141c5b4a051c1068803043695b00994200d968e058490978002902d0022900d061e0554b0069196840004018c61970084000019049f1fdfd4e4aaa2112684e4b803212691b685200d2180b01d2185181484a55211268484b803212691b685200d21815239b01d2189182414a20211268424b803212691b685200d21855235b01d2185181002801d149f1dffdea07d20fa0210120002a00d061e07a0800d35ee0620800d35be025e02f8849f1c2fda02131803780002801d149f1c7fd304901200870802139403088802202408a420ed08009f8d3308880231840884207d090203080f02030800120fcbc08bc184702350236023c012cd7d833e077087f0028783988720802d2ff22120201e00002ff2210430140009149f18cfda021398000993980002801d149f190fd1449012008700099802319403888802202408a420bd08009f8d3388880231840884204d090203880f0203880c6e701350136013c002ccbd80199902008800199f02008800020bae7'), (58, 142, 176, 190, 284, 300), ((8, 2), (26, 1), (40, 3), (62, 2), (68, 3), (86, 2), (92, 3), (112, 2), (118, 3), (194, 1), (304, 1))),
    'erase': (bytes.fromhex('90b5194c071c207800280dd0012805d0022809d1012090bc08bc184749f1e0fe1249ea20f3f734f91148006880300069790840180f4908600f49400009684118aa2318010818438155221527bf01c9198a828027478143818a8230214181012020700020d7e7'), (28, 36), ((2, 4), (32, 1), (40, 0), (52, 1), (56, 1))),
    'poll': (bytes.fromhex('144880b514490068096840004018028801884a40402313400022002b0f4f15d0890911d3018800884840c0090ed30c480088042804dc131c00210a4849f1c4fe012080bc08bc18471520fae73a700020f7e7'), (60,), ((0, 0), (4, 1), (28, 7), (46, 0), (58, 0))),
    'suspend': (bytes.fromhex('f0b41949194a0024002009680027126849008a18b0211180154b01211970002511881ee00b1c11880e1c5e404423334007d0042b15d115200e4a02211170f0bc70470d4b994206d00137052fe8db094a01201570f3e7f0201080064a00201570ede7002cded0eae7'), (), ((2, 1), (4, 2), (24, 3), (56, 2), (66, 3), (78, 2), (90, 2))),
    'resume': (bytes.fromhex('0648074900680968400041183020088004490120087000207047'), (), ((0, 0), (2, 1), (16, 1))),
    'irq_save': (bytes.fromhex('7847000000000fe1c01080e301f021e1c00000e21eff2fe1'), (), ()),
    'irq_restore': (bytes.fromhex('7847000000000fe1c010c0e301f021e1c00000e21eff2fe1'), (), ()),
}
_STATE_REFS = {'read': {0: 'object', 20: 'base'}, 'program': {8: 'object', 26: 'mode', 40: 'base', 62: 'object', 68: 'base', 86: 'object', 92: 'base', 112: 'object', 118: 'base'}, 'erase': {2: 'mode', 40: 'object', 52: 'operation', 56: 'base'}, 'poll': {0: 'operation', 4: 'base', 28: 'mode'}, 'suspend': {2: 'operation', 4: 'base', 56: 'mode', 78: 'mode', 90: 'mode'}, 'resume': {0: 'operation', 2: 'base', 16: 'mode'}}
_ROOT = bytes.fromhex('04429fe5010014e300e29f1500e29f0514ff2fe178470000f8419fe5010014e3f4e19f15f4e19f0514ff2fe178470000ec419fe5010014e3e8e19f15e8e19f0514ff2fe178470000e0419fe5010014e3dce19f15dce19f0514ff2fe178470000000050e31a00001ad7f021e378d19fe5dbf021e3c0d19fe5d3f021e3bcd19fe5bc419fe5010014e3b8e19f15b8e19f0514ff2fe178470000b0419fe5010014e3ace19f15ace19f0514ff2fe178470000')
_MOVE = bytes.fromhex('78470000013040e0020053e1bafeff2a030010e3030011030d00000a020080e0021081e0012052e20130712501c071850130602501c06085022052e2f9ffff2a1eff2fe1')
_FORWARD = bytes.fromhex('04f01fe590c1800304f01fe548c2800300c09fe51cff2fe1ed711e0000c09fe5')
_ALIGNED = bytes.fromhex('10402de9021081e0020080e0030010e3013071150120421201306015faffff1a')


class _Unclosed(ValueError):
    pass


def _need(value, reason):
    if not value:
        raise _Unclosed(reason)


def _word(image, at):
    _need(type(at) is int and 0 <= at <= len(image) - 4, 'source-bounds')
    return struct.unpack_from('<I', image, at)[0]


def _at(image, at, role):
    result = _shape(image, at, *_SPEC[role])
    _need(result is not None, role + '-body')
    return result


def _hits(image, role):
    pattern, calls, literals = _SPEC[role]
    holes = {offset + n for offset in calls for n in range(4)}
    holes.update(offset + n for offset, _ in literals for n in (0, 1))
    runs = []
    i = 0
    while i < len(pattern):
        if i in holes:
            i += 1
            continue
        end = i + 1
        while end < len(pattern) and end not in holes:
            end += 1
        runs.append((i, pattern[i:end]));i = end
    offset, anchor = max(runs, key=lambda value: len(value[1]))
    start = 0
    while True:
        hit = image.find(anchor, start)
        if hit < 0:
            return
        start = hit + 1
        result = _shape(image, hit - offset, pattern, calls, literals)
        if result is not None:
            yield hit - offset, result


def _arm_literal(image, pc):
    instruction = _word(image, pc)
    _need(instruction & 0x0f7f0000 == 0x051f0000, 'arm-literal')
    return _word(image, pc + 8 + (instruction & 0xfff))


def _overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def _ram(address, size, base, extent):
    return base <= address and size > 0 and address + size <= base + extent


def _copy_context(image, ram_base, ram_size):
    root = arm_b_target(image, 0)
    _need(root is not None and root >= 4 and not root & 3 and root + len(_ROOT) <= len(image), 'reset-owner')
    pools = []
    for off in range(0, len(_ROOT), 4):
        want = struct.unpack_from('<I', _ROOT, off)[0]
        actual = _word(image, root + off)
        mask = 0xfffff000 if want & 0x0f7f0000 == 0x051f0000 else 0xffffffff
        _need(actual & mask == want & mask, 'reset-body')
        if mask != 0xffffffff:
            pool = root + off + 8 + (actual & 0xfff)
            _word(image, pool);pools.append((pool, pool + 4))
    for offset in (0, 0x18, 0x30, 0x48, 0x80, 0x98):
        pc = root + offset
        target = _arm_literal(image, pc)
        _need((target & 1 or not target & 3) and target < len(image) and
              _arm_literal(image, pc + 8) == pc + 21 and
              _arm_literal(image, pc + 12) == pc + 24, 'reset-call-return')
    for offset in (0x6c, 0x74, 0x7c):
        sp = _arm_literal(image, root + offset)
        _need(not sp & 3 and _ram(sp - 4, 4, ram_base, ram_size), 'reset-stack')
    _need(_arm_literal(image, root + 0x80) & 1, 'copy-isa')
    copy = _arm_literal(image, root + 0x80) - 1
    _, values = _at(image, copy, 'copy')
    _need(all(values[offset] == 0x03000700 for offset in (2,0x3a,0x68,0xa0,0xd0,0xdc,0x114)), 'copy-pulse')
    tables = []
    copies = []
    zeros = []
    for source_off, target_off, size_off, reload_off, zero_offsets in (
            (0x16,0xa,0xe,0x1c,(0x42,0x46,0x4e)),
            (0x7c,0x70,0x74,0x82,(0xa8,0xac,0xb4)),
            (0xf0,0xe4,0xe8,0xf6,None)):
        table = values[source_off]
        _need(not table & 3 and values[target_off] == table + 4 and
              values[size_off] == table + 8 and values[reload_off] == table + 4, 'copy-tuple')
        source, target, size = (_word(image, table + n) for n in (0,4,8))
        _need(size > 0 and not (source | target | size) & 3 and source + size <= len(image), 'copy-span')
        _need(_ram(target, size, ram_base, ram_size) or
              0x03800000 <= target < target + size <= 0x03a00000, 'copy-destination')
        copies.append({'table_offset':table,'source':source,'target':target,'size':size})
        if zero_offsets is not None:
            a,b,c = zero_offsets
            _need(values[a] == table + 12 and values[b] == table + 16 and values[c] == table + 12, 'zero-tuple')
            begin, length = _word(image, table + 12), _word(image, table + 16)
            _need(length > 0 and not (begin | length) & 3 and target + size == begin and
                  _ram(begin, length, ram_base, ram_size), 'zero-span')
            zeros.append((begin, begin + length));tables.append((table, table + 20))
        else:
            tables.append((table, table + 12))
    destinations = [(item['target'], item['target'] + item['size']) for item in copies] + zeros
    _need(not any(_overlap(a,b) for i,a in enumerate(destinations) for b in destinations[i+1:]), 'copy-zero-overlap')
    return root, copy, copies, zeros, pools, tables


def _profile(image, init, initial, context, ram_base, ram_size):
    root, copy, copies, zeros, root_pools, tables = context
    main = copies[1]
    def source(address, size):
        _need(_ram(address,size,ram_base,ram_size) and main['target'] <= address and
              address + size <= main['target'] + main['size'], 'copied-table-provenance')
        return main['source'] + address - main['target']
    calls, values = initial
    base_global, object_global = values[2], values[6]
    _need(not (base_global | object_global) & 3 and
          _ram(base_global,12,ram_base,ram_size) and _ram(object_global,4,ram_base,ram_size), 'globals')
    ramtest, lookup = calls[14], calls[22]
    ramtest_shape = _at(image, ramtest, 'ramtest')
    lookup_shape = _at(image, lookup, 'lookup')
    _need(ramtest_shape[1][0] == 0x2e and ramtest_shape[1][8] == base_global, 'ramtest-owner')
    probe_table = lookup_shape[1][2]
    probe_pointer = _word(image, source(probe_table,4))
    _need(probe_pointer & 1, 'probe-pointer');probe = probe_pointer - 1
    probe_shape = _at(image, probe, 'probe')
    active_table = probe_shape[1][0x34]
    active_source = source(active_table,8)
    object_, terminator = _word(image,active_source),_word(image,active_source+4)
    _need(not terminator and object_ and not object_ & 3 and object_ + 0xc0 <= len(image), 'active-singleton')
    _need(probe_shape[1][0] == object_ + 0x80 and probe_shape[1][4] == base_global, 'probe-object-base')
    ram_owners = [(base_global,base_global+12),(object_global,object_global+4),
                  (probe_table,probe_table+4),(active_table,active_table+8)]
    _need(not any(_overlap(a,b) for i,a in enumerate(ram_owners) for b in ram_owners[i+1:]),
          'initializer-metadata-alias')
    _need(all(not _overlap((address,address+size),span) for address,size in
              ((probe_table,4),(active_table,8),(object_global,4))
              for span in zeros + [(c['target'],c['target']+c['size']) for c in (copies[0],copies[2])]), 'metadata-write-conflict')
    count = _word(image,object_+4)
    _need(0 < count <= (0x84-8)//4, 'sector-count')
    sizes = [_word(image,object_+8+4*i) for i in range(count)]
    sector = sizes[0]
    base, size = _word(image,object_+0x90)*2,_word(image,object_+0x94)*2
    _need(sector > 0 and not sector & (sector-1) and all(n == sector for n in sizes) and
          sum(sizes) == size and not base % sector and 0 < base < base+size <= min(len(image),ram_base), 'geometry')
    _need(_word(image,object_+0x88) == 0 and _word(image,object_+0x8c) == 1, 'descriptor-flags')
    id0,id1 = struct.unpack_from('<HH',image,object_+0x84)
    methods = {'probe':probe}
    shapes = {'init':initial,'ramtest':ramtest_shape,'lookup':lookup_shape,'probe':probe_shape}
    entries = {'init':init,'ramtest':ramtest,'lookup':lookup,'probe':probe,'copy':copy}
    shapes['copy'] = _at(image,copy,'copy')
    for role, offset in (('reset',0x98),('read',0x9c),('program',0xa0),('erase',0xa4),
                         ('poll',0xa8),('suspend',0xac),('resume',0xb0)):
        pointer = _word(image,object_+offset)
        _need(pointer & 1,'callback-isa');at = pointer - 1
        shapes[role] = _at(image,at,role);entries[role]=at
        methods['init' if role=='reset' else role]=at
    _need(calls[56] == lookup_shape[0][10] and image[calls[56]:calls[56]+2] == b'\x00\x47', 'callback-thunk')
    for role, refs in _STATE_REFS.items():
        addresses = {'base':base_global,'mode':base_global+4,
                     'operation':base_global+8,'object':object_global}
        _need(all(shapes[role][1].get(off)==addresses[kind] for off,kind in refs.items()),role+'-globals')
    # Progress counters/diagnostic literals are not controller state or ID inputs.
    for role in ('program','erase','poll','suspend','resume'):
        for offset, value in shapes[role][1].items():
            if offset in _STATE_REFS[role]:
                continue
            _need(value < len(image) or _ram(value,2,ram_base,ram_size),role+'-foreign-literal')
    save = shapes['program'][0][0x3a]
    restore = shapes['program'][0][0x8e]
    _at(image,save,'irq_save');_at(image,restore,'irq_restore')
    _need(all(target == (save if offset in (0x3a,0xb0,0x11c) else restore)
              for offset,target in shapes['program'][0].items()), 'program-irq-links')
    memmove = shapes['read'][0][0x2e]
    _need(not memmove & 3 and memmove + len(_MOVE) <= len(image), 'array-copy-entry')
    _need(image[memmove:memmove+12] == _MOVE[:12] and image[memmove+16:memmove+24] == _MOVE[16:24] and
          image[memmove+28:memmove+len(_MOVE)] == _MOVE[28:], 'array-copy-body')
    lib=[]
    for offset,condition,pattern in ((12,0x2a,_FORWARD),(24,0x0a,_ALIGNED)):
        op=_word(image,memmove+offset)
        _need(op>>24==condition,'array-copy-branch')
        target=arm_b_word_target((op&0xffffff)|0xea000000,memmove+offset)
        _need(target is not None and 0 <= target <= len(image)-len(pattern) and image[target:target+len(pattern)]==pattern,'array-copy-target')
        lib.append((target,target+len(pattern)))
    code=[(root,root+len(_ROOT)),(save,save+len(_SPEC['irq_save'][0])),
          (restore,restore+len(_SPEC['irq_restore'][0])),(calls[56],calls[56]+2),
          (memmove,memmove+len(_MOVE))]+lib
    code += [(at,at+len(_SPEC[role][0])) for role,at in entries.items()]
    _need(not any(_overlap(a,b) for i,a in enumerate(code) for b in code[i+1:]), 'code-owner-overlap')
    pools=list(root_pools)
    for role,at in entries.items():
        for off,_ in _SPEC[role][2]:
            instruction=struct.unpack_from('<H',image,at+off)[0]
            pool=((at+off+4)&~3)+(instruction&255)*4;pools.append((pool,pool+4))
    data=tables+[(object_,object_+0xc0),(active_source,active_source+8),(source(probe_table,4),source(probe_table,4)+4)]
    data += [(item['source'],item['source']+item['size']) for item in copies]
    _need(all(0<=a<b<=len(image) and not any(_overlap((a,b),span)for span in code) for a,b in pools+tables+[(object_,object_+0xc0)]),'data-owner-overlap')
    guards=sorted(set(code+pools+data))
    _need(all(not _overlap(span,(base,base+size)) for span in guards),'mutable-source-overlap')
    backing=1<<(size-1).bit_length()
    unsupported=[_word(image,object_+off) for off in (0xb4,0xb8,0xbc)]
    _need(all(value&1 and value<len(image) for value in unsupported),'reserved-helper-bounds')
    return {'signature':'thumb-copy-selected-amd-x16-bank-v1','admission':'temporary-evidence-gated',
            'base':base,'size':size,'sector_size':sector,'backing_size':backing,'id0':id0,'id1':id1,
            'code_intervals':[list(p)for p in sorted(set(code))],
            'literal_intervals':[list(p)for p in sorted(set(pools+data))],
            'guard_intervals':[list(p)for p in guards], 'object':object_,'object_global':object_global,
            'base_global':base_global,'mode_address':base_global+4,'operation_address':base_global+8,
            'probe_table':probe_table,'active_table':active_table,'methods':methods,'copy_layouts':copies,
            'zero_ranges':[list(p)for p in zeros],'copy_entry':copy,'reset_entry':root,'initializer':init,
            'reserved_range':[base+size,base+backing],'unsupported_callbacks':unsupported,
            'physical_part':None,'library_policy':'guest-executed array copy; bounded entry shapes only, no HLE'}


def find_amd_bank_profile(image:bytes, load_address:int, flash_size:int,
                          ram_base:int, ram_size:int)->tuple[dict|None,str]:
    if (not isinstance(image,(bytes,bytearray)) or any(type(value)is not int for value in
            (load_address,flash_size,ram_base,ram_size)) or load_address!=0 or
            not 0<flash_size<=len(image) or ram_size<=0 or ram_base<flash_size or ram_base+ram_size>0x100000000):
        return None,'amd-bank-layout-unverified'
    image=image[:flash_size]
    try:context=_copy_context(image,ram_base,ram_size)
    except _Unclosed as error:return None,'amd-bank-'+str(error)
    profiles=[];reasons=[]
    for init,shape in _hits(image,'init'):
        try:profiles.append(_profile(image,init,shape,context,ram_base,ram_size))
        except _Unclosed as error:reasons.append(str(error))
    if len(profiles)>1:return None,'amd-bank-profile-ambiguous'
    if profiles:return profiles[0],'accepted-source-bound-amd-bank-candidate'
    return None,'amd-bank-'+(reasons[0]if len(reasons)==1 else'candidates-unclosed'if reasons else'not-found')
