"""Complete source-owned multiplexed monochrome page producer candidates."""
from __future__ import annotations
import hashlib
import struct
from .arm import arm_b_target, thumb_normalized_source_shape

_SHAPES = {'mux_writer': (218,
                '04b9c4417dd1b1d8a26d66798df0a05e95695e1af5384d6a05f124588681ee67',
                (134, 148, 172, 196),
                (20, 66, 68, 70, 138, 152)),
 'reset_commands': (34, 'bd0900f3a66a1383a21a8833eab86efaa26b7533907e64b2a07d7f557afaca9c', (10, 18, 26), ()),
 'page_producer': (324,
                   'c0e2cb6f140f46590f0eb41e72e9e015ff56f36b9e9914ed7555caaf1fcb3f07',
                   (66, 90, 114, 130, 152, 170, 192, 240, 258, 308),
                   (2, 14, 22)),
 'rectangle_producer': (176,
                        '34f3c87a18afd19334ad6b12b5ef5f935c42401ef0d609959b1a45ab578183fd',
                        (78, 146),
                        (46, 76, 94, 136)),
 'geometry_descriptor': (90,
                         '3f76093d901a257b7fc669320b67788d8b86e8375447da5c24d1e850001c0f74',
                         (80,),
                         (28, 60)),
 'clear_initializer': (386,
                       '60adb807a304ed9a8b0324e0b87044b7cfc53fa78f37fa0f64495ed323888f54',
                       (36, 78, 122, 162, 176, 204, 226, 240, 258, 282, 296, 310, 332, 362),
                       (4, 6, 16, 24, 30, 86, 94, 186, 322)),
 'first_init': (468,
                '6d7566c66055c578f33de93e1d0b4ad4ed040f172e2b412a0d6a7b07052f17f5',
                (148,
                 172,
                 184,
                 196,
                 208,
                 220,
                 232,
                 246,
                 260,
                 274,
                 288,
                 302,
                 316,
                 330,
                 344,
                 358,
                 372,
                 386,
                 408,
                 442,
                 456),
                (2, 4, 16, 34, 40, 132, 146, 162, 420, 434, 448)),
 'command_parameters': (322,
                        '3c5889adcc7f73755e47c8cc7050dc93af97516baeab1315e4d582002713a090',
                        (236, 246, 278, 300, 312),
                        (2,
                         8,
                         60,
                         66,
                         78,
                         84,
                         102,
                         110,
                         120,
                         142,
                         164,
                         176,
                         186,
                         202,
                         216,
                         234,
                         244,
                         256,
                         270,
                         292,
                         304)),
 'configuration_bridge': (104,
                          'cedec22ccf3e92411ef67caef10d783b86d048b009764045fcd6de5a0a55242b',
                          (46, 92),
                          (0, 6, 10, 16, 22, 28, 34, 40)),
 'main_copy': (202,
               '8950062c1c8dac210cc5f99dddce1f24dba742645cee837231e56370b8d4ef02',
               (),
               (0, 12, 14, 22, 44, 46, 70, 72, 80, 102, 104, 138, 140, 148, 168, 170, 178)),
 'gpio_configure': (112,
                    'b7611458b5df14a6c75f522ef63566c944b8702a1dafa10fea75fd5fb2af5454',
                    (78, 94),
                    (8, 20, 36, 68, 76, 82)),
 'gpio_output': (166,
                 '9b5d414fed9f76d5890e1fc2c95af78d288431f2d4b2ca6c4957fbba7058e70f',
                 (54, 142),
                 (18, 20, 52, 66, 78)),
 'gpio_selected_output': (62,
                          '0ce744998cac36d8473a01e824d00ef41ff3a2dc5201e78c54d7b193e87d4297',
                          (52,),
                          (2,)),
 'gpio_masked_slave_write': (102,
                             'ea08880cf273c208d82ad886bb0403ee68faff2891e0392a26f3992da8f2cab6',
                             (30, 40, 50, 90, 96),
                             (14, 28, 34, 36, 58)),
 'gpio_sbi_single_write': (98,
                           'bb2ef5f58ea9ae804eadf1a00958a9a7278c4b6e9c2bc14866b1527a79bd2ead',
                           (60, 72, 84),
                           (2, 10, 22, 44, 58, 64)),
 'write_delay': (2, 'c7dfbb7d02759eacb64dbc916c1bb6f21eabaff1c1032ea5c9176abf7fd28df8', (), ()),
 'board_kind_getter': (6, 'e84b4a5a908abcc0d1344fe3d3527db470a4708af852fb5b047223e26214fd69', (), (0,)),
 'clear_optional_logo_predicate': (46,
                                   'bc1dc3b1849482bcb2e69635e8faed68f3dd43d7be8dc01b63b78825f91894d6',
                                   (4,),
                                   ())}

_EXACT = {'irq_save_arm': (20, '764f0accd61c176d34e1399dc28021f4dba6f95b40ffa452b84fdfd12ec114e4'),
 'irq_restore_arm': (28, '5e4cabdd47b397e2868cbbd5a5a26d76ab431f4006ee1558f886fdcc8a82ba64'),
 'memcpy_tcm_source': (296, '35c2c2e61394e6c93dd0e2f07cd7fe47d3977030f7724f7a606303afea27726a'),
 'memset_tcm_source': (80, 'a5d4f3600fb375c74df76490f8aaebb50e77b8545a3a49cc8291b4ffd6c5ba7d'),
 'memset_arm_fill': (88, 'dd4952f77f161aa5da5c77195458577840c427dd09e23131d4716fa8af936e0b')}

def _at(image, at, role):
    return thumb_normalized_source_shape(image, at, _SHAPES[role])


def _hits(image, role, opcode, offset=0, limit=None):
    anchor = struct.pack('<H', opcode); start = 0
    end = min(len(image), limit) if limit is not None else len(image)
    while (hit := image.find(anchor, start, end)) >= 0:
        start = hit+1; at = hit-offset
        if at < 0 or at & 1:
            continue
        shape = _at(image, at, role)
        if shape is not None:
            yield at, shape


def _exact(image, at, role):
    size, digest = _EXACT[role]
    return (not at & 1 and 0 <= at <= len(image)-size
            and hashlib.sha256(image[at:at+size]).hexdigest() == digest)


def _word(image, at):
    if at & 3 or not 0 <= at <= len(image)-4:
        raise ValueError('mux-page-literal-bounds')
    return struct.unpack_from('<I', image, at)[0]


def _copies(image, main_copy):
    shape = _at(image, main_copy, 'main_copy')
    if shape is None:
        raise ValueError('mux-page-main-copy-source')
    calls, values, pools = shape
    if calls or values[0] != 0x03000700:
        raise ValueError('mux-page-main-copy-domain')
    preliminary = values[0x16]
    if (values[0xc] != preliminary+4 or values[0xe] != preliminary+8
            or values[0x2c] != preliminary+12 or values[0x2e] != preliminary+16):
        raise ValueError('mux-page-preliminary-copy-fields')
    source0, target0, size0, zero0, length0 = tuple(_word(image, preliminary+n*4) for n in range(5))
    if (size0 or not length0 or (source0|target0|zero0|length0)&3 or zero0 != target0
            or not 0x01000000 <= zero0 < zero0+length0 <= 0x02000000):
        raise ValueError('mux-page-preliminary-zero-layout')
    table = values[0x50]
    if (values[0x46] != table+4 or values[0x48] != table+8
            or values[0x66] != table+12 or values[0x68] != table+16
            or values[0xb2] != table+20 or values[0xa8] != table+24
            or values[0xaa] != table+28):
        raise ValueError('mux-page-main-copy-fields')
    source, target, size, zero, length, source2, target2, size2 = tuple(_word(image, table+n*4) for n in range(8))
    if (not size or not size2 or not length or (source|target|size|zero|length|source2|target2|size2)&3
            or source+size > len(image) or source2+size2 > len(image)
            or zero != target+size or not 0x01000000 <= target < zero < zero+length <= 0x02000000
            or not 0x01000000 <= target2 < target2+size2 <= 0x02000000
            or (target2 < zero+length and target < target2+size2)):
        raise ValueError('mux-page-main-copy-bounds')
    iram_table = values[0x94]
    if values[0x8a] != iram_table+4 or values[0x8c] != iram_table+8:
        raise ValueError('mux-page-tcm-copy-fields')
    iram_source, iram_target, iram_size = tuple(_word(image, iram_table+n*4) for n in range(3))
    if (not iram_size or (iram_source|iram_target|iram_size)&3 or iram_source+iram_size > len(image)
            or not 0x03800000 <= iram_target < iram_target+iram_size <= 0x03a00000):
        raise ValueError('mux-page-tcm-copy-bounds')
    def translate(address, width):
        if target <= address < address+width <= zero:
            return source+address-target
        if target2 <= address < address+width <= target2+size2:
            return source2+address-target2
        if iram_target <= address < address+width <= iram_target+iram_size:
            return iram_source+address-iram_target
        raise ValueError('mux-page-copy-source-unprovided')
    return dict(translate=translate, main=(source,target,size,zero,length),
        second=(source2,target2,size2), iram=(iram_source,iram_target,iram_size),
        code=[(main_copy, main_copy+_SHAPES['main_copy'][0])], pools=pools,
        data=[(preliminary,preliminary+20),(table,table+32),(iram_table,iram_table+12),
              (source,source+size),(source2,source2+size2)],
        ram=[(zero0,zero0+length0),(target,zero),(zero,zero+length),(target2,target2+size2)])



def _need(value, reason):
    if not value:
        raise ValueError('mux-page-'+reason)


def _candidate(image, page, page_shape):
    entries = {'page_producer': page}; shapes = {'page_producer': page_shape}
    def add(role, at):
        shape = _at(image, at, role)
        _need(shape is not None, role+'-source')
        entries[role] = at; shapes[role] = shape
        return shape
    def linked(role, opcode, predicate, offset=0, limit=None):
        hits = [(a,s) for a,s in _hits(image,role,opcode,offset,limit) if predicate(s)]
        _need(len(hits)==1,role+'-unique-owner')
        at, shape = hits[0]; entries[role]=at; shapes[role]=shape
        return shape
    pc, pv, _ = page_shape
    _need(len(set(pc.values()))==1 and pv[2]==pv[0xe], 'page-links')
    writer = next(iter(pc.values())); wc,wv,_ = add('mux_writer',writer)
    _need(wc[0x86]==wc[0x94] and wv[0x8a]==wv[0x98], 'mux-irq-shadow-links')
    delay = wc[0xc4]; add('write_delay',delay)
    rc,rv,_ = linked('rectangle_producer',0xb5f0,lambda s:s[0][0x92]==page)
    _need(rv[0x2e]==pv[2] and len({rv[o] for o in (0x4c,0x5e,0x88)})==1,
          'rectangle-buffer-links')
    cc,cv,_ = linked('clear_initializer',0xb5f0,
        lambda s:all(s[0][o]==page for o in (0xa2,0xe2,0x11a,0x16a))
        and s[0][0x136]==entries['rectangle_producer'])
    _need(cv[6]==pv[2] and cv[0x5e]==cv[0x142]==rv[0x4c]
          and rv[0x4c]==pv[0x16]+2, 'clear-state-buffer-links')
    linked('first_init',0xb5f0,lambda s:set(s[0].values())=={writer} and s[1][0x10]==pv[2])
    linked('command_parameters',0xb5f0,
        lambda s:set(s[0].values())=={writer} and s[1][2]==pv[2]+0x1e)
    bc,bv,_ = linked('configuration_bridge',0xb580,
        lambda s:s[0][0x5c]==entries['first_init'],offset=2)
    reset = bc[0x2e]; reset_shape = add('reset_commands',reset)
    _need(set(reset_shape[0].values())=={delay}, 'reset-delay-links')
    _need(bv[6]==cv[4], 'configuration-fields')
    # Source fields are a contiguous seven-byte configuration record.
    _need([bv[o] for o in (0xa,0x10,0x16,0x1c,0x22,0x28)]==[bv[0]-1]+list(range(bv[0]+1,bv[0]+6)),
          'configuration-record')
    fc,fv,_ = shapes['first_init']
    _need(fv[2]==cv[4] and fv[4]==pv[0x16]
          and all(fv[o]==pv[2] for o in (0x10,0x22,0x28,0x84,0xa2)), 'init-state-links')
    gc,gv,_ = linked('geometry_descriptor',0xb58e,
        lambda s:s[1][0x1c]==pv[2] and s[0][0x50]==rc[0x4e])
    table=gv[0x3c]
    _need(table&1==0 and 0<=table<=len(image)-32
          and hashlib.sha256(image[table:table+32]).hexdigest()==
          '62a0da7dfaa9521ab802af3857d3d7a70628488d36b149b37fe7d0e991491da5', 'geometry-table')
    copies = list(_hits(image,'main_copy',0xb480,offset=2,limit=0x20000))
    _need(len(copies)==1,'main-copy-unique')
    copies=_copies(image,copies[0][0]); translate=copies['translate']
    code=list(copies['code']); pools=list(copies['pools']); data=list(copies['data'])+[(table,table+32)]
    _need(len({cc[o] for o in (0xb0,0xf0,0x128)})==1,'optional-logo-predicate-links')
    predicate=add('clear_optional_logo_predicate',cc[0xb0])
    kind=add('board_kind_getter',predicate[0][4])
    _need(0x01000000<=kind[1][0]<0x02000000,'board-kind-state-bounds')
    main_source,main_target,main_size,zero,length=copies['main']
    def ram(at,size):
        return any(a<=at<at+size<=b for a,b in copies['ram'])
    state=pv[2]; bias=pv[0x16]; descriptor_cell=wv[0x42]
    descriptor=_word(image,translate(descriptor_cell,4))
    _need(_word(image,translate(descriptor,4))==0x02800000
          and wv[0x46]==descriptor_cell+4 and wv[0x14]==main_target+0xca
          and wv[0x44]==main_target+0xb4 and bv[0]==main_target+0xa7,
          'copied-mode-descriptor')
    specific_ram=[(state,state+0x3c),(bias,bias+2),(bias+2,bias+98),
        (descriptor_cell,descriptor_cell+8),(descriptor,descriptor+64),
        (wv[0x8a],wv[0x8a]+1),(cv[4],cv[4]+3),(wv[0x14],wv[0x14]+2)]
    _need(all(ram(a,b-a) for a,b in specific_ram),'device-ram-layout')
    data.extend(((translate(descriptor_cell,8),translate(descriptor_cell,8)+8),
                 (translate(descriptor,64),translate(descriptor,64)+64)))
    def veneer(at,size,digest):
        _need(not at&1 and 0<=at<=len(image)-size-4
              and hashlib.sha256(image[at:at+size]).hexdigest()==digest,'interworking-veneer')
        code.append((at,at+size));pools.append((at+size,at+size+4))
        return _word(image,at+size)
    for at,role in ((wc[0x86],'irq_save_arm'),(wc[0xac],'irq_restore_arm')):
        target=veneer(at,8,'bf1f24845bec959b53dfb798b98593982c6b13b4a32bf1334000945955fdd3d7')
        _need(not target&3 and _exact(image,target,role),'irq-arm-source')
        code.append((target,target+_EXACT[role][0]))
    _need(len({cc[o] for o in (0x7a,0xcc,0x102,0x14c)})==1,'clear-memset-links')
    helper_sources={}
    for at,role in ((rc[0x4e],'memcpy_tcm_source'),(cc[0x7a],'memset_tcm_source')):
        target=veneer(at,12,'4f9bdfba5ca50c368608697d8d40d0096073a49ddef42e2545f33dfe5aac82fc')
        _need(target&1,'tcm-thumb-entry')
        source=translate(target-1,_EXACT[role][0])
        _need(_exact(image,source,role),'tcm-library-source')
        code.append((source,source+_EXACT[role][0]));helper_sources[role]=source
    fill_veneer=arm_b_target(image,helper_sources['memset_tcm_source']+0x38)
    _need(fill_veneer is not None,'tcm-fill-branch')
    fill=veneer(fill_veneer,4,'0312bf80d0c3005ff824cbe7fd69fee6f24c7bf126b40d67c3e3a8cf6427ec71')
    _need(not fill&3 and _exact(image,fill,'memset_arm_fill'),'arm-fill-source')
    code.append((fill,fill+_EXACT['memset_arm_fill'][0]))
    # GPIO setup and its selected immutable row remain natural guest execution.
    ac,av,_=add('gpio_configure',cc[0x24]);oc,ov,_=add('gpio_output',cc[0x4e])
    _need(av[8]==av[0x52]==ov[0x12]==ov[0x14]==ov[0x42]
          and av[0x14]==av[0x24]==av[8]+0x500
          and av[0x44]==ov[0x4e] and ac[0x4e]==oc[0x36], 'gpio-table-links')
    selector=translate(cv[0x1e],1);number=image[selector];row=av[8]+number*32
    _need(number<40 and 0<=row<=len(image)-32
          and _word(image,row)==0 and image[row+0x18]==0
          and struct.unpack_from('<H',image,row+0x1a)[0]==40,'gpio-selected-row')
    selected=_word(image,row+8)
    _need(selected&1,'gpio-output-method')
    sc,sv,_=add('gpio_selected_output',selected-1)
    _need(sv[2]==av[8],'gpio-output-table')
    mc,mv,_=add('gpio_masked_slave_write',sc[0x34])
    tc,tv,_=add('gpio_sbi_single_write',mc[0x5a])
    _need(mc[0x32]==wc[0x86] and mc[0x60]==wc[0xac]
          and tc[0x3c]==mc[0x1e] and tc[0x48]==mc[0x28]
          and tv[2]==0x8840 and tv[0xa]==0x03000dc0 and tv[0x16]==0x03000c80,
          'gpio-sbi-source-links')
    poll_delay = tc[0x54]
    _need(_at(image,poll_delay,'write_delay') is not None,'gpio-poll-delay')
    code.append((poll_delay,poll_delay+2))
    data.extend(((selector,selector+1),(row,row+32)))
    # Inactive error arms are not replaced. Their bounded entry ownership is
    # explicit; no formatting, GPIO or serial call is executed by the decoder.
    error_entries=set((ac[0x4e],mc[0x1e],mc[0x28]))
    for at in error_entries:
        _need(not at&1 and 0<=at<=len(image)-2 and image[at:at+2] not in (bytes(2),b'\xff\xff'),
              'error-entry-bounds')
        code.append((at,at+2))
    for at,word in ((ac[0x5e],0x4708),(oc[0x8e],0x4710)):
        _need(0<=at<=len(image)-2 and struct.unpack_from('<H',image,at)[0]==word,'gpio-call-thunk')
        code.append((at,at+2))
    # Literal values used as source assets must remain supplied immutable data.
    assets=[]
    for role, offsets in (('clear_initializer',(0x10,0x18)),('first_init',(0x92,)),
                          ('command_parameters',(0xea,)),('gpio_masked_slave_write',(0x1c,)),
                          ('gpio_sbi_single_write',(0x3a,))):
        for offset in offsets:
            at=shapes[role][1][offset]
            _need(0<=at<=len(image)-8,'asset-header-bounds')
            assets.append((at,at+8))
    data.extend(assets)
    for role,at in entries.items():
        code.append((at,at+_SHAPES[role][0]));pools.extend(shapes[role][2])
    code=sorted(set(code));pools=sorted(set(pools));data=sorted(set(data))
    def overlap(a,b):return a[0]<b[1] and b[0]<a[1]
    _need(not any(overlap(a,b)for i,a in enumerate(code)for b in code[i+1:]),'code-alias')
    _need(not any(overlap(a,b)for a in code for b in pools),'code-literal-alias')
    _need(not any(overlap(a,b)for a in assets for b in code+pools),'asset-header-alias')
    _need(all(0<=a<b<=len(image) for a,b in code+pools+data),'source-bounds')
    return dict(signature='source-external-bit4-mono96-page-v1',admission='temporary-evidence-gated',
        width=96,height=64,clear_pages=10,clear_row_bytes=96,command_port=0x02000000,
        data_port=0x02000000,mode_port=0x02800000,mode_mask=0x10,access_width=1,
        runtime_qualification='reset-and-ten-ordered-zero-rows-with-consistent-wire-origin',
        optical_properties=None,pixel_order='provisional-vertical-lsb-first',
        mutable_configuration='unclaimed-observed-full-mono-clear-required',
        natural_error_entries=sorted(error_entries),source_pcs=entries,
        code_intervals=[list(v)for v in code],literal_intervals=[list(v)for v in pools],
        data_intervals=[list(v)for v in data],ram_intervals=[list(v)for v in copies['ram']+specific_ram]+
            [[kind[1][0],kind[1][0]+1]],
        iram_intervals=[[copies['iram'][1],copies['iram'][1]+copies['iram'][2]]])


def find_mux_page_profile(image):
    candidates=[];failures=[]
    for page,shape in _hits(image,'page_producer',0x2460,offset=0xa):
        try:candidates.append(_candidate(image,page,shape))
        except (ValueError,KeyError,struct.error)as error:failures.append(str(error))
    if len(candidates)==1:return candidates[0],'accepted-source-mux-awaiting-complete-clear'
    return None,'mux-page-ambiguous' if candidates else failures[0] if failures else 'mux-page-source-unclosed'
