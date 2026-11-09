"""Legacy halfword-FF console family pending generic facts replacement."""
from __future__ import annotations

import hashlib
import re
import struct

from ...arm import arm_b_target, thumb_bl_target, thumb_literal_value
from ...contracts import BodySpec
from ...facts import facts_for
from .legacy_dd import _find_prior_uart_console_profile
from .legacy_simple import _byte_writes, _word

_FF_SPECS = {
    'tag': ('????0088????0988884201d100207047????fce7', (), ((0, 0), (4, 1), (16, 0))),
    'console': ('00b50020????0880????????????????????????????????????????????????08bc1847', (8, 12, 16, 20, 24, 28), ((4, 1),)),
    'primary': ('????0068002809d1????0079000905d20120????087000200870f5e77047', (), ((0, 0), (8, 0), (18, 1))),
    'init': ('00b50020????087100210920????????????????c020????10390871b22008727d2008731c20????08700020????2039087088811e2008810020????403988813420????30390870ff200871302008731020087308732020087308730120087304200873????0068002800d00ee0????30380079400800d208e0????3038027a0120????087000200870f0e708bc1847', (12, 16), ((4, 1), (22, 1), (38, 1), (44, 1), (58, 1), (66, 1), (100, 0), (110, 0), (122, 0), (130, 1))),
    'rx': ('80b4031c002b16d0????002a10dd02e0501e021cf9e7????0179480802d3081c80bc70470120????387000203870efe70120c043f4e7????0179480801d3081ceee70120????387000203870f3e7', (), ((8, 2), (22, 0), (38, 7), (54, 0), (68, 7))),
    'wrapper': ('90b5????0078002804d00120????????071c03e00020????????071cbb1c07d1????0078002803d0981e90bc08bc1847f80904d3????047a0020c043f5e7b80904d3????047a0020c043eee7????007a041c0020????0870201ce6e7', (12, 22), ((2, 0), (32, 0), (52, 0), (66, 0), (76, 0), (84, 1))),
    'tx': ('????0978490805d20121????117000211170f5e7????103908727047', (), ((0, 1), (10, 2), (20, 1))),
    'byteflag': ('????002008280ada02e0421c101cf9e70a5cff2af9d00022????1a7070470122????1a70fae7', (), ((0, 1), (24, 3), (32, 3))),
    'dispatch': ('90b5????0068002841d1????0068????4718381c????????041c38780f282ed201a31b5c5b009f442a072a2a0c1116192a2a1c1f242a2700211c381c????????20e0211c381c????????1be0211c381c????????16e0????????13e0????????10e0????????0de0211c381c????????08e0????????05e0????????02e00620????????????0068????4718c1e790bc08bc1847', (20, 60, 70, 80, 86, 92, 98, 108, 114, 120, 128), ((2, 0), (10, 0), (14, 1), (132, 0), (136, 1))),
    'parser': ('f1b5002600250024032c00d15ae00120????087000200870????????071c7b1c01d10024f0e7bb1c01d1????????002c04d0012c06d0022c42d108e07e2fe3d10124e1e77e2fdfd00025????02247e2f10d1032d04da0420????????0024d3e7????9e4204d00120????????0024cbe70324c9e77d2f09d1????????071c7b1c01d10024c0e720207840071c01235b039d4204db0520????????0024b4e7681c0004000c291c051c0098475430127e40311c0906c90d????515a4840061ca3e70024a1e7281cf8bc08bc1847', (24, 42, 88, 104, 120, 150), ((16, 1), (74, 6), (96, 3), (182, 2))),
    'ack1': ('90b5041ce71c7e20????????3878????????3878791c0f1c7e28f7d190bc08bc1847', (8, 14), ()),
    'ack2': ('90b5041ca000????0f587e20????????3878????????3878791c0f1c7e28f7d190bc08bc1847', (12, 18), ((6, 1),)),
    'wordflag': ('01200021096a????994200d00020????48607047', (), ((6, 3), (14, 1))),
    'aux': ('90b5????0068002811d1????????0420????888200200881081c007bc707ff0f05d10220????08828880????????90bc08bc1847', (10, 42), ((2, 0), (16, 1), (36, 1))),
    'delay': ('????6021017004210170ff2101700020????0860????09680a2905da????09680131????1160f5e77047', (), ((0, 0), (16, 1), (20, 1), (28, 1), (34, 2))),
    'hardware': ('0320????88800420????403908820020????20398881????0880????888000208882????088100200883????df308883????08827047', (), ((2, 1), (8, 1), (16, 1), (22, 0), (26, 0), (34, 0), (42, 0), (48, 0))),
    'prelude': ('0921c905087b0022002804d1082008720120087301e00a700a730a71????????0880????88807047', (), ((28, 0), (30, 1), (34, 0))),
    'config': ('fcb5041c0d1c????????300c4718072c13d0092c20d1????????798a????1940c0222a4011437982798ab180002801d1????????fcbc08bc1847????????798a????bd331940aa07920f11437982798ab1800028ecd0ede7????00270088032805dc3b1c0022211c????????????????????f83a019200223b1c0091211c08a0????????d6e7', (22, 48, 58, 106, 128), ((6, 6), (8, 1), (28, 3), (64, 3), (88, 0), (104, 0), (110, 2), (112, 1))),
    'copy': ('0120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb44206d202e0201d041cf9e700202060f9e70120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb4420dd202e0201d041cf9e700202060a003f8d10120????087000200870f2e70120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????0870002008707047', (), ((2, 1), (10, 0), (14, 1), (22, 0), (28, 0), (58, 1), (66, 0), (70, 1), (78, 0), (104, 1), (112, 0), (116, 1), (124, 0), (130, 0), (160, 1), (168, 0), (172, 1), (180, 0), (208, 1), (220, 1), (228, 0), (232, 1), (240, 0), (246, 0), (276, 1))),
}
_FF_RESET = bytes.fromhex('38429fe5010014e334e29f1534e29f0514ff2fe1784700002c429fe5010014e328e29f1528e29f0514ff2fe17847000020429fe5010014e31ce29f151ce29f0514ff2fe17847000014429fe5010014e310e29f1510e29f0514ff2fe178470000000050e32000001ad7f021e3a8d19fe5dbf021e3f4d19fe5d3f021e3f0d19fe5f0419fe5010014e3ece19f15ece19f0514ff2fe178470000e4419fe5010014e3e0e19f15e0e19f0514ff2fe178470000000050e30c00001ad0419fe5010014e3cce19f15cce19f0514ff2fe178470000c4419fe5010014e3c0e19f15c0e19f0514ff2fe17847000077d60aead3f021e37cd19fe534119fe5010011e3a4e19f15a4e19f0511ff2fe17847000078470000d3f021e358d19fe590419fe5010014e38ce19f158ce19f0514ff2fe1784700001eff2fe178470000d3f021e378419fe514ff2fe1')
_FF_THUNK = bytes.fromhex('7847c04600c09fe51cff2fe1')
_FF_IRQ_SAVE = bytes.fromhex('7847000000000fe1c01080e301f021e1c00000e21eff2fe1')
_FF_IRQ_RESTORE = bytes.fromhex('7847000000000fe1c010c0e301f021e1c00000e21eff2fe1')

from .legacy_constants import HIGH_RAM_TEST_SHA256


def _source_thumb_shape(image, at, pattern, calls=(), literals=()):
    result = BodySpec.thumb_body(pattern, calls, literals).match(facts_for(image), at)
    return (result.targets, result.values) if result is not None else None


class _HalfFFUnclosed(ValueError):
    pass


def _ff_need(condition, reason):
    if not condition:
        raise _HalfFFUnclosed('console-half-ff-' + reason)


def _ff_u32(image, at):
    _ff_need(type(at) is int and 0 <= at <= len(image)-4, 'source-bounds')
    return struct.unpack_from('<I', image, at)[0]


def _ff_shape(image, at, role):
    mask,calls,literals = _FF_SPECS[role]
    result = _source_thumb_shape(image,at,bytes.fromhex(mask.replace('??','00')),calls,literals)
    _ff_need(result is not None,role+'-body')
    return result


def _ff_hits(image, role):
    mask,_,_ = _FF_SPECS[role]
    runs=[(match.start()//2,bytes.fromhex(match.group()))
          for match in re.finditer(r'(?:[0-9a-f]{2})+',mask)]
    offset,anchor=max(runs,key=lambda pair:len(pair[1]));start=0
    while (hit:=image.find(anchor,start))>=0:
        start=hit+1;at=hit-offset
        try:result=_ff_shape(image,at,role)
        except _HalfFFUnclosed:continue
        yield at,result


def _ff_overlap(a,b):
    return a[0]<b[1] and b[0]<a[1]


def _ff_ram(address,size):
    return 0x01000000<=address and size>0 and address+size<=0x01800000


def _ff_thunk(image,at):
    _ff_need(type(at)is int and not at&3 and 0<=at<=len(image)-16 and
             image[at:at+12]==_FF_THUNK,'interwork-thunk')
    target=_ff_u32(image,at+12)
    _ff_need(target&1,'interwork-target-isa')
    return target-1


def _ff_reset_copy(image):
    reset=arm_b_target(image,0)
    _ff_need(reset is not None and reset>=4 and not reset&3 and reset+len(_FF_RESET)<=len(image),'reset-owner')
    pools=[]
    for off in range(0,len(_FF_RESET),4):
        want=struct.unpack_from('<I',_FF_RESET,off)[0];actual=_ff_u32(image,reset+off)
        mask=0xfffff000 if want&0x0f7f0000==0x051f0000 else 0xffffffff
        if off==0xe8:mask=0xff000000
        _ff_need(actual&mask==want&mask,'reset-body')
        if mask==0xfffff000:
            pool=reset+off+8+(actual&4095);_ff_u32(image,pool);pools.append((pool,pool+4))
    def literal(pc):
        op=_ff_u32(image,pc)
        return _ff_u32(image,pc+8+(op&4095))
    for off in (0,0x18,0x30,0x48,0x80,0x98,0xb8,0xd0,0xf4,0x118):
        pc=reset+off;target=literal(pc)
        _ff_need(target<len(image) and (target&1 or not target&3) and
                 literal(pc+8)==pc+21 and literal(pc+12)==pc+(25 if off==0xf4 else 24),'reset-return')
    stacks=[literal(reset+off) for off in (0x6c,0x74,0x7c,0xf0,0x114)]
    _ff_need(all(not sp&3 and _ff_ram(sp-56,56) for sp in stacks),'stack-range')
    test=literal(reset+0x48);test_table=test-28
    _ff_need(not test&3 and test_table>=0 and test+0x150<=len(image) and
             hashlib.sha256(image[test:test+0x150]).hexdigest()==HIGH_RAM_TEST_SHA256,'ram-test-body')
    fields=struct.unpack_from('<7I',image,test_table)
    base,extent,stride,word,half,byte,watchdog=fields
    _ff_need(not base&3 and extent>=15 and extent&15==15 and
             _ff_ram(base,extent+1) and (stride,word,half,byte,watchdog)==
             (16,0x55aa0f,0xaa0f,0x55,0x03000700),'ram-test-span')
    test_pools=[]
    for off,field in ((0,0),(0x10,8),(0x40,24),(0x6c,4),(0x80,4),
                      (0xf4,12),(0x108,16),(0x11c,20)):
        op=_ff_u32(image,test+off);pool=test+off+8+(op&4095)
        _ff_need(_ff_u32(image,pool)==test_table+field,'ram-test-field')
        test_pools.append((pool,pool+4))
    failure_pool=test+0x148+8+(_ff_u32(image,test+0x148)&4095)
    _ff_need(_ff_u32(image,failure_pool)!=0,'ram-test-failure-return')
    test_pools.append((failure_pool,failure_pool+4))
    tag=literal(reset+0x98)-1;_,tag_values=_ff_shape(image,tag,'tag')
    _ff_need(tag_values[0]==0x24 and tag_values[4]==0x2c and tag_values[16]!=0 and
             _word(image,0x24)==_word(image,0x2c),'header-pair-normal-path')
    copy=literal(reset+0x80)-1;_,values=_ff_shape(image,copy,'copy')
    _ff_need(all(values[o]==0x03000700 for o in (2,0x3a,0x68,0xa0,0xd0,0xdc,0x114)),'copy-pulse')
    copies=[];zeros=[];tables=[]
    for source_off,target_off,size_off,reload_off,zrefs in (
            (0x16,0xa,0xe,0x1c,(0x42,0x46,0x4e)),
            (0x7c,0x70,0x74,0x82,(0xa8,0xac,0xb4)),(0xf0,0xe4,0xe8,0xf6,None)):
        table=values[source_off]
        _ff_need(not table&3 and values[target_off]==table+4 and values[size_off]==table+8 and
                 values[reload_off]==table+4,'copy-fields')
        source,target,size=(_ff_u32(image,table+n) for n in (0,4,8))
        _ff_need(size>0 and not(source|target|size)&3 and source+size<=len(image),'copy-bounds')
        _ff_need(_ff_ram(target,size) if zrefs else 0x03800000<=target<target+size<=0x03a00000,'copy-owner')
        copies.append({'table_offset':table,'source':source,'target':target,'size':size})
        if zrefs:
            a,b,c=zrefs
            _ff_need(values[a]==table+12 and values[b]==table+16 and values[c]==table+12,'zero-fields')
            begin,length=_ff_u32(image,table+12),_ff_u32(image,table+16)
            _ff_need(target+size==begin and not(begin|length)&3 and _ff_ram(begin,length),'zero-bounds')
            zeros.append((begin,begin+length));tables.append((table,table+20))
        else:tables.append((table,table+12))
    spans=[(c['target'],c['target']+c['size']) for c in copies]+zeros
    _ff_need(not any(_ff_overlap(a,b)for i,a in enumerate(spans)for b in spans[i+1:]),'copy-zero-overlap')
    app=arm_b_target(image,reset+0xe8)
    _ff_need(app is not None and not app&3 and 0<=app<=len(image)-4,'application-target')
    return dict(reset=reset,literal=literal,copy=copy,copies=copies,zeros=zeros,tables=tables,
                pools=pools,stacks=stacks,application=app,test=test,test_table=test_table,
                test_pools=test_pools,test_ram=(base,base+extent+1),tag=tag)


def _ff_profile_at(image,console,console_shape,context,all_calls):
    root=context['reset'];literal=context['literal'];copies=context['copies']
    _ff_need(literal(root+0x118)==console|1,'console-reset-link')
    calls,values=console_shape
    entries={'console':console,'copy':context['copy'],'tag':context['tag']};shapes={'console':console_shape}
    shapes['tag']=_ff_shape(image,context['tag'],'tag')
    for off,role in ((12,'hardware'),(16,'primary'),(20,'init'),(24,'byteflag'),(28,'dispatch')):
        entries[role]=calls[off];shapes[role]=_ff_shape(image,entries[role],role)
    primary=entries['primary'];pv=shapes['primary'][1];word_flag=pv[0];pulse=pv[18];base=pv[8]-4
    window=(base,base+0x24)
    _ff_need(base==0x03000f0c and pulse==0x03000700 and
             not any(_ff_overlap(window,span)for span in ((0x03000624,0x03000626),(0x03000720,0x03000736),(0x03000740,0x03000742),(pulse,pulse+1),
               (copies[2]['target'],copies[2]['target']+copies[2]['size']))),'hardware-owner')
    _ff_need(_ff_ram(word_flag,4) and not word_flag&3,'word-flag-range')
    word_entry=literal(root+0xb8)-1;entries['wordflag']=word_entry
    shapes['wordflag']=_ff_shape(image,word_entry,'wordflag');wv=shapes['wordflag'][1]
    _ff_need(wv[14]+4==word_flag and _ff_u32(image,0x20)!=wv[6],'header-normal-path')
    aux=literal(root+0xd0)-1;entries['aux']=aux;shapes['aux']=_ff_shape(image,aux,'aux')
    ac,av=shapes['aux'];_ff_need(av[2]==word_flag and av[16]==av[36]==0x03000720 and ac[42]==root+0x10c,'aux-root-link')
    entries['delay']=ac[10];shapes['delay']=_ff_shape(image,ac[10],'delay')
    dv=shapes['delay'][1];delay_counter=dv[16]
    _ff_need(dv[20]==dv[28]==dv[34]==delay_counter and _ff_ram(delay_counter,4) and
             dv[0] < len(image) and not _ff_overlap((dv[0],dv[0]+1),window),'delay-owner')
    init=entries['init'];ic,iv=shapes['init']
    _ff_need(ic[16]==primary and iv[100]==word_flag,'init-primary-flag')
    parsed=_byte_writes(image,init+0x14,init+0x64,primary)
    _ff_need(parsed is not None,'init-writes')
    writes,_,write_calls=parsed
    expected=[(base+0x28,1,0xc0),(base+0x2c,1,0xb2),(base+0x30,1,0x7d),(base+0x34,1,0x1c),
              (base+0x14,1,0),(base+0x20,2,0),(base+0x1c,2,30),(base,2,0),(base+4,1,0x34),
              (base+8,1,0xff),*[(base+0x10,1,v)for v in (0x30,0x10,0x10,0x20,0x20,1,4)]]
    _ff_need(not write_calls and [(w['address'],w['size'],w['value'])for w in writes]==expected and
             iv[4]==base+0x34 and iv[110]-0x30==iv[122]-0x30==base+4 and iv[130]==pulse,'typed-init')
    prelude_thunk=calls[8];config_thunk=ic[12]
    entries['prelude']=_ff_thunk(image,prelude_thunk);shapes['prelude']=_ff_shape(image,entries['prelude'],'prelude')
    entries['config']=_ff_thunk(image,config_thunk);shapes['config']=_ff_shape(image,entries['config'],'config')
    _ff_need(shapes['prelude'][1][30]==0x04800080,'prelude-domain')
    hw=_byte_writes(image,entries['hardware'],entries['hardware']+len(_FF_SPECS['hardware'][0])//2-2,primary)
    _ff_need(hw is not None and all(0x04800000<=w['address']<0x04800100 for w in hw[0]),'hardware-domain')
    cfg_calls,cfg_values=shapes['config'];gpio=cfg_values[6]
    _ff_need(gpio==0x03000620 and cfg_values[28]==0xff3f,'config-nine-domain')
    shadow=cfg_values[8]+(gpio>>16)+0x12
    _ff_need(not shadow&1 and _ff_ram(shadow,2),'config-shadow')
    irq_sources=[];irq_entries=[];thunks=[]
    iram=copies[2]
    for off,pattern in ((22,_FF_IRQ_SAVE),(48,_FF_IRQ_RESTORE)):
        thunk=cfg_calls[off];ram_entry=_ff_thunk(image,thunk)
        _ff_need(not ram_entry&3 and iram['target']<=ram_entry and ram_entry+24<=iram['target']+iram['size'],'irq-copy-range')
        source=iram['source']+ram_entry-iram['target']
        _ff_need(image[source:source+24]==pattern,'copied-irq-body')
        irq_sources.append((source,source+24));irq_entries.append((ram_entry,ram_entry+24));thunks.append((thunk,thunk+16))
    dispatch=entries['dispatch'];dc,dv_dispatch=shapes['dispatch']
    _ff_need(dv_dispatch[2]==word_flag and dv_dispatch[10]==dv_dispatch[132]==copies[0]['table_offset']+4 and
             dv_dispatch[14]==dv_dispatch[136]==0xffffe000,'dispatch-global-ownership')
    packet_buffer=(copies[0]['target']+dv_dispatch[14])&0xffffffff
    _ff_need(any(a<=packet_buffer and packet_buffer+0x2000<=b for a,b in context['zeros']),'packet-buffer-provenance')
    entries['parser']=dc[20];shapes['parser']=_ff_shape(image,entries['parser'],'parser')
    pcalls,pl=shapes['parser'];wrapper=pcalls[24]
    _ff_need(pl[16]==pulse,'parser-pulse')
    _ff_need(pcalls[120]==wrapper and pcalls[42]==root+0x134,'parser-receive-links')
    entries['wrapper']=wrapper;shapes['wrapper']=_ff_shape(image,wrapper,'wrapper')
    wc,wl=shapes['wrapper'];rx=wc[12]
    _ff_need(wc[22]==rx,'receive-call-links');entries['rx']=rx;shapes['rx']=_ff_shape(image,rx,'rx')
    timeout=wl[2]
    _ff_need(wl[32]==wl[84]==timeout and wl[52]==wl[66]==wl[76]==base+4,'receive-global-links')
    rv=shapes['rx'][1]
    _ff_need(rv[22]==rv[54]==base+4 and rv[38]==rv[68]==pulse and rv[8]>0,'receive-domain')
    main=copies[1];private=copies[0]
    _ff_need(private['target']<=timeout<private['target']+private['size'],'timeout-copy')
    timeout_source=private['source']+timeout-private['target']
    _ff_need(image[timeout_source]==1,'timeout-initial-one')
    bf=shapes['byteflag'][1]
    _ff_need(bf[0]==0x44 and bf[24]==bf[32]==timeout-4,'byte-flag-domain')
    _ff_need(main['target']<=word_flag and word_flag+4<=main['target']+main['size'],'word-flag-copy')
    ram_fields=[(word_flag,word_flag+4),(timeout,timeout+1),(timeout-4,timeout-3),
                (delay_counter,delay_counter+4),(shadow,shadow+2)]
    _ff_need(not any(_ff_overlap(a,b)for i,a in enumerate(ram_fields)for b in ram_fields[i+1:]),'metadata-alias')
    ack2=pcalls[88];_ff_need(pcalls[104]==ack2 and dc[128]==ack2,'ack2-links')
    entries['ack2']=ack2;shapes['ack2']=_ff_shape(image,ack2,'ack2')
    response_table=shapes['ack2'][1][6]
    _ff_need(not response_table&3 and 0<=response_table<=len(image)-4,'response-table')
    tx=shapes['ack2'][0][12];_ff_need(shapes['ack2'][0][18]==tx,'ack2-transmit-links')
    entries['tx']=tx;shapes['tx']=_ff_shape(image,tx,'tx')
    tv=shapes['tx'][1];_ff_need(tv[0]==base+0x14 and tv[10]==pulse and tv[20]-0x10==base+4,'transmit-domain')
    ack1s=[(at,shape)for at,shape in _ff_hits(image,'ack1')if shape[0][8]==shape[0][14]==tx]
    _ff_need(len(ack1s)==1,'ack1-owner');entries['ack1'],shapes['ack1']=ack1s[0]
    # Shared RX/TX ownership is a complete local call family, not a lone poll.
    owned={rx:{wrapper+12,wrapper+22},wrapper:{entries['parser']+24,entries['parser']+120},
           tx:{entries['ack1']+8,entries['ack1']+14,ack2+12,ack2+18},init:{console+20}}
    _ff_need(all({site for site,target in all_calls if target==at}==sites for at,sites in owned.items()),'consumer-call-ownership')
    code=[(at,at+len(_FF_SPECS[role][0])//2)for role,at in entries.items()]
    code+=irq_sources+[(prelude_thunk,prelude_thunk+16),(config_thunk,config_thunk+16)]+thunks
    code.append((context['test'],context['test']+0x150))
    _ff_need(not any(_ff_overlap(a,b)for i,a in enumerate(code)for b in code[i+1:]),'code-owner-overlap')
    app=context['application']
    _ff_need(not any(a<=app<b for a,b in code+[(root,root+len(_FF_RESET))]),'application-code-owner')
    pools=list(context['pools'])+context['test_pools']
    for role,at in entries.items():
        for off,_reg in _FF_SPECS[role][2]:
            op=_word(image,at+off);pool=((at+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
    pools += [(at+12,at+16)for at,_end in [(prelude_thunk,prelude_thunk+16),(config_thunk,config_thunk+16)]+thunks]
    # Thunk literal words belong to their own 16-byte body; ordinary Thumb
    # pools must not alias known instruction bodies.
    ordinary=pools[:len(pools)-4]
    _ff_need(all(0<=a<b<=len(image) and not any(_ff_overlap((a,b),c)for c in code)for a,b in ordinary),'literal-owner')
    data=context['tables']+[(context['test_table'],context['test_table']+28),(0x24,0x26),(0x2c,0x2e)]+[(c['source'],c['source']+c['size'])for c in copies]+[(0x20,0x24),(0x44,0x4c),(response_table,response_table+4)]
    _ff_need(all(0<=a<b<=len(image)for a,b in data) and
             not any(a<=app<b for a,b in pools+data),'application-data-owner')
    guards=sorted(set(code+pools+data+[(root,root+len(_FF_RESET))]))
    ram_intervals=[context['test_ram']]+[(c['target'],c['target']+c['size'])for c in copies[:2]]+context['zeros']+ram_fields+[(sp-56,sp)for sp in context['stacks']]
    return dict(signature='thumb-byte-uart-word-flag-fixed-ff-mixed-v1',admission='temporary-evidence-gated',
        policy='provisional-synchronous-null-console',register_width=2,csr_value=0xff,
        base=base,status_address=base+8,control_address=base+0x10,isr_address=base+0x14,fifo_address=base+0xc,
        pulse_address=pulse,primary_entry=primary,primary_status_pc=primary+10,primary_control_pc=None,
        init_entry=init,tx_entry=tx,console_root=console,rx_drain_pc=init+0x72,receive_entry=rx,receive_wrapper=wrapper,
        tx_callers=sorted(owned[tx]),tx_isr_pc=tx+2,tx_fifo_pc=tx+24,init_writes=writes,clock_setup=(0xc0,0xb2,0x7d,0x1c),
        code_intervals=[list(x)for x in sorted(set(code))],literal_intervals=[list(x)for x in sorted(set(pools))],
        data_intervals=[list(x)for x in sorted(set(data))],boot_guard_intervals=[list(x)for x in sorted(((root,root+len(_FF_RESET)),(0x20,0x24),(0x24,0x26),(0x2c,0x2e)))],
        guard_intervals=[list(x)for x in guards],ram_intervals=[list(x)for x in sorted(set(ram_intervals))],
        iram_intervals=[list(x)for x in sorted(set(irq_entries+[(iram['target'],iram['target']+iram['size'])]))],
        word_flag=word_flag,word_flag_producer=word_entry,header_marker=wv[6],header_value=_ff_u32(image,0x20),
        receive_timeout_flag=timeout,receive_timeout_source=timeout_source,copy_layouts=copies,
        reset_entry=root,copy_entry=context['copy'],stack_predecrement_bytes=56,packet_buffer=packet_buffer,
        runtime_source_policy='defer-until-postpatch-primary-reparse-and-immutable-byte-match')


def _find_half_ff_uart_console_profile(image):
    roots=list(_ff_hits(image,'console'))
    if not roots:return None,'console-half-ff-not-found'
    try:context=_ff_reset_copy(image)
    except _HalfFFUnclosed as error:return None,str(error)
    calls=list(facts_for(image).call_candidates('thumb'))
    profiles=[];reasons=[]
    for at,shape in roots:
        try:profiles.append(_ff_profile_at(image,at,shape,context,calls))
        except _HalfFFUnclosed as error:reasons.append(str(error))
    if len(profiles)>1:return None,'console-half-ff-profiles-ambiguous'
    if profiles:return profiles[0],'accepted'
    return None,reasons[0]if len(reasons)==1 else'console-half-ff-candidates-unclosed'


def find_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    prior,reason=_find_prior_uart_console_profile(image,ready_profile)
    new,new_reason=_find_half_ff_uart_console_profile(image)
    if new is not None:
        if prior is not None or 'ambiguous' in reason:
            return None,'console-protocol-ownership-ambiguous'
        return new,'accepted'
    if 'ambiguous' in new_reason:return None,new_reason
    if prior is not None or 'ambiguous' in reason:return prior,reason
    return (None,reason)if new_reason=='console-half-ff-not-found'else(None,new_reason)


# A distinct finite boot probe; old source contracts above remain unchanged.
