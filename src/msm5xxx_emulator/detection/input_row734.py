"""Source-owned row734 low-five-bit matrix; no guest state or UI injection."""
from __future__ import annotations
import re
import struct
from .arm import (_thumb_function_start,_thumb_reachable,_thumb_path_preserves_register)
from .boot_contact import find_boot_contact_profile,_thumb_shape
from .protected_nor import (_normal_copy,_Unclosed,_need,_word,_literal,_call,_in_ram,_code,_MASKS as _COPY_MASKS)
from .input_descriptor import _descriptor_mmio_provenance
from .ready_poll import _THUMB_BL

_SPECS = {'dispatch': ('00b569f00bfc002803d000f03df908bc184700f001f8fae7', {}, (2, 10, 18)),
 'single': ('fcb5954968460cc90cc094480421407a934a002809d010680b02184310608f4b00209872ef20587019708d480068020a0ad38a4a137a013b13721b0604d1884f8023984338601172844ca078002800d0ffe00421834897f22ffe834e002771681f200988c90807d27c4c6178752901d1752716e0512714e097f26cfdb18d9f239943b185b18d326a1180002801d197f26dfd706b0088c006c00e1f2801d06f4c677800251f2800d15fe0002497f252fdf18d9f239943694b62000c339a5a9f231a401143f185f18db26a1180002801d197f24cfd14205bf7fffd706b0088c006c00e1f2812d000216a46525c824204d001310906090e0529f6db06204843564924394018075d01352d062d0e01342406240e062ccadb97f21dfdb18d9f239943b185b18d326a1180002801d197f21efd97f210fdb18d9f239943b185b18d326a1180002801d197f211fd97f203fdf18d9f221143f185f18db26a1180002801d197f204fd012d00ddef273c4c01252078062800d364e002a31b5c5b009f4400006003311751586770002f08d00220344a2070106801239b02184310604fe03048012301689b029943016048d134e0002f0ed1002060702570ff20fef705f82848a5720068002803d10421264897f27afd6078874233d06770ff20fdf7f5ffa5722de0607887420dd11d48012301689b029943016003202070381cfdf7e5ff0020a0721ce06770002f19d125700020607013480068002812d10421124897f252fd0de000206168fff7bbfe0520207005e06078b84202d1002f00d12570677006e097f2fafc6520c0000849eef79ffb00206072fcbc08bc1847',
            {2: (1, None),
             10: (0, None),
             16: (2, None),
             30: (3, None),
             42: (0, None),
             50: (2, None),
             62: (7, None),
             72: (4, None),
             84: (0, None),
             90: (6, None),
             104: (4, None),
             158: (4, None),
             182: (3, None),
             254: (1, None),
             362: (4, None),
             398: (2, None),
             414: (0, None),
             446: (0, None),
             458: (0, None),
             488: (0, None),
             528: (0, None),
             538: (0, None),
             584: (1, None)},
            (86,
             120,
             142,
             172,
             208,
             214,
             278,
             300,
             304,
             326,
             330,
             352,
             442,
             460,
             474,
             506,
             540,
             550,
             576,
             586)),
 'single_filtered': ('ffb5b94901a80cc90cc001200090b7480026407a0024b64900280bd001220868920210430860b14a00209072ef20507004201070ae490868010a0bd3ab490a7a013a0a72120605d1a94a80239843106004200872a5488078002800d040e10421a448e4f23ffea44d002769681f200988c90807d29d4d6978752901d1752717e0512715e0e4f27cfd9b4d9f23a98d9943a985a98d2a6a1180002801d1e4f27cfd686b0088c006c00e1f2801d08f4d6f78002103911f2800d185e00025e4f260fd8d4a9f23d18d9943884b6a000c339a5a9f231a401143884ad185d18d926a1180002801d1e4f258fd142057f7c5ff8248406b0088c006c00e1f2830d0002101aa525c824204d001310906090e0529f6db0623754a5943243a8918c006c00e1e284f5d16d1002d14d0052d12d06f484078b8420fd00a2f01d1042008e0092f01d1082004e0542f01d1012000e00220044300e00126039801300006000e039001352d062d0e062da9dbe4f20afd624d9f23a98d9943a985a98d2a6a1180002801d1e4f20afde4f2fcfca98d9f239943a985a98d2a6a1180002801d1e4f2fdfce4f2effce98d9f221143e985e98daa6a1180002801d1e4f2f0fc002e00d000240398012800ddef27494d2878062800d37fe001a31b5c5b009f447b024b176c726f70002f08d00220424928700868012292021043086072e03e49012308689b029843086000d06ae04fe0002f0fd10020687001262e70ff20fdf727ff3549ae720868002803d104213348e4f262fd6878874200d153e0ef2f12d10a2805d0092803d0542801d055280ad1002c08d0610801d3552807d0a10841d354283fd102e0009800283bd06f70ff20fdf7fefe01200ee0687887420dd11e49012308689b029843086003202870381cfdf7eefe0020a87224e06f70002f21d1012028700020144968700868002819d104211248e4f220fd14e000206968fff773fe052005e06878b84203d1002f01d1012028706f7005e0e4f2c8fc09490a48edf730ff00206872ffbc08bc18470000',
                     {2: (1, None),
                      14: (0, None),
                      22: (1, None),
                      38: (2, None),
                      52: (1, None),
                      60: (1, None),
                      72: (2, None),
                      84: (0, None),
                      96: (0, None),
                      102: (5, None),
                      116: (5, None),
                      136: (5, None),
                      172: (5, None),
                      192: (2, None),
                      200: (3, None),
                      214: (2, None),
                      238: (0, None),
                      274: (2, None),
                      300: (0, None),
                      364: (5, None),
                      454: (5, None),
                      486: (1, None),
                      502: (1, None),
                      538: (1, None),
                      550: (0, None),
                      630: (1, None),
                      670: (1, None),
                      682: (0, None),
                      724: (1, None),
                      726: (0, None)},
                     (98,
                      132,
                      156,
                      188,
                      228,
                      234,
                      360,
                      384,
                      388,
                      410,
                      414,
                      436,
                      534,
                      552,
                      616,
                      648,
                      684,
                      694,
                      720,
                      728)),
 'multi': ('f0b5824c0027607a0025814901280bd0012208689202104308607e4ee8437062002060600420207679490868010a0ad3217a01392172090605d1754980239843086004202072714ca078002800d0d9e00421714897f2f8fc704e70680088c00801d2012515e097f23dfcb18d9f239943b185b18d326a1180002801d197f23efc706b0088c006c00e1f2802d1002d00d154e0002497f226fcf18d9f2399435b4b62001a339a5a9f231a401143f185f18db26a1180002801d197f220fc14205bf7d3fc706b0088c006c00e554aa10051588840074301342406240e062cdadb97f201fcb18d9f239943b185b18d326a1180002801d197f202fc97f2f4fbb18d9f239943b185b18d326a1180002801d197f2f5fb97f2e7fbf18d9f221143f185f18db26a1180002801d197f2e8fbf8438700bf08002d02d0012080070743334c0125207e012810d002283cd0042847d0052800d04fe02f4e706ab84203d1002f01d17762257677624ce02a4e0220716a8f421ed1002f07d02649207608680122920210430860eee7607e012805d1381c6168fff7cefd002060761d49012308689b0298430860ded104211b4897f253fcd9e7002fd7d0164a012311689b02194311602076cfe7134e706a874205d1381c6168fff7aefd657600e07762257611e0a07a002802d1ff20fdf7b7fe0a4e05207762207606e097f2e8fb09490a488839eef78dfa6572f0bc08bc1847',
           {2: (4, None),
            10: (1, None),
            26: (6, None),
            40: (1, None),
            58: (1, None),
            70: (4, None),
            82: (0, None),
            88: (6, None),
            158: (3, None),
            202: (2, None),
            316: (4, None),
            340: (6, None),
            360: (6, None),
            374: (1, None),
            408: (1, None),
            424: (0, None),
            436: (2, None),
            452: (6, None),
            490: (6, None),
            504: (1, None),
            506: (0, None)},
           (84, 102, 124, 148, 184, 190, 222, 244, 248, 270, 274, 296, 400, 426, 464, 486, 500, 510)),
 'init_rows': ('99f2a4f8b98d9f239943b985b98d3a6a1180002801d199f2a5f899f297f8f98d9f221143f985f98dba6a1180002801d199f298f8',
               {},
               (0, 22, 26, 48)),
 'forward': ('b8b5071c12480178124800290ad0816a002907d000ab1f7000989af214f8b8bc08bc18470c49002509880c4c032908dc0088032805dc2b1c0022391c201c99f251fd2b1c0022391c201cf0f71ff9e6e7',
             {4: (0, None), 8: (0, None), 36: (1, None), 42: (4, None)},
             (26, 62, 74)),
 'setter': ('034a0121117000215170024988627047', {0: (2, None), 10: (1, None)}, ()),
 'register_api': ('03b500ab081c1978012903d10549c97a002903d1002002b008bc184701f056fe0120f8e7',
                  {12: (1, None)},
                  (28,)),
 'register_window': ('008800ab09491880009894f7f7f801b008bc1847', {4: (1, None)}, (10,)),
 'callback': ('f1b52ff247fe07043f0c00211f226448520180180171447b0121624a012c0bd1d61d1b3675780b1c36780135ed06ed0eb54209d1002307e055780b1c16780135ed06ed0eb542f5d01b063cd0012c0cd1544e00ab2236717818788919887070780130c006c00e70708fe000ab1b78dc1fcb3c2e2c1cd202a31b5d5b009f44',
              {14: (0, None), 26: (2, None), 80: (6, None)},
              (2,)),
 'callback_shifted': ('f1b523f281f807043f0c002321206c494001081843221201891803724c780121684a012c0bd1d61d1b3675780b1c36780135ed06ed0eb54209d1002307e055780b1c16780135ed06ed0eb542f5d01b063bd0012c0cd15b4e00ab2236717818788919887070780130c006c00e707096e000ab1b78dc1fcb3c2e2c1bd201a31b5d5b009f44',
                      {14: (1, None), 32: (2, None), 86: (6, None)},
                      (2,)),
 'store': ('00ab517818788918887050780130c006c00e5070', {}, ()),
 'success': ('002f01d12ff28dfd022106482ff235fef8bc08bc1847', {10: (0, None)}, (4, 12)),
 'dequeue': ('064a50781178884201d10020704788180131c906c90e807811707047', {0: (2, None)}, ()),
 'bitmap': ('f0b5041c251c0e484d400e4e0027446068080cd3600804d30a49b8009439085801e0b80030580006000efef7fdf86d08640801371f2febd3f0bc08bc1847',
            {6: (0, None), 10: (6, None), 24: (1, None)},
            (42,)),
 'gate': ('074880b500780027002804d120f1e6fd012800d10127381c80bc08bc1847', {0: (0, None)}, (12,)),
 'delay': ('f0b41d4a978c116a79437a013f239a1a0026322809dc4843222179438018401a801100d4061c154f22e032234b439d1822237b43341ceb1a9b1100d41c1c0f4f3c8032234b4332389b189b1101d41c1c00e0341c2404240c01e03c8032383228fbdc002805dd48438018801100d4061c3e80f0bc7047',
           {2: (2, None), 38: (7, None), 62: (7, None)},
           ()),
 'timer_init': ('00b50021016041608160c1600161416101772030fff0cdfc08bc1847', {}, (20,)),
 'timer_reg': ('9cb50f1c141c002205990192221c0091391c00f003f89cbc08bc1847', {}, (18,)),
 'timer_core': ('f8b5071c1e1c0d1c141c002905d13cf3a4fa1449154893f04af9002c01dd002e06da3cf39afa10480f49073093f03ff93cf321fa0004000c0090381cfff767ffbc60fd603c617e61069838770798b861381cfff72aff0098002801d13cf317faf8bc08bc1847',
                {18: (1, None), 20: (0, None), 38: (0, None), 40: (1, None)},
                (14, 22, 34, 44, 48, 60, 82, 92)),
 'timer_insert': ('80b5071c3cf3e2fa03041b0c134812e0b968826891420cda01684f6001687860396007608168ba68891a8160002b11d10ee0891ab96040680028e9d10848416b4f60416b3960002179604763002b01d13cf3c8fa80bc08bc1847',
                  {12: (0, None), 60: (0, None)},
                  (4, 80)),
 'timer_remove': ('80b5071c3cf3b0fa0204120c03cf083f002800d04160002905d008608868bb68c018886003e0002801d006494863002078603860002a01d13cf3a2fa80bc08bc1847',
                  {42: (1, None)},
                  (4, 56)),
 'timer_flag_init': ('002101717047', {}, ())}
_SINGLE = {'single': {'descriptor': (90, 6),
            'key_state': (10, 0),
            'presence': 148,
            'sense': 220,
            'row': 182,
            'event': 254,
            'eventreg': 1,
            'delay': 214,
            'links': {'save': (120, 172, 278, 304, 330),
                      'restore': (142, 208, 300, 326, 352),
                      'forward': (442, 474, 506),
                      'bitmap': (550,),
                      'set_sigs': (460, 540),
                      'clear_sigs': (86,)}},
 'single_filtered': {'descriptor': (102, 5),
                     'key_state': (14, 0),
                     'presence': 162,
                     'sense': 242,
                     'row': 200,
                     'event': 274,
                     'eventreg': 2,
                     'delay': 234,
                     'links': {'save': (132, 188, 360, 388, 414),
                               'restore': (156, 228, 384, 410, 436),
                               'forward': (534, 616, 648),
                               'bitmap': (694,),
                               'set_sigs': (552, 684),
                               'clear_sigs': (98,)}},
 'multi': {'links': {'save': (102, 148, 222, 248, 274),
                     'restore': (124, 184, 244, 270, 296),
                     'forward': (486,),
                     'bitmap': (400, 464),
                     'set_sigs': (426,),
                     'clear_sigs': (84,)}}}


def _shape(image,at,name):
    pattern,literals,calls=_SPECS[name]
    pattern=bytes.fromhex(pattern)
    if type(at)is not int or at<0 or at+len(pattern)>len(image):return False
    # Inline ADR tables have the two witnessed word-aligned layouts.
    if name in ('single','single_filtered','callback','callback_shifted')and at&3:return False
    if not _thumb_shape(image,at,pattern,literals,calls):return False
    try:
        for off in calls:_call(image,at+off)
    except _Unclosed:return False
    return True


def _find(image,name):
    pattern,literals,calls=_SPECS[name];raw=bytes.fromhex(pattern)
    holes={off+i for off in literals for i in (0,1)}
    holes.update(off+i for off in calls for i in range(4))
    runs=[];start=None
    for i in range(len(raw)+1):
        if i<len(raw)and i not in holes:
            if start is None:start=i
        elif start is not None:runs.append((start,raw[start:i]));start=None
    offset,anchor=max(runs,key=lambda pair:len(pair[1]));cursor=0
    while True:
        hit=image.find(anchor,cursor)
        if hit<0:return
        cursor=hit+1;at=hit-offset
        if at>=0 and not at&1 and _shape(image,at,name):yield at


def _short_branch(image,pc):
    op=_word(image,pc,2)
    _need(op&0xf800==0xe000,'branch-kind')
    d=(op&2047)*2
    return pc+4+(d-4096 if d&2048 else d)


def _callers(image,target):
    # Filter raw BL-shaped bytes by target and the exact owning templates below.
    return [m.start()for m in _THUMB_BL.finditer(image)
            if not m.start()&1 and _try_call(image,m.start())==target]


def _try_call(image,at):
    try:return _call(image,at)
    except _Unclosed:return None


def _bound(image,at,name,owned):
    _need(_shape(image,at,name),name+'-shape');owned.append((at,name));return at


def _mapped(image,context,address,size,ram_base,ram_size):
    _need(_in_ram(address,size,ram_base,ram_size),'ram-range')
    matches=[copy for copy in context['copies']if copy.target<=address and address+size<=copy.target+copy.size]
    _need(len(matches)==1,'copy-provenance')
    copy=matches[0]
    _need(all(not(dest<address+size and address<dest+length)for dest,length in context['writes']
              if (dest,length)!=(copy.target,copy.size)),'copy-write-conflict')
    return copy.source+address-copy.target


def _consumer(image,forward,bitmap,key_state,context,ram_base,ram_size,owned):
    _bound(image,forward,'forward',owned)
    _bound(image,bitmap,'bitmap',owned)
    _need(_call(image,bitmap+0x2a)==forward and _literal(image,bitmap+6,0)==key_state,'bitmap-forward')
    release=_literal(image,bitmap+0xa,6)
    _need(_literal(image,bitmap+0x18,1)==release,'bitmap-map-link')
    press=release-0x94
    _need(0<=press<=len(image)-124 and 0<=release<=len(image)-124,'bitmap-map-bounds')
    box,enable=_literal(image,forward+8,0),_literal(image,forward+4,0)
    _need(_in_ram(box,0x2c,ram_base,ram_size)and _in_ram(enable,2,ram_base,ram_size),'callback-global')
    setters=[at for at in _find(image,'setter')if _literal(image,at,2)==enable and _literal(image,at+0xa,1)==box]
    _need(len(setters)==1,'setter-owner');setter=_bound(image,setters[0],'setter',owned)
    apis=[site-0x1c for site in _callers(image,setter)if _shape(image,site-0x1c,'register_api')]
    _need(len(apis)==1,'register-api-owner');api=_bound(image,apis[0],'register_api',owned)
    sites=[site for site in _callers(image,api)if _shape(image,site-0xa,'register_window')]
    _need(len(sites)==1,'ui-register-owner');site=sites[0];_bound(image,site-0xa,'register_window',owned)
    callback=_literal(image,site-6,1)
    _need(callback&1,'callback-isa');callback&=~1
    forms=[name for name in ('callback','callback_shifted')if _shape(image,callback,name)]
    _need(len(forms)==1,'callback-form');form=forms[0];_bound(image,callback,form,owned)
    shifted=form=='callback_shifted';guard=callback+(0x70 if shifted else 0x6a)
    op=_word(image,guard+0xa,2);_need(op&0xff00==0xd200,'ascii-default-branch')
    d=op&255;d-=256 if d&128 else 0
    store=guard+0xe+2*d;_bound(image,store,'store',owned)
    branch_intervals=[(store+0x14,store+0x16)]
    tail=_short_branch(image,store+0x14)
    fast=_short_branch(image,callback+(0x6e if shifted else 0x68))
    _need(fast==tail,'dual-store-tail')
    if _word(image,tail,2)&0xf800==0xe000:
        branch_intervals.append((tail,tail+2));tail=_short_branch(image,tail)
    _bound(image,tail,'success',owned)
    ring=_literal(image,callback+(0x20 if shifted else 0x1a),2)
    _need(_in_ram(ring,0x44,ram_base,ram_size),'ring-range')
    dequeues=[at for at in _find(image,'dequeue')if _literal(image,at,2)==ring]
    _need(len(dequeues)==1,'dequeue-owner');dequeue=_bound(image,dequeues[0],'dequeue',owned)
    return dict(forward=forward,bitmap=bitmap,press_map=press,release_map=release,
        callback=callback,slot=box+0x28,enable=enable,ring=ring,dequeue=dequeue,
        IRQ_save=_call(image,callback+2),IRQ_restore=_call(image,tail+4),notify=_call(image,tail+0xc),
        confidence='byte-preserving stores; primary dequeue verified; secondary repack/UI behavior unclassified',
        activation_depends_on_UI_mode=False,branch_intervals=branch_intervals)


def _registration(image,dispatch,descriptor,save,restore,ram_base,ram_size,owned):
    candidates=[];cursor=0;pointer=dispatch|1
    while True:
        pool=image.find(pointer.to_bytes(4,'little'),cursor)
        if pool<0:break
        cursor=pool+1
        if pool&3:continue
        for pc in range(max(0,pool-0x400),pool,2):
            op=_word(image,pc,2)
            if op&0xff00!=0x4900 or ((pc+4)&~3)+(op&255)*4!=pool:continue
            # Exact timer object producer, 25/25 and repeating flag, not constants alone.
            if image[pc-10:pc-2]!=bytes.fromhex('0122009219221923')or _word(image,pc-2,2)!=0x1c20:continue
            if _word(image,pc-16,2)!=0x1c20 or _word(image,pc-18,2)&0xff00!=0x4c00:continue
            timer=_literal(image,pc-18,4)
            init=_try_call(image,pc-14);reg=_try_call(image,pc+2)
            if not(_shape(image,init,'timer_init')and _shape(image,reg,'timer_reg')):continue
            if not _in_ram(timer,0x34,ram_base,ram_size):continue
            core=_call(image,reg+0x12)
            if not _shape(image,core,'timer_core'):continue
            if _call(image,core+0x30)!=save or _call(image,core+0x5c)!=restore:continue
            insert,remove=_call(image,core+0x52),_call(image,core+0x3c)
            if not(_shape(image,insert,'timer_insert')and _shape(image,remove,'timer_remove')):continue
            if not _shape(image,_call(image,init+0x14),'timer_flag_init'):continue
            for block in _find(image,'init_rows'):
                if block>=pc or pc-block>0x800:continue
                start=_thumb_function_start(image,block)
                if not start<=pc<start+0x1000:continue
                end=image.find(bytes.fromhex('08bc1847'),pc+6,min(start+0x1000,len(image)))
                if end<0:continue
                end+=4;reachable=_thumb_reachable(image,start,end)
                if block not in reachable or pc+2 not in reachable:continue
                desc_loads=[at for at in range(start,block,2)
                    if _word(image,at,2)&0xff00==0x4f00 and _literal(image,at,7)==descriptor
                    and _thumb_path_preserves_register(image,at+2,block,end,7)]
                if len(desc_loads)!=1:continue
                if any(_call(image,block+off)!=expected for off,expected in ((0,save),(0x16,restore),(0x1a,save),(0x30,restore))):continue
                candidates.append((pc,timer,init,reg,core,insert,remove,block,start,end,desc_loads[0]))
    _need(len(candidates)==1,'init-timer-owner')
    pc,timer,init,reg,core,insert,remove,block,start,end,desc_load=candidates[0]
    for at,name in ((init,'timer_init'),(reg,'timer_reg'),(core,'timer_core'),(insert,'timer_insert'),(remove,'timer_remove'),(_call(image,init+0x14),'timer_flag_init'),(block,'init_rows')):_bound(image,at,name,owned)
    return dict(object=timer,registration_pc=pc+2,callback=pointer,initial=25,repeat=25,
                repeat_flag=1,units='source-clock units; physical timing unverified',
                initialization_entry=start,initialization_end=end,descriptor_load=desc_load,
                constructor_literal_pcs=[desc_load,pc-18,pc])


def _at(image,dispatch,context,boot,ram_base,ram_size):
    owned=[];_bound(image,dispatch,'dispatch',owned)
    gate,multi,single=(_call(image,dispatch+off)for off in (2,0xa,0x12))
    _bound(image,gate,'gate',owned);_bound(image,multi,'multi',owned)
    forms=[name for name in ('single','single_filtered')if _shape(image,single,name)]
    _need(len(forms)==1,'single-form');form=forms[0];_bound(image,single,form,owned);meta=_SINGLE[form]
    descriptor=_literal(image,single+meta['descriptor'][0],meta['descriptor'][1])
    key_state=_literal(image,single+meta['key_state'][0],meta['key_state'][1])
    _need(_literal(image,multi+2,4)==key_state,'scanner-key-state')
    dsrc=_mapped(image,context,descriptor,0x38,ram_base,ram_size)
    expected={0:0x03000720,4:0x03000720,8:0x0300072c,0x10:0x03000724,
              0x14:0x03000724,0x18:0x03000730,0x20:0x03000728,0x24:0x03000728,
              0x28:0x03000734,0x34:0x0300072c}
    _need(all(_word(image,dsrc+off)==value for off,value in expected.items()),'descriptor-fields')
    provenance=_descriptor_mmio_provenance(image,descriptor)
    if provenance is not None:_need(provenance['source']==dsrc,'descriptor-copy-conflict')
    sense_table=_literal(image,single+2,1)
    _need(0<=sense_table<=len(image)-8,'sense-table-bounds')
    senses=list(image[sense_table:sense_table+5]);_need(senses==[30,29,27,23,15],'sense-table')
    event_table=_literal(image,single+meta['event'],meta['eventreg'])-0x24
    _need(event_table+0x24==sense_table and 0<=event_table<=len(image)-30,'event-table')
    events=list(image[event_table:event_table+30])
    row_base=_literal(image,single+meta['row'],3)
    _need(row_base==key_state and _literal(image,multi+0x9e,3)==key_state,'row-table-owner')
    row_tables=(key_state+0xc,key_state+0x1a);row_values=[1,2,4,8,16,128]
    row_sources=[_mapped(image,context,at,12,ram_base,ram_size)for at in row_tables]
    _need(all(list(struct.unpack_from('<6H',image,at))==row_values for at in row_sources),'row-table')
    shifts=_literal(image,multi+0xca,2)
    _need(0<=shifts<=len(image)-24 and list(struct.unpack_from('<6I',image,shifts))==[0,5,10,15,20,25],'bitmap-shifts')
    bindings={}
    for role in ('save','restore','forward','bitmap','set_sigs','clear_sigs'):
        offsets=meta['links'][role];_need(offsets,'scanner-call-owner')
        target=_call(image,single+offsets[0]);bindings[role]=target
        _need(all(_call(image,single+off)==target for off in offsets)
              and all(_call(image,multi+off)==target for off in _SINGLE['multi']['links'][role]),'scanner-call-link')
    _need(_code(image,bindings['save'],'irq_save')and _code(image,bindings['restore'],'irq_restore'),'irq-primitives')
    delay=_call(image,single+meta['delay']);_bound(image,delay,'delay',owned)
    _need(_call(image,multi+0xbe)==delay,'delay-link')
    for off,(reg,_)in _SPECS['delay'][1].items():
        if reg==7:_need(_literal(image,delay+off,reg)==0x04800020,'delay-write-domain')
    consumer=_consumer(image,bindings['forward'],bindings['bitmap'],key_state,context,ram_base,ram_size,owned)
    _need(consumer['IRQ_save']==bindings['save']and consumer['IRQ_restore']==bindings['restore']
          and consumer['notify']==bindings['set_sigs'],'consumer-kernel-link')
    timer=_registration(image,dispatch,descriptor,bindings['save'],bindings['restore'],ram_base,ram_size,owned)
    # Lazy import avoids cycles through the public input aggregation module.
    from .input_matrix import ASCII_KEY_EVENTS
    mappings={}
    for index,event in enumerate(ASCII_KEY_EVENTS):
        cells=[(column,row)for column in range(5)for row in range(6)if events[column*6+row]==event]
        _need(len(cells)==1,'numeric-table-ambiguous');column,row=cells[0]
        _need(_word(image,consumer['press_map']+4*(row*5+column))&255==event,'numeric-bitmap-consumer')
        mappings[11+index]=dict(event=event,row=row,column=column,sense=senses[column],
            rule='temporary-unique-ascii-row734',evidence='source-table+byte-event-ring; native key1 cross-dump witness')
    code=[(at,at+len(bytes.fromhex(_SPECS[name][0])))for at,name in owned]
    code += consumer['branch_intervals']
    code += [(bindings['save'],bindings['save']+24),(bindings['restore'],bindings['restore']+24),
             (context['root'],context['decision']+12),(context['normal'],context['normal']+0x40)]
    code += [(context['copy'],context['copy']+0x10c),(timer['initialization_entry'],timer['initialization_end'])]
    pools=[]
    for at,name in owned:
        for off in _SPECS[name][1]:
            op=_word(image,at+off,2);pool=((at+off+4)&~3)+(op&255)*4
            _need(not any(lo<pool+4 and pool<hi for lo,hi in code),'pool-code-overlap')
            pools.append((pool,pool+4))
    for pc in timer['constructor_literal_pcs']:
        op=_word(image,pc,2);pool=((pc+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
    # Reuse the exact copier, but guard its dereferenced pools/tables as well.
    mask=_COPY_MASKS['copy'];off=0
    while off<len(mask)//2:
        if mask[off*2:off*2+8]=='????????':off+=4;continue
        op=_word(image,context['copy']+off,2)
        if op&0xf800==0x4800:
            pool=((context['copy']+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
        off+=2
    for lo,hi in ((context['root'],context['decision']+12),(context['normal'],context['normal']+0x40)):
        for pc in range(lo,hi,4):
            op=_word(image,pc)
            if op&0x0fff0000==0x059f0000:
                pool=pc+8+(op&4095);_word(image,pool);pools.append((pool,pool+4))
    for index,copy in enumerate(context['copies']):
        pools.append((copy.table_offset,copy.table_offset+(20 if index<3 else 12)))
    _need(not any(lo<pool_end and pool<hi for pool,pool_end in pools for lo,hi in code),'guard-pool-code-overlap')
    data=[(dsrc,dsrc+0x38),(sense_table,sense_table+8),(event_table,event_table+30),
          (shifts,shifts+24),(consumer['press_map'],consumer['press_map']+124),
          (consumer['release_map'],consumer['release_map']+124)]+[(at,at+12)for at in row_sources]
    _need(not any(lo<hi2 and lo2<hi for lo,hi in data for lo2,hi2 in code),'table-code-overlap')
    return dict(grammar='descriptor-row734-low5-6x5-v1',family='descriptor-row734-byte-ring32-v1',
        admission='temporary-evidence-gated',descriptor_pointer=descriptor,descriptor_source=dsrc,
        presence_sites=[single+meta['presence'],multi+0x82],row_sense_sites=[single+meta['sense'],multi+0xc4],
        boot_sense_site=boot['read_pc'],rows=6,columns=5,no_key=31,senses=senses,
        row_values=row_values,row_tables=list(row_tables),row_mask=0x9f,row_output=0x03000728,
        row_select=0x03000734,sense_address=0x0300072c,event_table=event_table,event_codes=events,
        provisional_mappings=mappings,dispatcher=dispatch,single_scanner=single,multi_scanner=multi,
        single_form=form,timer=timer,consumer=consumer,
        boot_source={name:boot[name]for name in ('signature','root','normal_entry','predicate_entry','initialization_entry')},
        boot_guard_intervals=[[entry['address'],entry['address']+len(entry['hex'])//2]for entry in boot['expected_code']],
        auxiliary_status=dict(address=0x03000720,width=2,mask=4,level=4,physical_identity='unverified'),
        timing='unverified',key_state=key_state,
        runtime_controller_guards=dict(descriptor_fields=expected,row_tables=list(row_tables),row_values=row_values,
            preserve_input_upper_bits=True,preserve_all_control_writes=True,UI_mode_gates_contacts=False),
        code_intervals=[list(p)for p in sorted(set(code))],
        literal_intervals=[list(p)for p in sorted(set(pools))],data_intervals=[list(p)for p in data],
        semantic_limit='Numeric-only provisional mappings; secondary repack/UI response and physical aux identity/timing unclassified')


def find_row734_input_profile(image:bytes,ram_base:int,ram_size:int,load_address:int=0):
    if not isinstance(image,bytes)or any(type(v)is not int for v in(ram_base,ram_size,load_address))or load_address!=0 or ram_base<0 or ram_size<=0 or ram_base+ram_size>0x100000000:
        return None,'row734-layout-unverified'
    try:
        context=_normal_copy(image,ram_base,ram_size)
        boot,reason=find_boot_contact_profile(image)
        _need(boot is not None,'boot-contact-'+reason)
        _need(boot['normal_entry']==context['normal']and boot['root']==context['root']
              and boot['address']==0x0300072c and boot['mask']==31,'boot-normal-link')
    except _Unclosed as error:return None,'row734-'+str(error)
    profiles=[];reasons=[]
    for dispatch in _find(image,'dispatch'):
        try:profiles.append(_at(image,dispatch,context,boot,ram_base,ram_size))
        except _Unclosed as error:reasons.append(str(error))
    if len(profiles)>1:return None,'row734-profiles-ambiguous'
    if profiles:return profiles[0],'accepted'
    return None,'row734-'+(reasons[0]if len(reasons)==1 else'candidates-unclosed'if reasons else'not-found')
