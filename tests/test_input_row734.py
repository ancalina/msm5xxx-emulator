"""Synthetic source graphs plus two private supplied-image controls. No VM."""
from pathlib import Path
import hashlib
import os
import struct
import unittest
from msm5xxx_emulator.detection import input_row734 as module
from msm5xxx_emulator.detection.protected_nor import _MASKS as COPY_MASKS
from corpus import FIRMWARE_ROOT

# Reuse the reviewed portable boot-contact fixture, not an original dump.
_BOOT_CHUNKS = [(304,
  '24429fe5010014e320e29f1520e29f0514ff2fe17847000018429fe5010014e314e29f1514e29f0514ff2fe1784700000c429fe5010014e308e29f1508e29f0514ff2fe178470000d7f021e3a4d19fe5dbf021e3f4d19fe5d3f021e3f0d19fe5f0419fe5010014e3ece19f15ece19f0514ff2fe178470000e4419fe5010014e3e0e19f15e0e19f0514ff2fe178470000d8419fe5010014e3d4e19f15d4e19f0514ff2fe178470000000050e30300001ac63f00ead3f021e394d19fe578470000d3f021e388d19fe5ac419fe5010014e3a8e19f15a8e19f0514ff2fe1784700001eff2fe1'),
 (808, '64f28701'),
 (860, '5d0b0000'),
 (864, '45010000'),
 (868, '48010000'),
 (872, '410a0000'),
 (876, '5d010000'),
 (880, '60010000'),
 (884, '7d0a0000'),
 (888, '75010000'),
 (892, '78010000'),
 (896, '64f38701'),
 (900, 'd4f08701'),
 (904, '850b0000'),
 (908, 'a5010000'),
 (912, 'a8010000'),
 (916, 'e1070000'),
 (920, 'bd010000'),
 (924, 'c0010000'),
 (928, '150c0000'),
 (932, 'd5010000'),
 (936, 'd8010000'),
 (940, 'a11a0000'),
 (944, '0d020000'),
 (948, '10020000'),
 (2016, '80b4'),
 (2624, '0420'),
 (2684,
  '0020c1002f4a515800290bd0c10089188988c2002b4b9a581180411c0904090c081ceee704210922d205117000211171082111728321c901234a91810021234a11811180224a11731f4ad03a11721e4aa03a11731c4a11801b4a203211801b4ac03a11800121490391810021194a918211831949118091800021164a20329180118191811449134a11819181118203210d4a50321171fd21117001210b4aa03a11720a4ae03a11700021117000200b4b984200db04e0411c0904090c081cf6e77047'),
 (2880, '04280000'),
 (2884, '00060003'),
 (2888, 'e0070003'),
 (2892, 'f0040003'),
 (2896, '800c0003'),
 (2900, 'ffff0000'),
 (2904, 'ac0d0000'),
 (2908, '7047'),
 (2948, '0948'),
 (2996,
  '9fb4164902a80cc90cc001221204002103290cda04e04b1c1b041b0c191cf7e71388971c3a1c4f006c46e353f3e70120002103290eda04e04b1c1b041b0c191cf7e74b006f46fb5a4f0002ace75bbb42f2d0002004b090bc7047'),
 (3088, '24280000'),
 (3092,
  '80b50027fff7ccff3c4908703b480078002803d1012080bc08bc18470020384b18810022052a00db66e004e0501c0004000c021cf6e71f20314b98820620314b18802f488089c106c90e1f2901d10020e1e700202a4b1881012098820620294b18802748808904210140dfd1002f07d0012f12d0022f1dd0032f00d034e026e004201f4b988206201e4b18801c4880890821014028d1012726e00420184b98820620184b188016488089102101401bd1022719e00220124b98820620114b18800f488089082101400ed103270ce002200b4b988206200b4b1880094880891021014001d1012096e700220120044b203b18700020187099e700208ce7'),
 (3344, '00f08701'),
 (3348, '20070003'),
 (3352, '20008004'),
 (6816, '80b5'),
 (10244, 'a00080040600000038070003fe0700003c0700030020000000000000000000006d6f64656c200000'),
 (65792,
  'd2f021e388d09fe5dff021e384d09fe5d1f021e30dd02de07cd09fe5d3f021e378009fe5010010e374e09f1574e09f0510ff2fe1784700006c209fe512ff2fe1'),
 (65940, '7cf58701'),
 (65944, '7cf98701'),
 (65948, '2cfa8701'),
 (65952, 'c9b90500'),
 (65956, '35010100'),
 (65960, '38010100'),
 (65964, '15f50e00')]


def fixture(filtered=False,shift=0,ram_delta=0):
    data=bytearray(0x80000+shift)
    def h(at,value):struct.pack_into('<H',data,at,value)
    def w(at,value):struct.pack_into('<I',data,at,value)
    def bl(at,target):
        d=target-at-4;struct.pack_into('<HH',data,at,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
    for at,hexdata in _BOOT_CHUNKS:
        blob=bytes.fromhex(hexdata);data[at+shift:at+shift+len(blob)]=blob
        if len(blob)==4:
            value=int.from_bytes(blob,'little')
            if 0<value<0x20000 and value not in(0xdac,0xffff):w(at+shift,value+shift)
    w(0,0xea000000|((0x130+shift-8)//4));data[0x10000:0x10006]=b'model '
    pos={name:at+shift for name,at in dict(copy=0x11000,dispatch=0x12000,single=0x13000,
        multi=0x14000,init=0x15000,timer_init=0x16000,timer_reg=0x16100,timer_core=0x16200,
        timer_insert=0x16300,timer_remove=0x16400,timer_flag_init=0x16500,forward=0x17000,
        setter=0x17100,register_api=0x17200,register_window=0x17300,callback=0x18000,
        store=0x180b4 if filtered else 0x180b0,success=0x181a8 if filtered else 0x1818a,
        dequeue=0x19000,bitmap=0x1a000,gate=0x1b000,delay=0x1b800,
        press_map=0x1c000,event_table=0x1c200,shifts=0x1c300,
        save=0x1e000,restore=0x1e040,set_sigs=0x1e080,clear_sigs=0x1e082,
        stub=0x1e100,copy_tables=0x30000,copy_data=0x40000,descriptor_source=0x44000).items()}
    ram=0x01000000+ram_delta;descriptor=0x014fcefc+ram_delta
    pos.update(ram=ram,descriptor=descriptor,key_state=ram+0x300,callback_box=ram+0x600,
               ring=ram+0x7000,timer=ram+0x5000)
    normal=0x10100+shift
    for off,target in ((0x20,pos['copy']+1),(0x38,pos['init']+1)):
        pc=normal+off;op=struct.unpack_from('<I',data,pc)[0];w(pc+8+(op&4095),target)
    role_keys={name:name for name in ('dispatch','single','multi','timer_init','timer_reg','timer_core',
        'timer_insert','timer_remove','timer_flag_init','forward','setter','register_api','register_window',
        'callback','store','success','dequeue','bitmap','gate','delay')}
    if filtered:role_keys.update(single='single_filtered',callback='callback_shifted')
    literal_pools={};next_pool={}
    def literal(role,off,value):
        key=role,off;at=pos[role]+off
        if key not in literal_pools:
            pool=next_pool.setdefault(role,(pos[role]+(0x340 if role=='single' else 0x2c0 if role=='multi'else 0x280)+3)&~3)
            next_pool[role]=pool+4;literal_pools[key]=pool
        pool=literal_pools[key];op=struct.unpack_from('<H',data,at)[0]
        assert 0<=pool-((at+4)&~3)<=1020,(role,off)
        h(at,0x4800|(op&0x700)|((pool-((at+4)&~3))//4));w(pool,value)
    for role,key in role_keys.items():
        pattern,literals,calls=module._SPECS[key];blob=bytes.fromhex(pattern)
        data[pos[role]:pos[role]+len(blob)]=blob
        for off in calls:bl(pos[role]+off,pos['stub'])
        for off in literals:literal(role,off,ram+0xa00)
    # Shared copier and IRQ primitives are already tested production dependencies.
    mask=COPY_MASKS['copy'];data[pos['copy']:pos['copy']+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
    off=0
    while off<len(mask)//2:
        if mask[off*2:off*2+8]=='????????':bl(pos['copy']+off,pos['stub']);off+=4;continue
        op=struct.unpack_from('<H',data,pos['copy']+off)[0]
        if op&0xf800==0x4800:literal('copy',off,ram+0xa00)
        off+=2
    for role in ('save','restore'):
        blob=bytes.fromhex(COPY_MASKS['irq_'+role]);data[pos[role]:pos[role]+len(blob)]=blob
    for role in ('set_sigs','clear_sigs','stub'):h(pos[role],0x4770)
    t=pos['copy_tables'];source=pos['copy_data']
    tuples=[(source,ram,0x2000,ram+0x2000,0x6000),
            (0x42000+shift,ram+0x10000,0x1000,ram+0x11000,0x1000),
            (pos['descriptor_source'],descriptor,0x8c,descriptor+0x8c,4),
            (0x45000+shift,0x03800000,0x100,0,0)]
    for i,values in enumerate(tuples):struct.pack_into('<5I',data,t+i*0x20,*values)
    literal('copy',0,0x03000700);literal('copy',0xd6,0x048000a0)
    for off,value in ((0xc,t+4),(0xe,t+8),(0x16,t),(0x38,t+12),(0x3a,t+16)):
        literal('copy',off,value)
    for i,offs in ((1,(0x56,0x58,0x60,0x7c,0x7e)),(2,(0x96,0x98,0xa0,0xbc,0xbe))):
        for off,value in zip(offs,(t+i*0x20+4,t+i*0x20+8,t+i*0x20,t+i*0x20+12,t+i*0x20+16)):
            literal('copy',off,value)
    for off,value in ((0xda,t+0x64),(0xdc,t+0x68),(0xe4,t+0x60)):literal('copy',off,value)
    fields={0:0x3000720,4:0x3000720,8:0x300072c,0xc:0x20000000,0x10:0x3000724,
            0x14:0x3000724,0x18:0x3000730,0x20:0x3000728,0x24:0x3000728,
            0x28:0x3000734,0x34:0x300072c}
    for off,value in fields.items():w(pos['descriptor_source']+off,value)
    key=pos['key_state'];rows=[1,2,4,8,16,128]
    for offset in (0xc,0x1a):struct.pack_into('<6H',data,source+key-ram+offset,*rows)
    data[source+key-ram+0x18]=4
    senses=[30,29,27,23,15];sense_table=pos['event_table']+0x24
    data[sense_table:sense_table+8]=bytes(senses+[0,0,0])
    table=[0]*30
    for event,column,row in zip(b'123456789*0#',[2,3,4,2,3,4,2,3,4,2,3,4],[1,1,1,2,2,2,3,3,3,4,4,4]):table[column*6+row]=event
    data[pos['event_table']:pos['event_table']+30]=bytes(table)
    release=pos['press_map']+0x94
    for column in range(5):
        for row in range(6):w(pos['press_map']+4*(row*5+column),table[column*6+row])
    struct.pack_into('<6I',data,pos['shifts'],0,5,10,15,20,25)
    single_key=role_keys['single'];meta=module._SINGLE[single_key]
    literal('single',meta['descriptor'][0],descriptor);literal('single',meta['key_state'][0],key)
    literal('single',2,sense_table);literal('single',meta['row'],key)
    literal('single',meta['event'],sense_table)
    literal('multi',2,key);literal('multi',0x58,descriptor);literal('multi',0x9e,key);literal('multi',0xca,pos['shifts'])
    for role,meta_ in (('single',meta),('multi',module._SINGLE['multi'])):
        for link,offs in meta_['links'].items():
            for off in offs:bl(pos[role]+off,pos[link])
    bl(pos['single']+meta['delay'],pos['delay']);bl(pos['multi']+0xbe,pos['delay'])
    for off,(reg,_)in module._SPECS['delay'][1].items():
        if reg==7:literal('delay',off,0x04800020)
    literal('bitmap',6,key);literal('bitmap',0xa,release);literal('bitmap',0x18,release)
    bl(pos['bitmap']+0x2a,pos['forward'])
    for off,role in ((2,'gate'),(0xa,'multi'),(0x12,'single')):bl(pos['dispatch']+off,pos[role])
    # Normal callback registration and both byte-preserving stores; UI mode is not a device gate.
    box=pos['callback_box'];enable=box+0x21
    literal('forward',4,enable);literal('forward',8,box)
    literal('setter',0,enable);literal('setter',0xa,box);bl(pos['register_api']+0x1c,pos['setter'])
    literal('register_window',4,pos['callback']+1);bl(pos['register_window']+0xa,pos['register_api'])
    bl(pos['callback']+2,pos['save']);literal('callback',0x20 if filtered else 0x1a,pos['ring'])
    literal('dequeue',0,pos['ring']);bl(pos['success']+4,pos['restore']);bl(pos['success']+0xc,pos['set_sigs'])
    branch=pos['store']+0x14;tail=pos['callback']+(0x19e if filtered else 0x18a)
    h(branch,0xe000|((tail-branch-4)//2&2047))
    if filtered:h(tail,0xe000|((pos['success']-tail-4)//2&2047))
    # Clock API ownership and 25/25 repeating timer source constructor.
    bl(pos['timer_init']+0x14,pos['timer_flag_init']);bl(pos['timer_reg']+0x12,pos['timer_core'])
    for off,role in ((0x30,'save'),(0x5c,'restore'),(0x3c,'timer_remove'),(0x52,'timer_insert')):
        bl(pos['timer_core']+off,pos[role])
    init=pos['init'];h(init,0xb5f8)
    h(init+2,0x4f00|((init+0x200-((init+6)&~3))//4));w(init+0x200,descriptor)
    block=init+8;blob=bytes.fromhex(module._SPECS['init_rows'][0]);data[block:block+len(blob)]=blob
    for off,role in ((0,'save'),(0x16,'restore'),(0x1a,'save'),(0x30,'restore')):bl(block+off,pos[role])
    clock=init+0x60
    h(clock,0x4c00|((init+0x204-((clock+4)&~3))//4));w(init+0x204,pos['timer'])
    h(clock+2,0x1c20);bl(clock+4,pos['timer_init']);h(clock+8,0x2201);h(clock+10,0x9200)
    h(clock+12,0x2219);h(clock+14,0x2319);h(clock+16,0x1c20)
    h(clock+18,0x4900|((init+0x208-((clock+22)&~3))//4));w(init+0x208,pos['dispatch']+1)
    bl(clock+20,pos['timer_reg']);data[clock+24:clock+30]=bytes.fromhex('f8bc08bc1847')
    pos.update(clock=clock,row_init=block,sense_table=sense_table,literal_pools=literal_pools,filtered=filtered)
    return bytes(data),pos


class Row734Tests(unittest.TestCase):
    def detect(self,data):return module.find_row734_input_profile(data,0x01000000,0x01000000)
    def test_two_forms_and_relocation(self):
        for filtered,shift,ram in ((False,0,0),(True,0,0),(False,0x400,0x10000),(True,0x1000,0x20000)):
            with self.subTest(filtered=filtered,shift=shift):
                data,p=fixture(filtered,shift,ram);profile,reason=self.detect(data)
                self.assertIsNotNone(profile,reason)
                self.assertEqual(profile['grammar'],'descriptor-row734-low5-6x5-v1')
                self.assertEqual(profile['provisional_mappings'][11]['event'],49)
                self.assertEqual((profile['provisional_mappings'][11]['row'],profile['provisional_mappings'][11]['sense']),(1,27))
                self.assertEqual(set(profile['provisional_mappings']),set(range(11,23)))
                self.assertFalse(profile['runtime_controller_guards']['UI_mode_gates_contacts'])
    def test_mutations(self):
        data,p=fixture()
        cases=(('dispatch-call',p['dispatch']+0x13,0),('row-width',p['single']+0xcb,0x70),
               ('sense-mask',p['single']+0xdf,0x07),('bitmap-call',p['multi']+0x191,0),
               ('row-init-mask',p['row_init']+6,0x1f),('timer-repeat',p['clock']+8,0),
               ('timer-period',p['clock']+12,24),('callback-call',p['register_api']+0x1d,0))
        for name,at,value in cases:
            with self.subTest(name=name):
                changed=bytearray(data);self.assertNotEqual(changed[at],value);changed[at]=value
                self.assertIsNone(self.detect(bytes(changed))[0])
    def test_tables_descriptor_copy_and_partial(self):
        data,p=fixture()
        for name,at,value in (('row-table',p['copy_data']+0x30c,2),
                              ('descriptor',p['descriptor_source']+0x34,0x03000720),
                              ('copy-zero',p['copy_tables']+12,p['key_state'])):
            changed=bytearray(data)
            if name=='row-table':struct.pack_into('<H',changed,at,value)
            else:struct.pack_into('<I',changed,at,value)
            self.assertIsNone(self.detect(bytes(changed))[0],name)
        changed=bytearray(data);changed[p['event_table']+13]=ord('2')
        self.assertIsNone(self.detect(bytes(changed))[0])
        for end in (0,0x100,p['copy_data']+0x1fff,p['descriptor_source']+0x8b):
            self.assertIsNone(self.detect(data[:end])[0])
        self.assertIsNone(module.find_row734_input_profile(data,0x1000000,0x1000000,4)[0])
    def test_complete_duplicate_and_partial_decoy(self):
        data,p=fixture();changed=bytearray(data);dispatch=0x25000;init=0x26000
        def bl(at,target):
            d=target-at-4
            struct.pack_into('<HH',changed,at,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
        changed[dispatch:dispatch+0x18]=changed[p['dispatch']:p['dispatch']+0x18]
        for off,role in ((2,'gate'),(0xa,'multi'),(0x12,'single')):bl(dispatch+off,p[role])
        changed[init:init+0x7e]=changed[p['init']:p['init']+0x7e]
        changed[init+0x200:init+0x20c]=changed[p['init']+0x200:p['init']+0x20c]
        struct.pack_into('<I',changed,init+0x208,dispatch+1)
        for off,role in ((0,'save'),(0x16,'restore'),(0x1a,'save'),(0x30,'restore')):
            bl(init+8+off,p[role])
        bl(init+0x64,p['timer_init']);bl(init+0x74,p['timer_reg'])
        profile,reason=self.detect(bytes(changed))
        self.assertIsNone(profile);self.assertIn('ambiguous',reason)
        # A still literal-valid but unclosed dispatcher must not hide the first profile.
        bl(dispatch+0x12,p['stub'])
        self.assertIsNotNone(self.detect(bytes(changed))[0])

    def test_boot_link_and_foreign_call(self):
        data,p=fixture();changed=bytearray(data)
        profile,reason=self.detect(data);self.assertIsNotNone(profile,reason)
        struct.pack_into('<H',changed,profile['boot_sense_site'],0x8800)
        self.assertIsNone(self.detect(bytes(changed))[0])
        changed=bytearray(data);at=p['multi']+module._SINGLE['multi']['links']['bitmap'][0]
        d=p['stub']-at-4
        struct.pack_into('<HH',changed,at,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
        self.assertIsNone(self.detect(bytes(changed))[0])

    def test_zero_pointer_provenance_dependency(self):
        data,p=fixture()
        for offsets in ((0x38,0x3a),(0x7c,0x7e),(0xbc,0xbe)):
            changed=bytearray(data);foreign=0x70000
            struct.pack_into('<II',changed,foreign,p['key_state'],4)
            for off,value in zip(offsets,(foreign,foreign+4)):
                pool=p['literal_pools']['copy',off]
                struct.pack_into('<I',changed,pool,value)
            profile,reason=self.detect(bytes(changed))
            self.assertIsNone(profile);self.assertIn('zero-tuple',reason)

    def test_actual_two_originals(self):
        root=FIRMWARE_ROOT / 'incoming-20260719-r1/MSM5100'
        for name,sha in [('SCP-4900_1.059SP_JTAG.bin','6ff77b7f6a2933c227a1097043ffa162d4b693fd9e9d2890a40f2375b600111e'),('SCP-7200_2.046SP_JTAG.bin','72486e9a0b3bac598adee2913405ad287a65880bc896816f69453131fe949714')]:
            with self.subTest(name=name):
                path=root/name
                if not path.is_file(): self.skipTest('optional original firmware witnesses unavailable')
                before=path.stat();image=path.read_bytes()
                self.assertEqual(hashlib.sha256(image).hexdigest(),sha)
                profile,reason=self.detect(image);self.assertIsNotNone(profile,reason)
                self.assertEqual(profile['provisional_mappings'][11]['row'],1)
                after=path.stat();self.assertEqual((before.st_size,before.st_mtime_ns),(after.st_size,after.st_mtime_ns))

if __name__=='__main__':unittest.main()
