"""Portable complete bank/copy compiler fixture; no original firmware dependency."""
import struct
import unittest
from msm5xxx_emulator.detection.amd_bank import (
    _SPEC, _ROOT, _MOVE, _FORWARD, _ALIGNED, _STATE_REFS, find_amd_bank_profile,
)


def fixture(shift=0, ram_shift=0, ids=(0x98,0x95), count=3, sector=0x10000):
    image=bytearray(0x80000+shift)
    roles={role:0x1000+i*0x1000+shift for i,role in enumerate(_SPEC)}
    r=0x200+shift;obj=0x10000+shift;tables=0x14000+shift;src=0x18000+shift
    lib,forward,aligned=(v+shift for v in (0x11000,0x11200,0x11400))
    thunk,stub=(v+shift for v in (0x12000,0x12010))
    ram=0x01000000+ram_shift;base=ram+0x3000;global_=ram+0x100
    probe_table=ram+0x104;active=ram+0x108
    data={'root':r,'object':obj,'tables':tables,'source':src,'base':base,'global':global_,
          'probe_table':probe_table,'active':active,'lib':lib,'logical':0x40000,'ram':ram}
    put=lambda at,value:struct.pack_into('<I',image,at,value)
    def bl(at,target):
        delta=target-at-4
        struct.pack_into('<HH',image,at,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
    def literal(at,reg,pool,value):
        delta=pool-((at+4)&~3);assert 0<=delta<=1020 and not delta&3
        struct.pack_into('<H',image,at,0x4800|reg<<8|delta//4);put(pool,value)
    cp={2:0x03000700,0xa:tables+4,0xe:tables+8,0x16:tables,0x1c:tables+4,
        0x3a:0x03000700,0x42:tables+12,0x46:tables+16,0x4e:tables+12,
        0x68:0x03000700,0x70:tables+0x24,0x74:tables+0x28,0x7c:tables+0x20,0x82:tables+0x24,
        0xa0:0x03000700,0xa8:tables+0x2c,0xac:tables+0x30,0xb4:tables+0x2c,
        0xd0:0x03000700,0xdc:0x03000700,0xe4:tables+0x44,0xe8:tables+0x48,
        0xf0:tables+0x40,0xf6:tables+0x44,0x114:0x03000700}
    addresses={'base':base,'mode':base+4,'operation':base+8,'object':global_}
    values={'copy':cp,'init':{2:base,6:global_,30:0x15000+shift},
            'ramtest':{0:0x2e,8:base},'lookup':{2:probe_table},
            'probe':{0:obj+0x80,4:base,0x34:active}}
    for role,refs in _STATE_REFS.items():
        values[role]={off:addresses[kind] for off,kind in refs.items()}
    values['program'].update({0xc2:ram+0x4000,0x130:ram+0x4000})
    values['erase'][0x20]=0x15000+shift
    values['poll'].update({0x2e:ram+0x4004,0x3a:0x15000+shift})
    values['suspend'].update({0x18:ram+0x4000,0x42:0xffff})
    links={'init':{14:roles['ramtest'],22:roles['lookup'],36:stub,46:stub+4,
                   56:thunk,64:stub,74:stub+4},'lookup':{10:thunk},'read':{46:lib},
           'program':{off:roles['irq_save'] if off in (0x3a,0xb0,0x11c) else roles['irq_restore']
                      for off in _SPEC['program'][1]},'erase':{28:stub,36:stub+4},'poll':{60:stub+8}}
    for role,(pattern,calls,literals) in _SPEC.items():
        at=roles[role];image[at:at+len(pattern)]=pattern;pool=at+((len(pattern)+15)&~3)
        for off,reg in literals:literal(at+off,reg,pool,values[role][off]);pool+=4
        for off in calls:bl(at+off,links[role][off])
    image[r:r+len(_ROOT)]=_ROOT;rootpool=r+0x300
    for off in range(0,len(_ROOT),4):
        op=struct.unpack_from('<I',_ROOT,off)[0]
        if op&0x0f7f0000!=0x051f0000:continue
        pc=r+off
        if off in (0x6c,0x74,0x7c):value=ram+0xa100
        else:
            group=next(g for g in (0,0x18,0x30,0x48,0x80,0x98)if off in (g,g+8,g+12))
            if off==group:value=roles['copy']|1 if group==0x80 else stub|1
            else:value=r+group+(21 if off==group+8 else 24)
        put(pc,(op&0xfffff000)|(rootpool-pc-8));put(rootpool,value);rootpool+=4
    put(0,0xea000000|((r-8)//4))
    tuples=((0x1a000+shift,ram+0xa000,8,ram+0xa008,0x100),
            (src,ram,0x2000,ram+0x2000,0x8000),(0x1a008+shift,0x03800000,0x100))
    for i,tup in enumerate(tuples):struct.pack_into('<'+'I'*len(tup),image,tables+i*0x20,*tup)
    put(src+0x100,0);put(src+0x104,roles['probe']|1);put(src+0x108,obj);put(src+0x10c,0)
    put(obj,0x15000+shift);put(obj+4,count)
    for i in range(count):put(obj+8+4*i,sector)
    struct.pack_into('<HH',image,obj+0x84,*ids);put(obj+0x88,0);put(obj+0x8c,1)
    put(obj+0x90,0x40000//2);put(obj+0x94,count*sector//2)
    for off,role in ((0x98,'reset'),(0x9c,'read'),(0xa0,'program'),(0xa4,'erase'),
                     (0xa8,'poll'),(0xac,'suspend'),(0xb0,'resume')):put(obj+off,roles[role]|1)
    for i,off in enumerate((0xb4,0xb8,0xbc)):put(obj+off,stub+0x20+4*i|1)
    image[thunk:thunk+2]=bytes.fromhex('0047')
    image[lib:lib+len(_MOVE)]=_MOVE
    image[forward:forward+len(_FORWARD)]=_FORWARD;image[aligned:aligned+len(_ALIGNED)]=_ALIGNED
    for off,condition,target in ((12,0x2a,forward),(24,0x0a,aligned)):
        put(lib+off,condition<<24|((target-lib-off-8)//4&0xffffff))
    return image,roles,data


def literal_change(image,pc,value):
    op=struct.unpack_from('<H',image,pc)[0];pool=((pc+4)&~3)+(op&255)*4
    struct.pack_into('<I',image,pool,value)


class AmdBankTests(unittest.TestCase):
    def detect(self,image,**kw):
        return find_amd_bank_profile(image,kw.get('load',0),kw.get('flash',len(image)),0x01000000,0x100000)

    def test_complete_relocated_and_derived_ids_geometry(self):
        for shift,ramshift,ids,count,sector in ((0,0,(0x98,0x95),3,0x10000),
                (0x4000,0x10000,(0xab,0x1234),4,0x4000)):
            image,roles,data=fixture(shift,ramshift,ids,count,sector);before=bytes(image)
            profile,why=self.detect(image);self.assertIsNotNone(profile,why)
            self.assertEqual((profile['base'],profile['size'],profile['sector_size']),(0x40000,count*sector,sector))
            self.assertEqual((profile['id0'],profile['id1']),ids)
            self.assertEqual(profile['object'],data['object']);self.assertEqual(profile['methods']['probe'],roles['probe'])
            self.assertEqual(len(profile['copy_layouts']),3);self.assertEqual(len(profile['zero_ranges']),2)
            self.assertIsNone(profile['physical_part']);self.assertEqual(bytes(image),before)

    def test_nv_mutation_ignored_but_code_and_object_mutation_not(self):
        image,_,data=fixture();profile,_=self.detect(image)
        image[data['logical']:data['logical']+profile['size']]=b'\xa5'*profile['size']
        self.assertEqual(self.detect(image)[0],profile)
        struct.pack_into('<H',image,data['object']+0x84,0x99)
        changed,_=self.detect(image);self.assertNotEqual(changed,profile)

    def test_typed_width_call_loop_and_root_mutations(self):
        changes=(('probe',0x10,0x7053),('probe',0x28,0x7802),('probe',0x22,0x2354),
                 ('probe',0x32,0x7001),('program',0xb8,0x7031),('erase',0x5a,0x277f),
                 ('read',0xe,0x00a4),('copy',0x94,0x7020))
        for role,off,value in changes:
            image,roles,_=fixture();struct.pack_into('<H',image,roles[role]+off,value)
            self.assertIsNone(self.detect(image)[0],(role,off))
        image,_,data=fixture();image[data['root']+0x64]^=1;self.assertIsNone(self.detect(image)[0])

    def test_copied_selection_globals_zero_and_geometry_rejects(self):
        for case in range(9):
            image,roles,data=fixture();obj=data['object'];src=data['source'];table=data['tables']
            if case==0:struct.pack_into('<I',image,src+0x10c,obj)
            if case==1:struct.pack_into('<I',image,src+0x104,roles['erase']|1)
            if case==2:literal_change(image,roles['probe'],obj+0x84)
            if case==3:literal_change(image,roles['program']+0x3e,data['global']+4)
            if case==4:literal_change(image,roles['copy']+0xa8,table+0x24)
            if case==5:struct.pack_into('<I',image,table+0xc,data['probe_table'])
            if case==6:struct.pack_into('<I',image,obj+0x94,1)
            if case==7:struct.pack_into('<I',image,obj+4,32)
            if case==8:struct.pack_into('<I',image,obj+8,0x10001)
            self.assertIsNone(self.detect(image)[0],case)

    def test_initializer_cannot_clear_its_copied_probe_table(self):
        image,roles,data=fixture();newbase=data['probe_table']
        for role,off in (('init',2),('ramtest',8),('probe',4)):
            literal_change(image,roles[role]+off,newbase)
        for role,refs in _STATE_REFS.items():
            for off,kind in refs.items():
                if kind in ('base','mode','operation'):
                    literal_change(image,roles[role]+off,newbase+{'base':0,'mode':4,'operation':8}[kind])
        profile,reason=self.detect(image)
        self.assertIsNone(profile);self.assertIn('initializer-metadata-alias',reason)

    def test_duplicate_complete_and_partial_decoy(self):
        image,roles,_=fixture();new=0x13000;old=roles['init'];pattern,calls,lits=_SPEC['init']
        image[new:new+len(pattern)]=image[old:old+len(pattern)];pool=new+0x100
        for off,reg in lits:
            op=struct.unpack_from('<H',image,old+off)[0];value=struct.unpack_from('<I',image,((old+off+4)&~3)+(op&255)*4)[0]
            struct.pack_into('<H',image,new+off,0x4800|reg<<8|(pool-((new+off+4)&~3))//4)
            struct.pack_into('<I',image,pool,value);pool+=4
        from msm5xxx_emulator.detection.arm import thumb_bl_target
        for off in calls:
            target=thumb_bl_target(image,old+off);delta=target-new-off-4
            struct.pack_into('<HH',image,new+off,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
        self.assertEqual(self.detect(image)[1],'amd-bank-profile-ambiguous')
        image[new+14]^=1;self.assertIsNotNone(self.detect(image)[0])

    def test_call_family_and_copied_table_bounds(self):
        for kind in range(3):
            image,roles,data=fixture()
            if kind==0:
                site=roles['program']+0x3a;target=roles['irq_restore'];delta=target-site-4
                struct.pack_into('<HH',image,site,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
            if kind==1:literal_change(image,roles['lookup']+2,data['ram']+0x9000)
            if kind==2:struct.pack_into('<I',image,data['source']+0x108,data['object']+4)
            self.assertIsNone(self.detect(image)[0])
        image,_,_=fixture();profile,_=self.detect(image);extent=len(image)
        image.extend(b'\xff'*0x10000)
        self.assertEqual(self.detect(image,flash=extent)[0],profile)

    def test_layout_bounds_partial_and_foreign_bank(self):
        image,_,data=fixture()
        self.assertIsNone(self.detect(image,load=4)[0]);self.assertIsNone(self.detect(image,flash=0x60000)[0])
        for end in (0,0x2af,data['object']+0xbf,data['source']+0x1fff,0x6ffff):
            self.assertIsNone(self.detect(image[:end])[0])
        struct.pack_into('<I',image,data['object']+0x90,0x1000//2)
        self.assertIsNone(self.detect(image)[0])


if __name__=='__main__':unittest.main()
