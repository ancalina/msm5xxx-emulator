"""Portable complete source groups, not filename-selected display behavior."""
import hashlib,json,os,struct,unittest
from pathlib import Path
from msm5xxx_emulator.detection import copied_window as m


def fixture(shift=0,ram_shift=0):
    b=bytearray(0x20000+shift);ram=0x1000000+ram_shift
    sites={role:at+shift for role,at in dict(reset=0x1000,copy=0x3000,init=0x4000,command=0x5000,delay=0x5100,command_wrapper=0x5200,init_wrapper=0x5300,off=0x5400,on=0x5500,power=0x5600,contrast=0x5700,logo=0x6000,fill=0x6200,veneer=0x6300,blit_veneer=0x6400,iram_source=0x8000,full=0x9000,count=0x15000,asset=0x15100).items()}
    tables=[0x14000+shift,0x14020+shift,0x14040+shift]
    copies=[(0x12000+shift,ram+0x6000,0xc4,ram+0x60c4,0x3000),(0x10000+shift,ram,0x1000,ram+0x1000,0x5000),(sites['iram_source'],0x3800000,0x2000)]
    def w(at,v):struct.pack_into('<I',b,at,v)
    def h(at,v):struct.pack_into('<H',b,at,v)
    def bl(at,target):
        d=target-at-4;struct.pack_into('<HH',b,at,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
    def lit(at,reg,pool,value):h(at,0x4800|reg<<8|(pool-((at+4)&~3))//4);w(pool,value)
    def role(name,values=None,links=None):
        at=sites[name];pattern,calls,literals=m._SPEC[name];b[at:at+len(pattern)//2]=bytes.fromhex(pattern)
        for off in calls:bl(at+off,links[off])
        for i,(off,reg)in enumerate(literals):lit(at+off,reg,at+(0x100 if name=='logo' else 0x300)+i*4,values[off])
    b[sites['reset']:sites['reset']+len(m._RESET)]=m._RESET;pool=sites['reset']+0x500
    gates={0:sites['delay']|1,0x18:sites['delay']|1,0x30:sites['delay']|1,0x48:sites['delay']|1,0x80:sites['copy']|1}
    for off in range(0,len(m._RESET),4):
        op=struct.unpack_from('<I',m._RESET,off)[0]
        if op&0x0f7f0000!=0x051f0000:continue
        value=gates.get(off,ram+0xa000)
        for base in gates:
            if off==base+8:value=sites['reset']+base+21
            if off==base+12:value=sites['reset']+base+24
        w(sites['reset']+off,(op&0xfffff000)|(pool-sites['reset']-off-8));w(pool,value);pool+=4
    w(0,0xea000000|(((sites['reset']-8)>>2)&0xffffff))
    for table,values in zip(tables,copies):
        for i,v in enumerate(values):w(table+4*i,v)
    values={o:0x3000700 for o,_ in m._SPEC['copy'][2]}
    for table,ofs in zip(tables[:2],((0x16,0xa,0xe,0x1c,0x42,0x46,0x4e),(0x7c,0x70,0x74,0x82,0xa8,0xac,0xb4))):
        for off,n in zip(ofs,(0,4,8,4,12,16,12)):values[off]=table+n
    values.update({0xf0:tables[2],0xe4:tables[2]+4,0xf6:tables[2]+4,0xe8:tables[2]+8})
    role('copy',values,{})
    role('init',{}, {o:sites['delay']if o in(10,28,130)else sites['command']for o in m._SPEC['init'][1]})
    role('command',{},{});b[sites['delay']:sites['delay']+2]=b'\x70\x47'
    role('command_wrapper',{}, {2:sites['command']});role('init_wrapper',{}, {2:sites['init']})
    for name in('off','on','power','contrast'):role(name,{}, {o:sites['command_wrapper']for o in m._SPEC[name][1]})
    role('fill',{},{});context=ram+0x8000
    role('logo',{2:context,4:0xffff,26:sites['asset']},{8:sites['fill'],28:sites['blit_veneer'],34:sites['veneer']})
    full=sites['full'];runtime=0x3801000
    b[full:full+0x60]=m._FULL;w(full+0x60,sites['count']);b[full+0x64:full+0xe4]=m._PARTIAL;b[full+0xe4:full+0x154]=m._CONTIGUOUS
    w(sites['count'],0x4000)
    for name,target in(('veneer',runtime),('blit_veneer',0x3800100)):
        b[sites[name]:sites[name]+8]=m._VENEER;w(sites[name]+8,target)
    b[sites['iram_source']+0x100:sites['iram_source']+0x104]=bytes.fromhex('f04f2de9')
    sites.update(tables=tables,copies=copies,ram=ram,context=context)
    return bytes(b),sites


class CopiedWindowTests(unittest.TestCase):
    def test_complete_relocated_source_candidate(self):
        for shift,ram in((0,0),(0x400,0x10000)):
            image,s=fixture(shift,ram);p,why=m.find_copied_window_profile(image)
            self.assertIsNotNone(p,why);self.assertEqual((p['width'],p['height'],p['access_width']),(128,128,2))
            self.assertEqual(p['init_commands'],m._INIT_COMMANDS);self.assertEqual(p['after_clear_command'],0x51)
            self.assertEqual(p['opaque_control_sequences'],[[0x51],[0x2c,0x51],[0x50,0x2d],[0x50,0x2d,0x26,0,2,0]])
            self.assertEqual(p['full_entry'],0x3801000);self.assertIn('unproved',p['init_upper_caller'])
            for key in('code_intervals','literal_intervals','data_intervals','boot_guard_intervals','ram_intervals','iram_intervals'):self.assertTrue(p[key])
            self.assertTrue(all(0<=a<b<=len(image)for a,b in p['guard_intervals']))
    def test_critical_code_width_geometry_control_and_copy_mutations(self):
        image,s=fixture();cases=[]
        def half(at,v):cases.append((at,struct.pack('<H',v)))
        def word(at,v):cases.append((at,struct.pack('<I',v)))
        half(s['command']+4,0x8008);half(s['init']+0xbe,0x704a)
        half(s['init']+0x4a,0x2002);half(s['init']+0x62,0x2087);half(s['init']+0x6e,0x2001)
        half(s['init']+0xb0,0x2001);half(s['init']+0xa4,0x209f);half(s['copy']+0x34,0x6021)
        word(s['full']+0x48,0xe5cc2002);word(s['full']+0x14,0xe3a02001)
        word(s['full']+0x18,0xe5cc2000);word(s['full']+0x64+0x2c,0xe1a0c302)
        word(s['full']+0xe4+0x4c,0xe5d03000);word(s['count'],0x5000)
        word(s['tables'][0]+12,s['ram']+0x9000);word(s['tables'][1]+4,s['ram']+0x6000)
        word(s['tables'][2]+4,0x1000000);word(s['tables'][2]+8,0x1000)
        word(s['veneer']+8,0x3801004);word(s['blit_veneer']+8,0x3803000)
        word(s['reset']+0x84,0xe1a00000)
        for at,value in cases:
            altered=bytearray(image);altered[at:at+len(value)]=value
            with self.subTest(at=hex(at)):self.assertIsNone(m.find_copied_window_profile(bytes(altered))[0])
    def test_literal_owner_truncation_and_foreign_offset4(self):
        image,s=fixture()
        for role,index,value in(('logo',0,s['ram']+0x100),('logo',1,0),('logo',2,len(image)+4),('copy',3,s['tables'][0]+4)):
            changed=bytearray(image);struct.pack_into('<I',changed,s[role]+(0x100 if role=='logo' else 0x300)+index*4,value)
            self.assertIsNone(m.find_copied_window_profile(bytes(changed))[0])
        for end in(s['copy']+280,s['full']+0x150,s['count']+3):self.assertIsNone(m.find_copied_window_profile(image[:end])[0])
        changed=bytearray(image);struct.pack_into('<I',changed,s['full']+0x48,0xe1cc20b4)
        self.assertIsNone(m.find_copied_window_profile(bytes(changed))[0])
    def test_duplicate_complete_owned_groups_reject(self):
        image,s=fixture();b=bytearray(image);full=s['full']+0x800;b[full:full+0x154]=image[s['full']:s['full']+0x154]
        at=0x17000;old=s['logo'];pattern,calls,literals=m._SPEC['logo'];b[at:at+len(pattern)//2]=image[old:old+len(pattern)//2]
        veneer=0x17600;b[veneer:veneer+8]=m._VENEER;struct.pack_into('<I',b,veneer+8,0x3801800)
        from msm5xxx_emulator.detection.arm import thumb_bl_target
        for off in calls:
            target=veneer if off==34 else thumb_bl_target(image,old+off);d=target-at-off-4
            struct.pack_into('<HH',b,at+off,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
        for i,(off,reg)in enumerate(literals):
            op=struct.unpack_from('<H',image,old+off)[0];pool=((old+off+4)&~3)+(op&255)*4
            struct.pack_into('<H',b,at+off,0x4800|reg<<8|((at+0x300+4*i-((at+off+4)&~3))//4));b[at+0x300+4*i:at+0x304+4*i]=image[pool:pool+4]
        p,why=m.find_copied_window_profile(bytes(b));self.assertIsNone(p);self.assertIn('ambiguous',why)
    def test_actual_full_partial_and_BYTE_negative_controls(self):
        manifest_path=os.environ.get('MSM5XXX_TEST_COPIED_WINDOW_MANIFEST')
        if not manifest_path:self.skipTest('private provided corpus unavailable')
        manifest=Path(manifest_path)
        if not manifest.is_file():self.skipTest('private provided corpus unavailable')
        rows=json.loads(manifest.read_text())
        for i,row in enumerate(rows):
            path=Path(row['path'])
            if not path.exists():self.skipTest('private provided image unavailable')
            st=path.stat();image=path.read_bytes();self.assertEqual(hashlib.sha256(image).hexdigest(),row['sha256'])
            p,why=m.find_copied_window_profile(image)
            with self.subTest(sha=row['sha256']):
                self.assertEqual(p is not None,i>=2,why)
                if p:self.assertEqual(p['source_pcs']['init'],0x2894)
            self.assertEqual((st.st_size,st.st_mtime_ns),(path.stat().st_size,path.stat().st_mtime_ns))
