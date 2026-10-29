"""Synthetic closed compiler groups; no original firmware dependency or guest."""
import struct
import unittest

from msm5xxx_emulator.detection import mono_page as detector


def fixture(shift=0, ram_shift=0, image=None):
    if image is None: image=bytearray(0x20000)
    sites={name:at+shift for name,at in {'raster':0x1000,'column':0x2002,
        'clear':0x3002,'icon_clear':0x4000,'icons':0x5000,'init':0x6002,
        'fill':0x7000,'delay':0x8000,'stack':0x9000}.items()}
    for role,at in sites.items():
        pattern=getattr(detector,'_'+role.upper())
        image[at:at+len(pattern)]=pattern
    def call(at,target):
        delta=target-at-4
        struct.pack_into('<HH',image,at,0xF000|(delta>>12&0x7FF),0xF800|(delta>>1&0x7FF))
    def literal(at,value):
        ins=struct.unpack_from('<H',image,at)[0]
        pool=((at+4)&~3)+(ins&255)*4
        struct.pack_into('<I',image,pool,value)
    links={'raster':{6:'stack',0x5A:'column'},'clear':{6:'stack',0x12:'fill',0x26:'raster'},
           'icon_clear':{6:'stack',0x18:'column'},'icons':{o:'column' for o in detector._ICONS_CALLS},
           'init':{6:'stack',0x34:'delay',0x40:'delay',0x4C:'delay',0x7E:'clear',0x84:'icon_clear'}}
    links['icons'][6]='stack'
    for role,entries in links.items():
        for offset,target in entries.items():call(sites[role]+offset,sites[target])
    context,flags=0x01002000+ram_shift,0x01001000+ram_shift
    for role,values in {'raster':{0x2C:context,0x34:context+0x24},
                        'clear':{0xA:context+0x24,0x16:context,0x2C:flags},
                        'init':{0x1C:flags}}.items():
        for offset,value in values.items():literal(sites[role]+offset,value)
    struct.pack_into('<II',image,sites['stack']+0x78,sites['stack']+0x2C,sites['stack']+0x30)
    return image,sites


class OddBytePageDetectionTest(unittest.TestCase):
    def test_relocated_complete_group(self):
        for shift in (0,4,0x400):
            for ram_shift in (0,0x1000):
                image,sites=fixture(shift,ram_shift)
                profile,reason=detector.find_odd_byte_page_profile(bytes(image))
                self.assertIsNotNone(profile,reason)
                self.assertEqual((profile['width'],profile['height'],profile['column_bias']), (128,64,4))
                self.assertEqual((profile['command_port'],profile['data_port'],profile['access_width']), (0x02000001,0x02000003,1))
                self.assertEqual(profile['producer_entry'],sites['raster'])
                self.assertEqual(profile['column_helper'],sites['column'])
                self.assertEqual(profile['icon_page'],8)
                self.assertFalse(profile['init_data_argument']['pixel'])
                self.assertIsNone(profile['controller_part'])
                self.assertIsNone(profile['optical_polarity'])

    def test_typed_geometry_port_bias_and_index_mutations(self):
        image,sites=fixture()
        cases=[('raster',0x18),('raster',0x1A), # lowerpage/clamp
               ('raster',0x18+2),('raster',0x26), # pageend/columnlower
               ('raster',0x26+2),('raster',0x2A), # xlimit
               ('raster',0x56),('raster',0x62),('raster',0x6E),('raster',0x70),('raster',0x72),
               ('column',0),('column',2),('column',0x10),('column',0x14),('column',0x1A),
               ('icon_clear',0xE),('icon_clear',0x22),('icon_clear',0x30),
               ('icons',0xA),('icons',0x10),('icons',0x1A),
               ('init',0x12),('init',0x16),('init',0x18),('init',0x1A),('init',0x8A),
               ('clear',0xC),('clear',0x10),('clear',0x1E),('clear',0x20),('clear',0x24)]
        for role,offset in cases:
            with self.subTest(role=role,offset=hex(offset)):
                changed=image.copy();changed[sites[role]+offset]^=1
                self.assertIsNone(detector.find_odd_byte_page_profile(bytes(changed))[0])

    def test_explicit_bus_width_port_and_stride_changes(self):
        image,sites=fixture()
        # STRB -> STR, base shift25 ->24, DATA+3 ->+2, column stride8 ->4.
        mutations=[('raster',0x56,0x1000),('raster',0x72,0x1000),
                   ('column',0x14,0x1000),('column',0x1A,0x1000),
                   ('init',0x18,0x1000),('column',0x12,0x40),
                   ('raster',0x72,0x40),('raster',0x6E,0x40)]
        for role,offset,mask in mutations:
            changed=image.copy();at=sites[role]+offset
            word=struct.unpack_from('<H',changed,at)[0]
            struct.pack_into('<H',changed,at,word^mask)
            self.assertIsNone(detector.find_odd_byte_page_profile(bytes(changed))[0])

    def test_calls_and_literal_owners(self):
        image,sites=fixture()
        for role,offset in [('raster',6),('raster',0x5A),('clear',6),('clear',0x12),
                            ('clear',0x26),('icon_clear',0x18),('icons',0x14),
                            ('init',0x34),('init',0x40),('init',0x7E),('init',0x84)]:
            with self.subTest(role=role,offset=offset):
                changed=image.copy();changed[sites[role]+offset]^=1
                self.assertIsNone(detector.find_odd_byte_page_profile(bytes(changed))[0])
        for role,offset in [('raster',0x2C),('raster',0x34),('clear',0xA),('clear',0x16),('clear',0x2C),('init',0x1C)]:
            at=sites[role]+offset;ins=struct.unpack_from('<H',image,at)[0]
            pool=((at+4)&~3)+(ins&255)*4
            changed=image.copy();changed[pool]^=4
            self.assertIsNone(detector.find_odd_byte_page_profile(bytes(changed))[0])
        for role,offset in [('fill',0x10),('delay',0xA),('stack',0x30),('stack',0x78)]:
            changed=image.copy();changed[sites[role]+offset]^=1
            self.assertIsNone(detector.find_odd_byte_page_profile(bytes(changed))[0])

    def test_unique_group_and_truncation(self):
        image,sites=fixture()
        for role in sites:
            changed=image.copy();changed[sites[role]:sites[role]+2]=b'\0\0'
            self.assertIsNone(detector.find_odd_byte_page_profile(bytes(changed))[0])
        duplicate,_=fixture(0xA000,image=image.copy())
        self.assertEqual(detector.find_odd_byte_page_profile(bytes(duplicate))[1],'odd-byte-page-group-ambiguous')
        for end in (0,2,sites['raster']+len(detector._RASTER)-1,
                    sites['init']+len(detector._INIT)-1,sites['stack']+0x7F):
            self.assertIsNone(detector.find_odd_byte_page_profile(bytes(image[:end]))[0])


if __name__=='__main__': unittest.main()
