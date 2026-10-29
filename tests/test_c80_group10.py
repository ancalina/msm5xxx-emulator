"""Portable typed group-10 compiler fixture; no original firmware dependency."""
import struct
import unittest
from corpus import snippet
from msm5xxx_emulator.detection.rex import (
    _controller_registrar_at, find_rex_static_controller_callback_candidate)

def chunks():
    return (
        (0x18,bytes.fromhex('f8ff3fea')),
        (0x2000,bytes.fromhex('7c755c000000000100ad000000ad0001')),
        (0x34cc0,snippet("test_c80_group10", "chunk_34cc0")),
        (0x353ac,snippet("test_c80_group10", "chunk_353ac")),
        (0x101b64,snippet("test_c80_group10", "chunk_101b64")),
        (0x101e6c,snippet("test_c80_group10", "chunk_101e6c")),
        (0x13521c,snippet("test_c80_group10", "controller_handler_chunk")),
        (0x135468,snippet("test_c80_group10", "controller_registrar_chunk")),
        (0x371e8c,snippet("test_c80_group10", "interrupt_runtime_chunk")),
        (0x372074,snippet("test_c80_group10", "interrupt_enable_chunk")),
        (0x37208c,snippet("test_c80_group10", "interrupt_disable_chunk")),
        (0x37272c,snippet("test_c80_group10", "interrupt_vector_chunk")),
        (0x372730,bytes.fromhex('10471847204728473047384778470000000050e31eff2f11600200ea78470000020090e00310a1e01eff2fe178470000020090e0c21fa1e01eff2fe178470000')),
        (0x5c757c,bytes.fromhex('a1c7cdea')),
        (0x5cb210,snippet("test_c80_group10", "group_descriptor_table")),
        (0x13545c,bytes.fromhex('49521300')),
     )

RAM = dict(ram_base=0x01000000,ram_size=0x00800000)
HANDLER=0x135248
REGISTRAR=0x135468
MASKS=0x01003c94
SEED=0x5cb210+0x354
GROUP=0x5cb210+0x374
SPECIAL=0x01003fd4


def fixture():
    image=bytearray(0x800000)
    for at,data in chunks():image[at:at+len(data)]=data
    return image


def candidate(image):
    return find_rex_static_controller_callback_candidate(bytes(image),**RAM)


class C80Group10Tests(unittest.TestCase):
    def test_full_typed_fixture_promotes_preserving_special_slot(self):
        image=fixture();result=candidate(image)
        self.assertIsNotNone(result)
        self.assertTrue(result['accepted'])
        self.assertEqual(result.get('group_row_size'),10)
        self.assertEqual(result['descriptor_table'],SPECIAL)
        self.assertEqual(_controller_registrar_at(image,REGISTRAR,result['default_callback']),SPECIAL)
        self.assertEqual(_controller_registrar_at(image,REGISTRAR,result['default_callback'],group_base=True),MASKS+12)
        self.assertEqual(result['promotion'],'temporary-evidence-gated')
        self.assertEqual(result['status_bank_count'],2)
        self.assertEqual(result['pending_read_semantics'],'latched-read')
        self.assertEqual(result['pending_ack_semantics'],'write-one-to-clear')
        self.assertEqual((result['time_tick_status_bank'],result['time_tick_clear_bank'],result['time_tick_mask']),
                         (0x03000c80,0x03000c80,0x200))
        self.assertEqual(result['callback_delta'],5)
        self.assertFalse(result['active'])

    def test_registrar_typed_base_and_legacy_default_layouts(self):
        for row in (20,24):
            image=bytearray(0x300);at=0x40;words=[0]*34
            words[:3]=(0xb5f0,0x1c04,0x1c0f)
            words[3:5]=(0xf000,0xf800)
            words[5:7]=(0x1c05,0x2f00)
            words[8:14]=(0xd100,0x1c37,0x2c00,0xdb01,0x2c1f,0xdb01)
            words[14:16]=(0xf000,0xf800)
            words[row:row+10]=(0x201c,0,0x4360,0x1840,0x2c00,0xd102,0,0x630f,0xe000,0x6147)
            struct.pack_into('<34H',image,at,*words)
            for off,reg,value,pool in ((14,6,0x201,0x180),
                                       ((row+1)*2,1,0x01001000,0x184),
                                       ((row+6)*2,1,0x01002000,0x188)):
                pc=at+off
                struct.pack_into('<H',image,pc,0x4800|(reg<<8)|((pool-((pc+4)&~3))//4))
                struct.pack_into('<I',image,pool,value)
            self.assertEqual(_controller_registrar_at(image,at,0x201),0x01002000)
            self.assertEqual(_controller_registrar_at(image,at,0x201,group_base=True),0x01001000)
            for off in ((row+1)*2+1,(row+2)*2,(row+3)*2,(row+7)*2):
                changed=bytearray(image);changed[at+off]^=1
                self.assertIsNone(_controller_registrar_at(changed,at,0x201,group_base=True))
            # A broken base instruction cannot be rescued by a later literal.
            changed=bytearray(image);struct.pack_into('<H',changed,at+(row+1)*2,0)
            self.assertIsNone(_controller_registrar_at(changed,at,0x201,group_base=True))

    def test_second_closed_registration_is_ambiguous(self):
        image=fixture();pc=0x7000
        for at,value,pool in ((pc-8,0x030007a0,0x7100),
                              (pc-2,0x34cc1,0x7104)):
            struct.pack_into('<H',image,at,0x4900|((pool-((at+4)&~3))//4))
            struct.pack_into('<I',image,pool,value)
        struct.pack_into('<2H',image,pc-6,0x2002,0x7008)
        struct.pack_into('<H',image,pc,0x201e)
        displacement=REGISTRAR-(pc+2)-4
        struct.pack_into('<2H',image,pc+2,0xf000|((displacement>>12)&0x7ff),
                         0xf800|((displacement>>1)&0x7ff))
        fallback=candidate(image)
        self.assertIsNotNone(fallback)
        self.assertFalse(fallback['accepted'])
        self.assertEqual(fallback['reject_reason'],'row1e-callback-route-not-unique')

    def test_type_pool_group_and_bounds_fail_closed(self):
        image=fixture();result=candidate(image)
        load=REGISTRAR+0x2a
        pool=((load+4)&~3)+(struct.unpack_from('<H',image,load)[0]&255)*4
        changes=[('typed-register',load+1,b'J'),
                 ('base-pointer',pool,struct.pack('<I',MASKS+16)),
                 ('stride',HANDLER+0x4a,bytes.fromhex('0c23')),
                 ('tick-mask',GROUP+30,b'\x00\x00'),
                 ('tick-index',GROUP+38,b'\x1d'),
                 ('row-source',0x2000,struct.pack('<I',0x5c757c+4)),
                 ('copy-end',0x2000+12,struct.pack('<I',0x01000000+0xad00-4))]
        for label,at,value in changes:
            with self.subTest(label=label):
                changed=bytearray(image);changed[at:at+len(value)]=value
                fallback=candidate(changed)
                self.assertTrue(fallback is None or not fallback['accepted'] or 'promotion' not in fallback)
        changed=bytearray(image);changed[0x2010:0x2020]=image[0x2000:0x2010]
        fallback=candidate(changed)
        self.assertTrue(fallback is None or not fallback['accepted'])


if __name__=='__main__':unittest.main()
