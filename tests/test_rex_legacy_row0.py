import struct
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection import rex


RAM = 0x01000000


def fixture(shift=0, compact=False):
    names = ('callback', 'arm', 'registrar', 'init', 'copy', 'core', 'walker',
             'signal', 'scheduler', 'accumulator', 'software', 'setter',
             'default', 'drain', 'handler', 'lock', 'free', 'guard', 'getter',
             'bx0', 'bx1', 'dummy', 'zero64', 'irq_enable')
    sites = {name: 0x400 + i * 0x400 + shift for i, name in enumerate(names)}
    related = ('expiry_remove','expiry_insert','submit','queue_init','link_init','push','pop')
    sites.update({name: 0xB000+i*0x400+shift for i,name in enumerate(related)})
    names += related
    image = bytearray(b'\xff' * (0xE000 + shift))
    shapes = {name: name for name in names if name in rex._ROW0_BODIES}
    if compact:
        shapes.update(registrar='registrar_compact', software='software_compact',
                      drain='drain_compact')
        shapes.update({name:name+'_compact' for name in related})
    shapes.pop('handler', None)
    for name, shape in shapes.items():
        body = rex._ROW0_BODIES[shape]
        image[sites[name]:sites[name] + len(body)] = body
    for shape, offset in (('handler_prefix', 0), ('handler_row', 0x102), ('handler_end', 0x32A)):
        body = rex._ROW0_BODIES[shape]
        at = sites['handler'] + offset
        image[at:at + len(body)] = body
    for name, data in (('lock', rex.REX_INTLOCK_SIGNATURE + bytes.fromhex('1eff2fe1')),
                       ('free', rex.REX_INTFREE_SIGNATURE + bytes.fromhex('1eff2fe1')),
                       ('getter', bytes.fromhex('c068f746')),
                       ('bx0', b'\x00\x47'), ('bx1', b'\x08\x47'),
                       ('guard', b'\x70\x47'), ('dummy', b'\x70\x47')):
        image[sites[name]:sites[name] + len(data)] = data

    def word(at, value):
        struct.pack_into('<I', image, at, value)

    def bl(at, target):
        delta = target - at - 4
        struct.pack_into('<2H', image, at, 0xF000 | (delta >> 12 & 0x7FF),
                         0xF800 | (delta >> 1 & 0x7FF))

    def literal(name, offset, value):
        at = sites[name] + offset
        opcode = struct.unpack_from('<H', image, at)[0]
        word(((at + 4) & ~3) + (opcode & 255) * 4, value)

    def arm_literal(name, offset, value):
        at = sites[name] + offset
        word(at + 8 + (struct.unpack_from('<I', image, at)[0] & 0xFFF), value)

    calls = {
        'callback': {6:'guard', 0xA:'lock', 0x16:'accumulator', 0x1C:'getter',
                     0x3A:'walker', 0x42:'software', 0x4A:'free'},
        'arm': {6:'guard', 0x10:'zero64', 0x26:'registrar'},
        'registrar': {6:'guard', 0xE:'lock', (0xFC if compact else 0x114):'free'},
        'init': {6:'guard', 0xA:'lock', 0x10:'lock', 0x22:'free', 0x26:'lock',
                 0x32:'free', 0x42:'free', 0x4A:'setter', 0x52:'setter', 0x58:'irq_enable',0x5E:'queue_init'},
        'walker': {6:'guard', 0x36:'signal'},
        'signal': {6:'guard', 0xE:'lock', 0x34:'scheduler', 0x3C:'free'},
        'software': {6:'guard', 0x10:'lock',0x36:'expiry_remove',0x52:'expiry_insert',
                     0x5E:'submit',0x72:'free'},
        'drain': {6:'guard',0xC:'pop',0x1C:'bx1'},
        'expiry_remove': {6:'guard',0xC:'lock',0x40:'free'},
        'expiry_insert': {6:'guard',0xC:'lock',0x42:'free',0x62:'free'},
        'submit': {6:'guard',0xC:'lock',
                   (0x28 if compact else 0x3E):'free',
                   (0x36 if compact else 0x4C):'free',
                   (0x3E if compact else 0x54):'link_init',
                   (0x46 if compact else 0x5C):'push'},
        'push': {6:'guard',0xE:'lock',(0x24 if compact else 0x2A):'free'},
        'pop': {6:'guard',(0xE if compact else 0xC):'lock',
                (0x36 if compact else 0x2E):'free'},
    }
    for name, shape in shapes.items():
        body = rex._ROW0_BODIES[shape]
        for offset in range(0, len(body) - 3, 2):
            if rex.thumb_bl_target(body, offset) is not None:
                bl(sites[name] + offset, sites[calls.get(name, {}).get(offset, 'dummy')])
        for offset in range(0, len(body) - 1, 2):
            if struct.unpack_from('<H', body, offset)[0] & 0xF800 == 0x4800:
                literal(name, offset, RAM + 0x2800)
    bl(sites['handler'] + 6, sites['guard'])
    bl(sites['handler'] + 0x10C, sites['bx0'])
    bl(sites['handler'] + 0x32A, sites['drain'])

    descriptors, state = RAM + 0x200, RAM + 0x3000
    fields, source, length = 0x7000 + shift, 0x8000 + shift, 0x1000
    slots, short, shadow = descriptors + 0x178, descriptors + 0x1F8, descriptors - 8
    for offset, value in ((0x12,RAM+0x2000),(0x1A,RAM+0x2100),
                          (0x26,RAM+0x2200),(0x30,RAM+0x2300),(0x3E,RAM+0x2400)):
        literal('callback', offset, value)
    for offset, value in ((0xA,RAM+0x1F00),(0x16,RAM+0x2000),
                          (0x1E,0x030006E0),(0x22,sites['callback']|1)):
        literal('arm', offset, value)
    for offset, value in ((0x14,sites['default']|1),(0x1C,slots),(0x1E,short),
                          (0xC2 if compact else 0xDA,descriptors)):
        literal('registrar', offset, value)
    for offset, value in ((0x16,RAM+0x2500),(0x1A,0x03000600),(0x38,0xFFFF),
                          (0x46,sites['handler']|1),(0x4E,sites['dummy']|1),
                          (0x5C,RAM+0x2700)):
        literal('init', offset, value)
    for offset, value in ((0x50,fields+4),(0x54,fields+8),(0x5A,fields)):
        literal('copy', offset, value)
    for offset, value in ((0xC,RAM+0x2600),(0x10,RAM+0x2620)):
        literal('walker', offset, value)
    literal('signal', 0x28, state)
    literal('setter', 0, state)
    literal('default', 0, RAM+0x2500)
    literal('drain', 0xA, RAM+0x2700)
    literal('expiry_remove',0x32,RAM+0x2400)
    literal('expiry_insert',0x14,RAM+0x2400)
    literal('expiry_insert',0x4E,RAM+0x2400)
    literal('submit',0x44 if compact else 0x5A,RAM+0x2700)
    for offset, value in ((0x24,state),(0x2C,state+12),
                          (0x38,sites['core']+0x44),(0x3C,sites['core']+0x48),
                          (0x50,state+8),(0x58,state+4)):
        arm_literal('core', offset, value)
    arm_literal('scheduler', 0x20, state+8)
    arm_literal('scheduler', 0x28, state+4)
    for offset, value in ((0xA,slots),(0xC,RAM+0x2500),(0xE,short),
                          (0x10,shadow),(0x14,0x03000600),(0x11A,0x03000600)):
        literal('handler', offset, value)
    struct.pack_into('<5I', image, fields, source, RAM, length, RAM+length, 0x1000)
    # Architectural IRQ vector -> copied branch -> original ARM core.
    word(0x18, 0xEA000000 | (((RAM - 0x18 - 8) >> 2) & 0xFFFFFF))
    word(source, 0xEA000000 | (((sites['core'] - RAM - 8) >> 2) & 0xFFFFFF))
    for index in range(27):
        record = (0x03000620,0x03000628,0x200,shadow) if index == 0 else (
            0x03000624,0x0300062C,1,shadow+2)
        struct.pack_into('<4I', image, source+descriptors-RAM+index*16, *record)
    word(source+slots+0x38-RAM, sites['default']|1)
    sites.update(source=source,fields=fields,descriptors=descriptors,state=state,
                 slot=slots+0x38,compact=compact)
    return image, sites


def call(image, at, target):
    delta = target - at - 4
    struct.pack_into('<2H', image, at, 0xF000 | (delta >> 12 & 0x7FF),
                     0xF800 | (delta >> 1 & 0x7FF))


def set_literal(image, at, value):
    word = struct.unpack_from('<H', image, at)[0]
    struct.pack_into('<I', image, ((at+4)&~3)+(word&255)*4, value)


class LegacyRow0Tests(unittest.TestCase):
    def test_two_layouts_and_relocation(self):
        for compact in (False, True):
            for shift in (0, 0x2400):
                with self.subTest(compact=compact, shift=shift):
                    image, sites = fixture(shift, compact)
                    result, reason = rex.find_rex_legacy_row0_profile(bytes(image), RAM, 0x10000)
                    self.assertEqual(reason, 'accepted')
                    self.assertEqual(result['route'], (sites['core'],sites['handler'],
                        sites['state']+12,sites['slot'],0x03000620,0x03000628,0x200))
                    self.assertEqual(result['callback_file_offset'], sites['callback'])
                    self.assertEqual(result['timer_walker_file_offset'], sites['walker'])
                    self.assertEqual((result['logical_delta'],result['logical_carry']), (5,1000))
                    self.assertEqual(result['virtual_interval_ns'], 5_000_000)
                    self.assertIsNone(result['idle_address'])

    def test_critical_calls_delta_and_carry(self):
        for name, offsets in {'callback':(6,0xA,0x16,0x1C,0x3A,0x42,0x4A),
                              'arm':(6,0x10,0x26),'walker':(6,0x36),
                              'signal':(6,0xE,0x34,0x3C),
                              'init':(6,0x4A,0x52,0x58)}.items():
            for offset in offsets:
                with self.subTest(name=name, offset=offset):
                    image, sites = fixture()
                    call(image, sites[name]+offset, sites['dummy'])
                    self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])
        for name, offset in (('callback',0x38),('callback',0x14),('accumulator',0xA),
                             ('accumulator',0x10),('arm',0x1C)):
            image, sites = fixture()
            image[sites[name]+offset] ^= 1
            self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])

    def test_descriptor_width_mask_stride_and_slot(self):
        for kind in ('mask','duplicate','slot','width','stride','row'):
            with self.subTest(kind=kind):
                image, sites = fixture()
                at = sites['source']+sites['descriptors']-RAM
                if kind == 'mask':struct.pack_into('<I',image,at+8,0x400)
                elif kind == 'duplicate':image[at+16:at+32]=image[at:at+16]
                elif kind == 'slot':struct.pack_into('<I',image,sites['source']+sites['slot']-RAM,0)
                elif kind == 'width':image[sites['handler']+0x120] ^= 0x10
                elif kind == 'stride':image[sites['registrar']+0xD8] ^= 1
                else:image[sites['arm']+0x24] = 1
                self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])

    def test_copy_producer_vector_bounds_and_layout_precedence(self):
        image, sites = fixture()
        layout=SimpleNamespace(source=sites['source'],target=RAM,size=0x1000)
        self.assertIsNotNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000,(layout,))[0])
        for bad in (SimpleNamespace(source=sites['source']+4,target=RAM,size=0x1000),
                    SimpleNamespace(source=sites['source']+4,target=sites['descriptors']+4,size=16)):
            self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000,(bad,))[0])
        for name, offset in (('copy',0x50),('core',0),('scheduler',4)):
            changed=bytearray(image);changed[sites[name]+offset] ^= 1
            self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(changed),RAM,0x10000)[0])
        changed=bytearray(image);struct.pack_into('<I',changed,sites['fields']+8,0xFFFFFFFC)
        self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(changed),RAM,0x10000)[0])
        self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image[:sites['source']+4]),RAM,0x10000)[0])

    def test_mixed_registrar_expiry_or_drain_fields_rejected(self):
        extended, a=fixture();compact, b=fixture(compact=True)
        for name in ('software','registrar','drain'):
            changed=bytearray(extended)
            changed[a[name]:a[name]+0x300]=compact[b[name]:b[name]+0x300]
            self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(changed),RAM,0x10000)[0])

    def test_duplicate_complete_callback_or_arm_is_ambiguous(self):
        for name in ('callback','arm'):
            image, sites=fixture()
            at=0x9000
            shape=rex._ROW0_BODIES[name]
            image[at:at+len(shape)]=image[sites[name]:sites[name]+len(shape)]
            # Preserve each absolute literal/call link after relocating only this body.
            for offset in range(0,len(shape)-1,2):
                target=rex.thumb_bl_target(shape,offset)
                if target is not None:
                    call(image,at+offset,rex.thumb_bl_target(image,sites[name]+offset))
                word=struct.unpack_from('<H',shape,offset)[0]
                if word&0xF800==0x4800:
                    value=rex.thumb_literal_value(image,sites[name]+offset,word>>8&7)
                    struct.pack_into('<I',image,((at+offset+4)&~3)+(word&255)*4,value)
            if name=='callback':
                # Duplicate its fully bound arm as well.
                arm=0x9800;body=rex._ROW0_BODIES['arm'];image[arm:arm+len(body)]=image[sites['arm']:sites['arm']+len(body)]
                for offset in (6,0x10,0x26):call(image,arm+offset,rex.thumb_bl_target(image,sites['arm']+offset))
                for offset in (0xA,0x16,0x1E,0x22):
                    word=struct.unpack_from('<H',body,offset)[0]
                    value=at|1 if offset==0x22 else rex.thumb_literal_value(image,sites['arm']+offset,word>>8&7)
                    struct.pack_into('<I',image,((arm+offset+4)&~3)+(word&255)*4,value)
            self.assertEqual(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[1],
                             'row0-profile-ambiguous')

    def test_all_three_review_call_bundles_reject_both_layouts(self):
        for compact in (False,True):
            for name,offset in (('init',0x26),('software',0x36),('software',0x52),
                                ('software',0x5E),('drain',0xC),('init',0x5E)):
                for target in ('free','dummy'):
                    with self.subTest(compact=compact,name=name,offset=offset,target=target):
                        image,sites=fixture(compact=compact)
                        call(image,sites[name]+offset,sites[target])
                        self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])

    def test_direct_callee_irq_links_and_fixed_bodies(self):
        for compact in (False,True):
            checks={'expiry_remove':(6,0xC,0x40),
                    'expiry_insert':(6,0xC,0x42,0x62),
                    'submit':(6,0xC,*( (0x28,0x36,0x3E,0x46) if compact
                                      else (0x3E,0x4C,0x54,0x5C))),
                    'push':(6,0xE,0x24 if compact else 0x2A),
                    'pop':(6,0xE if compact else 0xC,0x36 if compact else 0x2E)}
            for name,offsets in checks.items():
                for offset in offsets:
                    with self.subTest(compact=compact,name=name,call=offset):
                        image,sites=fixture(compact=compact)
                        call(image,sites[name]+offset,sites['dummy'])
                        self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])
            for name,offset in (('expiry_remove',0x14),('expiry_insert',0x50),
                                ('submit',0x14),('queue_init',6),('link_init',0),
                                ('push',0x18),('pop',0x18)):
                with self.subTest(compact=compact,name=name,body=offset):
                    image,sites=fixture(compact=compact)
                    image[sites[name]+offset] ^= 1
                    self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])

    def test_expiry_context_is_shared_and_full_span_bounded(self):
        fields=(('callback',0x3E),('expiry_remove',0x32),
                ('expiry_insert',0x14),('expiry_insert',0x4E))
        for compact in (False,True):
            for name,offset in fields:
                with self.subTest(compact=compact,alias=(name,offset)):
                    image,sites=fixture(compact=compact)
                    set_literal(image,sites[name]+offset,RAM+0x2404)
                    self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])
            span=0x30 if compact else 0x3C
            for excess,expected in ((0,True),(4,False)):
                image,sites=fixture(compact=compact)
                context=RAM+0x10000-span+excess
                for name,offset in fields:set_literal(image,sites[name]+offset,context)
                result=rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0]
                self.assertEqual(result is not None,expected)

    def test_queue_object_is_shared_and_full_header_bounded(self):
        for compact in (False,True):
            fields=(('drain',0xA),('init',0x5C),('submit',0x44 if compact else 0x5A))
            for name,offset in fields:
                with self.subTest(compact=compact,alias=(name,offset)):
                    image,sites=fixture(compact=compact)
                    set_literal(image,sites[name]+offset,RAM+0x2704)
                    self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0])
            span=0xA if compact else 0x14
            for excess,expected in ((0,True),(4,False)):
                image,sites=fixture(compact=compact)
                queue=RAM+0x10000-((span+3)&~3)+excess
                for name,offset in fields:set_literal(image,sites[name]+offset,queue)
                result=rex.find_rex_legacy_row0_profile(bytes(image),RAM,0x10000)[0]
                self.assertEqual(result is not None,expected)

    def test_direct_helper_layouts_cannot_be_mixed(self):
        extended,a=fixture();compact,b=fixture(compact=True)
        for name in ('expiry_remove','expiry_insert','submit','link_init','push','pop','queue_init'):
            for target,source,ts,ss in ((extended,compact,a,b),(compact,extended,b,a)):
                with self.subTest(name=name,target_compact=ts['compact']):
                    changed=bytearray(target)
                    changed[ts[name]:ts[name]+0x300]=source[ss[name]:ss[name]+0x300]
                    self.assertIsNone(rex.find_rex_legacy_row0_profile(bytes(changed),RAM,0x10000)[0])

    def test_absent_and_invalid_inputs(self):
        self.assertEqual(rex.find_rex_legacy_row0_profile(b'',RAM,0x10000),
                         (None,'row0-callback-none'))
        self.assertIsNone(rex.find_rex_legacy_row0_profile(b'',-1,4)[0])
        self.assertIsNone(rex.find_rex_legacy_row0_profile(b'',RAM,0x10000,({},))[0])


if __name__=='__main__':
    unittest.main()
