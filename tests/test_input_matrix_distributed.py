"""Synthesized distributed byte scanner/queue instructions; no firmware fixture."""
import struct
import unittest

from msm5xxx_emulator.detection.input_matrix import (
    resolve_distributed_matrix_input, resolve_direct_matrix_input,
    classify_matrix_event_sink, UNCLASSIFIED, SAMSUNG_RAW_DEQUEUE,
)


class DistributedMatrixTests(unittest.TestCase):
    @staticmethod
    def bl(image, pc, target):
        delta = target - pc - 4
        struct.pack_into('<HH', image, pc, 0xf000 | ((delta >> 12) & 0x7ff),
                         0xf800 | ((delta >> 1) & 0x7ff))

    @staticmethod
    def literal(image, pc, register, slot, value):
        delta = slot - ((pc + 4) & ~3)
        assert delta % 4 == 0 and 0 <= delta <= 1020
        struct.pack_into('<H', image, pc, 0x4800 | register << 8 | delta // 4)
        struct.pack_into('<I', image, slot, value)

    @staticmethod
    def branch(image, pc, target, condition=None):
        delta = (target - pc - 4) // 2
        struct.pack_into('<H', image, pc, 0xe000 | (delta & 0x7ff) if condition is None
                         else 0xd000 | condition << 8 | (delta & 255))

    def image(self, delta=0):
        image = bytearray(bytes.fromhex('c046') * ((delta + 0x2400) // 2))
        start, helper, sink, dequeue, lock, unlock = [delta + n for n in (0x400,0x200,0x100,0x80,0x1800,0x1820)]
        put = lambda pc, code: image.__setitem__(slice(pc,pc + len(code)//2),bytes.fromhex(code))
        def literal(pc, reg, slot, value):
            self.literal(image,pc,reg,slot,value + delta if 0x1000000 <= value < 0x3000000 else value)
        def bl(pc, target): self.bl(image,pc,target)
        def branch(pc, target, condition=None): self.branch(image,pc,target,condition)
        for pc,mode in ((lock,'80'),(unlock,'c0')):
            put(pc,'7847000001e08ee300000fe1c010'+mode+'e301f021e1c00000e21eff2fe1')
        put(helper,'80b5')
        shadows=[0x1001022,0x1001020,0x100101e]
        for index,(block,call,offset,mask) in enumerate(zip((6,34,60),(2,30,56),(12,8,4),(0x62,6,0x80))):
            bl(helper + call,lock)
            pc = helper + block
            literal(pc,1,helper + 0xd0 + index*4,shadows[index])
            put(pc + 2,f'{mask:02x}230a78')
            shift=2 if index==0 else 0
            if index==0: literal(helper + 12,7,helper + 0xdc,0x3000660)
            put(pc + 6 + shift,'9a430a700978')
            struct.pack_into('<HH',image,pc + 12 + shift,0x7039 | offset<<6,0x2800)
            branch(pc + 16 + shift,pc + 22 + shift,1)
            bl(pc + 18 + shift,unlock)
        put(helper + 82,'80bd')
        put(start,'f0b587b000276846')
        put(start + 16,'0026')
        literal(start + 0x40,4,start + 0x3e0,0x1002000)
        presence, sense, switch = start + 0xca,start + 0x310,start + 0xe8
        bl(presence - 4,helper)
        literal(presence,0,start + 0x3e4,0x3000690)
        put(presence + 2,'01790907090f0f29')
        branch(presence + 10,start + 0x15a,0)
        branch(start + 0x15a,sense + 0x190)
        put(switch - 8,'00220392'); bl(switch - 4,helper)
        put(switch,'039a062a'); branch(switch + 4,switch + 14,2);branch(switch + 14,sense)
        put(switch + 6,'02a39b5c5b009f44')
        arms=[start + x for x in (0xfe,0x15c,0x1b4,0x20a,0x264,0x2ba)]
        image[switch + 16:switch + 22]=bytes((a-switch-16)//2 for a in arms)
        tuples=[[0x60,6,0x80],[0x42,6,0x80],[0x22,6,0x80],
                [0x62,4,0x80],[0x62,2,0x80],[0x62,6,0]]
        stores=[]
        for row,arm in enumerate(arms):
            pc=arm
            for index,(offset,mask,value) in enumerate(zip((12,8,4),(0x62,6,0x80),tuples[row])):
                bl(pc,lock); literal(pc + 4,1,start + 0x3ec + index*4,shadows[index])
                put(pc + 6,f'{mask:02x}230a78'); cursor=pc + 10
                if value != mask:
                    put(cursor,'9a43'); cursor+=2
                    if value:
                        put(cursor,f'{value:02x}231a43');cursor+=4
                else: put(cursor,'1a43');cursor+=2
                put(cursor,'0a700978');literal(cursor+4,2,start + 0x3f8,0x3000660);cursor+=6
                struct.pack_into('<HH',image,cursor,0x7011 | offset<<6,0x2800)
                stores.append(cursor)
                if index != 2:
                    branch(cursor+4,cursor+10,1);bl(cursor+6,unlock);pc=cursor+10
                else:
                    branch(cursor+4,start+0x154 if sense-(cursor+8)>254 else sense,1)
                    if cursor+6 != sense-4: branch(cursor+6,sense-4)
        branch(start+0x154,sense)
        bl(sense-4,unlock);literal(sense,0,start + 0x3e4,0x3000690)
        put(sense+2,'00790007000f0f28');branch(sense+10,sense+76,0)
        put(sense+12,'0107090f0020ca43069201218140069a11400cd006214143')
        literal(sense+36,2,start + 0x3fc,delta + 0x1900)
        put(sense+38,'8918039a8b5c711c0a06120e311c161c6a4653540a2e0eda01300006000e0428e6db0a2e07da039a501c0206120e0392062a00da')
        branch(sense+90,switch-4);bl(sense+92,helper)
        put(sense+96,'012e');branch(sense+98,sense+0x122,13)
        branch(sense+0x122,sense+0x152)
        put(sense+0x152,'012e');literal(sense+0x156,2,start+0x5f0,0x1002100)
        put(sense+0x158,'517b0029');branch(sense+0x15c,sense+0x18a,13)
        put(sense+0x18a,'00af3f78');branch(sense+0x18e,sense+0x196)
        literal(sense+0x1ac,1,start+0x5f4,0x1002200)
        literal(sense+0x1fc,0,start+0x5f0,0x1002100)
        put(sense+0x222,'381c');bl(sense+0x224,sink)
        put(sink,'b0b5');literal(sink+2,4,sink+0xc0,0x1002200);put(sink+4,'071c')
        bl(sink+56,lock);put(sink+60,'0504');literal(sink+62,0,sink+0xc4,0x1002300)
        put(sink+64,'2d0c417803784a1cd206d20e9a4207d009188f7041780131c906c90e417003e0')
        bl(sink+108,unlock);put(sink+124,'b0bd')
        image[dequeue:dequeue+len(SAMSUNG_RAW_DEQUEUE)]=SAMSUNG_RAW_DEQUEUE
        literal(dequeue,2,dequeue+28,0x1002300)
        # Numeric events generated independently, unique column*6+row positions.
        events=bytearray(24)
        for i,token in enumerate(b'123456789*0#'): events[(i%3)*6 + 2 + i//3]=token
        image[delta+0x1900:delta+0x1918]=events
        return image, {'start':start,'sense':sense,'sink':sink,'table':delta+0x1900,
                       'stores':stores,'last_branch':stores[-1]+4}

    def test_numeric_only_closed_shape_and_rejections(self):
        image,sites=self.image()
        profile,status,_=resolve_distributed_matrix_input(bytes(image))
        self.assertEqual(status,'static-candidate')
        self.assertEqual((profile['presence_site'],profile['sense_site']),(0x4cc,0x712))
        self.assertEqual(profile['row_values'][5],[0x62,6,0])
        self.assertEqual(profile['producer']['wrap_mask'],31)
        self.assertEqual(profile['producer']['ring'],0x1002300)
        self.assertEqual((profile['scanner_state_size'], profile['batch_state'],
                          profile['batch_state_size'], profile['producer']['state_size']),
                         (0xA, 0x1002100, 0xE, 0x34))
        self.assertEqual({c['token'] for c in profile['token_cells']},set('123456789*0#'))
        self.assertFalse(profile['runtime_admitted'])
        self.assertNotIn('key_mapping',profile)
        self.assertIsNone(resolve_direct_matrix_input(bytes(image))[0])
        self.assertEqual(classify_matrix_event_sink(bytes(image),sites['sink'])['family'],UNCLASSIFIED)
        for pc in (sites['start']+16,sites['start']+0xe8,sites['sense']+2,
                   sites['sense']+56,sites['sense']+0x18a,sites['sense']+0x222,
                   sites['sink']+72,sites['stores'][-1],sites['last_branch']):
            with self.subTest(pc=hex(pc)):
                changed=image.copy();struct.pack_into('<H',changed,pc,0x4770)
                self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])
        changed=image.copy();struct.pack_into('<H',changed,sites['stores'][0]-2,0x4770)
        self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])  # Missing GPIO literal.
        changed=image.copy();changed[sites['table']+2]=ord('2')
        self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])
        changed=image.copy();struct.pack_into('<H',changed,sites['sense']+0x1b0,0x2700)
        self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])
        changed=image.copy()
        struct.pack_into('<H',changed,sites['sense']+0x156,0x2200)
        struct.pack_into('<H',changed,sites['sense']+0x1fc,0x2000)
        self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])  # None is not a state link.
        for slots,size in (((sites['start']+0x3e0,),0xA),
                           ((sites['start']+0x5f0,),0xE),
                           ((sites['start']+0x5f4,sites['sink']+0xc0),0x34)):
            for value in (0,0xffffffff,0x03000000-size+1):
                with self.subTest(state_slots=slots,value=hex(value)):
                    changed=image.copy()
                    for slot in slots: struct.pack_into('<I',changed,slot,value)
                    self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])
            changed=image.copy()
            for slot in slots: struct.pack_into('<I',changed,slot,0x03000000-size)
            self.assertIsNotNone(resolve_distributed_matrix_input(bytes(changed))[0])
        changed=image.copy();switch_table=sites['start']+0xe8+16
        changed[switch_table],changed[switch_table+1]=changed[switch_table+1],changed[switch_table]
        self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])  # Native rows use ascending bits per ordered port.
        changed=image.copy()
        for slot in (sites['start']+0x3f0,0x200+0xd4):
            struct.pack_into('<I',changed,slot,0x1001022)
        self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])  # Two ports cannot share an unproven shadow.
        changed=image.copy()
        for slot in (sites['start']+0x3f8,0x200+0xdc):
            struct.pack_into('<I',changed,slot,0x03000fe0)
        struct.pack_into('<I',changed,sites['start']+0x3e4,0x03001010)
        self.assertIsNone(resolve_distributed_matrix_input(bytes(changed))[0])  # Sense base+52 crosses the GPIO aperture.
        self.assertEqual(resolve_distributed_matrix_input(bytes(image),0x1000)[1],'unsupported-load-address')
        self.assertIsNone(resolve_distributed_matrix_input(bytes(image[:sites['sense']+80]))[0])
        relocated,_=self.image(0x3000)
        p,st,_=resolve_distributed_matrix_input(bytes(relocated))
        self.assertEqual(st,'static-candidate')
        self.assertEqual(p['function'],profile['function']+0x3000)
        self.assertEqual(p['event_table'],profile['event_table']+0x3000)
        self.assertEqual(p['token_cells'],profile['token_cells'])
        relocated[:len(image)]=image
        self.assertEqual(resolve_distributed_matrix_input(bytes(relocated))[1],'ambiguous-scanners')
