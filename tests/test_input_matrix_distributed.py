"""Synthesized distributed byte scanner/queue instructions; no firmware fixture."""
from corpus import snippet
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
        put(sense+12,snippet("test_input_matrix_distributed", "sense_prefix").hex())
        literal(sense+36,2,start + 0x3fc,delta + 0x1900)
        put(sense+38,snippet("test_input_matrix_distributed", "sense_loop").hex())
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
        put(sink+64,snippet("test_input_matrix_distributed", "sink_tail").hex())
        bl(sink+108,unlock);put(sink+124,'b0bd')
        image[dequeue:dequeue+len(SAMSUNG_RAW_DEQUEUE)]=SAMSUNG_RAW_DEQUEUE
        literal(dequeue,2,dequeue+28,0x1002300)
        # Numeric events generated independently, unique column*6+row positions.
        events=bytearray(24)
        for i,token in enumerate(b'123456789*0#'): events[(i%3)*6 + 2 + i//3]=token
        image[delta+0x1900:delta+0x1918]=events
        return image, {'start':start,'sense':sense,'sink':sink,'table':delta+0x1900,
                       'stores':stores,'last_branch':stores[-1]+4}

    def controls_image(self, delta=0):
        image, sites = self.image(delta)
        image.extend(bytes.fromhex('c046') * ((delta + 0x7000 - len(image)) // 2))
        put = lambda pc, body: image.__setitem__(slice(pc,pc+len(body)//2),bytes.fromhex(body))
        def literal(pc, reg, slot, value):
            self.literal(image, pc, reg, slot, value + delta)
        call, task, sink, consumer, app, menu, confirm = [delta+n for n in
                                                       (0x2800,0x2600,0x2A00,0x2C00,0x4000,0x6000,0x6400)]
        returned = call+4
        self.bl(image,call,delta+0x80); put(returned,'071c')
        self.branch(image,returned+2,returned+6,0); self.branch(image,returned+4,task)
        forwards = [returned-0x60,returned-0x3E]
        self.branch(image,task,forwards[0]-0x20)
        put(forwards[0]-0x20,'0028')
        self.branch(image,forwards[0]-0x1E,forwards[1],0)
        self.branch(image,forwards[0]-0x1C,forwards[0])
        for pc in forwards:put(pc,'381c');self.bl(image,pc+2,sink)
        put(sink,'90b5');literal(sink+2,4,sink+0x80,0x1003000);put(sink+4,'071c')
        put(sink+6,snippet("test_input_matrix_distributed", "controls_press").hex())
        put(sink+0x28,snippet("test_input_matrix_distributed", "controls_release").hex())
        put(consumer-0x12,'013004d54042c006c00e404201e0c006c00e')
        put(consumer,'5060400080180089');self.bl(image,consumer+8,app)
        literal(consumer+0x12,2,consumer+0x40,0x1003000)
        put(consumer+0x14,'506811688842');self.branch(image,consumer+0x1A,consumer-0x12,1)
        put(app,'f0b598b000210191');put(app+10,'071c')
        literal(app+0x6A,1,app+0x2FC,0x1003300)
        put(app+0x6C,'0879303116910028');self.branch(image,app+0x74,app+0x92,0)
        put(app+0x76,'1699087a0028');self.branch(image,app+0x7C,app+0x92,1)
        put(app+0x7E,'381c');self.bl(image,app+0x80,delta+0x3800)
        for offset,reg in ((0x84,1),(0x92,0),(0x96,0)):
            literal(app+offset,reg,app+0x300,0x1003100)
        put(app+0x8C,'0860');put(app+0x94,'0760');put(app+0x9A,'0168')
        literal(app+0xF4,7,app+0x304,0x1003200)
        dispatch=app+0x14FC;join=dispatch+0x10C;table=dispatch+0x14
        for first,last in ((app+0xF6,app+0x700),(app+0x700,app+0xE00),(app+0xE00,dispatch)):
            self.branch(image,first,last)
        put(dispatch,'7878b87002381d28');self.branch(image,dispatch+8,dispatch+0x86,2)
        put(dispatch+10,'02a31b5c5b009f44001c')
        image[table:table+29]=bytes(29)
        for state,stub,target in ((5,dispatch+0x3E,menu),(12,dispatch+0x6E,confirm)):
            image[table+state-2]=(stub-table)//2
            self.bl(image,stub,target);self.branch(image,stub+4,join)
        put(join,'041c0128');self.branch(image,join+4,join+0x1C,1)
        self.bl(image,join+6,delta+0x3800);put(join+10,'7870041c')
        put(join+0x20,'7878');self.bl(image,join+0x22,delta+0x3820)
        put(join+0x26,'7c70002c');self.branch(image,join+0x2C,dispatch)
        put(menu,'f0b5beb0');literal(menu+0xE,4,menu+0x3E8,0x1003400)
        put(menu+0x1A,'a178e170');literal(menu+0xCE,4,menu+0x3E8,0x1003400)
        put(menu+0xD0,'0026e078');put(menu+0xD6,'a070e670')
        put(confirm,'f0b5b2b0');literal(confirm+4,4,confirm+0x3E0,0x1003500)
        put(confirm+6,'0026e71d1937be73387b')
        for offset,reg in ((0x10,5),(0x22C,1),(0x286,6),(0x1A2,6)):
            literal(confirm+offset,reg,confirm+0x3E4,0x1003100)
        for offset in (0x15E,0x284):literal(confirm+offset,1,confirm+0x3E0,0x1003500)
        put(confirm+0x22E,'08685428');put(confirm+0x280,'5328')
        self.branch(image,confirm+0x282,confirm+0x31C,1)
        put(confirm+0x288,'486bc21d29323260496d')
        put(confirm+0x19A,'0020c8650121f973');put(confirm+0x1A4,'5521316002217973269a')
        image[sites['table']+6]=0x5B;image[sites['table']+7]=0x53
        sites.update(call=call,task=task,forwards=forwards,secondary=sink,consumer=consumer,
                     app=app,dispatch=dispatch,join=join,menu=menu,confirm=confirm)
        return image,sites

    def call_image(self, code_delta=0, ram_delta=0, handler_shift=0):
        from msm5xxx_emulator.detection.input_matrix import _DISTRIBUTED_CALL_SPANS
        delta=0xC0000+code_delta
        image,sites=self.controls_image(delta)
        image.extend(bytes.fromhex('c046')*((delta+0xD000-len(image))//2))
        # Relocate the existing parent's RAM owners independently of its code.
        for pc in range(0,len(image)-3,4):
            value=struct.unpack_from('<I',image,pc)[0]
            if 0x1000000+delta <= value < 0x1010000+delta:
                struct.pack_into('<I',image,pc,value+ram_delta)
        handler=sites['confirm']+handler_shift
        if handler_shift:
            image[handler:handler+0x400]=image[sites['confirm']:sites['confirm']+0x400]
            self.bl(image,sites['dispatch']+0x6E,handler)
        owners=dict(status=0x1003500+delta+ram_delta,global_word=0x1003100+delta+ram_delta,
                    gate_state=0x1200000+ram_delta,cleanup_node=0x1200100+ram_delta,
                    cleanup_flags=0x1200202+ram_delta,exit_status=0x1200300+ram_delta,mask_constant=0xFFF7)
        call_slots={}
        for relative,body,literals,calls in _DISTRIBUTED_CALL_SPANS:
            pc=handler+relative;image[pc:pc+len(body)//2]=bytes.fromhex(body)
            pool=((pc+len(body)//2+0x100+3)&~3)
            for index,(offset,register,role) in enumerate(literals):
                slot=pool+4*index;self.literal(image,pc+offset,register,slot,owners[role]);call_slots[relative+offset]=slot
            for offset,target_relative in calls:self.bl(image,pc+offset,handler+target_relative)
        # Keep the existing independent confirm consumer's pool identities coherent.
        for offset,reg,role in ((4,4,'status'),(0x10,5,'global_word'),(0x15E,1,'status'),
                                (0x1A2,6,'global_word'),(0x284,1,'status'),(0x286,6,'global_word')):
            slot=((handler+0x3E0+3)&~3)+(0 if role=='status' else 4)
            self.literal(image,handler+offset,reg,slot,owners[role])
        image[sites['table']+13]=0x50
        sites.update(confirm=handler,call_slots=call_slots,call_owners=owners)
        return image,sites

    def test_optional_call_relocation_and_independent_parent(self):
        for code_delta,ram_delta,shift in ((0,0,0),(0x2000,0,0),(0,0x5000,0),(0,0,2)):
            image,sites=self.call_image(code_delta,ram_delta,shift)
            parent,status,_=resolve_distributed_matrix_input(bytes(image))
            self.assertEqual(status,'static-candidate')
            self.assertEqual(parent['call_mapping_status'],'accepted-provisional',parent.get('call_mapping_reject_reasons'))
            self.assertEqual(parent['call_consumer']['handler'],sites['confirm'])
            self.assertEqual(parent['call_consumer']['request_code'],0x32)
            self.assertEqual(parent['call_consumer']['global_word'],sites['call_owners']['global_word'])
            self.assertEqual(parent['provisional_mappings'][3]['event'],0x50)
            self.assertIn(dict(token='S',event=0x50,row=1,column=2),parent['token_cells'])
            self.assertIs(parent['runtime_admitted'],False)
            self.assertEqual(parent['menu_mapping_status'],parent['ok_mapping_status'])

    def test_call_rejection_keeps_parent_and_other_optional_keys(self):
        from copy import deepcopy
        from msm5xxx_emulator.detection.input_matrix import _distributed_call_profile
        image,sites=self.call_image();parent,status,_=resolve_distributed_matrix_input(bytes(image))
        self.assertEqual(parent['call_mapping_status'],'accepted-provisional')
        handler=sites['confirm']
        for pc,code in ((handler+0x266,'1ed1'),(handler+0x43C,'3320'),
                        (handler+0x36B8,'b873'),(handler+0x156,'38e3')):
            changed=bytearray(image);changed[pc:pc+2]=bytes.fromhex(code)
            before=deepcopy(parent);mapping,meta=_distributed_call_profile(bytes(changed),parent)
            self.assertEqual(mapping,{})
            self.assertEqual(meta['call_mapping_status'],'rejected')
            self.assertEqual(parent,before)
        for key,value in (('confirm_handler',True),('confirm_status',True),('global_word',1),
                          ('application',True),('application',0.0)):
            changed=deepcopy(parent);changed['control_consumer'][key]=value
            self.assertEqual(_distributed_call_profile(bytes(image),changed)[0],{})
        for events in ([v if v!=0x50 else 0x87 for v in parent['event_codes']],
                       parent['event_codes'][:12]+[0x50]+parent['event_codes'][13:],
                       [True]+parent['event_codes'][1:]):
            changed=deepcopy(parent);changed['event_codes']=events
            self.assertEqual(_distributed_call_profile(bytes(image),changed)[0],{})
        changed=bytearray(image)
        struct.pack_into('<I',changed,sites['call_slots'][0x9C2],sites['call_owners']['status'])
        self.assertEqual(_distributed_call_profile(bytes(changed),parent)[0],{})
        from msm5xxx_emulator.detection.arm import thumb_literal_value
        mode=thumb_literal_value(image,parent['control_consumer']['application']+0x6A,1)
        for site in (-0xF3DE,-0x11CC4,-0x11CBC,0x581C):
            changed=bytearray(image)
            struct.pack_into('<I',changed,sites['call_slots'][site],mode)
            mapping,meta=_distributed_call_profile(bytes(changed),parent)
            self.assertEqual(mapping,{})
            self.assertEqual(meta['call_mapping_reject_reasons'],['call-owned-span-alias'])
        for end in (handler+0x584C,sites['call_slots'][0x581C]+3):
            self.assertEqual(_distributed_call_profile(bytes(image[:end]),parent)[0],{})

    def test_call_actual_source_and_optional_tail_failure(self):
        import os
        from pathlib import Path
        from msm5xxx_emulator.detection.input_matrix import _distributed_call_profile
        from corpus import firmware_path
        image = firmware_path('SPH-X4500.bin').read_bytes()
        parent,status,_=resolve_distributed_matrix_input(image)
        self.assertEqual(status,'static-candidate');self.assertEqual(parent['call_mapping_status'],'accepted-provisional')
        self.assertEqual((parent['call_consumer']['event'],parent['call_consumer']['request_code']),(0x50,0x32))
        self.assertEqual(set(parent['provisional_mappings']),{0,1,2,3,4,5,6,9})
        changed=bytearray(image);changed[0xCDF74:0xCDF76]=bytes.fromhex('0120')
        rejected,_,_=resolve_distributed_matrix_input(bytes(changed))
        self.assertEqual(rejected['call_mapping_status'],'rejected')
        self.assertEqual(set(rejected['provisional_mappings']),set(parent['provisional_mappings'])-{3})
        self.assertEqual(rejected['back_mapping_status'],'accepted-provisional')
        self.assertEqual(rejected['navigation_mapping_status'],'accepted-provisional')

    def navigation_image(self, code_delta=0, ram_delta=0, handler_shift=0):
        """Independent Thumb instruction fixture, symbolic owners and local BLs."""
        image,sites=self.controls_image(code_delta)
        image.extend(bytes.fromhex('c046')*((code_delta+0x9000-len(image))//2))
        # Separate RAM relocation from code relocation of the existing parent.
        ram_values=(0x1001022,0x1001020,0x100101e,0x1002000,0x1002100,0x1002200,
                    0x1002300,0x1003000,0x1003100,0x1003200,0x1003300,0x1003400,0x1003500)
        for pc in range(0,len(image)-3,4):
            value=struct.unpack_from('<I',image,pc)[0]
            if value-code_delta in ram_values:
                struct.pack_into('<I',image,pc,value-code_delta+ram_delta)
        handler=sites['confirm']+handler_shift
        if handler_shift:
            body=bytes(image[sites['confirm']:sites['confirm']+0x400])
            image[handler:handler+len(body)]=body
            self.bl(image,sites['dispatch']+0x6E,handler)
        status,global_word,grid,alternate=[v+ram_delta for v in (0x1003500,0x1003100,0x1003700,0x1003740)]
        def put(offset,body):
            image[handler+offset:handler+offset+len(body)//2]=bytes.fromhex(body)
        # Event decision tree: numeric/OK cases plus the 63/64/65/66 branches.
        put(0x22C,'00490868542836d036dc362835d013dc322832d009dc23282fd02a282dd030282bd0312864d11ae191e0332825d0342823d035285cd112e150281ed006dc37281bd0382819d0392852d108e1512850d052284fd053284bd10049004e486bc21d29323260496d004a914244d1002843d1ff2005301fe369e000e03be3ff230233984236d039dc642838d038dc552837d05b2836d060282cd0632829d1')
        # -3 primary mode: previous/current/count stores and signed wrap math.
        put(0x2C8,'004a004e516d004ee160506bb142106344d1c11e51631991106d0068002813d01999004800290fda806bc11c061c03200000000043001999181840180049b042486301dd00484663ff20004e013030600048bfe1')
        put(0x31C,snippet("test_input_matrix_distributed", "navigation_dispatch").hex())
        # +1 current/previous stores, mode flag and count+1 remainder call.
        put(0x338,'ff2000490130004a0860566de660506b411c10635163106d0068002812d0906b013000000000004a516393e1')
        put(0x364,snippet("test_input_matrix_distributed", "navigation_handler").hex())
        # +1 alternate mode uses (value-1) remainder then adds one.
        put(0x67C,'00480139806b00000000481c00494863')
        # -1: old store, software100, decrement, signed/zero mode wrap to count.
        put(0x730,'004aff21506b004e10630131316001385063116d0968002902d0002804da01e0002801d1906b5063')
        # -3 alternate descriptor: threshold one, signed wrap and software100.
        put(0x88C,'004b994225d12799497a002921d10049033848631890086d0069002813d01899004801290fda806bc11c061c03200000000043001899181840180049b042486301dd00484663ff20004e013030600048e3e6')
        # +3 both descriptor/mode arms: count comparisons/clamp/remainder.
        put(0x8E4,'0049004a486d904228d1486bc61c08634e63086d0068002817d0886b1790864213dd1798c11c03200000000043001818b04204dd00491798486306e04be00320311c0000000000484163ff200049013008600049486b000000001ee1004a904232d1279b587a00282fd10049486bc61c08634e63086d0069002817d0886b1690864213dd1698c11c032000000000430018180130b04203dd00491698486305e00320311c0000000000484163ff20004901300860')
        division=code_delta+0x8000
        body='cb175940c91ac2175040801a0cb44b08021c02d10000000052009a42fcd90023914205d2db18824206d052089142f9d35b41891a8242f8d1181c0cbc5a405040801a5940c91a7047'
        image[division:division+len(body)//2]=bytes.fromhex(body)
        self.bl(image,division+0x14,code_delta+0x8200)
        for offset in (0x2F8,0x35A,0x682,0x8BA,0x90C,0x926,0x96E,0x988):
            self.bl(image,handler+offset,division)
        self.bl(image,handler+0x93A,handler-0x2870)
        status_sites=(0x284,0x2C8,0x2EA,0x304,0x30C,0x318,0x33E,0x35E,0x67C,0x688,
                      0x730,0x89A,0x8AC,0x8C6,0x8CE,0x8DA,0x8E4,0x918,0x92A,0x936,0x94E,0x97C,0x98C)
        global_sites=(0x22C,0x286,0x2CA,0x312,0x33A,0x736,0x8D4,0x930,0x992)
        literal_sites={**{o:status for o in status_sites},**{o:global_word for o in global_sites},
                       **{o:grid for o in (0x292,0x2CE,0x8E6)},**{o:alternate for o in (0x88C,0x940)}}
        slots={}
        for offset,value in literal_sites.items():
            bank=0x3E0 if offset<0x400 else 0x7D0 if offset<0x800 else 0xBD0
            owner_index=(status,global_word,grid,alternate).index(value)
            slot=(handler+bank+3)&~3;slot+=owner_index*4
            register=(struct.unpack_from('<H',image,handler+offset)[0]>>8)&7
            self.literal(image,handler+offset,register,slot,value);slots[offset]=slot
        # Parent initializer/internal55 pools remain coherent after a 2-mod4 shift.
        for offset,reg,value in ((4,4,status),(0x10,5,global_word),(0x15E,1,status),(0x1A2,6,global_word)):
            slot=((handler+0x3E0+3)&~3)+(0 if value==status else 4)
            self.literal(image,handler+offset,reg,slot,value)
        for index,value in ((0,0x63),(1,0x66),(12,0x65),(19,0x64)):
            image[sites['table']+index]=value
        sites.update(confirm=handler,division=division,nav_slots=slots)
        return image,sites

    def back_image(self, code_delta=0, ram_delta=0, handler_shift=0):
        image,sites=self.navigation_image(code_delta,ram_delta,handler_shift)
        handler=sites['confirm']
        # Independent saved-menu branch fixture: preserve, decrement, restore,
        # indexed saved entry/selection, request and internal55 publication.
        body=bytes.fromhex('004a0049506d884201d101209070906d002803d1ff200130004930e300490868002802dd0138086005e0ff20004e0130306032207873506d004b984206d1279b587a002802d0279b00205872906d004950654369161c13650968002905dc0022b265ff22e272a27208e0004bca00d2181268b265e27aa2720022e272004ac90089184968321c01397163007e02210138b0630120f8737973004e55213160')
        image[handler+0x52A:handler+0x52A+len(body)]=body
        status,global_word,alternate,history,comparison=[v+ram_delta for v in
            (0x1003500,0x1003100,0x1003740,0x1003900,0x1003980)]
        owners={0x52A:status,0x52C:comparison,0x542:global_word,0x546:history,
                0x556:global_word,0x562:alternate,0x578:history,0x594:history,0x5A6:history,0x5C2:global_word}
        slots={}
        for offset,value in owners.items():
            owner_index=(status,global_word,alternate,history,comparison).index(value)
            slot=((handler+0x7D0+3)&~3)+owner_index*4
            # Existing navigation bank owns status/global/grid/alternate slots.
            if value==alternate:slot=((handler+0x7D0+3)&~3)+12
            elif value==history:slot=((handler+0x7D0+3)&~3)+16
            elif value==comparison:slot=((handler+0x7D0+3)&~3)+20
            register=(struct.unpack_from('<H',image,handler+offset)[0]>>8)&7
            self.literal(image,handler+offset,register,slot,value);slots[offset]=slot
        image[sites['table']+20]=0x52
        sites.update(back_slots=slots,history=history,comparison=comparison)
        return image,sites

    def test_optional_back_rom_ram_relocation_and_halfword_handler(self):
        for code_delta,ram_delta,shift in ((0,0,0),(0x3000,0,0),(0,0x5000,0),(0,0,2)):
            image,sites=self.back_image(code_delta,ram_delta,shift)
            parent,status,_=resolve_distributed_matrix_input(bytes(image))
            self.assertEqual(status,'static-candidate')
            self.assertEqual(parent['back_mapping_status'],'accepted-provisional')
            self.assertIs(parent['runtime_admitted'],False)
            self.assertEqual(parent['back_consumer']['history'],sites['history'])
            self.assertEqual(parent['back_consumer']['handler'],sites['confirm'])
            self.assertEqual(parent['provisional_mappings'][2]['event'],0x52)
            self.assertEqual(set(parent['provisional_mappings']),{0,1,2,4,5,6,9})
            self.assertEqual({c['token'] for c in parent['token_cells']},set('123456789*0#MOUDLRC'))
            self.assertIn(dict(token='C',event=0x52,row=2,column=3),parent['token_cells'])

    def test_back_reject_keeps_navigation_controls_numeric(self):
        image,sites=self.back_image();handler=sites['confirm'];mutations=[]
        for relative in (0x536,0x53C,0x550,0x55A,0x57A,0x580,0x58A,0x59C,0x5B2,0x5BA,0x5BE,0x5C6):
            changed=image.copy();struct.pack_into('<H',changed,handler+relative,0x4770);mutations.append(changed)
        # Source-owned history aliases, foreign pools and misaligned pointers.
        for value in (0x1003500,0x1003700,0x1003300,0x1001020,0x3000660,0x2FFFFFC,sites['history']+2):
            changed=image.copy();struct.pack_into('<I',changed,sites['back_slots'][0x546],value);mutations.append(changed)
        changed=image.copy();struct.pack_into('<I',changed,sites['back_slots'][0x52C],sites['history']);mutations.append(changed)
        changed=image.copy();self.literal(changed,handler+0x578,1,sites['back_slots'][0x578]+4,sites['comparison']);mutations.append(changed)
        changed=image.copy();changed[sites['table']+21]=0x52;mutations.append(changed)
        changed=image.copy();changed[sites['table']+20]=0;mutations.append(changed)
        # Remove only tail of back span while retaining all parent/nav code in a
        # direct optional-helper fixture; resolver-level truncation can also reject nav.
        from msm5xxx_emulator.detection.input_matrix import _distributed_back_profile
        parent,_,_=resolve_distributed_matrix_input(bytes(image))
        mappings,metadata=_distributed_back_profile(bytes(image[:handler+0x5C6]),parent)
        self.assertFalse(mappings);self.assertEqual(metadata['back_mapping_status'],'rejected')
        for changed in mutations:
            with self.subTest():
                parent,status,_=resolve_distributed_matrix_input(bytes(changed))
                self.assertEqual(status,'static-candidate')
                self.assertEqual(parent['back_mapping_status'],'rejected')
                self.assertEqual(parent['menu_mapping_status'],'accepted-provisional')
                self.assertEqual(parent['ok_mapping_status'],'accepted-provisional')
                self.assertEqual(parent['navigation_mapping_status'],'accepted-provisional')
                self.assertEqual(set(parent['provisional_mappings']),{0,1,4,5,6,9})
                self.assertEqual({c['token'] for c in parent['token_cells']},set('123456789*0#MOUDLR'))
                self.assertTrue(parent['back_mapping_reject_reasons'])

    def test_optional_navigation_code_and_ram_relocation(self):
        for code_delta,ram_delta,handler_shift in ((0,0,0),(0x3000,0,0),(0,0x5000,0),(0,0,2)):
            image,sites=self.navigation_image(code_delta,ram_delta,handler_shift)
            profile,status,_=resolve_distributed_matrix_input(bytes(image))
            self.assertEqual(status,'static-candidate')
            self.assertEqual(profile['navigation_mapping_status'],'accepted-provisional')
            nav=profile['navigation_consumer']
            self.assertEqual((nav['handler'],nav['status'],nav['global_word'],nav['grid_stride']),
                             (sites['confirm'],0x1003500+ram_delta,0x1003100+ram_delta,3))
            self.assertEqual({bit:profile['provisional_mappings'][bit]['event'] for bit in (1,9,4,6)},
                             {1:0x63,9:0x64,4:0x65,6:0x66})
            self.assertEqual({cell['token'] for cell in profile['token_cells']},set('123456789*0#MOUDLR'))

    def test_navigation_reject_keeps_controls_and_numeric(self):
        image,sites=self.navigation_image();handler=sites['confirm'];mutations=[]
        for offset in (0x264,0x2D8,0x2DC,0x332,0x334,0x348,0x34C,0x35A,0x682,
                       0x73E,0x740,0x74C,0x756,0x89C,0x8B0,0x8BA,0x8F0,0x8F4,0x8FE,0x958,0x988):
            changed=image.copy();struct.pack_into('<H',changed,handler+offset,0x4770);mutations.append(changed)
        for slot,value in ((sites['nav_slots'][0x8E6],0x1003780),
                           (sites['nav_slots'][0x940],0x1003700),
                           (sites['nav_slots'][0x8E6],0x1003500),
                           (sites['nav_slots'][0x8E6],0x1001020),
                           (sites['nav_slots'][0x8E6],0x1003300)):
            changed=image.copy();struct.pack_into('<I',changed,slot,value);mutations.append(changed)
        for site,target in ((handler+0x35A,sites['division']+2),
                            (handler+0x988,len(image)+0x100),
                            (sites['division']+0x14,len(image)+0x100)):
            changed=image.copy();self.bl(changed,site,target);mutations.append(changed)
        changed=image.copy();changed[sites['division']+2]^=1;mutations.append(changed)
        changed=image.copy();changed[sites['table']+23]=0x63;mutations.append(changed)
        changed=image.copy();changed[sites['table']+12]=0x67;mutations.append(changed)
        mutations.extend((image[:handler+0x950],image[:sites['division']+30]))
        for changed in mutations:
            with self.subTest():
                profile,status,_=resolve_distributed_matrix_input(bytes(changed))
                self.assertEqual(status,'static-candidate')
                self.assertEqual(profile['menu_mapping_status'],'accepted-provisional')
                self.assertEqual(profile['ok_mapping_status'],'accepted-provisional')
                self.assertEqual(profile['navigation_mapping_status'],'rejected')
                self.assertEqual(set(profile['provisional_mappings']),{0,5})
                self.assertEqual({c['token'] for c in profile['token_cells']},set('123456789*0#MO'))
                self.assertTrue(profile['navigation_mapping_reject_reasons'])

    def test_optional_controls_relocate_and_reject_broken_links_without_numeric_loss(self):
        for delta in (0,0x3000):
            image,sites=self.controls_image(delta)
            profile,status,_=resolve_distributed_matrix_input(bytes(image))
            self.assertEqual(status,'static-candidate')
            self.assertEqual(profile['menu_mapping_status'],'accepted-provisional')
            self.assertEqual(profile['ok_mapping_status'],'accepted-provisional')
            self.assertFalse(profile['runtime_admitted'])
            self.assertEqual(profile['control_consumer']['global_word'],0x1003100+delta)
            self.assertEqual(profile['control_consumer']['application'],sites['app'])
            self.assertEqual(profile['token_cells'][-2:],[
                dict(token='M',event=91,row=0,column=1),dict(token='O',event=83,row=1,column=1)])
        image,sites=self.controls_image()
        mutations=[]
        for pc in (sites['call'],sites['forwards'][0],sites['secondary']+0x46,
                   sites['consumer']+8,sites['app']+0x94,sites['dispatch'],sites['join']+0x26,
                   sites['menu']+0x1A,sites['confirm']+0x1A4,sites['confirm']+0x28C):
            changed=image.copy();struct.pack_into('<H',changed,pc,0x4770);mutations.append(changed)
        for slot,value in ((sites['secondary']+0x80,0x1002300),
                           (sites['consumer']+0x40,0x1003040),
                           (sites['app']+0x300,0x1003000),
                           (sites['app']+0x300,0x1003101),
                           (sites['app']+0x300,0x1002200),
                           (sites['confirm']+0x3E4,0x1003104),
                           (sites['confirm']+0x3E0,0x1003400)):
            changed=image.copy();struct.pack_into('<I',changed,slot,value);mutations.append(changed)
        changed=image.copy()
        struct.pack_into('<I',changed,sites['app']+0x300,0x1001020)
        struct.pack_into('<I',changed,sites['confirm']+0x3E4,0x1001020)
        mutations.append(changed)  # Coherent owned global must not overwrite GPIO shadows.
        changed=image.copy();changed[sites['table']]=0x5B;mutations.append(changed)
        changed=image.copy();changed[sites['dispatch']+0x14+3]=0;mutations.append(changed)
        changed=image.copy();self.bl(changed,sites['task']+0x10,0x80)
        changed[sites['task']+0x14:sites['task']+0x18]=image[sites['call']+4:sites['call']+8]
        self.branch(changed,sites['task']+0x18,sites['task']);mutations.append(changed)
        for changed in mutations:
            with self.subTest():
                profile,status,_=resolve_distributed_matrix_input(bytes(changed))
                self.assertEqual(status,'static-candidate')
                self.assertEqual(profile['menu_mapping_status'],'rejected')
                self.assertEqual(profile['ok_mapping_status'],'rejected')
                self.assertNotIn('provisional_mappings',profile)
                self.assertEqual({c['token'] for c in profile['token_cells']},set('123456789*0#'))
                self.assertTrue(profile['control_mapping_reject_reasons'])

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
