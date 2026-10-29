import struct
import os
import unittest

from msm5xxx_emulator.detection.ready_poll import find_ready_poll_profile
from msm5xxx_emulator.detection.uart_console import find_uart_console_profile
from corpus import FIRMWARE_ROOT


def fixture(shift=0, sibling=False):
    data = bytearray(0x400 + shift)
    def word(at, value):
        struct.pack_into('<H', data, at + shift, value)
    def words(at, values):
        for i, value in enumerate(values):
            word(at + i * 2, value)
    def bl(at, target):
        displacement = target - at - 4
        words(at, (0xF000 | (displacement >> 12 & 0x7FF),
                   0xF800 | (displacement >> 1 & 0x7FF)))
    def literal(at, register, target):
        word(at, 0x4800 | register << 8 | ((target + shift - ((at + shift + 4) & ~3)) // 4))
    def value(at, number):
        struct.pack_into('<I', data, at + shift, number)
    words(0x40, (0xB500,))
    for at, target in ((0x42, 0x100), (0x46, 0x130), (0x4A, 0x280)):
        bl(at, target)
    data[0x4E + shift:0x5E + shift] = bytes.fromhex('011c0c2902d1012008bc18470020fbe7')
    primary = bytes.fromhex('00200949097909090dd2011c421c101c4908f6d30121054a1170002111702021014a1173ede77047')
    data[0x100 + shift:0x128 + shift] = primary
    literal(0x102, 1, 0x128); literal(0x116, 2, 0x12C); literal(0x120, 2, 0x128)
    value(0x128, 0x03000F10); value(0x12C, 0x03000700)
    init = [0xB500,0x2000,0,0x7108,0x2080,0,0x8088,0,0,
            0x20C0,0,0x3910,0x7108,0x20AF,0x7208,0x2080,0x7308,0x2019,0,0x7008,
            0x2000,0,0x3920,0x7008,0x8188,0x201E,0x8108,0x2000,0,0x3940,0x8188,
            0x2034,0,0x3930,0x7008,0x2099,0x7108,0x2030,0x7308,0x2010,0x7308,
            0x7308,0x2020,0x7308,0x7308,0x2001,0x7308,0x2004,0x7308]
    words(0x130, init)
    for offset in (4, 0x14, 0x24, 0x2A, 0x38, 0x40):
        literal(0x130 + offset, 1, 0x1C0)
    literal(0x13A, 1, 0x1C4); bl(0x13E, 0x100)
    if sibling:
        for at, number in ((0x14A,0xB2),(0x14E,0x7D),(0x152,0x1C)):
            word(at, 0x2000 | number)
    words(0x192, (0,0x3830,0x7900,0x0840,0xD200,0xE008,0,0x3830,0x7A02,
                  0x2001,0,0x7008,0x2000,0x7008,0xE7F0,0xBC08,0x4718))
    literal(0x192,0,0x1C0);literal(0x19E,0,0x1C0);literal(0x1A6,1,0x1C8)
    value(0x1C0,0x03000F40);value(0x1C4,0x03000620);value(0x1C8,0x03000700)
    words(0x200,(0xB5B0,0x1C05,0x200A));bl(0x206,0x300);word(0x20A,0x2D00)
    literal(0x210,0,0x2F0);word(0x212,0x7904)
    literal(0x214,0,0x2F0);word(0x216,0x7A00)
    word(0x23E,0x200A);bl(0x240,0x300)
    words(0x244,(0xBCB0,0xBC08,0x4718))
    words(0x280,(0xB590,0,0x7800,0x2800,0xD004,0x2001,0,0,0x1C07,
                  0xE003,0x2000,0,0,0x1C07,0x1CBB))
    literal(0x282,0,0x2F4);bl(0x28C,0x200);bl(0x296,0x200)
    value(0x2F0,0x03000F10);value(0x2F4,0x01800000)
    words(0x300,(0,0x7809,0x0849,0xD205,0x2101,0,0x7011,0x2100,
                  0x7011,0xE7F5,0,0x3910,0x7208,0x4770))
    literal(0x300,1,0x330);literal(0x30A,2,0x334);literal(0x314,1,0x330)
    value(0x330,0x03000F20);value(0x334,0x03000700)
    return bytes(data)


def legacy_fixture(layout='register-and',shift=0,extended_root=False):
    from msm5xxx_emulator.detection.uart_console import _BYTE_LAYOUTS, _BYTE_EXTENDED_ROOT
    spec=_BYTE_LAYOUTS[layout]
    if extended_root:
        assert layout=='register-and'
        spec={**spec,**_BYTE_EXTENDED_ROOT}
    data=bytearray(0x3400+shift)
    positions={name:at+shift for name,at in dict(primary=0x2000,init_head=0x2080,
        root=0x1800,dispatch=0x1400,parser_head=0x1000,rx=0x2500,wrapper=0x2800,
        tx=0x2b00,ack1=0x800,ack2=0xc00,flag=0x1c00).items()}
    positions['drain']=positions['init_head']+spec['drain_off']
    def bl(site,target):
        disp=target-site-4
        struct.pack_into('<2H',data,site,0xf000|(disp>>12&2047),0xf800|(disp>>1&2047))
    pools={name:(at+(0x40 if name=='primary' else 0x180 if name=='init_head' else 0x200)+3)&~3
           for name,at in positions.items()}
    def literal(name,offset,value):
        site=positions[name]+offset
        word=struct.unpack_from('<H',data,site)[0]
        pool=pools[name];pools[name]+=4
        assert pool>=((site+4)&~3) and pool-((site+4)&~3)<=0x3fc
        struct.pack_into('<H',data,site,0x4800|(word&0x700)|((pool-((site+4)&~3))//4))
        struct.pack_into('<I',data,pool,value)
    for name,at in positions.items():
        mask=spec[name]
        for index in range(0,len(mask),2):
            if mask[index:index+2]!='??':data[at+index//2]=int(mask[index:index+2],16)
        offset=0
        while offset<len(mask)//2-1:
            if mask[offset*2:offset*2+8]=='????????':
                bl(at+offset,0x3000+shift);offset+=4;continue
            word=struct.unpack_from('<H',data,at+offset)[0]
            if word&0xf800==0x4800:literal(name,offset,0x1801000)
            offset+=2
    bodies={'register-and': '82211c480181802404810027078187801a490180018008210175184901800180fff7d7ffc02116480175af21017604771921144a1170077007731e210172124a177334201074ff201075302010771020107710772020107710770121117704201077', 'lsr-ready': 'c02017490871af2008728020087319201549087000201449087008731e200872002012490873342012490870ff200871302008731020087308732020087308730120087304200873'}
    body=bytes.fromhex(bodies[layout]);start=positions['init_head']+spec['body']
    data[start:start+len(body)]=body
    for offset in range(spec['body'],spec['drain_off'],2):
        word=struct.unpack_from('<H',data,positions['init_head']+offset)[0]
        if word&0xf800==0x4800:literal('init_head',offset,0x1801000)
    init=positions['init_head'];root=positions['root'];primary=positions['primary']
    for off,target in ((spec['root_init_call'],init),(spec['root_primary_call'],primary),
                       (spec['root_flag_call'],positions['flag']),(spec['root_dispatch_call'],positions['dispatch'])):
        bl(root+off,target)
    bl(init+spec['primary_call'],primary)
    bl(positions['dispatch']+spec['dispatch_parser_call'],positions['parser_head'])
    for off in spec['parser_receive_calls']:bl(positions['parser_head']+off,positions['wrapper'])
    for off in spec['wrapper_rx_calls']:bl(positions['wrapper']+off,positions['rx'])
    for name,offsets in zip(('ack1','ack2'),spec['ack_calls']):
        for off in offsets:bl(positions[name]+off,positions['tx'])
    bl(positions['parser_head']+0x50,positions['ack2'])
    base,pulse,flag=0x030007ac,0x03000600,0x1801000
    terms={}
    if layout=='register-and':
        terms={'primary':((2,base-12),(6,pulse)),
               'init_head':((0xc,base-0x6c),(0x1a,0x37f),(0x24,0x37d),
                            (0x30,base+0x14),(0x3c,base+0x34),(0x48,base-12)),
               'root':((0xc,base-0x16c),),'dispatch':((0xa,0x40),(0x14,flag)),
               'parser_head':((0x16,pulse),),'flag':((2,flag),),
               'drain':((0,pulse),),'rx':((6,base-12),(12,pulse),(18,0xf4240)),
               'wrapper':((0xa,flag+0x3c),(0x38,base-12)),
               'tx':((6,base+0x14),(10,pulse),(0x1c,base-12)), 'ack2':((0xc,flag+4),)}
    else:
        terms={'primary':((0,base+4),(10,pulse)),
               'init_head':((0xc,base+0x24),(0x1a,base+0x34),(0x20,base+0x14),
                            (0x2c,base-12),(0x32,base+4)),
               'root':((4,base-0x12c),),'dispatch':((2,0x40),(0xc,flag),(0x10,flag),(0x1a,flag)),
               'parser_head':((0xe,pulse),),'flag':((0,0x40),(0x16,flag),(0x20,flag)),
               'drain':((0,base+4),(8,base+4),(14,pulse)),
               'rx':((8,0xf4240),(0x14,base+4),(0x24,pulse),(0x36,base+4),(0x44,pulse)),
               'wrapper':((2,flag+8),(0x34,base+4),(0x42,base+4),(0x4c,base+4)),
               'tx':((0,base+0x14),(10,pulse),(0x14,base+4)),'ack2':((6,0x40),)}
    if extended_root:
        terms['root']=((0xc,base-0x16c),(0x12,base-0x10c))
    for name,values in terms.items():
        for offset,value in values:literal(name,offset,value)
    return bytes(data),positions


class UartConsoleTests(unittest.TestCase):
    def test_relocated_closed_profile_and_clock_sibling(self):
        for shift in (0, 0x204):
            for sibling in (False, True):
                image = fixture(shift, sibling)
                ready = find_ready_poll_profile(image)
                profile, reason = find_uart_console_profile(image, ready)
                self.assertEqual(reason, 'accepted')
                self.assertEqual(profile['base'], 0x03000F0C)
                self.assertEqual(profile['primary_entry'], 0x100 + shift)
                self.assertEqual(profile['init_entry'], 0x130 + shift)
                self.assertEqual(profile['tx_entry'], 0x300 + shift)
                self.assertEqual(profile['policy'], 'provisional-synchronous-null-console')
                self.assertEqual(len(profile['init_writes']), 19)
                self.assertEqual(profile['clock_setup'], (0xC0,0xB2,0x7D,0x1C) if sibling else (0xC0,0xAF,0x80,0x19))

    def test_required_links_widths_values_aliases_and_branches_fail_closed(self):
        original = fixture()
        ready = find_ready_poll_profile(original)
        mutations = {
            'primary-status':0x104, 'primary-branch':0x108, 'primary-control':0x122,
            'root-primary-call':0x42, 'root-init-call':0x46, 'root-receive-call':0x4A,
            'init-primary-call':0x13E, 'init-MR1-width':0x16C, 'init-MR2':0x16E,
            'init-CSR':0x176, 'init-TFWR':0x162, 'init-RFWR-width':0x160,
            'init-IMR':0x158, 'init-CR-reset':0x17A, 'init-CR-enable':0x18A,
            'init-base':0x1C0, 'clock-third-tuple':0x14A,
            'suffix-RX-width':0x196, 'suffix-RF':0x1A2, 'suffix-backedge':0x1AE,
            'wrapper-branch':0x288, 'wrapper-first-call':0x28C,
            'wrapper-second-call':0x296, 'wrapper-flag':0x2F7,
            'receive-TX-call':0x206, 'receive-status-base':0x2F0,
            'receive-TX-value':0x23E, 'TX-status-width':0x302, 'TX-branch':0x306,
            'TX-backedge':0x312, 'TX-TF-width':0x318, 'TX-base':0x330, 'TX-pulse':0x334,
        }
        for name, at in mutations.items():
            with self.subTest(name=name):
                changed = bytearray(original);changed[at] ^= 1
                self.assertIsNone(find_uart_console_profile(bytes(changed), ready)[0])
        profile, _ = find_uart_console_profile(original, ready)
        for write in profile['init_writes']:
            with self.subTest(typed_write_width_pc=write['pc']):
                changed = bytearray(original)
                word = struct.unpack_from('<H', changed, write['pc'])[0]
                struct.pack_into('<H', changed, write['pc'], word ^ 0x1000)
                self.assertIsNone(find_uart_console_profile(bytes(changed), ready)[0])
        self.assertIsNone(find_uart_console_profile(original, None)[0])
        self.assertIsNone(find_uart_console_profile(original[:0x319], ready)[0])

    def test_duplicates_and_forged_profile_do_not_select_first(self):
        image = fixture();ready = find_ready_poll_profile(image)
        self.assertIsNone(find_uart_console_profile(image + image, ready)[0])
        duplicate_tx = bytearray(image)
        duplicate_tx[0x380:0x39C] = image[0x300:0x31C]
        duplicate_tx[0x3B0:0x3B8] = image[0x330:0x338]
        self.assertIsNone(find_uart_console_profile(bytes(duplicate_tx), ready)[0])
        changed = bytearray(image)
        displacement = 0x130 - 0x380 - 4
        struct.pack_into('<2H',changed,0x380,0xF000|(displacement>>12&0x7FF),0xF800|(displacement>>1&0x7FF))
        self.assertIsNone(find_uart_console_profile(bytes(changed),ready)[0])
        self.assertIsNone(find_uart_console_profile(image,{**ready,'entries':[0x100,0x200]})[0])
        self.assertIsNone(find_uart_console_profile(image,{**ready,'status_address':0x030007B4})[0])

    def test_legacy_byte_profiles_relocate_without_ready_marker(self):
        for layout in ('register-and','lsr-ready'):
            for shift in (0,0x204):
                image,pos=legacy_fixture(layout,shift)
                profile,reason=find_uart_console_profile(image,None)
                self.assertEqual(reason,'accepted')
                self.assertEqual(profile['signature'],'thumb-uart-byte-sync-console-v1')
                self.assertEqual((profile['register_width'],profile['csr_value']),(1,0xff))
                self.assertEqual(profile['base'],0x030007ac)
                self.assertEqual(profile['primary_entry'],pos['primary'])
                self.assertEqual(profile['init_entry'],pos['init_head'])
                self.assertEqual(profile['tx_entry'],pos['tx'])
                self.assertIsNone(profile['primary_control_pc'])

    def test_legacy_typed_producers_links_literals_and_returns(self):
        from msm5xxx_emulator.detection.uart_console import _BYTE_LAYOUTS
        for layout in ('register-and','lsr-ready'):
            image,pos=legacy_fixture(layout)
            profile,_=find_uart_console_profile(image,None)
            for write in profile['init_writes']:
                changed=bytearray(image)
                opcode=struct.unpack_from('<H',changed,write['pc'])[0]
                struct.pack_into('<H',changed,write['pc'],opcode^0x1000)
                changed_profile, _ = find_uart_console_profile(bytes(changed),None)
                self.assertIsNone(changed_profile)
                if write['address'] == profile['base'] + 0x1c:
                    # STRH scales the immediate by two; retain the original address.
                    imm = (opcode >> 6) & 31
                    self.assertEqual(imm % 2, 0)
                    struct.pack_into('<H',changed,write['pc'],
                                     ((opcode & 0x7ff) | 0x8000) - (imm // 2 << 6))
                    changed_profile, _ = find_uart_console_profile(bytes(changed),None)
                    if layout == 'lsr-ready':
                        self.assertEqual(changed_profile['signature'],
                                         'thumb-uart-byte-tfwr16-sync-console-v1')
                    else:
                        self.assertIsNone(changed_profile)
            for role in ('primary','drain','rx','wrapper','tx','root','dispatch','parser_head','ack1','ack2','flag'):
                changed=bytearray(image);changed[pos[role]]^=1
                self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0],(layout,role))
            spec=_BYTE_LAYOUTS[layout]
            for role,offset in (('root',spec['root_init_call']),('root',spec['root_primary_call']),
                                ('dispatch',spec['dispatch_parser_call']),('wrapper',spec['wrapper_rx_calls'][0]),
                                ('ack2',spec['ack_calls'][1][0])):
                changed=bytearray(image);changed[pos[role]+offset:pos[role]+offset+4]=bytes(4)
                self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0])
            # Primary literals, including out-of-image targets, cannot be borrowed.
            changed=bytearray(image)
            site=pos['primary']+(2 if layout=='register-and' else 0)
            word=struct.unpack_from('<H',changed,site)[0]
            pool=((site+4)&~3)+(word&255)*4
            struct.pack_into('<I',changed,pool,0x02000000)
            self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0])
            self.assertIsNone(find_uart_console_profile(image[:pos['tx']+4],None)[0])
            self.assertIsNone(find_uart_console_profile(b'X'+image,None)[0])
            branch_offsets=(0xa,0xc,0x10,0x16,0x1a) if layout=='register-and' else (2,4,6,0x12,0x14)
            for offset in branch_offsets:
                changed=bytearray(image);changed[pos['primary']+offset]^=1
                self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0])
            changed=bytearray(image)
            csr=changed.find(bytes.fromhex('ff20'),pos['init_head'],pos['drain'])
            self.assertGreater(csr,0)
            changed[csr]^=1
            self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0])
            self.assertIsNone(find_uart_console_profile(image[pos['primary']:],None)[0])

    def test_legacy_ambiguity_and_useful_reject_reason(self):
        image,pos=legacy_fixture()
        self.assertIsNone(find_uart_console_profile(image+image,None)[0])
        modern=fixture();combined=bytearray(image);combined[:len(modern)]=modern
        self.assertEqual(find_uart_console_profile(bytes(combined),find_ready_poll_profile(modern))[1],
                         'console-protocol-ownership-ambiguous')
        changed=bytearray(image);changed[pos['init_head']+0xa]^=1
        self.assertTrue(find_uart_console_profile(bytes(changed),None)[1].startswith('console-byte-'))
        self.assertEqual(find_uart_console_profile(bytes(32),None)[1],'console-primary-profile-absent')

    def test_extended_register_root_relocates_with_closed_controller_setup(self):
        for shift in (0,0x204):
            image,pos=legacy_fixture(shift=shift,extended_root=True)
            profile,reason=find_uart_console_profile(image,None)
            self.assertEqual(reason,'accepted')
            self.assertEqual(profile['console_root'],pos['root'])
            self.assertEqual(profile['base'],0x030007ac)
            self.assertEqual((profile['register_width'],profile['csr_value']),(1,0xff))
            self.assertIn((pos['root'],pos['root']+52),profile['code_intervals'])
            self.assertEqual(profile['tx_callers'],[pos['ack1']+14,pos['ack1']+20,
                                                   pos['ack2']+18,pos['ack2']+24])

    def test_extended_root_opcodes_producers_calls_and_boundaries(self):
        for shift in (0,0x204):
            image,pos=legacy_fixture(shift=shift,extended_root=True)
            root=pos['root']
            for offset in (0,2,4,0xe,0x10,0x14,0x16,0x18,0x1a,0x1c,0x1e,0x20,
                           34,38,42,46,50):
                changed=bytearray(image);changed[root+offset]^=1
                self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0],hex(offset))
            for offset,wrong in ((0xc,0x03000600),(0x12,0x03000680)):
                changed=bytearray(image);site=root+offset
                opcode=struct.unpack_from('<H',changed,site)[0]
                pool=((site+4)&~3)+(opcode&255)*4
                struct.pack_into('<I',changed,pool,wrong)
                self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0])
            for offset in (0xe,0x14,0x16,0x1a,0x1c,0x1e,0x20):
                changed=bytearray(image);site=root+offset
                opcode=struct.unpack_from('<H',changed,site)[0]
                struct.pack_into('<H',changed,site,opcode^0x1000)
                self.assertIsNone(find_uart_console_profile(bytes(changed),None)[0])
            self.assertIsNone(find_uart_console_profile(image[:root+50],None)[0])
            self.assertIsNone(find_uart_console_profile(b'X'+image,None)[0])

    def test_extended_root_does_not_hide_ambiguity_or_modern_ownership(self):
        image,pos=legacy_fixture(extended_root=True)
        self.assertIsNone(find_uart_console_profile(image+image,None)[0])
        modern=fixture();combined=bytearray(image);combined[:len(modern)]=modern
        self.assertEqual(find_uart_console_profile(bytes(combined),find_ready_poll_profile(modern))[1],
                         'console-protocol-ownership-ambiguous')

    def test_partial_legacy_primaries_do_not_hide_a_complete_profile(self):
        from unittest import mock
        from msm5xxx_emulator.detection import uart_console
        legacy,pos=legacy_fixture()
        primary=legacy[pos['primary']:pos['primary']+0x60]
        modern=fixture();ready=find_ready_poll_profile(modern)
        decoys=bytearray(0x3800)
        for at in (0x3500,0x3600):decoys[at:at+len(primary)]=primary
        decoys[:len(modern)]=modern
        expected,reason=find_uart_console_profile(modern,ready)
        profile,reason=find_uart_console_profile(bytes(decoys),ready)
        self.assertEqual(reason,'accepted')
        self.assertEqual(profile,expected)
        # Every literal-valid primary decoy is checked, but lacks the full graph.
        self.assertEqual(find_uart_console_profile(bytes(decoys),None)[1],
                         'console-byte-candidates-unclosed')
        unique=bytearray(decoys);unique[:len(legacy)]=legacy
        profile,reason=find_uart_console_profile(bytes(unique),None)
        self.assertEqual(reason,'accepted')
        self.assertEqual(profile['signature'],'thumb-uart-byte-sync-console-v1')
        # Combiner ambiguity is defined by complete graphs, independently of core predicates.
        with mock.patch.object(uart_console,'_byte_profile_at',return_value=({'base':0x030007ac},'accepted')) as close:
            self.assertEqual(find_uart_console_profile(bytes(decoys),None)[1],
                             'console-byte-profiles-ambiguous')
            self.assertEqual(close.call_count,2)


if __name__ == '__main__':
    unittest.main()


# Synthetic instruction fixtures contain no handset payload or string resources.
def dd_fixture(shift=0):
    from msm5xxx_emulator.detection.uart_console import _DD_MASKS
    roles = list(_DD_MASKS)
    pos = {role: 0x400 + index*0x400 + shift for index,role in enumerate(roles)}
    data = bytearray(0x8000+shift)
    def word(at,value): struct.pack_into('<H',data,at,value)
    def value(at,number): struct.pack_into('<I',data,at,number)
    def bl(at,target):
        delta=target-at-4
        struct.pack_into('<HH',data,at,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
    pools={role:at+0x280 for role,at in pos.items()}
    def literal(role,off,number):
        at=pos[role]+off;pool=pools[role];pools[role]+=4
        old=struct.unpack_from('<H',data,at)[0]
        word(at,0x4800|(old&0x700)|((pool-((at+4)&~3))//4));value(pool,number)
    for role,at in pos.items():
        mask=_DD_MASKS[role]
        for off in range(0,len(mask),2):
            if mask[off:off+2]!='??':data[at+off//2]=int(mask[off:off+2],16)
        off=0
        while off<len(mask)//2-1:
            if mask[off*2:off*2+8]=='????????':bl(at+off,0x100+shift);off+=4;continue
            if struct.unpack_from('<H',data,at+off)[0]&0xf800==0x4800:literal(role,off,0x100+shift)
            off+=2
    base,pulse,flag=0x03000f0c,0x03000700,0x014feffc
    pointer,table,crc,seed,source=(at+shift for at in (0x7100,0x7200,0x7400,0x7600,0x7610))
    terms={
        'primary':((6,base+4),(8,pulse)),
        'init':((0,base+0x34),(0xa,pulse-0x100),(0x10,pulse-0x100),(0x1a,pulse+0x20),
                (0x28,base+0x34),(0x38,base+0x34),(0x3e,base+0x34),(0x4c,base+0x34),
                (0x54,base+0x34),(0x78,pulse+0x20)),
        'root':((2,pulse+0x40),),'flag':((0,source),(2,flag)),
        'dispatch':((2,pointer),(4,0xffffe000)),
        'clear':((0,pointer),(2,0xffffde00)),
        'parser':((8,pulse),(0x20,pulse),(0x56,0xffff),(0x78,0xf0b8),(0x92,crc)),
        'wrapper':((2,flag+4),(0x2c,base+4)),
        'rx':((8,base+4),(0xa,pulse),(0xe,0x5b8d80)),
        'tx':((6,base+0x14),(8,pulse),(0x16,base+0x14)),
        'ack2':((0,table),),'policy':((8,flag+4),),'boolean':((2,seed),),
    }
    for role,items in terms.items():
        for off,number in items:literal(role,off,number)
    value(pointer,flag)
    for index in range(13):
        value(table+index*4,0x7300+shift+index*2)
        data[0x7300+shift+index*2:0x7302+shift+index*2]=b'\x01\x7e'
    links={'root':((0x24,'primary'),(0x28,'init'),(0x2c,'flag'),(0x30,'clear'),(0x34,'dispatch')),
           'init':((0x24,'primary'),),'dispatch':((0xc,'parser'),(0x112,'ack2')),
           'parser':((0x12,'wrapper'),(0x5e,'wrapper'),(0x80,'ack2')),
           'wrapper':((0xc,'rx'),(0x1e,'rx')),
           'ack1':((8,'tx'),(0xe,'tx')),'ack2':((0xa,'tx'),(0x10,'tx')),
           'extra':tuple((off,'tx')for off in (4,0xa,0x10,0x16,0x1c)),
           'policy':((4,'boolean'),)}
    for role,items in links.items():
        for off,to in items:bl(pos[role]+off,pos[to])
    for index in range(22):
        at=0x7800+shift+index*6;word(at,0x2000|(index%13));bl(at+2,pos['ack2'])
    return bytes(data),pos


class DDConsoleTests(unittest.TestCase):
    def profile(self,data): return find_uart_console_profile(data,find_ready_poll_profile(data))
    def test_dd_relocated(self):
        for shift in (0,0x100):
            data,pos=dd_fixture(shift);profile,reason=self.profile(data)
            self.assertIsNotNone(profile,reason)
            self.assertEqual((profile['signature'],profile['register_width'],profile['csr_value']),
                             ('thumb-uart-sync-console-dd-v1',2,0xdd))
            self.assertEqual(profile['console_root'],pos['root'])
            self.assertEqual(len(profile['tx_callers']),9)
    def test_dd_mutations_fail_closed(self):
        data,pos=dd_fixture()
        mutations=(('CSR',pos['init']+0x5c,0xde),('width',pos['init']+0x46,0x70),
                   ('branch',pos['primary']+0x14,0xff),('return',pos['rx']+0x26,0),
                   ('extra-frame',pos['extra']+2,0x7d),('root-call',pos['root']+0x24,0),
                   ('init-call',pos['init']+0x24,0),('rx-link',pos['wrapper']+0xd,0),
                   ('tx-link',pos['ack1']+8,0),('index',0x7800,13))
        for name,at,value_ in mutations:
            with self.subTest(name=name):
                changed=bytearray(data);changed[at]=value_
                self.assertIsNone(self.profile(bytes(changed))[0])
    def test_dd_foreign_literal_and_truncation(self):
        data,pos=dd_fixture()
        # Only one producer changes: same instruction shape cannot own a foreign port.
        changed=bytearray(data)
        at=pos['primary']+6;word=struct.unpack_from('<H',changed,at)[0]
        pool=((at+4)&~3)+(word&255)*4
        struct.pack_into('<I',changed,pool,0x03000e10)
        self.assertIsNone(self.profile(bytes(changed))[0])
        for end in (pos['root']+8,pos['init']+0x90,0x7233,0x74ff):
            self.assertIsNone(self.profile(data[:end])[0])
    def test_dd_partial_decoy_does_not_disable_modern(self):
        from msm5xxx_emulator.detection.uart_console import _DD_MASKS
        data=bytearray(fixture());data.extend(b'\0'*0x200)
        at=0x500
        for i in range(0,len(_DD_MASKS['root']),2):
            token=_DD_MASKS['root'][i:i+2]
            if token!='??':data[at+i//2]=int(token,16)
        self.assertIsNotNone(self.profile(bytes(data))[0])
    def test_dd_duplicate_rejected(self):
        from msm5xxx_emulator.detection.uart_console import _DD_MASKS
        data,pos=dd_fixture();changed=bytearray(data)
        # A second exact policy producer with the same owned global is ambiguous.
        changed[0x6800:0x680c]=changed[pos['policy']:pos['policy']+12]
        delta=pos['boolean']-0x6804-4
        struct.pack_into('<HH',changed,0x6804,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
        struct.pack_into('<H',changed,0x6808,0x4900|((0x6900-0x680c)//4))
        struct.pack_into('<I',changed,0x6900,0x014ff000)
        self.assertIsNone(self.profile(bytes(changed))[0])

    def test_dd_and_modern_complete_ambiguity(self):
        data,pos=dd_fixture();modern=fixture();changed=bytearray(data)
        changed[:len(modern)]=modern
        profile,reason=find_uart_console_profile(bytes(changed),find_ready_poll_profile(modern))
        self.assertIsNone(profile)
        self.assertEqual(reason,'console-protocol-ownership-ambiguous')

    def test_modern_with_two_complete_dd_profiles_rejected(self):
        first,_=dd_fixture();second,_=dd_fixture(0x9000)
        data=bytearray(second);data[:len(first)]=first
        modern=fixture();data[:len(modern)]=modern
        profile,reason=find_uart_console_profile(bytes(data),find_ready_poll_profile(modern))
        self.assertIsNone(profile)
        self.assertIn(reason,('console-dd-profiles-ambiguous','console-dd-complete-ownership-ambiguous'))

    def test_dd_preserved_with_legacy_primary_only_decoy(self):
        data,_=dd_fixture();changed=bytearray(data);legacy,_=legacy_fixture()
        changed[0x6800:0x6880]=legacy[0x2000:0x2080]
        profile,reason=self.profile(bytes(changed))
        self.assertIsNotNone(profile,reason)
        self.assertEqual(profile['signature'],'thumb-uart-sync-console-dd-v1')


def dd_argument_fixture(shift=0):
    from msm5xxx_emulator.detection.uart_console import _DD_MASKS
    original,pos=dd_fixture(shift);data=bytearray(original)
    root,prelude=pos['root'],pos['argument_prelude']
    mask=_DD_MASKS['argument_root']
    data[root:root+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
    def bl(at,target):
        delta=target-at-4
        struct.pack_into('<HH',data,at,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
    def literal(at,pool,value):
        h=struct.unpack_from('<H',data,at)[0]
        struct.pack_into('<H',data,at,0x4800|(h&0x700)|((pool-((at+4)&~3))//4))
        struct.pack_into('<I',data,pool,value)
    literal(root+2,root+0x3a0,0x03000740)
    for off,role in ((0xa,'argument_prelude'),(0x26,'primary'),(0x2a,'init'),
                     (0x2e,'flag'),(0x32,'clear'),(0x36,'dispatch')):
        bl(root+off,pos[role])
    for index,(off,reg) in enumerate(((0x38,2),(0xd4,2),(0xf0,1),(0xfc,1),
                                    (0x10c,1),(0x11a,1),(0x12c,1),(0x13a,1))):
        literal(prelude+off,prelude+0x280+index*4,0x03000720)
    for site,to in ((0x42,0x118),(0x46,0xec),(0x54,0x108),(0x70,0x108),
                    (0x8c,0x118),(0xa4,0x138),(0xaa,0x128),(0xc0,0x118),(0xc4,0x138)):
        bl(prelude+site,prelude+to)
    return bytes(data),pos


class DDArgumentRootTests(unittest.TestCase):
    def profile(self,data): return find_uart_console_profile(data,find_ready_poll_profile(data))
    def test_argument_root_relocation(self):
        for shift in (0,0x100):
            data,pos=dd_argument_fixture(shift);profile,reason=self.profile(data)
            self.assertIsNotNone(profile,reason)
            self.assertEqual(profile['signature'],'thumb-uart-sync-console-dd-v1')
            self.assertEqual(profile['console_root'],pos['root'])
            self.assertEqual((profile['register_width'],profile['csr_value']),(2,0xdd))
            self.assertEqual(len(profile['tx_callers']),9)
    def test_argument_and_prelude_mutations(self):
        data,pos=dd_argument_fixture();root=pos['root'];prelude=pos['argument_prelude']
        for name,at,value in (('argument',root+8,2),('root-primary',root+0x27,0),
                              ('root-init',root+0x2b,0),('prelude-call',root+0xb,0),
                              ('prelude-register',prelude+0x39,0x49),
                              ('prelude-width',prelude+0x41,0x72),
                              ('prelude-internal-link',prelude+0x43,0),
                              ('prelude-return',prelude+0xe4,0)):
            with self.subTest(name=name):
                changed=bytearray(data);changed[at]=value
                self.assertIsNone(self.profile(bytes(changed))[0])
    def test_prelude_domain_and_bounds(self):
        data,pos=dd_argument_fixture();prelude=pos['argument_prelude'];changed=bytearray(data)
        struct.pack_into('<I',changed,prelude+0x280,0x03000f10)
        self.assertIsNone(self.profile(bytes(changed))[0])
        self.assertIsNone(self.profile(data[:prelude+0x147])[0])
    def test_old_root_and_argument_root_ambiguity(self):
        old,_=dd_fixture();new,_=dd_argument_fixture(0x9000)
        combined=bytearray(new);combined[:len(old)]=old
        self.assertIsNone(self.profile(bytes(combined))[0])
    def test_argument_root_partial_decoy_preserves_modern(self):
        from msm5xxx_emulator.detection.uart_console import _DD_MASKS
        modern=fixture();data=bytearray(modern);data.extend(b'\0'*0x300)
        at=0x500;mask=_DD_MASKS['argument_root']
        data[at:at+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
        struct.pack_into('<H',data,at+2,0x4800|((0x640-((at+6)&~3))//4))
        struct.pack_into('<I',data,0x640,0x03000740)
        for off in (0xa,0x26,0x2a,0x2e,0x32,0x36):
            delta=0x100-(at+off)-4
            struct.pack_into('<HH',data,at+off,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
        profile,reason=self.profile(bytes(data))
        self.assertIsNotNone(profile,reason)
        self.assertNotEqual(profile['signature'],'thumb-uart-sync-console-dd-v1')


# Portable compiler-shaped source graph; no original file is needed.
from msm5xxx_emulator.detection import uart_console as _console
_FF_FIXTURE_VALUES = {'console': {'calls': {'8': 8372, '12': 1580, '16': 5216, '20': 5260, '24': 5128, '28': 4968},
             'literals': {'4': 50333504}},
 'primary': {'calls': {}, 'literals': {'0': 16787696, '8': 50335504, '18': 50333440}},
 'init': {'calls': {'12': 8388, '16': 5216},
          'literals': {'4': 50335552,
                       '22': 50335552,
                       '38': 50335552,
                       '44': 50335552,
                       '58': 50335552,
                       '66': 50335552,
                       '100': 16787696,
                       '110': 50335552,
                       '122': 50335552,
                       '130': 50333440}},
 'rx': {'calls': {},
        'literals': {'8': 1000000, '22': 50335504, '38': 50333440, '54': 50335504, '68': 50333440}},
 'wrapper': {'calls': {'12': 5416, '22': 5416},
             'literals': {'2': 19998540,
                          '32': 19998540,
                          '52': 50335504,
                          '66': 50335504,
                          '76': 50335504,
                          '84': 19998540}},
 'tx': {'calls': {}, 'literals': {'0': 50335520, '10': 50333440, '20': 50335520}},
 'byteflag': {'calls': {}, 'literals': {'0': 68, '24': 19998536, '32': 19998536}},
 'dispatch': {'calls': {'20': 3940,
                        '60': 4160,
                        '70': 4332,
                        '80': 4480,
                        '86': 4660,
                        '92': 4672,
                        '98': 4800,
                        '108': 4560,
                        '114': 4850,
                        '120': 4948,
                        '128': 3898},
              'literals': {'2': 16787696,
                           '10': 12244,
                           '14': 4294959104,
                           '132': 12244,
                           '136': 4294959104}},
 'parser': {'calls': {'24': 5508, '42': 7352, '88': 3898, '104': 3898, '120': 5508, '150': 3898},
            'literals': {'16': 50333440, '74': 65535, '96': 61624, '182': 10516}},
 'ack1': {'calls': {'8': 5608, '14': 5608}, 'literals': {}},
 'ack2': {'calls': {'12': 5608, '18': 5608}, 'literals': {'6': 11116}},
 'wordflag': {'calls': {}, 'literals': {'6': 48815, '14': 16787692}},
 'aux': {'calls': {'10': 2720, '42': 7312},
         'literals': {'2': 16787696, '16': 50333472, '36': 50333472}},
 'delay': {'calls': {},
           'literals': {'0': 6293504,
                        '16': 16944636,
                        '20': 16944636,
                        '28': 16944636,
                        '34': 16944636}},
 'hardware': {'calls': {},
              'literals': {'2': 75497632,
                           '8': 75497632,
                           '16': 75497632,
                           '22': 8243,
                           '26': 4147,
                           '34': 1057,
                           '42': 1057,
                           '48': 1539}},
 'prelude': {'calls': {}, 'literals': {'28': 8243, '30': 75497600, '34': 4147}},
 'config': {'calls': {'22': 2869432, '48': 2869448, '58': 2869432, '106': 771736, '128': 772808},
            'literals': {'6': 50333216,
                         '8': 17278552,
                         '28': 65343,
                         '64': 65343,
                         '88': 16787224,
                         '104': 2896144,
                         '110': 2896144,
                         '112': 1881}},
 'copy': {'calls': {},
          'literals': {'2': 50333440,
                       '10': 12244,
                       '14': 12248,
                       '22': 12240,
                       '28': 12244,
                       '58': 50333440,
                       '66': 12252,
                       '70': 12256,
                       '78': 12252,
                       '104': 50333440,
                       '112': 2848380,
                       '116': 2848384,
                       '124': 2848376,
                       '130': 2848380,
                       '160': 50333440,
                       '168': 2848388,
                       '172': 2848392,
                       '180': 2848388,
                       '208': 50333440,
                       '220': 50333440,
                       '228': 12264,
                       '232': 12268,
                       '240': 12260,
                       '246': 12264,
                       '276': 50333440}},
 'tag': {'calls': {}, 'literals': {'0': 36, '4': 44, '16': 8968}}}
_FF_FIXTURE_ORIGINS = {'console': 5176, 'primary': 5216, 'init': 5260, 'rx': 5416, 'wrapper': 5508, 'tx': 5608, 'byteflag': 5128, 'dispatch': 4968, 'parser': 3940, 'ack1': 3864, 'ack2': 3898, 'wordflag': 809784, 'aux': 2772, 'delay': 2720, 'hardware': 1580, 'prelude': 245808, 'config': 245452, 'copy': 2864, 'tag': 2832}
_FF_FIXTURE_TEST = bytes.fromhex(
    "54019fe5000090e50110a0e30020a0e348319fe5003093e5004083e0001080e5002084e5003090e5010053e14500001a8110a0e1800c51e3f7ffffda0120a0e31c319fe5003093e50020c3e50020a0e30020c3e50f10a0e30010c0e5aa10a0e30110c0e55510a0e30210c0e5f4109fe5001091e5001081e0031001e50420a0e3e0309fe5003093e50240e0e1004082e78220a0e1030052e1faffffba0020d0e50f0052e32700001a0120d0e5aa0052e32400001a0220d0e5550052e32100001a0420a0e30240e0e1005092e7040055e11c00001a8220a0e1030052e1f8ffffba032011e5010052e11600001a0030a0e30330c0e570209fe5002092e5004090e5040052e10f00001a60209fe5002092e5b040d0e1040052e10a00001a50209fe5002092e5b240d0e1040052e10500001aaa20a0e30140d0e5040052e10100001a0000a0e30ef0a0e128009fe50ef0a0e1")


def half_ff_fixture(shift=0, ram_shift=0, copied_flag=0):
    data=bytearray(0x40000+shift); root=0x1000+shift
    sites={role:0x3000+i*0x1000+shift for i,role in enumerate(_console._FF_SPECS)}
    thunks=[0x18000+shift+i*16 for i in range(4)]
    test=0x1b000+shift;stub=0x19000+shift;app=0x19080+shift
    tables=[0x24000+shift,0x24020+shift,0x24040+shift]
    ram=0x01000000+ram_shift;iram=0x03800000
    src=[0x26000+shift,0x25000+shift,0x26008+shift]
    targets=[ram+0x6000,ram,iram];sizes=[8,0x1000,0x400]
    def u32(at,value):struct.pack_into('<I',data,at,value)
    def u16(at,value):struct.pack_into('<H',data,at,value)
    def bl(at,target):
        delta=target-at-4;struct.pack_into('<HH',data,at,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
    def thumb_lit(at,reg,pool,value):
        u16(at,0x4800|reg<<8|((pool-((at+4)&~3))//4));u32(pool,value)
    def arm_branch(at,target):u32(at,0xea000000|(((target-at-8)>>2)&0xffffff))
    remap={old:sites[role]for role,old in _FF_FIXTURE_ORIGINS.items()}
    remap.update({0x20b4:thunks[0],0x20c4:thunks[1],0x2bc8b8:thunks[2],0x2bc8c8:thunks[3],
      0x1c90:root+0x10c,0x1cb8:root+0x134,0x10028f0:ram+0x100,0x10028ec:ram+0xfc,
      0x131274c:ram+0x6004,0x1312748:ram+0x6000,0x1028dfc:ram+0x2000,
      0x107a658:ram+0x2c58,0x600800:0x2e000+shift,0x2b6c:0x27000+shift,
      0x2914:0x27020+shift,0x2c3110:0x27040+shift,0x1002818:ram+0x300})
    for old,new in zip((0x2fd0,0x2b7678,0x2fe4),tables):
        for off in (0,4,8,12,16):remap[old+off]=new+off
    for role,at in sites.items():
        mask,calls,lits=_console._FF_SPECS[role]
        data[at:at+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
        for off in calls:
            old=_FF_FIXTURE_VALUES[role]['calls'][str(off)]
            bl(at+off,remap.get(old,stub))
        for i,(off,reg)in enumerate(lits):
            old=_FF_FIXTURE_VALUES[role]['literals'][str(off)]
            thumb_lit(at+off,reg,at+0x300+i*4,remap.get(old,old))
    for at,target in zip(thunks,(sites['prelude'],sites['config'],iram+0x100,iram+0x118)):
        data[at:at+12]=_console._FF_THUNK;u32(at+12,target|1)
    data[src[2]+0x100:src[2]+0x118]=_console._FF_IRQ_SAVE
    data[src[2]+0x118:src[2]+0x130]=_console._FF_IRQ_RESTORE
    data[src[0]+4]=1;u32(src[1]+0x100,copied_flag)
    for i,table in enumerate(tables):
        for off,value in zip((0,4,8),(src[i],targets[i],sizes[i])):u32(table+off,value)
        if i<2:
            u32(table+12,targets[i]+sizes[i]);u32(table+16,0x100 if i==0 else 0x5000)
    u32(0x20,0);u16(0x24,0x4c);u16(0x2c,0x4c)
    data[test:test+0x150]=_FF_FIXTURE_TEST
    for i,value in enumerate((ram,0x3fffff,16,0x55aa0f,0xaa0f,0x55,0x03000700)):u32(test-28+i*4,value)
    for off,field in ((0,0),(0x10,8),(0x40,24),(0x6c,4),(0x80,4),(0xf4,12),(0x108,16),(0x11c,20)):
        op=struct.unpack_from('<I',data,test+off)[0];u32(test+off+8+(op&4095),test-28+field)
    u32(test+0x178,0x1234)
    data[root:root+len(_console._FF_RESET)]=_console._FF_RESET
    gate_targets={0:stub|1,0x18:sites['hardware']|1,0x30:stub|1,0x48:test,
                  0x80:sites['copy']|1,0x98:sites['tag']|1,0xb8:sites['wordflag']|1,
                  0xd0:sites['aux']|1,0xf4:stub|1,0x118:sites['console']|1}
    pool=root+0x600
    for off in range(0,len(_console._FF_RESET),4):
        want=struct.unpack_from('<I',_console._FF_RESET,off)[0]
        if want&0x0f7f0000==0x051f0000:
            value=ram+0x7000
            if off in gate_targets:value=gate_targets[off]
            elif any(off==gate+8 for gate in gate_targets):value=root+off-8+21
            elif any(off==gate+12 for gate in gate_targets):value=root+off-12+(25 if off-12==0xf4 else 24)
            else:value=ram+0x7000+(off&0x70)
            u32(root+off,(want&0xfffff000)|(pool-(root+off+8)));u32(pool,value);pool+=4
    arm_branch(0,root);arm_branch(root+0xe8,app)
    sites.update(root=root,test=test,stub=stub,application=app,thunks=thunks,tables=tables,sources=src,ram=ram)
    return bytes(data),sites


class HalfFFConsoleTests(unittest.TestCase):
    def profile(self,data):return find_uart_console_profile(data,None)
    def test_complete_relocated_graph_and_copied_flag_overwrite(self):
        for shift,ram_shift,flag in ((0,0,0),(0x400,0x10000,1)):
            data,sites=half_ff_fixture(shift,ram_shift,flag)
            profile,reason=self.profile(data);self.assertIsNotNone(profile,reason)
            self.assertEqual(profile['signature'],'thumb-byte-uart-word-flag-fixed-ff-mixed-v1')
            self.assertEqual((profile['register_width'],profile['csr_value']),(2,255))
            self.assertEqual(profile['base'],0x03000f0c)
            for role in ('code_intervals','literal_intervals','data_intervals','boot_guard_intervals','ram_intervals','iram_intervals'):
                self.assertTrue(profile[role],role)
            self.assertEqual(profile['primary_entry'],sites['primary'])
    def test_required_body_and_link_mutations(self):
        original,s=half_ff_fixture()
        mutations=[]
        def half(at,value):mutations.append((at,struct.pack('<H',value)))
        def word(at,value):mutations.append((at,struct.pack('<I',value)))
        half(0x24,0);word(0x20,0xbeaf)
        half(s['init']+0x3e,0x7088) # HALF MR1 becomes BYTE
        half(s['init']+0x48,0x2099) # CSR differs
        half(s['primary']+12,0x0840) # status bit differs
        half(s['rx']+24,0x8801) # BYTE status becomes HALF
        half(s['parser']+42,0x46c0) # reset handoff link
        half(s['console']+20,0x46c0) # initializer link
        half(s['config']+22,0x46c0) # IRQsave link
        half(s['copy']+0x28,0x6021) # typed copy consumer
        half(s['wordflag']+12,0x2001) # header-normal producer cannot set flag1
        half(s['tag']+8,0x4280) # header compare
        word(s['test']+0x20,0xe1a00000) # RAM readback producer
        word(s['test']+0x178,0) # zero failure return must not pass RAM test
        word(s['test']-24,0xffffffff) # overflowing/unaligned extent
        word(s['tables'][0]+4,s['ram']+0x100) # copy overlaps main
        word(s['root']+0x48,0xe1a00000) # RAMtest rootcall
        at=s['root']+0xe8
        word(at,0xea000000|(((s['root']-at-8)>>2)&0xffffff)) # application cannot reenter reset owner
        word(s['sources'][0]+4,0) # privateRX initial byte
        half(s['sources'][2]+0x100,0) # copied IRQ save body
        for at,replacement in mutations:
            with self.subTest(at=hex(at)):
                data=bytearray(original);data[at:at+len(replacement)]=replacement
                self.assertIsNone(self.profile(bytes(data))[0])
    def test_literals_and_aliases_are_source_owned(self):
        original,s=half_ff_fixture()
        for role,index,value in (('primary',0,s['ram']+0x6004),('primary',1,0x03000724),
             ('wrapper',0,s['ram']+0x6000),('config',1,s['ram']+0x2c59),('wordflag',1,s['ram']+0x2000)):
            data=bytearray(original);at=s[role]+0x300+4*index;struct.pack_into('<I',data,at,value)
            with self.subTest(role=role,index=index):self.assertIsNone(self.profile(bytes(data))[0])
    def test_truncation_and_unlinked_partial_decoy(self):
        data,s=half_ff_fixture()
        for end in (s['root']+32,s['copy']+80,s['sources'][2]+0x110,s['test']+0x100):
            with self.subTest(end=hex(end)):self.assertIsNone(self.profile(data[:end])[0])
        altered=bytearray(data);at=0x28000
        mask=_console._FF_SPECS['console'][0]
        altered[at:at+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
        self.assertIsNotNone(self.profile(bytes(altered))[0])
    def test_duplicate_complete_transmit_owner_rejects(self):
        data,s=half_ff_fixture();altered=bytearray(data);target=0x28000
        length=len(_console._FF_SPECS['ack1'][0])//2
        altered[target:target+length]=data[s['ack1']:s['ack1']+length]
        for off in (8,14):
            delta=s['tx']-(target+off)-4
            struct.pack_into('<HH',altered,target+off,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
        self.assertIsNone(self.profile(bytes(altered))[0])
    def test_prior_profiles_and_cross_class_ambiguity(self):
        old=fixture();self.assertIsNotNone(find_uart_console_profile(old,find_ready_poll_profile(old))[0])
        data,s=half_ff_fixture();combined=bytearray(data);combined[0x40:len(old)]=old[0x40:]
        # The old modern finder conservatively rejects its now-duplicate TX shape.
        self.assertIsNotNone(find_uart_console_profile(bytes(combined),find_ready_poll_profile(bytes(combined)))[0])
        legacy,_=legacy_fixture(shift=0x30000)
        combined=bytearray(data);combined.extend(b'\0'*max(0,len(legacy)-len(combined)))
        combined[0x30000:]=legacy[0x30000:]
        profile,reason=find_uart_console_profile(bytes(combined),None)
        self.assertIsNone(profile);self.assertIn('ambiguous',reason)


_PROBE_FIXTURE_ORIGINS = {'root': 9454, 'init': 9576, 'setup': 3772, 'config': 5112, 'primary': 9536, 'rx': 9728, 'wrapper': 9820, 'tx': 9920, 'delay': 7356, 'pinset': 4832, 'clockset': 4884, 'apply': 3568, 'clockclear': 4724}
_PROBE_FIXTURE_VALUES = {'root': {'calls': {2: 9536, 8: 9576, 14: 9920, 18: 9820, 32: 13192, 38: 10804, 52: 9576}, 'literals': {36: 15876}}, 'init': {'calls': {4: 3772, 18: 5112, 22: 9536}, 'literals': {10: 50335552, 28: 50335552, 44: 50335552, 50: 50335552, 64: 50335552, 72: 50335552, 106: 50335552, 118: 50335552, 126: 50333440}}, 'setup': {'calls': {10: 1948876, 14: 12896, 22: 12896, 52: 12920, 56: 12896, 92: 12920, 96: 12896, 120: 12920, 124: 12896, 154: 12920, 158: 12896, 182: 12920, 188: 7356, 194: 4832, 200: 4884, 206: 3568, 212: 4724, 216: 12896, 238: 12920, 242: 12896, 274: 12920, 286: 12896, 310: 12920, 314: 12896, 334: 12920, 344: 12920}, 'literals': {8: 13732, 26: 18206292, 36: 65409, 38: 50333440, 60: 18206292, 70: 65409, 72: 50333184, 102: 65409, 104: 50333184, 130: 65409, 132: 18206292, 146: 50333440, 164: 65409, 166: 50333440, 186: 20000, 222: 50333184, 254: 65409, 264: 50333440, 278: 50333440, 290: 16778616}}, 'config': {'calls': {20: 12896, 46: 12920, 56: 12896, 90: 532804}, 'literals': {2: 50333216, 6: 18206292, 26: 65343, 62: 65343, 86: 13528, 88: 1877}}, 'primary': {'calls': {}, 'literals': {2: 50335504, 8: 50335504, 18: 50333440}}, 'rx': {'calls': {}, 'literals': {8: 200000, 22: 50335504, 38: 50333440, 54: 50335504, 68: 50333440}}, 'wrapper': {'calls': {12: 9728, 22: 9728}, 'literals': {2: 18202092, 32: 18202092, 52: 50335504, 66: 50335504, 76: 50335504, 84: 18202092}}, 'tx': {'calls': {}, 'literals': {0: 50335520, 10: 50333440, 20: 50335520}}, 'delay': {'calls': {}, 'literals': {2: 18202048, 38: 75497504, 62: 75497504}}, 'pinset': {'calls': {4: 12896, 34: 12920}, 'literals': {8: 18206292, 26: 50333200}}, 'clockset': {'calls': {16: 12896, 30: 7484, 34: 7484, 38: 12896, 60: 12920, 80: 12896, 102: 12920, 116: 12896, 144: 12920}, 'literals': {2: 50333184, 4: 18206292, 12: 13544, 24: 50332672, 132: 50333184}}, 'apply': {'calls': {4: 12896, 18: 1948876, 36: 4884, 40: 3484, 44: 2972, 48: 12896, 82: 12920, 86: 12896, 116: 12920, 124: 12896, 144: 12920, 148: 12896, 166: 12920, 170: 2748, 180: 12920}, 'literals': {16: 18201912, 22: 18206292, 52: 18201912, 74: 50333216, 106: 50333216, 130: 50333216, 154: 50333216}}, 'clockclear': {'calls': {22: 12896, 46: 12920, 58: 12896, 84: 12920}, 'literals': {6: 13544, 10: 18206292, 38: 50333184, 74: 50333184}}}
_PROBE_OLD_SOURCE_SHA = '094dd4839e67662c67c2f659f5f7d46c24efb8efaa60492e968ce68bd946ccd3'


_PROBE_FIXTURE_ORIGINS['copy'] = 0x9a8
_PROBE_FIXTURE_VALUES['copy'] = {'calls': {}, 'literals': {2: 50333440, 10: 17092, 14: 17096, 22: 17088, 28: 17092, 58: 50333440, 66: 17100, 70: 17104, 78: 17100, 104: 50333440, 112: 17072, 116: 17076, 124: 17068, 130: 17072, 160: 50333440, 168: 17080, 172: 17084, 180: 17080, 208: 50333440, 220: 50333440}}

def probe_fixture(shift=0, ram_shift=0, ffcc=False):
    data=bytearray(0x40000+shift);ram=0x01000000+ram_shift
    roles=list(_console._PROBE_SPECS)+['rx','wrapper','tx']
    sites={role:0x3000+i*0x1000+shift for i,role in enumerate(roles)}
    reset=0x1000+shift;test=0x1b000+shift;app=0x19000+shift;thumb=0x19100+shift
    irqsave=0x18000+shift;irqrestore=irqsave+24;memcpy=0x17000+shift;stub=0x23000+shift
    tables=[0x24000+shift,0x24020+shift];sources=[0x26000+shift,0x28000+shift]
    targets=[ram+0x6000,ram];sizes=[0xc0,0x1000];template=0x2a000+shift
    def u32(at,v):struct.pack_into('<I',data,at,v)
    def u16(at,v):struct.pack_into('<H',data,at,v)
    def bl(at,target):
        d=target-at-4;struct.pack_into('<HH',data,at,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
    def lit(at,reg,pool,value):
        u16(at,0x4800|reg<<8|((pool-((at+4)&~3))//4));u32(pool,value)
    def branch(at,target):u32(at,0xea000000|(((target-at-8)>>2)&0xffffff))
    remap={old:sites[role]for role,old in _PROBE_FIXTURE_ORIGINS.items()}
    remap.update({0x3260:irqsave,0x3278:irqrestore,0x1dbccc:memcpy,
                 0x35a4:template,0x115ce54:ram+0x7000,0x1000578:ram+0x578,
                 0x115bdec:ram+0x60b4,0x115bdc0:ram+0x6088})
    for old,new in zip((0x42c0,0x42ac),tables):
        for off in (0,4,8,12,16):remap[old+off]=new+off
    for role,at in sites.items():
        mask,calls,lits=(_console._PROBE_SPECS if role in _console._PROBE_SPECS else _console._FF_SPECS)[role]
        data[at:at+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
        for off in calls:bl(at+off,remap.get(_PROBE_FIXTURE_VALUES[role]['calls'][off],stub))
        for i,(off,reg)in enumerate(lits):
            value=_PROBE_FIXTURE_VALUES[role]['literals'][off]
            lit(at+off,reg,at+0x300+i*4,remap.get(value,value))
    data[template:template+44]=_console._PROBE_TEMPLATE
    data[irqsave:irqsave+24]=_console._FF_IRQ_SAVE;data[irqrestore:irqrestore+24]=_console._FF_IRQ_RESTORE
    data[memcpy:memcpy+len(_console._PROBE_MEMCPY_44)]=_console._PROBE_MEMCPY_44
    for i,table in enumerate(tables):
        for n,value in enumerate((sources[i],targets[i],sizes[i],targets[i]+sizes[i],0x1804 if i==0 else 0x4000)):u32(table+4*n,value)
    data[sources[0]+0xb4]=1
    u32(sources[0]+0xa8,19);u16(sources[0]+0xac,1)
    gpio=[0x3000720,0x3000720,0x300072c,0,0x3000724,0x3000724,0x3000730,0x1000100,0x3000728,0x3000728,0x3000734]
    for i,value in enumerate(gpio):u32(sources[1]+0x578+4*i,value)
    data[test:test+0x150]=_FF_FIXTURE_TEST
    for i,value in enumerate((0x1000000,0x1fffff,16,0x55aa0f,0xaa0f,0x55,0x3000700)):u32(test-28+4*i,value)
    for off,field in ((0,0),(0x10,8),(0x40,24),(0x6c,4),(0x80,4),(0xf4,12),(0x108,16),(0x11c,20)):
        op=struct.unpack_from('<I',data,test+off)[0];u32(test+off+8+(op&4095),test-28+field)
    u32(test+0x178,0x1234)
    data[reset:reset+len(_console._PROBE_RESET)]=_console._PROBE_RESET
    gates={0:stub|1,0x18:stub|1,0x30:stub|1,0x48:test,0x80:sites['copy']|1,0x98:sites['root']|1,0x138:stub|1}
    pool=reset+0x600
    for off in range(0,len(_console._PROBE_RESET),4):
        w=struct.unpack_from('<I',_console._PROBE_RESET,off)[0]
        if w&0x0f7f0000==0x051f0000:
            value=gates.get(off,ram+0xa000)
            if any(off==n+8 for n in gates):value=reset+off-8+21
            if any(off==n+12 for n in gates):value=reset+off-12+24
            u32(reset+off,(w&0xfffff000)|(pool-reset-off-8));u32(pool,value);pool+=4
    branch(0,reset);branch(reset+0xc0,app)
    data[app:app+len(_console._PROBE_APP)]=_console._PROBE_APP;pool=app+0x80
    for off in range(0,len(_console._PROBE_APP),4):
        w=struct.unpack_from('<I',_console._PROBE_APP,off)[0]
        if w&0x0f7f0000==0x051f0000:
            value=thumb|1 if off==32 else ram+0xb000+off*4
            u32(app+off,(w&0xfffff000)|(pool-app-off-8));u32(pool,value);pool+=4
    data[thumb:thumb+4]=bytes.fromhex('0fb50022')
    sites.update(reset=reset,test=test,application=app,thumb=thumb,tables=tables,sources=sources,ram=ram,template=template)
    _complete_probe_clock_fixture(data,sites,shift,ffcc)
    return bytes(data),sites


def _complete_probe_clock_fixture(data,s,shift,ffcc):
    # Portable linked compiler graph: every address is fixture-local or a typed
    # source MMIO constant. No provided image is needed to construct it.
    ram=s['ram'];params=ram+0x6000;shadow=ram+0x7000
    def word(at,v):struct.pack_into('<I',data,at,v)
    def half(at,v):struct.pack_into('<H',data,at,v)
    def bl(at,target):
        d=target-at-4;struct.pack_into('<HH',data,at,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
    def lit(at,reg,pool,value):
        half(at,0x4800|reg<<8|((pool-((at+4)&~3))//4));word(pool,value)
    def setlit(role,off,value):
        pc=s[role]+off;op=struct.unpack_from('<H',data,pc)[0]
        word(((pc+4)&~3)+(op&255)*4,value)
    roles=['clock_commit','clock_regs','clock_version','clock_select_a',
           'clock_select_b','clock_select_c','clock_update','clock_version_get']
    s.update({role:0x30000+shift+i*0x400 for i,role in enumerate(roles)})
    s.update(selector_table=0x39000+shift,division=0x38000+shift,
             division_veneer=0x37c00+shift,version_output=ram+0x7500)
    irqsave=0x18000+shift;irqrestore=irqsave+24;stub=0x23000+shift;memcpy=0x17000+shift
    literals={
      'clock_commit':{2:params+0x1c,0x10:params+0x38,0x14:params+0x38,0xca:params+0x38},
      'clock_regs':{6:params,8:shadow,0x14:0x3000600,0x22:0x3000600,0x2e:0x3000600},
      'clock_version':{2:params,4:0x3000640},
      'clock_update':{0xa:params+0x88},
      'clock_version_get':{0:params+0xb8,0xc:0x30007a0,0x10:s['version_output'],0x18:s['version_output']}}
    calls={
      'clock_commit':{0x30:s['clock_select_b'],0x3a:s['clock_select_c'],0x98:s['clock_select_a'],0xbe:s['division_veneer'],0xc4:s['clock_update']},
      'clock_regs':{2:irqsave,0x1c:irqrestore},
      'clock_version':{0xa:s['clock_version_get'],0x28:s['delay']},
      'clock_update':{6:irqsave,0x14:irqrestore}}
    for role in roles:
        mask,cs,ls=_console._probe_specs(role,ffcc);at=s[role]
        data[at:at+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
        for off in cs:bl(at+off,calls.get(role,{}).get(off,stub))
        values=literals.get(role,{})
        for i,(off,reg) in enumerate(ls):
            if role.startswith('clock_select_'):
                value=0x2033 if off in (0x16,0x26,0x36,0x42) else 0x4800080 if off in (0x18,0x2a,0x38,0x46) else (0x1033 if ffcc else 0x833) if off in (0x1c,0x2e,0x3c,0x4a) else 0x21000+shift
            else:value=values[off]
            lit(at+off,reg,at+0x300+4*i,value)
    for off,target in ((4,irqsave),(0x12,memcpy),(0x24,s['clockset']),(0x28,s['clock_regs']),(0x2c,s['clock_version']),(0xaa,s['clock_commit'])):
        bl(s['apply']+off,target)
    for off in (0x30,0x56,0x7c,0x94):bl(s['apply']+off,irqsave)
    for off in (0x52,0x74,0x90,0xa6,0xb4):bl(s['apply']+off,irqrestore)
    setlit('apply',0x10,params);setlit('apply',0x34,params)
    setlit('clockset',0xc,s['selector_table']);setlit('clockclear',6,s['selector_table'])
    for offset,values in ((8,(0x737f,8)),(32,(0xff7f,15))):
        struct.pack_into('<2I',data,s['selector_table']+offset,*values)
    data[s['division']:s['division']+len(_console._PROBE_DIVIDE)]=_console._PROBE_DIVIDE
    # The only external ARM branch is the zero-divisor path, not selected by
    # the fixed nonzero source divisor. Keep its target owned and aligned.
    pc=s['division']+0x50;word(pc,0x2a000000|(((stub-pc-8)>>2)&0xffffff))
    data[s['division_veneer']:s['division_veneer']+12]=_console._FF_THUNK
    word(s['division_veneer']+12,s['division']|1)
    if not ffcc:return
    # Same typed protocol, different three-copy compiler and bounded RX root.
    table=0x24040+shift;src=0x2b000+shift;target=0x3800000
    s.update(iram_table=table,iram_source=src,marker=0x39080+shift)
    struct.pack_into('<3I',data,table,src,target,0x100)
    word(s['tables'][0]+8,0xc4);word(s['tables'][0]+12,params+0xc4)
    word(s['test']-24,0x3fffff)
    mask,cs,ls=_console._probe_specs('copy',True);at=s['copy']
    old=_console._probe_shape(bytes(data),at,'copy')[1]
    data[at:at+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
    for i,(off,reg)in enumerate(ls):
        value=old.get(off,{0xe4:table+4,0xe8:table+8,0xf0:table,0xf6:table+4,0x112:0x3000700}.get(off,0x3000700))
        lit(at+off,reg,at+0x300+i*4,value)
    mask,cs,ls=_console._probe_specs('root',True);at=s['root']
    data[at:at+len(mask)//2]=bytes.fromhex(mask.replace('??','00'))
    for off in cs:bl(at+off,{0x16:s['primary'],0x20:s['init'],0x28:s['init'],0x2e:s['tx'],0x40:s['wrapper'],0x72:s['init']}.get(off,stub))
    for i,(off,reg)in enumerate(ls):lit(at+off,reg,at+0x300+4*i,s['marker'] if off==2 else 0x21000+shift)
    word(s['marker'],0x6c64)
    half(s['init']+0xe,0x2180)
    data[src:src+len(_console._PROBE_MEMCPY_44)]=_console._PROBE_MEMCPY_44
    data[memcpy:memcpy+12]=_console._FF_THUNK;word(memcpy+12,target|1)
    data[s['thumb']:s['thumb']+6]=bytes.fromhex('0fb50ca11f20')


class FiniteProbeConsoleTests(unittest.TestCase):
    def detect(self,data):return find_uart_console_profile(data,None)
    def test_complete_relocated_graph(self):
        for shift,ram in ((0,0),(0x400,0x10000)):
            data,s=probe_fixture(shift,ram);p,reason=self.detect(data)
            self.assertIsNotNone(p,reason)
            self.assertEqual(p['signature'],'thumb-byte-uart-finite-ff-dd-console-v1')
            self.assertEqual(p['csr_sequence'],[255,221]);self.assertEqual(p['iram_intervals'],[])
            self.assertEqual(p['console_root'],s['root'])
            for key in ('code_intervals','literal_intervals','data_intervals','boot_guard_intervals','ram_intervals'):self.assertTrue(p[key])
    def test_mutated_source_and_controlflow_reject(self):
        data,s=probe_fixture();cases=[]
        def half(a,v):cases.append((a,struct.pack('<H',v)))
        def word(a,v):cases.append((a,struct.pack('<I',v)))
        half(s['root']+6,0x20cc);half(s['root']+0x32,0x2099)
        half(s['root']+0x1c,0x280d);half(s['root']+8,0x46c0)
        half(s['init']+0xe,0x2180);half(s['init']+0x4a,0x7088)
        half(s['init']+0x52,0x20dd);half(s['init']+0x56,0x2020)
        half(s['setup']+0x15e,0xb001);half(s['config']+0x14,0x46c0)
        half(s['copy']+0x34,0x6021);word(s['tables'][0]+4,s['ram'])
        word(s['tables'][0]+16,0x10000000);word(s['tables'][0]+12,s['ram']+0x8000);word(s['sources'][0]+0xb4,0)
        word(s['reset']+0xb4,0x1a000001);word(s['test']-24,0x7fffff)
        word(s['test']+0x20,0xe1a00000);word(s['test']+0x178,0);word(s['sources'][1]+0x578+0x10,0x3000f0c)
        half(s['template'],0);half(s['tx']+2,0x8809);half(s['wrapper']+12,0x46c0)
        for at,value in cases:
            changed=bytearray(data);changed[at:at+len(value)]=value
            with self.subTest(at=hex(at)):self.assertIsNone(self.detect(bytes(changed))[0])
    def test_copy_field_pointer_boundaries_and_duplicate(self):
        data,s=probe_fixture()
        for role,index in (('copy',1),('copy',5),('copy',10),('setup',0),('wrapper',0)):
            altered=bytearray(data);at=s[role]+0x300+4*index
            struct.pack_into('<I',altered,at,s['tables'][0]+12)
            with self.subTest(role=role,index=index):self.assertIsNone(self.detect(bytes(altered))[0])
        for end in (s['copy']+20,s['test']+100,s['sources'][0]+0xb4,s['sources'][1]+0x590):
            self.assertIsNone(self.detect(data[:end])[0])
        changed=bytearray(data);at=0x3a000;mask,calls,lits=_console._PROBE_SPECS['root']
        changed[at:at+len(mask)//2]=data[s['root']:s['root']+len(mask)//2]
        for off in calls:
            target=_console.thumb_bl_target(data,s['root']+off);d=target-at-off-4
            struct.pack_into('<HH',changed,at+off,0xf000|(d>>12&2047),0xf800|(d>>1&2047))
        for i,(off,reg)in enumerate(lits):
            pool=at+0x300+4*i;op=struct.unpack_from('<H',data,s['root']+off)[0];oldpool=((s['root']+off+4)&~3)+(op&255)*4
            struct.pack_into('<H',changed,at+off,0x4800|reg<<8|((pool-((at+off+4)&~3))//4));changed[pool:pool+4]=data[oldpool:oldpool+4]
        self.assertIn('ambiguous',self.detect(bytes(changed))[1])
    def test_old_source_and_AST_preserved(self):
        import ast,hashlib,inspect
        source=inspect.getsource(_console);prefix=source.split('\n\n# A distinct finite boot probe;')[0]
        self.assertEqual(hashlib.sha256(prefix.encode()).hexdigest(),_PROBE_OLD_SOURCE_SHA)
        old=[ast.dump(n,include_attributes=False)for n in ast.parse(prefix).body if isinstance(n,ast.FunctionDef)]
        now=[ast.dump(n,include_attributes=False)for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)]
        self.assertEqual(old,now[:len(old)])
    def test_old_profile_priority_and_unused_header(self):
        data,sites=probe_fixture()
        changed=bytearray(data)
        struct.pack_into('<I',changed,0x20,0xbeaf)
        struct.pack_into('<H',changed,0x24,0x1111)
        struct.pack_into('<H',changed,0x2c,0x2222)
        self.assertIsNotNone(self.detect(bytes(changed))[0])
        old=fixture();combined=bytearray(len(data));combined[:len(old)]=old
        length=len(_console._PROBE_SPECS['root'][0])//2
        combined[0x30000:0x30000+length]=data[sites['root']:sites['root']+length]
        before,reason=find_uart_console_profile(old,find_ready_poll_profile(old))
        after,why=find_uart_console_profile(bytes(combined),find_ready_poll_profile(bytes(combined)))
        self.assertIsNotNone(before,reason);self.assertIsNotNone(after,why)
        self.assertEqual(after['signature'],before['signature'])
    def test_guard_union_and_initialized_write_pcs(self):
        data,sites=probe_fixture();profile,reason=self.detect(data);self.assertIsNotNone(profile,reason)
        union=profile['guard_intervals']
        for name in ('code_intervals','literal_intervals','data_intervals','boot_guard_intervals'):
            for lo,hi in profile[name]:
                self.assertTrue(any(a<=lo and hi<=b for a,b in union),(name,lo,hi))
        writes=profile['init_writes'];self.assertEqual(len(writes),13)
        self.assertEqual([w['value']for w in writes[-7:]],[0x30,0x10,0x10,0x20,0x20,1,4])
        self.assertEqual(writes[5]['value'],0xff)
        changed=bytearray(data);struct.pack_into('<H',changed,sites['init']+0x44,0x7188)
        self.assertIsNone(self.detect(bytes(changed))[0])
    def test_delay_domain_and_private_counter_ownership(self):
        data,sites=probe_fixture();profile,why=self.detect(data)
        self.assertIsNotNone(profile,why)
        for literal,value in ((0x26,0x03000f0c),(0x3e,0x03000f0c),(0x26,0x04800022),
                              (2,sites['ram']+0x60b4),(2,sites['ram']+0x60b0),
                              (2,sites['ram']+0x578),(2,sites['ram']+0x60c0)):
            changed=bytearray(data)
            op=struct.unpack_from('<H',data,sites['delay']+literal)[0]
            pool=((sites['delay']+literal+4)&~3)+(op&255)*4
            struct.pack_into('<I',changed,pool,value)
            with self.subTest(literal=literal,value=hex(value)):
                self.assertIsNone(self.detect(bytes(changed))[0])
        for offset,width in ((0xa8,4),(0xac,2)):
            changed=bytearray(data);changed[sites['sources'][0]+offset:sites['sources'][0]+offset+width]=bytes(width)
            self.assertIsNone(self.detect(bytes(changed))[0])
        state=profile['delay_state_source']
        self.assertTrue(any(lo<=state and state+0x26<=hi for lo,hi in profile['guard_intervals']))
    def test_memcpy_44_continuation_and_return_guarded(self):
        data,sites=probe_fixture();profile,why=self.detect(data)
        self.assertIsNotNone(profile,why);entry=profile['setup_memcpy_entry']
        self.assertTrue(any(lo<=entry and entry+0x50<=hi for lo,hi in profile['guard_intervals']))
        for offset in (0x18,0x1c,0x20,0x24,0x28,0x34,0x38,0x3c,0x40,0x44,0x48,0x4c):
            changed=bytearray(data);changed[entry+offset]^=1
            with self.subTest(offset=hex(offset)):
                self.assertIsNone(self.detect(bytes(changed))[0])
        for end in (entry+24,entry+0x48,entry+0x4f):
            self.assertIsNone(self.detect(data[:end])[0])
    def test_actual_two_positive_and_two_probe_negative(self):
        import hashlib
        from pathlib import Path
        root=FIRMWARE_ROOT
        controls=[(root/'T030TEDT09_5.177_JTAG - Old Phone Preservation.bin','f236bcf02a9f16e9e5aa0d13c714a832f5e1ed8dbd5da4d58278ecfd103338ed',True),
          (root/'incoming-msm5xxx-all-manufacturers-20260726/Audiovox/CDM-8500/T050VMDM01_3.191_JTAG/T050VMDM01_3.191_JTAG.bin','67f47b9ab99e9f4c8477fc56d3b969f2dc02a9713ed28bb57b8812de557b0ef8',True),
          (root/'incoming-20260719-r1/MSM5100/T055BW1T19_1.242_JTAG.bin','24bf05931ac81cce005b1ad5e970e061b38daf25ea3d70f658e2fa66fb801491',False)]
        for path,sha,accepted in controls:
            if not path.exists():self.skipTest('private supplied image unavailable')
            before=path.stat();data=path.read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),sha)
            profile,why=_console._find_previous_uart_console_profile(data,None)
            with self.subTest(sha=sha):
                self.assertEqual(profile is not None,accepted,why)
                if not accepted:self.assertEqual(why,'console-byte-primary-code-unclosed')
                if accepted:self.assertEqual(profile['csr_sequence'],[255,221])
                if accepted:
                    for literal in (0x26,0x3e):
                        changed=bytearray(data);pc=profile['delay_entry']+literal
                        op=struct.unpack_from('<H',data,pc)[0];pool=((pc+4)&~3)+(op&255)*4
                        struct.pack_into('<I',changed,pool,0x03000f0c)
                        self.assertIsNone(self.detect(bytes(changed))[0])
                    changed=bytearray(data);changed[profile['setup_memcpy_entry']+0x4c]^=1
                    self.assertIsNone(self.detect(bytes(changed))[0])
            after=path.stat();self.assertEqual((before.st_size,before.st_mtime_ns),(after.st_size,after.st_mtime_ns))


class FiniteFFCCConsoleTests(unittest.TestCase):
    def detect(self,data):return find_uart_console_profile(data,None)
    def test_portable_relocated_full_copy_and_clock_graph(self):
        for shift,ram in ((0,0),(0x400,0x10000)):
            data,s=probe_fixture(shift,ram,True);p,why=self.detect(data)
            self.assertIsNotNone(p,why)
            self.assertEqual(p['signature'],'thumb-byte-uart-finite-ff-cc-99-console-v1')
            self.assertEqual(p['csr_sequence'],[255,204,153]);self.assertEqual(p['outside_config_drains'],[4,4,2])
            self.assertEqual(p['lf_stages'],[True,True,False]);self.assertEqual(p['config9_argument'],128)
            self.assertEqual(len(p['copy_layouts']),3);self.assertTrue(p['iram_intervals'])
            self.assertNotIn('reset_reentry',p)
            for role in ('code_intervals','literal_intervals','data_intervals','boot_guard_intervals'):
                self.assertTrue(p[role])
                for lo,hi in p[role]:self.assertTrue(any(a<=lo and hi<=b for a,b in p['guard_intervals']))
            self.assertEqual(p['setup_memcpy_source'],s['iram_source'])
    def test_critical_source_mutations_and_truncation(self):
        data,s=probe_fixture(ffcc=True);cases=[]
        def half(at,v):cases.append((at,struct.pack('<H',v)))
        def word(at,v):cases.append((at,struct.pack('<I',v)))
        half(s['root']+0x1e,0x20cc);half(s['root']+0x26,0x20ff);half(s['root']+0x70,0x20dd)
        half(s['root']+0x34,0x2c03);half(s['root']+0x50,0x46c0)
        half(s['init']+0xe,0x2100);half(s['init']+0x4c,0x8088)
        half(s['copy']+0x100,0x46c0);half(s['setup']+0x12,0x46c0)
        word(s['marker'],0x006c65);word(s['iram_table']+4,0x1000100)
        word(s['iram_table'],s['sources'][1]);word(s['tables'][1]+12,s['ram']+0x6000)
        word(s['selector_table']+8,0x737e);word(s['selector_table']+36,16)
        half(s['clock_regs']+0x16,0x7001);half(s['clock_version']+0xa,0x46c0)
        half(s['clock_commit']+0x1c,0x2000);half(s['clock_update']+0xc,0x7008)
        word(s['division']+0x58,0xe1a00000);half(s['iram_source']+0x4c,0x4778)
        word(s['division_veneer']+12,s['division']+3)
        for at,value in cases:
            changed=bytearray(data);changed[at:at+len(value)]=value
            with self.subTest(at=hex(at)):self.assertIsNone(self.detect(bytes(changed))[0])
        for end in (s['iram_source']+0x4f,s['clock_commit']+0xd5,s['division']+0xc3,s['marker']+3):
            self.assertIsNone(self.detect(data[:end])[0])
    def test_active_clock_mutations_tighten_both_protocols(self):
        for ffcc in (False,True):
            data,s=probe_fixture(ffcc=ffcc)
            for at in (s['clock_regs']+0x12,s['clock_commit']+0x28,s['clock_version_get']+0xe,
                       s['clock_select_a']+0x20,s['clock_update']+0xc,s['selector_table']+32):
                altered=bytearray(data);altered[at]^=1
                with self.subTest(ffcc=ffcc,at=hex(at)):self.assertIsNone(self.detect(bytes(altered))[0])
    def test_old_reentry_metadata_is_source_derived(self):
        data,s=probe_fixture();p,why=self.detect(data);self.assertIsNotNone(p,why)
        r=p['reset_reentry'];self.assertEqual(r['write_pcs'],[s['primary']+4,s['primary']+6])
        self.assertEqual(r['status_read_pc'],s['primary']+10)
        self.assertEqual(r['root_lr'],(s['root']+6)|1);self.assertEqual(r['config_lr'],(s['init']+0x1a)|1)
        self.assertEqual((r['width'],r['value'],r['status_mask']),(1,32,8))
    def test_complete_owner_ambiguity(self):
        data,s=probe_fixture(ffcc=True);changed=bytearray(data);at=0x3a000
        mask,calls,lits=_console._probe_specs('root',True)
        changed[at:at+len(mask)//2]=data[s['root']:s['root']+len(mask)//2]
        for off in calls:
            target=_console.thumb_bl_target(data,s['root']+off);delta=target-at-off-4
            struct.pack_into('<HH',changed,at+off,0xf000|(delta>>12&2047),0xf800|(delta>>1&2047))
        for i,(off,reg)in enumerate(lits):
            op=struct.unpack_from('<H',data,s['root']+off)[0];pool=((s['root']+off+4)&~3)+(op&255)*4
            struct.pack_into('<H',changed,at+off,0x4800|reg<<8|((at+0x300+i*4-((at+off+4)&~3))//4))
            changed[at+0x300+i*4:at+0x304+i*4]=data[pool:pool+4]
        # A raw unowned duplicate must not steal the unique reset-linked owner.
        p,why=self.detect(bytes(changed));self.assertIsNotNone(p,why)
        self.assertEqual(p['console_root'],s['root'])
    def test_actual_full_and_partial_independent_witnesses(self):
        import hashlib,json
        from pathlib import Path
        manifest_path=os.environ.get('MSM5XXX_TEST_UART_PEER_MANIFEST')
        if not manifest_path:self.skipTest('private supplied evidence unavailable')
        manifest=Path(manifest_path)
        if not manifest.is_file():self.skipTest('private supplied evidence unavailable')
        for row in json.loads(manifest.read_text()):
            path=Path(row['path'])
            if not path.exists():self.skipTest('private supplied image unavailable')
            st=path.stat();data=path.read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),row['sha256'])
            p,why=self.detect(data);self.assertIsNotNone(p,why)
            self.assertEqual(p['csr_sequence'],[255,204,153]);self.assertEqual(p['console_root'],row['root'])
            self.assertTrue(all(0<=lo<hi<=len(data)for lo,hi in p['guard_intervals']))
            self.assertEqual((st.st_size,st.st_mtime_ns),(path.stat().st_size,path.stat().st_mtime_ns))

    def test_inactive_external_peer_body_is_not_claimed(self):
        data,s=probe_fixture(ffcc=True);p,why=self.detect(data);self.assertIsNotNone(p,why)
        self.assertEqual(p['external_peer_branch']['policy'],'unreachable-while-owned-null-rx-empty')
        changed=bytearray(data)
        for target in p['external_peer_branch']['targets']:changed[target:target+2]=bytes.fromhex('00de')
        after,why=self.detect(bytes(changed));self.assertIsNotNone(after,why)
        self.assertEqual(p,after)
        # The source-owned call/branch instruction remains an immutable guard.
        self.assertTrue(all(any(lo<=pc and pc+4<=hi for lo,hi in p['code_intervals'])
                            for pc in p['external_peer_branch']['call_pcs']))
