"""Focused consumer/typed bus closure; no VM or firmware fixtures required."""
import copy
import struct
import unittest

import test_sbi_bootstrap_profile as bootstrap_fixture
from msm5xxx_emulator.detection.input import find_sbi_bootstrap_profile
from msm5xxx_emulator.detection.sbi_raw_input import find_sbi_raw_input_profile, _clock_pair

_RAW = bytes.fromhex('b0b50406240e0000000005042d0c000000002a20000000000000387880231843387038789f2318403870402c04d138784023184338700de0602c04d1387860231843387006e0002c04d13878202318433870ffe739780a2000000000000000000000000038788023db431840387039780a2000000000000000000b2000000000000000000000808907063f0e002d01d100000000002c05d1000000680078002800d0ffe7381cb0bd')
_FILTER = bytes.fromhex('f0b582b082b00006000e00900d062d0e1106090e019182b00027002001900024002100910026e91f03390591e91d03310491032e30da03e0701c0606360ef8e7029800000000002d1ad00399884217db0599814209da0499814206dd20180404240c781c07063f0e09e0009908180104090c0091019801300006000e01900ae0002d08d10399884205db20180404240c781c07063f0ecfe70198032807db00990198000000000006000e06b0f0bd002f02d1281c06b0f9e7211c381c000000000006000e06b0f1e7')


def fixture(selector=0x40, parameter=0x5A, shift=0, ram_base=0x01000000):
    prefix, _ = bootstrap_fixture.SbiBootstrapProfileTest._image('direct')
    image = bytearray(0x1800); image[:len(prefix)] = prefix
    def words(at, values):
        for offset, value in values.items():
            struct.pack_into('<H', image, at + offset, value)
    def bl(at, target):
        delta = target - at - 4
        struct.pack_into('<2H', image, at, 0xF000 | (delta >> 12 & 0x7FF),
                         0xF800 | (delta >> 1 & 0x7FF))
    def literal(at, register, pool, value):
        pc = (at + 4) & ~3
        struct.pack_into('<H', image, at, 0x4800 | register << 8 | (pool-pc)//4)
        struct.pack_into('<I', image, pool, value)
    raw, filt, cache = 0x500, 0x800, 0xC00
    image[raw:raw+len(_RAW)] = _RAW
    image[filt:filt+len(_FILTER)] = _FILTER
    links = {6:0x1000,0x0E:0x1100,0x14:0x1200,0x58:0x1240,0x5C:0x1280,
             0x60:0x1140,0x72:0x1240,0x76:0x1140,0x7C:0x12C0,0x80:0x1180,0x90:0x1040}
    for offset, target in links.items(): bl(raw+offset, target)
    literal(raw+0x18,7,raw+0xB0,ram_base+0x100)
    literal(raw+0x84,0,raw+0xB4,0x03000780)
    literal(raw+0x98,0,raw+0xB8,ram_base+0x200)
    for offset,target in ((0x42,raw),(0xA2,0x1320),(0xBC,0x1320)):bl(filt+offset,target)
    words(cache,{0:0xB580,4:0x7839,6:0x2200|parameter,8:0x2000|selector,
                 0x0E:0x7038,0x10:0xBD80})
    literal(cache+2,7,cache+0x40,ram_base+0x300);bl(cache+0x0A,filt)
    image[0x1000:0x101C] = bytes.fromhex('7847000001e08ee300000fe1801080e301f021e1800000e21eff2fe1')
    image[0x1040:0x105C] = bytes.fromhex('7847000001e08ee300000fe18010c0e301f021e1800000e21eff2fe1')
    words(0x1200,{0:0x0680,2:0x0E80,4:0x2321,6:0x019B,8:0x4318,12:0x8088,14:0x46F7})
    literal(0x120A,1,0x1210,0x03000780)
    words(0x1240,{0:0x0600,2:0x0E00,4:0x0609,6:0x0E09,8:0x0700,10:0x0F00,
                  12:0x0200,14:0x4308,18:0x8188,20:0x46F7})
    literal(0x1250,1,0x1258,0x03000780)
    words(0x1280,{0:0x2100,4:0x7401,6:0x2101,8:0x7401,10:0x46F7})
    literal(0x1282,0,0x128C,0x03000780)
    words(0x12C0,{0:0x0400,2:0x0C00,4:0x0640,6:0x0E40,8:0x0200,10:0x2301,
                  12:0x03DB,14:0x4318,18:0x8188,20:0x46F7})
    literal(0x12D0,1,0x12D8,0x03000780)
    for at,busy in ((0x1100,True),(0x1140,False)):
        words(at,{0:0xB590,2:0x2732,6:0x8820,8:0x2304 if busy else 0x07C0,
                  10:0x4018 if busy else 0x0FC0,12:0x2804 if busy else 0x2801,
                  14:0xD109,24:0x1C38,26:0x3F01,28:0x2800,30:0xD100,
                  32:0xE000,34:0xE7F0,36:0xBD90})
        literal(at+4,4,at+0x28,0x03000780);bl(at+16,0x1300);bl(at+20,0x1300)
    words(0x1180,{0:0xB590,2:0x2732,6:0x8820,8:0x2302,10:0x4018,12:0xD109,
                  22:0x1C38,24:0x3F01,26:0x2800,28:0xD100,30:0xE000,
                  32:0xE7F1,34:0xBD90})
    literal(0x1184,4,0x11A4,0x03000780);bl(0x118E,0x1300);bl(0x1192,0x1300)
    clock = 0x1200 - 0x44
    words(clock,{4:0x214A,8:0x7039,12:0x7021,14:0x2800,16:0xD101,
                 26:0x1C01,28:0x20CA,30:0x7038,32:0x7020,34:0x2900,
                 36:0xD101,42:0xBD90})
    literal(clock+6,7,0x11F8,ram_base+0x80)
    literal(clock+10,4,0x11FC,0x03000780)
    for offset,target in ((0,0x1000),(18,0x1040),(22,0x1000),(38,0x1040)):
        bl(clock+offset,target)
    words(0x1300,{0:0x46F7});words(0x1320,{0:0x4770})
    return bytes(shift)+image


class SbiRawInputTests(unittest.TestCase):
    def detect(self, image, bootstrap=None, ram_base=0x01000000, ram_size=0x00800000):
        if bootstrap is None: bootstrap=find_sbi_bootstrap_profile(image)
        return find_sbi_raw_input_profile(image, bootstrap, ram_base, ram_size)

    def test_relocated_explicit_selector_branches_and_ram_parameters(self):
        for shift in (0,0x204):
            for selector,wire in ((0,0x20),(0x40,0x40),(0x60,0x60)):
                for ram_base in (0x01000000,0x14000000):
                    with self.subTest(shift=shift,selector=selector,ram_base=ram_base):
                        image=fixture(selector,shift=shift,ram_base=ram_base)
                        profile,reason=self.detect(image,ram_base=ram_base)
                        self.assertEqual(reason,'accepted')
                        self.assertEqual(profile['read_pc'],0x586+shift)
                        self.assertEqual(profile['entry'],0x500+shift)
                        self.assertEqual(profile['selector_value'],wire)
                        self.assertEqual(profile['selector_mask'],0x60)
                        self.assertEqual(profile['source_selector'],selector)
                        self.assertEqual(profile['control'],0x086A)
                        self.assertEqual(profile['read_command'],0x8B00)
                        self.assertEqual(profile['policy'],'configured-virtual-raw-byte-uncalibrated')
                        self.assertNotIn('raw_value',profile)
                        self.assertEqual(profile['clock_values'],[0x4A,0xCA])
                        self.assertEqual(profile['clock_entry'],0x11BC+shift)
                        self.assertEqual(profile['clock_write_pcs'],[0x11C8+shift,0x11DC+shift])
                        self.assertEqual(profile['clock_shadow'],ram_base+0x80)
        # The software filter parameter does not choose the configured virtual byte.
        self.assertIsNotNone(self.detect(fixture(parameter=1))[0])
        for selector in (1,0x20,0x80,0xFF):
            self.assertIsNone(self.detect(fixture(selector))[0])

    def test_required_opcode_width_literal_call_and_branch_mutations(self):
        original=fixture();bootstrap=find_sbi_bootstrap_profile(original)
        mutations={
            'raw-control':0x512,'raw-first-command':0x556,'raw-second-command':0x570,
            'raw-read-command':0x57A,'raw-data-width':0x586,'raw-lowbyte':0x588,
            'raw-selector-mask':0x524,'raw-selector-branch':0x52C,'raw-clear80':0x568,
            'raw-literal-register':0x518,'raw-status-base':0x5B4,'raw-flag-branch':0x59E,
            'filter-three-samples':0x832,'filter-backedge':0x83E,'filter-return':0x8C2,
            'cache-read-width':0xC04,'cache-write-width':0xC0E,'cache-return':0xC10,
            'control-width':0x120C,'write-width':0x1252,'start-width':0x1284,
            'read-request-width':0x12D2,'request-base':0x1258,'start-base':0x128C,
            'busy-width':0x1106,'busy-mask':0x1108,'busy-backedge':0x1122,
            'write-poll-branch':0x114E,'read-full-mask':0x1188,'read-full-edge':0x11A0,
            'delay-return':0x1300,'irq-save-bit':0x1010,
        }
        for name,at in mutations.items():
            with self.subTest(name=name):
                image=bytearray(original);image[at]^=1
                self.assertIsNone(self.detect(bytes(image),bootstrap)[0])
        for at in (0x506,0x50E,0x514,0x558,0x55C,0x560,0x572,0x576,0x57C,
                   0x580,0x590,0x842,0x8A2,0x8BC,0xC0A):
            image=bytearray(original);image[at:at+4]=bytes(4)
            self.assertIsNone(self.detect(bytes(image),bootstrap)[0])
        for address in (0x03000780,0x01000100,0x01000201,0x01800000):
            image=bytearray(original);struct.pack_into('<I',image,0xC40,address)
            self.assertIsNone(self.detect(bytes(image),bootstrap)[0])

    def test_bootstrap_ram_bounds_duplicates_and_missing_consumers(self):
        image=fixture();bootstrap=find_sbi_bootstrap_profile(image)
        for name,value in (('accepted',False),('signature','other'),('entries',[-2]),
                           ('entries',[True]),('layout',None)):
            bad=copy.deepcopy(bootstrap);bad[name]=value
            self.assertIsNone(self.detect(image,bad)[0])
        bad=copy.deepcopy(bootstrap);bad['bootstrap'][0][1]=True
        self.assertIsNone(self.detect(image,bad)[0])
        self.assertIsNotNone(self.detect(image,bootstrap,ram_size=0x301)[0])
        self.assertIsNone(self.detect(image,bootstrap,ram_size=0x300)[0])
        self.assertIsNone(find_sbi_raw_input_profile(image,None,0x01000000,0x800000)[0])
        for base,size in ((True,0x800000),(0x01000000,0),(0x01000000,0x100),(-1,0x800000)):
            self.assertIsNone(self.detect(image,bootstrap,base,size)[0])
        self.assertIsNone(self.detect(bytes(image)*2,bootstrap)[0])
        extra=bytearray(image);extra[0xE00:0xE12]=image[0xC00:0xC12];extra[0xE40:0xE44]=image[0xC40:0xC44]
        delta=0x800-0xE0A-4
        struct.pack_into('<2H',extra,0xE0A,0xF000|(delta>>12&0x7FF),0xF800|(delta>>1&0x7FF))
        self.assertIsNone(self.detect(bytes(extra),bootstrap)[0])
        for end in (0x586,0x8C7,0x1300):
            self.assertIsNone(self.detect(image[:end],bootstrap)[0])
        missing=bytearray(image);missing[0xC00:0xC12]=bytes(0x12)
        self.assertIsNone(self.detect(bytes(missing),bootstrap)[0])
        self.assertIsNone(self.detect(b'\0'+bytes(image),bootstrap)[0])

    def test_mandatory_clock_pair_mutations_and_missing_body(self):
        original=fixture();bootstrap=find_sbi_bootstrap_profile(original);clock=0x11BC
        for offset in (4,6,8,10,12,14,16,26,28,30,32,34,36,42):
            with self.subTest(clock_offset=offset):
                changed=bytearray(original);changed[clock+offset]^=1
                self.assertIsNone(self.detect(bytes(changed),bootstrap)[0])
        for offset in (0,18,22,38):
            changed=bytearray(original);changed[clock+offset:clock+offset+4]=bytes(4)
            self.assertIsNone(self.detect(bytes(changed),bootstrap)[0])
        for offset in (8,12,30,32):
            changed=bytearray(original)
            word=struct.unpack_from('<H',changed,clock+offset)[0]
            struct.pack_into('<H',changed,clock+offset,word^0x1000)
            self.assertIsNone(self.detect(bytes(changed),bootstrap)[0])
        for pointer in (0x03000780,0x01000100,0x01000200,0x01000300,0x01800000):
            changed=bytearray(original);struct.pack_into('<I',changed,0x11F8,pointer)
            self.assertIsNone(self.detect(bytes(changed),bootstrap)[0])
        changed=bytearray(original);struct.pack_into('<I',changed,0x11FC,0x03000784)
        self.assertIsNone(self.detect(bytes(changed),bootstrap)[0])
        self.assertIsNone(_clock_pair(original[:clock+0x2B],{0x14:0x1200,6:0x1000,0x90:0x1040}))
        changed=bytearray(original);changed[clock:clock+0x2C]=bytes(0x2C)
        self.assertIsNone(self.detect(bytes(changed),bootstrap)[0])
        self.assertEqual(find_sbi_bootstrap_profile(changed),bootstrap)
