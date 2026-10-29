"""Reset/callee/literal mutations, without original-firmware dependencies."""
import struct
import unittest

from msm5xxx_emulator.detection import boot_keysense as detector


def fixture(prefixed=False, shift=0):
    image = bytearray(0xB000+shift)
    reset, entry = 0x100+shift, 0x1000+shift
    stack, diagnostic, delay, noop = 0x4000+shift, 0x5000+shift, 0x6000+shift, 0x6100+shift
    def word(at, value): struct.pack_into('<I', image, at, value)
    def branch(at, target): word(at, 0xEA000000 | ((target-at-8)//4 & 0xFFFFFF))
    def bl(at, target):
        delta=target-at-4
        struct.pack_into('<HH', image, at, 0xF000 | (delta>>12 & 0x7FF), 0xF800 | (delta>>1 & 0x7FF))
    def arm_literal(at, value):
        instruction=struct.unpack_from('<I',image,at)[0]
        pool=at+8+(instruction&0xFFF)*(1 if instruction&0x800000 else -1)
        word(pool,value)
    pattern=detector._PREFIXED if prefixed else detector._LEAF
    literals=detector._PREFIXED_LITERALS if prefixed else detector._LEAF_LITERALS
    image[entry:entry+len(pattern)] = pattern
    for offset,(reg,value) in literals.items():
        ins=struct.unpack_from('<H',image,entry+offset)[0]
        pool=((entry+offset+4)&~3)+(ins&255)*4
        word(pool,value)
    branch(0,reset)
    gate=reset+len(detector._RESET_PREFIX);service=gate+0x50
    image[reset:gate]=detector._RESET_PREFIX
    image[gate:gate+len(detector._GATE)]=detector._GATE
    image[service:service+len(detector._SERVICE)]=detector._SERVICE
    arm_literal(gate,entry|1);arm_literal(gate+8,gate+0x14);arm_literal(gate+12,gate+0x18)
    branch(gate+0x20,0x8000+shift)
    arm_literal(service+12,0x8201+shift)
    arm_literal(service+20,service+0x20);arm_literal(service+24,service+0x24)
    if prefixed:
        for offset,target in ((6,stack),(0x32,noop),(0x3A,noop),(0x3E,noop),(0x52,delay)):
            bl(entry+offset,target)
        image[stack:stack+len(detector._STACK_FAILURE)]=detector._STACK_FAILURE
        arm_literal(stack+0x18,diagnostic|1)
        arm_literal(stack+0x20,stack+0x2C);arm_literal(stack+0x24,stack+0x30)
        image[diagnostic:diagnostic+0x18]=bytes.fromhex('00b5d54501da000000000000000002a103480000000000bd')
        bl(diagnostic+6,stack);bl(diagnostic+0xA,0x9000+shift);bl(diagnostic+0x12,0x9100+shift)
        image[delay:delay+len(detector._DELAY)]=detector._DELAY
        image[noop:noop+2]=bytes.fromhex('f746')
    return image,dict(reset=reset,entry=entry,gate=gate,service=service,stack=stack,
                      diagnostic=diagnostic,delay=delay,noop=noop)


class BootKeysenseTest(unittest.TestCase):
    def test_both_layouts_and_relocation(self):
        for prefixed in (False,True):
            for shift in (0,4,0x180):
                with self.subTest(prefixed=prefixed,shift=shift):
                    image,p=fixture(prefixed,shift)
                    profile,reason=detector.find_boot_keysense_release(bytes(image))
                    self.assertIsNotNone(profile,reason)
                    offsets=(0x7E,0x86,0x92) if prefixed else (14,22,34)
                    self.assertEqual(profile['read_pcs'],[p['entry']+x for x in offsets])
                    self.assertEqual((profile['address'],profile['mask'],profile['released']), (0x03000694,15,15))

    def test_predicate_mutations(self):
        for prefixed in (False,True):
            image,p=fixture(prefixed);e=p['entry']
            mutations=[('setup-value',e+(0x64 if prefixed else 0)),
                       ('width',e+(0x7E if prefixed else 14)),
                       ('mask',e+(0x80 if prefixed else 16)),
                       ('stable-branch',e+(0x8E if prefixed else 30)),
                       ('released',e+(0x98 if prefixed else 40)),
                       ('return',e+(0x9C if prefixed else 80)),
                       ('reset-route',p['gate']+0x1C),('root',0),('application',p['gate']+0x23)]
            for label,at in mutations:
                with self.subTest(prefixed=prefixed,label=label):
                    changed=image.copy();changed[at]^=1
                    self.assertIsNone(detector.find_boot_keysense_release(bytes(changed))[0])
            literals=detector._PREFIXED_LITERALS if prefixed else detector._LEAF_LITERALS
            for offset in literals:
                at=e+offset;ins=struct.unpack_from('<H',image,at)[0];pool=((at+4)&~3)+(ins&255)*4
                changed=image.copy();changed[pool]^=1
                self.assertIsNone(detector.find_boot_keysense_release(bytes(changed))[0])

    def test_links_duplicates_truncation(self):
        for prefixed in (False,True):
            image,p=fixture(prefixed)
            at=p['gate'];pool=at+8+(struct.unpack_from('<I',image,at)[0]&0xFFF)
            changed=image.copy();changed[pool]^=4
            self.assertIsNone(detector.find_boot_keysense_release(bytes(changed))[0])
            # A second complete owner is ambiguous even when only the first is reset-linked.
            # Relocate just the self-contained predicate and its local pools by a multiple of four.
            pattern=detector._PREFIXED if prefixed else detector._LEAF
            if not prefixed:
                changed=image.copy();changed[0x2000:0x2080]=image[0x1000:0x1080]
                self.assertIsNone(detector.find_boot_keysense_release(bytes(changed))[0])
            for end in (0,4,p['gate']+0x10,p['entry']+len(pattern)-1):
                self.assertIsNone(detector.find_boot_keysense_release(bytes(image[:end]))[0])

    def test_route_targets_conflicting_with_known_code_owners(self):
        for prefixed in (False, True):
            image,p=fixture(prefixed)
            pattern=detector._PREFIXED if prefixed else detector._LEAF
            for target in (p['entry'], p['entry']+4,
                           (p['entry']+len(pattern)-1)&~3):
                changed=image.copy();at=p['gate']+0x20
                struct.pack_into('<I',changed,at,0xEA000000|((target-at-8)//4&0xFFFFFF))
                self.assertEqual(detector.find_boot_keysense_release(bytes(changed))[1], 'route-target-unclosed')
            at=p['service']+12
            pool=at+8+(struct.unpack_from('<I',image,at)[0]&0xFFF)
            for target in (p['reset'],p['gate'],p['service'],p['entry'],
                           p['entry']+len(pattern)-2):
                changed=image.copy();struct.pack_into('<I',changed,pool,target|1)
                self.assertEqual(detector.find_boot_keysense_release(bytes(changed))[1], 'route-target-unclosed')

    def test_all_read_widths_masks_and_return_polarity(self):
        for prefixed in (False, True):
            image,p=fixture(prefixed)
            offsets=(0x7E,0x86,0x92) if prefixed else (14,22,34)
            for offset in offsets:
                for delta in (0,2,4):
                    changed=image.copy();changed[p['entry']+offset+delta]^=1
                    self.assertIsNone(detector.find_boot_keysense_release(bytes(changed))[0])
            changed=image.copy()
            changed[p['entry']+(0x9C if prefixed else 80)]=0
            self.assertIsNone(detector.find_boot_keysense_release(bytes(changed))[0])
            # A prepended/rebased image is not the low reset-rooted source contract.
            self.assertIsNone(detector.find_boot_keysense_release(b'\0'*4+bytes(image))[0])

    def test_prefixed_duplicate_owner(self):
        image,p=fixture(True)
        # Copy all local code/pools and rebind BLs at another location.
        target=0x2000;delta=target-p['entry']
        image[target:target+0xC4]=image[p['entry']:p['entry']+0xC4]
        for offset in detector._PREFIXED_CALLS:
            callee=detector.thumb_bl_target(image,p['entry']+offset)
            displacement=callee-(target+offset)-4
            struct.pack_into('<HH',image,target+offset,
                             0xF000|(displacement>>12&0x7FF),0xF800|(displacement>>1&0x7FF))
        self.assertEqual(detector.find_boot_keysense_release(bytes(image))[1], 'predicate-ambiguous')

    def test_prefixed_helpers_and_terminal_boundary(self):
        image,p=fixture(True)
        for at in (p['entry']+6,p['entry']+0x32,p['entry']+0x3A,p['entry']+0x52,
                   p['stack'],p['stack']+0x30,p['diagnostic']+6,
                   p['diagnostic']+0x16,p['delay']+0xA,p['noop']):
            with self.subTest(at=hex(at)):
                changed=image.copy();changed[at]^=1
                self.assertIsNone(detector.find_boot_keysense_release(bytes(changed))[0])


if __name__=='__main__':unittest.main()
