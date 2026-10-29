"""Original two-ROM class and destructive in-memory mutation checks."""
from pathlib import Path
import os
import hashlib
import unittest
from msm5xxx_emulator.detection.service import (
    _at as at, find_origination_service_profile as find,
    _SIZE, _CALLS, _LITERALS, _CALLEE_BODIES, thumb_bl_target)
from corpus import FIRMWARE_ROOT

CASES=[('x350_VC22.bin',0x1081c,'7a6a4df853b51a4b44e86c3334330c12facad2954eef5a94031724ff1ff44073'),
       ('schx150.bin',0x1086c,'347057aeb9985579bb31c64e7fa20dc18486b7fb59aea82a682d4b10d9711de0')]

class ServiceDetectionTests(unittest.TestCase):
    def test_two_roms_and_mutated_dependencies(self):
        ROOT=FIRMWARE_ROOT
        if not all((ROOT/name).is_file() for name,_,_ in CASES):
            self.skipTest('original service producer ROM fixtures unavailable')
        mutations=0
        for name,entry,digest in CASES:
            raw=(ROOT/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest
            profile=find(raw,0x1000000,0x800000)
            assert profile['accepted'] and profile['entry']==entry
            assert profile['revision_address']==0x13800ac
            assert profile['message_type']==4 and profile['dispatcher']==entry+0xe1c
            image=bytearray(raw);masked=set()
            for off,group in _CALLS:masked.update(range(off,off+4))
            masked.update(off for off,reg,pool in _LITERALS)
            masked.update(range(0x478,0x480))
            for off in range(_SIZE):
                if off in masked:continue
                image[entry+off]^=1;assert at(image,entry,0x1000000,0x800000) is None
                image[entry+off]^=1;mutations+=1
            for off,group in _CALLS:
                image[entry+off+1]^=0x80;assert at(image,entry,0x1000000,0x800000) is None
                image[entry+off+1]^=0x80;mutations+=1
            for off,reg,pool in _LITERALS:
                image[entry+off]^=1;assert at(image,entry,0x1000000,0x800000) is None
                image[entry+off]^=1;mutations+=1
            for group,(length,digest) in _CALLEE_BODIES.items():
                off=next(off for off,g in _CALLS if g==group);target=thumb_bl_target(raw,entry+off)
                for byte in range(length):
                    image[target+byte]^=1;assert at(image,entry,0x1000000,0x800000) is None
                    image[target+byte]^=1;mutations+=1
            image[entry+0x478:entry+0x47c]=(0x3000410).to_bytes(4,'little')
            assert at(image,entry,0x1000000,0x800000) is None
            image[entry+0x478:entry+0x480]=raw[entry+0x478:entry+0x480]
            image[entry+0x47c]^=1;assert at(image,entry,0x1000000,0x800000) is None
            for off in (0x478,0x47c):
                image[entry+off:entry+off+4]=(int.from_bytes(raw[entry+off:entry+off+4],'little')+0x1000).to_bytes(4,'little')
            assert at(image,entry,0x1000000,0x800000) is None  # Header must share revision source.
            header=profile['header_packer'];pc=header+4
            word=int.from_bytes(raw[pc:pc+2],'little');pool=((pc+4)&~3)+4*(word&255)
            image[pool:pool+4]=(0x13810ac).to_bytes(4,'little')
            shifted=at(image,entry,0x1000000,0x800000)
            assert shifted['accepted'] and shifted['revision_address']==0x13810ac
            image[:]=raw
            dispatch=profile['dispatcher'];image[dispatch+0x14]^=1
            assert at(image,entry,0x1000000,0x800000) is None
            image[:]=raw;image[dispatch+0x2f]^=0x80
            assert at(image,entry,0x1000000,0x800000) is None
            image[:]=raw;image[pool]^=1
            assert at(image,entry,0x1000000,0x800000) is None
            assert at(raw[:entry+_SIZE],entry,0x1000000,0x800000) is None
            assert at(raw,entry+1,0x1000000,0x800000) is None
            assert at(raw,entry,0x1000000,0) is None
        self.assertEqual(mutations,3842)

    def test_unmatched_input(self):
        self.assertFalse(find(b'',0x1000000,0x800000)['accepted'])
        self.assertFalse(find(bytes(4096),0x1000000,0x800000)['accepted'])

    def test_multiple_valid_producers_are_rejected(self):
        root=FIRMWARE_ROOT
        path=root/CASES[0][0]
        if not path.is_file():self.skipTest('original service producer ROM fixture unavailable')
        image=bytearray(path.read_bytes());original=find(image,0x1000000,0x800000)
        self.assertTrue(original['accepted'])
        entry=original['entry'];dispatcher=original['dispatcher'];clone=0x200000;dispatch_clone=clone+_SIZE+4
        def relocate(blob,old,new,size,call_offsets,replacement=None):
            image[new:new+size]=blob[old:old+size]
            for offset in call_offsets:
                target=thumb_bl_target(blob,old+offset)
                if replacement and target==replacement[0]:target=replacement[1]
                delta=target-(new+offset+4)
                self.assertTrue(-0x400000<=delta<0x400000 and not delta&1)
                encoded=delta&0x7fffff
                image[new+offset:new+offset+4]=((0xf000|(encoded>>12)).to_bytes(2,'little')+
                                              (0xf800|((encoded>>1)&2047)).to_bytes(2,'little'))
        raw=bytes(image)
        relocate(raw,entry,clone,_SIZE+4,[off for off,_ in _CALLS])
        from msm5xxx_emulator.detection.service import _DISPATCHER_CALLS
        relocate(raw,dispatcher,dispatch_clone,92,_DISPATCHER_CALLS,(entry,clone))
        result=find(image,0x1000000,0x800000)
        self.assertFalse(result['accepted']);self.assertEqual(result['matches'],2)
        self.assertEqual(result['reject_reason'],'service-packer-ambiguous')
