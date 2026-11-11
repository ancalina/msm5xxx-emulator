import unittest

from msm5xxx_emulator.devices.display import b0_page as m
from msm5xxx_emulator.detection.devices.display import b0_page_writer as evidence

class Tests(unittest.TestCase):
    def test_unrelated_source_is_rejected(self):
        self.assertFalse(evidence.has_paired_page_writer(bytes(4096)))
        self.assertFalse(evidence.has_byte_paired_page_writer(bytes(4096)))
        self.assertFalse(evidence.has_separate_mono_page_writer(bytes(4096)))
        self.assertFalse(evidence.has_offset_mono_page_writer(bytes(4096)))

    def test_full_then_partial(self):
        p=m.PairedPage();frame=None
        for page in range(16):
            for v in (0xb0+page,0x10,0):p.write(0x2000000,2,v)
            for n in range(256):
                owned,frame=p.write(0x2000002,2,0)
                self.assertTrue(owned)
                if page!=15 or n!=255:self.assertIsNone(frame)
        self.assertEqual(len(frame),128*128*3)
        self.assertEqual(frame[:3],b'\xff'*3)
        for v in (0xb0,0x10,0):p.write(0x2000000,2,v)
        self.assertIsNone(p.write(0x2000002,2,1)[1])
        frame=p.write(0x2000002,2,1)[1]
        self.assertEqual(frame[:3],b'\0'*3)
        self.assertEqual(frame[128*3:128*3+3],b'\xff'*3)
        self.assertEqual(p.write(0x2000002,1,1),(False,None))

    def test_byte_port_crops_controller_columns(self):
        p=m.PairedPage(width=120,access_width=1)
        frame=None
        for page in range(16):
            for value in (0xb0+page,0x10,0): p.write(0x2000000,1,value)
            for column in range(128):
                p.write(0x2000002,1,0xff)
                _,frame=p.write(0x2000002,1,0xff)
        self.assertEqual(len(frame),120*128*3)
        self.assertEqual(frame,b"\0"*len(frame))
        for value in (0xb0,0x10,0): p.write(0x2000000,1,value)
        p.write(0x2000002,1,0)
        _,frame=p.write(0x2000002,1,0)
        self.assertEqual(frame[:3],b"\xff"*3)
        self.assertEqual(frame[3:6],b"\0"*3)

    def test_separate_mono_port(self):
        p=m.MonoPage();frame=None
        for page in range(8):
            for value in (0xb0+page,0x10,0): p.write(0x2000000,1,value)
            for column in range(128):
                owned,frame=p.write(0x2200002,1,0)
                self.assertTrue(owned)
                if page!=7 or column!=127:self.assertIsNone(frame)
        self.assertEqual(frame,b"\xff"*(128*64*3))
        for value in (0xb0,0x10,0): p.write(0x2000000,1,value)
        _,frame=p.write(0x2200002,1,1)
        self.assertEqual(frame[:3],b"\0"*3)
        self.assertEqual(frame[128*3:128*3+3],b"\xff"*3)
        self.assertEqual(p.write(0x2000002,1,0),(False,None))

    def test_offset_mono_viewport(self):
        p=m.OffsetMonoPage();frame=None
        for page in range(14):
            for value in (0xb0+page,0x10,0): p.write(0x2000000,1,value)
            for col in range(160):
                _,candidate=p.write(0x2000002,1,0xff)
                if candidate is not None: frame=candidate
        self.assertEqual(frame,b"\0"*(128*64*3))
        for value in (0xb2,0x11,0):p.write(0x2000000,1,value)
        _,frame=p.write(0x2000002,1,0)
        self.assertEqual(frame[:3],b"\xff"*3)
        self.assertEqual(frame[3:6],b"\0"*3)

if __name__ == '__main__':unittest.main()
