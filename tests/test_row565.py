import unittest

from msm5xxx_emulator.devices.display import row565 as m
from msm5xxx_emulator.detection.devices.display import row565_writer as evidence

class Tests(unittest.TestCase):
    def test_source_rejects_unrelated(self):
        self.assertFalse(evidence.has_row565_writer(bytes(4096)))

    def test_full_and_partial(self):
        p=m.Row565();frame=None
        for y in range(160):
            for address,v in ((0x2000000,3),(0x2000002,0),(0x2000000,5),
                              (0x2000002,y),(0x2000000,11)):
                p.write(address,1,v)
            for x in range(128):
                p.write(0x2000002,1,255)
                _,frame=p.write(0x2000002,1,255)
                if y!=159 or x!=127:self.assertIsNone(frame)
        self.assertEqual(frame,b'\xff'*(128*160*3))
        for address,v in ((0x2000000,3),(0x2000002,1),(0x2000000,5),
                          (0x2000002,2),(0x2000000,11),(0x2000002,0xf8)):
            self.assertIsNone(p.write(address,1,v)[1])
        _,frame=p.write(0x2000002,1,0)
        at=(2*128+1)*3
        self.assertEqual(frame[at:at+3],b'\xff\x00\x00')
        self.assertEqual(frame[at+3:at+6],b'\xff'*3)

    def test_sequence_and_interrupted_pixels(self):
        p=m.Row565()
        for address,value in ((0x2000000,5),(0x2000002,0),(0x2000000,3),
                              (0x2000002,0),(0x2000000,11),(0x2000002,255)):
            self.assertIsNone(p.write(address,1,value)[1])
        self.assertEqual(p.seen_count,0)
        self.assertEqual(p.write(0x2000002,2,0),(False,None))

if __name__=='__main__':unittest.main()
