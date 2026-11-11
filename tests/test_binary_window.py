import unittest

from msm5xxx_emulator.devices.display import binary_window as m
from msm5xxx_emulator.detection.devices.display import binary_window_writer as evidence

C, D = 0x02000004, 0x02000006

class Tests(unittest.TestCase):
    def test_source_rejects_unrelated(self):
        self.assertFalse(evidence.has_binary_window_writer(bytes(4096)))

    def test_full_then_partial(self):
        p=m.BinaryWindow()
        for a,v in ((C,0x75),(D,0),(D,142),(C,0x15),(D,0),(D,119),(C,0x5c)):
            self.assertIsNone(p.write(a,1,v)[1])
        for i in range(120*143):
            _,frame=p.write(D,1,255)
            if i!=120*143-1:self.assertIsNone(frame)
        self.assertEqual(frame,b'\xff'*(120*143*3))
        for a,v in ((C,0x75),(D,1),(C,0x15),(D,2),(C,0x5c)):
            self.assertIsNone(p.write(a,1,v)[1])
        _,frame=p.write(D,1,0)
        off=(120+2)*3
        self.assertEqual(frame[off:off+3],b'\0'*3)
        self.assertEqual(frame[off+3:off+6],b'\xff'*3)

    def test_unproven_color_is_rejected(self):
        p=m.BinaryWindow()
        for a,v in ((C,0x75),(D,0),(C,0x15),(D,0),(C,0x5c)):
            p.write(a,1,v)
        self.assertEqual(p.write(D,1,7),(True,None))
        self.assertTrue(p.rejected)
        self.assertEqual(p.write(D,1,0),(False,None))

if __name__=='__main__':unittest.main()
