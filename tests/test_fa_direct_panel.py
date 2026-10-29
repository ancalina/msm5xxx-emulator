import unittest
from msm5xxx_emulator.devices.display.fa_direct_panel import (
    FaDirectPanel, find_fa_direct_port, _ROW, _WINDOW, _CALLER, _HEIGHT,
    _CONTROL_INIT, _CONTROL_STANDBY, _CONTROL_VALUES)


class FaDirectTests(unittest.TestCase):
    base = 0x02000000

    def setup(self, panel):
        for c, v in FaDirectPanel._SETUP:
            panel.write(self.base+0x78,2,c)
            panel.write(self.base+0xFA,2,v)
        panel.write(self.base+0x78,2,0x22)

    def test_complete_clear_and_atomic_repaint(self):
        p=FaDirectPanel();self.setup(p)
        for i in range(20480):
            p.write(self.base+0xFA,2,0xF800)
            if i%127==0:
                p.flush();self.assertFalse(p.qualified)
        p.flush();self.assertTrue(p.qualified)
        self.assertEqual(p.frame,b'\xff\0\0'*20480)
        self.assertIsNone(p.snapshot()['enabled'])
        sequence=p.sequence;p.flush();self.assertEqual(p.sequence,sequence)
        self.setup(p);old=p.frame
        for i in range(20480):
            p.write(self.base+0xFA,2,0)
            if i%131==0:
                p.flush();self.assertEqual(p.frame,old)
        p.write(self.base+0x78,2,5)
        self.assertEqual(p.frame,bytes(20480*3));self.assertEqual(p.sequence,2)

    def test_partial_overflow_reset_and_foreign(self):
        for count in (20479,20481):
            p=FaDirectPanel();self.setup(p)
            for _ in range(count):p.write(self.base+0xFA,2,0)
            p.write(self.base+0x78,2,5)
            self.assertFalse(p.qualified);self.assertEqual(p.sequence,0)
        for size,val in ((1,0),(4,0),(2,-1),(2,65536),(2,True)):
            p=FaDirectPanel();self.setup(p);p.write(self.base+0xFA,size,val)
            self.assertIsNotNone(p.rejection)
        p=FaDirectPanel();self.setup(p)
        for _ in range(20480):p.write(self.base+0xFA,2,0xffff)
        p.flush();frame=p.frame
        for event in ((0x02800002,1,17),(self.base+0x7c,2,0x91),(self.base+0x7e,2,1)):
            p.write(*event);self.assertTrue(p.qualified);self.assertEqual(p.frame,frame)
        p.write(self.base+0xFA,2,0);self.assertFalse(p.qualified)
        with self.assertRaises(ValueError):FaDirectPanel(0x02800000)
        self.setup(p)
        for _ in range(20480):p.write(self.base+0xFA,2,0)
        p.flush();old=p.frame
        self.setup(p);p.write(self.base+0xFA,2,1)
        p.write(self.base+0x78,2,5)
        self.assertFalse(p.qualified);self.assertEqual(p.frame,old)
        p.write(self.base+0x78,1,5)
        self.assertEqual(p.rejection,'invalid-halfword-transfer')
        self.setup(p)
        for _ in range(20480):p.write(self.base+0xFA,2,0)
        p.flush();p.write(self.base+0x78,2,0)
        self.assertFalse(p.qualified)

    def test_setup_near_misses(self):
        for index in range(4):
            for mask in (1,0x100):
                p=FaDirectPanel()
                for n,(c,v) in enumerate(FaDirectPanel._SETUP):
                    p.write(self.base+0x78,2,c)
                    p.write(self.base+0xFA,2,v^mask if n==index else v)
                    if n==index:break
                self.assertFalse(p.qualified);self.assertIsNotNone(p.rejection)
        p=FaDirectPanel();p.write(self.base+0x78,2,0x17)
        self.assertIsNotNone(p.rejection)
        # Packed-register FA dialect is a different class.
        p=FaDirectPanel()
        for v in (0x0800,0x0977,0x0A00,0x0B9F):p.write(self.base+0x78,2,v)
        self.assertFalse(p.qualified)

    def completed(self):
        p=FaDirectPanel();self.setup(p)
        for _ in range(20480):p.write(self.base+0xfa,2,0xffff)
        p.flush()
        return p

    def test_known_control_holds_then_revalidates_atomically(self):
        p=self.completed();frame=p.frame
        for c,v in FaDirectPanel._CONTROL:
            for address,value in ((self.base+0x78,c),(self.base+0xfa,v)):
                p.write(address,2,value);p.flush()
                self.assertTrue(p.qualified);self.assertEqual(p.frame,frame)
                self.assertEqual(p.observation,'provisional-last-complete-image')
                p.write(0x02800002,1,255)
        self.setup(p)
        for i in range(20480):
            p.write(self.base+0xfa,2,0)
            if i%127==0:
                p.flush();self.assertEqual(p.frame,frame)
                self.assertEqual(p.observation,'provisional-last-complete-image')
        p.flush();self.assertEqual(p.frame,bytes(20480*3))
        self.assertEqual(p.sequence,2);self.assertTrue(p.qualified)
        self.assertEqual(p.observation,'complete-fa-direct-raster')
        self.assertIsNone(p.enabled)

    def test_control_near_miss_cold_and_partial_boundaries(self):
        events=[(a,v) for c,value in FaDirectPanel._CONTROL
                for a,v in ((self.base+0x78,c),(self.base+0xfa,value))]
        for bad in range(len(events)):
            p=self.completed();frame=p.frame
            for n,(address,value) in enumerate(events):
                p.write(address,2,value^0x80 if n==bad else value)
                if n==bad:
                    self.assertFalse(p.qualified)
                    self.assertIsNotNone(p.rejection)
                    self.assertEqual(p.frame,frame);break
        p=FaDirectPanel()
        for address,value in events:p.write(address,2,value)
        self.assertFalse(p.qualified);self.assertEqual(p.frame,b'')
        p=self.completed();self.setup(p);p.write(self.base+0xfa,2,0)
        p.write(self.base+0x78,2,7)
        self.assertFalse(p.qualified)
        self.assertEqual(p.rejection,'interrupted-partial-raster')
        p=self.completed();p.write(self.base+0x78,2,7)
        p.write(self.base+0xfa,1,4)
        self.assertFalse(p.qualified)

    def test_static_negative_tail_wrap_rejected(self):
        at=0x800
        image=bytearray(0x2000)
        helper=at-0x750;caller=at-0x2d8
        image[at:at+len(_ROW)]=_ROW
        image[helper:helper+len(_WINDOW)]=_WINDOW
        image[caller:caller+len(_CALLER)]=_CALLER
        image[at-0xbc:at-0xbc+len(_HEIGHT)]=_HEIGHT
        # Negative prefix slices must never bind unrelated image-tail bytes.
        image[helper-0x104:helper-0x100]=bytes.fromhex('30100000')
        image[at-0xb14:at-0xb14+len(_CONTROL_INIT)]=_CONTROL_INIT
        image[at-0x7dc:at-0x7dc+len(_CONTROL_STANDBY)]=_CONTROL_STANDBY
        image[at-0x860:at-0x860+len(_CONTROL_VALUES)]=_CONTROL_VALUES
        self.assertIsNone(find_fa_direct_port(bytes(image))[0])

    def test_static_source_binding_relocation_and_mutation(self):
        def fixture(at):
            image=bytearray(at+len(_ROW))
            helper=at-0x750;caller=at-0x2d8
            image[at:at+len(_ROW)]=_ROW
            image[helper:helper+len(_WINDOW)]=_WINDOW
            image[caller:caller+len(_CALLER)]=_CALLER
            image[at-0xbc:at-0xbc+len(_HEIGHT)]=_HEIGHT
            image[helper-0x104:helper-0x100]=bytes.fromhex('30100000')
            image[at-0xb14:at-0xb14+len(_CONTROL_INIT)]=_CONTROL_INIT
            image[at-0x7dc:at-0x7dc+len(_CONTROL_STANDBY)]=_CONTROL_STANDBY
            image[at-0x860:at-0x860+len(_CONTROL_VALUES)]=_CONTROL_VALUES
            return image
        for at in (0xc00,0x1800):
            image=fixture(at)
            self.assertEqual(find_fa_direct_port(bytes(image))[0],self.base)
            for offset in (at,at+20,at+28,at+60,at+76,at-0xbc+8,
                           at-0x750+48,at-0x750+128,at-0x750+160,
                           at-0x2d8+4,at-0x2d8+16,at-0x2d8+24,at-0x854,at-0xb14,at-0xb14+8,
                           at-0x7dc,at-0x7dc+8,at-0x860):
                bad=image[:];bad[offset]^=1
                self.assertIsNone(find_fa_direct_port(bytes(bad))[0],hex(offset))
            self.assertIsNone(find_fa_direct_port(b'X'+bytes(image))[0])
        image=fixture(0xc00)
        self.assertIsNone(find_fa_direct_port(bytes(image)+bytes(image))[0])
        self.assertIsNone(find_fa_direct_port(_ROW)[0])

if __name__=='__main__':unittest.main()
