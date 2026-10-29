from types import SimpleNamespace
import unittest
from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin

class CursorClassTests(unittest.TestCase):
    def test_explicit_geometry_remains_authoritative(self):
        import threading
        from unittest.mock import Mock
        for source, width, height, owns in (("auto-default",96,64,True),
                                            ("runtime:cursor-bgr444",192,160,True),
                                            ("override",96,64,False),
                                            ("external-config",96,64,False),
                                            ("framebuffer-descriptor",96,64,False),
                                            ("override",128,160,True)):
            with self.subTest(source=source,width=width,height=height):
                d=DisplayControllerMixin();d.config=SimpleNamespace(width=width,height=height,display_geometry_source=source)
                d._display_lock=threading.Lock();d.display_frame=bytes(width*height*3)
                state=dict(qualified=True,width=128,height=160,frame=b'\xff'*(128*160*3),rejection=None)
                d._lcd_packed2_panel=Mock();d._lcd_packed2_panel.snapshot.return_value=state
                result=d.display_snapshot()
                self.assertEqual(result,(128,160,state["frame"]) if owns else (width,height,d.display_frame))
                telemetry=d.parallel_candidates_snapshot()["packed2"]
                self.assertEqual(telemetry["display_owner"],owns)
                self.assertEqual((d.config.width,d.config.height),(width,height))

    def test_cpu_only_observer_needs_no_display_lock(self):
        state = DisplayControllerMixin().parallel_candidates_snapshot()
        self.assertEqual(set(state), {"packed_cursor12", "packed2", "split18", "split565", "fa_direct"})
        self.assertTrue(all(not value["qualified"] for value in state.values()))
        self.assertTrue(all(value["static_reason"] == "not-initialized" for value in state.values()))

    def fixture(self):
        d=DisplayControllerMixin();d._lcd_protocol='parallel-2';d._lcd_command=0
        d.config=SimpleNamespace(width=128,height=160)
        d._lcd_x=[0,127];d._lcd_y=[0,159];d._lcd_window_axis_mask=15
        d._lcd_cursor=[0,0];d._lcd_gram_cursor=[0,0];d._lcd_gram_addressed=False
        return d
    def feed(self,d,c,v,a=0x02000002,size=2):
        d._lcd_command=c;return d._lcd_packed_cursor_data(a,size,v)
    def setup(self,d):
        for c,v in [(1,0x113),(2,0x700),(5,0x1030)]:self.assertFalse(self.feed(d,c,v))
    def test_closed_class_and_fallback_boundaries(self):
        d=self.fixture()
        self.assertFalse(self.feed(d,0x21,0x7360));self.setup(d)
        self.assertTrue(self.feed(d,0x21,0x7360));self.assertEqual(d._lcd_gram_cursor,[96,115])
        self.assertTrue(self.feed(d,0x21,0x0060));self.assertEqual(d._lcd_gram_cursor,[96,0])
        before=d._lcd_gram_cursor[:]
        for value in (-65536,65536,0xa000,0x0080):
            self.assertFalse(self.feed(d,0x21,value));self.assertEqual(d._lcd_gram_cursor,before)
        self.assertFalse(self.feed(d,0,1));self.assertFalse(self.feed(d,0x21,0x7360))
        for mutate in ('wrong-bus','wrong-mode','wrong-window','incomplete-window','wrong-protocol','wrong-order'):
            d=self.fixture();self.setup(d)
            if mutate=='wrong-bus':
                before=d.direct_cursor_snapshot()
                self.assertFalse(self.feed(d,0x21,0x7360,0x02800002))
                self.assertEqual(d.direct_cursor_snapshot(),before)
                self.assertTrue(self.feed(d,0x21,0x7360));continue
            if mutate=='wrong-mode':self.feed(d,5,0x0230)
            if mutate=='wrong-window':d._lcd_x=[0,126]
            if mutate=='incomplete-window':d._lcd_window_axis_mask=3
            if mutate=='wrong-protocol':d._lcd_protocol='selector-4'
            if mutate=='wrong-order':self.feed(d,1,0x113);self.feed(d,5,0x1030);self.feed(d,2,0x700)
            self.assertFalse(self.feed(d,0x21,0x7360),mutate)
        for height, end, accepted in ((160,159,True),(160,175,True),(176,175,True),(176,159,False)):
            d=self.fixture();d.config.height=height;d._lcd_y=[0,end];self.setup(d)
            self.assertEqual(self.feed(d,0x21,0x7360),accepted)
        self.assertEqual(self.fixture().direct_cursor_snapshot()['accepted'],0)
if __name__=='__main__':unittest.main()
