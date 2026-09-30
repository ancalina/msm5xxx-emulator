import unittest
from msm5xxx_emulator.devices.display.packed12_panel import Packed12Panel


class Packed12PanelTests(unittest.TestCase):
    def test_complete_raster_and_rejection(self):
        panel = Packed12Panel(0x02000000)
        def command(c, args=()):
            panel.write(panel.port, 1, c)
            for v in args:
                panel.write(panel.port + 2, 1, v)
        command(0xBC, (2, 0, 2))
        command(0x15, (6, 6))
        command(0x75, (0, 0))
        command(0x5C)
        panel.write(panel.port + 2, 1, 0xF0)
        panel.write(panel.port + 2, 1, 0x00)
        self.assertFalse(panel.qualified)
        panel.write(panel.port + 2, 1, 0xF0)
        self.assertEqual(panel.frame, bytes((255, 0, 0, 0, 255, 0)))
        panel.write(panel.port + 4, 2, 0xFFFF)
        panel.write(panel.port + 2, 1, 0xFF)
        self.assertEqual((panel.sequence, panel.trailing_bytes), (1, 1))
        command(0x15, (6,))
        command(0x5C)
        self.assertEqual(panel.rejection, 'incomplete-register')
        self.assertFalse(panel.qualified)

    def test_same_size_shifted_window_rejects(self):
        panel = Packed12Panel(0x02000000)
        for c, args in ((0xBC, (2, 0, 2)), (0x15, (6, 6)),
                        (0x75, (0, 0)), (0x5C, (0, 0, 0)),
                        (0x15, (7, 7)), (0x5C, ())):
            panel.write(panel.port, 1, c)
            for v in args:
                panel.write(panel.port + 2, 1, v)
        self.assertEqual(panel.rejection, 'unsupported-window-change')
        self.assertFalse(panel.qualified)

    def test_interrupted_raster_rejects_stale_frame(self):
        panel = Packed12Panel(0x02000000)
        for c, args in ((0xBC, (2, 0, 2)), (0x15, (6, 6)),
                        (0x75, (0, 0)), (0x5C, (0, 0, 0)),
                        (0x5C, (0,)), (0xAF, ())):
            panel.write(panel.port, 1, c)
            for v in args:
                panel.write(panel.port + 2, 1, v)
        self.assertEqual(panel.rejection, 'incomplete-raster')
        self.assertFalse(panel.qualified)

    def test_unknown_command_and_changed_setup_reject(self):
        for register, args in ((0xFF, ()), (0x81, (29, 4))):
            panel = Packed12Panel(0x02000000)
            panel.qualified = True
            panel.write(panel.port, 1, register)
            for value in args:
                panel.write(panel.port + 2, 1, value)
            self.assertFalse(panel.qualified)
            self.assertIsNotNone(panel.rejection)
