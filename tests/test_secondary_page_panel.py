"""Descriptor-bound secondary scanout and lossless candidate rejection."""
from collections import Counter
import unittest
from threading import Event, Lock, Thread
from types import SimpleNamespace

from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin
from msm5xxx_emulator.devices.display.page_panel import PagePanel


class SecondaryPagePanelTests(unittest.TestCase):
    def test_primary_power_requires_qualified_complete_transaction_and_retains_ram(self):
        controller, fallback = self.controller()
        controller._lcd_primary_page_port = 0x02800000
        controller._lcd_primary_power_commands = []
        controller._lcd_primary_power_argument = False
        controller._lcd_primary_enabled = None
        controller._lcd_page_qualified = True
        controller._display_lock = Lock()
        controller.config = SimpleNamespace(width=1, height=1)
        controller.display_frame = b'\x55\xaa\xff'
        controller.framebuffer = bytearray(controller.display_frame)
        panel = controller._lcd_secondary_panel
        def commands(values):
            for value in values:
                controller._lcd_write(None, 0, 0x02800000, 2, value, None)
        off = [0xAE, 0x2D, 0x2C, 0x28]
        on = [0x2C, 0x2E, 0x2F, 0xAF]
        commands(off)  # No committed secondary class: native fallback.
        self.assertIsNone(controller._lcd_primary_enabled)
        panel.rejection = None
        panel.committed = True
        commands([0x81] + off)  # AE is a contrast argument, not power.
        self.assertIsNone(controller._lcd_primary_enabled)
        commands([0x81])
        controller._lcd_write(None, 0, panel.port, 2, 0xAF, None)
        commands(off)  # Other controller writes cannot consume that argument.
        self.assertIsNone(controller._lcd_primary_enabled)
        commands(off[:2])
        controller._lcd_write(None, 0, 0x02800004, 2, 0, None)
        commands(off[2:])
        self.assertIsNone(controller._lcd_primary_enabled)
        commands(off)
        self.assertEqual(controller.display_snapshot(), (1, 1, bytes(3)))
        self.assertEqual(controller.framebuffer, b'\x55\xaa\xff')
        self.assertEqual(controller.display_frame, b'\x55\xaa\xff')
        commands(on)
        self.assertEqual(controller.display_snapshot()[2], controller.display_frame)
        commands(off)
        panel.rejection = 'unsupported command'
        self.assertEqual(controller.display_snapshot()[2], controller.display_frame)
        self.assertTrue(fallback)  # Power observation never consumes primary writes.

    def test_helper_bound_paired_state_preserves_frame_and_rejects_arguments(self):
        controller, fallback = self.controller()
        controller._lcd_paired_state_ports = (0x02800000, 0x02000000)
        controller._lcd_paired_state_candidate = None
        controller._lcd_paired_state_arguments = set()
        controller._lcd_paired_state_enabled = None
        controller._lcd_secondary_panel = None
        controller._lcd_page_qualified = True
        controller._lcd_frame_protocol = 'page-2bpp'
        controller.config = SimpleNamespace(width=1, height=1)
        controller._display_lock = Lock()
        controller.display_frame = b'\x55\xaa\xff'
        def write(port, value, size=2):
            controller._lcd_write(None, 0, port, size, value, None)
        main, sub = controller._lcd_paired_state_ports
        write(main, 0xAE)
        self.assertIsNone(controller._lcd_paired_state_enabled)
        write(sub + 4, 0)
        write(sub, 0xAE)
        self.assertIsNone(controller._lcd_paired_state_enabled)
        write(main, 0x81)
        write(sub, 0xAE)
        write(main, 0xAE)  # A command-port contrast argument, not OFF.
        self.assertIsNone(controller._lcd_paired_state_enabled)
        for value in (0xAE, 0x2D, 0x2C, 0x28):
            write(main, value)
        self.assertIsNone(controller._lcd_paired_state_enabled)
        write(main, 0xAE, 1)
        write(sub, 0xAE)
        self.assertIsNone(controller._lcd_paired_state_enabled)
        write(main, 0xE3)
        write(main, 0xAE)
        write(sub, 0xAE)
        self.assertEqual(controller.display_snapshot()[2], bytes(3))
        self.assertEqual(controller.display_frame, b'\x55\xaa\xff')
        write(main, 0xAF)
        self.assertEqual(controller.display_snapshot()[2], bytes(3))
        write(sub, 0xAF)
        self.assertEqual(controller.display_snapshot()[2], controller.display_frame)
        write(main, 0xAE)
        write(sub, 0xAE)
        controller._lcd_frame_protocol = 'direct'
        self.assertEqual(controller.display_snapshot()[2], controller.display_frame)
        self.assertEqual(len(fallback), controller.lcd_writes)

    def test_mixed_power_pairs_preserve_pixels_and_reject_interrupted_commands(self):
        controller, fallback = self.controller()
        controller._lcd_mixed_primary_power_port = port = 0x02800000
        controller._lcd_primary_enabled = None
        controller.config = SimpleNamespace(width=1, height=1)
        controller.display_frame = b'\x55\xaa\xff'
        controller.framebuffer = bytearray(controller.display_frame)
        panel = controller._lcd_secondary_panel
        panel.committed = True
        def write(value, address=port, size=2):
            controller._lcd_write(None, 0, address, size, value, None)
        write(0xAE)
        self.assertIsNone(controller._lcd_primary_enabled)
        write(0x95, port + 4)  # Data must never complete a power pair.
        write(0x95)
        self.assertIsNone(controller._lcd_primary_enabled)
        write(0xAE, size=1)
        write(0x95)
        self.assertIsNone(controller._lcd_primary_enabled)
        write(0xAE)
        write(0x95)
        self.assertEqual(controller.display_snapshot()[2], bytes(3))
        self.assertEqual(controller.framebuffer, b'\x55\xaa\xff')
        controller.display_frame = b'\x11\x22\x33'  # Guest rendering continues while off.
        write(0x94)
        self.assertEqual(controller.display_snapshot()[2], bytes(3))
        write(0xAF)
        self.assertEqual(controller.display_snapshot()[2], controller.display_frame)
        panel.rejection = 'unsupported command'
        write(0xAE)
        write(0x95)
        self.assertTrue(controller._lcd_primary_enabled)
        self.assertEqual(len(fallback), controller.lcd_writes)

    def controller(self):
        controller = DisplayControllerMixin()
        controller._display_lock = Lock()
        controller._lcd_secondary_panel = PagePanel(0x02000000)
        controller._audio_transport_owns_write = lambda *args: False
        controller.lcd_writes = 0
        controller.lcd_port_writes = Counter()
        fallback = []
        controller._lcd_write_fallback = lambda uc, access, address, size, value, data: fallback.append((address, size, value))
        return controller, fallback

    def test_secondary_snapshot_waits_for_complete_write(self):
        controller, _ = self.controller()
        panel = controller._lcd_secondary_panel
        panel.committed = True
        entered, release, reading, done = (Event() for _ in range(4))
        frame = bytes([255]) * len(panel.frame)
        snapshots = []
        def write(*args):
            panel.enabled = True
            entered.set()
            release.wait(2)
            panel.frame = frame
            return True
        panel.write = write
        def read():
            reading.set()
            snapshots.append(controller.secondary_display_snapshot())
            done.set()
        writer = Thread(target=controller._lcd_write,
                        args=(None, 0, panel.port, 2, 0xAF, None))
        reader = Thread(target=read)
        writer.start()
        try:
            self.assertTrue(entered.wait(1))
            reader.start()
            self.assertTrue(reading.wait(1))
            self.assertFalse(done.wait(.05))
        finally:
            release.set()
            writer.join(2)
            if reader.ident is not None:
                reader.join(2)
        self.assertEqual(snapshots[0]['frame'], frame)
        self.assertTrue(snapshots[0]['enabled'])

    def test_qualified_panel_keeps_primary_writes_and_power_independent(self):
        controller, fallback = self.controller()
        panel = controller._lcd_secondary_panel
        def write(address, value):
            controller._lcd_write(None, 0, address, 2, value, None)
        write(panel.port, 0xAE)
        for page in range(3):
            for command in (0xB0 + page, 0x12, 0):
                write(panel.port, command)
            for column in range(96):
                write(panel.port + 4, 1 if column == 0 else 0)
        panel.flush()
        write(0x02800000, 0xAF)
        snapshot = controller.secondary_display_snapshot()
        self.assertTrue(snapshot['qualified'])
        self.assertEqual(snapshot['column_offset'], 32)
        self.assertFalse(snapshot['enabled'])
        self.assertEqual(snapshot['frame'][:6], b'\xff\xff\xff\0\0\0')
        self.assertEqual(fallback, [(0x02800000, 2, 0xAF)])
        write(panel.port, 0xAF)
        self.assertTrue(controller.secondary_display_snapshot()['enabled'])
        write(panel.port, 0xFF)  # Unknown command must never pollute primary.
        self.assertFalse(controller.secondary_display_snapshot()['qualified'])
        write(panel.port + 4, 0x1234)
        self.assertEqual(fallback, [(0x02800000, 2, 0xAF)])
        self.assertEqual(panel.pending, [])

    def test_rejected_candidate_replays_interleaved_writes_exactly_once(self):
        controller, fallback = self.controller()
        writes = [(0x02000000, 2, 0xAE), (0x02800000, 1, 0xB0),
                  (0x02000004, 2, 0x1234), (0x02800004, 1, 7)]
        for address, size, value in writes:
            controller._lcd_write(None, 0, address, size, value, None)
        self.assertEqual(fallback, writes)
        self.assertEqual(controller.lcd_writes, len(writes))
        self.assertFalse(controller.secondary_display_snapshot()['qualified'])
        self.assertEqual(controller._lcd_secondary_panel.pending, [])
        self.assertEqual(controller._lcd_secondary_panel.rejection,
                         'interleaved ports before page qualification')

    def test_rejection_at_second_row_boundary_does_not_commit_ownership(self):
        controller, fallback = self.controller()
        writes = []
        for page in range(2):
            writes.extend((0x02000000, 2, value)
                          for value in (0xB0 + page, 0x12, 0))
            writes.extend([(0x02000004, 2, 0)] * 96)
        writes.extend([(0x02000000, 2, 0xFF), (0x02000000, 2, 0xAF)])
        for address, size, value in writes:
            controller._lcd_write(None, 0, address, size, value, None)
        self.assertEqual(fallback, writes)
        self.assertFalse(controller._lcd_secondary_panel.committed)
        self.assertFalse(controller.secondary_display_snapshot()['qualified'])


if __name__ == '__main__':
    unittest.main()
