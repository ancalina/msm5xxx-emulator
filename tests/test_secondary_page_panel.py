"""Descriptor-bound secondary scanout and lossless candidate rejection."""
from corpus import snippet
from collections import Counter
import struct
import unittest
from threading import Event, Lock, Thread
from types import SimpleNamespace

from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin
from msm5xxx_emulator.devices.display.page_panel import PagePanel
from msm5xxx_emulator.detection.display import find_byte_main_page_secondary


class SecondaryPagePanelTests(unittest.TestCase):
    def test_color_byte_page_contract_requires_shared_object_and_unique_links(self):
        # Synthetic instructions and relocated links, not a firmware fixture.
        image = bytearray(0x1000)
        descriptor = 0x01002000
        def put(address, hexbytes):
            value = bytes.fromhex(hexbytes)
            image[address:address + len(value)] = value
        def bl(address, target):
            delta = target - address - 4
            struct.pack_into('<HH', image, address,
                             0xf000 | ((delta >> 12) & 0x7ff),
                             0xf800 | ((delta >> 1) & 0x7ff))
        def literal(address, register, slot, value=descriptor):
            delta = slot - ((address + 4) & ~3)
            struct.pack_into('<H', image, address, 0x4800 | register << 8 | delta // 4)
            struct.pack_into('<I', image, slot, value)
        command, data, window = 0x40, 0x50, 0x60
        selector, setup, caller, byte, color = 0x100, 0x200, 0x300, 0x400, 0x700
        put(command, '0121490608807047')
        put(data, '0121490688807047')
        put(window, snippet("test_secondary_page_panel", "window_writer").hex())
        put(selector, '80b5002817d10527ff0500290e480bd02c21398000000000512038800b480000000080bc08bc184750213980000000002d203880f5e7002901d0af2000e0ae2000000000ede7')
        bl(selector + 0x40, command)
        put(0x380, '397d002000000000397d012000000000')
        bl(0x384, selector)
        bl(0x38c, selector)
        put(setup, '80b5ae2000000000402000000000a02000000000102000000000002000000000a62000000000a32000000000c820000000002c20000000007d27ff00381c000000002e2000000000381c000000002f2000000000381c0000000024200000000081200000000023200000000006490320886200224a625f200862ca610000000080bc08bc1847')
        for offset in (4, 10, 16, 22, 28, 34, 40, 46, 52, 68, 80, 92, 98, 104):
            bl(setup + offset, command)
        literal(setup + 0x6c, 1, 0x2a0)
        bl(setup + 0x7c, byte)
        put(caller, '064a042010805160012000000000')
        literal(caller, 2, 0x320)
        bl(caller + 10, setup)
        put(byte, 'f0b5004c004fe0690028')
        literal(byte + 2, 4, 0x600)
        put(byte + 0x18, '206a5f2806dd')
        put(byte + 0x28, '5f202062606a0028')
        put(byte + 0x40, 'a06a032806dd')
        put(byte + 0x50, '0320a062')
        for offset in (0x70, 0x7a, 0x84):
            bl(byte + offset, command)
        put(byte + 0x88, 'e8690204120c60247c4307e068682018805c0000000001321204120c286a824201dc602af2db01373f043f0ca86a874201dc042fd0db')
        bl(byte + 0x9a, data)
        put(color - 0xc0, snippet("test_secondary_page_panel", "color_clamp").hex())
        put(color, '004c3a1ca068e1686369000000007820a168784340184000e11d273140180523db057821491b490009e02a1c03e0068802309e80')
        literal(color, 4, 0x800)
        bl(color + 10, window)
        expected = (0x02000000, 'temporary-color-page-consumer-awaiting-runtime')
        self.assertEqual(find_byte_main_page_secondary(bytes(image)), expected)
        for label, address, replacement in (
                ('shared-object', 0x800, struct.pack('<I', descriptor + 4)),
                ('page-bound', byte + 0x42, bytes.fromhex('0728')),
                ('setup-consumer', setup + 0x7c, bytes(4)),
                ('selector-leaf', selector + 0x40, bytes(4))):
            with self.subTest(label=label):
                broken = image.copy()
                broken[address:address + len(replacement)] = replacement
                self.assertEqual(find_byte_main_page_secondary(bytes(broken)),
                                 (None, 'temporary-color-page-contract-rejected'))
        duplicate = image.copy()
        duplicate[0x900:0x900 + 14] = image[caller:caller + 14]
        # Relocated duplicate valid caller and its object link is ambiguous.
        delta = setup - 0x90a - 4
        struct.pack_into('<HH', duplicate, 0x90a, 0xf000 | ((delta >> 12) & 0x7ff),
                         0xf800 | ((delta >> 1) & 0x7ff))
        struct.pack_into('<H', duplicate, 0x900, 0x4a07)
        struct.pack_into('<I', duplicate, 0x920, descriptor)
        self.assertEqual(find_byte_main_page_secondary(bytes(duplicate)),
                         (None, 'temporary-color-page-contract-rejected'))
        self.assertEqual(find_byte_main_page_secondary(bytes(0x100)),
                         (None, 'mixed-descriptor-missing-or-ambiguous'))
        # Existing descriptor admission/rejection takes precedence over this class.
        put(0xa00, 'b0b5141c1f1c0028004d0fd17820288395206883122028844b221202081ce962ff21'
                   '00000000ac60ef60b0bd6020a8834020e8830820288669632c616f61')
        self.assertEqual(find_byte_main_page_secondary(bytes(image)),
                         (None, 'mixed-initializer-clear-unproven'))

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
        controller._lcd_observe_shifted_orientation = lambda *args: None
        controller._lcd_packed_window_observe = lambda *args: None
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
