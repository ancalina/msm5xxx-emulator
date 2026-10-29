import unittest
from msm5xxx_emulator.devices.display.arm_page_panel import ArmPagePanel


class ArmPagePanelTests(unittest.TestCase):
    def test_descending_pages_and_rejection(self):
        panel = ArmPagePanel(0x2800000)
        command, data = panel.port, panel.port + 2
        for value in (0xe2, 0xae, 0xa0, 0xc0, 0, 0x10, 0, 0x81, 0x20, 0xaf):
            self.assertTrue(panel.write(command, 1, value))
        for page in range(7, -1, -1):
            for value in (0xb0 + page, 0x10, 0):
                self.assertTrue(panel.write(command, 1, value))
            for x in range(96):
                self.assertTrue(panel.write(data, 1, 1 if x == 0 else 0))
        self.assertTrue(panel.write(command, 1, 0xb7))
        self.assertEqual(panel.bias, 0)
        self.assertTrue(panel.enabled)
        panel.flush()
        self.assertEqual(panel.frame[(7 * 96) * 3:(7 * 96) * 3 + 3], b'\x00' * 3)
        self.assertEqual(panel.frame[(7 * 96 + 1) * 3:(7 * 96 + 1) * 3 + 3], b'\xff' * 3)
        self.assertFalse(panel.write(data, 2, 1))
        self.assertEqual(panel.rejection, 'non-byte page transfer')

    def test_requires_page_column_and_foreign_port_rejected(self):
        panel = ArmPagePanel(0x2800000)
        self.assertFalse(panel.write(panel.port + 2, 1, 0))
        self.assertEqual(panel.rejection, 'data without bounded page/column')
        panel = ArmPagePanel(0x2800000)
        self.assertFalse(panel.write(panel.port + 4, 1, 0))
        self.assertEqual(panel.rejection, 'unbound port')
        panel = ArmPagePanel(0x2800000)
        for value in (0xb7, 0x10, 0):
            self.assertTrue(panel.write(panel.port, 1, value))
        for _ in range(104):
            self.assertTrue(panel.write(panel.port + 2, 1, 0))
        self.assertFalse(panel.write(panel.port + 2, 1, 0))
        panel = ArmPagePanel(0x2800000)
        self.assertFalse(panel.write(panel.port + 2, 1, 256))


class ArmPageRoutingTests(unittest.TestCase):
    def make_controller(self, loaded=None):
        from types import SimpleNamespace
        from test_secondary_page_panel import SecondaryPagePanelTests
        from test_secondary_arm_page import fixture
        from msm5xxx_emulator.detection.secondary_arm_page import find_secondary_arm_page
        image = bytes(fixture())
        profile, _ = find_secondary_arm_page(image)
        controller, fallback = SecondaryPagePanelTests().controller()
        controller.image = image
        controller.config = SimpleNamespace(ram_base=0x1000000, ram_size=0x800000)
        controller._lcd_page_loaded_image = image if loaded is None else loaded
        controller._lcd_secondary_panel = ArmPagePanel(profile['command_port'], profile)
        controller._lcd_source_window_write = lambda *args: False
        return controller, fallback

    def test_interleaved_main_and_secondary_rejection_fallback(self):
        controller, fallback = self.make_controller()
        panel = controller._lcd_secondary_panel
        def send(address, value, size=1):
            controller._lcd_write(None, 0, address, size, value, None)
        send(panel.port, 0, 2)  # Existing halfword setup stays on native path.
        self.assertEqual(fallback, [(panel.port, 2, 0)])
        panel = controller._lcd_secondary_panel
        send(panel.port, 0xe2)
        send(0x02000000, 0xaf)  # Main-panel interleaving is not a conflict.
        for page in range(7, -1, -1):
            for value in (0xb0 + page, 0x10, 0):
                send(panel.port, value)
            for _ in range(96):
                send(panel.port + 2, 0x55)
        send(panel.port, 0xb7)
        self.assertTrue(panel.committed)
        self.assertIsNone(panel.rejection)
        self.assertIn((0x02000000, 1, 0xaf), fallback)
        send(panel.port + 2, 0, 2)
        self.assertFalse(panel.committed)
        self.assertIn((panel.port + 2, 2, 0), fallback)

    def test_bus_reinitialization_requires_fresh_full_page_proof(self):
        controller, fallback = self.make_controller()
        panel = controller._lcd_secondary_panel
        def send(address, value, size=1):
            controller._lcd_write(None, 0, address, size, value, None)
        def pages():
            send(panel.port, 0xe2)
            for page in range(7, -1, -1):
                for value in (0xb0 + page, 0x10, 0):
                    send(panel.port, value)
                for _ in range(96):
                    send(panel.port + 2, 0x55)
            send(panel.port, 0xb7)
        pages()
        self.assertTrue(panel.committed)
        send(panel.port, 0, 2)
        self.assertIn((panel.port, 2, 0), fallback)
        new = controller._lcd_secondary_panel
        self.assertIsNot(new, panel)
        self.assertFalse(new.committed)
        panel = new
        pages()
        self.assertTrue(panel.committed)
        self.assertIsNone(panel.rejection)

    def test_changed_loaded_source_keeps_native(self):
        from test_secondary_arm_page import fixture
        loaded = fixture()
        loaded[0x434] ^= 1
        controller, fallback = self.make_controller(bytes(loaded))
        panel = controller._lcd_secondary_panel
        controller._lcd_write(None, 0, panel.port, 1, 0xe2, None)
        self.assertEqual(panel.rejection, 'source-or-ram-owner-unverified')
        self.assertFalse(panel.started)
        self.assertEqual(fallback, [(panel.port, 1, 0xe2)])
