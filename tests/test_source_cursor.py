import collections
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.devices.display.controller import DisplayControllerMixin
from msm5xxx_emulator.devices.display.source_cursor import (
    SourcePackedCursor,
)


from msm5xxx_emulator.detection.devices.display.source_cursor_writer import find_source_packed_cursor

class SourceCursorTests(unittest.TestCase):
    def test_unrelated_source_is_rejected(self):
        self.assertIsNone(find_source_packed_cursor(bytes(4096)))

    def test_mode_and_viewport_gate_packed_coordinates(self):
        panel = SourcePackedCursor()
        x_window, y_window, geometry = [0, 127], [0, 159], (128, 160)
        self.assertIsNone(panel.coordinate(0x21, 0x0301, x_window, y_window, geometry))
        for command, value in ((1, 0x090c), (2, 0x0200), (3, 0x1030)):
            self.assertIsNone(panel.coordinate(command, value, x_window, y_window, geometry))
        self.assertEqual(panel.coordinate(0x21, 0x0301, x_window, y_window, geometry), (1, 3))
        self.assertEqual(panel.coordinate(0x21, 0, x_window, y_window, geometry), (0, 0))
        self.assertIsNone(panel.coordinate(0x21, 0xa001, x_window, y_window, geometry))
        self.assertIsNone(panel.coordinate(0x21, 0x0301, [0, 126], y_window, geometry))
        panel.coordinate(0, 0, x_window, y_window, geometry)
        self.assertIsNone(panel.coordinate(0x21, 0x0301, x_window, y_window, geometry))

    def test_incorrect_controller_setup_is_not_admitted(self):
        panel = SourcePackedCursor()
        for command, value in ((1, 0x090c), (2, 0x0201), (3, 0x1030)):
            panel.coordinate(command, value, [0, 127], [0, 159], (128, 160))
        self.assertIsNone(panel.coordinate(0x21, 0x0301, [0, 127], [0, 159], (128, 160)))

    def test_mode_write_is_observed_before_other_routes(self):
        class Controller(DisplayControllerMixin):
            def _audio_transport_owns_write(self, uc, address, size):
                return False

            def _lcd_write_slow(self, *args):
                pass

            def _lcd_bind_fast_write(self, address, size):
                pass

        controller = Controller()
        controller.lcd_writes = 0
        controller.lcd_port_writes = collections.Counter()
        controller._lcd_source_packed_cursor = SourcePackedCursor()
        controller._lcd_source_packed_cursor.stage = 2
        controller._lcd_protocol = 'parallel-2'
        controller._lcd_command = 3
        controller._lcd_x, controller._lcd_y = [0, 127], [0, 159]
        controller.config = SimpleNamespace(width=128, height=160)
        controller._lcd_write(None, 0, 0x02000000, 2, 3, None)
        controller._lcd_write(None, 0, 0x02000002, 2, 0x1030, None)
        self.assertEqual(controller._lcd_source_packed_cursor.stage, 3)
        controller._lcd_write(None, 0, 0x02000000, 2, 0, None)
        self.assertEqual(controller._lcd_source_packed_cursor.stage, 0)

    def test_cursor_requires_programmed_window(self):
        controller = DisplayControllerMixin()
        controller._lcd_protocol = 'parallel-2'
        controller._lcd_command = 0x21
        controller._lcd_source_packed_cursor = SourcePackedCursor()
        controller._lcd_source_packed_cursor.stage = 3
        controller._lcd_packed_cursor_stage = 0
        controller._lcd_window_axis_mask = 0
        controller._lcd_x, controller._lcd_y = [0, 127], [0, 159]
        controller._lcd_cursor, controller._lcd_gram_cursor = [0, 0], [0, 0]
        controller.config = SimpleNamespace(width=128, height=160)
        self.assertFalse(controller._lcd_packed_cursor_data(0x02000002, 2, 0x0301))
        controller._lcd_window_axis_mask = 0xf
        self.assertTrue(controller._lcd_packed_cursor_data(0x02000002, 2, 0x0301))
        self.assertEqual(controller._lcd_gram_cursor, [1, 3])


if __name__ == '__main__':
    unittest.main()
