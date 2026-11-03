import unittest
from types import SimpleNamespace
from corpus import firmware_path
from msm5xxx_emulator.detection.input_distributed7 import find_seven_row_input_profile
from msm5xxx_emulator.qemu.transport import matrix_input_command, qemu_seven_row_matrix_property


class SevenRowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = firmware_path('x4000.bin').read_bytes()
        cls.profile, cls.reason = find_seven_row_input_profile(cls.image)

    def test_source_closure_and_open_fold(self):
        p = self.profile
        self.assertEqual(self.reason, 'accepted')
        self.assertEqual((p['rows'], p['columns'], p['period_ms']), (7, 4, 25))
        self.assertEqual(tuple(p['lid_input'][k] for k in ('address', 'mask', 'open_value')), (0x3000660, 1, 1))
        self.assertEqual(find_seven_row_input_profile(self.image, 1)[1], 'unsupported-load-address')
        changed = bytearray(self.image)
        changed[p['function'] + 0x126] ^= 1
        self.assertIsNone(find_seven_row_input_profile(bytes(changed))[0])

    def test_physical_rows_and_profile_revalidation(self):
        p = self.profile
        for row, physical in enumerate((0, 2, 3, 4, 5, 6, 1)):
            self.assertEqual(matrix_input_command(p, (0, row, 0), True), bytes((0x80, 1, physical, 14)))
        config = SimpleNamespace(load_address=0)
        self.assertIn('matrix-gpio=3000694:', qemu_seven_row_matrix_property(self.image, config, p))
        with self.assertRaises(ValueError):
            qemu_seven_row_matrix_property(self.image, config, dict(p, rows=6))
